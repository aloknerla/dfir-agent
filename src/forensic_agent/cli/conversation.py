"""Bounded, non-evidentiary conversation history for the interactive CLI.

This store is deliberately narrower than an investigation trace. It retains user
questions, final verified answers, references to durable audit material, and the
paths of the evidence the investigation was opened over — enough to reattach the
same sources later, and nothing that could stand in for the forensic record.
Tool payloads, model messages, and private reasoning have no field in the schema
and are never placed in model prompt context. Persisted documents are authenticated
with a store-local HMAC key before loading, while revision-based compare-and-swap
writes prevent stale processes from silently replacing newer conversation state.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib
import json
import os
import re
import secrets
import stat
import tempfile
import threading
import uuid
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO
from urllib.parse import urlsplit

from forensic_agent.agent.case_context import (
    CASE_CONTEXT_END_MARKER,
    CASE_CONTEXT_MARKER,
    case_context_sha256,
    normalize_case_context,
    render_case_context,
)

SCHEMA = "forensic_agent.conversation.v5"
LEGACY_CONTEXT_SCHEMA = "forensic_agent.conversation.v4"
LEGACY_BOUND_SCHEMA = "forensic_agent.conversation.v3"
LEGACY_UNBOUND_SCHEMA = "forensic_agent.conversation.v2"
INTEGRITY_ALGORITHM = "HMAC-SHA256"
SESSION_CONTEXT_MARKER = "SESSION CONTEXT NON_EVIDENCE"
SESSION_CONTEXT_END_MARKER = "END SESSION CONTEXT NON_EVIDENCE"
DEFAULT_MAX_TURNS = 20
DEFAULT_MAX_TURN_BYTES = 24_000
DEFAULT_MAX_CONTEXT_BYTES = 64_000

_HARD_MAX_TURNS = 100
_HARD_MAX_TURN_BYTES = 256 * 1024
_HARD_MAX_CONTEXT_BYTES = 1024 * 1024
_MAX_PERSISTED_BYTES = 32 * 1024 * 1024
_MAX_ID_BYTES = 256
_MAX_REFERENCE_BYTES = 4096
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
#: Deliberately the shape ``PcapSourceCatalog`` itself accepts. A component name
#: the console can build must survive a round trip through this store, or a
#: restore would fail on a name the operator never chose.
_SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$")
_HMAC_KEY_BYTES = 32
_HMAC_TAG = re.compile(r"^[0-9a-f]{64}$")
_KEY_FILENAME = ".conversation-hmac.key"
_LOCK_FILENAME = ".conversation.lock"
_MAX_EVIDENCE_SOURCES = 64

#: The four source kinds the console can reopen. A binding that names anything
#: else is refused rather than guessed at: restoring must not invent evidence.
EVIDENCE_SOURCE_KINDS: tuple[str, ...] = ("disk", "memory", "network")


class ConversationError(RuntimeError):
    """Base error for conversation state and persistence."""


class ConversationLimitError(ConversationError):
    """A value exceeds a configured or hard conversation limit."""


class ConversationNotFoundError(ConversationError):
    """A requested session or turn does not exist."""


class ConversationIdentityError(ConversationError):
    """A session does not belong to the expected evidence or inference identity."""


class ConversationPersistenceError(ConversationError):
    """Conversation state could not be read or atomically persisted."""


class ConversationConflictError(ConversationPersistenceError):
    """Another process updated the session after it was loaded."""


def _size(value: str) -> int:
    return len(value.encode("utf-8"))


def _text(value: object, name: str, *, max_bytes: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConversationError(f"{name} must be a non-empty string.")
    result = value.strip()
    if "\x00" in result:
        raise ConversationError(f"{name} contains a NUL character.")
    if _size(result) > max_bytes:
        raise ConversationLimitError(f"{name} exceeds {max_bytes} UTF-8 bytes.")
    return result


def _identifier(value: object, name: str) -> str:
    result = _text(value, name, max_bytes=_MAX_ID_BYTES)
    if not _SAFE_ID.fullmatch(result):
        raise ConversationError(
            f"{name} must contain only letters, numbers, dots, underscores, or hyphens."
        )
    return result


def _component(value: object, name: str) -> str:
    result = _text(value, name, max_bytes=_MAX_ID_BYTES)
    if not _SAFE_COMPONENT.fullmatch(result):
        raise ConversationError(f"{name} is not a valid capture component name.")
    return result


def _positive(value: object, name: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ConversationLimitError(f"{name} must be a positive integer.")
    if value > maximum:
        raise ConversationLimitError(f"{name} exceeds the hard maximum of {maximum}.")
    return value


def _revision(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ConversationPersistenceError("Persisted revision is invalid.")
    return value


def _timestamp(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ConversationPersistenceError(f"Persisted {name} is invalid.")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ConversationPersistenceError(f"Persisted {name} is invalid.") from exc
    return value


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _provider_endpoint(value: object) -> str:
    """Validate a non-secret endpoint suitable for persisted provenance."""

    result = _text(value, "provider_endpoint", max_bytes=_MAX_REFERENCE_BYTES)
    parsed = urlsplit(result)
    if (
        parsed.scheme.casefold() not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or bool(parsed.query)
        or bool(parsed.fragment)
    ):
        raise ConversationError(
            "provider_endpoint must be an HTTP(S) URL without credentials, "
            "a query, or a fragment."
        )
    return result.rstrip("/")


@dataclass(frozen=True, slots=True)
class ConversationInferenceIdentity:
    """Non-secret provider endpoint and exact model used by one conversation."""

    provider: str
    endpoint: str
    model: str

    @classmethod
    def create(
        cls,
        *,
        provider: object,
        endpoint: object,
        model: object,
    ) -> ConversationInferenceIdentity:
        provider_name = _identifier(provider, "provider")
        provider_endpoint = _provider_endpoint(endpoint)
        model_name = _text(model, "model", max_bytes=_MAX_REFERENCE_BYTES)
        if any(character.isspace() for character in model_name):
            raise ConversationError("model may not contain whitespace.")
        return cls(provider_name, provider_endpoint, model_name)

    def to_dict(self) -> dict[str, str]:
        return {
            "provider": self.provider,
            "endpoint": self.endpoint,
            "model": self.model,
        }


@dataclass(frozen=True, slots=True)
class ConversationEvidenceSource:
    """One reopenable evidence source: what it is and where it was read from.

    ``component_id`` and ``role`` carry the model-visible identity of a network
    capture, which the console derives when the catalog is built. They are
    persisted because a capture set restored under different component names is
    a different evidence set, and the session would then refuse to resume for a
    reason the operator never caused.
    """

    kind: str
    path: str
    component_id: str = ""
    role: str = ""

    @classmethod
    def create(
        cls,
        *,
        kind: object,
        path: object,
        component_id: object = "",
        role: object = "",
    ) -> ConversationEvidenceSource:
        source_kind = _text(kind, "evidence source kind", max_bytes=_MAX_ID_BYTES)
        if source_kind not in EVIDENCE_SOURCE_KINDS:
            raise ConversationError(
                "evidence source kind must be one of: "
                + ", ".join(EVIDENCE_SOURCE_KINDS)
            )
        source_path = _text(path, "evidence source path", max_bytes=_MAX_REFERENCE_BYTES)
        component = (
            _component(component_id, "component_id")
            if isinstance(component_id, str) and component_id
            else ""
        )
        capture_role = (
            _component(role, "role") if isinstance(role, str) and role else ""
        )
        if source_kind != "network" and (component or capture_role):
            raise ConversationError(
                "Only a network capture carries a component_id and a role."
            )
        return cls(source_kind, source_path, component, capture_role)

    def to_dict(self) -> dict[str, str]:
        return {
            "kind": self.kind,
            "path": self.path,
            "component_id": self.component_id,
            "role": self.role,
        }


@dataclass(frozen=True, slots=True)
class ConversationEvidenceBinding:
    """The evidence set one investigation was opened over, as reopenable paths.

    This is a non-evidentiary convenience record, exactly like the rest of this
    store: it holds no contents and no digests, only what the console needs in
    order to reattach the same sources. Whether the reattached set is still the
    same evidence remains decided by ``source_identity``, not by this record.
    """

    case_label: str
    sources: tuple[ConversationEvidenceSource, ...]
    network_default: str = ""
    network_inputs: tuple[str, ...] = ()

    @classmethod
    def create(
        cls,
        *,
        case_label: object,
        sources: object,
        network_default: object = "",
        network_inputs: object = (),
    ) -> ConversationEvidenceBinding:
        label = _text(case_label, "case_label", max_bytes=_MAX_ID_BYTES)
        if not isinstance(sources, Sequence) or isinstance(sources, str | bytes):
            raise ConversationError("evidence sources must be a sequence.")
        if not sources:
            raise ConversationError("An evidence binding needs at least one source.")
        # Counted before anything is parsed, so a persisted document cannot make
        # this validator do unbounded work on its way to being rejected.
        if len(sources) > _MAX_EVIDENCE_SOURCES:
            raise ConversationLimitError(
                f"An evidence binding may name at most {_MAX_EVIDENCE_SOURCES} sources."
            )
        parsed: list[ConversationEvidenceSource] = []
        for source in sources:
            if isinstance(source, ConversationEvidenceSource):
                parsed.append(source)
            elif isinstance(source, Mapping):
                if set(source) - {"kind", "path", "component_id", "role"}:
                    raise ConversationError("An evidence source has unknown fields.")
                parsed.append(
                    ConversationEvidenceSource.create(
                        kind=source.get("kind"),
                        path=source.get("path"),
                        component_id=source.get("component_id", ""),
                        role=source.get("role", ""),
                    )
                )
            else:
                raise ConversationError(
                    f"An evidence source must be an object, not {type(source).__name__}."
                )
        rows = tuple(parsed)
        components = [row.component_id for row in rows if row.component_id]
        if len(components) != len(set(components)):
            raise ConversationError("Network component identifiers must be unique.")
        default = (
            _component(network_default, "network_default")
            if isinstance(network_default, str) and network_default
            else ""
        )
        if default and default not in components:
            raise ConversationError(
                "network_default must name one of the bound network captures."
            )
        if not isinstance(network_inputs, Sequence) or isinstance(
            network_inputs, str | bytes
        ):
            raise ConversationError("network_inputs must be a sequence.")
        inputs = tuple(
            _component(value, "network input component") for value in network_inputs
        )
        if len(inputs) != len(set(inputs)):
            raise ConversationError("Network input identifiers must be unique.")
        if any(value not in components for value in inputs):
            raise ConversationError(
                "Every network input must name one of the bound network captures."
            )
        return cls(label, rows, default, inputs)

    def to_dict(self) -> dict[str, object]:
        return {
            "case_label": self.case_label,
            "sources": [source.to_dict() for source in self.sources],
            "network_default": self.network_default,
            "network_inputs": list(self.network_inputs),
        }


@dataclass(frozen=True, slots=True)
class ConversationTurn:
    """One question and its final verified answer.

    Audit references are persisted for review but excluded from prompt context.
    """

    turn_id: str
    question: str
    verified_answer: str
    audit_ref: str
    verification_ref: str
    created_at: str
    included_in_context: bool = True

    def to_dict(self) -> dict[str, object]:
        return {
            "turn_id": self.turn_id,
            "question": self.question,
            "verified_answer": self.verified_answer,
            "audit_ref": self.audit_ref,
            "verification_ref": self.verification_ref,
            "created_at": self.created_at,
            "included_in_context": self.included_in_context,
        }


class ConversationSession:
    """Automatically persisted state for one case and source identity."""

    def __init__(
        self,
        *,
        store: ConversationStore,
        session_id: str,
        case_id: str,
        source_identity: str,
        inference_identity: ConversationInferenceIdentity | None,
        max_turns: int,
        max_turn_bytes: int,
        max_context_bytes: int,
        created_at: str,
        updated_at: str,
        revision: int = 0,
        turns: tuple[ConversationTurn, ...] = (),
        case_context: str = "",
        evidence_binding: ConversationEvidenceBinding | None = None,
    ) -> None:
        self._store = store
        self.session_id = session_id
        self.case_id = case_id
        self.source_identity = source_identity
        self.inference_identity = inference_identity
        self.max_turns = max_turns
        self.max_turn_bytes = max_turn_bytes
        self.max_context_bytes = max_context_bytes
        self.created_at = created_at
        self.updated_at = updated_at
        self.revision = revision
        self._turns = list(turns)
        self._case_context = case_context
        self._evidence_binding = evidence_binding
        self._lock = threading.RLock()

    @property
    def evidence_binding(self) -> ConversationEvidenceBinding | None:
        """Return the evidence set this investigation was opened over, if recorded."""

        with self._lock:
            return self._evidence_binding

    def bind_evidence(
        self, binding: ConversationEvidenceBinding | None
    ) -> ConversationEvidenceBinding | None:
        """Record which sources to reopen, so leaving is never bookkeeping."""

        if binding is not None and not isinstance(binding, ConversationEvidenceBinding):
            raise ConversationError(
                "evidence binding must be a ConversationEvidenceBinding."
            )
        with self._lock:
            old = (self._evidence_binding, self.updated_at, self.revision)
            self._evidence_binding = binding
            self.updated_at = _now()
            self.revision += 1
            try:
                self._store._persist(self, expected_revision=old[2])
            except Exception:
                self._evidence_binding, self.updated_at, self.revision = old
                raise
            return self._evidence_binding

    @property
    def case_context(self) -> str:
        """Return the user-supplied, non-evidentiary case description."""

        with self._lock:
            return self._case_context

    @property
    def case_context_sha256(self) -> str | None:
        """Return a stable digest for the exact normalized case context."""

        with self._lock:
            return case_context_sha256(self._case_context)

    def set_case_context(self, value: str) -> str:
        """Replace and persist the non-evidentiary context for this session."""

        try:
            normalized = normalize_case_context(value)
        except ValueError as exc:
            raise ConversationError(str(exc)) from exc
        rendered = render_case_context(normalized)
        if _size(rendered) > self.max_context_bytes:
            raise ConversationLimitError(
                "case_context leaves no room within the model context limit."
            )
        with self._lock:
            old = (self._case_context, self.updated_at, self.revision)
            self._case_context = normalized
            self.updated_at = _now()
            self.revision += 1
            try:
                self._store._persist(self, expected_revision=old[2])
            except Exception:
                self._case_context, self.updated_at, self.revision = old
                raise
            return self._case_context

    def clear_case_context(self) -> bool:
        """Remove persisted case context while retaining conversation turns."""

        with self._lock:
            if not self._case_context:
                return False
            old = (self._case_context, self.updated_at, self.revision)
            self._case_context = ""
            self.updated_at = _now()
            self.revision += 1
            try:
                self._store._persist(self, expected_revision=old[2])
            except Exception:
                self._case_context, self.updated_at, self.revision = old
                raise
            return True

    def append(
        self,
        question: str,
        verified_answer: str,
        *,
        audit_ref: str,
        verification_ref: str,
        turn_id: str | None = None,
    ) -> ConversationTurn:
        """Append only a final verified answer and persist it atomically."""

        question = _text(question, "question", max_bytes=self.max_turn_bytes)
        verified_answer = _text(
            verified_answer, "verified_answer", max_bytes=self.max_turn_bytes
        )
        if _size(question) + _size(verified_answer) > self.max_turn_bytes:
            raise ConversationLimitError(
                "question and verified_answer exceed the per-turn UTF-8 byte limit."
            )
        audit_ref = _text(audit_ref, "audit_ref", max_bytes=_MAX_REFERENCE_BYTES)
        verification_ref = _text(
            verification_ref, "verification_ref", max_bytes=_MAX_REFERENCE_BYTES
        )
        turn_id = _identifier(turn_id or uuid.uuid4().hex, "turn_id")

        with self._lock:
            if any(turn.turn_id == turn_id for turn in self._turns):
                raise ConversationError(f"Turn already exists: {turn_id}")
            now = _now()
            turn = ConversationTurn(
                turn_id,
                question,
                verified_answer,
                audit_ref,
                verification_ref,
                now,
            )
            old = (list(self._turns), self.updated_at, self.revision)
            self._turns.append(turn)
            if len(self._turns) > self.max_turns:
                del self._turns[: len(self._turns) - self.max_turns]
            self.updated_at = now
            self.revision += 1
            try:
                self._store._persist(self, expected_revision=old[2])
            except Exception:
                self._turns, self.updated_at, self.revision = old
                raise
            return turn

    def history(
        self, limit: int | None = None, *, context_only: bool = False
    ) -> tuple[ConversationTurn, ...]:
        """Return retained turns in chronological order."""

        with self._lock:
            rows = [
                turn for turn in self._turns if not context_only or turn.included_in_context
            ]
            if limit is None:
                return tuple(rows)
            if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
                raise ConversationLimitError("history limit must be non-negative.")
            return tuple(rows[-limit:]) if limit else ()

    def retry_question(self, turn_id: str | None = None) -> str:
        """Return a retained question; this method never invokes a model."""

        with self._lock:
            if not self._turns:
                raise ConversationNotFoundError("The session has no retained questions.")
            if turn_id is None:
                return self._turns[-1].question
            turn_id = _identifier(turn_id, "turn_id")
            for turn in self._turns:
                if turn.turn_id == turn_id:
                    return turn.question
        raise ConversationNotFoundError(f"Turn not found: {turn_id}")

    def undo_from_context(self, turn_id: str | None = None) -> ConversationTurn:
        """Exclude a turn from prompt context without deleting its audit reference."""

        with self._lock:
            index: int | None = None
            if turn_id is None:
                index = next(
                    (
                        i
                        for i in range(len(self._turns) - 1, -1, -1)
                        if self._turns[i].included_in_context
                    ),
                    None,
                )
            else:
                turn_id = _identifier(turn_id, "turn_id")
                index = next(
                    (i for i, turn in enumerate(self._turns) if turn.turn_id == turn_id),
                    None,
                )
            if index is None:
                raise ConversationNotFoundError("No matching context turn was found.")
            current = self._turns[index]
            if not current.included_in_context:
                raise ConversationError(
                    f"Turn is already excluded from context: {current.turn_id}"
                )

            old = (list(self._turns), self.updated_at, self.revision)
            updated = replace(current, included_in_context=False)
            self._turns[index] = updated
            self.updated_at = _now()
            self.revision += 1
            try:
                self._store._persist(self, expected_revision=old[2])
            except Exception:
                self._turns, self.updated_at, self.revision = old
                raise
            return updated

    @staticmethod
    def _render_prompt(turns: list[ConversationTurn]) -> str:
        rows = [
            {
                "question": turn.question,
                "final_verified_answer": turn.verified_answer,
            }
            for turn in turns
        ]
        content = json.dumps(rows, ensure_ascii=False, separators=(",", ":"))
        return (
            f"{SESSION_CONTEXT_MARKER}\n"
            "Prior exchanges are conversational context only. They are not forensic "
            "evidence; revalidate every case-specific claim with approved tools.\n"
            f"{content}\n{SESSION_CONTEXT_END_MARKER}"
        )

    def prompt_context(self) -> str:
        """Return bounded complete Q/A turns, always labelled as non-evidence."""

        with self._lock:
            case_block = (
                render_case_context(self._case_context)
                if self._case_context
                else ""
            )
            included = [turn for turn in self._turns if turn.included_in_context]
            selected: list[ConversationTurn] = []
            for turn in reversed(included):
                candidate = [turn, *selected]
                blocks = [block for block in (case_block, self._render_prompt(candidate)) if block]
                if _size("\n\n".join(blocks)) <= self.max_context_bytes:
                    selected = candidate
            blocks = [
                block
                for block in (
                    case_block,
                    self._render_prompt(selected) if selected else "",
                )
                if block
            ]
            return "\n\n".join(blocks)

    def history_prompt_context(self) -> str:
        """Return only prior Q/A context, excluding the separate case brief."""

        with self._lock:
            included = [turn for turn in self._turns if turn.included_in_context]
            selected: list[ConversationTurn] = []
            for turn in reversed(included):
                candidate = [turn, *selected]
                if _size(self._render_prompt(candidate)) <= self.max_context_bytes:
                    selected = candidate
            return self._render_prompt(selected) if selected else ""

    def status(self) -> dict[str, object]:
        """Return a UI-friendly summary without evidence contents."""

        with self._lock:
            prompt = self.prompt_context()
            return {
                "session_id": self.session_id,
                "case_id": self.case_id,
                "source_identity": self.source_identity,
                "inference_identity": (
                    self.inference_identity.to_dict()
                    if self.inference_identity is not None
                    else None
                ),
                "inference_identity_bound": self.inference_identity is not None,
                "retained_turns": len(self._turns),
                "context_turns": sum(turn.included_in_context for turn in self._turns),
                "case_context_set": bool(self._case_context),
                "case_context_bytes": _size(self._case_context),
                "case_context_sha256": self.case_context_sha256,
                "evidence_binding": (
                    self._evidence_binding.to_dict()
                    if self._evidence_binding is not None
                    else None
                ),
                "prompt_context_bytes": _size(prompt),
                "max_turns": self.max_turns,
                "revision": self.revision,
                "created_at": self.created_at,
                "updated_at": self.updated_at,
            }

    def _payload(self) -> dict[str, object]:
        if self.inference_identity is None:
            raise ConversationPersistenceError(
                "A legacy conversation without provider and model binding "
                "cannot be persisted."
            )
        payload: dict[str, object] = {
            "schema": SCHEMA,
            "session_id": self.session_id,
            "case_id": self.case_id,
            "source_identity": self.source_identity,
            "inference_identity": self.inference_identity.to_dict(),
            "case_context": self._case_context,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "revision": self.revision,
            "limits": {
                "max_turns": self.max_turns,
                "max_turn_bytes": self.max_turn_bytes,
                "max_context_bytes": self.max_context_bytes,
            },
            "turns": [turn.to_dict() for turn in self._turns],
        }
        # A conversation over no evidence has nothing to reopen, so the key is
        # left out entirely rather than written as an empty promise.
        if self._evidence_binding is not None:
            payload["evidence_binding"] = self._evidence_binding.to_dict()
        return payload


class ConversationStore:
    """Atomic JSON store for bounded conversation sessions."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root).expanduser().resolve()
        try:
            self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as exc:
            raise ConversationPersistenceError(
                f"Cannot create conversation root: {self.root}"
            ) from exc
        if not self.root.is_dir():
            raise ConversationPersistenceError(
                f"Conversation root is not a directory: {self.root}"
            )
        self._lock = threading.RLock()
        self._lock_path = self.root / _LOCK_FILENAME
        with self._interprocess_lock():
            self._integrity_key = self._load_or_create_integrity_key()

    @contextmanager
    def _interprocess_lock(self) -> Iterator[None]:
        """Serialize compare-and-swap writes across store instances and processes."""

        with self._lock:
            if self._lock_path.is_symlink():
                raise ConversationPersistenceError(
                    "Conversation store lock may not be a symlink."
            )
            flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor: int | None = None
            try:
                descriptor = os.open(self._lock_path, flags, 0o600)
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode):
                    raise ConversationPersistenceError(
                        "Conversation store lock is not a regular file."
                    )
                handle: BinaryIO = os.fdopen(descriptor, "r+b")
                descriptor = None
            except ConversationError:
                raise
            except OSError as exc:
                raise ConversationPersistenceError(
                    "Cannot open the conversation store lock."
                ) from exc
            finally:
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
            locked = False
            try:
                try:
                    os.chmod(self._lock_path, 0o600)
                except OSError:
                    pass
                handle.seek(0, os.SEEK_END)
                if handle.tell() == 0:
                    handle.write(b"\0")
                    handle.flush()
                    os.fsync(handle.fileno())
                handle.seek(0)
                if os.name == "nt":
                    msvcrt = importlib.import_module("msvcrt")
                    msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
                else:
                    fcntl = importlib.import_module("fcntl")
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                locked = True
                yield
            except ConversationError:
                raise
            except OSError as exc:
                raise ConversationPersistenceError(
                    "Cannot lock the conversation store."
                ) from exc
            finally:
                if locked:
                    try:
                        handle.seek(0)
                        if os.name == "nt":
                            msvcrt = importlib.import_module("msvcrt")
                            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                        else:
                            fcntl = importlib.import_module("fcntl")
                            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                    except OSError:
                        pass
                handle.close()

    def _read_integrity_key(self) -> bytes:
        path = self.root / _KEY_FILENAME
        if path.is_symlink():
            raise ConversationPersistenceError(
                "Conversation integrity key may not be a symlink."
            )
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise ConversationPersistenceError(
                "Cannot read the conversation integrity key."
            ) from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise ConversationPersistenceError(
                    "Conversation integrity key is not a regular file."
                )
            if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
                raise ConversationPersistenceError(
                    "Conversation integrity key permissions are too broad."
                )
            key = os.read(descriptor, _HMAC_KEY_BYTES + 1)
        finally:
            os.close(descriptor)
        if len(key) != _HMAC_KEY_BYTES:
            raise ConversationPersistenceError(
                "Conversation integrity key has an invalid length."
            )
        return key

    def _load_or_create_integrity_key(self) -> bytes:
        path = self.root / _KEY_FILENAME
        if path.exists() or path.is_symlink():
            return self._read_integrity_key()

        temporary: Path | None = None
        try:
            descriptor, name = tempfile.mkstemp(
                prefix=".conversation-hmac.",
                suffix=".tmp",
                dir=self.root,
            )
            temporary = Path(name)
            try:
                os.chmod(temporary, 0o600)
            except OSError:
                pass
            key = secrets.token_bytes(_HMAC_KEY_BYTES)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(key)
                handle.flush()
                os.fsync(handle.fileno())
            if path.exists() or path.is_symlink():
                return self._read_integrity_key()
            os.replace(temporary, path)
            temporary = None
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            return self._read_integrity_key()
        except ConversationError:
            raise
        except OSError as exc:
            raise ConversationPersistenceError(
                "Cannot create the conversation integrity key."
            ) from exc
        finally:
            if temporary is not None:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass

    @staticmethod
    def _canonical_payload(payload: Mapping[str, object]) -> bytes:
        return json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def _seal_payload(self, payload: Mapping[str, object]) -> dict[str, object]:
        unsigned = dict(payload)
        if "integrity" in unsigned:
            raise ConversationPersistenceError(
                "Unsigned conversation payload unexpectedly contains integrity metadata."
            )
        tag = hmac.new(
            self._integrity_key,
            self._canonical_payload(unsigned),
            hashlib.sha256,
        ).hexdigest()
        return {
            **unsigned,
            "integrity": {
                "algorithm": INTEGRITY_ALGORITHM,
                "tag": tag,
            },
        }

    def _verify_payload(self, payload: object) -> dict[str, object]:
        if not isinstance(payload, Mapping):
            raise ConversationPersistenceError(
                "Conversation payload must be a JSON object."
            )
        integrity = payload.get("integrity")
        if (
            not isinstance(integrity, Mapping)
            or set(integrity) != {"algorithm", "tag"}
            or integrity.get("algorithm") != INTEGRITY_ALGORITHM
        ):
            raise ConversationPersistenceError(
                "Conversation integrity metadata is missing or invalid."
            )
        tag = integrity.get("tag")
        if not isinstance(tag, str) or not _HMAC_TAG.fullmatch(tag):
            raise ConversationPersistenceError(
                "Conversation integrity tag is invalid."
            )
        unsigned = dict(payload)
        del unsigned["integrity"]
        expected = hmac.new(
            self._integrity_key,
            self._canonical_payload(unsigned),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(tag, expected):
            raise ConversationPersistenceError(
                "Conversation integrity verification failed."
            )
        return unsigned

    def _path(self, session_id: str) -> Path:
        session_id = _identifier(session_id, "session_id")
        path = self.root / f"{session_id}.conversation.json"
        if path.parent.resolve() != self.root:
            raise ConversationPersistenceError("Session path escaped its root.")
        return path

    def new_session(
        self,
        *,
        case_id: str,
        source_identity: str,
        provider: str,
        provider_endpoint: str,
        model: str,
        session_id: str | None = None,
        max_turns: int = DEFAULT_MAX_TURNS,
        max_turn_bytes: int = DEFAULT_MAX_TURN_BYTES,
        max_context_bytes: int = DEFAULT_MAX_CONTEXT_BYTES,
    ) -> ConversationSession:
        """Create and persist a new empty session."""

        session_id = _identifier(session_id or uuid.uuid4().hex, "session_id")
        case_id = _text(case_id, "case_id", max_bytes=_MAX_ID_BYTES)
        source_identity = _text(
            source_identity, "source_identity", max_bytes=_MAX_REFERENCE_BYTES
        )
        inference_identity = ConversationInferenceIdentity.create(
            provider=provider,
            endpoint=provider_endpoint,
            model=model,
        )
        max_turns = _positive(max_turns, "max_turns", _HARD_MAX_TURNS)
        max_turn_bytes = _positive(
            max_turn_bytes, "max_turn_bytes", _HARD_MAX_TURN_BYTES
        )
        max_context_bytes = _positive(
            max_context_bytes, "max_context_bytes", _HARD_MAX_CONTEXT_BYTES
        )
        if max_context_bytes < max_turn_bytes:
            raise ConversationLimitError(
                "max_context_bytes must be at least max_turn_bytes."
            )
        path = self._path(session_id)
        with self._lock:
            if path.exists():
                raise ConversationError(f"Session already exists: {session_id}")
            now = _now()
            session = ConversationSession(
                store=self,
                session_id=session_id,
                case_id=case_id,
                source_identity=source_identity,
                inference_identity=inference_identity,
                max_turns=max_turns,
                max_turn_bytes=max_turn_bytes,
                max_context_bytes=max_context_bytes,
                created_at=now,
                updated_at=now,
            )
            self._persist(session, create_only=True)
            return session

    def resume(
        self,
        session_id: str,
        *,
        case_id: str,
        source_identity: str,
        provider: str,
        provider_endpoint: str,
        model: str,
    ) -> ConversationSession:
        """Resume only when evidence and inference identities match exactly."""

        expected_case = _text(case_id, "case_id", max_bytes=_MAX_ID_BYTES)
        expected_source = _text(
            source_identity, "source_identity", max_bytes=_MAX_REFERENCE_BYTES
        )
        expected_inference = ConversationInferenceIdentity.create(
            provider=provider,
            endpoint=provider_endpoint,
            model=model,
        )
        path = self._path(session_id)
        with self._lock:
            if not path.is_file():
                raise ConversationNotFoundError(f"Session not found: {session_id}")
            session = self._load(path)
        if (
            session.case_id != expected_case
            or session.source_identity != expected_source
        ):
            raise ConversationIdentityError(
                "Session case_id/source_identity does not match active evidence."
            )
        if session.inference_identity is None:
            raise ConversationIdentityError(
                "This saved investigation predates provider and model binding and "
                "cannot be resumed safely. Start a new investigation."
            )
        if session.inference_identity != expected_inference:
            saved = session.inference_identity
            raise ConversationIdentityError(
                "Resume blocked because provider/model identity does not match "
                "the active configuration. "
                f"Saved: {saved.provider} at {saved.endpoint}, model {saved.model}. "
                f"Active: {expected_inference.provider} at "
                f"{expected_inference.endpoint}, model {expected_inference.model}."
            )
        return session

    def list_sessions(
        self,
        *,
        case_id: str | None = None,
        source_identity: str | None = None,
    ) -> tuple[dict[str, object], ...]:
        """List sessions, optionally filtered by exact identities."""

        expected_case = (
            _text(case_id, "case_id", max_bytes=_MAX_ID_BYTES)
            if case_id is not None
            else None
        )
        expected_source = (
            _text(source_identity, "source_identity", max_bytes=_MAX_REFERENCE_BYTES)
            if source_identity is not None
            else None
        )
        with self._lock:
            # One truncated or foreign-keyed file must not take down the
            # whole listing — and with it /sessions, /resume, /continue and
            # every --continue launch. Unreadable documents are skipped and
            # remembered so a caller can say how many were passed over;
            # resume-by-exact-id stays strict.
            sessions = []
            unreadable: list[str] = []
            for path in self.root.glob("*.conversation.json"):
                try:
                    sessions.append(self._load(path))
                except (ConversationPersistenceError, OSError):
                    unreadable.append(path.name)
            self.last_unreadable: tuple[str, ...] = tuple(unreadable)
        rows = [
            session.status()
            for session in sessions
            if (expected_case is None or session.case_id == expected_case)
            and (
                expected_source is None
                or session.source_identity == expected_source
            )
        ]
        rows.sort(
            key=lambda row: (str(row["updated_at"]), str(row["session_id"])),
            reverse=True,
        )
        return tuple(rows)

    def list(
        self,
        *,
        case_id: str | None = None,
        source_identity: str | None = None,
    ) -> tuple[dict[str, object], ...]:
        """Short alias for ``list_sessions``."""

        return self.list_sessions(
            case_id=case_id, source_identity=source_identity
        )

    def _load(self, path: Path) -> ConversationSession:
        if path.is_symlink():
            raise ConversationPersistenceError("Session files may not be symlinks.")
        try:
            if path.stat().st_size > _MAX_PERSISTED_BYTES:
                raise ConversationPersistenceError(
                    "Conversation file exceeds its hard size limit."
                )
            payload = self._verify_payload(
                json.loads(path.read_text(encoding="utf-8"))
            )
        except ConversationPersistenceError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ConversationPersistenceError(
                f"Cannot read conversation file: {path.name}"
            ) from exc
        session = self._from_payload(payload)
        if path.name != f"{session.session_id}.conversation.json":
            raise ConversationPersistenceError(
                "Session filename and payload identity do not match."
            )
        return session

    def _from_payload(self, payload: object) -> ConversationSession:
        if not isinstance(payload, Mapping):
            raise ConversationPersistenceError(
                "Conversation payload must be a JSON object."
            )
        common_fields = {
            "schema",
            "session_id",
            "case_id",
            "source_identity",
            "created_at",
            "updated_at",
            "revision",
            "limits",
            "turns",
        }
        schema = payload.get("schema")
        # The evidence binding is optional within its own schema: a conversation
        # opened over no evidence writes no key at all, so the field set is
        # checked as a range rather than as one exact set.
        optional_fields: set[str] = set()
        if schema == SCHEMA:
            fields = common_fields | {"inference_identity", "case_context"}
            optional_fields = {"evidence_binding"}
        elif schema == LEGACY_CONTEXT_SCHEMA:
            fields = common_fields | {"inference_identity", "case_context"}
        elif schema == LEGACY_BOUND_SCHEMA:
            fields = common_fields | {"inference_identity"}
        elif schema == LEGACY_UNBOUND_SCHEMA:
            fields = common_fields
        else:
            fields = set()
        present = set(payload)
        if not fields <= present <= fields | optional_fields:
            raise ConversationPersistenceError(
                "Conversation schema or fields are invalid."
            )
        inference_identity: ConversationInferenceIdentity | None = None
        if schema in {SCHEMA, LEGACY_BOUND_SCHEMA}:
            raw_identity = payload.get("inference_identity")
            identity_fields = {"provider", "endpoint", "model"}
            if (
                not isinstance(raw_identity, Mapping)
                or set(raw_identity) != identity_fields
            ):
                raise ConversationPersistenceError(
                    "Persisted provider and model identity is invalid."
                )
            try:
                inference_identity = ConversationInferenceIdentity.create(
                    provider=raw_identity["provider"],
                    endpoint=raw_identity["endpoint"],
                    model=raw_identity["model"],
                )
            except (KeyError, ConversationError) as exc:
                raise ConversationPersistenceError(
                    "Persisted provider and model identity is invalid."
                ) from exc
        limits = payload.get("limits")
        limit_fields = {
            "max_turns",
            "max_turn_bytes",
            "max_context_bytes",
        }
        if not isinstance(limits, Mapping) or set(limits) != limit_fields:
            raise ConversationPersistenceError("Conversation limits are invalid.")
        try:
            max_turns = _positive(
                limits["max_turns"], "max_turns", _HARD_MAX_TURNS
            )
            max_turn_bytes = _positive(
                limits["max_turn_bytes"],
                "max_turn_bytes",
                _HARD_MAX_TURN_BYTES,
            )
            max_context_bytes = _positive(
                limits["max_context_bytes"],
                "max_context_bytes",
                _HARD_MAX_CONTEXT_BYTES,
            )
        except (KeyError, ConversationLimitError) as exc:
            raise ConversationPersistenceError(
                "Conversation limits are invalid."
            ) from exc
        if max_context_bytes < max_turn_bytes:
            raise ConversationPersistenceError(
                "Context limit cannot fit one complete turn."
            )

        raw_turns = payload.get("turns")
        if not isinstance(raw_turns, list) or len(raw_turns) > max_turns:
            raise ConversationPersistenceError(
                "Persisted conversation history is invalid."
            )
        turn_fields = {
            "turn_id",
            "question",
            "verified_answer",
            "audit_ref",
            "verification_ref",
            "created_at",
            "included_in_context",
        }
        turns: list[ConversationTurn] = []
        seen: set[str] = set()
        for raw in raw_turns:
            if not isinstance(raw, Mapping) or set(raw) != turn_fields:
                raise ConversationPersistenceError(
                    "Persisted conversation turn is invalid."
                )
            try:
                turn_id = _identifier(raw["turn_id"], "turn_id")
                question = _text(
                    raw["question"], "question", max_bytes=max_turn_bytes
                )
                answer = _text(
                    raw["verified_answer"],
                    "verified_answer",
                    max_bytes=max_turn_bytes,
                )
                audit_ref = _text(
                    raw["audit_ref"],
                    "audit_ref",
                    max_bytes=_MAX_REFERENCE_BYTES,
                )
                verification_ref = _text(
                    raw["verification_ref"],
                    "verification_ref",
                    max_bytes=_MAX_REFERENCE_BYTES,
                )
            except (KeyError, ConversationError) as exc:
                raise ConversationPersistenceError(
                    "Persisted conversation turn is invalid."
                ) from exc
            if _size(question) + _size(answer) > max_turn_bytes:
                raise ConversationPersistenceError(
                    "Persisted turn exceeds its byte limit."
                )
            if turn_id in seen:
                raise ConversationPersistenceError(
                    "Persisted turn identifiers must be unique."
                )
            seen.add(turn_id)
            included = raw.get("included_in_context")
            if not isinstance(included, bool):
                raise ConversationPersistenceError(
                    "Persisted context flag is invalid."
                )
            turns.append(
                ConversationTurn(
                    turn_id,
                    question,
                    answer,
                    audit_ref,
                    verification_ref,
                    _timestamp(raw.get("created_at"), "turn created_at"),
                    included,
                )
            )
        try:
            session_id = _identifier(payload["session_id"], "session_id")
            case_id = _text(
                payload["case_id"], "case_id", max_bytes=_MAX_ID_BYTES
            )
            source_identity = _text(
                payload["source_identity"],
                "source_identity",
                max_bytes=_MAX_REFERENCE_BYTES,
            )
        except (KeyError, ConversationError) as exc:
            raise ConversationPersistenceError(
                "Persisted session identity is invalid."
            ) from exc
        try:
            case_context = (
                normalize_case_context(payload.get("case_context"), allow_empty=True)
                if schema in {SCHEMA, LEGACY_CONTEXT_SCHEMA}
                else ""
            )
        except ValueError as exc:
            raise ConversationPersistenceError(
                "Persisted case context is invalid."
            ) from exc
        raw_binding = payload.get("evidence_binding")
        evidence_binding: ConversationEvidenceBinding | None = None
        if raw_binding is not None:
            if not isinstance(raw_binding, Mapping) or set(raw_binding) != {
                "case_label",
                "sources",
                "network_default",
                "network_inputs",
            }:
                raise ConversationPersistenceError(
                    "Persisted evidence binding is invalid."
                )
            try:
                evidence_binding = ConversationEvidenceBinding.create(
                    case_label=raw_binding["case_label"],
                    sources=raw_binding["sources"],
                    network_default=raw_binding["network_default"],
                    network_inputs=raw_binding["network_inputs"],
                )
            except ConversationError as exc:
                raise ConversationPersistenceError(
                    "Persisted evidence binding is invalid."
                ) from exc
        return ConversationSession(
            store=self,
            session_id=session_id,
            case_id=case_id,
            source_identity=source_identity,
            inference_identity=inference_identity,
            max_turns=max_turns,
            max_turn_bytes=max_turn_bytes,
            max_context_bytes=max_context_bytes,
            created_at=_timestamp(payload.get("created_at"), "created_at"),
            updated_at=_timestamp(payload.get("updated_at"), "updated_at"),
            revision=_revision(payload.get("revision")),
            turns=tuple(turns),
            case_context=case_context,
            evidence_binding=evidence_binding,
        )

    def _persist(
        self,
        session: ConversationSession,
        *,
        create_only: bool = False,
        expected_revision: int | None = None,
    ) -> None:
        if session._store is not self:
            raise ConversationPersistenceError(
                "Session belongs to a different store."
            )
        if create_only and expected_revision is not None:
            raise ConversationPersistenceError(
                "A create-only write cannot specify an expected revision."
            )
        if expected_revision is not None:
            expected_revision = _revision(expected_revision)
        target = self._path(session.session_id)
        sealed = self._seal_payload(session._payload())
        document = (
            json.dumps(
                sealed,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        if len(document) > _MAX_PERSISTED_BYTES:
            raise ConversationLimitError(
                "Conversation file exceeds its hard size limit."
            )

        temp_path: Path | None = None
        with self._interprocess_lock():
            if create_only and target.exists():
                raise ConversationError(
                    f"Session already exists: {session.session_id}"
                )
            if expected_revision is not None:
                if not target.is_file():
                    raise ConversationConflictError(
                        "Conversation disappeared before the update could be persisted."
                    )
                persisted = self._load(target)
                if (
                    persisted.case_id != session.case_id
                    or persisted.source_identity != session.source_identity
                    or persisted.inference_identity != session.inference_identity
                    or persisted.created_at != session.created_at
                ):
                    raise ConversationConflictError(
                        "Conversation identity changed before the update could be persisted."
                    )
                if persisted.revision != expected_revision:
                    raise ConversationConflictError(
                        "Conversation changed in another process "
                        f"(expected revision {expected_revision}, "
                        f"found {persisted.revision})."
                    )
            try:
                fd, name = tempfile.mkstemp(
                    prefix=f".{session.session_id}.",
                    suffix=".tmp",
                    dir=self.root,
                )
                temp_path = Path(name)
                try:
                    os.chmod(temp_path, 0o600)
                except OSError:
                    pass
                with os.fdopen(fd, "wb") as handle:
                    handle.write(document)
                    handle.flush()
                    os.fsync(handle.fileno())
                if create_only and target.exists():
                    raise ConversationError(
                        f"Session already exists: {session.session_id}"
                    )
                os.replace(temp_path, target)
                temp_path = None
            except ConversationError:
                raise
            except OSError as exc:
                raise ConversationPersistenceError(
                    f"Cannot atomically persist session: {session.session_id}"
                ) from exc
            finally:
                if temp_path is not None:
                    try:
                        temp_path.unlink(missing_ok=True)
                    except OSError:
                        pass


__all__ = [
    "ConversationConflictError",
    "ConversationError",
    "ConversationEvidenceBinding",
    "ConversationEvidenceSource",
    "ConversationInferenceIdentity",
    "ConversationIdentityError",
    "ConversationLimitError",
    "ConversationNotFoundError",
    "ConversationPersistenceError",
    "ConversationSession",
    "ConversationStore",
    "ConversationTurn",
    "CASE_CONTEXT_END_MARKER",
    "CASE_CONTEXT_MARKER",
    "DEFAULT_MAX_CONTEXT_BYTES",
    "DEFAULT_MAX_TURN_BYTES",
    "DEFAULT_MAX_TURNS",
    "EVIDENCE_SOURCE_KINDS",
    "INTEGRITY_ALGORITHM",
    "LEGACY_BOUND_SCHEMA",
    "LEGACY_CONTEXT_SCHEMA",
    "LEGACY_UNBOUND_SCHEMA",
    "SESSION_CONTEXT_END_MARKER",
    "SESSION_CONTEXT_MARKER",
]
