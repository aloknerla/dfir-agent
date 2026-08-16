"""Complete tool-output capture, taken before any shaping for the model.

Three artifacts are kept strictly separate, because conflating them lets a
truncated preview be published as if it were the tool's answer:

* **canonical pre-standardization tool return** — the value the tool adapter
  returned to the agent, captured and hashed here *before* pagination-for-display,
  byte caps, preview construction or any other normalization loss.  Precisely:
  this is the adapter's Python return value in canonical JSON form, NOT the
  upstream program's byte-exact stdout.  Where an adapter shells out, its stdout
  has already been parsed by the adapter before this boundary; capturing that
  stdout verbatim would require capturing it inside the adapter, which this layer
  deliberately does not claim to do.
* **complete structured payload** — the canonical structured result built from
  that return value, whose receipt covers the whole payload;
* **bounded model-visible projection** — the deliberately smaller view the model
  receives, which carries truthful metadata about what it omits.

Capture completeness is likewise its own concept, distinct from page/window
completeness (did this request return the whole requested page?) and from
analytical source coverage (did the tool examine the whole source?).  A complete
capture of one requested page still says nothing about source coverage.

If a configured safety limit interrupts capture, that is recorded explicitly:
the digest is then labelled as covering only the captured prefix and
``capture_complete`` is false.  A truncated capture is never presented as a
complete raw-output digest.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from forensic_agent.core.controlled_scratch import (
    ControlledScratchError,
    attest_controlled_scratch_root,
)
from forensic_agent.core.repro import canonical_json
from forensic_agent.core.storage_containment import (
    EvidenceWriteScope,
    StorageContainmentError,
    acquire_evidence_write_dir,
)

#: Default ceiling on a single captured output.  Generous compared with the
#: model-visible cap (16 KiB) because the point of capture is to retain what the
#: tool actually produced; it exists only so a pathological output cannot
#: exhaust the host.  Exceeding it yields an explicitly incomplete capture, never
#: a silently truncated "raw" digest.
DEFAULT_CAPTURE_LIMIT_BYTES = 64 * 1024 * 1024

#: Chunk size for streaming a large output through the hash and onto disk, so a
#: big result is not additionally copied whole in memory.
_STREAM_CHUNK_BYTES = 1 << 20

CAPTURE_SCHEMA_ID = "forensic.output-capture.v1"


class OutputCaptureError(RuntimeError):
    """A captured output could not be stored or verified."""


@dataclass(frozen=True, slots=True)
class CapturedOutput:
    """One tool output captured before any model-facing shaping.

    ``captured_sha256`` covers exactly ``captured_bytes`` of canonical output.
    When ``capture_complete`` is true those bytes are the whole raw output and
    the digest may be published as ``raw_output_sha256``; when it is false the
    digest covers only the retained prefix and must never be described as the
    complete raw output.
    """

    captured_sha256: str
    captured_bytes: int
    capture_complete: bool
    is_text: bool
    capture_limit_bytes: int
    incomplete_reason: str | None = None
    object_sha256: str | None = None
    object_bytes: int | None = None
    #: Storage is a separate failure domain from the tool and from shaping: the
    #: output was produced and hashed, only its retention failed.
    storage_failed: bool = False
    storage_error: str | None = None

    @property
    def raw_output_sha256(self) -> str | None:
        """The complete-raw-output digest, or ``None`` when capture was cut short."""

        return self.captured_sha256 if self.capture_complete else None

    def metadata(self) -> dict[str, Any]:
        """Content-free capture metadata suitable for the private audit record."""

        record: dict[str, Any] = {
            "schema_id": CAPTURE_SCHEMA_ID,
            "capture_complete": self.capture_complete,
            "captured_sha256": self.captured_sha256,
            "captured_bytes": self.captured_bytes,
            "capture_limit_bytes": self.capture_limit_bytes,
        }
        if self.incomplete_reason is not None:
            record["incomplete_reason"] = self.incomplete_reason
        if self.object_sha256 is not None:
            record["object_sha256"] = self.object_sha256
            record["object_bytes"] = self.object_bytes
        if self.storage_failed:
            record["storage_failed"] = True
            record["storage_error"] = self.storage_error
        return record


class FullOutputStore:
    """Content-addressed store for complete tool outputs.

    Writes are atomic: content goes to a temporary file in the same directory
    and is fsynced before ``os.replace`` publishes it under its digest, so a
    crash or a safety abort can never leave a partial object visible at the
    content address.  Reads re-hash the stored bytes, so tampering with a stored
    object is detected rather than trusted.
    """

    def __init__(self, root: str) -> None:
        self.root = str(root)
        self._root_validated = False

    def _path(self, digest: str, *, is_text: bool) -> str:
        return os.path.join(self.root, f"{digest}{'.txt' if is_text else '.json'}")

    def _validate_root(self) -> None:
        """Refuse a store root that is not an absolute, link-free, contained directory.

        Complete tool outputs are evidence content, so the directory they are
        written under is held to the same standard as any other evidence write:
        an absolute local path reached through no symlink or reparse point, on
        storage not demonstrably shared with the host filesystem. Absoluteness
        and the link/reparse walk reuse the controlled-scratch attestation; the
        containment classification goes through the write-scope facade under the
        recorded weak scope, so a host-shared root is refused. The root is
        classified once per store; the run directory it lands in is contained on
        a native host and inside the container's own storage on a containerized
        run.
        """

        if self._root_validated:
            return
        try:
            attest_controlled_scratch_root(Path(self.root))
        except ControlledScratchError as error:
            raise OutputCaptureError(
                "output store root is not an absolute link-free directory"
            ) from error
        try:
            acquire_evidence_write_dir(
                self.root,
                subject="complete tool outputs captured before shaping",
                scope=EvidenceWriteScope.NOT_HOST_SHARED,
            )
        except StorageContainmentError as error:
            raise OutputCaptureError(
                "output store root is shared with the host filesystem"
            ) from error
        self._root_validated = True

    def put(self, text: str, *, is_text: bool) -> tuple[str, int]:
        """Stream ``text`` through SHA-256 into the store; return digest and bytes."""

        os.makedirs(self.root, exist_ok=True)
        self._validate_root()
        raw = text.encode("utf-8")
        digest = hashlib.sha256()
        handle, temporary = tempfile.mkstemp(dir=self.root, suffix=".partial")
        try:
            with os.fdopen(handle, "wb") as stream:
                for start in range(0, len(raw), _STREAM_CHUNK_BYTES):
                    chunk = raw[start : start + _STREAM_CHUNK_BYTES]
                    digest.update(chunk)
                    stream.write(chunk)
                stream.flush()
                os.fsync(stream.fileno())
            final = self._path(digest.hexdigest(), is_text=is_text)
            # os.replace is atomic on POSIX and Windows: the object appears at its
            # content address only once it is complete and durable.
            os.replace(temporary, final)
        except BaseException:
            # Never leave a partial object behind, and never mask the original
            # failure with a cleanup error.
            with contextlib.suppress(OSError):
                os.unlink(temporary)
            raise
        return digest.hexdigest(), len(raw)

    def read(self, digest: str, *, is_text: bool) -> str:
        """Return a stored object, verifying its content address first."""

        path = self._path(digest, is_text=is_text)
        try:
            with open(path, "rb") as stream:
                raw = stream.read()
        except OSError as error:
            raise OutputCaptureError("stored output is unavailable") from error
        if hashlib.sha256(raw).hexdigest() != digest:
            raise OutputCaptureError("stored output does not match its content address")
        return raw.decode("utf-8")

    def verify(self, digest: str, *, is_text: bool) -> bool:
        """Whether the stored object still hashes to its content address."""

        try:
            self.read(digest, is_text=is_text)
        except OutputCaptureError:
            return False
        return True


def capture_output(
    output: Any,
    *,
    store: FullOutputStore | None = None,
    limit_bytes: int = DEFAULT_CAPTURE_LIMIT_BYTES,
) -> CapturedOutput:
    """Capture and hash a tool's complete output before any shaping.

    The canonical serialization is the same one the result contract hashes, so a
    complete capture's digest is directly comparable with ``raw_output_sha256``.
    """

    if limit_bytes <= 0:
        raise ValueError("capture limit must be positive")
    # ONE hash domain for every tool.  The digest is always taken over the
    # canonical serialization the result contract uses, so a complete capture is
    # directly comparable with ``canonical_raw_output_sha256`` no matter whether
    # the tool returned text or a structure.  Hashing bare text in its own domain
    # would leave the oversight chain holding two incompatible kinds of digest.
    is_text = isinstance(output, str)
    text = canonical_json(output)
    raw = text.encode("utf-8")
    complete = len(raw) <= limit_bytes
    reason: str | None = None
    if not complete:
        # Retain a bounded prefix on a UTF-8 character boundary, and say plainly
        # that the digest covers only that prefix.
        end = limit_bytes
        while end > 0 and raw[end] & 0xC0 == 0x80:
            end -= 1
        raw = raw[:end]
        text = raw.decode("utf-8")
        reason = "capture_limit_bytes exceeded; digest covers the retained prefix only"

    object_sha256: str | None = None
    object_bytes: int | None = None
    if store is not None:
        object_sha256, object_bytes = store.put(text, is_text=is_text)

    return CapturedOutput(
        captured_sha256=hashlib.sha256(raw).hexdigest(),
        captured_bytes=len(raw),
        capture_complete=complete,
        is_text=is_text,
        capture_limit_bytes=limit_bytes,
        incomplete_reason=reason,
        object_sha256=object_sha256,
        object_bytes=object_bytes,
    )


#: The capture for the tool call currently executing.  The output guard is the
#: innermost wrapper and therefore the only place the complete output exists; the
#: oversight recorder and the result standardizer run outside it and read the
#: capture from here rather than re-deriving it from the already-bounded value.
@dataclass(frozen=True, slots=True)
class CapturedToolOutput:
    """A tool's complete output carried together with its own capture.

    The capture travels WITH the value it describes rather than through ambient
    state, so an oversight entry or a standardized result can only ever be bound
    to the capture of its own invocation — never to a leftover from a previous or
    a nested call, and never to a sibling running concurrently.
    """

    output: Any
    capture: CapturedOutput


def unwrap_captured(value: Any) -> tuple[Any, CapturedOutput | None]:
    """Split a possibly capture-carrying value into ``(output, capture)``."""

    if isinstance(value, CapturedToolOutput):
        return value.output, value.capture
    return value, None


def capture_for_invocation(
    output: Any,
    *,
    store: FullOutputStore | None = None,
    limit_bytes: int = DEFAULT_CAPTURE_LIMIT_BYTES,
) -> CapturedToolOutput:
    """Capture one invocation's complete output, tolerating a storage failure.

    A storage failure is NOT a tool failure: the tool already produced its
    result, so the digest is still computed and the result still returned.  The
    failure is recorded on the capture instead of being raised into the tool's
    own outcome, which would misreport a successful tool as having failed.
    """

    try:
        captured = capture_output(output, store=store, limit_bytes=limit_bytes)
    except Exception as error:
        captured = capture_output(output, store=None, limit_bytes=limit_bytes)
        captured = replace(
            captured,
            storage_failed=True,
            storage_error=type(error).__name__,
        )
    return CapturedToolOutput(output=output, capture=captured)


__all__ = [
    "CAPTURE_SCHEMA_ID",
    "DEFAULT_CAPTURE_LIMIT_BYTES",
    "CapturedOutput",
    "CapturedToolOutput",
    "FullOutputStore",
    "OutputCaptureError",
    "unwrap_captured",
    "capture_for_invocation",
    "capture_output",
]
