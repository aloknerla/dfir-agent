"""Reproducibility: run manifests, transcript hashing, and record / replay.

A locked decoding profile (see :mod:`forensic_agent.core.config`) is necessary but
not sufficient for reproducible forensic analysis: non-deterministic *tool* outputs
(OS file ordering, timestamps, network) enter the model context and break
reproducibility before decoding even happens. The remedy is twofold:

1. **Record the full trace** of a run — the prompt, every tool call with its
   arguments, return value and order, plus the model, engine and environment — so
   the run can be replayed and independently audited.
2. **Hash the transcript** to give the run a stable identity for the chain of
   custody, and to detect divergence when a case is re-run.

These primitives make reproducibility measurable: run a case N times and report
the rate and the first point of divergence.
"""
from __future__ import annotations

import hashlib
import json
import platform
from dataclasses import dataclass, field
from importlib import metadata as _md
from typing import Any

from forensic_agent.core.telemetry_egress import telemetry_egress_record

__all__ = [
    "canonical_json",
    "canonical_model_messages",
    "canonical_sha256",
    "sha256_hex",
    "model_messages_sha256",
    "environment_info",
    "RunManifest",
    "Recorder",
    "load_trace",
    "replay_index",
]


def canonical_json(obj: Any) -> str:
    """Deterministic JSON serialization (sorted keys, compact, UTF-8 safe)."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def canonical_sha256(obj: Any) -> str:
    """SHA-256 hex digest over the canonical JSON encoding of a JSON value.

    The single content-digest primitive: every seal that commits to a JSON
    structure, and every verifier that re-derives one, hashes it through here, so
    two sides of one equality check can never canonicalize the same value two
    different ways.
    """
    return sha256_hex(canonical_json(obj))


def _json_value(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return json.loads(canonical_json(value))


def _model_message_record(message: Any) -> dict[str, Any]:
    """Project one model-visible message to exact role/content/tool-call fields."""
    if isinstance(message, str):
        return {"role": "prompt", "content": message, "tool_calls": []}
    if isinstance(message, dict):
        role = message.get("role") or message.get("type") or "unknown"
        content = message.get("content", "")
        tool_calls = message.get("tool_calls") or []
        tool_call_id = message.get("tool_call_id")
        name = message.get("name")
    else:
        role = getattr(message, "type", None) or getattr(message, "role", None) or "unknown"
        content = getattr(message, "content", "")
        tool_calls = getattr(message, "tool_calls", None) or []
        additional = getattr(message, "additional_kwargs", None)
        if not tool_calls and isinstance(additional, dict):
            tool_calls = additional.get("tool_calls") or []
        tool_call_id = getattr(message, "tool_call_id", None)
        name = getattr(message, "name", None)
    record = {
        "role": str(role),
        "content": _json_value(content),
        "tool_calls": _json_value(tool_calls),
    }
    if tool_call_id not in (None, ""):
        record["tool_call_id"] = str(tool_call_id)
    if name not in (None, ""):
        record["name"] = str(name)
    return record


def canonical_model_messages(messages: Any) -> list[Any]:
    """Canonicalize model-visible messages without retaining unrelated metadata.

    LangChain callbacks provide a batch of message lists, whereas direct OpenAI
    clients use one flat list. Nested list structure is preserved in the digest.
    """
    if not isinstance(messages, (list, tuple)):
        raise TypeError("model messages must be a list or tuple")
    return [
        canonical_model_messages(item)
        if isinstance(item, (list, tuple))
        else _model_message_record(item)
        for item in messages
    ]


def model_messages_sha256(messages: Any) -> str:
    """Hash exact canonical role/content/tool-call messages without storing prompts."""
    return sha256_hex(canonical_json(canonical_model_messages(messages)))


def _pkg_version(name: str) -> str | None:
    try:
        return _md.version(name)
    except Exception:
        return None


def environment_info(hardware: str | None = None) -> dict[str, Any]:
    """Capture the parts of the environment that affect reproducibility."""
    return {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "hardware": hardware,
        "libraries": {
            name: _pkg_version(name)
            for name in (
                "openai",
                "langchain",
                "langgraph",
                "langchain-openai",
                "langchain-core",
                # The package that performs run upload: the one library able to
                # send evidence off the machine.
                "langsmith",
            )
        },
        # A receipt that cannot say whether egress was possible does not support
        # the claim that the run was offline. This states the posture of the
        # process that wrote the manifest: which ambient upload channels were
        # found set and removed, and whether any is live now. It is deliberately
        # outside `fingerprint()`, which covers reproducibility-relevant
        # configuration only — a run that had to neutralise a stray variable
        # reproduces the same answers as one that had nothing to neutralise.
        "telemetry_egress": telemetry_egress_record(),
    }


@dataclass
class RunManifest:
    """Everything needed to reproduce and audit a single agent run.

    ``started_at`` is supplied by the caller (a timestamp string) so the manifest
    has no hidden clock dependency; the run's identity is the transcript hash, not
    the wall-clock time.
    """

    case_id: str
    model: str
    engine: str
    backend: str
    profile: dict[str, Any]
    started_at: str | None = None
    model_digest: str | None = None
    system_fingerprint: str | None = None
    environment: dict[str, Any] = field(default_factory=environment_info)
    transcript_sha256: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "model": self.model,
            "model_digest": self.model_digest,
            "engine": self.engine,
            "backend": self.backend,
            "system_fingerprint": self.system_fingerprint,
            "started_at": self.started_at,
            "profile": self.profile,
            "environment": self.environment,
            "transcript_sha256": self.transcript_sha256,
        }

    def fingerprint(self) -> str:
        """Stable hash of the reproducibility-relevant configuration (not timing)."""
        relevant = {
            "model": self.model,
            "model_digest": self.model_digest,
            "engine": self.engine,
            "backend": self.backend,
            "profile": self.profile,
        }
        return sha256_hex(canonical_json(relevant))


@dataclass
class Recorder:
    """Collects the ordered trace of a run and hashes it.

    Each event captures a tool call (or model step): its kind, name, arguments,
    result and position. The transcript hash is computed over the canonicalized,
    ordered events so the same run yields the same hash.
    """

    events: list[dict[str, Any]] = field(default_factory=list)

    def record(self, kind: str, name: str, args: Any = None, result: Any = None) -> None:
        self.events.append(
            {
                "i": len(self.events),
                "kind": kind,
                "name": name,
                "args": args,
                "result": result,
            }
        )

    def transcript_hash(self) -> str:
        return sha256_hex(canonical_json(self.events))

    def save(self, path: str, manifest: RunManifest | None = None) -> str:
        """Write the trace as JSONL: an optional manifest header, then one event per line.

        Returns the transcript hash (also stamped into the manifest if given).
        """
        thash = self.transcript_hash()
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            if manifest is not None:
                manifest.transcript_sha256 = thash
                f.write(canonical_json({"manifest": manifest.to_dict()}) + "\n")
            for ev in self.events:
                f.write(canonical_json(ev) + "\n")
        return thash


def load_trace(path: str) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    """Load a recorded trace: returns ``(manifest_or_None, events)``."""
    manifest: dict[str, Any] | None = None
    events: list[dict[str, Any]] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if "manifest" in obj and "kind" not in obj:
                manifest = obj["manifest"]
            else:
                events.append(obj)
    return manifest, events


def replay_index(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Index recorded tool results by a stable key (kind+name+canonical args).

    Enables deterministic replay: a tool call with the same signature returns its
    recorded result instead of touching the (possibly non-deterministic) evidence,
    so a recorded investigation can be re-derived exactly.
    """
    index: dict[str, Any] = {}
    for ev in events:
        key = sha256_hex(canonical_json([ev.get("kind"), ev.get("name"), ev.get("args")]))
        index[key] = ev.get("result")
    return index
