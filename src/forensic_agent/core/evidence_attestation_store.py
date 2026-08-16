"""Verify a medium once, remember the proof, re-check identity every open.

The full decoded-media hash used to run on EVERY case open, minutes per
launch on a multi-gigabyte image. The established tools verify at ingest
and record the result: EnCase, FTK and Autopsy all hash when evidence is
added and re-verify only on demand. This store gives the console the same
behaviour without weakening what an open asserts:

- the FIRST open of a source still streams every byte and records the
  canonical attestation here, keyed by the source's absolute path;
- every LATER open reuses the stored digests only after the same
  stat-identity check the streaming pass itself performs — device, inode,
  size and timestamps of every physical segment must still match, so a
  replaced or touched file forces a fresh full pass;
- ``verify_image_integrity`` keeps streaming the whole medium on demand,
  which is the operator's re-verification instrument, exactly like the
  "verify evidence" action of the established tools.

Set ``DFA_VERIFY_EVERY_OPEN=1`` to restore the old behaviour outright.

The trade this makes is the one the established tools make: content
tampering that preserves file metadata goes unnoticed until an explicit
re-verification. The stored attestation never REPLACES custody facts —
it IS the custody fact from the first verified pass, and reuse is stated
to the operator rather than silent.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

from forensic_agent.core.evidence_source import (
    EvidenceSegmentDescriptor,
    EvidenceSourceAttestation,
    assert_evidence_source_current,
)

_SCHEMA = "forensic.evidence-open-attestation.v1"
_DIRECTORY = "integrity-attestations"
VERIFY_EVERY_OPEN_ENVIRONMENT_VARIABLE = "DFA_VERIFY_EVERY_OPEN"


def verification_reuse_enabled() -> bool:
    """Reuse is the default; the environment can force the old full pass."""

    return os.environ.get(VERIFY_EVERY_OPEN_ENVIRONMENT_VARIABLE, "").strip() != "1"


def _store_root() -> Path | None:
    from forensic_agent.tools.entity_index import index_root_for

    root = index_root_for(None)
    if root is None:
        return None
    return Path(root) / _DIRECTORY


def _record_path(primary_path: str) -> Path | None:
    root = _store_root()
    if root is None:
        return None
    key = hashlib.sha256(
        os.path.normcase(os.path.normpath(primary_path)).encode("utf-8", "replace")
    ).hexdigest()
    return root / f"{key}.json"


def store_open_attestation(
    attestation: EvidenceSourceAttestation,
    *,
    md5: str | None = None,
    sha1: str | None = None,
) -> None:
    """Persist a freshly streamed attestation; never raises."""

    try:
        path = _record_path(attestation.primary_path)
        if path is None:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema": _SCHEMA,
            "verified_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "source_type": attestation.source_type,
            "digest_semantics": attestation.digest_semantics,
            "sha256": attestation.sha256,
            "size_bytes": attestation.size_bytes,
            "primary_path": attestation.primary_path,
            "segments": [
                {
                    "path": segment.path,
                    "size_bytes": segment.size_bytes,
                    "device": segment.device,
                    "inode": segment.inode,
                    "mtime_ns": segment.mtime_ns,
                    "ctime_ns": segment.ctime_ns,
                }
                for segment in attestation.segments
            ],
            "md5": md5,
            "sha1": sha1,
        }
        staging = path.with_suffix(f".staging-{os.getpid()}")
        staging.write_text(
            json.dumps(payload, indent=1, sort_keys=True), encoding="utf-8"
        )
        os.replace(staging, path)
    except Exception:
        return


def load_reusable_attestation(
    primary_path: str,
) -> tuple[EvidenceSourceAttestation, str] | None:
    """The stored attestation for this path, IF its identity still holds.

    Returns ``(attestation, verified_at)`` only when every physical
    segment still matches the recorded device, inode, size and
    timestamps — the same identity comparison the streaming pass anchors
    to. Anything else (no record, unreadable record, changed file)
    returns ``None`` and the caller streams the medium in full.
    """

    try:
        path = _record_path(primary_path)
        if path is None or not path.is_file():
            return None
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("schema") != _SCHEMA:
            return None
        attestation = EvidenceSourceAttestation(
            source_type=payload["source_type"],
            digest_semantics=payload["digest_semantics"],
            sha256=payload["sha256"],
            size_bytes=payload["size_bytes"],
            primary_path=payload["primary_path"],
            segments=tuple(
                EvidenceSegmentDescriptor(
                    path=segment["path"],
                    size_bytes=segment["size_bytes"],
                    device=segment["device"],
                    inode=segment["inode"],
                    mtime_ns=segment["mtime_ns"],
                    ctime_ns=segment["ctime_ns"],
                )
                for segment in payload["segments"]
            ),
        )
        if os.path.normcase(os.path.normpath(attestation.primary_path)) != (
            os.path.normcase(os.path.normpath(primary_path))
        ):
            return None
        # The identity gate: the exact check the fresh pass performs.
        assert_evidence_source_current(attestation)
        return attestation, str(payload.get("verified_at") or "")
    except Exception:
        return None


__all__ = [
    "VERIFY_EVERY_OPEN_ENVIRONMENT_VARIABLE",
    "load_reusable_attestation",
    "store_open_attestation",
    "verification_reuse_enabled",
]
