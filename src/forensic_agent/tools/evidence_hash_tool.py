"""Byte-accurate hashing of one file inside a forensic image."""

from __future__ import annotations

import hashlib
import time
from collections.abc import Iterable, Mapping

from forensic_agent.core.evidence_locator import (
    EvidencePathError,
    evidence_locator_commitment,
    normalize_evidence_path,
)

HASH_CHUNK_BYTES = 1 << 20
MAX_HASH_BYTES = 512 << 20


class _HashByteLimitExceeded(RuntimeError):
    pass


def _iter_chunks(disk, path: str) -> Iterable[bytes]:
    iterator = getattr(disk, "iter_file_chunks", None)
    if not callable(iterator):
        raise RuntimeError("disk adapter does not provide byte-accurate file streaming")
    for chunk in iterator(path, chunk_size=HASH_CHUNK_BYTES):
        if not isinstance(chunk, bytes):
            raise RuntimeError("disk adapter returned a non-byte file chunk")
        if not chunk:
            continue
        if len(chunk) > HASH_CHUNK_BYTES:
            raise RuntimeError("disk adapter exceeded the fixed hash chunk bound")
        yield chunk


def evidence_file_hash(disk, path: str) -> dict[str, object]:
    """Return the SHA-256 and exact streamed size of one in-image regular file."""

    try:
        normalized = normalize_evidence_path(path, allow_root=False)
    except EvidencePathError as exc:
        invalid_locator = evidence_locator_commitment(path)
        return {
            "path": invalid_locator,
            "error": {"code": "invalid_evidence_path", "message": str(exc)},
            "scan_complete": False,
            "coverage": {"complete": False, "scope": invalid_locator},
        }

    try:
        metadata = disk.file_metadata(normalized)
    except Exception:
        return {
            "path": normalized,
            "error": {
                "code": "evidence_file_unreadable",
                "message": "The requested in-image file could not be opened.",
            },
            "scan_complete": False,
            "coverage": {"complete": False, "scope": normalized},
        }
    metadata_size = metadata.get("size") if isinstance(metadata, Mapping) else None
    if isinstance(metadata_size, bool) or not isinstance(metadata_size, int) or metadata_size < 0:
        metadata_size = None
    if metadata_size is not None and metadata_size > MAX_HASH_BYTES:
        return {
            "path": normalized,
            "algorithm": "sha256",
            "metadata_size_bytes": metadata_size,
            "limits": {"max_file_bytes": MAX_HASH_BYTES},
            "error": {
                "code": "evidence_file_hash_size_limit",
                "message": "The in-image file exceeds the fixed full-hash byte limit.",
            },
            "scan_complete": False,
            "coverage": {
                "complete": False,
                "scope": normalized,
                "reason": "file exceeds the deterministic full-hash byte limit",
            },
        }

    started = time.monotonic()
    digest = hashlib.sha256()
    bytes_read = 0
    try:
        for chunk in _iter_chunks(disk, normalized):
            if bytes_read + len(chunk) > MAX_HASH_BYTES:
                raise _HashByteLimitExceeded
            digest.update(chunk)
            bytes_read += len(chunk)
    except _HashByteLimitExceeded:
        return {
            "path": normalized,
            "algorithm": "sha256",
            "bytes_read": bytes_read,
            "metadata_size_bytes": metadata_size,
            "limits": {"max_file_bytes": MAX_HASH_BYTES},
            "error": {
                "code": "evidence_file_hash_size_limit",
                "message": "The streamed in-image file exceeded the fixed full-hash byte limit.",
            },
            "scan_complete": False,
            "coverage": {
                "complete": False,
                "scope": normalized,
                "reason": "file exceeded the deterministic full-hash byte limit before EOF",
            },
        }
    except Exception:
        return {
            "path": normalized,
            "algorithm": "sha256",
            "bytes_read": bytes_read,
            "metadata_size_bytes": metadata_size,
            "limits": {"max_file_bytes": MAX_HASH_BYTES},
            "error": {
                "code": "evidence_file_stream_failed",
                "message": "Byte-accurate streaming stopped before the file was exhausted.",
            },
            "scan_complete": False,
            "coverage": {
                "complete": False,
                "scope": normalized,
                "reason": "in-image file streaming failed before EOF",
            },
        }

    size_matches = metadata_size is None or metadata_size == bytes_read
    result: dict[str, object] = {
        "path": normalized,
        "algorithm": "sha256",
        "sha256": digest.hexdigest(),
        "size_bytes": bytes_read,
        "bytes_read": bytes_read,
        "metadata_size_bytes": metadata_size,
        "size_matches_metadata": size_matches,
        "limits": {"max_file_bytes": MAX_HASH_BYTES},
        "scan_complete": size_matches,
        "coverage": {
            "complete": size_matches,
            "scope": normalized,
            "reason": None if size_matches else "streamed size differs from filesystem metadata",
        },
    }
    audit = getattr(disk, "audit", None)
    if audit is not None and callable(getattr(audit, "record", None)):
        audit.record(
            tool="filesystem.evidence_file_hash",
            args={"path": normalized, "algorithm": "sha256"},
            output=result,
            input_sha=getattr(disk, "image_sha", None),
            duration_s=time.monotonic() - started,
        )
    return result
