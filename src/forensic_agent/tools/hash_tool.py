"""Agent-callable file hashing — a chain-of-custody primitive.

Lets the agent compute the SHA-256 (and size) of a recovered/host file on demand,
e.g. to fingerprint an extracted artifact for the report. Read-only.
"""
from __future__ import annotations

import os

from forensic_agent.core.audit import sha256_file
from forensic_agent.core.tool_failure import tool_failure_result


def hash_file(path: str) -> dict:
    """Compute the SHA-256 digest and size of a file on disk — a chain-of-custody
    primitive (read-only). Use to fingerprint a recovered/host file for the
    report; to also classify it as known-good/known-bad use hash_lookup.

    Example: hash_file("C:/tmp/recovered.bin")

    Input: `path` is a local filesystem path to an existing file. Read-only over
    the evidence.

    Returns: {"path", "sha256", "size_bytes"}. On a missing path / non-file /
    read error returns {"error"}.
    """
    if not path or not os.path.exists(path):
        return {"error": f"file not found: {path}"}
    if not os.path.isfile(path):
        return {"error": f"not a file: {path}"}
    try:
        return {"path": os.path.basename(path),
                "sha256": sha256_file(path),
                "size_bytes": os.path.getsize(path)}
    except Exception as e:
        return tool_failure_result(e, subject=str(path), backend="hashlib")
