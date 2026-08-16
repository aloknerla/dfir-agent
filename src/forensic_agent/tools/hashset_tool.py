"""NSRL-style known-file filtering.

Computes a file's SHA-256 and classifies it against configurable hash sets:
known-good (e.g. the NSRL Reference Data Set of standard OS/application files that
can safely be ignored during triage) and known-bad (malware hashes to flag). This
mirrors the hash-lookup ingest module of established tools and cuts investigative
noise by separating routine files from those that need review.

Hash-set files are plain text with one hex digest per line (an NSRL RDS export or a
simple hash list). Their paths come from the environment variables
DFA_NSRL_GOOD and DFA_NSRL_BAD (os.pathsep-separated for several
files). Read-only.
"""
from __future__ import annotations

import os
import re

from forensic_agent.core.audit import sha256_file

_HEX = re.compile(r"\b([0-9a-fA-F]{32,64})\b")   # MD5 / SHA-1 / SHA-256 digests
_CACHE: dict[str, frozenset] = {}                 # file path -> set of lowercase hashes


def _load_set(spec: str) -> set:
    """Load and cache hashes from one or more files (os.pathsep-separated)."""
    out: set = set()
    for p in (spec or "").split(os.pathsep):
        p = p.strip()
        if not p or not os.path.exists(p):
            continue
        if p in _CACHE:
            out |= _CACHE[p]
            continue
        found: set = set()
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                for line in f:
                    m = _HEX.search(line)
                    if m:
                        found.add(m.group(1).lower())
        except Exception:
            continue
        _CACHE[p] = frozenset(found)
        out |= found
    return out


def hash_lookup(path: str) -> dict:
    """Hash a file and classify it against known-good and known-bad hash sets
    (NSRL-style) to cut triage noise: routine OS/application files are filtered
    and known malware flagged. Use to triage a file by reputation; for just a
    digest use hash_file. Read-only.

    Example: hash_lookup("C:/evidence/suspicious.dll")

    Input: `path` is a local filesystem path to an existing file. Hash-set file
    paths come from the DFA_NSRL_GOOD / DFA_NSRL_BAD environment variables
    (os.pathsep-separated; one hex digest per line). Read-only over the evidence.

    Returns: {"path", "sha256", "status" (known_good | known_bad | unknown),
    "known_good_set", "known_bad_set" (set sizes)}. On a missing path / non-file
    / read error returns {"error"}.
    """
    if not path or not os.path.exists(path):
        return {"error": f"file not found: {path}"}
    if not os.path.isfile(path):
        return {"error": f"not a file: {path}"}
    try:
        digest = sha256_file(path).lower()
    except Exception as e:
        return {"error": f"hash failed: {str(e)[:150]}"}
    good = _load_set(os.environ.get("DFA_NSRL_GOOD", ""))
    bad = _load_set(os.environ.get("DFA_NSRL_BAD", ""))
    if digest in bad:
        status = "known_bad"
    elif digest in good:
        status = "known_good"
    else:
        status = "unknown"
    return {"path": os.path.basename(path), "sha256": digest, "status": status,
            "known_good_set": len(good), "known_bad_set": len(bad)}
