"""Strict POSIX path handling for files inside a forensic image.

These paths are evidence locators, not host filesystem paths.  Keeping their
validation in one small module prevents a model-supplied ``..`` component or a
malformed directory entry from ever being handed to dfVFS as a lookup path.
"""

from __future__ import annotations

import hashlib

MAX_EVIDENCE_PATH_CHARS = 4096
MAX_EVIDENCE_NAME_CHARS = 1024


class EvidencePathError(ValueError):
    """An in-image path or directory-entry name is not safe to resolve."""


def evidence_locator_commitment(value: object) -> str:
    """Commit an invalid locator without reflecting a possible host path."""

    text = value if isinstance(value, str) else repr(value)
    digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
    return f"invalid-evidence-locator:sha256:{digest}"


def normalize_evidence_path(path: str, *, allow_root: bool = True) -> str:
    """Return one canonical absolute POSIX path, rejecting traversal.

    Backslashes are rejected rather than reinterpreted.  On Linux they can be
    literal filename bytes, while on NTFS they are separators; accepting them
    here would therefore make the locator's meaning filesystem-dependent.
    """

    if not isinstance(path, str) or not path:
        raise EvidencePathError("evidence path must be non-empty text")
    if len(path) > MAX_EVIDENCE_PATH_CHARS:
        raise EvidencePathError("evidence path exceeds the hard length limit")
    if "\x00" in path:
        raise EvidencePathError("evidence path contains a NUL character")
    if "\\" in path:
        raise EvidencePathError("evidence path must use POSIX separators")
    if not path.startswith("/"):
        raise EvidencePathError("evidence path must be absolute")

    parts = path.split("/")
    if any(part in {".", ".."} for part in parts):
        raise EvidencePathError("evidence path contains traversal components")
    normalized_parts = [part for part in parts if part]
    normalized = "/" + "/".join(normalized_parts)
    if normalized == "/" and not allow_root:
        raise EvidencePathError("evidence path must identify a file")
    return normalized


def validate_evidence_name(name: object) -> str:
    """Validate one direct-child name returned by an image filesystem."""

    if not isinstance(name, str) or not name or name in {".", ".."}:
        raise EvidencePathError("directory entry has no usable name")
    if len(name) > MAX_EVIDENCE_NAME_CHARS:
        raise EvidencePathError("directory entry name exceeds the hard length limit")
    if any(character in name for character in ("/", "\\", "\x00")):
        raise EvidencePathError("directory entry name contains a separator or NUL")
    return name


def evidence_parent(path: str) -> tuple[str, str]:
    """Return ``(parent, basename)`` for a validated non-root evidence path."""

    normalized = normalize_evidence_path(path, allow_root=False)
    parent, _, name = normalized.rpartition("/")
    return parent or "/", name


def evidence_child(parent: str, name: object) -> str:
    """Join a validated direct-child name without host path semantics."""

    normalized_parent = normalize_evidence_path(parent)
    child_name = validate_evidence_name(name)
    return (
        (normalized_parent.rstrip("/") + "/" + child_name)
        if normalized_parent != "/"
        else "/" + child_name
    )
