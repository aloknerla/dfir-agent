"""Deterministic, bounded filename discovery inside a forensic image."""

from __future__ import annotations

import fnmatch
import time
from collections import deque
from collections.abc import Mapping
from pathlib import PurePosixPath

from forensic_agent.core.evidence_locator import (
    EvidencePathError,
    evidence_child,
    evidence_locator_commitment,
    normalize_evidence_path,
)

MAX_PATTERN_CHARS = 512
MAX_DIR_CAP = 10_000
MAX_ENTRY_CAP = 100_000
MAX_RESULT_CAP = 500

#: Timestamps copied out of ``file_metadata`` and the fields that say how to read
#: them. They travel together or not at all: a bare number in a row cannot be told
#: apart from a UTC instant once the basis is left behind, and a FAT reading whose
#: zone was never recorded is exactly the value that would be misread.
_TIMESTAMP_VALUE_FIELDS = ("mtime", "atime", "ctime", "crtime")
_TIMESTAMP_DISCLOSURE_FIELDS = (
    "timestamp_bases",
    "timestamp_precisions",
    "timestamp_semantics",
)
_DISCLOSURE_PRESENT = "carried_with_the_values"
_DISCLOSURE_NOT_READ = "no metadata was read for this row"
_DISCLOSURE_WITHHELD = (
    "withheld: this evidence adapter reported timestamps without a timestamp "
    "basis, and a value whose basis is unknown cannot be distinguished from a "
    "UTC instant once it is copied into a row"
)


def _bounded_positive(value: int, *, name: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer")
    if value > maximum:
        raise ValueError(f"{name} exceeds the hard limit of {maximum}")
    return value


def _match(path: str, pattern: str, mode: str, *, case_sensitive: bool) -> bool:
    basename = path.rsplit("/", 1)[-1]
    candidate_pattern = pattern
    if not case_sensitive:
        path = path.casefold()
        basename = basename.casefold()
        candidate_pattern = candidate_pattern.casefold()
    if mode == "name":
        return candidate_pattern in basename
    if mode == "path":
        return candidate_pattern in path
    match_full_path = "/" in candidate_pattern.strip("/")
    if not match_full_path:
        return fnmatch.fnmatchcase(basename, candidate_pattern)
    normalized_pattern = "/" + candidate_pattern.lstrip("/")
    return PurePosixPath(path).match(normalized_pattern)


def _metadata_from_listing(path: str, entry: Mapping[str, object]) -> dict[str, object]:
    return {
        "path": path,
        "name": path.rsplit("/", 1)[-1],
        "inode": entry.get("inode"),
        "size": entry.get("size"),
        "type": "file",
        "mtime": None,
        "atime": None,
        "ctime": None,
        "crtime": None,
        "timestamp_bases": None,
        "timestamp_precisions": None,
        "timestamp_semantics": None,
        "timestamp_disclosure": _DISCLOSURE_NOT_READ,
        "metadata_complete": False,
    }


def _discloses_timestamp_basis(detailed: Mapping[str, object]) -> bool:
    """Report whether this metadata states how to read its own timestamps.

    A basis is required for every field that is copied, because a partial map
    would leave the uncovered field exactly as undisclosed as no map at all.
    """

    bases = detailed.get("timestamp_bases")
    if not isinstance(bases, Mapping):
        return False
    return all(
        isinstance(bases.get(field), str) and bases.get(field)
        for field in _TIMESTAMP_VALUE_FIELDS
    )


def find_files(
    disk,
    pattern: str,
    *,
    start: str = "/",
    match_mode: str = "glob",
    case_sensitive: bool = False,
    recursive: bool = True,
    max_dirs: int = 1_000,
    max_entries: int = 10_000,
    max_results: int = 100,
) -> dict[str, object]:
    """Find image files with explicit deterministic traversal coverage.

    ``match_mode='glob'`` applies a shell-style glob to the basename unless the
    pattern contains a slash, in which case it applies to the absolute image
    path. ``name`` and ``path`` are literal substring matches.  Traversal is
    breadth-first, and every directory listing is sorted by case-folded name and
    then exact name before it can affect the queue or result order.

    A row's timestamps are copied from ``file_metadata`` only together with the
    basis that says how to read them; where the adapter states no basis the
    values stay ``None`` and ``timestamp_disclosure`` says why.
    """

    try:
        scope = normalize_evidence_path(start)
        if not isinstance(pattern, str) or not pattern:
            raise ValueError("pattern must be non-empty text")
        if len(pattern) > MAX_PATTERN_CHARS or "\x00" in pattern:
            raise ValueError("pattern is malformed or exceeds the hard length limit")
        if match_mode not in {"glob", "name", "path"}:
            raise ValueError("match_mode must be glob, name, or path")
        if not isinstance(case_sensitive, bool) or not isinstance(recursive, bool):
            raise ValueError("case_sensitive and recursive must be booleans")
        dir_cap = _bounded_positive(max_dirs, name="max_dirs", maximum=MAX_DIR_CAP)
        entry_cap = _bounded_positive(max_entries, name="max_entries", maximum=MAX_ENTRY_CAP)
        result_cap = _bounded_positive(max_results, name="max_results", maximum=MAX_RESULT_CAP)
    except (EvidencePathError, ValueError) as exc:
        invalid_scope = evidence_locator_commitment(start)
        return {
            "error": {"code": "invalid_find_request", "message": str(exc)},
            "scan_complete": False,
            "coverage": {"complete": False, "scope": invalid_scope},
        }

    queue: deque[str] = deque([scope])
    queued = {scope}
    visited: set[str] = set()
    files: list[dict[str, object]] = []
    stop_reasons: set[str] = set()
    warnings: list[dict[str, object]] = []
    directories_scanned = 0
    entries_examined = 0
    metadata_failures = 0
    undisclosed_timestamps = 0
    unsafe_entries = 0
    bounded_listing_calls = 0
    unbounded_adapter_calls = 0
    started = time.monotonic()

    while queue:
        if directories_scanned >= dir_cap:
            stop_reasons.add("max_dirs_reached")
            break
        if entries_examined >= entry_cap:
            stop_reasons.add("max_entries_reached")
            break
        directory = queue.popleft()
        if directory in visited:
            continue
        visited.add(directory)
        directories_scanned += 1
        try:
            bounded_lister = getattr(disk, "list_directory_bounded", None)
            if callable(bounded_lister):
                listing = bounded_lister(
                    directory,
                    max_entries=max(1, entry_cap - entries_examined),
                )
                bounded_listing_calls += 1
            else:
                # Development adapters may expose only the legacy materializing
                # API. Results remain useful for positive discovery, but absence
                # cannot be treated as complete bounded coverage.
                listing = disk.list_directory(directory)
                unbounded_adapter_calls += 1
                stop_reasons.add("adapter_lacks_bounded_directory_enumeration")
        except FileNotFoundError:
            # A path that is absent and a path that cannot be read are different
            # findings. Reporting both as unreadable makes a mistyped or
            # wrong-generation path look like an evidence limitation, and an empty
            # result then reads as "cannot be determined" rather than "look
            # elsewhere".
            stop_reasons.add("directory_not_found")
            warnings.append(
                {
                    "code": "directory_not_found",
                    "message": (
                        "No directory with this path exists in the image. The empty "
                        "result describes the path that was requested, not the "
                        "evidence; list a parent directory to see what is present."
                    ),
                    "path": directory,
                }
            )
            continue
        except Exception:
            stop_reasons.add("directory_unreadable")
            warnings.append(
                {
                    "code": "directory_unreadable",
                    "message": (
                        "A directory in the requested image scope exists but could "
                        "not be enumerated."
                    ),
                    "path": directory,
                }
            )
            continue
        if not isinstance(listing, Mapping):
            stop_reasons.add("malformed_directory_listing")
            continue
        if (
            listing.get("incomplete") is True
            or listing.get("scan_complete") is False
            or listing.get("enumeration_complete") is False
        ):
            stop_reasons.add("partial_directory_listing")
        raw_entries = listing.get("entries")
        if not isinstance(raw_entries, list):
            stop_reasons.add("malformed_directory_listing")
            continue

        sortable: list[tuple[str, str, Mapping[str, object]]] = []
        for raw_entry in raw_entries:
            if not isinstance(raw_entry, Mapping):
                unsafe_entries += 1
                stop_reasons.add("malformed_directory_entry")
                continue
            try:
                child_path = evidence_child(directory, raw_entry.get("name"))
            except EvidencePathError:
                unsafe_entries += 1
                stop_reasons.add("unsafe_directory_entry")
                continue
            exact_name = child_path.rsplit("/", 1)[-1]
            sortable.append((exact_name.casefold(), exact_name, raw_entry))
        sortable.sort(key=lambda item: (item[0], item[1]))

        for _folded_name, _exact_name, entry in sortable:
            if entries_examined >= entry_cap:
                stop_reasons.add("max_entries_reached")
                break
            entries_examined += 1
            child_path = evidence_child(directory, entry.get("name"))
            is_directory = str(entry.get("type")) == "3"
            if is_directory:
                if recursive and child_path not in queued:
                    queue.append(child_path)
                    queued.add(child_path)
                continue
            if not _match(
                child_path,
                pattern,
                match_mode,
                case_sensitive=case_sensitive,
            ):
                continue

            metadata = _metadata_from_listing(child_path, entry)
            try:
                detailed = disk.file_metadata(child_path)
                if isinstance(detailed, Mapping):
                    for key in ("inode", "size"):
                        metadata[key] = detailed.get(key, metadata.get(key))
                    if _discloses_timestamp_basis(detailed):
                        for key in _TIMESTAMP_VALUE_FIELDS:
                            metadata[key] = detailed.get(key)
                        for key in _TIMESTAMP_DISCLOSURE_FIELDS:
                            metadata[key] = detailed.get(key)
                        metadata["timestamp_disclosure"] = _DISCLOSURE_PRESENT
                        metadata["metadata_complete"] = True
                    else:
                        # Carry the disclosure with the value, or do not carry the
                        # value: an undisclosed timestamp reaching the model is
                        # the failure this branch exists to prevent.
                        metadata["timestamp_disclosure"] = _DISCLOSURE_WITHHELD
                        undisclosed_timestamps += 1
                        if undisclosed_timestamps == 1:
                            warnings.append(
                                {
                                    "code": "timestamp_basis_not_disclosed",
                                    "message": _DISCLOSURE_WITHHELD,
                                    "path": child_path,
                                }
                            )
                else:
                    metadata_failures += 1
                    stop_reasons.add("metadata_incomplete")
            except Exception:
                metadata_failures += 1
                stop_reasons.add("metadata_incomplete")
            files.append(metadata)
            if len(files) >= result_cap:
                stop_reasons.add("max_results_reached")
                break
        if stop_reasons & {"max_entries_reached", "max_results_reached"}:
            break

    # If queued paths remain after a cap, the requested scope was not exhausted.
    if queue and not stop_reasons:
        stop_reasons.add("traversal_stopped_with_pending_directories")
    files.sort(key=lambda row: (str(row["path"]).casefold(), str(row["path"])))
    complete = not stop_reasons and not queue
    reason = "; ".join(sorted(stop_reasons)) if stop_reasons else None
    result: dict[str, object] = {
        "pattern": pattern,
        "start": scope,
        "match_mode": match_mode,
        "case_sensitive": case_sensitive,
        "recursive": recursive,
        "rows": files,
        "returned": len(files),
        "truncated": not complete,
        "scan_complete": complete,
        "coverage": {"complete": complete, "scope": scope, "reason": reason},
        "scan": {
            "directories_scanned": directories_scanned,
            "entries_examined": entries_examined,
            "metadata_failures": metadata_failures,
            "rows_with_timestamps_withheld": undisclosed_timestamps,
            "unsafe_entries": unsafe_entries,
            "pending_directories": len(queue),
            "bounded_listing_calls": bounded_listing_calls,
            "unbounded_adapter_calls": unbounded_adapter_calls,
            "enumeration_bound_mode": (
                "adapter-enforced"
                if unbounded_adapter_calls == 0
                else "legacy-post-materialization-incomplete"
            ),
        },
        "caps": {
            "max_dirs": dir_cap,
            "max_entries": entry_cap,
            "max_results": result_cap,
        },
        "stop_reasons": sorted(stop_reasons),
        "warnings": warnings[:20],
        "warnings_total": len(warnings),
        "warnings_truncated": len(warnings) > 20,
    }
    audit = getattr(disk, "audit", None)
    if audit is not None and callable(getattr(audit, "record", None)):
        audit.record(
            tool="filesystem.find_files",
            args={
                "pattern": pattern,
                "start": scope,
                "match_mode": match_mode,
                "case_sensitive": case_sensitive,
                "recursive": recursive,
                "max_dirs": dir_cap,
                "max_entries": entry_cap,
                "max_results": result_cap,
            },
            output=result,
            input_sha=getattr(disk, "image_sha", None),
            duration_s=time.monotonic() - started,
        )
    return result
