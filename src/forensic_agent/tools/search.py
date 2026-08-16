"""Bounded keyword search across a disk image (filename + file contents).

Works over any disk object exposing list_directory/read_file (real TSK image or
the demo disk). Bounded by design so the agent never scans a whole volume.

Reach on REAL images: a naive BFS from "/" burns its file budget inside the OS tree
(e.g. C:\\WINDOWS has thousands of files) before it ever reaches the user profiles
where most user artefacts live, so it misses them. This traversal therefore (1) DEFERS
well-known system-noise directories to the end, (2) PRIORITISES user/application data
directories, and (3) uses a larger-but-still-bounded budget and per-file scan window,
so user artefacts in deep profile/app-config paths are actually reached.
"""

from __future__ import annotations

from collections import deque

# These two tables are this project's own judgement about where evidence lives, and
# under a traversal bound they decide which evidence a result can contain. They are
# therefore private to ``search_disk`` and have no other consumer.
# Directories explored FIRST (user / application data — where user artefacts live).
_PRIORITY_DIRS = {
    "documents and settings",
    "users",
    "programdata",
    "program files",
    "program files (x86)",
    "home",
    "root",
}
# Directories DEFERRED to the end (OS noise — rarely holds user artefacts, burns budget).
# NOTE: recycle bin ($Recycle.Bin / RECYCLER) is EVIDENCE and is intentionally NOT here.
_NOISE_DIRS = {
    "windows",
    "winnt",
    "winsxs",
    "system volume information",
    "perflogs",
    "msocache",
    "recovery",
    "$orphanfiles",
    "$extend",
}


def _search_hit(path: str, **observation: object) -> dict[str, object]:
    """Build one search observation from the discovered path and its fields."""

    return {"path": path, **observation}


def _search_result(
    *,
    keyword: str,
    scope: str,
    files_scanned: int,
    hits: list[dict[str, object]],
    scan_complete: bool,
    stop_reasons: list[str] | None = None,
) -> dict[str, object]:
    """Separate source coverage from pagination for a non-resumable search.

    ``search_keyword`` has no cursor or offset argument.  Its historical
    ``truncated`` flag therefore means bounded *source coverage*, not that a next
    result page exists.  ``pagination_supported=False`` lets the standardized
    model-facing adapter preserve that distinction and avoid inventing a
    misleading ``next_offset``.
    """

    reasons = list(stop_reasons or [])
    if scan_complete and reasons:
        raise ValueError("a complete keyword scan cannot have stop reasons")
    if not scan_complete and not reasons:
        raise ValueError("an incomplete keyword scan must disclose a stop reason")
    coverage: dict[str, object] = {"complete": scan_complete, "scope": scope}
    if not scan_complete:
        coverage["reason"] = "; ".join(reasons)
    return {
        "keyword": keyword,
        "files_scanned": files_scanned,
        "hits": hits,
        # Retained for direct legacy callers.  The explicit non-resumable marker
        # prevents this source-coverage flag from becoming page.next_offset.
        "truncated": not scan_complete,
        "pagination_supported": False,
        "scan_complete": scan_complete,
        "coverage_complete": scan_complete,
        "coverage": coverage,
        "stop_reasons": reasons,
    }


def search_disk(
    disk,
    keyword: str,
    max_files: int = 1200,
    max_dirs: int = 800,
    max_bytes: int = 32768,
    max_hits: int = 30,
    start: str = "/",
) -> dict:
    """Bounded keyword search across the disk image — both file names and file
    contents — returning the matching paths. Use to locate evidence by term when
    the path is unknown; if you already know the path, read it with read_file.
    Bounded by design so it never scans a whole volume; system directories are
    searched last so user artefacts are reached first.

    Example: search_disk(disk, "password")            # whole image, user data first
             search_disk(disk, "smtp", start="/Documents and Settings")  # scope a subtree

    Input: `disk` is the open image handle; `keyword` is a case-insensitive
    substring. `start` scopes the search to a subtree (default whole image).
    Optional caps: max_files, max_dirs, max_bytes (content read per file), max_hits.
    Read-only over the evidence.

    Returns: {"keyword", "files_scanned", "hits"} (plus "truncated": True when a
    cap stopped the scan). Each hit is {"path", "match": "filename"} for a name
    match or {"path", "snippet"} for a content match. Returns
    {"error": "empty keyword"} when no keyword is given. ``start`` must identify a
    directory. If it identifies a file, the result recommends ``search_in_file``.
    """
    kw = (keyword or "").strip().lower()
    if not kw:
        return {"error": "empty keyword"}
    scope = start or "/"

    # A directory listing of a file can legitimately look exactly like an empty
    # directory on some filesystem adapters. Check the parent entry's advertised
    # type first so a file-scoped search does not silently produce zero hits.
    if scope != "/":
        stripped = scope.rstrip("/")
        parent, _, basename = stripped.rpartition("/")
        parent = parent or "/"
        try:
            parent_entries = disk.list_directory(parent).get("entries") or []
        except Exception:
            parent_entries = []
        matching_entry = next(
            (
                entry
                for entry in parent_entries
                if str(entry.get("name") or "").casefold() == basename.casefold()
            ),
            None,
        )
        if matching_entry is not None and str(matching_entry.get("type")) != "3":
            return {
                "error": "start path is a file; search_keyword requires a directory",
                "start": scope,
                "keyword": keyword,
                "recommended_tool": "search_in_file",
                "recommendation": ("Use search_in_file with this path and keyword as its term."),
            }
    hits: list[dict[str, object]] = []
    scanned_files = 0
    main: deque[str] = deque([scope])
    deferred: deque[str] = deque()
    seen: set[str] = set()
    visited_dirs = 0

    def _bucket(name: str) -> int:
        n = name.lower()
        if n in _PRIORITY_DIRS:
            return 0
        if n in _NOISE_DIRS:
            return 2
        return 1

    while (main or deferred) and visited_dirs < max_dirs and scanned_files < max_files:
        d = main.popleft() if main else deferred.popleft()
        if d in seen:
            continue
        seen.add(d)
        visited_dirs += 1
        try:
            listing = disk.list_directory(d)
        except Exception:
            continue
        for e in listing.get("entries") or []:
            name = e.get("name")
            if not name or name in (".", ".."):
                continue
            path = (d.rstrip("/") + "/" + name) if d != "/" else "/" + name
            t = e.get("type")
            is_dir = t == "3"
            if t is None:  # demo disk: probe whether it lists as a directory
                try:
                    sub = disk.list_directory(path)
                    is_dir = bool(sub.get("entries"))
                except Exception:
                    is_dir = False
            if is_dir:
                b = _bucket(name)
                if b == 2:
                    deferred.append(path)  # OS noise -> search last
                elif b == 0:
                    main.appendleft(path)  # user/app data -> search first
                else:
                    main.append(path)
                continue
            scanned_files += 1
            if kw in name.lower():
                hits.append(_search_hit(path, match="filename"))
            else:
                try:
                    r = disk.read_file(path, max_bytes)
                    txt = str(r.get("content_text") or "")
                    low = txt.lower()
                    if kw in low:
                        i = low.find(kw)
                        hits.append(
                            _search_hit(
                                path,
                                snippet=txt[max(0, i - 40) : i + len(kw) + 40],
                            )
                        )
                except Exception:
                    pass
            if len(hits) >= max_hits or scanned_files >= max_files:
                stop_reasons = []
                if len(hits) >= max_hits:
                    stop_reasons.append("max_hits_reached")
                if scanned_files >= max_files:
                    stop_reasons.append("max_files_reached")
                return _search_result(
                    keyword=keyword,
                    scope=scope,
                    files_scanned=scanned_files,
                    hits=hits,
                    scan_complete=False,
                    stop_reasons=stop_reasons,
                )

    truncated = bool(main or deferred) and (visited_dirs >= max_dirs or scanned_files >= max_files)
    stop_reasons = []
    if truncated and visited_dirs >= max_dirs:
        stop_reasons.append("max_dirs_reached")
    if truncated and scanned_files >= max_files:
        stop_reasons.append("max_files_reached")
    return _search_result(
        keyword=keyword,
        scope=scope,
        files_scanned=scanned_files,
        hits=hits,
        scan_complete=not truncated,
        stop_reasons=stop_reasons,
    )


def search_in_file(
    disk,
    path: str,
    term: str,
    max_hits: int = 50,
    max_scan_bytes: int = 8_000_000,
    snippet_len: int = 240,
    offset: int = 0,
) -> dict:
    """Search WITHIN a single file for a case-insensitive term, returning the matching
    LINES with their byte offsets — so you can then read_file(path, offset=<byte_offset>)
    to read around a hit. Use this for LARGE files (logs, configs, sync histories) where
    read_file shows only one window. Read-only; scans at most the first max_scan_bytes.

    ``offset`` and ``max_hits`` page through the matches found in the bounded
    source scan. Returns a paginated envelope {"path", "term", "file_size", "scanned_bytes",
    "scan_complete", total_matching, returned, offset, truncated, note,
    rows:[{"byte_offset", "snippet"}]}, or {"error": ...}. ``truncated`` is true
    when either matching rows were paginated or the source file was only partly read.
    """
    t = (term or "").strip()
    if not t:
        return {"error": "empty term"}
    try:
        r = disk.read_file(path, max_bytes=max_scan_bytes, offset=0)
    except Exception as e:
        return {"error": f"cannot read {path}: {str(e)[:120]}"}
    text = str(r.get("content_text") or "")
    source_truncated = r.get("eof") is False
    if not text:
        if source_truncated:
            note = (
                f"Search read no text from a partial scan of {r.get('size')} bytes; "
                "unscanned content may contain matches."
            )
        else:
            note = "file empty or unreadable"
        return {
            "path": path,
            "term": term,
            "file_size": r.get("size"),
            "scanned_bytes": r.get("returned_bytes"),
            "scan_complete": not source_truncated,
            "total_matching": 0,
            "returned": 0,
            "offset": 0,
            "truncated": source_truncated,
            "note": note,
            "rows": [],
        }
    tl = t.lower()
    rows, byte_off = [], 0
    for line in text.splitlines(keepends=True):
        if tl in line.lower():
            rows.append({"byte_offset": byte_off, "snippet": line.strip()[:snippet_len]})
        byte_off += len(line.encode("utf-8", "replace"))
    from forensic_agent.core.toolio import shape

    env = shape(rows, offset=offset, limit=max_hits)
    if source_truncated:
        scanned = r.get("returned_bytes")
        source_note = (
            f"Search covered only {scanned} of {r.get('size')} bytes; "
            "unscanned content may contain additional matches."
        )
        if r.get("fixture_truncated"):
            source_note += " The remaining bytes are unavailable in this synthetic fixture."
        env["truncated"] = True
        env["note"] = " ".join(part for part in (env.get("note"), source_note) if part)
    return {
        "path": path,
        "term": term,
        "file_size": r.get("size"),
        "scanned_bytes": r.get("returned_bytes"),
        "scan_complete": not source_truncated,
        **env,
    }
