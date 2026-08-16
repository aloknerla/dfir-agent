"""Uniform tool-output contract (applies to every row-returning tool).

Solves the "buried evidence" problem from both directions: large outputs are
never silently truncated, and a single huge row never overflows the model
context. Every result carries total/returned/offset/truncated plus a note,
supports `offset`/`limit` pagination and a substring `filter`, and is bounded in
BYTES: a per-row cap shrinks any oversized entry (e.g. a registry `services`
dump of >1 MB) and a total cap stops the page before it overruns the context
window. So any tool can be drilled down on, and no tool can firehose.

A result that carries only PART of the matching set says so in one dedicated
field (:data:`CARDINALITY_TRUNCATED_KEY`), separately from every other reason an
output was shortened. Rows are never discarded to signal a bound: in a forensic
examination a matching row is evidence, so "this is a prefix" is made a state a
reader can test rather than enforced by refusing to return rows.

Grounded in MCP pagination/filtering and the truncation-with-metadata pattern
(Lemon Agent).
"""

from __future__ import annotations

import json
import re
from typing import Any

#: Default byte budgets. A single registry/memory plugin can emit >1 MB; the model
#: context (e.g. 131072 tokens) must not be overrun by one tool result.
MAX_ROW_BYTES = 2000
MAX_TOTAL_BYTES = 16000

#: Declared when matching rows exist that this result does not carry, so a reader
#: can tell a bounded search from an exhausted one without parsing counters.
#: Kept separate from ``truncated``, which is also true when only a value inside a
#: returned row was shortened: a shortened value leaves the matching set complete,
#: a withheld row does not, and only the latter can invalidate a conclusion that
#: something is absent.
CARDINALITY_TRUNCATED_KEY = "cardinality_truncated"

#: How many matching rows this result does not carry.  Written only beside the
#: flag above, and never as zero: the number quantifies a shortfall that has
#: already been declared, it never announces one on its own.
ROWS_WITHHELD_KEY = "rows_withheld"

#: The consequence of holding only a prefix, stated in the result that is one:
#: the counters give the shortfall, this warns against taking the part for the
#: whole and reporting what is missing from the prefix as missing from evidence.
_PREFIX_CANNOT_SHOW_ABSENCE = (
    "These are only the first matching rows, so this result cannot show that "
    "anything is absent: narrow the query with 'filter' until every match fits, "
    "or run a search that reads the whole image, before reporting anything as "
    "not present."
)

_FIELD_TRUNCATION_MARKER = "…[truncated; filter/paginate to drill in]"
_VALUE_TRUNCATION_MARKER = "…[truncated]"
#: Bytes held back for the note while rows are being fitted. Sized to hold the
#: sentence above: a smaller reserve would let the fitting spend the budget on
#: rows and then cut the warning off the end.
_TRUNCATION_NOTE_RESERVE = "x" * (192 + len(_PREFIX_CANNOT_SHOW_ABSENCE))
_SHAPE_RESERVED_KEYS = frozenset(
    {
        "total_matching",
        "returned",
        "offset",
        "next_offset",
        "next_cursor",
        "truncated",
        "page_truncated",
        CARDINALITY_TRUNCATED_KEY,
        ROWS_WITHHELD_KEY,
        "note",
        "rows",
        "_bounded",
    }
)

#: Keys under which a producer puts repeatable records, mirroring the contract's
#: own list in :data:`forensic_agent.core.tool_result._ITEM_KEYS`.  ``bound`` has
#: to recognise the same set the standardizer does: a record list it does not
#: recognise is flattened into a truncated string with no counters at all, and a
#: result that lost its counters is indistinguishable from one that matched
#: nothing.  A test pins the two lists together so they cannot drift.
_RECORD_LIST_KEYS = (
    "items",
    "rows",
    "entries",
    "hits",
    "events",
    "files",
    "artifacts",
    "members",
    "results",
)


def _json_text(value: Any) -> str:
    """Serialize the exact compact UTF-8 representation used for byte accounting."""

    return json.dumps(
        value,
        ensure_ascii=False,
        default=str,
        separators=(",", ":"),
    )


def _row_bytes(r) -> int:
    """Return serialized UTF-8 bytes, not Python code-point count."""

    return len(_json_text(r).encode("utf-8"))


def row_bytes(row: Any) -> int:
    """Weigh one row in the units :data:`MAX_ROW_BYTES` is spent in.

    Published beside the cap because a tool that builds a row large enough to be
    shortened here cannot otherwise tell that it did: the shortening keeps the
    row's own counters and rewrites only its text, so the row arrives describing
    content it no longer carries.  A producer that needs its row to survive
    intact sizes it against this measure.
    """

    return _row_bytes(row)


def _positive_cap(value: int, *, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


_MIN_BOUNDED_BYTES = _row_bytes({"_bounded": True})


def _fit_text_field(
    target: dict[str, Any],
    *,
    key: str,
    text: str,
    cap: int,
    marker: str = _FIELD_TRUNCATION_MARKER,
) -> tuple[bool, bool]:
    """Add one text field without allowing ``target`` to exceed ``cap``.

    Returns ``(added, truncated)``.  Truncation is character-boundary safe while
    the fit decision is made on the final UTF-8 JSON representation.
    """

    candidate = dict(target)
    candidate[key] = text
    if _row_bytes(candidate) <= cap:
        target[key] = text
        return True, False

    for suffix in (marker, _VALUE_TRUNCATION_MARKER, "…", ""):
        low = 0
        high = len(text)
        best: str | None = None
        while low <= high:
            middle = (low + high) // 2
            shortened = text[:middle] + suffix
            candidate = dict(target)
            candidate[key] = shortened
            if _row_bytes(candidate) <= cap:
                best = shortened
                low = middle + 1
            else:
                high = middle - 1
        if best is not None:
            target[key] = best
            return True, True
    return False, True


def _shrink_row_with_status(r: Any, cap: int) -> tuple[Any, bool]:
    """Return one JSON-friendly row that is *actually* within ``cap`` bytes."""

    cap = _positive_cap(cap, name="row byte cap")
    if _row_bytes(r) <= cap:
        return r, False

    if not isinstance(r, dict):
        # Preserve a useful preview without ever slicing serialized JSON syntax.
        source = _json_text(r)
        holder: dict[str, Any] = {}
        added, _ = _fit_text_field(
            holder,
            key="value",
            text=source,
            cap=cap,
            marker=_VALUE_TRUNCATION_MARKER,
        )
        if added:
            value = holder["value"]
            if _row_bytes(value) <= cap:
                return value, True
        # ``0`` is valid JSON and fits every positive byte cap.
        return 0, True

    # Stringify keys so the result is safe for JSON transports.  Keep compact
    # scalar identifiers first, then spend the remaining budget on text fields.
    items: list[tuple[str, Any]] = []
    seen_keys: set[str] = set()
    for key, value in r.items():
        normalized_key = str(key)
        if normalized_key in seen_keys:
            continue
        seen_keys.add(normalized_key)
        items.append((normalized_key, value))

    scalar_items = [
        item for item in items if item[1] is None or isinstance(item[1], (bool, int, float))
    ]
    text_items = [item for item in items if item not in scalar_items]
    out: dict[str, Any] = {}

    for key, value in scalar_items:
        candidate = dict(out)
        candidate[key] = value
        if _row_bytes(candidate) <= cap:
            out[key] = value

    for key, value in text_items:
        text = value if isinstance(value, str) else _json_text(value)
        _fit_text_field(out, key=key, text=text, cap=cap)

    if _row_bytes(out) > cap:  # Defensive invariant; construction above is monotone.
        return 0, True
    # The input exceeded ``cap`` on entry, so at least one source byte was
    # necessarily omitted or rewritten even if every compact scalar survived.
    return out, True


def _shrink_row(r, cap: int):
    """Cap an oversized row so one giant entry cannot overflow the context. Large
    fields are truncated with a marker; small scalar fields are kept so the row stays
    identifiable and filterable."""
    return _shrink_row_with_status(r, cap)[0]


def _shape_envelope(
    *,
    prefix: dict[str, Any],
    rows: list[Any],
    total_matching: int,
    offset: int,
    truncated: bool,
    page_truncated: bool,
    note: str,
    bounded: bool,
    rows_withheld: int,
) -> dict[str, Any]:
    result = dict(prefix)
    result.update(
        {
            "total_matching": total_matching,
            "returned": len(rows),
            "offset": offset,
            "truncated": truncated,
            "page_truncated": page_truncated,
            "note": note,
            "rows": rows,
        }
    )
    end = offset + len(rows)
    if truncated and end < total_matching:
        result["next_offset"] = end
    if rows_withheld > 0:
        result[CARDINALITY_TRUNCATED_KEY] = True
        result[ROWS_WITHHELD_KEY] = rows_withheld
    if bounded:
        result["_bounded"] = True
    return result


def _fit_row_in_envelope(
    row: Any,
    *,
    row_cap: int,
    existing_rows: list[Any],
    prefix: dict[str, Any],
    total_matching: int,
    offset: int,
    max_total_bytes: int,
    bounded: bool,
) -> tuple[Any | None, bool]:
    """Find the largest row preview that fits the complete result envelope."""

    low = 1
    high = row_cap
    best: Any | None = None
    while low <= high:
        middle = (low + high) // 2
        preview, _ = _shrink_row_with_status(row, middle)
        candidate = _shape_envelope(
            prefix=prefix,
            rows=[*existing_rows, preview],
            total_matching=total_matching,
            offset=offset,
            truncated=True,
            page_truncated=True,
            note=_TRUNCATION_NOTE_RESERVE,
            bounded=bounded,
            # The measured candidate must never be smaller than the envelope that
            # finally ships, and the shortfall a shipped envelope can declare is
            # at most the whole matching set, so reserve for that.
            rows_withheld=total_matching,
        )
        if _row_bytes(candidate) <= max_total_bytes:
            best = preview
            low = middle + 1
        else:
            high = middle - 1
    return best, best is not None


def _record_list_key(result: dict[str, Any]) -> str | None:
    """Name the field holding this mapping's repeatable records, or ``None``.

    First match wins, as the standardizer's own scan does, so both read the same
    field of a mapping that happens to carry two of these names.
    """

    for key in _RECORD_LIST_KEYS:
        value = result.get(key)
        if isinstance(value, list) and value:
            return key
    return None


def _records_lost(records: list[Any], kept: Any) -> int:
    """Count records the caller's shortened view no longer carries.

    ``kept`` may be a shorter list, the serialized text of the whole list (which
    loses no record), a truncated preview of that text, or nothing at all.  Only
    the second of those is a complete delivery, so anything else that is not a
    list is counted as the whole set: over-declaring a shortfall costs a caller
    one narrower query, and under-declaring one costs it a false negative.
    """

    if isinstance(kept, list):
        return max(0, len(records) - len(kept))
    if isinstance(kept, str) and kept == _json_text(records):
        return 0
    return len(records)


def bound(result, *, max_bytes: int = MAX_TOTAL_BYTES, max_row_bytes: int = MAX_ROW_BYTES):
    """Central output guard applied to EVERY tool result (one place, all tools), so no
    tool can overflow the context window regardless of whether it called ``shape``.
    Small results pass through unchanged; an oversized row-envelope is re-shaped; any
    other oversized dict/list has its large fields capped. (Restorable content-addressed
    storage of the full output is layered on top of this separately.)"""
    max_bytes = _positive_cap(max_bytes, name="total byte cap")
    max_row_bytes = _positive_cap(max_row_bytes, name="row byte cap")
    if min(max_bytes, max_row_bytes) < _MIN_BOUNDED_BYTES:
        raise ValueError("tool-output byte caps must accommodate the partial marker")
    if not isinstance(result, (dict, list)):
        return result
    if _row_bytes(result) <= max_bytes:
        return result
    if isinstance(result, list):
        return shape(
            result,
            limit=len(result) or 1,
            max_total_bytes=max_bytes,
            max_row_bytes=max_row_bytes,
            _force_bounded=True,
        )
    if isinstance(result.get("rows"), list):  # already a row-envelope
        source_rows = result["rows"]
        raw_offset = result.get("offset", 0)
        source_offset = (
            raw_offset
            if isinstance(raw_offset, int) and not isinstance(raw_offset, bool) and raw_offset >= 0
            else 0
        )
        minimum_total = source_offset + len(source_rows)
        raw_total = result.get("total_matching", result.get("total"))
        explicit_page_truncated = result.get("page_truncated")
        source_truncated = (
            explicit_page_truncated
            if isinstance(explicit_page_truncated, bool)
            else bool(result.get("truncated", False))
        )
        source_truncated = bool(
            source_truncated
            or result.get("next_offset") is not None
            or result.get("next_cursor") is not None
        )
        source_total = (
            raw_total
            if isinstance(raw_total, int)
            and not isinstance(raw_total, bool)
            and raw_total >= minimum_total
            else minimum_total + int(source_truncated)
        )
        return shape(
            source_rows,
            limit=len(source_rows) or 1,
            max_total_bytes=max_bytes,
            max_row_bytes=max_row_bytes,
            _prefix={key: value for key, value in result.items() if key != "rows"},
            _force_bounded=True,
            _reported_offset=source_offset,
            _reported_total=source_total,
            _reported_truncated=source_truncated,
        )

    # One plain mapping is also one row: respect both the row and total cap,
    # reserving a transport-level marker so downstream code cannot mistake the
    # preview for complete evidence.
    limit = min(max_bytes, max_row_bytes)
    carried = {
        str(key): value for key, value in result.items() if str(key) not in {"_bounded", "note"}
    }

    def _prepared(*, record_key: str | None, withheld: int) -> dict[str, Any]:
        prepared: dict[str, Any] = {"_bounded": True}
        if record_key is not None and withheld > 0:
            prepared[CARDINALITY_TRUNCATED_KEY] = True
            prepared[ROWS_WITHHELD_KEY] = withheld
            # Placed IN FRONT of the payload, not after it: text fields are fitted
            # in the order they appear, so a note behind a large record preview
            # gets whatever bytes that preview leaves — which on exactly these
            # results is none, and the model would receive the prefix without the
            # sentence explaining what the prefix cannot be used for.
            prepared["note"] = (
                f"output truncated to fit context: the {withheld} record(s) under "
                f"'{record_key}' were shortened into a preview. "
                f"{_PREFIX_CANNOT_SHOW_ABSENCE}"
            )
        prepared.update(carried)
        prepared.setdefault(
            "note", "output truncated to fit context; narrow the query or paginate"
        )
        return prepared

    out, _ = _shrink_row_with_status(_prepared(record_key=None, withheld=0), limit)
    record_key = _record_list_key(result)
    if record_key is not None:
        withheld = _records_lost(
            result[record_key], out.get(record_key) if isinstance(out, dict) else None
        )
        if withheld > 0:
            out, _ = _shrink_row_with_status(
                _prepared(record_key=record_key, withheld=withheld), limit
            )
    if not isinstance(out, dict) or out.get("_bounded") is not True:
        out = {"_bounded": True}
    if _row_bytes(out) > limit:  # pragma: no cover - guarded by helper invariants
        raise AssertionError("bounded tool output exceeded its hard byte cap")
    return out


#: Query-expression syntax that a substring test can never satisfy.  A lone
#: apostrophe is not enough: a real filename such as ``John's Documents`` must
#: still be treated as an ordinary literal that simply did not match.
_EXPRESSION_FILTER_RE = re.compile(
    r"(?:[!=<>]=|=~|&&|\|\||\s+(?:and|or|not|like|in)\s+"
    r"|'[^']*'|\"[^\"]*\")",
    re.IGNORECASE,
)
_MAX_ADVERTISED_FIELDS = 12
#: Above this many further pages, exhaustive paging is not a realistic plan for a
#: caller working under a call budget, so the note says so instead of only
#: advertising the next offset.
_COSTLY_PAGE_CHAIN_CALLS = 10


def _remaining_page_calls(remaining_rows: int, page_rows: int) -> int | None:
    """Estimate the calls still needed at the page size actually achieved."""

    if page_rows < 1 or remaining_rows < 1:
        return None
    return -(-remaining_rows // page_rows)


def _row_field_names(rows: list) -> list[str]:
    """Collect the field names a caller can realistically filter on."""

    names: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        for key in row:
            name = str(key)
            if name not in names and not name.startswith("__"):
                names.append(name)
        if len(names) >= _MAX_ADVERTISED_FIELDS:
            break
    return names[:_MAX_ADVERTISED_FIELDS]


def _empty_filter_directive(filter_text: str, rows: list) -> str:
    """Explain an empty filtered page so the next call can succeed.

    A filter that carries comparison operators or quotes is a query expression,
    and this filter is a plain substring test, so such a filter can only ever
    match zero rows.  Saying so once is far cheaper than letting the caller
    rephrase the same expression until its call budget is gone.
    """

    fields = _row_field_names(rows)
    field_hint = f" Fields present in this result: {', '.join(fields)}." if fields else ""
    if _EXPRESSION_FILTER_RE.search(filter_text) is not None:
        return (
            "no rows matched: 'filter' is a plain substring test, not a query "
            f"expression, so {filter_text!r} was compared literally against each row "
            "and cannot match. Pass a single literal value instead, such as a PID, "
            "process name, IP address or status word (for example filter=\"ESTABLISHED\"), "
            f"or omit 'filter' and read the full result.{field_hint}"
        )
    return (
        f"no rows matched the substring {filter_text!r}; try a shorter or different "
        f"literal value, or call without a filter.{field_hint}"
    )


def shape(
    rows: list,
    offset: int = 0,
    limit: int = 50,
    filter: str | None = None,
    *,
    max_row_bytes: int = MAX_ROW_BYTES,
    max_total_bytes: int = MAX_TOTAL_BYTES,
    _prefix: dict[str, Any] | None = None,
    _force_bounded: bool = False,
    _reported_offset: int | None = None,
    _reported_total: int | None = None,
    _reported_truncated: bool = False,
) -> dict:
    """Filter + paginate `rows` AND bound the result in bytes, returning an envelope
    with truncation metadata."""
    max_row_bytes = _positive_cap(max_row_bytes, name="row byte cap")
    max_total_bytes = _positive_cap(max_total_bytes, name="total byte cap")
    if max_total_bytes < _MIN_BOUNDED_BYTES:
        raise ValueError("total byte cap must accommodate the partial marker")
    rows = rows or []
    if filter:
        f = str(filter).lower()
        matched = [r for r in rows if f in json.dumps(r, ensure_ascii=False, default=str).lower()]
    else:
        matched = rows
    offset = max(0, int(offset or 0))
    limit = max(1, int(limit or 50))
    page = matched[offset : offset + limit]
    reported_offset = offset if _reported_offset is None else max(0, int(_reported_offset))
    minimum_reported_total = reported_offset + len(matched)
    reported_total = (
        len(matched)
        if _reported_total is None
        else max(minimum_reported_total, int(_reported_total))
    )

    raw_prefix = {
        str(key): value
        for key, value in (_prefix or {}).items()
        if str(key) not in _SHAPE_RESERVED_KEYS
    }
    prefix_cap = max(1, max_total_bytes // 3)
    prefix_value, prefix_truncated = _shrink_row_with_status(raw_prefix, prefix_cap)
    prefix = prefix_value if isinstance(prefix_value, dict) else {}

    out_rows: list[Any] = []
    byte_capped = False
    content_truncated = prefix_truncated
    for r in page:
        row, row_was_truncated = _shrink_row_with_status(r, max_row_bytes)
        candidate_bounded = _force_bounded or content_truncated or row_was_truncated
        candidate = _shape_envelope(
            prefix=prefix,
            rows=[*out_rows, row],
            total_matching=reported_total,
            offset=reported_offset,
            truncated=True,
            page_truncated=True,
            note=_TRUNCATION_NOTE_RESERVE,
            bounded=candidate_bounded,
            rows_withheld=reported_total,
        )
        if _row_bytes(candidate) <= max_total_bytes:
            out_rows.append(row)
            content_truncated = content_truncated or row_was_truncated
            continue

        preview, fitted = _fit_row_in_envelope(
            r,
            row_cap=min(max_row_bytes, max_total_bytes),
            existing_rows=out_rows,
            prefix=prefix,
            total_matching=reported_total,
            offset=reported_offset,
            max_total_bytes=max_total_bytes,
            bounded=True,
        )
        if fitted:
            out_rows.append(preview)
            content_truncated = True
        byte_capped = True
        break

    local_end = offset + len(out_rows)
    end = reported_offset + len(out_rows)
    row_truncated = (
        local_end < len(matched)
        or end < reported_total
        or bool(_reported_truncated)
    )
    truncated = row_truncated or byte_capped or content_truncated
    # Rows this envelope does not carry, which is a different fact from
    # ``truncated``: a page whose values were shortened withholds no row at all.
    # Counted from the reported end so a caller that paged to the last page is not
    # told it is still holding a prefix, which would make the flag mean nothing.
    rows_withheld = max(0, reported_total - end) if truncated else 0
    note = ""
    if truncated:
        more = reported_total - end
        if more > 0:
            note = (
                f"{more} more matching rows (output capped at {max_total_bytes} UTF-8 B). "
                f"Call again with offset={end}"
                + ("." if filter else " or add a 'filter' to narrow.")
            ).strip()
            remaining_calls = _remaining_page_calls(more, len(out_rows))
            if remaining_calls is not None and remaining_calls > _COSTLY_PAGE_CHAIN_CALLS:
                note = (
                    f"{note} At this page size that is about {remaining_calls} further "
                    "calls, which will not fit a normal call budget, so do not page "
                    "through them one by one. Narrow with 'filter', or use a summary "
                    "field in this result if one already covers the full output."
                )
            note = f"{note} {_PREFIX_CANNOT_SHOW_ABSENCE}"
        else:
            note = (
                "one or more returned values were truncated to fit the UTF-8 byte cap; "
                "narrow the query or request a smaller artifact range"
            )
    elif filter and not matched:
        note = _empty_filter_directive(str(filter), rows)
    elif not out_rows and matched and offset >= len(matched):
        note = (
            f"offset {offset} is past the last row: this result has {len(matched)} "
            f"matching row(s), so the valid offsets are 0 to {len(matched) - 1}. "
            "Call again with offset=0 and page forward from there."
        )

    bounded = _force_bounded or byte_capped or content_truncated
    envelope_without_note = _shape_envelope(
        prefix=prefix,
        rows=out_rows,
        total_matching=reported_total,
        offset=reported_offset,
        truncated=truncated,
        page_truncated=row_truncated or byte_capped,
        note="",
        bounded=bounded,
        rows_withheld=rows_withheld,
    )
    envelope_without_note.pop("note")
    added, _ = _fit_text_field(
        envelope_without_note,
        key="note",
        text=note,
        cap=max_total_bytes,
        marker=_VALUE_TRUNCATION_MARKER,
    )
    if not added:
        envelope_without_note["note"] = ""
    if _row_bytes(envelope_without_note) > max_total_bytes:
        # Only unrealistically tiny caller caps can reach this branch.  Keep a
        # valid, explicit partial marker rather than returning oversized JSON.
        minimal: dict[str, Any] = {"_bounded": True}
        return minimal
    return envelope_without_note
