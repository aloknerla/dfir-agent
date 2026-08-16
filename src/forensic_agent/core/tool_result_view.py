"""Compatibility views over a standardized tool result, for legacy consumers.

The wire contract deliberately uses one stable ``data.attributes/items`` shape.
Several deterministic research components predate it and consume semantic legacy
keys such as ``entries`` or ``rows``.  This module provides a read-only projection;
it never changes the receipt-verified envelope and must not be used when calculating receipts.

Both the historical envelope and the active contract are projected here.  The
fields these views read — ``data``, ``page``, ``coverage``, ``status``, ``error``
and ``warnings`` — are the same value objects in both, so the projection itself is
shared; only recognising which envelope arrived is dispatched, in
:mod:`forensic_agent.core.result_reading`.  A value that claims a tool-result
envelope this branch cannot read is refused outright rather than passed through as
though it were an ordinary legacy dict: passing it through is precisely how an
unrecognised result gets consumed as if it had been understood.
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from forensic_agent.core.result_contract import (
    is_admissible_case_evidence as active_result_is_admissible_case_evidence,
)
from forensic_agent.core.result_reading import (
    READABLE_SCHEMA_IDS,
    UnreadableResult,
    claims_result_envelope,
    declared_schema_version,
    read_result,
)
from forensic_agent.core.tool_result import SCHEMA_ID as LEGACY_SCHEMA_ID


def parse_json_value(value: Any) -> Any:
    """Parse a JSON string when possible and otherwise return the original value."""
    if not isinstance(value, str):
        return value
    stripped = value.strip()
    if not stripped:
        return value
    try:
        return json.loads(stripped)
    except (json.JSONDecodeError, TypeError):
        return value


def _unreadable_envelope_version(parsed: Any) -> str | None:
    """Return the declared version when it is an envelope this branch cannot read."""

    version = declared_schema_version(parsed)
    if claims_result_envelope(parsed) and version not in READABLE_SCHEMA_IDS:
        return version
    return None


def _refuse_unreadable_envelope(parsed: Any) -> None:
    """Refuse a value that claims an envelope version this branch cannot read."""

    version = _unreadable_envelope_version(parsed)
    if version is not None:
        raise UnreadableResult(
            f"value claims tool-result envelope {version!r}, which this reader cannot read"
        )


def legacy_tool_result_view(value: Any) -> Any:
    """Project a standardized envelope to legacy semantic keys for deterministic consumers."""
    parsed = parse_json_value(value)
    _refuse_unreadable_envelope(parsed)
    if not isinstance(parsed, Mapping) or declared_schema_version(parsed) not in (
        READABLE_SCHEMA_IDS
    ):
        return parsed

    data = parsed.get("data")
    if not isinstance(data, Mapping):
        return dict(parsed)
    attributes = data.get("attributes")
    view = dict(attributes) if isinstance(attributes, Mapping) else {}
    items = data.get("items")
    if not isinstance(items, list):
        items = []
    data_type = str(data.get("type") or "")

    if data_type == "filesystem.directory_listing":
        view["entries"] = items
    elif data_type == "reference.artifact_locations":
        view["artifacts"] = items
    elif data_type == "archive.records":
        view["members"] = items
    elif items:
        # Row-oriented legacy consumers use this for registry, EVTX,
        # memory, PCAP, search, recovery, and carved-file records.
        view["rows"] = items
        if "search" in data_type:
            view["hits"] = items

    page = parsed.get("page")
    if isinstance(page, Mapping):
        view.update({
            "offset": page.get("offset"),
            "returned": page.get("returned"),
            "total": page.get("total"),
            "next_offset": page.get("next_offset"),
            "truncated": page.get("truncated"),
        })
        if page.get("unit") == "item":
            view["total_matching"] = page.get("total")

    coverage = parsed.get("coverage")
    if isinstance(coverage, Mapping):
        view["coverage"] = dict(coverage)
        view["coverage_complete"] = coverage.get("complete")
    view["status"] = parsed.get("status")
    if parsed.get("status") == "error":
        error = parsed.get("error")
        if isinstance(error, Mapping):
            view["error"] = error.get("message") or dict(error)
        else:
            view["error"] = error or "tool execution failed"
    if parsed.get("warnings"):
        view["warnings"] = parsed.get("warnings")
    return view


def tool_result_is_error(value: Any) -> bool:
    """Return true only for a genuine failed result, including the envelope status rule."""
    parsed = parse_json_value(value)
    _refuse_unreadable_envelope(parsed)
    if isinstance(parsed, Mapping) and declared_schema_version(parsed) in READABLE_SCHEMA_IDS:
        return parsed.get("status") == "error"
    return isinstance(parsed, Mapping) and bool(parsed.get("error"))


def tool_result_is_admissible_case_evidence(value: Any) -> bool | None:
    """Return the receipt-verified evidentiary role, or ``None`` for a pre-envelope value.

    A malformed or receipt-invalid object that claims a readable schema fails closed as
    non-admissible. Values that were never an envelope return ``None`` so migration
    consumers can apply their existing policy explicitly.

    A value that claims a tool-result envelope this branch cannot read also fails
    closed, as ``False``.  It must NOT return ``None`` there: ``None`` means "no
    contract applies, decide for yourself", and a caller applying its own legacy
    policy to an unreadable result is how one would get admitted unchecked.
    """
    parsed = parse_json_value(value)
    if _unreadable_envelope_version(parsed) is not None:
        return False
    version = declared_schema_version(parsed)
    if not isinstance(parsed, Mapping) or version not in READABLE_SCHEMA_IDS:
        return None
    if version != LEGACY_SCHEMA_ID:
        # The active contract carries invariants the historical one has no way to
        # express — a mandatory epistemic class, and a derivation lineage for a
        # computed claim — so its own structural gate decides, rather than a
        # re-implementation here that would drift from it.
        return active_result_is_admissible_case_evidence(parsed)
    try:
        result = read_result(parsed)
    except UnreadableResult:
        return False
    # The historical verdict is stated once, where the final check states it, so
    # this structural gate and the final check can never come to disagree about
    # what the envelope production still emits is allowed to mean.
    from forensic_agent.core.result_admission import historical_result_backs_a_case_claim

    return historical_result_backs_a_case_claim(result)


__all__ = [
    "legacy_tool_result_view",
    "parse_json_value",
    "tool_result_is_admissible_case_evidence",
    "tool_result_is_error",
]
