"""Bounded recovery for truncated memory-analysis results."""

from __future__ import annotations

import json
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from typing import cast

from langchain_core.messages import AIMessage, ToolMessage

from forensic_agent.agent.evidence_classification import MEMORY_OPERATIONS
from forensic_agent.agent.execution_budget import _DispatchDenied
from forensic_agent.agent.recovery.common import (
    _realized_continuation_arguments,
    _validated_continuation_result,
)
from forensic_agent.agent.tool_contract import _TOOL_DATA_TYPES
from forensic_agent.core.repro import canonical_json, sha256_hex
from forensic_agent.core.result_contract import PageUnit, ToolStatus
from forensic_agent.core.result_navigation import page_continuation
from forensic_agent.core.result_reading import AnyToolResult

_MEMORY_PAGINATION_METRICS_SCHEMA_ID = "forensic.memory-pagination-metrics.v1"
_MEMORY_PAGINATION_SAFETY_CAP = 12
_MEMORY_QUERY_ARGUMENTS = frozenset({"plugin", "limit", "offset", "filter", "operation"})
#: ``filter`` is the only optional member: the consolidated JSON-Schema facade
#: does not expand a default the model omitted, and the summary operations do not
#: declare ``filter`` at all, so a real summary call carries only these four keys.
#: Keying on the full five-key set made every summary page fail validation, which
#: left the complete-full-output escape hatch permanently unreachable.
_MEMORY_QUERY_REQUIRED_ARGUMENTS = frozenset({"plugin", "limit", "offset", "operation"})
#: Continuation completes a truncated page of the OBSERVED plugin read.  A derived
#: computation over that output is a different claim, so a page of one is never
#: continued as if it were the plugin's own rows.
_CONTINUABLE_MEMORY_OPERATION = "plugin_rows"
#: Every other registered operation is a computation over one plugin's COMPLETE
#: output, so it is the kind of result an unfinishable page of raw rows can be
#: judged against.  Taken from the authoritative classifier, so a new operation
#: cannot be forgotten here.
_FULL_OUTPUT_SUMMARY_OPERATIONS = MEMORY_OPERATIONS - {_CONTINUABLE_MEMORY_OPERATION}
_MEMORY_PAGINATION_BLOCKING_DECISIONS = frozenset(
    {
        "nonresumable_truncation",
        "lineage_total_conflict",
        "page_semantic_conflict",
        "memory_query_not_visible",
        "continuation_cycle",
        "safety_cap_reached",
        "chain_exceeds_safety_cap",
        "dispatch_budget_exhausted",
    }
)


@dataclass(frozen=True, slots=True)
class _MemoryPage:
    """Receipt-valid page and the exact arguments that produced it."""

    result: AnyToolResult
    arguments: dict[str, object]


@dataclass(frozen=True, slots=True)
class _MemoryFrontier:
    """One exact next page bound to an immutable evidence lineage."""

    arguments: dict[str, object]
    case_id: str | None
    source_id: str
    source_sha256: str | None
    total: int | None
    page_size: int = 0


def _empty_memory_pagination_metrics(*, enabled: bool) -> dict[str, object]:
    """Return the stable telemetry shape for memory page continuation."""

    return {
        "schema_id": _MEMORY_PAGINATION_METRICS_SCHEMA_ID,
        "enabled": enabled,
        "activated": False,
        "decision": "not_evaluated" if enabled else "arm_disabled",
        "receipt_valid_pages": 0,
        "frontiers_seen": 0,
        "nonresumable_truncations": 0,
        "lineage_total_conflicts": 0,
        "page_semantic_conflicts": 0,
        "chains_exceeding_safety_cap": 0,
        "chains_covered_by_complete_projection": 0,
        "executed_calls": 0,
        "completed_chains": 0,
        "executed_calls_sha256": None,
    }


def _validated_memory_page(
    record: Mapping[str, object],
    *,
    operations: Collection[str],
) -> _MemoryPage | None:
    """Validate one memory page without interpreting any forensic content.

    ``operations`` decides which epistemic claim is being validated, because the
    observed plugin read and the computations over it are different results that
    must never be mistaken for one another.
    """

    if record.get("tool") != "memory_query":
        return None
    raw_arguments = record.get("arguments")
    if (
        not isinstance(raw_arguments, Mapping)
        or not _MEMORY_QUERY_REQUIRED_ARGUMENTS.issubset(raw_arguments)
        or not set(raw_arguments) <= _MEMORY_QUERY_ARGUMENTS
    ):
        return None
    plugin = raw_arguments.get("plugin")
    limit = raw_arguments.get("limit")
    offset = raw_arguments.get("offset")
    filter_text = raw_arguments.get("filter")
    operation = raw_arguments.get("operation")
    if (
        not isinstance(plugin, str)
        or not plugin.strip()
        or isinstance(limit, bool)
        or not isinstance(limit, int)
        or limit < 1
        or isinstance(offset, bool)
        or not isinstance(offset, int)
        or offset < 0
        or (filter_text is not None and not isinstance(filter_text, str))
        or not isinstance(operation, str)
        or operation not in operations
    ):
        return None
    result = _validated_continuation_result(record)
    if (
        result is None
        or result.data.type != _TOOL_DATA_TYPES["memory_query"]
        or result.page.unit is not PageUnit.ITEM
        or result.page.offset != offset
        or result.page.returned > limit
        or result.page.next_cursor is not None
        or result.data.attributes.get("plugin") != plugin
    ):
        return None
    arguments = {
        "plugin": plugin,
        "limit": limit,
        "offset": offset,
        "filter": filter_text,
        "operation": operation,
    }
    return _MemoryPage(result=result, arguments=arguments)


def _validated_memory_query_page(
    record: Mapping[str, object],
) -> _MemoryPage | None:
    """Validate one page of the OBSERVED plugin read, the only continuable one."""

    return _validated_memory_page(record, operations=(_CONTINUABLE_MEMORY_OPERATION,))


def _validated_memory_summary_page(
    record: Mapping[str, object],
) -> _MemoryPage | None:
    """Validate one page of a DERIVED computation over a plugin's whole output."""

    return _validated_memory_page(record, operations=_FULL_OUTPUT_SUMMARY_OPERATIONS)


def _valid_next_offset(page: _MemoryPage) -> int | None:
    """Return a strictly advancing next offset or ``None`` for no safe continuation.

    The rule itself lives in :func:`page_continuation`, so this decision is made
    on the same stated page facts every other reader uses.  A second local copy
    of "is there more?" is how two parts of the run come to disagree about
    whether an enumeration finished.
    """

    return page_continuation(page.result).resumable_offset


def _same_memory_lineage(left: AnyToolResult, right: AnyToolResult) -> bool:
    return (
        left.provenance.case_id == right.provenance.case_id
        and left.provenance.source.id == right.provenance.source.id
        and left.provenance.source.sha256 == right.provenance.source.sha256
    )


def _memory_lineage_total_conflicts(
    records: list[dict[str, object]],
) -> int:
    """Count immutable query lineages that report incompatible known totals."""

    totals_by_query: dict[str, set[int]] = {}
    for record in records:
        page = _validated_memory_query_page(record)
        if page is None or page.result.page.total is None:
            continue
        key = canonical_json(
            {
                "plugin": page.arguments["plugin"],
                "filter": page.arguments["filter"],
                "case_id": page.result.provenance.case_id,
                "source_id": page.result.provenance.source.id,
                "source_sha256": page.result.provenance.source.sha256,
            }
        )
        totals_by_query.setdefault(key, set()).add(page.result.page.total)
    return sum(len(totals) > 1 for totals in totals_by_query.values())


def _memory_page_semantic_conflicts(
    records: list[dict[str, object]],
) -> int:
    """Count immutable page coordinates with incompatible forensic contents."""

    semantics_by_page: dict[str, set[str]] = {}
    for record in records:
        page = _validated_memory_query_page(record)
        if page is None:
            continue
        key = canonical_json(
            {
                "arguments": page.arguments,
                "case_id": page.result.provenance.case_id,
                "source_id": page.result.provenance.source.id,
                "source_sha256": page.result.provenance.source.sha256,
                "total": page.result.page.total,
            }
        )
        semantics = canonical_json(
            {
                "data": page.result.data.model_dump(mode="json"),
                "page": page.result.page.model_dump(mode="json"),
                "coverage": page.result.coverage.model_dump(mode="json"),
            }
        )
        semantics_by_page.setdefault(key, set()).add(semantics)
    return sum(len(semantic_variants) > 1 for semantic_variants in semantics_by_page.values())


def _memory_query_frontiers(
    records: list[dict[str, object]],
) -> tuple[list[_MemoryFrontier], int, int]:
    """Return every unconsumed exact next page in stable order."""

    pages = [
        page for record in records if (page := _validated_memory_query_page(record)) is not None
    ]
    candidates: dict[str, _MemoryFrontier] = {}
    nonresumable = 0
    for page in pages:
        if not page.result.page.truncated:
            continue
        next_offset = _valid_next_offset(page)
        if next_offset is None:
            nonresumable += 1
            continue
        next_arguments = {**page.arguments, "offset": next_offset}
        consumed = any(
            candidate.arguments == next_arguments
            and _same_memory_lineage(page.result, candidate.result)
            and candidate.result.page.total == page.result.page.total
            for candidate in pages
        )
        if consumed:
            continue
        frontier = _MemoryFrontier(
            arguments=next_arguments,
            case_id=page.result.provenance.case_id,
            source_id=page.result.provenance.source.id,
            source_sha256=page.result.provenance.source.sha256,
            total=page.result.page.total,
            page_size=page.result.page.returned,
        )
        key = canonical_json(
            {
                "arguments": next_arguments,
                "case_id": frontier.case_id,
                "source_id": frontier.source_id,
                "source_sha256": frontier.source_sha256,
                "total": frontier.total,
            }
        )
        candidates.setdefault(key, frontier)
    return [candidates[key] for key in sorted(candidates)], len(pages), nonresumable


def complete_full_output_projection(result: AnyToolResult) -> Mapping[str, object] | None:
    """Return the declaration of a DERIVED summary of one entire plugin output.

    Some plugins produce far more rows than a byte-bounded page can carry, so a
    caller can ask for a computation over the complete output instead.  That
    result is complete evidence in its own right: the row page is a window into an
    output that has already been characterized in full.

    The declaration is accepted only when the summary states that it ran over the
    whole plugin output, says how many rows that was, and came back whole itself.
    A summary the page limit or the byte guard shortened describes only part of
    the output whatever its scope claims, and its own envelope says so, so it is
    treated as absent.
    """

    attributes = result.data.attributes
    page = result.page
    source_row_count = attributes.get("source_row_count")
    if (
        attributes.get("summary_scope") != "full_plugin_output"
        or attributes.get("evidence_class") != "derived"
        or isinstance(source_row_count, bool)
        or not isinstance(source_row_count, int)
        or source_row_count < 0
        or page.truncated
        or page.next_offset is not None
        or page.next_cursor is not None
        or page.offset != 0
        or page.total is None
        or page.returned != page.total
    ):
        return None
    return {
        "summary_scope": "full_plugin_output",
        "source_row_count": source_row_count,
    }


def _lineage_projection_keys(records: list[dict[str, object]]) -> set[str]:
    """Return lineage/plugin keys that already carry a complete full-output view."""

    covered: set[str] = set()
    for record in records:
        page = _validated_memory_summary_page(record)
        if (
            page is None
            or page.result.status is not ToolStatus.OK
            or not page.result.coverage.complete
            or page.arguments["filter"] is not None
            or complete_full_output_projection(page.result) is None
        ):
            continue
        covered.add(_projection_key(page.result, page.arguments["plugin"]))
    return covered


def _projection_key(result: AnyToolResult, plugin: object) -> str:
    return canonical_json(
        {
            "case_id": result.provenance.case_id,
            "source_id": result.provenance.source.id,
            "source_sha256": result.provenance.source.sha256,
            "plugin": plugin,
        }
    )


def _frontier_projection_key(frontier: _MemoryFrontier) -> str:
    return canonical_json(
        {
            "case_id": frontier.case_id,
            "source_id": frontier.source_id,
            "source_sha256": frontier.source_sha256,
            "plugin": frontier.arguments.get("plugin"),
        }
    )


def _chain_exceeds_safety_cap(frontier: _MemoryFrontier) -> bool:
    """Whether finishing this chain provably needs more calls than the cap allows.

    A byte-bounded page holds far fewer rows than a plugin such as ``netscan``
    produces, so some row sets cannot be enumerated exhaustively at all.  Walking
    a few pages into such a set consumes the shared tool budget without ever
    reaching completeness, which starves the investigation itself.  Only chains
    with a known total and a known page size are judged here; anything unknown
    keeps the previous behaviour and is attempted.
    """

    total = frontier.total
    offset = frontier.arguments.get("offset")
    if (
        total is None
        or frontier.page_size < 1
        or isinstance(offset, bool)
        or not isinstance(offset, int)
    ):
        return False
    remaining = total - offset
    if remaining <= 0:
        return False
    required_calls = -(-remaining // frontier.page_size)
    return required_calls > _MEMORY_PAGINATION_SAFETY_CAP


def _memory_pagination_is_blocked(metrics: Mapping[str, object]) -> bool:
    """Whether unresolved pagination makes any existing draft unsafe to accept."""

    return metrics.get("decision") in _MEMORY_PAGINATION_BLOCKING_DECISIONS


def _validate_memory_continuation_result(
    wire: Mapping[str, object],
    *,
    expected_arguments: Mapping[str, object],
    frontier: _MemoryFrontier,
) -> _MemoryPage:
    """Validate the newly executed page against its exact call and source."""

    record = {
        "tool": "memory_query",
        "arguments": dict(expected_arguments),
        "result": dict(wire),
    }
    page = _validated_memory_query_page(record)
    # ``_validated_memory_query_page`` already binds the record's arguments to the
    # result through the shared gate, which is version-dispatched; repeating one
    # contract's field here is what would silently stop binding under the other.
    if (
        page is None
        or page.result.provenance.case_id != frontier.case_id
        or page.result.provenance.source.id != frontier.source_id
        or page.result.provenance.source.sha256 != frontier.source_sha256
        or page.result.page.total != frontier.total
    ):
        raise RuntimeError(
            "deterministic memory continuation failed receipt, argument or source validation"
        )
    if page.result.page.truncated and _valid_next_offset(page) is None:
        raise RuntimeError("deterministic memory continuation returned an invalid next page")
    if not page.result.page.truncated and page.result.page.next_offset is not None:
        raise RuntimeError(
            "deterministic memory continuation returned contradictory terminal state"
        )
    return page


def _continuation_messages(
    arguments: Mapping[str, object],
    wire: Mapping[str, object],
    *,
    result: AnyToolResult,
) -> list[object]:
    """Represent a harness-executed page as a valid auditable tool-call pair."""

    call_digest = sha256_hex(
        canonical_json(
            {
                "tool": "memory_query",
                "arguments": dict(arguments),
                "case_id": result.provenance.case_id,
                "source_id": result.provenance.source.id,
                "source_sha256": result.provenance.source.sha256,
                "invocation_id": result.provenance.invocation_id,
                "origin": "deterministic_harness",
            }
        )
    )
    call_id = f"deterministic-memory-page-{call_digest[:20]}"
    return [
        AIMessage(
            content="",
            tool_calls=[
                {
                    "name": "memory_query",
                    "args": dict(arguments),
                    "id": call_id,
                    "type": "tool_call",
                }
            ],
            additional_kwargs={"forensic_origin": "deterministic_harness"},
        ),
        ToolMessage(
            content=canonical_json(dict(wire)),
            tool_call_id=call_id,
            name="memory_query",
            additional_kwargs={"forensic_origin": "deterministic_harness"},
        ),
    ]


def _follow_memory_query_pagination(
    tools: list,
    records: list[dict[str, object]],
) -> tuple[list[object], dict[str, object], str | None]:
    """Complete trusted ``memory_query`` pages without choosing forensic semantics."""

    metrics = _empty_memory_pagination_metrics(enabled=True)
    pending, valid_pages, nonresumable = _memory_query_frontiers(records)
    total_conflicts = _memory_lineage_total_conflicts(records)
    semantic_conflicts = _memory_page_semantic_conflicts(records)
    metrics["receipt_valid_pages"] = valid_pages
    metrics["frontiers_seen"] = len(pending)
    metrics["nonresumable_truncations"] = nonresumable
    metrics["lineage_total_conflicts"] = total_conflicts
    metrics["page_semantic_conflicts"] = semantic_conflicts
    if semantic_conflicts:
        metrics["decision"] = "page_semantic_conflict"
        return [], metrics, None
    if total_conflicts:
        metrics["decision"] = "lineage_total_conflict"
        return [], metrics, None
    unfinishable = [frontier for frontier in pending if _chain_exceeds_safety_cap(frontier)]
    pending = [frontier for frontier in pending if not _chain_exceeds_safety_cap(frontier)]
    projected = _lineage_projection_keys(records)
    # A row set that cannot be enumerated is only a coverage gap when nothing
    # else characterizes the full result.  When the producer already returned a
    # declared-complete projection of the entire plugin output for the same
    # source and plugin, the missing rows are a window, not a hole.
    uncovered = [
        frontier
        for frontier in unfinishable
        if _frontier_projection_key(frontier) not in projected
    ]
    metrics["chains_exceeding_safety_cap"] = len(unfinishable)
    metrics["chains_covered_by_complete_projection"] = len(unfinishable) - len(uncovered)
    if not pending:
        if uncovered:
            metrics["decision"] = "chain_exceeds_safety_cap"
        elif unfinishable:
            metrics["decision"] = "complete_projection_covers_truncated_rows"
        else:
            metrics["decision"] = (
                "nonresumable_truncation" if nonresumable else "no_unconsumed_frontier"
            )
        return [], metrics, None

    tool = next((candidate for candidate in tools if candidate.name == "memory_query"), None)
    if tool is None:
        metrics["decision"] = "memory_query_not_visible"
        return [], metrics, None

    emitted: list[object] = []
    executed: list[dict[str, object]] = []
    completed_chains = 0
    seen: set[str] = set()
    while pending:
        pending.sort(
            key=lambda item: canonical_json(
                {
                    "arguments": item.arguments,
                    "case_id": item.case_id,
                    "source_id": item.source_id,
                    "source_sha256": item.source_sha256,
                    "total": item.total,
                }
            )
        )
        frontier = pending.pop(0)
        call_key = canonical_json(
            {
                "arguments": frontier.arguments,
                "case_id": frontier.case_id,
                "source_id": frontier.source_id,
                "source_sha256": frontier.source_sha256,
                "total": frontier.total,
            }
        )
        if call_key in seen:
            metrics["decision"] = "continuation_cycle"
            break
        if len(executed) >= _MEMORY_PAGINATION_SAFETY_CAP:
            metrics["decision"] = "safety_cap_reached"
            break
        seen.add(call_key)
        realized = _realized_continuation_arguments(tool, frontier.arguments)
        try:
            raw_wire = tool.invoke(frontier.arguments)
        except _DispatchDenied as exc:
            metrics.update(
                {
                    "activated": bool(executed),
                    "decision": "dispatch_budget_exhausted",
                    "executed_calls": len(executed),
                    "completed_chains": completed_chains,
                    "executed_calls_sha256": (
                        sha256_hex(canonical_json(executed)) if executed else None
                    ),
                }
            )
            return emitted, metrics, exc.reason
        if not isinstance(raw_wire, Mapping):
            raise RuntimeError("deterministic memory continuation returned no structured result")
        wire = cast(dict[str, object], json.loads(canonical_json(raw_wire)))
        page = _validate_memory_continuation_result(
            wire,
            expected_arguments=realized,
            frontier=frontier,
        )
        if page.result.receipt is None:
            raise RuntimeError("validated memory continuation unexpectedly lacks a receipt")
        emitted.extend(_continuation_messages(realized, wire, result=page.result))
        executed.append(
            {
                "tool": "memory_query",
                "arguments": realized,
                "payload_sha256": page.result.receipt.payload_sha256,
            }
        )
        metrics["activated"] = True
        next_offset = _valid_next_offset(page)
        if next_offset is None:
            completed_chains += 1
            continue
        pending.append(
            _MemoryFrontier(
                arguments={**page.arguments, "offset": next_offset},
                case_id=page.result.provenance.case_id,
                source_id=page.result.provenance.source.id,
                source_sha256=page.result.provenance.source.sha256,
                total=page.result.page.total,
            )
        )

    metrics["executed_calls"] = len(executed)
    metrics["completed_chains"] = completed_chains
    metrics["executed_calls_sha256"] = sha256_hex(canonical_json(executed)) if executed else None
    if not metrics["decision"] or metrics["decision"] == "not_evaluated":
        if uncovered:
            metrics["decision"] = "chain_exceeds_safety_cap"
        elif unfinishable:
            metrics["decision"] = "complete_projection_covers_truncated_rows"
        else:
            metrics["decision"] = "nonresumable_truncation" if nonresumable else "completed"
    return emitted, metrics, None
