"""Bounded recovery for reading discovered and carved files."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import cast

from forensic_agent.agent.execution_budget import _DispatchDenied
from forensic_agent.agent.recovery.common import (
    _deterministic_tool_call_messages,
    _realized_continuation_arguments,
    _validated_continuation_result,
)
from forensic_agent.core.repro import canonical_json, sha256_hex

_CONTINUATION_METRICS_SCHEMA_ID = "forensic.deterministic-continuation-metrics.v1"


_CONTINUATION_SAFETY_CAP = 12


_CARVED_FILE_DATA_TYPE = "filesystem.carved_files"


_CARVE_FUNCTION = "carve_query"
_CARVE_OPERATION = "carve"
_READ_OPERATION = "read_artifact"
#: A row the model already searched is as consumed as a row it already read: the
#: search reaches the same artifact through the same index.
_DEREFERENCING_OPERATIONS = frozenset({_READ_OPERATION, "search_artifact"})


_TEXT_BEARING_CARVE_TYPES = frozenset(
    {
        "csv",
        "doc",
        "html",
        "json",
        "log",
        "ole",
        "pdf",
        "ppt",
        "rtf",
        "txt",
        "xls",
        "xml",
    }
)


def _empty_continuation_metrics(*, enabled: bool) -> dict[str, object]:
    """Return the exact telemetry shape for deterministic content continuations."""

    return {
        "schema_id": _CONTINUATION_METRICS_SCHEMA_ID,
        "enabled": enabled,
        "activated": False,
        "decision": "not_evaluated" if enabled else "arm_disabled",
        "receipt_valid_case_results": 0,
        "candidates_seen": 0,
        "ambiguous_candidate_count": 0,
        "executed_calls": 0,
        "completed": False,
        "executed_calls_sha256": None,
    }


def _carve_read_affordance(item: object) -> dict[str, object] | None:
    """Return one exact trusted carve read affordance, never an inferred call."""

    if not isinstance(item, Mapping):
        return None
    carved_type = item.get("type")
    if not isinstance(carved_type, str) or carved_type.casefold() not in _TEXT_BEARING_CARVE_TYPES:
        return None
    raw = item.get("read_with")
    index = item.get("index")
    if not isinstance(raw, Mapping) or set(raw) != {"tool", "operation", "index"}:
        return None
    offered = raw.get("index")
    if (
        raw.get("tool") != _CARVE_FUNCTION
        or raw.get("operation") != _READ_OPERATION
        or isinstance(offered, bool)
        or not isinstance(offered, int)
        or offered < 0
        or index != offered
    ):
        return None
    return {
        "tool": _CARVE_FUNCTION,
        "arguments": {"operation": _READ_OPERATION, "index": offered},
    }


def _successful_carve_read_exists(
    records: list[dict[str, object]],
    *,
    after_index: int,
    index: int,
    source_case_id: str | None,
    source_id: str,
    source_sha256: str | None,
) -> bool:
    """Whether the model already dereferenced a manifest row successfully."""

    for record in records[after_index + 1 :]:
        if record.get("tool") != _CARVE_FUNCTION:
            continue
        arguments = record.get("arguments")
        if (
            not isinstance(arguments, Mapping)
            or arguments.get("operation") not in _DEREFERENCING_OPERATIONS
            or arguments.get("index") != index
        ):
            continue
        result = _validated_continuation_result(record)
        if (
            result is not None
            and result.provenance.case_id == source_case_id
            and result.provenance.source.id == source_id
            and result.provenance.source.sha256 == source_sha256
        ):
            return True
    return False


def _unconsumed_carve_read_candidates(
    records: list[dict[str, object]],
) -> tuple[list[dict[str, object]], int]:
    """Extract unique unconsumed read calls from trusted carved-file manifests."""

    receipt_valid_results = 0
    by_key: dict[str, dict[str, object]] = {}
    for record_index, record in enumerate(records):
        result = _validated_continuation_result(record)
        if result is None:
            continue
        receipt_valid_results += 1
        if record.get("tool") != _CARVE_FUNCTION or result.data.type != _CARVED_FILE_DATA_TYPE:
            continue
        arguments = record.get("arguments")
        # Only the manifest nominates rows; a read-back result carries none.
        if not isinstance(arguments, Mapping) or arguments.get("operation") != _CARVE_OPERATION:
            continue
        for item in result.data.items:
            candidate = _carve_read_affordance(item)
            if candidate is None:
                continue
            index = cast(dict[str, object], candidate["arguments"])["index"]
            if _successful_carve_read_exists(
                records,
                after_index=record_index,
                index=cast(int, index),
                source_case_id=result.provenance.case_id,
                source_id=result.provenance.source.id,
                source_sha256=result.provenance.source.sha256,
            ):
                continue
            key = canonical_json(
                {
                    "candidate": candidate,
                    "source_case_id": result.provenance.case_id,
                    "source_id": result.provenance.source.id,
                    "source_sha256": result.provenance.source.sha256,
                }
            )
            by_key.setdefault(
                key,
                {
                    **candidate,
                    "source_case_id": result.provenance.case_id,
                    "source_id": result.provenance.source.id,
                    "source_sha256": result.provenance.source.sha256,
                    "source_invocation_id": result.provenance.invocation_id,
                },
            )
    return [by_key[key] for key in sorted(by_key)], receipt_valid_results


def _next_carve_read_continuation(
    wire: Mapping[str, object],
    *,
    expected_index: int,
    expected_arguments: Mapping[str, object],
    source_case_id: str | None,
    source_id: str,
    source_sha256: str | None,
) -> tuple[dict[str, object] | None, bool]:
    """Validate the next exact page call and report whether EOF was reached."""

    from forensic_agent.agent.tool_contract import result_binds_call
    from forensic_agent.core.result_contract import ProvenanceType, ToolStatus
    from forensic_agent.core.result_reading import (
        UnreadableResult,
        is_candidate_case_evidence,
        read_result,
        receipt_is_valid,
    )

    try:
        result = read_result(wire)
    except (TypeError, UnreadableResult) as exc:
        raise RuntimeError("deterministic continuation returned an invalid tool result") from exc
    if (
        not receipt_is_valid(result)
        or result.status not in {ToolStatus.OK, ToolStatus.PARTIAL}
        or result.provenance.type is not ProvenanceType.CASE_EVIDENCE
        or not is_candidate_case_evidence(result)
        or result.provenance.tool.name != _CARVE_FUNCTION
        or not result_binds_call(result, expected_arguments)
        or result.data.type != _CARVED_FILE_DATA_TYPE
        or result.provenance.case_id != source_case_id
        or result.provenance.source.id != source_id
        or result.provenance.source.sha256 != source_sha256
    ):
        raise RuntimeError("deterministic continuation result failed receipt/provenance validation")

    attributes = result.data.attributes
    eof = attributes.get("eof")
    if eof is True:
        if result.page.truncated or result.page.next_offset is not None:
            raise RuntimeError("deterministic continuation reported contradictory EOF state")
        return None, True
    raw = attributes.get("continue_read_with")
    if eof is not False or not isinstance(raw, Mapping):
        return None, False
    if set(raw) != {"tool", "operation", "index", "offset", "max_bytes"}:
        return None, False
    index = raw.get("index")
    offset = raw.get("offset")
    max_bytes = raw.get("max_bytes")
    if (
        raw.get("tool") != _CARVE_FUNCTION
        or raw.get("operation") != _READ_OPERATION
        or index != expected_index
        or isinstance(offset, bool)
        or not isinstance(offset, int)
        or offset < 0
        or isinstance(max_bytes, bool)
        or not isinstance(max_bytes, int)
        or max_bytes < 1
        or not result.page.truncated
        or result.page.next_offset != offset
    ):
        return None, False
    return {
        "tool": _CARVE_FUNCTION,
        "arguments": {
            "operation": _READ_OPERATION,
            "index": index,
            "offset": offset,
            "max_bytes": max_bytes,
        },
    }, False


def _follow_unique_content_continuation(
    tools: list,
    records: list[dict[str, object]],
) -> tuple[list[object], dict[str, object], str | None]:
    """Follow one unambiguous receipt-valid content chain for S-FINAL.

    This is deliberately narrower than generic recursive JSON execution.  Only a
    trusted carved-file manifest may nominate a row, and only that tool's exact
    ``continue_read_with`` pages are followed.  Ambiguity always stops execution.
    """

    metrics = _empty_continuation_metrics(enabled=True)
    candidates, valid_results = _unconsumed_carve_read_candidates(records)
    metrics["receipt_valid_case_results"] = valid_results
    metrics["candidates_seen"] = len(candidates)
    if not candidates:
        metrics["decision"] = "no_unconsumed_candidate"
        return [], metrics, None
    if len(candidates) != 1:
        metrics["decision"] = "ambiguous_candidates"
        metrics["ambiguous_candidate_count"] = len(candidates)
        return [], metrics, None

    candidate = candidates[0]
    tool_name = cast(str, candidate["tool"])
    tool_by_name = {tool.name: tool for tool in tools}
    tool = tool_by_name.get(tool_name)
    if tool is None:
        metrics["decision"] = "candidate_tool_not_visible"
        return [], metrics, None

    index = cast(int, cast(dict[str, object], candidate["arguments"])["index"])
    source_case_id = cast(str | None, candidate["source_case_id"])
    source_id = cast(str, candidate["source_id"])
    source_sha256 = cast(str | None, candidate["source_sha256"])
    pending: dict[str, object] | None = {
        "tool": tool_name,
        "arguments": dict(cast(dict[str, object], candidate["arguments"])),
    }
    emitted: list[object] = []
    executed: list[dict[str, object]] = []
    seen: set[str] = set()

    while pending is not None:
        call_key = canonical_json(pending)
        if call_key in seen:
            metrics["decision"] = "continuation_cycle"
            break
        if len(executed) >= _CONTINUATION_SAFETY_CAP:
            metrics["decision"] = "safety_cap_reached"
            break
        seen.add(call_key)
        pending_arguments = dict(cast(dict[str, object], pending["arguments"]))
        realized_arguments = _realized_continuation_arguments(tool, pending_arguments)
        try:
            raw_wire = tool.invoke(pending_arguments)
        except _DispatchDenied as exc:
            metrics["decision"] = "dispatch_budget_exhausted"
            metrics["executed_calls"] = len(executed)
            metrics["activated"] = bool(executed)
            metrics["executed_calls_sha256"] = (
                sha256_hex(canonical_json(executed)) if executed else None
            )
            return emitted, metrics, exc.reason
        if not isinstance(raw_wire, Mapping):
            raise RuntimeError("deterministic continuation did not return a structured result")
        wire = cast(dict[str, object], json.loads(canonical_json(raw_wire)))
        emitted.extend(_deterministic_tool_call_messages(tool_name, pending_arguments, wire))
        executed.append(pending)
        metrics["activated"] = True
        pending, eof = _next_carve_read_continuation(
            wire,
            expected_index=index,
            expected_arguments=realized_arguments,
            source_case_id=source_case_id,
            source_id=source_id,
            source_sha256=source_sha256,
        )
        if eof:
            metrics["decision"] = "completed_eof"
            metrics["completed"] = True
            break
        if pending is None:
            metrics["decision"] = "incomplete_without_valid_continuation"
            break

    metrics["executed_calls"] = len(executed)
    metrics["executed_calls_sha256"] = sha256_hex(canonical_json(executed)) if executed else None
    return emitted, metrics, None
