"""Bounded recovery for correlating findings across evidence sources."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import cast

from forensic_agent.agent.execution_budget import _DispatchDenied
from forensic_agent.agent.recovery.common import (
    _case_bundle_sha256,
    _deterministic_tool_call_messages,
    _realized_continuation_arguments,
    _validated_continuation_result,
)
from forensic_agent.agent.tool_contract import _TOOL_DATA_TYPES
from forensic_agent.core.repro import canonical_json, sha256_hex

_MATCH_WITH_CONTINUATION_METRICS_SCHEMA_ID = (
    "forensic.deterministic-match-with-continuation-metrics.v1"
)


def _empty_match_with_continuation_metrics(*, enabled: bool) -> dict[str, object]:
    """Return bounded telemetry for trusted cross-tool join affordances."""

    return {
        "schema_id": _MATCH_WITH_CONTINUATION_METRICS_SCHEMA_ID,
        "enabled": enabled,
        "activated": False,
        "decision": "not_evaluated" if enabled else "arm_disabled",
        "receipt_valid_case_results": 0,
        "affordances_seen": 0,
        "candidates_seen": 0,
        "ambiguous_candidate_count": 0,
        "executed_calls": 0,
        "completed": False,
        "executed_call_sha256": None,
    }


def _normalized_match_crc32(value: object) -> str | None:
    text = str(value or "").strip().casefold().removeprefix("0x")
    return text if re.fullmatch(r"[0-9a-f]{8}", text) is not None else None


def _positive_match_size(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    return value


def _trusted_match_with_candidates(
    tools: list,
    records: list[dict[str, object]],
) -> tuple[list[dict[str, object]], int, int]:
    """Extract unique, schema-valid archive joins from receipt-valid results.

    Only the typed ``archive_member_summary`` contract is executable.  This is
    intentionally not a recursive JSON walker: an unrelated evidence string or
    nested object named ``match_with`` can never become control data.
    """

    from forensic_agent.core.result_contract import ToolStatus

    tool_by_name = {str(tool.name): tool for tool in tools}
    unique: dict[str, dict[str, object]] = {}
    receipt_valid_results = 0
    affordances_seen = 0
    for record in records:
        result = _validated_continuation_result(record)
        if result is None:
            continue
        receipt_valid_results += 1
        if (
            result.provenance.tool.name != "pcap_query"
            or result.data.type != _TOOL_DATA_TYPES["pcap_query"]
            or result.provenance.source.attributes.get("active_modality") != "pcap"
            or result.status is not ToolStatus.OK
            or not result.coverage.complete
            or result.page.truncated
            or result.page.next_offset is not None
            or result.page.next_cursor is not None
            or (
                result.page.total is not None
                and result.page.offset + result.page.returned != result.page.total
            )
        ):
            continue
        case_id = str(result.provenance.case_id or "").strip()
        bundle_sha256 = _case_bundle_sha256(result)
        summary = result.data.attributes.get("archive_member_summary")
        if not case_id or bundle_sha256 is None or not isinstance(summary, Mapping):
            continue
        candidates = summary.get("candidates")
        if not isinstance(candidates, list):
            continue
        executable_candidates = [
            candidate
            for candidate in candidates
            if isinstance(candidate, Mapping) and "match_with" in candidate
        ]
        if not executable_candidates:
            continue
        candidate_count = summary.get("candidate_count")
        returned_count = summary.get("returned_candidate_count")
        if (
            isinstance(candidate_count, bool)
            or not isinstance(candidate_count, int)
            or isinstance(returned_count, bool)
            or not isinstance(returned_count, int)
            or candidate_count != len(candidates)
            or returned_count != len(candidates)
            or len(candidates) != 1
            or summary.get("truncated") is not False
            or summary.get("selection_ambiguous") is not False
        ):
            raise RuntimeError("match_with summary failed completeness/ambiguity validation")
        for candidate in candidates:
            if not isinstance(candidate, Mapping) or "match_with" not in candidate:
                continue
            affordances_seen += 1
            match_with = candidate.get("match_with")
            if not isinstance(match_with, Mapping) or set(match_with) != {
                "tool",
                "size",
                "crc32",
            }:
                raise RuntimeError("match_with affordance has an invalid shape")
            tool_name = match_with.get("tool")
            size = _positive_match_size(match_with.get("size"))
            crc32 = _normalized_match_crc32(match_with.get("crc32"))
            candidate_size = _positive_match_size(
                candidate.get("uncompressed_size", candidate.get("size"))
            )
            candidate_crc32 = _normalized_match_crc32(candidate.get("crc32"))
            if (
                not isinstance(tool_name, str)
                or tool_name != "carve_files"
                or size is None
                or crc32 is None
                or candidate_size != size
                or candidate_crc32 != crc32
            ):
                raise RuntimeError("match_with affordance disagrees with its evidence row")
            tool = tool_by_name.get(tool_name)
            if tool is None:
                continue
            arguments = {"size": size, "crc32": crc32}
            realized_arguments = _realized_continuation_arguments(tool, arguments)
            value: dict[str, object] = {
                "tool": tool_name,
                "arguments": arguments,
                "realized_arguments": realized_arguments,
                "case_id": case_id,
                "case_bundle_sha256": bundle_sha256,
                "source_invocation_id": result.provenance.invocation_id,
            }
            key = canonical_json(
                {
                    "tool": tool_name,
                    "arguments": realized_arguments,
                    "case_id": case_id,
                    "case_bundle_sha256": bundle_sha256,
                }
            )
            unique.setdefault(key, value)
    return [unique[key] for key in sorted(unique)], receipt_valid_results, affordances_seen


class _MatchTargetUnusable(RuntimeError):
    """The join target could not be produced, as opposed to being inconsistent."""


def _validate_match_with_target_result(
    wire: Mapping[str, object],
    *,
    tool_name: str,
    realized_arguments: Mapping[str, object],
    match_arguments: Mapping[str, object],
    case_id: str,
    case_bundle_sha256: str,
) -> None:
    """Fail closed unless a joined target row exactly satisfies the affordance."""

    from forensic_agent.core.result_contract import ToolStatus

    record = {
        "tool": tool_name,
        "arguments": dict(realized_arguments),
        "result": wire,
    }
    # The reported status is read before the receipt, because a tool that could
    # not run has nothing to attest and would fail receipt validation for a
    # reason unrelated to the join. Raising here ended the whole examination when
    # a container engine was simply not running, losing every finding the run had
    # already established. The caller declines instead, and the ordinary gates
    # decide what may be published.
    reported = str(wire.get("status") or "").strip().casefold()
    if reported and reported != "ok":
        raise _MatchTargetUnusable(reported)
    result = _validated_continuation_result(record)
    if result is not None and result.status is not ToolStatus.OK:
        raise _MatchTargetUnusable(str(result.status.value))
    expected_data_type = _TOOL_DATA_TYPES.get(tool_name)
    if (
        result is None
        or not result.coverage.complete
        or result.page.truncated
        or result.page.next_offset is not None
        or result.page.next_cursor is not None
        or result.provenance.case_id != case_id
        or _case_bundle_sha256(result) != case_bundle_sha256
        or result.provenance.source.attributes.get("active_modality") != "disk"
        or expected_data_type is None
        or result.data.type != expected_data_type
    ):
        raise RuntimeError("match_with target failed receipt/case/bundle validation")
    expected_size = _positive_match_size(match_arguments.get("size"))
    expected_crc32 = _normalized_match_crc32(match_arguments.get("crc32"))
    filters = result.data.attributes.get("filters")
    returned_matching = result.data.attributes.get("returned_matching_artifact_count")
    if (
        result.data.attributes.get("filter_scan_complete") is not True
        or returned_matching != 1
        or not isinstance(filters, Mapping)
        or _positive_match_size(filters.get("size")) != expected_size
        or _normalized_match_crc32(filters.get("crc32")) != expected_crc32
    ):
        raise RuntimeError("match_with target did not exhaust the exact requested filter")
    matching_rows = [
        row
        for row in result.data.items
        if isinstance(row, Mapping)
        and _positive_match_size(row.get("size")) == expected_size
        and _normalized_match_crc32(row.get("crc32")) == expected_crc32
    ]
    if expected_size is None or expected_crc32 is None or len(matching_rows) != 1:
        raise RuntimeError("match_with target did not return one exact matching row")


def _follow_unique_match_with_continuation(
    tools: list,
    records: list[dict[str, object]],
) -> tuple[list[object], dict[str, object], str | None]:
    """Execute one unique receipt-bound cross-tool join, or fail closed."""

    metrics = _empty_match_with_continuation_metrics(enabled=True)
    try:
        candidates, valid_results, affordances_seen = _trusted_match_with_candidates(tools, records)
    except RuntimeError:
        metrics["decision"] = "invalid_or_incomplete_affordance"
        return [], metrics, None
    metrics["receipt_valid_case_results"] = valid_results
    metrics["affordances_seen"] = affordances_seen
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
    realized_arguments = cast(dict[str, object], candidate["realized_arguments"])
    match_arguments = cast(dict[str, object], candidate["arguments"])
    case_id = cast(str, candidate["case_id"])
    bundle_sha256 = cast(str, candidate["case_bundle_sha256"])
    for record in records:
        if record.get("tool") != tool_name:
            continue
        arguments = record.get("arguments")
        result_wire = record.get("result")
        if (
            not isinstance(arguments, Mapping)
            or canonical_json(dict(arguments)) != canonical_json(realized_arguments)
            or not isinstance(result_wire, Mapping)
        ):
            continue
        existing = _validated_continuation_result(record)
        if (
            existing is None
            or existing.provenance.case_id != case_id
            or _case_bundle_sha256(existing) != bundle_sha256
        ):
            continue
        try:
            _validate_match_with_target_result(
                result_wire,
                tool_name=tool_name,
                realized_arguments=realized_arguments,
                match_arguments=match_arguments,
                case_id=case_id,
                case_bundle_sha256=bundle_sha256,
            )
        except _MatchTargetUnusable:
            continue
        metrics["decision"] = "equivalent_call_already_satisfied"
        metrics["completed"] = True
        return [], metrics, None

    tool_by_name = {str(tool.name): tool for tool in tools}
    tool = tool_by_name[tool_name]
    try:
        raw_wire = tool.invoke(match_arguments)
    except _DispatchDenied as exc:
        metrics["decision"] = "dispatch_budget_exhausted"
        return [], metrics, exc.reason
    if not isinstance(raw_wire, Mapping):
        raise RuntimeError("match_with continuation did not return a structured result")
    wire = cast(dict[str, object], json.loads(canonical_json(raw_wire)))
    try:
        _validate_match_with_target_result(
            wire,
            tool_name=tool_name,
            realized_arguments=realized_arguments,
            match_arguments=match_arguments,
            case_id=case_id,
            case_bundle_sha256=bundle_sha256,
        )
    except _MatchTargetUnusable as exc:
        # The join could not be produced, most often because the tool it needs
        # is unavailable. Declining leaves the rest of the examination intact.
        metrics["activated"] = True
        metrics["decision"] = f"match_target_unusable:{exc}"
        return [], metrics, None
    metrics["activated"] = True
    metrics["decision"] = "completed_exact_match"
    metrics["executed_calls"] = 1
    metrics["completed"] = True
    metrics["executed_call_sha256"] = sha256_hex(
        canonical_json({"tool": tool_name, "arguments": realized_arguments})
    )
    return _deterministic_tool_call_messages(tool_name, realized_arguments, wire), metrics, None
