"""Bounded recovery after a reference-only or empty result."""

from __future__ import annotations

from collections.abc import Mapping

from forensic_agent.agent.recovery.common import _validated_continuation_result
from forensic_agent.agent.recovery.multisource_coverage import _direct_tool_modality

_REFERENCE_EVIDENCE_RECOVERY_METRICS_SCHEMA_ID = (
    "forensic.reference-evidence-recovery-metrics.v2"
)
def _empty_reference_evidence_recovery_metrics(*, enabled: bool) -> dict[str, object]:
    """Return bounded telemetry for missing-evidence investigation recovery.

    A reference lookup may guide planning, but it is never case evidence.  When a
    model stops after such a lookup, the fail-closed arm may force exactly one
    visible evidence-reading tool selected from the lookup's first ranked hit.  A
    run that produced no tool result at all is never handed a tool derived from
    the question wording: it reaches the reserved concluding turn and reports what
    the (absent) evidence establishes.
    """

    return {
        "schema_id": _REFERENCE_EVIDENCE_RECOVERY_METRICS_SCHEMA_ID,
        "enabled": enabled,
        "activated": False,
        "decision": "not_evaluated" if enabled else "arm_disabled",
        "receipt_valid_reference_results": 0,
        "tool_results_seen": 0,
        "candidates_seen": 0,
        "candidate_source": "none",
        "question_intents_matched": 0,
        "ambiguous_candidate_count": 0,
        "forced_tool": None,
        "recovery_attempted": False,
        "recovery_model_requests": 0,
        "case_results_before": 0,
        "case_results_after": 0,
    }
def _validated_reference_lookup_result(record: Mapping[str, object]):
    """Validate one local, receipt-bound ``lookup_artifact`` result.

    Reference material is trusted only as control guidance.  It remains explicitly
    non-admissible as case evidence, and neither its prose nor its locations are
    executed.  The recovery gate may consume only the exact parser identifier of
    the first ranked item and still subjects the resulting model call to the normal
    tool schema and oversight policy.
    """

    from forensic_agent.core.result_contract import ProvenanceType, ToolStatus
    from forensic_agent.core.result_reading import (
        UnreadableResult,
        is_candidate_case_evidence,
        read_result,
        receipt_is_valid,
    )

    tool_name = record.get("tool")
    arguments = record.get("arguments")
    wire = record.get("result")
    if (
        tool_name != "lookup_artifact"
        or not isinstance(arguments, Mapping)
        or not isinstance(wire, Mapping)
    ):
        return None
    from forensic_agent.agent.tool_contract import result_binds_call

    try:
        result = read_result(wire)
    except (TypeError, UnreadableResult):
        return None
    if not receipt_is_valid(result):
        return None
    if (
        result.status not in {ToolStatus.OK, ToolStatus.PARTIAL}
        or result.provenance.type is not ProvenanceType.REFERENCE_KNOWLEDGE
        or is_candidate_case_evidence(result)
        or result.provenance.tool.name != tool_name
        or not result_binds_call(result, arguments)
        or result.provenance.source.id != "bundled-procedural-reference"
        or result.data.type != "reference.artifact_locations"
    ):
        return None
    return result
def _receipt_valid_case_result_count(
    records: list[dict[str, object]],
    *,
    case_id: str,
) -> int:
    """Count receipt-valid, admissible results bound to the active case."""

    return sum(
        result is not None and result.provenance.case_id == case_id
        for record in records
        for result in (_validated_continuation_result(record),)
    )
def _reference_evidence_tool_candidates(
    tools: list,
    records: list[dict[str, object]],
) -> tuple[list[str], int]:
    """Return exact visible parsers nominated by valid first-ranked references.

    Only the first ranked item is used.  A bounded reference result can therefore
    remain honestly marked as truncated without pretending that every catalogue hit
    was examined.  Multiple different parser nominations are ambiguity and are
    never resolved by guessing.
    """

    visible_case_tools = {
        str(tool.name)
        for tool in tools
        if _direct_tool_modality(str(tool.name)) is not None
    }
    candidates: set[str] = set()
    valid_reference_results = 0
    for record in records:
        result = _validated_reference_lookup_result(record)
        if result is None:
            continue
        valid_reference_results += 1
        if not result.data.items:
            continue
        first = result.data.items[0]
        if not isinstance(first, Mapping):
            continue
        parser = first.get("parser")
        if isinstance(parser, str) and parser in visible_case_tools:
            candidates.add(parser)
    return sorted(candidates), valid_reference_results
def _reference_recovery_tool_candidates(
    tools: list,
    records: list[dict[str, object]],
) -> tuple[list[str], int, str]:
    """Select an evidence-reading parser named by receipt-valid reference guidance.

    Receipt-valid reference guidance is the only source of a forced tool here.  A
    run that already holds any tool result, even one unusable for this gate, is
    left to its own trace so a failed parser is not silently replaced by another;
    a run with no tool result at all is not handed a tool either.  The instrument
    is never chosen from the wording of the question -- doing so would let the
    harness pick the forensic method from the phrasing of the task.
    """

    candidates, valid_references = _reference_evidence_tool_candidates(tools, records)
    if valid_references:
        return candidates, valid_references, "reference_result"
    if records:
        return [], 0, "existing_tool_result"
    return [], 0, "none"
