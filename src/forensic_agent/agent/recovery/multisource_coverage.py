"""Bounded recovery for coverage across multiple evidence sources."""

from __future__ import annotations

from typing import cast

from forensic_agent.agent.recovery.common import _validated_continuation_result
from forensic_agent.agent.tool_taxonomy import (
    _HOST_PATH_TOOLS,
    _MEMORY_TOOLS,
    _PCAP_TOOLS,
    _REFERENCE_TOOLS,
)

_MULTISOURCE_COVERAGE_METRICS_SCHEMA_ID = "forensic.explicit-multisource-coverage-metrics.v1"
def _empty_multisource_coverage_metrics(*, enabled: bool) -> dict[str, object]:
    """Return bounded telemetry for the explicit disk/PCAP coverage gate."""

    return {
        "schema_id": _MULTISOURCE_COVERAGE_METRICS_SCHEMA_ID,
        "enabled": enabled,
        "activated": False,
        "decision": "not_evaluated" if enabled else "arm_disabled",
        "named_modalities": [],
        "covered_before": [],
        "missing_before": [],
        "forced_tool": None,
        "recovery_attempted": False,
        "recovery_model_requests": 0,
        "covered_after": [],
        "missing_after": [],
    }
def _active_cross_source_disk_pcap(case_evidence_source: object) -> tuple[str, ...]:
    """Return ``('disk', 'pcap')`` only when the case binds BOTH direct modalities.

    The cross-source coverage gate applies by what the case actually holds, never
    by what the question mentions: a run whose case binds both a disk and a
    capture should read from both before it concludes, whatever the task wording.
    A single-source case has no cross-source obligation, so the gate does not
    apply and nothing is derived from the phrasing of the question.
    """

    active = getattr(case_evidence_source, "active_component_ids_by_modality", None)
    if active is None:
        return ()
    modalities = {modality for modality, _components in active}
    named = tuple(modality for modality in ("disk", "pcap") if modality in modalities)
    return named if len(named) == 2 else ()
def _receipt_covered_modalities(
    records: list[dict[str, object]],
    *,
    case_id: str,
) -> frozenset[str]:
    """Return receipt-valid DEV source modalities actually queried in this run."""

    covered: set[str] = set()
    for record in records:
        result = _validated_continuation_result(record)
        if result is None or result.provenance.case_id != case_id:
            continue
        modality = result.provenance.source.attributes.get("active_modality")
        if modality in {"disk", "pcap"}:
            covered.add(cast(str, modality))
    return frozenset(covered)
def _direct_tool_modality(tool_name: str) -> str | None:
    """Map a direct case-evidence tool to the source modality it parses."""

    if tool_name in _REFERENCE_TOOLS or tool_name in _HOST_PATH_TOOLS or tool_name == "decode":
        return None
    if tool_name in _MEMORY_TOOLS:
        return "memory"
    if tool_name in _PCAP_TOOLS:
        return "pcap"
    return "disk"
def _specific_coverage_tool(
    tools: list,
    *,
    modality: str,
) -> str | None:
    """Select one unambiguous relevant visible tool without supplying arguments.

    The instrument is never chosen from a keyword in the question: doing so would
    let the harness pick the forensic method from the phrasing of the task.  A tool
    is forced only when the modality exposes a fixed single parser (``pcap_query``
    for a capture) or exactly one visible parser overall; otherwise the gate does
    not guess.
    """

    names = sorted(tool.name for tool in tools if _direct_tool_modality(str(tool.name)) == modality)
    if modality == "pcap" and "pcap_query" in names:
        return "pcap_query"
    return names[0] if len(names) == 1 else None
