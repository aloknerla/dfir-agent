"""Stable telemetry shape retained after the memory-corroboration arm was withdrawn.

The arm was gated on a regular expression over the QUESTION text, so it fired
only when a task was worded a particular way.  Its single forensic call,
``memory_malware_scan(scope='all_candidates')``, also keyed on an argument shape
the consolidated surface no longer offers (the operation is
``scan_all_candidates``), so every activation burned a dispatch on a refused call
and then cleared the run's draft.  With no evidence-driven trigger on the shipped
surface, only the stable metrics shape survives, so a run that carries the
disabled arm still records why it did nothing.
"""

from __future__ import annotations

_MEMORY_INJECTION_CORROBORATION_METRICS_SCHEMA_ID = (
    "forensic.memory-injection-corroboration-metrics.v1"
)


def _empty_memory_injection_corroboration_metrics(*, enabled: bool) -> dict[str, object]:
    return {
        "schema_id": _MEMORY_INJECTION_CORROBORATION_METRICS_SCHEMA_ID,
        "enabled": enabled,
        "activated": False,
        "decision": "not_evaluated" if enabled else "arm_disabled",
        "receipt_valid_malfind_results": 0,
        "ambiguous_malfind_candidate_count": 0,
        "receipt_valid_all_candidate_scans": 0,
        "scan_executed": False,
        "scan_complete": False,
        "selection_status": None,
        "completed": False,
    }
