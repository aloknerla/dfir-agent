"""Transactional coordinator for the investigation phases."""

from __future__ import annotations

from forensic_agent.agent.deterministic_recovery import (
    _empty_continuation_metrics,
    _empty_match_with_continuation_metrics,
    _empty_memory_injection_corroboration_metrics,
    _empty_memory_pagination_metrics,
    _empty_multisource_coverage_metrics,
    _empty_pending_tool_recovery_metrics,
    _empty_reference_evidence_recovery_metrics,
)
from forensic_agent.agent.identifier_grounding import empty_identifier_grounding_metrics
from forensic_agent.agent.orchestration.finalization import (
    _empty_final_answer_metrics,
    _finalize_report,
    _finalize_runtime,
    empty_unpublished_answer_metrics,
)
from forensic_agent.agent.orchestration.investigation import run_analysis_phase
from forensic_agent.agent.orchestration.recovery import (
    _run_deterministic_recovery,
)
from forensic_agent.agent.orchestration.state import (
    InvestigationState,
    PreparedRuntime,
)
from forensic_agent.agent.recovery.evidence_region_advisory import (
    empty_evidence_region_metrics,
)
from forensic_agent.agent.recovery.premature_absence import (
    empty_premature_absence_metrics,
)
from forensic_agent.agent.recovery.result_frontier import (
    empty_result_navigation_metrics,
)
from forensic_agent.agent.recovery.unfinished_examination import (
    empty_unfinished_examination_metrics,
)
from forensic_agent.agent.recovery.unproductive_repetition import (
    empty_unproductive_repetition_metrics,
)
from forensic_agent.agent.structured_answer import empty_structured_answer_metrics
from forensic_agent.agent.verifier_projection import _empty_verifier_metrics
from forensic_agent.core.evidence_source import EvidenceSourceChangedError
from forensic_agent.core.toolkit import cell_deadline


def _initial_runtime_state(runtime: PreparedRuntime) -> InvestigationState:
    """Create all terminally observable state before entering the custody boundary."""

    config = runtime.config
    return InvestigationState(
        messages=[],
        final="",
        evidence_integrity_error=None,
        verification_telemetry={"request_ledger": []},
        verification_evidence_present=False,
        verifier_metrics=_empty_verifier_metrics(
            activation_reason="arm_disabled" if not config.verify else "not_evaluated"
        ),
        final_answer_metrics=_empty_final_answer_metrics(
            verification_mode="enabled" if config.verify else "disabled"
        ),
        structured_answer_metrics=empty_structured_answer_metrics(
            enabled=config.deliver_model_result_envelope
        ),
        continuation_metrics=_empty_continuation_metrics(
            enabled=bool(config.verify and config.standardize_tool_results)
        ),
        pending_tool_recovery_metrics=_empty_pending_tool_recovery_metrics(
            enabled=bool(config.recover_incomplete_run and runtime.tools_available)
        ),
        tool_dispatch_closure_metrics={
            "schema_id": "forensic.tool-dispatch-closure-metrics.v1",
            "reason": None,
            "closed_call_count": 0,
            "closed_call_ids": [],
            "redispatched_call_count": 0,
        },
        reference_evidence_recovery_metrics=_empty_reference_evidence_recovery_metrics(
            enabled=bool(
                config.verify
                and config.standardize_tool_results
                and config.verification_fail_closed
            )
        ),
        match_with_continuation_metrics=_empty_match_with_continuation_metrics(
            enabled=bool(config.verify and config.standardize_tool_results)
        ),
        memory_injection_corroboration_metrics=(
            _empty_memory_injection_corroboration_metrics(
                enabled=config.ambiguous_memory_candidate_corroboration
            )
        ),
        memory_pagination_metrics=_empty_memory_pagination_metrics(
            enabled=bool(config.verify and config.standardize_tool_results)
        ),
        result_navigation_metrics=empty_result_navigation_metrics(
            # It reads standardized results, so it is meaningful exactly where
            # such results exist; it executes nothing, so it needs nothing else.
            enabled=bool(config.standardize_tool_results)
        ),
        multisource_coverage_metrics=_empty_multisource_coverage_metrics(
            enabled=config.enforce_explicit_multisource_coverage
        ),
        premature_absence_metrics=empty_premature_absence_metrics(
            enabled=bool(config.recover_incomplete_run)
        ),
        evidence_region_metrics=empty_evidence_region_metrics(
            # It reads recorded operations, so it is meaningful exactly where the
            # run records them; it speaks to the model, so it needs the recovery
            # arm's permission to address one.
            enabled=bool(config.recover_incomplete_run and config.standardize_tool_results)
        ),
        unfinished_examination_metrics=empty_unfinished_examination_metrics(
            # It reads the coverage and page blocks of standardized results, so
            # it is meaningful exactly where such results exist; it speaks to the
            # model, so it needs the recovery arm's permission to address one.
            enabled=bool(config.recover_incomplete_run and config.standardize_tool_results)
        ),
        unproductive_repetition_metrics=empty_unproductive_repetition_metrics(
            # It reads the recorded results and nothing else, so it needs no
            # standardization switch; it speaks to the model, so it needs the
            # recovery arm's permission to address one.
            enabled=bool(config.recover_incomplete_run)
        ),
        recursion_limited=False,
        investigation_restarts=0,
        forced_final=False,
        forced_final_requests=0,
        transient_midrun_error=False,
        dispatch_exhaustion_reason=None,
        multisource_coverage_blocked=False,
        match_with_continuation_blocked=False,
        reference_evidence_recovery_blocked=False,
        pending_tool_recovery_blocked=False,
        memory_injection_corroboration_blocked=False,
        memory_pagination_blocked=False,
        evidence_region_blocked=False,
        unfinished_examination_blocked=False,
        identifier_grounding_blocked=False,
        identifier_grounding_metrics=empty_identifier_grounding_metrics(enabled=True),
        unpublished_answer_metrics=empty_unpublished_answer_metrics(),
    )


def _run_execution_and_recovery(
    runtime: PreparedRuntime,
    state: InvestigationState,
) -> None:
    """Run the analysis phase and then the bounded deterministic recovery."""

    run_analysis_phase(runtime, state)
    _run_deterministic_recovery(runtime, state)


def _execute_runtime(runtime: PreparedRuntime) -> str | None:
    """Run all phases under a single transactional cleanup boundary."""

    state = _initial_runtime_state(runtime)
    budget = runtime.execution_budget
    # Bind every external process started in this cell to the cell's own
    # deadline. A tool ceiling measured in minutes must not keep a console cell
    # busy long after the cell's time is gone.
    deadline = budget.deadline_monotonic if budget is not None else None
    try:
        with cell_deadline(deadline):
            _run_execution_and_recovery(runtime, state)
            _finalize_report(runtime, state)
    finally:
        _finalize_runtime(runtime, state)
    if state.evidence_integrity_error is not None:
        raise EvidenceSourceChangedError(
            "evidence source runtime integrity failed; graph result is not scoreable"
        ) from state.evidence_integrity_error
    if runtime.config.verbose:
        for message in state.messages:
            for tool_call in getattr(message, "tool_calls", None) or []:
                print(f"[tool] {tool_call.get('name')}({tool_call.get('args')})")
        print("\n=== FINAL ANSWER ===\n", state.final or "")
    return state.final
