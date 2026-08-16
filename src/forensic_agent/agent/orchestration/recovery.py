"""Bounded deterministic recovery phases for an investigation."""

from __future__ import annotations

from contextlib import nullcontext

from langchain_core.messages import HumanMessage
from langgraph.errors import GraphRecursionError

from forensic_agent.agent.answer_format import (
    defers_to_a_prior_answer,
    is_operator_clarification_request,
    reject_internal_model_output,
    reports_pagination_progress_instead_of_finding,
)
from forensic_agent.agent.deterministic_recovery import (
    _active_cross_source_disk_pcap,
    _follow_memory_query_pagination,
    _follow_unique_content_continuation,
    _follow_unique_match_with_continuation,
    _memory_pagination_is_blocked,
    _pending_final_tool_call,
    _receipt_covered_modalities,
    _receipt_valid_case_result_count,
    _recover_pending_tool_call,
    _reference_recovery_tool_candidates,
    _specific_coverage_tool,
)
from forensic_agent.agent.direct_answer import (
    ATOMIC_DIRECT_TERMINAL_REQUEST,
    is_atomic_direct_answer,
    is_single_direct_factual_question,
)
from forensic_agent.agent.execution_budget import _DispatchDenied
from forensic_agent.agent.execution_dispatch import _final_ai_text
from forensic_agent.agent.orchestration.state import (
    InvestigationConfig,
    InvestigationState,
    PreparedRuntime,
)
from forensic_agent.agent.recovery.coverage_bound import bound_stated_for, unread_region_labels
from forensic_agent.agent.recovery.pending_tool_recovery import (
    MALFORMED_FINAL_CALL_DECISIONS,
    close_refused_tool_calls,
    correct_malformed_final_tool_call,
)
from forensic_agent.agent.recovery.premature_absence import (
    absence_scoped_to_complete_record,
    answer_claims_absence,
)
from forensic_agent.agent.recovery.result_frontier import result_navigation_metrics
from forensic_agent.agent.structured_answer import (
    STRUCTURED_TERMINAL_REQUEST,
    is_segment_document,
    segment_document_response_format,
)
from forensic_agent.agent.tool_taxonomy import STORED_RESULT_NAVIGATION_TOOLS

#: The reserved terminal request as it has always been worded.  Held as a
#: constant beside the structured one so the two forms sit side by side and a run
#: without the answer binding still reaches this exact text.
_PROSE_TERMINAL_REQUEST = (
    "Stop investigating. Based ONLY on the tool results above, answer the original "
    "question now using the FINAL ANSWER format in the system prompt. If the evidence "
    "does not establish the requested answer, say so concisely."
)


def _enforce_terminal_tool_call_state(state: InvestigationState) -> None:
    """Fail closed when the last model response still requests a tool."""

    (
        _remaining_call,
        remaining_decision,
        remaining_count,
        remaining_invalid,
    ) = _pending_final_tool_call(state.messages)
    state.pending_tool_recovery_metrics.update(
        {
            "final_state_decision": remaining_decision,
            "final_state_pending_call_count": remaining_count,
            "final_state_invalid_call_count": remaining_invalid,
        }
    )
    if remaining_decision != "no_unresolved_final_tool_call":
        state.pending_tool_recovery_metrics["completed"] = False
        if not state.pending_tool_recovery_blocked:
            state.pending_tool_recovery_metrics["decision"] = "final_state_unresolved_tool_call"
        state.pending_tool_recovery_blocked = True
        state.final = ""


def _unusable_terminal_draft(config: InvestigationConfig, state: InvestigationState) -> bool:
    """Whether the run reached the end without a draft it is able to publish.

    One situation: the model ran out of steps mid-tooling, or terminated empty,
    and left nothing behind.

    Under the answer binding there is a second.  The model DID conclude — in
    prose, because the ordinary terminal answer falls out of the tool-bearing
    loop, where the shape can only be asked for and never held.  Prose assembles
    into nothing, so the run publishes nothing and discards a finding it already
    had.  A draft the assembler cannot use is not a draft this run has, which is
    why the two cases answer the same way: both send the run to the ONE request
    that carries no functions and can therefore be constrained to the shape.

    A draft already in the declared shape is left alone.  Asking again would
    spend a request re-obtaining what the run holds, and the reply the model has
    already given is the one it gave to the evidence.

    There is a third case: the draft is not empty and not malformed, it is the
    model asking the OPERATOR to clarify — "I am unable to identify which result
    you are referring to; could you point me to it?" — after a recovery advisory
    nudged it.  A request handed back to the operator states nothing about the
    evidence and is no more publishable than an empty draft, so it is sent to the
    same reserved terminal request, which concludes from what the run already
    gathered.

    A fourth: after a nudge sent the model to finish a registry page, its final
    turn was about that page and closed with "the original list of seven
    hacking-relevant programs remains unchanged" — an answer that points at a
    list from an earlier turn without carrying it.  A published answer has to
    stand on its own; one that defers to a prior turn is sent to the terminal
    request to state what it found in full.

    A fifth, the same failure seen from the other side: the nudge to finish a
    page or hear an unread region was answered with reading-bookkeeping — "the
    remaining entries at offset 50+ were only X", "coverage.complete=true", "sve
    nedovršene stranice su pročitane" — that recites how the results were
    paginated and never states the value the run already held in a completed tool
    result.  Such a draft carries the page cursor, not the finding, so it too is
    sent to the terminal request to restate what it found.
    """

    if not state.final.strip():
        return True
    if is_operator_clarification_request(state.final):
        return True
    if defers_to_a_prior_answer(state.final):
        return True
    if reports_pagination_progress_instead_of_finding(state.final):
        return True
    if _needs_atomic_direct_reformat(config, state):
        return True
    return config.deliver_model_result_envelope and not is_segment_document(state.final)


def _needs_atomic_direct_reformat(
    config: InvestigationConfig, state: InvestigationState
) -> bool:
    """Whether one bounded rewrite would turn a direct answer atomic.

    A sixth case, and unlike the five above it never withholds: a recovery arm
    that re-drove the model (to finish a page, to hear an unread region) took the
    model's acknowledgement of that nudge — "I have now read everything", "the
    list is complete" — as the new conclusion, and the found value it prefixes or
    replaces is lost to reading-narration.  For a SINGLE direct factual question
    the published answer should be one plain sentence carrying only the fact, so
    a draft that reads as narration, source recital, a second appended fact, or
    several sentences is sent to the reserved terminal request for one clean
    restatement from the same gathered evidence.

    This only STEERS.  There is no publication gate keyed to it: if the one
    rewrite is not atomic either, the draft is still published (verified, or with
    the keep-or-mark caveat) — never discarded on its shape.  It is scoped to the
    verified arm and to the narrow single-question classifier so it cannot fire
    on list, multipart or "with its source" questions whose honest answer is not
    one bare fact.
    """

    if not config.verify or config.deliver_model_result_envelope:
        return False
    if not is_single_direct_factual_question(config.question):
        return False
    normalized, _metrics = reject_internal_model_output(state.final)
    if not normalized:
        return False
    from forensic_agent.reliability.verify import build_verification_claims

    claims = build_verification_claims(normalized)
    return not is_atomic_direct_answer(normalized, claim_count=len(claims))


def _should_reissue_forced_final(
    *, atomic_direct_reformat: bool, still_unusable: bool
) -> bool:
    """Reserve the reasoning-relieved re-issue for the missing-draft recovery.

    The relief exists for a turn that spent its whole budget reasoning and wrote
    no answer.  A bounded atomic rewrite is a different job — the answer already
    exists, it is only too verbose — so it gets exactly one corrective turn and
    never the second, relieved one.
    """

    return still_unusable and not atomic_direct_reformat


def _keep_finding_or_withhold_over_coverage_gap(
    runtime: PreparedRuntime,
    state: InvestigationState,
    *,
    blocked_attr: str,
    metrics: dict[str, object],
) -> None:
    """Decide what a coverage gate does with the draft it was about to clear.

    Both of this module's coverage gates could end a run by setting
    ``state.final = ""`` when the model HAD found the answer: the gate read only
    that the examination was not exhaustive and threw the finding away.  NIST SP
    800-86's analysis phase and ACPO Principle 4 both say the opposite: an
    examiner who found the answer records it AND states the scope they did not
    examine; a stated, justifiable bound — not withholding — is what guards
    against overreach.  This extends the absence-gate disposition in
    :mod:`forensic_agent.agent.orchestration.finalization` to these two gates.

    So the disposition turns on what the draft's ANSWER actually is, read by the
    principal-claim variant of the project's one absence reading
    (:func:`answer_claims_absence`, beside :func:`report_asserts_absence` in the
    same module) together with :func:`absence_scoped_to_complete_record`:

    * A positive finding — the run found an answer and leads with it — is KEPT,
      even when an honest side clause ("no other X were found in <the artifact
      it examined>") follows it.  The wide whole-report reading would classify
      exactly such reports as absences and withhold findings that rested on
      complete listings.  The draft is left exactly as the model wrote it, so it
      still passes the raw/envelope binding that requires the published text to
      be the model's own response and, in the enabled arm, still faces identifier
      grounding; nothing here moves the answer past a downstream check.  The
      coverage limit is composed from the run's own records (the same shared
      helper the absence gate uses) and recorded.
    * An absence whose principal claim names an artifact some coverage-complete
      record examined in full is likewise KEPT: it rests on an exhausted
      examination, which is the only thing that can establish one, and the
      remaining gap is a bound to state beside it.
    * A BARE absence claim is NOT a finding — the run concluded something
      was not there over evidence it left unread and, asked to widen, kept the
      claim.  The coverage check still withholds it, exactly as before — and now
      records which finding closed the gate and what would satisfy it.
    * An empty draft is not a finding either and stays empty.

    The bound is stated, never appended to the draft here: appending would rewrite
    the model's response and fail the binding that keeps a published answer the
    model's own.  Where the published text does have a bound stated on it is after
    verification, in the finalization absence gate, which re-hashes the qualified
    text it produces.
    """

    restated = state.final if (state.final or "").strip() else ""
    # The disposition turns on the report's PRINCIPAL claim, not on any clause
    # anywhere in it: complete listings can establish the finding, the draft
    # leads with it, and a scoped side clause ("No other executable files were
    # found in the Recycle Bin") must not classify the whole report as an
    # absence and clear it.  A gate may hold only the claim that rests on what
    # went unexamined: a bare absence.  An absence whose principal claim names an
    # artifact some coverage-complete record examined in full rests on the
    # examined, so it is published and the remaining gap is stated as a bound
    # instead.
    bare_absence = restated and (
        answer_claims_absence(restated)
        and not absence_scoped_to_complete_record(restated, runtime.standardized_result_records)
    )
    if not restated or bare_absence:
        # No finding to preserve: an empty draft, or an absence the run concluded
        # over evidence it left unread and would not qualify.  The gate holds —
        # and the record says WHICH finding closed it and what would open it,
        # because a block naming only its gate tells the operator nothing.
        setattr(state, blocked_attr, True)
        state.final = ""
        metrics["publication_disposition"] = "withheld"
        blocking, satisfied_by = _blocking_finding_for(runtime, blocked_attr)
        metrics["blocking_finding"] = blocking
        metrics["satisfied_by"] = satisfied_by
        return
    # A positive finding: keep it, and state the coverage scope it was found under.
    regions = unread_region_labels(runtime.standardized_result_records, tools=runtime.tools)
    metrics["publication_disposition"] = "published_with_coverage_bound"
    metrics["unread_region_count"] = len(regions)
    metrics["coverage_bound"] = bound_stated_for(regions)


def _blocking_finding_for(runtime: PreparedRuntime, blocked_attr: str) -> tuple[str, str]:
    """Name what closed this gate and what would satisfy it, content-free.

    Region names are a closed vocabulary about the medium and tool/operation
    names are the run's own function surface, so both travel wherever the
    metrics do without carrying case material.  Offsets and totals are counts.
    """

    if blocked_attr == "evidence_region_blocked":
        regions = unread_region_labels(runtime.standardized_result_records, tools=runtime.tools)
        listed = ", ".join(sorted(regions)) or "an unread evidence region"
        return (
            f"unread evidence region(s): {listed}",
            "a read of those regions, or an answer that does not rest its absence claim on them",
        )
    from forensic_agent.agent.recovery.result_frontier import unconsumed_frontiers

    remaining, _pages_read, _stated = unconsumed_frontiers(runtime.standardized_result_records)
    open_frontiers = sorted(
        {
            f"{frontier.tool}.{frontier.operation}"
            for frontier in remaining
            if frontier.next_arguments is not None
        }
    )
    listed = ", ".join(open_frontiers) or "an enumeration left unfinished"
    return (
        f"unfinished enumeration(s): {listed}",
        "consuming the continuation those results themselves state, or an "
        "answer that does not rest its absence claim on them",
    )


def _run_deterministic_recovery(
    runtime: PreparedRuntime,
    state: InvestigationState,
) -> None:
    """Apply bounded recovery gates to the partial or completed investigation."""

    config = runtime.config
    llm = runtime.llm
    agent = runtime.agent
    tools = runtime.tools
    investigation_ledger = runtime.investigation_ledger

    budget = getattr(runtime, "execution_budget", None)
    tool_budget_closed_a_call = False
    if budget is not None and budget.tool_budget_exhausted():
        # No forensic function can run again, so re-attempting the refused call
        # would only spend a second rejection on the same ID.  Close every
        # unanswered call instead: the exchange becomes well formed, the run
        # keeps the evidence it already gathered, and the reserved terminal
        # request can still conclude from it.
        #
        # Spending the last permitted call is NOT itself a refusal.  A run that
        # used its ceiling exactly and then answered has nothing unresolved, so
        # it must keep its own finish reason rather than inherit an exhaustion
        # it never hit.
        # Only the calls this exhaustion actually reaches.  Navigation answers to
        # its own ceiling, so a run out of forensic dispatches may still read a
        # page of a result it already holds; closing that call would end
        # something that was still permitted.
        closed_messages, closure_metrics = close_refused_tool_calls(
            state.messages,
            reason="tool_budget_exhausted",
            closes=lambda name: name not in STORED_RESULT_NAVIGATION_TOOLS,
        )
        if closed_messages:
            state.messages.extend(closed_messages)
            state.tool_dispatch_closure_metrics = closure_metrics
            budget.record_control_closure(
                call_count=len(closed_messages),
                reason="tool_budget_exhausted",
            )
            state.dispatch_exhaustion_reason = state.dispatch_exhaustion_reason or "max_tool_calls"
            tool_budget_closed_a_call = True

    (
        recovered_tool_messages,
        state.pending_tool_recovery_metrics,
        pending_tool_exhaustion,
        state.pending_tool_recovery_blocked,
    ) = _recover_pending_tool_call(
        tools,
        state.messages,
        enabled=bool(config.recover_incomplete_run and runtime.tools_available),
    )
    state.messages.extend(recovered_tool_messages)
    if pending_tool_exhaustion is not None:
        state.dispatch_exhaustion_reason = (
            state.dispatch_exhaustion_reason or pending_tool_exhaustion
        )
    # A malformed final tool call is a recoverable model mistake: it executed
    # nothing and produced no evidence.  Return the failure once instead of
    # withholding a report the model may still be able to ground.
    if (
        state.pending_tool_recovery_blocked
        and config.recover_incomplete_run
        and runtime.tools_available
        and state.pending_tool_recovery_metrics.get("decision") in MALFORMED_FINAL_CALL_DECISIONS
    ):
        (
            state.messages,
            correction_exhaustion,
            state.pending_tool_recovery_blocked,
        ) = correct_malformed_final_tool_call(
            state.messages,
            state.pending_tool_recovery_metrics,
            llm=llm,
            agent=agent,
            investigation_ledger=investigation_ledger,
            recursion_limit=config.max_steps * 2 + 5,
        )
        if correction_exhaustion is not None:
            state.dispatch_exhaustion_reason = (
                state.dispatch_exhaustion_reason or correction_exhaustion
            )
    if recovered_tool_messages and not state.pending_tool_recovery_blocked:
        state.pending_tool_recovery_metrics["resume_attempted"] = True
        resume_requests_before = investigation_ledger.count
        resume_interrupted = False
        try:
            request_role = getattr(llm, "request_role", None)
            role_scope = request_role("investigation") if callable(request_role) else nullcontext()
            with role_scope:
                for chunk in agent.stream(
                    {"messages": list(state.messages)},
                    config={
                        # Same derivation as the investigation loop. The dispatch
                        # budget below is the real bound; a separate graph limit
                        # would only cut a resume the run still had budget for.
                        "recursion_limit": config.max_steps * 2 + 5,
                        "callbacks": [investigation_ledger],
                    },
                    stream_mode="values",
                ):
                    state.messages = chunk.get("messages", state.messages)
        except _DispatchDenied as exc:
            state.dispatch_exhaustion_reason = state.dispatch_exhaustion_reason or exc.reason
            state.pending_tool_recovery_metrics["decision"] = "resume_dispatch_budget_exhausted"
            resume_interrupted = True
            if exc.reason == "max_steps":
                state.recursion_limited = True
        except GraphRecursionError:
            state.recursion_limited = True
            state.pending_tool_recovery_metrics["decision"] = "resume_recursion_limit"
            resume_interrupted = True
        state.pending_tool_recovery_metrics["resume_model_requests"] = (
            investigation_ledger.count - resume_requests_before
        )
        remaining_call, remaining_decision, remaining_count, remaining_invalid = (
            _pending_final_tool_call(state.messages)
        )
        if remaining_call is not None or remaining_decision != "no_unresolved_final_tool_call":
            state.pending_tool_recovery_metrics.update(
                {
                    "decision": "resume_ended_with_unresolved_tool_call",
                    "pending_call_count": remaining_count,
                    "invalid_call_count": remaining_invalid,
                    "ambiguous_candidate_count": (
                        remaining_count
                        if remaining_decision == "multiple_unresolved_tool_calls"
                        else 0
                    ),
                }
            )
            state.pending_tool_recovery_blocked = True
        elif not state.pending_tool_recovery_blocked:
            if not resume_interrupted:
                state.pending_tool_recovery_metrics["decision"] = (
                    "recovered_with_equivalent_prior_result"
                    if state.pending_tool_recovery_metrics.get("result_reused") is True
                    else "recovered_after_pending_tool_execution"
                )
            state.pending_tool_recovery_metrics["completed"] = True
    state.final = "" if state.pending_tool_recovery_blocked else _final_ai_text(state.messages)
    if tool_budget_closed_a_call and config.recover_incomplete_run:
        # The last model turn was cut off mid-plan.  Whatever text an earlier turn
        # left behind is a working note, not a conclusion, so it must not survive
        # as the report by default.  Clearing it hands the decision to the
        # reserved terminal request, which sees the evidence and concludes — or
        # says the evidence is inconclusive.
        #
        # Only where that terminal request actually exists.  The declared raw arm
        # runs without it, so clearing there would discard the model's own draft
        # and put nothing in its place — a worse outcome than the interrupted
        # draft, and a silent change to that arm's behaviour.
        state.final = ""
    if (
        config.recover_incomplete_run
        and runtime.tools_available
        and not state.pending_tool_recovery_blocked
    ):
        # Every other arm here guards the conclusion, so none of them can see a run
        # that never reaches one: a run can issue the same disk-wide search
        # repeatedly over overlapping subtrees, spend its whole step budget and
        # publish nothing.  This reads the records for that and says so once.
        #
        # It reads FIRST, ahead of the three arms below, and the order is
        # load-bearing rather than cosmetic.  Each of them pushes the run to open a
        # region, widen a partial view or finish a page, so a run that OBEYS them
        # issues a call it has issued before — by instruction, not by circling.
        # Reading afterwards would put those continuations in this window and
        # reprove the run for doing exactly what it was just told to do.  Going
        # first is what keeps the window the run's own behaviour.
        from forensic_agent.agent.recovery.unproductive_repetition import (
            state_unproductive_repetition,
        )

        state.messages, repetition_exhaustion = state_unproductive_repetition(
            state.messages,
            runtime.standardized_result_records,
            state.unproductive_repetition_metrics,
            llm=llm,
            agent=agent,
            investigation_ledger=investigation_ledger,
            recursion_limit=config.max_steps * 2 + 5,
        )
        if repetition_exhaustion is not None:
            state.dispatch_exhaustion_reason = (
                state.dispatch_exhaustion_reason or repetition_exhaustion
            )
        if state.unproductive_repetition_metrics.get("nudge_delivered") is True:
            # Whatever the model said after hearing it is the newer conclusion, and
            # every arm below reads the report.  Only a non-empty reply replaces the
            # draft: this arm has nothing to withhold, so it must never be the
            # reason a run that held an answer ends up holding none.
            restated_final = _final_ai_text(state.messages)
            if restated_final.strip():
                state.final = restated_final
    if (
        config.recover_incomplete_run
        and config.standardize_tool_results
        and runtime.tools_available
        and not state.pending_tool_recovery_blocked
    ):
        # Which regions of the medium went unread is a fact only the runtime
        # holds, and a run that read one region has no occasion to notice it.
        # Stated BEFORE the coverage recheck below: never having opened a region
        # is the more basic omission, and whatever the model gathers in response
        # is then evidence that recheck gets to read.
        from forensic_agent.agent.recovery.evidence_region_advisory import (
            empty_evidence_region_metrics,
            state_unread_evidence_regions,
        )

        if not config.evidence_region_advisory:
            # When the nudge is off it addresses the model not at all, and the
            # coverage row reads arm_disabled — the same shape a run that was
            # never eligible records — rather than the not_evaluated the
            # eligible-but-silent run leaves.
            state.evidence_region_metrics = empty_evidence_region_metrics(enabled=False)
        else:
            (
                state.messages,
                region_exhaustion,
                region_omission_survives,
            ) = state_unread_evidence_regions(
                state.messages,
                runtime.standardized_result_records,
                tools,
                state.final,
                state.evidence_region_metrics,
                llm=llm,
                agent=agent,
                investigation_ledger=investigation_ledger,
                recursion_limit=config.max_steps * 2 + 5,
            )
            if region_exhaustion is not None:
                state.dispatch_exhaustion_reason = (
                    state.dispatch_exhaustion_reason or region_exhaustion
                )
            if state.evidence_region_metrics.get("statement_delivered") is True:
                # Whatever the model said after hearing the fact is the newer
                # conclusion, whichever way the loop then ended.
                restated_final = _final_ai_text(state.messages)
                if restated_final.strip():
                    state.final = restated_final
            if region_omission_survives:
                # It kept concluding over a region that could have shown
                # otherwise.  A bare absence there is withheld as before; a report
                # that found the answer is kept, with its coverage scope stated,
                # rather than cleared to empty.
                _keep_finding_or_withhold_over_coverage_gap(
                    runtime,
                    state,
                    blocked_attr="evidence_region_blocked",
                    metrics=state.evidence_region_metrics,
                )
    if (
        config.recover_incomplete_run
        and runtime.tools_available
        and not state.pending_tool_recovery_blocked
    ):
        # A negative finding drawn from a view that reported its own coverage as
        # partial is a premature conclusion, not a result. The tools already said
        # so; this only makes the run act on it while it still has budget.
        from forensic_agent.agent.recovery.premature_absence import (
            recheck_premature_absence,
        )

        state.messages, absence_exhaustion = recheck_premature_absence(
            state.messages,
            runtime.standardized_result_records,
            state.final,
            state.premature_absence_metrics,
            llm=llm,
            agent=agent,
            investigation_ledger=investigation_ledger,
            recursion_limit=config.max_steps * 2 + 5,
        )
        if absence_exhaustion is not None:
            state.dispatch_exhaustion_reason = (
                state.dispatch_exhaustion_reason or absence_exhaustion
            )
        if state.premature_absence_metrics.get("decision") == "rechecked":
            rechecked_final = _final_ai_text(state.messages)
            state.premature_absence_metrics["report_changed"] = (
                rechecked_final.strip() != (state.final or "").strip()
            )
            if rechecked_final.strip():
                state.final = rechecked_final
    if (
        config.recover_incomplete_run
        and config.standardize_tool_results
        and runtime.tools_available
        and not state.pending_tool_recovery_blocked
    ):
        # Last of the three, and the only one that keeps asking.  The region
        # statement covers a region never opened at all and the recheck asks once
        # about an absence drawn from partial coverage; both may have sent the
        # model back to the evidence, and this reads what the records look like
        # AFTER they did.  What it holds to is narrower and harder: an
        # examination the run's own results show unfinished, that the run could
        # still finish, is a reason to continue — and conceding it in the report
        # is not finishing it.
        from forensic_agent.agent.recovery.unfinished_examination import (
            state_unfinished_examinations,
        )

        (
            state.messages,
            unfinished_exhaustion,
            unfinished_survives,
        ) = state_unfinished_examinations(
            state.messages,
            runtime.standardized_result_records,
            state.final,
            state.unfinished_examination_metrics,
            llm=llm,
            agent=agent,
            investigation_ledger=investigation_ledger,
            recursion_limit=config.max_steps * 2 + 5,
        )
        if unfinished_exhaustion is not None:
            state.dispatch_exhaustion_reason = (
                state.dispatch_exhaustion_reason or unfinished_exhaustion
            )
        if state.unfinished_examination_metrics.get("statement_delivered") is True:
            # Whatever the model said after hearing the fact is the newer
            # conclusion, whichever way the loop then ended.
            restated_final = _final_ai_text(state.messages)
            if restated_final.strip():
                state.final = restated_final
        if unfinished_survives:
            # It kept concluding over an examination it could have finished and
            # had the budget to finish.  A bare absence over that gap is withheld
            # as before; a report that found the answer is kept, with its coverage
            # scope stated, rather than cleared to empty.
            _keep_finding_or_withhold_over_coverage_gap(
                runtime,
                state,
                blocked_attr="unfinished_examination_blocked",
                metrics=state.unfinished_examination_metrics,
            )
    if (
        config.verify
        and config.standardize_tool_results
        and config.verification_fail_closed
        and not config.autonomous_tool_selection
        and not state.pending_tool_recovery_blocked
    ):
        case_results_before = _receipt_valid_case_result_count(
            runtime.standardized_result_records,
            case_id=runtime.effective_case_id,
        )
        state.reference_evidence_recovery_metrics["case_results_before"] = case_results_before
        state.reference_evidence_recovery_metrics["case_results_after"] = case_results_before
        state.reference_evidence_recovery_metrics["tool_results_seen"] = len(
            runtime.standardized_result_records
        )
        if case_results_before:
            state.reference_evidence_recovery_metrics["decision"] = "case_evidence_already_present"
        else:
            (
                candidates,
                valid_references,
                candidate_source,
            ) = _reference_recovery_tool_candidates(
                tools,
                runtime.standardized_result_records,
            )
            state.reference_evidence_recovery_metrics.update(
                {
                    "activated": True,
                    "receipt_valid_reference_results": valid_references,
                    "candidates_seen": len(candidates),
                    "candidate_source": candidate_source,
                }
            )
            state.final = ""  # a draft without case evidence can never become a finding
            if not candidates:
                if candidate_source == "reference_result":
                    # A reference named a parser this surface does not expose:
                    # there is a specific instrument to force and it is missing.
                    state.reference_evidence_recovery_metrics["decision"] = (
                        "no_unambiguous_reference_parser"
                    )
                    state.reference_evidence_recovery_blocked = True
                elif candidate_source == "existing_tool_result":
                    state.reference_evidence_recovery_metrics["decision"] = (
                        "existing_tool_result_not_usable"
                    )
                    state.reference_evidence_recovery_blocked = True
                else:
                    # No tool result at all and no reference to act on.  There is
                    # nothing to force, and the instrument is never taken from the
                    # question wording, so the run reaches the reserved concluding
                    # turn and reports what the (absent) evidence establishes
                    # rather than being blocked outright.
                    state.reference_evidence_recovery_metrics["decision"] = (
                        "no_reference_evidence_to_recover"
                    )
            elif len(candidates) != 1:
                state.reference_evidence_recovery_metrics.update(
                    {
                        "decision": "ambiguous_reference_parsers",
                        "ambiguous_candidate_count": len(candidates),
                    }
                )
                state.reference_evidence_recovery_blocked = True
            else:
                forced_tool = candidates[0]
                state.reference_evidence_recovery_metrics.update(
                    {
                        "forced_tool": forced_tool,
                        "recovery_attempted": True,
                    }
                )
                recovery_instruction = (
                    "The investigation cannot finish with reference knowledge alone. "
                    "The first ranked, receipt-valid artifact reference identifies "
                    f"{forced_tool} as the evidence-reading parser. Continue the original "
                    "investigation with exactly that tool. Choose arguments only from the "
                    "original question, the reference result, and the visible tool schema. "
                    "No expected value or answer is supplied. Then report only what the "
                    "case-evidence result establishes; if the call cannot establish it, "
                    "state that the evidence is inconclusive."
                )
                recovery_input = list(state.messages) + [HumanMessage(recovery_instruction)]
                recovery_requests_before = investigation_ledger.count
                try:
                    request_role = getattr(llm, "request_role", None)
                    role_scope = (
                        request_role("investigation") if callable(request_role) else nullcontext()
                    )
                    force_next = getattr(llm, "force_next_tool_choice", None)
                    if not callable(force_next):
                        raise RuntimeError(
                            "reference-evidence recovery lacks a specific tool-choice gate"
                        )
                    with role_scope, force_next(forced_tool):
                        recovered = agent.invoke(
                            {"messages": recovery_input},
                            config={
                                "recursion_limit": 8,
                                "callbacks": [investigation_ledger],
                            },
                        )
                    state.messages = recovered["messages"]
                except _DispatchDenied as exc:
                    state.dispatch_exhaustion_reason = (
                        state.dispatch_exhaustion_reason or exc.reason
                    )
                state.reference_evidence_recovery_metrics["recovery_model_requests"] = (
                    investigation_ledger.count - recovery_requests_before
                )
                case_results_after = _receipt_valid_case_result_count(
                    runtime.standardized_result_records,
                    case_id=runtime.effective_case_id,
                )
                state.reference_evidence_recovery_metrics["case_results_after"] = case_results_after
                if case_results_after <= case_results_before:
                    state.reference_evidence_recovery_metrics["decision"] = "recovery_incomplete"
                    state.reference_evidence_recovery_blocked = True
                    state.final = ""
                else:
                    state.reference_evidence_recovery_metrics["decision"] = (
                        "recovered_case_evidence"
                    )
                    new_messages = state.messages[len(recovery_input) :]
                    state.final = _final_ai_text(new_messages)
    if (
        config.verify
        and config.standardize_tool_results
        and not config.autonomous_tool_selection
        and not state.pending_tool_recovery_blocked
    ):
        (
            memory_page_messages,
            state.memory_pagination_metrics,
            memory_pagination_exhaustion,
        ) = _follow_memory_query_pagination(
            tools,
            runtime.standardized_result_records,
        )
        state.messages.extend(memory_page_messages)
        if state.memory_pagination_metrics.get("activated") is True:
            state.final = ""
        state.memory_pagination_blocked = _memory_pagination_is_blocked(
            state.memory_pagination_metrics
        )
        if state.memory_pagination_blocked:
            state.final = ""
        if memory_pagination_exhaustion is not None:
            state.dispatch_exhaustion_reason = (
                state.dispatch_exhaustion_reason or memory_pagination_exhaustion
            )
        (
            continuation_messages,
            state.continuation_metrics,
            continuation_exhaustion,
        ) = _follow_unique_content_continuation(
            tools,
            runtime.standardized_result_records,
        )
        state.messages.extend(continuation_messages)
        if continuation_exhaustion is not None:
            state.dispatch_exhaustion_reason = (
                state.dispatch_exhaustion_reason or continuation_exhaustion
            )
    if (
        config.enforce_explicit_multisource_coverage
        and not state.pending_tool_recovery_blocked
        and not state.memory_pagination_blocked
    ):
        named_modalities = _active_cross_source_disk_pcap(config.case_evidence_source)
        state.multisource_coverage_metrics["named_modalities"] = list(named_modalities)
        if not named_modalities:
            # The gate applies by what the case actually binds, never by what the
            # question mentions.  Coverage across a disk and a capture is owed only
            # when the case holds both; a single-source case has no cross-source
            # obligation and is left to publish, so the instrument is never derived
            # from a noun in the task.
            state.multisource_coverage_metrics["decision"] = "case_not_cross_source_disk_pcap"
        else:
            covered_before = _receipt_covered_modalities(
                runtime.standardized_result_records,
                case_id=runtime.effective_case_id,
            )
            missing_before = sorted(set(named_modalities) - covered_before)
            state.multisource_coverage_metrics.update(
                {
                    "covered_before": sorted(covered_before),
                    "missing_before": missing_before,
                }
            )
            if not missing_before:
                state.multisource_coverage_metrics["decision"] = "already_satisfied"
                state.multisource_coverage_metrics["covered_after"] = sorted(covered_before)
            elif len(missing_before) != 1:
                state.multisource_coverage_metrics["activated"] = True
                state.multisource_coverage_metrics["decision"] = "missing_modality_ambiguous"
                state.multisource_coverage_metrics["missing_after"] = missing_before
                state.multisource_coverage_blocked = True
                state.final = ""
            else:
                missing_modality = missing_before[0]
                coverage_tool = _specific_coverage_tool(
                    tools,
                    modality=missing_modality,
                )
                state.multisource_coverage_metrics["activated"] = True
                state.multisource_coverage_metrics["forced_tool"] = coverage_tool
                if coverage_tool is None:
                    state.multisource_coverage_metrics["decision"] = (
                        "no_unambiguous_missing_modality_tool"
                    )
                    state.multisource_coverage_metrics["missing_after"] = missing_before
                    state.multisource_coverage_blocked = True
                    state.final = ""
                else:
                    state.multisource_coverage_metrics["recovery_attempted"] = True
                    state.final = ""  # invalidate any draft that skipped a named source
                    recovery_input = list(state.messages) + [
                        HumanMessage(
                            "The explicit cross-source coverage gate cannot accept a final "
                            f"answer yet: no receipt-valid {missing_modality} evidence result "
                            "has been gathered for the original question. Continue the same "
                            f"investigation by using {coverage_tool} for one relevant check of "
                            f"the named {missing_modality} source. Choose the arguments from "
                            "the original question and the visible tool contract; no expected "
                            "answer is supplied. Then interpret the result and provide a new "
                            "final conclusion, or state that the evidence is inconclusive."
                        )
                    ]
                    recovery_requests_before = investigation_ledger.count
                    try:
                        request_role = getattr(llm, "request_role", None)
                        role_scope = (
                            request_role("investigation")
                            if callable(request_role)
                            else nullcontext()
                        )
                        force_next = getattr(llm, "force_next_tool_choice", None)
                        if not callable(force_next):
                            raise RuntimeError(
                                "explicit multi-source coverage lacks a specific tool-choice gate"
                            )
                        with role_scope, force_next(coverage_tool):
                            recovered = agent.invoke(
                                {"messages": recovery_input},
                                config={
                                    # Same derivation as the investigation
                                    # loop; the dispatch budget is the bound.
                                    "recursion_limit": config.max_steps * 2 + 5,
                                    "callbacks": [investigation_ledger],
                                },
                            )
                        state.messages = recovered["messages"]
                    except _DispatchDenied as exc:
                        state.dispatch_exhaustion_reason = (
                            state.dispatch_exhaustion_reason or exc.reason
                        )
                    state.multisource_coverage_metrics["recovery_model_requests"] = (
                        investigation_ledger.count - recovery_requests_before
                    )
                    covered_after = _receipt_covered_modalities(
                        runtime.standardized_result_records,
                        case_id=runtime.effective_case_id,
                    )
                    missing_after = sorted(set(named_modalities) - covered_after)
                    state.multisource_coverage_metrics["covered_after"] = sorted(covered_after)
                    state.multisource_coverage_metrics["missing_after"] = missing_after
                    if missing_after:
                        state.multisource_coverage_metrics["decision"] = "recovery_incomplete"
                        state.multisource_coverage_blocked = True
                        state.final = ""
                    else:
                        state.multisource_coverage_metrics["decision"] = "recovered"
                        new_messages = state.messages[len(recovery_input) :]
                        state.final = _final_ai_text(new_messages)
    if (
        config.verify
        and config.standardize_tool_results
        and not config.autonomous_tool_selection
        and not state.pending_tool_recovery_blocked
        and not state.memory_pagination_blocked
        and not state.multisource_coverage_blocked
        and not state.reference_evidence_recovery_blocked
        and _active_cross_source_disk_pcap(config.case_evidence_source) == ("disk", "pcap")
    ):
        (
            match_messages,
            state.match_with_continuation_metrics,
            match_exhaustion,
        ) = _follow_unique_match_with_continuation(
            tools,
            runtime.standardized_result_records,
        )
        state.messages.extend(match_messages)
        if match_exhaustion is not None:
            state.dispatch_exhaustion_reason = state.dispatch_exhaustion_reason or match_exhaustion
            state.match_with_continuation_blocked = True
            state.final = ""
    elif (
        config.verify
        and config.standardize_tool_results
        and not state.pending_tool_recovery_blocked
    ):
        state.match_with_continuation_metrics["decision"] = (
            "disabled_for_autonomous_tool_selection"
            if config.autonomous_tool_selection
            else "case_not_cross_source_disk_pcap"
            if not state.multisource_coverage_blocked
            else "multisource_coverage_blocked"
        )
    if (
        _unusable_terminal_draft(config, state)
        and config.recover_incomplete_run
        and not state.pending_tool_recovery_blocked
        and not state.memory_pagination_blocked
        and not state.multisource_coverage_blocked
        and not state.match_with_continuation_blocked
        and not state.reference_evidence_recovery_blocked
        and not state.memory_injection_corroboration_blocked
        and not state.evidence_region_blocked
        and not state.unfinished_examination_blocked
    ):
        state.forced_final = True
        # Model ran out of steps mid-tooling, terminated empty, or — under the
        # binding — answered the tool-bearing loop in prose, which assembles into
        # nothing. Force a grounded conclusion from the evidence already gathered
        # (bounded so it cannot loop).
        #
        # Where the answer is assembled, the shape of this reply is not the
        # model's to choose: the provider is asked to hold it to the same document
        # the assembler accepts.  A transport that cannot be asked, or a run
        # without the binding, reaches the request it always did.  The terminal
        # request text itself is fixed: where the answer is assembled it asks for
        # the thing that assembles (prose there would leave nothing to bind);
        # where a single direct question was answered with narration, it asks for
        # one clean sentence; otherwise it asks for prose.
        atomic_direct_reformat = _needs_atomic_direct_reformat(config, state)
        terminal_request = (
            STRUCTURED_TERMINAL_REQUEST
            if config.deliver_model_result_envelope
            else ATOMIC_DIRECT_TERMINAL_REQUEST
            if atomic_direct_reformat
            else _PROSE_TERMINAL_REQUEST
        )
        # Built once from the evidence the run gathered, so the reasoning-relieved
        # re-issue below concludes from exactly what the first attempt saw — not
        # from that attempt's own truncated, answerless turn.
        terminal_input = list(state.messages) + [HumanMessage(terminal_request)]
        constraint: object | None = None

        def _conclude_from_gathered_evidence(*, relieve_reasoning: bool) -> None:
            nonlocal constraint
            try:
                request_role = getattr(llm, "request_role", None)
                role_scope = (
                    request_role("forced_final") if callable(request_role) else nullcontext()
                )
                constrain = getattr(llm, "constrain_response_format", None)
                format_scope = (
                    constrain(segment_document_response_format())
                    if config.deliver_model_result_envelope and callable(constrain)
                    else nullcontext()
                )
                relieve = getattr(llm, "relieve_reasoning", None)
                # Only the re-issue asks for relief, and only where the transport
                # can grant it: a stand-in without the seam reasons as before, and
                # a re-issue that cannot relieve the budget honestly ends empty.
                reasoning_scope = (
                    relieve() if relieve_reasoning and callable(relieve) else nullcontext()
                )
                with role_scope, format_scope as scope_constraint, reasoning_scope:
                    res2 = agent.invoke(
                        {"messages": list(terminal_input)},
                        config={
                            "recursion_limit": 6,
                            "callbacks": [runtime.forced_final_ledger],
                        },
                    )
                if scope_constraint is not None:
                    constraint = scope_constraint
                state.messages = res2["messages"]
                state.final = _final_ai_text(state.messages) or state.final
            except _DispatchDenied as exc:
                state.dispatch_exhaustion_reason = state.dispatch_exhaustion_reason or exc.reason
            except Exception:
                if config.standardize_tool_results:
                    raise

        _conclude_from_gathered_evidence(relieve_reasoning=False)
        if _should_reissue_forced_final(
            atomic_direct_reformat=atomic_direct_reformat,
            still_unusable=_unusable_terminal_draft(config, state),
        ):
            # The reserved concluding turn returned no draft this run can publish.
            # On a reasoning model the ordinary cause is a turn that spent its whole
            # bounded output budget reasoning and stopped before writing the answer
            # (finish_reason "length", no content) — a finding the run already
            # gathered, lost to the form of the turn meant to state it.  Give the
            # conclusion ONE clean, reasoning-relieved reserved turn from the same
            # evidence, so its full output budget reaches the answer.  This is still
            # the model concluding, still gated by grounding downstream; if it too
            # returns nothing groundable, an empty result is the honest outcome.
            # It cannot loop: it runs at most once, and only after the ordinary
            # attempt left nothing to publish.  A bounded atomic rewrite gets only
            # this first turn — the answer already exists, it was only verbose —
            # so the relieved re-issue stays reserved for the missing-draft case.
            _conclude_from_gathered_evidence(relieve_reasoning=True)
        # Whether the shape was constrained, refused by the provider, or never
        # asked for.  A run that published nothing and one that was never held to
        # the shape read identically without it, so the same symptom would be
        # investigated twice.
        state.structured_answer_metrics["response_format"] = getattr(
            constraint, "outcome", "not_requested"
        )
        # Two forced-final requests here means the reasoning-relieved re-issue ran;
        # the run ledger and oversight chain carry both, so the relief is visible
        # without a field of its own.
        state.forced_final_requests = runtime.forced_final_ledger.count

    if config.standardize_tool_results:
        # Read LAST, after every stage that may have executed further pages, so
        # what it reports is the frontier the run actually finished with.  It is
        # an observation, not a gate: it executes nothing and blocks nothing, and
        # it states — from the results themselves, for every domain operation —
        # where an enumeration stopped short.  Without it the run can only say
        # that for the two families a stage happens to recognise.
        state.result_navigation_metrics = result_navigation_metrics(
            runtime.standardized_result_records
        )

    # Every recovery phase may append a new model response.  Recheck the final
    # message after all of them so reference, multisource and forced-final paths
    # cannot publish prose from an unresolved or malformed tool call.
    _enforce_terminal_tool_call_state(state)
