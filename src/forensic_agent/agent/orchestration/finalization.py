"""Report finalization, publication checks, cleanup, and telemetry."""

from __future__ import annotations

import time
from collections.abc import Mapping
from typing import TypeGuard

from forensic_agent.agent.answer_format import reject_internal_model_output
from forensic_agent.agent.evidence_regions import unread_regions
from forensic_agent.agent.execution_budget import _DispatchDenied, _DispatchPermit
from forensic_agent.agent.execution_dispatch import _final_ai_text
from forensic_agent.agent.identifier_grounding import check_identifier_grounding
from forensic_agent.agent.orchestration.state import (
    InvestigationState,
    PreparedRuntime,
)
from forensic_agent.agent.recovery.coverage_bound import bound_stated_for, unread_region_labels
from forensic_agent.agent.recovery.premature_absence import report_asserts_absence
from forensic_agent.agent.structured_answer import (
    assemble_structured_answer,
    model_authored_text,
)
from forensic_agent.agent.verifier_projection import _compact_verifier_evidence
from forensic_agent.core.evidence_source import EvidenceSourceError
from forensic_agent.core.repro import canonical_json, sha256_hex

_PUBLICATION_BLOCKERS = (
    "pending_tool_recovery_blocked",
    "multisource_coverage_blocked",
    "match_with_continuation_blocked",
    "reference_evidence_recovery_blocked",
    "memory_injection_corroboration_blocked",
    "memory_pagination_blocked",
    "evidence_region_blocked",
    "unfinished_examination_blocked",
    "identifier_grounding_blocked",
)


def _finalization_is_unblocked(state: InvestigationState) -> bool:
    """Return whether every deterministic recovery gate permits publication."""

    return not any(bool(getattr(state, name)) for name in _PUBLICATION_BLOCKERS)


def _a_reachable_region_is_unread(runtime: PreparedRuntime) -> bool:
    """Whether a region this run's own tools could open still went unread.

    Recomputed here from the records the run finished with rather than read off
    the advisory's row: recovery stages that ran after the advisory may have
    opened the region, and holding a report against a gap that has since been
    closed would withhold an answer this run had actually established.
    """

    names = tuple(
        name
        for name in (getattr(tool, "name", None) for tool in runtime.tools)
        if isinstance(name, str) and name
    )
    return bool(unread_regions(runtime.standardized_result_records, tools=names))


def _verifier_bundle_was_truncated(verifier_metrics: Mapping[str, object]) -> bool:
    """Whether the bundle the final check reasoned from lost evidence content.

    Both kinds of loss count: a result the ceiling refused to carry at all, and
    a result it shortened — a dropped attribute or row is content the verifier
    never saw any more than an omitted result is.  A reading that stayed
    bundle-level would let a truncated view carry unqualified negative
    conclusions.
    """

    if verifier_metrics.get("total_truncated") is True:
        return True
    # Within-result loss counts as truncation too: no result is dropped whole,
    # but the per-result share can silently drop the attributes and rows the
    # draft's claims rested on, and a bundle-level reading stays blind to it.
    for key in (
        "bundle_omitted_result_count",
        "per_result_truncated_count",
        "omitted_attribute_count",
    ):
        value = verifier_metrics.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            return True
    return False


def _absence_is_unestablished(
    runtime: PreparedRuntime, state: InvestigationState, report: str
) -> bool:
    """Whether this report asserts an absence nothing in this run established.

    One rule, applied to whoever wrote the report: absence is not established
    while a region that could refute it is unread, or while the evidence actually
    examined was truncated.  The project already holds its tools to this; a
    verifier drawing a negative conclusion from a bundle that admitted dropping
    results is the same error with more authority behind it.

    Deliberately the WIDE reading of the shared absence predicate: the coverage
    sentence belongs to every answer that contains a claim of nonexistence
    anywhere in it, side clause included, because the sentence bounds exactly
    "anything reported above as not present".  An answer with no such claim —
    a purely affirmative finding — gets no coverage sentence, where it would
    say nothing about the answer.  (The narrower principal-claim reading
    decides withhold-or-keep in the recovery gates, a different question.)

    It names a REGION and a byte ceiling — facts about this run — and never a
    tool, so it tells the model nothing about how to investigate.
    """

    if not report_asserts_absence(report):
        return False
    return _a_reachable_region_is_unread(runtime) or _verifier_bundle_was_truncated(
        state.verifier_metrics
    )


def verification_gap_stated_for(
    reason: str,
    *,
    unverified: int | None = None,
    claim_count: int | None = None,
    included: object = None,
    source: object = None,
    shortened: object = None,
) -> str:
    """Compose the marker that verification ended without a judgement.

    Composed by the runtime for the same reason every stated bound is: a marker
    the model writes is a marker it can get wrong.  The counts say how much of
    the evidence set the check actually saw.
    """

    if (
        reason == "contradicted"
        and isinstance(unverified, int)
        and isinstance(claim_count, int)
    ):
        # A stronger, explicit warning: the check judged something false, but it
        # is a probabilistic check that errs, so the finding is retained for the
        # examiner rather than withheld — with a clear instruction to confirm.
        return (
            f"The final check judged that the evidence contradicts {unverified} of "
            f"{claim_count} statements in this answer. That check is a probabilistic "
            "second opinion that can err — it has flagged correct derived values "
            "before — so the finding is retained for your review rather than "
            "withheld. Confirm it against the cited tool results before relying on "
            "it; the final assessment is yours."
        )
    if reason == "output_hygiene":
        return (
            "The final check flagged that this answer may carry process or reasoning "
            "commentary rather than only findings. The findings above are retained "
            "as the investigation reported them for your review."
        )
    if (
        reason == "insufficient_evidence"
        and isinstance(unverified, int)
        and isinstance(claim_count, int)
    ):
        cause = (
            f"the final check could not confirm {unverified} of {claim_count} "
            "claims against the evidence projection it was shown"
        )
    elif reason in ("incomplete_verification", "claim_coverage"):
        cause = "the final check did not return a verdict for every claim"
    elif reason == "cited_evidence_projection":
        cause = (
            "the final check's bounded evidence bundle could not retain the "
            "result content the answer cites"
        )
    elif reason == "cited_value_bound":
        cause = (
            "the answer cites more distinct values than the bounded evidence "
            "projection carries"
        )
    elif reason == "verifier_incomplete":
        cause = "the final check could not be completed for this answer"
    else:
        cause = "the final check ended without a verdict"
    counts = ""
    if isinstance(included, int) and isinstance(source, int):
        shortened_count = shortened if isinstance(shortened, int) else 0
        counts = (
            f" (bundle included {included} of {source} usable results; "
            f"{shortened_count} shortened)"
        )
    return (
        f"Verification of this answer could not be performed: {cause}{counts}. "
        "The findings above are retained as the investigation reported them, "
        "and no claim was judged false against evidence the check did not see."
    )


def _publish_draft_with_verification_gap(
    runtime: PreparedRuntime,
    state: InvestigationState,
    draft: str,
    draft_answer: str,
    *,
    gap_reason: str,
    unverified: int | None = None,
    claim_count: int | None = None,
) -> None:
    """Keep-or-mark: publish the draft when the check ended without a judgement.

    A verification that ends inconclusively — the bounded projection could not
    carry what the answer cites, or the verifier could not confirm a claim —
    has judged nothing false.  Discarding the whole answer for it hands the
    operator nothing and reads as a model failure when it is a bound of the
    check.  The draft is published with the gap stated instead, under the same
    deterministic gates a verified answer passes: it must be a genuine model
    response, every identifier it names must be grounded in retained results,
    and an absence claim still gets the coverage bound appended.  A judgement —
    a contradicted claim, leaked internal reasoning, an ungrounded identifier —
    never reaches this path.  Callers set the verification outcome first; this
    only decides whether the draft is handed over or withheld beside it.
    """

    metrics = state.final_answer_metrics
    # The same binding the raw arm applies: the published text must be the
    # surviving final AI text AND a genuine recorded model response, so an
    # orphan ledger row or a tampered draft cannot ride out on the gap marker.
    if draft != _final_ai_text(state.messages):
        state.verifier_metrics["draft_binding"] = "not_the_surviving_final_text"
        return
    if metrics.get("draft_report_sha256") not in _model_response_sha256s(runtime):
        state.verifier_metrics["draft_binding"] = "not_a_recorded_model_response"
        return

    allowed, state.identifier_grounding_metrics = check_identifier_grounding(
        draft_answer,
        runtime.standardized_result_records,
        case_id=runtime.effective_case_id,
        lineage=runtime.lineage,
    )
    metrics["identifier_grounding"] = "applied"
    if not allowed:
        state.identifier_grounding_blocked = True
        metrics.update(
            {
                "publication_outcome": "blocked_identifier_grounding",
                "accepted_source": "none",
                "accepted_report_sha256": None,
            }
        )
        return

    truncated = _verifier_bundle_was_truncated(state.verifier_metrics)
    included = state.verifier_metrics.get("included_results")
    omitted = state.verifier_metrics.get("bundle_omitted_result_count")
    usable = state.verifier_metrics.get("usable_case_results")
    source: int | None = None
    if isinstance(included, int) and isinstance(omitted, int):
        source = max(included + omitted, usable if isinstance(usable, int) else 0)
    shortened = state.verifier_metrics.get("per_result_truncated_count")

    qualified = draft_answer.rstrip()
    regions: tuple[str, ...] = ()
    if _absence_is_unestablished(runtime, state, draft_answer):
        regions = tuple(
            unread_region_labels(runtime.standardized_result_records, tools=runtime.tools)
        )
        bound = bound_stated_for(
            regions,
            bundle_truncated=truncated,
            bundle_included=included if isinstance(included, int) else None,
            bundle_source=source,
            bundle_shortened=shortened if isinstance(shortened, int) else None,
        )
        if bound:
            qualified = f"{qualified}\n\n{bound}"
    gap = verification_gap_stated_for(
        gap_reason,
        unverified=unverified,
        claim_count=claim_count,
        included=included if isinstance(included, int) else None,
        source=source,
        shortened=shortened if isinstance(shortened, int) else None,
    )
    qualified = f"{qualified}\n\n{gap}"
    state.final = qualified
    metrics.update(
        {
            "publication_outcome": "published_draft_verification_incomplete",
            "accepted_source": "investigation_model_draft",
            "published_text_origin": "investigation_model_draft",
            # The answer is the model's sentences; the appended gap marker (and
            # coverage bound, when one applies) was composed by the runtime, and
            # the publication outcome above is what records that.
            "published_text_authorship": "model_written",
            "accepted_report_sha256": sha256_hex(canonical_json({"report": qualified})),
            "unread_region_count": len(regions),
            "bundle_truncated": truncated,
        }
    )


def _verification_row_count(state: InvestigationState) -> int:
    """Count verification rows appended to the verification telemetry ledger."""

    rows = state.verification_telemetry.get("request_ledger")
    if not isinstance(rows, list):
        return 0
    return sum(1 for row in rows if isinstance(row, dict) and row.get("role") == "verification")


def _model_response_sha256s(runtime: PreparedRuntime) -> frozenset[str]:
    """Digests of every successful investigation/forced-final model response text.

    The raw arm accepts the model draft only when its digest is one of these,
    binding the accepted answer to a genuine model response recorded in the
    ledger.  Set membership (rather than the single last row) is deliberate: a
    rolled-back recovery re-run can leave an orphan model row in the shared
    ledger, so the *last* successful row is not reliably the surviving final
    answer — but the surviving draft is always some genuine model response
    recorded here, while a tampered draft matches none of them.
    """

    rows = list(runtime.investigation_ledger.entries) + list(runtime.forced_final_ledger.entries)
    digests: set[str] = set()
    for row in rows:
        if row.get("status") != "success":
            continue
        digest = row.get("response_content_sha256")
        if isinstance(digest, str) and digest:
            digests.add(digest)
    return frozenset(digests)


def _publication_gate_metrics(state: InvestigationState) -> dict[str, object]:
    """Return a content-free terminal publication decision for diagnostics."""

    blocked_gates = [name for name in _PUBLICATION_BLOCKERS if bool(getattr(state, name))]
    final_present = bool((state.final or "").strip())
    integrity_failed = state.evidence_integrity_error is not None
    return {
        "schema_id": "forensic.publication-gate-metrics.v1",
        "publication_allowed": not blocked_gates and final_present and not integrity_failed,
        "blocked_gates": blocked_gates,
        "final_present": final_present,
        "evidence_integrity_failed": integrity_failed,
    }


_UNPUBLISHED_ANSWER_SCHEMA_ID = "forensic.unpublished-answer-metrics.v1"

#: Every cause a run can reach with nothing published, as a closed vocabulary.
#: Nothing read from the evidence can travel in one of these: each names a
#: decision this run made about its own draft, which is why the cause is safe to
#: state wherever the failure is reported, an operator's screen included.
UNPUBLISHED_ANSWER_CAUSES = frozenset(
    {
        "published",
        "model_returned_no_draft",
        "draft_cleared_before_publication",
        "withheld_by_gate",
        "discarded_by_final_check",
        "draft_did_not_assemble",
        "draft_not_bound_to_a_model_response",
        "revoked_by_evidence_integrity",
        "unattributed",
    }
)


def empty_unpublished_answer_metrics() -> dict[str, object]:
    """Return the terminal publication-cause record before it is decided."""

    return {
        "schema_id": _UNPUBLISHED_ANSWER_SCHEMA_ID,
        "published": False,
        "cause": "unattributed",
        "model_draft_present": False,
        "draft_reached_publication": False,
        "blocked_gates": [],
        "examination_bound": None,
        "evidence_readings": 0,
    }


def _unpublished_answer_metrics(
    runtime: PreparedRuntime, state: InvestigationState
) -> dict[str, object]:
    """Say what became of this run's answer, never only that there is none.

    ``no_final_answer`` is one string standing for at least four different
    events: a failure can end on it naming no gate at all, so the record cannot
    distinguish a harness that discarded a finding from a model that never wrote
    one — the exact distinction on which "defect in this system" and "result
    about the model" turn.

    The decisive observation is that the surviving conversation still holds the
    model's own last text whatever any stage did to ``state.final``.  Reading both
    tells the two apart: ``model_draft_present`` is what the MODEL produced, and
    ``draft_reached_publication`` is what the publication path was handed.  True
    then false is a run whose finding this system threw away, and it is now one
    recorded field rather than an inference from the surrounding call list.
    """

    published = bool((state.final or "").strip())
    metrics = state.final_answer_metrics
    blocked_gates = [name for name in _PUBLICATION_BLOCKERS if bool(getattr(state, name))]
    model_draft_present = bool(_final_ai_text(state.messages).strip())
    # Set from ``state.final`` on entry to ``_finalize_report``, before any
    # publication path runs, so it reports what the publication path received
    # rather than what it decided.
    draft_reached_publication = metrics.get("draft_report_sha256") is not None
    cause: str
    if published:
        cause = "published"
    elif state.evidence_integrity_error is not None:
        cause = "revoked_by_evidence_integrity"
    elif blocked_gates:
        cause = "withheld_by_gate"
    elif not model_draft_present:
        cause = "model_returned_no_draft"
    elif not draft_reached_publication:
        # The model concluded and the publication path was handed nothing, so an
        # earlier stage cleared the draft.  Without a record this shape reads as
        # a model failure.
        cause = "draft_cleared_before_publication"
    elif metrics.get("verification_mode") == "enabled":
        cause = "discarded_by_final_check"
    elif metrics.get("verification_mode") == "runtime_assembly":
        cause = "draft_did_not_assemble"
    elif metrics.get("verification_mode") == "disabled":
        cause = "draft_not_bound_to_a_model_response"
    else:
        cause = "unattributed"
    return {
        "schema_id": _UNPUBLISHED_ANSWER_SCHEMA_ID,
        "published": published,
        "cause": cause,
        "model_draft_present": model_draft_present,
        "draft_reached_publication": draft_reached_publication,
        "blocked_gates": blocked_gates,
        "examination_bound": state.dispatch_exhaustion_reason,
        "evidence_readings": len(runtime.standardized_result_records),
    }


def _empty_final_answer_metrics(*, verification_mode: str) -> dict[str, object]:
    """Return the complete final-answer acceptance telemetry shape.

    A dedicated contract, deliberately separate from the verifier-input metrics:
    it records which of the two mutually exclusive final-answer paths ran and
    what, if anything, was accepted for publication.
    """

    return {
        "schema_id": "forensic.final-answer-metrics.v1",
        "verification_mode": verification_mode,
        "verification_outcome": "not_evaluated",
        "publication_outcome": "not_evaluated",
        "accepted_source": "none",
        "published_text_origin": "none",
        "verification_decision": "not_evaluated",
        "identifier_grounding": "not_evaluated",
        # Who produced the characters of the published text.  A deployment that
        # did not ask for assembly publishes model prose and used to say nothing
        # about it anywhere, so a reader of the record could only infer the
        # answer's authorship from which arm happened to be configured — and a
        # guarantee assumed to have held is worse than one known to be absent.
        "published_text_authorship": "not_evaluated",
        "verification_row_count": 0,
        "draft_report_sha256": None,
        "verifier_report_sha256": None,
        "accepted_report_sha256": None,
    }


def _publish_assembled_answer(
    runtime: PreparedRuntime, state: InvestigationState, draft: str
) -> None:
    """Assemble the published answer from the model's structured draft.

    The last step is a lookup, not another model call.  The draft is the model's
    own wording plus the delivery names of the values it wants stated; each name
    is re-checked against what this run actually handed the model, and the stored
    text is inserted.  Nothing is read afterwards, so no model sees the assembled
    answer and none can rewrite it.

    Anything that does not assemble publishes nothing.  A sentence built around a
    value the runtime could not produce is not a partial answer: it asserts
    exactly the thing that went unchecked.

    The draft is bound to a genuine model response the same way the raw arm binds
    its own: the text segments are still the model's wording, and wording that no
    recorded response of this run accounts for has no author to attribute it to.
    """

    metrics = state.final_answer_metrics
    # Not "enabled" and not "disabled": no verifier is reached from here at all,
    # so naming the configured arm would describe a request that never happens.
    metrics["verification_mode"] = "runtime_assembly"
    state.verifier_metrics["activation_reason"] = "answer_assembled_by_runtime"
    # The terminal request already recorded what became of its decoding
    # constraint in this same row.  It is a fact about the draft this step is
    # judging, so it survives the row the assembly step returns.
    response_format = state.structured_answer_metrics.get("response_format", "not_requested")
    if (
        draft
        and draft == _final_ai_text(state.messages)
        and sha256_hex(draft) in _model_response_sha256s(runtime)
    ):
        answer, state.structured_answer_metrics = assemble_structured_answer(
            draft, runtime.cited_value_resolver
        )
    else:
        answer = ""
        state.structured_answer_metrics["decision"] = "draft_not_bound_to_a_model_response"
    state.structured_answer_metrics["response_format"] = response_format
    metrics["verification_outcome"] = "not_requested"
    metrics["verification_decision"] = "not_requested"
    answer, normalization_metrics = reject_internal_model_output(answer)
    metrics["format_normalization"] = normalization_metrics

    if not answer:
        state.final = ""
        metrics.update(
            {
                "identifier_grounding": "skipped_no_published_answer",
                "accepted_source": "none",
                "published_text_origin": "none",
                "accepted_report_sha256": None,
                "publication_outcome": "no_accepted_answer",
                "published_text_authorship": "none",
            }
        )
        return

    # Receipt-based grounding applies here, split by segment kind rather than
    # skipped whole.  It used to be skipped on the reasoning that every stated
    # value came out of a retained result by construction — true of the bound
    # values, and false of the sentences around them, which are ordinary model
    # prose.  Skipping therefore dropped the ONLY check that reads what the model
    # itself wrote, on the very path whose point is that the model wrote less.
    # Checking the assembled text instead would hold a runtime-produced value to
    # a gate about model fabrication, and a value the runtime looked up cannot be
    # the thing that gate was built to catch.
    allowed, state.identifier_grounding_metrics = check_identifier_grounding(
        model_authored_text(draft),
        runtime.standardized_result_records,
        case_id=runtime.effective_case_id,
        lineage=runtime.lineage,
    )
    metrics["identifier_grounding"] = "applied_to_text_segments"
    if not allowed:
        state.final = ""
        state.identifier_grounding_blocked = True
        metrics.update(
            {
                "accepted_source": "none",
                "published_text_origin": "none",
                "accepted_report_sha256": None,
                "publication_outcome": "blocked_identifier_grounding",
                "published_text_authorship": "none",
            }
        )
        return

    state.final = answer
    metrics.update(
        {
            "accepted_source": "runtime_assembly",
            "published_text_origin": "runtime_assembly",
            "accepted_report_sha256": sha256_hex(answer),
            "publication_outcome": "published",
            "published_text_authorship": "runtime_assembled",
        }
    )


def _finalize_report(runtime: PreparedRuntime, state: InvestigationState) -> None:
    """Accept the final answer via exactly one of three mutually exclusive paths.

    There is no deterministic answer-shaping layer and no code-generated answer
    bypass.  Either the run bound its deliveries to names the answer cites, in
    which case the published text is assembled here from the model's structured
    draft and no model runs after it; or verification was deliberately disabled
    (the declared raw/basic arm), in which case the investigation model draft is
    accepted and scored as an explicitly unverified answer with zero verification
    requests; or verification is enabled, in which case a non-empty,
    receipt-bound, successful, ledger-bound claim report is mandatory and any
    failure yields no accepted answer and an explicit verification-failure
    outcome. The verifier approves or rejects the investigation draft but never
    authors replacement prose.
    """

    config = runtime.config
    metrics = state.final_answer_metrics
    metrics["verification_mode"] = "enabled" if config.verify else "disabled"
    draft = state.final if (state.final or "").strip() else ""
    metrics["draft_report_sha256"] = sha256_hex(draft) if draft else None

    if not _finalization_is_unblocked(state):
        state.final = ""
        metrics.update(
            {
                "verification_outcome": "finalization_blocked",
                "publication_outcome": "blocked_finalization",
                "accepted_source": "none",
                "published_text_origin": "none",
                "published_text_authorship": "none",
            }
        )
        return

    if config.deliver_model_result_envelope:
        _publish_assembled_answer(runtime, state, draft)
        return

    if not config.verify:
        # Raw/basic arm: accept the investigation model draft as an explicitly
        # unverified answer, but ONLY when (a) there is a draft, (b) no
        # verification row exists at all — the raw arm actively rejects any
        # pre-existing or newly added verification-ledger row — and (c) the draft
        # is a genuine, unmodified model response.  Branch-aware binding: the
        # draft must be the final AI text of the SURVIVING messages (so an orphan
        # ledger row left by a rolled-back recovery re-run cannot be replayed as
        # the answer) AND its digest must occur in a successful
        # investigation/forced-final model row (so a tampered draft is rejected).
        # Receipt-based identifier grounding is deliberately NOT run here (receipt
        # records are disabled in this arm); the difference is recorded explicitly.
        verification_rows = _verification_row_count(state)
        model_response_sha256s = _model_response_sha256s(runtime)
        accepted = (
            bool(draft)
            and draft == _final_ai_text(state.messages)
            and verification_rows == 0
            and metrics["draft_report_sha256"] is not None
            and metrics["draft_report_sha256"] in model_response_sha256s
        )
        if not accepted:
            state.final = ""
        else:
            safe_draft, normalization_metrics = reject_internal_model_output(draft)
            metrics["format_normalization"] = normalization_metrics
            if not safe_draft:
                accepted = False
                state.final = ""
            else:
                state.final = safe_draft
        metrics.update(
            {
                "verification_outcome": "not_requested",
                "verification_decision": "not_requested",
                "identifier_grounding": "skipped_receipts_disabled",
                "verification_row_count": verification_rows,
                "accepted_source": "investigation_model_draft" if accepted else "none",
                "published_text_origin": ("investigation_model_draft" if accepted else "none"),
                "accepted_report_sha256": (sha256_hex(state.final) if accepted else None),
                "publication_outcome": "published" if accepted else "no_accepted_answer",
                "published_text_authorship": "model_written" if accepted else "none",
            }
        )
        return

    try:
        _run_enabled_verification(runtime, state, draft)
    finally:
        metrics["verification_row_count"] = _verification_row_count(state)



def _record_verifier_bundle_composition(
    runtime: PreparedRuntime, state: InvestigationState, evidence: str
) -> None:
    """Record WHICH results the final check was allowed to read.

    A run extracted a file, read the text inside it and then published that
    none of it was established, "because the projection contains only the
    reconstructed payload".  Whether that was true of the bundle or invented by
    the model could not be settled from the record: the bundle is built, used
    and discarded, and nothing said what went into it.  It is written here as a
    list of producing functions and their invocation ids, never their content —
    the results themselves are already retained, receipts and all.
    """

    import json as _json

    gate = getattr(runtime, "gate", None)
    if gate is None:
        # A run with no oversight chain records nothing here: the composition is
        # a fact about the audited record, and without one there is none.
        return
    included: list[dict[str, object]] = []
    try:
        bundle = _json.loads(evidence) if evidence else {}
        for result in bundle.get("results", ()):
            provenance = result.get("provenance") or {}
            included.append(
                {
                    "tool": provenance.get("tool_name"),
                    "invocation_id": provenance.get("invocation_id"),
                    "evidence_class": provenance.get("evidence_class"),
                }
            )
        obstacles = len(bundle.get("obstacles") or ())
    except (ValueError, AttributeError, TypeError):
        # The bundle is the verifier's document, not this record's: a shape this
        # cannot read is reported as unreadable rather than silently as empty.
        gate.recorder.record_security(
            "verifier_bundle_composition",
            {"readable": False, "metrics": dict(state.verifier_metrics)},
        )
        return
    gate.recorder.record_security(
        "verifier_bundle_composition",
        {
            "readable": True,
            "included_results": included,
            "obstacle_count": obstacles,
            "metrics": dict(state.verifier_metrics),
        },
    )


def _run_enabled_verification(
    runtime: PreparedRuntime, state: InvestigationState, draft: str
) -> None:
    """Publish the original draft only after complete claim-level approval.

    The verifier can return decisions and evidence references, never replacement
    prose. ``state.final`` remains empty until the response, ledger binding,
    deterministic grounding, and output-confidentiality checks all pass.
    """

    config = runtime.config
    metrics = state.final_answer_metrics
    # Clear the draft before verification; it is only restored on full success.
    state.final = ""
    metrics["accepted_source"] = "none"
    metrics["publication_outcome"] = "no_accepted_answer"
    metrics["published_text_origin"] = "none"
    metrics["verification_decision"] = "not_evaluated"
    # Set once for every way this path can end without publishing, so a failure
    # that returns early cannot leave the record silent about authorship; the two
    # publishing returns below are the only places that overwrite it.
    metrics["published_text_authorship"] = "none"
    if not draft.strip():
        state.verifier_metrics["activation_reason"] = "no_draft_report"
        metrics["verification_outcome"] = "failed_no_draft_report"
        return
    from forensic_agent.reliability.verify import (
        VERIFIER_RETRYABLE_FAILURE_CODES,
        VerifierAttemptOrdinal,
        VerifierInputError,
        VerifierResponseError,
        VerifierResponseMode,
        VerifierRetryTriggerCode,
        build_verification_claims,
        build_verifier_user_content,
        verifier_retry_response_mode,
        verify_claims,
    )

    def is_retryable_trigger_code(code: object) -> TypeGuard[VerifierRetryTriggerCode]:
        """Whether the single bounded retry has a defined transport for this code.

        ``VERIFIER_RETRYABLE_FAILURE_CODES`` is exactly the set of codes
        ``VerifierRetryTriggerCode`` names, so membership in it is the type.
        """

        return code in VERIFIER_RETRYABLE_FAILURE_CODES

    draft_answer, normalization_metrics = reject_internal_model_output(draft)
    metrics["format_normalization"] = normalization_metrics
    if not draft_answer:
        state.verifier_metrics["activation_reason"] = "draft_failed_output_hygiene"
        metrics["verification_outcome"] = (
            "failed_internal_reasoning_exposure"
            if normalization_metrics.get("internal_reasoning_rejected") is True
            else "failed_no_draft_after_normalization"
        )
        return
    claims = build_verification_claims(draft_answer)
    if not claims:
        state.verifier_metrics["activation_reason"] = "no_verifiable_claims"
        metrics["verification_outcome"] = "failed_no_verifiable_claims"
        return

    try:
        evidence, state.verifier_metrics = _compact_verifier_evidence(
            state.messages,
            focus_text=f"{config.question}\n{draft_answer}",
            # Retention guarantees apply to values asserted in the answer, not
            # arbitrary value-shaped text in the user's question.
            citation_text=draft_answer,
            question_text=config.question,
            # The run's own case and the run's own lineage authority, so the final
            # check can refuse a result belonging to another case and can bind an
            # active-contract result to the append-only record its content was written
            # to.  The bundle is built from the model-visible projections, which the
            # resolver binds as artifacts in their own right; a resolver that held only
            # complete results would refuse every reduced bundle.
            lineage=runtime.lineage,
            active_case_id=runtime.effective_case_id,
        )
    except RuntimeError:
        state.verifier_metrics["activation_reason"] = "projection_failed"
        state.verifier_metrics["verification_status"] = "failed"
        metrics["verification_outcome"] = "failed_verifier_projection"
        return
    _record_verifier_bundle_composition(runtime, state, evidence)
    if state.verifier_metrics.get("cited_token_overflow") is True:
        state.verifier_metrics["activation_reason"] = "cited_value_bound_exceeded"
        state.verifier_metrics["verification_status"] = "incomplete"
        metrics["verification_outcome"] = "failed_cited_value_bound"
        metrics["verification_decision"] = "inconclusive"
        _publish_draft_with_verification_gap(
            runtime, state, draft, draft_answer, gap_reason="cited_value_bound"
        )
        return
    omitted_cited_tokens = state.verifier_metrics.get("omitted_cited_token_count", 0)
    if isinstance(omitted_cited_tokens, int) and omitted_cited_tokens > 0:
        state.verifier_metrics["activation_reason"] = "cited_evidence_not_retained"
        state.verifier_metrics["verification_status"] = "incomplete"
        metrics["verification_outcome"] = "failed_cited_evidence_projection"
        metrics["verification_decision"] = "inconclusive"
        _publish_draft_with_verification_gap(
            runtime, state, draft, draft_answer, gap_reason="cited_evidence_projection"
        )
        return
    if not evidence:
        state.verifier_metrics["activation_reason"] = "no_usable_case_evidence"
        metrics["verification_outcome"] = "failed_no_case_evidence"
        return

    verifier_user_content = build_verifier_user_content(config.question, evidence, claims)
    strict_user_content_sha256 = sha256_hex(canonical_json(verifier_user_content))
    question_sha256 = sha256_hex(config.question)
    evidence_sha256 = sha256_hex(evidence)
    draft_sha256 = sha256_hex(draft_answer)
    claims_sha256 = sha256_hex(
        canonical_json(
            {
                "schema_id": "forensic.verifier-claims.v1",
                "claims": [{"claim_id": claim.claim_id, "text": claim.text} for claim in claims],
            }
        )
    )
    state.verifier_metrics.update(
        {
            "verification_question_sha256": question_sha256,
            "verification_evidence_sha256": evidence_sha256,
            "verification_draft_sha256": draft_sha256,
            "verification_claims_sha256": claims_sha256,
            "claim_count": len(claims),
            "verification_user_content_sha256": strict_user_content_sha256,
        }
    )
    state.verification_evidence_present = True
    state.verifier_metrics["activated"] = True
    state.verifier_metrics["activation_reason"] = "receipt_valid_usable_case_evidence"

    ledger = state.verification_telemetry.get("request_ledger")
    rows_before = len(ledger) if isinstance(ledger, list) else 0
    verifier_report = None

    def salvage_unverified() -> None:
        """Publish the grounded draft with a stated gap when the final check
        could not deliver a usable verdict at all.

        A truncated report, a refused or undispatched request, an empty reply,
        or an unbindable ledger judged nothing about the answer — the same
        operational failure the OLD system also refused on, but refusing here
        hands the operator a blank where a grounded finding exists. The draft is
        published instead, under the same identifier-grounding, model-response
        binding and absence gates a verified answer passes, with the gap stated
        so the answer is never presented as verified. A verdict against the
        answer never reaches this path: it is set only where the verifier failed
        to produce a verdict, not where it produced an adverse one.
        """

        _publish_draft_with_verification_gap(
            runtime, state, draft, draft_answer, gap_reason="verifier_incomplete"
        )

    def reserve_verification() -> tuple[_DispatchPermit | None, bool]:
        permit: _DispatchPermit | None = None
        try:
            if runtime.execution_budget is not None:
                permit = runtime.execution_budget.reserve_model("verification")
        except _DispatchDenied as exc:
            state.dispatch_exhaustion_reason = state.dispatch_exhaustion_reason or exc.reason
            deadline = exc.reason == "max_wall_time_s"
            state.verifier_metrics["activation_reason"] = (
                "deadline_exhausted" if deadline else "model_budget_exhausted"
            )
            state.verifier_metrics["request_status"] = "not_dispatched"
            state.verifier_metrics["verification_status"] = "failed"
            metrics["verification_outcome"] = (
                "failed_deadline_exhausted" if deadline else "failed_model_budget_exhausted"
            )
            return None, True
        return permit, False

    def invoke_verifier(
        *,
        attempt_ordinal: VerifierAttemptOrdinal,
        response_mode: VerifierResponseMode,
        retry_trigger_code: VerifierRetryTriggerCode | None,
    ):
        permit, dispatch_denied = reserve_verification()
        if dispatch_denied:
            return None, None, False, True
        attempt_rows_before = len(ledger) if isinstance(ledger, list) else 0
        verification_started = time.monotonic()
        try:
            # Always raise on error: neither a malformed strict response nor a
            # failed compatibility retry may approve the draft implicitly.
            report = verify_claims(
                config.question,
                draft_answer,
                claims,
                evidence,
                model=config.verify_model or config.model,
                base_url=config.base_url,
                api_key=config.api_key,
                provider=config.verification_provider,
                provider_quantizations=(config.verification_provider_quantizations),
                profile=config.decoding_profile,
                allowed_parameters=config.decoding_parameters,
                telemetry=state.verification_telemetry,
                raise_on_error=True,
                # Application-level verification already owns the single bounded
                # retry. Disable hidden SDK retries so every reserved attempt maps
                # to exactly one provider request.
                max_retries=0,
                request_timeout_s=(
                    permit.remaining_s
                    if permit is not None
                    else (
                        runtime.frozen_request_timeout.timeout_s
                        if runtime.frozen_request_timeout is not None
                        else None
                    )
                ),
                response_mode=response_mode,
                attempt_ordinal=attempt_ordinal,
                retry_trigger_code=retry_trigger_code,
            )
            return report, None, True, False
        except (RuntimeError, VerifierInputError) as exc:
            return None, exc.__cause__, False, False
        finally:
            verification_rows = state.verification_telemetry.get("request_ledger")
            if isinstance(verification_rows, list) and len(verification_rows) > attempt_rows_before:
                completed = time.monotonic()
                for row in verification_rows[attempt_rows_before:]:
                    if not isinstance(row, dict):
                        continue
                    row["request_started_elapsed_s"] = round(
                        (permit.started_elapsed_s if permit is not None else 0.0),
                        6,
                    )
                    row["request_completed_elapsed_s"] = round(
                        (
                            completed - runtime.execution_budget.started_monotonic
                            if runtime.execution_budget is not None
                            else completed - verification_started
                        ),
                        6,
                    )
                    row["request_duration_s"] = round(
                        max(
                            0.0,
                            completed
                            - (
                                permit.started_monotonic
                                if permit is not None
                                else verification_started
                            ),
                        ),
                        6,
                    )
                    if permit is not None:
                        row["request_dispatch"] = permit.record()

    def record_terminal_failure(cause: object) -> None:
        state.verifier_metrics["request_status"] = "error"
        state.verifier_metrics["verification_status"] = "failed"
        malformed = isinstance(cause, VerifierResponseError)
        metrics["verification_outcome"] = (
            "failed_malformed_response" if malformed else "failed_verifier_request"
        )
        if cause is not None:
            state.verifier_metrics["validation_failure_type"] = type(cause).__name__
            if isinstance(cause, VerifierResponseError):
                state.verifier_metrics["validation_failure_code"] = cause.code

    verifier_report, first_cause, first_ok, dispatch_denied = invoke_verifier(
        attempt_ordinal=1,
        response_mode="json_schema",
        retry_trigger_code=None,
    )
    if dispatch_denied:
        salvage_unverified()
        return
    if first_ok:
        state.verifier_metrics["request_status"] = "success"
    else:
        retry_trigger_code = (
            first_cause.code if isinstance(first_cause, VerifierResponseError) else None
        )
        if not is_retryable_trigger_code(retry_trigger_code):
            record_terminal_failure(first_cause)
            salvage_unverified()
            return
        state.verifier_metrics.update(
            {
                "retry_attempted": True,
                "retry_trigger_code": retry_trigger_code,
                "initial_validation_failure_code": retry_trigger_code,
            }
        )
        retry_response_mode = verifier_retry_response_mode(retry_trigger_code)
        verifier_report, retry_cause, retry_ok, dispatch_denied = invoke_verifier(
            attempt_ordinal=2,
            response_mode=retry_response_mode,
            retry_trigger_code=retry_trigger_code,
        )
        if dispatch_denied:
            state.verifier_metrics["retry_outcome"] = "budget_denied"
            salvage_unverified()
            return
        if not retry_ok:
            state.verifier_metrics["retry_outcome"] = "failed"
            record_terminal_failure(retry_cause)
            salvage_unverified()
            return
        state.verifier_metrics["retry_outcome"] = "success"
        state.verifier_metrics["request_status"] = "success"

    if verifier_report is None:
        state.verifier_metrics["verification_status"] = "failed"
        metrics["verification_outcome"] = "failed_empty_response"
        salvage_unverified()
        return

    canonical_verifier_report = canonical_json(verifier_report.model_dump(mode="json"))
    verifier_report_sha256 = sha256_hex(canonical_verifier_report)
    metrics["verifier_report_sha256"] = verifier_report_sha256
    state.verifier_metrics["verification_claim_report_sha256"] = verifier_report_sha256

    # Bind either one successful strict request or one failed strict request
    # followed by exactly one successful compatibility retry. Both attempts must
    # refer to the same original question, evidence, draft, and claim set.
    new_rows = ledger[rows_before:] if isinstance(ledger, list) else []

    def binds_common_inputs(row: object) -> bool:
        return (
            isinstance(row, dict)
            and row.get("role") == "verification"
            and row.get("verification_question_sha256") == question_sha256
            and row.get("verification_evidence_sha256") == evidence_sha256
            and row.get("verification_draft_sha256") == draft_sha256
            and row.get("verification_claims_sha256") == claims_sha256
        )

    ledger_bound = False
    if len(new_rows) == 1 and binds_common_inputs(new_rows[0]):
        strict_row = new_rows[0]
        ledger_bound = (
            strict_row.get("status") == "success"
            and strict_row.get("verification_attempt_ordinal") == 1
            and strict_row.get("verification_response_mode") == "json_schema"
            and strict_row.get("verification_retry_trigger_code") in (None, "")
            and strict_row.get("verification_user_content_sha256") == strict_user_content_sha256
            and strict_row.get("verification_claim_report_sha256") == verifier_report_sha256
        )
    elif (
        len(new_rows) == 2 and binds_common_inputs(new_rows[0]) and binds_common_inputs(new_rows[1])
    ):
        strict_row, retry_row = new_rows
        trigger_code = strict_row.get("validation_failure_code")
        ledger_retry_response_mode = (
            verifier_retry_response_mode(trigger_code)
            if trigger_code in VERIFIER_RETRYABLE_FAILURE_CODES
            else None
        )
        retry_user_content_sha256 = (
            sha256_hex(
                canonical_json(
                    build_verifier_user_content(
                        config.question,
                        evidence,
                        claims,
                        response_mode=ledger_retry_response_mode,
                        attempt_ordinal=2,
                        retry_trigger_code=trigger_code,
                    )
                )
            )
            if ledger_retry_response_mode is not None
            else None
        )
        ledger_bound = (
            strict_row.get("status") == "error"
            and strict_row.get("verification_attempt_ordinal") == 1
            and strict_row.get("verification_response_mode") == "json_schema"
            and strict_row.get("verification_retry_trigger_code") in (None, "")
            and trigger_code in VERIFIER_RETRYABLE_FAILURE_CODES
            and strict_row.get("verification_user_content_sha256") == strict_user_content_sha256
            and retry_row.get("status") == "success"
            and retry_row.get("verification_attempt_ordinal") == 2
            and retry_row.get("verification_response_mode") == ledger_retry_response_mode
            and retry_row.get("verification_retry_trigger_code") == trigger_code
            and retry_row.get("verification_user_content_sha256") == retry_user_content_sha256
            and retry_row.get("verification_claim_report_sha256") == verifier_report_sha256
        )
    if not ledger_bound:
        state.verifier_metrics["verification_status"] = "failed"
        metrics["verification_outcome"] = "failed_ledger_binding"
        salvage_unverified()
        return

    verdict_counts = {
        verdict: sum(1 for decision in verifier_report.claims if decision.verdict == verdict)
        for verdict in (
            "supported",
            "contradicted",
            "insufficient_evidence",
            "not_checked",
        )
    }
    state.verifier_metrics.update(
        {
            "answer_complete": verifier_report.answer_complete,
            "output_hygiene": verifier_report.output_hygiene,
            "verdict_counts": verdict_counts,
        }
    )
    # The LLM verifier is ADVISORY: its verdicts caveat a grounded answer, they
    # never discard it. The model that judges here is the same probabilistic
    # model that answered, and it errs — most visibly by marking a correct
    # derived value (an epoch decoded to a date) "contradicted". Withholding a
    # correct finding on that verdict is the worse failure for an examiner, and
    # the checks that DO withhold are the deterministic ones: the pre-verifier
    # internal-reasoning strip already ran, and the receipt-based identifier
    # grounding below runs inside every keep-or-mark publication too. So every
    # verifier verdict short of full support publishes the draft with the reason
    # stated, and the final assessment stays with the human. The more serious
    # verdicts are read first only so the stronger caveat is the one stated.
    if verifier_report.output_hygiene != "clean":
        state.verifier_metrics["verification_status"] = "flagged"
        metrics["verification_outcome"] = "flagged_output_hygiene"
        metrics["verification_decision"] = "advisory"
        _publish_draft_with_verification_gap(
            runtime, state, draft, draft_answer, gap_reason="output_hygiene"
        )
        return
    if verdict_counts["contradicted"]:
        state.verifier_metrics["verification_status"] = "flagged"
        metrics["verification_outcome"] = "flagged_contradicted_claim"
        metrics["verification_decision"] = "advisory"
        _publish_draft_with_verification_gap(
            runtime,
            state,
            draft,
            draft_answer,
            gap_reason="contradicted",
            unverified=verdict_counts["contradicted"],
            claim_count=len(claims),
        )
        return
    if not verifier_report.answer_complete or verdict_counts["not_checked"]:
        state.verifier_metrics["verification_status"] = "incomplete"
        metrics["verification_outcome"] = "failed_incomplete_verification"
        metrics["verification_decision"] = "advisory"
        _publish_draft_with_verification_gap(
            runtime,
            state,
            draft,
            draft_answer,
            gap_reason="incomplete_verification",
            unverified=verdict_counts["not_checked"],
            claim_count=len(claims),
        )
        return
    if verdict_counts["insufficient_evidence"]:
        state.verifier_metrics["verification_status"] = "inconclusive"
        metrics["verification_outcome"] = "failed_insufficient_evidence"
        metrics["verification_decision"] = "advisory"
        _publish_draft_with_verification_gap(
            runtime,
            state,
            draft,
            draft_answer,
            gap_reason="insufficient_evidence",
            unverified=verdict_counts["insufficient_evidence"],
            claim_count=len(claims),
        )
        return
    if verdict_counts["supported"] != len(claims):
        state.verifier_metrics["verification_status"] = "flagged"
        metrics["verification_outcome"] = "flagged_claim_coverage"
        metrics["verification_decision"] = "advisory"
        _publish_draft_with_verification_gap(
            runtime, state, draft, draft_answer, gap_reason="claim_coverage"
        )
        return

    state.verifier_metrics["verification_status"] = "verified"
    metrics["verification_outcome"] = "verified"
    metrics["verification_decision"] = "approve"

    # Receipt-based identifier grounding gate (enabled arm only): a report may
    # only name identifiers that a tool actually returned.
    allowed, state.identifier_grounding_metrics = check_identifier_grounding(
        draft_answer,
        runtime.standardized_result_records,
        case_id=runtime.effective_case_id,
        # This gate reads the COMPLETE retained results, which the resolver binds
        # as their own artifacts, so it asks the same authority about the same
        # kind of record the verifier bundle asked about the projections.
        lineage=runtime.lineage,
    )
    metrics["identifier_grounding"] = "applied"
    if not allowed:
        state.identifier_grounding_blocked = True
        metrics.update(
            {
                "publication_outcome": "blocked_identifier_grounding",
                "accepted_source": "none",
                "accepted_report_sha256": None,
            }
        )
        return

    # Apply the absence gate to the exact investigation draft that would be
    # published. A bounded verifier bundle cannot establish an unqualified
    # negative conclusion about content it did not carry.
    if _absence_is_unestablished(runtime, state, draft_answer):
        # A report whose answer was a positive finding, verified, must not be
        # discarded whole because one neighbouring sentence also said something
        # had not been found. Withholding is too blunt for that. The rule this
        # gate enforces is that no UNQUALIFIED absence claim reaches the
        # operator — and a report that states its own bound has satisfied that
        # rule, by this project's own reading of what a forensic report is.
        #
        # So the bound is stated rather than the report destroyed. The finding
        # survives with its evidence, the absence beside it is held to what was
        # actually examined, and the operator is told which region is missing
        # instead of being handed nothing at all.
        regions = unread_region_labels(runtime.standardized_result_records, tools=runtime.tools)
        truncated = _verifier_bundle_was_truncated(state.verifier_metrics)
        included = state.verifier_metrics.get("included_results")
        omitted = state.verifier_metrics.get("bundle_omitted_result_count")
        usable = state.verifier_metrics.get("usable_case_results")
        shortened = state.verifier_metrics.get("per_result_truncated_count")
        source: int | None = None
        if isinstance(included, int) and isinstance(omitted, int):
            # The fuller of the two accountings: candidates the packer admitted
            # plus the ones it left out, or the usable count when it is larger.
            source = max(included + omitted, usable if isinstance(usable, int) else 0)
        bound = bound_stated_for(
            regions,
            bundle_truncated=truncated,
            bundle_included=included if isinstance(included, int) else None,
            bundle_source=source,
            bundle_shortened=shortened if isinstance(shortened, int) else None,
        )
        qualified = f"{draft_answer.rstrip()}\n\n{bound}" if bound else draft_answer
        state.final = qualified
        metrics.update(
            {
                "publication_outcome": "published_with_stated_bound",
                "accepted_source": "verifier",
                "published_text_origin": "investigation_model_draft",
                # The answer is the model's sentences; only the appended coverage
                # bound was composed by the runtime, and the outcome above is
                # what records that a bound was appended at all.
                "published_text_authorship": "model_written",
                "accepted_report_sha256": sha256_hex(canonical_json({"report": qualified})),
                "unread_region_count": len(regions),
                "bundle_truncated": truncated,
            }
        )
        return

    state.final = draft_answer
    metrics.update(
        {
            "accepted_source": "verifier",
            "published_text_origin": "investigation_model_draft",
            "accepted_report_sha256": sha256_hex(draft_answer),
            "publication_outcome": "published",
            "published_text_authorship": "model_written",
        }
    )


def _finalize_runtime(runtime: PreparedRuntime, state: InvestigationState) -> None:
    """Close custody/oversight resources and publish final execution metrics."""

    config = runtime.config
    runtime_evidence_guard = runtime.runtime_evidence_guard
    gate = runtime.gate

    if runtime_evidence_guard is not None:
        try:
            runtime_evidence_guard.check(
                "graph_completion",
                full_content=True,
            )
        except EvidenceSourceError as exc:
            state.evidence_integrity_error = exc
            if gate is not None:
                gate.recorder.record_security(
                    "evidence_source_integrity_violation",
                    {
                        "checkpoint": "graph_completion",
                        "source_attestation_sha256": (
                            runtime_evidence_guard.telemetry()["source_attestation_sha256"]
                        ),
                        "sticky": True,
                    },
                )
        if runtime.owns_evidence_guard:
            try:
                runtime_evidence_guard.close()
            except EvidenceSourceError as exc:
                state.evidence_integrity_error = state.evidence_integrity_error or exc
                if gate is not None:
                    gate.recorder.record_security(
                        "evidence_source_integrity_violation",
                        {
                            "checkpoint": "read_lease_close",
                            "source_attestation_sha256": (
                                runtime_evidence_guard.telemetry()["source_attestation_sha256"]
                            ),
                            "sticky": True,
                        },
                    )
    if state.evidence_integrity_error is not None:
        # An evidence-integrity failure at graph completion occurs after the
        # answer was accepted.  It revokes that answer BEFORE telemetry and audit
        # closure: a published answer can no longer be trusted once the underlying
        # evidence source failed its integrity check.
        state.final = ""
        state.final_answer_metrics.update(
            {
                "accepted_source": "none",
                "published_text_origin": "none",
                "accepted_report_sha256": None,
                "publication_outcome": "blocked_evidence_integrity",
                "published_text_authorship": "none",
            }
        )
    if config.telemetry is not None:
        publication_gate_metrics = _publication_gate_metrics(state)
        # Computed here, after every stage and after the integrity revocation
        # above, because it is a reading of what the run FINISHED with; taken
        # earlier it would name a disposition a later stage went on to change.
        state.unpublished_answer_metrics = _unpublished_answer_metrics(runtime, state)
        # What the run could and could not bind to its own oversight chain.  A
        # result the run refused to bind is a DIAGNOSTIC result: stored, readable
        # and never an evidential basis.  Without this row that refusal would
        # reach a reader only as an unexplained absence of evidence, which is
        # indistinguishable from an investigation that found nothing.
        lineage_binding_metrics = runtime.lineage.metrics()
        verification_rows = state.verification_telemetry.get("request_ledger")
        verification_ledger = list(verification_rows) if isinstance(verification_rows, list) else []
        graph_request_ledger = (
            runtime.investigation_ledger.entries + runtime.forced_final_ledger.entries
        )
        if runtime.request_payload_ledger is not None:
            graph_request_ledger = runtime.request_payload_ledger.bind(graph_request_ledger)
        if runtime.execution_budget is not None:
            # A callback row can be created before ``_get_request_payload``.
            # Rows rejected by the budget at that boundary were never sent to
            # OpenRouter and therefore are metrics, not request attempts.
            graph_request_ledger = [
                row
                for row in graph_request_ledger
                if isinstance(row.get("request_dispatch"), Mapping)
            ]
        investigation_requests = sum(
            row.get("role") == "investigation" for row in graph_request_ledger
        )
        state.forced_final_requests = sum(
            row.get("role") == "forced_final" for row in graph_request_ledger
        )
        verification_requests = len(verification_ledger)
        request_ledger = graph_request_ledger + verification_ledger
        cell_execution_metrics = (
            runtime.execution_budget.metrics() if runtime.execution_budget is not None else None
        )
        if (
            isinstance(cell_execution_metrics, Mapping)
            and cell_execution_metrics.get("deadline_exhausted") is True
            and state.dispatch_exhaustion_reason is None
        ):
            state.dispatch_exhaustion_reason = "max_wall_time_s"
        if request_ledger:
            # These are bounded primitive-only metrics. Evidence content never
            # enters checkpoint receipts; the control receipt binds this ledger
            # by digest without reproducing its data.
            request_ledger[-1] = {
                **request_ledger[-1],
                "cell_execution_metrics": cell_execution_metrics,
                "verifier_metrics": dict(state.verifier_metrics),
                "final_answer_metrics": dict(state.final_answer_metrics),
                "structured_answer_metrics": dict(state.structured_answer_metrics),
                "reference_evidence_recovery_metrics": dict(
                    state.reference_evidence_recovery_metrics
                ),
                "pending_tool_recovery_metrics": dict(state.pending_tool_recovery_metrics),
                "tool_dispatch_closure_metrics": dict(state.tool_dispatch_closure_metrics),
                "continuation_metrics": dict(state.continuation_metrics),
                "match_with_continuation_metrics": dict(state.match_with_continuation_metrics),
                "memory_injection_corroboration_metrics": dict(
                    state.memory_injection_corroboration_metrics
                ),
                "memory_pagination_metrics": dict(state.memory_pagination_metrics),
                "result_navigation_metrics": dict(state.result_navigation_metrics),
                "identifier_grounding_metrics": dict(state.identifier_grounding_metrics),
                "premature_absence_metrics": dict(state.premature_absence_metrics),
                "evidence_region_metrics": dict(state.evidence_region_metrics),
                "unfinished_examination_metrics": dict(state.unfinished_examination_metrics),
                "unproductive_repetition_metrics": dict(state.unproductive_repetition_metrics),
                **(
                    {"multisource_coverage_metrics": dict(state.multisource_coverage_metrics)}
                    if config.enforce_explicit_multisource_coverage
                    else {}
                ),
                "publication_gate_metrics": publication_gate_metrics,
                "unpublished_answer_metrics": dict(state.unpublished_answer_metrics),
                "lineage_binding_metrics": lineage_binding_metrics,
            }
        config.telemetry.update(
            {
                "investigation_model_requests": investigation_requests,
                "forced_final_model_requests": state.forced_final_requests,
                "verification_model_requests": verification_requests,
                "model_requests": (
                    investigation_requests + state.forced_final_requests + verification_requests
                ),
                "request_ledger": request_ledger,
                "verification_evidence_present": state.verification_evidence_present,
                "verification_status": state.verifier_metrics.get(
                    "verification_status",
                    "not_verified",
                ),
                "verifier_metrics": dict(state.verifier_metrics),
                "final_answer_metrics": dict(state.final_answer_metrics),
                "structured_answer_metrics": dict(state.structured_answer_metrics),
                "reference_evidence_recovery_metrics": dict(
                    state.reference_evidence_recovery_metrics
                ),
                "pending_tool_recovery_metrics": dict(state.pending_tool_recovery_metrics),
                "tool_dispatch_closure_metrics": dict(state.tool_dispatch_closure_metrics),
                "continuation_metrics": dict(state.continuation_metrics),
                "match_with_continuation_metrics": dict(state.match_with_continuation_metrics),
                "memory_injection_corroboration_metrics": dict(
                    state.memory_injection_corroboration_metrics
                ),
                "memory_pagination_metrics": dict(state.memory_pagination_metrics),
                "result_navigation_metrics": dict(state.result_navigation_metrics),
                "identifier_grounding_metrics": dict(state.identifier_grounding_metrics),
                "premature_absence_metrics": dict(state.premature_absence_metrics),
                "evidence_region_metrics": dict(state.evidence_region_metrics),
                "unfinished_examination_metrics": dict(state.unfinished_examination_metrics),
                "unproductive_repetition_metrics": dict(state.unproductive_repetition_metrics),
                **(
                    {"multisource_coverage_metrics": dict(state.multisource_coverage_metrics)}
                    if config.enforce_explicit_multisource_coverage
                    else {}
                ),
                "publication_gate_metrics": publication_gate_metrics,
                "unpublished_answer_metrics": dict(state.unpublished_answer_metrics),
                "lineage_binding_metrics": lineage_binding_metrics,
                "cell_execution_metrics": cell_execution_metrics,
                "steps": investigation_requests,
                "forced_final": state.forced_final,
                "recursion_limit_hit": state.recursion_limited,
                "transient_midrun_error": state.transient_midrun_error,
                "finish_reason": (
                    f"budget_exhausted:{state.dispatch_exhaustion_reason}"
                    if state.dispatch_exhaustion_reason is not None
                    else (
                        "completed"
                        if (state.final or "").strip() and not state.recursion_limited
                        else (
                            "completed_after_step_limit"
                            if (state.final or "").strip()
                            else "no_final_answer"
                        )
                    )
                ),
                "evidence_source_runtime_integrity": (
                    runtime_evidence_guard.telemetry()
                    if runtime_evidence_guard is not None
                    else None
                ),
            }
        )
    if gate is not None:
        gate.recorder.close_case(
            final=state.final or "",
            status=(
                "integrity_violation"
                if runtime_evidence_guard is not None and runtime_evidence_guard.violation_detected
                else ("ok" if (state.final or "").strip() else "aborted")
            ),
        )
