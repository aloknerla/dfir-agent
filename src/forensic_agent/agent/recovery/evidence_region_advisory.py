"""State which regions of the evidence this run never read, before it concludes.

A run can be told in the question itself that deleted and unallocated content are
in scope and still glob for filenames and conclude from an empty folder: it has
read what the filesystem lists and nothing else, and has no occasion to notice
that.

So the runtime says the one thing only the runtime knows: which regions of this
evidence went unread.  It is a fact about the run, not an instruction and not a
hint.  It names the region and stops, because naming a tool would be this project
choosing the method and describing what might be there would be this project
saying where the answer lives.  What the model does with the fact is the model's
own forensic judgement, which is the part that was never broken.

It executes nothing itself.  A region no available tool can reach is not an
omission and is never mentioned; a run without a draft conclusion is not at the
moment before its conclusion and is left to the terminal request that will
produce one.

What it does hold to is one rule: absence is not established while a region that
could refute it is unread, or while the evidence actually examined was truncated.
So the statement is not a single-shot nudge that records itself as delivered and
looks away.  It is recomputed from the LIVE records and repeated, up to a small
fixed cap, for as long as the report still asserts an absence over a region this
run never opened — and if the omission is still standing when the cap is reached,
the caller is told so, and that report is not this run's answer.

A run whose budget ran out is not stubborn, it is spent: exhaustion ends the loop
and reports no surviving omission, because punishing it would score the ceiling
rather than the reasoning.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from contextlib import nullcontext
from typing import Any

from langchain_core.messages import HumanMessage

from forensic_agent.agent.evidence_regions import (
    reachable_regions,
    regions_read,
    unread_regions,
    unread_regions_statement,
)
from forensic_agent.agent.execution_budget import _DispatchDenied
from forensic_agent.agent.execution_dispatch import _final_ai_text
from forensic_agent.agent.recovery.common import _messages_accept_a_follow_up
from forensic_agent.agent.recovery.premature_absence import report_asserts_absence

EVIDENCE_REGION_METRICS_SCHEMA_ID = "forensic.evidence-region-coverage.v1"

#: How many times the SAME statement may be put again after the first one.  Small
#: and fixed: this is a bounded check that the fact reached the model, not a
#: negotiation, and every restatement costs the run a model request it would
#: rather spend reading the evidence.
_RESTATEMENT_CAP = 2


def empty_evidence_region_metrics(*, enabled: bool) -> dict[str, object]:
    """The stable telemetry shape for what this run read of the medium.

    Region names are a closed vocabulary describing the medium, never anything
    read out of it, so they travel verbatim without carrying case material.
    """

    return {
        "schema_id": EVIDENCE_REGION_METRICS_SCHEMA_ID,
        "enabled": enabled,
        "activated": False,
        "decision": "not_evaluated" if enabled else "arm_disabled",
        "regions_reachable": [],
        "regions_read": [],
        "regions_unread": [],
        "statement_delivered": False,
        # How many times the same statement was put again after the first.
        "restatements": 0,
        # The ceiling those restatements answer to, recorded beside the count so a
        # reader can tell a run that stopped early from one that ran out of
        # permitted repetitions.
        "restatement_cap": _RESTATEMENT_CAP,
        # Whether the loop ended with an absence still asserted over a region this
        # run never opened.  Only this ends a run's answer.
        "omission_survives": False,
    }


def _tool_names(tools: Iterable[object]) -> tuple[str, ...]:
    """The model-visible names of the functions this run was given."""

    names: list[str] = []
    for tool in tools:
        name = getattr(tool, "name", tool)
        if isinstance(name, str) and name:
            names.append(name)
    return tuple(names)


def _record_regions(
    metrics: dict[str, object],
    records: Sequence[Mapping[str, Any]],
    names: tuple[str, ...],
) -> tuple[str, ...]:
    """Recompute what this run has read SO FAR and record it, returning the gap.

    Read from the live records on every pass rather than once at the start: the
    whole point of stating the omission is that the model may go and close it,
    and a check that never looks again cannot tell that it did.
    """

    unread = unread_regions(records, tools=names)
    metrics.update(
        {
            "regions_read": sorted(regions_read(records)),
            "regions_unread": [region.name for region in unread],
        }
    )
    return tuple(region.name for region in unread)


def state_unread_evidence_regions(
    messages: list[object],
    records: Sequence[Mapping[str, Any]],
    tools: Iterable[object],
    report: str | None,
    metrics: dict[str, object],
    *,
    llm,
    agent,
    investigation_ledger,
    recursion_limit: int,
) -> tuple[list[object], str | None, bool]:
    """State which reachable regions went unread, and hold the run to the answer.

    Absence is not established while a region that could refute it is unread.
    So the statement is put, the LIVE records are read again, and it is put once
    more — up to a small fixed cap — for as long as the report still asserts an
    absence over a region this run never opened.  It restates the same fact
    rather than escalating: the wording changes only where the fact does, when a
    region has since been opened, because rewording it to press would stop it
    being a fact about the run and start it being an instruction.

    Returns the message state to keep, any dispatch-exhaustion reason, and
    whether the omission survived.  That last one is True only when the loop ends
    with an absence still asserted, a reachable region still unread, and budget
    not the reason it ended — an exhausted run is spent, not stubborn, and must
    never be scored as though it had refused.
    """

    names = _tool_names(tools)
    reachable = reachable_regions(names)
    metrics["regions_reachable"] = sorted(reachable)
    unread = _record_regions(metrics, records, names)
    if not reachable:
        metrics["decision"] = "no_region_reachable"
        return messages, None, False
    if not unread:
        metrics["decision"] = "every_reachable_region_read"
        return messages, None, False
    if not (report or "").strip():
        # Nothing is about to be published, so this is not the moment before a
        # conclusion.  The terminal request that will produce one is a different
        # stage's business and is left to it.
        metrics["decision"] = "no_conclusion_to_precede"
        return messages, None, False
    if not report_asserts_absence(report):
        # This advisory exists only to hold an ABSENCE claim to what the run
        # actually read: absence is not established while a region that could
        # refute it is unread.  Every enforcement branch below acts solely when
        # an absence is asserted — the in-loop recheck, the restatement cap, and
        # the surviving-omission withhold.  A positive finding names a value the
        # run found; no unread region can refute it, so delivering the statement
        # here does nothing but re-invoke the model, whose acknowledgement of the
        # statement then REPLACES the answer it already gave (the caller adopts
        # the post-advisory turn once a statement was delivered).  Turned away
        # before that re-invocation, the positive answer stands.  This mirrors
        # the sibling premature-absence recheck, which gates the same way.
        metrics["decision"] = "no_absence_asserted"
        return messages, None, False
    if not _messages_accept_a_follow_up(messages):
        metrics["decision"] = "unresolved_tool_call_precedes_statement"
        return messages, None, False

    metrics["activated"] = True
    metrics["statement_delivered"] = True
    kept = messages
    delivered = 0
    while True:
        # Rebuilt from the live records each pass rather than held from the first
        # one.  Where nothing has been read since, this is the identical sentence
        # — which is the point: the fact has not changed, so neither does its
        # wording.  Where a region HAS been opened, restating the old sentence
        # would be the runtime telling the model something untrue about its run.
        statement = unread_regions_statement(records, tools=names)
        if statement is None:  # pragma: no cover - unread is non-empty here
            metrics["decision"] = "every_reachable_region_read"
            return kept, None, False
        try:
            request_role = getattr(llm, "request_role", None)
            role_scope = request_role("investigation") if callable(request_role) else nullcontext()
            with role_scope:
                answered = agent.invoke(
                    {"messages": [*kept, HumanMessage(statement)]},
                    config={
                        "recursion_limit": recursion_limit,
                        "callbacks": [investigation_ledger],
                    },
                )
        except _DispatchDenied as exc:
            # The run is out of requests, so it was never asked again.  Whatever
            # is still unread is the ceiling's doing and is not held against it.
            metrics["decision"] = "statement_dispatch_budget_exhausted"
            metrics["statement_delivered"] = delivered > 0
            return kept, exc.reason, False
        except Exception:
            # Stating a fact is an improvement, never a precondition.  Losing it
            # must not lose the report the run already produced.
            metrics["decision"] = "statement_failed"
            metrics["statement_delivered"] = delivered > 0
            return kept, None, False

        raw_messages = answered.get("messages") if isinstance(answered, Mapping) else None
        if not isinstance(raw_messages, list) or len(raw_messages) < len(kept):
            metrics["decision"] = "statement_returned_no_message_state"
            return kept, None, False
        kept = list(raw_messages)
        delivered += 1
        # The first delivery is the statement; every one after it is a
        # restatement, and only those answer to the cap.
        metrics["restatements"] = delivered - 1

        unread = _record_regions(metrics, records, names)
        if not unread:
            # The model went and opened it.  There is nothing left to withhold.
            metrics["decision"] = "region_read_after_statement"
            return kept, None, False
        if not report_asserts_absence(_final_ai_text(kept)):
            # No absence is being asserted any more, so no absence rests on the
            # region that is still unread.
            metrics["decision"] = "stated"
            return kept, None, False
        if delivered - 1 >= _RESTATEMENT_CAP:
            # It has heard the fact as often as the cap permits and still says
            # something is not there without having looked where it could be.
            metrics["decision"] = "omission_survives_restatement"
            metrics["omission_survives"] = True
            return kept, None, True
        if not _messages_accept_a_follow_up(kept):
            # The exchange is mid-call, so it cannot carry another human turn.
            # Unresolved calls are the pending-tool recovery's business.
            metrics["decision"] = "unresolved_tool_call_follows_statement"
            return kept, None, False


__all__ = [
    "EVIDENCE_REGION_METRICS_SCHEMA_ID",
    "empty_evidence_region_metrics",
    "state_unread_evidence_regions",
]
