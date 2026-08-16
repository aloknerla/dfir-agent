"""Hold the run to work its own results say it left unfinished.

Consider a run asked for the computer's address that opens two of the four
interface subkeys the registry had listed it, reads 0.0.0.0 in both, and
concludes — writing, honestly, that two subkeys were not queried.  It had budget
left.  It simply stopped, and the sentence conceding the gap was the last thing
it did about it.

An investigator may not do that.  While something the run has ITSELF shown to be
unexamined is still reachable and the budget still allows reaching it, the
honest sentence is a reason to continue, not a licence to conclude.

So this reads the results, never the prose.  Two facts, both stated by the
result contract rather than inferred from how full a page looked:

* a **page that returned less than it reported** — truncated, or a total above
  what the page covered — which no later call in this run continued.  The stated
  frontier and the question of whether the run ever consumed it are the result
  frontier's reading, reused here rather than copied, so a second opinion about
  what "unfinished" means cannot grow beside the first one.
* whether that same result **also declared its own coverage incomplete**, which
  is the same shortfall said in the coverage block rather than the page block.
  It changes how the fact is worded back to the model and nothing else: both are
  equally unfinished.

Neither invents forensic knowledge, neither names a function, and the sentence
that goes back to the model does neither either: it says what is unfinished in
the run's own terms and stops, because saying which call to make would be this
project choosing the method.

**Unfinished work and a limit are not the same thing**, and the word
"incomplete" does not tell them apart — the result's own continuation does.  A
result that says more exists AND states the next call has left work on the
table.  A result that says its coverage is incomplete and offers no continuation
has said where its evidence ends: the read failed, or the tool covered what it
could.  Asking for more there is asking for a call nothing in the run says
exists, and no number of restatements would produce one.  (Widening such a query
is a real remedy, and the premature-absence recheck asks for it once; this arm
deliberately does not press it a second time, because only the model can know
whether a wider query is even the right question.)

**Why a concession does not release the report.**  The absence gate reads the
report's prose and lets a report that concedes its own bound through
(``_COVERAGE_CONCEDED`` in :mod:`forensic_agent.agent.recovery.premature_absence`),
on the sound grounds that stating your limits is what a forensic report is
supposed to do.  That is true of a limit the run could not have closed; it is
exactly wrong for one it could.  Prose can concede anything, and conceding a
truncated page you still had the budget to continue describes a gap rather than
disposing of it — which is precisely the case above.  This arm therefore never
asks the prose whether a limit was conceded; it asks the RESULTS whether the
limit is still closable, and the two rules then compose without contradiction:

* closable and conceded — withheld here.  The concession is honest and the gap
  is still open; the run had a way to close it and the budget to try.
* unreachable and conceded — released, by both rules.  A read that failed, a
  page that offers no safe continuation, an exhausted budget: nothing the model
  could do would change the record, so the concession IS the correct ending.
* unreachable and not conceded — released here (nothing is unfinished that this
  run could finish) and left to the absence gate, whose business is whether the
  report is entitled to the claim it makes.

Budget exhaustion ends the loop and reports nothing surviving.  A run that ran
out is not a run that gave up, and scoring it as one would measure the ceiling
instead of the reasoning.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from contextlib import nullcontext
from dataclasses import dataclass
from typing import Any

from langchain_core.messages import HumanMessage

from forensic_agent.agent.execution_budget import _DispatchDenied
from forensic_agent.agent.execution_dispatch import _final_ai_text
from forensic_agent.agent.recovery.common import _messages_accept_a_follow_up
from forensic_agent.agent.recovery.result_frontier import frontier_of, unconsumed_frontiers

UNFINISHED_EXAMINATION_METRICS_SCHEMA_ID = "forensic.unfinished-examination.v1"

#: How many times the SAME statement may be put again after the first one.  Held
#: at the region advisory's cap and for the region advisory's reason: this is a
#: bounded check that the fact reached the model, not a negotiation, and every
#: restatement costs the run a request it would rather spend on the evidence.
_RESTATEMENT_CAP = 2

#: One clause per kind of unfinished work, worded as a fact about this run's own
#: records.  Deliberately unit-neutral — a page counts items in one operation and
#: bytes in another, and a sentence true of only one of them would be false in
#: the other half of the surface.
_TRUNCATED_PAGE_CLAUSE = "a result page reported more than it returned, and the rest was not read"
_INCOMPLETE_READ_CLAUSE = "a read reported its own coverage incomplete"


@dataclass(frozen=True, slots=True)
class UnfinishedExaminations:
    """What the retained results state is unfinished, split by whether it is reachable.

    The split is the whole point.  Work this run could still finish is a reason
    to continue; a limit it cannot close is a fact to disclose, and treating the
    second as the first would hold a report hostage to something no further
    request could ever change.
    """

    #: Unconsumed frontiers whose result covered its scope and simply returned
    #: less of it than it reported: a listing read short.
    truncated_pages: int
    #: Unconsumed frontiers whose result ALSO declared its own coverage
    #: incomplete.  Counted apart from the above only so the statement can say
    #: which of the two the run is looking at; both are equally unfinished.
    incomplete_reads: int
    #: Incompleteness nothing further can close: a read that failed, a result
    #: that disclosed a partial view and offered no continuation, or a page
    #: stating more exists while offering no safe way to ask for it.
    unreachable_limits: int

    @property
    def open_count(self) -> int:
        """How much unfinished work this run could still finish."""

        return self.truncated_pages + self.incomplete_reads

    def statement(self) -> str | None:
        """One line naming what is unfinished, or ``None`` when nothing is.

        A fact about the run and nothing else: no function is named, no next call
        is described, and nothing read out of the evidence appears in it.
        """

        clauses = [
            clause
            for clause, present in (
                (_TRUNCATED_PAGE_CLAUSE, self.truncated_pages),
                (_INCOMPLETE_READ_CLAUSE, self.incomplete_reads),
            )
            if present
        ]
        if not clauses:
            return None
        return f"Left unfinished in this run: {'; '.join(clauses)}."


def empty_unfinished_examination_metrics(*, enabled: bool) -> dict[str, object]:
    """The stable telemetry shape for what this run left unfinished.

    Counts and a closed decision vocabulary only: the row says how much was
    unfinished and how the loop ended, never anything that was read.
    """

    return {
        "schema_id": UNFINISHED_EXAMINATION_METRICS_SCHEMA_ID,
        "enabled": enabled,
        "activated": False,
        "decision": "not_evaluated" if enabled else "arm_disabled",
        # Work this run could still finish, and its two kinds.
        "unfinished_examinations": 0,
        "truncated_pages": 0,
        "incomplete_reads": 0,
        # Incompleteness no further request could close.  Recorded beside the
        # rest so a reader can tell a run that stopped short from one that hit
        # the edge of what its evidence and tools can say.
        "unreachable_limits": 0,
        "statement_delivered": False,
        # How many times the same statement was put again after the first.
        "restatements": 0,
        # The ceiling those restatements answer to, recorded beside the count so
        # a run that was released early is distinguishable from one that used up
        # its permitted repetitions.
        "restatement_cap": _RESTATEMENT_CAP,
        # Whether the loop ended with finishable work still unfinished under a
        # report that still concludes.  Only this ends a run's answer.
        "unfinished_survives": False,
    }


def _declares_incomplete_coverage(record: Mapping[str, Any]) -> bool:
    """Whether this record's result said, in its coverage block, that it fell short.

    Read from the wire rather than the parsed contract, as the premature-absence
    recheck reads it: the question is only whether a tool disclosed that it had
    not covered everything, and a record that fails receipt validation for some
    unrelated reason must not thereby become "complete".
    """

    result = record.get("result")
    if not isinstance(result, Mapping):
        return False
    coverage = result.get("coverage")
    return isinstance(coverage, Mapping) and coverage.get("complete") is False


def unfinished_examinations(records: Sequence[Mapping[str, Any]]) -> UnfinishedExaminations:
    """Read, from the results alone, what this run left unfinished.

    Which frontiers are still open is the result frontier's reading, reused: the
    question is whether a SPECIFIC next call was ever made, only a receipt-valid
    result may nominate a call, and one answer to "is this enumeration finished?"
    is better than two.  A record is then unfinished work when it holds an open
    frontier this run could still take, and a disclosed limit when it says it
    fell short with no such frontier on offer.
    """

    remaining, _pages_read, _stated = unconsumed_frontiers(records)
    standing = {frontier.key() for frontier in remaining}
    open_keys = {
        frontier.key() for frontier in remaining if frontier.next_arguments is not None
    }
    # A frontier that states more exists while offering no safe continuation is
    # a limit by the frontier reader's own definition, not a page anyone forgot.
    unreachable = sum(1 for frontier in remaining if frontier.next_arguments is None)
    truncated_pages = 0
    incomplete_reads = 0
    counted: set[str] = set()
    for record in records:
        if not isinstance(record, Mapping):
            continue
        frontier = frontier_of(record)
        key = frontier.key() if frontier is not None else None
        if key is not None and key in standing:
            # Already accounted for above as work or as a limit.  Only the open
            # ones still need saying which kind of shortfall they are, and only
            # once: two identical calls state one frontier, and closing it closes
            # both.
            if key in open_keys and key not in counted:
                counted.add(key)
                if _declares_incomplete_coverage(record):
                    incomplete_reads += 1
                else:
                    truncated_pages += 1
            continue
        if _declares_incomplete_coverage(record):
            unreachable += 1
    return UnfinishedExaminations(
        truncated_pages=truncated_pages,
        incomplete_reads=incomplete_reads,
        unreachable_limits=unreachable,
    )


def _record_unfinished(
    metrics: dict[str, object], records: Sequence[Mapping[str, Any]]
) -> UnfinishedExaminations:
    """Recompute what is unfinished RIGHT NOW and record it.

    Read from the live records on every pass rather than once at the start: the
    whole point of stating the omission is that the model may go and close it,
    and a check that never looks again cannot tell that it did.
    """

    unfinished = unfinished_examinations(records)
    metrics.update(
        {
            "unfinished_examinations": unfinished.open_count,
            "truncated_pages": unfinished.truncated_pages,
            "incomplete_reads": unfinished.incomplete_reads,
            "unreachable_limits": unfinished.unreachable_limits,
        }
    )
    return unfinished


def state_unfinished_examinations(
    messages: list[object],
    records: Sequence[Mapping[str, Any]],
    report: str | None,
    metrics: dict[str, object],
    *,
    llm,
    agent,
    investigation_ledger,
    recursion_limit: int,
) -> tuple[list[object], str | None, bool]:
    """State what this run left unfinished, and hold it to the answer.

    The trigger is deliberately not the absence predicate.  The report above
    asserted no absence at all — it gave an address and conceded, in the same
    breath, that two listed subkeys went unread — so a rule keyed to absence
    would have watched that run stop and said nothing.  What matters here is that
    a conclusion is about to be recorded while the run's own results say the
    examination is unfinished, whether that conclusion concedes the gap or not.

    The statement is put, the LIVE records are read again, and it is put once
    more — up to a small fixed cap — for as long as finishable work is still
    unfinished under a report that still concludes.  The same fact is restated
    rather than escalated: the wording changes only where the fact does.

    Returns the message state to keep, any dispatch-exhaustion reason, and
    whether the unfinished work survived.  That last one is True only when the
    loop ends with finishable work still open, a conclusion still standing, and
    budget not the reason it ended — an exhausted run is spent, not stubborn.
    """

    unfinished = _record_unfinished(metrics, records)
    if unfinished.open_count == 0:
        metrics["decision"] = (
            "every_limit_unreachable" if unfinished.unreachable_limits else "no_unfinished_work"
        )
        return messages, None, False
    if not (report or "").strip():
        # Nothing is about to be published, so this is not the moment before a
        # conclusion.  The terminal request that will produce one is a different
        # stage's business and is left to it.
        metrics["decision"] = "no_conclusion_to_precede"
        return messages, None, False
    if not _messages_accept_a_follow_up(messages):
        metrics["decision"] = "unresolved_tool_call_precedes_statement"
        return messages, None, False

    metrics["activated"] = True
    metrics["statement_delivered"] = True
    kept = messages
    delivered = 0
    while True:
        statement = unfinished.statement()
        if statement is None:  # pragma: no cover - open_count is non-zero here
            metrics["decision"] = "no_unfinished_work"
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
            # is still unfinished is the ceiling's doing and is not held against
            # it.
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

        unfinished = _record_unfinished(metrics, records)
        if unfinished.open_count == 0:
            # Released the moment the work is done, or the moment everything left
            # is beyond this run's reach.  Either way there is nothing further to
            # ask for.
            metrics["decision"] = (
                "remaining_limit_unreachable"
                if unfinished.unreachable_limits
                else "unfinished_work_completed"
            )
            return kept, None, False
        if not _final_ai_text(kept).strip():
            # No conclusion is being recorded any more, so no conclusion rests on
            # the work that is still unfinished.
            metrics["decision"] = "no_conclusion_follows_statement"
            return kept, None, False
        if delivered - 1 >= _RESTATEMENT_CAP:
            # It has heard the fact as often as the cap permits and still records
            # a conclusion over an examination it could have finished.
            metrics["decision"] = "unfinished_survives_restatement"
            metrics["unfinished_survives"] = True
            return kept, None, True
        if not _messages_accept_a_follow_up(kept):
            # The exchange is mid-call, so it cannot carry another human turn.
            # Unresolved calls are the pending-tool recovery's business.
            metrics["decision"] = "unresolved_tool_call_follows_statement"
            return kept, None, False


__all__ = [
    "UNFINISHED_EXAMINATION_METRICS_SCHEMA_ID",
    "UnfinishedExaminations",
    "empty_unfinished_examination_metrics",
    "state_unfinished_examinations",
    "unfinished_examinations",
]
