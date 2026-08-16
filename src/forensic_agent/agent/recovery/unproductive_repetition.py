"""Say once, to a run that is circling, that it is asking the same thing again.

Every other arm in this package exists to stop a run concluding too early.  This
one is the mirror.  A run can, asked a single question, issue the same disk-wide
keyword search several times over overlapping subtrees — each result declaring
its coverage incomplete, and each time the run answering that by asking again —
until it spends its whole budget and publishes nothing.  A run that never
concludes is not a cautious run, it is a lost one, and no gate that guards the
conclusion can see a run that never reaches one.

So this reads the recorded results and nothing else.  Three facts, each of them
structural equality over what the run already holds — no model is consulted, no
clock is read, nothing is sampled — so the same records always yield the same
verdict, and a replayed run reaches it at the same point:

* **the same call again** — one tool name with byte-identical canonical
  arguments, issued at least ``_REPEAT_THRESHOLD`` times inside the window.
  Identical arguments are also what separates this from paging: a continuation
  carries the frontier its predecessor stated, so a run working through a large
  result varies its arguments by construction and is never counted here.
* **different calls, the same content** — one observation identity returned by at
  least ``_REPEAT_THRESHOLD`` DISTINCT calls.  The run varied its query and the
  evidence handed back exactly what it had already been given, which is motion
  without information.  This is the pattern such a loop actually shows: several
  searches that are not identical, over subtrees that overlap, returning the same
  nothing.
* **the same failure again** — one tool returning a byte-identical error block at
  least ``_REPEAT_THRESHOLD`` times.  Identical, not merely similar: three "not
  present" replies naming three different paths are three real findings about
  the evidence, and only a failure that repeats itself unchanged is a loop.

**Which digest identifies an observation.**  ``payload_sha256`` names a RESULT,
not an observation.  Its canonical payload covers the provenance, whose
``invocation_id`` carries a per-call ordinal, so two calls can never share it and
an equality test over it would never fire once.  The digest that identifies the
observation is ``provenance.raw_output_sha256``, taken over the tool's raw output
before standardization: two calls that read the same bytes carry the same one.
It is recorded only where the oversight chain bound the call, so where it is
absent the same equality is taken over the result's own content-bearing blocks —
status, data, page and coverage — which is the same question asked of the wire
the run retained.  The two are namespaced apart so a window holding both kinds
can never match one against the other.

**Errors carry no content identity.**  An error observed nothing: its data block
is empty and its page and coverage are defaults, so every error in the window
would digest alike and the second pattern would fire on any two unrelated
failures.  Failures are the third pattern's business, where the error block
itself — code, message and details — is what has to be identical.

The first and third patterns overlap where a run hammers one failing call: both
are then true, and the sentence says both, because it says what is repeating and
a run repeating a failing call is doing exactly the two things it names.

**One nudge, and nothing else.**  The model is told once per pattern that it is
repeating itself, and that a different instrument or a narrower query is what
moves the run on.  The sentence names no tool, no path and no value read out of
the evidence: it is assembled from fixed clauses in a fixed order, so it is
byte-identical on every case.  A nudge that varied with the case would be this
harness handing the model its investigation.

This arm never ends a run.  It has no veto to return and no report to withhold —
a run that is circling still holds whatever evidence it did gather, and taking
its answer away would punish it twice for one mistake.  The only reason it can
return is a dispatch budget the run had already exhausted before it asked.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Mapping, Sequence
from contextlib import nullcontext
from dataclasses import dataclass
from typing import Any

from langchain_core.messages import HumanMessage

from forensic_agent.agent.execution_budget import _DispatchDenied
from forensic_agent.agent.recovery.common import _messages_accept_a_follow_up
from forensic_agent.core.repro import canonical_json, sha256_hex

UNPRODUCTIVE_REPETITION_METRICS_SCHEMA_ID = "forensic.unproductive-repetition.v1"

#: How many recorded results the check looks back over.  Half the default step
#: budget: wide enough to see a loop that interleaves other work between its
#: repeats, narrow enough that a query legitimately revisited much later — after
#: an intervening finding gave it a new meaning — is not called one.
_WINDOW = 10

#: How many occurrences inside the window make repetition a pattern rather than a
#: coincidence.  Two is a retry, which is ordinary and frequently correct; three
#: is a habit, and the habit is what the run cannot see in itself.
_REPEAT_THRESHOLD = 3

#: Stable pattern names.  They reach the receipt and are compared against the
#: patterns already nudged, so they are part of the recorded vocabulary and not
#: display text.
_REPEATED_CALL = "repeated_call"
_UNCHANGED_RESULT = "unchanged_result"
_REPEATED_FAILURE = "repeated_failure"

#: One clause per pattern, and the fixed order they are said in.  The order is
#: fixed rather than taken from the records so the sentence depends only on WHICH
#: patterns fired, never on the order the repeats happened to arrive in.
_CLAUSES: tuple[tuple[str, str], ...] = (
    (_REPEATED_CALL, "a query already issued in this run was issued again unchanged"),
    (_UNCHANGED_RESULT, "separate queries returned byte-identical content"),
    (_REPEATED_FAILURE, "a query failed, and the same failure came back again"),
)

_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True, slots=True)
class UnproductiveRepetition:
    """What the retained results say this run is repeating, by pattern.

    Counts of DISTINCT repeated things, not of repeats: a run that asked one
    question four times and another three times has two repeated calls, which is
    what a reader of the receipt wants to know.  The sentence put to the model
    uses only which of them are non-zero.
    """

    #: Distinct (tool, arguments) pairs issued at or above the threshold.
    repeated_calls: int
    #: Distinct observation identities returned to that many distinct calls.
    unchanged_results: int
    #: Distinct (tool, error) pairs returned at or above the threshold.
    repeated_failures: int

    @property
    def patterns(self) -> tuple[str, ...]:
        """The pattern names that fired, in the order they are said in."""

        counts = {
            _REPEATED_CALL: self.repeated_calls,
            _UNCHANGED_RESULT: self.unchanged_results,
            _REPEATED_FAILURE: self.repeated_failures,
        }
        return tuple(name for name, _clause in _CLAUSES if counts[name])


def statement_for(patterns: Sequence[str]) -> str | None:
    """The one sentence for these patterns, or ``None`` when none of them fired.

    Assembled from fixed clauses, so it carries nothing read out of this case and
    is byte-identical wherever the same patterns fire.  It states the repetition
    and the two ways out of it — a different instrument, or a narrower query —
    and stops there, because saying which instrument would be this project
    choosing the method.
    """

    named = set(patterns)
    clauses = [clause for name, clause in _CLAUSES if name in named]
    if not clauses:
        return None
    return (
        f"Repeated without new information in this run: {'; '.join(clauses)}. "
        "Issuing it again in the same form returns the same thing. Reach for a "
        "different kind of instrument, or narrow the query so that it asks "
        "something the previous one did not."
    )


def empty_unproductive_repetition_metrics(*, enabled: bool) -> dict[str, object]:
    """The stable telemetry shape for what this run repeated.

    Counts, a closed decision vocabulary and the fixed pattern names only: the
    row says how much repeated and how the arm ended, never what was repeated.
    """

    return {
        "schema_id": UNPRODUCTIVE_REPETITION_METRICS_SCHEMA_ID,
        "enabled": enabled,
        "activated": False,
        "decision": "not_evaluated" if enabled else "arm_disabled",
        # The two constants the counts below are meaningless without: a reader of
        # the receipt cannot tell a quiet run from a narrow window otherwise.
        "window": _WINDOW,
        "repeat_threshold": _REPEAT_THRESHOLD,
        "repeated_calls": 0,
        "unchanged_results": 0,
        "repeated_failures": 0,
        "patterns_detected": [],
        # What has already been said. A pattern named here is never said again,
        # which is what makes this a single-shot nudge per pattern rather than a
        # standing complaint.
        "patterns_nudged": [],
        "nudge_delivered": False,
    }


def _call_key(record: Mapping[str, Any]) -> str | None:
    """The canonical identity of the call this record holds, or ``None``.

    Name and arguments together: the same arguments given to two different tools
    are two different questions, and one tool asked two different things is not
    repeating itself.
    """

    tool = record.get("tool")
    arguments = record.get("arguments")
    if not isinstance(tool, str) or not tool or not isinstance(arguments, Mapping):
        return None
    return canonical_json([tool, dict(arguments)])


def _content_key(record: Mapping[str, Any]) -> str | None:
    """The identity of what this record OBSERVED, or ``None`` when it observed nothing.

    Prefers the digest the run itself recorded over the raw pre-standardization
    output; falls back to the same equality taken over the retained wire's
    content-bearing blocks where the oversight chain bound no digest to the call.
    The two are namespaced apart because they answer the same question about
    different bytes, and a window holding both must not match one against the
    other.
    """

    result = record.get("result")
    if not isinstance(result, Mapping):
        return None
    if result.get("status") == "error":
        # An error observed nothing, and every error's content blocks look alike.
        # Comparing them would make any two unrelated failures "the same content".
        return None
    provenance = result.get("provenance")
    if isinstance(provenance, Mapping):
        recorded = provenance.get("raw_output_sha256")
        if isinstance(recorded, str) and _SHA256_HEX.fullmatch(recorded):
            return f"raw:{recorded}"
    return "wire:" + sha256_hex(
        canonical_json([result.get(field) for field in ("status", "data", "page", "coverage")])
    )


def _failure_key(record: Mapping[str, Any]) -> str | None:
    """The identity of this record's failure, or ``None`` when it did not fail.

    The whole error block, not the code alone: a code says which kind of thing
    went wrong, and two calls failing the same KIND of way over different paths
    are two findings, not a loop.  Only a failure identical down to its message
    and details is one.
    """

    tool = record.get("tool")
    result = record.get("result")
    if not isinstance(tool, str) or not tool or not isinstance(result, Mapping):
        return None
    error = result.get("error")
    if not isinstance(error, Mapping):
        return None
    return canonical_json([tool, dict(error)])


def unproductive_repetition(
    records: Sequence[Mapping[str, Any]],
) -> UnproductiveRepetition:
    """Read, from the last few records alone, what this run is repeating.

    The window is a tail of the records rather than a filter over all of them:
    what matters is whether the run is circling NOW, and a query it asked twice
    early and once again much later, having learned something in between, is not
    the failure this arm was built for.
    """

    window = [record for record in records[-_WINDOW:] if isinstance(record, Mapping)]
    call_counts: Counter[str] = Counter()
    failure_counts: Counter[str] = Counter()
    callers_by_content: dict[str, set[str]] = {}
    for record in window:
        call = _call_key(record)
        failure = _failure_key(record)
        if failure is not None:
            failure_counts[failure] += 1
        if call is None:
            # Nothing to compare: a record whose call cannot be read can neither
            # repeat another call nor stand as a distinct caller of a result.
            continue
        call_counts[call] += 1
        content = _content_key(record)
        if content is not None:
            callers_by_content.setdefault(content, set()).add(call)
    return UnproductiveRepetition(
        repeated_calls=sum(1 for count in call_counts.values() if count >= _REPEAT_THRESHOLD),
        unchanged_results=sum(
            1 for callers in callers_by_content.values() if len(callers) >= _REPEAT_THRESHOLD
        ),
        repeated_failures=sum(
            1 for count in failure_counts.values() if count >= _REPEAT_THRESHOLD
        ),
    )


def _patterns_already_nudged(metrics: Mapping[str, Any]) -> tuple[str, ...]:
    """The patterns this run has already been told about.

    Read back out of the metrics rather than kept in a module-level or object
    state, for the same reason every other count here lives there: the receipt is
    the record, and a suppression the receipt cannot show is a suppression nobody
    can audit.
    """

    nudged = metrics.get("patterns_nudged")
    if not isinstance(nudged, Sequence) or isinstance(nudged, (str, bytes)):
        return ()
    return tuple(name for name in nudged if isinstance(name, str))


def _record_repetition(
    metrics: dict[str, object], records: Sequence[Mapping[str, Any]]
) -> UnproductiveRepetition:
    """Recompute what is repeating RIGHT NOW and record it."""

    repetition = unproductive_repetition(records)
    metrics.update(
        {
            "repeated_calls": repetition.repeated_calls,
            "unchanged_results": repetition.unchanged_results,
            "repeated_failures": repetition.repeated_failures,
            "patterns_detected": list(repetition.patterns),
        }
    )
    return repetition


def state_unproductive_repetition(
    messages: list[object],
    records: Sequence[Mapping[str, Any]],
    metrics: dict[str, object],
    *,
    llm,
    agent,
    investigation_ledger,
    recursion_limit: int,
) -> tuple[list[object], str | None]:
    """Tell the run once that it is repeating itself, and leave the rest alone.

    Deliberately asks for no report and reads none.  Such a run has no conclusion
    to precede — it consumes its whole budget and publishes nothing — so a rule
    keyed to the moment before a conclusion would watch it circle and say nothing.
    What matters here is only whether the records show repetition, and that is
    true of a run at any point in its life.

    A pattern is stated once.  It is put again for a pattern the run has not been
    told about yet, never for one it has, because the second telling of the same
    fact is no longer information — it is pressure, and pressure is how a harness
    starts steering the investigation it is supposed to be observing.

    Returns the message state to keep and any dispatch-exhaustion reason.  There
    is deliberately no third element: this arm has no verdict to hand back, so no
    caller can be written that ends a run on its say-so.
    """

    repetition = _record_repetition(metrics, records)
    already = _patterns_already_nudged(metrics)
    unsaid = tuple(name for name in repetition.patterns if name not in already)
    if not repetition.patterns:
        metrics["decision"] = "no_unproductive_repetition"
        return messages, None
    if not unsaid:
        # It has been told. Saying it a second time spends a request the run would
        # rather spend on the evidence, and adds nothing it has not already heard.
        metrics["decision"] = "every_pattern_already_stated"
        return messages, None
    if not _messages_accept_a_follow_up(messages):
        # A trailing tool call still awaits its result, and a human turn inserted
        # there is an invalid exchange the provider rejects whole. Unresolved
        # calls are the pending-tool recovery's business.
        metrics["decision"] = "unresolved_tool_call_precedes_statement"
        return messages, None
    statement = statement_for(unsaid)
    if statement is None:  # pragma: no cover - unsaid is non-empty here
        metrics["decision"] = "no_unproductive_repetition"
        return messages, None

    metrics["activated"] = True
    try:
        request_role = getattr(llm, "request_role", None)
        role_scope = request_role("investigation") if callable(request_role) else nullcontext()
        with role_scope:
            answered = agent.invoke(
                {"messages": [*messages, HumanMessage(statement)]},
                config={
                    "recursion_limit": recursion_limit,
                    "callbacks": [investigation_ledger],
                },
            )
    except _DispatchDenied as exc:
        # The run is out of requests, so it was never told. Nothing is marked as
        # said, and the exhaustion the caller already had is handed back unchanged.
        metrics["decision"] = "statement_dispatch_budget_exhausted"
        return messages, exc.reason
    except Exception:
        # Stating a fact is an improvement, never a precondition. Losing it must
        # not lose the evidence and the message state the run already has.
        metrics["decision"] = "statement_failed"
        return messages, None

    raw_messages = answered.get("messages") if isinstance(answered, Mapping) else None
    if not isinstance(raw_messages, list) or len(raw_messages) < len(messages):
        metrics["decision"] = "statement_returned_no_message_state"
        return messages, None
    metrics["nudge_delivered"] = True
    metrics["patterns_nudged"] = sorted({*already, *unsaid})
    metrics["decision"] = "repetition_stated"
    return list(raw_messages), None


__all__ = [
    "UNPRODUCTIVE_REPETITION_METRICS_SCHEMA_ID",
    "UnproductiveRepetition",
    "empty_unproductive_repetition_metrics",
    "state_unproductive_repetition",
    "statement_for",
    "unproductive_repetition",
]
