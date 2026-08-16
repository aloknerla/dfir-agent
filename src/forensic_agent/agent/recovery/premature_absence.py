"""Require exhaustive search before recovering an absence conclusion.

This module also owns the project's single reading of when a report is even
making that claim (:func:`report_asserts_absence`).  Every rule that refuses to
let an absence stand — this recheck, the unread-region gate, the final check over
the verifier's own report — asks it, so they cannot drift apart into one arm
withholding a report another was happy to publish.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from contextlib import nullcontext

from langchain_core.messages import HumanMessage

from forensic_agent.agent.execution_budget import _DispatchDenied
from forensic_agent.agent.recovery.common import _messages_accept_a_follow_up
from forensic_agent.core.toolio import CARDINALITY_TRUNCATED_KEY

_PREMATURE_ABSENCE_METRICS_SCHEMA_ID = "forensic.premature-absence-recheck.v1"

#: A report that says the thing asked for is not there, or cannot be determined.
#: Deliberately narrow: it must be a claim about the examination's outcome, not
#: an incidental "no" somewhere in the prose.  Every branch therefore pairs a
#: negation with a second anchor — an examination verb, an evidential noun, or
#: the evidence it is negated over — and none of them fires on a bare "no".
#:
#: An examiner chooses their own words, so this list is not derivable from first
#: principles and is not treated as complete; it is widened when a wording gets
#: past it.  See :func:`report_asserts_absence` for what is known to still get
#: past it.
#:
#: The windows stop at a clause break (``;`` ``:`` and, where the two anchors
#: belong to one clause, ``,``) as well as at a sentence end.  A loose window
#: read "the header carries no magic bytes of its own; the type was identified
#: from the footer" — a positive finding that says where the answer came from —
#: as a claim of absence, by pairing the "no" of one clause with the verb of the
#: next.
_ABSENCE_CLAIM = re.compile(
    r"(?:"
    # A negated examination verb: "could not be established", "did not find".
    r"\b(?:not|never|cannot|could\s+not|can[’']t|unable\s+to)\b[^.;:!?\n]{0,60}"
    r"\b(?:establish(?:ed)?|determin(?:e|ed)|identif(?:y|ied)|recover(?:ed)?|"
    r"confirm(?:ed)?|locat(?:e|ed)|found|find|detect(?:ed)?|observ(?:e|ed)|"
    r"retriev(?:e|ed)|extract(?:ed)?|discover(?:ed)?)\b"
    r"|"
    # The quantifier before the outcome it negates: "no executables were found".
    r"\b(?:no|none|zero)\b[^.,;:!?\n]{0,50}"
    r"\b(?:were\s+)?(?:observed|found|present|recorded|returned|identified|"
    r"recovered|detected|located|extracted|retrieved|discovered|seen)\b"
    r"|"
    # The same two anchors the other way round, which is the half that was
    # missing: the outcome verb first, then the quantifier — "the image contains
    # no password", "the search returned no results".  "has"/"records" are left
    # out on purpose; a report writes "the registry records no install date for
    # that key, but the file system does" when it is saying where a value IS.
    r"\b(?:contain(?:s|ed)?|hold(?:s)?|held|include[sd]?|show(?:s|ed|n)?|"
    r"reveal(?:s|ed)?|return(?:s|ed)?|yield(?:s|ed)?|produce[sd]?|"
    r"disclos(?:e|es|ed)|report(?:s|ed)?|found|recover(?:s|ed)?|"
    r"detect(?:s|ed)?|locat(?:e|es|ed)|match(?:es|ed)?)\s+(?:any\s+)?no\b"
    r"|"
    # An existential claim about the case: "there is no password on this disk".
    # The lookahead drops the stance idioms, which negate the examiner's own
    # hesitation rather than anything in the evidence.
    r"\bthere\s+(?:is|are|was|were)\s+(?:currently\s+|now\s+)?no\b"
    r"(?!\s+(?:doubt|ambiguity|dispute|question|reason|need|fewer|less|more|"
    r"longer)\b)"
    r"|"
    # A negation and the evidence it ranges over, within one clause: "no password
    # exists on this disk", "nothing of the kind in the image".
    r"\b(?:no|nothing|nowhere)\b[^.,;:!?\n]{0,45}"
    r"\b(?:on|in|within|across|throughout|from)\s+(?:this|that|the|any)\s+"
    r"(?:\w+\s+){0,2}"
    r"(?:disks?|images?|volumes?|drives?|media|medium|captures?|filesystems?|"
    r"file\s+systems?|registry|hives?|partitions?|dumps?|acquisitions?|"
    r"evidence|systems?|devices?|shares?|mailboxes?|archives?|exports?)\b"
    r"|"
    # An evidential noun under negation claims an absence on its own, whatever
    # follows it: "no evidence of tampering", "no trace of the account".
    r"\bno\s+(?:\w+\s+){0,2}"
    r"(?:evidence|traces?|indications?|signs?|references?|mentions?|"
    r"artefacts?|artifacts?)\b"
    r"|"
    r"\bnothing\b[^.,;:!?\n]{0,40}"
    r"\b(?:indicat(?:e|es|ed)|show(?:s|ed)?|suggest(?:s|ed)?|point(?:s|ed)?|"
    r"reveal(?:s|ed)?|establish(?:es|ed)?|identif(?:y|ies|ied)|found|present|"
    r"recovered|remain(?:s|ed)?)\b"
    r"|"
    r"\bdoes\s+not\s+contain\b"
    r"|"
    r"\b(?:is|are|was|were)\s+(?:not\s+)?(?:absent|unavailable|unknown|"
    r"unresolved|undetermined|missing|non-?existent|not\s+established|"
    r"not\s+present|not\s+recorded|not\s+available)\b"
    r")",
    re.IGNORECASE,
)

#: Wording that already concedes the search was bounded. A report that says this
#: has not concluded prematurely; it has reported its own limit, which is what a
#: forensic report is supposed to do.
_COVERAGE_CONCEDED = re.compile(
    r"(?:"
    r"\b(?:partial|bounded|incomplete|truncated|not\s+exhaustive|"
    r"limited\s+(?:scan|search|coverage|projection))\b"
    r"|"
    r"\bcoverage\b[^.!?\n]{0,40}\b(?:incomplete|partial|not\s+complete)\b"
    r"|"
    r"\bcannot\s+be\s+confirmed\s+definitively\b"
    r")",
    re.IGNORECASE,
)

_RECHECK_REQUEST = (
    "Before this is recorded as your conclusion: your report states that "
    "something could not be found or established, but at least one tool result "
    "you relied on declared its own coverage incomplete, or declared that it "
    "returned only some of the rows that matched. Neither can establish that "
    "something is absent, only that it was not in the part you were shown.\n\n"
    "Re-read the coverage and truncation fields of the results above. Where a "
    "result fell short, either widen or continue that query so its coverage is "
    "complete, or narrow it until every matching row fits, or query a view that "
    "is complete, and then answer. If after that the evidence still does not "
    "support an answer, say so and state which limit remains. Do not repeat the "
    "previous report unchanged without checking."
)


def empty_premature_absence_metrics(*, enabled: bool) -> dict[str, object]:
    """Return bounded telemetry for the premature-absence recheck."""

    return {
        "schema_id": _PREMATURE_ABSENCE_METRICS_SCHEMA_ID,
        "enabled": enabled,
        "activated": False,
        "decision": "not_evaluated" if enabled else "arm_disabled",
        "partial_results_seen": 0,
        "recheck_requested": False,
        "report_changed": False,
    }


def _declares_a_cardinality_cut(result: Mapping[str, object]) -> bool:
    """Whether this result declared itself a prefix of the rows that matched.

    The envelope states it in :data:`~forensic_agent.core.toolio.CARDINALITY_TRUNCATED_KEY`,
    and the standardizer has no control key of that name, so on a standardized
    record the same flag arrives under ``data.attributes``.  Both are read, for
    the same reason the coverage and page fields are read off the wire: this asks
    a question about what a tool disclosed, not about whether some later layer
    parsed the disclosure into the shape it prefers.

    It is a THIRD reading beside coverage and paging, not a substitute for either.
    A result can be cut by row count while its coverage block truthfully says the
    tool examined its whole scope and while it carries no page metadata at all —
    that combination is exactly how a cut-short search came to look complete.
    """

    if result.get(CARDINALITY_TRUNCATED_KEY) is True:
        return True
    data = result.get("data")
    attributes = data.get("attributes") if isinstance(data, Mapping) else None
    return isinstance(attributes, Mapping) and attributes.get(CARDINALITY_TRUNCATED_KEY) is True


def _partial_result_count(records: list[dict[str, object]]) -> int:
    """Count receipt-shaped tool results whose coverage was not established.

    Reads the wire form rather than the parsed contract so a result that fails
    receipt validation for an unrelated reason still counts as a coverage
    caveat; the point is only whether anything the report leaned on admitted it
    had not looked everywhere.

    Three ways a result can admit that, and a result needs only one of them: its
    coverage block says the tool fell short of its scope, its page says rows
    remain, or its envelope says the matching set was cut to fit.  The third is
    counted because coverage and paging together do not cover it: a result whose
    rows were dropped without page counters surviving reports complete coverage
    and an untruncated page, which is byte-for-byte what a search that genuinely
    matched nothing reports.  A reader that cannot tell those apart will read a
    bounded search as an exhausted one, and an exhausted search is the only thing
    that can establish that something is not there.
    """

    partial = 0
    for record in records:
        result = record.get("result")
        if not isinstance(result, Mapping):
            continue
        coverage = result.get("coverage")
        page = result.get("page")
        incomplete = isinstance(coverage, Mapping) and coverage.get("complete") is False
        paged = isinstance(page, Mapping) and (
            page.get("truncated") is True or page.get("next_offset") is not None
        )
        if incomplete or paged or _declares_a_cardinality_cut(result):
            partial += 1
    return partial


def report_asserts_absence(report: str | None) -> bool:
    """Return whether this report claims something is not there, without qualifying it.

    The one reading of a report that every absence rule in this project shares.
    Absence is not established while a region that could refute it is unread, or
    while the evidence actually examined was truncated — and a rule that says so
    has to agree with every other rule about which reports are even making the
    claim.  Two private copies of this reading would eventually disagree, and one
    arm would then withhold a report the other was happy to publish.

    Deliberately narrow in the same way the recheck has always been: a report
    that already concedes its own bound has not asserted an absence, it has
    reported its own limit, which is what a forensic report is supposed to do.
    Withholding such a report would punish exactly the behaviour being asked for.

    This reading is an approximation, not a complete rule, and a reader deciding
    how much to trust it should know which one they have.  An examiner writes an
    absence in their own words, so no phrase list can be closed over them, and
    any assertion can be worded around one: an absence stated without a negation
    ("the account was configured for autologon" in place of "no password is
    stored"), a hedge that never names the evidence ("it is unlikely that any
    password exists"), or a negation carried by the question rather than the
    report ("Correct — none.") all pass this predicate and reach the operator
    with no gate having engaged.  The list is widened when a wording gets past it,
    and each widening leaves the class open rather than closed.

    The balance is not symmetric, and the wider reading is deliberate.  Missing a
    claim means an absence drawn from a bounded search is published unchallenged,
    which is the failure this arm exists to prevent; over-reading one costs an
    extra request from the recheck, a restatement from the region advisory, or a
    stated bound appended in finalization — except in
    :func:`~forensic_agent.agent.orchestration.recovery._keep_finding_or_withhold_over_coverage_gap`,
    where a report read as an absence is withheld outright.  That is why every
    branch here needs a second anchor beside the negation, and why the negation
    and that anchor have to sit in the same clause: a report that mentions a
    negative in passing while answering the question is a finding, not a claim of
    absence, and withholding it would lose an answer the run had established.
    """

    if not report or not report.strip():
        return False
    if _ABSENCE_CLAIM.search(report) is None:
        return False
    return _COVERAGE_CONCEDED.search(report) is None


def answer_claims_absence(report: str | None) -> bool:
    """Whether this report's PRINCIPAL claim is an absence, not a side clause.

    :func:`report_asserts_absence` reads the whole report, deliberately wide,
    because during the investigation an unqualified absence anywhere in a draft
    is worth challenging.  A publication disposition needs the narrower
    question: what is this report's ANSWER?  A complete recycle-bin listing can
    produce "There are 4 executable files: ..." followed by the honest side
    clause "No other executable files were found", and the wide reading would
    classify the whole report as an absence claim and withhold the finding — the
    exact overreach NIST SP 800-86's record-and-state-scope rule exists to
    prevent.

    So this reads only the first sentence after any heading decoration — the
    standalone answer the verifier contract puts first — with the same absence
    predicate and the same conceded-coverage release.  A report that leads with
    its finding is a finding; where it leads with an absence, the wide and the
    narrow reading agree.
    """

    from forensic_agent.agent.answer_format import first_sentence

    return report_asserts_absence(first_sentence(report or ""))


def _complete_record_scope_strings(records: Sequence[Mapping[str, object]]) -> tuple[str, ...]:
    """Every scope a coverage-complete record states, normalized for matching.

    Read from the wire form, as every reading in this module is: the question
    is what a tool disclosed about where it looked, and the disclosure lives in
    the call's own path argument, the result's path/key attributes, and the
    coverage scope.  Only records whose coverage block says complete qualify —
    an absence can rest on a completely examined artifact and on nothing else.
    """

    scopes: list[str] = []
    for record in records:
        if not isinstance(record, Mapping):
            continue
        result = record.get("result")
        if not isinstance(result, Mapping):
            continue
        coverage = result.get("coverage")
        if not (isinstance(coverage, Mapping) and coverage.get("complete") is True):
            continue
        candidates: list[object] = []
        arguments = record.get("arguments")
        if isinstance(arguments, Mapping):
            candidates.extend(arguments.values())
        data = result.get("data")
        attributes = data.get("attributes") if isinstance(data, Mapping) else None
        if isinstance(attributes, Mapping):
            candidates.extend(attributes.get(key) for key in ("path", "key", "scope"))
        candidates.append(coverage.get("scope"))
        for candidate in candidates:
            if isinstance(candidate, str) and len(candidate) >= 4:
                scopes.append(_normalized_scope(candidate))
    return tuple(scopes)


def _normalized_scope(value: str) -> str:
    return value.casefold().replace("\\", "/").rstrip("/")


def absence_scoped_to_complete_record(
    report: str | None,
    records: Sequence[Mapping[str, object]],
) -> bool:
    """Whether the principal absence claim names an artifact read in full.

    "No executables besides the four above in <path>" — where <path> is the
    scope of a record whose coverage block says complete — is not a bare
    absence: it rests on an exhausted examination of the artifact it ranges
    over, which is the only thing that can establish one.  What else went
    unread is then a limit to state beside it, never a reason to withhold it.
    """

    from forensic_agent.agent.answer_format import first_sentence

    claim = _normalized_scope(first_sentence(report or ""))
    if not claim:
        return False
    return any(scope in claim for scope in _complete_record_scope_strings(records))


def report_concludes_absence_on_partial_evidence(
    report: str | None,
    records: list[dict[str, object]],
) -> tuple[bool, int]:
    """Return whether an absence claim rests on coverage the run never established.

    "Partial" here is the whole of :func:`_partial_result_count`: a tool that fell
    short of its scope, a page with rows still behind it, or a result cut down to
    the matches that fit.  The last of those is not a smaller version of the other
    two — a search cut at the row count reports complete coverage and an
    untruncated page — so it has to be admitted here or an absence drawn from it
    is published without anything having asked.
    """

    partial = _partial_result_count(records)
    if partial == 0 or not report_asserts_absence(report):
        return False, partial
    return True, partial


def recheck_premature_absence(
    messages: list[object],
    records: list[dict[str, object]],
    report: str | None,
    metrics: dict[str, object],
    *,
    llm,
    agent,
    investigation_ledger,
    recursion_limit: int,
) -> tuple[list[object], str | None]:
    """Ask once more when absence was concluded from partial coverage.

    This supplies no evidence and names nothing the model has not already seen.
    It restates the coverage the tools themselves reported and asks the model to
    exhaust or widen a partial view before recording a negative finding.

    Returns the message state to keep and any dispatch-exhaustion reason.
    """

    should_recheck, partial = report_concludes_absence_on_partial_evidence(report, records)
    metrics["partial_results_seen"] = partial
    if not should_recheck:
        metrics["decision"] = (
            "no_partial_evidence"
            if partial == 0
            else "absence_not_claimed_or_already_qualified"
        )
        return messages, None
    if not _messages_accept_a_follow_up(messages):
        # A trailing tool call still awaits its result. Appending a human turn
        # there produces an invalid sequence, and the provider rejects the whole
        # request. Unresolved calls are the pending-tool recovery's business.
        metrics["decision"] = "unresolved_tool_call_precedes_recheck"
        return messages, None

    metrics["activated"] = True
    metrics["recheck_requested"] = True
    try:
        request_role = getattr(llm, "request_role", None)
        role_scope = request_role("investigation") if callable(request_role) else nullcontext()
        with role_scope:
            rechecked = agent.invoke(
                {"messages": [*messages, HumanMessage(_RECHECK_REQUEST)]},
                config={
                    "recursion_limit": recursion_limit,
                    "callbacks": [investigation_ledger],
                },
            )
    except _DispatchDenied as exc:
        metrics["decision"] = "recheck_dispatch_budget_exhausted"
        return messages, exc.reason
    except Exception:
        # A recheck is an improvement, never a precondition. Losing it must not
        # lose the report the run already produced.
        metrics["decision"] = "recheck_failed"
        return messages, None

    raw_messages = rechecked.get("messages") if isinstance(rechecked, Mapping) else None
    if not isinstance(raw_messages, list) or len(raw_messages) < len(messages):
        metrics["decision"] = "recheck_returned_no_message_state"
        return messages, None
    metrics["decision"] = "rechecked"
    return list(raw_messages), None
