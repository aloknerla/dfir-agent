"""Safe, bounded projections for the interactive forensic console.

The console must make an investigation understandable without reproducing raw
evidence, host paths, credentials, or model-internal reasoning.  These helpers
therefore project only the typed metadata of standardized tool results.

The executed-command projection is the one deliberate exception, and only in one
direction: it reproduces the arguments the model itself proposed, in full,
because an operator cannot audit a call they can read only half of.  Those are
the model's own words about the evidence, never the host's, and an argument name
known to carry a secret is withheld rather than printed.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

MAX_DISPLAYED_FINDINGS = 12
#: Columns the arguments may occupy on one activity line.  The rest of the line
#: carries the icon, the tool name and the elapsed time, and the whole line has
#: to fit the bounded console panels beside it.
ACTIVITY_DETAIL_WIDTH = 62
#: Shortest shortened value that still says something: a few leading characters,
#: the elision mark, and a tail long enough to tell two sibling paths apart.
_MIN_ARGUMENT_VALUE_WIDTH = 12
#: The argument that names which capability of a consolidated function ran.  It
#: is not an ordinary argument competing for a share of the line: ``read_key``
#: and ``read_value`` under one ``registry_query`` are two different readings of
#: the evidence, and a feed that shortens the one to ``rea…_key`` has stopped
#: saying which of them the model made.  It is therefore rendered whole, before
#: the remaining room is divided among the rest.
_OPERATION_ARGUMENT = "operation"
#: Ceiling on ONE argument value in the full command listing.  The listing exists
#: so the call can be read exactly as the model made it, so this sits far above
#: any argument a forensic operation takes; a value that still exceeds it keeps
#: its beginning and the row states how long it really was, because silently
#: cutting a value is the very defect the listing exists to correct.
MAX_LISTED_ARGUMENT_VALUE = 4000
_IDENTIFIER = re.compile(r"[A-Za-z0-9_.:-]+")
_SHA256 = re.compile(r"[0-9a-fA-F]{64}")
_KNOWN_STATUSES = frozenset({"ok", "partial", "error", "blocked"})
#: Argument names known to carry a secret rather than an observation.  One list
#: serves both the live activity feed and the full command listing: a name that
#: is unsafe to print abbreviated is no safer printed whole, and two lists would
#: eventually disagree about which.
_SENSITIVE_ARGUMENTS = frozenset(
    {
        "api_key",
        "apikey",
        "authorization",
        "passphrase",
        "password",
        "secret",
        "token",
    }
)

#: The four outcomes an oversight action entry states about the call it
#: recorded.  They are the ONE vocabulary in which every console view names what
#: became of a call: a listing that collapsed them into words of its own was how
#: a single call came to read ``BLOCKED`` in the reconstruction and ``REFUSED``
#: in the listing printed beside it.  Spelled as literals rather than imported
#: from the oversight package: this module reads a recorded trace as data and
#: sits on the import path that draws the prompt, which the agent stack has to
#: stay off of.  A test pins them to the recorder's own names so the two
#: vocabularies cannot drift.
RECORDED_EXECUTED = "executed"
RECORDED_FAILED = "failed"
RECORDED_REFUSED_BY_OVERSIGHT = "refused_by_oversight"
RECORDED_REFUSED_BY_TOOL = "refused_by_tool"

RECORDED_OUTCOMES = frozenset(
    {
        RECORDED_EXECUTED,
        RECORDED_FAILED,
        RECORDED_REFUSED_BY_OVERSIGHT,
        RECORDED_REFUSED_BY_TOOL,
    }
)

#: What the run's final-answer contract says the answer on screen actually is.
#: Named here rather than written out at each render site because the answer
#: panel and the run summary both key off it: framing every answer as a verified
#: one, in the success colour and under the verified glyph, while the summary
#: three panels below said the run had accepted no answer at all would be a
#: screen that reads as settled about a degraded result — the defect this console
#: exists to avoid, so the two read one value.
ANSWER_VERIFIED = "verified model report"
ANSWER_UNVERIFIED_DRAFT = "unverified model draft"
#: An answer the runtime assembled: the values in it were inserted from stored
#: results and the model never typed them.  It is a THIRD outcome and not a
#: variant of either other one, because no verifier ran and the sentences around
#: those values are still the model's.  Without it an assembled answer would
#: read as "no accepted answer" even though a value-bearing answer was delivered.
ANSWER_ASSEMBLED = "runtime-assembled answer"
#: A verified report the absence gate published with the coverage it never
#: reached stated beneath it.  The verification ran and succeeded and the
#: sentences are the model's; only the statement of the limit was composed by
#: the runtime, which is why this qualifies a verified answer rather than being
#: a fourth way of accepting one.  Without it every bounded publication read as
#: "no accepted answer" while the run record said the answer was published.
ANSWER_VERIFIED_WITH_BOUND = "verified model report, coverage bound stated"

#: The keep-or-mark backstop publishes the model's own draft, with a marker
#: naming the values the bounded bundle never carried to the verifier. The
#: verifier ran and returned; what it could not do was judge those values, so
#: this is a published answer that is verified in part, and neither a fully
#: verified report nor an unrequested draft. It needs its own name because
#: reading it as either would misstate which half of the answer was checked.
ANSWER_DRAFT_VERIFICATION_INCOMPLETE = "model draft, verification incomplete"
ANSWER_NONE = "no accepted answer"

#: What the final-answer contract's outcome triple means on this console.  Only
#: a fully self-consistent triple names an accepted answer; every triple absent
#: from this table, contradictory ones included, is :data:`ANSWER_NONE`.
#:
#: Held as a table rather than as a chain of comparisons because the same
#: knowledge is written a second time in
#: :mod:`forensic_agent.reporting.trace_svg`, and both copies have now been
#: missing the same newly recorded outcome twice.  Two tables can be compared
#: against each other by a test; two chains of comparisons cannot.
ACCEPTED_ANSWER_SOURCES: Mapping[tuple[str, str, str], str] = {
    ("verifier", "verified", "published"): ANSWER_VERIFIED,
    ("verifier", "verified", "published_with_stated_bound"): ANSWER_VERIFIED_WITH_BOUND,
    ("investigation_model_draft", "not_requested", "published"): ANSWER_UNVERIFIED_DRAFT,
    ("runtime_assembly", "not_requested", "published"): ANSWER_ASSEMBLED,
}

#: The keep-or-mark backstop publishes the model's own grounded draft, gap
#: stated, whenever the final check could not certify it — for many reasons,
#: each recorded verbatim in ``verification_outcome``. Enumerating every
#: (source, reason, publication) triple in the tables above was both a
#: maintenance trap and the exact defect this module guards against (two tables
#: drifting apart). The answer source is instead identified by the published
#: pair it shares, so a new inconclusive reason needs no table change here.
_VERIFICATION_INCOMPLETE_PUBLICATION = "published_draft_verification_incomplete"


def is_verification_incomplete_publication(
    accepted_source: str, publication_outcome: str
) -> bool:
    """Whether the run published a draft the final check could not certify."""

    return (
        accepted_source == "investigation_model_draft"
        and publication_outcome == _VERIFICATION_INCOMPLETE_PUBLICATION
    )


@dataclass(frozen=True, slots=True)
class FindingSummary:
    """A non-evidentiary display projection of one standardized tool result."""

    sequence: int
    tool: str
    status: str
    data_type: str
    records: str
    coverage: str
    notes: str
    receipt: str


@dataclass(frozen=True, slots=True)
class FindingsProjection:
    rows: tuple[FindingSummary, ...]
    omitted: int


@dataclass(frozen=True, slots=True)
class IncompleteExamination:
    """What a run that published no conclusion is still able to say for itself.

    Every field is composed from the run's own control record: a closed cause
    vocabulary, a bound name, and counts.  Nothing read from the evidence enters
    it, and it never carries or reconstructs an answer — a run that published no
    conclusion has none, and inventing one here is the failure this projection
    exists to make visible rather than to commit.
    """

    statement: str
    cause: str
    bound: str | None
    evidence_readings: int
    model_draft_present: bool


@dataclass(frozen=True, slots=True)
class RecordedQuestion:
    """What was asked, separated from everything composed around it.

    The trace records the whole user message the model received, which is the
    right thing to record: prior exchanges, delimiters and standing instructions
    were all in front of the model and a view that hid them would misdescribe
    the run.  It is the wrong thing to print on a line labelled ``question``,
    where screens of session context bury the one sentence the label promises.
    So the two are separated here and neither is thrown away.
    """

    #: The sentence the operator actually asked.
    asked: str
    #: The complete composed message, exactly as recorded.
    composed: str
    #: Characters of the composed message that the summary line does not show.
    withheld_characters: int

    @property
    def has_context(self) -> bool:
        return self.withheld_characters > 0


@dataclass(frozen=True, slots=True)
class PageFacts:
    """The typed pagination record, carried as recorded rather than as a phrase."""

    returned: int | None
    total: int | None
    truncated: bool | None
    next_offset: int | None
    #: The counting unit, an identifier of the result contract ("item", "byte").
    unit: str


@dataclass(frozen=True, slots=True)
class CoverageFacts:
    """What the result declares about how completely the source was examined."""

    complete: bool | None
    #: The scope the reading covered, as the record states it.
    scope: str
    #: The result's own statement of why coverage stopped short, or "".
    reason: str


@dataclass(frozen=True, slots=True)
class FindingDetail:
    """One finding at full length, still without a byte of what it observed.

    The listing answers "which calls produced findings"; this answers "what came
    of this one" — what it warned of, what it declared when it failed, where it
    was read from, and the digest it was recorded under, given whole so it can
    be matched against the run record.  ``data.attributes`` and ``data.items``
    are the observation itself and stay where they are.

    Warning messages are carried in full, deliberately: this detail is the
    operator's review surface, and an analyst auditing a bounded reading needs
    the tool's own statement of the bound, not a code standing in for it.
    Nothing model-facing renders from here, and the declared error stays a code.
    """

    summary: FindingSummary
    #: Warning codes, in the order recorded.
    warnings: tuple[str, ...]
    #: The failure the envelope declares, by code, or "" when it declares none.
    error: str
    #: The receipt digest in full, or "—" when the result carries no receipt.
    receipt: str
    #: Position of the oversight entry that recorded the call, so the arguments
    #: the model actually passed can be shown beside the result they produced.
    #: ``None`` when the result binds to no entry on the chain.
    oversight_sequence: int | None
    #: The epistemic class the record carries (observed/derived/reference/…),
    #: or "" where the record predates the field and established none.
    evidence_class: str = ""
    #: The evidence source the reading names: its registry id and its URI.
    source_id: str = ""
    source_uri: str = ""
    #: The precise artifact within that source.
    artifact_type: str = ""
    artifact_locator: str = ""
    #: The documented components that produced the bytes, as "name version".
    producers: tuple[str, ...] = ()
    #: The full text of each warning, parallel to :attr:`warnings`; "" where a
    #: recorded warning carried no message.
    warning_messages: tuple[str, ...] = ()
    page: PageFacts = PageFacts(
        returned=None, total=None, truncated=None, next_offset=None, unit=""
    )
    coverage: CoverageFacts = CoverageFacts(complete=None, scope="", reason="")


@dataclass(frozen=True, slots=True)
class ExecutedCallArgument:
    """One argument of one recorded call, as the model actually passed it."""

    name: str
    #: The value in full.  Empty when the name is on the withheld list, and
    #: bounded to :data:`MAX_LISTED_ARGUMENT_VALUE` only when the value is
    #: enormous — in which case ``total_characters`` says what it really was.
    value: str
    withheld: bool = False
    total_characters: int | None = None


@dataclass(frozen=True, slots=True)
class ExecutedCall:
    """One tool call the run recorded, projected for the command listing."""

    sequence: int
    function: str
    #: The operation the call selected, or "" when it declared none.  Never
    #: translated anywhere: it is the identifier the model wrote.
    operation: str
    #: What the record says became of the call, as one of :data:`RECORDED_OUTCOMES`.
    #: Carried through unreduced so every view names it the same way.
    outcome: str
    duration_s: float | None
    arguments: tuple[ExecutedCallArgument, ...]
    #: What the gate decided, distinct from what became of the call: a
    #: permitted call can still be refused by the tool it reached.  Absent in a
    #: pre-field trace, where a call the record does not mark denied is read as
    #: permitted, exactly as :func:`classify_action_outcome` reads it.
    allowed: bool = True
    #: The recorded risk name, or "" where the trace predates the field.
    risk_name: str = ""
    #: The gate's own grounds: the decision reason for a permitted call, the
    #: denial ground for one it refused.  Carried whole — this is the one
    #: record of WHY, and a view that cannot show it cannot be reviewed against.
    reasons: tuple[str, ...] = ()
    #: The capabilities this call required — the authority it requested, to be
    #: read against the granted set the case_open entry records.
    capabilities: tuple[str, ...] = ()
    #: What the tool or the failure declared, or "" when nothing was declared.
    outcome_detail: str = ""
    #: Every output digest the entry recorded, as (field name, digest) pairs.
    #: The names are the recorder's own and are never translated.
    output_digests: tuple[tuple[str, str], ...] = ()
    #: The sentence the refusing layer wrote, read back out of the recorded
    #: output.  ``reasons`` names a refusal by its code; this is the readable
    #: form of the same fact, and it is what a view leads with.  Empty when the
    #: entry carries none.
    refusal_message: str = ""


@dataclass(frozen=True, slots=True)
class ControlSummary:
    """Bounded execution metadata suitable for the user-facing console."""

    verification: str
    answer_source: str
    tool_calls: int
    findings: int
    model_requests: int | None
    trace_id: str
    #: The final-answer contract's own three outcomes, carried whenever they do
    #: not name an accepted answer. "no accepted answer" says that the triple was
    #: not one of the four the table admits and nothing else; without the values
    #: themselves a reader cannot tell a run that failed verification from one
    #: that passed it and was refused at publication, and the two need opposite
    #: repairs. Empty when the answer was accepted, because then it adds nothing.
    unaccepted_outcome: tuple[str, str, str] | None = None


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _safe_identifier(value: object, *, fallback: str, limit: int = 48) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        return fallback
    if _IDENTIFIER.fullmatch(value) is None:
        return fallback
    return value


def _nonnegative_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _record_count(
    page: Mapping[str, object],
    data: Mapping[str, object],
    *,
    status: str,
) -> str:
    returned = _nonnegative_int(page.get("returned"))
    total = _nonnegative_int(page.get("total"))
    if returned is None:
        return "—"
    attributes = data.get("attributes")
    items = data.get("items")
    if (
        returned == 0
        and total is None
        and status in {"ok", "partial"}
        and isinstance(attributes, Mapping)
        and bool(attributes)
        and isinstance(items, Sequence)
        and not isinstance(items, (str, bytes))
        and not items
    ):
        # Page counters describe repeatable ``data.items``. A successful
        # attributes-only payload is one scalar finding, not an empty result.
        return "1 result"
    if total is not None:
        return f"{returned}/{total} records"
    return f"{returned} records"


def _receipt_digest(row: Mapping[str, object], result: Mapping[str, object]) -> str:
    candidate = row.get("payload_sha256")
    if not isinstance(candidate, str):
        candidate = _mapping(result.get("receipt")).get("payload_sha256")
    if not isinstance(candidate, str) or _SHA256.fullmatch(candidate) is None:
        return "—"
    return candidate.lower()


def _receipt_prefix(row: Mapping[str, object], result: Mapping[str, object]) -> str:
    digest = _receipt_digest(row, result)
    return digest if digest == "—" else digest[:12] + "…"


def _elide_middle(value: str, width: int) -> str:
    """Shorten a value from the middle, where a repeated prefix carries least."""

    if len(value) <= width:
        return value
    if width <= 1:
        return "…"
    # Sibling calls share their leading path components and differ at the end,
    # so the tail keeps the larger share of what is left.
    head = (width - 1) // 3
    tail = width - 1 - head
    return f"{value[:head]}…{value[-tail:]}"


def summarize_call_arguments(
    arguments: object,
    *,
    width: int = ACTIVITY_DETAIL_WIDTH,
) -> str:
    """Render one tool call's arguments so it stays distinguishable from the next.

    The activity feed is how an operator follows where the investigation went,
    which only works while two calls read differently.  Cutting the rendered
    line at a fixed column removed exactly the discriminating part — the tail of
    a long path — and printed several distinct calls as one repeated line.  Every
    argument therefore keeps its name and its ends, short values are never
    shortened, and the room they leave goes to the long ones.

    ``width`` is what the arguments of an ordinary call are meant to occupy, not
    a hard ceiling: an argument is never dropped to respect it, so a call
    carrying unusually many of them is allowed to run over rather than hide one.
    The operation is likewise never shortened to respect it — see
    :data:`_OPERATION_ARGUMENT`.

    These are the arguments the model proposed, never host paths or credentials
    of the machine running the console; argument names known to carry a secret
    are replaced rather than displayed shortened.
    """

    pairs = [
        (
            str(name),
            "[REDACTED]"
            if str(name).casefold() in _SENSITIVE_ARGUMENTS
            # A value spanning lines would break the one-call-one-line feed.
            else " ".join(str(value).split()),
        )
        for name, value in _mapping(arguments).items()
        if value is not None
    ]
    if not pairs:
        return ""

    labels = sum(len(name) + 1 for name, _ in pairs) + 2 * (len(pairs) - 1)
    room = max(width - labels, 0)
    widths = [0] * len(pairs)
    divisible = []
    for index, (name, value) in enumerate(pairs):
        if name.casefold() == _OPERATION_ARGUMENT:
            widths[index] = len(value)
            room = max(room - len(value), 0)
        else:
            divisible.append(index)
    shortest_first = sorted(divisible, key=lambda index: len(pairs[index][1]))
    for taken, index in enumerate(shortest_first):
        share = max(room // (len(divisible) - taken), _MIN_ARGUMENT_VALUE_WIDTH)
        widths[index] = min(len(pairs[index][1]), share)
        room = max(room - widths[index], 0)
    return ", ".join(
        f"{name}={_elide_middle(value, widths[index])}"
        for index, (name, value) in enumerate(pairs)
    )


def _argument_value(value: object) -> str:
    """Render one argument value the way the model expressed it.

    Arguments reach the recorder as JSON, so a structure is rendered back as
    JSON rather than as a Python repr: the operator is meant to be able to
    compare the row against the record without translating quote styles in
    their head.  Line breaks inside a value are kept — the listing is a full
    account of the call, not a one-line feed, and a cell may run to several
    lines.
    """

    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, default=str)


def _listed_argument(
    name: object,
    value: object,
    *,
    bound: int | None = MAX_LISTED_ARGUMENT_VALUE,
) -> ExecutedCallArgument:
    """Project one argument, withholding a secret and bounding only the enormous.

    ``bound=None`` lifts the ceiling entirely for the single-call detail view,
    which exists precisely so one call can be read whole; a withheld secret
    stays withheld there too, because a name that is unsafe to print in a
    listing is no safer printed in a panel.
    """

    label = str(name)
    if label.casefold() in _SENSITIVE_ARGUMENTS:
        return ExecutedCallArgument(name=label, value="", withheld=True)
    text = _argument_value(value)
    if bound is None or len(text) <= bound:
        return ExecutedCallArgument(name=label, value=text)
    return ExecutedCallArgument(
        name=label,
        value=text[:bound],
        total_characters=len(text),
    )


def _recorded_outcome(entry: Mapping[str, object]) -> str:
    """Read what became of one recorded call, in the recorder's own words.

    The reading is delegated to the recorder that owns the field rather than
    repeated here.  A second derivation is a second opinion: this module and the
    oversight reconstruction each kept one, and they answered differently about
    the same entry, which is precisely how one call acquired two names.

    The import is deferred because the console draws its prompt through this
    module and must not pull the agent stack onto that path; nothing calls this
    until an operator asks to see a recorded run.
    """

    from forensic_agent.oversight.audit import classify_action_outcome

    return classify_action_outcome(entry)


def _recorded_duration(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _recorded_strings(value: object) -> tuple[str, ...]:
    """The recorded list of strings, dropping anything that is not one."""

    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return ()
    return tuple(item for item in value if isinstance(item, str))


#: The digest fields an action entry can carry, in the order the recorder
#: writes them.  Read as data so a pre-field trace simply yields fewer pairs.
_OUTPUT_DIGEST_FIELDS = (
    "output_sha256",
    "canonical_output_sha256",
    "recorded_output_sha256",
    "captured_prefix_sha256",
)


def _recorded_output_digests(
    entry: Mapping[str, object],
) -> tuple[tuple[str, str], ...]:
    digests: list[tuple[str, str]] = []
    for name in _OUTPUT_DIGEST_FIELDS:
        value = entry.get(name)
        if isinstance(value, str) and _SHA256.fullmatch(value) is not None:
            digests.append((name, value.lower()))
    return tuple(digests)


#: Where the refusing layer wrote its sentence, if the preview did not survive
#: as parseable JSON.  The preview is the recorded output cut to 500 characters,
#: so a long validator report leaves the object mid-string and ``json.loads``
#: refuses the whole thing; the message itself is usually complete well before
#: that cut, and this reads it out of the raw text.
#: The closing quote is optional because the cut can land inside the message
#: itself; what was retained is still worth showing, and a whole sentence
#: usually survives it.
_PREVIEW_MESSAGE = re.compile(r'"message"\s*:\s*"((?:[^"\\]|\\.)*)"?')
#: Everything from here on is the validator's own transcript of the failure —
#: useful in the stored object, unreadable in a five-line pane.
_VALIDATOR_DETAIL = "\nValidator detail:"


def _refusal_message(entry: Mapping[str, object]) -> str:
    """The sentence the refusing layer wrote, read back for a reader to see.

    ``reasons`` carries the refusal as a CODE (``invalid-arguments:
    invalid_operation_arguments``); the sentence that says what the field
    actually takes lives in the recorded output, which is the only place the
    tool's own schema ever reached.  It is read back here rather than
    reconstructed, so the operator is shown the same words the model was.

    Empty when the entry carries no such sentence — a pre-field trace, or a
    policy denial whose whole ground is already in ``reasons``.
    """

    preview = entry.get("output_preview")
    if not isinstance(preview, str) or not preview:
        return ""
    message: object = None
    try:
        payload = json.loads(preview)
    except ValueError:
        match = _PREVIEW_MESSAGE.search(preview)
        if match is not None:
            # A cut landing on a backslash leaves an escape with nothing to
            # escape; drop it rather than lose the whole sentence to it.
            escaped = match.group(1).rstrip("\\")
            try:
                message = json.loads(f'"{escaped}"')
            except ValueError:
                message = None
    else:
        error = payload.get("error") if isinstance(payload, Mapping) else None
        if isinstance(error, Mapping):
            message = error.get("message")
        elif isinstance(error, str):
            # A layer that states its refusal as prose rather than as a block.
            # "BLOCKED by oversight policy" says nothing ``reasons`` does not
            # already say better, so it is left to the reasons.
            message = None
    if not isinstance(message, str):
        return ""
    return message.split(_VALIDATOR_DETAIL)[0].strip()


def executed_calls(
    entries: Sequence[Mapping[str, object]],
    *,
    argument_bound: int | None = MAX_LISTED_ARGUMENT_VALUE,
) -> tuple[ExecutedCall, ...]:
    """Project every tool call the most recent case recorded, in order.

    This reads an oversight trace that the run already wrote; it records
    nothing, decides nothing, and drops no call.  Scoping to the last opened
    case matches how the oversight summary reads the same file, so the two views
    of one trace can never disagree about which run they describe.

    ``argument_bound`` is the ceiling one argument value may occupy;
    ``None`` lifts it for the single-call detail view, where a value must be
    readable whole.
    """

    rows = [entry for entry in entries if isinstance(entry, Mapping)]
    opened = [entry for entry in rows if entry.get("event") == "case_open"]
    case_id = opened[-1].get("case_id") if opened else None
    scoped = (
        [entry for entry in rows if entry.get("case_id") == case_id]
        if case_id
        else rows
    )
    calls: list[ExecutedCall] = []
    for ordinal, entry in enumerate(
        (entry for entry in scoped if entry.get("event") == "action"), start=1
    ):
        arguments = _mapping(entry.get("args"))
        recorded_sequence = _nonnegative_int(entry.get("seq"))
        outcome_detail = entry.get("outcome_detail")
        calls.append(
            ExecutedCall(
                # The chain position, so a row can be matched to the entry that
                # recorded it; the call's own ordinal stands in only when an
                # entry carries no position.
                sequence=recorded_sequence if recorded_sequence is not None else ordinal,
                function=_safe_identifier(entry.get("tool"), fallback="unknown_tool"),
                operation=_safe_identifier(arguments.get("operation"), fallback=""),
                outcome=_recorded_outcome(entry),
                duration_s=_recorded_duration(entry.get("duration_s")),
                arguments=tuple(
                    _listed_argument(name, value, bound=argument_bound)
                    for name, value in arguments.items()
                ),
                # What the gate decided.  A pre-field trace marks a denial with
                # ``blocked``; a call the record does not mark denied reads as
                # permitted, exactly as the outcome classifier reads it.
                allowed=(
                    entry.get("allowed") is not False
                    and entry.get("blocked") is not True
                ),
                risk_name=_safe_identifier(entry.get("risk_name"), fallback=""),
                reasons=_recorded_strings(entry.get("reasons")),
                capabilities=_recorded_strings(entry.get("capabilities")),
                outcome_detail=outcome_detail if isinstance(outcome_detail, str) else "",
                output_digests=_recorded_output_digests(entry),
                refusal_message=_refusal_message(entry),
            )
        )
    return tuple(calls)


@dataclass(frozen=True, slots=True)
class GrantedAuthority:
    """What the case_open entry says this run was permitted, read back whole.

    The policy summary's key set is fixed — an identity digest is taken over it —
    so this reads from it and never adds to it.  ``write_scope`` sits beside
    the summary in the entry, where the recorder deliberately keeps runtime
    facts that must not move the pinned identity.
    """

    policy_name: str
    granted_caps: tuple[str, ...]
    #: The session tool allowlist, or ``None`` when the policy named none —
    #: which is the policy restricting no tool by name, not an absent record.
    allowed_tools: tuple[str, ...] | None
    write_scope: tuple[str, ...]


def granted_authority(
    entries: Sequence[Mapping[str, object]],
) -> GrantedAuthority | None:
    """The authority the last opened case granted, or ``None`` if unrecorded."""

    opened = [
        entry
        for entry in entries
        if isinstance(entry, Mapping) and entry.get("event") == "case_open"
    ]
    if not opened:
        return None
    case = opened[-1]
    policy = case.get("policy")
    if not isinstance(policy, Mapping):
        return None
    allowed_tools = policy.get("allowed_tools")
    return GrantedAuthority(
        policy_name=_safe_identifier(policy.get("name"), fallback=""),
        granted_caps=_recorded_strings(policy.get("granted_caps")),
        allowed_tools=(
            _recorded_strings(allowed_tools) if allowed_tools is not None else None
        ),
        write_scope=_recorded_strings(case.get("write_scope")),
    )


def summarize_finding(row: Mapping[str, object], *, sequence: int) -> FindingSummary:
    """Project one trace row without copying its evidence-bearing values."""

    result = _mapping(row.get("result"))
    data = _mapping(result.get("data"))
    page = _mapping(result.get("page"))
    coverage = _mapping(result.get("coverage"))

    status = _safe_identifier(result.get("status"), fallback="unknown", limit=16).casefold()
    if status not in _KNOWN_STATUSES:
        status = "unknown"

    if page.get("truncated") is True:
        coverage_label = "truncated"
    elif coverage.get("complete") is True:
        coverage_label = "complete"
    elif coverage.get("complete") is False:
        coverage_label = "incomplete"
    else:
        coverage_label = "unknown"

    notes: list[str] = []
    warnings = result.get("warnings")
    if isinstance(warnings, Sequence) and not isinstance(warnings, (str, bytes)) and warnings:
        notes.append(f"warnings: {len(warnings)}")
    if page.get("truncated") is True:
        notes.append("continuation available")

    return FindingSummary(
        sequence=sequence,
        tool=_safe_identifier(row.get("tool"), fallback="unknown_tool"),
        status=status,
        data_type=_safe_identifier(data.get("type"), fallback="unknown_type"),
        records=_record_count(page, data, status=status),
        coverage=coverage_label,
        notes="; ".join(notes) if notes else "—",
        receipt=_receipt_prefix(row, result),
    )


#: The delimiters the run composes around the operator's question before sending
#: it. READ-ONLY COPIES: this text is model-facing and is authored where the
#: message is built (the console's session-context wrapper and the agent's
#: case-context wrapper, which use the same pair). Nothing here may change it —
#: the projection only has to recognise it. ``test_cli_presentation`` composes a
#: message through the real wrapper and checks that this recovers the question,
#: so a delimiter that moved is caught rather than quietly unparsed.
_QUESTION_OPEN = "CURRENT INVESTIGATION QUESTION"
_QUESTION_CLOSE = "END CURRENT INVESTIGATION QUESTION"
#: Ceiling on the question line itself, for the case where no delimiter is found
#: and the whole composed message is all there is to show. Generous for a real
#: question, and short of the screens this projection exists to prevent.
_MAX_QUESTION = 400


def _bounded_prose(value: object, limit: int) -> str:
    if not isinstance(value, str) or not value.strip():
        return ""
    collapsed = " ".join(value.split())
    return collapsed if len(collapsed) <= limit else collapsed[: limit - 1] + "…"


def _delimited_question(composed: str) -> str:
    """The innermost delimited question, or "" when the message carries none.

    Matched line by whole line, never by substring: the closing delimiter ends
    with the opening one, so a substring search finds the close and reports the
    message as undelimited.  The wrappers nest — the agent may wrap a message
    the console already wrapped — so the LAST opening line is the innermost one,
    and the question is what stands between it and the next closing line.
    """

    lines = composed.splitlines()
    opened = next(
        (
            index
            for index in range(len(lines) - 1, -1, -1)
            if lines[index].strip() == _QUESTION_OPEN
        ),
        None,
    )
    if opened is None:
        return ""
    closed = next(
        (
            index
            for index in range(opened + 1, len(lines))
            if lines[index].strip() == _QUESTION_CLOSE
        ),
        None,
    )
    if closed is None:
        return ""
    return "\n".join(lines[opened + 1 : closed]).strip()


def project_recorded_question(recorded: object) -> RecordedQuestion:
    """Separate the question asked from the message it was sent inside.

    A message carrying no delimiter is taken to be the question itself; it is
    still bounded, so a composition this projection does not recognise costs the
    operator a shortened line rather than screens of prompt.
    """

    composed = recorded if isinstance(recorded, str) else ""
    asked = _bounded_prose(_delimited_question(composed) or composed, _MAX_QUESTION)
    return RecordedQuestion(
        asked=asked,
        composed=composed,
        withheld_characters=max(0, len(composed) - len(asked)),
    )


def resolve_finding_id(identifier: str, *, count: int) -> int | None:
    """Resolve the id shown in the findings listing to a one-based position.

    The listing prints the id zero-padded, so ``01`` and ``1`` are the same
    finding and both are accepted; anything that is not a number the listing
    actually shows resolves to nothing, and the caller answers with the shape of
    the command rather than with a failure.
    """

    text = identifier.strip().removeprefix("#").lstrip("0") or "0"
    if not text.isdecimal():
        return None
    position = int(text)
    return position if 1 <= position <= count else None


def _recorded_text(value: object) -> str:
    """A recorded free-text field, or "" for anything that is not one."""

    return value if isinstance(value, str) else ""


def _recorded_producers(provenance: Mapping[str, object]) -> tuple[str, ...]:
    """Each producing component as "name version", in the order recorded.

    A backend whose role is ``support`` only made the read possible and is not
    listed as a producer; one recorded without a role predates the field and is
    kept, because dropping it would hide the only producer such a record names.
    """

    backends = provenance.get("upstream_backends")
    if not isinstance(backends, Sequence) or isinstance(backends, (str, bytes)):
        return ()
    producers: list[str] = []
    for backend in backends:
        record = _mapping(backend)
        if record.get("role") == "support":
            continue
        name = _recorded_text(record.get("name"))
        if not name:
            continue
        version = _recorded_text(record.get("version"))
        producers.append(f"{name} {version}".strip())
    return tuple(producers)


def summarize_finding_detail(
    row: Mapping[str, object], *, sequence: int
) -> FindingDetail:
    """Project one finding at full length, evidence-bearing values still excluded.

    Everything here is metadata the envelope states ABOUT the reading: what the
    reading covered, what it warned of, what it declared when it failed, where
    it was read from, and the digest it was recorded under.
    ``data.attributes`` and ``data.items`` — the reading itself — are
    deliberately absent, as they are from every other view the console draws.
    """

    result = _mapping(row.get("result"))
    error = _mapping(result.get("error"))
    provenance = _mapping(result.get("provenance"))
    source = _mapping(provenance.get("source"))
    artifact = _mapping(provenance.get("artifact"))
    page = _mapping(result.get("page"))
    coverage = _mapping(result.get("coverage"))
    page_truncated = page.get("truncated")
    coverage_complete = coverage.get("complete")

    warnings = result.get("warnings")
    codes: tuple[str, ...] = ()
    messages: tuple[str, ...] = ()
    if isinstance(warnings, Sequence) and not isinstance(warnings, (str, bytes)):
        codes = tuple(
            _safe_identifier(_mapping(warning).get("code"), fallback="unknown_warning")
            for warning in warnings
        )
        messages = tuple(
            _recorded_text(_mapping(warning).get("message")) for warning in warnings
        )

    return FindingDetail(
        summary=summarize_finding(row, sequence=sequence),
        warnings=codes,
        error=_safe_identifier(error.get("code"), fallback="") if error else "",
        receipt=_receipt_digest(row, result),
        oversight_sequence=_nonnegative_int(provenance.get("oversight_sequence")),
        evidence_class=_safe_identifier(
            provenance.get("evidence_class"), fallback=""
        ),
        source_id=_recorded_text(source.get("id")),
        source_uri=_recorded_text(source.get("uri")),
        artifact_type=_safe_identifier(artifact.get("type"), fallback="", limit=128),
        artifact_locator=_recorded_text(artifact.get("locator")),
        producers=_recorded_producers(provenance),
        warning_messages=messages,
        page=PageFacts(
            returned=_nonnegative_int(page.get("returned")),
            total=_nonnegative_int(page.get("total")),
            truncated=page_truncated if isinstance(page_truncated, bool) else None,
            next_offset=_nonnegative_int(page.get("next_offset")),
            unit=_safe_identifier(page.get("unit"), fallback=""),
        ),
        coverage=CoverageFacts(
            complete=coverage_complete if isinstance(coverage_complete, bool) else None,
            scope=_recorded_text(coverage.get("scope")),
            reason=_recorded_text(coverage.get("reason")),
        ),
    )


def summarize_findings(
    rows: Sequence[Mapping[str, object]],
    *,
    limit: int = MAX_DISPLAYED_FINDINGS,
) -> FindingsProjection:
    """Return at most ``limit`` safe rows, taken from both ends of the run.

    The bound is unchanged; which rows it spends is not.  Taking the first
    ``limit`` drops the tail of every long run, and the tail is where a run
    gets nearest its answer — precisely the readings an operator needs.  Keeping
    both ends shows how the examination opened and what it finished on, and the
    sequence numbers stay those of the full list, so the omission is legible in
    the numbering and ``/findings <id>`` still resolves every row.
    """

    bounded_limit = max(1, min(int(limit), MAX_DISPLAYED_FINDINGS))
    numbered = list(enumerate(rows, start=1))
    if len(numbered) > bounded_limit:
        head = bounded_limit // 2
        numbered = numbered[:head] + numbered[len(numbered) - (bounded_limit - head) :]
    projected = tuple(
        summarize_finding(row, sequence=index) for index, row in numbered
    )
    return FindingsProjection(rows=projected, omitted=max(0, len(rows) - len(projected)))


#: How each recorded cause reads to an operator.  The keys are the runtime's
#: closed unpublished-answer vocabulary, owned by
#: :data:`forensic_agent.agent.orchestration.finalization.UNPUBLISHED_ANSWER_CAUSES`,
#: minus its two meta-values: ``published`` is not an unpublished cause, and
#: ``unattributed`` is the fallback rendered below.  The owner is not imported
#: here — this module reads a recorded record as data and sits on the import
#: path that draws the prompt, which the agent stack has to stay off of — so a
#: test pins these keys to the owner's vocabulary and the two cannot drift.  An
#: unrecognised value is reported as unattributed rather than rendered, so a
#: future cause cannot arrive on screen as a sentence nobody wrote.
_UNPUBLISHED_CAUSE_SENTENCE: dict[str, str] = {
    "model_returned_no_draft": (
        "The model stated no conclusion, so there was none to publish."
    ),
    "draft_cleared_before_publication": (
        "The model stated a conclusion and this system cleared it before it "
        "reached publication."
    ),
    "withheld_by_gate": "A publication control withheld the conclusion.",
    "discarded_by_final_check": (
        "The final check returned no report this run could accept."
    ),
    "draft_did_not_assemble": (
        "The model's draft did not assemble into an answer bound to stored results."
    ),
    "draft_not_bound_to_a_model_response": (
        "The draft was not bound to a recorded model response and was not accepted."
    ),
    "revoked_by_evidence_integrity": (
        "The evidence source failed its integrity check, which revokes any "
        "conclusion drawn from it."
    ),
}


#: What each budget ceiling means to the person reading the line.  The keys are
#: :data:`forensic_agent.agent.execution_budget.BUDGET_EXHAUSTION_REASONS`, the
#: closed vocabulary the budget itself raises with; the owner is not imported
#: here for the reason given above, so a test pins these keys to it.
#:
#: The distinction matters more than it looks.  "It stopped at the
#: max_wall_time_s ceiling" is a field name, and a field name on an operator's
#: screen reads as a fault in this software.  The same fact in words is a result
#: about the run, which is what it is, and which is what a comparison between
#: two models is made of.
_EXAMINATION_BOUND_PHRASE: dict[str, str] = {
    "max_steps": "the limit on how many steps one message may take",
    "max_model_requests": "the limit on how many times one message may ask the model",
    "max_tool_calls": "the limit on how many tool calls one message may make",
    "max_navigation_calls": "the limit on how far one message may page through results",
    "max_wall_time_s": "the time budget for one message",
}


def examination_bound_phrase(bound: str) -> str:
    """One ceiling in words, or the recorded name when it is not a known one.

    An unrecognised bound is shown under the name it was recorded with rather
    than dropped: the operator can still quote it, and a ceiling this console
    has not learned about must not quietly become no ceiling at all.
    """

    return _EXAMINATION_BOUND_PHRASE.get(bound, bound)


def summarize_incomplete_examination(
    telemetry: Mapping[str, object],
) -> IncompleteExamination:
    """Say what a run that published nothing did, and what became of its answer.

    A run that ends without a conclusion must not leave an operator one line
    naming a finish reason, while the readings it had made — receipt-bound, and
    sometimes holding the very file the question asked for — go unshown because
    the panels that show them are only reached by a run that published.  This
    projects the run's own record into something that can be stated instead:
    what stopped it, what became of the draft, and how much evidence it had read
    when it stopped.

    It is deliberately not an answer and cannot become one.  The counts and the
    cause come from control telemetry; the readings themselves are rendered by
    the ordinary evidence-summary projection, which shows what was read and never
    what was in it.
    """

    unpublished = _mapping(telemetry.get("unpublished_answer_metrics"))
    cause_value = unpublished.get("cause")
    cause = (
        cause_value
        if isinstance(cause_value, str) and cause_value in _UNPUBLISHED_CAUSE_SENTENCE
        else "unattributed"
    )
    bound_value = unpublished.get("examination_bound")
    bound = _safe_identifier(bound_value, fallback="", limit=48) if bound_value else None
    readings = _nonnegative_int(unpublished.get("evidence_readings")) or 0
    blocked = unpublished.get("blocked_gates")
    gates = [
        _safe_identifier(name, fallback="", limit=64)
        for name in (blocked if isinstance(blocked, Sequence) else ())
        if isinstance(name, str)
    ]
    sentences = ["This examination did not complete, and no conclusion was published."]
    sentences.append(
        f"It ran out of {examination_bound_phrase(bound)} after {readings} "
        f"{'reading' if readings == 1 else 'readings'} of the evidence."
        if bound
        else (
            f"It ended after {readings} "
            f"{'reading' if readings == 1 else 'readings'} of the evidence."
        )
    )
    if cause == "withheld_by_gate" and gates:
        sentences.append(
            "A publication control withheld the conclusion: " + ", ".join(sorted(gates)) + "."
        )
    else:
        sentences.append(
            _UNPUBLISHED_CAUSE_SENTENCE.get(cause, "The cause was not attributed.")
        )
    sentences.append(
        "What follows is the record of what this run read, not an answer to the "
        "question, and it must not be reported as one."
    )
    return IncompleteExamination(
        statement=" ".join(sentences),
        cause=cause,
        bound=bound,
        evidence_readings=readings,
        model_draft_present=unpublished.get("model_draft_present") is True,
    )


def _outcome_token(value: object) -> str:
    """One recorded outcome as the token it is looked up by.

    Anything that is not a recorded string is an absent outcome rather than a
    value to be coerced into one: a triple carrying a number where an outcome
    belongs has not named a path this console can accept.
    """

    return value if isinstance(value, str) else ""


def summarize_controls(
    telemetry: Mapping[str, object],
    *,
    run_id: str,
    tool_calls: int,
    findings: int,
) -> ControlSummary:
    """Interpret control telemetry without claiming that request success is a verdict."""

    verifier = _mapping(telemetry.get("verifier_metrics"))
    verifier_activated = verifier.get("activated") is True
    request_status = verifier.get("request_status")
    if verifier_activated and request_status == "success":
        verification = "completed"
    elif verifier_activated and request_status == "error":
        verification = "failed"
    elif verifier_activated:
        verification = "started; completion unconfirmed"
    else:
        verification = "not started"

    # The accepted answer comes from exactly one path, read from the dedicated
    # final-answer contract as the whole triple it recorded.  A triple the table
    # does not hold is displayed as "no accepted answer" and never as a verified
    # report: a partially matching outcome is not an accepted answer wearing a
    # small defect.
    final_answer = _mapping(telemetry.get("final_answer_metrics"))
    accepted_source = _outcome_token(final_answer.get("accepted_source"))
    verification_outcome = _outcome_token(final_answer.get("verification_outcome"))
    publication_outcome = _outcome_token(final_answer.get("publication_outcome"))
    outcome = (accepted_source, verification_outcome, publication_outcome)
    if is_verification_incomplete_publication(accepted_source, publication_outcome):
        # The keep-or-mark backstop publishes the model's own grounded draft
        # with the gap stated whenever the final check could not certify it —
        # for any of several reasons named in ``verification_outcome``. The
        # answer source is the same in every one, so it is read from the
        # published-draft pair rather than enumerated per reason.
        answer_source = ANSWER_DRAFT_VERIFICATION_INCOMPLETE
        unaccepted_outcome = None
    else:
        answer_source = ACCEPTED_ANSWER_SOURCES.get(outcome, ANSWER_NONE)
        unaccepted_outcome = None if answer_source != ANSWER_NONE else outcome

    safe_run_id = _safe_identifier(run_id, fallback="unavailable", limit=128)
    trace_id = safe_run_id[:12] if safe_run_id != "unavailable" else safe_run_id
    return ControlSummary(
        verification=verification,
        answer_source=answer_source,
        unaccepted_outcome=unaccepted_outcome,
        tool_calls=_nonnegative_int(tool_calls) or 0,
        findings=_nonnegative_int(findings) or 0,
        model_requests=_nonnegative_int(telemetry.get("model_requests")),
        trace_id=trace_id,
    )
