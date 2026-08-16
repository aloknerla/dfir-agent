"""Deterministic shape and confidentiality checks for a published answer.

The published text is the investigation model's verifier-approved draft. A
model completion can open with a heading it invented ("## Final Answer",
"**Final answer:**", "**Answer: ...**"), or carry a sentence of the internal
draft/verifier exchange in the second person ("The coverage limitation you
noted does not affect this finding"). Some backends can also expose hidden
reasoning markup. None of that is the answer; all of it is machinery showing.

The shape is enforced here, in code, before verification and publication: the
claim comes first, the evidence the model wrote stays untouched, and the only
sentences removed are the closed class that addresses the other side of an
internal exchange. Every removal is recorded in metrics, and a normalization
that would empty the answer publishes nothing rather than an empty string
dressed as one — the same fail-closed disposition the grounding gate takes.

:func:`split_published_answer` at the end of this module is a different kind of
thing and is kept here for one reason: it reads the same shape. It changes
nothing and publishes nothing. It reads an already published, already verified
report the way a console has to lay it out, so the heading over the evidence is
a word the console owns rather than whichever synonym the model reached for,
and so a long answer arrives as a finding with its evidence set off from it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: One leading title token, with or without markdown decoration, ending at a
#: colon, dash or line break.  Closed by construction: only the title tokens
#: listed here (and their obvious casings) are recognized, so a claim that
#: legitimately begins with one of these words mid-sentence is never touched —
#: the separator is required.
_LEADING_HEADING = re.compile(
    r"^\s*(?:#{1,6}\s*)?(?:[*_]{1,3}\s*)?"
    r"(?:final\s+answer|final\s+conclusion|corrected\s+answer(?:\s*\([^)\n]*\))?|answer)"
    r"\s*(?:[:—–-]|\n)\s*(?:[*_]{1,3}\s*(?=\S))?",
    re.IGNORECASE,
)

#: A sentence that talks to the other side of the internal exchange rather than
#: stating a finding.  Deliberately narrow — a second person plus a
#: conversational verb, or an explicit reference to the draft under review —
#: because the cost of over-matching is deleting evidence prose.
_META_DIALOGUE = re.compile(
    r"\b(?:you|your)\s+(?:noted|mentioned|raised|stated|pointed\s+out|asked)\b"
    r"|\byour\s+(?:report|draft|question)\b"
    r"|\bthe\s+draft(?:'s)?\b",
    re.IGNORECASE,
)
_TERMINAL_META_DIALOGUE = re.compile(
    r"(?:(?<=\.)|(?<=!)|(?<=\?))\s+the\s+question\s+is\s+answered\s*[.!?]?\s*$",
    re.IGNORECASE,
)
_LEADING_ACKNOWLEDGEMENT = re.compile(r"^\s*(?i:understood)\s*[.!?]\s+")

#: A complete sentence that merely narrates the transition from analysis to the
#: answer.  This is not a finding and used to be removed incidentally when the
#: verifier rewrote prose.  The claim-only verifier never authors replacement
#: text, so the closed set is removed deterministically instead.
_LEADING_PROCESS_NARRATION = re.compile(
    r"^\s*(?:"
    r"i\s+(?:now\s+)?have\s+(?:enough|sufficient)\s+evidence"
    r"|now\s+i\s+can\s+answer"
    r"|here\s+(?:is|'s)\s+(?:the|my)\s+answer"
    r"|sada\s+imam\s+dovoljno\s+dokaza"
    r"|sada\s+mogu\s+odgovoriti"
    r"|evo\s+odgovora"
    r")\s*(?:[.!?](?:\s+|$)|(?:\r?\n)+|$)",
    re.IGNORECASE,
)

#: Sentence boundary: terminal punctuation followed by whitespace.  Filenames
#: like ``setup1.exe`` carry no whitespace after their dot, so they do not split.
_SENTENCE_BOUNDARY = re.compile(r"(?<=[.!?])\s+")

# The normalization helper can remove complete hidden-reasoning blocks for
# legacy display cleanup. The stricter publication gate below refuses even a
# complete block; a surviving tag is truncated or malformed and always fails.
_HIDDEN_REASONING_BLOCK = re.compile(
    r"<(?P<tag>think|analysis|reasoning)>.*?</(?P=tag)>",
    re.IGNORECASE | re.DOTALL,
)
_HIDDEN_REASONING_TAG = re.compile(
    r"</?(?:think|analysis|reasoning)>",
    re.IGNORECASE,
)
_INTERNAL_PROTOCOL_MARKER = re.compile(
    r"(?:<\|(?:analysis|assistant|tool|developer|system)\|>"
    r"|\b(?:assistant|analysis|tool)\s+to=[A-Za-z0-9_.-]+"
    r"|\btool_calls?\b)",
    re.IGNORECASE,
)
_INTERNAL_REASONING_LEAD = re.compile(
    r"^\s*(?:let\s+me\s+(?:analy[sz]e|reason|think)"
    r"|we\s+need\s+to\s+(?:analy[sz]e|reason|determine)"
    r"|i\s+(?:need|should|will)\s+to\s+(?:analy[sz]e|reason|think))\b",
    re.IGNORECASE,
)
_PLAINTEXT_INTERNAL_REASONING_LABEL = re.compile(
    r"^[ \t]*(?:>{1,3}[ \t]*)?(?:(?:[-+*]|\d+[.)])[ \t]*)?"
    r"(?:#{1,6}[ \t]*)?(?:[*_]{1,3}[ \t]*)?"
    r"(?:analysis|reasoning|chain[- ]of[- ]thought)"
    r"[ \t]*(?:[*_]{1,3}[ \t]*)?"
    r"(?::|[—–-]|\r?\n)[ \t]*(?:[*_]{1,3}[ \t]*)?",
    re.IGNORECASE | re.MULTILINE,
)
_INTERNAL_REASONING_CODE_FENCE = re.compile(
    r"^\s*(?:>{1,3}\s*)?(?:(?:[-+*]|\d+[.)])\s*)?"
    r"(?:`{3,}|~{3,})\s*(?:analysis|reasoning|chain[- ]of[- ]thought)\b",
    re.IGNORECASE | re.MULTILINE,
)

#: A reply that hands the question back to the operator instead of answering it,
#: e.g. "I am unable to identify which specific result you are referring to.
#: Could you please point me to the exact result...".  A forensic answer states
#: what the evidence shows; a request that the operator identify or point to a
#: result states nothing about the evidence.  Deliberately narrow — it must name
#: the operator ("you"/"please") AND ask about a result/finding/query — so an
#: answer that merely contains a question mark is untouched.
_OPERATOR_CLARIFICATION_REQUEST = re.compile(
    r"(?:"
    r"\b(?:unable\s+to|cannot|can[’']t|could\s+not|do\s+not|don[’']t)\s+"
    r"(?:identify|determine|tell|know)\b[^.!?\n]{0,40}"
    r"\bwhich\b[^.!?\n]{0,40}\b(?:result|finding|record|query|call|item|file)\b"
    r"|"
    r"\b(?:could|can|would|please|would\s+you)\b[^.!?\n]{0,30}"
    r"\b(?:point|direct|refer|specify|clarify|tell|show)\b[^.!?\n]{0,40}"
    r"\b(?:me|us)\b"
    r"|"
    r"\bplease\s+(?:specify|clarify|identify|indicate|tell\s+me|point)\b[^.!?\n]{0,40}"
    r"\b(?:which|the\s+exact|what)\b"
    r"|"
    r"\bwhich\s+(?:result|finding|record|query|call|item|file)\b[^.!?\n]{0,30}"
    r"\bare\s+you\s+referring\s+to\b"
    r")",
    re.IGNORECASE,
)


def is_operator_clarification_request(text: str | None) -> bool:
    """Whether this reply asks the operator to clarify rather than answering.

    Such a reply is the model talking back to whoever prompted it, not a
    statement about the evidence — so it is never a publishable forensic answer,
    and a run that produced one should conclude from what it gathered instead.
    """

    if not text:
        return False
    return _OPERATOR_CLARIFICATION_REQUEST.search(text) is not None


#: A final answer that points at a list or conclusion given in an EARLIER turn
#: instead of stating it here, e.g. one closing with "the original list ...
#: remains unchanged and complete" — the answer names nothing, and an operator
#: reading only the published text sees no list.  Deliberately narrow: it
#: requires a back-reference (original/previous/earlier) to an ENUMERABLE noun
#: (list, answer, findings…), not a bare "remains", so "the registered owner
#: remains the same account" is untouched.
_DEFERS_TO_PRIOR_ANSWER = re.compile(
    r"(?:"
    r"\b(?:original|previous|earlier|prior|preceding)\b[^.!?\n]{0,25}"
    r"\b(?:list|answer|answers|conclusion|set|finding|findings|result|results|"
    r"enumeration)\b"
    r"|"
    r"\b(?:list|answer|conclusion|set|finding|findings|result|results|enumeration)\b"
    r"[^.!?\n]{0,25}"
    r"\b(?:remains?\s+unchanged|remain\s+unchanged|is\s+unchanged|"
    r"stands?\s+unchanged|unchanged\s+and\s+complete)\b"
    r"|"
    r"\b(?:my|the)\s+(?:earlier|previous|prior|original)\s+"
    r"(?:answer|list|conclusion|response|report|finding|enumeration)\b"
    r")",
    re.IGNORECASE,
)


def defers_to_a_prior_answer(text: str | None) -> bool:
    """Whether this answer refers to an earlier turn's list instead of stating it.

    A published forensic answer has to stand on its own: an operator reads the
    final text, not the model's intermediate drafts.  An answer that says a
    prior list "remains unchanged" without carrying that list is not self
    contained, and the run should re-conclude from the evidence it gathered so
    the published answer names what it found.
    """

    if not text:
        return False
    return _DEFERS_TO_PRIOR_ANSWER.search(text) is not None


#: A closing turn that recites how the results were PAGINATED — the raw page
#: cursor, the coverage flag, "all pages read" — instead of stating the finding.
#: A recovery arm that nudged the model to finish a page or hear an unread region
#: is answered with reading-bookkeeping ("the remaining entries at offset 50+ were
#: only X", "coverage.complete=true", "sve nedovršene stranice su pročitane"), and
#: the value the run already held in a completed tool result is never carried into
#: the published text.  These tokens are tool-internal pagination vocabulary — a
#: stated forensic finding never needs ``offset``, ``coverage.complete``,
#: ``next_offset`` or ``max_entries`` — so the set is closed to that machinery and
#: to the two narrowest reading-completion phrasings.  Deliberately conservative:
#: it does NOT match a finding that merely recites how much was examined ("after
#: examining all 214 entries, three are recoverable") or a bare document page
#: count, because the cost of over-matching is re-rolling a good answer.
_PAGINATION_PROGRESS_REPORT = re.compile(
    r"(?:"
    r"\bcoverage\.complete\b"
    r"|\bnext_offset\b"
    r"|\bmax_entries\b"
    r"|\boffset\s+\d+\+"
    r"|\b(?:all|the)\s+(?:remaining|unfinished|pending)\s+pages?\s+"
    r"(?:are|were|have\s+been)\s+(?:now\s+)?(?:read|examined|processed)\b"
    r"|\bno\s+(?:more\s+)?un(?:read|examined)\s+(?:results?|pages?|records?|entries)\b"
    r"|\bsve\s+(?:nedovršene\s+|preostale\s+)?stranice\s+su\s+(?:sada\s+)?pročitane\b"
    r"|\bnema\s+više\s+nepročitanih\s+(?:rezultata|stranica|zapisa|unosa)\b"
    r")",
    re.IGNORECASE,
)


def reports_pagination_progress_instead_of_finding(text: str | None) -> bool:
    """Whether this answer reports on pagination/coverage rather than the finding.

    The value the run gathered lives in a completed tool result; a terminal draft
    that instead recites the page cursor ("offset 50+"), the coverage flag
    ("coverage.complete=false"), or reading completion ("sve nedovršene stranice
    su pročitane", "no more unread results") carries none of it to the operator.
    Such a draft is not a publishable forensic answer, so the run should conclude
    again from the evidence it holds and restate what it found — it never
    discards on this reading, it only re-drives one bounded concluding turn.
    """

    if not text:
        return False
    return _PAGINATION_PROGRESS_REPORT.search(text) is not None


def strip_leading_heading(text: str) -> tuple[str, bool]:
    """Remove one leading answer-heading token, preserving the claim after it.

    Only the start of the text is inspected, so a quoted value later in the
    report can never be touched.  A bold heading that wrapped the claim itself
    ("**Answer: J. Doe**") leaves an orphaned closing mark on the first line;
    that orphan is removed only when nothing else on the line pairs with it.
    """

    match = _LEADING_HEADING.match(text or "")
    if match is None:
        return text, False
    stripped = (text or "")[match.end() :]
    first_line, separator, rest = stripped.partition("\n")
    if first_line.rstrip().endswith("**") and first_line.count("**") == 1:
        first_line = first_line.rstrip()[:-2].rstrip()
        stripped = first_line + separator + rest
    return stripped.lstrip(), True


def _strip_leading_process_narration(text: str) -> tuple[str, int]:
    """Remove only a contiguous process preamble at the start of an answer."""

    body = text
    removed = 0
    while (match := _LEADING_PROCESS_NARRATION.match(body)) is not None:
        body = body[match.end() :]
        removed += 1
    return body.lstrip(), removed


def _strip_closed_meta_bookends(text: str) -> tuple[str, int]:
    """Remove the exact acknowledgement/closure pair around a substantive answer.

    The terminal completion sentence is removed when it follows a substantive
    answer. The leading acknowledgement is removed only when that terminal
    sentence is also present, preserving recovered prose such as
    ``Understood. Transfer the files.``.
    """

    terminal = _TERMINAL_META_DIALOGUE.search(text)
    if terminal is None:
        return text, 0
    body = text[: terminal.start()].rstrip()
    removed = 1
    acknowledgement = _LEADING_ACKNOWLEDGEMENT.match(body)
    if acknowledgement is not None and body[acknowledgement.end() :].strip():
        body = body[acknowledgement.end() :].lstrip()
        removed += 1
    return body, removed


def first_sentence(text: str) -> str:
    """The principal claim: the first sentence after any heading decoration."""

    body, _stripped = strip_leading_heading(text or "")
    body = body.strip()
    if not body:
        return ""
    first_paragraph = body.split("\n\n", 1)[0]
    return _SENTENCE_BOUNDARY.split(first_paragraph, 1)[0].strip()


def normalize_published_answer(text: str) -> tuple[str, dict[str, object]]:
    """Return the answer in its published shape, and what was done to it.

    Two operations, both deterministic and both recorded: one leading heading
    token is stripped, and sentences of the closed internal-dialogue class are
    dropped.  The body — the model's own support and wording — is never
    restyled.  An answer the removal would empty comes back as ``""`` with
    ``emptied_by_normalization`` set, so the caller can refuse to publish it
    instead of publishing silence.
    """

    metrics: dict[str, object] = {
        "heading_stripped": False,
        "meta_dialogue_sentences_removed": 0,
        "hidden_reasoning_blocks_removed": 0,
        "internal_reasoning_rejected": False,
        "emptied_by_normalization": False,
    }
    body, removed_blocks = _HIDDEN_REASONING_BLOCK.subn("", text or "")
    metrics["hidden_reasoning_blocks_removed"] = removed_blocks
    if (
        _HIDDEN_REASONING_TAG.search(body) is not None
        or _INTERNAL_PROTOCOL_MARKER.search(body) is not None
        or _INTERNAL_REASONING_LEAD.search(body) is not None
        or _PLAINTEXT_INTERNAL_REASONING_LABEL.search(body) is not None
        or _INTERNAL_REASONING_CODE_FENCE.search(body) is not None
    ):
        metrics["internal_reasoning_rejected"] = True
        metrics["emptied_by_normalization"] = True
        return "", metrics

    body, stripped = strip_leading_heading(body)
    metrics["heading_stripped"] = stripped
    body, removed = _strip_leading_process_narration(body)
    body, bookends_removed = _strip_closed_meta_bookends(body)
    removed += bookends_removed

    kept_lines: list[str] = []
    for line in body.split("\n"):
        sentences = _SENTENCE_BOUNDARY.split(line)
        kept_sentences = [
            sentence for sentence in sentences if _META_DIALOGUE.search(sentence) is None
        ]
        removed += len(sentences) - len(kept_sentences)
        kept_lines.append(" ".join(kept_sentences))
    metrics["meta_dialogue_sentences_removed"] = removed
    normalized = "\n".join(kept_lines).strip() if removed else body.strip()

    if not normalized:
        metrics["emptied_by_normalization"] = True
        return "", metrics
    return normalized, metrics


def reject_internal_model_output(text: str) -> tuple[str, dict[str, object]]:
    """Fail closed on any reasoning block or internal protocol marker.

    This stricter pre-publication gate is used for investigation-model output.
    ``normalize_published_answer`` remains useful for legacy display cleanup, but
    an answer containing even a well-formed hidden-reasoning block is not
    published: removing it could hide that the provider exposed internal state.
    """

    normalized, metrics = normalize_published_answer(text)
    if metrics.get("hidden_reasoning_blocks_removed"):
        metrics["internal_reasoning_rejected"] = True
        metrics["emptied_by_normalization"] = True
        return "", metrics
    return normalized, metrics


#: How many supporting points an answer shows before the rest is left to
#: ``/findings``.  Three, because the prompt's own standard for a direct factual
#: question is the ONE authoritative artifact that records it, and the
#: corroboration standard for an interpretive one asks for a second, independent
#: reading; the third line is the room a bound or a qualification needs.  A
#: fourth is an inventory, and the run already keeps a complete, receipt-bound
#: inventory that ``/findings`` shows in full — so nothing is lost by not
#: printing it inside the answer panel, and a negative answer stops arriving as
#: five bullets about searches that found nothing.
SUPPORT_ITEM_LIMIT = 3

#: The opening of a coverage bound the RUNTIME appends to a published report
#: (see ``recovery.coverage_bound.bound_stated_for``).  It is the one paragraph
#: in a report that the model did not write, it always arrives last, and it
#: states the limit that everything the report calls absent is held to.  It is
#: therefore never a supporting point and never subject to the cap: an operator
#: who does not read it reads an unqualified negative.
_COVERAGE_BOUND_OPENING = re.compile(
    r"^(?:Coverage for this run is incomplete:"
    r"|The final check also reasoned from a truncated evidence bundle)",
)

#: A label the model wrote over its own evidence despite being told not to.  The
#: console prints the heading, so a surviving label would be printed twice; it is
#: removed here rather than in the renderer, because both renderers read this.
_SUPPORT_LABEL = re.compile(
    r"^\s*(?:#{1,6}\s*)?(?:[*_]{1,3}\s*)?"
    r"(?:supporting\s+evidence|evidence|support|basis|"
    r"dokazi|dokaz|dokazna\s+osnova|potpora|osnova)"
    r"\s*(?:[*_]{1,3}\s*)?:\s*",
    re.IGNORECASE,
)

#: One list marker at the start of a line.  The renderer writes its own, so the
#: model's is removed to keep a mixed answer from arriving double-bulleted.
_LEADING_LIST_MARKER = re.compile(r"^\s*(?:[-+*•]|\d+[.)])\s+")

#: Markdown the line-by-line split would destroy.  A table row means nothing on
#: its own and a fenced block is one unit of text, so an answer carrying either
#: is left exactly as the run published it.
_UNSPLITTABLE_MARKDOWN = re.compile(r"^\s*(?:\|.*\||`{3,}|~{3,})", re.MULTILINE)


@dataclass(frozen=True, slots=True)
class PublishedAnswer:
    """A published report in the parts a console can lay out separately.

    Purely a reading of the published text: nothing here decides what is
    published, and the parts concatenate back to what the run verified. The
    split exists so the heading over the evidence belongs to the console —
    where it is one word in the operator's own language instead of whichever
    synonym the model reached for — and so a long answer arrives as a finding
    with its evidence set off from it rather than as a block.
    """

    #: The principal claim, alone, always non-empty for a non-empty report.
    finding: str
    #: The evidence lines the console shows, already capped.
    support: tuple[str, ...]
    #: How many further lines the cap left to ``/findings``.
    omitted_support: int
    #: The runtime-appended coverage bound, kept whole and never capped.
    coverage_bound: str


def split_published_answer(
    report: str,
    *,
    support_limit: int = SUPPORT_ITEM_LIMIT,
) -> PublishedAnswer:
    """Read a published report as a finding, its evidence, and any stated bound.

    Display only, and deliberately late: verification has already run over the
    complete text by the time anything calls this, and the complete text is what
    the run recorded, exported and hands to ``/findings``. A cap applied here
    therefore cannot hide anything a check depends on — it can only shorten what
    one panel prints — which is why the cap lives here as well as in the prompt.
    The prompt's ceiling is what keeps the extra lines from being written and
    verified at all; this one is what cannot be disobeyed.

    An answer whose layout the line split would destroy — a markdown table, a
    fenced block — comes back whole as the finding, with no evidence part, so a
    console renders it exactly as before.
    """

    text = (report or "").strip()
    if not text:
        return PublishedAnswer(finding="", support=(), omitted_support=0, coverage_bound="")

    body, bound = _detach_coverage_bound(text)
    if not body:
        # A report that is nothing but the appended bound still has to say
        # something, so the bound becomes the finding rather than a heading over
        # an empty answer.
        return PublishedAnswer(finding=bound, support=(), omitted_support=0, coverage_bound="")
    if _UNSPLITTABLE_MARKDOWN.search(body) is not None:
        return PublishedAnswer(finding=body, support=(), omitted_support=0, coverage_bound=bound)

    lines = [line.strip() for line in body.splitlines()]
    lines = [line for line in lines if line]
    head, *rest = lines
    finding, _separator, remainder = _split_first_sentence(head)
    items = [item for item in (_support_item(line) for line in (remainder, *rest)) if item]

    limit = max(int(support_limit), 0)
    shown = tuple(items[:limit])
    return PublishedAnswer(
        finding=finding,
        support=shown,
        omitted_support=len(items) - len(shown),
        coverage_bound=bound,
    )


def _detach_coverage_bound(text: str) -> tuple[str, str]:
    """Split off a trailing runtime-composed coverage bound, if one is there."""

    blocks = re.split(r"\n\s*\n", text)
    if len(blocks) > 1 and _COVERAGE_BOUND_OPENING.match(blocks[-1].strip()):
        return "\n\n".join(blocks[:-1]).strip(), blocks[-1].strip()
    if len(blocks) == 1 and _COVERAGE_BOUND_OPENING.match(blocks[0].strip()):
        return "", blocks[0].strip()
    return text, ""


def _split_first_sentence(line: str) -> tuple[str, str, str]:
    """The first sentence of a line, and whatever followed it on that line."""

    parts = _SENTENCE_BOUNDARY.split(line, 1)
    if len(parts) == 1:
        return line.strip(), "", ""
    return parts[0].strip(), " ", parts[1].strip()


def _support_item(line: str) -> str:
    """One evidence line as the console shows it, without the model's own label.

    Removing a label can leave the line opening in lower case, and it is left
    that way on purpose. Recasing the first character of a forensic line is a
    change to a literal value whenever the line opens with one — an account
    name, a filename, a decoded token — and an answer that reads slightly off is
    a much smaller fault than an answer that reports ``Jdoe`` for ``jdoe``.
    """

    item = _LEADING_LIST_MARKER.sub("", line or "", count=1)
    item = _SUPPORT_LABEL.sub("", item, count=1)
    return item.strip()


__all__ = [
    "SUPPORT_ITEM_LIMIT",
    "PublishedAnswer",
    "defers_to_a_prior_answer",
    "first_sentence",
    "is_operator_clarification_request",
    "normalize_published_answer",
    "reject_internal_model_output",
    "reports_pagination_progress_instead_of_finding",
    "split_published_answer",
    "strip_leading_heading",
]
