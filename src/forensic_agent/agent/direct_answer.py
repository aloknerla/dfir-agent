"""Closed syntactic contract for one direct factual answer.

The classifier is deliberately conservative. It may request a bounded rewrite
of an overlong answer, but it never selects or removes a factual claim.
"""

from __future__ import annotations

import re

_QUESTION_WORD = re.compile(
    r"\b(?:what|which|who|where|when|što|koji|koja|koje|tko|gdje|kada)\b",
    re.IGNORECASE,
)
_QUESTION_START = re.compile(
    r"^\s*(?:what|which|who|where|when|što|koji|koja|koje|tko|gdje|kada)\b",
    re.IGNORECASE,
)
_REJECTED_START = re.compile(r"^\s*(?:why|how|zašto|kako)\b", re.IGNORECASE)
_EMBEDDED_DIRECT_FILENAME = re.compile(
    r"^.{1,300}\b(?:under|as)\s+what\s+(?:file\s+name|filename)\?\s*$",
    re.IGNORECASE,
)
_MULTIPART = re.compile(
    r"(?:[;\n]|\b(?:and|or|both|respectively|i|ili|te)\b)",
    re.IGNORECASE,
)
_LIST_CUE = re.compile(
    r"\b(?:list|enumerate|all|each|every|how\s+many|popis|nabroji|svi|sve|svaki|koliko|"
    r"files|accounts|users|addresses|processes|programs|artifacts|records|entries|values|"
    r"datoteke|računi|korisnici|adrese|procesi|programi|artefakti|zapisi|vrijednosti)\b",
    re.IGNORECASE,
)
_PLURAL_AUXILIARY = re.compile(r"\b(?:are|were|do|have|su|jesu|imaju)\b", re.IGNORECASE)
_REQUESTS_ADDITIONAL_CONTEXT = re.compile(
    r"(?:,|:|\b(?:with|including|include|along\s+with|together\s+with|as\s+well\s+as|"
    r"plus|evidence\s+source|supporting\s+evidence|"
    r"(?:in\s+addition\s+to|alongside)\s+(?:(?:its|the)\s+)?"
    r"(?:sid|identifier|source|address|path|time|timestamp|hash)|"
    r"uklju[čc]uju[ćc]i|zajedno\s+s|"
    r"uz\s+(?:(?:pripadaju[ćc](?:i|a|e|u|ega|em|oj|im)|"
    r"odgovaraju[ćc](?:i|a|e|u|ega|em|oj|im)|njegov\w*|njezin\w*)\s+)?"
    r"(?:sid|identifikator|izvor|putanj[au]|vrijeme|adres[au]|sažetak|lokacij[au])|"
    r"uz\s+izvor|izvor\s+dokaza|dokazni\s+izvor)\b)",
    re.IGNORECASE,
)
_BULLET_OR_NUMBER = re.compile(r"^\s*(?:[-+*•]|\d+[.)])\s+")
_ANSWER_CLAUSE_COORDINATION = re.compile(
    r"\b(?:and|or|but|while|whereas|i|ili|ali|dok)\s+"
    r"(?:it|this|that|which|the|he|she|they|was|is|came|has|had|"
    r"to|ta|ono|koji|je|su|dolazi|ima)\b",
    re.IGNORECASE,
)
_STRUCTURED_TOOL_NAME = (
    r"registry_query|filesystem_query|memory_query|archive_query|registry_ripper"
)
_SOURCE_NARRATION = re.compile(
    r"\b(?:according\s+to|based\s+on|(?:was\s+|is\s+)?(?:obtained|recovered|derived)\s+from|"
    r"as\s+(?:returned|reported)\s+by|came\s+from|"
    rf"from\s+(?:the\s+)?(?:SYSTEM|SOFTWARE|SAM|SECURITY|{_STRUCTURED_TOOL_NAME}|"
    r"registry|hive|tool|result|evidence)\b|"
    rf"via\s+(?:the\s+)?(?:{_STRUCTURED_TOOL_NAME}|tool|function|query)\b|"
    rf"(?:{_STRUCTURED_TOOL_NAME})\s+(?:shows?|reports?|returns?|records?)\b|"
    rf"using\s+(?:the\s+)?(?:{_STRUCTURED_TOOL_NAME}|tool|function|query)\b|"
    r"using\s+(?:[\w.-]+\s+)?(?:tool|function|query)\b|"
    r"(?:recorded|stored|found|observed|shown|reported)\s+"
    r"(?:in|by|from)\s+(?:the\s+)?(?:registry_query|SYSTEM|SOFTWARE|SAM|SECURITY|registry|hive)\b|"
    r"owned\s+by|because\b|prema|na\s+temelju|"
    r"(?:dobiven[ao]?|pronađen[ao]?|oporavljen[ao]?|izveden[ao]?)\s+(?:je\s+)?iz|"
    r"(?:zabilježen[ao]?|spremljen[ao]?|prikazan[ao]?)\s+(?:je\s+)?u\s+"
    r"(?:registry_query|SYSTEM|SOFTWARE|SAM|SECURITY|registru)\b|"
    r"kako\s+(?:je\s+)?(?:vratio|prijavio|zabilježio))\b",
    re.IGNORECASE,
)
_RELATIVE_SECOND_FACT = re.compile(
    r"\b(?:whose|čiji|čija|čije)\s+(?:sid|identifier|id|account|user|owner|"
    r"identifikator|račun|korisnik|vlasnik)\b",
    re.IGNORECASE,
)
_ANSWER_ADDITIONAL_FIELD = re.compile(
    r"\b(?:as\s+well\s+as|along\s+with|together\s+with|plus|"
    r"uz\s+(?:(?:pripadaju[ćc]i|odgovaraju[ćc]i|njegov|njezin)\s+)?"
    r"(?:sid|identifikator|izvor|putanju|vrijeme))\b",
    re.IGNORECASE,
)

_COVERAGE_NARRATION = re.compile(
    r"\b(?:complete\s+coverage|coverage\s+(?:is\s+)?complete|fully\s+examined|"
    r"entire\s+(?:source|scope)|after\s+(?:examining|searching|reviewing)\s+"
    r"(?:the\s+)?(?:entire|whole)\s+(?:disk|image|source)|"
    r"potpun[ai]?\s+obuhvat|obuhvat\s+je\s+potpun|u\s+cijelosti\s+obra[đd]en[ao]?|"
    r"nakon\s+(?:pregleda|pretrage)\s+(?:cijelog|čitavog)\s+"
    r"(?:diska|slike|izvora))\b",
    re.IGNORECASE,
)
# An honest "cannot be determined" is a legitimate one-sentence direct answer,
# not narration to rewrite: the reformat only STEERS, so treating this as
# non-atomic would fire a pointless bounded rewrite over an answer that is
# already atomic, and the terminal request even instructs the model to state
# exactly this when the evidence does not establish the fact.  It is therefore
# NOT part of the atomic contract here (the codex origin, which also gated
# publication, wrongly rejected it and dead-ended honest unknowns).
ATOMIC_DIRECT_TERMINAL_REQUEST = (
    "Stop investigating. Based ONLY on the tool results above, answer the original "
    "question in exactly one plain sentence containing only the requested fact. Do not "
    "add explanation, source or tool narration, citations, lists, bullets, tables, or "
    "semicolons. If the evidence does not establish the answer, state that in one plain "
    "sentence."
)


def is_single_direct_factual_question(question: object) -> bool:
    """Recognize only one narrow EN/HR direct factual interrogative."""

    text = str(question or "").strip()
    if not text or text.count("?") != 1 or not text.endswith("?"):
        return False
    if _REJECTED_START.search(text):
        return False
    if not (_QUESTION_START.search(text) or _EMBEDDED_DIRECT_FILENAME.fullmatch(text)):
        return False
    if len(_QUESTION_WORD.findall(text)) != 1:
        return False
    return not any(
        pattern.search(text) is not None
        for pattern in (
            _MULTIPART,
            _LIST_CUE,
            _PLURAL_AUXILIARY,
            _REQUESTS_ADDITIONAL_CONTEXT,
        )
    )


def is_atomic_direct_answer(draft: object, *, claim_count: int) -> bool:
    """Whether normalized prose is one plain line and one claim unit."""

    if isinstance(claim_count, bool) or claim_count != 1:
        return False
    text = str(draft or "").strip()
    if not text or len(text.splitlines()) != 1:
        return False
    if any(marker in text for marker in (";", "\t", "|")):
        return False
    if (
        _ANSWER_CLAUSE_COORDINATION.search(text)
        or _ANSWER_ADDITIONAL_FIELD.search(text)
        or _RELATIVE_SECOND_FACT.search(text)
        or _SOURCE_NARRATION.search(text)
        or _COVERAGE_NARRATION.search(text)
    ):
        return False
    return _BULLET_OR_NUMBER.match(text) is None


__all__ = [
    "ATOMIC_DIRECT_TERMINAL_REQUEST",
    "is_atomic_direct_answer",
    "is_single_direct_factual_question",
]
