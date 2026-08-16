"""Extract the value-like tokens a draft answer actually cites.

The verifier's evidence bundle is byte-bounded, and what must never fall out of
it is precisely the material the draft's claims rest on.  The focus-token
machinery cannot guarantee that: it tokenizes question+draft into short words,
caps them at 128, and zeroes any token common across candidates — so the very
value under discussion can end up with no retention weight at all.  A cited
setting can be window-clipped out of a completely read configuration file, and a
cited address dropped with its whole content-text attribute.

This module reads the draft the way the identifier-grounding gate reads a
report: it extracts VALUE-shaped tokens — addresses, filenames, hashes,
key=value settings, quoted strings, path segments, serial-like codes — and
nothing conversational.  The extraction is deterministic and derives only from
the given text; nothing here knows any case.  Consumers use the tokens for two
things: guaranteed retention when packing the verifier bundle, and detecting,
after verification, that a grounded draft value never reached the verifier's
view at all.
"""

from __future__ import annotations

import re

#: Value forms a draft cites from evidence rather than composes itself.  Each
#: alternative matches one self-delimiting token; the order only affects which
#: match wins on overlap, not the extracted set.
_CITED_VALUE_RE = re.compile(
    # An email address.
    r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"
    # A filename with a known-value extension (the grounding gate's own class,
    # widened by document/config/archive forms a draft cites as evidence).
    r"|\b[\w.-]+\.(?:exe|dll|sys|bat|ps1|vbs|scr|cmd|com|jar|msi|tmp|ini|txt|"
    r"log|dat|doc|docx|pdf|zip|rar|jpg|jpeg|png|gif|pst|dbx|eml|pcap|cfg|conf)\b"
    # A dotted quad.
    r"|\b(?:\d{1,3}\.){3}\d{1,3}\b"
    # MD5 / SHA-1 / SHA-256.
    r"|\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b"
    # A composite bulk_extractor position inside a decoded/compressed stream.
    r"|\b\d{6,}(?:-[A-Za-z0-9]+)+\b"
    # A large decimal evidence position, such as a raw-image or memory offset.
    # Short numbers are intentionally excluded: years, counts, ports and table
    # ordinals are too common to spend guaranteed-retention slots on.
    r"|\b\d{6,}\b"
    # A key=value setting; the whole pair is the citation.
    r"|\b\w[\w.-]*=[^\s,;\"']+"
    # A quoted or backticked literal.
    r"|\"([^\"\n]{3,80})\"|'([^'\n]{3,80})'|`([^`\n]{3,80})`"
    # An upper-case code with at least one digit (computer names, serials).
    r"|\b(?=[A-Z0-9-]*\d)[A-Z][A-Z0-9-]{4,}\b"
    # A long hyphen- or underscore-joined word: recovered filenames and
    # setting names cite this way even without an extension.
    r"|\b(?=[\w-]{8,}\b)\w+[-_][\w-]*\w\b"
    # A path: two or more separated segments, either slash direction.
    r"|(?:[A-Za-z]:)?(?:[\\/][\w .$-]+){2,}",
)

# A bare recovered value can be the whole answer (a single unqualified token)
# without matching a filename extension, path, code, or other value shape.
# Bare words are much more ambiguous than the forms above, so their extraction
# is deliberately closed: the answer must make one unqualified value explicit,
# and the more natural filename phrasings are enabled only for one direct,
# singular filename question.
_ONE_TOKEN_ANSWER_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9_-]{3,79})[.!?]?\s*$")
_BARE_LITERAL_VALUE = r"[A-Za-z0-9][A-Za-z0-9_-]{3,79}"
_LONG_BARE_LITERAL_VALUE = r"[A-Za-z0-9][A-Za-z0-9_-]{7,79}"
_EXPLICIT_BARE_LITERAL_RES = (
    re.compile(
        rf"(?ix)\b(?:file[ -]?name|filename|answer|value)\s*"
        rf"(?:is|was|:|=)\s*(?P<value>{_LONG_BARE_LITERAL_VALUE})\b"
    ),
    re.compile(rf"(?ix)\b(?:called|named)\s+(?P<value>{_LONG_BARE_LITERAL_VALUE})\b"),
)
_FILENAME_BARE_LITERAL_RES = (
    re.compile(rf"(?ix)\b(?:stored|saved)\s+as\s+(?P<value>{_BARE_LITERAL_VALUE})\b"),
    re.compile(
        rf"(?ix)\b(?P<value>{_BARE_LITERAL_VALUE})\s+(?:is|was)\s+"
        rf"the\s+(?:file[ -]?name|filename)\b"
    ),
)
_FILENAME_PHRASE_RE = re.compile(r"(?i)\b(?:file[ -]?name|filename)\b")
_FILENAME_QUESTION_WORD_RE = re.compile(r"(?i)\b(?:what|which)\b")
_FILENAME_QUESTION_CUE_RE = re.compile(
    r"(?i)\b(?:what|which)\s+"
    r"(?:(?:is|was)\s+(?:the\s+)?)?(?:exact\s+)?"
    r"(?:file[ -]?name|filename)\b"
)
_FILENAME_QUESTION_REJECT_RE = re.compile(
    r"(?i)\b(?:file[ -]?names|filenames|multiple|several|all|list|two|three|or)\b"
)
_BARE_LITERAL_ANSWER_REJECT_RE = re.compile(
    r"(?ix)\b(?:"
    r"not|no|never|neither|nor|without|cannot|"
    r"maybe|may|might|could|can|would|should|possible|possibly|probably|perhaps|"
    r"likely|unlikely|allegedly|purportedly|reportedly|supposedly|tentatively|"
    r"apparently|presumably|seem|seems|seemed|appear|appears|appeared|"
    r"unclear|uncertain|suggest|suggests|suggested|"
    r"or|either|alternatively|instead|rather|but|however|although|though|yet|"
    r"except|unless|versus|vs"
    r")\b|\bn['’]t\b"
)
_BARE_LITERAL_SENTINELS = frozenset(
    {
        "blank",
        "empty",
        "error",
        "failed",
        "failure",
        "false",
        "true",
        "missing",
        "none",
        "no-file",
        "no_file",
        "nofile",
        "not-applicable",
        "not-available",
        "not-found",
        "not_applicable",
        "not_available",
        "not_found",
        "notapplicable",
        "notavailable",
        "notfound",
        "null",
        "placeholder",
        "redacted",
        "undefined",
        "unspecified",
        "unknown",
        "unavailable",
    }
)

#: Bound the set the same way the grounding gate bounds its checks.  Exceeding
#: the bound is reported to the caller and fails verification closed; values
#: after the bound are never silently treated as if the complete draft had been
#: covered.
_MAX_CITED_VALUES = 64

#: Tokens shorter than this are too ambiguous to guarantee retention for.
_MIN_TOKEN_LENGTH = 4


def _without_exact_question(text: str, question: str | None) -> str:
    """Blank the separately supplied question so it can never become a citation."""

    needle = (question or "").strip()
    if not needle:
        return text
    return re.sub(
        re.escape(needle),
        lambda match: " " * len(match.group(0)),
        text,
        flags=re.IGNORECASE,
    )


def _is_singular_filename_question(question: str | None) -> bool:
    """Recognize only a direct ``what/which ... file name?`` question."""

    source = (question or "").strip()
    return bool(
        source.endswith("?")
        and len(_FILENAME_QUESTION_WORD_RE.findall(source)) == 1
        and len(_FILENAME_PHRASE_RE.findall(source)) == 1
        and _FILENAME_QUESTION_CUE_RE.search(source)
        and not _FILENAME_QUESTION_REJECT_RE.search(source)
    )


def _bare_literal_candidates(
    source: str,
    *,
    question: str | None,
) -> list[tuple[int, str]]:
    """Return one unambiguous bare value, or none when the answer qualifies it."""

    if _BARE_LITERAL_ANSWER_REJECT_RE.search(source):
        return []

    candidates: list[tuple[int, str]] = []
    one_token = _ONE_TOKEN_ANSWER_RE.fullmatch(source)
    if one_token is not None:
        candidates.append((one_token.start(1), one_token.group(1)))
    for pattern in _EXPLICIT_BARE_LITERAL_RES:
        candidates.extend(
            (match.start("value"), match.group("value")) for match in pattern.finditer(source)
        )
    if _is_singular_filename_question(question):
        for pattern in _FILENAME_BARE_LITERAL_RES:
            candidates.extend(
                (match.start("value"), match.group("value")) for match in pattern.finditer(source)
            )

    admissible = [
        (position, value)
        for position, value in candidates
        if value.casefold() not in _BARE_LITERAL_SENTINELS
    ]
    unique = {value.casefold() for _position, value in admissible}
    if len(unique) != 1:
        return []
    return [min(admissible, key=lambda item: item[0])]


def select_cited_value_tokens(
    text: str,
    *,
    question: str | None = None,
) -> tuple[tuple[str, ...], bool]:
    """Return bounded unique draft values and whether their bound was exceeded.

    ``question`` is control context only. Its exact text is removed before
    extraction, and it can merely enable the closed singular-filename patterns.
    """

    source = _without_exact_question(text or "", question)
    candidates: list[tuple[int, str]] = []
    for match in _CITED_VALUE_RE.finditer(source):
        quoted = next((group for group in match.groups() if group), None)
        candidates.append((match.start(), quoted or match.group(0)))
    candidates.extend(_bare_literal_candidates(source, question=question))

    seen: dict[str, None] = {}
    for _position, candidate in sorted(candidates, key=lambda item: item[0]):
        token = candidate.strip().casefold()
        if len(token) < _MIN_TOKEN_LENGTH:
            continue
        seen.setdefault(token, None)
        if len(seen) > _MAX_CITED_VALUES:
            return tuple(seen)[:_MAX_CITED_VALUES], True
    return tuple(seen), False


def cited_value_tokens(text: str, *, question: str | None = None) -> tuple[str, ...]:
    """Unique, casefolded value tokens of ``text``, in first-seen order."""

    tokens, _overflow = select_cited_value_tokens(text, question=question)
    return tokens


__all__ = ["cited_value_tokens", "select_cited_value_tokens"]
