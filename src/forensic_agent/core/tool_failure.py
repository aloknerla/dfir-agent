"""What a failed tool call actually failed at, decided in one place.

Wording chosen at a single call site becomes a claim about the evidence.  A
filesystem read that fails inside the NTFS layer must not be reported as a path
that could not be found: a reader entitled to conclude absence from that would
stop looking, though the tool established no absence, only a failed read.  The
method a reader follows says a tool error is not evidence that an artifact is
absent, and that rule cannot be honoured when the tool reports the failure AS an
absence.

A classification therefore replaces a free-text sentence: what kind of failure
this was, what the backend said about it, and whether it says anything about the
artifact being there.  It is decided from the exception rather than from the call
site, so the decision is testable in one place.
"""

from __future__ import annotations

import re
from enum import StrEnum

_TOOL_FAILURE_SCHEMA_ID = "forensic.tool-failure.v1"


class UnreadableEvidenceError(OSError):
    """Raised where a read failed and absence could not be established.

    A backend that answers a lookup with nothing has said one word for two
    different facts: the entry is not there, and the entry could not be read.
    dfVFS's TSK adapter discards the backend's ``OSError`` and returns ``None``,
    and a read that comes back wrong is parsed as a directory index that simply
    does not name what was asked for.  A caller that could not tell those apart
    raises this rather than wording a sentence, because the class of a failure is
    the one part of it that cannot be read as a claim about the evidence.
    """


class FailureKind(StrEnum):
    """What failed, in the only terms a reader can act on."""

    #: The named artifact is genuinely not there.  The only kind that says
    #: anything about absence, and it says it about one path, not a medium.
    NOT_FOUND = "not_found"
    #: The medium, container or parser could not deliver the bytes.  Establishes
    #: nothing about whether the artifact exists; a retry may well succeed.
    UNREADABLE = "unreadable"
    #: The backend does not handle this input at all.  Nothing was examined.
    UNSUPPORTED = "unsupported"
    #: A rule, ceiling or missing authority stopped the call before it ran.
    REFUSED = "refused"
    #: The arguments never described a call the tool could make.
    INVALID_ARGUMENTS = "invalid_arguments"
    #: Classified as nothing more specific.  Deliberately not "not found".
    FAILED = "failed"


#: Whether a failure permits a reader to conclude the artifact is not there.
#: Only one kind does, and it is the one that says so.
_ESTABLISHES_ABSENCE = frozenset({FailureKind.NOT_FOUND})

#: Matched against the exception's own text.  Backend messages are the most
#: reliable signal available: a library that could not read a buffer says so,
#: whatever exception class it happens to raise through.
_TEXT_RULES: tuple[tuple[re.Pattern[str], FailureKind], ...] = (
    (re.compile(r"read_buffer|unable to read|read error|i/?o error", re.I), FailureKind.UNREADABLE),
    (re.compile(r"unable to (open|retrieve|resolve)", re.I), FailureKind.UNREADABLE),
    (re.compile(r"corrupt|checksum|crc mismatch|bad sector", re.I), FailureKind.UNREADABLE),
    (re.compile(r"unsupported|not supported|unknown format|no handler", re.I), FailureKind.UNSUPPORTED),
    (re.compile(r"no such file or directory|does not exist|not found", re.I), FailureKind.NOT_FOUND),
    (re.compile(r"permission denied|not permitted|refused|forbidden", re.I), FailureKind.REFUSED),
    (re.compile(r"invalid|malformed|validation error", re.I), FailureKind.INVALID_ARGUMENTS),
)

#: Exception classes whose meaning is unambiguous regardless of wording.
_TYPE_RULES: dict[str, FailureKind] = {
    "FileNotFoundError": FailureKind.NOT_FOUND,
    "NotADirectoryError": FailureKind.NOT_FOUND,
    "IsADirectoryError": FailureKind.INVALID_ARGUMENTS,
    "PermissionError": FailureKind.REFUSED,
    "TimeoutError": FailureKind.UNREADABLE,
    "NotImplementedError": FailureKind.UNSUPPORTED,
}

#: Classes that exist only to report that a backend did not deliver.  Their
#: wording is a diagnostic about the library, never a statement about the medium,
#: so they are decided before any text is read: dfVFS raises ``BackEndError`` for
#: everything libfsntfs, libfsext and libfsfat refuse to hand over, and a phrase
#: like "index entry not found" inside one of those describes a structure the
#: parser walked, not an artifact an examiner asked about.
_BACKEND_FAILURE_TYPES: frozenset[str] = frozenset(
    {
        "UnreadableEvidenceError",
        "BackEndError",
    }
)

#: The frame a forensic C library prefixes to its own diagnostics
#: (``libewf_chunk_data_unpack:``, ``pyfsntfs_volume_get_file_entry_by_path:``).
#: Its presence means the sentence was written about the library's internals, so
#: an absence phrase inside it is not an answer about the evidence.
_BACKEND_DIAGNOSTIC: re.Pattern[str] = re.compile(r"\b(?:lib|py)[a-z0-9]+_[a-z0-9_]+\s*:")


def classify_failure(error: BaseException) -> FailureKind:
    """Decide what one exception says about the read that raised it.

    The backend's own words are read before the exception class, because a
    library that reports "unable to read buffer" through a generic OSError has
    said the more useful thing.  ``FileNotFoundError`` and its siblings are
    unambiguous, so they are honoured first among the classes.

    Absence is the one conclusion a reader acts on irreversibly, so it is the one
    the wording alone may not reach: a class that exists only for a failed
    backend is decided first, and a "not found" phrase sitting inside a library's
    own diagnostic frame falls back to a read failure.  Every other direction of
    doubt is cheap; this one costs the answer.
    """

    name = type(error).__name__
    text = str(error)
    if name in _BACKEND_FAILURE_TYPES:
        return FailureKind.UNREADABLE
    # A library saying it could not read outranks a class that says only that
    # something went wrong at the OS boundary.
    for pattern, kind in _TEXT_RULES:
        if pattern.search(text):
            if kind is FailureKind.NOT_FOUND:
                if name in _TYPE_RULES:
                    return _TYPE_RULES[name]
                if _BACKEND_DIAGNOSTIC.search(text):
                    return FailureKind.UNREADABLE
            return kind
    if name in _TYPE_RULES:
        return _TYPE_RULES[name]
    return FailureKind.FAILED


def establishes_absence(kind: FailureKind) -> bool:
    """Whether this failure may be read as the artifact not being there."""

    return kind in _ESTABLISHES_ABSENCE


def tool_failure(
    error: BaseException,
    *,
    subject: str,
    backend: str | None = None,
    detail_limit: int = 300,
) -> dict[str, object]:
    """Describe one failed call: its kind, its subject, and what the backend said.

    ``subject`` is what the call was about (a path, a hive name, a capture) so
    the record names the thing without the caller having to word the failure.
    The backend's own diagnostic is carried rather than replaced: it is the only
    text that explains the failure, and burying it is what let a read error read
    as a missing directory.
    """

    kind = classify_failure(error)
    return {
        "schema_id": _TOOL_FAILURE_SCHEMA_ID,
        "kind": str(kind),
        "subject": subject,
        "backend": backend,
        "establishes_absence": establishes_absence(kind),
        "exception_type": type(error).__name__,
        "detail": str(error)[:detail_limit],
        "message": _message(kind, subject=subject, backend=backend),
    }


def tool_failure_result(
    error: BaseException,
    *,
    subject: str,
    backend: str | None = None,
) -> dict[str, object]:
    """The legacy result one failed call returns, carrying its classification.

    Deliberately no coverage flag: a call that produced nothing is an error, and
    declaring incomplete coverage beside it turns the result partial — which
    reads as "some of it was examined" about a call that examined none.
    """

    record = tool_failure(error, subject=subject, backend=backend)
    # The classification is added to what the backend said, never substituted
    # for it.  Where the raw text is noise the sentence carries the meaning; but
    # a configuration failure states the one thing an operator needs — which
    # variable, which directory — and replacing that with a category would take
    # away the only actionable part of the message.
    detail = str(record["detail"]).strip()
    message = str(record["message"])
    return {
        "error": f"{message} {detail}".strip() if detail else message,
        "failure": record,
    }


def _message(kind: FailureKind, *, subject: str, backend: str | None) -> str:
    """One sentence that states the failure without overstating it."""

    where = f" ({backend})" if backend else ""
    if kind is FailureKind.NOT_FOUND:
        return f"not present in the evidence: {subject}"
    if kind is FailureKind.UNREADABLE:
        return (
            f"could not be read{where}: {subject}. This is a read failure, not an "
            "absence: it establishes nothing about whether the artifact is there."
        )
    if kind is FailureKind.UNSUPPORTED:
        return f"this backend{where} does not handle: {subject}"
    if kind is FailureKind.REFUSED:
        return f"the call was refused before reading: {subject}"
    if kind is FailureKind.INVALID_ARGUMENTS:
        return f"the arguments did not describe a call that could run: {subject}"
    return (
        f"the call failed{where}: {subject}. What this means for the artifact is "
        "not established."
    )
