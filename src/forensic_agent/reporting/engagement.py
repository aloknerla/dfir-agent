"""The facts about an engagement that no run can observe.

SWGDE 18-Q-002 §5 requires an examination report to name the requester, to state
the disposition of the evidence and to carry a report authorization; §5.7
requires that authorization to name its authorizer *and* to carry a signature.
None of those four is a property of the examination the software performed. They
are properties of the instruction under which it was performed, of what happened
to the exhibit afterwards, and of who is willing to put their name to the result
— so no run can read them off anything, and every default that could be invented
for them would be a fabrication in a document meant to be read as evidence.

They therefore enter a report only from here: a record the operator supplies,
read from a file the report then names and digests, with every field the file
does not carry rendered as not supplied rather than omitted. A reader who is
told a field was not supplied knows something; a reader shown a report with no
requester line at all cannot tell the difference between an engagement with no
requester and a generator that never asked.

Nothing in this module infers, defaults or completes a value.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TypeGuard

from forensic_agent.core.repro import sha256_hex

#: Environment variable naming the JSON file that carries the engagement record.
#: It exists so an operator can supply these facts to the shipped export path
#: without a caller having to thread them through by hand.
ENGAGEMENT_RECORD_VARIABLE = "DFA_ENGAGEMENT_RECORD"

#: What the report prints where the operator supplied nothing. One phrase, used
#: everywhere, so "not supplied" can never read as a value someone chose.
NOT_SUPPLIED = "Not supplied"

#: The keys an engagement file may carry. A file is refused for any other key,
#: because a misspelled field would otherwise be silently dropped and the report
#: would then state that a value was not supplied when the operator supplied it.
ENGAGEMENT_FIELDS = (
    "requester",
    "authorizing_examiner",
    "authorization_signature",
    "evidence_disposition",
)


class EngagementRecordError(ValueError):
    """An operator-supplied engagement record could not be read as one."""


def is_supplied(value: str | None) -> TypeGuard[str]:
    """Whether a field carries something an operator actually wrote."""

    return isinstance(value, str) and bool(value.strip())


def stated(value: str | None) -> str:
    """The value as the report prints it, or the explicit not-supplied phrase."""

    return value.strip() if is_supplied(value) else NOT_SUPPLIED


@dataclass(frozen=True, slots=True)
class EngagementRecord:
    """What an operator stated about the engagement, and where they stated it.

    ``source_path`` and ``source_sha256`` describe the file the values were read
    from, not the engagement, so a reader can check the authorization block
    against the record it came from instead of taking the document's word for it.
    A record built in memory carries neither, and the report then says only that
    the values were supplied by the caller.
    """

    requester: str | None = None
    authorizing_examiner: str | None = None
    authorization_signature: str | None = None
    evidence_disposition: str | None = None
    source_path: str | None = None
    source_sha256: str | None = None

    @property
    def is_authorized(self) -> bool:
        """Whether both halves of a report authorization were supplied.

        SWGDE 18-Q-002 §5.7 requires the authorizer's name and a signature, so
        one without the other authorizes nothing: a name with no signature is an
        intention, and a signature with no name identifies nobody.
        """

        return is_supplied(self.authorizing_examiner) and is_supplied(
            self.authorization_signature
        )


def load_engagement_record(path: str | Path) -> EngagementRecord:
    """Read an engagement record from a JSON file, or refuse to read one.

    Every failure raises rather than returning an empty record: a report that
    printed "not supplied" because the operator's file failed to parse would
    misreport the one thing this record exists to state honestly.
    """

    location = Path(path)
    try:
        raw = location.read_bytes()
    except OSError as exc:
        raise EngagementRecordError(
            f"the engagement record at {location} could not be read"
        ) from exc
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EngagementRecordError(
            f"the engagement record at {location} is not valid UTF-8 JSON"
        ) from exc
    if not isinstance(parsed, Mapping):
        raise EngagementRecordError(
            f"the engagement record at {location} is not a JSON object"
        )
    unknown = sorted(str(key) for key in parsed if key not in ENGAGEMENT_FIELDS)
    if unknown:
        raise EngagementRecordError(
            f"the engagement record at {location} carries unsupported "
            f"field(s) {', '.join(unknown)}; supported fields are "
            f"{', '.join(ENGAGEMENT_FIELDS)}"
        )
    values: dict[str, str | None] = {}
    for name in ENGAGEMENT_FIELDS:
        value = parsed.get(name)
        if value is None:
            values[name] = None
            continue
        if not isinstance(value, str):
            raise EngagementRecordError(
                f"the engagement record at {location} states {name!r} as "
                f"{type(value).__name__}; every field is text or null"
            )
        values[name] = value.strip() or None
    return EngagementRecord(
        **values,
        source_path=str(location),
        source_sha256=sha256_hex(raw),
    )


def engagement_record_from_environment(
    environment: Mapping[str, str] | None = None,
) -> EngagementRecord | None:
    """The record the environment names, or ``None`` when it names no file.

    A variable that names a file this cannot read raises out of
    :func:`load_engagement_record` rather than resolving to no record, so an
    operator who supplied the facts is never told by the report that they did
    not.
    """

    source = os.environ if environment is None else environment
    location = source.get(ENGAGEMENT_RECORD_VARIABLE, "").strip()
    if not location:
        return None
    return load_engagement_record(location)
