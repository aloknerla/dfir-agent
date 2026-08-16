"""The one place a reader recognises which result contract it is holding.

A reader bound to a single contract treats every other envelope as invalid input.
That is not a harmless no-op here: the standardizer emits
:mod:`forensic_agent.core.result_contract` envelopes, and a reader bound only to
the historical model would drop real, receipt-valid evidence while leaving
nothing behind to say that it ever arrived.  Every reader therefore accepts BOTH
shapes from here.

Recognition is by the record's own ``schema_version``, never by guessing from the
field layout.  The two envelopes share most of their fields, so a structural
guess would happily validate one as the other and then read the wrong invariants
off it — the active contract's mandatory epistemic class would simply vanish.

A value that declares neither known envelope is refused explicitly, with
:class:`UnreadableResult`, rather than returned as "not a result".  An unreadable
record and an absent record must never look the same to a caller: that is exactly
how a result gets discarded in silence.  ``UnreadableResult`` derives from
``ValueError`` so a reader that already treats a validation failure as a rejection
keeps concluding what it concluded before.

This module reads; it never builds a result and never modifies one.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeAlias

from forensic_agent.core.result_contract import SCHEMA_ID as ACTIVE_SCHEMA_ID
from forensic_agent.core.result_contract import (
    ToolResult,
)
from forensic_agent.core.result_contract import (
    verify_receipt as verify_active_receipt,
)
from forensic_agent.core.tool_result import SCHEMA_ID as LEGACY_SCHEMA_ID
from forensic_agent.core.tool_result import (
    ToolResult as LegacyToolResult,
)
from forensic_agent.core.tool_result import (
    verify_receipt as verify_legacy_receipt,
)

#: A result of either contract.  Everything a reader needs beyond this alias —
#: ``status``, ``data``, ``page``, ``coverage``, ``warnings``, ``error`` and the
#: provenance's source/artifact/tool/case/invocation identity — is spelled
#: identically in both, because the active contract reuses those value objects
#: unchanged.  Only the receipt algorithm and the name of the case-evidence flag
#: differ, and both are resolved by the helpers below.
AnyToolResult: TypeAlias = ToolResult | LegacyToolResult

#: The envelope versions a reader on this branch understands.
READABLE_SCHEMA_IDS = frozenset({ACTIVE_SCHEMA_ID, LEGACY_SCHEMA_ID})

# Any record whose declared version starts with this prefix is claiming to be one
# of our tool-result envelopes.  It matters that an unknown version under this
# prefix is told apart from an ordinary legacy dict: the first is a result we
# cannot read and must refuse loudly, the second was never an envelope at all.
_ENVELOPE_SCHEMA_PREFIX = "forensic.tool-result."


class UnreadableResult(ValueError):
    """A value could not be read as a result of either contract."""


def declared_schema_version(value: Any) -> str | None:
    """Return the envelope version a value declares, without validating it."""

    if isinstance(value, (ToolResult, LegacyToolResult)):
        return value.schema_version
    if isinstance(value, Mapping):
        version = value.get("schema_version")
        return version if isinstance(version, str) else None
    return None


def claims_result_envelope(value: Any) -> bool:
    """Whether a value presents itself as one of our tool-result envelopes.

    True for an unknown version under the envelope prefix as well.  A caller uses
    this to separate "this is a result I cannot read" from "this was never a
    result", which are different facts and must not share an answer.
    """

    version = declared_schema_version(value)
    return version is not None and version.startswith(_ENVELOPE_SCHEMA_PREFIX)


def is_readable_result(value: Any) -> bool:
    """Whether a value declares an envelope version this branch can read."""

    return declared_schema_version(value) in READABLE_SCHEMA_IDS


def read_result(value: Any) -> AnyToolResult:
    """Validate a wire value under the contract it declares, or refuse.

    Raises :class:`UnreadableResult` for a value that declares no known envelope
    and for one that declares a known envelope but fails its invariants.  The
    refusal is deliberately not a ``None`` return: a caller that wanted to fall
    back would then have to invent the distinction between a malformed result and
    no result at all, which is where evidence goes missing.
    """

    if isinstance(value, (ToolResult, LegacyToolResult)):
        return value
    version = declared_schema_version(value)
    if version == ACTIVE_SCHEMA_ID:
        model: type[AnyToolResult] = ToolResult
    elif version == LEGACY_SCHEMA_ID:
        model = LegacyToolResult
    else:
        raise UnreadableResult(
            f"value declares no readable tool-result envelope (schema_version={version!r})"
        )
    try:
        return model.model_validate(value)
    except Exception as exc:
        raise UnreadableResult(
            f"value declares {version!r} but does not satisfy that contract"
        ) from exc


def receipt_is_valid(result: AnyToolResult) -> bool:
    """Whether a result carries a receipt that matches its own payload.

    Each contract canonicalizes and verifies its own payload, so the check is
    dispatched rather than shared: running one contract's verifier over the
    other's envelope would compare a digest against a payload it never covered.
    """

    if isinstance(result, ToolResult):
        return result.receipt is not None and verify_active_receipt(result)
    return result.receipt is not None and verify_legacy_receipt(result)


def is_candidate_case_evidence(result: AnyToolResult) -> bool:
    """Whether the provenance marks this result as possibly case evidence.

    The two contracts spell the same fact differently — the historical envelope
    calls it ``admissible_as_case_evidence``, the active one deliberately renamed
    it ``candidate_case_evidence`` because admissibility is the final check's
    verdict, not the standardizer's.  Both remain a statement that the provenance
    type is case evidence, and nothing more.
    """

    if isinstance(result, ToolResult):
        return result.provenance.candidate_case_evidence
    return result.provenance.admissible_as_case_evidence


__all__ = [
    "ACTIVE_SCHEMA_ID",
    "LEGACY_SCHEMA_ID",
    "READABLE_SCHEMA_IDS",
    "AnyToolResult",
    "UnreadableResult",
    "claims_result_envelope",
    "declared_schema_version",
    "is_candidate_case_evidence",
    "is_readable_result",
    "read_result",
    "receipt_is_valid",
]
