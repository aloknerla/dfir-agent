"""Verify that every identifier in a report exists in receipted evidence.

The model must not add an identifier from general knowledge. For example, a
process-listing tool can return a truncated executable name while the model
silently expands it to a plausible full name. Even when such a guess happens
to be correct, later review cannot distinguish it from a grounded claim unless
another receipted result contains the complete identifier.

The check is deliberately narrow. It considers only values that should never be
guessed: executable and similar filenames, IPv4 addresses, and digests.
Ordinary prose, numbers, and plugin names are outside its scope.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

from forensic_agent.core.repro import canonical_json
from forensic_agent.core.result_admission import wire_passes_final_check
from forensic_agent.core.result_contract import DerivationLineageResolver

_IDENTIFIER_GROUNDING_METRICS_SCHEMA_ID = "forensic.identifier-grounding-metrics.v1"

#: Value forms that must come from a tool rather than general knowledge.
_IDENTIFIER_RE = re.compile(
    r"\b[A-Za-z0-9_.\-]+\.(?:exe|dll|sys|bat|ps1|vbs|scr|cmd|com|jar|msi|tmp)\b"
    r"|\b(?:\d{1,3}\.){3}\d{1,3}\b"
    r"|\b[a-fA-F0-9]{32}\b"
    r"|\b[a-fA-F0-9]{40}\b"
    r"|\b[a-fA-F0-9]{64}\b",
    re.IGNORECASE,
)
#: A report naming more distinct identifiers than this is refused outright rather
#: than partially checked: a gate that has not read the whole report cannot clear
#: it, so exceeding the bound is a fail-closed refusal, never a silent pass.
_MAX_CHECKED_IDENTIFIERS = 64


def empty_identifier_grounding_metrics(*, enabled: bool) -> dict[str, object]:
    """Return the stable telemetry shape for grounding verification."""

    return {
        "schema_id": _IDENTIFIER_GROUNDING_METRICS_SCHEMA_ID,
        "enabled": enabled,
        "activated": False,
        "decision": "not_evaluated" if enabled else "arm_disabled",
        "identifiers_checked": 0,
        "identifiers_grounded": 0,
        "ungrounded_identifiers": [],
    }


def report_identifiers(report: str) -> list[str]:
    """Return unique report identifiers in stable order.

    Extraction stops one past the refusal bound.  The gate never has to enumerate
    a larger population than that: a report carrying more distinct identifiers than
    the bound is refused as a whole rather than cleared on a truncated view, so
    seeing one identifier beyond the bound is all the caller needs to decide.
    """

    seen: dict[str, None] = {}
    for match in _IDENTIFIER_RE.finditer(report):
        seen.setdefault(match.group(0).casefold(), None)
        if len(seen) > _MAX_CHECKED_IDENTIFIERS:
            break
    return list(seen)


def evidence_text(
    records: list[dict[str, object]],
    *,
    case_id: str | None,
    lineage: DerivationLineageResolver | None = None,
) -> str:
    """Combine the OBSERVATION-bearing text of admissible same-case results.

    Search only ``result['data']`` — the attributes and rows a tool actually
    returned.  An identifier may legitimately appear there in a path, command
    line, and process name at once, so no single field is prescribed; but the
    provenance, receipt and derivation are excluded on purpose.  A DERIVED
    result's ``provenance.derivation.parameters`` echoes back the CALLER's own
    arguments (for example a ``find_files`` pattern), so grounding a claim against
    the full result would let a model launder an invented identifier by searching
    for it first.  The parameters are what the model said; ``data`` is what the
    tool answered, and only the latter can ground a claim.

    The records are the COMPLETE standardized results the run retained, each
    carrying its own receipt, distinct from the bounded projection the model was
    shown.  This gate reads the complete result, so the complete result's
    receipt is the one it verifies — and only what passes the final check may
    ground a published claim.  A merely PRESENT receipt object proves nothing: it
    is a digest anyone editing the payload can recompute, so it is verified here
    rather than counted.
    """

    parts: list[str] = []
    for record in records:
        result = record.get("result")
        if not isinstance(result, Mapping):
            continue
        if not wire_passes_final_check(result, lineage=lineage, active_case_id=case_id):
            continue
        # The historical envelope leaves ``case_id`` optional and the final check
        # cannot bind what a record does not carry, so the run's own case filter
        # stays in place for it.  A result of the active contract has already
        # been bound to ``case_id`` exactly, by the check above.
        provenance = result.get("provenance")
        if case_id is not None and (
            not isinstance(provenance, Mapping)
            or provenance.get("case_id") not in (None, case_id)
        ):
            continue
        data = result.get("data")
        if data is None:
            continue
        try:
            parts.append(canonical_json(data))
        except (TypeError, ValueError):
            # A result whose observation cannot be serialized cannot ground
            # anything, and withholding a report is never worth crashing
            # finalization over.
            continue
    return " ".join(parts).casefold()


def evidence_identifiers(
    records: list[dict[str, object]],
    *,
    case_id: str | None,
    lineage: DerivationLineageResolver | None = None,
) -> set[str]:
    """Return exact, case-normalized identifiers from admissible result data."""

    text = evidence_text(records, case_id=case_id, lineage=lineage)
    return {match.group(0).casefold() for match in _IDENTIFIER_RE.finditer(text)}


def check_identifier_grounding(
    report: str | None,
    records: list[dict[str, object]],
    *,
    case_id: str | None,
    lineage: DerivationLineageResolver | None = None,
) -> tuple[bool, dict[str, object]]:
    """Return whether publication is allowed and the associated telemetry.

    A report without identifiers passes. A report passes when every identifier
    exists in evidence that passed the final check. Otherwise publication is
    withheld.
    """

    metrics = empty_identifier_grounding_metrics(enabled=True)
    if not isinstance(report, str) or not report.strip():
        metrics["decision"] = "no_report"
        return True, metrics
    identifiers = report_identifiers(report)
    metrics["identifiers_checked"] = len(identifiers)
    if not identifiers:
        metrics["decision"] = "no_identifier_claims"
        return True, metrics
    metrics["activated"] = True
    if len(identifiers) > _MAX_CHECKED_IDENTIFIERS:
        # More distinct identifiers than the gate will verify.  The bound exists
        # so a pathological report cannot make verification expensive, but a gate
        # that has not read the whole report must not clear it: exceeding the
        # bound is refused, and ``identifiers_checked`` records that it was hit.
        metrics["decision"] = "identifier_count_exceeds_gate_bound"
        return False, metrics
    grounded = evidence_identifiers(records, case_id=case_id, lineage=lineage)
    ungrounded = [value for value in identifiers if value not in grounded]
    metrics["identifiers_grounded"] = len(identifiers) - len(ungrounded)
    metrics["ungrounded_identifiers"] = sorted(ungrounded)
    if ungrounded:
        metrics["decision"] = "ungrounded_identifier_claim"
        return False, metrics
    metrics["decision"] = "all_identifiers_grounded"
    return True, metrics
