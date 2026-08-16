"""Carrying the run's observation/interpretation decision into the report.

ACPO v5 §6.5.4 requires a report to "always identify where an opinion is being
given, to distinguish this from fact", and where opinion is given, to "state the
facts on which this is based, and how he or she came to this conclusion".
SWGDE 18-Q-002 §5.5 imposes the same duty on the same document.

The run already decides this, once, per result: every standardized result
carries a mandatory ``provenance.evidence_class`` — OBSERVED for a reading a
named forensic component reported from bound evidence, DERIVED for a computation
this system performed over typed inputs, REFERENCE for procedural knowledge, and
DIAGNOSTIC for a real reading whose standing the run could not establish. A
DERIVED result additionally carries the method and the inputs it was computed
over, which is exactly the basis ACPO asks an opinion to state.

This module carries that decision to the report; it does not make one. No row is
classified by what its text says, and no value in it is read back out of the
evidence. A record that does not satisfy the contract it declares is reported as
carrying no established class rather than being read for one, because the class
is only worth printing if the record it came from is the record it claims to be.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from forensic_agent.core.result_contract import (
    DerivationInput,
    DerivationMetadata,
    EvidenceClass,
    ToolResult,
)
from forensic_agent.core.result_reading import (
    AnyToolResult,
    UnreadableResult,
    read_result,
    receipt_is_valid,
)

_UNKNOWN_TOOL = "unknown_tool"
_UNKNOWN_TYPE = "unknown"


@dataclass(frozen=True, slots=True)
class ReportedFinding:
    """One standardized finding as a report states it, carrying no evidence values.

    Everything here is metadata the run recorded *about* a reading: which call
    produced it, which chain entry recorded it, what kind of result it is, what
    class the run assigned it, and — for an interpretation — the method and the
    inputs it was computed over. The reading itself stays in the run record.
    """

    sequence: int
    tool: str
    evidence_class: EvidenceClass | None
    chain_entry: int | None = None
    data_type: str = _UNKNOWN_TYPE
    derivation_method: str | None = None
    derivation_inputs: tuple[str, ...] = ()
    assumptions: tuple[str, ...] = ()
    producers: tuple[str, ...] = ()
    receipt_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class ClassifiedFindings:
    """The run's findings split the way a reader has to be able to split them.

    ``unadmitted`` holds everything the run did not admit as either an
    observation or an interpretation — procedural knowledge, a reading whose
    standing the run could not establish, and a record that does not satisfy its
    own contract. They are neither hidden nor promoted: each states its own
    standing where the report prints it.
    """

    observations: tuple[ReportedFinding, ...]
    interpretations: tuple[ReportedFinding, ...]
    unadmitted: tuple[ReportedFinding, ...]

    @property
    def total(self) -> int:
        return len(self.observations) + len(self.interpretations) + len(self.unadmitted)


def classify_findings(
    rows: Sequence[Mapping[str, object]],
) -> ClassifiedFindings:
    """Split traced findings by the evidence class their own record carries."""

    observations: list[ReportedFinding] = []
    interpretations: list[ReportedFinding] = []
    unadmitted: list[ReportedFinding] = []
    for position, row in enumerate(rows, start=1):
        finding = _reported_finding(row, sequence=position)
        if finding.evidence_class is EvidenceClass.OBSERVED:
            observations.append(finding)
        elif finding.evidence_class is EvidenceClass.DERIVED:
            interpretations.append(finding)
        else:
            unadmitted.append(finding)
    return ClassifiedFindings(
        observations=tuple(observations),
        interpretations=tuple(interpretations),
        unadmitted=tuple(unadmitted),
    )


def standing_of(finding: ReportedFinding) -> str:
    """The words a report uses for a finding it admits as neither class."""

    if finding.evidence_class is None:
        return "class not established by the record"
    return finding.evidence_class.value


def _reported_finding(row: Mapping[str, object], *, sequence: int) -> ReportedFinding:
    try:
        read = read_result(_result_value(row))
    except UnreadableResult:
        # All such a row establishes is that a call was traced and under which
        # name. Its own account of itself is exactly what did not validate.
        return ReportedFinding(
            sequence=sequence,
            tool=_text(row.get("tool"), fallback=_UNKNOWN_TOOL),
            evidence_class=None,
        )
    derivation = _derivation(read)
    method = f"{derivation.method} {derivation.method_version}" if derivation else None
    inputs = (
        tuple(_input_label(item) for item in derivation.derivation_inputs)
        if derivation
        else ()
    )
    return ReportedFinding(
        sequence=sequence,
        tool=_text(read.provenance.tool.name, fallback=_UNKNOWN_TOOL),
        evidence_class=_evidence_class(read),
        chain_entry=read.provenance.oversight_sequence,
        data_type=_text(read.data.type, fallback=_UNKNOWN_TYPE),
        derivation_method=method,
        derivation_inputs=inputs,
        assumptions=tuple(derivation.assumptions) if derivation else (),
        producers=_producers(read),
        receipt_sha256=_verified_receipt_digest(read),
    )


def _result_value(row: Mapping[str, object]) -> object:
    """The result a traced row holds, or the row itself when it is the result."""

    return row["result"] if "result" in row else row


def _evidence_class(read: AnyToolResult) -> EvidenceClass | None:
    """The class the record carries, or ``None`` where its contract has no such field.

    The historical envelope predates the mandatory epistemic class, so a result
    written under it establishes no class at all; reporting one for it would
    state a decision the run never made.
    """

    return read.provenance.evidence_class if isinstance(read, ToolResult) else None


def _derivation(read: AnyToolResult) -> DerivationMetadata | None:
    return read.provenance.derivation if isinstance(read, ToolResult) else None


def _producers(read: AnyToolResult) -> tuple[str, ...]:
    if not isinstance(read, ToolResult):
        return ()
    return tuple(
        f"{backend.name} {backend.version}"
        for backend in read.provenance.upstream_backends
        if backend.role == "producer"
    )


def _verified_receipt_digest(read: AnyToolResult) -> str | None:
    """The payload digest, printed only where it actually covers the payload.

    An unverified digest in a report reads as an integrity guarantee, so a
    receipt that does not match the result it travels with yields nothing.
    """

    if read.receipt is None or not receipt_is_valid(read):
        return None
    return read.receipt.payload_sha256


def _input_label(item: DerivationInput) -> str:
    """One derivation input, named by the identity its contract requires of it."""

    if item.kind == "source":
        return f"evidence source {item.source_id}"
    return f"earlier result {item.invocation_id}"


def _text(value: object, *, fallback: str) -> str:
    text = " ".join(str(value or "").split())
    return text or fallback


__all__ = [
    "ClassifiedFindings",
    "ReportedFinding",
    "classify_findings",
    "standing_of",
]
