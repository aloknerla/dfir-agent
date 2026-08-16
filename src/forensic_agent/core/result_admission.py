"""The final check: whether one standardized result may back a case claim.

Every gate that decides what the final answer is allowed to rest on asks
this module, so the rules live in one place and cannot drift apart between the
verifier's evidence bundle and the downstream gates that follow it.  The rules
themselves are not restated here: for a result of the active contract the verdict
is :func:`forensic_agent.core.result_contract.result_is_admissible`, which
already expresses them — an ERROR result is never evidence, a REFERENCE result is
never evidence of the active case, an OBSERVED result names exactly one real
versioned producer, a DERIVED result carries a derivation with verifiable inputs,
and the result is bound to its case, its source, its invocation and the trusted
oversight chain.

Two things this module deliberately does NOT do.

It does not read a record loosely.  A value is validated under the contract it
declares first, so a record that violates the contract it claims — an OBSERVED
result with no producing backend, a DERIVED result with no derivation — never
reaches the rules at all: it is not a result, and the only safe verdict for
something that is not a result is refusal.

It does not decide which artifact a caller should be asking about.  A run keeps
the COMPLETE standardized result and the bounded model-visible projection as two
separate artifacts with two separate receipts, and each gate must pass the
one it actually relies on: the verifier judges the projection the model was
given, the downstream gates judge the complete result the run retained.  Passing
the other one would attest an artifact the decision was never made from.

The lineage resolver is a runtime seam, exactly like the transform surface's
cited-value resolver: ``None`` means no trusted lineage store is bound, and a
result of the active contract is then refused deterministically rather than
admitted on the strength of its own self-consistent receipt.  A receipt can be
recomputed by whoever can edit the payload, so without an external record there
is nothing left to check the content against.
"""

from __future__ import annotations

from typing import Any

from forensic_agent.core.result_contract import (
    DerivationLineageResolver,
    ToolResult,
    ToolStatus,
    result_is_admissible,
)
from forensic_agent.core.result_reading import (
    AnyToolResult,
    UnreadableResult,
    is_candidate_case_evidence,
    read_result,
    receipt_is_valid,
)


def historical_result_backs_a_case_claim(result: AnyToolResult) -> bool:
    """The verdict the historical envelope has always been given.

    It has no epistemic class and no lineage to validate, so all it can state is
    that the payload matches its receipt, that its provenance is case evidence
    rather than reference knowledge, and that the call did not fail.  This is
    kept exactly as it was because production still emits this envelope: tighten
    it before the emitters switch and a live run loses evidence it has always
    been allowed to use.  It disappears with the historical envelope itself.
    """

    return bool(
        receipt_is_valid(result)
        and is_candidate_case_evidence(result)
        # An error result reports that the call produced no usable finding, so it
        # can never back a case claim however well formed it is.  PARTIAL stays
        # admissible: it carries real data with disclosed incomplete coverage.
        and result.status is not ToolStatus.ERROR
    )


def result_passes_final_check(
    result: AnyToolResult,
    *,
    lineage: DerivationLineageResolver | None = None,
    active_case_id: str | None = None,
) -> bool:
    """Whether an already-read result may back a claim about the active case."""

    if isinstance(result, ToolResult):
        return result_is_admissible(result, lineage=lineage, active_case_id=active_case_id)
    return historical_result_backs_a_case_claim(result)


def wire_passes_final_check(
    value: Any,
    *,
    lineage: DerivationLineageResolver | None = None,
    active_case_id: str | None = None,
) -> bool:
    """Read a stored or transported record and apply the final check to it."""

    try:
        result = read_result(value)
    except (TypeError, UnreadableResult):
        return False
    return result_passes_final_check(result, lineage=lineage, active_case_id=active_case_id)


__all__ = [
    "historical_result_backs_a_case_claim",
    "result_passes_final_check",
    "wire_passes_final_check",
]
