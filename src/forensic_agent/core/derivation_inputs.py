"""What a DERIVED tool operation states it was computed over.

A derived operation is only readable as a derivation if it names its inputs.  The
result contract already defines the shape a *confirmed* prior result is cited in
— :class:`~forensic_agent.core.result_contract.ResultInput`, which binds a case,
an invocation and the payload digest of that earlier result — so a caller holding
one is validated against that model rather than against a second definition of
the same thing.

A parser is also called directly, below the runtime standardizer, by the bounded
joins in :mod:`forensic_agent.tools.windows_artifacts`.  At that layer no
invocation id and no receipt exist yet, so there is nothing confirmed to cite.
Such an operation performs the observed read itself and cites exactly that read:
the tool, the observed operation and the parameters that identify it over an
immutable evidence source.  That is weaker than a receipt-bound citation and says
so through its own ``kind``; it is never presented as one.

Either way the derived result names what produced it, which is what keeps it from
being read as something a tool observed.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

#: ``kind`` of a citation of an earlier, receipt-verified result.
CONFIRMED_RESULT_INPUT = "result"
#: ``kind`` of a citation of the observed read the same call performed.
OBSERVED_OPERATION_INPUT = "observed_operation"


class DerivationInputError(ValueError):
    """A caller cited derivation inputs that are not a usable citation."""


def confirmed_result_inputs(cited: Any) -> list[dict[str, Any]]:
    """Validate caller-supplied citations of prior confirmed results.

    Every entry is parsed through the contract's own ``ResultInput``, so a
    citation missing its case, its invocation or its payload digest — or carrying
    a field the contract does not define — is refused here rather than travelling
    on as a derivation nobody can resolve.  ``None`` means "no confirmed citation
    was supplied", which is not an error; an empty sequence is treated the same
    way.
    """

    if cited is None:
        return []
    if isinstance(cited, Mapping) or isinstance(cited, (str, bytes)) or not isinstance(
        cited, Sequence
    ):
        raise DerivationInputError("cited derivation inputs must be a sequence of mappings")
    from forensic_agent.core.result_contract import ResultInput

    inputs: list[dict[str, Any]] = []
    for entry in cited:
        if not isinstance(entry, Mapping):
            raise DerivationInputError("each cited derivation input must be a mapping")
        try:
            parsed = ResultInput.model_validate(dict(entry))
        except Exception as error:
            raise DerivationInputError(
                "a cited derivation input does not match the result-input contract"
            ) from error
        inputs.append(parsed.model_dump(mode="json"))
    return inputs


def observed_operation_input(
    *,
    tool: str,
    operation: str,
    parameters: Mapping[str, Any],
    **details: Any,
) -> dict[str, Any]:
    """Cite the observed read this same call performed.

    ``parameters`` must identify that read completely against an immutable
    evidence source, because they are what makes it reproducible: this citation
    carries no receipt, and pretending otherwise would be the exact confusion
    this module exists to prevent.
    """

    return {
        "kind": OBSERVED_OPERATION_INPUT,
        "tool": tool,
        "operation": operation,
        "parameters": dict(parameters),
        **details,
    }


__all__ = [
    "CONFIRMED_RESULT_INPUT",
    "OBSERVED_OPERATION_INPUT",
    "DerivationInputError",
    "confirmed_result_inputs",
    "observed_operation_input",
]
