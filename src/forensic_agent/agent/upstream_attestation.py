"""What one finished call may claim about the component that produced it.

``provenance.tool`` names OUR wrapper.  It says nothing about the forensic
component underneath, and a reader who cannot tell dfVFS from The Sleuth Kit, or
which Volatility built a process list, can neither reproduce nor challenge a
finding.  :class:`~forensic_agent.core.result_contract.UpstreamBackend` is where
that is recorded, and this module is the one place a record is decided.

Three facts have to meet, and each comes from a different authority:

* **What the operation can reach.**  The shared operation registry
  (:mod:`forensic_agent.agent.tool_operations`) declares the backends of every
  operation, with a role: ``producer`` produced the bytes or the records, and
  ``support`` only made the read possible.  Several declared producers mean a
  runtime fallback set, never a merge.
* **What this host can state.**  The version registry
  (:mod:`forensic_agent.core.backend_versions`) resolves real versions from the
  running interpreter and from one controlled preflight.  A component it did not
  resolve cannot be named: the contract refuses a backend without a real version,
  and rightly, since such a record could not be reproduced.
* **Which path ran.**  A declaration is not an observation.  Where a fallback set
  has more than one candidate left, the executed component has to be read off the
  result the tool produced (``engine``, ``parser_backend`` — the fields the tools
  already write for exactly this purpose), never taken from the table.

The refusals are the point.  A component this host did not install cannot have
produced anything, so it drops out.  When what remains is not a single component,
the run states no producer at all, and the result is emitted as DIAGNOSTIC:
recorded, readable, quotable, and never an evidential basis.  Nothing here
invents a producer, downgrades an operation's declared class silently, or lets a
table stand in for the path that actually executed.

Nothing here is specific to a question, a case or an artifact type: every input
is the call itself, the registries, and the tool's own statement about itself.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from forensic_agent.agent.evidence_classification import (
    Classification,
    ToolClassificationError,
    build_derivation_metadata,
    classify_tool_result,
)
from forensic_agent.agent.tool_operations import (
    DOMAIN_FUNCTIONS,
    LEGACY_FUNCTION_DISPOSITIONS,
    OperationDefinition,
    resolved_operation,
)
from forensic_agent.core.backend_versions import (
    BackendStatus,
    BackendVersionError,
    BackendVersionRegistry,
)
from forensic_agent.core.result_contract import (
    DerivationMetadata,
    EvidenceClass,
    ResultInput,
    SourceInput,
    UpstreamBackend,
)

#: Result keys through which a tool states which component actually ran.  Both
#: are written by tools that reach more than one component and fall back between
#: them, and both carry the ids the version registry inventories.  A key is read
#: only to CHOOSE among the components the operation already declares, so a value
#: naming anything else selects nothing rather than introducing a new backend.
EXECUTED_BACKEND_KEYS: tuple[str, ...] = ("engine", "parser_backend")

#: Why a call could not be published under the class its operation declares.
#: Short codes, because they end up in run records that are diffed across hosts.
PRODUCER_NOT_ESTABLISHED = "producer_not_established"
PRODUCER_AMBIGUOUS = "producer_ambiguous"
NO_ATTESTED_DERIVATION_INPUT = "no_attested_derivation_input"
UNCLASSIFIED_CALL = "unclassified_call"


@dataclass(frozen=True, slots=True)
class CallAttestation:
    """Everything the contract needs about one call's epistemic standing.

    ``evidence_class`` is the operation's declared class when the run could
    establish what that class requires, and ``DIAGNOSTIC`` when it could not.
    ``unattested_reason`` is set exactly in the second case and states what was
    missing, so a refusal reaches a reader as a fact rather than as an absence.
    """

    evidence_class: EvidenceClass
    derivation: DerivationMetadata | None
    upstream_backends: tuple[UpstreamBackend, ...]
    unattested_reason: str | None = None

    @property
    def attested(self) -> bool:
        return self.unattested_reason is None


def _declared_operations(tool_name: str, arguments: Mapping[str, Any]) -> tuple[
    str, tuple[OperationDefinition, ...]
]:
    """The registered operations one call could have executed, and their label.

    A consolidated domain function resolves to the ONE operation the registry
    says the call selected.  A pre-consolidation name resolves through the
    consolidation's own disposition table to the operations it became, which may
    be several: the historical call shape carries no operation selector, so which
    of them ran is not established.  That is enough for the backends — the
    dispositions that map to several operations map to one producing component —
    and where it is not, the ambiguity is refused below rather than resolved by
    picking one.
    """

    function = DOMAIN_FUNCTIONS.get(tool_name)
    if function is not None:
        operation = resolved_operation(tool_name, arguments)
        if operation is None:
            legacy_selector = arguments.get("query")
            if isinstance(legacy_selector, str):
                candidate = legacy_selector.strip().casefold()
                if candidate in function.operation_names():
                    operation = candidate
        if operation is not None:
            return operation, (function.operation(operation),)
        return tool_name, function.operations
    disposition = LEGACY_FUNCTION_DISPOSITIONS.get(tool_name)
    if disposition is None or disposition.domain_function is None:
        return tool_name, ()
    target = DOMAIN_FUNCTIONS.get(disposition.domain_function)
    if target is None:  # pragma: no cover - the registry verifies its own table
        return tool_name, ()
    operations = tuple(target.operation(name) for name in disposition.operations)
    label = operations[0].name if len(operations) == 1 else tool_name
    return label, operations


def _declared_backends(
    operations: Sequence[OperationDefinition],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Distinct declared producer and support names over the candidate operations."""

    def names(role: str) -> tuple[str, ...]:
        seen: dict[str, None] = {}
        for operation in operations:
            for backend in operation.backends:
                if backend.role == role:
                    seen.setdefault(backend.name, None)
        return tuple(seen)

    return names("producer"), names("support")


def _resolved(registry: BackendVersionRegistry | None, backend: str) -> bool:
    """Whether this host established a real version for ``backend``."""

    if registry is None:
        return False
    try:
        entry = registry.entry(backend)
    except BackendVersionError:
        return False
    return entry.status is BackendStatus.RESOLVED


def _stated_executed_backend(raw_result: Any, candidates: Collection[str]) -> str | None:
    """The component the tool itself says ran, when it names one of ``candidates``."""

    if not isinstance(raw_result, Mapping):
        return None
    for key in EXECUTED_BACKEND_KEYS:
        value = raw_result.get(key)
        if isinstance(value, str) and value in candidates:
            return value
    return None


def _producing_backend(
    *,
    declared: Sequence[str],
    raw_result: Any,
    registry: BackendVersionRegistry | None,
) -> tuple[str | None, str | None]:
    """Which declared producer this run may name, and why it may name none.

    Order matters.  The host inventory is applied first because a component that
    is not installed cannot have produced anything and could not be attested even
    if it had; what survives is the set of components this run could honestly
    name.  Only then is the tool's own statement consulted, and only to CHOOSE
    among that set.  A single survivor needs no statement: the operation declares
    no other path it could have taken.
    """

    resolvable = tuple(name for name in declared if _resolved(registry, name))
    if not resolvable:
        return None, PRODUCER_NOT_ESTABLISHED
    stated = _stated_executed_backend(raw_result, resolvable)
    if stated is not None:
        return stated, None
    if len(resolvable) == 1:
        return resolvable[0], None
    # Several installed components could have produced this, and the tool did not
    # say which one did.  Naming either would be a guess recorded as a fact.
    return None, PRODUCER_AMBIGUOUS


def _upstream_records(
    *,
    operation_label: str,
    producer: str | None,
    support: Sequence[str],
    registry: BackendVersionRegistry | None,
) -> tuple[UpstreamBackend, ...]:
    """Turn the established components into the records a result carries.

    Support components are recorded only when the declaration leaves no choice
    about them: a support fallback set has no reader that could say which member
    presented the container, so taking one from the table would attest a
    component that may never have run.
    """

    records: list[UpstreamBackend] = []
    if producer is not None and registry is not None:
        records.append(
            registry.upstream_backend(producer, operation=operation_label, role="producer")
        )
    if len(support) == 1 and registry is not None and _resolved(registry, support[0]):
        records.append(
            registry.upstream_backend(support[0], operation=operation_label, role="support")
        )
    return tuple(records)


def _source_input(
    *,
    case_id: str,
    source_id: str,
    source_sha256: str | None,
    source_uri: str | None,
    artifact_locator: str | None,
) -> SourceInput | None:
    """The citation for the evidence a computation ran over, or ``None``.

    A source the run never digested cannot be cited: the contract's citation is
    resolved against the case's evidence registry by digest, so a citation
    without one names something no registry could ever confirm.  Returning
    ``None`` here is what makes such a computation DIAGNOSTIC instead of a
    derivation whose chain points at nothing.
    """

    digest = (source_sha256 or "").casefold()
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        return None
    return SourceInput(
        case_id=case_id,
        source_id=source_id,
        sha256=digest,
        uri=source_uri,
        artifact_locator=artifact_locator,
    )


def attest_call(
    *,
    tool_name: str,
    arguments: Mapping[str, Any],
    raw_result: Any,
    case_id: str,
    source_id: str,
    source_sha256: str | None = None,
    source_uri: str | None = None,
    artifact_locator: str | None = None,
    implementation: str | None = None,
    private_paths: Collection[str] = (),
    result_inputs: Sequence[ResultInput] = (),
    backend_versions: BackendVersionRegistry | None = None,
) -> CallAttestation:
    """Decide the class, the lineage and the backends of one finished call.

    ``tool_name`` is the MODEL-VISIBLE function the call was made against, which
    is the identity both registries are keyed by: the classifier resolves a
    consolidated function per call from its ``operation`` argument, and the
    disposition table carries a pre-consolidation name to the operations it
    became.  Passing the shape-keyed semantic name instead would classify a
    consolidated call through the historical flat table and record a derivation
    method the operation registry does not declare.

    The declared class is published only when what it requires was established:
    an OBSERVED result needs exactly one producing component with a real version,
    a DERIVED result needs at least one backend and at least one citable input.
    Otherwise the call is published as DIAGNOSTIC with the reason recorded.  A
    REFERENCE call names nothing and needs nothing: it reads no evidence.
    """

    try:
        classification: Classification = classify_tool_result(tool_name, arguments)
    except ToolClassificationError:
        # An unregistered tool has no declared class, and inventing one is how an
        # unclassified result would silently become an observation.
        return CallAttestation(
            evidence_class=EvidenceClass.DIAGNOSTIC,
            derivation=None,
            upstream_backends=(),
            unattested_reason=UNCLASSIFIED_CALL,
        )
    if classification.evidence_class is EvidenceClass.REFERENCE:
        return CallAttestation(
            evidence_class=EvidenceClass.REFERENCE, derivation=None, upstream_backends=()
        )

    operation_label, operations = _declared_operations(tool_name, arguments)
    declared_producers, declared_support = _declared_backends(operations)
    producer, refusal = _producing_backend(
        declared=declared_producers, raw_result=raw_result, registry=backend_versions
    )
    backends = _upstream_records(
        operation_label=operation_label,
        producer=producer,
        support=declared_support,
        registry=backend_versions,
    )

    if classification.evidence_class is EvidenceClass.OBSERVED:
        if producer is None:
            return CallAttestation(
                evidence_class=EvidenceClass.DIAGNOSTIC,
                derivation=None,
                upstream_backends=backends,
                unattested_reason=refusal or PRODUCER_NOT_ESTABLISHED,
            )
        return CallAttestation(
            evidence_class=EvidenceClass.OBSERVED, derivation=None, upstream_backends=backends
        )

    source_input = _source_input(
        case_id=case_id,
        source_id=source_id,
        source_sha256=source_sha256,
        source_uri=source_uri,
        artifact_locator=artifact_locator,
    )
    derivation: DerivationMetadata | None = None
    if source_input is not None or result_inputs:
        derivation = build_derivation_metadata(
            classification,
            arguments=arguments,
            implementation=implementation,
            source_input=source_input,
            result_inputs=result_inputs,
            private_paths=private_paths,
        )
    if derivation is None or not backends:
        return CallAttestation(
            evidence_class=EvidenceClass.DIAGNOSTIC,
            derivation=None,
            upstream_backends=backends,
            unattested_reason=(
                NO_ATTESTED_DERIVATION_INPUT
                if derivation is None
                else (refusal or PRODUCER_NOT_ESTABLISHED)
            ),
        )
    return CallAttestation(
        evidence_class=EvidenceClass.DERIVED,
        derivation=derivation,
        upstream_backends=backends,
    )


__all__ = [
    "EXECUTED_BACKEND_KEYS",
    "NO_ATTESTED_DERIVATION_INPUT",
    "PRODUCER_AMBIGUOUS",
    "PRODUCER_NOT_ESTABLISHED",
    "UNCLASSIFIED_CALL",
    "CallAttestation",
    "attest_call",
]
