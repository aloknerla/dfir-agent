"""The classified, lineage-bearing tool-result contract.

This is the active result contract. Its serialized envelope stays versioned as
``forensic.tool-result.v2`` so a reader can tell one record format from another,
but that version belongs to the wire format alone: the names in this module are
the plain names production code imports. It adds, on top of the legacy envelope, an
explicit epistemic class (OBSERVED / DERIVED / REFERENCE) and a typed derivation
lineage.  Production emits it across the readers, the recovery, reporting,
verifier and final-check paths, the standardizer and the oversight record.  Every
reader accepts both envelopes, so a historical record stays readable and no
result is ever silently discarded.  The legacy contract in :mod:`forensic_agent.core.tool_result` is
retained **read-only** for legacy parsing and is imported here unchanged; this
module never modifies it, so legacy wire and frozen receipts stay byte-identical.

Provenance boundary (why so strict): a tool must never be able to supply its own
classification, source identity or receipt.  Only the runtime standardizer builds
provenance.  ``adapt_legacy_result`` therefore accepts only unstructured raw
values and rejects any structured or self-classified envelope, and the models are
immutable.  The receipt is an integrity digest, **not** a signature: an actor who
can recompute it (drop the receipt, edit the payload, re-attach) obtains a
self-consistent result, so the receipt alone can never prove authenticity.
Integrity instead comes from binding the standardized result to the trusted,
append-only oversight record; the final check enforces that binding over the
actual payload digest, so a mutated-and-re-signed result no longer matches its
recorded entry and is rejected.
"""

from __future__ import annotations

import hmac
from collections.abc import Mapping, Sequence
from enum import StrEnum
from typing import Annotated, Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from forensic_agent.core.repro import canonical_json, sha256_hex
from forensic_agent.core.tool_result import (
    SCHEMA_ID as LEGACY_SCHEMA_ID,
)

# The historical contract is imported under explicit Legacy names. It is frozen
# and stays readable for records written before this contract existed, but it
# must never be mistaken for the active one, so every colliding name is aliased
# at the import rather than shadowed somewhere further down. The value objects
# that carry no version semantics (status, metadata, paging) are shared as they
# are, because a second identical definition would be the real hazard.
from forensic_agent.core.tool_result import (
    ArtifactMetadata,
    CoverageMetadata,
    PageMetadata,
    PageUnit,
    ProvenanceType,
    SourceMetadata,
    ToolData,
    ToolError,
    ToolMetadata,
    ToolStatus,
    ToolWarning,
)
from forensic_agent.core.tool_result import (
    ToolProvenance as LegacyToolProvenance,
)
from forensic_agent.core.tool_result import (
    ToolResult as LegacyToolResult,
)
from forensic_agent.core.tool_result import (
    adapt_legacy_result as legacy_adapt_result,
)
from forensic_agent.core.tool_result import (
    error_result as legacy_error_result,
)
from forensic_agent.core.tool_result import (
    ok_result as legacy_ok_result,
)
from forensic_agent.core.tool_result import (
    partial_result as legacy_partial_result,
)

SCHEMA_ID = "forensic.tool-result.v2"
RECEIPT_SCHEMA_ID = "forensic.tool-result-receipt.v2"


class ToolContractError(RuntimeError):
    """A tool tried to supply structured/self-classified output to the contract."""


class _ContractModel(BaseModel):
    """Strict, immutable base for every wire object of this contract.

    ``frozen=True`` blocks attribute mutation after construction; combined with
    revalidation before receipt attachment, a result cannot be signed in an
    invalid state.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)


class EvidenceClass(StrEnum):
    """Explicit epistemic class of a factual claim.

    * ``OBSERVED`` — a finding directly reported by a documented, versioned
      upstream forensic tool from bound case evidence, with no agent-owned
      semantic transformation.  Filtering by the upstream tool may remain
      observed; filtering, decoding or correlation by our code is derived.
    * ``DERIVED`` — a deterministic, agent-owned computation over one or more
      typed inputs, carrying the full derivation lineage.
    * ``REFERENCE`` — procedural knowledge, never case evidence.
    * ``DIAGNOSTIC`` — a real reading whose epistemic standing the run could not
      establish: no component was established as its producer, or a computation
      could cite no attested input.  It is recorded, readable and quotable, and
      it is never an evidential basis.  It exists because the alternative to
      publishing the honest gap is publishing an invented producer or an
      invented lineage, which is exactly what this contract prevents; an
      OBSERVED result must name its one producer and a DERIVED result must carry
      its chain, so neither can be constructed for such a call.

    There is no default: a case result whose class is unset is a contract error
    and is inadmissible, never silently OBSERVED.
    """

    OBSERVED = "observed"
    DERIVED = "derived"
    REFERENCE = "reference"
    DIAGNOSTIC = "diagnostic"

    @property
    def provenance_type(self) -> ProvenanceType:
        """The coarse evidentiary role the envelope carries beside this class.

        ``ProvenanceType`` answers only "is this material about the case or is it
        procedural knowledge".  DIAGNOSTIC material IS about the case — it is a
        reading of the case's own evidence — so it keeps ``CASE_EVIDENCE`` and is
        refused by the admissibility rules below, which is where the verdict
        belongs.  Calling it reference knowledge would state that a disk read is
        procedural documentation, which is false.
        """

        return (
            ProvenanceType.REFERENCE_KNOWLEDGE
            if self is EvidenceClass.REFERENCE
            else ProvenanceType.CASE_EVIDENCE
        )


class SourceInput(_ContractModel):
    """A runtime-attested evidence source a derivation was computed over.

    Owned by the runtime, never the model: it must resolve against the active
    case's evidence registry (matching ``case_id``, ``source_id`` and
    ``sha256``) and must have been established during ingestion before the
    derived operation.  ``case_id`` is mandatory so an input can never be
    unbound from a case.  Validated by the lineage resolver at the final check.
    """

    kind: Literal["source"] = "source"
    case_id: str = Field(min_length=1)
    source_id: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    uri: str | None = None
    artifact_locator: str | None = None


class ResultInput(_ContractModel):
    """A prior receipt-verified result a derivation consumed.

    ``case_id`` and ``invocation_id`` are mandatory: the parent must be an
    unambiguously identified earlier call in the same case, so the lineage
    resolver can tie it to the trusted audit record and reject a foreign,
    future, cyclic or unidentifiable parent.
    """

    kind: Literal["result"] = "result"
    case_id: str = Field(min_length=1)
    payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    invocation_id: str = Field(min_length=1)


DerivationInput = Annotated[SourceInput | ResultInput, Field(discriminator="kind")]


class DerivationMetadata(_ContractModel):
    """Full provenance chain of a DERIVED claim.

    Nonempty ``derivation_inputs`` is a construction invariant: a DERIVED result
    always cites at least one typed input (a ``SourceInput`` for a computation
    over attested evidence, a ``ResultInput`` for a computation over an earlier
    receipt-verified result, or both).  ``method``/``method_version``/
    ``implementation`` and ``parameters`` identify the operation and its
    effective (already redaction-safe, canonicalized) arguments.
    """

    method: str = Field(min_length=1)
    method_version: str = Field(min_length=1)
    implementation: str | None = None
    derivation_inputs: list[DerivationInput] = Field(min_length=1)
    parameters: dict[str, JsonValue] = Field(default_factory=dict)
    assumptions: list[str] = Field(default_factory=list)


class UpstreamBackend(_ContractModel):
    """One documented component that actually did the work for this result.

    ``provenance.tool`` identifies OUR model-visible wrapper; this identifies the
    forensic component underneath it, so a reader can tell that a listing came
    from dfVFS rather than from The Sleuth Kit even though one wrapper can reach
    either.  It is recorded from the path that actually executed, never from a
    static table: a fallback can reach a different component than the table
    predicts, and a table-derived record would then be a false attestation.

    ``role`` separates the component that produced the bytes (``producer``) from
    one that only made the read possible (``support``), for example pyewf
    presenting an E01 container to the parser that then read the filesystem.
    """

    name: str = Field(min_length=1)
    version: str = Field(min_length=1)
    operation: str = Field(min_length=1)
    role: Literal["producer", "support"]

    @model_validator(mode="after")
    def _version_is_evidentially_usable(self) -> UpstreamBackend:
        # A result whose backend version is a placeholder cannot be reproduced or
        # audited, so it is refused at construction rather than shipped and
        # explained away later.
        if self.version.strip().casefold() in _UNUSABLE_VERSIONS:
            raise ValueError(
                f"backend {self.name!r} reported an unusable version {self.version!r}; "
                "an evidentially usable result requires a real version"
            )
        return self


_UNUSABLE_VERSIONS = frozenset({"unknown", "unspecified", "n/a", "na", "none", "null", "-", "?"})


class ToolProvenance(_ContractModel):
    """Provenance: legacy fields plus a mandatory epistemic class and lineage.

    ``candidate_case_evidence`` marks a result that *may* be case evidence (its
    provenance type is case_evidence).  It is deliberately **not** named
    "admissible": admissibility is decided only by the final check, which also
    requires a non-error status, a case binding, a trusted audit binding and
    validated lineage.  ``case_id`` is mandatory so a result is never unbound
    from a case.
    """

    type: ProvenanceType
    candidate_case_evidence: bool
    evidence_class: EvidenceClass
    derivation: DerivationMetadata | None = None
    invocation_id: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    raw_output_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    oversight_entry_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    oversight_sequence: int | None = Field(default=None, ge=0)
    source: SourceMetadata
    artifact: ArtifactMetadata
    tool: ToolMetadata
    upstream_backends: list[UpstreamBackend] = Field(default_factory=list)

    @model_validator(mode="after")
    def _upstream_backends_are_declared(self) -> ToolProvenance:
        producers = [backend for backend in self.upstream_backends if backend.role == "producer"]
        if self.evidence_class is EvidenceClass.OBSERVED:
            # Exactly one producer, not merely at least one. Two producers under a
            # single OBSERVED result is the unlabelled merge this contract exists
            # to prevent: the reader could not tell which component reported which
            # row. Heterogeneous work stays in separate results, or its
            # combination is DERIVED, which is what makes several producers legal
            # below.
            if len(producers) != 1:
                raise ValueError(
                    "an OBSERVED result must name exactly one producing backend, "
                    f"found {len(producers)}; combining several is DERIVED"
                )
        elif self.evidence_class is EvidenceClass.DERIVED and not self.upstream_backends:
            raise ValueError("a DERIVED result must name the backends it computed over")
        seen: set[tuple[str, str, str]] = set()
        for backend in self.upstream_backends:
            key = (backend.name, backend.operation, backend.role)
            if key in seen:
                raise ValueError(f"backend {backend.name!r} is declared twice for {backend.operation!r}")
            seen.add(key)
        return self

    @model_validator(mode="after")
    def _evidentiary_role_is_consistent(self) -> ToolProvenance:
        expected = self.type is ProvenanceType.CASE_EVIDENCE
        if self.candidate_case_evidence is not expected:
            raise ValueError(
                "candidate_case_evidence must be true only for case_evidence provenance"
            )
        if self.evidence_class.provenance_type is not self.type:
            raise ValueError("evidence_class and provenance type disagree on admissibility")
        if (self.evidence_class is EvidenceClass.DERIVED) != (self.derivation is not None):
            raise ValueError("a DERIVED result requires a derivation chain and vice versa")
        oversight_binding = (
            self.raw_output_sha256,
            self.oversight_entry_sha256,
            self.oversight_sequence,
        )
        if any(value is not None for value in oversight_binding) and not all(
            value is not None for value in oversight_binding
        ):
            raise ValueError(
                "raw output digest, oversight entry digest and sequence must be supplied together"
            )
        return self


class ToolResultReceipt(_ContractModel):
    schema_version: Literal["forensic.tool-result-receipt.v2"] = "forensic.tool-result-receipt.v2"
    algorithm: Literal["sha256"] = "sha256"
    payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class AuditBindingRecord(_ContractModel):
    """The content a trusted oversight entry must bind a standardized result to.

    Written to the append-only oversight chain *after* standardization, so it can
    reference the finished ``payload_sha256`` without the payload having to embed
    the entry — which would be circular, since the payload already carries the
    oversight pointers.  A lineage resolver confirms the trusted chain holds
    exactly this record for the result's invocation.  Binding ``payload_sha256``
    (the digest of the whole standardized result), not merely the provenance's
    oversight pointers, is what defeats a mutate-payload-then-re-sign attack: the
    changed payload yields a digest the recorded entry does not contain.
    """

    invocation_id: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    raw_output_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    previous_oversight_entry_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class ToolResult(_ContractModel):
    """The ``forensic.tool-result.v2`` structured result envelope."""

    schema_version: Literal["forensic.tool-result.v2"] = "forensic.tool-result.v2"
    status: ToolStatus
    data: ToolData
    page: PageMetadata = Field(default_factory=PageMetadata)
    coverage: CoverageMetadata = Field(default_factory=CoverageMetadata)
    warnings: list[ToolWarning] = Field(default_factory=list)
    error: ToolError | None = None
    provenance: ToolProvenance
    receipt: ToolResultReceipt | None = None

    @model_validator(mode="after")
    def _status_invariants(self) -> ToolResult:
        if self.page.unit is PageUnit.ITEM and self.page.returned != len(self.data.items):
            raise ValueError("page.returned must equal the number of data.items")
        if self.status is ToolStatus.OK:
            if not self.coverage.complete:
                raise ValueError("ok status requires complete coverage")
            if self.error is not None:
                raise ValueError("ok status cannot carry an error")
        elif self.status is ToolStatus.PARTIAL:
            if self.coverage.complete:
                raise ValueError("partial status requires incomplete coverage")
            if self.error is not None:
                raise ValueError("partial failures belong in warnings, not error")
        else:
            if self.coverage.complete:
                raise ValueError("error status requires incomplete coverage")
            if self.error is None:
                raise ValueError("error status requires a structured error")
        return self


def make_provenance(
    *,
    evidence_class: EvidenceClass | str,
    provenance_type: ProvenanceType | str,
    invocation_id: str,
    case_id: str,
    source_id: str,
    artifact_locator: str,
    tool_name: str,
    tool_version: str,
    derivation: DerivationMetadata | None = None,
    source_sha256: str | None = None,
    source_uri: str | None = None,
    source_media_type: str | None = None,
    source_attributes: Mapping[str, Any] | None = None,
    acquisition_id: str | None = None,
    artifact_type: str | None = None,
    artifact_offset: int | None = None,
    artifact_sha256: str | None = None,
    tool_implementation: str | None = None,
    upstream_backends: Sequence[UpstreamBackend] | None = None,
    raw_output_sha256: str | None = None,
    oversight_entry_sha256: str | None = None,
    oversight_sequence: int | None = None,
) -> ToolProvenance:
    """Build validated provenance with a mandatory epistemic class.

    The model-visible ``provenance.tool.parameters_sha256`` is **not** taken from
    any caller-supplied argument mapping — trusting such a mapping to be "safe"
    would let raw arguments (a ``key`` or ``password``) slip back into a public
    digest that then becomes an oracle for guessing the secret.  Instead it is
    derived here, and only for a DERIVED result, solely from the already
    redaction-safe ``derivation.parameters`` (the non-sensitive projection the
    classifier built and the contract carries in the payload).  OBSERVED and
    REFERENCE results leave it ``None``, having no such projection to digest: an
    OBSERVED payload is upstream output carried verbatim, so its identity is the
    raw output digest rather than ours.  The digest of the *complete* raw
    argument set is never placed here; it belongs solely in the private,
    non-model-visible oversight record.
    """

    parameters_sha256 = None
    if derivation is not None:
        parameters_sha256 = sha256_hex(canonical_json(dict(derivation.parameters)))
    return ToolProvenance(
        type=ProvenanceType(provenance_type),
        candidate_case_evidence=(
            ProvenanceType(provenance_type) is ProvenanceType.CASE_EVIDENCE
        ),
        evidence_class=EvidenceClass(evidence_class),
        derivation=derivation,
        invocation_id=invocation_id,
        case_id=case_id,
        raw_output_sha256=raw_output_sha256,
        oversight_entry_sha256=oversight_entry_sha256,
        oversight_sequence=oversight_sequence,
        source=SourceMetadata(
            id=source_id,
            sha256=source_sha256,
            uri=source_uri,
            media_type=source_media_type,
            acquisition_id=acquisition_id,
            attributes=dict(source_attributes or {}),
        ),
        artifact=ArtifactMetadata(
            locator=artifact_locator,
            type=artifact_type,
            offset=artifact_offset,
            sha256=artifact_sha256,
        ),
        tool=ToolMetadata(
            name=tool_name,
            version=tool_version,
            implementation=tool_implementation,
            parameters_sha256=parameters_sha256,
        ),
        upstream_backends=list(upstream_backends or ()),
    )


def _legacy_provenance_from(provenance: ToolProvenance) -> LegacyToolProvenance:
    """Project provenance to its legacy shape, to reuse legacy normalization logic."""

    return LegacyToolProvenance(
        type=provenance.type,
        admissible_as_case_evidence=provenance.candidate_case_evidence,
        invocation_id=provenance.invocation_id,
        case_id=provenance.case_id,
        raw_output_sha256=provenance.raw_output_sha256,
        oversight_entry_sha256=provenance.oversight_entry_sha256,
        oversight_sequence=provenance.oversight_sequence,
        source=provenance.source,
        artifact=provenance.artifact,
        tool=provenance.tool,
    )


def _from_legacy(result: LegacyToolResult, provenance: ToolProvenance) -> ToolResult:
    return ToolResult(
        status=result.status,
        data=result.data,
        page=result.page,
        coverage=result.coverage,
        warnings=result.warnings,
        error=result.error,
        provenance=provenance,
    )


def ok_result(
    *,
    data_type: str,
    provenance: ToolProvenance,
    attributes: Mapping[str, Any] | None = None,
    items: list[Any] | None = None,
    page: PageMetadata | None = None,
    warnings: list[ToolWarning] | None = None,
) -> ToolResult:
    legacy = legacy_ok_result(
        data_type=data_type,
        provenance=_legacy_provenance_from(provenance),
        attributes=attributes,
        items=items,
        page=page,
        warnings=warnings,
    )
    return _from_legacy(legacy, provenance)


def partial_result(
    *,
    data_type: str,
    provenance: ToolProvenance,
    coverage_reason: str,
    attributes: Mapping[str, Any] | None = None,
    items: list[Any] | None = None,
    page: PageMetadata | None = None,
    warnings: list[ToolWarning] | None = None,
    coverage_scope: str | None = None,
) -> ToolResult:
    legacy = legacy_partial_result(
        data_type=data_type,
        provenance=_legacy_provenance_from(provenance),
        coverage_reason=coverage_reason,
        attributes=attributes,
        items=items,
        page=page,
        warnings=warnings,
        coverage_scope=coverage_scope,
    )
    return _from_legacy(legacy, provenance)


def error_result(
    *,
    data_type: str,
    provenance: ToolProvenance,
    error: ToolError,
    coverage_reason: str,
    attributes: Mapping[str, Any] | None = None,
    warnings: list[ToolWarning] | None = None,
) -> ToolResult:
    legacy = legacy_error_result(
        data_type=data_type,
        provenance=_legacy_provenance_from(provenance),
        error=error,
        coverage_reason=coverage_reason,
        attributes=attributes,
        warnings=warnings,
    )
    return _from_legacy(legacy, provenance)


def adapt_legacy_result(
    result: Any,
    *,
    data_type: str,
    provenance: ToolProvenance,
) -> ToolResult:
    """Adapt an UNSTRUCTURED legacy raw value into this contract.

    A tool may only return raw data (dict/list/scalar).  A structured or
    self-classified envelope is rejected: a tool must never supply its own
    classification, source identity or receipt — only the runtime standardizer
    creates provenance.
    """

    # Both contracts are refused, by type and by self-declared schema. The legacy
    # envelope has to be named explicitly here: it is a different constant and a
    # different class from the active one, and collapsing the two would let a tool
    # hand back a legacy-marked envelope that this guard silently accepted.
    if isinstance(result, (ToolResult, LegacyToolResult)):
        raise ToolContractError(
            "a tool may not supply a structured tool-result envelope"
        )
    if isinstance(result, Mapping) and result.get("schema_version") in (
        SCHEMA_ID,
        LEGACY_SCHEMA_ID,
    ):
        raise ToolContractError(
            "a tool may not supply its own tool-result envelope or classification"
        )
    legacy = legacy_adapt_result(
        result,
        data_type=data_type,
        provenance=_legacy_provenance_from(provenance),
    )
    return _from_legacy(legacy, provenance)


def canonical_payload(result: ToolResult) -> str:
    payload = result.model_dump(mode="json", exclude={"receipt"})
    return canonical_json(payload)


def payload_sha256(result: ToolResult) -> str:
    return sha256_hex(canonical_payload(result))


def audit_binding_record(
    result: ToolResult, *, previous_oversight_entry_sha256: str | None = None
) -> AuditBindingRecord:
    """Build the canonical audit-binding record for a standardized result.

    Consumes the finished payload (via :func:`payload_sha256`) and the
    provenance's raw-output digest, so it is created after standardization and
    written to the trusted oversight chain.  A result with no ``raw_output_sha256``
    cannot be bound to that chain and is rejected here rather than recorded
    unbound.  The full-argument attestation, when needed, is a separate field of
    the private oversight record — never the model-visible result.
    """

    provenance = result.provenance
    if provenance.raw_output_sha256 is None:
        raise ToolContractError(
            "cannot build an audit binding for a result with no raw_output_sha256"
        )
    return AuditBindingRecord(
        invocation_id=provenance.invocation_id,
        case_id=provenance.case_id,
        raw_output_sha256=provenance.raw_output_sha256,
        payload_sha256=payload_sha256(result),
        previous_oversight_entry_sha256=previous_oversight_entry_sha256,
    )


def revalidate(result: ToolResult) -> ToolResult:
    """Rebuild a result from its complete canonical wire, re-running validators.

    ``model_copy`` bypasses validators, so any code that produced a result via
    copy-with-update must pass through here before its receipt is trusted.  A
    result that cannot be rebuilt (an invariant was bypassed) raises.
    """

    return ToolResult.model_validate(result.model_dump(mode="json"))


def make_receipt(result: ToolResult) -> ToolResultReceipt:
    return ToolResultReceipt(payload_sha256=payload_sha256(result))


def attach_receipt(result: ToolResult) -> ToolResult:
    """Attach the integrity digest, over the revalidated complete wire.

    This is an **internal runtime operation**, not a signature.  The receipt is a
    SHA-256 of the canonical payload: it detects a change only when compared
    against a copy that has not itself been recomputed, so it cannot by itself
    prove authenticity against an actor who can recompute it (removing the
    receipt, editing the payload and re-attaching a receipt yields a
    self-consistent result).  Integrity against such an actor comes from the
    trusted, append-only oversight/audit record, which the final check binds the
    result to.  Attaching is done once here by the runtime; revalidating the
    JSON round-trip first deep-copies every nested container and re-runs all
    invariants so the receipt never covers an invalid or caller-shared instance.
    """

    revalidated = revalidate(result.model_copy(update={"receipt": None}))
    return revalidated.model_copy(update={"receipt": make_receipt(revalidated)})


def verify_receipt(result: ToolResult) -> bool:
    """Return whether the receipt matches the payload; never raise.

    Checks the receipt's ``schema_version`` and ``algorithm`` before the
    constant-time digest comparison, recomputes the payload from the revalidated
    wire (receipt excluded), and returns ``False`` on any malformed input rather
    than propagating an exception.  This detects a change only against a
    non-recomputed copy; it is not proof of authenticity (see the final check's
    audit binding).
    """

    try:
        receipt = result.receipt
        if receipt is None:
            return False
        if receipt.schema_version != RECEIPT_SCHEMA_ID or receipt.algorithm != "sha256":
            return False
        canonical = revalidate(result.model_copy(update={"receipt": None}))
        return hmac.compare_digest(receipt.payload_sha256, payload_sha256(canonical))
    except Exception:
        return False


@runtime_checkable
class DerivationLineageResolver(Protocol):
    """Runtime authority that binds a result to the trusted case + audit record.

    Implementations are built from the active case's evidence registry and its
    append-only oversight/audit chain.  Every method must be total: it returns a
    boolean and never raises; the final check treats an exception as ``False``.
    """

    def validate_audit_binding(self, result: ToolResult) -> bool:
        """True iff the *content* of ``result`` is bound to a trusted audit entry.

        Must confirm the trusted append-only oversight chain holds an entry for
        this invocation whose recorded payload digest equals this result's
        :func:`payload_sha256` and whose raw-output digest, case and invocation
        match the provenance (see :func:`audit_binding_record`).  Binding the
        payload digest — not merely the provenance's oversight pointers — is what
        anchors the content to a record an actor cannot silently recompute:
        keeping the pointers, mutating the payload and re-attaching a receipt
        yields a digest the recorded entry does not contain.  The result is passed
        whole (rather than only its provenance) precisely so the resolver can
        compare the actual payload digest.
        """

    def validate_source_input(self, source: SourceInput) -> bool:
        """True iff ``source`` resolves to an attested case source ingested first."""

    def validate_result_input(
        self, parent: ResultInput, *, current_invocation_id: str | None
    ) -> bool:
        """True iff ``parent`` is an earlier receipt-valid result from this case."""


def _safe_resolver_call(call) -> bool:
    """Invoke a resolver method, treating any exception as a False verdict."""

    try:
        return bool(call())
    except Exception:
        return False


def result_is_admissible(
    result: ToolResult,
    *,
    lineage: DerivationLineageResolver | None = None,
    active_case_id: str | None = None,
) -> bool:
    """Whether a result may back a case claim in the final verification.

    Fail-closed. The result is rebuilt from its canonical wire, then all of the
    following must hold: the receipt matches; the status is not ERROR (PARTIAL is
    allowed — usable data with disclosed incomplete coverage); the provenance is
    a case-evidence candidate and not REFERENCE; the result is bound to the
    active case (``provenance.case_id == active_case_id``); the oversight binding
    triple (raw-output digest, oversight entry digest, oversight sequence) is
    present; a resolver is supplied and confirms the trusted audit binding **over
    the actual result content** (so a mutated-and-re-signed payload no longer
    matches its recorded entry); and the evidence is grounded — an OBSERVED
    result's source resolves to an attested case source, a DERIVED result's every
    typed input resolves and matches the active case.  Every resolver call is
    exception-safe (an exception counts as False).
    """

    try:
        result = revalidate(result)
    except Exception:
        return False
    if not verify_receipt(result):
        return False
    if result.status is ToolStatus.ERROR:
        return False
    provenance = result.provenance
    if not provenance.candidate_case_evidence:
        return False
    evidence_class = provenance.evidence_class
    if evidence_class is EvidenceClass.REFERENCE:
        return False
    # A DIAGNOSTIC result is a reading whose producer or whose lineage the run
    # could not establish.  Nothing downstream can repair that, so it is refused
    # here rather than being handed to a resolver that would have to guess.
    if evidence_class is EvidenceClass.DIAGNOSTIC:
        return False
    if lineage is None:
        return False
    if active_case_id is None or provenance.case_id != active_case_id:
        return False
    # The result must be anchored to the trusted oversight chain: the binding
    # triple must be present, and the resolver must bind THIS result's content
    # (its payload digest), not merely the provenance's oversight pointers.
    if (
        provenance.raw_output_sha256 is None
        or provenance.oversight_entry_sha256 is None
        or provenance.oversight_sequence is None
    ):
        return False
    if not _safe_resolver_call(lambda: lineage.validate_audit_binding(result)):
        return False
    if evidence_class is EvidenceClass.OBSERVED:
        source = provenance.source
        if not source.sha256:
            return False
        source_input = SourceInput(
            case_id=provenance.case_id,
            source_id=source.id,
            sha256=source.sha256.casefold(),
            uri=source.uri,
            artifact_locator=provenance.artifact.locator,
        )
        return _safe_resolver_call(lambda: lineage.validate_source_input(source_input))
    derivation = provenance.derivation
    if derivation is None or not derivation.derivation_inputs:
        return False
    current_invocation_id = provenance.invocation_id
    for derivation_input in derivation.derivation_inputs:
        if derivation_input.case_id != active_case_id:
            return False
        if isinstance(derivation_input, SourceInput):
            if not _safe_resolver_call(lambda di=derivation_input: lineage.validate_source_input(di)):
                return False
        elif not _safe_resolver_call(
            lambda di=derivation_input: lineage.validate_result_input(
                di, current_invocation_id=current_invocation_id
            )
        ):
            return False
    return True


def is_admissible_case_evidence(value: Any) -> bool | None:
    """Broad contract gate; returns ``None`` for any foreign value (a legacy result never enters).

    Structural filter (the deep case/audit/lineage validation is the final
    check's job): for a value of this contract the receipt must verify, the status must not be
    ERROR, and the result must be a case-evidence candidate that is not
    REFERENCE — OBSERVED passes, DERIVED passes only with a derivation carrying
    at least one typed input.
    """

    parsed = value
    if isinstance(value, str):
        import json

        try:
            parsed = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return None
    if not isinstance(parsed, Mapping) or parsed.get("schema_version") != SCHEMA_ID:
        return None
    try:
        result = ToolResult.model_validate(parsed)
    except Exception:
        return False
    if not verify_receipt(result):
        return False
    if result.status is ToolStatus.ERROR:
        return False
    provenance = result.provenance
    if not provenance.candidate_case_evidence:
        return False
    if provenance.evidence_class in (EvidenceClass.REFERENCE, EvidenceClass.DIAGNOSTIC):
        return False
    if provenance.evidence_class is EvidenceClass.OBSERVED:
        return True
    derivation = provenance.derivation
    return derivation is not None and bool(derivation.derivation_inputs)


__all__ = [
    "SCHEMA_ID",
    "RECEIPT_SCHEMA_ID",
    # The value objects that carry no version semantics are re-exported under
    # their plain names so production can spell a status, a page unit or a
    # provenance type without importing the historical module directly. They are
    # the same objects, shared deliberately (see the import note above).
    "ArtifactMetadata",
    "CoverageMetadata",
    "PageMetadata",
    "PageUnit",
    "ProvenanceType",
    "SourceMetadata",
    "ToolData",
    "ToolError",
    "ToolMetadata",
    "ToolStatus",
    "ToolWarning",
    "ToolContractError",
    "EvidenceClass",
    "SourceInput",
    "ResultInput",
    "DerivationInput",
    "DerivationMetadata",
    "UpstreamBackend",
    "DerivationLineageResolver",
    "ToolProvenance",
    "ToolResultReceipt",
    "AuditBindingRecord",
    "ToolResult",
    "make_provenance",
    "audit_binding_record",
    "ok_result",
    "partial_result",
    "error_result",
    "adapt_legacy_result",
    "canonical_payload",
    "payload_sha256",
    "revalidate",
    "make_receipt",
    "attach_receipt",
    "verify_receipt",
    "result_is_admissible",
    "is_admissible_case_evidence",
]
