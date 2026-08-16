"""forensic.tool-result.v2 contract: classification, lineage, receipts, v1 isolation.

Covers the v2 guarantees plus the provenance-boundary attacks and the
upstream-backend declaration that keeps an unlabelled merge of two producing
components out of an OBSERVED result.
"""

from __future__ import annotations

import copy

import pytest
from pydantic import ValidationError

from forensic_agent.core import result_contract as T
from forensic_agent.core import tool_result as V1

# --- v1 helpers (legacy read-only format) -------------------------------------

def _v1_case_result():
    prov = V1.make_provenance(
        provenance_type=V1.ProvenanceType.CASE_EVIDENCE,
        invocation_id="run:0001",
        source_id="disk-1",
        artifact_locator="/x",
        tool_name="list_directory",
        tool_version="0.1",
    )
    return V1.attach_receipt(
        V1.ok_result(data_type="filesystem.directory_listing", provenance=prov)
    )


CASE = "case-1"


# --- upstream backends (the components that really did the work) --------------

# Real components, with the versions this repo's own environment reports
# (``dfvfs.__version__``, ``pytsk3.TSK_VERSION_STR``, ``pyewf.get_version()``).
# A fixture must not invent one: the contract refuses placeholder versions, so a
# made-up value would exercise the contract against evidence it would reject.
DFVFS_VERSION = "20260731"
TSK_VERSION = "4.15.0"
PYEWF_VERSION = "20240506"


def _dfvfs(operation="filesystem.list_directory", role="producer"):
    return T.UpstreamBackend(name="dfvfs", version=DFVFS_VERSION, operation=operation, role=role)


def _tsk(operation="filesystem.list_directory", role="producer"):
    return T.UpstreamBackend(
        name="sleuthkit", version=TSK_VERSION, operation=operation, role=role
    )


def _pyewf(operation="storage_media.ewf_read", role="support"):
    return T.UpstreamBackend(name="pyewf", version=PYEWF_VERSION, operation=operation, role=role)


# What each tested wrapper would really have run: ``list_directory`` reads the
# filesystem through dfVFS, which pyewf only makes readable (support, never the
# reporter of the rows); ``evidence_file_hash`` and ``decode`` are our
# computations over bytes dfVFS produced; ``artifact_reference_query`` is
# procedural knowledge with no forensic component under it at all.  Indexing is
# deliberately strict so a future test must state the backend its scenario really
# used instead of silently inheriting none.
_BACKENDS_BY_TOOL = {
    "list_directory": (_dfvfs("filesystem.list_directory"), _pyewf()),
    "evidence_file_hash": (_dfvfs("filesystem.read_file"),),
    "decode": (_dfvfs("filesystem.read_file"),),
    "artifact_reference_query": (),
}


def _v2_provenance(
    evidence_class="observed",
    *,
    derivation=None,
    tool="list_directory",
    inv="run:0002",
    bound=True,
    backends=None,
):
    # ``bound`` supplies the oversight binding triple (raw-output digest, entry
    # digest, sequence) the final check requires; bound=False builds a result that
    # carries no anchor to the trusted chain.  ``backends`` defaults to the
    # components ``tool`` genuinely uses and is overridden only where the backend
    # declaration is itself under test.
    return T.make_provenance(
        evidence_class=evidence_class,
        provenance_type=(
            T.ProvenanceType.REFERENCE_KNOWLEDGE
            if evidence_class == "reference"
            else T.ProvenanceType.CASE_EVIDENCE
        ),
        derivation=derivation,
        invocation_id=inv,
        case_id=CASE,
        source_id="disk-1",
        source_sha256="a" * 64,
        artifact_locator="/x",
        tool_name=tool,
        tool_version="0.1",
        upstream_backends=_BACKENDS_BY_TOOL[tool] if backends is None else backends,
        raw_output_sha256=("c" * 64) if bound else None,
        oversight_entry_sha256=("d" * 64) if bound else None,
        oversight_sequence=7 if bound else None,
    )


def _source_deriv(sha="a" * 64):
    return T.DerivationMetadata(
        method="hash.sha256",
        method_version="1",
        derivation_inputs=[T.SourceInput(case_id=CASE, source_id="disk-1", sha256=sha)],
    )


def _v2_observed():
    return T.attach_receipt(
        T.ok_result(data_type="filesystem.directory_listing", provenance=_v2_provenance())
    )


def _v2_derived(sha="a" * 64):
    return T.attach_receipt(
        T.ok_result(
            data_type="filesystem.file_hash",
            provenance=_v2_provenance("derived", derivation=_source_deriv(sha), tool="evidence_file_hash"),
        )
    )


class _TrustingLineage:
    """Resolver that attests the audit binding and every case-bound input."""

    def validate_audit_binding(self, result):
        return True

    def validate_source_input(self, s):
        return s.case_id == CASE and (s.source_id, s.sha256) == ("disk-1", "a" * 64)

    def validate_result_input(self, p, *, current_invocation_id):
        return False


class _AuditBoundLineage(_TrustingLineage):
    """Resolver backed by a trusted record captured at standardization time.

    Models the real oversight chain: it stores each result's canonical audit
    binding record and only attests a result whose current content still produces
    that exact record.  A mutated (even re-signed) result yields a different
    payload digest and no longer matches.
    """

    def __init__(self, results):
        self._records = {
            r.provenance.invocation_id: T.audit_binding_record(r) for r in results
        }

    def validate_audit_binding(self, result):
        record = self._records.get(result.provenance.invocation_id)
        return record is not None and T.audit_binding_record(result) == record


def _admissible(result, **overrides):
    kwargs = {"lineage": _TrustingLineage(), "active_case_id": CASE}
    kwargs.update(overrides)
    return T.result_is_admissible(result, **kwargs)


# --- v1 / unclassified cannot enter the v2 final verifier ---------------------

def test_v1_result_is_not_admissible_under_the_v2_gate():
    assert T.is_admissible_case_evidence(_v1_case_result().model_dump(mode="json")) is None


def test_v2_observed_passes_gate_reference_never_does():
    assert T.is_admissible_case_evidence(_v2_observed().model_dump(mode="json")) is True
    ref = T.attach_receipt(
        T.ok_result(
            data_type="reference.artifact_locations",
            provenance=_v2_provenance("reference", tool="artifact_reference_query"),
        )
    )
    assert T.is_admissible_case_evidence(ref.model_dump(mode="json")) is False
    assert _admissible(ref) is False


def test_error_status_is_never_admissible_at_either_gate():
    err = T.attach_receipt(
        T.error_result(
            data_type="filesystem.directory_listing",
            provenance=_v2_provenance(),
            error=T.ToolError(code="not_found", message="missing"),
            coverage_reason="target not present",
        )
    )
    assert T.is_admissible_case_evidence(err.model_dump(mode="json")) is False
    assert _admissible(err) is False


def test_result_must_be_bound_to_the_active_case():
    observed = _v2_observed()  # case_id == CASE
    # No active case, or a different active case, is inadmissible.
    assert _admissible(observed, active_case_id=None) is False
    assert _admissible(observed, active_case_id="other-case") is False
    assert _admissible(observed) is True


def test_observed_requires_source_and_audit_binding():
    observed = _v2_observed()

    class NoAudit(_TrustingLineage):
        def validate_audit_binding(self, result):
            return False

    class WrongSource(_TrustingLineage):
        def validate_source_input(self, s):
            return False

    assert _admissible(observed, lineage=None) is False
    assert _admissible(observed, lineage=NoAudit()) is False       # audit binding required
    assert _admissible(observed, lineage=WrongSource()) is False   # source must resolve
    assert _admissible(observed) is True


def test_resolver_exception_does_not_abort_the_final_check():
    observed = _v2_observed()

    class Explodes(_TrustingLineage):
        def validate_source_input(self, s):
            raise RuntimeError("boom")

    # An exception in the resolver is treated as False, not propagated.
    assert _admissible(observed, lineage=Explodes()) is False


def test_observed_without_source_digest_is_inadmissible():
    prov = T.make_provenance(
        evidence_class="observed",
        provenance_type=T.ProvenanceType.CASE_EVIDENCE,
        invocation_id="run:9",
        case_id=CASE,
        source_id="disk-1",
        artifact_locator="/x",
        tool_name="list_directory",
        tool_version="0.1",
        # The producing backend is declared, so the check reaches (and fails at)
        # the source requirement rather than the backend declaration.
        upstream_backends=[_dfvfs("filesystem.list_directory")],
        # Oversight triple present so the check reaches (and fails at) the source
        # requirement, not the audit-binding gate.
        raw_output_sha256="c" * 64,
        oversight_entry_sha256="d" * 64,
        oversight_sequence=7,
    )  # no source_sha256
    result = T.attach_receipt(
        T.ok_result(data_type="filesystem.directory_listing", provenance=prov)
    )
    assert _admissible(result) is False


def test_result_and_lineage_inputs_require_case_id():
    with pytest.raises(ValidationError):
        T.SourceInput(source_id="disk-1", sha256="a" * 64)  # no case_id
    with pytest.raises(ValidationError):
        T.ResultInput(payload_sha256="a" * 64)  # no case_id / invocation_id


# --- (c) classification and lineage affect the v2 receipt ---------------------

def test_evidence_class_and_lineage_change_the_v2_receipt():
    assert T.payload_sha256(_v2_observed()) != T.payload_sha256(_v2_derived())
    assert T.payload_sha256(_v2_derived("a" * 64)) != T.payload_sha256(_v2_derived("b" * 64))


# --- (d) tampering / provenance-boundary attacks ------------------------------

def test_tampering_with_payload_breaks_the_v2_receipt():
    tampered = copy.deepcopy(_v2_observed().model_dump(mode="json"))
    tampered["data"]["attributes"] = {"forged": True}
    assert not T.verify_receipt(T.ToolResult.model_validate(tampered))


def test_inconsistent_classification_cannot_be_constructed():
    tampered = copy.deepcopy(_v2_derived().model_dump(mode="json"))
    tampered["provenance"]["evidence_class"] = "observed"
    # Pinned to the classification rule: several invariants can now reject a
    # relabelled payload, and this test must fail if the class/lineage agreement
    # stops being one of them.
    with pytest.raises(ValidationError, match="requires a derivation chain"):
        T.ToolResult.model_validate(tampered)


def test_adapt_legacy_result_rejects_structured_and_self_classified_input():
    prov = _v2_provenance()
    # A v1 ToolResult instance.
    with pytest.raises(T.ToolContractError):
        T.adapt_legacy_result(_v1_case_result(), data_type="x", provenance=prov)
    # A v2 ToolResult instance.
    with pytest.raises(T.ToolContractError):
        T.adapt_legacy_result(_v2_observed(), data_type="x", provenance=prov)
    # A mapping self-marked as a v1 envelope.
    with pytest.raises(T.ToolContractError):
        T.adapt_legacy_result(
            {"schema_version": V1.SCHEMA_ID, "status": "ok"}, data_type="x", provenance=prov
        )
    # A mapping self-marked as a v2 envelope.
    with pytest.raises(T.ToolContractError):
        T.adapt_legacy_result(
            {"schema_version": T.SCHEMA_ID, "status": "ok"}, data_type="x", provenance=prov
        )
    # An unstructured raw dict is accepted.
    ok = T.adapt_legacy_result({"rows": [{"a": 1}]}, data_type="x", provenance=prov)
    assert isinstance(ok, T.ToolResult)


def test_v2_models_are_immutable():
    result = _v2_observed()
    with pytest.raises(ValidationError):
        result.status = T.ToolStatus.ERROR  # frozen model rejects mutation


def test_model_copy_bypass_cannot_be_signed_or_admitted():
    # model_copy skips validators; a receipt attached to a bypassed-invalid
    # instance must not verify, and attach_receipt must not sign it.
    result = _v2_observed()
    # Force an invalid page.returned via copy (bypasses the status invariant).
    bad_page = result.page.model_copy(update={"returned": 999})
    bypassed = result.model_copy(update={"page": bad_page, "receipt": None})
    with pytest.raises(ValidationError):
        T.attach_receipt(bypassed)  # revalidation catches the bypass
    assert _admissible(bypassed) is False


def test_receipt_is_an_integrity_digest_not_a_signature():
    # Removing the receipt, editing the payload and re-attaching a receipt
    # yields a self-consistent result whose receipt VERIFIES — the digest alone
    # is not proof of authenticity.  Integrity against such an actor comes from
    # the final check's audit binding, which the forged result cannot satisfy.
    forged = T.attach_receipt(
        _v2_observed().model_copy(
            update={
                "receipt": None,
                "data": T.ToolData(type="filesystem.directory_listing", items=[{"forged": True}]),
                "page": T.PageMetadata(returned=1, total=1),
            }
        )
    )
    assert T.verify_receipt(forged) is True   # recomputed digest is self-consistent
    # ... but with no trusted audit binding it is inadmissible.
    class NoAudit(_TrustingLineage):
        def validate_audit_binding(self, result):
            return False

    assert _admissible(forged, lineage=NoAudit()) is False


def test_audit_binding_is_bound_to_the_actual_result_content():
    # The decisive property: the audit binding is over THIS result's payload
    # digest, captured in the trusted record at standardization.  Keeping the
    # provenance and oversight pointers, mutating the data and re-attaching a
    # fresh receipt yields a self-consistent result that nonetheless no longer
    # matches its recorded binding, so the final check rejects it.
    observed = _v2_observed()
    lineage = _AuditBoundLineage([observed])
    assert _admissible(observed, lineage=lineage) is True

    forged = T.attach_receipt(
        observed.model_copy(
            update={
                "receipt": None,
                "data": T.ToolData(type="filesystem.directory_listing", items=[{"forged": True}]),
                "page": T.PageMetadata(returned=1, total=1),
            }
        )
    )
    assert T.verify_receipt(forged) is True            # receipt recomputed, self-consistent
    assert forged.provenance.oversight_entry_sha256 == observed.provenance.oversight_entry_sha256
    assert _admissible(forged, lineage=lineage) is False  # payload digest no longer recorded


def test_result_without_the_oversight_binding_triple_is_inadmissible():
    unbound = T.attach_receipt(
        T.ok_result(
            data_type="filesystem.directory_listing",
            provenance=_v2_provenance(bound=False),
        )
    )
    # Even a fully trusting resolver cannot admit a result that carries no
    # oversight pointers to anchor it to the trusted chain.
    assert _admissible(unbound) is False


def test_audit_binding_record_requires_a_raw_output_digest():
    unbound = T.attach_receipt(
        T.ok_result(
            data_type="filesystem.directory_listing",
            provenance=_v2_provenance(bound=False),
        )
    )
    with pytest.raises(T.ToolContractError):
        T.audit_binding_record(unbound)


def test_mutating_a_signed_nested_container_fails_verification():
    signed = _v2_observed()
    # Mutate the signed result's nested attributes dict in place (frozen only
    # blocks field reassignment, not container mutation).
    signed.data.attributes["injected"] = "tamper"
    assert T.verify_receipt(signed) is False


def test_verify_rejects_a_tampered_receipt_header():
    signed = _v2_observed()
    # Simulate a receipt whose schema/algorithm header was altered while keeping
    # the payload digest, via model_construct (which bypasses validation).
    forged_receipt = T.ToolResultReceipt.model_construct(
        schema_version="forensic.tool-result-receipt.v1",
        algorithm="sha256",
        payload_sha256=signed.receipt.payload_sha256,
    )
    forged = signed.model_copy(update={"receipt": forged_receipt})
    assert T.verify_receipt(forged) is False


# --- (e) construction invariants ----------------------------------------------

def test_v2_provenance_requires_evidence_class_and_case_id():
    # evidence_class is a required keyword.
    with pytest.raises(TypeError):
        T.make_provenance(  # type: ignore[call-arg]
            provenance_type=T.ProvenanceType.CASE_EVIDENCE,
            invocation_id="run:1",
            case_id=CASE,
            source_id="s",
            artifact_locator="a",
            tool_name="x",
            tool_version="0.1",
        )
    # case_id is required too.
    with pytest.raises(TypeError):
        T.make_provenance(  # type: ignore[call-arg]
            evidence_class="observed",
            provenance_type=T.ProvenanceType.CASE_EVIDENCE,
            invocation_id="run:1",
            source_id="s",
            artifact_locator="a",
            tool_name="x",
            tool_version="0.1",
        )


def test_public_parameters_digest_is_derived_only_from_the_safe_projection():
    # make_provenance takes NO caller-supplied parameter mapping: the public
    # tool.parameters_sha256 is derived solely from the already-safe
    # derivation.parameters, so raw arguments can never re-enter it and it can
    # never become an oracle for a low-entropy secret (e.g. a four-digit key).
    safe = {"op": "rc4", "kdf": "sha256"}
    deriv = T.DerivationMetadata(
        method="transform.decode",
        method_version="1",
        derivation_inputs=[T.SourceInput(case_id=CASE, source_id="disk-1", sha256="a" * 64)],
        parameters=safe,
    )
    prov = _v2_provenance("derived", derivation=deriv, tool="decode")

    digest = prov.tool.parameters_sha256
    assert digest == T.sha256_hex(T.canonical_json(safe))
    # It is NOT the digest of the raw arguments carrying the secret key/data...
    raw = {"op": "rc4", "kdf": "sha256", "key": "1234", "data": "deadbeef"}
    assert digest != T.sha256_hex(T.canonical_json(raw))
    # ...and no four-digit key candidate reproduces it (the digest omits `key`).
    assert all(
        digest != T.sha256_hex(T.canonical_json({**raw, "key": f"{n:04d}"}))
        for n in range(10000)
    )
    # OBSERVED / REFERENCE carry no public parameters digest at all.
    assert _v2_provenance("observed").tool.parameters_sha256 is None
    assert _v2_provenance("reference", tool="artifact_reference_query").tool.parameters_sha256 is None


def test_derived_requires_nonempty_inputs_at_construction():
    with pytest.raises(ValidationError):
        T.DerivationMetadata(method="m", method_version="1", derivation_inputs=[])


def test_v2_derived_needs_resolver_and_validated_inputs():
    derived = _v2_derived()

    class BadLineage(_TrustingLineage):
        def validate_source_input(self, s):
            return False

    assert _admissible(derived, lineage=None) is False
    assert _admissible(derived, lineage=BadLineage()) is False
    assert _admissible(derived) is True


# --- (f) upstream backend declaration -----------------------------------------

def test_observed_must_name_exactly_one_producing_backend():
    # Naming no producer leaves the decisive question unanswered: which
    # documented component actually reported these rows.
    with pytest.raises(ValidationError, match="exactly one producing backend"):
        _v2_provenance(backends=[])
    # Two producers under ONE observed result is the unlabelled merge the
    # contract exists to prevent — no reader could tell which component reported
    # which row, and nothing in the payload says the rows were combined.
    with pytest.raises(ValidationError, match="exactly one producing backend"):
        _v2_provenance(
            backends=[_dfvfs("filesystem.list_directory"), _tsk("filesystem.list_directory")]
        )
    provenance = _v2_provenance(backends=[_dfvfs("filesystem.list_directory")])
    assert [(b.name, b.role) for b in provenance.upstream_backends] == [("dfvfs", "producer")]


def test_a_support_backend_is_never_counted_as_the_producer():
    # pyewf only presents the E01 container to the parser; it never reports the
    # filesystem itself, so a result naming only pyewf has no producer at all.
    with pytest.raises(ValidationError, match="exactly one producing backend"):
        _v2_provenance(backends=[_pyewf()])
    # Support entries also never push a single-producer result over the limit,
    # however many of them the read needed.
    provenance = _v2_provenance(
        backends=[
            _dfvfs("filesystem.list_directory"),
            _pyewf("storage_media.ewf_open"),
            _pyewf("storage_media.ewf_read"),
        ]
    )
    assert len(provenance.upstream_backends) == 3
    assert sum(b.role == "producer" for b in provenance.upstream_backends) == 1


def test_derived_may_combine_producers_but_must_name_at_least_one_backend():
    derivation = _source_deriv()
    # The combination the observed class refuses is exactly what DERIVED is for:
    # once the result is labelled as our computation, citing both components it
    # read is honest rather than an unlabelled merge.
    combined = _v2_provenance(
        "derived",
        derivation=derivation,
        tool="evidence_file_hash",
        backends=[_dfvfs("filesystem.read_file"), _tsk("filesystem.read_file")],
    )
    assert sum(b.role == "producer" for b in combined.upstream_backends) == 2
    # A derivation that names nothing attests nothing about where its bytes came
    # from, even though its typed lineage is intact.
    with pytest.raises(ValidationError, match="must name the backends"):
        _v2_provenance(
            "derived", derivation=derivation, tool="evidence_file_hash", backends=[]
        )
    # The DERIVED rule is "at least one backend", not "at least one producer":
    # a computation over bytes only pyewf made readable still declares pyewf.
    support_only = _v2_provenance(
        "derived", derivation=derivation, tool="evidence_file_hash", backends=[_pyewf()]
    )
    assert [b.role for b in support_only.upstream_backends] == ["support"]


def test_reference_knowledge_declares_no_backend():
    # REFERENCE is procedural knowledge, never a reading of evidence, so there is
    # no component underneath it to name and the backend rules do not apply.
    assert _v2_provenance("reference", tool="artifact_reference_query").upstream_backends == []


#: Placeholder versions spelled out here rather than read from the contract, so
#: the test still bites if the contract's own set is emptied.
_PLACEHOLDER_VERSIONS = (
    "unknown",
    "unspecified",
    "n/a",
    "na",
    "none",
    "null",
    "-",
    "?",
    " Unknown ",
    "N/A",
    "NONE\t",
)


def test_a_placeholder_backend_version_is_refused_at_construction():
    # A backend version that says nothing cannot be reproduced or re-examined by
    # anyone checking the work, so it is refused where it is created rather than
    # shipped and explained away in the report.  Case and surrounding whitespace
    # do not launder it.
    for placeholder in _PLACEHOLDER_VERSIONS:
        with pytest.raises(ValidationError, match="unusable version"):
            T.UpstreamBackend(
                name="dfvfs",
                version=placeholder,
                operation="filesystem.list_directory",
                role="producer",
            )
    # An absent version is refused by the field constraint itself.
    with pytest.raises(ValidationError):
        T.UpstreamBackend(
            name="dfvfs", version="", operation="filesystem.list_directory", role="producer"
        )
    # Every placeholder the contract refuses is covered above, so one added there
    # cannot go untested here.
    assert set(T._UNUSABLE_VERSIONS) <= {v.strip().casefold() for v in _PLACEHOLDER_VERSIONS}
    # The real reported versions are accepted.
    for version in (DFVFS_VERSION, TSK_VERSION, PYEWF_VERSION):
        assert (
            T.UpstreamBackend(
                name="dfvfs", version=version, operation="filesystem.read_file", role="producer"
            ).version
            == version
        )


def test_the_same_backend_may_not_be_declared_twice():
    derivation = _source_deriv()
    # DERIVED so several producers are legal and the duplicate rule is the only
    # rule the repeated entry can violate.
    with pytest.raises(ValidationError, match="declared twice"):
        _v2_provenance(
            "derived",
            derivation=derivation,
            tool="evidence_file_hash",
            backends=[_dfvfs("filesystem.read_file"), _dfvfs("filesystem.read_file")],
        )
    # A backend is identified by what it did, not merely by its name: one
    # component doing two different jobs for the same result is a real
    # distinction and stays declarable.
    two_jobs = _v2_provenance(
        "derived",
        derivation=derivation,
        tool="evidence_file_hash",
        backends=[_dfvfs("filesystem.read_file"), _dfvfs("filesystem.list_directory")],
    )
    assert len(two_jobs.upstream_backends) == 2


def test_an_unlabelled_merge_cannot_be_smuggled_in_through_the_wire():
    # The merge rule is a construction invariant, so it survives a round trip: a
    # wire that relabels a two-producer DERIVED result as OBSERVED is refused on
    # re-parse, which is where a tampered payload would arrive.
    merged = T.attach_receipt(
        T.ok_result(
            data_type="filesystem.file_hash",
            provenance=_v2_provenance(
                "derived",
                derivation=_source_deriv(),
                tool="evidence_file_hash",
                backends=[_dfvfs("filesystem.read_file"), _tsk("filesystem.read_file")],
            ),
        )
    )
    assert T.verify_receipt(T.revalidate(merged)) is True

    relabelled = copy.deepcopy(merged.model_dump(mode="json"))
    relabelled["provenance"]["evidence_class"] = "observed"
    # Dropped too, so the only invariant left to break is the merge rule.
    relabelled["provenance"]["derivation"] = None
    with pytest.raises(ValidationError, match="exactly one producing backend"):
        T.ToolResult.model_validate(relabelled)


def test_upstream_backends_survive_the_receipt_round_trip():
    signed = _v2_observed()
    wire = signed.model_dump(mode="json")
    assert wire["provenance"]["upstream_backends"] == [
        {
            "name": "dfvfs",
            "version": DFVFS_VERSION,
            "operation": "filesystem.list_directory",
            "role": "producer",
        },
        {
            "name": "pyewf",
            "version": PYEWF_VERSION,
            "operation": "storage_media.ewf_read",
            "role": "support",
        },
    ]
    reparsed = T.ToolResult.model_validate(wire)
    assert reparsed.provenance.upstream_backends == signed.provenance.upstream_backends
    assert T.verify_receipt(reparsed) is True
    # The declaration is inside the signed payload, so attributing the same rows
    # to a different component is a different result, not a cosmetic annotation.
    other = T.attach_receipt(
        T.ok_result(
            data_type="filesystem.directory_listing",
            provenance=_v2_provenance(
                backends=[_tsk("filesystem.list_directory"), _pyewf()]
            ),
        )
    )
    assert T.payload_sha256(other) != T.payload_sha256(signed)


def test_mutating_the_declared_backends_breaks_receipt_verification():
    signed = _v2_observed()
    # A support entry keeps the provenance valid, so verification can only fail
    # on the digest: the receipt genuinely covers the backend declaration rather
    # than the mutation merely making the result unparseable.
    signed.provenance.upstream_backends.append(_tsk("filesystem.list_directory", role="support"))
    assert T.verify_receipt(signed) is False

    # Rewriting the producer's version on the wire is caught — a real version
    # string is still a false attestation once it is not the one dfVFS reported.
    restamped = copy.deepcopy(_v2_observed().model_dump(mode="json"))
    restamped["provenance"]["upstream_backends"][0]["version"] = PYEWF_VERSION
    assert T.verify_receipt(T.ToolResult.model_validate(restamped)) is False
    # ... and so is swapping the producer for another real component.
    swapped = copy.deepcopy(_v2_observed().model_dump(mode="json"))
    swapped["provenance"]["upstream_backends"][0]["name"] = "sleuthkit"
    swapped["provenance"]["upstream_backends"][0]["version"] = TSK_VERSION
    assert T.verify_receipt(T.ToolResult.model_validate(swapped)) is False
    # Dropping the support entry is equally visible.
    dropped = copy.deepcopy(_v2_observed().model_dump(mode="json"))
    del dropped["provenance"]["upstream_backends"][1]
    assert T.verify_receipt(T.ToolResult.model_validate(dropped)) is False
