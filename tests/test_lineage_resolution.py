"""The run's lineage authority: what it binds, what it refuses, and why.

Every test drives the PRODUCTION resolver against a real append-only oversight
chain and the run's real retained-result store, and asks the production final
check (:func:`forensic_agent.core.result_admission.wire_passes_final_check`) for
the verdict.  Nothing here restates a contract rule: the rules are the contract's,
and what is under test is whether the run can honestly satisfy them from what it
established itself.

The refusals are the point rather than the exception.  A result the run cannot
bind stays stored, readable and quotable as a diagnostic record; it simply may
never be an evidential basis, and no producer and no lineage is invented to make
it pass.
"""

from __future__ import annotations

import json

from forensic_agent.agent.lineage_resolution import (
    FOREIGN_CASE_RESULT,
    NO_OVERSIGHT_CHAIN,
    PARENT_CYCLIC,
    PARENT_FOREIGN_CASE,
    PARENT_NOT_EARLIER,
    PARENT_UNIDENTIFIABLE,
    PRODUCER_NOT_ESTABLISHED,
    SOURCE_NOT_ATTESTED,
    SOURCE_NOT_DIGESTED,
    AttestedSource,
    RunLineageResolver,
    attested_case_sources,
)
from forensic_agent.agent.result_lineage import ResultLineageStore
from forensic_agent.core import result_contract as contract
from forensic_agent.core.result_admission import wire_passes_final_check
from forensic_agent.core.result_reading import read_result, receipt_is_valid
from forensic_agent.oversight.audit import OversightLog, verify_chain
from forensic_agent.oversight.policy import Policy, evaluate

CASE = "case-lineage"
OTHER_CASE = "case-elsewhere"
SOURCE_SHA = "a" * 64
SOURCE_ID = f"evidence-sha256:{SOURCE_SHA}"
FOREIGN_SHA = "b" * 64

# Components a filesystem listing in this repository really runs through.  The
# contract refuses a placeholder version, so the fixtures state real ones.
_DFVFS = contract.UpstreamBackend(
    name="dfvfs", version="20240115", operation="filesystem.directory_listing", role="producer"
)
_PYEWF = contract.UpstreamBackend(
    name="pyewf", version="20231119", operation="filesystem.directory_listing", role="support"
)


# --- fixtures -----------------------------------------------------------------


def _provenance(
    invocation: str,
    *,
    sequence: int,
    case_id: str = CASE,
    evidence_class=contract.EvidenceClass.OBSERVED,
    derivation=None,
    backends=(_DFVFS,),
    source_sha256: str | None = SOURCE_SHA,
    raw_output_sha256: str = "c" * 64,
    entry_sha256: str = "d" * 64,
):
    return contract.make_provenance(
        evidence_class=evidence_class,
        provenance_type=contract.ProvenanceType.CASE_EVIDENCE,
        derivation=derivation,
        invocation_id=invocation,
        case_id=case_id,
        source_id=SOURCE_ID,
        source_sha256=source_sha256,
        artifact_locator="path:/Users",
        tool_name="filesystem_query",
        tool_version="0.1",
        upstream_backends=backends,
        raw_output_sha256=raw_output_sha256,
        oversight_entry_sha256=entry_sha256,
        oversight_sequence=sequence,
    )


def _observed(invocation: str, *, sequence: int, items=None, **provenance_kwargs):
    result = contract.ok_result(
        data_type="filesystem.directory_listing",
        provenance=_provenance(invocation, sequence=sequence, **provenance_kwargs),
        items=list(items or [{"name": "notes.txt"}]),
    )
    return contract.attach_receipt(result)


def _cite(parent, *, case_id: str = CASE, invocation: str | None = None):
    """A typed citation of one earlier result, as a derivation carries it."""

    return contract.ResultInput(
        case_id=case_id,
        payload_sha256=contract.payload_sha256(parent),
        invocation_id=invocation or parent.provenance.invocation_id,
    )


def _derived(invocation: str, *, sequence: int, inputs, backends=(_DFVFS,), **kwargs):
    derivation = contract.DerivationMetadata(
        method="filesystem.correlate",
        method_version="1",
        derivation_inputs=list(inputs),
        parameters={"scope": "/Users"},
    )
    result = contract.ok_result(
        data_type="filesystem.correlated_entries",
        provenance=_provenance(
            invocation,
            sequence=sequence,
            evidence_class=contract.EvidenceClass.DERIVED,
            derivation=derivation,
            backends=backends,
            **kwargs,
        ),
        items=[{"name": "notes.txt"}],
    )
    return contract.attach_receipt(result)


class _Run:
    """One run's chain, retained-result store and lineage authority together.

    Assembled exactly as ``orchestration/preparation.py`` assembles them, so a
    test drives the production objects rather than a description of them.
    """

    def __init__(
        self,
        tmp_path,
        *,
        case_id: str = CASE,
        sources=None,
        chain: bool = True,
        name: str = "oversight",
    ):
        self.path = str(tmp_path / f"{name}.jsonl")
        self.log = OversightLog(self.path) if chain else None
        if self.log is not None:
            self.log.open_case(question="what was read?", case_id=case_id)
        self.store = ResultLineageStore()
        self.lineage = RunLineageResolver(
            self.store,
            case_id=case_id,
            sources=(
                sources
                if sources is not None
                else (AttestedSource(case_id, SOURCE_ID, SOURCE_SHA),)
            ),
            recorder=self.log,
        )

    def standardized(self, result, *, tool="filesystem_query", arguments=None):
        """Retain and bind one standardized result, in the production order."""

        wire = result.model_dump(mode="json")
        self.store.record_complete_result(tool, dict(arguments or {}), wire)
        self.lineage.record_result(tool, dict(arguments or {}), wire)
        return wire

    def entries(self):
        return OversightLog.load(self.path) if self.log is not None else []

    def bindings(self):
        return [entry for entry in self.entries() if entry.get("event") == "result_binding"]

    def passes(self, wire, *, case_id: str = CASE) -> bool:
        return wire_passes_final_check(wire, lineage=self.lineage, active_case_id=case_id)


# --- the positive control -----------------------------------------------------


def test_a_result_this_run_bound_backs_a_case_claim(tmp_path) -> None:
    """The authority is not merely refusing everything."""

    run = _Run(tmp_path)
    wire = run.standardized(_observed("run:0001", sequence=1))

    assert run.passes(wire) is True
    # BITES: the identical result with no lineage authority bound is refused,
    # because its own receipt is then the only thing left to check it against and
    # whoever edited the payload could have recomputed that.
    assert wire_passes_final_check(wire, lineage=None, active_case_id=CASE) is False
    metrics = run.lineage.metrics()
    assert metrics["bound_artifacts"] == 1
    assert metrics["diagnostic_artifacts"] == 0


def test_a_derivation_over_an_earlier_bound_result_resolves(tmp_path) -> None:
    """The lineage arm has a passing case, or every refusal below proves nothing."""

    run = _Run(tmp_path)
    parent = _observed("run:0001", sequence=1)
    run.standardized(parent)
    child = _derived("run:0002", sequence=2, inputs=[_cite(parent)])
    wire = run.standardized(child)

    assert run.lineage.validate_result_input(
        _cite(parent), current_invocation_id="run:0002"
    ) is True
    assert run.passes(wire) is True


# --- the audit binding is written after standardization -----------------------


def test_the_audit_binding_is_written_after_standardization_and_matches_the_entry(
    tmp_path,
) -> None:
    """The record carries the finished payload digest, so it cannot precede it.

    The order is forced by the contract, not chosen for convenience: the payload
    already carries the chain pointers, so a record written before
    standardization would have to reference a result that references it.
    """

    run = _Run(tmp_path)
    raw = {"entries": [{"name": "notes.txt"}]}
    action = run.log.record_action(
        tool="filesystem_query",
        args={"operation": "list_directory", "path": "/Users"},
        decision=evaluate(Policy.permissive(), "filesystem_query", {}),
        output=raw,
    )

    result = _observed(
        "run:0001",
        sequence=action["seq"],
        raw_output_sha256=action["canonical_output_sha256"],
        entry_sha256=action["entry_hash"],
    )
    run.standardized(result)

    binding = run.bindings()[-1]
    # AFTER: the binding entry follows the action whose output it attests, and
    # carries a digest that does not exist until the result has been built.
    assert binding["seq"] > action["seq"]
    assert binding["prev_hash"] == action["entry_hash"]
    assert binding["bound"] is True
    assert binding["binding"]["payload_sha256"] == contract.payload_sha256(result)
    assert binding["binding"]["raw_output_sha256"] == action["canonical_output_sha256"]
    # MATCHES: the entry holds exactly the canonical record the contract builds
    # for this result at this position in the chain.
    assert binding["binding"] == contract.audit_binding_record(
        result, previous_oversight_entry_sha256=action["entry_hash"]
    ).model_dump(mode="json")
    assert verify_chain(run.entries())["ok"] is True

    # And the binding is what the verdict rests on: a payload edited and re-signed
    # is self-consistent and still refused, because the chain holds no record of
    # THAT content.
    edited = json.loads(json.dumps(result.model_dump(mode="json")))
    edited["data"]["items"] = [{"name": "invoice.pdf"}]
    resigned = contract.attach_receipt(
        contract.ToolResult.model_validate({**edited, "receipt": None})
    ).model_dump(mode="json")
    assert contract.verify_receipt(contract.ToolResult.model_validate(resigned)) is True
    assert run.passes(resigned) is False
    assert run.passes(result.model_dump(mode="json")) is True


def test_without_an_oversight_chain_nothing_is_bound(tmp_path) -> None:
    """No append-only record means nothing to check content against."""

    run = _Run(tmp_path, chain=False)
    wire = run.standardized(_observed("run:0001", sequence=1))

    assert run.passes(wire) is False
    assert run.lineage.metrics()["refusals_by_code"] == {NO_OVERSIGHT_CHAIN: 1}
    # Storable and displayable all the same: the run keeps the result and can
    # still read a value out of it.
    assert receipt_is_valid(read_result(wire)) is True
    assert run.store.retained("run:0001") is not None


# --- a foreign parent ---------------------------------------------------------


def test_a_parent_from_another_case_is_refused(tmp_path) -> None:
    """Evidence of another case is evidence about something else."""

    run = _Run(tmp_path)
    foreign = _observed("other:0001", sequence=1, case_id=OTHER_CASE)
    run.standardized(foreign)

    # The run refuses to bind it at all: a run attests only its own case.
    assert run.lineage.metrics()["refusals_by_code"] == {FOREIGN_CASE_RESULT: 1}
    assert run.bindings()[-1]["refusal_code"] == FOREIGN_CASE_RESULT

    # Cited truthfully, the citation names another case and is refused as such.
    truthful = _cite(foreign, case_id=OTHER_CASE)
    assert run.lineage.validate_result_input(
        truthful, current_invocation_id="run:0002"
    ) is False
    assert run.lineage.metrics()["citation_refusals_by_code"][PARENT_FOREIGN_CASE] == 1

    # Cited with this case's id — the citation lying about which case it came
    # from — the run holds no binding for that content and refuses again.  The
    # citation is a lookup key here, never the authority.
    lying = _cite(foreign, case_id=CASE)
    assert run.lineage.validate_result_input(lying, current_invocation_id="run:0002") is False
    assert run.lineage.metrics()["citation_refusals_by_code"][PARENT_UNIDENTIFIABLE] == 1

    child = _derived("run:0002", sequence=2, inputs=[lying])
    assert run.passes(run.standardized(child)) is False


def test_a_source_the_case_never_attested_is_refused(tmp_path) -> None:
    """A digest is checked against the registry, never the registry against it."""

    run = _Run(tmp_path)
    wire = run.standardized(_observed("run:0001", sequence=1, source_sha256=FOREIGN_SHA))

    assert run.passes(wire) is False
    assert run.lineage.metrics()["citation_refusals_by_code"] == {SOURCE_NOT_ATTESTED: 1}
    # BITES: the same reading over the source this case really ingested passes,
    # so the refusal is about the evidence and not about the fixture.
    assert run.passes(run.standardized(_observed("run:0002", sequence=2))) is True


# --- a future parent ----------------------------------------------------------


def test_a_parent_recorded_after_the_call_citing_it_is_refused(tmp_path) -> None:
    """A call cannot have consumed a result that did not exist yet."""

    run = _Run(tmp_path)
    later = _observed("run:0009", sequence=9)
    run.standardized(later)
    child = _derived("run:0002", sequence=2, inputs=[_cite(later)])
    wire = run.standardized(child)

    assert run.lineage.validate_result_input(
        _cite(later), current_invocation_id="run:0002"
    ) is False
    assert run.lineage.metrics()["citation_refusals_by_code"][PARENT_NOT_EARLIER] == 1
    assert run.passes(wire) is False

    # BITES: the same two results with the observations in the other order — the
    # parent observed first — resolve, so what bit is the order and nothing else.
    ordered = _Run(tmp_path, name="ordered")
    earlier = _observed("run:0001", sequence=1)
    ordered.standardized(earlier)
    assert ordered.passes(
        ordered.standardized(_derived("run:0002", sequence=2, inputs=[_cite(earlier)]))
    ) is True


# --- a cyclic parent ----------------------------------------------------------


def test_a_cyclic_parent_is_refused(tmp_path) -> None:
    """A derivation citing itself has no observation under it.

    The indirect cycle is refused by the same ordering rule: every parent must sit
    strictly earlier in the append-only chain than the call citing it, and a set
    of positions where each is smaller than the next cannot close.
    """

    run = _Run(tmp_path)
    first = _observed("run:0001", sequence=1)
    run.standardized(first)
    second = _derived("run:0002", sequence=2, inputs=[_cite(first)])
    run.standardized(second)

    # Direct: the call cites its own invocation.
    self_citing = contract.ResultInput(
        case_id=CASE, payload_sha256=contract.payload_sha256(second), invocation_id="run:0002"
    )
    assert run.lineage.validate_result_input(
        self_citing, current_invocation_id="run:0002"
    ) is False
    assert run.lineage.metrics()["citation_refusals_by_code"][PARENT_CYCLIC] == 1

    # Indirect: run:0002 already cites run:0001, so run:0001 citing run:0002 back
    # would close the loop.  It is refused as the later observation it is.
    assert run.lineage.validate_result_input(
        _cite(second), current_invocation_id="run:0001"
    ) is False
    assert run.lineage.metrics()["citation_refusals_by_code"][PARENT_NOT_EARLIER] == 1

    cyclic = _derived("run:0002", sequence=2, inputs=[self_citing])
    assert run.passes(run.standardized(cyclic)) is False


# --- an unidentifiable parent -------------------------------------------------


def test_an_unidentifiable_parent_is_refused(tmp_path) -> None:
    """A citation of something this run cannot identify is a citation of nothing."""

    run = _Run(tmp_path)
    parent = _observed("run:0001", sequence=1)
    run.standardized(parent)

    # An invocation this run never recorded.
    unknown = contract.ResultInput(
        case_id=CASE, payload_sha256=contract.payload_sha256(parent), invocation_id="run:9999"
    )
    assert run.lineage.validate_result_input(unknown, current_invocation_id="run:0002") is False

    # The right invocation, but content the run does not hold for it: a handle
    # minted over one payload must not resolve against a different one.
    other = _observed("run:0001", sequence=1, items=[{"name": "invoice.pdf"}])
    mismatched = contract.ResultInput(
        case_id=CASE, payload_sha256=contract.payload_sha256(other), invocation_id="run:0001"
    )
    assert run.lineage.validate_result_input(
        mismatched, current_invocation_id="run:0002"
    ) is False
    assert run.lineage.metrics()["citation_refusals_by_code"][PARENT_UNIDENTIFIABLE] == 2

    child = _derived("run:0002", sequence=2, inputs=[unknown])
    assert run.passes(run.standardized(child)) is False


# --- the honest refusal -------------------------------------------------------


def test_a_result_with_no_established_producer_stays_a_stored_diagnostic(tmp_path) -> None:
    """No component established, no evidential basis, and nothing invented.

    Both halves are asserted: the result may never back a claim, AND it is still
    retained, still readable, still receipted and still quotable as a diagnostic
    record.  Discarding it would lose real output; admitting it would publish a
    value nobody can attribute to a component or reproduce.
    """

    run = _Run(tmp_path)
    parent = _observed("run:0001", sequence=1)
    run.standardized(parent)
    # Support components only: something made the read possible, but nothing was
    # established as the component that produced these values.
    unattested = _derived(
        "run:0002", sequence=2, inputs=[_cite(parent)], backends=(_PYEWF,)
    )
    wire = run.standardized(unattested)

    assert run.passes(wire) is False
    assert run.lineage.metrics()["refusals_by_code"] == {PRODUCER_NOT_ESTABLISHED: 1}

    # STORED AND DISPLAYABLE: the run keeps it, it still reads back, its receipt
    # still covers it, and a value can still be read out of it for display.
    retained = run.store.retained("run:0002")
    assert retained is not None
    assert receipt_is_valid(read_result(retained.wire)) is True
    assert run.store.cited_value(
        "run:0002", wire["receipt"]["payload_sha256"], "data.items[0].name"
    ) == "notes.txt"

    # DISCLOSED, not silent: the append-only chain records that the run saw this
    # result and could not bind it, naming the role it keeps and the reason.
    disclosure = run.bindings()[-1]
    assert disclosure["bound"] is False
    assert disclosure["binding"] is None
    assert disclosure["evidential_role"] == "diagnostic"
    assert disclosure["refusal_code"] == PRODUCER_NOT_ESTABLISHED
    assert disclosure["invocation_id"] == "run:0002"
    # NOTHING INVENTED: the support component that made the read possible is not
    # promoted to producer, and no digest is claimed for a result nothing was
    # bound to.  The record states the refusal and stops there.
    recorded = json.dumps(disclosure)
    assert _PYEWF.name not in recorded
    assert SOURCE_SHA not in recorded
    assert verify_chain(run.entries())["ok"] is True


def test_a_reading_of_an_undigested_source_stays_a_stored_diagnostic(tmp_path) -> None:
    """A source no registry can confirm cannot be an evidential basis either."""

    run = _Run(tmp_path)
    wire = run.standardized(_observed("run:0001", sequence=1, source_sha256=None))

    assert run.passes(wire) is False
    assert run.lineage.metrics()["refusals_by_code"] == {SOURCE_NOT_DIGESTED: 1}
    assert run.bindings()[-1]["refusal_code"] == SOURCE_NOT_DIGESTED
    assert receipt_is_valid(read_result(wire)) is True
    assert run.store.retained("run:0001") is not None
    # BITES: identical in every other respect, the same reading over the digested
    # source the case established passes.
    assert run.passes(run.standardized(_observed("run:0002", sequence=2))) is True


# --- the production wiring ----------------------------------------------------


def test_the_production_run_binds_its_lineage_authority() -> None:
    """The seam is bound where the run is built, and asked where it publishes.

    Unbound, every result of the active contract is refused deterministically —
    fail-closed, but a total loss of publishable evidence once the standardizer
    switches.  This states, in one place, that the run builds the authority, gives
    it the chain, feeds it both traced artifacts, and that every gate deciding
    what may be published consults it.
    """

    import inspect

    from forensic_agent.agent.orchestration import finalization, preparation

    prepared = inspect.getsource(preparation._prepare_runtime)
    assert "RunLineageResolver(" in prepared
    assert "sources=attested_case_sources(" in prepared
    # The chain is created with the model-visible surface, so the recorder is
    # attached once it exists; before that there is nothing to append to.
    assert "lineage.bind_recorder(" in prepared
    # Both traced artifacts of a call: the complete retained result the
    # publication gates read, and the projection the verifier reads.
    assert prepared.count("lineage.record_result(") == 2
    assert "lineage=lineage" in prepared

    published = inspect.getsource(finalization)
    # Four consultations, one per gate that reads evidence before publishing:
    # the verifier bundle, identifier grounding on the verifier path,
    # identifier grounding on the assembled path over the model's own text
    # segments, and identifier grounding on the keep-or-mark path that
    # publishes a draft whose verification ended without a judgement. A gate
    # added without the authority would read unbound results, so this count is
    # meant to be noticed when it moves.
    assert published.count("lineage=runtime.lineage") == 4
    assert "runtime.lineage.metrics()" in published


# --- the registry the run builds ---------------------------------------------


def test_the_source_registry_holds_only_what_the_run_established() -> None:
    """An undigested source produces no entry, so nothing can confirm it."""

    class _Disk:
        image_sha = SOURCE_SHA

    class _OpaqueDisk:
        image_sha = None

    class _Bundle:
        source_id = "case-evidence-bundle-sha256:" + FOREIGN_SHA
        case_bundle_sha256 = FOREIGN_SHA

    established = attested_case_sources(case_id=CASE, disk=_Disk(), case_evidence_source=_Bundle())
    assert [source.source_id for source in established] == [
        _Bundle.source_id,
        SOURCE_ID,
    ]
    assert {source.case_id for source in established} == {CASE}
    assert attested_case_sources(case_id=CASE, disk=_OpaqueDisk()) == ()

    store = ResultLineageStore()
    resolver = RunLineageResolver(store, case_id=CASE, sources=established)
    assert resolver.validate_source_input(
        contract.SourceInput(case_id=CASE, source_id=SOURCE_ID, sha256=SOURCE_SHA)
    ) is True
    # The same source id under a different digest is a different source.
    assert resolver.validate_source_input(
        contract.SourceInput(case_id=CASE, source_id=SOURCE_ID, sha256=FOREIGN_SHA)
    ) is False
    # A source of another case is not this case's, whatever it is called.
    assert resolver.validate_source_input(
        contract.SourceInput(case_id=OTHER_CASE, source_id=SOURCE_ID, sha256=SOURCE_SHA)
    ) is False
