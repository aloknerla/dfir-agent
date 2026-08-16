"""Binding the run's retained results to a registry the CALLER built.

The controlled console builds the executable registry itself, before the run
exists, because the palette and the oversight policy are derived from real
function names.  The run's retained results do not exist at that moment, so the
operations that consume an earlier result were left holding nothing: every
citation refused with "no lineage resolver is bound to this surface", which
reads like a policy decision and was a missing wire.  The model's answer was
then left to state a value it had decoded for itself, with no result to cite.

What is under test is the wire, driven through the production registry builder
and the production lineage store rather than a description of either.
"""

from __future__ import annotations

import pytest

from forensic_agent.agent.result_lineage import (
    CitationError,
    DeferredCitedValueResolver,
    ResultLineageStore,
)
from forensic_agent.agent.tool_registry import build_tools
from forensic_agent.core import result_contract as contract

CASE = "case-citation-binding"
SOURCE_SHA = "a" * 64
#: The value the citation names, encoded the way a capture would carry it.
#:
#: Synthetic, and deliberately so. This used to be the real archive password
#: from a competition task that is still running: the task is solved by finding
#: it, and a public repository is indexed. The decoder is exercised exactly the
#: same way by a made-up string, so the real one bought this test nothing and
#: cost the task its answer. The pair below is base64-consistent — change one
#: and you must change the other.
ENCODED = "RVhBTVBMRS1QVzE="
DECODED = "EXAMPLE-PW1"

_TSHARK = contract.UpstreamBackend(
    name="tshark", version="4.2.0", operation="network.dns_queries", role="producer"
)


def _retained_dns_result(invocation: str = "run:0004:e108c345d1ab"):
    """One complete standardized result of the shape a DNS listing produces."""

    provenance = contract.make_provenance(
        evidence_class=contract.EvidenceClass.OBSERVED,
        provenance_type=contract.ProvenanceType.CASE_EVIDENCE,
        derivation=None,
        invocation_id=invocation,
        case_id=CASE,
        source_id=f"evidence-sha256:{SOURCE_SHA}",
        source_sha256=SOURCE_SHA,
        artifact_locator="path:/evidence/promet.pcap",
        tool_name="pcap_query",
        tool_version="0.1",
        upstream_backends=(_TSHARK,),
        raw_output_sha256="c" * 64,
        oversight_entry_sha256="d" * 64,
        oversight_sequence=4,
    )
    result = contract.ok_result(
        data_type="network.dns_queries",
        provenance=provenance,
        items=[["1", "192.168.30.57", "192.168.22.1", f"{ENCODED}.evil.hr", "1"]],
    )
    return contract.attach_receipt(result)


def _transform_tool(slot, tmp_path):
    """The citing operation as the console builds it: registry first, run later."""

    tools = build_tools(
        None,
        capture=False,
        project=False,
        cited_value_resolver=slot,
    )
    by_name = {tool.name: tool for tool in tools}
    assert "transform_query" in by_name, "the citing operation must be on this palette"
    return by_name["transform_query"]


def _config_with_slot(slot):
    """The run's real frozen configuration, stating only what this wire reads."""

    import dataclasses

    from forensic_agent.agent.orchestration.state import InvestigationConfig

    required = {
        field.name: None
        for field in dataclasses.fields(InvestigationConfig)
        if field.default is dataclasses.MISSING
        and field.default_factory is dataclasses.MISSING
    }
    return InvestigationConfig(**{**required, "citation_resolver_slot": slot})


def _invoke(tool, retained):
    return tool.func(
        operation="base64",
        source_invocation_id=retained.provenance.invocation_id,
        source_payload_sha256=contract.payload_sha256(retained),
        source_field="data.items[0][3]",
    )


def test_an_unbound_slot_refuses_the_citation_it_cannot_resolve(tmp_path):
    """No run bound this surface, so the operation refuses rather than guesses."""

    tool = _transform_tool(DeferredCitedValueResolver(), tmp_path)
    outcome = _invoke(tool, _retained_dns_result())
    assert "no run has bound" in str(outcome)


def test_a_caller_built_registry_resolves_once_the_run_binds_its_results(tmp_path):
    """The console's own registry decodes a cited value after the run fills the slot.

    This is the defect the network run exposed: the citation named a field that
    really was in the retained result, and the transform refused anyway because
    the console's registry was built before the store existed and never received
    it.  The model then decoded the value itself, leaving the password it used
    with no result behind it.
    """

    slot = DeferredCitedValueResolver()
    tool = _transform_tool(slot, tmp_path)
    retained = _retained_dns_result()

    # Exactly what preparation does once the run's store exists.
    store = ResultLineageStore()
    store.record_complete_result("pcap_query", {"operation": "dns"}, retained.model_dump(mode="json"))
    slot.bind(store.cited_value)

    outcome = _invoke(tool, retained)
    assert DECODED in str(outcome)


def test_preparation_fills_the_slot_a_caller_handed_the_run(tmp_path):
    """The wire itself: the run's setup binds the slot its caller supplied.

    Without this step the console's registry and the console's run were two
    halves that never met, which is how a correctly cited field came back as
    "no lineage resolver is bound to this surface".
    """

    from forensic_agent.agent.orchestration.preparation import _bind_caller_citation_slot

    slot = DeferredCitedValueResolver()
    tool = _transform_tool(slot, tmp_path)
    retained = _retained_dns_result()
    store = ResultLineageStore()
    store.record_complete_result(
        "pcap_query", {"operation": "dns"}, retained.model_dump(mode="json")
    )

    _bind_caller_citation_slot(_config_with_slot(slot), store)

    assert slot.bound
    assert DECODED in str(_invoke(tool, retained))


def test_a_run_that_built_its_own_tools_needs_no_slot():
    """No slot is a legitimate configuration, not an omission to repair."""

    from forensic_agent.agent.orchestration.preparation import _bind_caller_citation_slot

    _bind_caller_citation_slot(_config_with_slot(None), ResultLineageStore())


def test_a_slot_belongs_to_one_run(tmp_path):
    """Rebinding is refused: a second run's results are not this surface's."""

    slot = DeferredCitedValueResolver()
    slot.bind(ResultLineageStore().cited_value)
    with pytest.raises(RuntimeError):
        slot.bind(ResultLineageStore().cited_value)


def test_an_unbound_slot_raises_a_citation_error_rather_than_a_bare_failure():
    """The refusal keeps the shape the surface already knows how to report."""

    with pytest.raises(CitationError):
        DeferredCitedValueResolver()("run:0001", "0" * 64, "data.items[0][0]")
