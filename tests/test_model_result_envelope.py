"""Oznaka isporuke stoji uz nalaz, a ne u njemu.

``result_ref`` je činjenica o isporuci — ovaj run je modelu predao ovaj dokument
— a ne činjenica o dokazu. Zato ne ulazi u forenzički rezultat: unutra bi ili
razbila receipt koji potvrđuje sadržaj, ili prisilila ponovno potpisivanje iz
razloga koji s opažanjem nema veze.

Omotnica nije dokaz. Nikad se ne prihvaća kao rezultat, ne ulazi u lineage, a
svaki čitatelj dokaza poseže kroz ``result`` do dokumenta koji to jest.
"""

from __future__ import annotations

import json

import pytest

from forensic_agent.agent.model_result_envelope import (
    MODEL_RESULT_SCHEMA_ID,
    envelope_reference,
    is_model_result_envelope,
    unwrap_result,
    wrap_for_model,
)
from forensic_agent.core.result_contract import (
    EvidenceClass,
    ProvenanceType,
    UpstreamBackend,
    attach_receipt,
    make_provenance,
    ok_result,
    verify_receipt,
)
from forensic_agent.core.result_reading import read_result, receipt_is_valid

_CASE = "case-env"


def _result_wire(**attributes) -> dict:
    provenance = make_provenance(
        evidence_class=EvidenceClass.OBSERVED,
        provenance_type=ProvenanceType.CASE_EVIDENCE,
        invocation_id="run:0001:aaaa",
        case_id=_CASE,
        source_id="evidence-1",
        artifact_locator="registry_query:registry_values",
        tool_name="registry_query",
        tool_version="0.1",
        upstream_backends=[
            UpstreamBackend(
                name="regipy",
                version="4.0.0",
                operation="registry_query.registry_values",
                role="producer",
            )
        ],
    )
    result = attach_receipt(
        ok_result(
            data_type="windows.registry_values",
            provenance=provenance,
            attributes=dict(attributes),
            items=[],
        )
    )
    return json.loads(result.model_dump_json())


def test_the_envelope_carries_the_name_and_the_result_untouched() -> None:
    """Omotnica nosi oznaku; nalaz ostaje bajt za bajt isti."""

    wire = _result_wire(product_name="Microsoft Windows XP")
    envelope = wrap_for_model(wire, result_ref="R001")

    assert envelope["schema_version"] == MODEL_RESULT_SCHEMA_ID
    assert envelope["result_ref"] == "R001"
    assert envelope["result"] == wire


def test_the_inner_receipt_still_verifies_after_wrapping() -> None:
    """Potpis nalaza mora preživjeti isporuku nedirnut."""

    wire = _result_wire(product_name="Microsoft Windows XP")
    envelope = wrap_for_model(wire, result_ref="R001")

    inner = unwrap_result(envelope)
    assert receipt_is_valid(read_result(inner))
    assert verify_receipt(read_result(inner))


def test_the_envelope_is_never_a_result() -> None:
    """Omotnica se ne smije čitati kao nalaz."""

    envelope = wrap_for_model(_result_wire(x="1"), result_ref="R001")

    assert is_model_result_envelope(envelope) is True
    # It declares its own schema, which is not the result contract's.
    assert envelope["schema_version"] != envelope["result"]["schema_version"]
    # And it carries no receipt of its own to be mistaken for one.
    assert "receipt" not in envelope
    assert "provenance" not in envelope


def test_every_reader_of_evidence_reaches_through_the_result() -> None:
    """Čitanje dokaza ide kroz ``result``, ne kroz omotnicu."""

    wire = _result_wire(product_name="XP")
    envelope = wrap_for_model(wire, result_ref="R001")

    assert unwrap_result(envelope) == wire
    # A bare result passes through unchanged, so one reader serves both shapes.
    assert unwrap_result(wire) == wire


def test_a_bare_result_is_not_mistaken_for_an_envelope() -> None:
    """Neomotani rezultat nije omotnica i nema oznaku isporuke."""

    wire = _result_wire(product_name="XP")

    assert is_model_result_envelope(wire) is False
    assert envelope_reference(wire) is None


def test_a_delivery_without_a_name_is_refused() -> None:
    """Isporuka bez oznake nema smisla i ne gradi se."""

    for empty in ("", "   ", None):
        with pytest.raises((ValueError, TypeError)):
            wrap_for_model(_result_wire(x="1"), result_ref=empty)  # type: ignore[arg-type]


def test_the_reference_is_read_only_from_a_real_envelope() -> None:
    """Oznaka se čita samo s onoga što jest omotnica."""

    assert envelope_reference(wrap_for_model(_result_wire(x="1"), result_ref="R007")) == "R007"
    assert envelope_reference({"schema_version": MODEL_RESULT_SCHEMA_ID}) is None
    assert envelope_reference("not a mapping") is None
