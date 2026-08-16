from forensic_agent.core.tool_result import (
    ProvenanceType,
    adapt_legacy_result,
    attach_receipt,
    make_provenance,
)
from forensic_agent.core.tool_result_view import (
    legacy_tool_result_view,
    tool_result_is_admissible_case_evidence,
    tool_result_is_error,
)


def _provenance():
    return make_provenance(
        provenance_type=ProvenanceType.CASE_EVIDENCE,
        invocation_id="case:1",
        source_id="disk",
        artifact_locator="path:/Downloads",
        tool_name="list_directory",
        tool_version="0.1.0",
    )


def test_directory_envelope_projects_to_legacy_entries_without_mutating_wire_shape():
    result = attach_receipt(adapt_legacy_result(
        {"path": "/Downloads", "entries": [{"name": "one.txt"}]},
        data_type="filesystem.directory_listing",
        provenance=_provenance(),
    ))
    wire = result.model_dump(mode="json")

    view = legacy_tool_result_view(wire)

    assert view["path"] == "/Downloads"
    assert view["entries"] == [{"name": "one.txt"}]
    assert "entries" not in wire["data"]["attributes"]
    assert tool_result_is_error(wire) is False


def test_error_field_presence_does_not_mark_successful_envelope_as_error():
    result = attach_receipt(adapt_legacy_result(
        {"rows": [{"event_id": 4624}]},
        data_type="windows.event_records",
        provenance=_provenance(),
    )).model_dump(mode="json")

    assert "error" in result and result["error"] is None
    assert tool_result_is_error(result) is False
    assert legacy_tool_result_view(result)["rows"] == [{"event_id": 4624}]


def test_admissibility_is_derived_from_validated_provenance_and_receipt():
    case_result = attach_receipt(adapt_legacy_result(
        {"rows": [{"value": "observed"}]},
        data_type="test.rows",
        provenance=_provenance(),
    )).model_dump(mode="json")
    assert tool_result_is_admissible_case_evidence(case_result) is True
    assert tool_result_is_admissible_case_evidence({"legacy": True}) is None

    case_result["data"]["items"][0]["value"] = "tampered"
    assert tool_result_is_admissible_case_evidence(case_result) is False
