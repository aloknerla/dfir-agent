"""Focused tests for the versioned forensic tool-result contract."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from forensic_agent.core.tool_result import (
    SCHEMA_ID,
    CoverageMetadata,
    PageMetadata,
    PageUnit,
    ProvenanceType,
    ToolData,
    ToolError,
    ToolProvenance,
    ToolResult,
    ToolStatus,
    ToolWarning,
    adapt_legacy_result,
    attach_receipt,
    canonical_raw_output_sha256,
    error_result,
    make_provenance,
    ok_result,
    partial_result,
    payload_sha256,
    to_mcp_tool_result,
    tool_result_output_schema,
    verify_receipt,
)


@pytest.fixture
def case_provenance() -> ToolProvenance:
    return make_provenance(
        provenance_type=ProvenanceType.CASE_EVIDENCE,
        invocation_id="inv-0001",
        case_id="case-42",
        source_id="disk-01",
        source_sha256="a" * 64,
        artifact_locator="/Users/Alice/Downloads",
        artifact_type="filesystem.directory",
        tool_name="list_directory",
        tool_version="1.2.3",
        parameters={"path": "/Users/Alice/Downloads", "limit": 2},
    )


def test_ok_result_has_versioned_typed_wire_shape(case_provenance: ToolProvenance):
    result = ok_result(
        data_type="filesystem.directory_listing",
        provenance=case_provenance,
        attributes={"path": "/Users/Alice/Downloads"},
        items=[{"name": "invoice.pdf", "size": 1234}],
    )

    wire = result.model_dump(mode="json")
    assert wire["schema_version"] == SCHEMA_ID
    assert wire["status"] == "ok"
    assert wire["data"] == {
        "type": "filesystem.directory_listing",
        "attributes": {"path": "/Users/Alice/Downloads"},
        "items": [{"name": "invoice.pdf", "size": 1234}],
    }
    assert wire["page"]["returned"] == 1
    assert wire["coverage"]["complete"] is True
    assert wire["provenance"]["type"] == "case_evidence"
    assert wire["provenance"]["admissible_as_case_evidence"] is True
    assert case_provenance.admissible_as_case_evidence is True


def test_page_truncation_does_not_mean_incomplete_coverage(case_provenance: ToolProvenance):
    result = ok_result(
        data_type="event.records",
        provenance=case_provenance,
        items=[{"event_id": 4624}, {"event_id": 4625}],
        page=PageMetadata(
            offset=0,
            returned=2,
            total=500,
            next_cursor="cursor-2",
            truncated=True,
        ),
    )

    assert result.status is ToolStatus.OK
    assert result.page.truncated is True
    assert result.coverage.complete is True


def test_byte_page_is_not_constrained_by_item_count(case_provenance: ToolProvenance):
    result = ok_result(
        data_type="filesystem.file_chunk",
        provenance=case_provenance,
        attributes={"content": "abcd"},
        page=PageMetadata(
            unit=PageUnit.BYTE,
            offset=4096,
            returned=4,
            total=8192,
            next_offset=4100,
            truncated=True,
        ),
    )

    assert result.data.items == []
    assert result.page.unit is PageUnit.BYTE
    assert result.page.returned == 4
    assert result.page.next_offset == 4100
    assert result.status is ToolStatus.OK


def test_partial_result_preserves_usable_rows(case_provenance: ToolProvenance):
    result = partial_result(
        data_type="filesystem.directory_listing",
        provenance=case_provenance,
        items=[{"name": "recovered.txt"}],
        coverage_reason="MFT entry 91 could not be parsed",
        warnings=[
            ToolWarning(
                code="mft_record_corrupt",
                message="One directory record was skipped",
                details={"inode": 91},
            )
        ],
    )

    assert result.status is ToolStatus.PARTIAL
    assert result.data.items == [{"name": "recovered.txt"}]
    assert result.coverage.complete is False
    assert result.error is None
    assert result.warnings[0].code == "mft_record_corrupt"


def test_error_result_has_structured_error_and_incomplete_coverage(
    case_provenance: ToolProvenance,
):
    result = error_result(
        data_type="registry.query",
        provenance=case_provenance,
        error=ToolError(
            code="hive_unreadable",
            message="The hive header is corrupt",
            retryable=False,
            details={"offset": 4096},
        ),
        coverage_reason="registry hive could not be opened",
    )

    assert result.status is ToolStatus.ERROR
    assert result.error is not None
    assert result.error.code == "hive_unreadable"
    assert result.coverage.complete is False


@pytest.mark.parametrize(
    ("status", "coverage", "error"),
    [
        (ToolStatus.OK, CoverageMetadata(complete=False, reason="broken"), None),
        (ToolStatus.PARTIAL, CoverageMetadata(complete=True), None),
        (ToolStatus.ERROR, CoverageMetadata(complete=False, reason="broken"), None),
    ],
)
def test_invalid_status_combinations_are_rejected(
    case_provenance: ToolProvenance,
    status: ToolStatus,
    coverage: CoverageMetadata,
    error: ToolError | None,
):
    with pytest.raises(ValidationError):
        ToolResult(
            status=status,
            data=ToolData(type="test"),
            coverage=coverage,
            error=error,
            provenance=case_provenance,
        )


def test_page_returned_must_match_item_count(case_provenance: ToolProvenance):
    with pytest.raises(ValidationError, match="page.returned"):
        ToolResult(
            status=ToolStatus.OK,
            data=ToolData(type="test", items=[{"id": 1}]),
            page=PageMetadata(returned=0),
            provenance=case_provenance,
        )


def test_reference_knowledge_is_explicitly_not_case_evidence():
    provenance = make_provenance(
        provenance_type=ProvenanceType.REFERENCE_KNOWLEDGE,
        invocation_id="lookup-1",
        source_id="forensic-artifacts-2026-01",
        source_sha256="b" * 64,
        artifact_locator="artifact://Windows/USBSTOR",
        artifact_type="reference.fragment",
        tool_name="lookup_artifact",
        tool_version="1.0.0",
    )

    assert provenance.type is ProvenanceType.REFERENCE_KNOWLEDGE
    assert provenance.admissible_as_case_evidence is False
    assert provenance.source.sha256 == "b" * 64
    assert provenance.artifact.locator == "artifact://Windows/USBSTOR"
    wire = provenance.model_dump(mode="json")
    assert wire["admissible_as_case_evidence"] is False


def test_provenance_rejects_inconsistent_admissibility(case_provenance: ToolProvenance):
    wire = case_provenance.model_dump(mode="json")
    wire["admissible_as_case_evidence"] = False

    with pytest.raises(ValidationError, match="admissible_as_case_evidence"):
        ToolProvenance.model_validate(wire)


def test_provenance_requires_complete_oversight_binding(case_provenance: ToolProvenance):
    wire = case_provenance.model_dump(mode="json")
    wire["raw_output_sha256"] = "b" * 64

    with pytest.raises(ValidationError, match="must be supplied together"):
        ToolProvenance.model_validate(wire)


def test_receipt_covers_canonical_raw_output_and_oversight_action_binding(
    case_provenance: ToolProvenance,
):
    raw_output = {"entries": [{"name": "invoice.pdf"}], "path": "/Downloads"}
    raw_output_sha256 = canonical_raw_output_sha256(raw_output)
    assert raw_output_sha256 == canonical_raw_output_sha256(
        {"path": "/Downloads", "entries": [{"name": "invoice.pdf"}]}
    )

    provenance_wire = case_provenance.model_dump(mode="json")
    provenance_wire.update(
        {
            "raw_output_sha256": raw_output_sha256,
            "oversight_entry_sha256": "c" * 64,
            "oversight_sequence": 7,
        }
    )
    provenance = ToolProvenance.model_validate(provenance_wire)
    receipt_verified = attach_receipt(
        ok_result(data_type="filesystem.entries", provenance=provenance)
    )
    assert verify_receipt(receipt_verified)

    tampered_wire = receipt_verified.model_dump(mode="json")
    tampered_wire["provenance"]["raw_output_sha256"] = "d" * 64
    tampered = ToolResult.model_validate(tampered_wire)
    assert not verify_receipt(tampered)


def test_receipt_is_canonical_and_detects_payload_mutation(case_provenance: ToolProvenance):
    first = ok_result(
        data_type="hash.lookup",
        provenance=case_provenance,
        attributes={"b": 2, "a": 1},
    )
    second = ok_result(
        data_type="hash.lookup",
        provenance=case_provenance,
        attributes={"a": 1, "b": 2},
    )

    assert payload_sha256(first) == payload_sha256(second)
    receipt_verified = attach_receipt(first)
    assert verify_receipt(receipt_verified) is True
    assert payload_sha256(receipt_verified) == payload_sha256(
        first
    )  # receipt is not self-hashed

    tampered_wire = receipt_verified.model_dump(mode="json")
    tampered_wire["data"]["attributes"]["a"] = 999
    tampered = ToolResult.model_validate(tampered_wire)
    assert verify_receipt(tampered) is False


def test_mcp_output_schema_is_generated_from_contract():
    schema = tool_result_output_schema()

    assert schema["type"] == "object"
    assert schema["properties"]["schema_version"]["const"] == SCHEMA_ID
    assert "ToolProvenance" in schema["$defs"]
    assert "data" in schema["required"]
    assert "provenance" in schema["required"]


def test_mcp_mapping_attaches_receipt_and_mirrors_structured_content(
    case_provenance: ToolProvenance,
):
    result = ok_result(
        data_type="filesystem.metadata",
        provenance=case_provenance,
        attributes={"name": "invoice.pdf", "size": 1234},
    )

    mapped = to_mcp_tool_result(result)
    structured = ToolResult.model_validate(mapped["structuredContent"])

    assert mapped["isError"] is False
    assert verify_receipt(structured) is True
    assert mapped["content"] == [
        {
            "type": "text",
            "text": json.dumps(
                mapped["structuredContent"],
                sort_keys=True,
                ensure_ascii=False,
                separators=(",", ":"),
            ),
        }
    ]


def test_mcp_is_error_only_for_error_status(case_provenance: ToolProvenance):
    partial = partial_result(
        data_type="filesystem.entries",
        provenance=case_provenance,
        coverage_reason="one MFT record was corrupt",
        items=[{"name": "usable.txt"}],
    )
    failed = error_result(
        data_type="filesystem.entries",
        provenance=case_provenance,
        coverage_reason="image could not be opened",
        error=ToolError(code="open_failed", message="image could not be opened"),
    )

    assert to_mcp_tool_result(partial)["isError"] is False
    assert to_mcp_tool_result(failed)["isError"] is True


def test_mcp_mapping_rejects_stale_receipt(case_provenance: ToolProvenance):
    receipt_verified = attach_receipt(
        ok_result(
            data_type="hash.lookup",
            provenance=case_provenance,
            attributes={"known": False},
        )
    )
    wire = receipt_verified.model_dump(mode="json")
    wire["data"]["attributes"]["known"] = True

    with pytest.raises(ValueError, match="receipt"):
        to_mcp_tool_result(wire)


def test_adapter_wraps_plain_list(case_provenance: ToolProvenance):
    result = adapt_legacy_result(
        [{"name": "a"}, {"name": "b"}],
        data_type="filesystem.entries",
        provenance=case_provenance,
    )

    assert result.status is ToolStatus.OK
    assert result.data.items == [{"name": "a"}, {"name": "b"}]
    assert result.page.returned == 2
    assert result.page.total == 2


def test_adapter_does_not_turn_paginated_result_into_partial_or_error(
    case_provenance: ToolProvenance,
):
    result = adapt_legacy_result(
        {
            "rows": [{"event_id": 4624}],
            "returned": 1,
            "total_matching": 100,
            "offset": 0,
            "truncated": True,
            "note": "99 more rows; request offset=1",
        },
        data_type="event.records",
        provenance=case_provenance,
    )

    assert result.status is ToolStatus.OK
    assert result.page.unit is PageUnit.ITEM
    assert result.page.truncated is True
    assert result.page.total == 100
    assert result.page.next_offset == 1
    assert result.coverage.complete is True
    assert result.error is None


def test_adapter_keeps_explicit_row_continuation_in_item_units(
    case_provenance: ToolProvenance,
):
    result = adapt_legacy_result(
        {
            "rows": [{"event_id": 4625}],
            "offset": 1,
            "total_matching": 3,
            "next_offset": 2,
            "truncated": True,
        },
        data_type="event.records",
        provenance=case_provenance,
    )

    assert result.page.unit is PageUnit.ITEM
    assert result.page.returned == 1
    assert result.page.next_offset == 2


def test_adapter_does_not_treat_bounded_values_as_missing_item_pages(
    case_provenance: ToolProvenance,
) -> None:
    result = adapt_legacy_result(
        {
            "rows": [{"PID": 3644, "__children": "bounded preview…[truncated]"}],
            "returned": 1,
            "total_matching": 1,
            "offset": 0,
            "truncated": True,
            "page_truncated": False,
            "note": "one or more returned values were truncated to fit the byte cap",
        },
        data_type="memory.plugin_records",
        provenance=case_provenance,
    )

    assert result.status is ToolStatus.OK
    assert result.coverage.complete is True
    assert result.page.returned == result.page.total == 1
    assert result.page.truncated is False
    assert result.page.next_offset is None
    assert {warning.code for warning in result.warnings} == {
        "legacy_content_truncation",
        "legacy_note",
    }


def test_adapter_accepts_legacy_bounded_complete_item_page(
    case_provenance: ToolProvenance,
) -> None:
    result = adapt_legacy_result(
        {
            "rows": [{"PID": 3644, "value": "bounded preview…[truncated]"}],
            "returned": 1,
            "total_matching": 1,
            "offset": 0,
            "truncated": True,
            "_bounded": True,
        },
        data_type="memory.plugin_records",
        provenance=case_provenance,
    )

    assert result.page.truncated is False
    assert result.page.next_offset is None
    assert {warning.code for warning in result.warnings} == {
        "legacy_content_truncation"
    }


def test_adapter_keeps_ambiguous_legacy_truncation_fail_closed(
    case_provenance: ToolProvenance,
) -> None:
    result = adapt_legacy_result(
        {
            "rows": [{"PID": 3644}],
            "returned": 1,
            "total_matching": 1,
            "offset": 0,
            "truncated": True,
        },
        data_type="memory.plugin_records",
        provenance=case_provenance,
    )

    assert result.page.truncated is True
    assert "legacy_content_truncation" not in {
        warning.code for warning in result.warnings
    }


def test_adapter_repairs_contradictory_explicit_page_metadata(
    case_provenance: ToolProvenance,
) -> None:
    result = adapt_legacy_result(
        {
            "rows": [{"PID": 3644}],
            "returned": 1,
            "total_matching": 2,
            "offset": 0,
            "next_offset": 1,
            "truncated": True,
            "page_truncated": False,
        },
        data_type="memory.plugin_records",
        provenance=case_provenance,
    )

    assert result.page.truncated is True
    assert result.page.next_offset == 1
    assert "legacy_page_metadata_conflict" in {
        warning.code for warning in result.warnings
    }


def test_adapter_maps_recovered_data_plus_error_to_partial(
    case_provenance: ToolProvenance,
):
    result = adapt_legacy_result(
        {
            "entries": [{"name": "good.txt"}],
            "error": "corrupt MFT record encountered after recovered entries",
        },
        data_type="filesystem.directory_listing",
        provenance=case_provenance,
    )

    assert result.status is ToolStatus.PARTIAL
    assert result.data.items == [{"name": "good.txt"}]
    assert result.error is None
    assert result.coverage.complete is False
    assert result.warnings[-1].code == "legacy_partial_error"


def test_adapter_maps_failure_without_data_to_error(case_provenance: ToolProvenance):
    result = adapt_legacy_result(
        {"ok": False, "status": "error", "error": {"message": "image is unreadable"}},
        data_type="disk.open",
        provenance=case_provenance,
    )

    assert result.status is ToolStatus.ERROR
    assert result.error is not None
    assert result.error.message == "image is unreadable"
    assert result.data.items == []


def test_adapter_does_not_mistake_error_context_for_recovered_evidence(
    case_provenance: ToolProvenance,
):
    result = adapt_legacy_result(
        {"log": "Security", "error": "EVTX parser unavailable"},
        data_type="windows.event_records",
        provenance=case_provenance,
    )

    assert result.status is ToolStatus.ERROR
    assert result.error is not None
    assert result.error.message == "EVTX parser unavailable"
    assert result.data.attributes == {"log": "Security"}


def test_adapter_honours_explicit_incomplete_coverage(case_provenance: ToolProvenance):
    result = adapt_legacy_result(
        {
            "hits": [{"path": "/one"}],
            "coverage": {
                "complete": False,
                "scope": "partition-2",
                "reason": "one directory could not be enumerated",
            },
        },
        data_type="search.hits",
        provenance=case_provenance,
    )

    assert result.status is ToolStatus.PARTIAL
    assert result.coverage.scope == "partition-2"
    assert result.coverage.reason == "one directory could not be enumerated"


def test_adapter_maps_byte_pagination_and_scan_incompleteness(
    case_provenance: ToolProvenance,
):
    result = adapt_legacy_result(
        {
            "content": "abcd",
            "offset": 256,
            "returned_bytes": 4,
            "total_bytes": 1024,
            "next_offset": 260,
            "truncated": True,
            "scan_complete": False,
        },
        data_type="filesystem.file_chunk",
        provenance=case_provenance,
    )

    assert result.page.unit is PageUnit.BYTE
    assert result.page.returned == 4
    assert result.page.next_offset == 260
    assert result.page.truncated is True
    assert result.status is ToolStatus.PARTIAL
    assert result.coverage.complete is False


def test_adapter_normalizes_non_json_legacy_values(case_provenance: ToolProvenance):
    when = datetime(2026, 7, 13, tzinfo=UTC)
    result = adapt_legacy_result(
        {"path": "/evidence", "observed_at": when},
        data_type="legacy.singleton",
        provenance=case_provenance,
    )

    assert result.data.attributes["observed_at"] == "2026-07-13 00:00:00+00:00"


def test_contract_rejects_unknown_wire_fields(case_provenance: ToolProvenance):
    with pytest.raises(ValidationError, match="Extra inputs"):
        ToolResult.model_validate(
            {
                "schema_version": SCHEMA_ID,
                "status": "ok",
                "data": {"type": "test", "attributes": {}, "items": []},
                "page": {
                    "offset": 0,
                    "returned": 0,
                    "total": None,
                    "next_cursor": None,
                    "truncated": False,
                },
                "coverage": {
                    "complete": True,
                    "scope": None,
                    "reason": None,
                    "examined": None,
                    "expected": None,
                },
                "warnings": [],
                "error": None,
                "provenance": case_provenance.model_dump(mode="json"),
                "unexpected": "field",
            }
        )
