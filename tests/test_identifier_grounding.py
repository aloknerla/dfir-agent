"""Nalaz smije imenovati samo identifikatore koje je neki alat doista vratio."""

from __future__ import annotations

from forensic_agent.agent.identifier_grounding import (
    check_identifier_grounding,
    report_identifiers,
)
from forensic_agent.core import tool_result as legacy

_CASE_ID = "synthetic-memory-case"
_ARGUMENTS = {"plugin": "pslist", "limit": 50, "offset": 0, "filter": None}


def _record(items: list[dict[str, object]], *, case_id: str = _CASE_ID) -> dict[str, object]:
    """One retained COMPLETE standardized result, receipted as the runtime does it.

    The gate verifies that receipt against the payload, so a fixture cannot state
    a digest it has not computed: an invented one is exactly what the check now
    refuses.  Production still emits the historical envelope, so that is what a
    retained record looks like here.
    """

    provenance = legacy.make_provenance(
        provenance_type=legacy.ProvenanceType.CASE_EVIDENCE,
        invocation_id="run:0001",
        case_id=case_id,
        source_id="memory-1",
        source_sha256="a" * 64,
        artifact_locator="/memory.raw",
        tool_name="memory_query",
        tool_version="0.1",
        parameters=_ARGUMENTS,
        raw_output_sha256="c" * 64,
        oversight_entry_sha256="d" * 64,
        oversight_sequence=7,
    )
    result = legacy.attach_receipt(
        legacy.ok_result(
            data_type="memory.plugin_records",
            provenance=provenance,
            items=list(items),
        )
    )
    return {
        "tool": "memory_query",
        "arguments": dict(_ARGUMENTS),
        "result": result.model_dump(mode="json"),
    }


def test_a_truncated_process_name_claim_is_withheld():
    """pslist truncates a name to 14 chars; a name completed to .exe is not grounded."""

    records = [_record([{"PID": 4242, "ImageFileName": "netagentsvc.ex"}])]

    allowed, metrics = check_identifier_grounding(
        "The netagentsvc.exe process observed in memory has PID 4242.",
        records,
        case_id=_CASE_ID,
    )

    assert allowed is False
    assert metrics["decision"] == "ungrounded_identifier_claim"
    assert metrics["ungrounded_identifiers"] == ["netagentsvc.exe"]


def test_the_same_name_is_accepted_once_a_tool_actually_returned_it():
    """pstree carries the full path, so the same claim becomes grounded."""

    records = [
        _record(
            [
                {
                    "PID": 4242,
                    "ImageFileName": "netagentsvc.ex",
                    "Audit": r"\Device\HarddiskVolume2\Windows\System32\netagentsvc.exe",
                }
            ]
        )
    ]

    allowed, metrics = check_identifier_grounding(
        "The netagentsvc.exe process observed in memory has PID 4242.",
        records,
        case_id=_CASE_ID,
    )

    assert allowed is True
    assert metrics["decision"] == "all_identifiers_grounded"
    assert metrics["identifiers_grounded"] == 1


def test_a_filename_suffix_does_not_ground_a_different_filename():
    records = [_record([{"ImageFileName": "notevil.exe"}])]

    allowed, metrics = check_identifier_grounding(
        "The evil.exe process was observed in memory.",
        records,
        case_id=_CASE_ID,
    )

    assert allowed is False
    assert metrics["ungrounded_identifiers"] == ["evil.exe"]


def test_a_short_digest_is_not_grounded_by_a_longer_digest_containing_it():
    digest_32 = "ab" * 16
    digest_64 = digest_32 + ("cd" * 16)
    records = [_record([{"SHA256": digest_64}])]

    allowed, metrics = check_identifier_grounding(
        f"The recorded digest is {digest_32}.",
        records,
        case_id=_CASE_ID,
    )

    assert allowed is False
    assert metrics["ungrounded_identifiers"] == [digest_32]


def test_exact_identifier_matching_remains_case_insensitive():
    records = [_record([{"ImageFileName": "EVIL.EXE"}])]

    allowed, metrics = check_identifier_grounding(
        "The evil.exe process was observed in memory.",
        records,
        case_id=_CASE_ID,
    )

    assert allowed is True
    assert metrics["decision"] == "all_identifiers_grounded"


def test_prose_without_identifiers_is_never_withheld():
    allowed, metrics = check_identifier_grounding(
        "The evidence does not establish which process was responsible.",
        [_record([{"PID": 4, "ImageFileName": "System"}])],
        case_id=_CASE_ID,
    )

    assert allowed is True
    assert metrics["decision"] == "no_identifier_claims"
    assert metrics["activated"] is False


def test_an_address_from_another_case_does_not_ground_this_report():
    records = [_record([{"ForeignAddr": "203.78.103.109"}], case_id="other-case")]

    allowed, metrics = check_identifier_grounding(
        "The host contacted 203.78.103.109.",
        records,
        case_id=_CASE_ID,
    )

    assert allowed is False
    assert metrics["ungrounded_identifiers"] == ["203.78.103.109"]


def test_a_result_without_a_receipt_cannot_ground_a_claim():
    record = _record([{"ForeignAddr": "203.78.103.109"}])
    record["result"].pop("receipt")

    allowed, _metrics = check_identifier_grounding(
        "The host contacted 203.78.103.109.",
        [record],
        case_id=_CASE_ID,
    )

    assert allowed is False


def test_identifier_extraction_covers_the_shapes_a_tool_must_supply():
    found = report_identifiers(
        "svchost.exe and driver.sys contacted 10.42.85.10; hash "
        f"{'ab' * 32} was recorded. Microsoft.Acti is a truncated name."
    )

    assert "svchost.exe" in found
    assert "driver.sys" in found
    assert "10.42.85.10" in found
    assert "ab" * 32 in found
    # A truncated process name has no known extension and is not an identifier
    # shape, so it is left to the evidence-correlation gates instead.
    assert "microsoft.acti" not in found


def test_a_record_without_provenance_cannot_ground_a_scoped_claim():
    record = _record([{"ForeignAddr": "203.78.103.109"}])
    record["result"].pop("provenance")

    allowed, _metrics = check_identifier_grounding(
        "The host contacted 203.78.103.109.",
        [record],
        case_id=_CASE_ID,
    )

    assert allowed is False


def test_an_exotic_record_value_never_crashes_finalization():
    """Serialization must not raise, and an unserializable record grounds nothing.

    A value that cannot be canonicalized is not covered by the record's receipt
    either, so the record can no longer stand behind the address it contains.
    Withholding the report is the fail-closed outcome; crashing finalization is
    still never one.
    """

    record = _record([{"ForeignAddr": "203.78.103.109"}])
    record["result"]["data"]["items"][0]["blob"] = object()

    allowed, metrics = check_identifier_grounding(
        "The host contacted 203.78.103.109.",
        [record],
        case_id=_CASE_ID,
    )

    assert allowed is False
    assert metrics["decision"] == "ungrounded_identifier_claim"
