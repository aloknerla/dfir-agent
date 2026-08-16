"""Every production reader accepts BOTH result contracts, before any emitter switches.

Production still emits the historical envelope; these tests prove that a reader
handed a result of the active contract keeps the same verdict it reaches for the
historical one, and that a record claiming an envelope this build cannot read is
refused where a caller can see it rather than being quietly dropped.

Each test carries its own "bites" assertion: the same input read under the single
contract each reader used before, showing what would have been discarded.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from forensic_agent.agent.draft_citations import (
    cited_value_tokens,
    select_cited_value_tokens,
)
from forensic_agent.agent.recovery.common import _validated_continuation_result
from forensic_agent.agent.tool_bindings.output_guard import project_for_model
from forensic_agent.agent.verifier_projection import (
    _VERIFIER_RESULT_LIMIT_BYTES,
    _VERIFIER_TOTAL_LIMIT_BYTES,
    _compact_verifier_evidence,
)
from forensic_agent.agent.verifier_projection_values import _text_contains_token
from forensic_agent.core import result_contract as contract
from forensic_agent.core import tool_result as legacy
from forensic_agent.core.repro import canonical_json, sha256_hex
from forensic_agent.core.result_reading import (
    UnreadableResult,
    claims_result_envelope,
    is_candidate_case_evidence,
    read_result,
    receipt_is_valid,
)
from forensic_agent.core.tool_result_view import (
    legacy_tool_result_view,
    tool_result_is_admissible_case_evidence,
    tool_result_is_error,
)
from forensic_agent.core.toolio import MAX_TOTAL_BYTES, bound
from forensic_agent.oversight import enforce
from forensic_agent.oversight.core import OversightGate, OversightLog, Policy
from forensic_agent.oversight.enforcement import _is_deterministic_tool_error
from forensic_agent.reliability.verify import collect_evidence
from forensic_agent.reporting.trace_record import controlled_run_trace_record

CASE = "case-1"

# Versions this repository's own environment reports for the components a
# ``list_directory`` call really runs through.  The contract refuses a
# placeholder version, so a fixture must state a real one rather than invent it.
_DFVFS = contract.UpstreamBackend(
    name="dfvfs", version="20260731", operation="filesystem.list_directory", role="producer"
)
_PYEWF = contract.UpstreamBackend(
    name="pyewf", version="20240506", operation="storage_media.ewf_read", role="support"
)


# --- fixtures: the same finding, expressed under each contract ----------------


def _legacy_provenance(
    *, tool="list_directory", reference=False, arguments=None, entry="d" * 64, sequence=7
):
    provenance_type = (
        legacy.ProvenanceType.REFERENCE_KNOWLEDGE
        if reference
        else legacy.ProvenanceType.CASE_EVIDENCE
    )
    return legacy.make_provenance(
        provenance_type=provenance_type,
        invocation_id="run:0001",
        case_id=CASE,
        source_id="bundled-procedural-reference" if reference else "disk-1",
        source_sha256=None if reference else "a" * 64,
        artifact_locator="/x",
        tool_name=tool,
        tool_version="0.1",
        parameters=arguments,
        raw_output_sha256="c" * 64,
        oversight_entry_sha256=entry,
        oversight_sequence=sequence,
    )


def _legacy_wire(
    *,
    attributes=None,
    items=None,
    tool="list_directory",
    reference=False,
    arguments=None,
    **binding,
):
    result = legacy.ok_result(
        data_type="filesystem.directory_listing",
        provenance=_legacy_provenance(
            tool=tool, reference=reference, arguments=arguments, **binding
        ),
        attributes=attributes,
        items=list(items or [{"name": "one.txt"}]),
    )
    return legacy.attach_receipt(result).model_dump(mode="json")


def _active_provenance(
    *,
    evidence_class="observed",
    derivation=None,
    tool="list_directory",
    backends=(_DFVFS, _PYEWF),
    entry="d" * 64,
    sequence=7,
):
    provenance_type = (
        contract.ProvenanceType.REFERENCE_KNOWLEDGE
        if evidence_class == "reference"
        else contract.ProvenanceType.CASE_EVIDENCE
    )
    return contract.make_provenance(
        evidence_class=evidence_class,
        provenance_type=provenance_type,
        derivation=derivation,
        invocation_id="run:0001",
        case_id=CASE,
        source_id="bundled-procedural-reference" if evidence_class == "reference" else "disk-1",
        source_sha256=None if evidence_class == "reference" else "a" * 64,
        artifact_locator="/x",
        tool_name=tool,
        tool_version="0.1",
        upstream_backends=backends,
        raw_output_sha256="c" * 64,
        oversight_entry_sha256=entry,
        oversight_sequence=sequence,
    )


def _active_wire(
    *, items=None, provenance=None, data_type="filesystem.directory_listing", **binding
):
    result = contract.ok_result(
        data_type=data_type,
        provenance=provenance or _active_provenance(**binding),
        items=list(items or [{"name": "one.txt"}]),
    )
    return contract.attach_receipt(result).model_dump(mode="json")


def _active_reference_wire():
    return _active_wire(
        provenance=_active_provenance(
            evidence_class="reference", tool="lookup_artifact", backends=()
        ),
        data_type="reference.artifact_locations",
    )


def _active_error_wire():
    result = contract.error_result(
        data_type="filesystem.directory_listing",
        provenance=_active_provenance(),
        error=contract.ToolError(code="denied", message="the parser refused the image"),
        coverage_reason="the parser never opened the source",
    )
    return contract.attach_receipt(result).model_dump(mode="json")


def _active_derived_wire(*, arguments, tool="evidence_file_hash"):
    """A DERIVED result whose redaction-safe parameters ARE the call arguments.

    ``make_provenance`` derives ``tool.parameters_sha256`` from
    ``derivation.parameters`` alone, so this is the shape whose argument digest a
    continuation gate can bind.  See the report note on OBSERVED results, which
    carry no parameters digest at all under the active contract.
    """

    derivation = contract.DerivationMetadata(
        method="hash.sha256",
        method_version="1",
        derivation_inputs=[contract.SourceInput(case_id=CASE, source_id="disk-1", sha256="a" * 64)],
        parameters=dict(arguments),
    )
    return _active_wire(
        provenance=_active_provenance(
            evidence_class="derived",
            derivation=derivation,
            tool=tool,
            backends=(_DFVFS,),
        ),
        data_type="filesystem.file_hash",
    )


def _unreadable_envelope():
    """A record that claims one of our envelopes under a version we cannot read."""

    wire = _active_wire()
    return {**wire, "schema_version": "forensic.tool-result.v9"}


def _tampered(wire):
    tampered = json.loads(json.dumps(wire))
    tampered["data"]["items"][0]["name"] = "tampered.txt"
    return tampered


class _RunLineage:
    """Stand-in for the runtime authority the final check consults.

    Attests the audit binding of exactly the results it was built from, plus this
    case's one attested source.  The final check refuses a result of the active
    contract without such a resolver, so a stage-1 reader test that wants to see
    an active result travel all the way through has to supply one; the refusals
    themselves are pinned in ``tests/test_final_check.py``.
    """

    def __init__(self, wires=()):
        results = [contract.ToolResult.model_validate(wire) for wire in wires]
        self._records = {
            result.provenance.invocation_id: contract.audit_binding_record(result)
            for result in results
        }

    def validate_audit_binding(self, result):
        record = self._records.get(result.provenance.invocation_id)
        return record is not None and contract.audit_binding_record(result) == record

    def validate_source_input(self, source):
        return (source.case_id, source.source_id, source.sha256) == (CASE, "disk-1", "a" * 64)

    def validate_result_input(self, parent, *, current_invocation_id):
        return False


# --- the recognition seam -----------------------------------------------------


def test_the_seam_reads_both_contracts_and_refuses_everything_else() -> None:
    """Recognition is by the declared version, and an unknown one is not a shrug."""

    assert isinstance(read_result(_legacy_wire()), legacy.ToolResult)
    assert isinstance(read_result(_active_wire()), contract.ToolResult)

    with pytest.raises(UnreadableResult, match="forensic.tool-result.v9"):
        read_result(_unreadable_envelope())
    with pytest.raises(UnreadableResult):
        read_result({"rows": [{"name": "one.txt"}]})
    with pytest.raises(UnreadableResult):
        read_result({"schema_version": contract.SCHEMA_ID, "data": "not-a-mapping"})

    # BITES: the single-contract reader every caller used before really does
    # reject the active envelope outright, so accepting it is not a no-op.
    with pytest.raises(ValidationError):
        legacy.ToolResult.model_validate(_active_wire())
    with pytest.raises(ValidationError):
        contract.ToolResult.model_validate(_legacy_wire())

    # An unknown version still declares itself one of ours: a caller must be able
    # to tell "a result I cannot read" from "never a result".
    assert claims_result_envelope(_unreadable_envelope()) is True
    assert claims_result_envelope({"rows": []}) is False


def test_receipt_and_case_evidence_flags_are_answered_per_contract() -> None:
    """Each contract verifies its own payload, and both spell the same flag."""

    for wire in (_legacy_wire(), _active_wire()):
        result = read_result(wire)
        assert receipt_is_valid(result) is True
        assert is_candidate_case_evidence(result) is True
        assert receipt_is_valid(read_result(_tampered(wire))) is False

    assert is_candidate_case_evidence(read_result(_active_reference_wire())) is False
    assert is_candidate_case_evidence(read_result(_legacy_wire(reference=True))) is False

    # BITES: the flag is not the same attribute in both, so a reader that simply
    # kept reading ``admissible_as_case_evidence`` would raise on the active one.
    assert not hasattr(read_result(_active_wire()).provenance, "admissible_as_case_evidence")
    assert not hasattr(read_result(_legacy_wire()).provenance, "candidate_case_evidence")


# --- the admissibility gate ---------------------------------------------------


def test_the_admissibility_gate_answers_for_both_and_never_defers_on_an_unreadable_record() -> None:
    """``None`` means "apply your own policy"; an unreadable result must not get it."""

    assert tool_result_is_admissible_case_evidence(_legacy_wire()) is True
    assert tool_result_is_admissible_case_evidence(_active_wire()) is True

    assert tool_result_is_admissible_case_evidence(_active_reference_wire()) is False
    assert tool_result_is_admissible_case_evidence(_active_error_wire()) is False
    assert tool_result_is_admissible_case_evidence(_tampered(_active_wire())) is False
    assert tool_result_is_admissible_case_evidence(_tampered(_legacy_wire())) is False

    # The documented hazard: an envelope this build cannot read used to answer
    # ``None``, which invites the caller to fall back to its own legacy policy and
    # admit an unverified record.  It now fails closed, explicitly.
    assert tool_result_is_admissible_case_evidence(_unreadable_envelope()) is False

    # A value that never claimed to be a result keeps deferring, as before.
    assert tool_result_is_admissible_case_evidence({"legacy": True}) is None
    assert tool_result_is_admissible_case_evidence("plain tool text") is None

    # BITES: the gate reads the JSON form too, so a serialized active result is
    # judged rather than mistaken for free text.
    assert tool_result_is_admissible_case_evidence(canonical_json(_active_wire())) is True


def test_the_legacy_view_projects_both_contracts_and_refuses_an_unreadable_envelope() -> None:
    for wire in (_legacy_wire(), _active_wire()):
        view = legacy_tool_result_view(wire)
        assert view["entries"] == [{"name": "one.txt"}]
        assert view["coverage_complete"] is True
        assert tool_result_is_error(wire) is False

    assert tool_result_is_error(_active_error_wire()) is True

    with pytest.raises(UnreadableResult, match="forensic.tool-result.v9"):
        legacy_tool_result_view(_unreadable_envelope())
    with pytest.raises(UnreadableResult, match="forensic.tool-result.v9"):
        tool_result_is_error(_unreadable_envelope())

    # BITES: a pre-envelope value is still passed through untouched, so the
    # refusal is about the CLAIM and not about every unfamiliar mapping.
    assert legacy_tool_result_view({"rows": [1]}) == {"rows": [1]}


# --- the verifier's evidence collection ---------------------------------------


def _tool_message(wire):
    return {"role": "tool", "content": canonical_json(wire)}


def test_verifier_evidence_collection_gates_both_contracts() -> None:
    active = _active_wire(items=[{"name": "active.txt"}])
    collected = collect_evidence(
        [
            _tool_message(_legacy_wire()),
            _tool_message(active),
            _tool_message(_active_reference_wire()),
            _tool_message(_active_error_wire()),
            {"role": "tool", "content": "plain legacy tool text"},
        ],
        lineage=_RunLineage([active]),
        active_case_id=CASE,
    )

    assert "one.txt" in collected
    assert "active.txt" in collected
    assert "reference.artifact_locations" not in collected
    assert "the parser refused the image" not in collected
    assert "plain legacy tool text" in collected

    # BITES: an unreadable envelope is dropped rather than forwarded as raw text,
    # which is what the previous "not my schema, pass it through" branch did.
    assert collect_evidence([_tool_message(_unreadable_envelope())]) == ""


def test_the_verifier_projection_bundles_an_active_result_and_counts_an_unreadable_one() -> None:
    active = _active_wire(items=[{"name": "active.txt"}])
    evidence, metrics = _compact_verifier_evidence(
        [_tool_message(active)],
        lineage=_RunLineage([active]),
        active_case_id=CASE,
    )

    # BITES: this whole bundle was empty before the projection read the active
    # contract — the result was counted as invalid and silently left out.
    assert metrics["results_seen"] == 1
    assert metrics["receipt_valid_case_results"] == 1
    assert metrics["usable_case_results"] == 1
    assert metrics["included_results"] == 1
    assert metrics["rejected_invalid_or_unreceipted"] == 0
    assert "active.txt" in evidence

    _unreadable, refused = _compact_verifier_evidence([_tool_message(_unreadable_envelope())])
    assert refused["rejected_invalid_or_unreceipted"] == 1
    assert refused["included_results"] == 0
    # The frozen accounting identity the runtime-fairness control checks must
    # still balance, so no new counter may appear to carry this refusal.
    assert refused["results_seen"] == (
        refused["rejected_invalid_or_unreceipted"]
        + refused["rejected_non_case_evidence"]
        + refused["receipt_valid_case_results"]
    )


def test_verifier_projection_retains_a_draft_cited_numeric_offset() -> None:
    cited_offset = "2052195216"
    items = [
        {
            "offset": str(700_000_000 + index),
            "match": f"decoy-{index}",
            "context": "x" * 180,
        }
        for index in range(120)
    ]
    items[113] = {
        "offset": cited_offset,
        "match": "POST /submit.php?id=544313186 HTTP/1.1",
        "context": "Host: 198.51.100.33",
    }
    active = _active_wire(items=items)

    evidence, metrics = _compact_verifier_evidence(
        [_tool_message(active)],
        focus_text=(f"POST /submit.php?id=544313186 was observed at offset {cited_offset}."),
        lineage=_RunLineage([active]),
        active_case_id=CASE,
    )

    assert metrics["per_result_truncated_count"] == 1
    assert cited_offset in evidence
    assert "POST /submit.php?id=544313186 HTTP/1.1" in evidence


def test_cited_value_extraction_recognizes_plain_and_composite_offsets() -> None:
    assert cited_value_tokens(
        "Offsets 2052195216 and 598631936-GZIP-1450 contain the reported values."
    ) == ("2052195216", "598631936-gzip-1450")


def test_cited_value_extraction_recognizes_bare_literal_answers_without_generic_words() -> None:
    assert cited_value_tokens("savedreport") == ("savedreport",)
    assert cited_value_tokens("The file name is savedreport.") == ("savedreport",)
    assert cited_value_tokens("The analysis recovered an ordinary browser history entry.") == ()


_FILENAME_QUESTION = "Yahoo webmail stores a saved copy of a viewed message under what file name?"


@pytest.mark.parametrize(
    "answer",
    (
        "The saved message was stored as savedreport.",
        "The saved message was saved as savedreport.",
        "savedreport is the file name.",
        "It was saved as savedreport and stored as savedreport.",
    ),
)
def test_singular_filename_question_retains_one_unqualified_bare_value(answer: str) -> None:
    assert cited_value_tokens(answer, question=_FILENAME_QUESTION) == ("savedreport",)


@pytest.mark.parametrize(
    ("question", "answer"),
    (
        (None, "The saved message was stored as savedreport."),
        ("What did Yahoo webmail store?", "The saved message was stored as savedreport."),
        ("What file names were used?", "The saved message was stored as savedreport."),
        ("Which file name or path was used?", "The saved message was stored as savedreport."),
        (_FILENAME_QUESTION, "It might be called savedreport."),
        (_FILENAME_QUESTION, "It was probably named savedreport."),
        (_FILENAME_QUESTION, "The file name is likely savedreport."),
        (_FILENAME_QUESTION, "It was saved as savedreport or draftreport."),
        (
            _FILENAME_QUESTION,
            "The file name is savedreport and it was stored as draftreport.",
        ),
        (_FILENAME_QUESTION, "It was saved as unknown."),
    ),
)
def test_bare_filename_retention_rejects_non_filename_or_qualified_answers(
    question: str | None,
    answer: str,
) -> None:
    assert cited_value_tokens(answer, question=question) == ()


def test_the_question_itself_never_becomes_a_cited_value() -> None:
    question = "Which file name corresponds to WS-EXAMPLE-07?"
    text = f"{question}\nThe saved message was stored as savedreport."

    assert cited_value_tokens(text, question=question) == ("savedreport",)


def test_bare_literal_cited_outside_the_ordinary_source_sample_is_promoted() -> None:
    items = [{"filename": f"decoy{index}"} for index in range(1_025)]
    items[513] = {"filename": "savedreport"}

    evidence, metrics = _compact_verifier_evidence(
        [_tool_message(_legacy_wire(items=items))],
        focus_text="The file name is savedreport.",
        citation_text="The file name is savedreport.",
    )

    assert "savedreport" in evidence
    assert metrics["source_cited_token_count"] == 1
    assert metrics["retained_cited_token_count"] == 1
    assert metrics["omitted_cited_token_count"] == 0


def test_question_aware_filename_literal_outside_the_source_sample_is_promoted() -> None:
    items = [{"filename": f"decoy{index}"} for index in range(1_025)]
    items[997] = {"filename": "savedreport"}
    answer = "The viewed message was stored as savedreport."

    evidence, metrics = _compact_verifier_evidence(
        [_tool_message(_legacy_wire(items=items))],
        focus_text=f"{_FILENAME_QUESTION}\n{answer}",
        citation_text=answer,
        question_text=_FILENAME_QUESTION,
    )

    assert "savedreport" in evidence
    assert metrics["source_cited_token_count"] == 1
    assert metrics["retained_cited_token_count"] == 1
    assert metrics["omitted_cited_token_count"] == 0


def test_cited_value_extraction_reports_more_than_sixty_four_values() -> None:
    tokens, overflow = select_cited_value_tokens(
        " ".join(str(700_000 + index) for index in range(65))
    )

    assert len(tokens) == 64
    assert overflow is True


def test_numeric_cited_token_requires_exact_alphanumeric_boundaries() -> None:
    token = "2052195216"

    assert _text_contains_token('{"offset":2052195216}', token)
    assert not _text_contains_token('{"offset":120521952160}', token)
    assert not _text_contains_token('{"offset":20521952160}', token)


def test_cited_item_outside_the_ordinary_source_sample_is_promoted() -> None:
    cited_offset = "2052195216"
    items = [
        {"offset": str(700_000_000 + index), "value": f"decoy-{index}"} for index in range(1_025)
    ]
    items[513] = {"offset": cited_offset, "value": "target"}

    evidence, metrics = _compact_verifier_evidence(
        [_tool_message(_legacy_wire(items=items))],
        focus_text=f"The target appears at offset {cited_offset}.",
        citation_text=f"The target appears at offset {cited_offset}.",
    )

    assert cited_offset in evidence
    assert metrics["source_cited_token_count"] == 1
    assert metrics["retained_cited_token_count"] == 1
    assert metrics["omitted_cited_token_count"] == 0


def test_repeated_cited_token_does_not_displace_a_distinct_late_token() -> None:
    repeated = "evidence.exe"
    late_offset = "2052195216"
    items = [{"name": repeated, "offset": str(700_000_000 + index)} for index in range(1_025)]
    items[777] = {"name": "target.bin", "offset": late_offset}

    evidence, metrics = _compact_verifier_evidence(
        [_tool_message(_legacy_wire(items=items))],
        focus_text=f"{repeated} and offset {late_offset} were observed.",
        citation_text=f"{repeated} and offset {late_offset} were observed.",
    )

    assert repeated in evidence
    assert late_offset in evidence
    assert metrics["source_cited_token_count"] == 2
    assert metrics["retained_cited_token_count"] == 2
    assert metrics["omitted_cited_token_count"] == 0


def test_cited_attribute_key_survives_final_projection_shedding() -> None:
    cited_name = "evidence.exe"
    # Enough uncited bulk to overflow the per-result ceiling, whatever it is,
    # so the projection must shed attributes and the cited key must survive it.
    uncited_key_count = 2 * _VERIFIER_RESULT_LIMIT_BYTES // 700
    long_uncited_keys = {
        f"{'x' * 700}-{index}": "uncited" for index in range(uncited_key_count)
    }

    evidence, metrics = _compact_verifier_evidence(
        [
            _tool_message(
                _legacy_wire(
                    attributes={cited_name: "present", **long_uncited_keys},
                    items=[],
                )
            )
        ],
        focus_text=f"The recovered name is {cited_name}.",
        citation_text=f"The recovered name is {cited_name}.",
    )

    assert f'"{cited_name}":"present"' in evidence
    assert metrics["omitted_attribute_count"] > 0
    assert metrics["source_cited_token_count"] == 1
    assert metrics["retained_cited_token_count"] == 1
    assert metrics["omitted_cited_token_count"] == 0
    assert len(evidence.encode("utf-8")) <= _VERIFIER_TOTAL_LIMIT_BYTES


def test_unavoidable_oversized_cited_attribute_is_reported_as_lost() -> None:
    cited_offset = "2052195216"
    # One attribute value bigger than the whole per-result ceiling, so no
    # packing strategy can retain the cited token it carries.
    oversized_field_count = 2 * _VERIFIER_RESULT_LIMIT_BYTES // 2_048
    oversized_value = {
        "offset": cited_offset,
        **{f"field-{index}": "x" * 2_048 for index in range(oversized_field_count)},
    }

    evidence, metrics = _compact_verifier_evidence(
        [
            _tool_message(
                _legacy_wire(
                    attributes={"oversized": oversized_value},
                    items=[],
                )
            )
        ],
        focus_text=f"The target offset is {cited_offset}.",
        citation_text=f"The target offset is {cited_offset}.",
    )

    assert cited_offset not in evidence
    assert metrics["source_cited_token_count"] == 1
    assert metrics["retained_cited_token_count"] == 0
    assert metrics["omitted_cited_token_count"] == 1


def test_twenty_result_bundle_keeps_every_draft_cited_offset() -> None:
    cited_offsets = tuple(str(900_000_000 + index * 1_000_003) for index in range(15))
    # Each result is built to roughly double its even share of the total, so the
    # packer must shorten every one of them regardless of the configured caps.
    even_share = _VERIFIER_TOTAL_LIMIT_BYTES // 20
    context_length = max(120, (2 * even_share) // 60)
    messages = []
    for result_index in range(20):
        items = [
            {
                "offset": str(600_000_000 + result_index * 10_000 + item_index),
                "match": f"decoy-{result_index}-{item_index}",
                "context": "x" * context_length,
            }
            for item_index in range(60)
        ]
        if result_index < len(cited_offsets):
            items[53] = {
                "offset": cited_offsets[result_index],
                "match": f"reported-value-{result_index}",
                "context": "visible support",
            }
        messages.append(_tool_message(_legacy_wire(items=items)))

    evidence, metrics = _compact_verifier_evidence(
        messages,
        focus_text="The reported offsets are " + ", ".join(cited_offsets) + ".",
    )

    assert metrics["included_results"] == 20
    assert metrics["bundle_omitted_result_count"] == 0
    assert metrics["per_result_truncated_count"] > 0
    assert all(offset in evidence for offset in cited_offsets)
    assert metrics["source_cited_token_count"] == len(cited_offsets)
    assert metrics["retained_cited_token_count"] == len(cited_offsets)
    assert metrics["omitted_cited_token_count"] == 0
    assert len(evidence.encode("utf-8")) <= _VERIFIER_TOTAL_LIMIT_BYTES


# --- deterministic recovery ---------------------------------------------------


def _continuation_record(wire, *, tool, arguments):
    return {"tool": tool, "arguments": dict(arguments), "result": wire}


def test_continuation_records_are_validated_under_both_contracts() -> None:
    arguments = {"path": "/Downloads"}

    historical = _continuation_record(
        _legacy_wire(arguments=arguments), tool="list_directory", arguments=arguments
    )
    assert _validated_continuation_result(historical) is not None

    active = _continuation_record(
        _active_derived_wire(arguments=arguments),
        tool="evidence_file_hash",
        arguments=arguments,
    )
    validated = _validated_continuation_result(active)
    assert validated is not None
    assert validated.provenance.tool.parameters_sha256 == sha256_hex(canonical_json(arguments))

    # Reference material is control guidance, never a continuation source.
    assert (
        _validated_continuation_result(
            _continuation_record(_active_reference_wire(), tool="lookup_artifact", arguments={})
        )
        is None
    )
    # A record whose payload no longer matches its receipt stays rejected.
    tampered = _continuation_record(
        _tampered(_active_derived_wire(arguments=arguments)),
        tool="evidence_file_hash",
        arguments=arguments,
    )
    assert _validated_continuation_result(tampered) is None
    # BITES: an envelope this build cannot read is rejected, not trusted as
    # executable control data.
    assert (
        _validated_continuation_result(
            _continuation_record(_unreadable_envelope(), tool="list_directory", arguments=arguments)
        )
        is None
    )


# --- the model-visible projection ---------------------------------------------


def _oversized_active_wire():
    filler = "x" * 400
    items = [{"name": f"{index:04d}-{filler}"} for index in range(120)]
    return _active_wire(items=items)


def test_the_model_projection_preserves_an_active_envelope() -> None:
    small = _active_wire()
    assert project_for_model(small, boundary=bound) == small

    oversized = _oversized_active_wire()
    assert len(canonical_json(oversized).encode("utf-8")) > MAX_TOTAL_BYTES

    # BITES: the generic byte boundary — the branch an unrecognised envelope falls
    # into — destroys exactly the fields that made the document evidence.
    generic = bound(oversized, max_bytes=MAX_TOTAL_BYTES)
    assert not isinstance(generic.get("provenance"), dict)

    projected = project_for_model(oversized, boundary=bound)
    assert projected["schema_version"] == contract.SCHEMA_ID
    assert projected["provenance"]["evidence_class"] == "observed"
    assert len(canonical_json(projected).encode("utf-8")) <= MAX_TOTAL_BYTES
    assert projected["data"]["attributes"]["projection_truncated"] is True
    # The shortened view is a different artifact and carries its OWN receipt,
    # computed by the contract it belongs to.
    assert projected["receipt"]["payload_sha256"] != oversized["receipt"]["payload_sha256"]
    assert receipt_is_valid(read_result(projected)) is True

    # An active result whose receipt does not match its payload is never
    # forwarded and never re-signed.
    refused = project_for_model(_tampered(_active_wire()), boundary=bound)
    assert refused["error"] == "unverified tool result was not projected"
    assert "schema_version" not in refused

    unreadable = project_for_model(_unreadable_envelope(), boundary=bound)
    assert unreadable["projection_failed"] is True
    assert "forensic.tool-result.v9" in unreadable["projection_note"]
    assert "schema_version" not in unreadable


# --- oversight ----------------------------------------------------------------


def _gate(tmp_path):
    gate = OversightGate(Policy.permissive(), OversightLog(str(tmp_path / "oversight.jsonl")))
    gate.recorder.open_case(question="q", policy=gate.policy)
    return gate


def test_oversight_keeps_every_declared_envelope_json_native_under_spotlighting(tmp_path) -> None:
    gate = _gate(tmp_path)

    for wire in (_legacy_wire(), _active_wire(), _unreadable_envelope()):
        published = enforce(
            gate, "list_directory", {"p": wire["schema_version"]}, lambda w=wire: w, spotlight=True
        )
        # BITES: text-wrapping an envelope leaves every reader downstream unable
        # to parse it, so a result they should have refused out loud disappears
        # instead.  Only a value that never claimed an envelope gets the markers.
        assert isinstance(published, dict)
        assert published["schema_version"] == wire["schema_version"]

    plain = enforce(gate, "list_directory", {"p": "plain"}, lambda: {"a": 1}, spotlight=True)
    assert isinstance(plain, str)
    assert plain.startswith("«EVIDENCE_DATA»")


def test_deterministic_error_detection_reads_the_status_of_both_envelopes() -> None:
    assert _is_deterministic_tool_error(_active_wire()) is False
    assert _is_deterministic_tool_error(_active_error_wire()) is False
    assert _is_deterministic_tool_error(_legacy_wire()) is False
    # A pre-envelope failure still declares itself the ordinary way.
    assert _is_deterministic_tool_error({"error": "boom", "deterministic_error": True}) is True

    # BITES: a self-contradictory active envelope claiming ``ok`` while carrying
    # an error block is judged by its status, exactly as the historical envelope
    # is.  Read as a pre-envelope mapping it would have been called a permanent
    # failure and the identical call suppressed for the rest of the run.
    contradictory = {
        "schema_version": contract.SCHEMA_ID,
        "status": "ok",
        "error": {"code": "x", "message": "y"},
        "deterministic_error": True,
    }
    assert _is_deterministic_tool_error(contradictory) is False
    assert _is_deterministic_tool_error({**contradictory, "schema_version": "other"}) is True


def test_the_model_surface_spotlight_keeps_both_envelopes_structured() -> None:
    from langchain_core.tools import StructuredTool
    from pydantic import BaseModel

    from forensic_agent.agent.model_surface import _spotlight_tools

    class _Args(BaseModel):
        pass

    for wire in (_legacy_wire(), _active_wire()):
        tool = StructuredTool.from_function(
            lambda w=wire: w, name="list_directory", description="d", args_schema=_Args
        )
        (spotlighted,) = _spotlight_tools([tool])
        assert spotlighted.func() == wire

    plain = StructuredTool.from_function(
        lambda: {"a": 1}, name="list_directory", description="d", args_schema=_Args
    )
    (wrapped,) = _spotlight_tools([plain])
    assert str(wrapped.func()).startswith("«EVIDENCE_DATA»")


# --- reporting ----------------------------------------------------------------


def test_the_interactive_trace_view_verifies_receipts_of_both_contracts(tmp_path) -> None:
    oversight_path = tmp_path / "oversight.jsonl"
    results_path = tmp_path / "tool-results.jsonl"
    actions = []
    rows = []
    for sequence, build in enumerate((_legacy_wire, _active_wire), start=1):
        # The oversight binding is part of the payload the receipt covers, so it
        # has to be set BEFORE the receipt is attached, exactly as the runtime
        # does it; editing it afterwards would invalidate the very receipt under
        # test.
        bound_wire = build(entry=f"{sequence:064d}", sequence=sequence)
        actions.append(
            {
                "seq": sequence,
                "event": "action",
                "tool": "list_directory",
                "args": {},
                "allowed": True,
                "blocked": False,
                "reasons": [],
                "entry_hash": f"{sequence:064d}",
            }
        )
        rows.append({"tool": "list_directory", "result": bound_wire})
    oversight_path.write_text(
        "".join(json.dumps(action) + "\n" for action in actions), encoding="utf-8"
    )
    results_path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    record = controlled_run_trace_record(
        SimpleNamespace(
            run_id="run-01",
            report="report",
            oversight_path=oversight_path,
            tool_result_trace_path=results_path,
            telemetry={},
        ),
        question="q",
        model="m",
        provider="p",
    )

    # BITES: the second call carries the active contract.  Read under the
    # historical model alone its receipt could not be checked at all, and the
    # trace would have reported a receipted result as unverified.
    assert [call["output_receipt_verified"] for call in record["calls"]] == [True, True]
    assert [call["oversight_binding_verified"] for call in record["calls"]] == [True, True]
    assert record["case_id"] == CASE
