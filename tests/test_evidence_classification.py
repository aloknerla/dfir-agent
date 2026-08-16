"""Authoritative classifier: fail-closed, per-operation, aligned with the impl."""

from __future__ import annotations

from pathlib import Path

import pytest

from forensic_agent.agent.evidence_classification import (
    MEMORY_OPERATIONS,
    PCAP_OPERATIONS,
    REGISTRY_OPERATIONS,
    ToolClassificationError,
    build_derivation_metadata,
    classify_tool_result,
)
from forensic_agent.core.result_contract import EvidenceClass, ResultInput, SourceInput


def _cls(name, **args):
    return classify_tool_result(name, args or None).evidence_class


def test_observed_and_derived_tools():
    assert _cls("list_directory") is EvidenceClass.OBSERVED
    assert _cls("registry_query") is EvidenceClass.OBSERVED
    assert _cls("evidence_file_hash") is EvidenceClass.DERIVED
    assert _cls("decode") is EvidenceClass.DERIVED


def test_unknown_tool_fails_closed():
    with pytest.raises(ToolClassificationError):
        classify_tool_result("totally_unknown_tool")


def test_every_pcap_operation_is_derived():
    # The pcap tool runs our code over tshark output (summaries, endpoint roles,
    # filtering, reconstruction), so every operation is DERIVED — including the
    # "extraction" views.
    for op in PCAP_OPERATIONS:
        assert classify_tool_result("pcap_query", {"query": op}).evidence_class is (
            EvidenceClass.DERIVED
        ), op


def test_omitted_pcap_query_uses_the_signature_default():
    # The binding default is query="dns"; an omitted query classifies as that,
    # not rejected.
    assert classify_tool_result("pcap_query", {}).method == "network.dns_summary"
    assert classify_tool_result("pcap_query", {"query": ""}).method == "network.dns_summary"


def test_pcap_nonexistent_and_unknown_operations_raise():
    with pytest.raises(ToolClassificationError):
        classify_tool_result("pcap_query", {"query": "http_exfil"})  # not a real op
    with pytest.raises(ToolClassificationError):
        classify_tool_result("pcap_query", {"query": "made_up"})


def test_pcap_classifier_registry_matches_the_tool_registry():
    # Cross-check the classifier's registry against the operations the tool
    # actually accepts, not a second hand-maintained list.  The tool layer
    # publishes its accepted set as PCAP_QUERY_OPERATIONS (its unknown-query guard
    # is driven by that same constant); the binding layer services exactly one
    # further operation, cross_capture_linkage, before delegating the rest.  If
    # the tool gains or drops an operation, this equality fails until the
    # classifier is updated — so an unclassified operation can never ship.
    from forensic_agent.tools import pcap_tool

    tool_registry = set(pcap_tool.PCAP_QUERY_OPERATIONS) | {"cross_capture_linkage"}
    assert set(PCAP_OPERATIONS) == tool_registry


def test_cross_capture_linkage_is_a_binding_layer_operation():
    # Guard the one hand-named operation above: it must genuinely be dispatched by
    # the binding layer and genuinely absent from the tool layer, so the split in
    # the registry cross-check reflects the real code rather than an assumption.
    from forensic_agent.tools import pcap_tool

    binding = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "forensic_agent"
        / "agent"
        / "tool_bindings"
        / "pcap.py"
    )
    text = binding.read_text(encoding="utf-8")
    assert 'query.casefold() == "cross_capture_linkage"' in text
    assert "cross_capture_linkage" not in pcap_tool.PCAP_QUERY_OPERATIONS


def test_memory_query_is_classified_per_operation_not_per_function():
    # The plugin read is what Volatility emitted, including pstree, where the
    # parentage IS the plugin's own answer.
    assert classify_tool_result("memory_query", {"plugin": "pstree"}).evidence_class is (
        EvidenceClass.OBSERVED
    )
    assert classify_tool_result(
        "memory_query", {"plugin": "pslist", "operation": "plugin_rows"}
    ).evidence_class is EvidenceClass.OBSERVED
    # Every computation this project performs over those rows is a separate
    # operation, and every one of them is DERIVED with its own named method.
    assert {
        operation: (
            classify_tool_result(
                "memory_query", {"plugin": "pslist", "operation": operation}
            ).evidence_class,
            classify_tool_result(
                "memory_query", {"plugin": "pslist", "operation": operation}
            ).method,
        )
        for operation in (
            "process_parentage",
            "external_connections",
            "injection_candidates",
            "field_distribution",
        )
    } == {
        "process_parentage": (EvidenceClass.DERIVED, "memory.process_parentage_join"),
        "external_connections": (
            EvidenceClass.DERIVED,
            "memory.external_connection_filter",
        ),
        "injection_candidates": (
            EvidenceClass.DERIVED,
            "memory.injection_candidate_summary",
        ),
        "field_distribution": (EvidenceClass.DERIVED, "memory.row_field_distribution"),
    }


def test_registry_query_is_classified_per_operation_not_per_function():
    assert classify_tool_result(
        "registry_query", {"hive": "SECURITY", "operation": "registry_values"}
    ).evidence_class is EvidenceClass.OBSERVED
    readings = classify_tool_result(
        "registry_query", {"hive": "SECURITY", "key": "Policy", "operation": "value_readings"}
    )
    assert readings.evidence_class is EvidenceClass.DERIVED
    assert readings.method == "registry.value_readings"


def test_an_unregistered_memory_or_registry_operation_never_defaults_to_observed():
    for tool, arguments in (
        ("memory_query", {"plugin": "pslist", "operation": "invent_something"}),
        ("registry_query", {"hive": "SYSTEM", "operation": "invent_something"}),
    ):
        with pytest.raises(ToolClassificationError):
            classify_tool_result(tool, arguments)


def test_memory_and_registry_classifier_registries_match_their_tools():
    # Cross-check against the operation set each tool actually accepts, not a
    # second hand-maintained list: an operation the tool gains or drops must fail
    # this equality until the classifier is updated, so an unclassified operation
    # can never ship.
    from forensic_agent.tools import memory_tool, registry_tool

    assert set(MEMORY_OPERATIONS) == set(memory_tool.MEMORY_QUERY_OPERATIONS)
    assert set(REGISTRY_OPERATIONS) == set(registry_tool.REGISTRY_QUERY_OPERATIONS)


def test_the_derived_operations_carry_the_defaults_their_tools_run():
    from forensic_agent.tools import memory_tool, registry_tool

    # An omitted operation must classify as the operation that actually runs.
    assert classify_tool_result("memory_query", {}).evidence_class is (
        classify_tool_result(
            "memory_query", {"operation": memory_tool._DEFAULT_MEMORY_OPERATION}
        ).evidence_class
    )
    assert classify_tool_result("registry_query", {}).evidence_class is (
        classify_tool_result(
            "registry_query", {"operation": registry_tool._DEFAULT_REGISTRY_OPERATION}
        ).evidence_class
    )


@pytest.mark.parametrize(
    ("plugin", "operation", "method"),
    [
        ("pslist", "process_parentage", "memory.process_parentage_join"),
        ("netscan", "external_connections", "memory.external_connection_filter"),
        ("malfind", "injection_candidates", "memory.injection_candidate_summary"),
        ("dlllist", "field_distribution", "memory.row_field_distribution"),
    ],
)
def test_every_memory_computation_cites_the_result_it_was_computed_over(
    plugin, operation, method
):
    classification = classify_tool_result(
        "memory_query", {"plugin": plugin, "operation": operation}
    )
    parent = ResultInput(
        case_id="case-1", invocation_id="run.001:0007:abcdef012345", payload_sha256="b" * 64
    )

    derivation = build_derivation_metadata(
        classification,
        arguments={"plugin": plugin, "operation": operation, "filter": "cs.exe"},
        implementation="impl",
        source_input=None,
        result_inputs=(parent,),
    )

    assert derivation.method == method
    assert derivation.derivation_inputs == [parent]
    # the substring filter is denied outright, the operation selectors survive
    assert derivation.parameters == {"plugin": plugin, "operation": operation}


def test_the_readings_operation_cites_the_source_it_was_computed_over():
    classification = classify_tool_result(
        "registry_query", {"hive": "SECURITY", "operation": "value_readings"}
    )
    source = SourceInput(case_id="case-1", source_id="disk-1", sha256="a" * 64)

    derivation = build_derivation_metadata(
        classification,
        arguments={
            "hive": "SECURITY",
            "key": r"Policy\PolPrDmN",
            "depth": 0,
            "operation": "value_readings",
            "filter": "PolPrDmN",
        },
        implementation="impl",
        source_input=source,
    )

    assert derivation.method == "registry.value_readings"
    assert derivation.derivation_inputs == [source]
    # ``key`` and ``filter`` are both denied outright: ``key`` names a decryption
    # key elsewhere on this surface, and the denylist is not weakened for a
    # registry path.
    assert derivation.parameters == {
        "hive": "SECURITY",
        "depth": 0,
        "operation": "value_readings",
    }


def test_autopsy_names_have_no_special_classification():
    # Autopsy je uklonjen: ``autopsy__*`` više nije registrirana klasa, pa mora
    # pasti zatvoreno kroz isti generički put kao svako drugo neregistrirano ime,
    # a ne biti tiho svrstan u OBSERVED.
    for name in (
        "autopsy__query_files",
        "autopsy__get_server_status",
        "autopsy__delete_everything",
    ):
        with pytest.raises(ToolClassificationError):
            classify_tool_result(name)


def test_derivation_parameters_are_a_safe_per_function_projection():
    # decode: op/kdf/input_enc are safe; key and data must never appear.
    classification = classify_tool_result("decode")
    derivation = build_derivation_metadata(
        classification,
        arguments={
            "op": "rc4",
            "kdf": "sha256",
            "input_enc": "hex",
            "key": "SUPERSECRET",
            "data": "deadbeef",
        },
        implementation="impl",
        source_input=SourceInput(case_id="c", source_id="disk-1", sha256="a" * 64),
    )
    params = derivation.parameters
    assert params == {"op": "rc4", "kdf": "sha256", "input_enc": "hex"}
    assert "key" not in params and "data" not in params


def test_host_path_argument_never_reaches_the_derivation():
    classification = classify_tool_result("evidence_file_hash")
    secret = r"D:\private\host\secret.bin"
    derivation = build_derivation_metadata(
        classification,
        arguments={"path": secret, "algorithm": "sha256"},
        implementation="impl",
        source_input=SourceInput(case_id="c", source_id="disk-1", sha256="a" * 64),
        private_paths=[secret],
    )
    import json

    serialized = json.dumps(derivation.model_dump(mode="json"))
    assert secret not in serialized
    assert "path" not in derivation.parameters  # 'path' is denied outright
    assert derivation.parameters == {"algorithm": "sha256"}


def test_derived_without_any_input_is_a_caller_error():
    classification = classify_tool_result("decode")  # DERIVED
    with pytest.raises(ToolClassificationError):
        build_derivation_metadata(
            classification,
            arguments={"op": "base64"},
            implementation="impl",
            source_input=None,
            result_inputs=(),
        )


def test_observed_tool_has_no_derivation():
    classification = classify_tool_result("list_directory")  # OBSERVED
    assert build_derivation_metadata(
        classification, arguments={}, implementation="impl", source_input=None
    ) is None
