"""The shared operation registry: one definition drives enum, schema, class, text.

Every negative case carries its positive twin, so a failure is attributable to
the one offending element rather than to an unrelated defect in the payload.
"""

from __future__ import annotations

from typing import Literal, get_args

import pytest

from forensic_agent.agent.evidence_classification import (
    MEMORY_OPERATIONS,
    PCAP_OPERATIONS,
    REGISTRY_OPERATIONS,
    classify_tool_result,
)
from forensic_agent.agent.tool_operations import (
    DOMAIN_FUNCTIONS,
    KNOWN_BACKEND_NAMES,
    LEGACY_FUNCTION_DISPOSITIONS,
    WITHDRAWN_OPERATIONS,
    DomainFunction,
    OperationArguments,
    OperationBackend,
    OperationDefinition,
    OperationNavigation,
    OperationValidationError,
    UnknownDomainFunctionError,
    classification_table,
    domain_function,
    function_description,
    functions_for_scope,
    operation_definition,
    operation_names,
    validate_operation_arguments,
)
from forensic_agent.core.result_contract import EvidenceClass

# ---------------------------------------------------------------------------
# Accepting a valid operation with its own arguments.
# ---------------------------------------------------------------------------


def test_valid_operation_validates_to_its_own_model():
    parsed = validate_operation_arguments(
        "filesystem_query", {"operation": "read_file", "path": "/etc/hosts", "max_bytes": 100}
    )
    assert parsed.operation == "read_file"
    assert parsed.path == "/etc/hosts"
    assert parsed.max_bytes == 100

    parsed = validate_operation_arguments(
        "registry_query",
        {"operation": "value_readings", "hive": "SYSTEM", "key": "Select"},
    )
    assert parsed.operation == "value_readings"
    assert parsed.key == "Select"

    parsed = validate_operation_arguments(
        "pcap_query", {"operation": "follow", "stream": 3, "transport": "udp"}
    )
    assert parsed.operation == "follow"
    assert parsed.stream == 3


def test_default_operation_is_applied_when_omitted():
    # memory_query defaults to the observed plugin read, exactly as the
    # classifier assumes for an omitted operation.
    parsed = validate_operation_arguments("memory_query", {"plugin": "pslist"})
    assert parsed.operation == "plugin_rows"
    # A function whose default is declared is callable without naming it.
    parsed = validate_operation_arguments("pcap_query", {})
    assert parsed.operation == "dns"
    # A function without a default requires the operation explicitly.
    with pytest.raises(OperationValidationError, match="explicit operation"):
        validate_operation_arguments("transform_query", {})


def test_operation_value_is_normalized_like_the_classifier():
    parsed = validate_operation_arguments(
        "filesystem_query", {"operation": "  READ_FILE  ", "path": "/x"}
    )
    assert parsed.operation == "read_file"


def test_validated_arguments_are_immutable():
    from pydantic import ValidationError

    parsed = validate_operation_arguments("pcap_query", {})
    with pytest.raises(ValidationError):
        parsed.limit = 999  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Rejection before any evidence access.
# ---------------------------------------------------------------------------


def test_unknown_operation_is_rejected():
    with pytest.raises(OperationValidationError):
        validate_operation_arguments("filesystem_query", {"operation": "carve"})
    with pytest.raises(OperationValidationError):
        validate_operation_arguments("pcap_query", {"operation": "http_exfil"})
    # Twin: the same payload under a defined operation passes.
    assert (
        validate_operation_arguments("pcap_query", {"operation": "http"}).operation == "http"
    )


def test_unknown_domain_function_is_rejected():
    with pytest.raises(UnknownDomainFunctionError):
        validate_operation_arguments("filesystem", {"operation": "read_file", "path": "/x"})


def test_missing_required_argument_is_rejected():
    # value_readings computes over one named key, so the key is required...
    with pytest.raises(OperationValidationError):
        validate_operation_arguments(
            "registry_query", {"operation": "value_readings", "hive": "SYSTEM"}
        )
    # ...while the observed read accepts the very same payload.
    parsed = validate_operation_arguments(
        "registry_query", {"operation": "registry_values", "hive": "SYSTEM"}
    )
    assert parsed.operation == "registry_values"

    with pytest.raises(OperationValidationError):
        validate_operation_arguments("memory_malware_scan", {"operation": "scan_pid"})
    assert (
        validate_operation_arguments(
            "memory_malware_scan", {"operation": "scan_pid", "pid": 4}
        ).pid
        == 4
    )


def test_extra_argument_is_rejected():
    payload = {"operation": "list_directory", "path": "/Users"}
    assert validate_operation_arguments("filesystem_query", payload).path == "/Users"
    with pytest.raises(OperationValidationError):
        validate_operation_arguments(
            "filesystem_query", {**payload, "frobnicate": True}
        )


def test_argument_of_another_operation_is_rejected():
    # `pattern` belongs to find_files; under list_directory it must die in
    # validation, not be silently dropped.
    with pytest.raises(OperationValidationError):
        validate_operation_arguments(
            "filesystem_query",
            {"operation": "list_directory", "path": "/", "pattern": "*.exe"},
        )
    assert (
        validate_operation_arguments(
            "filesystem_query", {"operation": "find_files", "pattern": "*.exe"}
        ).pattern
        == "*.exe"
    )

    # cross_capture_linkage reads every bound capture: a source selector is an
    # argument of the single-capture operations and is refused.
    with pytest.raises(OperationValidationError):
        validate_operation_arguments(
            "pcap_query", {"operation": "cross_capture_linkage", "source": "pcap-1"}
        )
    assert (
        validate_operation_arguments(
            "pcap_query", {"operation": "cross_capture_linkage"}
        ).operation
        == "cross_capture_linkage"
    )

    # A pid belongs to scan_pid alone.
    with pytest.raises(OperationValidationError):
        validate_operation_arguments(
            "memory_malware_scan", {"operation": "scan_all_candidates", "pid": 4}
        )

    # A named plugin belongs to the plugin run, not the profile run.
    with pytest.raises(OperationValidationError):
        validate_operation_arguments(
            "registry_ripper",
            {"operation": "profile", "hive": "SAM", "plugin": "samparse"},
        )
    assert (
        validate_operation_arguments(
            "registry_ripper",
            {"operation": "plugin", "hive": "SAM", "plugin": "samparse"},
        ).plugin
        == "samparse"
    )


def test_derived_memory_operations_bind_their_plugin_domain():
    # The parentage join is defined over the process listings only; asking it of
    # a network plugin is a wrong-operation argument at the value level.
    with pytest.raises(OperationValidationError):
        validate_operation_arguments(
            "memory_query", {"operation": "process_parentage", "plugin": "netscan"}
        )
    parsed = validate_operation_arguments(
        "memory_query", {"operation": "process_parentage", "plugin": "pslist"}
    )
    assert parsed.plugin == "pslist"


# ---------------------------------------------------------------------------
# Withdrawn capabilities stay withdrawn in the one shared source.
# ---------------------------------------------------------------------------


def test_hand_written_crypto_is_not_a_transform_operation():
    names = set(operation_names("transform_query"))
    assert "rc4" not in names and "xor" not in names
    for operation in domain_function("transform_query").operations:
        assert "kdf" not in operation.arguments.model_fields
        # Ruling B3: a transform cites an earlier result, it never takes
        # retyped text.
        assert "data" not in operation.arguments.model_fields
        assert "source_invocation_id" in operation.arguments.model_fields


def test_transform_time_operations_require_an_explicit_form():
    citation = {
        "source_invocation_id": "case:0001:abcdefabcdef",
        "source_payload_sha256": "0" * 64,
    }
    with pytest.raises(OperationValidationError):
        validate_operation_arguments("transform_query", {"operation": "filetime", **citation})
    parsed = validate_operation_arguments(
        "transform_query", {"operation": "filetime", "input_form": "hex_le", **citation}
    )
    assert parsed.input_form == "hex_le"
    with pytest.raises(OperationValidationError):
        validate_operation_arguments("transform_query", {"operation": "epoch", **citation})
    assert (
        validate_operation_arguments(
            "transform_query", {"operation": "epoch", "unit": "seconds", **citation}
        ).unit
        == "seconds"
    )


def test_pcap_export_has_no_ftp_route_and_no_host_write_arguments():
    export = operation_definition("pcap_query", "export")
    assert "ftp" not in get_args(export.arguments.model_fields["proto"].annotation)
    assert "ftp_objects" in operation_names("pcap_query")
    for operation in domain_function("pcap_query").operations:
        assert "save_path" not in operation.arguments.model_fields
        assert "metadata_only" not in operation.arguments.model_fields


def test_recover_deleted_exposes_only_the_tsk_view():
    names = set(operation_names("recover_deleted"))
    assert names == {"list_deleted", "recover_content"}
    disposition = LEGACY_FUNCTION_DISPOSITIONS["recover_deleted_files"]
    assert any("FAT" in note for note in disposition.withdrawn)


# ---------------------------------------------------------------------------
# The derived artefacts all read the one definition.
# ---------------------------------------------------------------------------


class _ProbeArguments(OperationArguments):
    operation: Literal["probe"] = "probe"
    target: str


def _variant_with_probe() -> DomainFunction:
    base = domain_function("registry_query")
    probe = OperationDefinition(
        name="probe",
        arguments=_ProbeArguments,
        evidence_class=EvidenceClass.DERIVED,
        method="registry.probe",
        method_version="1",
        backends=(OperationBackend(name="regipy", role="producer"),),
        description="A test-only probe operation.",
        # How the operation is navigated is part of the SAME definition: an
        # operation cannot exist without stating whether it can be continued.
        navigation=OperationNavigation(
            cursor_argument=None,
            cursor_unit=None,
            cursor_source=None,
            page_size_argument=None,
            filter_arguments=(),
            no_continuation_reason="a test-only probe returns one page",
        ),
    )
    return DomainFunction(
        name=base.name,
        scope=base.scope,
        summary=base.summary,
        operations=(*base.operations, probe),
        default_operation=base.default_operation,
    )


def test_enum_classification_and_description_follow_one_definition():
    variant = _variant_with_probe()

    # One added definition extends the closed enum...
    assert "probe" in operation_names(variant)
    # ...the classification table...
    table = classification_table(variant)
    assert table["probe"].evidence_class is EvidenceClass.DERIVED
    assert table["probe"].method == "registry.probe"
    # ...the description text, navigation statement included...
    assert "probe" in function_description(variant)
    assert "a test-only probe returns one page" in function_description(variant)
    # ...and the validation schema, all without touching any other artefact.
    parsed = validate_operation_arguments(
        variant, {"operation": "probe", "target": "Select"}
    )
    assert parsed.operation == "probe"

    # The unmodified registry knows none of it: the artefacts really are derived
    # from the definitions, not from parallel hand-written lists.
    assert "probe" not in operation_names("registry_query")
    assert "probe" not in classification_table("registry_query")
    assert "probe" not in function_description("registry_query")
    with pytest.raises(OperationValidationError):
        validate_operation_arguments(
            "registry_query", {"operation": "probe", "target": "Select"}
        )


def test_description_reflects_required_and_optional_arguments():
    text = function_description("registry_query")
    # The observed read's key is optional, the derived readings' key is not; the
    # description must state the difference because it is read from the models.
    assert "- registry_values [observed] (hive, key?," in text
    assert "- value_readings [derived] (hive, key," in text
    assert "Method: registry.value_readings." in text


# ---------------------------------------------------------------------------
# Structural invariants of the registry as a whole.
# ---------------------------------------------------------------------------


def test_every_operation_definition_is_internally_consistent():
    for function in DOMAIN_FUNCTIONS.values():
        for operation in function.operations:
            annotation = operation.arguments.model_fields["operation"].annotation
            assert get_args(annotation) == (operation.name,)
            derived = operation.evidence_class is EvidenceClass.DERIVED
            assert derived == (operation.method is not None)
            assert derived == (operation.method_version is not None)
            if operation.evidence_class is not EvidenceClass.REFERENCE:
                assert operation.backends, f"{function.name}.{operation.name}"
            if operation.evidence_class is EvidenceClass.OBSERVED:
                assert any(backend.role == "producer" for backend in operation.backends)
            for backend in operation.backends:
                assert backend.name in KNOWN_BACKEND_NAMES


def test_palette_availability_is_scope_driven_only():
    memory_palette = {function.name for function in functions_for_scope("memory")}
    assert memory_palette == {"memory_query", "memory_malware_scan", "memory_strings"}
    pcap_palette = {function.name for function in functions_for_scope("pcap")}
    assert pcap_palette == {"pcap_query"}


def test_backend_declaration_is_the_recording_seam():
    sqlite_schema = operation_definition("sqlite_query", "schema")
    roles = {(backend.name, backend.role) for backend in sqlite_schema.backends}
    assert ("cpython_sqlite3", "producer") in roles
    assert ("dfvfs", "support") in roles


# ---------------------------------------------------------------------------
# The previous surface is fully accounted for.
# ---------------------------------------------------------------------------


def test_every_legacy_function_maps_to_a_defined_operation():
    for disposition in LEGACY_FUNCTION_DISPOSITIONS.values():
        assert disposition.status == "operation"
        assert disposition.domain_function in DOMAIN_FUNCTIONS
        target = DOMAIN_FUNCTIONS[disposition.domain_function]
        # A withdrawn operation counts as defined: its definition is still here,
        # because a call recorded under it still has to be classified and
        # attested. What it lost is its place in the enum, not its existence.
        defined = set(target.operation_names()) | {
            withdrawn.definition.name
            for withdrawn in WITHDRAWN_OPERATIONS.values()
            if withdrawn.function == target.name
        }
        assert disposition.operations, disposition.legacy_name
        for operation in disposition.operations:
            assert operation in defined, (disposition.legacy_name, operation)


def test_a_withdrawn_operation_is_declared_rather_than_deleted():
    """Zamjena operacije mora se dati pročitati, ne samo primijetiti.

    Bez zapisa, povučena operacija izgleda isto kao izbrisana: čitatelj vidi da
    poziv više ne postoji i nema odakle saznati zašto ni što ga je zamijenilo.
    """

    for key, withdrawn in WITHDRAWN_OPERATIONS.items():
        host = DOMAIN_FUNCTIONS[withdrawn.function]
        assert key == f"{withdrawn.function}.{withdrawn.definition.name}"
        assert withdrawn.definition.name not in host.operation_names(), key
        assert withdrawn.superseded_by in host.operation_names(), key
        assert withdrawn.reason.strip(), key
        # Definicija je i dalje razrješiva kroz funkciju, jer ju zapis o starom
        # pozivu treba — a validacija ju svejedno odbija.
        assert host.operation(withdrawn.definition.name) is withdrawn.definition
        with pytest.raises(OperationValidationError):
            validate_operation_arguments(
                host.name, {"operation": withdrawn.definition.name}
            )


#: Operations added AFTER the consolidation, with no legacy predecessor: the
#: whole-image content search, which replaced a bounded tree walk with a different
#: instrument over a different scope rather than renaming it, and the
#: hardware-address registry lookup, which
#: nothing on the previous surface performed at all. They are net-new capability,
#: so the legacy old-to-new mapping does not — and must not — account for them;
#: enumerating them here keeps this test able to catch a genuinely UNannounced
#: operation while admitting these.
_NET_NEW_OPERATIONS = frozenset(
    {
        ("filesystem_query", "search_image_content"),
        # The same instrument over a raw image of any kind, and net-new for the
        # same reason: the previous surface had no whole-image literal search a
        # memory image could reach.
        ("bulk_extract", "find_literal"),
        ("artifact_reference_query", "hardware_vendor"),
        # The pattern search over the raw bytes of the MEMORY image. Its name
        # existed on the withdrawn surface, but nothing on the previous surface
        # ran this operation, and the operation is what this mapping accounts
        # for -- so it is declared net-new here rather than mapped to a
        # predecessor it does not have.
        ("memory_strings", "pattern_hits"),
    }
)


def test_every_defined_operation_is_reachable_from_the_legacy_mapping():
    # The consolidation adds structure, never unannounced capability: every
    # operation is either mapped from the previous surface or one of the two
    # net-new mediator tools declared above. Anything else is a leak.
    mapped = {
        (disposition.domain_function, operation)
        for disposition in LEGACY_FUNCTION_DISPOSITIONS.values()
        for operation in disposition.operations
    }
    defined = {
        (function.name, operation.name)
        for function in DOMAIN_FUNCTIONS.values()
        for operation in function.operations
    } | {
        (withdrawn.function, withdrawn.definition.name)
        for withdrawn in WITHDRAWN_OPERATIONS.values()
    }
    # Every legacy mapping still points at a real operation...
    assert mapped <= defined
    # ...and the only operations outside that mapping are the net-new tools.
    assert defined - mapped == _NET_NEW_OPERATIONS


# ---------------------------------------------------------------------------
# Alignment with the active per-call classifier, until it is rewired to read
# this registry: the two sources must agree operation for operation.
# ---------------------------------------------------------------------------


def test_classification_agrees_with_the_active_classifier():
    assert set(operation_names("memory_query")) == set(MEMORY_OPERATIONS)
    for name, entry in classification_table("memory_query").items():
        active = classify_tool_result("memory_query", {"operation": name})
        assert active.evidence_class is entry.evidence_class, name
        assert active.method == entry.method, name

    assert set(operation_names("registry_query")) == set(REGISTRY_OPERATIONS)
    for name, entry in classification_table("registry_query").items():
        active = classify_tool_result("registry_query", {"operation": name})
        assert active.evidence_class is entry.evidence_class, name
        assert active.method == entry.method, name

    assert set(operation_names("pcap_query")) == set(PCAP_OPERATIONS)
    for name, entry in classification_table("pcap_query").items():
        active = classify_tool_result("pcap_query", {"query": name})
        assert active.evidence_class is entry.evidence_class, name
        assert active.method == entry.method, name
