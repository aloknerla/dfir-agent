"""Authoritative epistemic classification of every model-visible tool result.

Single source of truth for whether a tool call produces an OBSERVED, DERIVED or
REFERENCE result.  The runtime standardizer consults it so classification is
never inferred from scattered name checks at the call site, and any tool that is
not registered here yields a structured :class:`ToolClassificationError` rather
than a silent OBSERVED default.

Classification is resolved per call from ``(tool_name, arguments)`` because one
wrapper can perform operations of different epistemic classes — ``memory_query``
returns the rows a Volatility plugin emitted (OBSERVED) but also joins, filters,
groups and counts those rows itself (DERIVED), and ``registry_query`` returns the
value regipy reported (OBSERVED) but also reads a date or a string out of those
bytes (DERIVED).  Each of those is a distinct operation with its own class, never
one result carrying both.

For every consolidated domain function the per-operation classes are READ from
the shared operation registry (:mod:`forensic_agent.agent.tool_operations`)
rather than maintained here a second time: the enum, the validation schema, the
model-visible description and this classification all follow one definition, so
they cannot drift apart again.  The flat entries below cover only the previous
surface's names, which the historical opt-in still builds.
"""

from __future__ import annotations

from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass
from functools import partial
from typing import Any

from forensic_agent.agent.tool_operations import (
    DOMAIN_FUNCTIONS,
    classification_table,
)
from forensic_agent.agent.tool_taxonomy import REFERENCE_TOOLS
from forensic_agent.core.repro import canonical_json
from forensic_agent.core.result_contract import (
    DerivationMetadata,
    EvidenceClass,
    ResultInput,
    SourceInput,
)


class ToolClassificationError(RuntimeError):
    """A model-visible tool has no authoritative epistemic classification."""


@dataclass(frozen=True, slots=True)
class Classification:
    """The resolved epistemic class of one tool result, plus derivation labels."""

    evidence_class: EvidenceClass
    method: str | None = None
    method_version: str | None = None


_OBSERVED = Classification(EvidenceClass.OBSERVED)
_REFERENCE = Classification(EvidenceClass.REFERENCE)


def _derived(method: str, version: str = "1") -> Classification:
    return Classification(EvidenceClass.DERIVED, method=method, method_version=version)


#: Tools whose result is verbatim upstream output (OBSERVED).
_OBSERVED_TOOLS: frozenset[str] = frozenset(
    {
        "list_directory",
        "file_metadata",
        "read_file",
        "read_text_file",
        "registry_ripper",
        "evtx_query",
        "sqlite_query",
        "bulk_extract",
        "archive_query",
    }
)

#: Tools whose result is a deterministic computation over observed inputs.
_DERIVED_TOOLS: dict[str, Classification] = {
    "find_files": _derived("filesystem.name_filter"),
    "search_keyword": _derived("filesystem.keyword_scan"),
    "search_in_file": _derived("filesystem.in_file_search"),
    "evidence_file_hash": _derived("hash.sha256"),
    "hash_file": _derived("hash.sha256"),
    "hash_lookup": _derived("hashset.classification"),
    "verify_image_integrity": _derived("evidence.integrity_compare"),
    "recover_deleted_files": _derived("filesystem.tsk_recovery"),
    "decode": _derived("transform.decode"),
    "reconstruct_http_exfil": _derived("network.http_reconstruction"),
    "memory_malware_scan": _derived("memory.signature_scan"),
    "memory_strings": _derived("memory.string_scan"),
    "ocr_image": _derived("image.ocr"),
    "vision_read": _derived("image.vision_read"),
    "configuration_query": _derived("config.extraction"),
    "find_email_addresses": _derived("filesystem.email_extraction"),
    "google_drive_sync_events": _derived("application.gdrive_sync_parse"),
    "printing_activity_events": _derived("application.print_activity_parse"),
    "gcode_metadata": _derived("application.gcode_metadata_parse"),
    "printing_job_sessions": _derived("application.print_session_correlation"),
    "usb_storage_history": _derived("windows.usb_history_join"),
    "installed_applications": _derived("windows.installed_apps_join"),
    "windows_domain_identity": _derived("windows.domain_identity_derivation"),
    "windows_local_accounts": _derived("windows.local_accounts_derivation"),
    "windows_network_config": _derived("windows.network_config_derivation"),
}

#: Reference tools — procedural knowledge, never case evidence.  Deferred to the
#: single tool-taxonomy authority (:mod:`forensic_agent.agent.tool_taxonomy`)
#: rather than restated here, so the reference vocabulary is declared once.
#: Binding the owner's set is itself the drift guard: this module cannot hold a
#: divergent copy, and a withdrawn name absent from the owner cannot reappear on
#: any surface this classifier feeds.
_REFERENCE_TOOLS: frozenset[str] = REFERENCE_TOOLS

def _registered_operations(function_name: str) -> dict[str, Classification]:
    """One domain function's per-operation classes, read from the shared registry.

    ``tool_operations`` is the single source of operation definitions; mapping
    its table onto this module's ``Classification`` keeps exactly one place
    where an operation's epistemic class is declared.
    """

    return {
        name: Classification(
            entry.evidence_class,
            method=entry.method,
            method_version=entry.method_version,
        )
        for name, entry in classification_table(function_name).items()
    }


#: The ``pcap_query`` default operation, from the shared registry — the same
#: default the tool binding's signature applies, so an omitted ``query``
#: classifies exactly as the tool would run it.
_PCAP_DEFAULT_QUERY = DOMAIN_FUNCTIONS["pcap_query"].default_operation

#: ``pcap_query`` operations, read from the shared registry.  Every operation is
#: DERIVED: even the "extraction" views run our code over tshark output (``dns``
#: computes its own summaries, ``fields`` adds endpoint roles / session
#: summaries, the substring ``filter`` is our post-processing), and the rest
#: reconstruct or correlate content.  Classifying the whole ``pcap_query``
#: result as DERIVED is the honest choice until the raw tshark records are
#: separated from our additions.
_PCAP_DERIVED_QUERIES: dict[str, Classification] = _registered_operations("pcap_query")

#: The authoritative set of valid ``pcap_query`` operations (single source of
#: truth; the classifier test cross-checks it against the tool implementation).
PCAP_OPERATIONS: frozenset[str] = frozenset(_PCAP_DERIVED_QUERIES)

#: ``memory_query`` operations, read from the shared registry.  The plugin read
#: is OBSERVED because its rows are what Volatility emitted — including
#: ``pstree``, where the parentage IS the plugin's own answer.  Everything else
#: is a computation this project performs over that output, each a separate
#: DERIVED operation asked for by name, so one result never carries two classes.
_MEMORY_OPERATIONS: dict[str, Classification] = _registered_operations("memory_query")

#: The authoritative set of valid ``memory_query`` operations (the classifier
#: test cross-checks it against the tool implementation).
MEMORY_OPERATIONS: frozenset[str] = frozenset(_MEMORY_OPERATIONS)

#: ``registry_query`` operations, read from the shared registry.  The value read
#: is OBSERVED: it carries what regipy reported.  Reading a Unix epoch, a
#: Windows FILETIME or UTF-16LE text out of those bytes is a guess about a
#: meaning the registry never states, so it is a separate DERIVED operation.
_REGISTRY_OPERATIONS: dict[str, Classification] = _registered_operations("registry_query")

#: The authoritative set of valid ``registry_query`` operations (the classifier
#: test cross-checks it against the tool implementation).
REGISTRY_OPERATIONS: frozenset[str] = frozenset(_REGISTRY_OPERATIONS)


def _classify_registered_operation(
    tool_name: str,
    arguments: Mapping[str, Any],
    *,
    argument: str,
    operations: Mapping[str, Classification],
    default: str | None,
) -> Classification:
    """Resolve one call to the registered class of the operation it selects.

    The selector's own default is applied first, so an omitted argument
    classifies as the operation the tool would actually run; a function without
    a default refuses the omission.  An operation the registry does not name
    raises: an unclassified case result must fail closed, never fall back to
    OBSERVED.
    """

    raw = arguments.get(argument)
    if raw in (None, ""):
        if default is None:
            raise ToolClassificationError(
                f"{tool_name} requires an explicit operation to classify"
            )
        operation = default
    else:
        operation = str(raw).strip().casefold()
    classification = operations.get(operation)
    if classification is None:
        raise ToolClassificationError(
            f"{tool_name} operation {operation!r} is not a registered classified operation"
        )
    return classification


def _classify_pcap_query(arguments: Mapping[str, Any]) -> Classification:
    # The legacy binding selects the operation through ``query``; the domain
    # facade names it ``operation``.  Both surfaces classify identically.
    if arguments.get("query") in (None, "") and arguments.get("operation") not in (None, ""):
        arguments = {**arguments, "query": arguments["operation"]}
    return _classify_registered_operation(
        "pcap_query",
        arguments,
        argument="query",
        operations=_PCAP_DERIVED_QUERIES,
        default=_PCAP_DEFAULT_QUERY,
    )


def _classify_memory_query(arguments: Mapping[str, Any]) -> Classification:
    return _classify_registered_operation(
        "memory_query",
        arguments,
        argument="operation",
        operations=_MEMORY_OPERATIONS,
        default=DOMAIN_FUNCTIONS["memory_query"].default_operation,
    )


def _classify_registry_query(arguments: Mapping[str, Any]) -> Classification:
    return _classify_registered_operation(
        "registry_query",
        arguments,
        argument="operation",
        operations=_REGISTRY_OPERATIONS,
        default=DOMAIN_FUNCTIONS["registry_query"].default_operation,
    )


def _classify_domain_function(
    function_name: str, arguments: Mapping[str, Any]
) -> Classification:
    """Classify one consolidated domain function call from the shared registry.

    A call without an explicit operation classifies as the function's declared
    default.  A function with no default falls back to the flat entry its
    LEGACY namesake carries, because the historical surface shares several
    names (``sqlite_query``, ``archive_query``, ...) whose call shape has no
    ``operation`` argument; a name with neither fails closed.
    """

    raw = arguments.get("operation")
    default = DOMAIN_FUNCTIONS[function_name].default_operation
    if raw in (None, "") and default is None:
        if function_name in _OBSERVED_TOOLS:
            return _OBSERVED
        if function_name in _DERIVED_TOOLS:
            return _DERIVED_TOOLS[function_name]
        raise ToolClassificationError(
            f"{function_name} requires an explicit operation to classify"
        )
    return _classify_registered_operation(
        function_name,
        arguments,
        argument="operation",
        operations=_registered_operations(function_name),
        default=default,
    )


_PER_CALL_RESOLVERS: dict[str, Callable[[Mapping[str, Any]], Classification]] = {
    "pcap_query": _classify_pcap_query,
    "memory_query": _classify_memory_query,
    "registry_query": _classify_registry_query,
}
# Every remaining domain function resolves per call against the shared registry,
# so the consolidated surface is classified without a second registration here.
for _function_name in DOMAIN_FUNCTIONS:
    _PER_CALL_RESOLVERS.setdefault(
        _function_name, partial(_classify_domain_function, _function_name)
    )
del _function_name


def classify_tool_result(
    tool_name: str,
    arguments: Mapping[str, Any] | None = None,
) -> Classification:
    """Return the authoritative classification for one tool call, or raise.

    ``ToolClassificationError`` is raised for any unregistered tool or operation
    so an unclassified case result fails closed rather than defaulting to
    OBSERVED.
    """

    resolver = _PER_CALL_RESOLVERS.get(tool_name)
    if resolver is not None:
        return resolver(arguments or {})
    if tool_name in _REFERENCE_TOOLS:
        return _REFERENCE
    if tool_name in _OBSERVED_TOOLS:
        return _OBSERVED
    if tool_name in _DERIVED_TOOLS:
        return _DERIVED_TOOLS[tool_name]
    raise ToolClassificationError(
        f"tool {tool_name!r} has no authoritative epistemic classification"
    )


#: Per-derivation-method allowlist of non-sensitive argument names that may
#: appear in the model-visible derivation.  This is a safe projection, not a
#: general dump: default-deny — an argument not listed here is dropped, so a
#: ``key``, ``password``, ``token``, raw ``data`` payload or host path can never
#: reach the model-visible result.  A separate full-argument attestation lives
#: only in the private oversight record; it is never the model-visible
#: ``tool.parameters_sha256`` (which carries, at most, a digest of this safe
#: projection).
_SAFE_PARAMETERS_BY_METHOD: dict[str, frozenset[str]] = {
    "transform.decode": frozenset({"op", "kdf", "input_enc"}),
    # The nine consolidated transforms take a CITATION plus, for two of them, the
    # form the cited text is to be read in.  The citation itself is recorded as a
    # derivation input rather than a parameter, so only ``source_field`` — the
    # path to the value inside the cited result — and the stated form or unit
    # survive: without them two different computations over one parent result
    # would record identical parameters.
    "transform.base64": frozenset({"source_field"}),
    "transform.base32": frozenset({"source_field"}),
    "transform.hex": frozenset({"source_field"}),
    "transform.rot13": frozenset({"source_field"}),
    "transform.url": frozenset({"source_field"}),
    "transform.utf16le": frozenset({"source_field"}),
    "transform.gzip": frozenset({"source_field"}),
    "transform.filetime": frozenset({"source_field", "input_form"}),
    "transform.epoch": frozenset({"source_field", "unit"}),
    "hash.sha256": frozenset({"algorithm"}),
    # Both host-file methods take one host path and nothing else, and a host path
    # is denied outright below, so neither can record a parameter at all. The
    # entries are written out because default-deny must be a decision here rather
    # than an omission.
    "hash.host_file_sha256": frozenset(),
    "hashset.classification": frozenset(),
    "evidence.integrity_compare": frozenset(),
    # The archive path is a host path and the password is a secret; what remains
    # is the bound on how many members the inspection characterized.
    "archive.extract_inspection": frozenset({"limit"}),
    "filesystem.name_filter": frozenset({"pattern", "recursive", "max_results"}),
    "filesystem.keyword_scan": frozenset({"max_hits"}),
    # ``start`` is denied outright below, so what identifies one page of a
    # whole-image search is the page itself; the term is the question and is
    # never recorded as a parameter of the answer.
    "image.literal_content_scan": frozenset({"max_hits", "offset"}),
    "filesystem.in_file_search": frozenset({"max_hits"}),
    "filesystem.tsk_recovery": frozenset({"fs_type"}),
    "image.ocr": frozenset({"language"}),
    "image.vision_read": frozenset(),
    "config.extraction": frozenset({"keys", "limit", "offset"}),
    "filesystem.email_extraction": frozenset({"domain", "limit", "offset"}),
    "application.gdrive_sync_parse": frozenset(),
    "application.print_activity_parse": frozenset({"date_from", "date_to", "limit", "offset"}),
    "application.gcode_metadata_parse": frozenset(),
    "application.print_session_correlation": frozenset({"date_from", "date_to", "limit", "offset"}),
    "windows.usb_history_join": frozenset(),
    "windows.installed_apps_join": frozenset(),
    "windows.domain_identity_derivation": frozenset(),
    "windows.local_accounts_derivation": frozenset(),
    "windows.network_config_derivation": frozenset(),
    "memory.signature_scan": frozenset({"scope", "pid"}),
    "memory.string_scan": frozenset({"max_hits", "context"}),
    # Each memory computation is identified by the plugin whose output it ran
    # over, and by the page it returned; the substring filter is denied outright
    # below.
    "memory.process_parentage_join": frozenset({"operation", "plugin", "limit", "offset"}),
    "memory.external_connection_filter": frozenset({"operation", "plugin", "limit", "offset"}),
    "memory.injection_candidate_summary": frozenset(
        {"operation", "plugin", "limit", "offset"}
    ),
    "memory.row_field_distribution": frozenset({"operation", "plugin", "limit", "offset"}),
    # ``key`` is deliberately absent even though an in-hive key path is not
    # sensitive: it is on the defence-in-depth denylist below because a ``key``
    # argument elsewhere is a decryption key, and weakening that denylist to
    # spell a registry path is not worth the leak it would allow.
    "registry.value_readings": frozenset({"operation", "hive", "depth", "limit", "offset"}),
    # pcap operations: keep the operation selectors, never a display_filter,
    # substring filter, field list values, stat expression or save path.
    "network.dns_summary": frozenset({"query", "limit", "offset"}),
    "network.http_summary": frozenset({"query", "limit", "offset"}),
    "network.protocol_hierarchy": frozenset({"query"}),
    "network.conversations": frozenset({"query"}),
    "network.endpoints": frozenset({"query"}),
    "network.tshark_statistic": frozenset({"query"}),
    "network.field_extraction_with_roles": frozenset({"query", "limit", "offset"}),
    "network.dns_exfil_reconstruction": frozenset({"query", "transport"}),
    "network.cross_capture_correlation": frozenset({"query"}),
    "network.ftp_session_summary": frozenset({"query", "transport"}),
    "network.telnet_session_reconstruction": frozenset({"query", "transport"}),
    "network.http_auth_extraction": frozenset({"query"}),
    "network.ftp_object_reconstruction": frozenset({"query", "metadata_only"}),
    "network.http_object_reconstruction": frozenset({"query", "proto", "metadata_only"}),
    "network.object_export": frozenset({"query", "proto", "metadata_only"}),
    "network.stream_follow_reconstruction": frozenset({"query", "transport"}),
}

#: Argument names that must NEVER appear in a model-visible derivation, whatever
#: the per-method allowlist says — a defence-in-depth denylist.
_ALWAYS_DROP_PARAMETERS: frozenset[str] = frozenset(
    {
        "key",
        "password",
        "passphrase",
        "token",
        "secret",
        "data",
        "content",
        "display_filter",
        "filter",
        "stat",
        "fields",
        "path",
        "start",
        "dump_path",
        "image_path",
        "archive_path",
        "save_path",
    }
)


def build_derivation_metadata(
    classification: Classification,
    *,
    arguments: Mapping[str, Any] | None,
    implementation: str | None,
    source_input: SourceInput | None,
    result_inputs: Sequence[ResultInput] = (),
    private_paths: Collection[str] = (),
) -> DerivationMetadata | None:
    """Assemble the DERIVED lineage for one classified call, or None if not DERIVED.

    ``source_input`` is the runtime-attested evidence source the operation ran
    over (built by the caller from the case registry, never from model input);
    ``result_inputs`` are prior receipt-verified results a correlation consumed.

    Effective arguments are recorded as a **safe per-function projection**: only
    the non-sensitive argument names allowlisted for this derivation method
    survive (default-deny), the defence-in-depth denylist removes any sensitive
    name regardless, and the surviving values are still redacted for private
    paths and canonicalized.  A ``key``/``password``/``token``/raw ``data`` or
    host path therefore never appears in the model-visible result; the full
    argument set is attested only in the private oversight record, never in the
    model-visible ``tool.parameters_sha256``.  A DERIVED classification with no
    inputs is a caller error, surfaced here.
    """

    if classification.evidence_class is not EvidenceClass.DERIVED:
        return None
    inputs: list[SourceInput | ResultInput] = []
    if source_input is not None:
        inputs.append(source_input)
    inputs.extend(result_inputs)
    if not inputs:
        raise ToolClassificationError(
            f"DERIVED result for {classification.method!r} must cite at least one input"
        )
    method = classification.method or "derived"
    parameters = _safe_parameter_projection(method, arguments or {}, private_paths)
    return DerivationMetadata(
        method=method,
        method_version=classification.method_version or "1",
        implementation=implementation,
        derivation_inputs=inputs,
        parameters=parameters,
    )


def _safe_parameter_projection(
    method: str, arguments: Mapping[str, Any], private_paths: Collection[str]
) -> dict[str, Any]:
    """Project effective arguments to the method's safe, non-sensitive subset."""

    import json

    from forensic_agent.core.tool_standardization import redact_private_source_literals

    allowed = _SAFE_PARAMETERS_BY_METHOD.get(method, frozenset())
    projected = {
        key: value
        for key, value in arguments.items()
        if key in allowed and key not in _ALWAYS_DROP_PARAMETERS
    }
    safe = redact_private_source_literals(projected, private_paths)
    return json.loads(canonical_json(safe))


def is_classified(tool_name: str) -> bool:
    """Whether ``tool_name`` has an authoritative classification (any arguments)."""

    return (
        tool_name in _PER_CALL_RESOLVERS
        or tool_name in _REFERENCE_TOOLS
        or tool_name in _OBSERVED_TOOLS
        or tool_name in _DERIVED_TOOLS
    )


def classified_tool_names() -> frozenset[str]:
    """Every tool name with a fixed (non-per-call) authoritative classification."""

    return frozenset(_REFERENCE_TOOLS | _OBSERVED_TOOLS | set(_DERIVED_TOOLS))


__all__ = [
    "Classification",
    "ToolClassificationError",
    "MEMORY_OPERATIONS",
    "PCAP_OPERATIONS",
    "REGISTRY_OPERATIONS",
    "classify_tool_result",
    "build_derivation_metadata",
    "is_classified",
    "classified_tool_names",
]
