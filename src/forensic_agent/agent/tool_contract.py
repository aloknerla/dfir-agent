"""Standardization, provenance, and finding contract for forensic functions."""

from __future__ import annotations

import hashlib
import itertools
import os
import re
from collections.abc import Collection, Mapping
from urllib.parse import quote

from langchain_core.tools import StructuredTool

from forensic_agent.agent.case_evidence import (
    CaseEvidenceSource,
    DerivedArtifactEvidenceSource,
)
from forensic_agent.agent.derived_artifacts import (
    DerivedArtifactCatalog,
    named_artifact_path,
)
from forensic_agent.agent.tool_operations import (
    DOMAIN_FUNCTIONS,
    LEGACY_FUNCTION_DISPOSITIONS,
    resolved_operation,
)
from forensic_agent.agent.tool_taxonomy import (
    _HOST_PATH_TOOLS,
    _MEMORY_TOOLS,
    _PCAP_TOOLS,
    _REFERENCE_TOOLS,
    _TIMELINE_TOOLS,
    CITED_RESULT_INPUT_TOOLS,
)
from forensic_agent.agent.upstream_attestation import attest_call
from forensic_agent.core.backend_versions import (
    BackendVersionRegistry,
    backend_versions_for_environment,
)
from forensic_agent.core.repro import canonical_json, sha256_hex
from forensic_agent.core.tool_standardization import (
    COMMON_CASE_TOOL_DATA_TYPES,
    common_case_artifact_locator,
    redact_private_source_literals,
    standardize_case_evidence_result,
)
from forensic_agent.tools.pcap_sources import PcapSourceCatalog

# Stable semantic discriminators for the versioned tool-result contract.  They are
# intentionally independent of the Python collection key used by a legacy tool
# (``entries``, ``rows``, ``hits`` ...).
_TOOL_DATA_TYPES = {
    **COMMON_CASE_TOOL_DATA_TYPES,
    # The whole-image content search is the first operation with no
    # pre-consolidation predecessor, so :func:`_semantic_tool_name` resolves it
    # to the function's own name.  Its result shape is declared here rather than
    # left to the ``forensic.<name>`` fallback, which would publish OUR function
    # name where a reader expects the kind of thing the result is.
    "filesystem_query": "filesystem.image_search_hits",
    # The same case one function over: the hardware-address lookup has no
    # pre-consolidation predecessor, so it publishes its own result shape.
    "artifact_reference_query": "reference.hardware_vendor",
    "verify_image_integrity": "evidence.integrity",
    "registry_ripper": "windows.registry_records",
    "windows_local_accounts": "windows.local_accounts",
    "windows_network_config": "windows.network_configuration",
    "windows_domain_identity": "windows.domain_identity",
    "usb_storage_history": "windows.usb_storage_history",
    "installed_applications": "windows.installed_applications",
    "configuration_query": "filesystem.configuration_records",
    "find_email_addresses": "filesystem.email_address_records",
    "google_drive_sync_events": "application.google_drive_sync_events",
    "printing_activity_events": "application.printing_activity_events",
    "gcode_metadata": "application.gcode_metadata",
    "printing_job_sessions": "application.printing_job_sessions",
    "bulk_extract": "filesystem.bulk_features",
    "memory_query": "memory.plugin_records",
    "memory_malware_scan": "memory.malware_signature_scan",
    "memory_strings": "memory.string_hits",
    "pcap_query": "network.capture_records",
    "reconstruct_http_exfil": "network.reconstructed_object",
    "archive_query": "archive.records",
    "ocr_image": "image.ocr_text",
    "read_text_file": "host_file.text_content",
    "decode": "derived.decoded_value",
    "hash_file": "host_file.hash",
    "hash_lookup": "hashset.classification",
    "vision_read": "image.vision_text",
}

#: In-image ``path`` readers OUTSIDE the common palette, mapped to whether the
#: image root is a legal value for them.  The common-palette in-image readers are
#: deliberately absent: their locator is derived by the single owner,
#: :func:`forensic_agent.core.tool_standardization.common_case_artifact_locator`,
#: which :func:`_artifact_locator` defers to before this map is ever consulted, so
#: listing them here would be a second copy of a rule that used to drift.  These
#: are the readers that own no common-palette identity.
_IN_IMAGE_PATH_TOOLS: Mapping[str, bool] = {
    "google_drive_sync_events": False,
    "configuration_query": False,
    "gcode_metadata": False,
}
_IN_IMAGE_SCOPE_TOOLS = {"printing_activity_events", "printing_job_sessions"}

#: ``(domain function, operation) -> previous model-visible name``, derived from
#: the consolidation's own disposition table so it cannot drift from it.
_LEGACY_NAME_BY_OPERATION: dict[tuple[str, str], str] = {
    (disposition.domain_function, operation): disposition.legacy_name
    for disposition in LEGACY_FUNCTION_DISPOSITIONS.values()
    if disposition.status == "operation" and disposition.domain_function is not None
    for operation in disposition.operations
}


def _semantic_tool_name(tool_name: str, args: Mapping[str, object]) -> str:
    """The pre-consolidation identity of one call, resolved per operation.

    Standardization is keyed by what a result MEANS — data type, page unit,
    locator and normalization rules were all declared per previous function
    name.  A consolidated domain function carries several of those result
    shapes, one per operation, so the semantic key has to be resolved from the
    operation the facade will execute; renaming the function must not silently
    demote a ``read_file`` page to the generic adapter.  Provenance still names
    the function the model actually called.  Names outside the domain registry
    (the historical surface) resolve to themselves.
    """

    function = DOMAIN_FUNCTIONS.get(tool_name)
    if function is None:
        return tool_name
    raw_operation = args.get("operation")
    if isinstance(raw_operation, str) and raw_operation.strip():
        # Mirrors the facade's own normalization so the identity resolved here
        # is the identity that validated and dispatched.
        operation = raw_operation.strip().casefold()
    elif function.default_operation is not None:
        operation = function.default_operation
    else:
        return tool_name
    return _LEGACY_NAME_BY_OPERATION.get((tool_name, operation), tool_name)


def _executed_operation(tool_name: str, args: Mapping[str, object]) -> str | None:
    """Which registered operation one recorded call ran, or ``None``.

    Only the shared registry knows what an omitted ``operation`` means, so the
    answer is asked of it rather than re-derived from an argument name here; a
    second reading of the same question is how the shape rules below came to
    recognise the pre-consolidation selector only.  The historical bindings are
    not registered call shapes — pcap spells the selector ``query`` there and
    their signatures carry arguments no operation model defines — so the registry
    refuses them, and their own selector is then the only statement of which view
    ran.  It is accepted solely when it names an operation the registry defines,
    so an argument that merely happens to be called ``query`` (the SQL of a
    ``sqlite_query`` call) can never be read as one.
    """

    function = DOMAIN_FUNCTIONS.get(tool_name)
    if function is None:
        return None
    operation = resolved_operation(tool_name, args)
    if operation is not None:
        return operation
    legacy_selector = args.get("query")
    if not isinstance(legacy_selector, str):
        return None
    selected = legacy_selector.strip().casefold()
    return selected if selected in function.operation_names() else None


def _stated_operation(tool_name: str, args: Mapping[str, object]) -> str | None:
    """The registered operation a call NAMES, or ``None`` when it names none.

    A locator cites what one call addressed.  Where the caller wrote no selector
    the registry still resolves the function's declared default, but that word
    was never part of the call, so it is not part of the citation either; the
    argument digest published beside the view already tells two such calls apart.
    """

    for selector in ("operation", "query"):
        value = args.get(selector)
        if isinstance(value, str) and value.strip():
            return _executed_operation(tool_name, args)
    return None


TOOL_RESULT_CONTRACT_NOTE = (
    "TOOL RESULT CONTRACT: every forensic tool response uses schema "
    "forensic.tool-result.v2. Read data.items and data.attributes; status=partial means "
    "usable data with incomplete source coverage, whereas status=error means the call failed. "
    "page.truncated describes pagination only and MUST NOT be confused with "
    "coverage.complete. provenance.type=case_evidence may support a case claim; "
    "provenance.type=reference_knowledge is procedural NON_EVIDENCE and may guide the next "
    "tool call but can never prove a fact about this case. provenance.evidence_class states "
    "what the result IS: observed=reported by the upstream tool named in "
    "provenance.upstream_backends, derived=computed by this system over the inputs in "
    "provenance.derivation, reference=procedural knowledge, diagnostic=the run could not "
    "establish which component produced it or what it was computed over, so it may be read "
    "but can never support a case claim. Verify the canonical receipt before "
    "treating a result as auditable; receipt verification is performed by the deterministic "
    "harness/recorder, not by guessing the hash yourself."
)


def _valid_sha256(value: object) -> str | None:
    text = str(value or "").casefold()
    return text if re.fullmatch(r"[0-9a-f]{64}", text) else None


#: How many leading hex characters of the canonical-argument digest the emitted
#: invocation id carries.  Declared once, here, because the emitter writes it and
#: :func:`result_binds_call` reads it; two spellings of one format is how a
#: binding check silently stops binding anything.
_INVOCATION_ARGUMENT_DIGEST_CHARACTERS = 12


def invocation_binds_arguments(invocation_id: str, arguments: Mapping[str, object]) -> bool:
    """Whether an emitted invocation id was minted from exactly these arguments.

    The id is ``<namespace>:<ordinal>:<argument digest prefix>``, built by the
    standardizer from the canonical JSON of the realized call.  It is the run's
    OWN statement about which arguments a result belongs to, and the active
    contract publishes it where the historical envelope published a digest of the
    complete argument set.
    """

    expected = sha256_hex(canonical_json(dict(arguments)))[
        :_INVOCATION_ARGUMENT_DIGEST_CHARACTERS
    ]
    _, separator, suffix = invocation_id.rpartition(":")
    return bool(separator) and suffix == expected


def result_binds_call(result, arguments: Mapping[str, object]) -> bool:
    """Whether a standardized result belongs to a call with exactly ``arguments``.

    Two fields can answer, and the answer is taken from whichever one the
    envelope in hand actually publishes.  The historical envelope publishes
    ``tool.parameters_sha256`` over the complete argument set.  The active
    contract deliberately does not: that digest is an oracle for a low-entropy
    secret passed as an argument, so it publishes at most a digest of the
    redaction-safe projection of a DERIVED call's parameters and nothing at all
    for an observation.  What it does publish for every class is the invocation
    identity the run minted from the same canonical arguments.

    Both are statements the runtime standardizer made about one call, never the
    tool's and never the model's, so either answering yes settles the same
    question.  Requiring the digest alone would silently stop binding anything
    the moment the emitter moved to the active contract — a check that quietly
    becomes a no-op is worse than one that is absent.
    """

    if result.provenance.tool.parameters_sha256 == sha256_hex(
        canonical_json(dict(arguments))
    ):
        return True
    return invocation_binds_arguments(result.provenance.invocation_id, arguments)


#: The case identity a run publishes when it is bound to no case at all.  The
#: invocation id has always carried this word for the same situation; reusing it
#: keeps one spelling for one fact.  It can never equal an active case id, so a
#: result carrying it is refused by the final check rather than admitted unbound.
UNBOUND_CASE_ID = "case-unset"

#: Distinct from the development manifest digest, so provenance never claims a
#: verified component bundle that an interactive run does not have.
_CONSOLE_BUNDLE_SEMANTICS = "sha256-canonical-console-bound-evidence-v1"


def console_bundle_digest(
    image_sha256: object, *, bound_modalities: Collection[str] = ()
) -> str | None:
    """Identify one bound evidence set, disclosing no host path.

    The deterministic recovery stages compare this digest across results to
    refuse a correlation that mixes two evidence sets.  Without an attested image
    digest the value is absent and those stages keep failing closed rather than
    binding to something unverified.

    The receipt builder computes the same value for the same evidence,
    because a receipt has to stay byte-identical to the live result.
    """

    image_sha = _valid_sha256(image_sha256)
    if image_sha is None:
        return None
    return sha256_hex(
        canonical_json(
            {
                "semantics": _CONSOLE_BUNDLE_SEMANTICS,
                "disk_sha256": image_sha,
                "bound_modalities": sorted(bound_modalities),
            }
        )
    )


def _console_bundle_digest(
    disk,
    *,
    timeline_path: str | None,
    memory_path: str | None,
    pcap_path: str | None,
    pcap_sources: object | None,
) -> str | None:
    """Derive the run's bundle digest from the evidence bound to this graph."""

    return console_bundle_digest(
        getattr(disk, "image_sha", None) if disk is not None else None,
        bound_modalities=[
            modality
            for modality, value in (
                ("timeline", timeline_path),
                ("memory", memory_path),
                ("pcap", pcap_path or pcap_sources),
            )
            if value
        ],
    )


def _console_source_attributes(
    tool_name: str, bundle_sha256: str | None = None
) -> dict[str, object] | None:
    """Name the evidence modality when no explicit case-source descriptor is bound.

    The deterministic recovery stages read ``active_modality`` to decide whether
    a result came from the disk, the capture, and so on.  Interactive sources may
    not carry that richer descriptor, so the modality is derived from the same
    registered-tool classification used for source attribution.  This is not a
    new class of claim:
    ``_tool_source`` already derives the source URI and media type for the same
    tool from the same classification.
    """

    if tool_name in _REFERENCE_TOOLS:
        return None
    if tool_name in _TIMELINE_TOOLS:
        modality = "timeline"
    elif tool_name in _MEMORY_TOOLS:
        modality = "memory"
    elif tool_name in _PCAP_TOOLS:
        modality = "pcap"
    else:
        modality = "disk"
    attributes: dict[str, object] = {"active_modality": modality}
    if bundle_sha256 is not None:
        attributes["case_bundle_sha256"] = bundle_sha256
        attributes["bundle_digest_semantics"] = _CONSOLE_BUNDLE_SEMANTICS
    return attributes


def _legacy_result_for_contract(tool_name: str, value, args: Mapping[str, object]):
    """Add non-common-tool semantics the generic legacy adapter cannot infer."""

    if not isinstance(value, Mapping):
        return value
    normalized = dict(value)
    if normalized.pop("_bounded", None) is True:
        # ``_bounded`` is the output guard's internal marker that the
        # MODEL-VISIBLE PROJECTION was byte-capped.  Leaking the raw marker told
        # the model nothing it could act on, so state the fact explicitly instead.
        # This is projection truncation only: it says nothing about whether the
        # tool examined its whole source (analytical coverage) or returned the
        # whole requested page (window completeness), which are tracked
        # separately and must not be inferred from it.
        normalized["projection_truncated"] = True
        normalized.setdefault("truncated", True)
        normalized.setdefault(
            "projection_note",
            "the model-visible projection was shortened by the output guard; "
            "the complete tool output was captured and hashed before shaping",
        )
    if (
        tool_name == "pcap_query"
        and _executed_operation(tool_name, args) == "fields"
        and isinstance(normalized.get("named_rows"), list)
    ):
        # The generic adapter otherwise prefers positional ``rows`` and demotes
        # the safer field-name-bound records to metadata.  Promote semantic rows
        # while retaining the raw positional representation for audit/debug use.
        # Keyed off the operation the registry resolves, not off one surface's
        # argument NAME: the facade passes ``operation`` where the historical
        # binding passed ``query``, and reading only the latter silently demoted
        # every consolidated field read back to unlabelled column arrays.
        normalized["positional_rows"] = normalized.get("rows", [])
        normalized["items"] = normalized["named_rows"]
    if tool_name == "read_text_file":
        if normalized.get("size") is not None:
            normalized.setdefault("total_bytes", normalized.get("size"))
    if tool_name == "read_text_file" and type(normalized.get("eof")) is bool:
        eof = normalized["eof"]
        normalized["truncated"] = not eof
        if eof:
            normalized["next_offset"] = None
    return normalized


def _common_result_for_contract(tool_name: str, value):
    """Normalize common-tool semantics that cannot be inferred generically."""

    if not isinstance(value, Mapping):
        return value
    normalized = dict(value)
    if tool_name == "search_keyword" and normalized.get("pagination_supported") is False:
        # ``search_keyword`` is a bounded, non-resumable source scan.  Its raw
        # legacy ``truncated`` flag means that source coverage is incomplete, not
        # that another item page can be requested.  Preserve the explicit
        # scan_complete/coverage fields but do not let the generic adapter invent
        # a page.next_offset that the tool schema cannot consume.
        normalized["truncated"] = False
        normalized["next_offset"] = None
    return normalized


def _artifact_locator(tool_name: str, args: Mapping[str, object]) -> str:
    # The common-palette locator rule has exactly one owner:
    # core.tool_standardization.common_case_artifact_locator, which the
    # receipt path already calls directly.  Defer to it here rather than
    # deciding the same question a second way: the copy that used to win on this
    # live path disagreed with the declared owner on real inputs (it truncated a
    # long in-image path to a digest, committed an invalid path instead of
    # rejecting it, and named a raw argument where the owner names the view a call
    # ran), so a live result and its receipt could carry different
    # locators for the same call.  Only tools OUTSIDE that palette are decided
    # below, and their rule has no counterpart in the owner.
    if tool_name in COMMON_CASE_TOOL_DATA_TYPES:
        return common_case_artifact_locator(tool_name, args)
    if tool_name in _IN_IMAGE_SCOPE_TOOLS:
        from forensic_agent.core.evidence_locator import (
            EvidencePathError,
            evidence_locator_commitment,
            normalize_evidence_path,
        )

        raw_scope = args.get("start", "/")
        if not isinstance(raw_scope, str):
            return f"start:{evidence_locator_commitment(raw_scope)}"
        try:
            scope = normalize_evidence_path(raw_scope)
        except EvidencePathError:
            return f"start:{evidence_locator_commitment(raw_scope)}"
        return f"start:{scope}"
    for key in (
        "path",
        "archive_path",
        "image_path",
        "hive",
        "log",
        "plugin",
        "feature",
        "name_or_keyword",
    ):
        value = args.get(key)
        if value not in (None, ""):
            text = str(value)
            if tool_name in _IN_IMAGE_PATH_TOOLS and key == "path":
                from forensic_agent.core.evidence_locator import (
                    EvidencePathError,
                    evidence_locator_commitment,
                    normalize_evidence_path,
                )

                try:
                    text = normalize_evidence_path(
                        text, allow_root=_IN_IMAGE_PATH_TOOLS[tool_name]
                    )
                except EvidencePathError:
                    return f"{key}:{evidence_locator_commitment(text)}"
            if tool_name in _HOST_PATH_TOOLS and key in {
                "path",
                "archive_path",
                "image_path",
            }:
                return f"{key}:private-source"
            if len(text) > 240:
                text = "sha256:" + sha256_hex(text)
            return f"{key}:{text}"
    # Nothing this call names is an object; what it identifies is the VIEW it ran
    # over the source.  The pre-consolidation locator read that view off the one
    # function that spelled its selector ``query``, which the facade no longer
    # passes, so every consolidated call fell through to a bare digest naming
    # nothing a reader could act on.  The registry states the view for every
    # function.  The argument digest stays beside it: two calls of one view over
    # different arguments are two artifacts and must not share a locator.
    identity = sha256_hex(canonical_json(dict(args)))[:16]
    operation = _stated_operation(tool_name, args)
    if operation is None:
        return f"tool://{quote(tool_name, safe='')}/{identity}"
    return f"tool://{quote(tool_name, safe='')}/{quote(operation, safe='')}/{identity}"


def _tool_source(
    tool_name: str,
    args: Mapping[str, object],
    *,
    disk,
    timeline_path: str | None,
    memory_path: str | None,
    pcap_path: str | None,
    result,
    # A call reading a reconstructed artifact is served by the derived source;
    # both carry the same source identity this reads.
    case_evidence_source: CaseEvidenceSource | DerivedArtifactEvidenceSource | None = None,
) -> tuple[str, str | None, str | None, str | None]:
    """Return source-id, sha256, URI and media type without hashing evidence at call time."""
    if tool_name in _REFERENCE_TOOLS:
        # Reference tools read a generic bundled table, never the case evidence,
        # so they carry a static non-evidentiary source rather than a case bundle.
        # The table each answer actually came from is named in the result itself.
        return (
            "bundled-procedural-reference",
            None,
            "pkg://forensic_agent/reference",
            "application/json",
        )

    if case_evidence_source is not None:
        # Resolve the modality here as well as when attributes are emitted.  This
        # deliberately fails closed for inline/derived tools and for any direct
        # parser whose task-selected physical inputs were not bound preflight.
        case_evidence_source.source_attributes_for_tool(tool_name)
        return (
            case_evidence_source.source_id,
            case_evidence_source.case_bundle_sha256,
            case_evidence_source.source_uri,
            case_evidence_source.source_media_type,
        )

    if tool_name in _TIMELINE_TOOLS:
        source_path, media_type = timeline_path, "application/x-plaso-storage"
    elif tool_name in _MEMORY_TOOLS:
        source_path, media_type = memory_path, "application/octet-stream"
    elif tool_name in _PCAP_TOOLS:
        source_path, media_type = pcap_path, "application/vnd.tcpdump.pcap"
    elif tool_name in _HOST_PATH_TOOLS:
        source_path = str(
            args.get("path") or args.get("archive_path") or args.get("image_path") or ""
        )
        media_type = "application/octet-stream"
    elif tool_name == "decode":
        inline = str(args.get("data") or "")
        inline_digest = hashlib.sha256(inline.encode("utf-8")).hexdigest()
        return (
            "inline-derived-input",
            inline_digest,
            f"inline://sha256/{inline_digest}",
            "text/plain",
        )
    else:
        source_path = str(getattr(disk, "image_path", "") or "")
        media_type = "application/x-disk-image"

    digest: str | None = None
    if disk is not None and source_path == str(getattr(disk, "image_path", "") or ""):
        digest = _valid_sha256(getattr(disk, "image_sha", None))
    if digest is None and isinstance(result, Mapping):
        digest = _valid_sha256(result.get("sha256"))
    if source_path:
        disk_path = str(getattr(disk, "image_path", "") or "")
        if disk is not None and source_path == disk_path:
            if digest is not None:
                return (
                    f"evidence-sha256:{digest}",
                    digest,
                    f"evidence://sha256/{digest}",
                    media_type,
                )
            return "evidence:opaque-source", None, "evidence://opaque-source", media_type
        if tool_name in _TIMELINE_TOOLS:
            source_kind = "timeline"
        elif tool_name in _MEMORY_TOOLS:
            source_kind = "memory"
        elif tool_name in _PCAP_TOOLS:
            source_kind = "pcap"
        else:
            source_kind = "host-file"
        if digest is not None:
            return (
                f"{source_kind}-sha256:{digest}",
                digest,
                f"artifact://{source_kind}/sha256/{digest}",
                media_type,
            )
        return (
            f"{source_kind}:opaque-source",
            None,
            f"artifact://{source_kind}/opaque-source",
            media_type,
        )
    synthetic = type(disk).__name__ if disk is not None else "unbound"
    return f"runtime:{synthetic}", digest, f"runtime://{synthetic}", media_type


def _private_source_paths(
    tool_name: str,
    args: Mapping[str, object],
    *,
    disk,
    timeline_path: str | None,
    memory_path: str | None,
    pcap_path: str | None,
    pcap_sources: PcapSourceCatalog | None = None,
) -> tuple[str, ...]:
    values = [
        str(getattr(disk, "image_path", "") or ""),
        str(timeline_path or ""),
        str(memory_path or ""),
        str(pcap_path or ""),
    ]
    if pcap_sources is not None:
        values.extend(pcap_sources.paths)
    if tool_name in _HOST_PATH_TOOLS:
        # A host path a caller named is private, except inside the declared
        # payload root: what is in there is this run's own reconstruction, and
        # redacting it breaks the only thing these functions are for.
        from forensic_agent.core.storage_containment import payload_scratch_root

        payload_root = payload_scratch_root()
        prefix = f"{payload_root}{os.sep}" if payload_root is not None else None
        for key in ("path", "archive_path", "image_path"):
            named = str(args.get(key) or "")
            if not named:
                continue
            if prefix is not None and os.path.abspath(named).startswith(prefix):
                continue
            values.append(named)
    return tuple(dict.fromkeys(value for value in values if value))


def _redact_private_source_literals(value, private_paths: Collection[str]):
    """Compatibility delegate to the pure offline/live redaction contract."""

    return redact_private_source_literals(value, private_paths)


#: How a tool reports the one thing it wrote out of the evidence it read.
_RECONSTRUCTION_PATH_FIELD = "saved_to"
#: And how one reports several, as an extraction of many members does.
_RECONSTRUCTED_PATHS_FIELD = "extracted_paths"


def _parent_result_inputs(call_evidence_source: object) -> tuple:
    """The earlier result a reading of a reconstructed artifact descends from."""

    invocation = getattr(call_evidence_source, "producing_invocation_id", None)
    payload_digest = getattr(call_evidence_source, "producing_payload_sha256", None)
    case_id = getattr(call_evidence_source, "case_id", None)
    if not invocation or not payload_digest or not case_id:
        return ()
    from forensic_agent.core.result_contract import ResultInput

    return (
        ResultInput(
            case_id=str(case_id),
            invocation_id=str(invocation),
            payload_sha256=str(payload_digest),
        ),
    )


def _register_reconstructed_artifact(
    catalog: DerivedArtifactCatalog,
    *,
    raw: object,
    wire: object,
    tool_name: str,
    case_id: str,
) -> None:
    """Record an artifact this call wrote, with this call as its parent."""

    if not isinstance(raw, Mapping) or not isinstance(wire, Mapping):
        return
    produced: list[str] = []
    single = raw.get(_RECONSTRUCTION_PATH_FIELD)
    if isinstance(single, str) and single.strip():
        produced.append(single)
    many = raw.get(_RECONSTRUCTED_PATHS_FIELD)
    if isinstance(many, list):
        produced.extend(item for item in many if isinstance(item, str) and item.strip())
    if not produced:
        return
    provenance = wire.get("provenance")
    receipt = wire.get("receipt")
    if not isinstance(provenance, Mapping) or not isinstance(receipt, Mapping):
        return
    for path in produced:
        catalog.register(
            path,
            case_id=case_id,
            producing_invocation_id=str(provenance.get("invocation_id") or ""),
            producing_payload_sha256=str(receipt.get("payload_sha256") or ""),
            producing_tool=tool_name,
        )


def _unproduced_artifact_result(
    *,
    tool_name: str,
    semantic_name: str,
    arguments: Mapping[str, object],
    case_id: str,
    invocation_id: str,
) -> dict:
    """Refuse a reading of a path this run did not produce."""

    from forensic_agent.core.result_contract import (
        EvidenceClass,
        ToolError,
        attach_receipt,
        error_result,
        make_provenance,
    )

    provenance = make_provenance(
        evidence_class=EvidenceClass.DIAGNOSTIC,
        provenance_type=EvidenceClass.DIAGNOSTIC.provenance_type,
        invocation_id=invocation_id,
        case_id=case_id,
        source_id="unproduced-artifact",
        artifact_locator=_artifact_locator(semantic_name, arguments),
        tool_name=tool_name,
        tool_version=__import__("forensic_agent").__version__,
    )
    refused = error_result(
        data_type=_TOOL_DATA_TYPES.get(semantic_name, "tool.result"),
        provenance=provenance,
        error=ToolError(
            code="artifact_not_produced_by_this_run",
            message=(
                "this function reads an artifact reconstructed from the case "
                "evidence, and the named path is not one this run produced, so "
                "the reading would have no lineage to the case"
            ),
        ),
        coverage_reason=(
            "no artifact of this run answers to the named path, so nothing was read"
        ),
    )
    return attach_receipt(refused).model_dump(mode="json")


def _standardize_tool_outputs(
    tools: list,
    *,
    case_id: str | None,
    invocation_namespace: str | None,
    disk,
    timeline_path: str | None = None,
    memory_path: str | None = None,
    pcap_path: str | None = None,
    pcap_sources: PcapSourceCatalog | None = None,
    case_evidence_source: CaseEvidenceSource | None = None,
    derived_artifacts: DerivedArtifactCatalog | None = None,
    on_result=None,
    backend_versions: BackendVersionRegistry | None = None,
) -> list:
    """Wrap LangChain tools with the same MCP-compatible result contract.

    ``backend_versions`` is the host's inventory of the components underneath the
    wrappers.  It is resolved HERE, while the surface is being built, because
    that is a preflight: no evidence is bound yet and no execution cell is open,
    which is the only point at which a command-line backend may be executed to
    state its version.  A caller may supply one instead — the offline receipt path
    builder does, so a receipt describes the host that produced it rather than
    the host that is reading it.
    """
    from forensic_agent import __version__
    from forensic_agent.core.result_contract import (
        EvidenceClass,
        adapt_legacy_result,
        attach_receipt,
        make_provenance,
    )
    from forensic_agent.core.tool_result import canonical_raw_output_sha256
    from forensic_agent.oversight import OversightBoundOutput

    if backend_versions is None:
        backend_versions = backend_versions_for_environment()
    # The active contract binds every result to a case.  A run that states none
    # publishes its own unbound sentinel — the same one the invocation id has
    # always carried — which no active case can equal, so such a result is
    # refused by the final check instead of floating free of any case.
    bound_case_id = case_id or UNBOUND_CASE_ID
    sequence = itertools.count(1)
    # One digest for the whole run: the recovery stages compare it across results
    # and refuse a correlation that mixes two evidence sets, so it must not vary
    # per tool or per modality.
    console_bundle_sha256 = _console_bundle_digest(
        disk,
        timeline_path=timeline_path,
        memory_path=memory_path,
        pcap_path=pcap_path,
        pcap_sources=pcap_sources,
    )
    wrapped_tools = []
    for tool in tools:
        original = tool.func
        name = tool.name
        raw_metadata = getattr(tool, "metadata", None)
        tool_metadata = dict(raw_metadata) if isinstance(raw_metadata, Mapping) else {}

        def make(fn, tool_name):
            def wrapped(**kwargs):
                # Everything SHAPE-keyed below (branch choice, data type, page
                # normalization, locator, source classification) reads the
                # semantic identity; provenance's tool NAME alone stays on the
                # model-visible function the call was made against.
                semantic_name = _semantic_tool_name(tool_name, kwargs)
                call_evidence_source: CaseEvidenceSource | DerivedArtifactEvidenceSource | None = (
                    case_evidence_source
                )
                if tool_name in CITED_RESULT_INPUT_TOOLS and case_evidence_source is not None:
                    # Its input is a value from a result this run already
                    # produced, and the call itself names that parent: the
                    # invocation and the payload digest are arguments of the
                    # operation, so the provenance comes from the citation rather
                    # than from any component of the bundle.
                    cited = type(
                        "CitedParent",
                        (),
                        {
                            "case_id": bound_case_id,
                            "producing_invocation_id": str(
                                kwargs.get("source_invocation_id") or ""
                            ),
                            "producing_payload_sha256": str(
                                kwargs.get("source_payload_sha256") or ""
                            ).casefold(),
                            "producing_tool": "cited result",
                        },
                    )()
                    try:
                        call_evidence_source = case_evidence_source.for_derived_artifact(
                            tool_name, cited
                        )
                    except ValueError:
                        refusal_ordinal = next(sequence)
                        refusal_namespace = invocation_namespace or case_id or UNBOUND_CASE_ID
                        refusal = _unproduced_artifact_result(
                            tool_name=tool_name,
                            semantic_name=semantic_name,
                            arguments=kwargs,
                            case_id=bound_case_id,
                            invocation_id=(
                                f"{refusal_namespace}:{refusal_ordinal:04d}:"
                                f"{sha256_hex(canonical_json(kwargs))[:12]}"
                            ),
                        )
                        if on_result is not None:
                            on_result(tool_name, kwargs, refusal)
                        return refusal
                if tool_name in _HOST_PATH_TOOLS and case_evidence_source is not None:
                    # A function reading a reconstructed artifact is served by
                    # the call that produced it; an unregistered path is a host
                    # object with no lineage to this case.
                    named = named_artifact_path(kwargs)
                    artifact = (
                        derived_artifacts.resolve(named)
                        if derived_artifacts is not None
                        else None
                    )
                    if artifact is None:
                        refusal_ordinal = next(sequence)
                        refusal_namespace = invocation_namespace or case_id or UNBOUND_CASE_ID
                        refusal = _unproduced_artifact_result(
                            tool_name=tool_name,
                            semantic_name=semantic_name,
                            arguments=kwargs,
                            case_id=bound_case_id,
                            invocation_id=(
                                f"{refusal_namespace}:{refusal_ordinal:04d}:"
                                f"{sha256_hex(canonical_json(kwargs))[:12]}"
                            ),
                        )
                        if on_result is not None:
                            on_result(tool_name, kwargs, refusal)
                        return refusal
                    call_evidence_source = case_evidence_source.for_derived_artifact(
                        tool_name, artifact
                    )
                if tool_name in _PCAP_TOOLS and pcap_sources is not None:
                    selected_binding = pcap_sources.resolve(kwargs.get("source"))
                    # Only a case source narrows to a component. A derived-artifact
                    # source is served to the host-path and cited-result functions,
                    # and neither set overlaps the PCAP ones.
                    if isinstance(call_evidence_source, CaseEvidenceSource):
                        call_evidence_source = call_evidence_source.for_tool_component(
                            tool_name,
                            selected_binding.component_id,
                            related_component_ids=(
                                pcap_sources.default_input_component_ids
                                if selected_binding.component_id
                                == pcap_sources.default_component_id
                                else ()
                            ),
                        )
                from forensic_agent.core.output_capture import unwrap_captured

                produced = fn(**kwargs)
                if isinstance(produced, OversightBoundOutput):
                    action = produced.action
                    raw = produced.output
                    capture = getattr(produced, "capture", None)
                else:
                    action = None
                    # Without the oversight layer the capture arrives paired with
                    # the value itself.
                    raw, capture = unwrap_captured(produced)
                # ``raw`` is now the COMPLETE pre-projection result: the
                # model-facing boundary runs after standardization, so the
                # receipt built below covers the whole canonical payload rather
                # than a preview.  The oversight entry binds the bytes captured
                # before any shaping, so compare against exactly those.
                captured_sha256 = (
                    capture.captured_sha256
                    if capture is not None
                    else canonical_raw_output_sha256(raw)
                )
                # A result whose complete output was not RETAINED cannot be an
                # evidentiary basis, even when the tool itself succeeded: nothing
                # can be re-derived or independently checked against it later.
                # Retention failure is therefore treated exactly like a capture cut
                # short — the call is published as a non-admissible error.
                capture_retained = capture is None or (
                    capture.capture_complete and not capture.storage_failed
                )
                capture_complete = capture_retained
                # An incomplete capture cannot yield an admissible case result:
                # there IS no complete-raw-output digest, and putting the prefix
                # digest in ``raw_output_sha256`` would name a fragment as the
                # whole.  v1 requires the raw digest, the oversight entry digest
                # and the sequence to be supplied together, so all three are
                # withheld and the result is published as a non-admissible error.
                # The prefix digest survives only in the private audit record,
                # under a name that says it covers a prefix.
                raw_output_sha256 = captured_sha256 if capture_complete else None
                oversight_entry_sha256 = None
                oversight_sequence = None
                if action is not None:
                    recorded_raw_sha256 = _valid_sha256(action.get("canonical_output_sha256"))
                    oversight_entry_sha256 = _valid_sha256(action.get("entry_hash"))
                    action_sequence = action.get("seq")
                    # Only a complete capture has a canonical output digest to
                    # agree on; an incomplete one is published as a non-admissible
                    # error below and binds nothing.
                    if capture_complete and recorded_raw_sha256 != captured_sha256:
                        raise RuntimeError(
                            "oversight action does not bind the captured output being standardized"
                        )
                    if oversight_entry_sha256 is None:
                        raise RuntimeError("oversight action has no valid hash-chain entry digest")
                    if (
                        isinstance(action_sequence, bool)
                        or not isinstance(action_sequence, int)
                        or action_sequence < 0
                    ):
                        raise RuntimeError("oversight action has no valid sequence number")
                    oversight_sequence = action_sequence
                if not capture_complete:
                    # Withhold the whole binding triple together, so the contract
                    # invariant holds and nothing claims a digest it does not have.
                    oversight_entry_sha256 = None
                    oversight_sequence = None
                private_paths = _private_source_paths(
                    semantic_name,
                    kwargs,
                    disk=disk,
                    timeline_path=timeline_path,
                    memory_path=memory_path,
                    pcap_path=pcap_path,
                    pcap_sources=pcap_sources,
                )
                ordinal = next(sequence)
                args_digest = sha256_hex(canonical_json(kwargs))
                namespace = invocation_namespace or case_id or UNBOUND_CASE_ID
                invocation_id = f"{namespace}:{ordinal:04d}:{args_digest[:12]}"
                if not capture_complete:
                    # Retention stopped before the tool's output was fully
                    # captured, so this call cannot back a case claim: there is no
                    # complete-output digest to bind it to.  Publish a
                    # non-admissible error carrying none of the binding triple,
                    # rather than a result that looks admissible on a fragment.
                    from forensic_agent.core.result_contract import ToolError, error_result

                    # DIAGNOSTIC, not the operation's declared class: a call whose
                    # output was not retained cannot be attributed to a producing
                    # component or reproduced from anything, which is exactly what
                    # that class states.  It also keeps the envelope constructible
                    # without naming a backend this call cannot honestly name.
                    incomplete_provenance = make_provenance(
                        evidence_class=EvidenceClass.DIAGNOSTIC,
                        provenance_type=EvidenceClass.DIAGNOSTIC.provenance_type,
                        invocation_id=invocation_id,
                        case_id=bound_case_id,
                        source_id="capture-incomplete",
                        artifact_locator=_artifact_locator(semantic_name, kwargs),
                        tool_name=tool_name,
                        tool_version=__version__,
                    )
                    incomplete = error_result(
                        data_type=_TOOL_DATA_TYPES.get(semantic_name, "tool.result"),
                        provenance=incomplete_provenance,
                        error=ToolError(
                            code=(
                                "output_retention_failed"
                                if capture is not None and capture.storage_failed
                                else "output_capture_incomplete"
                            ),
                            message=(
                                "the tool's complete output was not retained (capture "
                                "was cut short or its storage failed), so no attestable "
                                "complete-output digest exists for this call and it "
                                "cannot be used as case evidence"
                            ),
                        ),
                        coverage_reason=(
                            "the tool's output was not retained in full, so neither its "
                            "content nor its coverage can be attested"
                        ),
                    )
                    wire = attach_receipt(incomplete).model_dump(mode="json")
                    if on_result is not None:
                        on_result(tool_name, kwargs, wire)
                    return wire
                if semantic_name in COMMON_CASE_TOOL_DATA_TYPES:
                    contract_raw = _common_result_for_contract(semantic_name, raw)
                    source_id, source_sha, source_uri, media_type = _tool_source(
                        semantic_name,
                        kwargs,
                        disk=disk,
                        timeline_path=timeline_path,
                        memory_path=memory_path,
                        pcap_path=pcap_path,
                        result=raw,
                        case_evidence_source=call_evidence_source,
                    )
                    source_attributes = (
                        call_evidence_source.source_attributes_for_tool(semantic_name)
                        if call_evidence_source is not None
                        else _console_source_attributes(semantic_name, console_bundle_sha256)
                    )
                    attestation = attest_call(
                        tool_name=tool_name,
                        arguments=kwargs,
                        raw_result=contract_raw,
                        case_id=bound_case_id,
                        source_id=source_id,
                        source_sha256=source_sha,
                        source_uri=source_uri,
                        artifact_locator=_artifact_locator(semantic_name, kwargs),
                        implementation=f"forensic_agent.agent.runtime:{semantic_name}",
                        private_paths=private_paths,
                        result_inputs=_parent_result_inputs(call_evidence_source),
                        backend_versions=backend_versions,
                    )
                    result = standardize_case_evidence_result(
                        contract_raw,
                        tool_name=semantic_name,
                        arguments=kwargs,
                        invocation_id=invocation_id,
                        case_id=bound_case_id,
                        evidence_class=attestation.evidence_class,
                        derivation=attestation.derivation,
                        upstream_backends=attestation.upstream_backends,
                        source_id=source_id,
                        source_sha256=source_sha,
                        source_uri=source_uri,
                        source_media_type=media_type,
                        source_attributes=source_attributes,
                        artifact_locator=_artifact_locator(semantic_name, kwargs),
                        private_paths=private_paths,
                        tool_version=__version__,
                        # The implementation names the executed legacy adapter;
                        # the provenance NAME stays the function the model saw.
                        tool_implementation=f"forensic_agent.agent.runtime:{semantic_name}",
                        model_visible_tool_name=tool_name,
                        raw_output_sha256=(raw_output_sha256 if action is not None else None),
                        oversight_entry_sha256=oversight_entry_sha256,
                        oversight_sequence=oversight_sequence,
                        # A centrally bounded preview is incomplete evidence.
                        # Keep the live model-visible contract aligned with the
                        # stricter receipt path.
                        bounded_output_is_incomplete=True,
                    )
                    wire = result.model_dump(mode="json")
                else:
                    safe_raw = _redact_private_source_literals(raw, private_paths)
                    normalized = _legacy_result_for_contract(semantic_name, safe_raw, kwargs)
                    source_id, source_sha, source_uri, media_type = _tool_source(
                        semantic_name,
                        kwargs,
                        disk=disk,
                        timeline_path=timeline_path,
                        memory_path=memory_path,
                        pcap_path=pcap_path,
                        result=normalized,
                        case_evidence_source=call_evidence_source,
                    )
                    source_attributes = (
                        call_evidence_source.source_attributes_for_tool(semantic_name)
                        if call_evidence_source is not None
                        and semantic_name not in _REFERENCE_TOOLS
                        else _console_source_attributes(semantic_name, console_bundle_sha256)
                    )
                    data_type = _TOOL_DATA_TYPES.get(
                        semantic_name, f"forensic.{semantic_name}"
                    )
                    tool_version = __version__
                    tool_implementation = f"forensic_agent.agent.runtime:{semantic_name}"
                    locator = _artifact_locator(semantic_name, kwargs)
                    attestation = attest_call(
                        tool_name=tool_name,
                        arguments=kwargs,
                        raw_result=normalized,
                        case_id=bound_case_id,
                        source_id=source_id,
                        source_sha256=source_sha,
                        source_uri=source_uri,
                        artifact_locator=locator,
                        implementation=tool_implementation,
                        private_paths=private_paths,
                        result_inputs=_parent_result_inputs(call_evidence_source),
                        backend_versions=backend_versions,
                    )
                    provenance = make_provenance(
                        evidence_class=attestation.evidence_class,
                        provenance_type=attestation.evidence_class.provenance_type,
                        derivation=attestation.derivation,
                        upstream_backends=attestation.upstream_backends,
                        invocation_id=invocation_id,
                        case_id=bound_case_id,
                        source_id=source_id,
                        source_sha256=source_sha,
                        source_uri=source_uri,
                        source_media_type=media_type,
                        source_attributes=source_attributes,
                        artifact_locator=locator,
                        artifact_type=data_type,
                        tool_name=tool_name,
                        tool_version=tool_version,
                        tool_implementation=tool_implementation,
                        raw_output_sha256=(raw_output_sha256 if action is not None else None),
                        oversight_entry_sha256=oversight_entry_sha256,
                        oversight_sequence=oversight_sequence,
                    )
                    result = adapt_legacy_result(
                        normalized,
                        data_type=data_type,
                        provenance=provenance,
                    )
                    wire = attach_receipt(result).model_dump(mode="json")
                if derived_artifacts is not None:
                    # Recorded where the finished result exists: the artifact's
                    # parent is THIS call, and its invocation and payload digest
                    # are what a later reading must cite.
                    _register_reconstructed_artifact(
                        derived_artifacts,
                        raw=raw,
                        wire=wire,
                        tool_name=semantic_name,
                        case_id=bound_case_id,
                    )
                if on_result is not None:
                    on_result(tool_name, kwargs, wire)
                return wire

            return wrapped

        wrapped_tools.append(
            StructuredTool.from_function(
                make(original, name),
                name=name,
                description=tool.description,
                args_schema=tool.args_schema,
                metadata=tool_metadata or None,
            )
        )
    return wrapped_tools
