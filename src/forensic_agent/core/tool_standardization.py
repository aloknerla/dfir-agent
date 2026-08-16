"""Pure standardization of trusted forensic tool output.

This module is deliberately free of model, network, subprocess, and filesystem
opening code.  A caller supplies an already-produced raw result plus explicit
case/evidence identity.  The helper then:

* removes caller-declared private host paths;
* maps the result into the active contract, ``forensic.tool-result.v2``;
* binds exact canonical arguments and blinded evidence provenance; and
* attaches a verifiable canonical receipt.

Keeping this operation pure makes it usable by offline builders without
importing the agent graph or any model transport.  That purity is also why the
epistemic class, the derivation chain and the executed backends arrive as
arguments rather than being decided here: deciding them needs the operation
registry, the classifier and the host's version inventory, all of which live in
the agent layer.  :mod:`forensic_agent.agent.upstream_attestation` decides them
once, and every emitter passes what it decided, so they cannot come to disagree
about one call.
"""

from __future__ import annotations

import json
import ntpath
import os
import posixpath
import re
from collections.abc import Collection, Mapping
from typing import Any
from urllib.parse import quote

from forensic_agent import __version__
from forensic_agent.core.evidence_locator import (
    EvidencePathError,
    evidence_locator_commitment,
    normalize_evidence_path,
)
from forensic_agent.core.repro import canonical_json, sha256_hex
from forensic_agent.core.result_contract import (
    DerivationMetadata,
    EvidenceClass,
    ToolResult,
    ToolStatus,
    UpstreamBackend,
    adapt_legacy_result,
    attach_receipt,
    make_provenance,
)

COMMON_CASE_TOOL_PALETTE = (
    "list_directory",
    "find_files",
    "file_metadata",
    "read_file",
    "search_keyword",
    "search_in_file",
    "evidence_file_hash",
    "sqlite_query",
    "recover_deleted_files",
    "registry_query",
    "evtx_query",
)

COMMON_CASE_TOOL_DATA_TYPES: Mapping[str, str] = {
    "list_directory": "filesystem.directory_listing",
    "find_files": "filesystem.file_discovery",
    "file_metadata": "filesystem.metadata",
    "read_file": "filesystem.file_content",
    "search_keyword": "filesystem.search_hits",
    "search_in_file": "filesystem.file_search_hits",
    "evidence_file_hash": "filesystem.file_hash",
    "sqlite_query": "filesystem.sqlite_records",
    "recover_deleted_files": "filesystem.recovery",
    "registry_query": "windows.registry_records",
    "evtx_query": "windows.event_records",
}

#: Common-palette readers whose ``path`` argument is an IN-IMAGE locator, mapped
#: to whether the image root is a legal value for that reader.  Public because it
#: is the single declaration of that policy: the runtime standardizer canonicalizes
#: the same argument before publishing it as ``provenance.artifact.locator``, and a
#: second list there would drift from this one.
COMMON_CASE_PATH_TOOLS_ALLOW_ROOT: Mapping[str, bool] = {
    "list_directory": True,
    "file_metadata": False,
    "read_file": False,
    "search_in_file": False,
    "evidence_file_hash": False,
    "sqlite_query": False,
    "recover_deleted_files": True,
}

PRIVATE_SOURCE_REDACTION_TOKEN = "artifact://private/redacted-source"


class ToolStandardizationError(RuntimeError):
    """A raw tool result cannot be safely frozen as case evidence."""


class IncompleteToolResultError(ToolStandardizationError):
    """A call marked complete did not return one complete unpaginated result."""


def _json_native(value: Any) -> Any:
    """Normalize legacy Python values before redaction and contract validation."""

    return json.loads(canonical_json(value))


def _dos_83_component(component: str) -> str | None:
    """Return a conservative first-alias probe without querying the host filesystem."""

    if component in {"", ".", ".."} or component.endswith(":"):
        return None
    stem, extension = os.path.splitext(component)
    safe_stem = "".join(character for character in stem if character.isalnum()).upper()
    safe_extension = "".join(
        character for character in extension.removeprefix(".") if character.isalnum()
    ).upper()
    if not safe_stem:
        return None
    alias = f"{safe_stem[:6]}~1"
    return f"{alias}.{safe_extension[:3]}" if safe_extension else alias


def _separator_variants(path: str) -> set[str]:
    return {path, path.replace("\\", "/"), path.replace("/", "\\")}


def _host_path_modules(path: str):
    """Select every plausible path syntax independently of this runtime OS."""

    if path.startswith("//"):
        # ``//server/share`` can be a Windows UNC path, while POSIX preserves a
        # leading double slash as an implementation-defined absolute path.  A
        # privacy boundary must cover both interpretations instead of guessing.
        return (posixpath, ntpath)
    if path.startswith("/"):
        # Backslash is a legal POSIX filename character.  When it appears inside
        # an absolute POSIX path, also generate Windows-style diagnostic forms.
        return (posixpath, ntpath) if "\\" in path else (posixpath,)
    windows_drive, _tail = ntpath.splitdrive(path)
    if windows_drive or "\\" in path:
        return (ntpath,)
    return (posixpath,)


def _private_path_variants(private_path: str) -> tuple[str, ...]:
    """Enumerate cross-platform path, parent, basename, and DOS-alias probes."""

    variants = _separator_variants(private_path)
    for path_module in _host_path_modules(private_path):
        normalized = path_module.normpath(private_path)
        variants.update(_separator_variants(normalized))

        # Parser and OS errors sometimes report only the containing directory.
        # Add full ancestors (never a drive/root by itself) as defense in depth.
        parent = path_module.dirname(normalized)
        drive, tail = path_module.splitdrive(normalized)
        anchor = drive + path_module.sep if tail.startswith(("/", "\\")) else drive
        while parent and parent.casefold() not in {
            anchor.casefold(),
            path_module.dirname(parent).casefold(),
        }:
            variants.update(_separator_variants(parent))
            parent = path_module.dirname(parent)
        basename = path_module.basename(normalized)
        if len(basename) >= 4:
            variants.add(basename)

        # A Windows diagnostic may use a short 8.3-style alias.  The exact alias
        # is filesystem metadata, so conservative ~1 forms cover common leaks.
        components = re.split(r"([\\/])", normalized)
        aliasable: list[tuple[int, str]] = []
        for index, component in enumerate(components):
            alias = _dos_83_component(component)
            if alias is not None:
                aliasable.append((index, alias))
                variants.add(alias)
        if aliasable:
            all_aliased = list(components)
            for index, alias in aliasable:
                all_aliased[index] = alias
            variants.update(_separator_variants("".join(all_aliased)))
            for index, alias in aliasable:
                one_aliased = list(components)
                one_aliased[index] = alias
                variants.update(_separator_variants("".join(one_aliased)))

    return tuple(sorted((item for item in variants if item), key=len, reverse=True))


def redact_private_source_literals(value: Any, private_paths: Collection[str]) -> Any:
    """Replace private host-path literals recursively, including mapping keys."""

    paths = tuple(dict.fromkeys(str(path) for path in private_paths if str(path)))
    if isinstance(value, os.PathLike):
        value = os.fspath(value)
    if isinstance(value, str):
        variants = tuple(
            sorted(
                {
                    variant
                    for private_path in paths
                    for variant in _private_path_variants(private_path)
                },
                key=len,
                reverse=True,
            )
        )
        if not variants:
            return value
        # One substitution pass prevents a later private-path variant (for
        # example a directory literally named ``private``) from reprocessing
        # the fixed replacement token produced for an earlier match.
        pattern = "|".join(re.escape(variant) for variant in variants)
        return re.sub(
            pattern,
            lambda _match: PRIVATE_SOURCE_REDACTION_TOKEN,
            value,
            # Host paths are sensitive provenance on every runtime.  Diagnostics
            # and adapters may change path casing even when the source was opened
            # on a case-sensitive filesystem, so privacy matching is deliberately
            # case-insensitive and consistent across Windows and POSIX CI.
            flags=re.IGNORECASE,
        )
    if isinstance(value, Mapping):
        output: dict[Any, Any] = {}
        for key, item in value.items():
            redacted_key = redact_private_source_literals(key, paths)
            if redacted_key in output:
                raise ToolStandardizationError(
                    "private-path redaction produced a mapping-key collision"
                )
            output[redacted_key] = redact_private_source_literals(item, paths)
        return output
    if isinstance(value, list):
        return [redact_private_source_literals(item, paths) for item in value]
    if isinstance(value, tuple):
        return [redact_private_source_literals(item, paths) for item in value]
    return value


def assert_no_private_source_literals(value: Any, private_paths: Collection[str]) -> None:
    """Fail closed if any declared host path remains in model-visible strings."""

    def walk_strings(item: Any):
        if isinstance(item, os.PathLike):
            yield os.fspath(item)
        elif isinstance(item, str):
            yield item
        elif isinstance(item, Mapping):
            for key, nested in item.items():
                yield from walk_strings(key)
                yield from walk_strings(nested)
        elif isinstance(item, list | tuple):
            for nested in item:
                yield from walk_strings(nested)

    variants = tuple(
        variant.casefold()
        for private_path in private_paths
        for variant in _private_path_variants(str(private_path))
        if variant
    )
    for text in walk_strings(value):
        # The fixed token is an intentional replacement, not retained host data.
        haystack = text.replace(PRIVATE_SOURCE_REDACTION_TOKEN, "").casefold()
        if any(needle in haystack for needle in variants):
            raise ToolStandardizationError("standardized output retains a private host path")


def common_case_artifact_locator(tool_name: str, arguments: Mapping[str, Any]) -> str:
    """Return a deterministic, publication-safe locator for one common tool call."""

    if tool_name not in COMMON_CASE_TOOL_DATA_TYPES:
        raise ToolStandardizationError(f"unsupported common case tool: {tool_name}")
    if tool_name in COMMON_CASE_PATH_TOOLS_ALLOW_ROOT:
        raw_path = arguments.get("path")
        if isinstance(raw_path, str) and raw_path:
            allow_root = COMMON_CASE_PATH_TOOLS_ALLOW_ROOT[tool_name]
            try:
                path = normalize_evidence_path(raw_path, allow_root=allow_root)
            except EvidencePathError:
                # A model-supplied path that is not a safe in-image locator is
                # committed to a digest rather than published as a location or
                # raised past the caller: the read it named was already refused,
                # and the provenance must still carry one deterministic,
                # non-reflective locator.
                return f"path:{evidence_locator_commitment(raw_path)}"
            return f"path:{path}"
        # A call that names no path addressed no single in-image location; it is
        # identified by the view it ran, exactly like the non-path readers below.
    elif tool_name == "registry_query":
        hive = arguments.get("hive")
        if isinstance(hive, str) and hive:
            return f"hive:{hive}"
    elif tool_name == "evtx_query":
        log = arguments.get("log")
        if isinstance(log, str) and log:
            return f"log:{log}"
    digest = sha256_hex(canonical_json(dict(arguments)))[:16]
    return f"tool://{quote(tool_name, safe='')}/{digest}"


def _normalize_common_legacy_result(
    tool_name: str,
    value: Any,
    arguments: Mapping[str, Any],
    *,
    bounded_output_is_incomplete: bool,
) -> Any:
    """Preserve common-palette legacy semantics under an explicit cap policy."""

    if not isinstance(value, Mapping):
        return value
    normalized = dict(value)
    if tool_name in {"find_files", "evidence_file_hash", "sqlite_query"}:
        has_items = any(
            isinstance(normalized.get(key), list) and bool(normalized.get(key))
            for key in ("files", "rows", "items")
        )
        if normalized.get("error") not in (None, "", False) and not has_items:
            normalized["status"] = "error"
            normalized.pop("scan_complete", None)
            normalized.pop("coverage_complete", None)
            normalized.pop("coverage", None)
    if tool_name == "search_keyword" and normalized.get("truncated") is True:
        normalized.setdefault("coverage_complete", False)
        normalized.setdefault(
            "coverage",
            {
                "complete": False,
                "scope": str(arguments.get("start") or normalized.get("start") or "/"),
                "reason": ("bounded keyword scan stopped before exhausting the requested scope"),
            },
        )
    if tool_name == "read_file":
        if normalized.get("size") is not None:
            normalized.setdefault("total_bytes", normalized.get("size"))
        if normalized.get("eof") is not None:
            normalized.setdefault("truncated", normalized.get("eof") is False)
    # ``_bounded`` is the output guard's INTERNAL marker.  Consume it here so it
    # can never reach the model.  It records only that the MODEL-VISIBLE
    # PROJECTION was byte-capped, which is a different fact from whether the tool
    # examined its whole source: overwriting a truthful analytical-coverage claim
    # with it would destroy real information about what the tool actually did.
    # The two are therefore reported side by side and never merged.
    if normalized.pop("_bounded", None) is True:
        normalized.setdefault("projection_truncated", True)
    return normalized


def standardize_case_evidence_result(
    raw_result: Any,
    *,
    tool_name: str,
    arguments: Mapping[str, Any],
    invocation_id: str,
    case_id: str,
    evidence_class: EvidenceClass | str,
    derivation: DerivationMetadata | None = None,
    upstream_backends: Collection[UpstreamBackend] = (),
    source_id: str,
    source_sha256: str | None,
    source_media_type: str | None,
    source_uri: str | None = None,
    source_attributes: Mapping[str, Any] | None = None,
    artifact_locator: str | None = None,
    private_paths: Collection[str] = (),
    tool_version: str = __version__,
    tool_implementation: str | None = None,
    raw_output_sha256: str | None = None,
    oversight_entry_sha256: str | None = None,
    oversight_sequence: int | None = None,
    bounded_output_is_incomplete: bool = True,
    model_visible_tool_name: str | None = None,
) -> ToolResult:
    """Create one receipt-bound ``ToolResult`` from a trusted in-process call.

    The caller supplies runtime provenance rather than asking this pure helper to
    inspect a disk or host path. Offline construction uses the strict default
    for centrally bounded output. The live graph explicitly retains its
    historical cap policy until the locked model-visible contract is revised.

    ``tool_name`` is the SEMANTIC identity of the call — the common-palette name
    that selects the data type, the shape normalization and the locator rules.
    On the consolidated surface the model calls a domain function whose
    operation resolves to that identity, so ``model_visible_tool_name`` lets the
    provenance name the function the model actually invoked while everything
    shape-keyed stays on the semantic name.  Omitted, the two coincide, which
    keeps every sealed receipt byte-identical.

    ``evidence_class``, ``derivation`` and ``upstream_backends`` are decided by
    :func:`forensic_agent.agent.upstream_attestation.attest_call` and passed in
    whole.  They are deliberately not defaulted here: a default would be a claim
    this module has no authority to make, and the contract's invariants — exactly
    one producing component under OBSERVED, a citable chain under DERIVED — would
    then be satisfied by an emitter's convenience instead of by what a run
    actually established.
    """

    if tool_name not in COMMON_CASE_TOOL_DATA_TYPES:
        raise ToolStandardizationError(f"unsupported common case tool: {tool_name}")
    if not invocation_id or not source_id:
        raise ToolStandardizationError("invocation and source IDs must be non-empty")
    if not case_id:
        # The active contract binds every result to a case.  A run that states
        # none has to say so explicitly through its own unbound sentinel, which
        # no active case can equal, rather than leaving the field empty.
        raise ToolStandardizationError("case ID cannot be empty")
    if source_sha256 is not None and re.fullmatch(r"[0-9a-f]{64}", source_sha256) is None:
        raise ToolStandardizationError("source SHA-256 must be lowercase hexadecimal")
    if not isinstance(arguments, Mapping) or any(not isinstance(key, str) for key in arguments):
        raise ToolStandardizationError("tool arguments must be a string-keyed object")
    if not isinstance(bounded_output_is_incomplete, bool):
        raise ToolStandardizationError("bounded-output policy must be boolean")

    native = _json_native(raw_result)
    safe_raw = redact_private_source_literals(native, private_paths)
    normalized = _normalize_common_legacy_result(
        tool_name,
        safe_raw,
        arguments,
        bounded_output_is_incomplete=bounded_output_is_incomplete,
    )
    data_type = COMMON_CASE_TOOL_DATA_TYPES[tool_name]
    if source_uri is None and source_sha256 is not None:
        source_uri = f"evidence://sha256/{source_sha256}"
    resolved_class = EvidenceClass(evidence_class)
    provenance = make_provenance(
        evidence_class=resolved_class,
        provenance_type=resolved_class.provenance_type,
        derivation=derivation,
        upstream_backends=tuple(upstream_backends),
        invocation_id=invocation_id,
        case_id=case_id,
        source_id=source_id,
        source_sha256=source_sha256,
        source_uri=source_uri,
        source_media_type=source_media_type,
        source_attributes=source_attributes,
        artifact_locator=(artifact_locator or common_case_artifact_locator(tool_name, arguments)),
        artifact_type=data_type,
        tool_name=model_visible_tool_name or tool_name,
        tool_version=tool_version,
        tool_implementation=(tool_implementation or f"forensic_agent.common_palette:{tool_name}"),
        raw_output_sha256=raw_output_sha256,
        oversight_entry_sha256=oversight_entry_sha256,
        oversight_sequence=oversight_sequence,
    )
    result = attach_receipt(
        adapt_legacy_result(
            normalized,
            data_type=data_type,
            provenance=provenance,
        )
    )
    assert_no_private_source_literals(result.model_dump(mode="json"), private_paths)
    return result


def require_fully_complete_result(result: ToolResult, *, receipt_id: str) -> None:
    """Apply the annotation protocol's strict complete-result predicate."""

    complete = (
        result.status is ToolStatus.OK
        and result.error is None
        and result.coverage.complete
        and not result.page.truncated
        and result.page.next_offset is None
        and result.page.next_cursor is None
        and (
            result.page.total is None
            or result.page.offset + result.page.returned == result.page.total
        )
    )
    if not complete:
        raise IncompleteToolResultError(
            f"required-complete call {receipt_id!r} returned incomplete or error status"
        )


__all__ = [
    "COMMON_CASE_TOOL_PALETTE",
    "COMMON_CASE_TOOL_DATA_TYPES",
    "COMMON_CASE_PATH_TOOLS_ALLOW_ROOT",
    "PRIVATE_SOURCE_REDACTION_TOKEN",
    "ToolStandardizationError",
    "IncompleteToolResultError",
    "redact_private_source_literals",
    "assert_no_private_source_literals",
    "common_case_artifact_locator",
    "standardize_case_evidence_result",
    "require_fully_complete_result",
]
