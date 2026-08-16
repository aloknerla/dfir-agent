"""Versioned, JSON-native contract for forensic tool results.

The contract deliberately separates three concepts which legacy tool outputs often
conflate:

* ``status`` describes whether the invocation produced usable data;
* ``page`` describes how much of the *result set* is present in this response; and
* ``coverage`` describes whether the tool examined the requested evidence scope.

Consequently, a completely executed query may return a truncated page while still
being ``ok`` and having complete coverage.  Conversely, a parser that recovered
some records before encountering corruption is ``partial`` even if all recovered
records fit in one page.

All payload-bearing fields accept JSON values only.  This keeps the wire format
suitable for MCP ``structuredContent`` and makes the SHA-256 receipt independent of
Python object representations.
"""

from __future__ import annotations

import hmac
import json
from collections.abc import Mapping
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from forensic_agent.core.repro import canonical_json, sha256_hex

SCHEMA_ID = "forensic.tool-result.v1"
RECEIPT_SCHEMA_ID = "forensic.tool-result-receipt.v1"


class _ContractModel(BaseModel):
    """Strict base class for every object in the public wire contract."""

    model_config = ConfigDict(extra="forbid")


class ToolStatus(StrEnum):
    OK = "ok"
    PARTIAL = "partial"
    ERROR = "error"


class PageUnit(StrEnum):
    """Unit used by page offsets/counts."""

    ITEM = "item"
    BYTE = "byte"


class ProvenanceType(StrEnum):
    """The evidentiary role of the returned material."""

    CASE_EVIDENCE = "case_evidence"
    REFERENCE_KNOWLEDGE = "reference_knowledge"


class ToolData(_ContractModel):
    """Typed tool payload.

    ``type`` is the stable semantic discriminator (for example
    ``filesystem.directory_listing``).  Singleton/scalar fields belong in
    ``attributes`` and repeatable records belong in ``items``.
    """

    type: str = Field(min_length=1)
    attributes: dict[str, JsonValue] = Field(default_factory=dict)
    items: list[JsonValue] = Field(default_factory=list)


class PageMetadata(_ContractModel):
    """Transport/pagination state, not evidence-coverage state."""

    unit: PageUnit = PageUnit.ITEM
    offset: int = Field(default=0, ge=0)
    returned: int = Field(default=0, ge=0)
    total: int | None = Field(default=None, ge=0)
    next_offset: int | None = Field(default=None, ge=0)
    next_cursor: str | None = None
    truncated: bool = False

    @model_validator(mode="after")
    def _consistent_total(self) -> PageMetadata:
        if self.total is not None and self.total < self.offset + self.returned:
            raise ValueError("page.total cannot be smaller than offset + returned")
        return self


class CoverageMetadata(_ContractModel):
    """Whether the requested source/scope was examined completely."""

    complete: bool = True
    scope: str | None = None
    reason: str | None = None
    examined: int | None = Field(default=None, ge=0)
    expected: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def _reason_matches_completeness(self) -> CoverageMetadata:
        if self.complete and self.reason is not None:
            raise ValueError("complete coverage cannot have an incompleteness reason")
        if not self.complete and not self.reason:
            raise ValueError("incomplete coverage requires a reason")
        if (
            self.examined is not None
            and self.expected is not None
            and self.examined > self.expected
        ):
            raise ValueError("coverage.examined cannot exceed coverage.expected")
        return self


class ToolWarning(_ContractModel):
    code: str = Field(min_length=1)
    message: str = Field(min_length=1)
    details: dict[str, JsonValue] = Field(default_factory=dict)


class ToolError(_ContractModel):
    code: str = Field(min_length=1)
    message: str = Field(min_length=1)
    retryable: bool = False
    details: dict[str, JsonValue] = Field(default_factory=dict)


class SourceMetadata(_ContractModel):
    """The acquired evidence source or frozen reference corpus/document."""

    id: str = Field(min_length=1)
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-fA-F]{64}$")
    uri: str | None = None
    media_type: str | None = None
    acquisition_id: str | None = None
    attributes: dict[str, JsonValue] = Field(default_factory=dict)


class ArtifactMetadata(_ContractModel):
    """Precise location within ``source`` that produced the result."""

    locator: str = Field(min_length=1)
    type: str | None = None
    offset: int | None = Field(default=None, ge=0)
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-fA-F]{64}$")
    attributes: dict[str, JsonValue] = Field(default_factory=dict)


class ToolMetadata(_ContractModel):
    name: str = Field(min_length=1)
    version: str = Field(min_length=1)
    implementation: str | None = None
    parameters_sha256: str | None = Field(default=None, pattern=r"^[0-9a-fA-F]{64}$")


class ToolProvenance(_ContractModel):
    """Trace from a result back to its invocation, source, artifact and tool."""

    type: ProvenanceType
    admissible_as_case_evidence: bool
    invocation_id: str = Field(min_length=1)
    case_id: str | None = None
    raw_output_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    oversight_entry_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    oversight_sequence: int | None = Field(default=None, ge=0)
    source: SourceMetadata
    artifact: ArtifactMetadata
    tool: ToolMetadata

    @model_validator(mode="after")
    def _evidentiary_role_is_consistent(self) -> ToolProvenance:
        expected = self.type is ProvenanceType.CASE_EVIDENCE
        if self.admissible_as_case_evidence is not expected:
            raise ValueError(
                "admissible_as_case_evidence must be true only for case_evidence provenance"
            )
        oversight_binding = (
            self.raw_output_sha256,
            self.oversight_entry_sha256,
            self.oversight_sequence,
        )
        if any(value is not None for value in oversight_binding) and not all(
            value is not None for value in oversight_binding
        ):
            raise ValueError(
                "raw output digest, oversight entry digest and sequence must be supplied together"
            )
        return self


class ToolResultReceipt(_ContractModel):
    schema_version: Literal["forensic.tool-result-receipt.v1"] = "forensic.tool-result-receipt.v1"
    algorithm: Literal["sha256"] = "sha256"
    payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ToolResult(_ContractModel):
    """The ``forensic.tool-result.v1`` structured result envelope."""

    schema_version: Literal["forensic.tool-result.v1"] = "forensic.tool-result.v1"
    status: ToolStatus
    data: ToolData
    page: PageMetadata = Field(default_factory=PageMetadata)
    coverage: CoverageMetadata = Field(default_factory=CoverageMetadata)
    warnings: list[ToolWarning] = Field(default_factory=list)
    error: ToolError | None = None
    provenance: ToolProvenance
    receipt: ToolResultReceipt | None = None

    @model_validator(mode="after")
    def _status_invariants(self) -> ToolResult:
        if self.page.unit is PageUnit.ITEM and self.page.returned != len(self.data.items):
            raise ValueError("page.returned must equal the number of data.items")

        if self.status is ToolStatus.OK:
            if not self.coverage.complete:
                raise ValueError("ok status requires complete coverage")
            if self.error is not None:
                raise ValueError("ok status cannot carry an error")
        elif self.status is ToolStatus.PARTIAL:
            if self.coverage.complete:
                raise ValueError("partial status requires incomplete coverage")
            if self.error is not None:
                raise ValueError("partial failures belong in warnings, not error")
        else:
            if self.coverage.complete:
                raise ValueError("error status requires incomplete coverage")
            if self.error is None:
                raise ValueError("error status requires a structured error")
        return self


def make_provenance(
    *,
    provenance_type: ProvenanceType | str,
    invocation_id: str,
    source_id: str,
    artifact_locator: str,
    tool_name: str,
    tool_version: str,
    case_id: str | None = None,
    source_sha256: str | None = None,
    source_uri: str | None = None,
    source_media_type: str | None = None,
    source_attributes: Mapping[str, Any] | None = None,
    acquisition_id: str | None = None,
    artifact_type: str | None = None,
    artifact_offset: int | None = None,
    artifact_sha256: str | None = None,
    tool_implementation: str | None = None,
    parameters: Mapping[str, Any] | None = None,
    raw_output_sha256: str | None = None,
    oversight_entry_sha256: str | None = None,
    oversight_sequence: int | None = None,
) -> ToolProvenance:
    """Build validated provenance and optionally bind it to canonical parameters."""

    parameters_sha256 = None
    if parameters is not None:
        parameters_sha256 = sha256_hex(canonical_json(_json_value(dict(parameters))))
    return ToolProvenance(
        type=ProvenanceType(provenance_type),
        admissible_as_case_evidence=(
            ProvenanceType(provenance_type) is ProvenanceType.CASE_EVIDENCE
        ),
        invocation_id=invocation_id,
        case_id=case_id,
        raw_output_sha256=raw_output_sha256,
        oversight_entry_sha256=oversight_entry_sha256,
        oversight_sequence=oversight_sequence,
        source=SourceMetadata(
            id=source_id,
            sha256=source_sha256,
            uri=source_uri,
            media_type=source_media_type,
            acquisition_id=acquisition_id,
            attributes=dict(source_attributes or {}),
        ),
        artifact=ArtifactMetadata(
            locator=artifact_locator,
            type=artifact_type,
            offset=artifact_offset,
            sha256=artifact_sha256,
        ),
        tool=ToolMetadata(
            name=tool_name,
            version=tool_version,
            implementation=tool_implementation,
            parameters_sha256=parameters_sha256,
        ),
    )


def ok_result(
    *,
    data_type: str,
    provenance: ToolProvenance,
    attributes: Mapping[str, Any] | None = None,
    items: list[Any] | None = None,
    page: PageMetadata | None = None,
    warnings: list[ToolWarning] | None = None,
) -> ToolResult:
    """Create a successful result; page truncation does not imply partial coverage."""

    json_items = _json_list(items or [])
    return ToolResult(
        status=ToolStatus.OK,
        data=ToolData(
            type=data_type,
            attributes=_json_mapping(attributes or {}),
            items=json_items,
        ),
        page=page or PageMetadata(returned=len(json_items)),
        coverage=CoverageMetadata(complete=True),
        warnings=warnings or [],
        provenance=provenance,
    )


def partial_result(
    *,
    data_type: str,
    provenance: ToolProvenance,
    coverage_reason: str,
    attributes: Mapping[str, Any] | None = None,
    items: list[Any] | None = None,
    page: PageMetadata | None = None,
    warnings: list[ToolWarning] | None = None,
    coverage_scope: str | None = None,
) -> ToolResult:
    """Create a result containing usable data from incomplete evidence coverage."""

    json_items = _json_list(items or [])
    return ToolResult(
        status=ToolStatus.PARTIAL,
        data=ToolData(
            type=data_type,
            attributes=_json_mapping(attributes or {}),
            items=json_items,
        ),
        page=page or PageMetadata(returned=len(json_items)),
        coverage=CoverageMetadata(
            complete=False,
            scope=coverage_scope,
            reason=coverage_reason,
        ),
        warnings=warnings or [],
        provenance=provenance,
    )


def error_result(
    *,
    data_type: str,
    provenance: ToolProvenance,
    error: ToolError,
    coverage_reason: str,
    attributes: Mapping[str, Any] | None = None,
    warnings: list[ToolWarning] | None = None,
) -> ToolResult:
    """Create a failed invocation with no repeatable result items."""

    return ToolResult(
        status=ToolStatus.ERROR,
        data=ToolData(type=data_type, attributes=_json_mapping(attributes or {})),
        coverage=CoverageMetadata(complete=False, reason=coverage_reason),
        warnings=warnings or [],
        error=error,
        provenance=provenance,
    )


def canonical_payload(result: ToolResult) -> str:
    """Canonical JSON covered by the receipt (the receipt itself is excluded)."""

    payload = result.model_dump(mode="json", exclude={"receipt"})
    return canonical_json(payload)


def payload_sha256(result: ToolResult) -> str:
    """Return the deterministic SHA-256 of a validated result payload."""

    return sha256_hex(canonical_payload(result))


def canonical_raw_output_sha256(output: Any) -> str:
    """Hash a legacy/raw output in the contract's canonical JSON domain.

    This digest is deliberately distinct from a byte-for-byte object-store hash:
    it survives dictionary insertion-order differences and can therefore bind the
    oversight action to the standardized result that was derived from it.
    """

    return sha256_hex(canonical_json(_json_value(output)))


def make_receipt(result: ToolResult) -> ToolResultReceipt:
    return ToolResultReceipt(payload_sha256=payload_sha256(result))


def attach_receipt(result: ToolResult) -> ToolResult:
    """Return an immutable-style copy carrying a receipt for its current payload."""

    return result.model_copy(update={"receipt": make_receipt(result)})


def verify_receipt(result: ToolResult) -> bool:
    """Verify a receipt without leaking hash-comparison timing information."""

    if result.receipt is None:
        return False
    return hmac.compare_digest(result.receipt.payload_sha256, payload_sha256(result))


def tool_result_output_schema() -> dict[str, Any]:
    """Return the JSON Schema suitable for an MCP tool ``outputSchema`` field."""

    return ToolResult.model_json_schema(mode="serialization")


def to_mcp_tool_result(result: ToolResult | Mapping[str, Any]) -> dict[str, Any]:
    """Map a validated result to MCP's dependency-free tool-result wire shape.

    Results without a receipt receive a canonical one. An existing invalid receipt is
    rejected rather than silently replaced, because doing so would hide payload
    mutation.  The compact text block mirrors ``structuredContent`` for clients
    that do not yet consume structured tool outputs.
    """

    validated = ToolResult.model_validate(result)
    if validated.receipt is None:
        validated = attach_receipt(validated)
    elif not verify_receipt(validated):
        raise ValueError("tool result receipt does not match its canonical payload")

    structured = validated.model_dump(mode="json")
    return {
        "structuredContent": structured,
        "content": [{"type": "text", "text": canonical_json(structured)}],
        "isError": validated.status is ToolStatus.ERROR,
    }


_ITEM_KEYS = (
    "items",
    "rows",
    "entries",
    "hits",
    "events",
    "files",
    "artifacts",
    "members",
    "results",
)
_CONTROL_KEYS = {
    "schema_version",
    "status",
    "ok",
    "complete",
    "incomplete",
    "coverage_complete",
    "scan_complete",
    "coverage",
    "returned",
    "returned_bytes",
    "total",
    "total_matching",
    "total_bytes",
    "offset",
    "next_offset",
    "next_cursor",
    "truncated",
    "page_truncated",
    "note",
    "warning",
    "warnings",
    "error",
    "receipt",
    "provenance",
}


def adapt_legacy_result(
    result: Any,
    *,
    data_type: str,
    provenance: ToolProvenance,
) -> ToolResult:
    """Adapt an existing dict/list result without inventing evidentiary provenance.

    The caller must supply provenance because an adapter cannot infer a source or
    invocation identity safely.  New row envelopes distinguish a missing page from
    bounded content inside a returned row.  An ambiguous legacy ``truncated`` flag
    remains fail-closed as page truncation unless a transport-bounding marker proves
    that the complete item page was returned.  A legacy failure that also contains
    usable data maps to ``partial`` with a warning, preserving recovered evidence
    instead of falsely treating the whole invocation as an error.
    """

    if isinstance(result, ToolResult):
        return result
    if isinstance(result, Mapping) and result.get("schema_version") == SCHEMA_ID:
        return ToolResult.model_validate(result)

    if isinstance(result, list):
        items = _json_list(result)
        return ok_result(
            data_type=data_type,
            provenance=provenance,
            items=items,
            page=PageMetadata(returned=len(items), total=len(items)),
        )
    if not isinstance(result, Mapping):
        return ok_result(
            data_type=data_type,
            provenance=provenance,
            attributes={"value": _json_value(result)},
        )

    raw = dict(result)
    item_key = next((key for key in _ITEM_KEYS if isinstance(raw.get(key), list)), None)
    items = _json_list(raw.get(item_key, [])) if item_key else []

    nested_data = raw.get("data")
    if isinstance(nested_data, Mapping):
        nested_items = nested_data.get("items")
        if item_key is None and isinstance(nested_items, list):
            items = _json_list(nested_items)
        nested_attributes = nested_data.get("attributes", {})
        attributes = (
            _json_mapping(nested_attributes) if isinstance(nested_attributes, Mapping) else {}
        )
    else:
        attributes = {}

    excluded = _CONTROL_KEYS | ({item_key} if item_key else set()) | {"data"}
    attributes.update(
        _json_mapping({key: value for key, value in raw.items() if key not in excluded})
    )

    byte_page = "returned_bytes" in raw or "total_bytes" in raw
    unit = PageUnit.BYTE if byte_page else PageUnit.ITEM
    offset = _legacy_nonnegative_int(raw.get("offset"), default=0)
    returned = (
        _legacy_nonnegative_int(raw.get("returned_bytes"), default=0) if byte_page else len(items)
    )
    total_value = (
        raw.get("total_bytes", raw.get("total"))
        if byte_page
        else raw.get("total_matching", raw.get("total"))
    )
    total = _legacy_optional_int(total_value)
    minimum_total = offset + returned
    if total is not None and total < minimum_total:
        total = minimum_total
    declared_truncated = bool(raw.get("truncated", False))
    next_cursor_value = raw.get("next_cursor")
    next_cursor = str(next_cursor_value) if next_cursor_value is not None else None
    next_offset = _legacy_optional_int(raw.get("next_offset"))
    explicit_page_truncated = raw.get("page_truncated")
    observable_page_remainder = bool(
        next_offset is not None
        or next_cursor is not None
        or (total is not None and minimum_total < total)
    )
    bounded_complete_legacy_page = bool(
        raw.get("_bounded") is True
        and total is not None
        and minimum_total == total
        and not observable_page_remainder
    )
    # New row envelopes disambiguate missing result rows from bounded values
    # inside a returned row.  Older producers exposed only ``truncated``; that
    # shape remains fail-closed unless its bounding marker and counters prove
    # that no item page is missing.  Continuation metadata always wins over a
    # contradictory explicit ``page_truncated=False`` declaration.
    truncated = bool(
        observable_page_remainder
        or (
            explicit_page_truncated
            if isinstance(explicit_page_truncated, bool)
            else declared_truncated and not bounded_complete_legacy_page
        )
    )
    if (
        not byte_page
        and next_offset is None
        and truncated
        and returned > 0
        and (total is None or minimum_total < total)
    ):
        next_offset = minimum_total
    page = PageMetadata(
        unit=unit,
        offset=offset,
        returned=returned,
        total=total,
        next_offset=next_offset,
        next_cursor=next_cursor,
        truncated=truncated,
    )

    warnings = _legacy_warnings(raw.get("warnings", raw.get("warning")))
    if explicit_page_truncated is False and observable_page_remainder:
        warnings.append(
            ToolWarning(
                code="legacy_page_metadata_conflict",
                message=(
                    "page_truncated was false although continuation metadata "
                    "showed that result rows remain"
                ),
            )
        )
    if declared_truncated and not truncated:
        warnings.append(
            ToolWarning(
                code="legacy_content_truncation",
                message=(
                    "one or more returned values were bounded, but the complete "
                    "item page was returned"
                ),
            )
        )
    note = raw.get("note")
    if note:
        warnings.append(ToolWarning(code="legacy_note", message=str(note)))

    explicit_status = str(raw.get("status", "")).lower()
    explicit_incomplete = (
        explicit_status == ToolStatus.PARTIAL.value
        or raw.get("incomplete") is True
        or raw.get("complete") is False
        or raw.get("coverage_complete") is False
        or raw.get("scan_complete") is False
    )
    coverage_value = raw.get("coverage")
    coverage_reason: str | None = None
    coverage_scope: str | None = None
    coverage_examined: int | None = None
    coverage_expected: int | None = None
    if isinstance(coverage_value, Mapping):
        if coverage_value.get("complete") is False:
            explicit_incomplete = True
        if coverage_value.get("reason"):
            coverage_reason = str(coverage_value["reason"])
        if coverage_value.get("scope"):
            coverage_scope = str(coverage_value["scope"])
        # How much of the scope was examined is what separates "this view did not
        # cover everything" from "the claim is unproven".  A directly observed
        # event stays observed under partial coverage; only a claim about absence
        # or exhaustiveness needs the whole set.  Without the counts, a reader has
        # no way to tell those apart, so carry the tool's own numbers through.
        coverage_examined = _legacy_optional_int(coverage_value.get("examined"))
        coverage_expected = _legacy_optional_int(coverage_value.get("expected"))
        if (
            coverage_examined is not None
            and coverage_expected is not None
            and coverage_examined > coverage_expected
        ):
            # An inconsistent pair says nothing trustworthy about the scope, and
            # must not fail the standardization of evidence the tool did return.
            coverage_examined = None
            coverage_expected = None

    legacy_error = raw.get("error")
    # Context fields such as ``path``, ``hive`` or ``log`` explain where a total
    # failure occurred but are not themselves recovered evidence.  Singleton
    # attributes count as usable partial data only when the legacy tool explicitly
    # declares incomplete coverage; repeatable recovered items are always usable.
    has_usable_data = bool(items) or (explicit_incomplete and bool(attributes))
    failed = explicit_status == ToolStatus.ERROR.value or legacy_error not in (None, "", False)

    if failed and has_usable_data:
        explicit_incomplete = True
        warnings.append(
            ToolWarning(
                code="legacy_partial_error",
                message=_legacy_error_message(legacy_error),
            )
        )

    data = ToolData(type=data_type, attributes=attributes, items=items)
    if explicit_incomplete:
        reason = coverage_reason or _legacy_error_message(legacy_error)
        if not reason or reason == "legacy tool reported an error":
            reason = "legacy tool reported incomplete evidence coverage"
        return ToolResult(
            status=ToolStatus.PARTIAL,
            data=data,
            page=page,
            coverage=CoverageMetadata(
                complete=False,
                scope=coverage_scope,
                reason=reason,
                examined=coverage_examined,
                expected=coverage_expected,
            ),
            warnings=warnings,
            provenance=provenance,
        )

    if failed:
        message = _legacy_error_message(legacy_error)
        return ToolResult(
            status=ToolStatus.ERROR,
            data=data,
            page=page,
            coverage=CoverageMetadata(complete=False, reason=coverage_reason or message),
            warnings=warnings,
            error=ToolError(code="legacy_error", message=message),
            provenance=provenance,
        )

    # Page truncation describes transport completeness.  It does not by itself
    # change whether the tool examined the requested evidence scope.
    #
    # A complete result still has a scope, and it is carried here.  "Complete"
    # answers how much of the stated scope was examined; it does not state what
    # that scope was.  Dropping the scope would turn "this enumeration is
    # complete" into "this is everything the medium holds", letting a reader
    # claim absence about a medium nobody had examined in full.
    return ToolResult(
        status=ToolStatus.OK,
        data=data,
        page=page,
        coverage=CoverageMetadata(
            complete=True,
            scope=coverage_scope,
            reason=coverage_reason,
            examined=coverage_examined,
            expected=coverage_expected,
        ),
        warnings=warnings,
        provenance=provenance,
    )


def _legacy_error_message(value: Any) -> str:
    if isinstance(value, Mapping):
        for key in ("message", "detail", "error"):
            if value.get(key):
                return str(value[key])
        return canonical_json(_json_value(dict(value)))
    if value not in (None, "", False):
        return str(value)
    return "legacy tool reported an error"


def _legacy_warnings(value: Any) -> list[ToolWarning]:
    if value in (None, "", False):
        return []
    values = value if isinstance(value, list) else [value]
    warnings: list[ToolWarning] = []
    for item in values:
        if isinstance(item, Mapping):
            code = str(item.get("code") or "legacy_warning")
            message = str(item.get("message") or item.get("detail") or canonical_json(item))
            details_value = item.get("details", {})
            details = _json_mapping(details_value) if isinstance(details_value, Mapping) else {}
            warnings.append(ToolWarning(code=code, message=message, details=details))
        else:
            warnings.append(ToolWarning(code="legacy_warning", message=str(item)))
    return warnings


def _legacy_nonnegative_int(value: Any, *, default: int) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return default


def _legacy_optional_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return None


def _json_value(value: Any) -> JsonValue:
    """Normalize a legacy Python value to the same JSON domain as the contract."""

    return json.loads(canonical_json(value))


def _json_mapping(value: Mapping[str, Any]) -> dict[str, JsonValue]:
    normalized = _json_value(dict(value))
    if not isinstance(normalized, dict):  # defensive; ``dict(value)`` guarantees this
        raise TypeError("expected a JSON object")
    return normalized


def _json_list(value: list[Any]) -> list[JsonValue]:
    normalized = _json_value(value)
    if not isinstance(normalized, list):  # defensive; input annotation guarantees this
        raise TypeError("expected a JSON array")
    return normalized


__all__ = [
    "SCHEMA_ID",
    "RECEIPT_SCHEMA_ID",
    "ToolStatus",
    "PageUnit",
    "ProvenanceType",
    "ToolData",
    "PageMetadata",
    "CoverageMetadata",
    "ToolWarning",
    "ToolError",
    "SourceMetadata",
    "ArtifactMetadata",
    "ToolMetadata",
    "ToolProvenance",
    "ToolResultReceipt",
    "ToolResult",
    "make_provenance",
    "ok_result",
    "partial_result",
    "error_result",
    "canonical_payload",
    "payload_sha256",
    "canonical_raw_output_sha256",
    "make_receipt",
    "attach_receipt",
    "verify_receipt",
    "tool_result_output_schema",
    "to_mcp_tool_result",
    "adapt_legacy_result",
]
