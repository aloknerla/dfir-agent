"""Compact attestations for the exact OpenAI-compatible request body.

The runtime must be able to prove which request controls reached the SDK boundary
without copying case evidence and complete prompts into every result row.  This
module therefore records two things:

* a SHA-256 digest of the complete canonical request body handed to the SDK; and
* a compact, independently checkable manifest containing content digests plus the
  non-content controls (model, decoding fields, route, and tool palette digest).

``extra_body`` is merged exactly as the OpenAI SDK does: its values override
same-named body fields.  Transport-only request options such as ``timeout`` and
headers are excluded from the body digest and attested separately.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import math
import re
from collections.abc import Mapping
from typing import Any

from forensic_agent.core.repro import canonical_json, sha256_hex

REQUEST_PAYLOAD_ATTESTATION_SCHEMA_ID = "openrouter.request-payload-attestation.v1"
REQUEST_MESSAGE_MANIFEST_SCHEMA_ID = "openrouter.request-message-manifest.v2"

_REQUEST_OPTION_KEYS = frozenset({"extra_headers", "extra_query", "timeout"})
_SENSITIVE_CONTROL_KEYS = frozenset({"api_key", "authorization", "cookie", "proxy-authorization"})
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class RequestPayloadAttestationError(ValueError):
    """A request body cannot be safely or consistently attested."""


def _finite_positive_float(value: object, *, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise RequestPayloadAttestationError(f"{name} must be a positive finite number")
    normalized = float(value)
    if not math.isfinite(normalized) or normalized <= 0:
        raise RequestPayloadAttestationError(f"{name} must be a positive finite number")
    return normalized


def _assert_no_sensitive_keys(value: object) -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise RequestPayloadAttestationError("request payload contains a non-string key")
            if key.casefold() in _SENSITIVE_CONTROL_KEYS:
                raise RequestPayloadAttestationError(
                    f"request payload contains forbidden credential field {key!r}"
                )
            _assert_no_sensitive_keys(nested)
    elif isinstance(value, list | tuple):
        for nested in value:
            _assert_no_sensitive_keys(nested)


def canonical_request_body(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Return the exact semantic JSON body passed through the OpenAI SDK.

    The SDK treats ``extra_body`` as body extensions which take precedence over
    generated fields.  Request options do not appear in the HTTP JSON body.
    """

    if not isinstance(payload, Mapping):
        raise RequestPayloadAttestationError("request payload must be a mapping")
    body = {
        str(key): copy.deepcopy(value)
        for key, value in payload.items()
        if key not in _REQUEST_OPTION_KEYS and key != "extra_body"
    }
    extra_body = payload.get("extra_body")
    if extra_body is not None:
        if not isinstance(extra_body, Mapping):
            raise RequestPayloadAttestationError("extra_body must be a mapping")
        for key, value in extra_body.items():
            if not isinstance(key, str):
                raise RequestPayloadAttestationError("extra_body contains a non-string key")
            body[key] = copy.deepcopy(value)
    _assert_no_sensitive_keys(body)
    # Round-trip through the canonical encoder now so unsupported values fail at
    # the capture point, before the transport is allowed to proceed.
    normalized = canonical_json(body)
    decoded = json.loads(normalized)
    if not isinstance(decoded, dict):  # pragma: no cover - body is constructed as a dict
        raise RequestPayloadAttestationError("canonical request body is not an object")
    return decoded


def _message_manifest(messages: list[Any]) -> list[dict[str, Any]]:
    """Return a content-free, order-preserving identity for model messages.

    Raw prompt/evidence text is deliberately not retained.  Each complete
    canonical message is nevertheless bound by a digest, while the role and
    content-only digest make the initial system/user surface independently
    checkable.
    """

    manifest: list[dict[str, Any]] = []
    for index, message in enumerate(messages):
        if not isinstance(message, Mapping):
            raise RequestPayloadAttestationError(f"request message {index} must be an object")
        normalized_message = json.loads(canonical_json(dict(message)))
        if not isinstance(normalized_message, dict):  # pragma: no cover - guarded above
            raise RequestPayloadAttestationError(
                f"request message {index} is not a canonical object"
            )
        role = normalized_message.get("role")
        if not isinstance(role, str) or not role.strip():
            raise RequestPayloadAttestationError(f"request message {index} lacks a canonical role")
        content = normalized_message.get("content")
        tool_calls = normalized_message.get("tool_calls", [])
        content_part_manifest: list[dict[str, Any]] | None = None
        if isinstance(content, list):
            content_part_manifest = []
            for part_index, part in enumerate(content):
                if not isinstance(part, Mapping):
                    raise RequestPayloadAttestationError(
                        f"request message {index} content part {part_index} must be an object"
                    )
                normalized_part = json.loads(canonical_json(dict(part)))
                if not isinstance(normalized_part, dict):  # pragma: no cover - guarded above
                    raise RequestPayloadAttestationError(
                        f"request message {index} content part {part_index} is not canonical"
                    )
                part_type = normalized_part.get("type")
                if not isinstance(part_type, str) or not part_type.strip():
                    raise RequestPayloadAttestationError(
                        f"request message {index} content part {part_index} lacks a type"
                    )
                text = normalized_part.get("text")
                content_part_manifest.append(
                    {
                        "index": part_index,
                        "type": part_type,
                        "object_keys": sorted(normalized_part),
                        "part_sha256": sha256_hex(canonical_json(normalized_part)),
                        "text_sha256": sha256_hex(text) if isinstance(text, str) else None,
                    }
                )
        record: dict[str, Any] = {
            "index": index,
            "role": role,
            "message_sha256": sha256_hex(canonical_json(normalized_message)),
            "content_sha256": sha256_hex(canonical_json(content)),
            "content_text_sha256": (sha256_hex(content) if isinstance(content, str) else None),
            "content_part_manifest": content_part_manifest,
            "tool_calls_sha256": sha256_hex(canonical_json(tool_calls)),
        }
        manifest.append(record)
    return manifest


def _needs_detailed_semantic_manifest(
    body: Mapping[str, Any],
    messages: list[Any],
    *,
    force_detailed_semantic_manifest: bool,
) -> bool:
    """Keep existing reconstructable no-tool receipts byte-for-byte stable.

    Agent requests carry ``tools`` and therefore need a content-free per-message
    manifest for append-only validation.  A caller can explicitly request the
    same manifest for another exact no-tool surface, such as the verifier's
    system/user pair.  A no-tool body that reconstructs its entire two-message
    surface independently keeps the original compact receipt.
    """

    if force_detailed_semantic_manifest or "tools" in body:
        return True
    return not any(
        isinstance(message, Mapping)
        and str(message.get("role") or "").casefold() in {"system", "developer"}
        for message in messages
    )


def attest_request_payload(
    payload: Mapping[str, Any],
    *,
    force_detailed_semantic_manifest: bool = False,
) -> dict[str, Any]:
    """Create a compact receipt for the exact body immediately before transport.

    ``force_detailed_semantic_manifest`` changes only the content-free receipt;
    it never changes the canonical request body or the payload sent to the SDK.
    """

    if not isinstance(force_detailed_semantic_manifest, bool):
        raise RequestPayloadAttestationError("force_detailed_semantic_manifest must be a boolean")

    body = canonical_request_body(payload)
    if not isinstance(body.get("model"), str) or not str(body["model"]).strip():
        raise RequestPayloadAttestationError("request body lacks a model")
    messages = body.get("messages")
    if not isinstance(messages, list) or not messages:
        raise RequestPayloadAttestationError("request body lacks a non-empty message list")
    tools = body.get("tools", [])
    if not isinstance(tools, list):
        raise RequestPayloadAttestationError("request body tools must be a list")
    controls = {
        key: copy.deepcopy(value)
        for key, value in body.items()
        if key not in {"model", "messages", "tools"}
    }
    timeout = payload.get("timeout")
    timeout_s = (
        _finite_positive_float(timeout, name="request timeout") if timeout is not None else None
    )
    body_json = canonical_json(body)
    manifest: dict[str, Any] = {
        "request_payload_attestation_schema_id": REQUEST_PAYLOAD_ATTESTATION_SCHEMA_ID,
        "request_payload_sha256": sha256_hex(body_json),
        "request_payload_canonical_bytes": len(body_json.encode("utf-8")),
        "request_payload_model": str(body["model"]),
        "request_payload_messages_sha256": sha256_hex(canonical_json(messages)),
        "request_payload_tools_sha256": sha256_hex(canonical_json(tools)),
        "request_payload_controls": controls,
        "request_payload_controls_sha256": sha256_hex(canonical_json(controls)),
        "request_timeout_s": timeout_s,
    }
    if _needs_detailed_semantic_manifest(
        body,
        messages,
        force_detailed_semantic_manifest=force_detailed_semantic_manifest,
    ):
        message_manifest = _message_manifest(messages)
        # Tool schemas are protocol material, not case evidence or credentials.
        # Retaining the exact canonical schemas once per request makes the
        # model-visible palette independently checkable instead of trusting a
        # caller-supplied digest.  Prompt/evidence content remains hash-only.
        manifest.update(
            {
                "request_message_manifest_schema_id": (REQUEST_MESSAGE_MANIFEST_SCHEMA_ID),
                "request_message_manifest": message_manifest,
                "request_message_manifest_sha256": sha256_hex(canonical_json(message_manifest)),
                "request_payload_tools": copy.deepcopy(tools),
            }
        )
    manifest["request_payload_attestation_sha256"] = sha256_hex(canonical_json(manifest))
    return manifest


def validate_request_payload_attestation(value: Mapping[str, Any]) -> None:
    """Validate the self-contained portion of a compact request receipt."""

    expected_keys = {
        "request_payload_attestation_schema_id",
        "request_payload_sha256",
        "request_payload_canonical_bytes",
        "request_payload_model",
        "request_payload_messages_sha256",
        "request_payload_tools_sha256",
        "request_payload_controls",
        "request_payload_controls_sha256",
        "request_timeout_s",
        "request_payload_attestation_sha256",
    }
    missing = expected_keys.difference(value)
    if missing:
        raise RequestPayloadAttestationError(
            "request payload attestation lacks fields: " + ", ".join(sorted(missing))
        )
    if value.get("request_payload_attestation_schema_id") != (
        REQUEST_PAYLOAD_ATTESTATION_SCHEMA_ID
    ):
        raise RequestPayloadAttestationError("unknown request payload attestation schema")
    for name in (
        "request_payload_sha256",
        "request_payload_messages_sha256",
        "request_payload_tools_sha256",
        "request_payload_controls_sha256",
        "request_payload_attestation_sha256",
    ):
        digest = str(value.get(name) or "").casefold()
        if _SHA256.fullmatch(digest) is None:
            raise RequestPayloadAttestationError(f"{name} is not a canonical SHA-256")
    byte_count = value.get("request_payload_canonical_bytes")
    if isinstance(byte_count, bool) or not isinstance(byte_count, int) or byte_count < 1:
        raise RequestPayloadAttestationError(
            "request_payload_canonical_bytes must be a positive integer"
        )
    if (
        not isinstance(value.get("request_payload_model"), str)
        or not str(value["request_payload_model"]).strip()
    ):
        raise RequestPayloadAttestationError("request payload attestation lacks a model")
    controls = value.get("request_payload_controls")
    if not isinstance(controls, Mapping):
        raise RequestPayloadAttestationError("request payload controls must be a mapping")
    _assert_no_sensitive_keys(controls)
    controls_digest = sha256_hex(canonical_json(dict(controls)))
    if not hmac.compare_digest(
        str(value["request_payload_controls_sha256"]).casefold(), controls_digest
    ):
        raise RequestPayloadAttestationError("request payload controls digest mismatch")
    timeout = value.get("request_timeout_s")
    if timeout is not None:
        _finite_positive_float(timeout, name="request timeout")
    detail_keys = {
        "request_message_manifest_schema_id",
        "request_message_manifest",
        "request_message_manifest_sha256",
        "request_payload_tools",
    }
    present_detail_keys = detail_keys.intersection(value)
    if present_detail_keys and present_detail_keys != detail_keys:
        raise RequestPayloadAttestationError("request semantic manifest is only partially present")
    if present_detail_keys:
        if value.get("request_message_manifest_schema_id") != (REQUEST_MESSAGE_MANIFEST_SCHEMA_ID):
            raise RequestPayloadAttestationError("unknown request message manifest schema")
        message_manifest = value.get("request_message_manifest")
        if not isinstance(message_manifest, list) or not message_manifest:
            raise RequestPayloadAttestationError(
                "request message manifest must be a non-empty list"
            )
        expected_message_keys = {
            "index",
            "role",
            "message_sha256",
            "content_sha256",
            "content_text_sha256",
            "content_part_manifest",
            "tool_calls_sha256",
        }
        for index, row in enumerate(message_manifest):
            if not isinstance(row, Mapping) or set(row) != expected_message_keys:
                raise RequestPayloadAttestationError(
                    f"request message manifest row {index} is malformed"
                )
            if row.get("index") != index:
                raise RequestPayloadAttestationError(
                    "request message manifest indexes are not contiguous"
                )
            if not isinstance(row.get("role"), str) or not str(row["role"]).strip():
                raise RequestPayloadAttestationError(
                    f"request message manifest row {index} lacks a role"
                )
            for name in (
                "message_sha256",
                "content_sha256",
                "tool_calls_sha256",
            ):
                if _SHA256.fullmatch(str(row.get(name) or "").casefold()) is None:
                    raise RequestPayloadAttestationError(
                        f"request message manifest row {index} has invalid {name}"
                    )
            text_digest = row.get("content_text_sha256")
            if text_digest is not None and _SHA256.fullmatch(str(text_digest).casefold()) is None:
                raise RequestPayloadAttestationError(
                    f"request message manifest row {index} has invalid text digest"
                )
            part_manifest = row.get("content_part_manifest")
            if part_manifest is not None:
                if text_digest is not None or not isinstance(part_manifest, list):
                    raise RequestPayloadAttestationError(
                        f"request message manifest row {index} has invalid content parts"
                    )
                expected_part_keys = {
                    "index",
                    "type",
                    "object_keys",
                    "part_sha256",
                    "text_sha256",
                }
                for part_index, part in enumerate(part_manifest):
                    if not isinstance(part, Mapping) or set(part) != expected_part_keys:
                        raise RequestPayloadAttestationError(
                            f"request message manifest row {index} content part {part_index} "
                            "is malformed"
                        )
                    if part.get("index") != part_index:
                        raise RequestPayloadAttestationError(
                            f"request message manifest row {index} content-part indexes "
                            "are not contiguous"
                        )
                    part_type = part.get("type")
                    object_keys = part.get("object_keys")
                    if (
                        not isinstance(part_type, str)
                        or not part_type.strip()
                        or not isinstance(object_keys, list)
                        or any(not isinstance(key, str) or not key for key in object_keys)
                        or object_keys != sorted(set(object_keys))
                    ):
                        raise RequestPayloadAttestationError(
                            f"request message manifest row {index} content part {part_index} "
                            "has invalid public structure"
                        )
                    if _SHA256.fullmatch(str(part.get("part_sha256") or "").casefold()) is None:
                        raise RequestPayloadAttestationError(
                            f"request message manifest row {index} content part {part_index} "
                            "has invalid digest"
                        )
                    part_text_digest = part.get("text_sha256")
                    if part_text_digest is not None and (
                        _SHA256.fullmatch(str(part_text_digest).casefold()) is None
                    ):
                        raise RequestPayloadAttestationError(
                            f"request message manifest row {index} content part {part_index} "
                            "has invalid text digest"
                        )
        observed_manifest_digest = str(
            value.get("request_message_manifest_sha256") or ""
        ).casefold()
        expected_manifest_digest = sha256_hex(canonical_json(message_manifest))
        if not hmac.compare_digest(observed_manifest_digest, expected_manifest_digest):
            raise RequestPayloadAttestationError("request message manifest digest mismatch")
        payload_tools = value.get("request_payload_tools")
        if not isinstance(payload_tools, list):
            raise RequestPayloadAttestationError("request payload tools must be a list")
        _assert_no_sensitive_keys(payload_tools)
        observed_tools_digest = str(value["request_payload_tools_sha256"]).casefold()
        expected_tools_digest = sha256_hex(canonical_json(payload_tools))
        if not hmac.compare_digest(observed_tools_digest, expected_tools_digest):
            raise RequestPayloadAttestationError(
                "request payload tool schemas differ from their digest"
            )

    manifest_keys = expected_keys.union(present_detail_keys)
    manifest = {key: copy.deepcopy(value[key]) for key in manifest_keys}
    observed_attestation_digest = str(manifest.pop("request_payload_attestation_sha256")).casefold()
    expected_attestation_digest = sha256_hex(canonical_json(manifest))
    if not hmac.compare_digest(observed_attestation_digest, expected_attestation_digest):
        raise RequestPayloadAttestationError("request payload attestation digest mismatch")


def empty_tools_sha256() -> str:
    """Digest used by a direct no-tool request such as a verification pass."""

    return hashlib.sha256(canonical_json([]).encode("utf-8")).hexdigest()


__all__ = [
    "REQUEST_MESSAGE_MANIFEST_SCHEMA_ID",
    "REQUEST_PAYLOAD_ATTESTATION_SCHEMA_ID",
    "RequestPayloadAttestationError",
    "attest_request_payload",
    "canonical_request_body",
    "empty_tools_sha256",
    "validate_request_payload_attestation",
]
