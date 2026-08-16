"""Shared validation for bounded deterministic recovery rules."""

from __future__ import annotations

import re
from collections.abc import Mapping

from langchain_core.messages import AIMessage, ToolMessage

from forensic_agent.core.repro import canonical_json, sha256_hex
from forensic_agent.core.result_reading import AnyToolResult


def _deterministic_tool_call_messages(
    tool_name: str,
    arguments: Mapping[str, object],
    wire: Mapping[str, object],
) -> list[object]:
    """Represent a harness-executed tool call as a valid auditable message pair.

    A recovery arm that runs a tool itself must append the result the way the
    model surface reads it back.  A bare ``{"role": "tool", ...}`` dict carries no
    ``tool_call_id``: the moment the message list is sent to the model again,
    LangChain's coercion raises ``KeyError('tool_call_id')`` and the run dies
    before it can publish.  A tool message's content must also be a string, never
    a mapping.  The synthetic assistant turn supplies the matching call id, and
    the tool turn carries ``canonical_json(wire)`` bound to it, which is the same
    shape :func:`memory_pagination._continuation_messages` already produces.
    """

    call_digest = sha256_hex(
        canonical_json(
            {
                "tool": tool_name,
                "arguments": dict(arguments),
                "wire": dict(wire),
                "origin": "deterministic_harness",
            }
        )
    )
    call_id = f"deterministic-{tool_name}-{call_digest[:20]}"
    return [
        AIMessage(
            content="",
            tool_calls=[
                {
                    "name": tool_name,
                    "args": dict(arguments),
                    "id": call_id,
                    "type": "tool_call",
                }
            ],
            additional_kwargs={"forensic_origin": "deterministic_harness"},
        ),
        ToolMessage(
            content=canonical_json(dict(wire)),
            tool_call_id=call_id,
            name=tool_name,
            additional_kwargs={"forensic_origin": "deterministic_harness"},
        ),
    ]


def _validated_continuation_result(record: Mapping[str, object]) -> AnyToolResult | None:
    """Validate one callback record before trusting an embedded affordance.

    Continuation instructions are executable control data.  They are therefore
    accepted only from a receipt-valid case-evidence result whose provenance binds
    the exact tool name and canonical arguments captured by the local callback.

    Every deterministic recovery rule reaches its records through this one
    function, so recognising both contracts here is what keeps a recovery arm from
    quietly deciding there is nothing to continue simply because the envelope
    version moved on.
    """

    from forensic_agent.agent.tool_contract import result_binds_call
    from forensic_agent.core.result_contract import ProvenanceType, ToolStatus
    from forensic_agent.core.result_reading import (
        UnreadableResult,
        is_candidate_case_evidence,
        read_result,
        receipt_is_valid,
    )

    tool_name = record.get("tool")
    arguments = record.get("arguments")
    wire = record.get("result")
    if (
        not isinstance(tool_name, str)
        or not isinstance(arguments, Mapping)
        or not isinstance(wire, Mapping)
    ):
        return None
    try:
        result = read_result(wire)
    except (TypeError, UnreadableResult):
        return None
    if not receipt_is_valid(result):
        return None
    if (
        result.status not in {ToolStatus.OK, ToolStatus.PARTIAL}
        or result.provenance.type is not ProvenanceType.CASE_EVIDENCE
        or not is_candidate_case_evidence(result)
        or result.provenance.tool.name != tool_name
        or not result_binds_call(result, arguments)
    ):
        return None
    return result


def _realized_continuation_arguments(
    tool: object, arguments: Mapping[str, object]
) -> dict[str, object]:
    """Apply the visible tool schema defaults used by ``StructuredTool.invoke``.

    Continuation affordances intentionally contain only the discriminating fields
    (for example ``{"read": 9}``).  LangChain expands explicit schema defaults
    before it calls the wrapped tool, and those realized arguments are what the
    provenance receipt binds.  Validate and expand the same schema independently
    so the post-call comparison is strict without hashing a shorthand request.

    A JSON-Schema argument schema expands NOTHING on the way in: LangChain hands
    a mapping input to the wrapped function unchanged, so the call the receipt
    binds is the call that was supplied.  Saying that here keeps this comparison
    strict for both kinds of schema instead of refusing the continuation
    outright, which is what an assumed pydantic model would do.
    """

    schema = getattr(tool, "args_schema", None)
    if isinstance(schema, Mapping):
        return dict(arguments)
    validate = getattr(schema, "model_validate", None)
    if not callable(validate):
        raise RuntimeError("deterministic continuation tool lacks a Pydantic argument schema")
    try:
        validated = validate(dict(arguments))
        realized = validated.model_dump(mode="json")
    except (TypeError, ValueError) as exc:
        raise RuntimeError("deterministic continuation arguments failed schema validation") from exc
    if not isinstance(realized, Mapping):
        raise RuntimeError("deterministic continuation arguments did not realize to a mapping")
    return dict(realized)


def _messages_accept_a_follow_up(messages: list[object]) -> bool:
    """Return whether a human turn may be appended to this message state.

    Every tool call the model has issued must already have its result. A message
    list that ends on an unanswered call is mid-exchange, and inserting a human
    turn into it is not a valid conversation.

    Shared because every arm that addresses the model before it concludes needs
    exactly this precondition, and a second copy would eventually disagree about
    when an exchange is closed — one arm losing the whole run to a rejected
    request while the other stayed silent.
    """

    if not messages:
        return False
    answered: set[str] = set()
    requested: set[str] = set()
    for message in messages:
        if getattr(message, "type", None) == "tool":
            call_id = getattr(message, "tool_call_id", None)
            if isinstance(call_id, str):
                answered.add(call_id)
        for tool_call in getattr(message, "tool_calls", None) or []:
            call_id = tool_call.get("id") if isinstance(tool_call, Mapping) else None
            if isinstance(call_id, str):
                requested.add(call_id)
    if requested - answered:
        return False
    return getattr(messages[-1], "type", None) in {"ai", "tool"}


def _case_bundle_sha256(result: object) -> str | None:
    """Return a validated case-bundle digest from provenance."""

    provenance = getattr(result, "provenance", None)
    source = getattr(provenance, "source", None)
    attributes = getattr(source, "attributes", None)
    if not isinstance(attributes, Mapping):
        return None
    value = str(attributes.get("case_bundle_sha256") or "").strip().casefold()
    return value if re.fullmatch(r"[0-9a-f]{64}", value) is not None else None
