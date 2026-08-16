"""Bounded recovery of the most recent incomplete forensic-function call."""

from __future__ import annotations

import json
from collections.abc import Callable, Collection, Mapping
from contextlib import nullcontext
from dataclasses import dataclass

from langchain_core.messages import HumanMessage, ToolMessage
from langchain_core.tools import StructuredTool
from langgraph.errors import GraphRecursionError

from forensic_agent.agent.execution_budget import _DispatchDenied
from forensic_agent.agent.recovery.common import _realized_continuation_arguments
from forensic_agent.core.repro import canonical_json, sha256_hex

_PENDING_TOOL_RECOVERY_METRICS_SCHEMA_ID = "forensic.pending-tool-recovery-metrics.v1"

#: Identifies a control record that closes a model tool call which was never
#: executed.  It is deliberately NOT the tool-result contract: it carries no
#: receipt, no provenance and no data, so nothing downstream can mistake a
#: refusal for a reading of the evidence.
TOOL_DISPATCH_REFUSAL_SCHEMA_ID = "forensic.tool-dispatch-refusal.v1"

_REFUSAL_DETAIL = (
    "The execution budget refused this call before dispatch. No forensic operation "
    "was performed, nothing was read from the evidence, and this record is not "
    "evidence. Do not report it as a finding. Conclude from the tool results "
    "already gathered, or state that the evidence is inconclusive."
)


@dataclass(frozen=True, slots=True)
class _PendingToolCall:
    call_id: str
    name: str
    arguments: dict[str, object]
    fingerprint: str


def _empty_pending_tool_recovery_metrics(*, enabled: bool) -> dict[str, object]:
    """Return content-free telemetry for one unresolved model tool call."""

    return {
        "schema_id": _PENDING_TOOL_RECOVERY_METRICS_SCHEMA_ID,
        "enabled": enabled,
        "activated": False,
        "decision": "not_evaluated" if enabled else "arm_disabled",
        "pending_call_count": 0,
        "invalid_call_count": 0,
        "ambiguous_candidate_count": 0,
        "tool_name": None,
        "requested_call_sha256": None,
        "result_reused": False,
        "executed_calls": 0,
        "resume_attempted": False,
        "resume_model_requests": 0,
        "correction_requested": False,
        "correction_model_requests": 0,
        "completed": False,
    }


def _raw_tool_call_identity(value: object) -> tuple[str, str, dict[str, object]] | None:
    """Normalize one OpenAI-compatible raw function call without guessing."""

    if not isinstance(value, Mapping):
        return None
    call_id = value.get("id")
    function = value.get("function")
    if not isinstance(call_id, str) or not call_id.strip() or not isinstance(function, Mapping):
        return None
    name = function.get("name")
    raw_arguments = function.get("arguments")
    if not isinstance(name, str) or not name.strip():
        return None
    if isinstance(raw_arguments, str):
        try:
            arguments = json.loads(raw_arguments)
        except (TypeError, ValueError):
            return None
    else:
        arguments = raw_arguments
    if not isinstance(arguments, Mapping):
        return None
    normalized = json.loads(canonical_json(dict(arguments)))
    if not isinstance(normalized, dict):  # pragma: no cover - canonical object above
        return None
    return call_id.strip(), name.strip(), normalized


def _pending_final_tool_call(
    messages: Collection[object],
) -> tuple[_PendingToolCall | None, str, int, int]:
    """Inspect the final AI message for exactly one valid unresolved tool call.

    Both LangChain's parsed calls and the OpenAI-compatible raw call envelope are
    checked.  A provider response that declares ``finish_reason=tool_calls`` but
    supplies no executable call is a protocol defect, never permission to invent
    arguments or continue with an unrelated user message.
    """

    materialized = list(messages)
    if not materialized or getattr(materialized[-1], "type", None) != "ai":
        return None, "no_unresolved_final_tool_call", 0, 0
    message = materialized[-1]
    parsed = list(getattr(message, "tool_calls", None) or [])
    invalid = list(getattr(message, "invalid_tool_calls", None) or [])
    additional = getattr(message, "additional_kwargs", None)
    raw_value = additional.get("tool_calls") if isinstance(additional, Mapping) else None
    raw = list(raw_value) if isinstance(raw_value, list) else []
    response_metadata = getattr(message, "response_metadata", None)
    declared = (
        isinstance(response_metadata, Mapping)
        and response_metadata.get("finish_reason") == "tool_calls"
    )
    pending_count = max(len(parsed), len(invalid), len(raw))
    if not (parsed or invalid or raw or declared):
        return None, "no_unresolved_final_tool_call", 0, 0
    if invalid:
        return None, "invalid_tool_call", pending_count, len(invalid)
    if not parsed:
        if len(raw) != 1:
            return None, "declared_tool_call_not_parsed", pending_count, 1
        raw_identity = _raw_tool_call_identity(raw[0])
        if raw_identity is None:
            return None, "invalid_raw_tool_call", 1, 1
        raw_id, raw_name, raw_arguments = raw_identity
        fingerprint = sha256_hex(
            canonical_json({"tool": raw_name, "arguments": raw_arguments})
        )
        return (
            _PendingToolCall(
                call_id=raw_id,
                name=raw_name,
                arguments=raw_arguments,
                fingerprint=fingerprint,
            ),
            "unique_unresolved_raw_tool_call",
            1,
            0,
        )
    if len(parsed) != 1:
        return None, "multiple_unresolved_tool_calls", len(parsed), 0

    call = parsed[0]
    if not isinstance(call, Mapping):
        return None, "invalid_tool_call", 1, 1
    call_id = call.get("id")
    name = call.get("name")
    arguments = call.get("args")
    if (
        not isinstance(call_id, str)
        or not call_id.strip()
        or not isinstance(name, str)
        or not name.strip()
        or not isinstance(arguments, Mapping)
    ):
        return None, "invalid_tool_call", 1, 1
    normalized_arguments = json.loads(canonical_json(dict(arguments)))
    if not isinstance(normalized_arguments, dict):  # pragma: no cover - canonical object above
        return None, "invalid_tool_call", 1, 1
    if raw:
        if len(raw) != 1:
            return None, "raw_and_parsed_tool_calls_disagree", max(1, len(raw)), 1
        raw_identity = _raw_tool_call_identity(raw[0])
        if raw_identity is None:
            return None, "invalid_raw_tool_call", 1, 1
        raw_id, raw_name, raw_arguments = raw_identity
        if (
            raw_id != call_id.strip()
            or raw_name != name.strip()
            or canonical_json(raw_arguments) != canonical_json(normalized_arguments)
        ):
            return None, "raw_and_parsed_tool_calls_disagree", 1, 1
    fingerprint = sha256_hex(
        canonical_json({"tool": name.strip(), "arguments": normalized_arguments})
    )
    return (
        _PendingToolCall(
            call_id=call_id.strip(),
            name=name.strip(),
            arguments=normalized_arguments,
            fingerprint=fingerprint,
        ),
        "unique_unresolved_tool_call",
        1,
        0,
    )


def _resolved_tool_messages(
    messages: Collection[object],
) -> tuple[set[str], dict[str, list[ToolMessage]], set[str]]:
    """Index earlier call IDs and resolved results for duplicate-safe recovery."""

    calls_by_id: dict[str, str] = {}
    ambiguous_call_ids: set[str] = set()
    prior_call_ids: set[str] = set()

    def remember_fingerprint(call_id: str, fingerprint: str) -> None:
        normalized_id = call_id.strip()
        if not normalized_id:
            return
        prior_call_ids.add(normalized_id)
        previous = calls_by_id.get(normalized_id)
        if previous is not None and previous != fingerprint:
            ambiguous_call_ids.add(normalized_id)
            calls_by_id.pop(normalized_id, None)
        elif normalized_id not in ambiguous_call_ids:
            calls_by_id[normalized_id] = fingerprint

    for message in messages:
        if getattr(message, "type", None) != "ai":
            continue
        for call in [
            *(getattr(message, "tool_calls", None) or []),
            *(getattr(message, "invalid_tool_calls", None) or []),
        ]:
            if not isinstance(call, Mapping):
                continue
            call_id = call.get("id")
            if isinstance(call_id, str) and call_id.strip():
                prior_call_ids.add(call_id.strip())
            name = call.get("name")
            arguments = call.get("args", call.get("arguments"))
            if (
                not isinstance(call_id, str)
                or not call_id.strip()
                or not isinstance(name, str)
                or not name.strip()
                or not isinstance(arguments, Mapping)
            ):
                continue
            fingerprint = sha256_hex(
                canonical_json({"tool": name.strip(), "arguments": dict(arguments)})
            )
            remember_fingerprint(call_id, fingerprint)

        additional = getattr(message, "additional_kwargs", None)
        raw_value = additional.get("tool_calls") if isinstance(additional, Mapping) else None
        for raw_call in raw_value if isinstance(raw_value, list) else []:
            if isinstance(raw_call, Mapping):
                raw_id = raw_call.get("id")
                if isinstance(raw_id, str) and raw_id.strip():
                    prior_call_ids.add(raw_id.strip())
            raw_identity = _raw_tool_call_identity(raw_call)
            if raw_identity is None:
                continue
            raw_id, raw_name, raw_arguments = raw_identity
            raw_fingerprint = sha256_hex(
                canonical_json({"tool": raw_name, "arguments": raw_arguments})
            )
            remember_fingerprint(raw_id, raw_fingerprint)

    resolved_ids: set[str] = set()
    by_fingerprint: dict[str, list[ToolMessage]] = {}
    for message in messages:
        if not isinstance(message, ToolMessage):
            continue
        call_id = str(message.tool_call_id or "").strip()
        if not call_id:
            continue
        resolved_ids.add(call_id)
        resolved_fingerprint = calls_by_id.get(call_id)
        if resolved_fingerprint is not None:
            by_fingerprint.setdefault(resolved_fingerprint, []).append(message)
    return resolved_ids, by_fingerprint, prior_call_ids


def _final_message_tool_calls(messages: Collection[object]) -> list[tuple[str, str | None]]:
    """Every ``(call_id, name)`` the final assistant message asked for, in order.

    Both the parsed calls and the OpenAI-compatible raw envelope are read, and a
    call ID is reported once even when it appears in both.  Unlike
    :func:`_pending_final_tool_call` this does not require the message to carry
    exactly one call: a provider may emit a parallel batch, and every ID in that
    batch has to be accounted for.

    The message is the last assistant turn that requested tools, not literally
    the last message.  When a batch is interrupted partway, the results that did
    commit already follow it, so requiring an assistant message in final position
    would leave the unanswered siblings of an answered call invisible.
    """

    materialized = list(messages)
    message = None
    for candidate in reversed(materialized):
        if getattr(candidate, "type", None) != "ai":
            continue
        additional = getattr(candidate, "additional_kwargs", None)
        raw_value = additional.get("tool_calls") if isinstance(additional, Mapping) else None
        if (
            (getattr(candidate, "tool_calls", None) or [])
            or (getattr(candidate, "invalid_tool_calls", None) or [])
            or (raw_value if isinstance(raw_value, list) else [])
        ):
            message = candidate
            break
    if message is None:
        return []
    ordered: list[tuple[str, str | None]] = []
    seen: set[str] = set()

    def remember(call_id: object, name: object) -> None:
        if not isinstance(call_id, str) or not call_id.strip():
            return
        normalized_id = call_id.strip()
        if normalized_id in seen:
            return
        seen.add(normalized_id)
        ordered.append(
            (normalized_id, name.strip() if isinstance(name, str) and name.strip() else None)
        )

    for call in [
        *(getattr(message, "tool_calls", None) or []),
        *(getattr(message, "invalid_tool_calls", None) or []),
    ]:
        if isinstance(call, Mapping):
            remember(call.get("id"), call.get("name"))

    additional = getattr(message, "additional_kwargs", None)
    raw_value = additional.get("tool_calls") if isinstance(additional, Mapping) else None
    for raw_call in raw_value if isinstance(raw_value, list) else []:
        if not isinstance(raw_call, Mapping):
            continue
        function = raw_call.get("function")
        remember(
            raw_call.get("id"),
            function.get("name") if isinstance(function, Mapping) else None,
        )
    return ordered


def close_refused_tool_calls(
    messages: Collection[object],
    *,
    reason: str,
    closes: Callable[[str | None], bool] | None = None,
) -> tuple[list[ToolMessage], dict[str, object]]:
    """Close every unexecuted call ID on the final message with a control record.

    A refused dispatch leaves the exchange malformed: the assistant asked for a
    function and nothing answered it.  Every later gate then fails closed, and a
    run that already holds sufficient evidence is discarded with its model budget
    almost entirely unspent.  Closing the call restores a well-formed exchange
    WITHOUT inventing a result: the record states that nothing ran.

    The call is never re-dispatched here.  Re-attempting a call the ceiling has
    already refused only spends another rejection on the same ID.

    ``closes`` decides, per requested function, whether THIS exhaustion applies
    to it.  Ceilings are not shared: a run out of forensic dispatches may still
    read a stored result, and closing that call would end something that was
    still permitted — the reading of evidence the run had already gathered.
    Calls the exhaustion does not reach are left for the caller to resolve.
    """

    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("tool dispatch refusal reason must be a non-empty string")
    normalized_reason = reason.strip()
    materialized = list(messages)
    answered = {
        str(message.tool_call_id or "").strip()
        for message in materialized
        if isinstance(message, ToolMessage)
    }
    closed: list[ToolMessage] = []
    deferred = 0
    for call_id, name in _final_message_tool_calls(materialized):
        if call_id in answered:
            continue
        if closes is not None and not closes(name):
            deferred += 1
            continue
        payload = {
            "schema_id": TOOL_DISPATCH_REFUSAL_SCHEMA_ID,
            "status": "refused",
            "executed": False,
            "evidence": False,
            "reason": normalized_reason,
            "tool": name,
            "detail": _REFUSAL_DETAIL,
        }
        closed.append(
            ToolMessage(
                content=canonical_json(payload),
                tool_call_id=call_id,
                name=name,
                status="error",
            )
        )
    metrics: dict[str, object] = {
        "schema_id": "forensic.tool-dispatch-closure-metrics.v1",
        "reason": normalized_reason,
        "closed_call_count": len(closed),
        "closed_call_ids": [message.tool_call_id for message in closed],
        "deferred_call_count": deferred,
        "redispatched_call_count": 0,
    }
    return closed, metrics


def _recover_pending_tool_call(
    tools: Collection[StructuredTool],
    messages: Collection[object],
    *,
    enabled: bool,
) -> tuple[list[ToolMessage], dict[str, object], str | None, bool]:
    """Resolve one exact dangling model call through the registered wrapped tool.

    The controller does not select a tool or construct arguments.  It executes only
    the single parsed call already emitted by the model.  Ambiguous, malformed, or
    unknown calls remain blocked.  An earlier equivalent resolved call is replayed
    under the new call ID rather than executing the read-only operation twice.
    """

    metrics = _empty_pending_tool_recovery_metrics(enabled=enabled)
    if not enabled:
        return [], metrics, None, False
    candidate, decision, pending_count, invalid_count = _pending_final_tool_call(messages)
    metrics.update(
        {
            "decision": decision,
            "pending_call_count": pending_count,
            "invalid_call_count": invalid_count,
        }
    )
    if candidate is None:
        blocked = decision != "no_unresolved_final_tool_call"
        if decision == "multiple_unresolved_tool_calls":
            metrics["ambiguous_candidate_count"] = pending_count
        metrics["activated"] = blocked
        return [], metrics, None, blocked

    metrics.update(
        {
            "activated": True,
            "tool_name": candidate.name,
            "requested_call_sha256": candidate.fingerprint,
        }
    )
    prior_messages = list(messages)[:-1]
    resolved_ids, by_fingerprint, prior_call_ids = _resolved_tool_messages(prior_messages)
    if candidate.call_id in resolved_ids or candidate.call_id in prior_call_ids:
        metrics["decision"] = "tool_call_id_reused"
        return [], metrics, None, True
    equivalent = by_fingerprint.get(candidate.fingerprint, [])
    if len(equivalent) > 1:
        metrics.update(
            {
                "decision": "equivalent_prior_results_ambiguous",
                "ambiguous_candidate_count": len(equivalent),
            }
        )
        return [], metrics, None, True
    if equivalent:
        previous = equivalent[0]
        message = ToolMessage(
            content=previous.content,
            tool_call_id=candidate.call_id,
            name=candidate.name,
        )
        metrics.update(
            {
                "decision": "equivalent_prior_result_reused",
                "result_reused": True,
            }
        )
        return [message], metrics, None, False

    matching_tools = [tool for tool in tools if str(tool.name) == candidate.name]
    if len(matching_tools) != 1:
        metrics.update(
            {
                "decision": (
                    "requested_tool_not_registered"
                    if not matching_tools
                    else "requested_tool_registry_ambiguous"
                ),
                "ambiguous_candidate_count": max(0, len(matching_tools) - 1),
            }
        )
        return [], metrics, None, True
    tool = matching_tools[0]
    try:
        realized_arguments = _realized_continuation_arguments(tool, candidate.arguments)
    except (TypeError, ValueError, RuntimeError):
        metrics.update({"decision": "requested_arguments_schema_invalid", "invalid_call_count": 1})
        return [], metrics, None, True
    try:
        output = tool.invoke(realized_arguments)
    except _DispatchDenied as exc:
        metrics["decision"] = "pending_tool_dispatch_budget_exhausted"
        return [], metrics, exc.reason, True
    message = ToolMessage(
        content=canonical_json(output),
        tool_call_id=candidate.call_id,
        name=candidate.name,
    )
    metrics.update({"decision": "pending_tool_executed", "executed_calls": 1})
    return [message], metrics, None, False


#: A final message whose tool call cannot be parsed is a recoverable model
#: mistake, not evidence of anything.  The harness must never repair the
#: arguments itself, but returning the failure and asking once is exactly what a
#: tool node does for an executed call.
MALFORMED_FINAL_CALL_DECISIONS = frozenset(
    {
        "invalid_tool_call",
        "invalid_raw_tool_call",
        "declared_tool_call_not_parsed",
    }
)

_CORRECTION_REQUEST = (
    "Your previous message ended with a tool call that could not be parsed, so it "
    "was never executed and produced no evidence. No arguments were supplied or "
    "guessed on your behalf. Either reissue that call with valid arguments, or, if "
    "the tool results already above are sufficient, answer only the requested fields "
    "using the shortest complete answer those results support. Report observations rather "
    "than adding unrequested background or interpretation, and label any necessary inference. "
    "Do not describe the failed call as a finding."
)


def correct_malformed_final_tool_call(
    messages: list[object],
    metrics: dict[str, object],
    *,
    llm,
    agent,
    investigation_ledger,
    recursion_limit: int,
) -> tuple[list[object], str | None, bool]:
    """Ask once for a parseable message, then re-check the terminal state.

    ``recursion_limit`` is derived from the same step budget that bounds the
    investigation loop, so the configured budget is what stops this request.  A
    graph limit of its own would abort a correction the run still had budget for,
    and the unresolved call then blocks publication and costs the whole task.

    Returns the message state to keep, any dispatch-exhaustion reason, and
    whether the unresolved call is still blocking.
    """

    metrics["correction_requested"] = True
    requests_before = investigation_ledger.count
    try:
        request_role = getattr(llm, "request_role", None)
        role_scope = request_role("investigation") if callable(request_role) else nullcontext()
        with role_scope:
            corrected = agent.invoke(
                {"messages": [*messages, HumanMessage(_CORRECTION_REQUEST)]},
                config={
                    "recursion_limit": recursion_limit,
                    "callbacks": [investigation_ledger],
                },
            )
    except _DispatchDenied as exc:
        metrics["decision"] = "correction_dispatch_budget_exhausted"
        metrics["correction_model_requests"] = investigation_ledger.count - requests_before
        return messages, exc.reason, True
    except GraphRecursionError:
        metrics["decision"] = "correction_recursion_limit"
        metrics["correction_model_requests"] = investigation_ledger.count - requests_before
        return messages, None, True
    metrics["correction_model_requests"] = investigation_ledger.count - requests_before
    raw_messages = corrected.get("messages") if isinstance(corrected, Mapping) else None
    if not isinstance(raw_messages, list) or len(raw_messages) < len(messages):
        metrics["decision"] = "correction_returned_no_message_state"
        return messages, None, True
    _call, decision, pending_count, invalid_count = _pending_final_tool_call(raw_messages)
    metrics.update(
        {
            "pending_call_count": pending_count,
            "invalid_call_count": invalid_count,
        }
    )
    if decision != "no_unresolved_final_tool_call":
        metrics["decision"] = "correction_ended_with_unresolved_tool_call"
        return raw_messages, None, True
    metrics["decision"] = "recovered_after_malformed_call_correction"
    metrics["completed"] = True
    return raw_messages, None, False
