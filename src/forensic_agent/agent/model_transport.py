"""OpenRouter transport i potvrda stvarno poslanih zahtjeva."""

from __future__ import annotations

import copy
import re
import threading
from collections.abc import Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

import openai
from langchain_openai import ChatOpenAI as _LangChainChatOpenAI
from pydantic import PrivateAttr

from forensic_agent.agent.execution_budget import (
    _CellExecutionBudget,
    _DispatchDenied,
    _DispatchPermit,
    _FrozenRequestTimeout,
)
from forensic_agent.agent.provider_failure import ProviderFailure, describe_provider_failure
from forensic_agent.core.request_attestation import attest_request_payload

TOOL_CHOICE_DEGRADATION_SCHEMA_ID = "forensic.model-tool-choice-degradation.v1"
TOOL_CHOICE_DEGRADATION_EVENT = "model_tool_choice_degraded"

RESPONSE_FORMAT_DEGRADATION_SCHEMA_ID = "forensic.model-response-format-degradation.v1"
RESPONSE_FORMAT_DEGRADATION_EVENT = "model_response_format_degraded"

PROVIDER_SWAP_SCHEMA_ID = "forensic.model-provider-swap.v1"
PROVIDER_SWAP_EVENT = "model_provider_swap"

#: How many times ONE model request may be dispatched again after a provider it
#: was moved to rejected it.  One.
#:
#: The resend is not a wait for capacity — that is a run-level concern, and
#: repeatedly asking an endpoint that just answered is the hammering a forensic
#: tool must not do.  It asks the router to place the SAME body once more, which
#: is a question the router answers on the first resend or not at all.  Every
#: further attempt would spend another of the run's model requests re-asking a
#: question already answered, and would be indistinguishable from polling the
#: router until it yields.  The resend is deliberately immediate: a backoff
#: would add wall-clock delay to a per-cell deadline.
PROVIDER_SWAP_MAX_RESENDS = 1

# OpenRouter returns a model's own reasoning beside the tool call that it
# motivated, and requires the same blocks back, unchanged, on the request that
# carries the tool results, or the model cannot resume the thought the call
# interrupted.  These are the provider's bytes: they are read off the assistant
# message, carried on it, and written back onto that same assistant message.
#
# They are model-authored text and therefore never evidence.  They exist only in
# ``AIMessage.additional_kwargs`` and in the outbound request body.  Nothing
# projects them: the standardized result contract never sees them, the finding
# and answer paths read message CONTENT only, the reproducibility digest keeps
# role/content/tool_calls only, and the request receipt binds them by digest
# without retaining their text.
REASONING_CONTINUITY_FIELDS = ("reasoning", "reasoning_details")

# A provider that cannot accept a forced tool call says so by naming the
# parameter and calling it unsupported.  Both halves have to fall inside ONE
# clause: a 400 that merely mentions ``tool_choice`` (a forced function the
# palette does not contain, a malformed body) is a real error about this request
# and must keep surfacing exactly as it does today.
_UNSUPPORTED = (
    r"(?:does not support|is not supported|not supported|unsupported"
    r"|cannot be (?:set|used)|is not allowed)"
)
_CONSTRAINED_TOOL_CHOICE_REFUSALS = (
    re.compile(r"tool_choice\b[^.;\n]{0,120}?" + _UNSUPPORTED, re.IGNORECASE),
    re.compile(_UNSUPPORTED + r"[^.;\n]{0,120}?\btool_choice\b", re.IGNORECASE),
)

# The same reading applied to the parameter that constrains DECODING.  An
# endpoint that cannot hold a reply to a schema says so the same way, and under
# the same one-clause rule: "Invalid schema for response_format" names the
# parameter too, but it is a fault in THIS request and has to keep surfacing.
_RESPONSE_FORMAT = r"(?:response_format|json_schema|structured\s+outputs?)"
_CONSTRAINED_RESPONSE_FORMAT_REFUSALS = (
    re.compile(_RESPONSE_FORMAT + r"\b[^.;\n]{0,120}?" + _UNSUPPORTED, re.IGNORECASE),
    re.compile(_UNSUPPORTED + r"[^.;\n]{0,120}?\b" + _RESPONSE_FORMAT, re.IGNORECASE),
)


@dataclass
class ResponseFormatConstraint:
    """What became of the decoding constraint on one request.

    Only the transport sees whether the body really went out carrying the schema
    and whether the provider took it, while the phase that asked for it is the
    one that has to report it.  Carrying the answer on the handle the caller
    already holds keeps the fact beside the request it belongs to, instead of on
    a client that serves the whole run.
    """

    response_format: dict[str, Any]
    dispatched: bool = False
    refused: bool = False

    @property
    def outcome(self) -> str:
        """A closed vocabulary for the run's own telemetry."""

        if self.refused:
            return "refused_by_provider"
        if self.dispatched:
            return "constrained"
        return "not_dispatched"


def _is_constrained_tool_choice(tool_choice: object) -> bool:
    """Report whether a payload compelled a tool call instead of permitting one.

    ``auto`` leaves the bound palette usable and ``none`` withholds it; only
    ``required`` and the explicit function object take the choice away from the
    model, so only those are constraints a provider can refuse on its behalf.
    """

    return tool_choice == "required" or isinstance(tool_choice, Mapping)


def _refuses_request_control(
    error: BaseException, patterns: tuple[re.Pattern[str], ...]
) -> bool:
    """Recognise a provider rejecting a control itself, not the request.

    Only the provider's own wording is scanned, so a parameter name appearing in
    a machine-readable field cannot on its own be read as a refusal.
    """

    if not isinstance(error, openai.APIStatusError) or error.status_code != 400:
        return False
    texts = [str(getattr(error, "message", "") or "")]
    body = getattr(error, "body", None)
    if isinstance(body, Mapping):
        texts.append(str(body.get("message") or ""))
    return any(pattern.search(text) for text in texts for pattern in patterns)


def _refuses_constrained_tool_choice(error: BaseException) -> bool:
    """Whether the provider declined to be told which tool to call."""

    return _refuses_request_control(error, _CONSTRAINED_TOOL_CHOICE_REFUSALS)


def _refuses_constrained_response_format(error: BaseException) -> bool:
    """Whether the provider declined to hold the reply to a schema."""

    return _refuses_request_control(error, _CONSTRAINED_RESPONSE_FORMAT_REFUSALS)


def _visible_functions(tool_list: list[Any]) -> dict[str, Any]:
    """Index the model-visible palette by function name, in payload order."""

    visible: dict[str, Any] = {}
    for tool in tool_list:
        if not isinstance(tool, Mapping) or not isinstance(tool.get("function"), Mapping):
            continue
        name = tool["function"].get("name")
        if isinstance(name, str) and name:
            visible[name] = tool
    return visible


def _provider_reasoning(source: Mapping[str, Any] | Any) -> dict[str, Any]:
    """Lift the provider's reasoning blocks off one message, exactly as given.

    ``source`` is either a raw response message or a LangChain message carrying
    ``additional_kwargs``.  The blocks are deep-copied so the outbound body and
    the retained message can never alias one mutable structure, which copies the
    value without touching its shape: no re-ordering, no re-encoding, no
    truncation.  A provider that returns none yields an empty mapping, and then
    nothing is added anywhere.
    """

    fields = source if isinstance(source, Mapping) else getattr(source, "additional_kwargs", None)
    if not isinstance(fields, Mapping):
        return {}
    return {
        field: copy.deepcopy(fields[field])
        for field in REASONING_CONTINUITY_FIELDS
        if fields.get(field) is not None
    }


def _numeric_token_usage(usage: Any) -> dict[str, Any]:
    """Reduce one provider usage block to the numbers an examiner can add up.

    OpenAI-compatible providers report the reasoning-token count inside the
    completion details rather than beside the totals, so a flat copy of the block
    silently drops the one number that says how much thinking a request was
    billed for.  Only that count is lifted: everything else in a details block is
    a breakdown of a total already recorded here.
    """

    if not isinstance(usage, Mapping):
        return {}
    numbers = {
        name: amount
        for name, amount in usage.items()
        if isinstance(amount, int | float) and not isinstance(amount, bool)
    }
    details = usage.get("completion_tokens_details")
    if "reasoning_tokens" not in numbers and isinstance(details, Mapping):
        reasoning_tokens = details.get("reasoning_tokens")
        if isinstance(reasoning_tokens, int | float) and not isinstance(reasoning_tokens, bool):
            numbers["reasoning_tokens"] = reasoning_tokens
    return numbers


class _RequestPayloadLedger:
    """Bind exact SDK-bound request receipts to LangChain callback run IDs."""

    def __init__(self) -> None:
        self._rows: dict[str, dict[str, object]] = {}
        self._refused: dict[str, list[dict[str, object]]] = {}
        self._lock = threading.Lock()

    def capture(
        self,
        run_id: str,
        payload: Mapping[str, Any],
        *,
        dispatch: Mapping[str, object] | None = None,
    ) -> None:
        if not run_id:
            raise RuntimeError("request payload attestation lacks a callback run ID")
        attestation = attest_request_payload(payload)
        if dispatch is not None:
            attestation["request_dispatch"] = dict(dispatch)
        with self._lock:
            previous = self._rows.get(run_id)
            if previous is not None and previous != attestation:
                raise RuntimeError("conflicting request payloads share one callback run ID")
            self._rows[run_id] = attestation

    def refuse(self, run_id: str, refusal: Mapping[str, object]) -> None:
        """Retire the receipt of a body the provider rejected outright.

        A retry dispatches a DIFFERENT body under the same callback run ID.  The
        rejected body was really sent, so its receipt is retained beside the
        reason it was rejected instead of being overwritten; the retry then
        attests the body that actually reached the model.
        """

        if not run_id:
            raise RuntimeError("refused request payload lacks a callback run ID")
        with self._lock:
            attestation = self._rows.pop(run_id, None)
            if attestation is None:
                raise RuntimeError("refused request payload was never attested")
            self._refused.setdefault(run_id, []).append(
                {**attestation, "request_payload_refusal": dict(refusal)}
            )

    def bind(self, rows: list[dict[str, object]]) -> list[dict[str, object]]:
        with self._lock:
            pending = {key: dict(value) for key, value in self._rows.items()}
            refused = {
                key: [dict(item) for item in value] for key, value in self._refused.items()
            }
        bound: list[dict[str, object]] = []
        for value in rows:
            row = dict(value)
            run_id = str(row.get("callback_run_id") or "")
            attestation = pending.pop(run_id, None)
            if attestation is not None:
                row.update(attestation)
            attempts = refused.pop(run_id, None)
            if attempts is not None:
                # The refused body was dispatched too, so one row carries both:
                # what the provider rejected, and what was sent in its place.
                row["request_payload_refused_attempts"] = attempts
            bound.append(row)
        if pending or refused:
            raise RuntimeError("request payload attestation lacks a callback ledger row")
        return bound


def _request_run_id_context() -> ContextVar[str | None]:
    return ContextVar("openrouter_request_run_id", default=None)


class ChatOpenAI(_LangChainChatOpenAI):
    """Preserve OpenRouter's response-side routing attestation.

    ``langchain-openai`` intentionally normalizes the OpenAI-compatible response
    and otherwise drops OpenRouter's top-level ``provider`` and
    ``openrouter_metadata`` fields.  These fields let a downstream consumer
    prove the route that actually served each request without waiting for the
    eventually consistent generation-metadata endpoint.
    """

    _request_payload_ledger: _RequestPayloadLedger | None = PrivateAttr(default=None)
    _oversight_recorder: Any = PrivateAttr(default=None)
    _frozen_request_timeout: _FrozenRequestTimeout | None = PrivateAttr(default=None)
    _execution_budget: _CellExecutionBudget | None = PrivateAttr(default=None)
    _active_request_role: str = PrivateAttr(default="investigation")
    _first_investigation_tool_choice: str = PrivateAttr(default="auto")
    _investigation_request_count: int = PrivateAttr(default=0)
    _next_specific_tool_choice: str | None = PrivateAttr(default=None)
    _accepts_constrained_tool_choice: bool = PrivateAttr(default=True)
    _dispatched_tool_choice: Any = PrivateAttr(default=None)
    _dispatched_specific_tool: str | None = PrivateAttr(default=None)
    _response_format_constraint: ResponseFormatConstraint | None = PrivateAttr(default=None)
    _dispatched_response_format: Any = PrivateAttr(default=None)
    _reasoning_relieved: bool = PrivateAttr(default=False)
    _provider_swap_resends: int = PrivateAttr(default=0)
    _request_run_id: ContextVar[str | None] = PrivateAttr(default_factory=_request_run_id_context)

    def configure_request_attestation(
        self,
        ledger: _RequestPayloadLedger,
        request_timeout: _FrozenRequestTimeout,
        execution_budget: _CellExecutionBudget | None = None,
    ) -> None:
        """Enable payload capture and a fixed ceiling or remaining-deadline timeout."""

        self._request_payload_ledger = ledger
        self._frozen_request_timeout = request_timeout
        self._execution_budget = execution_budget

    def configure_oversight_recorder(self, recorder: Any) -> None:
        """Bind the run's append-only chain so transport controls reach it.

        The ledger proves what was sent; the chain carries the DECISIONS behind
        it.  A control the transport weakens on its own has to appear there next
        to every other control decision, or it is only visible as an absent
        constraint that nobody has a reason to look for.
        """

        self._oversight_recorder = recorder

    def configure_tool_choice_policy(self, *, first_investigation: str) -> None:
        """Freeze the per-role tool-selection policy before the graph is built.

        Only the first investigation request may differ from OpenAI's ``auto``
        behavior.  The graph deliberately resets neither this counter nor the
        policy mid-run, so retries inside one SDK request cannot create another
        "first" investigation turn.
        """

        if first_investigation not in {"auto", "required"}:
            raise ValueError("first investigation tool_choice must be 'auto' or 'required'")
        self._first_investigation_tool_choice = first_investigation
        self._investigation_request_count = 0

    @contextmanager
    def request_role(self, role: str):
        """Set the sequential graph role observed at the transport boundary."""

        if role not in {"investigation", "forced_final"}:
            raise ValueError("ChatOpenAI request role is invalid")
        previous = self._active_request_role
        self._active_request_role = role
        try:
            yield
        finally:
            self._active_request_role = previous

    @contextmanager
    def force_next_tool_choice(self, tool_name: str):
        """Force exactly the next tool-bearing request to call ``tool_name``.

        This narrow override is used only by the explicit multi-source coverage
        gate.  It leaves the full bound tool registry visible and consumes itself
        when the next transport payload is built, so the model can interpret the
        resulting evidence and conclude normally on the following request.
        """

        if not isinstance(tool_name, str) or not tool_name.strip():
            raise ValueError("specific tool choice must be a non-empty tool name")
        if self._next_specific_tool_choice is not None:
            raise RuntimeError("a specific tool choice is already pending")
        self._next_specific_tool_choice = tool_name.strip()
        try:
            yield
        finally:
            self._next_specific_tool_choice = None

    @contextmanager
    def constrain_response_format(self, response_format: Mapping[str, Any]):
        """Hold the terminal request's reply to one declared shape.

        The provider masks the tokens that would leave the schema, so the shape
        of the answer stops depending on the model choosing to produce it.  This
        is a request PARAMETER: no wording changes, and the model-visible surface
        stays exactly what it was.

        It applies only to the role that carries no functions.  A request that
        may still call a tool must still be able to return a tool call, so a
        constraint that reached one would replace the investigation with a
        conclusion drawn from nothing.  The handle it yields carries what became
        of the constraint, for the phase that has to report it.
        """

        if not isinstance(response_format, Mapping) or not response_format:
            raise ValueError("a response format constraint must be a non-empty mapping")
        if self._response_format_constraint is not None:
            raise RuntimeError("a response format constraint is already pending")
        constraint = ResponseFormatConstraint(copy.deepcopy(dict(response_format)))
        self._response_format_constraint = constraint
        try:
            yield constraint
        finally:
            self._response_format_constraint = None

    @contextmanager
    def relieve_reasoning(self):
        """Withhold the reasoning control from the one reserved concluding request.

        Every role spends the SAME bounded output budget, but the terminal turn
        alone must both reason over the whole gathered record AND write the
        conclusion into that budget.  On a reasoning model the first half can
        consume the whole allowance: the request stops at the output ceiling
        still reasoning, having written no answer, and a finding the run already
        holds is lost to the form of the turn that was meant to state it.

        Armed only around a RE-ISSUED terminal request whose ordinary attempt
        returned no usable draft, this hands that request's full output budget to
        the conclusion.  Like the tool withholding and the response-format
        constraint beside it, it is a request PARAMETER and reaches nothing but
        the role that carries no functions: no wording changes and the
        model-visible surface stays exactly what it was.
        """

        previous = self._reasoning_relieved
        self._reasoning_relieved = True
        try:
            yield
        finally:
            self._reasoning_relieved = previous

    def _get_request_payload(self, input_, *, stop=None, **kwargs):
        payload = super()._get_request_payload(input_, stop=stop, **kwargs)
        permit: _DispatchPermit | None = None
        if self._frozen_request_timeout is not None:
            # The OpenAI SDK treats ``timeout`` as a request option rather than a
            # JSON body field.  A caller with an execution budget reserves it
            # immediately before this exact transport payload is emitted and
            # receives only the remaining absolute cell time.  Other callers
            # retain the validated fixed ceiling.
            timeout_s = self._frozen_request_timeout.timeout_s
            if self._execution_budget is not None:
                permit = self._execution_budget.reserve_model(self._active_request_role)
                timeout_s = permit.remaining_s
            # The SDK applies ``timeout`` PER ATTEMPT and may retry up to
            # ``max_retries`` times, so the reserved time is shared out across
            # the attempts the client may actually make.  Sending the whole
            # reservation as the per-attempt timeout would let ONE dispatch
            # spend a multiple of the cell budget the reservation came from.
            attempts = max(1, int(getattr(self, "max_retries", 0) or 0) + 1)
            payload["timeout"] = max(1.0, timeout_s / attempts)
        forced_specific: str | None = None
        constrained_format: Any = None
        if self._active_request_role == "forced_final":
            # Withhold the palette structurally rather than by parameter.  A
            # request that carries no functions cannot call one whatever the
            # provider does with "tool_choice", and omitting both fields is the
            # form every OpenAI-compatible provider accepts identically.  This
            # is the payload the ledger attests: nothing is sent that the record
            # does not show.
            payload.pop("tools", None)
            payload.pop("tool_choice", None)
            constraint = self._response_format_constraint
            if constraint is not None and not constraint.refused:
                # Only here, and only while a constraint is armed: this is the
                # one request whose reply the runtime assembles rather than
                # publishes, so it is the one request whose shape is not the
                # model's to choose.
                payload["response_format"] = copy.deepcopy(constraint.response_format)
                constraint.dispatched = True
                constrained_format = payload["response_format"]
            if self._reasoning_relieved:
                # The concluding turn does not investigate; it states what the
                # gathered evidence already shows.  Where its ordinary attempt
                # spent the bounded output budget reasoning and stopped before the
                # answer, this re-issue withholds the reasoning control so the
                # whole budget reaches the conclusion.  The provider carries the
                # field in ``extra_body`` on the controlled OpenRouter route and,
                # defensively, at the top level; both are dropped here.
                payload.pop("reasoning", None)
                extra = payload.get("extra_body")
                if isinstance(extra, dict):
                    extra.pop("reasoning", None)
        tools = payload.get("tools")
        tool_list = tools if isinstance(tools, list) else []
        has_tools = bool(tool_list)
        if has_tools:
            self._declare_local_tool_choice_incapability()
            specific = self._next_specific_tool_choice
            if specific is not None:
                visible = _visible_functions(tool_list)
                if specific not in visible:
                    raise RuntimeError("specific tool choice is not model-visible")
                forced = {"type": "function", "function": {"name": specific}}
                # Recorded whichever way the compulsion is expressed, because a
                # resend of THIS body has to express it the same way; the
                # degradation path below reads the parameter it was sent with,
                # not this name, so it is unaffected by the wider capture.
                forced_specific = specific
                if self._accepts_constrained_tool_choice:
                    payload["tool_choice"] = forced
                else:
                    # This model cannot be compelled by the parameter, so the
                    # constraint moves to the only place the provider does
                    # honour: what it can see.  "Call anything you like" over
                    # a palette of exactly one function still means "call
                    # this function", which is the control the runtime chose.
                    # Only THIS body is narrowed; the bound palette object is
                    # replaced, never mutated, so the next request is offered
                    # everything again.  Record it every time rather than
                    # once: otherwise a tool the runtime meant to compel
                    # simply never appears in the run's record.
                    payload["tool_choice"] = "auto"
                    payload["tools"] = [visible[specific]]
                    self._record_tool_choice_degradation(forced, restricted_to=specific)
                self._next_specific_tool_choice = None
            else:
                payload["tool_choice"] = (
                    self._first_investigation_tool_choice
                    if self._active_request_role == "investigation"
                    and self._investigation_request_count == 0
                    and self._accepts_constrained_tool_choice
                    else "auto"
                )
        self._restore_provider_reasoning(input_, payload)
        # What THIS dispatch asked of the model, so a refusal can be attributed
        # to the constraint that was actually sent instead of guessed at.  The
        # named function is kept beside it because only a name can be restricted
        # to; "required" names nothing and has nothing to narrow the palette to.
        self._dispatched_tool_choice = payload.get("tool_choice")
        self._dispatched_specific_tool = forced_specific
        self._dispatched_response_format = constrained_format
        if self._active_request_role == "investigation":
            self._investigation_request_count += 1
        if self._request_payload_ledger is not None:
            run_id = self._request_run_id.get()
            if run_id is None:
                raise RuntimeError("attested model request lacks a callback run ID")
            self._request_payload_ledger.capture(
                run_id,
                payload,
                dispatch=permit.record() if permit is not None else None,
            )
        return payload

    def _restore_provider_reasoning(self, input_: Any, payload: dict[str, Any]) -> None:
        """Put each assistant message's own reasoning back on the way out.

        ``langchain-openai`` normalizes the OpenAI-compatible message and keeps
        neither ``reasoning`` nor ``reasoning_details``, so an exchange that was
        interrupted by a tool call would resume with the model's own chain of
        thought missing.  The blocks are written back onto the same assistant
        message they were returned on, in the same order, because OpenRouter
        requires the sequence of consecutive reasoning blocks to match what the
        model produced.  Only the Chat Completions body has ``messages``; any
        other shape is left alone.
        """

        messages = payload.get("messages")
        if not isinstance(messages, list):
            return
        source = self._convert_input(input_).to_messages()
        if len(source) != len(messages):  # pragma: no cover - super() maps one to one
            return
        for original, converted in zip(source, messages, strict=True):
            if not isinstance(converted, dict) or converted.get("role") != "assistant":
                continue
            converted.update(_provider_reasoning(original))

    def _carry_provider_reasoning(self, response_record: Mapping[str, Any], result: Any) -> None:
        """Keep the reasoning the provider returned beside the tool call it explains.

        The blocks ride on the assistant message itself rather than on a side
        channel, so anything that already carries that message through the graph
        carries them too and nothing has to re-associate them later.
        """

        choices = response_record.get("choices")
        if not isinstance(choices, list):
            return
        for generation, choice in zip(result.generations, choices, strict=False):
            message = choice.get("message") if isinstance(choice, Mapping) else None
            if not isinstance(message, Mapping):
                continue
            carried = _provider_reasoning(message)
            if not carried:
                continue
            additional = getattr(getattr(generation, "message", None), "additional_kwargs", None)
            if isinstance(additional, dict):
                additional.update(carried)

    def _model_request_recorder(self) -> Any:
        """Return the run's chain when it accepts model-request entries.

        The recorder is duck-typed at this seam, exactly as the output guard
        treats it, so a stand-in bound by a caller that predates this entry is
        left alone instead of failing the request it was recording.
        """

        record = getattr(self._oversight_recorder, "record_model_request", None)
        return record if callable(record) else None

    def _record_model_request(self, response_record: Mapping[str, Any]) -> None:
        """Put one line about this answered request on the run's oversight chain.

        The transport is the only place that sees the provider's own response
        body, and therefore the only place that can state whether reasoning came
        back and what the request consumed.  Reasoning counts as returned when
        the provider sent the same blocks the transport already carries back to
        it, so the record and the continuity mechanism cannot disagree about
        whether the model reasoned.  The blocks go no further than this method:
        what travels on is that they existed, and the numbers.
        """

        record = self._model_request_recorder()
        if record is None:
            return
        choices = response_record.get("choices")
        answered = (
            [choice for choice in choices if isinstance(choice, Mapping)]
            if isinstance(choices, list)
            else []
        )
        finish_reason = next(
            (
                choice["finish_reason"]
                for choice in answered
                if isinstance(choice.get("finish_reason"), str)
            ),
            None,
        )
        record(
            role=self._active_request_role,
            status="success",
            finish_reason=finish_reason,
            reasoning_returned=any(
                bool(_provider_reasoning(choice.get("message"))) for choice in answered
            ),
            token_usage=_numeric_token_usage(response_record.get("usage")),
        )

    def _record_failed_model_request(self, error: BaseException) -> None:
        """Record a request that spent its attempt and returned no response.

        A dispatch the provider refused is still a request this run made.  Left
        out, the record would show fewer requests than the run attempted and no
        reason for the difference.

        A frozen ceiling rejecting the work is the one failure that is NOT such a
        request: nothing left this process, so it is a budget metric and appears
        as one.  Recording it here would put a request in the chain that the
        provider was never asked to serve.
        """

        record = self._model_request_recorder()
        if record is None or isinstance(error, _DispatchDenied):
            return
        record(
            role=self._active_request_role,
            status="error",
            error_type=type(error).__name__,
        )

    def _declare_local_tool_choice_incapability(self) -> None:
        """Ollama's OpenAI-compatible endpoint drops ``tool_choice`` silently.

        The degradation detector below recognizes a 400 whose text names the
        refused parameter; a backend that drops unknown fields without one can
        never trigger it, so a local run would ATTEST a compulsion the
        provider never saw.  Declared up front instead: forced calls take the
        structural form the local backend does honour — a palette of exactly
        one function under ``tool_choice: auto`` — and the record carries the
        degradation rather than a dead parameter.
        """

        if not self._accepts_constrained_tool_choice:
            return
        from forensic_agent.core.config import is_local

        base = str(
            getattr(self, "openai_api_base", None)
            or getattr(self, "base_url", None)
            or ""
        )
        if base and is_local(base):
            self._accepts_constrained_tool_choice = False

    def _accept_tool_choice_refusal(self, error: BaseException) -> bool:
        """Treat an explicit refusal of a forced tool call as a model capability.

        A reasoning model that cannot be compelled to call a tool is a property
        of the model being routed to, not a fact about the evidence and not a
        failed investigation, so the run records the limitation and keeps going.
        The capability is remembered here, which is also what makes the retry
        happen at most once: nothing sends that constraint again.  Every other
        provider error returns ``False`` and surfaces unchanged.
        """

        if not self._accepts_constrained_tool_choice:
            return False
        refused = self._dispatched_tool_choice
        if not _is_constrained_tool_choice(refused):
            return False
        if not _refuses_constrained_tool_choice(error):
            return False
        self._accepts_constrained_tool_choice = False
        restricted_to = self._dispatched_specific_tool
        if restricted_to is not None:
            # The pending choice was consumed building the body that was just
            # refused.  Arming it again is what lets the retry rebuild the SAME
            # request the runtime asked for, which now expresses "call exactly
            # this function" through a palette of one instead of the parameter.
            # The retry consumes it immediately, so nothing stays armed.
            self._next_specific_tool_choice = restricted_to
        self._record_tool_choice_degradation(refused, restricted_to=restricted_to, error=error)
        return True

    def _accept_response_format_refusal(self, error: BaseException) -> bool:
        """Treat a refused decoding constraint as a property of the endpoint.

        Some routes, and a local Ollama backend, cannot hold a reply to a schema.
        That is a fact about where the request went, not about the evidence, so
        the run drops the constraint, records that it did, and asks again without
        it — which is exactly the request this phase issued before the constraint
        existed.  A model that then answers in prose still fails closed at
        assembly, because nothing about what may be published has changed.
        """

        constraint = self._response_format_constraint
        if constraint is None or self._dispatched_response_format is None:
            return False
        if constraint.refused or not _refuses_constrained_response_format(error):
            return False
        constraint.refused = True
        self._record_response_format_degradation(self._dispatched_response_format, error=error)
        return True

    def _accept_provider_refusal(self, error: BaseException) -> bool:
        """Whether a refused request CONTROL may be dropped and the body resent.

        Both controls degrade the same way, and one rejection can only be about
        one of them, so they are asked in turn and the first that recognises the
        provider's wording owns it.  Every other error returns ``False`` and
        surfaces unchanged.
        """

        return self._accept_tool_choice_refusal(error) or self._accept_response_format_refusal(
            error
        )

    def _accept_provider_swap(self, error: BaseException) -> bool:
        """Whether a rejection that followed a re-route may be sent again.

        OpenRouter answers an unavailable endpoint by moving the request to
        another one, and the second endpoint need not accept the body the first
        would have.  Then the rejection is about WHERE the request went, not
        about what it says, and the run has been ended by a routing collision
        rather than by anything the investigation did.

        What the two endpoints disagree about is not established here, and is
        deliberately not guessed at: the router reports the upstream body
        verbatim, and a provider that answers "invalid request params" has named
        no parameter.  So nothing is dropped from the body — dropping a control
        nobody named would silently change the request the run made.  The same
        body is offered to the router once more, and the record says so.

        The gate is :attr:`ProviderFailure.rejected_after_provider_swap`, which
        is built from status codes rather than wording: a genuine bad request is
        rejected by the first provider the router tries, and never reaches this
        path at all.
        """

        failure = describe_provider_failure(error)
        if failure is None or not failure.rejected_after_provider_swap:
            return False
        if self._provider_swap_resends >= PROVIDER_SWAP_MAX_RESENDS:
            # The bound is reached, and reaching it is itself a fact: the run
            # ends on the provider's own rejection, with a record that shows a
            # resend was already spent on it.
            self._record_provider_swap(failure, decision="resend_budget_exhausted")
            return False
        self._provider_swap_resends += 1
        self._rearm_refused_request()
        self._record_provider_swap(failure, decision="resent_same_body")
        return True

    def _rearm_refused_request(self) -> None:
        """Put back the per-request state that building the refused body spent.

        A resend must be the request the runtime asked for, not the request that
        would have come after it.  Building the refused body consumed any
        pending specific tool choice and advanced the position of the next
        investigation request, so a resend left alone would quietly drop a
        forced first turn.  The tool-choice degradation path re-arms the same
        way, and for the same reason; the counter is a position marker, not a
        count of dispatches, and the ledger is what counts dispatches.
        """

        if self._dispatched_specific_tool is not None:
            self._next_specific_tool_choice = self._dispatched_specific_tool
        if self._active_request_role == "investigation" and self._investigation_request_count:
            self._investigation_request_count -= 1

    def _record_provider_swap(self, failure: ProviderFailure, *, decision: str) -> None:
        """Report a request the router moved through the seams the run has.

        The rejected body really went out, so its receipt is retired beside the
        reason exactly as a refused control's is, and the resend attests the
        body that reached the second provider.  Both receipts are identical by
        digest, which is the point: the record shows one body dispatched twice
        rather than one dispatch standing for two.
        """

        swapped_from = failure.swapped_from
        run_id = self._request_run_id.get()
        record: dict[str, object] = {
            "schema_id": PROVIDER_SWAP_SCHEMA_ID,
            "decision": decision,
            "request_role": self._active_request_role,
            "rejecting_provider": failure.provider_name,
            "rejecting_status_code": failure.status_code,
            "rejecting_message": failure.message or None,
            "upstream_detail": failure.upstream_detail,
            "swapped_from_provider": swapped_from.provider_name if swapped_from else None,
            "swapped_from_status_code": swapped_from.status_code if swapped_from else None,
            "resends_spent": self._provider_swap_resends,
            "max_resends": PROVIDER_SWAP_MAX_RESENDS,
        }
        ledger = self._request_payload_ledger
        if decision == "resent_same_body" and ledger is not None and run_id:
            ledger.refuse(run_id, record)
        recorder = self._oversight_recorder
        if recorder is not None:
            recorder.record_security(
                PROVIDER_SWAP_EVENT,
                {**record, "callback_run_id": run_id},
            )

    def _record_response_format_degradation(
        self,
        withheld: object,
        *,
        error: BaseException,
    ) -> None:
        """Report a dropped decoding constraint through the seams the run has.

        The provider has just rejected the constraint and the request is
        dispatched again without it, so the ledger keeps the rejected receipt
        beside its reason and the chain carries the decision.  There is no
        second, remembered form of this: the constraint is armed around one
        request, so a refusal ends it rather than weakening later ones.
        """

        run_id = self._request_run_id.get()
        record: dict[str, object] = {
            "schema_id": RESPONSE_FORMAT_DEGRADATION_SCHEMA_ID,
            "request_role": self._active_request_role,
            "withheld_response_format": copy.deepcopy(withheld),
            "retried_after_refusal": True,
            "provider_status_code": getattr(error, "status_code", None),
            "provider_message": str(getattr(error, "message", "") or "")[:500],
        }
        ledger = self._request_payload_ledger
        if ledger is not None and run_id:
            ledger.refuse(run_id, record)
        recorder = self._oversight_recorder
        if recorder is not None:
            recorder.record_security(
                RESPONSE_FORMAT_DEGRADATION_EVENT,
                {**record, "callback_run_id": run_id},
            )

    def _record_tool_choice_degradation(
        self,
        withheld: object,
        *,
        restricted_to: str | None = None,
        error: BaseException | None = None,
    ) -> None:
        """Report a weakened control through the seams the run already has.

        Two different facts share this record.  With ``error`` the provider has
        just rejected the constraint and the request is dispatched again without
        it, so the ledger keeps the rejected receipt beside its reason.  Without
        one, a later request is dropping a constraint because that rejection is
        remembered; only the chain carries it, because the payload really sent is
        already attested and nothing was refused.

        ``restricted_to`` names the function the palette was narrowed to for that
        one body, so the record shows how much of the original constraint
        survived.  ``None`` means none of it could: "required" names no single
        function, so it degrades to a free choice over everything.
        """

        run_id = self._request_run_id.get()
        record: dict[str, object] = {
            "schema_id": TOOL_CHOICE_DEGRADATION_SCHEMA_ID,
            "request_role": self._active_request_role,
            "withheld_tool_choice": copy.deepcopy(withheld),
            "sent_tool_choice": "auto",
            "palette_restricted_to": restricted_to,
            "retried_after_refusal": error is not None,
            "provider_status_code": getattr(error, "status_code", None),
            "provider_message": (
                str(getattr(error, "message", "") or "")[:500] if error is not None else None
            ),
        }
        ledger = self._request_payload_ledger
        if error is not None and ledger is not None and run_id:
            ledger.refuse(run_id, record)
        recorder = self._oversight_recorder
        if recorder is not None:
            # ``record_security`` is this chain's general control-fact seam; the
            # realized-surface lock mismatch already reports through it.
            recorder.record_security(
                TOOL_CHOICE_DEGRADATION_EVENT,
                {**record, "callback_run_id": run_id},
            )

    def _dispatch_again_after(self, error: BaseException) -> bool:
        """Whether this failed dispatch may be attempted again, and record why.

        Two recoveries share the seam, both bounded and both leaving a record: a
        CONTROL the provider named is dropped and the body resent without it,
        and a body rejected only after the router moved it off an unavailable
        endpoint is resent unchanged.  Each can fire at most once per request —
        a dropped control is remembered, a spent resend is counted — so the
        caller's loop always terminates.  Every other error returns ``False``
        and surfaces exactly as it does today.
        """

        self._record_failed_model_request(error)
        return self._accept_provider_refusal(error) or self._accept_provider_swap(error)

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        run_id = str(getattr(run_manager, "run_id", "")) if run_manager is not None else None
        token = self._request_run_id.set(run_id)
        self._provider_swap_resends = 0
        try:
            while True:
                try:
                    return super()._generate(
                        messages,
                        stop=stop,
                        run_manager=run_manager,
                        **kwargs,
                    )
                except Exception as error:
                    if not self._dispatch_again_after(error):
                        raise
                # After a dropped control the bound palette is still there and
                # still visible; only the compulsion is gone.  If the model now
                # declines to call a tool, that is the model's own behaviour and
                # this response says so.  After a provider swap the body is not
                # changed at all: only its route is asked to be.
        finally:
            self._request_run_id.reset(token)

    async def _agenerate(self, messages, stop=None, run_manager=None, **kwargs):
        run_id = str(getattr(run_manager, "run_id", "")) if run_manager is not None else None
        token = self._request_run_id.set(run_id)
        self._provider_swap_resends = 0
        try:
            while True:
                try:
                    return await super()._agenerate(
                        messages,
                        stop=stop,
                        run_manager=run_manager,
                        **kwargs,
                    )
                except Exception as error:
                    if not self._dispatch_again_after(error):
                        raise
        finally:
            self._request_run_id.reset(token)

    def _create_chat_result(self, response, generation_info=None):
        result = super()._create_chat_result(response, generation_info)
        if isinstance(response, Mapping):
            response_record = response
        elif hasattr(response, "model_dump"):
            response_record = response.model_dump()
        else:
            response_record = {}
        self._carry_provider_reasoning(response_record, result)
        self._record_model_request(response_record)
        provider = response_record.get("provider")
        router_metadata = response_record.get("openrouter_metadata")
        if provider not in (None, "") or isinstance(router_metadata, Mapping):
            llm_output = dict(result.llm_output or {})
            llm_output["openrouter_response"] = {
                "provider": provider,
                "router_metadata": (
                    dict(router_metadata) if isinstance(router_metadata, Mapping) else None
                ),
            }
            result.llm_output = llm_output
        return result
