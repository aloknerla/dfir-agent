"""Model-request telemetry for a forensic investigation."""

from __future__ import annotations

import json
import threading
from collections.abc import Mapping
from typing import Any, cast

from langchain_core.callbacks import BaseCallbackHandler

from forensic_agent.agent.execution_budget import _CellExecutionBudget
from forensic_agent.agent.execution_dispatch import _ai_content_to_text
from forensic_agent.core.repro import canonical_json, model_messages_sha256, sha256_hex


class _ModelRequestLedger(BaseCallbackHandler):
    """Record one auditable row for every logical LangChain model request.

    OpenRouter's generation endpoint is keyed by the upstream response ID.  A mere
    request counter cannot prove which provider actually served the call, so the
    callback retains that ID together with the returned model, fingerprint, finish
    reason and token usage.  Provider metadata is resolved outside the graph by the
    controlled experiment adapter, never trusted from the request configuration.
    """

    def __init__(self, role: str, execution_budget: _CellExecutionBudget | None = None) -> None:
        self.role = role
        self._execution_budget = execution_budget
        self._rows: dict[str, dict[str, object]] = {}
        self._order: list[str] = []
        self._lock = threading.Lock()

    @property
    def count(self) -> int:
        return len(self._order)

    @property
    def entries(self) -> list[dict[str, object]]:
        with self._lock:
            return [dict(self._rows[key]) for key in self._order]

    def _start(self, run_id) -> dict[str, object]:
        key = str(run_id)
        with self._lock:
            row = self._rows.get(key)
            if row is None:
                row = {
                    "role": self.role,
                    "callback_run_id": key,
                    "status": "started",
                    "response_id": None,
                    "returned_model": None,
                    "system_fingerprint": None,
                    "finish_reason": None,
                    "token_usage": {},
                    "request_messages_sha256": None,
                }
                if self._execution_budget is not None:
                    row["request_started_elapsed_s"] = round(self._execution_budget.elapsed(), 6)
                self._rows[key] = row
                self._order.append(key)
            return row

    @staticmethod
    def _json_mapping(value) -> dict[str, object]:
        if value is None:
            return {}
        if hasattr(value, "model_dump"):
            value = value.model_dump()
        if not isinstance(value, Mapping):
            return {}
        normalized = json.loads(canonical_json(dict(value)))
        return normalized if isinstance(normalized, dict) else {}

    def on_chat_model_start(self, serialized, messages, *, run_id, **kwargs) -> None:
        del serialized, kwargs
        row = self._start(run_id)
        digest = model_messages_sha256(messages)
        with self._lock:
            previous = row.get("request_messages_sha256")
            if previous not in (None, digest):
                row["request_messages_sha256_conflict"] = True
            row["request_messages_sha256"] = digest

    def on_llm_start(self, serialized, prompts, *, run_id, **kwargs) -> None:
        del serialized, kwargs
        row = self._start(run_id)
        digest = model_messages_sha256(prompts)
        with self._lock:
            previous = row.get("request_messages_sha256")
            if previous not in (None, digest):
                row["request_messages_sha256_conflict"] = True
            row["request_messages_sha256"] = digest

    def on_llm_end(self, response, *, run_id, **kwargs) -> None:
        del kwargs
        row = self._start(run_id)
        llm_output = self._json_mapping(getattr(response, "llm_output", None))
        openrouter_response = self._json_mapping(llm_output.get("openrouter_response"))
        router_metadata = self._json_mapping(openrouter_response.get("router_metadata"))
        generation_info: dict[str, object] = {}
        message_metadata: dict[str, object] = {}
        usage_metadata: dict[str, object] = {}
        message_id = None
        response_text = ""
        generations = getattr(response, "generations", None) or []
        try:
            generation = generations[0][0]
        except (IndexError, TypeError):
            generation = None
        if generation is not None:
            generation_info = self._json_mapping(getattr(generation, "generation_info", None))
            message = getattr(generation, "message", None)
            if message is not None:
                message_id = getattr(message, "id", None)
                message_metadata = self._json_mapping(getattr(message, "response_metadata", None))
                usage_metadata = self._json_mapping(getattr(message, "usage_metadata", None))
                response_text = _ai_content_to_text(getattr(message, "content", None))
        token_usage = self._json_mapping(llm_output.get("token_usage"))
        if not token_usage:
            token_usage = usage_metadata
        update = {
            "status": "success",
            "response_id": (llm_output.get("id") or message_metadata.get("id") or message_id),
            "returned_model": (
                llm_output.get("model_name")
                or message_metadata.get("model_name")
                or message_metadata.get("model")
            ),
            "system_fingerprint": (
                llm_output.get("system_fingerprint")
                or message_metadata.get("system_fingerprint")
                or None
            ),
            "finish_reason": (
                generation_info.get("finish_reason") or message_metadata.get("finish_reason")
            ),
            "token_usage": token_usage,
            # Canonical digest of the normalized response text, so the accepted
            # answer can be bound to the actual final model response.  None when
            # the response carried no text (e.g. a tool-call-only turn).
            "response_content_sha256": sha256_hex(response_text) if response_text else None,
        }
        if openrouter_response:
            update.update(
                {
                    "response_provider": openrouter_response.get("provider"),
                    "router_metadata": router_metadata,
                }
            )
        with self._lock:
            if self._execution_budget is not None:
                started = row.get("request_started_elapsed_s")
                elapsed = self._execution_budget.elapsed()
                update["request_completed_elapsed_s"] = round(elapsed, 6)
                update["request_duration_s"] = round(
                    max(0.0, elapsed - float(cast(Any, started or 0.0))), 6
                )
            row.update(update)

    def on_llm_error(self, error, *, run_id, **kwargs) -> None:
        del kwargs
        row = self._start(run_id)
        with self._lock:
            update: dict[str, object] = {
                "status": "error",
                "error_type": type(error).__name__,
            }
            if self._execution_budget is not None:
                started = row.get("request_started_elapsed_s")
                elapsed = self._execution_budget.elapsed()
                update["request_completed_elapsed_s"] = round(elapsed, 6)
                update["request_duration_s"] = round(
                    max(0.0, elapsed - float(cast(Any, started or 0.0))), 6
                )
            row.update(update)
