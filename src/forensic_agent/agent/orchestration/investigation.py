"""Model-driven analysis phase for one forensic investigation."""

from __future__ import annotations

import time
from contextlib import nullcontext

from langgraph.errors import GraphRecursionError

from forensic_agent.agent.execution_budget import _DispatchDenied
from forensic_agent.agent.orchestration.state import (
    InvestigationState,
    PreparedRuntime,
)

#: Attempts at the opening request when the provider returns nothing at all.
#: Observed empty replies come back in about a second, so two back-to-back tries
#: land in the same bad instant; a third with a pause is what actually separates
#: a transient upstream failure from a provider that will not answer this call.
_MAX_INVESTIGATION_ATTEMPTS = 3

#: Seconds to wait before re-asking. Negligible against the cell's wall budget,
#: which is measured in minutes, and enough to leave the failing instant.
_INVESTIGATION_RETRY_BACKOFF_S = 2.0


def _investigation_produced_anything(messages) -> bool:
    """Return whether the pass yielded a tool call or any model text.

    A response carrying neither is not an answer and not a refusal, it is an
    empty turn. It leaves no case evidence, so every later gate fails closed and
    the run is lost with its budget almost entirely unspent.
    """

    for message in messages:
        kind = getattr(message, "type", None)
        if kind == "tool":
            return True
        if kind == "ai":
            if getattr(message, "tool_calls", None):
                return True
            content = getattr(message, "content", "")
            if isinstance(content, str) and content.strip():
                return True
            if isinstance(content, list) and content:
                return True
    return False


def run_analysis_phase(
    runtime: PreparedRuntime,
    state: InvestigationState,
) -> None:
    """Stream the first ReAct pass while preserving partial investigative state."""

    config = runtime.config
    runtime_evidence_guard = runtime.runtime_evidence_guard
    if runtime_evidence_guard is not None:
        if runtime.owns_evidence_guard:
            runtime_evidence_guard.acquire_read_lease()
            runtime_evidence_guard.check("graph_start", full_content=True)
        else:
            # The adapter already performed the expensive pre-open content
            # boundary on this same guard. A metadata checkpoint binds the
            # graph start without re-hashing a multi-gigabyte image again.
            runtime_evidence_guard.check("graph_start")

    try:
        request_role = getattr(runtime.llm, "request_role", None)
        role_scope = (
            request_role("investigation") if callable(request_role) else nullcontext()
        )
        with role_scope:
            for attempt in range(_MAX_INVESTIGATION_ATTEMPTS):
                for chunk in runtime.agent.stream(
                    {"messages": [("user", runtime.prepared.model_question)]},
                    config={
                        "recursion_limit": config.max_steps * 2 + 5,
                        "callbacks": [runtime.investigation_ledger],
                    },
                    stream_mode="values",
                ):
                    state.messages = chunk.get("messages", state.messages)
                if _investigation_produced_anything(state.messages):
                    break
                # The opening request came back empty even though tool_choice was
                # "required". Ending here would abort with the full request and
                # tool budget unspent, so ask once more. The ledger keeps counting,
                # so _DispatchDenied still bounds this.
                if attempt + 1 < _MAX_INVESTIGATION_ATTEMPTS:
                    state.investigation_restarts += 1
                    state.messages = []
                    time.sleep(_INVESTIGATION_RETRY_BACKOFF_S)
    except _DispatchDenied as exc:
        if exc.reason == "max_steps":
            # Preserve gathered evidence for the separately reserved forced-final
            # request; this boundary is independent of LangGraph recursion details.
            state.recursion_limited = True
        else:
            state.dispatch_exhaustion_reason = exc.reason
    except GraphRecursionError:
        # Keep messages accumulated so far; deterministic recovery concludes from
        # them below the compatibility coordinator.
        state.recursion_limited = True
    except Exception:
        if config.standardize_tool_results or not config.recover_incomplete_run:
            # Publication execution exhausts the frozen SDK retry budget inside
            # this same invocation. An interrupted standardized run is unscoreable.
            raise
        # LangGraph may emit the input HumanMessage before the first backend
        # request fails. That alone is not recoverable investigative progress.
        has_model_or_tool_progress = any(
            getattr(message, "type", None) in {"ai", "tool"}
            for message in state.messages
        )
        if not has_model_or_tool_progress:
            raise
        state.transient_midrun_error = True
