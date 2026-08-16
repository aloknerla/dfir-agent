"""Transport-level bounds on what a single model dispatch may spend."""

from __future__ import annotations

from langchain_core.messages import HumanMessage

from forensic_agent.agent.execution_budget import (
    _CellExecutionBudget,
    _FrozenRequestTimeout,
)
from forensic_agent.agent.model_transport import ChatOpenAI, _RequestPayloadLedger


def _transport(*, max_retries: int) -> ChatOpenAI:
    transport = ChatOpenAI(
        model="m",
        api_key="k",
        base_url="https://openrouter.ai/api/v1",
        max_retries=max_retries,
    )
    transport._request_run_id.set("run-1")
    return transport


def _payload(transport: ChatOpenAI) -> dict:
    return transport._get_request_payload([HumanMessage("q")])


def test_fixed_ceiling_is_divided_across_the_attempts_the_sdk_may_make():
    """The frozen ceiling bounds the dispatch, not one of its attempts."""

    transport = _transport(max_retries=3)
    transport.configure_request_attestation(
        _RequestPayloadLedger(), _FrozenRequestTimeout.from_budget(600.0)
    )
    assert _payload(transport)["timeout"] == 600.0 / 4


def test_reserved_cell_time_is_divided_across_the_attempts_the_sdk_may_make():
    """The remaining cell time bounds the dispatch, not one of its attempts.

    The SDK applies ``timeout`` per attempt, so sending the whole reservation
    would let one dispatch outlast the cell it was reserved from by the retry
    count.
    """

    now = 1_000.0
    budget = _CellExecutionBudget(
        started_monotonic=now,
        deadline_monotonic=now + 900.0,
        max_investigation_requests=20,
        max_model_requests=24,
        max_tool_calls=20,
        clock=lambda: now,
    )
    transport = _transport(max_retries=3)
    transport.configure_request_attestation(
        _RequestPayloadLedger(), _FrozenRequestTimeout.from_budget(900.0), budget
    )
    payload = _payload(transport)
    assert payload["timeout"] == 900.0 / 4
    # What the whole dispatch may spend stays inside the reservation.
    assert payload["timeout"] * 4 <= budget.remaining()


def test_a_client_that_never_retries_keeps_the_whole_reservation():
    transport = _transport(max_retries=0)
    transport.configure_request_attestation(
        _RequestPayloadLedger(), _FrozenRequestTimeout.from_budget(600.0)
    )
    assert _payload(transport)["timeout"] == 600.0
