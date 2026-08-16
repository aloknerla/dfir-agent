from __future__ import annotations

import pytest

from forensic_agent.agent.orchestration import preparation
from forensic_agent.agent.orchestration.runner import (
    InvestigationDependencies,
    _execute_investigation,
)
from forensic_agent.cli.controlled import ControlledInvestigationSession


class _BudgetCaptured(Exception):
    pass


@pytest.mark.parametrize(
    ("recover_incomplete_run", "verify", "reserved", "maximum"),
    [
        (False, False, 0, 20),
        (True, False, 2, 22),
        (False, True, 2, 22),
        (True, True, 4, 24),
    ],
)
def test_implicit_model_budget_reserves_two_recovery_and_two_verifier_requests(
    monkeypatch: pytest.MonkeyPatch,
    recover_incomplete_run: bool,
    verify: bool,
    reserved: int,
    maximum: int,
) -> None:
    captured: dict[str, object] = {}

    class CapturingBudget:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)
            raise _BudgetCaptured

    def unused(*args: object, **kwargs: object) -> object:
        return object()

    monkeypatch.setattr(preparation, "_CellExecutionBudget", CapturingBudget)
    dependencies = InvestigationDependencies(
        chat_openai=unused,
        create_agent_runtime=unused,
        prepare_model_surface=unused,
    )

    with pytest.raises(_BudgetCaptured):
        _execute_investigation(
            None,
            "question",
            max_steps=20,
            verify=verify,
            recover_incomplete_run=recover_incomplete_run,
            request_timeout_s=60.0,
            dependencies=dependencies,
        )

    assert captured["reserved_terminal_model_requests"] == reserved
    assert captured["max_model_requests"] == maximum


def test_controlled_session_default_budget_covers_full_terminal_reserve(tmp_path) -> None:
    session = ControlledInvestigationSession(
        model="local-model",
        base_url="http://127.0.0.1:11434/v1",
        api_key=None,
        output_root=tmp_path,
    )

    assert session.max_steps == 20
    assert session.max_model_requests == 24
