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


def test_the_consoles_default_clock_is_the_runners_own_default(tmp_path) -> None:
    """One number, in two places that cannot see each other, pinned here.

    ``/budget time`` needs a default to show and to fall back to when nothing
    is saved, and the console cannot read it off
    :class:`ControlledInvestigationSession` — that class is imported lazily,
    per question, from a module the console must not pull in at import time.
    So ``cli.budget.DEFAULT_MAX_WALL_TIME_S`` restates it, and this asserts the
    restatement is still true. A console that fell back to a different clock
    from the one an unconfigured run actually gets would tell the operator a
    limit that is not the limit.
    """

    from forensic_agent.cli.budget import DEFAULT_MAX_WALL_TIME_S

    session = ControlledInvestigationSession(
        model="local-model",
        base_url="http://127.0.0.1:11434/v1",
        api_key=None,
        output_root=tmp_path,
    )

    assert session.max_wall_time_s == float(DEFAULT_MAX_WALL_TIME_S)


def test_the_time_budget_reaches_the_next_question_the_way_the_others_do(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """Set, cached runner dropped, and the new clock carried into the rebuild.

    The other two budgets take effect by ``_apply_* -> self._runner = None``,
    and ``_controlled_runner()`` — read once at the start of ``ask()`` — then
    builds the next runner under whatever the session now holds. The clock
    goes down that same path rather than a second one of its own, which is
    what this pins: drop the runner, and the value arrives in the rebuild.
    """

    import types

    from forensic_agent.cli import model_request as _model_request
    from forensic_agent.cli.session import InteractiveSession

    holder = types.SimpleNamespace(
        _runner=object(),
        model="local-model",
        base_url="http://127.0.0.1:11434/v1",
        api_key=None,
        run_dir=tmp_path,
        run_root=tmp_path,
        max_steps=20,
        max_tool_calls=20,
        max_wall_time_s=900,
    )

    InteractiveSession._apply_max_wall_time_s(holder, 600)
    assert holder.max_wall_time_s == 600
    assert holder._runner is None, "a live runner would keep the old clock"

    captured: dict[str, object] = {}

    def _capture(**kwargs):
        captured.update(kwargs)
        return "runner"

    monkeypatch.setattr(_model_request, "build_controlled_runner", _capture)
    assert InteractiveSession._controlled_runner(holder) == "runner"
    assert captured["max_wall_time_s"] == 600
    # And the rebuilt runner really does run under it.
    built = ControlledInvestigationSession(
        model="local-model",
        base_url="http://127.0.0.1:11434/v1",
        api_key=None,
        output_root=tmp_path,
        max_wall_time_s=600,
    )
    assert built.max_wall_time_s == 600.0


# ---------------------------------------------------------------------------
# cancellation is not a ceiling, and must never be counted as one
# ---------------------------------------------------------------------------
def _a_cell(**overrides):
    import time as _time

    from forensic_agent.agent.execution_budget import _CellExecutionBudget

    now = _time.monotonic()
    fields = {
        "started_monotonic": now,
        "deadline_monotonic": now + 900.0,
        "max_investigation_requests": 20,
        "max_model_requests": 24,
        "max_tool_calls": 20,
    }
    fields.update(overrides)
    return _CellExecutionBudget(**fields)


def test_a_cancelled_run_is_not_recorded_as_budget_exhaustion():
    """The distinction the whole reason exists for.

    Cancellation is delivered by refusing the next dispatch, which is also how
    a spent time budget is delivered. Filing it under max_wall_time_s would be
    the obvious shortcut and would put every Ctrl+C into the bucket a later
    evaluation counts when it asks how often a model exhausts its budget.
    """

    from forensic_agent.agent.execution_budget import (
        BUDGET_EXHAUSTION_REASONS,
        CANCELLED_REASON,
        _DispatchDenied,
    )

    assert CANCELLED_REASON not in BUDGET_EXHAUSTION_REASONS

    cell = _a_cell()
    assert cell.remaining() > 0
    cell.cancel()

    with pytest.raises(_DispatchDenied) as denial:
        cell.remaining()
    assert denial.value.reason == CANCELLED_REASON

    metrics = cell.metrics()
    assert metrics["cancelled"] is True
    # The ceiling vocabulary is untouched: no reason was reached.
    assert metrics["exhaustion_reasons"] == []
    assert metrics["deadline_exhausted"] is False


def test_cancellation_is_reported_even_in_the_last_second_of_the_budget():
    """A run cancelled as its clock runs out is cancelled, not timed out."""

    import time as _time

    from forensic_agent.agent.execution_budget import CANCELLED_REASON, _DispatchDenied

    now = _time.monotonic()
    cell = _a_cell(started_monotonic=now - 899.99, deadline_monotonic=now + 0.01)
    cell.cancel()
    with pytest.raises(_DispatchDenied) as denial:
        cell.remaining()
    assert denial.value.reason == CANCELLED_REASON
    assert cell.metrics()["exhaustion_reasons"] == []


def test_a_cancel_reaches_a_cell_started_on_another_thread():
    """The console cancels from the UI thread; the cell was built on the run's."""

    import threading

    from forensic_agent.agent.execution_budget import (
        _DispatchDenied,
        cancel_active_cells,
    )

    built: dict[str, object] = {}
    ready = threading.Event()

    def build_on_another_thread() -> None:
        built["cell"] = _a_cell()
        ready.set()

    worker = threading.Thread(target=build_on_another_thread)
    worker.start()
    assert ready.wait(timeout=10)
    worker.join(timeout=10)

    cell = built["cell"]
    assert cell.remaining() > 0  # type: ignore[union-attr]
    assert cancel_active_cells() >= 1
    with pytest.raises(_DispatchDenied):
        cell.remaining()  # type: ignore[union-attr]


def test_a_cancelled_run_does_not_finish_under_the_budget_exhausted_prefix():
    """The record's own word for it, checked where the record is written.

    The run state carries one field for "why did dispatch stop", and every
    value it can hold except this one is a ceiling, so the finish reason is
    built by prefixing it with budget_exhausted:. A cancellation travelling
    that path would be filed as budget_exhausted:cancelled, which reads as a
    budget the run exhausted to anyone grepping the prefix.
    """

    import inspect

    from forensic_agent.agent.execution_budget import CANCELLED_REASON
    from forensic_agent.agent.orchestration import finalization

    source = inspect.getsource(finalization)
    assert "CANCELLED_REASON" in source, (
        "the finish reason no longer distinguishes a cancellation"
    )
    # The prefixed form must be reachable only when the reason is NOT this one.
    assert 'f"budget_exhausted:{state.dispatch_exhaustion_reason}"' in source
    assert CANCELLED_REASON == "cancelled"
