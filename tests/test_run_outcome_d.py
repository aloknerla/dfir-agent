"""A run that published nothing, and a fault in this program, are two things.

Both used to arrive under one word:

    agent error: _prepare_model_surface() got an unexpected keyword 'scope_triage'
    agent error: The agent did not produce a final finding (reason: budget_exhausted:...)

The first is this software breaking. The second is not an error in any sense the
operator cares about: the tools ran, the run record closed, the oversight
decisions were written, and the model spent its wall-time budget without stating
a conclusion. That is a RESULT, and for anyone comparing two models it is one of
the results being compared. Recording them under one name makes the comparison
unwritable.

The separation already existed in the code and was thrown away at the last step:
``IncompleteExaminationError`` is a distinct exception, ``ask`` catches it
separately and renders it properly, and then handed the exception to the generic
fault renderer whose fallback prints ``agent error:`` and the raw message.

Every situation here is constructed rather than asserted at. The unanswered run
is a real ``IncompleteExaminationError`` carrying real telemetry, raised from
the runner the session actually calls; the fault is a real ``TypeError`` from
the same place. The exit codes are taken from ``main`` itself.
"""

from __future__ import annotations

import io
from pathlib import Path
from types import SimpleNamespace

import pytest
from rich.console import Console

from forensic_agent.cli import app as _app
from forensic_agent.cli.controlled import ControlledRun, IncompleteExaminationError
from forensic_agent.cli.session import InteractiveSession


def _args(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        model="openai/gpt-oss-120b",
        base_url="https://openrouter.ai/api/v1",
        api_key="test-key",
        memory=None,
        pcap=None,
        max_steps=10,
        image=None,
        case=None,
        run_dir=str(tmp_path / "runs"),
        resume=None,
        continue_session=False,
    )


def _telemetry(finish_reason: str, *, bound: str | None, cause: str) -> dict:
    """The control telemetry a run of this shape actually records."""

    return {
        "finish_reason": finish_reason,
        "unpublished_answer_metrics": {
            "cause": cause,
            "examination_bound": bound,
            "evidence_readings": 4,
            "model_draft_present": False,
            "blocked_gates": [],
        },
    }


def _unanswered_run(tmp_path: Path, telemetry: dict) -> ControlledRun:
    run_dir = tmp_path / "runs" / "f34d13c7"
    run_dir.mkdir(parents=True, exist_ok=True)
    return ControlledRun(
        # Empty and it stays empty: this run published no conclusion.
        report="",
        run_id="f34d13c7",
        audit_path=run_dir / "audit.jsonl",
        oversight_path=run_dir / "oversight.jsonl",
        tool_result_trace_path=run_dir / "results.jsonl",
        visible_tools=(),
        telemetry=telemetry,
    )


def _asking_session(tmp_path: Path, monkeypatch, raiser):
    """A session whose one question runs ``raiser`` where the runner would be.

    The evidence check and the scope triage are the two things standing between
    ``ask`` and the runner, and neither is what these tests are about: one wants
    a real disk image, the other a live model. Everything after the runner is
    the code under test and is untouched.
    """

    console = Console(
        file=io.StringIO(), width=100, force_terminal=False, highlight=False
    )
    session = InteractiveSession(_args(tmp_path), console=console)
    monkeypatch.setattr(type(session), "has_evidence", lambda self: True)
    monkeypatch.setattr(
        "forensic_agent.cli.scope_check.question_in_scope",
        lambda *a, **k: True,
    )
    monkeypatch.setattr(
        type(session),
        "_case_evidence_binding",
        lambda self: (None, None),
    )
    monkeypatch.setattr(
        type(session),
        "_controlled_runner",
        lambda self: SimpleNamespace(provider="test", ask=raiser),
    )
    return session, console


_BOX = "".join(chr(code) for code in range(0x2500, 0x2580))


def _rendered(text_or_console) -> str:
    """The characters a person would read, with the panel frames taken out.

    A panel border sits between the words on every line it wraps, so a plain
    join glues a box-drawing character into the middle of the sentence being
    checked. Dropping the frame leaves exactly what the operator reads.
    """

    raw = (
        text_or_console.file.getvalue()
        if isinstance(text_or_console, Console)
        else text_or_console
    )
    stripped = "".join(" " if character in _BOX else character for character in raw)
    return " ".join(stripped.split())


# ---------------------------------------------------------------------------
# the run that published nothing
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("finish_reason", "bound", "cause", "expected_phrase"),
    [
        (
            "budget_exhausted:max_wall_time_s",
            "max_wall_time_s",
            "model_returned_no_draft",
            "It ran out of the time budget for one message",
        ),
        (
            "no_final_answer",
            None,
            "model_returned_no_draft",
            "The model stated no conclusion, so there was none to publish.",
        ),
    ],
)
def test_an_unanswered_run_is_reported_as_an_outcome_not_as_a_fault(
    tmp_path, monkeypatch, finish_reason, bound, cause, expected_phrase
):
    """Neither wording may contain the words reserved for a broken program."""

    record = _unanswered_run(tmp_path, _telemetry(finish_reason, bound=bound, cause=cause))

    def raiser(*_args, **_kwargs):
        raise IncompleteExaminationError(
            "The agent did not produce a final finding "
            f"(reason: {finish_reason}; cause: {cause}; run: f34d13c7; "
            "diagnostics: failure.json).",
            record=record,
        )

    session, console = _asking_session(tmp_path, monkeypatch, raiser)
    try:
        answered = session.ask("who plugged in the USB device?")
    finally:
        session.close()
    text = _rendered(console)

    assert answered is False
    assert session.last_ask_outcome == InteractiveSession.ASK_UNPUBLISHED
    # The words reserved for a defect in this program are absent, and so is the
    # raw exception string they used to trail.
    assert "agent error" not in text
    assert "did not produce a final finding" not in text
    # The outcome says what it is, in plain language.
    assert "The run finished without a publishable finding." in text
    assert "not a fault in this program" in text
    assert expected_phrase in text
    # A code is never the whole account of what happened.
    assert finish_reason not in text
    # And what makes it checkable afterwards is still there.
    assert "f34d13c7" in text
    assert "failure.json" in text


def test_the_ceiling_is_named_in_words_rather_than_as_a_field(tmp_path):
    """``max_wall_time_s`` on an operator's screen reads as a broken program."""

    from forensic_agent.agent.execution_budget import BUDGET_EXHAUSTION_REASONS
    from forensic_agent.cli.presentation import (
        _EXAMINATION_BOUND_PHRASE,
        examination_bound_phrase,
        summarize_incomplete_examination,
    )

    # The vocabulary is the budget's own; a ceiling it can raise with and this
    # console has no words for would reach the screen as a field name again.
    assert set(_EXAMINATION_BOUND_PHRASE) == set(BUDGET_EXHAUSTION_REASONS)
    # An unknown one is still shown, under the name it was recorded with.
    assert examination_bound_phrase("something_new") == "something_new"

    statement = summarize_incomplete_examination(
        _telemetry(
            "budget_exhausted:max_wall_time_s",
            bound="max_wall_time_s",
            cause="model_returned_no_draft",
        )
    ).statement
    assert "the time budget for one message" in statement
    assert "max_wall_time_s" not in statement
    del tmp_path


# ---------------------------------------------------------------------------
# the fault in this program
# ---------------------------------------------------------------------------
def test_a_real_software_fault_still_reads_as_one(tmp_path, monkeypatch):
    """The wording reserved for a defect is still spent on a defect."""

    def raiser(*_args, **_kwargs):
        raise TypeError(
            "_prepare_model_surface() got an unexpected keyword argument "
            "'scope_triage'"
        )

    session, console = _asking_session(tmp_path, monkeypatch, raiser)
    try:
        answered = session.ask("who plugged in the USB device?")
    finally:
        session.close()
    text = _rendered(console)

    assert answered is False
    assert session.last_ask_outcome == InteractiveSession.ASK_FAILED
    assert "agent error" in text
    assert "scope_triage" in text
    # And it is not dressed as an investigation outcome.
    assert "outcome of the investigation" not in text


# ---------------------------------------------------------------------------
# the exit codes a measurement harness reads
# ---------------------------------------------------------------------------
def _ask_exit_code(monkeypatch, tmp_path, *, outcome: str) -> int:
    """Run ``main`` down the ask path with a session that ends this way."""

    class _StubSession:
        ASK_UNPUBLISHED = InteractiveSession.ASK_UNPUBLISHED

        def __init__(self, _args_namespace):
            self.last_ask_outcome = ""

        def ask(self, _question):
            self.last_ask_outcome = outcome
            return outcome == InteractiveSession.ASK_ANSWERED

        def close(self):
            return None

    monkeypatch.setattr(_app, "Session", _StubSession)
    # The ask path is reached only by a console that believes it has a provider;
    # these tests are about what happens after the question, not about setup.
    monkeypatch.setattr(_app, "configuration_ready", lambda *a, **k: True)
    monkeypatch.setattr(
        "sys.argv",
        [
            "dfir-agent",
            "ask",
            "--question",
            "who plugged in the USB device?",
            "--run-dir",
            str(tmp_path / "runs"),
        ],
    )
    try:
        _app.main()
    except SystemExit as exit_request:
        code = exit_request.code
        return int(code) if isinstance(code, int) else 0
    return 0


def test_a_clean_run_that_published_nothing_exits_apart_from_a_crash(
    tmp_path, monkeypatch
):
    """rc 1 for both made the distinction unrecordable by any harness.

    The measurement this exists for asks how often a model answers. A script
    reading only the exit status could not previously tell "the model spent its
    budget" from "the console crashed", so the number it produced counted both.
    """

    unpublished = _ask_exit_code(
        monkeypatch, tmp_path, outcome=InteractiveSession.ASK_UNPUBLISHED
    )
    crashed = _ask_exit_code(
        monkeypatch, tmp_path, outcome=InteractiveSession.ASK_FAILED
    )
    answered = _ask_exit_code(
        monkeypatch, tmp_path, outcome=InteractiveSession.ASK_ANSWERED
    )

    assert unpublished == _app.UNPUBLISHED_ANSWER_EXIT_CODE == 79
    assert crashed == 1
    assert answered == 0
    # The two codes the launcher reads are untouched by this.
    assert _app.SESSION_STARTUP_FAILURE_EXIT_CODE == 78
    assert unpublished != _app.SESSION_STARTUP_FAILURE_EXIT_CODE


# ---------------------------------------------------------------------------
# the full-screen console
# ---------------------------------------------------------------------------
def test_the_console_shows_the_outcome_and_never_a_python_repr(tmp_path, monkeypatch):
    """Read back off the compositor, because that is where the defect was seen."""

    import asyncio

    pytest.importorskip("textual")
    from forensic_agent.tui import build_app
    from forensic_agent.tui.controller import LiveController

    record = _unanswered_run(
        tmp_path,
        _telemetry(
            "budget_exhausted:max_wall_time_s",
            bound="max_wall_time_s",
            cause="model_returned_no_draft",
        ),
    )

    def raiser(*_args, **_kwargs):
        raise IncompleteExaminationError(
            "The agent did not produce a final finding "
            "(reason: budget_exhausted:max_wall_time_s; run: f34d13c7).",
            record=record,
        )

    session, _console = _asking_session(tmp_path, monkeypatch, raiser)
    app = build_app(LiveController(session))

    async def scenario():
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.1)
            app._ask("who plugged in the USB device?")
            for _ in range(300):
                await pilot.pause(0.02)
                rendered = "\n".join(
                    strip.text for strip in app.screen._compositor.render_strips()
                )
                if "publishable finding" in rendered or "agent error" in rendered:
                    return rendered
            return "\n".join(
                strip.text for strip in app.screen._compositor.render_strips()
            )

    try:
        screen = asyncio.run(scenario())
    finally:
        session.close()
    flattened = _rendered(screen)

    assert "agent error" not in flattened
    # Not a Python repr of an exception object either.
    assert "IncompleteExaminationError(" not in flattened
    assert "not a fault in this program" in flattened
    assert "the time budget for one message" in flattened
