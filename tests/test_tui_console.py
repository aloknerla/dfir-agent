"""Smoke tests for the Textual investigation console (presentation layer).

These do not exercise the forensic core; they confirm the TUI composes, that the
demo controller replays a complete investigation into every pane, and that the
`dfir-agent tui` entry point is wired. The full-screen app is driven headlessly
through Textual's pilot so no real terminal is needed.
"""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("textual")

from rich.text import Text  # noqa: E402
from textual.containers import VerticalScroll  # noqa: E402
from textual.widgets import ListView, Static  # noqa: E402

from forensic_agent.cli.commands import COMMAND_REGISTRY  # noqa: E402
from forensic_agent.tui import build_app  # noqa: E402
from forensic_agent.tui import model as M  # noqa: E402
from forensic_agent.tui.app import OverlayScreen  # noqa: E402
from forensic_agent.tui.controller import DemoController  # noqa: E402
from forensic_agent.tui.model import (  # noqa: E402
    ControlCard,
    InvestigationResult,
    OversightCard,
    ToolEvent,
)


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    """Drop the demo's live-cadence delays so the suite stays fast."""

    monkeypatch.setattr("forensic_agent.tui.controller.time.sleep", lambda *_: None)


def test_demo_controller_replays_a_full_investigation():
    controller = DemoController()
    assert controller.is_demo is True
    events: list[ToolEvent] = []
    result = controller.run("who plugged in the USB device?", events.append)

    assert isinstance(result, InvestigationResult)
    # Six scripted tool calls, each emitted running -> settled.
    assert {e.sequence for e in events} == {1, 2, 3, 4, 5, 6}
    assert any(e.status == "running" for e in events)
    assert any(e.status == "refused" for e in events)  # the oversight-blocked call
    # Findings and guardrail decisions populated.
    assert len(result.findings) == 4
    assert len(result.oversight) == 6
    assert result.evidence_ids == ("EV-DISK-01",)
    # One step was blocked by the guardrails (safety) layer.
    blocked = [c for c in result.oversight if c.outcome == "refused_by_oversight"]
    assert len(blocked) == 1
    assert "network" in blocked[0].requested_caps
    # Findings carry plain, human labels for the Evidence pane.
    assert {f.display_label for f in result.findings} >= {"USB device", "setup log"}


def test_status_state_reports_budgets_and_mode():
    status = DemoController().status()
    assert status.mode == "DEMO"
    assert status.max_steps == 20
    assert status.max_tool_calls == 20
    assert status.evidence_sources  # at least one attached source


def test_console_app_conversation_and_calm_panes():
    async def scenario():
        app = build_app(DemoController())
        async with app.run_test(size=(120, 40)) as pilot:
            app.query_one("#prompt").value = "which USB device was connected?"
            await pilot.press("enter")
            for _ in range(60):
                await pilot.pause(0.02)
                if not app.running:
                    break
            assert app.running is False
            # Findings await the operator's review; the tool never files
            # evidence on its own. Accepting them lands them in the pane
            # under the exchange's group header.
            assert len(app._pending_review) == 4
            for exchange, card in list(app._pending_review):
                await app._accept_finding(exchange, card)
            app._pending_review.clear()
            await pilot.pause(0.1)
            evidence = app.query_one("#ev-1", ListView)
            assert len(evidence.children) == 4  # 4 accepted, inside group 01
            # Activity is the live tool feed on the right: one collapsible
            # group per exchange, one row per call inside it; 'a' focuses it.
            activity = app.query_one("#activity", VerticalScroll)
            assert len(app.query_one("#grp-1").children) == 6
            app.action_activity()
            await pilot.pause(0.05)
            # 'a' focuses the newest group title (so Enter folds/unfolds);
            # either way the focus must land inside the activity pane.
            assert app.focused is not None and (
                app.focused is activity or activity in app.focused.ancestors
            )
            # Selecting an evidence row opens its detail overlay on demand.
            evidence.focus()
            evidence.index = 2
            await pilot.press("enter")
            await pilot.pause(0.05)
            assert isinstance(app.screen, OverlayScreen)
            await pilot.press("escape")
            await pilot.pause(0.05)
            assert not isinstance(app.screen, OverlayScreen)

    asyncio.run(scenario())


def test_help_and_guardrails_overlays_open():
    async def scenario():
        app = build_app(DemoController())
        async with app.run_test(size=(120, 40)) as pilot:
            app.action_help()
            await pilot.pause(0.05)
            assert isinstance(app.screen, OverlayScreen)
            await pilot.press("escape")
            await pilot.pause(0.05)
            app.action_guardrails()
            await pilot.pause(0.05)
            assert isinstance(app.screen, OverlayScreen)

    asyncio.run(scenario())


def test_tui_command_is_registered_in_the_parser():
    from forensic_agent.cli.terminal import build_parser

    parser = build_parser(
        interactive_model="m",
        default_base_url="http://localhost",
        default_api_key="k",
        default_run_dir=".",
    )
    args = parser.parse_args(["tui", "--demo"])
    assert args.command == "tui"
    assert args.demo is True


# ---------------------------------------------------------------------------
# Full shell replacement: every registry command must dispatch in the console.
# ---------------------------------------------------------------------------
def test_every_registry_command_has_a_console_handler():
    """The line shell is retired; no command may fall through to a toast."""

    from forensic_agent.cli.commands import COMMAND_REGISTRY
    from forensic_agent.tui.app import InvestigationApp

    missing = [
        spec.name
        for spec in COMMAND_REGISTRY.commands
        if not hasattr(InvestigationApp, f"_cmd_{spec.name}")
    ]
    assert missing == []


def test_theme_switches_the_console_palette(tmp_path, monkeypatch):
    """/theme moves the Rich palette and the stylesheet together, and persists."""

    from forensic_agent.cli.preferences import load_console_theme
    from forensic_agent.tui import model as M

    monkeypatch.setenv("DFA_RUNS_DIR", str(tmp_path))
    before = M.active_palette_name()

    async def scenario():
        app = build_app(DemoController())
        async with app.run_test(size=(120, 40)) as pilot:
            assert app.theme == "dfir-tokyo"
            app.dispatch_command("theme", "dfir-contrast")
            await pilot.pause(0.1)
            assert M.active_palette_name() == "dfir-contrast"
            assert app.theme == "dfir-contrast"
            assert M.BACKGROUND == "#000000"
            assert load_console_theme() == "dfir-contrast"

    try:
        asyncio.run(scenario())
    finally:
        M.set_active_palette(before)


# ---------------------------------------------------------------------------
# Live-mode command surface, driven against a stub session (no real case).
# ---------------------------------------------------------------------------
class _FakeCase:
    case_id = "case-1"
    source_identity = "src-1"


class _FakeStore:
    def __init__(self, rows):
        self.rows = rows

    def list_sessions(self, case_id=None, source_identity=None):
        return list(self.rows)


class _FakeConversation:
    def __init__(self):
        self.case_context = "the workstation of employee X"


class _FakeHistory:
    def __init__(self, console, rows):
        self._console = console
        self._store = _FakeStore(rows)
        self.active_session_id = None
        self.conversation = _FakeConversation()
        self.shown: list[object] = []

    def show_completed_questions(self, limit=None, *, console=None):
        # The read-only views take a console of their own so they can be
        # opened while a message is being investigated.
        self.shown.append(limit)
        (console or self._console).print("HISTORY")

    def _case(self):
        return _FakeCase()

    def ensure_started(self):
        return self.conversation

    def question_to_retry(self):
        return "who logged in last?"


class _FakeSession:
    def __init__(self):
        import io

        from rich.console import Console

        self._console = Console(file=io.StringIO(), width=100)
        rows = [
            {
                "session_id": "aaaa111122223333",
                "retained_turns": 3,
                "context_turns": 3,
                "updated_at": "2026-08-14 10:00",
                "inference_identity": {"model": "test-model"},
            },
            {
                "session_id": "bbbb111122223333",
                "retained_turns": 1,
                "context_turns": 1,
                "updated_at": "2026-08-13 09:00",
                "inference_identity": {"model": "test-model"},
            },
        ]
        self._history = _FakeHistory(self._console, rows)
        self.model = "test-model"
        self.base_url = "https://openrouter.ai/api/v1"
        self.api_key = "k"
        self.max_steps = 20
        self.max_tool_calls = 20
        self.steps_changed: list[str] = []
        self.reasoning_changed: list[str] = []
        self.resumed: list[str] = []
        self.context_set: list[str] = []
        self.last_run = object()
        self.last_report = "report"
        self.last_q = "who logged in last?"
        self.completed: list = []
        self.exported: list = []
        self.traced: list = []
        self.new_histories: list = []
        self.cleared = 0

    def has_evidence(self):
        return True

    def complete_case(self, path=None):
        self.completed.append(path)
        self._console.print("Case marked complete")
        return True  # the engine's contract: True = artifacts were written

    def export_report(self, path=None, **_kwargs):
        self.exported.append(path)
        self._console.print("case report written")

    def export_trace(self, path=None):
        self.traced.append(path)
        self._console.print("execution trace written")

    def clear_evidence(self):
        self.cleared += 1

    def change_steps(self, argument):
        self.steps_changed.append(argument)
        self._console.print(f"Steps per message: {argument}")

    def change_reasoning(self, level):
        self.reasoning_changed.append(level)
        self._console.print(f"Reasoning effort: {level}")

    def resume_conversation(self, identifier, **_kwargs):
        self.resumed.append(identifier)
        self._console.print(f"Investigation resumed: {identifier}")

    def set_case_context(self, value):
        self.context_set.append(value)

    def new_conversation(self, name=None):
        self.new_histories.append(name)
        self._console.print("Investigation history started: cccc111122223333")

    def show_history(self, limit=None, *, console=None):
        self._history.show_completed_questions(limit, console=console)

    def show_sessions(self):
        # Deliberately prints through the HISTORY console, the way the real
        # InvestigationHistory does — the recording must capture it.
        self._history._console.print("SESSIONS TABLE VIA HISTORY CONSOLE")


class _FakeLiveController:
    is_demo = False

    def __init__(self):
        from forensic_agent.tui.model import StatusState

        self.session = _FakeSession()
        self._status = StatusState(
            mode="LIVE",
            model="test-model",
            provider="OpenRouter",
            case_label="case-1",
            case_id="case-1",
            evidence_sources=("disk: image.E01",),
            max_steps=20,
            max_tool_calls=20,
            max_model_requests=24,
            reasoning_effort="high",
        )

    def status(self):
        return self._status

    def has_evidence(self):
        return True

    def run(self, question, on_tool):  # pragma: no cover - not exercised here
        raise AssertionError("no live run in these tests")

    def finding_records(self, card):
        return None


def test_recording_captures_the_history_console_too():
    """sessions/history print through the history's own console reference;
    the recorder must capture that, or overlays claim 'Nothing to show.'"""

    async def scenario():
        app = build_app(_FakeLiveController())
        async with app.run_test(size=(120, 40)):
            session = app._controller.session
            with app._recording() as recorder:
                session.show_sessions()
            assert "SESSIONS TABLE VIA HISTORY CONSOLE" in recorder.export_text()
            # Both consoles restored afterwards.
            assert session._console is not recorder
            assert session._history._console is not recorder

    asyncio.run(scenario())


def test_live_command_flows_reach_the_session():
    async def scenario():
        from forensic_agent.tui.app import (
            ChoiceScreen,
            ContextScreen,
            FileBrowserScreen,
        )

        app = build_app(_FakeLiveController())
        async with app.run_test(size=(120, 40)) as pilot:
            session = app._controller.session

            # The typed limit form goes through the session's own setter
            # (runner drop + persistence live there), never a bare setattr.
            app.dispatch_command("effort", "steps 30")
            await pilot.pause(0.1)
            assert session.steps_changed == ["30"]

            # /retry re-sends the previous message through the ask pipeline.
            asked: list[str] = []
            app._ask = asked.append
            app.dispatch_command("retry", "")
            await pilot.pause(0.1)
            assert asked == ["who logged in last?"]

            # /sessions opens a picker; Enter resumes the chosen one.
            app.dispatch_command("sessions", "")
            await pilot.pause(0.2)
            assert isinstance(app.screen, ChoiceScreen)
            await pilot.press("enter")
            await pilot.pause(0.2)
            assert session.resumed == ["aaaa111122223333"]

            # Bare /context opens the brief screen showing the current text,
            # and Enter on edited text sets it.
            app.dispatch_command("context", "")
            await pilot.pause(0.2)
            assert isinstance(app.screen, ContextScreen)
            entry = app.screen.query_one("#context-entry")
            assert entry.value == "the workstation of employee X"
            entry.value = "a new brief"
            await pilot.press("enter")
            await pilot.pause(0.2)
            assert session.context_set == ["a new brief"]

            # Bare /case opens the folder browser.
            app.dispatch_command("case", "")
            await pilot.pause(0.3)
            assert isinstance(app.screen, FileBrowserScreen)
            await pilot.press("escape")
            await pilot.pause(0.1)

            # Bare /attach opens the kind chooser first.
            app.dispatch_command("attach", "")
            await pilot.pause(0.2)
            assert isinstance(app.screen, ChoiceScreen)
            await pilot.press("escape")
            await pilot.pause(0.1)

    asyncio.run(scenario())


def test_effort_screen_edits_reach_the_session():
    """Bare /effort is the one surface for all of it: Enter on a row edits it."""

    async def scenario():
        from forensic_agent.tui.app import EffortScreen, PromptScreen

        app = build_app(_FakeLiveController())
        async with app.run_test(size=(120, 40)) as pilot:
            app.dispatch_command("effort", "")
            await pilot.pause(0.2)
            assert isinstance(app.screen, EffortScreen)
            await pilot.press("enter")  # first row: steps
            await pilot.pause(0.2)
            assert isinstance(app.screen, PromptScreen)
            app.screen.query_one("#prompt-entry").value = "25"
            await pilot.press("enter")
            await pilot.pause(0.3)
            assert app._controller.session.steps_changed == ["25"]
            assert isinstance(app.screen, EffortScreen)
            await pilot.press("escape")
            await pilot.pause(0.1)

    asyncio.run(scenario())


def test_effort_takes_a_reasoning_level_directly():
    """/effort high is the merged command's other half: one name, both dials."""

    async def scenario():
        app = build_app(_FakeLiveController())
        async with app.run_test(size=(120, 40)) as pilot:
            app.dispatch_command("effort", "low")
            await pilot.pause(0.1)
            assert app._controller.session.reasoning_changed == ["low"]

    asyncio.run(scenario())


def test_complete_confirms_then_writes_everything_and_closes():
    """/complete is the one end-of-case act: confirm, write all, detach.

    /export is its own command and closes nothing."""

    from forensic_agent.cli.commands import COMMAND_REGISTRY

    assert COMMAND_REGISTRY.resolve("complete").name == "complete"
    assert COMMAND_REGISTRY.resolve("export").name == "export"

    async def scenario():
        from forensic_agent.tui.app import ChoiceScreen

        app = build_app(_FakeLiveController())
        async with app.run_test(size=(120, 40)) as pilot:
            session = app._controller.session
            app.dispatch_command("complete", "")
            await pilot.pause(0.2)
            assert isinstance(app.screen, ChoiceScreen)
            await pilot.press("enter")  # yes — complete and close the case
            for _ in range(60):
                await pilot.pause(0.05)
                if session.cleared:
                    break
            assert session.completed == [None]
            # complete_case writes the whole bundle on one stem: the case
            # report over every exchange, its oversight companion, the page a
            # browser opens, the diagram and the declaration. The console used
            # to call export_report and export_trace again afterwards, which
            # put two more files under a second stem and left the operator
            # four things that each looked like the report.
            assert session.exported == []
            assert session.traced == []
            assert session.cleared == 1

    asyncio.run(scenario())


def test_steps_alias_still_reaches_the_effort_command():
    """Typed /steps 30 keeps working, as an alias, not a command of its own."""

    from forensic_agent.cli.commands import COMMAND_REGISTRY

    assert COMMAND_REGISTRY.resolve("steps").name == "effort"
    assert COMMAND_REGISTRY.resolve("toolcalls").name == "effort"
    # The two commands this one replaced are gone, not hidden behind aliases.
    assert COMMAND_REGISTRY.resolve("budget") is None
    assert COMMAND_REGISTRY.resolve("reasoning") is None

    async def scenario():
        app = build_app(_FakeLiveController())
        async with app.run_test(size=(120, 40)) as pilot:
            app._handle_slash("/steps 30")
            await pilot.pause(0.1)
            assert app._controller.session.steps_changed == ["30"]

    asyncio.run(scenario())


def test_activity_groups_survive_past_exchange_nine():
    """Nothing may break once the exchange counter passes 09."""

    async def scenario():
        from textual.widgets import Collapsible

        app = build_app(DemoController())
        async with app.run_test(size=(120, 40)) as pilot:
            app._exchange = 10
            app._begin_run_panes()
            await pilot.pause(0.2)
            group = app.query_one("#sep-10", Collapsible)
            assert group.title == "10"
            assert app.query_one("#grp-10") is not None
            # The digit keys still target the first nine without crashing.
            app.action_jump(1)
            await pilot.pause(0.05)

    asyncio.run(scenario())


def test_overlapping_clears_do_not_duplicate_the_banner():
    """Two /clear dispatches in flight once interleaved into DuplicateIds."""

    async def scenario():
        app = build_app(DemoController())
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.2)  # the startup welcome settles first
            app.dispatch_command("clear", "")
            app.dispatch_command("clear", "")
            app.dispatch_command("clear", "all")
            await pilot.pause(0.5)
            banner = app._banner_widget
            assert banner is not None and banner.is_mounted

    asyncio.run(scenario())


def test_mutating_commands_wait_for_the_orphaned_run_thread():
    """After Ctrl+C the run thread lives on; /case and /new must wait for it."""

    async def scenario():
        app = build_app(_FakeLiveController())
        async with app.run_test(size=(120, 40)) as pilot:
            session = app._controller.session
            app._ask_thread_alive = True  # what action_interrupt leaves behind
            app.dispatch_command("new", "")
            await pilot.pause(0.1)
            assert session._console.file.getvalue() == ""  # session untouched
            app._ask_thread_alive = False
            app._case_op_alive = True  # a case operation in progress
            app.dispatch_command("new", "")
            await pilot.pause(0.1)
            assert session._console.file.getvalue() == ""

    asyncio.run(scenario())


def test_size_guard_reads_the_resize_event_not_stale_state():
    """on_resize once read self.size, which lags one event behind."""

    class _Size:
        def __init__(self, width, height):
            self.width = width
            self.height = height

    class _Event:
        def __init__(self, width, height):
            self.size = _Size(width, height)

    async def scenario():
        app = build_app(DemoController())
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.1)
            guard = app.query_one("#size-guard", Static)
            app.on_resize(_Event(90, 20))  # below the 96x28 floor
            assert str(guard.styles.display) == "block"
            app.on_resize(_Event(120, 40))
            assert str(guard.styles.display) == "none"

    asyncio.run(scenario())


def test_quit_needs_two_presses_and_ctrl_c_clears_prompt():
    async def scenario():
        app = build_app(DemoController())
        async with app.run_test(size=(120, 40)) as pilot:
            prompt = app.query_one("#prompt")
            prompt.focus()
            await pilot.pause(0.05)
            prompt.value = "half-typed"
            app.action_interrupt()  # Ctrl+C with text: clears, never quits
            assert prompt.value == ""
            app.action_quit()  # first press arms
            await pilot.pause(0.05)
            assert not app._exit
            app.action_quit()  # second press quits
            await pilot.pause(0.05)
            assert app._exit

    asyncio.run(scenario())


def test_e_and_a_show_their_thing_in_one_press():
    """g opens Guardrails in one press; e and a must match it — e opens the
    selected finding's detail, a unfolds the newest activity group."""

    async def scenario():
        from textual.widgets import Collapsible

        app = build_app(DemoController())
        async with app.run_test(size=(120, 40)) as pilot:
            prompt = app.query_one("#prompt")
            prompt.focus()
            await pilot.pause(0.05)
            prompt.value = "which USB device was connected?"
            await pilot.press("enter")
            for _ in range(60):
                await pilot.pause(0.02)
                if not app.running:
                    break
            for exchange, card in list(app._pending_review):
                await app._accept_finding(exchange, card)
            app._pending_review.clear()
            await pilot.pause(0.1)

            # e: one press opens the selected finding's detail.
            app.action_evidence()
            await pilot.pause(0.1)
            assert isinstance(app.screen, OverlayScreen)
            await pilot.press("escape")
            await pilot.pause(0.05)

            # a: one press unfolds a collapsed newest group.
            group = app.query_one("#sep-1", Collapsible)
            group.collapsed = True
            app.action_activity()
            await pilot.pause(0.1)
            assert group.collapsed is False

    asyncio.run(scenario())


def test_e_and_a_answer_even_when_empty():
    """Before any exchange, e and a must still open something — the way an
    empty Guardrails still answers — instead of silently moving focus."""

    async def scenario():
        app = build_app(DemoController())
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.2)
            app.action_evidence()
            await pilot.pause(0.1)
            assert isinstance(app.screen, OverlayScreen)
            await pilot.press("escape")
            await pilot.pause(0.05)
            app.action_activity()
            await pilot.pause(0.1)
            assert isinstance(app.screen, OverlayScreen)
            await pilot.press("escape")

    asyncio.run(scenario())


def test_host_path_handoff_exits_the_console_with_the_launcher_code():
    """In the container, /case with a host path writes a handoff request and
    must exit the WHOLE console with code 75 so the launcher can mount and
    relaunch — a thread's SystemExit ends only the thread on its own."""

    async def scenario():
        app = build_app(_FakeLiveController())

        def handoff(path):
            raise SystemExit(75)

        app._controller.session.open_case = handoff
        async with app.run_test(size=(120, 40)) as pilot:
            app.dispatch_command("case", r"D:\Cases\case-001")
            for _ in range(40):
                await pilot.pause(0.05)
                if app.return_code is not None:
                    break
        assert app.return_code == 75

    asyncio.run(scenario())


def test_session_panel_redraws_in_place_when_the_case_opens():
    """The Session panel is standing state: opening a case must update the
    ONE mounted panel — "active case  not loaded" lying above an open case
    is the bug this guards against — not print a second copy below it."""

    async def scenario():
        import dataclasses

        controller = _FakeLiveController()
        loaded = controller._status
        controller._status = dataclasses.replace(
            loaded, case_label="none", case_id="", evidence_sources=()
        )
        app = build_app(controller)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.1)
            panel = app._session_widget
            assert panel.is_mounted

            def panel_text() -> str:
                import io

                from rich.console import Console as RichConsole

                # Textual 8 wraps the Static's content in a RichVisual; the
                # Rich renderable itself sits behind ``_renderable``. The
                # StringIO sink keeps Windows' legacy console encoding out
                # of the glyph-bearing panel.
                console = RichConsole(width=100, record=True, file=io.StringIO())
                console.print(panel.render()._renderable)
                return console.export_text()

            before = panel_text()
            assert "not loaded" in before
            assert "open evidence" in before

            controller._status = loaded
            app._case_opened("")
            await pilot.pause(0.1)
            after = panel_text()
            assert "case-1" in after and "not loaded" not in after
            assert "open evidence" not in after
            assert panel is app._session_widget  # updated, not replaced

    asyncio.run(scenario())


def test_removing_accepted_evidence_takes_two_presses_of_m():
    """Accepted evidence is the case's record: the first m only arms the
    removal (a toast says so), the second m on the same row removes it."""

    async def scenario():
        from textual.widgets import ListView

        app = build_app(DemoController())
        async with app.run_test(size=(120, 40)) as pilot:
            prompt = app.query_one("#prompt")
            prompt.focus()
            await pilot.pause(0.05)
            prompt.value = "which USB device was connected?"
            await pilot.press("enter")
            for _ in range(60):
                await pilot.pause(0.02)
                if not app.running:
                    break
            for exchange, card in list(app._pending_review):
                await app._accept_finding(exchange, card)
            app._pending_review.clear()
            await pilot.pause(0.1)

            view = app.query_one(".evidence-list", ListView)
            view.focus()
            view.index = 0
            await pilot.pause(0.05)
            before = len(app._evidence_cards)
            assert before > 0
            app.action_mark()
            await pilot.pause(0.1)
            assert len(app._evidence_cards) == before  # armed, not removed
            app.action_mark()
            await pilot.pause(0.2)
            assert len(app._evidence_cards) == before - 1

    asyncio.run(scenario())


def test_a_declined_question_gives_its_number_back():
    """A run in which the model answered without touching the evidence —
    no tool calls, no findings, no oversight — must not consume a message
    number: the reply appears as an unnumbered note instead."""

    async def scenario():
        from forensic_agent.tui.model import (
            ANSWER_VERIFIED,
            ControlCard,
            InvestigationResult,
        )

        controller = _FakeLiveController()

        def declined_run(question, on_tool):
            return InvestigationResult(
                question=question,
                answer_markdown="That is not a question about this case.",
                answer_source=ANSWER_VERIFIED,
                evidence_ids=(),
                findings=(),
                oversight=(),
                controls=ControlCard(
                    verification="none",
                    answer_source=ANSWER_VERIFIED,
                    tool_calls=0,
                    findings=0,
                    model_requests=1,
                    trace_id="t-decline",
                    elapsed_s=0.1,
                ),
            )

        controller.run = declined_run
        app = build_app(controller)
        async with app.run_test(size=(120, 40)) as pilot:
            prompt = app.query_one("#prompt")
            prompt.focus()
            await pilot.pause(0.05)
            prompt.value = "write me a poem about disks"
            await pilot.press("enter")
            for _ in range(100):
                await pilot.pause(0.05)
                if not app.running:
                    break
            await pilot.pause(0.4)  # the deferred discard finishes
            assert app._exchange == 0
            assert not list(app.query("#sep-1"))
            assert not list(app.query("#q-1"))

    asyncio.run(scenario())


def test_layout_simple_inlines_activity_under_the_answer():
    """/layout simple hides the side panes and prints the run's calls
    directly beneath the answer; /layout full restores the panes and
    stops inlining. The default stays the full layout."""

    async def scenario():
        app = build_app(DemoController())
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.1)
            assert app._layout == "full"
            app.dispatch_command("layout", "simple")
            await pilot.pause(0.1)
            assert app.query_one("#rightcol").styles.display == "none"

            prompt = app.query_one("#prompt")
            prompt.focus()
            await pilot.pause(0.05)
            prompt.value = "which USB device was connected?"
            await pilot.press("enter")
            for _ in range(60):
                await pilot.pause(0.02)
                if not app.running:
                    break
            await pilot.pause(0.2)
            assert list(app.query("#inline-1")), "no inline activity block"

            app.dispatch_command("layout", "full")
            await pilot.pause(0.2)
            assert app._layout == "full"
            assert app.query_one("#rightcol").styles.display == "block"
            # The composite layout owns the ACTIVITY pane, so the inline copy
            # of the same rows must not still be sitting in the conversation.
            assert not list(app.query("#inline-1"))

    asyncio.run(scenario())


def test_inline_activity_pairs_recorder_cards_with_feed_events_by_order():
    """The recorder numbers actions 2, 7, 12… while the feed counts 1, 2,
    3…; pairing them by number made first calls vanish from the simple
    view and later ones appear twice. The nth card describes the nth
    event."""

    async def scenario():
        from forensic_agent.tui.model import (
            ANSWER_VERIFIED,
            ControlCard,
            InvestigationResult,
            OversightCard,
            ToolEvent,
        )

        def card(sequence, function, outcome="executed"):
            return OversightCard(
                sequence=sequence,
                function=function,
                operation="",
                outcome=outcome,
                requested_caps=(),
                granted_caps=(),
                allowed_tools=None,
                write_scope=(),
                risk_name="read",
                reasons=(),
                duration_s=0.5,
                arguments=(),
            )

        controller = _FakeLiveController()

        def run(question, on_tool):
            on_tool(ToolEvent(1, "registry_query", "", "key=Select", "approved", 0.1))
            on_tool(ToolEvent(2, "evtx_query", "", "log=System", "approved", 2.0))
            return InvestigationResult(
                question=question,
                answer_markdown="answer",
                answer_source=ANSWER_VERIFIED,
                evidence_ids=("disk:image.E01",),
                findings=(),
                oversight=(card(2, "registry_query"), card(7, "evtx_query")),
                controls=ControlCard(
                    "verified", ANSWER_VERIFIED, 2, 0, 3, "t-order", 3.0
                ),
            )

        controller.run = run
        app = build_app(controller)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.1)
            app.dispatch_command("layout", "simple")
            await pilot.pause(0.1)
            prompt = app.query_one("#prompt")
            prompt.focus()
            await pilot.pause(0.05)
            prompt.value = "which keys were read?"
            await pilot.press("enter")
            for _ in range(100):
                await pilot.pause(0.05)
                if not app.running:
                    break
            await pilot.pause(0.3)

            import io

            from rich.console import Console as RichConsole

            block = app.query_one("#inline-1")
            console = RichConsole(width=110, record=True, file=io.StringIO())
            console.print(block.render()._renderable)
            text = console.export_text()
            # Both calls present, in feed order, each exactly once.
            assert text.index("registry_query") < text.index("evtx_query")
            assert text.count("registry_query") == 1
            assert text.count("evtx_query") == 1

    asyncio.run(scenario())


def test_concurrent_same_shape_calls_pair_by_arguments():
    """Two identical-shaped calls that settled out of their recorded
    order must still get their own card: argument overlap decides."""

    from forensic_agent.tui.app import _pair_cards_to_events
    from forensic_agent.tui.model import OversightCard, ToolEvent

    def card(sequence, key):
        return OversightCard(
            sequence=sequence,
            function="registry_query",
            operation="registry_values",
            outcome="executed",
            requested_caps=(),
            granted_caps=(),
            allowed_tools=None,
            write_scope=(),
            risk_name="read",
            reasons=(),
            duration_s=0.1,
            arguments=(("key", key),),
        )

    events = [
        ToolEvent(1, "registry_query", "registry_values", "hive=SAM  key=Users/A", "approved", 0.1),
        ToolEvent(2, "registry_query", "registry_values", "hive=SAM  key=Users/B", "approved", 0.1),
    ]
    # Recorded in the opposite order to how they arrived.
    paired = _pair_cards_to_events(events, [card(2, "Users/B"), card(7, "Users/A")])
    assert [c.arguments[0][1] for c in paired] == ["Users/A", "Users/B"]


def _widget_text(widget, width: int = 110) -> str:
    """The plain text a mounted Static is showing, through a StringIO sink."""

    import io

    from rich.console import Console as RichConsole

    rendered = widget.render()
    # Textual 8 wraps Rich renderables in a RichVisual and plain text in a
    # Content; only the former has a Rich renderable to print.
    renderable = getattr(rendered, "_renderable", None)
    if renderable is None:
        return getattr(rendered, "plain", None) or str(rendered)
    console = RichConsole(width=width, record=True, file=io.StringIO())
    console.print(renderable)
    return console.export_text()


def test_a_discarded_exchange_does_not_break_the_next_answer():
    """A run that publishes nothing gives its message number back, and its
    ACTIVITY rows leave the DOM with it. The next message reuses that number
    and restarts its sequence: stale row ids made the console take the fresh
    rows for mounted ones and left it stuck on "Investigating"."""

    async def scenario():
        from forensic_agent.tui.model import (
            ANSWER_NONE,
            ANSWER_VERIFIED,
            ControlCard,
            InvestigationResult,
            OversightCard,
            ToolEvent,
        )

        controller = _FakeLiveController()
        asked: list[str] = []

        def run(question, on_tool):
            asked.append(question)
            on_tool(ToolEvent(1, "registry_query", "", "key=Select", "running", None))
            on_tool(ToolEvent(1, "registry_query", "", "key=Select", "approved", 0.1))
            if len(asked) == 1:
                # Nothing published — _render_result discards the exchange.
                return InvestigationResult(
                    question=question,
                    answer_markdown="",
                    answer_source=ANSWER_NONE,
                    evidence_ids=(),
                    findings=(),
                    oversight=(),
                    controls=ControlCard(
                        "no run", ANSWER_NONE, 0, 0, None, "t-empty", 0.1
                    ),
                    incomplete=True,
                    note="that run published nothing",
                )
            return InvestigationResult(
                question=question,
                answer_markdown="THE SECOND ANSWER",
                answer_source=ANSWER_VERIFIED,
                evidence_ids=("disk:image.E01",),
                findings=(),
                oversight=(
                    OversightCard(
                        sequence=2,
                        function="registry_query",
                        operation="",
                        outcome="executed",
                        requested_caps=(),
                        granted_caps=(),
                        allowed_tools=None,
                        write_scope=(),
                        risk_name="read",
                        reasons=(),
                        duration_s=0.1,
                        arguments=(),
                    ),
                ),
                controls=ControlCard(
                    "verified", ANSWER_VERIFIED, 1, 0, 2, "t-second", 0.2
                ),
            )

        controller.run = run
        app = build_app(controller)
        async with app.run_test(size=(120, 40)) as pilot:
            prompt = app.query_one("#prompt")

            async def ask(text: str) -> None:
                prompt.focus()
                await pilot.pause(0.05)
                prompt.value = text
                await pilot.press("enter")
                for _ in range(100):
                    await pilot.pause(0.05)
                    if not app.running:
                        break

            await ask("what did the run publish?")
            await pilot.pause(0.4)  # the deferred discard finishes
            assert app._exchange == 0
            assert not list(app.query("#sep-1"))
            assert not any(r.startswith("act-1-") for r in app._activity_rows)

            await ask("which USB device was connected?")
            await pilot.pause(0.3)
            # The exchange is numbered 01 again and its row really mounted.
            assert app._exchange == 1
            assert len(app.query_one("#grp-1").children) == 1
            # The working line is gone and the answer is on screen: the run
            # that follows a discarded one must not be stuck "Investigating".
            assert not list(app.query("#work-1"))
            answered = any(
                "THE SECOND ANSWER" in _widget_text(widget)
                for widget in app.query_one("#conversation", VerticalScroll).children
            )
            assert answered, "the second answer was never rendered"

    asyncio.run(scenario())


def test_an_interrupted_call_row_settles_instead_of_spinning():
    """Ctrl+C stops the run before the call reports back; the ACTIVITY row
    must settle rather than say "running…" for the rest of the session."""

    async def scenario():
        import threading

        from forensic_agent.tui.model import ToolEvent

        controller = _FakeLiveController()
        release = threading.Event()

        def run(question, on_tool):
            on_tool(ToolEvent(1, "evtx_query", "", "log=System", "running", None))
            release.wait(5)
            raise AssertionError("the run was cancelled before this")

        controller.run = run
        app = build_app(controller)
        async with app.run_test(size=(120, 40)) as pilot:
            prompt = app.query_one("#prompt")
            prompt.focus()
            await pilot.pause(0.05)
            prompt.value = "which events were logged?"
            await pilot.press("enter")
            for _ in range(100):
                await pilot.pause(0.05)
                if list(app.query("#act-1-1")):
                    break
            assert "running" in _widget_text(app.query_one("#act-1-1"))

            app.action_interrupt()
            await pilot.pause(0.1)
            row = _widget_text(app.query_one("#act-1-1"))
            assert "running" not in row
            assert "did not complete" in row
            release.set()

    asyncio.run(scenario())


def test_status_shows_one_titled_frame():
    """/status draws the overlay's own frame; the panel's border inside it
    made the operator read a "Session" box wrapping a "› Session" box."""

    async def scenario():
        app = build_app(_FakeLiveController())
        async with app.run_test(size=(120, 40)) as pilot:
            app.dispatch_command("status", "")
            await pilot.pause(0.1)
            assert isinstance(app.screen, OverlayScreen)
            body = app.screen.query_one("#overlay-body", VerticalScroll)
            rendered = _widget_text(body.query_one(Static))
            assert "test-model" in rendered
            assert "Session" not in rendered  # the frame's title, not the body's

    asyncio.run(scenario())


def test_export_writes_the_report_without_touching_the_case():
    """/export is the non-destructive half of /complete: it writes the case
    report and never detaches evidence or declares the case closed."""

    async def scenario():
        controller = _FakeLiveController()
        app = build_app(controller)
        async with app.run_test(size=(120, 40)) as pilot:
            app.dispatch_command("export", "")
            for _ in range(60):
                await pilot.pause(0.05)
                if controller.session.exported:
                    break
            assert controller.session.exported == [None]
            assert controller.session.completed == []
            assert controller.session.cleared == 0

    asyncio.run(scenario())


def test_unknown_coverage_is_not_reported_as_partial():
    """A finding whose coverage was never established must say so; rendering
    it as "only part was read" invents a bound the record never stated."""

    import dataclasses

    from forensic_agent.tui.app import _plain_coverage
    from forensic_agent.tui.model import FindingCard

    card = FindingCard(
        sequence=1,
        status="unknown",
        function="registry_query",
        operation="registry_values",
        data_type="registry.values",
        records="",
        coverage_label="unknown",
        coverage_complete=None,
        coverage_scope="",
        coverage_reason="",
        receipt_full="—",
        arguments=(),
        result_summary="",
        source_id="",
        source_uri="",
        evidence_class="",
        warnings=(),
        oversight_sequence=None,
    )
    assert "not recorded" in _plain_coverage(card)
    assert "more remains" not in _plain_coverage(card)
    assert _plain_coverage(dataclasses.replace(card, coverage_complete=True)) == (
        "read in full"
    )
    assert "more remains" in _plain_coverage(
        dataclasses.replace(card, coverage_complete=False)
    )


def test_slash_case_is_a_launch_form_too():
    """dfir-agent /case PATH opens the console on that case."""

    from forensic_agent.cli.app import _normalize_case_shortcut

    assert _normalize_case_shortcut(["/case", r"D:\Cases\x"]) == [
        "tui", "--case", r"D:\Cases\x"
    ]
    assert _normalize_case_shortcut(["/CASE", "x", "--demo"]) == [
        "tui", "--case", "x", "--demo"
    ]
    assert _normalize_case_shortcut(["/case"]) == ["tui"]


def test_a_palette_pick_runs_the_command_it_picked():
    """The palette is a menu. Picking from it does the thing.

    This asserted the opposite for a while. The reasoning was that running
    /model bare would strand the argument, so a pick inserted the name and
    notified instead — and the console lost its menus: picking `tools` said
    "run /tools" and did nothing, and every command behaved that way.

    The premise was wrong. The bare form of every argument-taking command
    here IS the menu for it: /model, /theme, /layout, /effort and /resume open
    a chooser, /attach and /case open a chooser and then a file browser. So a
    pick dispatches, and the value is chosen on the screen that opens.
    """

    async def scenario():
        app = build_app(DemoController())
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.1)
            prompt = app.query_one("#prompt")

            dispatched: list[tuple[str, str]] = []
            app.dispatch_command = lambda name, argument="": dispatched.append(
                (name, argument)
            )
            for spec in COMMAND_REGISTRY.commands:
                app.palette_insert(spec.name)
                await pilot.pause(0.02)
            assert [name for name, _ in dispatched] == [
                spec.name for spec in COMMAND_REGISTRY.commands
            ], "a palette pick did not run its command"
            assert all(argument == "" for _, argument in dispatched)
            # Nothing was typed on the operator's behalf either.
            assert prompt.value == ""

    asyncio.run(scenario())


def test_a_command_with_an_argument_can_still_be_typed_out_by_hand():
    """The menu must not cost the keyboard. Enter sends what was typed."""

    async def scenario():
        app = build_app(DemoController())
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.1)
            prompt = app.query_one("#prompt")
            sent: list[str] = []
            app._handle_slash = sent.append

            for typed in ("/clear all", "/model list", "/effort steps 30"):
                prompt.value = typed
                await pilot.press("enter")
                await pilot.pause(0.05)
            assert sent == ["/clear all", "/model list", "/effort steps 30"]

    asyncio.run(scenario())


def test_typing_a_slash_lists_the_commands_it_still_matches():
    """The operator has to be able to SEE what exists, not guess at a ghost.

    A single greyed completion after the cursor answers "what is the one
    command you think I mean"; typing ``/`` asks "what is there". So the
    matches are drawn out under the prompt, and they narrow as the prefix
    grows. The list is a Static: it cannot focus and cannot take a key.
    """

    from forensic_agent.tui.app import matching_commands

    every = {spec.name for spec in COMMAND_REGISTRY.commands}
    assert {name for name, _, _ in matching_commands("/")} == every
    assert {name for name, _, _ in matching_commands("/c")} == {
        "clear", "case", "context", "complete", "continue"
    }
    assert [name for name, _, _ in matching_commands("/cl")] == ["clear"]
    assert matching_commands("/nosuchcommand") == ()
    # An alias has to find something, or the list teaches that it is gone.
    assert "guardrails" in {name for name, _, _ in matching_commands("/gu")}
    # Once the argument starts, the command is settled and the list is done.
    assert matching_commands("/clear ") == ()
    assert matching_commands("/clear all") == ()
    assert matching_commands("hello") == ()

    async def scenario():
        app = build_app(DemoController())
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.1)
            prompt = app.query_one("#prompt")
            hints = app.query_one("#command-hints", Static)
            assert hints.display is False
            assert hints.can_focus is False

            for typed, visible in (
                ("/", True), ("/c", True), ("/cl", True),
                ("/clear ", False), ("/clear all", False), ("hello", False), ("", False),
            ):
                prompt.value = typed
                await pilot.pause(0.05)
                assert hints.display is visible, f"typing {typed!r}"

            # Enter still sends exactly what was typed, and the list goes.
            prompt.value = "/cl"
            await pilot.pause(0.05)
            assert hints.display is True
            sent: list[str] = []
            app._handle_slash = sent.append
            prompt.value = "/clear all"
            await pilot.press("enter")
            await pilot.pause(0.05)
            assert sent == ["/clear all"]
            assert hints.display is False

    asyncio.run(scenario())


def test_every_usage_line_matches_a_handler_that_reads_its_argument():
    """A usage line that advertises an argument the handler ignores is the
    same defect as /model list: the documentation and the console disagree."""

    import inspect

    from forensic_agent.cli.commands import COMMAND_REGISTRY
    from forensic_agent.tui.app import InvestigationApp

    for spec in COMMAND_REGISTRY.commands:
        handler = getattr(InvestigationApp, f"_cmd_{spec.name}")
        parameters = list(inspect.signature(handler).parameters)
        takes_argument = spec.usage.strip() != f"/{spec.name}"
        # The console's own convention: a handler that ignores its argument
        # names the parameter with a leading underscore.
        reads_argument = len(parameters) > 1 and not parameters[1].startswith("_")
        assert reads_argument == takes_argument, (
            f"/{spec.name}: usage {spec.usage!r} and handler {parameters} disagree"
        )


def test_read_only_commands_run_while_a_message_is_being_investigated():
    """/history and its kind read recorded state; a run cannot notice them.

    The commands that change the session are still refused, and the refusal
    now says what about THAT command cannot happen beside a running run.
    """

    async def scenario():
        app = build_app(_FakeLiveController())
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.1)
            app.running = True
            notes: list[tuple[str, str]] = []
            app.notify = lambda message, **kw: notes.append(
                (str(kw.get("title", "")), str(message))
            )

            app.dispatch_command("history", "")
            await pilot.pause(0.3)
            # It reached the session's own view rather than being refused.
            assert app._controller.session._history.shown

            app.dispatch_command("new", "")
            await pilot.pause(0.1)
            (title, message) = notes[-1]
            assert title == "/new"
            assert "starts a new investigation history" in message

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# evidence named on the command line opens IN the console, where it can be seen
# ---------------------------------------------------------------------------
def _launch_args(**overrides):
    """The evidence-bearing attributes of a parsed command line."""

    from types import SimpleNamespace

    fields = {
        "case": None, "image": None, "memory": None, "pcap": None,
        "resume": None, "continue_session": False,
    }
    fields.update(overrides)
    return SimpleNamespace(**fields)


def test_every_evidence_flag_is_opened_by_the_console_not_the_constructor():
    """The defect: `--image disk.raw` showed no progress and no indexing.

    Anything the session opens in its constructor runs before the screen
    exists, against the devnull console the console hands it — so hashing and
    indexing a disk image was minutes of blank terminal followed by a console
    that appeared with the case already loaded. Only --case was deferred.
    """

    from forensic_agent.tui import deferred_evidence

    args = _launch_args(image="disk.raw")
    assert deferred_evidence(args) == (None, (("disk", "disk.raw"),))
    assert args.image is None, "the session would open it again"

    args = _launch_args(memory="mem.raw", pcap="net.pcap")
    assert deferred_evidence(args) == (
        None, (("memory", "mem.raw"), ("network", "net.pcap"))
    )
    assert args.memory is None and args.pcap is None

    # A case directory with typed overlays: the directory first, then each
    # source, which is the order the session constructor applied them in.
    args = _launch_args(case="C:/cases/laptop", image="disk.raw", memory="mem.raw")
    assert deferred_evidence(args) == (
        "C:/cases/laptop", (("disk", "disk.raw"), ("memory", "mem.raw"))
    )
    assert args.case is None and args.image is None and args.memory is None

    # The bare --case that was always deferred still is.
    args = _launch_args(case="C:/cases/laptop")
    assert deferred_evidence(args) == ("C:/cases/laptop", ())


def test_resume_and_continue_keep_opening_their_own_case():
    """They reopen a case as a side effect of restoring a conversation, and
    deferring that would switch the case under a console already showing one."""

    from forensic_agent.tui import deferred_evidence

    args = _launch_args(case="C:/cases/laptop", resume="abc123")
    assert deferred_evidence(args) == (None, ())
    assert args.case == "C:/cases/laptop", "left for the session, untouched"

    args = _launch_args(image="disk.raw", continue_session=True)
    assert deferred_evidence(args) == (None, ())
    assert args.image == "disk.raw"


def test_a_launch_with_nothing_to_open_claims_nothing():
    from forensic_agent.tui import deferred_evidence

    assert deferred_evidence(_launch_args()) == (None, ())


# ---------------------------------------------------------------------------
# resuming puts the investigation back ON SCREEN, not only into context
# ---------------------------------------------------------------------------
def _stored_run(root, run_id="run-7b3e9c1a4f28"):
    """One finished run on disk, in the shape the oversight log writes it."""

    import json

    run_dir = root / run_id
    run_dir.mkdir(parents=True)
    policy = {
        "name": "case-default",
        "allowed_tools": ["registry_query", "http_fetch"],
        "granted_caps": ["disk.read"],
        "write_scope": [],
    }
    rows = [
        {"event": "case_open", "ts": 1000.0, "seq": 0, "case_id": "laptop-0731",
         "question": "who plugged in the USB device?", "policy": policy,
         "write_scope": [], "model": "deepseek-chat", "engine": "LangGraph"},
        {"event": "action", "ts": 1002.0, "seq": 1, "case_id": "laptop-0731",
         "tool": "registry_query",
         "args": {"operation": "enumerate_usbstor", "hive": "SYSTEM"},
         "allowed": True, "blocked": False, "outcome": "executed",
         "risk_name": "read", "reasons": [], "capabilities": ["disk.read"],
         "duration_s": 1.8, "output_sha256": "a" * 64},
        {"event": "action", "ts": 1005.0, "seq": 2, "case_id": "laptop-0731",
         "tool": "http_fetch",
         "args": {"operation": "resolve_vendor_id", "url": "https://usb.ids"},
         "allowed": False, "blocked": True, "outcome": "refused_by_oversight",
         "risk_name": "network", "reasons": ["network capability not granted"],
         "capabilities": ["network"], "duration_s": 0.0},
        {"event": "case_close", "ts": 1012.4, "seq": 3, "case_id": "laptop-0731",
         "status": "ok", "final_sha256": "b" * 64},
    ]
    (run_dir / "oversight.jsonl").write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8"
    )
    (run_dir / "tool-results.jsonl").write_text("", encoding="utf-8")
    return run_id


def _replay_controller(root):
    """A LiveController bound to nothing but a run root, which is all replay reads."""

    import types

    from forensic_agent.tui.controller import LiveController

    controller = LiveController.__new__(LiveController)
    controller._session = types.SimpleNamespace(run_root=str(root))
    return controller


def _turn(run_id, question="who plugged in the USB device?", answer="A SanDisk drive."):
    import types

    return types.SimpleNamespace(
        turn_id=run_id, question=question, verified_answer=answer
    )


def test_a_resumed_turn_brings_its_guardrail_decisions_back(tmp_path):
    """Resuming used to restore context and nothing else, so the operator got
    the conversation's meaning back and an empty screen. Every decision the run
    made is on disk and comes back through the same projections the live panes
    are built from."""

    run_id = _stored_run(tmp_path)
    result = _replay_controller(tmp_path).replay(_turn(run_id))

    assert result.question == "who plugged in the USB device?"
    assert result.answer_markdown == "A SanDisk drive."
    assert [card.sequence for card in result.oversight] == [1, 2]
    executed, refused = result.oversight
    assert (executed.function, executed.operation) == (
        "registry_query", "enumerate_usbstor",
    )
    assert executed.outcome == "executed"
    assert executed.duration_s == 1.8
    assert executed.granted_caps == ("disk.read",)
    # The refused call keeps the reason it was refused for; that sentence is
    # the whole value of a guardrails record and is never regenerated.
    assert refused.outcome == "refused_by_oversight"
    assert refused.requested_caps == ("network",)
    assert refused.reasons == ("network capability not granted",)
    assert result.controls.tool_calls == 1


def test_a_replayed_answer_claims_neither_a_pass_nor_a_failure(tmp_path):
    """The run's own verdict is not on disk, and a replay must not invent one.

    Whether the answer was verified lives in the run's telemetry, which reaches
    disk only when a run FAILS. Marking a restored answer verified would be a
    claim nothing supports; marking it ANSWER_NONE would say it was not
    accepted, when it is the answer the operator was actually given.
    """

    run_id = _stored_run(tmp_path)
    result = _replay_controller(tmp_path).replay(_turn(run_id))

    assert result.answer_source == M.ANSWER_REPLAYED
    assert result.controls.verification == "not recorded"
    assert result.controls.model_requests is None
    assert M.is_grounded(result.answer_source) is False
    colour, _glyph, qualifier = M.answer_frame(M.ANSWER_REPLAYED)
    assert "restored" in qualifier
    # The metadata colour, not a verdict colour: nothing is being judged here.
    assert colour == M.palette()["DIM_BRIGHT"]


def test_a_replay_reports_the_runs_own_clock(tmp_path):
    """Not the live path's wall clock around ask(), which is not recorded. The
    chain's last timestamp minus its first is what the record supports."""

    run_id = _stored_run(tmp_path)
    result = _replay_controller(tmp_path).replay(_turn(run_id))
    assert result.controls.elapsed_s == pytest.approx(12.4, abs=0.01)
    assert result.controls.trace_id == run_id[:12]


def test_a_turn_whose_run_folder_is_gone_says_so_instead_of_showing_nothing(tmp_path):
    """Run directories default to the operating system's temporary directory and
    get swept. The messages still restore; the panes must not imply the run made
    no tool calls when the truth is that the record is no longer there."""

    controller = _replay_controller(tmp_path)
    result = controller.replay(_turn("run-that-was-swept"))

    assert result.answer_markdown == "A SanDisk drive."
    assert result.oversight == ()
    assert result.findings == ()
    assert "no longer on disk" in result.note


def test_sessions_and_resume_are_one_command(tmp_path):
    """They were two specs running the same code: a bare /resume opened the same
    picker /sessions did, and picking from it resumed. Two names for one intent
    taught the operator there were two things to learn."""

    from forensic_agent.cli.commands import COMMAND_REGISTRY, parse_command
    from forensic_agent.tui.app import InvestigationApp

    spec = COMMAND_REGISTRY.resolve("sessions")
    assert spec is not None
    assert spec.name == "resume"
    assert "sessions" in spec.aliases
    assert spec.usage == "/resume [id]"
    # The old name still parses, and lands on the one handler.
    parsed = parse_command("/sessions")
    assert parsed is not None and parsed.name == "resume"
    assert not hasattr(InvestigationApp, "_cmd_sessions")
    assert hasattr(InvestigationApp, "_cmd_resume")


def test_an_alias_dispatched_by_name_still_finds_its_handler():
    """The palette, a key binding or a test can call dispatch_command with an
    alias; handlers are named for the canonical command."""

    from forensic_agent.tui.app import InvestigationApp

    canonical = InvestigationApp._canonical_command
    assert canonical("sessions") == "resume"
    assert canonical("guardrails") == "oversight"
    assert canonical("resume") == "resume"
    assert canonical("not-a-command") == "not-a-command"


def test_the_replayed_screen_says_it_is_a_replay():
    """In a forensic console the difference between "the agent just found this"
    and "it found this last week" is the point of keeping a record at all."""

    async def scenario():
        app = build_app(DemoController())
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.1)
            banner = app._replay_banner().plain
            assert "Restored from the record" in banner
            assert "Nothing here is running now" in banner

    asyncio.run(scenario())


def test_a_clean_message_never_erases_a_denial_the_case_recorded():
    """The one sentence a guardrails pane must never be able to produce.

    The all-clear line counts allowed steps and is replaced by the denial rows
    the moment something is blocked. It was re-mounted by the NEXT message if
    that message happened to be clean, so a case with a real refusal in it
    ended up stating, in the success colour, that every step had been allowed.
    """

    from forensic_agent.tui.model import OUTCOME_EXECUTED, OUTCOME_REFUSED_BY_OVERSIGHT

    def card(sequence, outcome):
        return OversightCard(
            sequence=sequence,
            function="http_fetch" if outcome != OUTCOME_EXECUTED else "registry_query",
            operation="resolve_vendor_id" if outcome != OUTCOME_EXECUTED else "read",
            outcome=outcome,
            requested_caps=("network",) if outcome != OUTCOME_EXECUTED else ("disk.read",),
            granted_caps=("disk.read",),
            allowed_tools=None,
            write_scope=(),
            risk_name="network",
            reasons=("network capability not granted",) if outcome != OUTCOME_EXECUTED else (),
            duration_s=0.0,
            arguments=(),
        )

    def result(*cards):
        return InvestigationResult(
            question="q",
            answer_markdown="a",
            answer_source=M.ANSWER_REPLAYED,
            evidence_ids=(),
            findings=(),
            oversight=cards,
            controls=ControlCard(
                verification="not recorded",
                answer_source=M.ANSWER_REPLAYED,
                tool_calls=len(cards),
                findings=0,
                model_requests=None,
                trace_id="t",
                elapsed_s=1.0,
            ),
        )

    async def scenario():
        app = build_app(DemoController())
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.1)
            app._exchange = 1
            app._populate_guardrails(result(card(1, OUTCOME_REFUSED_BY_OVERSIGHT)))
            await pilot.pause(0.1)
            assert not app.query("#guardrails-allclear")
            assert app._guardrail_blocks

            # A later, entirely clean message.
            app._exchange = 2
            app._populate_guardrails(result(card(2, OUTCOME_EXECUTED)))
            await pilot.pause(0.1)
            assert not app.query("#guardrails-allclear"), (
                "a clean message put the all-clear line back over a real denial"
            )

    asyncio.run(scenario())


def test_a_count_nobody_recorded_is_left_out_rather_than_printed_as_none():
    """A replayed exchange has no model-request count: the number is telemetry,
    and telemetry only reaches disk when a run fails. The footer used to
    interpolate it anyway and render the literal word "None"."""

    async def scenario():
        app = build_app(DemoController())
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.1)
            recorded = ControlCard(
                verification="ok", answer_source=M.ANSWER_VERIFIED, tool_calls=5,
                findings=4, model_requests=7, trace_id="t", elapsed_s=11.7,
            )
            missing = ControlCard(
                verification="not recorded", answer_source=M.ANSWER_REPLAYED,
                tool_calls=1, findings=0, model_requests=None, trace_id="t",
                elapsed_s=12.4,
            )
            assert "7 model requests" in app._run_counts(recorded).plain
            plain = app._run_counts(missing).plain
            assert "None" not in plain
            assert "model requests" not in plain
            assert "1 tool calls" in plain and "0 findings" in plain

    asyncio.run(scenario())


def test_every_usage_line_reaches_the_input_border_verbatim():
    """A border subtitle is parsed as markup, and a usage line is mostly brackets.

    rich.markup.escape only escapes the brackets that LOOK like tags, so
    /model's nested form arrived on screen as
    ``/model [list \[all|<text>]|<model-id>]`` with a stray backslash in the
    middle of it while /clear's simple form was fine. Every bracket is escaped
    now, which is the only encoding that is right for every usage line.
    """

    from forensic_agent.tui.app import _literal_markup

    async def scenario():
        app = build_app(DemoController())
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause(0.1)
            prompt = app.query_one("#prompt")
            for spec in COMMAND_REGISTRY.commands:
                prompt.value = f"/{spec.name} "
                await pilot.pause(0.02)
                # What the border will draw, once the markup parser is done.
                drawn = Text.from_markup(prompt.border_subtitle or "").plain
                assert drawn == spec.usage, (
                    f"/{spec.name} usage reached the border as {drawn!r}, "
                    f"not {spec.usage!r}"
                )
                assert "\\" not in drawn

    asyncio.run(scenario())

    # And the encoding itself is total: nothing survives as a style tag.
    assert Text.from_markup(_literal_markup("[bold]x[/]")).plain == "[bold]x[/]"
