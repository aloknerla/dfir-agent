"""Console behaviour: activity rows, /status, the choosers, and completing a case.

Every scenario here drives the real :class:`InvestigationApp` through Textual's
pilot and reads the characters that came out, because the alternative — checking
internal state — is how three fixes were reported green while the console was
still broken in the operator's hands.
"""

from __future__ import annotations

import asyncio
import dataclasses
import io

import pytest

pytest.importorskip("textual")

from textual.containers import VerticalScroll  # noqa: E402
from textual.widgets import Collapsible, ListView, Static  # noqa: E402

from forensic_agent.tui import build_app  # noqa: E402
from forensic_agent.tui import model as M  # noqa: E402
from forensic_agent.tui.app import (  # noqa: E402
    ChoiceScreen,
    OverlayScreen,
    PromptScreen,
    ReviewScreen,
    _activity_row,
    _recorded_reasons,
    _target_argument,
)
from forensic_agent.tui.controller import DemoController  # noqa: E402
from forensic_agent.tui.model import FindingCard, ToolEvent  # noqa: E402


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr("forensic_agent.tui.controller.time.sleep", lambda *_: None)


def _text(renderable, width: int = 110) -> str:
    from rich.console import Console as RichConsole

    console = RichConsole(width=width, record=True, file=io.StringIO())
    console.print(renderable)
    return console.export_text()


def _widget_text(widget, width: int = 110) -> str:
    rendered = widget.render()
    renderable = getattr(rendered, "_renderable", None)
    if renderable is None:
        return getattr(rendered, "plain", None) or str(rendered)
    return _text(renderable, width)


def _event(**overrides) -> ToolEvent:
    base = {
        "sequence": 1,
        "function": "registry_query",
        "operation": "registry_values",
        "args_summary": "key=/Policy/Lsa",
        "status": M.OUTCOME_EXECUTED,
        "duration_s": 0.4,
    }
    base.update(overrides)
    return ToolEvent(**base)


def _finding(**overrides) -> FindingCard:
    base = {
        "sequence": 1,
        "status": "partial",
        "function": "archive_query",
        "operation": "extract_inspect",
        "data_type": "archive.entries",
        "records": "0/0 entries",
        "coverage_label": "partial",
        "coverage_complete": False,
        "coverage_scope": "",
        "coverage_reason": "",
        "receipt_full": "—",
        "arguments": (),
        "result_summary": "",
        "source_id": "",
        "source_uri": "",
        "evidence_class": "",
        "warnings": (),
        "oversight_sequence": 1,
    }
    base.update(overrides)
    return FindingCard(**base)


# ---------------------------------------------------------------------------
# A5 — the scope line, printed only when it says something the arguments do not
# ---------------------------------------------------------------------------
def test_the_target_argument_is_found_by_one_shared_lookup():
    """The ACTIVITY row and the finding card must agree about what a call
    examined; two lookups eventually disagree."""

    assert _target_argument((("hive", "SYSTEM"), ("key", "ControlSet001"))) == (
        "ControlSet001"
    )
    assert _target_argument((("limit", "60"), ("log", "setupapi.dev.log"))) == (
        "setupapi.dev.log"
    )
    assert _target_argument((("offset", "0"),)) == ""
    assert _target_argument((("path", "   "), ("file", "a.evtx"))) == "a.evtx"


def test_an_equal_scope_is_suppressed_and_a_differing_one_is_kept():
    arguments = (("key", "/Policy/Lsa"),)
    same = _text(_activity_row(_event(), scope="/Policy/Lsa", arguments=arguments))
    assert "read" not in same

    differing = _text(_activity_row(_event(), scope="/Policy", arguments=arguments))
    assert "› read /Policy" in differing


def test_a_scope_differing_only_in_punctuation_is_still_suppressed():
    """A trailing separator, or a backslash for a slash, is the same place."""

    arguments = (("key", "/Policy/Lsa"),)
    for scope in ("/Policy/Lsa/", "\\Policy\\Lsa", "/Policy//Lsa", "/POLICY/LSA"):
        rendered = _text(_activity_row(_event(), scope=scope, arguments=arguments))
        assert "read" not in rendered, f"{scope!r} printed as a difference"


def test_a_scope_with_no_target_argument_at_all_is_kept():
    """With nothing to repeat, the scope is the only statement of what was read."""

    rendered = _text(
        _activity_row(
            _event(args_summary="operation=pslist"),
            scope="all processes in the image",
            arguments=(("operation", "pslist"),),
        )
    )
    assert "› read all processes in the image" in rendered


# ---------------------------------------------------------------------------
# A20 — the warning glyph says why, where it appears
# ---------------------------------------------------------------------------
def test_a_warning_row_names_the_outcome_and_the_reason():
    """▲ beside "all steps were allowed" reads as a contradiction until the row
    says which axis it is on and what the tool actually reported."""

    rendered = _text(
        _activity_row(
            _event(function="archive_query", operation="", args_summary="limit=60"),
            status=M.OUTCOME_FAILED,
            reason="the archive is password protected (PasswordRequired)",
        )
    )
    assert M.GLYPH_WARN in rendered
    assert "failed" in rendered
    assert "password protected" in rendered


def test_a_clean_call_carries_neither_an_outcome_word_nor_a_reason():
    """"executed" is what a call is supposed to do; saying so on every row
    buries the handful that did something else."""

    rendered = _text(
        _activity_row(_event(), status=M.OUTCOME_EXECUTED, reason="never shown")
    )
    assert "never shown" not in rendered
    head = rendered.split("\n")[0]
    assert M.GLYPH_OK in head
    assert M.OUTCOME_STYLE[M.OUTCOME_EXECUTED][2] not in head


def test_a_running_row_is_untouched_by_either():
    rendered = _text(_activity_row(_event(status="running"), reason="not yet"))
    assert "running" in rendered
    assert "not yet" not in rendered


def test_the_reason_comes_from_what_the_tool_reported_and_nothing_else():
    """Warning first, then the coverage reason; a call that reported neither
    contributes no entry, so no row can invent one."""

    result = dataclasses.replace(
        DemoController().run("q", lambda _e: None),
        findings=(
            _finding(sequence=1, oversight_sequence=3, warnings=("locked archive",)),
            _finding(sequence=2, oversight_sequence=4, coverage_reason="hit the limit"),
            _finding(sequence=3, oversight_sequence=5),
        ),
    )
    reasons = _recorded_reasons(result)
    assert reasons == {3: "locked archive", 4: "hit the limit"}


def test_a_failed_call_takes_its_reason_from_what_the_tool_declared():
    """A failed call files no finding, so the oversight record's own
    outcome_detail is the only place its reason can honestly come from."""

    from forensic_agent.tui.app import _row_reason
    from forensic_agent.tui.model import OversightCard

    card = OversightCard(
        sequence=6,
        function="archive_query",
        operation="extract_inspect",
        outcome=M.OUTCOME_FAILED,
        requested_caps=(),
        granted_caps=(),
        allowed_tools=None,
        write_scope=(),
        risk_name="",
        reasons=(),
        duration_s=0.0,
        arguments=(("archive_path", "/evidence/x.7z"),),
        outcome_detail="the archive is encrypted (PasswordRequired)",
    )
    assert _row_reason(card, {}) == "the archive is encrypted (PasswordRequired)"
    # A finding's own warning is nearer and wins.
    assert _row_reason(card, {6: "only part was readable"}) == "only part was readable"
    rendered = _text(
        _activity_row(
            _event(function="archive_query", operation="extract_inspect"),
            status=M.OUTCOME_FAILED,
            reason=_row_reason(card, {}),
        )
    )
    assert "PasswordRequired" in rendered


def test_the_two_axes_are_distinguishable_at_a_glance():
    """A refused call and a failed one wear the same ▲; the word is what tells
    them apart, so the word has to be there."""

    from forensic_agent.tui.app import _status_glyph

    assert _status_glyph(M.OUTCOME_FAILED) == _status_glyph(M.OUTCOME_REFUSED_BY_TOOL)
    failed = _text(_activity_row(_event(), status=M.OUTCOME_FAILED))
    refused = _text(_activity_row(_event(), status=M.OUTCOME_REFUSED_BY_TOOL))
    blocked = _text(_activity_row(_event(), status=M.OUTCOME_REFUSED_BY_OVERSIGHT))
    assert "failed" in failed
    assert "refused" in refused
    assert "BLOCKED" in blocked


# ---------------------------------------------------------------------------
# A1 — /status says what the Session panel cannot
# ---------------------------------------------------------------------------
def test_status_adds_this_session_to_the_standing_frame():
    async def scenario():
        app = build_app(DemoController())
        async with app.run_test(size=(140, 44)) as pilot:
            await pilot.pause(0.3)
            panel = _widget_text(app._session_widget, 90)
            app.dispatch_command("status", "")
            await pilot.pause(0.15)
            assert isinstance(app.screen, OverlayScreen)
            body = app.screen.query_one("#overlay-body", VerticalScroll)
            overlay = _widget_text(body.query_one(Static), 90)

            # No frame inside the frame: the overlay's own title is the only one.
            assert "› Session" not in overlay
            # The standing frame is still answered.
            assert "deepseek-chat" in overlay
            # And something the panel does not carry. Section headings are
            # uppercase, matching the pane titles they sit between.
            assert "THIS SESSION" in overlay
            for row in ("version", "theme", "language", "messages", "findings"):
                assert row in overlay, f"/status lost its {row} row"
                assert row not in panel
            # Two rows were removed as developer-facing rather than useful.
            # "build" said "code dated <mtime>", which /doctor now answers in
            # words an operator can act on; "run record" named a directory
            # that renders as "/runtime (inside the container)" — a path plus
            # an apology for the path.
            assert "code dated" not in overlay
            assert "run record" not in overlay
            assert "inside the container" not in overlay

    asyncio.run(scenario())


def test_status_counts_findings_from_the_review_queue_itself():
    """Accepted versus awaiting, read off the two lists the console keeps."""

    async def scenario():
        app = build_app(DemoController())
        async with app.run_test(size=(140, 44)) as pilot:
            app.query_one("#prompt").value = "which USB device was connected?"
            await pilot.press("enter")
            for _ in range(80):
                await pilot.pause(0.02)
                if not app.running:
                    break
            assert app._pending_review
            waiting = len(app._pending_review)
            overlay = _text(app._status_renderable(), 100)
            assert "0 accepted" in overlay
            assert f"{waiting} awaiting review" in overlay

            exchange, card = app._pending_review.pop(0)
            await app._accept_finding(exchange, card)
            overlay = _text(app._status_renderable(), 100)
            assert "1 accepted" in overlay
            assert f"{waiting - 1} awaiting review" in overlay
            # The run's own accounting, exactly as the ControlCard recorded it.
            assert "last message" in overlay
            assert f"{app._last_result.controls.tool_calls} tool calls" in overlay

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# A3 — one rule for every fixed-argument command
# ---------------------------------------------------------------------------
def test_a_bare_fixed_set_command_opens_its_chooser_on_the_current_value():
    async def scenario():
        app = build_app(DemoController())
        async with app.run_test(size=(140, 44)) as pilot:
            await pilot.pause(0.2)

            app.dispatch_command("layout", "")
            await pilot.pause(0.15)
            assert isinstance(app.screen, ChoiceScreen)
            view = app.screen.query_one("#choice-list", ListView)
            names = [name for name, _what in type(app).LAYOUTS]
            assert names[view.index] == app._layout
            await pilot.press("escape")
            await pilot.pause(0.1)
            assert app._layout == "full", "Esc changed the setting"

            app.dispatch_command("language", "")
            await pilot.pause(0.15)
            assert isinstance(app.screen, ChoiceScreen)
            from forensic_agent.cli import i18n

            view = app.screen.query_one("#choice-list", ListView)
            assert i18n.SUPPORTED_LANGUAGES[view.index] == i18n.current_language()
            before = i18n.current_language()
            await pilot.press("escape")
            await pilot.pause(0.1)
            assert i18n.current_language() == before

            app.dispatch_command("theme", "")
            await pilot.pause(0.15)
            assert isinstance(app.screen, ChoiceScreen)
            view = app.screen.query_one("#choice-list", ListView)
            assert M.available_palettes()[view.index] == M.active_palette_name()
            await pilot.press("escape")
            await pilot.pause(0.1)
            assert M.active_palette_name() == "dfir-tokyo"

    asyncio.run(scenario())


def test_a_valid_argument_acts_directly_with_no_chooser():
    async def scenario():
        app = build_app(DemoController())
        async with app.run_test(size=(140, 44)) as pilot:
            await pilot.pause(0.2)
            app.dispatch_command("layout", "simple")
            await pilot.pause(0.2)
            assert not isinstance(app.screen, ChoiceScreen)
            assert app._layout == "simple"

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("command", "argument", "accepted"),
    [
        ("layout", "sideways", "simple"),
        ("language", "klingon", "hr"),
        ("clear", "evidence", "all"),
        ("effort", "enormous", "high"),
        ("history", "lots", "number"),
        ("oversight", "everything", "calls"),
    ],
)
def test_an_unrecognised_argument_is_named_and_nothing_opens(
    command, argument, accepted
):
    """It must not silently fall through to the chooser as if nothing was typed."""

    async def scenario():
        app = build_app(DemoController())
        async with app.run_test(size=(140, 44)) as pilot:
            await pilot.pause(0.2)
            app._controller.is_demo = False  # /history and /effort are live-only
            app.dispatch_command(command, argument)
            await pilot.pause(0.2)
            assert not isinstance(app.screen, ChoiceScreen | OverlayScreen)
            said = " ".join(str(note.message) for note in app._notifications)
            assert argument in said, f"/{command} did not name {argument!r}"
            assert accepted in said, f"/{command} did not list what it takes"

    asyncio.run(scenario())


def test_an_unknown_theme_still_shows_the_swatches():
    """/theme is the one fixed set whose values are colours, so its refusal
    shows what they look like rather than only what they are called."""

    async def scenario():
        app = build_app(DemoController())
        async with app.run_test(size=(140, 44)) as pilot:
            await pilot.pause(0.2)
            app.dispatch_command("theme", "solarized")
            await pilot.pause(0.2)
            assert isinstance(app.screen, OverlayScreen)
            body = app.screen.query_one("#overlay-body", VerticalScroll)
            listing = _widget_text(body.query_one(Static), 90)
            assert "solarized" in listing
            for name in M.available_palettes():
                assert name in listing
            assert M.active_palette_name() == "dfir-tokyo"

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# A21 — the two conversation arrows
# ---------------------------------------------------------------------------
def test_both_bubble_arrows_sit_one_cell_from_their_border():
    async def scenario():
        app = build_app(DemoController())
        async with app.run_test(size=(140, 44)) as pilot:
            await pilot.pause(0.2)
            result = DemoController().run("who plugged it in?", lambda _e: None)
            you = _text(app._you_bubble("who plugged it in?", 1), 100).split("\n")
            agent = _text(app._agent_bubble(result, 1), 100).split("\n")

            you_row = next(line for line in you if "▶" in line)
            agent_row = next(line for line in agent if "◀" in line)
            # One blank cell between the arrow and the bubble border, both sides.
            assert you_row.rstrip().endswith("│ ▶")
            assert agent_row.lstrip().startswith("◀ ")
            assert agent_row.index("◀") == 0

            # And each arrow marks the row carrying the first line of text —
            # which is one row further down in the padded answer bubble, so a
            # single "\n" pointed the ◀ at blank padding.
            assert "who plugged it in?" in you_row
            body_rows = [
                index
                for index, line in enumerate(agent)
                if line.strip("◀│ ") and "─" not in line
            ]
            assert agent.index(agent_row) == body_rows[0]

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# A2 / A8 — completing a case, and where it is filed
# ---------------------------------------------------------------------------
def _live_app():
    from test_tui_console import _FakeLiveController

    controller = _FakeLiveController()
    return controller, build_app(controller)


def test_bare_complete_still_takes_one_confirmation_and_no_more():
    """The operator who wants the default must not be walked through a path."""

    async def scenario():
        controller, app = _live_app()
        async with app.run_test(size=(140, 44)) as pilot:
            await pilot.pause(0.3)
            app.dispatch_command("complete", "")
            await pilot.pause(0.2)
            assert isinstance(app.screen, ChoiceScreen)
            await pilot.press("enter")
            for _ in range(80):
                await pilot.pause(0.05)
                if controller.session.completed:
                    break
            assert controller.session.completed == [None]

    asyncio.run(scenario())


def test_completing_returns_the_console_to_the_opening_state():
    """Cleared and welcoming, and only after the receipt has been dismissed."""

    async def scenario():
        controller, app = _live_app()
        async with app.run_test(size=(140, 44)) as pilot:
            await pilot.pause(0.3)
            app._exchange = 3
            app._begin_run_panes()
            await pilot.pause(0.2)
            app.dispatch_command("complete", "")
            await pilot.pause(0.2)
            await pilot.press("enter")
            for _ in range(80):
                await pilot.pause(0.05)
                if isinstance(app.screen, OverlayScreen):
                    break
            # The paths are acknowledged BEFORE anything is cleared away.
            assert isinstance(app.screen, OverlayScreen)
            body = app.screen.query_one("#overlay-body", VerticalScroll)
            assert "Case marked complete" in _widget_text(body.query_one(Static), 90)
            conversation = app.query_one("#conversation", VerticalScroll)
            assert len(conversation.children) > 0

            await pilot.press("escape")
            for _ in range(80):
                await pilot.pause(0.05)
                if not isinstance(app.screen, OverlayScreen):
                    break
            await pilot.pause(0.4)
            rendered = "\n".join(
                _widget_text(child, 90) for child in conversation.children
            )
            assert "Session" in rendered, "the opening Session panel is not back"
            assert "Case completed and closed" in rendered
            # The closed case's instruments went with it.
            activity = app.query_one("#activity", VerticalScroll)
            assert not list(activity.query("#sep-3"))
            assert app._evidence_cards == []
            assert app._pending_review == []
            # And the message number is NOT rewound; the history keeps counting.
            assert app._exchange == 3

    asyncio.run(scenario())


def test_a_failed_completion_clears_nothing():
    async def scenario():
        controller, app = _live_app()

        def refuse(path=None):
            raise RuntimeError("the declaration could not be written")

        controller.session.complete_case = refuse
        async with app.run_test(size=(140, 44)) as pilot:
            await pilot.pause(0.3)
            app.dispatch_command("complete", "")
            await pilot.pause(0.2)
            await pilot.press("enter")
            rendered = ""
            for _ in range(80):
                await pilot.pause(0.05)
                rendered = "\n".join(
                    _widget_text(child, 90)
                    for child in app.query_one("#conversation", VerticalScroll).children
                )
                if "Completion stopped" in rendered:
                    break
            assert "Completion stopped" in rendered
            # The case is still open, and its transcript is still the record of
            # a live investigation.
            assert controller.session.cleared == 0
            assert "Session" not in rendered.split("Completion stopped")[1]

    asyncio.run(scenario())


def test_choosing_a_destination_offers_a_folder_and_a_base_name(tmp_path):
    """The middle option, and it reaches the worker as the path it built."""

    async def scenario():
        controller, app = _live_app()
        controller.session.run_root = tmp_path
        async with app.run_test(size=(140, 44)) as pilot:
            await pilot.pause(0.3)
            app.dispatch_command("complete", "")
            await pilot.pause(0.2)
            assert isinstance(app.screen, ChoiceScreen)
            await pilot.press("down", "enter")
            await pilot.pause(0.2)
            assert isinstance(app.screen, PromptScreen)
            app.screen.query_one("#prompt-entry").value = str(tmp_path / "filed")
            await pilot.press("enter")
            await pilot.pause(0.2)
            assert isinstance(app.screen, PromptScreen)
            app.screen.query_one("#prompt-entry").value = "closing"
            await pilot.press("enter")
            for _ in range(80):
                await pilot.pause(0.05)
                if controller.session.completed:
                    break
            assert controller.session.completed == [
                str(tmp_path / "filed" / "closing.md")
            ]

    asyncio.run(scenario())


def test_an_existing_name_is_never_overwritten_silently(tmp_path):
    async def scenario():
        controller, app = _live_app()
        controller.session.run_root = tmp_path
        (tmp_path / "filed").mkdir()
        (tmp_path / "filed" / "closing.md").write_text("already here", encoding="utf-8")
        async with app.run_test(size=(140, 44)) as pilot:
            await pilot.pause(0.3)
            app.dispatch_command("complete", "")
            await pilot.pause(0.2)
            await pilot.press("down", "enter")
            await pilot.pause(0.2)
            app.screen.query_one("#prompt-entry").value = str(tmp_path / "filed")
            await pilot.press("enter")
            await pilot.pause(0.2)
            app.screen.query_one("#prompt-entry").value = "closing"
            await pilot.press("enter")
            await pilot.pause(0.3)
            # It says what is in the way rather than writing over it.
            assert isinstance(app.screen, ChoiceScreen)
            assert "closing.md already exists" in app.screen._title
            assert controller.session.completed == []
            # Cancelling completes nothing at all.
            await pilot.press("down", "down", "enter")
            await pilot.pause(0.3)
            assert controller.session.completed == []
            assert controller.session.cleared == 0

    asyncio.run(scenario())


def test_a_call_with_attributes_but_no_entries_is_not_headed_zero_records():
    """The heading counted entries while the block also rendered attributes.

    A call that recorded attributes and no numbered entries printed
    ``recorded records (0)`` immediately above a screen of them, which reads as
    the console contradicting itself about what it is showing.
    """

    from rich.console import Console as _Console

    from forensic_agent.tui.demo_data import DEMO_FINDINGS

    card = DEMO_FINDINGS[0]

    def render(records):
        controller, app = _live_app()
        app._controller.finding_records = lambda _card: records  # type: ignore[assignment]
        console = _Console(record=True, width=100, file=io.StringIO())
        console.print(app._review_detail(card))
        return console.export_text()

    only_attributes = render({"items": [], "attributes": {"owner": "SYSTEM"}})
    assert "RECORDED RECORDS (0)" not in only_attributes
    assert "WHAT THIS CALL RECORDED" in only_attributes
    assert "owner=SYSTEM" in only_attributes

    with_entries = render({"items": [{"name": "a"}, {"name": "b"}], "attributes": {}})
    assert "RECORDED RECORDS (2)" in with_entries


# ---------------------------------------------------------------------------
# A2 — the conversation's own spacing
# ---------------------------------------------------------------------------
async def _ask(app, pilot, question: str) -> None:
    """One message, from the prompt, exactly as an operator sends it."""

    app.query_one("#prompt").focus()
    await pilot.pause(0.05)
    app.query_one("#prompt").value = question
    await pilot.press("enter")
    for _ in range(600):
        await pilot.pause(0.02)
        if not app.running:
            break
    await pilot.pause(0.2)


def _conversation_rows(app):
    """(id, top row in the scrollback, height, text) for every widget in it."""

    pane = app.query_one("#conversation", VerticalScroll)
    offset = pane.scroll_y
    return [
        (
            child.id,
            child.region.y + offset,
            child.region.height,
            _widget_text(child, 90).strip(),
        )
        for child in pane.children
    ]


def _blank_rows_per_exchange(rows) -> list[int]:
    """How many blank rows each exchange contributes, in order.

    An exchange runs from its question bubble to the next one, so this counts
    what the exchange itself left behind and never the opening screen's own
    blanks. One row per exchange is the invariant; the numbers this returns are
    what a drifting separator shows up in.
    """

    counts: list[int] = []
    for widget_id, _top, height, text in rows:
        if widget_id and widget_id.startswith("q-"):
            counts.append(0)
        elif counts and height == 1 and text == "":
            counts[-1] += 1
    return counts


def test_the_gap_between_exchanges_is_the_same_at_every_exchange():
    """One separator, one row, wherever an exchange ends.

    The parts of an exchange each used to end themselves — the answer wrote a
    blank, the review queue wrote two more around its hint, the simple layout's
    inline block wrote a fourth — so the distance from one exchange to the next
    was the sum of whatever that exchange happened to produce. Asserted at
    three exchange counts and off the rendered geometry, not off the code that
    writes it.
    """

    async def scenario(count: int):
        app = build_app(DemoController())
        async with app.run_test(size=(140, 44)) as pilot:
            await pilot.pause(0.3)
            for index in range(count):
                await _ask(app, pilot, f"question {index + 1}")
            rows = _conversation_rows(app)
            tops = {
                int(widget_id[2:]): top
                for widget_id, top, _height, _text in rows
                if widget_id and widget_id.startswith("q-")
            }
            order = sorted(tops)
            assert order == list(range(1, count + 1))
            pitches = {tops[b] - tops[a] for a, b in zip(order[:-1], order[1:], strict=True)}
            assert len(pitches) <= 1, f"{count} exchanges drifted apart: {pitches}"

            # And the separator itself: one blank row per exchange, wherever
            # that exchange ended.
            assert _blank_rows_per_exchange(rows) == [1] * count

    for exchanges in (1, 3, 6):
        asyncio.run(scenario(exchanges))


def test_an_answer_with_no_findings_is_separated_like_every_other():
    """The gap must not depend on what the exchange produced.

    A run that published nothing skips the review hint, and with each part
    writing its own trailing blank that made its separator two rows where an
    answer with findings had four.
    """

    async def scenario():
        app = build_app(DemoController())
        async with app.run_test(size=(140, 44)) as pilot:
            await pilot.pause(0.3)
            await _ask(app, pilot, "one with findings")
            barren = dataclasses.replace(app._last_result, findings=(), note="")
            app._exchange += 1
            app._write_you("one without findings")
            app._render_result(barren)
            await pilot.pause(0.3)
            app._exchange += 1
            app._write_you("and one more with findings")
            app._render_result(app._last_result)
            await pilot.pause(0.3)

            # The middle exchange published nothing and the two around it did;
            # all three cost the conversation the same one blank row.
            assert _blank_rows_per_exchange(_conversation_rows(app)) == [1, 1, 1]

    asyncio.run(scenario())


def test_a_resize_keeps_the_end_of_the_transcript_in_view():
    """Re-wrapping changes the row count; the scroll offset does not follow.

    A six-exchange conversation grows by twenty rows when the console narrows,
    so a pane that was showing the newest answer came back showing an older one
    with everything since below the fold. A pane the operator had scrolled back
    is left exactly where they left it.
    """

    async def scenario(scrolled_back: bool):
        app = build_app(DemoController())
        async with app.run_test(size=(200, 60)) as pilot:
            await pilot.pause(0.3)
            for index in range(6):
                await _ask(app, pilot, f"question {index + 1}")
            pane = app.query_one("#conversation", VerticalScroll)
            assert pane.scroll_y == pane.max_scroll_y
            if scrolled_back:
                pane.scroll_to(y=10, animate=False)
                await pilot.pause(0.2)
            await pilot.resize_terminal(120, 40)
            await pilot.pause(0.8)
            if scrolled_back:
                assert pane.scroll_y < pane.max_scroll_y
            else:
                assert pane.scroll_y == pane.max_scroll_y

    asyncio.run(scenario(False))
    asyncio.run(scenario(True))


# ---------------------------------------------------------------------------
# A3 — the finding review card
# ---------------------------------------------------------------------------
def _pcap_card_and_records():
    """A DNS page shaped exactly as the recorded envelope carries one.

    The shape matters and is not invented: a live ``pcap_query.dns`` records
    ``items`` as bare positional lists AND ``named_rows`` as the same page with
    the field names attached, plus a ``top_query_names`` distribution that is a
    second table in its own right.
    """

    from forensic_agent.tui.model import FindingCard

    fields = [
        "frame.number",
        "ip.src",
        "ip.dst",
        "dns.qry.name",
        "dns.qry.type",
    ]
    positional = [
        [str(number), "192.168.30.57", "192.168.22.1", f"{number}-sample.evil.hr", "1"]
        for number in range(1, 4)
    ]
    rows = [
        {
            "frame.number": str(number),
            "ip.src": "192.168.30.57",
            "ip.dst": "192.168.22.1",
            "dns.qry.name": f"{number}-sample.evil.hr",
            "dns.qry.type": "1",
        }
        for number in range(1, 4)
    ]
    card = FindingCard(
        sequence=1,
        status="ok",
        function="pcap_query",
        operation="dns",
        data_type="network.capture_records",
        records="44/179 records",
        coverage_label="complete",
        coverage_complete=True,
        coverage_scope="",
        coverage_reason="",
        receipt_full="9c11743536637f836199db19b332c477c35491d18f6a4187ccb81ba6af35b6f6",
        arguments=(("operation", "dns"), ("limit", "200")),
        result_summary="operation=dns  limit=200",
        source_id="case-evidence-bundle-sha256:3bfe1f54",
        source_uri="evidence-bundle://sha256/3bfe1f54",
        evidence_class="observed",
        warnings=(),
        oversight_sequence=None,
        label="dns",
    )
    records = {
        "items": positional,
        "attributes": {
            "available_sources": [
                {"basename": "artifact://private/redacted-source", "role": "pcap"}
            ],
            "source_input_component_ids": [],
            "output": "",
            "cardinality_truncated": True,
            "distinct_query_names": 179,
            "fields": fields,
            "named_rows": rows,
            "top_query_names": [["a.evil.hr", 2], ["b.evil.hr", 1]],
        },
    }
    return card, records


def _network_app():
    """A live console whose one attached source is the capture."""

    controller, app = _live_app()
    controller._status = dataclasses.replace(
        controller._status, evidence_sources=("network: promet.pcap",)
    )
    return controller, app


def test_the_card_says_what_the_call_looked_at_in_one_sentence():
    """A function name, a verb and a placeholder named nothing.

    The count was stranded on the line below as a fragment whose subject was on
    the line above. The call took no narrower target than the whole capture, so
    the capture is what the card names — by the name the Session panel shows.
    """

    async def scenario():
        card, records = _pcap_card_and_records()
        _controller, app = _network_app()
        async with app.run_test(size=(140, 44)) as pilot:
            await pilot.pause(0.3)
            app._controller.finding_records = lambda _card: records
            rendered = _text(app._review_detail(card), 94)

        assert (
            "pcap_query.dns examined promet.pcap and recorded 44 of 179 records."
            in rendered
        )
        assert "the evidence source" not in rendered
        assert "It recorded" not in rendered
        # And the coverage names what was read in full, rather than leaving the
        # phrase without an object.
        assert "read promet.pcap in full" in rendered

    asyncio.run(scenario())


def test_the_recorded_rows_are_a_table_and_the_run_record_stays_behind():
    """Forty-four rows of five fields are a table, not a serialised dict.

    The field names belong in one heading row; the plumbing that says which
    capture components existed belongs to the run record, which this does not
    touch, and not to an examiner deciding whether to accept a finding.
    """

    async def scenario():
        card, records = _pcap_card_and_records()
        _controller, app = _network_app()
        async with app.run_test(size=(140, 44)) as pilot:
            await pilot.pause(0.3)
            app._controller.finding_records = lambda _card: records
            rendered = _text(app._review_detail(card), 94)

        lines = [line.rstrip() for line in rendered.splitlines()]
        heading = next(line for line in lines if "dns.qry.name" in line)
        # One heading row carrying every field name, and no key=value pairs.
        for field in ("frame.number", "ip.src", "ip.dst", "dns.qry.type"):
            assert field in heading
            assert rendered.count(field + "=") == 0
        # The values are under it, one row each.
        assert "1-sample.evil.hr" in rendered
        assert "3-sample.evil.hr" in rendered
        # The rows are never also printed as a serialised attribute.
        assert "named_rows=" not in rendered
        assert "fields=" not in rendered
        # Run-record plumbing and empty attributes are off the card.
        assert "available_sources" not in rendered
        assert "artifact://private/redacted-source" not in rendered
        assert "source_input_component_ids" not in rendered
        assert "output=" not in rendered
        # What the call actually observed is still there.
        assert "cardinality_truncated=True" in rendered
        assert "distinct_query_names=179" in rendered
        # And a recorded distribution is a table of its own, not a paragraph.
        assert "top_query_names (2)" in rendered
        assert "top_query_names=" not in rendered
        assert "a.evil.hr" in rendered
        # Headings are uppercase, like the pane titles they sit between.
        assert "RECORDED RECORDS (3)" in rendered
        assert "COMMAND" in rendered and "COVERAGE" in rendered
        assert "WHERE THIS CAME FROM" in rendered

    asyncio.run(scenario())


def test_nothing_on_the_card_carries_information_in_the_dim_colour():
    """One colour rule: names in the accent, everything readable in TEXT.

    The palette was raised for contrast once already; a card that puts a
    record's keys, its provenance sentences and its receipt label back into DIM
    spends that contrast on the parts a reviewer has to read.
    """

    async def scenario():
        from rich.console import Console as _Console

        from forensic_agent.tui import model as _M

        card, records = _pcap_card_and_records()
        _controller, app = _network_app()
        async with app.run_test(size=(140, 44)) as pilot:
            await pilot.pause(0.3)
            app._controller.finding_records = lambda _card: records
            console = _Console(
                record=True, width=94, file=io.StringIO(), color_system="truecolor"
            )
            console.print(app._review_detail(card))
            exported = console.export_html(inline_styles=True)

        dim = _M.DIM.lstrip("#").lower()
        assert dim not in exported.lower()

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# A4 — getting a value off the card
# ---------------------------------------------------------------------------
def test_the_card_can_be_copied_and_says_whether_it_arrived(monkeypatch):
    """OSC 52 or an explanation — never a key that silently does nothing."""

    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.delenv("TERM_PROGRAM", raising=False)
    monkeypatch.delenv("TMUX", raising=False)

    async def scenario():
        card, records = _pcap_card_and_records()
        _controller, app = _network_app()
        async with app.run_test(size=(140, 44)) as pilot:
            await pilot.pause(0.3)
            app._controller.finding_records = lambda _card: records
            app._pending_review.append((1, card))
            app.action_review()
            for _ in range(80):
                await pilot.pause(0.05)
                if isinstance(app.screen, ReviewScreen):
                    break
            assert isinstance(app.screen, ReviewScreen)
            box = app.screen.query_one("#overlay-box")
            assert "y accept   n reject   esc later" in box.border_subtitle
            assert "c copy card   C receipt" in box.border_subtitle

            written: list[str] = []
            monkeypatch.setattr(app._driver, "write", written.append)

            await pilot.press("C")
            await pilot.pause(0.2)
            assert app.clipboard == card.receipt_full
            assert any("\x1b]52;c;" in chunk for chunk in written)

            await pilot.press("c")
            await pilot.pause(0.2)
            # The whole card, and every identifier on one line ready to paste.
            assert card.receipt_full in app.clipboard
            assert "promet.pcap" in app.clipboard
            assert "case-evidence-bundle-sha256:3bfe1f54" in app.clipboard
            assert all(len(line) <= 200 for line in app.clipboard.splitlines())

    asyncio.run(scenario())


def test_a_terminal_that_cannot_take_a_copy_is_told_so(monkeypatch):
    """The refusal is the interface, not a silent no-op."""

    from forensic_agent.tui.app import _copy_obstacles

    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.delenv("TERM_PROGRAM", raising=False)
    monkeypatch.delenv("TMUX", raising=False)
    assert _copy_obstacles(object()) == ("", "")

    monkeypatch.setenv("TERM", "dumb")
    refusal, _caveat = _copy_obstacles(object())
    assert "dumb" in refusal

    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setenv("TERM_PROGRAM", "Apple_Terminal")
    refusal, _caveat = _copy_obstacles(object())
    assert "macOS Terminal" in refusal

    monkeypatch.delenv("TERM_PROGRAM", raising=False)
    monkeypatch.setenv("TMUX", "/tmp/tmux-1000/default,1,0")
    refusal, caveat = _copy_obstacles(object())
    assert refusal == "" and "set-clipboard" in caveat

    # No terminal at all: nothing is written and the console says why.
    monkeypatch.delenv("TMUX", raising=False)
    refusal, _caveat = _copy_obstacles(None)
    assert "not attached to a terminal" in refusal

    async def scenario():
        card, _records = _pcap_card_and_records()
        _controller, app = _network_app()
        async with app.run_test(size=(140, 44)) as pilot:
            await pilot.pause(0.3)
            monkeypatch.setenv("TERM", "dumb")
            written: list[str] = []
            monkeypatch.setattr(app._driver, "write", written.append)
            assert app.copy_text(card.receipt_full, "The receipt") is False
            assert not any("\x1b]52;c;" in chunk for chunk in written)

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# A5 — /new against /clear
# ---------------------------------------------------------------------------
def test_new_clears_the_screen_it_invalidated_and_keeps_the_findings():
    """The display must not outlive the history that produced it.

    ``/new`` starts the next question from nothing, so the previous questions,
    their tool calls and their guardrail decisions go. The case, its evidence
    and the findings do not: accepting a finding is a statement about the
    evidence, and ``/new`` is the command that keeps the evidence. Whatever
    survives is named on screen rather than left to be inferred from a list
    that quietly changed length.
    """

    async def scenario():
        card, _records = _pcap_card_and_records()
        controller, app = _network_app()
        async with app.run_test(size=(140, 44)) as pilot:
            await pilot.pause(0.3)
            app._exchange = 2
            app._begin_run_panes()
            app._write_you("something already asked")
            app._pending_review.append((2, card))
            await app._accept_finding(2, card)
            await pilot.pause(0.3)
            activity = app.query_one("#activity", VerticalScroll)
            evidence = app.query_one("#evidence-pane", VerticalScroll)
            assert list(activity.query(Collapsible))
            assert list(evidence.query(Collapsible))

            app.dispatch_command("new", "")
            for _ in range(80):
                await pilot.pause(0.05)
                if controller.session.new_histories:
                    break
            await pilot.pause(0.8)

            # The history really rotated, and the case was never touched.
            assert controller.session.new_histories == [None]
            assert controller.session.cleared == 0

            rendered = "\n".join(
                _widget_text(child, 90)
                for child in app.query_one("#conversation", VerticalScroll).children
            )
            assert "something already asked" not in rendered
            assert "New investigation history" in rendered
            assert "the case and its evidence stay open" in rendered
            assert "1 accepted as evidence" in rendered
            assert "1 still awaiting review" in rendered

            # ACTIVITY and GUARDRAILS belonged to the discarded history.
            assert not list(activity.query(Collapsible))
            # The accepted evidence did not.
            assert list(evidence.query(Collapsible))
            assert len(app._evidence_cards) == 1
            assert len(app._pending_review) == 1

    asyncio.run(scenario())


def test_clear_changes_nothing_but_the_screen_and_says_what_is_pending():
    """/clear is the terminal, /new is the investigation.

    /clear keeps the instruments, the review queue and the message number, and
    puts back the one statement the cleared conversation was carrying.
    """

    async def scenario():
        card, _records = _pcap_card_and_records()
        controller, app = _network_app()
        async with app.run_test(size=(140, 44)) as pilot:
            await pilot.pause(0.3)
            app._exchange = 4
            app._begin_run_panes()
            app._pending_review.append((4, card))
            await pilot.pause(0.2)

            app.dispatch_command("clear", "")
            await pilot.pause(0.8)

            assert controller.session.new_histories == []
            assert controller.session.cleared == 0
            assert app._exchange == 4
            assert len(app._pending_review) == 1
            # The instruments are untouched — that is the whole difference.
            assert list(app.query_one("#activity", VerticalScroll).query(Collapsible))

            rendered = "\n".join(
                _widget_text(child, 90)
                for child in app.query_one("#conversation", VerticalScroll).children
            )
            assert "New investigation history" not in rendered
            assert "1 finding from the cleared screen" in rendered

    asyncio.run(scenario())
