"""Three console surfaces that hid, captured or buried what the operator needed.

* A refused call named its ground LAST, under two lines that are written only
  where the policy PERMITTED the call, so a short pane truncated the cause away
  and led with a sentence that said the opposite of what happened.
* Typing ``/`` opened the command palette, which took the keyboard: the palette
  matched a command and ran the bare form of it, so ``/clear all`` could not be
  typed at all.
* GUARDRAILS grouped its decisions per exchange like ACTIVITY, but its groups
  carried no identity, so the digit keys that narrow ACTIVITY to one exchange
  had nothing to reach in it.

None of these touches what a run records. They are all read-time.
"""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("textual")

from textual.containers import VerticalScroll  # noqa: E402
from textual.widgets import Collapsible, Input  # noqa: E402

from forensic_agent.tui import build_app  # noqa: E402
from forensic_agent.tui.controller import DemoController  # noqa: E402
from forensic_agent.tui.model import OversightCard  # noqa: E402


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr("forensic_agent.tui.controller.time.sleep", lambda *_: None)


# ---------------------------------------------------------------------------
# The refusal panel leads with the cause
# ---------------------------------------------------------------------------

#: The measured record: ``repo/runs/d33e2d30d59e43f8a761686612698d66``. The
#: policy PERMITTED this call (``allowed: true``) and the argument model refused
#: it, and the record puts the ground of that refusal last.
_MEASURED_REASONS = (
    "writes to host disk",
    "spawns external process",
    "invalid-arguments:invalid_operation_arguments",
)
_MEASURED_MESSAGE = (
    "pcap_query arguments were refused before any evidence access.\n"
    "proto: not an argument of this operation, which takes source?, fields, "
    "display_filter?, limit?, offset?, filter?."
)


def _measured_card(**overrides) -> OversightCard:
    fields = {
        "sequence": 2,
        "function": "pcap_query",
        "operation": "dns",
        "outcome": "refused_by_oversight",
        "requested_caps": ("read_evidence", "spawn_process", "write"),
        "granted_caps": ("read_evidence", "spawn_process", "write"),
        "allowed_tools": None,
        "write_scope": (),
        "risk_name": "low",
        "reasons": _MEASURED_REASONS,
        "duration_s": 0.0001657,
        "arguments": (("operation", "dns"), ("proto", "dicom")),
        "refusal_message": _MEASURED_MESSAGE,
    }
    fields.update(overrides)
    return OversightCard(**fields)


def _rendered_lines(card: OversightCard) -> list[str]:
    lines: list[str] = []

    async def scenario():
        app = build_app(DemoController())
        async with app.run_test(size=(120, 40)):
            for text in app._denial_detail(card).renderables:
                lines.append(str(text))

    asyncio.run(scenario())
    return lines


def test_a_refused_call_states_its_ground_first():
    """The readable sentence leads; the capability description is not the lede."""

    lines = _rendered_lines(_measured_card())
    assert lines[0] == "pcap_query arguments were refused before any evidence access."
    assert lines[1].startswith("proto: not an argument of this operation")
    # The two lines the owner read as the block are still shown, but last: they
    # describe what the tool does and are written only where the policy allowed
    # the call, so they can never be the ground of a refusal.
    assert lines[-2:] == ["writes to host disk", "spawns external process"]
    # Nothing recorded is dropped.
    for reason in _MEASURED_REASONS:
        assert reason in lines


def test_the_cause_is_shown_once_even_though_two_sources_carry_it():
    """The record now leads with the same sentence the output preview carries.

    Both are read — the preview because it is the fuller text, the reasons
    because a refusal may record no preview at all — and the line they share is
    exactly the one that matters, so an unguarded render printed the cause
    twice.
    """

    # The reason list as ``enforce()`` now writes it: cause, code, description.
    card = _measured_card(
        reasons=(
            "proto: not an argument of this operation, which takes source?, fields, "
            "display_filter?, limit?, offset?, filter?.",
            "invalid-arguments:invalid_operation_arguments",
            "writes to host disk",
            "spawns external process",
        )
    )
    lines = _rendered_lines(card)
    repeated = [line for line in lines if line.startswith("proto: not an argument")]
    assert len(repeated) == 1
    # The code is not part of the message, so it is still shown.
    assert "invalid-arguments:invalid_operation_arguments" in lines


def test_a_short_pane_truncates_the_description_and_not_the_cause():
    """The pane is five lines tall; what survives a cut has to be the why."""

    lines = _rendered_lines(_measured_card())
    survives = lines[:3]
    assert any("not an argument of this operation" in line for line in survives)
    assert "writes to host disk" not in survives


def test_a_policy_denial_leads_with_the_policy_ground():
    """No readable sentence recorded: the deciding reason is the lede instead."""

    lines = _rendered_lines(
        _measured_card(
            reasons=("unknown tool 'delivered_file_query' denied (deny-by-default)",),
            refusal_message="",
            requested_caps=("unknown",),
        )
    )
    assert lines[0] == "unknown tool 'delivered_file_query' denied (deny-by-default)"


def test_a_refusal_with_no_ground_recorded_says_so():
    """Better an explicit absence than a capability description standing in."""

    lines = _rendered_lines(
        _measured_card(reasons=("writes to host disk",), refusal_message="")
    )
    assert lines[0] == "no ground recorded for this refusal"


def test_the_reason_split_is_read_off_the_module_that_writes_them():
    """One transcript of these strings, in the code that appends them."""

    from forensic_agent.oversight.policy import (
        CAPABILITY_DESCRIPTION_REASONS,
        partition_reasons,
    )

    deciding, describing = partition_reasons(_MEASURED_REASONS)
    assert deciding == ("invalid-arguments:invalid_operation_arguments",)
    assert describing == ("writes to host disk", "spawns external process")
    # A qualified description is still a description.
    assert partition_reasons(("read-only evidence access within granted authority",))[
        1
    ] == ("read-only evidence access within granted authority",)
    # An unrecognised reason on a refused call is treated as its ground.
    assert partition_reasons(("something nobody has written yet",))[0] == (
        "something nobody has written yet",
    )
    assert "spawns external process" in CAPABILITY_DESCRIPTION_REASONS


def test_the_readable_sentence_is_read_back_out_of_the_recorded_output():
    """The record keeps a code; the sentence lives in the recorded output."""

    from forensic_agent.cli.presentation import executed_calls

    # A preview cut mid-object by the recorder's 500-character bound, exactly as
    # a long validator report leaves it.
    truncated = (
        '{"error": {"code": "invalid_operation_arguments", "tool": "pcap_query", '
        '"message": "pcap_query arguments were refused before any evidence access.'
        '\\nproto: not an argument of this operation.'
        '\\nValidator detail: 1 validation error for tagged-union[PcapDns'
    )
    (call,) = executed_calls(
        [
            {"event": "case_open", "case_id": "c"},
            {
                "event": "action",
                "case_id": "c",
                "seq": 2,
                "tool": "pcap_query",
                "args": {"operation": "dns"},
                "allowed": True,
                "outcome": "refused_by_oversight",
                "outcome_detail": "invalid_operation_arguments",
                "reasons": list(_MEASURED_REASONS),
                "output_preview": truncated,
            },
        ]
    )
    assert call.refusal_message == (
        "pcap_query arguments were refused before any evidence access.\n"
        "proto: not an argument of this operation."
    )
    # A policy denial states its whole ground in the reasons, so nothing is
    # lifted out of "BLOCKED by oversight policy".
    (denied,) = executed_calls(
        [
            {"event": "case_open", "case_id": "c"},
            {
                "event": "action",
                "case_id": "c",
                "seq": 0,
                "tool": "nope",
                "args": {},
                "allowed": False,
                "outcome": "refused_by_oversight",
                "reasons": ["unknown tool 'nope' denied (deny-by-default)"],
                "output_preview": '{"error": "BLOCKED by oversight policy"}',
            },
        ]
    )
    assert denied.refusal_message == ""


# ---------------------------------------------------------------------------
# The command line suggests without capturing
# ---------------------------------------------------------------------------


def _prompt_scenario(steps):
    captured: list[tuple[str, str]] = []

    async def scenario():
        app = build_app(DemoController())
        async with app.run_test(size=(120, 40)) as pilot:
            app.dispatch_command = lambda name, argument: captured.append(  # type: ignore[method-assign]
                (name, argument)
            )
            prompt = app.query_one("#prompt", Input)
            prompt.focus()
            await steps(app, pilot, prompt)

    asyncio.run(scenario())
    return captured


def test_a_command_and_its_argument_both_reach_the_handler():
    """The measured failure: /clear all was impossible to type."""

    async def steps(_app, pilot, _prompt):
        for key in "/clear all":
            await pilot.press("space" if key == " " else key)
        await pilot.press("enter")

    assert _prompt_scenario(steps) == [("clear", "all")]


def test_enter_submits_what_was_typed_and_not_what_was_suggested():
    """A partly typed name is sent as typed; the suggestion is never the value."""

    seen: list[str] = []

    async def steps(app, pilot, prompt):
        app._handle_slash = lambda text: seen.append(text)  # type: ignore[method-assign]
        for key in "/clea":
            await pilot.press(key)
        await pilot.pause()
        await pilot.press("enter")

    _prompt_scenario(steps)
    assert seen == ["/clea"]


def test_tab_completes_the_name_and_leaves_room_for_an_argument():
    """An accepted suggestion ends ready for the argument, not welded to it."""

    values: list[str] = []

    async def steps(_app, pilot, prompt):
        for key in "/cle":
            await pilot.press(key)
        await pilot.pause()
        await pilot.press("tab")
        values.append(prompt.value)
        values.append(str(prompt.cursor_position))

    _prompt_scenario(steps)
    assert values[0] == "/clear "
    assert values[1] == str(len("/clear "))


def test_a_bare_command_still_works():
    async def steps(_app, pilot, _prompt):
        for key in "/status":
            await pilot.press(key)
        await pilot.press("enter")

    assert _prompt_scenario(steps) == [("status", "")]


def test_every_command_that_takes_an_argument_can_receive_one():
    """General, not special-cased for /clear: the whole registry is exercised.

    Every command whose usage names an argument is typed with one and must
    arrive at the handler with that argument intact.
    """

    from forensic_agent.cli.commands import COMMAND_REGISTRY

    with_arguments = [
        spec.name
        for spec in COMMAND_REGISTRY.commands
        if "[" in spec.usage or "<" in spec.usage
    ]
    assert len(with_arguments) >= 15  # the registry really does have many

    async def steps(_app, pilot, prompt):
        for name in with_arguments:
            prompt.value = ""
            for key in f"/{name} zulu":
                await pilot.press("space" if key == " " else key)
            await pilot.press("enter")

    assert _prompt_scenario(steps) == [(name, "zulu") for name in with_arguments]


def test_typing_a_slash_no_longer_empties_the_line():
    """The palette used to clear the input the moment the slash was typed."""

    kept: list[str] = []

    async def steps(_app, pilot, prompt):
        await pilot.press("/")
        await pilot.pause()
        kept.append(prompt.value)

    _prompt_scenario(steps)
    assert kept == ["/"]


def test_the_usage_line_is_shown_while_the_argument_is_typed():
    """Assistance that cannot swallow a keystroke, unlike the palette."""

    subtitles: list[str] = []

    async def steps(_app, pilot, prompt):
        for key in "/clear":
            await pilot.press(key)
        await pilot.pause()
        subtitles.append(str(prompt.border_subtitle))
        prompt.value = "what files were opened"
        await pilot.pause()
        subtitles.append(str(prompt.border_subtitle))

    from rich.text import Text

    _prompt_scenario(steps)
    # Rendered, not stored: the brackets have to survive markup parsing, and
    # they are the part of a usage line that says what the argument is.
    assert Text.from_markup(subtitles[0]).plain == "/clear [all]"
    assert subtitles[1] == ""


def test_the_completion_list_covers_names_and_aliases():
    from forensic_agent.tui.app import slash_completions

    completions = slash_completions()
    assert "/clear" in completions
    assert "/guardrails" in completions  # an alias of /oversight
    assert "/steps" in completions  # an alias of /budget
    assert completions == tuple(sorted(completions))


# ---------------------------------------------------------------------------
# GUARDRAILS narrows to one exchange
# ---------------------------------------------------------------------------


def test_guardrails_narrows_to_one_exchange_by_its_number():
    """Filtered to 02, only exchange 02's decisions are open."""

    async def scenario():
        app = build_app(DemoController())
        async with app.run_test(size=(120, 40)) as pilot:
            result = DemoController().run("q", lambda _event: None)
            for number in (1, 2, 3):
                app._exchange = number
                app._populate_guardrails(result)
                await pilot.pause(0.05)

            groups = {
                int((g.id or "").removeprefix("guardsep-")): g
                for g in app.query_one("#guardrails-pane", VerticalScroll).query(
                    Collapsible
                )
                if (g.id or "").startswith("guardsep-")
            }
            assert set(groups) == {1, 2, 3}

            app.action_jump(2)
            await pilot.pause(0.05)
            assert groups[2].collapsed is False
            assert groups[1].collapsed is True
            assert groups[3].collapsed is True

            # And the same key moves it on, rather than sticking on one number.
            app.action_jump(3)
            await pilot.pause(0.05)
            assert groups[3].collapsed is False
            assert groups[2].collapsed is True

    asyncio.run(scenario())


def test_the_digit_key_still_reaches_activity():
    """The guardrails half must not have taken the key away from ACTIVITY."""

    async def scenario():
        app = build_app(DemoController())
        async with app.run_test(size=(120, 40)) as pilot:
            app._exchange = 2
            app._begin_run_panes()
            await pilot.pause(0.1)
            group = app.query_one("#sep-2", Collapsible)
            group.collapsed = True
            app.action_jump(2)
            await pilot.pause(0.05)
            assert group.collapsed is False

    asyncio.run(scenario())
