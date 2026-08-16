"""Views over the oversight chain: what the model asked for, and what ran.

The oversight chain is the record an investigation is judged by, so the three
views here read it and never anything else — no value below is recomputed from
the evidence, and nothing here writes or re-runs a single call. They differ only
in how much of the record they show: ``/oversight`` reconstructs the run as
counts and a timeline, ``/oversight prompt`` prints the composed message the run
actually sent in full, and ``/oversight calls`` lists every recorded call with
its arguments exactly as the model passed them.

The reason the refusals are counted apart rather than summed is the question
these views exist to answer: a call the policy denied and a call the tool
declined are both refusals, but only the first is the gate doing its work, and
reporting them as one word would leave the operator unable to tell which layer
stopped what.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from forensic_agent.cli.i18n import t as _t
from forensic_agent.cli.presentation import (
    RECORDED_EXECUTED,
    RECORDED_FAILED,
    RECORDED_REFUSED_BY_OVERSIGHT,
    RECORDED_REFUSED_BY_TOOL,
    ExecutedCall,
    ExecutedCallArgument,
    GrantedAuthority,
    executed_calls,
    granted_authority,
    project_recorded_question,
)
from forensic_agent.cli.terminal import (
    ACCENT,
    BORDER,
    DIM,
    GLYPH_ERROR,
    GLYPH_OK,
    GLYPH_POINT,
    GLYPH_WARN,
    ORANGE,
    PANEL_BOX,
    RED,
    SUCCESS,
    TABLE_BOX,
    build_usage_renderable,
)
from forensic_agent.core.durations import format_duration

#: How every view reads one recorded call: its glyph, its colour and its one
#: name. Declared once and shared, because the reconstruction and the call
#: listing print the same entry side by side and must not give it two different
#: words. The two refusals stay apart because that is the question these views
#: exist to answer: a call the policy denied and a call the tool declined are
#: both refusals, but only the first is the gate doing its work, and reporting
#: them as one word would leave the operator unable to tell which layer stopped
#: what.
RECORDED_OUTCOME_DISPLAY: dict[str, tuple[str, str, str]] = {
    RECORDED_EXECUTED: (GLYPH_OK, SUCCESS, "ok"),
    RECORDED_FAILED: (GLYPH_WARN, ORANGE, "failed"),
    RECORDED_REFUSED_BY_OVERSIGHT: (GLYPH_ERROR, RED, "BLOCKED"),
    RECORDED_REFUSED_BY_TOOL: (GLYPH_ERROR, RED, "refused"),
}


def outcome_text(outcome: str) -> Text:
    """Render one recorded outcome as the single label every view prints."""

    glyph, colour, word = RECORDED_OUTCOME_DISPLAY[outcome]
    return Text(f"{glyph} {_t(word)}", style=colour)


def run_bound_entries(oversight_path: str | None) -> list[dict[str, Any]] | None:
    """Load the trace the current run bound to this view, or ``None``.

    A run binds its record by the absolute path it wrote into the private run
    directory.  A bare relative name is not a binding: it resolves against
    whatever directory the process happened to start in, and an unrelated
    ``oversight.jsonl`` sitting there was reconstructed and printed as this
    session's own accountability record, question and all.
    """

    if not oversight_path or not Path(oversight_path).is_absolute():
        return None

    from forensic_agent.oversight import OversightLog

    entries = OversightLog.load(oversight_path)
    return entries or None


def show_oversight(console: Console, *, oversight_path: str | None) -> None:
    from forensic_agent.oversight import reconstruct

    entries = run_bound_entries(oversight_path)
    if entries is None:
        console.print(
            f"[{DIM}]No oversight trace is available for a completed investigation.[/]"
        )
        return
    r = reconstruct(entries)
    console.print(
        f"\n[bold {ACCENT}]{GLYPH_POINT} {_t('Oversight decisions')}[/]"
    )
    # The trace records the whole message the model received, and rightly so.
    # This line is labelled "question", so it carries the question; what was
    # composed around it is counted, named, and left one command away rather
    # than emptied over the summary.
    asked = project_recorded_question(r.get("question"))
    console.print(
        f"  [{DIM}]{_t('question:')}[/] {escape(asked.asked)}"
    )
    if asked.has_context:
        # The command is on its own line, not at the end of the sentence: it
        # contains a space, so wrapping split "/oversight prompt" across two
        # rows at eighty columns and the one move this line exists to offer
        # could not be read off the screen.
        console.print(
            f"  [{DIM}]{_t('sent inside')} {asked.withheld_characters} "
            f"{_t('further characters of session context')}[/]"
        )
        console.print(
            f"  [{DIM}]{GLYPH_POINT} {_t('read it with')}[/] "
            f"[{ACCENT}]/oversight prompt[/]"
        )
    # "blocked" answers only whether the GATE denied a call, so on its own it
    # reported zero for a run in which calls had been refused. The counts
    # here account for every recorded call once: how many ran, how many were
    # refused by either layer, and how many ran and failed.
    console.print(
        f"  [{DIM}]{_t('tool calls:')}[/] {r['tool_calls']}   "
        f"[{SUCCESS}]{_t('ran:')}[/] {r['executed_calls']}   "
        f"[{RED}]{_t('refused:')}[/] {r['refused_calls']}   "
        f"[{ORANGE}]{_t('failed:')}[/] {r['failed_calls']}   "
        f"[{DIM}]{_t('maximum risk:')}[/] {r['max_risk']}"
    )
    if r["refused_calls"]:
        counts = r["outcome_counts"]
        console.print(
            f"  [{DIM}]{_t('of the refusals:')} "
            f"{counts[RECORDED_REFUSED_BY_OVERSIGHT]} "
            f"{_t('blocked by the oversight policy')}, "
            f"{counts[RECORDED_REFUSED_BY_TOOL]} "
            f"{_t('refused by the tool before it read anything')}[/]"
        )
    for t in r["timeline"]:
        sequence = escape(str(t.get("seq", "")))
        tool = escape(str(t.get("tool", "")))
        risk = escape(str(t.get("risk", "")))
        glyph, colour, word = RECORDED_OUTCOME_DISPLAY[str(t["outcome"])]
        mark = f"[{colour}]{glyph} {_t(word)}[/]"
        # The gate's reasons name why IT refused; the recorded detail names
        # what the tool or the failure declared. Neither is invented here.
        ground = (
            "; ".join(map(str, t["reasons"]))
            if t["outcome"] == RECORDED_REFUSED_BY_OVERSIGHT
            else str(t.get("detail") or "")
        )
        extra = f"  [{DIM}]{escape(ground)}[/]" if ground else ""
        console.print(
            f"   [{DIM}]#{sequence}[/] [bold]{tool}[/] {mark} "
            f"[{DIM}]risk={risk}[/]{extra}"
        )
    # On its own line for the same reason the prompt hint is: the command
    # carries a space, and a form the operator cannot read off the screen is a
    # form that does not exist.
    console.print(
        f"  [{DIM}]{GLYPH_POINT} {_t('one call in full:')}[/] "
        f"[{ACCENT}]/oversight <n>[/]"
    )
    console.print()


def show_oversight_prompt(
    console: Console,
    *,
    oversight_path: str | None,
    width: int,
) -> None:
    """Print the composed message the run actually sent, in full.

    The summary shows the question; this shows everything that travelled
    with it. What the model saw is the thing this view exists to make
    checkable, so nothing here is summarized. Rendered as :class:`Text`
    rather than as markup: a bracket in a prior answer is a bracket, and
    must not be read as a style tag and vanish from the record of it.
    """

    from forensic_agent.oversight import reconstruct

    entries = run_bound_entries(oversight_path)
    if entries is None:
        console.print(
            f"[{DIM}]No oversight trace is available for a completed investigation.[/]"
        )
        return
    asked = project_recorded_question(reconstruct(entries).get("question"))
    if not asked.composed:
        console.print(f"[{DIM}]{_t('The trace recorded no question.')}[/]")
        return
    console.print()
    console.print(
        Panel(
            Text(asked.composed),
            title=f"[bold]{GLYPH_POINT} {_t('Message sent to the model')}[/]",
            title_align="left",
            subtitle=(
                f"[{DIM}]{len(asked.composed)} {_t('characters')}[/]"
            ),
            subtitle_align="right",
            border_style=BORDER,
            box=PANEL_BOX,
            padding=(0, 1),
            width=width,
        )
    )
    console.print()


def call_arguments_cell(arguments: Sequence[ExecutedCallArgument]) -> Text:
    """Lay out one call's arguments, one per line, values intact.

    Built as :class:`Text` rather than markup because an argument value is
    arbitrary recorded input: a path or a pattern containing brackets would
    otherwise be read as a style tag and disappear from the very listing
    that exists to show it whole.
    """

    if not arguments:
        return Text("—", style=DIM)
    cell = Text()
    for index, argument in enumerate(arguments):
        if index:
            cell.append("\n")
        # The argument name is the model's own identifier and is never
        # translated; only the withheld marker and the bound note are chrome.
        cell.append(argument.name, style=DIM)
        cell.append("=")
        if argument.withheld:
            cell.append(_t("[withheld]"), style=ORANGE)
            continue
        cell.append(argument.value)
        if argument.total_characters is not None:
            cell.append(
                f"  {_t('shortened; characters in total:')} "
                f"{argument.total_characters}",
                style=ORANGE,
            )
    return cell


def executed_commands_table(calls: Sequence[ExecutedCall]) -> Table:
    """Render every recorded call in full: the listing IS the record."""

    table = Table(
        title=Text(
            f"{GLYPH_POINT} {_t('Executed commands')} ({len(calls)})",
            style=f"bold {ACCENT}",
        ),
        title_justify="left",
        box=TABLE_BOX,
        header_style=f"bold {ACCENT}",
        # A call occupies several lines, so rows need to be separated or two
        # calls read as one.
        show_lines=True,
        pad_edge=False,
    )
    table.add_column("#", justify="right", no_wrap=True, style=DIM)
    table.add_column(_t("Function and operation"), min_width=18, overflow="fold")
    # Folded, never ellipsized: a long value wraps onto the next line rather
    # than losing its tail, which is where two sibling calls differ.
    table.add_column(_t("Arguments"), ratio=2, overflow="fold")
    table.add_column(_t("Outcome"), min_width=10, overflow="fold")
    table.add_column(_t("Duration"), min_width=8, justify="right", style=DIM)
    for call in calls:
        identity = Text(call.function, style=f"bold {ACCENT}")
        if call.operation:
            identity.append(f"\n{call.operation}", style=DIM)
        table.add_row(
            Text(str(call.sequence)),
            identity,
            call_arguments_cell(call.arguments),
            outcome_text(call.outcome),
            Text(
                "—"
                if call.duration_s is None
                else format_duration(call.duration_s, compact=True, decimals=2)
            ),
        )
    return table


def show_executed_commands(console: Console, *, oversight_path: str | None) -> None:
    """Print the complete call the model made, for every call of the run.

    The activity feed abbreviates while the run is in flight because it
    shares the line with the investigation. Afterwards the operator needs
    the opposite: the function, the operation, and every argument exactly as
    the model passed them. Both read the same recorded trace; this view
    writes nothing and re-runs nothing.
    """

    entries = run_bound_entries(oversight_path)
    calls = executed_calls(entries) if entries is not None else ()
    if not calls:
        absent = _t(
            "No recorded tool calls are available for a completed investigation."
        )
        console.print(f"[{DIM}]{absent}[/]")
        return
    console.print()
    console.print(executed_commands_table(calls))
    console.print()


def oversight_call_panel(
    call: ExecutedCall,
    authority: GrantedAuthority | None,
    *,
    width: int,
) -> Panel:
    """One recorded call whole: the request, both authorities, ground, outcome.

    The grounds are keyed off the recorded outcome, never the legacy
    ``blocked`` flag: a modern denial arrives as ``allowed=true`` with a
    refused outcome from the argument gate, and a view reading the flag would
    call it permitted. Labels are operator chrome; the function, operation,
    argument values, capability names and digests are the record itself and
    stay byte-identical in either language.
    """

    grid = Table.grid(padding=(0, 2))
    grid.add_column(justify="right", style=DIM, no_wrap=True)
    grid.add_column(overflow="fold")
    grid.add_row(_t("function"), Text(call.function, style=f"bold {ACCENT}"))
    grid.add_row(
        _t("operation"),
        Text(call.operation) if call.operation else Text("—", style=DIM),
    )
    # Unabridged by construction: the caller projects this call with the
    # listing's ceiling lifted, and the folded column wraps a long value
    # rather than cutting it.
    grid.add_row(_t("arguments"), call_arguments_cell(call.arguments))
    grid.add_row(_t("outcome"), outcome_text(call.outcome))
    refused = call.outcome in (
        RECORDED_REFUSED_BY_OVERSIGHT,
        RECORDED_REFUSED_BY_TOOL,
    )
    grounds = list(call.reasons)
    if refused and call.outcome_detail:
        grounds.append(call.outcome_detail)
    if refused:
        grid.add_row(
            _t("denial ground"),
            Text("; ".join(grounds), style=RED) if grounds else Text("—", style=DIM),
        )
    else:
        grid.add_row(
            _t("decision reason"),
            Text("; ".join(grounds)) if grounds else Text("—", style=DIM),
        )
        if call.outcome_detail:
            grid.add_row(_t("outcome detail"), Text(call.outcome_detail))
    grid.add_row(
        _t("requested authority"),
        Text(", ".join(call.capabilities))
        if call.capabilities
        else Text("—", style=DIM),
    )
    if authority is None:
        grid.add_row(
            _t("granted authority"),
            Text(_t("not recorded in this trace"), style=DIM),
        )
    else:
        if authority.policy_name:
            grid.add_row(_t("policy"), Text(authority.policy_name))
        grid.add_row(
            _t("granted authority"),
            Text(", ".join(authority.granted_caps))
            if authority.granted_caps
            else Text("—", style=DIM),
        )
        if authority.allowed_tools is not None:
            grid.add_row(
                _t("allowed tools"),
                Text(", ".join(authority.allowed_tools))
                if authority.allowed_tools
                else Text("—", style=DIM),
            )
        if authority.write_scope:
            grid.add_row(_t("write scope"), Text("\n".join(authority.write_scope)))
    grid.add_row(
        _t("risk"),
        Text(call.risk_name) if call.risk_name else Text("—", style=DIM),
    )
    grid.add_row(
        _t("duration"),
        Text(
            "—"
            if call.duration_s is None
            else format_duration(call.duration_s, compact=True, decimals=2)
        ),
    )
    if call.output_digests:
        digests = Text()
        for index, (name, digest) in enumerate(call.output_digests):
            if index:
                digests.append("\n")
            digests.append(name, style=DIM)
            digests.append("=")
            digests.append(digest)
        grid.add_row(_t("output digests"), digests)
    return Panel(
        grid,
        title=(
            f"[bold]{GLYPH_POINT} {_t('Oversight call')} "
            f"#{call.sequence}: {escape(call.function)}[/]"
        ),
        title_align="left",
        border_style=ACCENT,
        box=PANEL_BOX,
        padding=(0, 1),
        width=width,
    )


def show_oversight_call(
    console: Console,
    *,
    identifier: str,
    oversight_path: str | None,
    width: int,
) -> None:
    """Print one recorded call whole, named by the seq the summary prints.

    The summary and this view number a call the same way — by the position its
    entry occupies on the oversight chain — so the operator can read a number
    off the timeline and ask for exactly that call. A number the run has no
    call for is a shape mistake, not a failure: nothing was opened and nothing
    refused, so it gets the quiet guidance every other mistyped command gets.
    """

    entries = run_bound_entries(oversight_path)
    if entries is None:
        console.print(
            f"[{DIM}]No oversight trace is available for a completed investigation.[/]"
        )
        return
    calls = executed_calls(entries, argument_bound=None)
    text = identifier.strip().removeprefix("#")
    number = int(text) if text.isdecimal() else None
    selected = next(
        (call for call in calls if number is not None and call.sequence == number),
        None,
    )
    if selected is None:
        console.print(
            build_usage_renderable(
                "oversight",
                detail=(
                    "The number is the one the /oversight timeline prints "
                    "beside a call."
                ),
            )
        )
        return
    console.print()
    console.print(
        oversight_call_panel(selected, granted_authority(entries), width=width)
    )
    console.print()
