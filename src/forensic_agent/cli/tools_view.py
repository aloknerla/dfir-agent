"""What ``/tools`` shows: which functions can run here, and why the rest cannot.

An investigator has to be able to answer "why did the agent not look at X?"
without guessing, and there are three different reasons a function may be out of
play: the case holds no evidence of the kind it reads, the host lacks the
external tool it drives, or the registry withheld it from the model entirely.
The listing exists to keep those three apart, so this module reads the same
availability registry that gates the model's own surface rather than deciding
for itself — a listing that disagreed with the registry would be worse than no
listing at all.

It prints rather than returning one renderable because the command is several
blocks with deliberate spacing between them, and the spacing is part of what
makes the active and the inactive halves read as two answers rather than one.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from forensic_agent.cli.i18n import t as _t
from forensic_agent.cli.terminal import (
    ACCENT,
    DIM,
    GLYPH_ABSENT,
    GLYPH_OK,
    GLYPH_POINT,
    GLYPH_WARN,
    ORANGE,
    PANEL_BOX,
    SUCCESS,
    TABLE_BOX,
)

if TYPE_CHECKING:
    from forensic_agent.agent.tool_registry import UnavailableTool
    from forensic_agent.tools.pcap_sources import PcapSourceCatalog


def withheld_tools(
    *,
    disk: object | None,
    memory_path: str | None,
    pcap_path: str | None,
    pcap_sources: PcapSourceCatalog | None,
) -> Mapping[str, UnavailableTool]:
    """Every function this session's registry cannot execute, and why.

    Read from the registry snapshot rather than re-derived here, so /tools
    describes the exact surface an investigation would build — including, in
    this interactive mode, the functions the model is not offered at all.
    Without this the withheld functions would simply be missing from the
    listing, which is the one thing an investigator must not have to guess.
    """

    from forensic_agent.agent.tool_registry import (
        TOOL_EXPOSURE_HIDE_UNAVAILABLE,
        build_tool_registry,
    )

    snapshot = build_tool_registry(
        disk,
        memory_path=memory_path,
        pcap_path=pcap_path,
        pcap_sources=pcap_sources,
        capture=False,
        project=False,
        tool_exposure=TOOL_EXPOSURE_HIDE_UNAVAILABLE,
    )
    return snapshot.unavailable


def unavailability_note(record: UnavailableTool) -> str:
    """One line naming the reason and the override, for a withheld function."""

    note = f"unavailable: {record.reason}"
    # The one placement fact an operator acts on: a function the model is never
    # offered cannot be the answer to "why did the agent not look at X?", and
    # the listing exists to keep that apart from a missing external tool. How
    # the registry arranges the other case is its own business and is not said.
    if not record.exposed:
        note = f"{note}. The model is not offered this function"
    override = ", ".join(record.env_vars)
    return f"{note}. Set {override} to override." if override else note


def inactive_reason(entry) -> str:
    """A few words on why a catalog function is not on the current palette.

    The compact listing states the one thing an investigator acts on — the
    evidence type that would activate the function — and leaves the long
    host-path and override text for ``/tools <name>``.
    """

    if entry.source == "outside the case palette":
        return "outside the case palette"
    return f"requires {entry.source}"


def show_tools(
    console: Console,
    name: str | None,
    *,
    active_names: frozenset[str],
    disk: object | None,
    memory_path: str | None,
    pcap_path: str | None,
    pcap_sources: PcapSourceCatalog | None,
) -> None:
    from forensic_agent.cli.tool_catalog import native_tool_catalog
    from forensic_agent.core.tool_availability import (
        available_tools,
        dependency_summary,
    )

    catalog = native_tool_catalog()
    by_name = {entry.name: entry for entry in catalog}
    # The same availability registry that answers `doctor` and gates the
    # model-visible registry. Resolved once so every row in this listing
    # describes one consistent view of the host.
    external_dependencies = available_tools()
    withheld = withheld_tools(
        disk=disk,
        memory_path=memory_path,
        pcap_path=pcap_path,
        pcap_sources=pcap_sources,
    )

    def backing_for(function_name: str) -> str:
        record = withheld.get(function_name)
        if record is not None:
            return unavailability_note(record)
        return dependency_summary(function_name, external_dependencies)

    if name is not None:
        _show_tool_detail(
            console,
            name,
            by_name=by_name,
            backing_for=backing_for,
            active_names=active_names,
        )
        return

    active_table = Table(
        title=Text(
            f"{GLYPH_POINT} {_t('Active tools')} ({len(active_names)})",
            style=f"bold {ACCENT}",
        ),
        title_justify="left",
        box=TABLE_BOX,
        header_style=f"bold {ACCENT}",
        show_lines=False,
        pad_edge=False,
    )
    # A leading glyph states each function's readiness so the eye can scan
    # the column for anything degraded before reading the backing detail.
    active_table.add_column(_t("Function"), min_width=30)
    active_table.add_column(_t("Ops"), justify="right", no_wrap=True)
    active_table.add_column(_t("Evidence"))
    active_table.add_column(_t("External tool"), overflow="fold")
    for function_name in sorted(active_names):
        entry = by_name.get(function_name)
        backing = backing_for(function_name)
        degraded = backing.startswith("unavailable")
        mark = GLYPH_WARN if degraded else GLYPH_OK
        mark_color = ORANGE if degraded else SUCCESS
        active_table.add_row(
            Text.from_markup(
                f"[{mark_color}]{mark}[/] {escape(function_name)}()"
            ),
            Text(str(len(entry.operations)) if entry else "—"),
            Text(entry.source if entry else "case"),
            Text(backing or "—", style=ORANGE if degraded else DIM),
        )
    if not active_names:
        active_table.add_row(
            Text("—", style=DIM),
            "—",
            "—",
            _t("Open or attach an evidence source."),
        )

    inactive = tuple(entry for entry in catalog if entry.name not in active_names)
    inactive_table = Table(
        title=Text(
            f"{GLYPH_POINT} {_t('Not applicable')} ({len(inactive)})",
            style=f"bold {DIM}",
        ),
        title_justify="left",
        box=TABLE_BOX,
        header_style=f"bold {DIM}",
        show_lines=False,
        pad_edge=False,
    )
    inactive_table.add_column(_t("Function"), min_width=30)
    inactive_table.add_column(_t("Reason"), overflow="fold")
    for entry in inactive:
        inactive_table.add_row(
            f"[{DIM}]{GLYPH_ABSENT} {escape(entry.name)}()[/]",
            f"[{DIM}]{escape(inactive_reason(entry))}[/]",
        )

    console.print(active_table)
    console.print()
    console.print(inactive_table)


def _show_tool_detail(
    console: Console,
    name,
    *,
    by_name,
    backing_for,
    active_names: frozenset[str],
) -> None:
    """Full operations, description, and availability for one named function."""

    requested = name.strip().removesuffix("()")
    entry = by_name.get(requested)
    if entry is None:
        known = ", ".join(sorted(by_name))
        console.print(
            f"[{ORANGE}]Unknown function:[/] {escape(requested)}"
        )
        console.print(f"[{DIM}]Known functions: {escape(known)}[/]")
        return
    active = requested in active_names
    backing = backing_for(requested)
    grid = Table.grid(padding=(0, 2))
    grid.add_column(justify="right", style=DIM, no_wrap=True)
    grid.add_column()
    # Labels and the status word are operator chrome; the function name,
    # evidence scope, operations, external backing and the function's own
    # description are technical/model-facing and stay byte-identical.
    grid.add_row(_t("function"), f"{escape(entry.name)}()")
    grid.add_row(_t("evidence"), escape(entry.source))
    status_text = (
        f"[{SUCCESS}]{GLYPH_OK} {_t('active')}[/]"
        if active
        else f"[{DIM}]{GLYPH_ABSENT} {_t('not applicable')}[/]"
    )
    grid.add_row(_t("status"), status_text)
    grid.add_row(
        _t("operations"),
        escape(", ".join(entry.operations)) if entry.operations else "—",
    )
    grid.add_row(_t("external tool"), escape(backing or "—"))
    grid.add_row(_t("description"), escape(entry.description))
    console.print(
        Panel(
            grid,
            title=f"[bold]{GLYPH_POINT} {escape(entry.name)}[/]",
            title_align="left",
            border_style=ACCENT,
            box=PANEL_BOX,
            padding=(1, 2),
        )
    )
