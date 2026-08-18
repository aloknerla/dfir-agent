"""Terminal styling, argument parsing, and interactive command routing."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from rich import box
from rich.console import Console, Group, RenderableType
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from forensic_agent import __version__
from forensic_agent.cli.commands import (
    CATEGORY_ORDER,
    COMMAND_REGISTRY,
    CommandSpec,
    render_help,
)
from forensic_agent.cli.i18n import t as _t
from forensic_agent.core.environ import doctor as _doctor

# ---- Colour palette --------------------------------------------------------
# The console commits to one dark theme, tuned for the #0d1117 terminal the
# project ships with. Neutrals belong to the GitHub-dark family (the same hue as
# the raised panel fill), and the accents are a small semantic set so a colour
# always carries one meaning:
#   ACCENT  identity, headings, interactive hints, the operator's next move
#   SUCCESS a verified, complete, positive state — above all, the accepted answer
#   ORANGE  caution: partial coverage, a degraded capability, a warning
#   RED     a failed or blocked state
#   DIM     secondary metadata that must never outshine the line it annotates
ACCENT = "#bb9af7"

#: The secondary accent, kept identical to the full-screen console's PURPLE so
#: one role name does not carry two values in one codebase. This is the second
#: colour of the wordmark's gradient and is not adjusted for contrast: it is
#: only ever drawn on the terminal ground, where it measures 5.40:1.
PURPLE = "#9d7cd8"

SUCCESS = "#73daca"

ORANGE = "#e0af68"

RED = "#f7768e"

DIM = "grey50"

#: Quiet edge for panels that must recede beneath the answer. It shares the hue
#: family of the raised fill, so a supporting panel reads as a frame rather than
#: a second focal point competing with the final answer for the eye.
BORDER = "#30363d"

#: Fill for panels that must read as raised above the terminal background
#: (#0d1117), so the final answer separates from the surrounding transcript.
PANEL_BG = "#161b22"

#: The ground itself, and ordinary text upon it. Rich takes both from the
#: terminal, so these are named only for the places that must state a colour
#: outright — the completion menu is drawn by prompt_toolkit, which has no
#: notion of this palette and would otherwise arrive in a theme of its own.
BACKGROUND = "#0d1117"
TEXT = "#c9d1d9"

#: The raised fill together with the foreground that belongs on it. Stating a
#: background without stating a foreground leaves the text at whatever colour
#: the host terminal chose for ITS background, which is the opposite one on a
#: light terminal: the answer panel, the completion record and every second row
#: of /help each rendered near-black on near-black there. The console never
#: touches the host terminal's own background — the full-screen console paints
#: its whole viewport, and outside it the operator's colours are theirs — so a
#: surface that paints its own ground has to carry its own text with it.
RAISED_SURFACE = f"{TEXT} on {PANEL_BG}"

# ---- Iconography -----------------------------------------------------------
# One glyph per meaning, reused everywhere that meaning appears, rather than a
# decorative picture per tool. Each is a single terminal cell so status columns
# and the activity feed line up instead of drifting with double-width emoji.
GLYPH_OK = "✓"  # verified · available · approved by oversight
GLYPH_WARN = "▲"  # partial · degraded · caution
GLYPH_ERROR = "✗"  # failed · blocked
GLYPH_UNKNOWN = "·"  # a state that was never established
GLYPH_ABSENT = "○"  # optional and not present
GLYPH_POINT = "›"  # a pointer inside a hint or a sub-step

#: One border shape for every framed surface. Hierarchy is carried by colour and
#: fill, not by mixing box styles, which keeps the whole console reading calm.
PANEL_BOX = box.ROUNDED

#: Standalone tables (evidence sources, the tool catalogue) share a light ruled
#: head so they read as reference material, not as boxed-in output.
TABLE_BOX = box.SIMPLE_HEAD


def _command_form(command_spec: CommandSpec) -> Text:
    """The exact string to type, with any alias trailing it quietly.

    Rendered as Text, never as markup: a usage line spells an optional argument
    "[all]", "[en|hr]", and Rich would read those brackets as a style tag and
    drop the very syntax the operator has to type.
    """

    form = Text(command_spec.usage)
    if command_spec.aliases:
        aliases = ", ".join(f"/{alias}" for alias in command_spec.aliases)
        form.append(f"  ({aliases})", style=DIM)
    return form


def _command_name(command_spec: CommandSpec) -> Text:
    """Just the name, with any alias trailing it quietly.

    The name and the argument syntax are two columns rather than one, because
    one command's syntax is far longer than every other's and a single column
    is as wide as its widest member. Sharing a column with
    ``[none|low|medium|high|steps N|toolcalls N]`` left the descriptions of all
    twenty-odd commands a quarter of the sheet wide, wrapping after three words
    each; split, the syntax column answers for its own outlier and the
    descriptions get the rest of the width.
    """

    name = Text(f"/{command_spec.name}")
    if command_spec.aliases:
        aliases = ", ".join(f"/{alias}" for alias in command_spec.aliases)
        name.append(f"  ({aliases})", style=DIM)
    return name


def _command_arguments(command_spec: CommandSpec) -> Text:
    """What the usage line says may follow the name, or "" when nothing may.

    Read off the usage rather than kept beside it, and defensively: a usage
    that does not begin with its own name is shown whole rather than sliced at
    a prefix it does not have.
    """

    usage = command_spec.usage.strip()
    prefix = f"/{command_spec.name}"
    if usage.startswith(prefix):
        usage = usage[len(prefix) :].strip()
    return Text(usage)


#: Below this the three-column sheet has nothing left to give the descriptions:
#: the name column and the widest argument syntax in the registry together take
#: some seventy cells, and what remained was a description column four words
#: wide. Under it the sheet drops to two columns instead, which is the same
#: information laid out for a window that cannot hold three.
_HELP_THREE_COLUMN_WIDTH = 116


def _help_sections(width: int, palette: dict[str, str] | None) -> RenderableType:
    """The command reference laid out for a surface ``width`` cells wide.

    The full listing is what an operator reaches for to find the next command,
    so the groups have to be findable before the rows are readable. A category
    row sitting flush inside the same table read as one more command; each group
    carries its own heading, with a blank line holding the groups apart, and the
    column geometry is fixed across every group so the tables line up as one
    reference sheet.

    Three things this sheet deliberately does NOT do, each because the opposite
    was tried and read badly:

    * It does not repeat the column headings. Five tables meant the word
      "Command" five times down one screen, and a heading restated every eight
      rows reads as part of the content rather than as a label for it. They are
      stated once, above the first group, and every later group is the same
      columns in the same places.
    * It does not fill alternate rows. The band existed to hold a wrapped
      description to its own command, and it was a fixed colour from this
      module's own palette painted into a console that has several themes,
      where it belonged to none of them. Given the width not to wrap, the
      descriptions no longer need holding together.
    * It does not fix its own width. The tables expand into whatever the
      surface gives them, so the sheet is as wide as the window it is read in
      rather than a column down the middle of it.
    """

    colours = palette or {}
    accent = colours.get("ACCENT", ACCENT)
    dim = colours.get("DIM", DIM)
    dim_bright = colours.get("DIM_BRIGHT", DIM)
    ink = colours.get("TEXT", TEXT)
    three_columns = width >= _HELP_THREE_COLUMN_WIDTH

    # Measured over the whole registry, not per group, so every group's columns
    # start at the same x and the sheet reads as one table.
    name_width = max(
        len(_command_name(command_spec)) for command_spec in COMMAND_REGISTRY.commands
    )
    argument_width = max(
        len(_command_arguments(command_spec))
        for command_spec in COMMAND_REGISTRY.commands
    )
    sections: list[RenderableType] = []
    for category in CATEGORY_ORDER:
        members = tuple(
            command_spec
            for command_spec in COMMAND_REGISTRY.commands
            if command_spec.category is category
        )
        if not members:
            continue
        first = not sections
        if not first:
            sections.append(Text(""))
        table = Table(
            title=Text(
                f"{GLYPH_POINT} {_t(category.value)} · {len(members)}",
                style=f"bold {accent}",
            ),
            title_justify="left",
            box=TABLE_BOX,
            header_style=f"bold {dim_bright}",
            expand=True,
            # The headings belong to the sheet rather than to each group.
            show_header=first,
            # The blank ruled edges would double the gap the explicit blank line
            # already draws, and two gaps read as an accident rather than a
            # rhythm.
            show_edge=False,
            pad_edge=False,
            padding=(0, 2, 0, 0),
        )
        # Column headings and the group titles are operator-facing chrome, so
        # they pass through the language layer. The command names and their
        # usage syntax do not: they are the identifiers typed verbatim.
        if three_columns:
            table.add_column(_t("Command"), width=name_width, no_wrap=True, style=accent)
            # Wide enough for the longest syntax in the registry, so one
            # group's second column is never a different width from another's.
            table.add_column(
                _t("Arguments"), width=argument_width, overflow="fold", style=dim
            )
        else:
            # Narrow: the name and its syntax share one column that flexes
            # rather than two that are fixed. Fixed columns wider than the
            # window leave the third nothing at all, and Rich then drops it —
            # a reference sheet with the descriptions missing.
            table.add_column(
                _t("Command"), ratio=2, min_width=12, overflow="fold", style=accent
            )
        # The description is the column that flexes, so the slack the surface
        # has to spare lands there and the columns before it stay identical
        # from one group to the next.
        table.add_column(
            _t("What it does"), ratio=3, min_width=12, overflow="fold", style=ink
        )
        for command_spec in members:
            description = Text(_t(command_spec.description))
            if three_columns:
                table.add_row(
                    _command_name(command_spec),
                    _command_arguments(command_spec),
                    description,
                )
            else:
                table.add_row(_command_form(command_spec), description)
        sections.append(table)
    return Group(*sections)


class _HelpSheet:
    """The command reference, laid out for the width it is actually given.

    A Rich renderable rather than a finished Group because the layout depends
    on the room: the console this is shown in is resizable, and a sheet built
    for one width and drawn at another is the defect this replaced. Built when
    it is rendered, which is when the width is known, and not once per frame —
    the surface caches what it drew until something invalidates it.
    """

    def __init__(self, palette: dict[str, str] | None = None) -> None:
        self._palette = palette

    def __rich_console__(self, console, options):
        yield _help_sections(options.max_width, self._palette)


def build_help_renderable(
    command: str | None = None,
    *,
    palette: dict[str, str] | None = None,
) -> RenderableType:
    """The command reference, or one command's own block.

    ``palette`` lets a caller that owns a theme state the colours the sheet is
    drawn in; the line console passes nothing and gets this module's own.

    Help for one command stays a short block, since there the reader already
    knows what they want and only needs its exact form.
    """

    if command:
        # One command: the exact names, what it does, and how to type it.
        detail = render_help(command)
        return Text(detail)
    return _HelpSheet(palette)


def glyphed_line(glyph: str, glyph_style: str, body: Text) -> RenderableType:
    """One outcome line whose wrap stays underneath its own text.

    A glyph and a sentence printed as a single string wrap back to column zero,
    and the console then shows one message as two: the glyph says which outcome
    this is, so a continuation carrying none reads as a separate, unrelated
    note. The full-screen console makes that literal, because it colours a
    recorded line by the glyph it begins with, and a continuation begins with
    nothing.

    Rendering the pair as a two-column grid settles both at once. The glyph
    keeps its own column and its own colour, the sentence keeps its column and
    wraps inside it, and the style travels with the ``Text`` rather than with a
    markup tag that closes at the first line break.
    """

    line = Table.grid(padding=(0, 1))
    line.add_column(style=glyph_style, no_wrap=True)
    line.add_column(overflow="fold")
    line.add_row(glyph, body)
    return line


def build_usage_renderable(
    name: str, *, detail: str = "", usage: str = ""
) -> RenderableType:
    """Show the shape a command takes, as guidance rather than as a failure.

    A command typed in the wrong shape opened no evidence and refused nothing,
    so the console must not dress it as a fault. This follows what mature
    command-line tools do with a malformed invocation — git, cargo and gh each
    answer with a plain usage line, the exact form, and a pointer to the fuller
    help — and it keeps the red of a real refusal meaning a real refusal. Only
    the form is drawn in ACCENT, because it is the operator's next move;
    the label, the note and the pointer stay DIM.

    ``usage`` overrides the registry's declared form for the one caller whose
    accepted vocabulary is a runtime value rather than a fixed string: the
    reasoning efforts. That caller has to build the form from the vocabulary
    itself so a refusal can never name a choice the console no longer accepts,
    and it should still not be the only shape mistake in the console that
    answers in a different shape from all the others.
    """

    command_spec = COMMAND_REGISTRY.resolve(name)
    declared = command_spec.usage if command_spec is not None else f"/{name}"
    usage = usage or declared
    canonical = command_spec.name if command_spec is not None else name

    hint = Table.grid(padding=(0, 2))
    # The label column sets the hanging indent, so the continuation lines stay
    # aligned under the form whatever width the translated label takes.
    hint.add_column(style=DIM, no_wrap=True)
    hint.add_column(overflow="fold")
    hint.add_row(_t("Usage:"), Text(usage, style=ACCENT))
    if detail:
        hint.add_row("", Text(_t(detail), style=DIM))
    hint.add_row(
        "",
        Text(
            f"{GLYPH_POINT} /help {canonical} {_t('for the full description')}",
            style=DIM,
        ),
    )
    return hint


BANNER_ART = (
    "██████╗ ███████╗██╗██████╗        █████╗  ██████╗ ███████╗███╗   ██╗████████╗",
    "██╔══██╗██╔════╝██║██╔══██╗      ██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝",
    "██║  ██║█████╗  ██║██████╔╝█████╗███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║   ",
    "██║  ██║██╔══╝  ██║██╔══██╗╚════╝██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║   ",
    "██████╔╝██║     ██║██║  ██║      ██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║   ",
    "╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝      ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   ",
)

BANNER_COLORS = (
    "#7aa2f7",
    "#8a9cf6",
    "#9a95f5",
    "#aa8ef4",
    "#b58cf6",
    "#bb9af7",
)

BANNER_SUBTITLE = (
    "a u t o n o m o u s   i n v e s t i g a t i o n   "
    "a s s i s t a n t"
)


def resolved_cli_path(value: str) -> str:
    """Normalize a user-supplied host path consistently on Windows and POSIX."""

    expanded = os.path.expandvars(value.strip())
    if not expanded:
        raise argparse.ArgumentTypeError("path must not be empty")
    return str(Path(expanded).expanduser().resolve())


def bounded_steps(value: str) -> int:
    """Parse the supported per-question step budget."""

    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("step count must be an integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("step count must be at least 1")
    return parsed


def render_doctor(model, base_url, api_key=None, *, console: Console) -> bool:
    """Render preflight checks and report whether required components are ready."""

    rows = _doctor(base_url=base_url, model=model, api_key=api_key)
    console.print()
    console.print(f"[bold {ACCENT}]{GLYPH_POINT} Environment check[/]\n")
    ok_all = True
    optional_missing = False
    for r in rows:
        required = bool(r.get("required", True))
        if r["ok"]:
            mark = f"[{SUCCESS}]{GLYPH_OK}[/]"
        elif required:
            mark = f"[{RED}]{GLYPH_ERROR}[/]"
        else:
            mark = f"[{ORANGE}]{GLYPH_ABSENT}[/]"
        line = f"  {mark} {escape(str(r['name']))}"
        if r["detail"]:
            line += f"   [{DIM}]{escape(str(r['detail']))}[/]"
        env_var = str(r.get("env_var") or "")
        if env_var and not r["ok"]:
            # Rows for external tools carry the override variable the single
            # availability registry consulted. Naming it here means the report
            # says exactly which value to set, instead of leaving the reader to
            # infer it from the prose hint.
            line += f"   [{DIM}]not found · override with {escape(env_var)}[/]"
        console.print(line)
        if not r["ok"]:
            if required:
                ok_all = False
            else:
                optional_missing = True
            console.print(
                f"      [{DIM}]{GLYPH_POINT} {escape(str(r['hint']))}[/]"
            )
    console.print()
    if ok_all and not optional_missing:
        console.print(f"[{SUCCESS}]{GLYPH_OK} Ready.[/]\n")
    elif ok_all:
        console.print(
            f"[{SUCCESS}]{GLYPH_OK} Required components are ready.[/] "
            f"[{DIM}]Some optional capabilities are unavailable.[/]\n"
        )
    else:
        console.print(
            f"[{RED}]At least one required component is unavailable.[/] "
            f"[{DIM}]Resolve the marked items before starting an investigation.[/]\n"
        )
    return ok_all


def build_parser(
    *,
    interactive_model: str,
    default_base_url: str,
    default_api_key: str | None,
    default_run_dir: str | None,
) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dfir-agent",
        description=(
            "Autonomous investigation assistant for digital forensics "
            "and incident response"
        ),
        epilog=(
            "Examples:\n"
            "  dfir-agent doctor\n"
            "  dfir-agent models\n"
            "  dfir-agent D:\\Cases\\case-001\n"
            '  dfir-agent ask --case D:\\Cases\\case-001 --question "Who used the USB device?"\n'
            "\n"
            "Local execution with Ollama:\n"
            "  dfir-agent setup\n"
            "  dfir-agent models\n"
            "  dfir-agent"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "command",
        nargs="?",
        choices=("doctor", "ask", "models", "setup", "tui"),
        default="tui",
        metavar="COMMAND",
        help="optional: doctor, ask, models, setup, or tui",
    )
    # The full-screen Textual console (dfir-agent tui). --demo replays a
    # recorded, stubbed case so the interface is reviewable without Docker, an
    # evidence image, or a configured model.
    parser.add_argument(
        "--demo",
        action="store_true",
        help="run the tui over a recorded, stubbed investigation",
    )
    parser.add_argument("--image", help=argparse.SUPPRESS)
    parser.add_argument(
        "--case",
        help="case directory, evidence source, or case manifest",
    )
    # The provider-specific setup validates or discovers the selected model.
    parser.add_argument(
        "-m",
        "--model",
        default=None,
        help="override the configured model for this session",
    )
    # Provider endpoints and credentials come only from the protected setup
    # configuration. Keeping them out of argv prevents credentials from being
    # exposed in shell history or process listings.
    parser.set_defaults(
        base_url=default_base_url,
        api_key=default_api_key,
    )
    parser.add_argument(
        "--memory",
        default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--pcap",
        default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--max-steps",
        type=bounded_steps,
        default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--max-tool-calls",
        type=bounded_steps,
        default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument("-q", "--question", default=None, help="question for ask")
    continuation = parser.add_mutually_exclusive_group()
    continuation.add_argument(
        "--resume",
        default=None,
        help=argparse.SUPPRESS,
    )
    continuation.add_argument(
        "--continue",
        dest="continue_session",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--run-dir",
        default=default_run_dir,
        type=resolved_cli_path,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--doctor",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--case-root",
        action="append",
        default=None,
        help=argparse.SUPPRESS,
    )
    return parser

