"""What ``/model`` shows: the configured model, and what else could be chosen.

Choosing a model is a forensic decision before it is a cost decision: an
investigation runs entirely through tool calls, so a model that does not
advertise `tools` cannot conduct one at all. Every view below is therefore
organised by that capability first and by price second, and a model that
cannot investigate is never rendered as an ordinary row to pick from.

The two backends are listed side by side here rather than in separate modules
because the verdict has to be identical on both — the refusal reads the same,
in the same colour, whether the model is remote or on this machine — and the
one thing that would quietly break that is writing the two listings apart.

Kept out of the session because it is the console's one networked view. Nothing
here runs to draw a prompt or to answer a bare ``/model``; the terminal has to
stay usable with no connection at all, so the round trip happens only when the
operator asks for the catalogue by name.

The listing is laid out the way ``/help``'s command sheet is, and for the same
reasons: it is built for the width it is actually handed rather than for the
one its author's terminal happened to be, it states its column headings once,
it groups its rows under a heading each with a blank line between them, and it
paints no ground of its own. Read the two side by side — they are one reference
surface with two subjects, and a change to the shape of either belongs in both.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from rich.console import Console, Group, RenderableType
from rich.filesize import decimal as _decimal_size
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from forensic_agent.cli.console_layout import kv_row
from forensic_agent.cli.i18n import t as _t
from forensic_agent.cli.terminal import (
    ACCENT,
    DIM,
    GLYPH_ABSENT,
    GLYPH_ERROR,
    GLYPH_OK,
    GLYPH_POINT,
    GLYPH_WARN,
    ORANGE,
    PANEL_BOX,
    RED,
    SUCCESS,
    TABLE_BOX,
    TEXT,
)

if TYPE_CHECKING:
    from forensic_agent.cli.model_listing import ModelSelection

#: The colour roles this view names. A themed caller (the full-screen console)
#: owns several palettes and states the values it is running; the line console
#: passes nothing and gets this module's own. Kept to role names rather than to
#: values so no view here can acquire a colour of its own.
_ROLES = ("ACCENT", "DIM", "DIM_BRIGHT", "TEXT", "SUCCESS", "ORANGE", "RED")

_DEFAULT_COLOURS = {
    "ACCENT": ACCENT,
    "DIM": DIM,
    # The line console has no separate bright neutral; DIM is the honest
    # default rather than a value invented here.
    "DIM_BRIGHT": DIM,
    "TEXT": TEXT,
    "SUCCESS": SUCCESS,
    "ORANGE": ORANGE,
    "RED": RED,
}


def _colours(palette: dict[str, str] | None) -> dict[str, str]:
    """The seven roles this view draws in, taken from ``palette`` where stated."""

    stated = palette or {}
    return {role: stated.get(role, _DEFAULT_COLOURS[role]) for role in _ROLES}


# ---- The listing sheet -----------------------------------------------------
# One layout for every model listing this console prints, built the same way
# /help's command sheet is built and for the same reasons: the groups have to be
# findable before the rows are readable, the columns have to line up across the
# groups, and the sheet has to be laid out for the width it is actually given
# rather than for the width its author's terminal happened to be.


@dataclass(frozen=True, slots=True)
class _Measure:
    """One right-hand column: what it reports, in what unit, in what colour.

    The unit is a second heading line rather than a suffix on every figure. A
    column of "0.090 USD / 1M" repeats fifteen cells of unit down the screen to
    say once what the heading can say once.
    """

    heading: str
    unit: str = ""
    role: str = "TEXT"


@dataclass(frozen=True, slots=True)
class _Entry:
    """One model as the listing prints it, and whether it is the configured one."""

    identifier: str
    #: What the row prints: the identifier with its group's shared prefix
    #: removed, since the group's own title states that prefix once.
    label: str
    active: bool = False
    cells: tuple[str, ...] = ()
    note: str = ""


@dataclass(frozen=True, slots=True)
class _ModelGroup:
    """The models whose identifiers share one publisher prefix."""

    #: The shared prefix, trailing slash and all ("openai/"), or "" for a group
    #: that shares no prefix and therefore has no prefix to announce.
    title: str
    entries: tuple[_Entry, ...] = field(default_factory=tuple)


def _publisher_prefix(identifier: str) -> str:
    """The segment a provider's identifiers actually share, or "" when none.

    OpenRouter addresses a model as ``publisher/name`` — ``openai/gpt-oss-120b``,
    ``deepseek/deepseek-chat-v3-0324`` — so the text before the first slash is a
    real dimension of the catalogue and not a guess made from the spelling. A
    local Ollama name (``llama3.1:8b``) carries no such segment, and inventing
    one out of its tag would group models that share nothing.
    """

    prefix, slash, _rest = identifier.partition("/")
    return f"{prefix}{slash}" if slash else ""


def _group_models(
    rows: Sequence[_Entry],
    *,
    fallback_title: str,
) -> tuple[_ModelGroup, ...]:
    """Gather rows under the prefix their identifiers share.

    Groups keep the order the rows arrived in, which is the order the selection
    already sorted them into: the group holding the cheapest model comes first,
    so the listing's stated order survives being grouped.

    A group's title states the prefix, and the rows inside it drop it. The one
    group that strips nothing is titled only when it stands beside groups that
    do — alone, it would be a heading separating a listing from nothing.
    """

    order: list[str] = []
    members: dict[str, list[_Entry]] = {}
    for row in rows:
        prefix = _publisher_prefix(row.identifier)
        if prefix not in members:
            members[prefix] = []
            order.append(prefix)
        members[prefix].append(
            _Entry(
                row.identifier,
                row.identifier[len(prefix) :] or row.identifier,
                row.active,
                row.cells,
                row.note,
            )
        )
    if len(order) == 1 and not order[0]:
        return (_ModelGroup("", tuple(members[order[0]])),)
    return tuple(
        _ModelGroup(prefix or fallback_title, tuple(members[prefix]))
        for prefix in order
    )


#: The mark column is one terminal cell: a glyph and nothing else, so a folded
#: identifier can never carry the mark off onto a line of its own.
_MARK_WIDTH = 1

#: Rich's own right padding, counted here because the fit has to be decided
#: before the table exists.
_COLUMN_PAD = 2

#: Below the width at which the identifiers still have this much room, the
#: measures stop being one column each. Fixed columns whose widths together
#: exceed the window leave the identifier nothing, and Rich then drops a column
#: outright — a model listing with the prices missing.
_MIN_MODEL_WIDTH = 24

#: How far past its own content the sheet will stretch into a wide window.
#: Room the identifiers can use is room worth taking; room past that is not,
#: because right-aligned figures pushed to the far edge put a screen's width of
#: nothing between a model and its price. So the sheet grows into the window
#: while the window is the constraint, and stops once the content is.
_BREATHING = 8


def _measure_heading(measure: _Measure) -> str:
    heading = _t(measure.heading)
    return f"{heading}\n{_t(measure.unit)}" if measure.unit else heading


def _measure_width(
    measure: _Measure, groups: Sequence[_ModelGroup], index: int
) -> int:
    """How wide one measure's column has to be to fold nothing.

    Measured over every group rather than per group, so one group's Context
    column starts where the next one's does and the sheet reads as one table.
    """

    widths = [len(_t(measure.heading)), len(_t(measure.unit))]
    widths.extend(
        len(entry.cells[index])
        for group in groups
        for entry in group.entries
        if index < len(entry.cells)
    )
    return max(widths)


def _sheet_width(
    model_width: int,
    measure_widths: Sequence[int],
    note_width: int,
    has_note: bool,
) -> int:
    """How wide the sheet renders with these columns, padding and rules included.

    Worked out here rather than left to Rich because the decision that depends
    on it — whether to stretch into the window at all — has to be made before
    the table exists.
    """

    widths = [_MARK_WIDTH, model_width, *measure_widths]
    if has_note:
        widths.append(note_width)
    # Every column carries its right pad except the last, which ``pad_edge``
    # drops, and the box rules one cell between each pair.
    return sum(width + _COLUMN_PAD for width in widths) - _COLUMN_PAD + len(widths) - 1


def _group_title(group: _ModelGroup) -> str:
    """The line that names one group and says how many models are under it."""

    return f"{GLYPH_POINT} {group.title} · {len(group.entries)}"


def _entry_label(entry: _Entry, accent: str, success: str) -> Text:
    """The row's own text, with the configured model marked in words as well.

    The glyph in the mark column says which row is the active one at a glance;
    the word says it to a reader with no colour and to one scanning the text of
    the listing rather than its left edge.
    """

    label = Text(entry.label)
    if entry.active:
        label.stylize(f"bold {accent}")
        label.append(f"  {_t('active')}", style=success)
    return label


def _model_sections(
    width: int,
    groups: Sequence[_ModelGroup],
    measures: Sequence[_Measure],
    note_heading: str,
    palette: dict[str, str] | None,
) -> RenderableType:
    """The listing laid out for a surface ``width`` cells wide.

    Three things this sheet deliberately does NOT do, each because the version
    it replaced did the opposite and read badly:

    * It does not repeat the column headings, and it does not repeat a word a
      heading can carry. The capability glyph stood at the head of every single
      row of a section whose title already stated the capability, and every
      refused model carried the same sentence of reason as the model above it.
    * It does not fill rows with a colour of its own. The sheet takes the ground
      it is drawn on, which is the only way one listing looks right in a console
      that has several themes.
    * It does not fix its own width, and it does not let a fixed column push
      another one off the table. Wide, every measure is its own aligned column;
      too narrow for that, the measures share one column that flexes, in the
      order the heading states — nothing is dropped and nothing is cut.
    """

    colours = _colours(palette)
    accent = colours["ACCENT"]
    dim = colours["DIM"]
    dim_bright = colours["DIM_BRIGHT"]
    ink = colours["TEXT"]
    success = colours["SUCCESS"]

    measure_widths = [
        _measure_width(measure, groups, index)
        for index, measure in enumerate(measures)
    ]
    fixed = _MARK_WIDTH + _COLUMN_PAD + sum(
        measure_width + _COLUMN_PAD for measure_width in measure_widths
    )
    if note_heading:
        # A reason column flexes rather than being measured, so the fit has to
        # reserve it the same floor the identifiers get.
        fixed += _MIN_MODEL_WIDTH + _COLUMN_PAD
    columnar = not measures or width - fixed >= _MIN_MODEL_WIDTH

    # Measured across every group, so one group's columns begin where the next
    # one's do and the sheet reads as a single table rather than as a stack of
    # unrelated ones.
    model_width = max(
        [
            len(_entry_label(entry, accent, success))
            for group in groups
            for entry in group.entries
        ]
        + [len(_t("Model"))]
    )
    note_width = max(
        [len(entry.note) for group in groups for entry in group.entries]
        + [len(_t(note_heading))]
    ) if note_heading else 0
    content = _sheet_width(model_width, measure_widths, note_width, bool(note_heading))
    # A group title wider than the table beneath it leaves the heading hanging
    # over a rule that stops short of it. The identifiers take the difference.
    deficit = max(
        [len(_group_title(group)) for group in groups if group.title], default=0
    ) - content
    if deficit > 0:
        model_width += deficit
        content += deficit
    # Narrow, the window is the constraint and the sheet takes all of it.
    expand = not columnar or width < content + _BREATHING
    # What the identifiers may take of a window too narrow for a column per
    # measure: what they need, and never more than the larger share of it.
    narrow_model_width = max(
        10, min(model_width, (width - _MARK_WIDTH - _COLUMN_PAD - 1) * 3 // 5)
    )

    sections: list[RenderableType] = []
    for position, group in enumerate(groups):
        first = position == 0
        if not first:
            sections.append(Text(""))
        if group.title:
            # A line of its own rather than the table's own title, because a
            # table narrower than its heading wraps that heading to the table
            # and leaves the count orphaned on a second line.
            sections.append(Text(_group_title(group), style=f"bold {dim_bright}"))
        table = Table(
            box=TABLE_BOX,
            header_style=f"bold {dim_bright}",
            expand=expand,
            # The headings belong to the sheet, not to each group.
            show_header=first,
            # The ruled edges would double the gap the blank line already
            # draws, and two gaps read as an accident rather than a rhythm.
            show_edge=False,
            pad_edge=False,
            padding=(0, _COLUMN_PAD, 0, 0),
        )
        # The mark column carries no heading: a heading over one cell would be
        # wider than the column it names.
        table.add_column("", width=_MARK_WIDTH, no_wrap=True)
        # Column headings pass through the language layer. Model identifiers do
        # not: they are what the operator types back, byte for byte.
        if columnar and expand:
            table.add_column(
                _t("Model"),
                ratio=2,
                min_width=_MIN_MODEL_WIDTH,
                overflow="fold",
                style=accent,
            )
        else:
            # Narrow, the identifiers take what they need up to the larger
            # share of the window and the merged measures take the rest. A
            # fixed ratio instead left short local names half a screen of
            # blank column while the figures beside them wrapped.
            table.add_column(
                _t("Model"),
                width=model_width if columnar else narrow_model_width,
                overflow="fold",
                style=accent,
            )
        if columnar:
            for index, measure in enumerate(measures):
                table.add_column(
                    _measure_heading(measure),
                    width=measure_widths[index],
                    justify="right",
                    no_wrap=True,
                    style=colours[measure.role],
                )
        elif measures:
            # Narrow: one flexing column carrying the same figures in the same
            # order, with the heading naming that order once. The identifier
            # keeps the larger share, because it is the one cell the operator
            # has to read back character for character.
            table.add_column(
                " · ".join(
                    " ".join(part for part in (_t(m.heading), _t(m.unit)) if part)
                    for m in measures
                ),
                ratio=2,
                min_width=10,
                overflow="fold",
                style=dim,
            )
        if note_heading and expand:
            table.add_column(
                _t(note_heading), ratio=2, min_width=10, overflow="fold", style=ink
            )
        elif note_heading:
            table.add_column(
                _t(note_heading), width=note_width, overflow="fold", style=ink
            )
        for entry in group.entries:
            cells: list[Text] = [
                Text(GLYPH_OK, style=success) if entry.active else Text(" "),
                _entry_label(entry, accent, success),
            ]
            if columnar:
                cells.extend(Text(value) for value in entry.cells)
            elif measures:
                cells.append(Text(" · ".join(entry.cells)))
            if note_heading:
                cells.append(Text(entry.note))
            table.add_row(*cells)
        sections.append(table)
    return Group(*sections)


class _ModelSheet:
    """One model listing, laid out for the width it is actually given.

    A Rich renderable rather than a finished table because the layout depends on
    the room: the console this is shown in is resizable, and a sheet built for
    one width and drawn at another is the defect this replaced. Built when it is
    rendered, which is when the width is known.
    """

    def __init__(
        self,
        groups: Sequence[_ModelGroup],
        measures: Sequence[_Measure] = (),
        *,
        note_heading: str = "",
        palette: dict[str, str] | None = None,
    ) -> None:
        self._groups = tuple(groups)
        self._measures = tuple(measures)
        self._note_heading = note_heading
        self._palette = palette

    def __rich_console__(self, console, options):
        yield _model_sections(
            options.max_width,
            self._groups,
            self._measures,
            self._note_heading,
            self._palette,
        )


def _print_section(
    console: Console,
    title: str,
    count: str,
    role: str,
    groups: Sequence[_ModelGroup],
    measures: Sequence[_Measure] = (),
    *,
    note_heading: str = "",
    palette: dict[str, str] | None = None,
) -> None:
    """Open one section with its verdict and its count, then print its sheet.

    The verdict is the section's own line and carries the colour; the groups
    under it are neutral. Colouring both would put two competing claims on one
    screen, and the one that matters — whether these models can investigate at
    all — is the outer one.
    """

    colours = _colours(palette)
    console.print()
    console.print(Text(f"{title} · {count}", style=f"bold {colours[role]}"))
    console.print()
    console.print(
        _ModelSheet(groups, measures, note_heading=note_heading, palette=palette)
    )


def show_model(
    console: Console,
    *,
    model: str,
    base_url: str,
    palette: dict[str, str] | None = None,
) -> None:
    from forensic_agent.core.environ import backend_kind

    colours = _colours(palette)
    provider = (
        "Ollama"
        if backend_kind(base_url) == "ollama"
        else "OpenRouter"
    )
    table = Table.grid(padding=(0, 3))
    # The configured model is the one fact this panel exists to state, so it
    # carries the same mark the listing puts beside it: one glyph, one meaning,
    # whichever of the two views the operator is reading.
    kv_row(table, _t("model"), f"{GLYPH_OK} {model}", colours["SUCCESS"])
    kv_row(table, _t("provider"), provider, colours["ACCENT"])
    kv_row(table, _t("endpoint"), base_url, colours["DIM"])
    kv_row(table, "RAG", _t("disabled"), colours["DIM"])
    console.print(
        Panel(
            table,
            title=f"[bold]{GLYPH_POINT} {_t('Model configuration')}[/]",
            title_align="left",
            border_style=colours["ACCENT"],
            box=PANEL_BOX,
            padding=(1, 2),
        )
    )
    # The configuration answer is deliberately offline; the catalogue that
    # would answer "what else is there" costs a network round trip, so it is
    # named here and fetched only when the operator asks for it.
    console.print()
    console.print(
        f"[{colours['DIM']}]{_t('List what this provider offers:')}[/] "
        f"[{colours['ACCENT']}]/model list[/]"
    )


def show_model_catalog(
    console: Console,
    selector: str,
    *,
    model: str,
    base_url: str,
    api_key: str,
    palette: dict[str, str] | None = None,
) -> None:
    """List what the configured backend actually offers, capability first.

    This is the only console command that reaches the provider over the
    network, and it does so only when it is asked for: the terminal has to
    stay usable with no connection at all, so nothing here runs to draw a
    prompt or to answer a bare /model.
    """

    from forensic_agent.core.environ import backend_kind

    if backend_kind(base_url) == "ollama":
        _show_installed_models(
            console, selector, model=model, base_url=base_url, palette=palette
        )
    else:
        _show_provider_catalog(
            console,
            selector,
            model=model,
            base_url=base_url,
            api_key=api_key,
            palette=palette,
        )


def _model_catalog_header(
    console: Console,
    rows: Sequence[tuple[str, object, str]],
    selection: ModelSelection,
    *,
    model: str,
    available: bool,
    order: str,
    grouped: bool,
    palette: dict[str, str] | None,
) -> None:
    """Frame one listing with what it read, from where, and how it is ordered.

    The counts live here rather than inside a sentence so no rendered number
    is ever wedged into a translated one: labels pass through the language
    layer, values do not, and the two never share a string.
    """

    colours = _colours(palette)
    grid = Table.grid(padding=(0, 3))
    # The configured model heads the frame whether or not the listing below
    # reaches it: a bound, a filter or a provider that no longer offers it can
    # all leave the active model off the rows, and the one thing this view must
    # never leave the operator guessing at is which model they are on. The mark
    # states what this fetch found rather than what was configured, so a model
    # the backend does not carry is never ticked as though it were there.
    mark, role = (
        (GLYPH_OK, "SUCCESS") if available else (GLYPH_ABSENT, "ORANGE")
    )
    kv_row(grid, _t("model"), f"{mark} {model}", colours[role])
    for label, value, color in rows:
        kv_row(grid, _t(label), value, color)
    if selection.filter_text:
        # Under a filter every count below describes the match, not the
        # whole catalogue. Naming the filter and the size of what it matched
        # is what keeps "tool capable" from reading as a claim about all of
        # the provider's models.
        kv_row(grid, _t("filter"), selection.filter_text, colours["ACCENT"])
        kv_row(
            grid,
            _t("matched"),
            selection.capable_total + selection.incapable_total,
            colours["DIM"],
        )
    kv_row(grid, _t("tool capable"), selection.capable_total, colours["SUCCESS"])
    kv_row(grid, _t("order"), order, colours["DIM"])
    if grouped:
        # Grouping reorders the rows, so the frame that states the order has to
        # state the grouping beside it or it describes a listing that is not
        # the one below.
        kv_row(grid, _t("grouped by"), _t("publisher"), colours["DIM"])
    kv_row(
        grid,
        _t("snapshot"),
        _t("read when this command ran; not stored"),
        colours["DIM"],
    )
    console.print(
        Panel(
            grid,
            title=f"[bold]{GLYPH_POINT} {_t('Model catalogue')}[/]",
            title_align="left",
            border_style=colours["ACCENT"],
            box=PANEL_BOX,
            padding=(1, 2),
        )
    )


def _print_refused_models(
    console: Console,
    selection: ModelSelection,
    *,
    fallback_title: str,
    palette: dict[str, str] | None,
) -> None:
    """Name the models this backend advertises that still cannot investigate.

    Kept out of the choice sheet and given the refusal's own colour, so the
    verdict is read before the name — the same treatment on either backend,
    because the reason is the same on either backend.

    The reason is the section's, not each row's. Every model here is refused
    for the identical cause, and printing that cause once beside the heading
    says exactly as much as printing it forty times down a column.
    """

    if not selection.incapable:
        return
    groups = _group_models(
        [_Entry(str(entry.get("id")), "") for entry in selection.incapable],
        fallback_title=fallback_title,
    )
    _print_section(
        console,
        f"{GLYPH_ERROR} {_t('Cannot run an investigation: no tool calling')}",
        str(len(selection.incapable)),
        "RED",
        groups,
        palette=palette,
    )


def _model_listing_footer(
    console: Console, bounded: bool, *, palette: dict[str, str] | None
) -> None:
    colours = _colours(palette)
    console.print()
    if bounded:
        # Never a silent cut: the bound is stated together with the two
        # commands that lift it, so an operator can always reach the rest.
        console.print(
            f"[{colours['ORANGE']}]{GLYPH_WARN} "
            f"{_t('This view is bounded. The rest is not hidden:')}[/] "
            f"[{colours['ACCENT']}]/model list all[/] "
            f"[{colours['DIM']}]{_t('or')}[/] "
            f"[{colours['ACCENT']}]/model list <text>[/]"
        )
    console.print(
        f"[{colours['DIM']}]{_t('Select one with:')}[/] "
        f"[{colours['ACCENT']}]/model <model-id>[/]"
    )


def _print_empty_capable_notice(
    console: Console, palette: dict[str, str] | None
) -> None:
    """Say that nothing here can investigate, rather than drawing an empty table.

    A table with one row of dashes claims a shape the listing does not have;
    one line says the same thing and does not pretend to be a catalogue.
    """

    colours = _colours(palette)
    console.print()
    console.print(
        Text(
            f"{GLYPH_ABSENT} {_t('No model in this view can run an investigation.')}",
            style=colours["ORANGE"],
        )
    )


#: Each measure names its own unit, stacked above the figures rather than
#: repeated beside every one of them: a price column whose unit the reader has
#: to infer is worse than no price column, and a unit spelled out on every row
#: costs fifteen cells a row to say what one heading says once.
_REMOTE_MEASURES = (
    _Measure("Context", "tokens", "DIM"),
    _Measure("Input", "USD / 1M tokens"),
    _Measure("Output", "USD / 1M tokens"),
)

_LOCAL_MEASURES = (
    _Measure("Parameters", role="DIM"),
    _Measure("Quantization", role="DIM"),
    _Measure("Context", "tokens", "DIM"),
    _Measure("Size", role="DIM"),
)


def _show_provider_catalog(
    console: Console,
    selector: str,
    *,
    model: str,
    base_url: str,
    api_key: str,
    palette: dict[str, str] | None = None,
) -> None:
    """Render the remote catalogue: what it costs and what can call tools."""

    from forensic_agent.cli.model_listing import (
        context_tokens,
        select_models,
        usd_per_million_tokens,
    )
    from forensic_agent.core.environ import ModelCatalogError, catalog_models

    colours = _colours(palette)
    try:
        catalog = catalog_models(base_url, api_key)
    except ModelCatalogError as exc:
        detail = str(exc)
        if api_key:
            detail = detail.replace(api_key, "[REDACTED]")
        console.print(
            f"[{colours['RED']}]{GLYPH_ERROR} "
            f"{_t('The model catalogue could not be fetched.')}[/] "
            f"[{colours['DIM']}]{escape(detail[:180])}[/]"
        )
        console.print(
            f"[{colours['DIM']}]{_t('No listing is shown; this says nothing about which models the account has.')}[/]"
        )
        return

    selection = select_models(catalog, selector)
    groups = _group_models(
        [
            _Entry(
                str(entry.get("id")),
                "",
                str(entry.get("id")) == model,
                (
                    context_tokens(entry.get("context_length")),
                    usd_per_million_tokens(entry.get("prompt_usd_per_token")),
                    usd_per_million_tokens(entry.get("completion_usd_per_token")),
                ),
            )
            for entry in selection.capable
        ],
        fallback_title="OpenRouter",
    )
    _model_catalog_header(
        console,
        [
            ("provider", "OpenRouter", colours["ACCENT"]),
            ("endpoint", base_url, colours["DIM"]),
            ("in catalogue", selection.catalog_total, colours["DIM"]),
        ],
        selection,
        model=model,
        available=any(str(entry.get("id")) == model for entry in catalog),
        order=_t("lowest input price first"),
        grouped=len(groups) > 1,
        palette=palette,
    )

    if selection.capable:
        _print_section(
            console,
            _t("Can run an investigation"),
            f"{len(selection.capable)} / {selection.capable_total}",
            "ACCENT",
            groups,
            _REMOTE_MEASURES,
            palette=palette,
        )
    else:
        _print_empty_capable_notice(console, palette)

    _print_refused_models(
        console, selection, fallback_title="OpenRouter", palette=palette
    )

    _model_listing_footer(console, selection.bounded, palette=palette)


def _show_installed_models(
    console: Console,
    selector: str,
    *,
    model: str,
    base_url: str,
    palette: dict[str, str] | None = None,
) -> None:
    """Render what Ollama has actually pulled, and what it has not.

    A local model that is not installed cannot be offered as a choice at all,
    so the configured one is named in its own section when it is missing
    rather than left out of a listing that would then read as complete.
    """

    from forensic_agent.cli.model_listing import context_tokens, select_models
    from forensic_agent.core.environ import local_models

    colours = _colours(palette)
    installed = local_models(base_url)
    if not installed:
        # The tags endpoint answers the same way for a stopped service and
        # for an empty install, so the message claims neither on its own.
        console.print(
            f"[{colours['RED']}]{GLYPH_ERROR} "
            f"{_t('Ollama is unavailable, or no model is installed.')}[/]"
        )
        console.print(
            f"[{colours['DIM']}]{_t('Start the local service and install a model, then run /model list again.')}[/]"
        )
        return

    rows = [
        {
            "id": str(entry.get("name") or ""),
            "context_length": entry.get("context_length"),
            "supports_tools": entry.get("supports_tools") is True,
            "parameter_size": entry.get("parameter_size") or "",
            "quantization": entry.get("quantization") or "",
            "size_bytes": entry.get("size_bytes"),
        }
        for entry in installed
    ]
    # An inventory of the host reports everything on it: a model the operator
    # pulled must appear even when it cannot investigate, marked, rather than
    # vanish from a listing that would then misdescribe the machine.
    selection = select_models(rows, selector, include_incapable=True)
    listed: list[_Entry] = []
    for entry in selection.capable:
        size = entry.get("size_bytes")
        identifier = str(entry.get("id"))
        listed.append(
            _Entry(
                identifier,
                "",
                identifier == model,
                (
                    str(entry.get("parameter_size") or "—"),
                    str(entry.get("quantization") or "—"),
                    context_tokens(entry.get("context_length")),
                    _decimal_size(int(size)) if isinstance(size, int) else "—",
                ),
            )
        )
    groups = _group_models(listed, fallback_title="Ollama")
    _model_catalog_header(
        console,
        [
            ("provider", "Ollama", colours["ACCENT"]),
            ("endpoint", base_url, colours["DIM"]),
            ("installed", selection.catalog_total, colours["DIM"]),
        ],
        selection,
        model=model,
        available=any(row["id"] == model for row in rows),
        order=_t("by model id"),
        grouped=len(groups) > 1,
        palette=palette,
    )

    if selection.capable:
        _print_section(
            console,
            _t("Can run an investigation"),
            f"{len(selection.capable)} / {selection.capable_total}",
            "ACCENT",
            groups,
            _LOCAL_MEASURES,
            palette=palette,
        )
    else:
        _print_empty_capable_notice(console, palette)

    _print_refused_models(
        console, selection, fallback_title="Ollama", palette=palette
    )

    # The configured model is the one thing a listing must never pass over in
    # silence: if it is not on the host, the console has been pointing at a
    # model that cannot answer, and only this listing can say so.
    if model and model not in {row["id"] for row in rows}:
        _print_section(
            console,
            f"{GLYPH_ABSENT} {_t('Configured but not installed')}",
            "1",
            "ORANGE",
            _group_models(
                [
                    _Entry(
                        model,
                        "",
                        note=f"{_t('not installed in local Ollama')} "
                        f"· ollama pull {model}",
                    )
                ],
                fallback_title="Ollama",
            ),
            note_heading="Reason",
            palette=palette,
        )

    _model_listing_footer(console, selection.bounded, palette=palette)
