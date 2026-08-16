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
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from rich.console import Console
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
)

if TYPE_CHECKING:
    from forensic_agent.cli.model_listing import ModelSelection


def show_model(console: Console, *, model: str, base_url: str) -> None:
    from forensic_agent.core.environ import backend_kind

    provider = (
        "Ollama"
        if backend_kind(base_url) == "ollama"
        else "OpenRouter"
    )
    table = Table.grid(padding=(0, 2))
    kv_row(table, _t("model"), model, ACCENT)
    kv_row(table, _t("provider"), provider, ACCENT)
    kv_row(table, _t("endpoint"), base_url, DIM)
    kv_row(table, "RAG", _t("disabled"), DIM)
    console.print(
        Panel(
            table,
            title=f"[bold]{GLYPH_POINT} {_t('Model configuration')}[/]",
            title_align="left",
            border_style=ACCENT,
            box=PANEL_BOX,
        )
    )
    # The configuration answer is deliberately offline; the catalogue that
    # would answer "what else is there" costs a network round trip, so it is
    # named here and fetched only when the operator asks for it.
    console.print(
        f"[{DIM}]{_t('List what this provider offers:')}[/] [{ACCENT}]/model list[/]"
    )


def show_model_catalog(
    console: Console,
    selector: str,
    *,
    model: str,
    base_url: str,
    api_key: str,
) -> None:
    """List what the configured backend actually offers, capability first.

    This is the only console command that reaches the provider over the
    network, and it does so only when it is asked for: the terminal has to
    stay usable with no connection at all, so nothing here runs to draw a
    prompt or to answer a bare /model.
    """

    from forensic_agent.core.environ import backend_kind

    if backend_kind(base_url) == "ollama":
        _show_installed_models(console, selector, model=model, base_url=base_url)
    else:
        _show_provider_catalog(
            console, selector, base_url=base_url, api_key=api_key
        )


def _model_catalog_header(
    console: Console,
    rows: Sequence[tuple[str, object, str]],
    selection: ModelSelection,
    *,
    order: str,
) -> None:
    """Frame one listing with what it read, from where, and how it is ordered.

    The counts live here rather than inside a sentence so no rendered number
    is ever wedged into a translated one: labels pass through the language
    layer, values do not, and the two never share a string.
    """

    grid = Table.grid(padding=(0, 2))
    for label, value, color in rows:
        kv_row(grid, _t(label), value, color)
    if selection.filter_text:
        # Under a filter every count below describes the match, not the
        # whole catalogue. Naming the filter and the size of what it matched
        # is what keeps "tool capable" from reading as a claim about all of
        # the provider's models.
        kv_row(grid, _t("filter"), selection.filter_text, ACCENT)
        kv_row(
            grid,
            _t("matched"),
            selection.capable_total + selection.incapable_total,
            DIM,
        )
    kv_row(grid, _t("tool capable"), selection.capable_total, SUCCESS)
    kv_row(grid, _t("order"), order, DIM)
    kv_row(
        grid,
        _t("snapshot"),
        _t("read when this command ran; not stored"),
        DIM,
    )
    console.print(
        Panel(
            grid,
            title=f"[bold]{GLYPH_POINT} {_t('Model catalogue')}[/]",
            title_align="left",
            border_style=ACCENT,
            box=PANEL_BOX,
        )
    )


def _model_table(title: str, count: str, color: str) -> Table:
    """One listing section, opened by its capability verdict and its count.

    The capability marker gets a column of its own rather than sharing the
    identifier's cell: a model id can be long enough to wrap, and a wrapped
    cell would carry the glyph off on a line by itself, exactly where the
    verdict most needs to stay beside the model it judges.
    """

    table = Table(
        title=Text(
            f"{GLYPH_POINT} {_t(title)} ({count})",
            style=f"bold {color}",
        ),
        title_justify="left",
        box=TABLE_BOX,
        header_style=f"bold {color}",
        show_lines=False,
        pad_edge=False,
    )
    table.add_column("", width=1, no_wrap=True)
    table.add_column(_t("Model"), min_width=24, overflow="fold")
    return table


def _refused_model_table(title: str, shown: int, color: str) -> Table:
    """A section whose whole point is that nothing in it may be chosen."""

    table = _model_table(title, str(shown), color)
    table.add_column(_t("Reason"), overflow="fold")
    return table


def _print_refused_models(console: Console, selection: ModelSelection) -> None:
    """Name the models this backend advertises that still cannot investigate.

    Kept out of the choice table and given the refusal's own colour and
    glyph, so the verdict is read before the name — the same treatment on
    either backend, because the reason is the same on either backend.
    """

    if not selection.incapable:
        return
    refused = _refused_model_table(
        "Cannot run an investigation: no tool calling",
        len(selection.incapable),
        RED,
    )
    for entry in selection.incapable:
        refused.add_row(
            Text(GLYPH_ERROR, style=RED),
            Text(str(entry.get("id"))),
            Text(_t("does not advertise tool calling"), style=RED),
        )
    console.print()
    console.print(refused)


def _model_listing_footer(console: Console, bounded: bool) -> None:
    if bounded:
        # Never a silent cut: the bound is stated together with the two
        # commands that lift it, so an operator can always reach the rest.
        console.print(
            f"[{ORANGE}]{GLYPH_WARN} "
            f"{_t('This view is bounded. The rest is not hidden:')}[/] "
            f"[{ACCENT}]/model list all[/] [{DIM}]{_t('or')}[/] "
            f"[{ACCENT}]/model list <text>[/]"
        )
    console.print(
        f"[{DIM}]{_t('Select one with:')}[/] [{ACCENT}]/model <model-id>[/]"
    )


def _show_provider_catalog(
    console: Console,
    selector: str,
    *,
    base_url: str,
    api_key: str,
) -> None:
    """Render the remote catalogue: what it costs and what can call tools."""

    from forensic_agent.cli.model_listing import (
        context_tokens,
        select_models,
        usd_per_million_tokens,
    )
    from forensic_agent.core.environ import ModelCatalogError, catalog_models

    try:
        catalog = catalog_models(base_url, api_key)
    except ModelCatalogError as exc:
        detail = str(exc)
        if api_key:
            detail = detail.replace(api_key, "[REDACTED]")
        console.print(
            f"[{RED}]{GLYPH_ERROR} "
            f"{_t('The model catalogue could not be fetched.')}[/] "
            f"[{DIM}]{escape(detail[:180])}[/]"
        )
        console.print(
            f"[{DIM}]{_t('No listing is shown; this says nothing about which models the account has.')}[/]"
        )
        return

    selection = select_models(catalog, selector)
    _model_catalog_header(
        console,
        [
            ("provider", "OpenRouter", ACCENT),
            ("endpoint", base_url, DIM),
            ("in catalogue", selection.catalog_total, DIM),
        ],
        selection,
        order=_t("lowest input price first"),
    )

    table = _model_table(
        "Can run an investigation",
        f"{len(selection.capable)} / {selection.capable_total}",
        ACCENT,
    )
    # Each measure names its own unit, stacked above the figures rather than
    # spread along the header: a price column whose unit the reader has to
    # infer is worse than no price column, and a header wide enough to spell
    # it out on one line would squeeze the identifiers into folding.
    table.add_column(_t("Context") + "\n" + _t("tokens"), justify="right", no_wrap=True)
    table.add_column(_t("Input") + "\n" + _t("USD / 1M tokens"), justify="right", no_wrap=True)
    table.add_column(_t("Output") + "\n" + _t("USD / 1M tokens"), justify="right", no_wrap=True)
    for entry in selection.capable:
        table.add_row(
            Text(GLYPH_OK, style=SUCCESS),
            Text(str(entry.get("id"))),
            Text(context_tokens(entry.get("context_length")), style=DIM),
            Text(usd_per_million_tokens(entry.get("prompt_usd_per_token"))),
            Text(usd_per_million_tokens(entry.get("completion_usd_per_token"))),
        )
    if not selection.capable:
        table.add_row(
            Text(GLYPH_ABSENT, style=DIM),
            Text(
                _t("No model in this view can run an investigation."),
                style=ORANGE,
            ),
            "—",
            "—",
            "—",
        )
    console.print(table)

    _print_refused_models(console, selection)

    _model_listing_footer(console, selection.bounded)


def _show_installed_models(
    console: Console,
    selector: str,
    *,
    model: str,
    base_url: str,
) -> None:
    """Render what Ollama has actually pulled, and what it has not.

    A local model that is not installed cannot be offered as a choice at all,
    so the configured one is named in its own section when it is missing
    rather than left out of a listing that would then read as complete.
    """

    from forensic_agent.cli.model_listing import context_tokens, select_models
    from forensic_agent.core.environ import local_models

    installed = local_models(base_url)
    if not installed:
        # The tags endpoint answers the same way for a stopped service and
        # for an empty install, so the message claims neither on its own.
        console.print(
            f"[{RED}]{GLYPH_ERROR} "
            f"{_t('Ollama is unavailable, or no model is installed.')}[/]"
        )
        console.print(
            f"[{DIM}]{_t('Start the local service and install a model, then run /model list again.')}[/]"
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
    _model_catalog_header(
        console,
        [
            ("provider", "Ollama", ACCENT),
            ("endpoint", base_url, DIM),
            ("installed", selection.catalog_total, DIM),
        ],
        selection,
        order=_t("by model id"),
    )

    table = _model_table(
        "Can run an investigation",
        f"{len(selection.capable)} / {selection.capable_total}",
        ACCENT,
    )
    table.add_column(_t("Parameters"), justify="right", no_wrap=True)
    table.add_column(_t("Quantization"), justify="right", no_wrap=True)
    table.add_column(_t("Context") + "\n" + _t("tokens"), justify="right", no_wrap=True)
    table.add_column(_t("Size"), justify="right", no_wrap=True)
    for entry in selection.capable:
        size = entry.get("size_bytes")
        table.add_row(
            Text(GLYPH_OK, style=SUCCESS),
            Text(str(entry.get("id"))),
            Text(str(entry.get("parameter_size") or "—"), style=DIM),
            Text(str(entry.get("quantization") or "—"), style=DIM),
            Text(context_tokens(entry.get("context_length")), style=DIM),
            Text(
                _decimal_size(int(size)) if isinstance(size, int) else "—",
                style=DIM,
            ),
        )
    if not selection.capable:
        table.add_row(
            Text(GLYPH_ABSENT, style=DIM),
            Text(
                _t("No model in this view can run an investigation."),
                style=ORANGE,
            ),
            "—",
            "—",
            "—",
            "—",
        )
    console.print(table)

    _print_refused_models(console, selection)

    # The configured model is the one thing a listing must never pass over in
    # silence: if it is not on the host, the console has been pointing at a
    # model that cannot answer, and only this listing can say so.
    if model and model not in {row["id"] for row in rows}:
        absent = _refused_model_table("Configured but not installed", 1, ORANGE)
        absent.add_row(
            Text(GLYPH_ABSENT, style=ORANGE),
            Text(model),
            Text.from_markup(
                f"[{ORANGE}]{_t('not installed in local Ollama')}[/] "
                f"[{DIM}]· ollama pull {escape(model)}[/]"
            ),
        )
        console.print()
        console.print(absent)

    _model_listing_footer(console, selection.bounded)
