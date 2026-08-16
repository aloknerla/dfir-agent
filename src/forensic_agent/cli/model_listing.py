"""Bounded, capability-first selection from a provider's model catalogue.

The catalogue an operator has to choose from is not a list anyone reads: the
configured OpenRouter account advertises around four hundred models, and only
the ones that accept ``tools`` can conduct an investigation at all, because this
agent reaches evidence exclusively through tool calls. This module decides what
one screen carries and — just as importantly — records what it left out, so the
console can state its bound instead of truncating in silence.

It performs no I/O and draws nothing. The fetch belongs to ``core.environ`` and
the rendering to ``cli.session``; keeping the choice of rows separate from both
is what makes the bound testable without a provider and without a terminal.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

#: Rows one default listing carries. Small enough to read without scrolling on
#: an ordinary terminal, and never a silent ceiling: every view that reaches it
#: reports what it left out and the command that returns the rest.
DEFAULT_LISTING_LIMIT = 20

#: The selector that waives the bound entirely.
LISTING_ALL = "all"

#: One catalogue row as the fetch produces it: ``id``, ``context_length``,
#: ``supports_tools`` and the two per-token prices. Local Ollama rows carry the
#: same keys plus their install detail, so one selection serves both backends.
ModelRow = Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class ModelSelection:
    """The rows one listing shows, and the count of the ones it does not."""

    capable: tuple[ModelRow, ...]
    incapable: tuple[ModelRow, ...]
    capable_total: int
    incapable_total: int
    catalog_total: int
    #: The operator's filter text, unchanged, so the view can name what it
    #: narrowed to. Empty for the default view and for the unbounded one.
    filter_text: str
    #: True when the catalogue holds rows this view does not carry. The caller
    #: has to say so: a bound the operator cannot detect is a truncation.
    bounded: bool


def _price(entry: ModelRow, key: str) -> float | None:
    value = entry.get(key)
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def _cheapest_first(entry: ModelRow) -> tuple[int, float, float, str]:
    """Order by what a question costs, putting an unpriced model last.

    A model whose price the catalogue did not state cannot be compared on price,
    so it sorts after every model that can rather than being ranked as free. The
    model id breaks ties, which keeps the same catalogue in the same order twice.
    """

    prompt = _price(entry, "prompt_usd_per_token")
    completion = _price(entry, "completion_usd_per_token")
    return (
        1 if prompt is None else 0,
        prompt or 0.0,
        completion or 0.0,
        str(entry.get("id") or ""),
    )


def usd_per_million_tokens(usd_per_token: float | None) -> str:
    """Render a per-token price as the per-million figure people actually read.

    OpenRouter states prices in USD PER TOKEN, so the raw value ("0.00000009")
    tells an operator nothing about what a question will cost. The scale factor
    lives here alone and the unit is printed beside the column, because a price
    whose unit the reader has to guess is worse than no price at all. A price the
    catalogue did not state renders as absent, never as zero: free and unknown
    are different facts about a model.
    """

    if usd_per_token is None:
        return "—"
    scaled = usd_per_token * 1_000_000
    if scaled <= 0:
        return "0"
    # A fixed three decimals across the whole column so the decimal points line
    # up and two prices can be compared by eye; free stays a bare "0" so it is
    # never mistaken for a rounded-down price.
    rendered = f"{scaled:.3f}"
    if float(rendered) > 0:
        return rendered
    # Below the column's resolution but still not free. Printing "0.000" here
    # would state a model costs nothing, so the figure keeps its own scale.
    return f"{scaled:.2g}"


def context_tokens(context_length: object) -> str:
    """Render a context window as a grouped token count, or as absent.

    The grouping separator is Python's own, not the host locale's, so the figure
    is byte-identical whichever language the console is rendering in.
    """

    if isinstance(context_length, bool) or not isinstance(context_length, int):
        return "—"
    return f"{context_length:,}"


def select_models(
    catalog: Sequence[ModelRow],
    selector: str = "",
    *,
    limit: int = DEFAULT_LISTING_LIMIT,
    include_incapable: bool = False,
) -> ModelSelection:
    """Choose the rows one listing shows out of the whole fetched catalogue.

    An empty selector is the default view: only models that can run an
    investigation, cheapest first, bounded. ``all`` waives the bound and adds the
    incapable models under their own heading. Any other text filters on the model
    id, and a filter deliberately keeps its incapable matches — an operator who
    searched for a model by name is owed the answer that it exists and cannot be
    used here, not silence that reads as "no such model".

    ``include_incapable`` distinguishes the two things a listing can be. A remote
    catalogue is a menu of what could be bought, so entries that cannot
    investigate are noise the default view leaves out and a filter can still
    find. A local install is an INVENTORY of the host, and an inventory that
    omits a model the operator pulled is simply wrong about the machine — so it
    reports every installed model, capable or not, in its own section either way.
    """

    normalized = selector.strip()
    show_all = normalized.casefold() == LISTING_ALL
    filter_text = "" if show_all else normalized

    needle = filter_text.casefold()
    matched = [
        entry
        for entry in catalog
        if not needle or needle in str(entry.get("id") or "").casefold()
    ]
    capable = sorted(
        (entry for entry in matched if entry.get("supports_tools") is True),
        key=_cheapest_first,
    )
    incapable = sorted(
        (entry for entry in matched if entry.get("supports_tools") is not True),
        key=lambda entry: str(entry.get("id") or ""),
    )

    # The default view carries no model that cannot investigate: presenting one
    # as an ordinary row invites a choice that fails on its first tool call. The
    # count still travels, so the totals show such models exist.
    shown_incapable: tuple[ModelRow, ...] = (
        tuple(incapable) if show_all or needle or include_incapable else ()
    )
    shown_capable: tuple[ModelRow, ...] = tuple(capable)
    if not show_all:
        shown_capable = shown_capable[:limit]
        shown_incapable = shown_incapable[:limit]

    return ModelSelection(
        capable=shown_capable,
        incapable=shown_incapable,
        capable_total=len(capable),
        incapable_total=len(incapable),
        catalog_total=len(catalog),
        filter_text=filter_text,
        bounded=(
            len(shown_capable) < len(capable)
            or len(shown_incapable) < len(incapable)
            # Withholding the incapable models bounds the view just as surely as
            # cutting it for length does, even when nothing was cut for length.
            or bool(incapable and not shown_incapable)
        ),
    )
