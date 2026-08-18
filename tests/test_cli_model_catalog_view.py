"""What ``/model list`` puts on the screen, at the width it is given.

The listing is the surface an operator reads to choose the model an entire
investigation will run through, and it used to be laid out as one flat table
per section: the capability glyph repeated at the head of every row of a
section whose title already stated the capability, the publisher prefix
repeated on every identifier under it, the refusal sentence repeated beside
every refused model, and three fixed numeric columns that a narrow window
silently cut the figures out of.

These tests hold the replacement to what makes it readable rather than to how
it happens to be drawn: the groups are named once, the shared prefix is stated
once, the configured model is marked, nothing runs past the edge of the window,
and no identifier is lost at either width. The widths are PINNED rather than
taken from the environment — the ambient terminal is not the same here as it is
in CI, and this sheet chooses its layout by the width it is handed.
"""

from __future__ import annotations

import io
import re
from typing import Any

import pytest
from rich.console import Console

from forensic_agent.cli import i18n
from forensic_agent.cli.model_catalog_view import show_model_catalog

#: Wide enough for one column per measure, and narrow enough that the sheet has
#: to fold the measures into one. The threshold between them is a property of
#: the content, so both are stated as numbers a reader can check against the
#: rendering rather than derived from the module under test.
_WIDE = 120
_NARROW = 68

_OPENROUTER = "https://openrouter.ai/api/v1"
_OLLAMA = "http://localhost:11434/v1"

_ACTIVE = "openai/gpt-oss-120b"

#: A catalogue shaped like the real one: publisher-prefixed identifiers, one id
#: carrying no publisher at all, a model whose price the provider did not state,
#: and two models that cannot call tools.
_CATALOG: list[dict[str, Any]] = [
    {
        "id": "openai/gpt-oss-120b",
        "context_length": 131072,
        "supports_tools": True,
        "prompt_usd_per_token": 9e-08,
        "completion_usd_per_token": 4.5e-07,
    },
    {
        "id": "openai/gpt-oss-20b",
        "context_length": 131072,
        "supports_tools": True,
        "prompt_usd_per_token": 4e-08,
        "completion_usd_per_token": 1.5e-07,
    },
    {
        "id": "openai/o4-mini-high",
        "context_length": 200000,
        "supports_tools": True,
        "prompt_usd_per_token": 1.1e-06,
        "completion_usd_per_token": 4.4e-06,
    },
    {
        "id": "deepseek/deepseek-r1-distill-llama-70b",
        "context_length": 131072,
        "supports_tools": True,
        "prompt_usd_per_token": 3e-08,
        "completion_usd_per_token": 1.3e-07,
    },
    {
        "id": "deepseek/deepseek-chat-v3-0324",
        "context_length": 163840,
        "supports_tools": True,
        "prompt_usd_per_token": 2.7e-07,
        "completion_usd_per_token": 1.1e-06,
    },
    {
        "id": "anthropic/claude-sonnet-4.5",
        "context_length": 1000000,
        "supports_tools": True,
        "prompt_usd_per_token": 3e-06,
        "completion_usd_per_token": 1.5e-05,
    },
    {
        "id": "google/gemini-2.5-flash",
        "context_length": 1048576,
        "supports_tools": True,
        "prompt_usd_per_token": None,
        "completion_usd_per_token": None,
    },
    {
        "id": "mistral-large-latest",
        "context_length": 128000,
        "supports_tools": True,
        "prompt_usd_per_token": 2e-06,
        "completion_usd_per_token": 6e-06,
    },
    {"id": "openai/dall-e-3", "context_length": 4096, "supports_tools": False},
    {
        "id": "deepseek/deepseek-r1",
        "context_length": 163840,
        "supports_tools": False,
    },
]

_CAPABLE = tuple(
    str(entry["id"]) for entry in _CATALOG if entry.get("supports_tools") is True
)
_INCAPABLE = tuple(
    str(entry["id"]) for entry in _CATALOG if entry.get("supports_tools") is not True
)

_INSTALLED: list[dict[str, Any]] = [
    {
        "name": "llama3.1:8b",
        "context_length": 131072,
        "supports_tools": True,
        "parameter_size": "8.0B",
        "quantization": "Q4_K_M",
        "size_bytes": 4661224676,
    },
    {
        "name": "qwen2.5-coder:14b",
        "context_length": 32768,
        "supports_tools": True,
        "parameter_size": "14.8B",
        "quantization": "Q4_K_M",
        "size_bytes": 8988112040,
    },
    {
        "name": "nomic-embed-text:latest",
        "context_length": 2048,
        "supports_tools": False,
        "parameter_size": "137M",
        "quantization": "F16",
        "size_bytes": 274302450,
    },
]


@pytest.fixture(autouse=True)
def _english() -> object:
    """Language is process-global state; the column headings asserted are English."""

    previous = i18n.current_language()
    i18n.set_language(i18n.DEFAULT_LANGUAGE)
    try:
        yield
    finally:
        i18n.set_language(previous)


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Both fetches answer from a fixture: this view is being read, not exercised."""

    import forensic_agent.core.environ as environ

    monkeypatch.setattr(
        environ, "catalog_models", lambda *args, **kwargs: _CATALOG, raising=False
    )
    monkeypatch.setattr(
        environ, "local_models", lambda *args, **kwargs: _INSTALLED, raising=False
    )


def _render(
    width: int,
    *,
    selector: str = "",
    model: str = _ACTIVE,
    base_url: str = _OPENROUTER,
    **kwargs: Any,
) -> list[str]:
    """The lines the listing actually produces at ``width`` columns."""

    console = Console(width=width, record=True, file=io.StringIO())
    show_model_catalog(
        console,
        selector,
        model=model,
        base_url=base_url,
        api_key="k",
        **kwargs,
    )
    return [line.rstrip() for line in console.export_text().rstrip("\n").split("\n")]


def _below_the_frame(lines: list[str]) -> list[str]:
    """Everything under the header panel: the sheet itself, and nothing else.

    The panel names the configured model, so a count of "how often does this
    publisher prefix appear in the listing" has to start after it.
    """

    for index, line in enumerate(lines):
        if line.startswith("└"):
            return lines[index + 1 :]
    return lines


#: A row of the sheet: the one-cell mark column, its padding, then the label.
_ROW = re.compile(r"^[✓ ] {3}\S")


def _listed_identifiers(lines: list[str]) -> list[str]:
    """Rebuild the full model ids the sheet shows, group heading included.

    The heading states the publisher prefix once and the rows under it carry
    only what follows it, so the identifier an operator types is the two joined.
    Reading them back the same way is what proves nothing was dropped or cut.
    """

    prefix = ""
    listed: list[str] = []
    for line in lines:
        if line.startswith("› "):
            title = line[2:].rsplit(" · ", 1)[0]
            prefix = title if title.endswith("/") else ""
            continue
        if not _ROW.match(line):
            if line and not line.startswith((" ", "─", "│", "┌", "└")):
                # A section verdict, or the footer: any open group ends here.
                prefix = ""
            continue
        label = re.split(r"\s{2,}", line[4:].strip())[0]
        if label == "Model":  # the column heading, stated once
            continue
        listed.append(prefix + label)
    return listed


# ---------------------------------------------------------------------------
# grouping
# ---------------------------------------------------------------------------
def test_the_listing_groups_by_publisher_and_states_the_prefix_once() -> None:
    """``openai/`` belongs over the group, not in front of four identifiers."""

    body = _below_the_frame(_render(_WIDE))
    titles = [line for line in body if line.startswith("› ")]

    assert "› openai/ · 3" in titles
    assert "› deepseek/ · 2" in titles
    assert "› anthropic/ · 1" in titles
    # An identifier with no publisher segment cannot be filed under one, and is
    # named by the backend it is addressed at rather than dropped into a group
    # that would claim a prefix it does not carry.
    assert "› OpenRouter · 1" in titles

    listing = "\n".join(body)
    for prefix in ("openai/", "deepseek/", "anthropic/", "google/"):
        assert listing.count(prefix) == 1, (
            f"{prefix} is repeated on the rows it heads: "
            f"{[line for line in body if prefix in line]}"
        )


def test_a_local_install_is_not_split_into_groups_that_share_nothing() -> None:
    """Ollama names carry no publisher segment, so there is nothing to group by.

    A heading over a single group that strips no prefix separates the listing
    from nothing, and inventing groups out of the ``:tag`` would file models
    that share no publisher under one.
    """

    body = _below_the_frame(_render(_WIDE, model="llama3.1:8b", base_url=_OLLAMA))

    assert [line for line in body if line.startswith("› ")] == []
    assert set(_listed_identifiers(body)) == {
        "llama3.1:8b",
        "qwen2.5-coder:14b",
        "nomic-embed-text:latest",
    }


# ---------------------------------------------------------------------------
# the configured model
# ---------------------------------------------------------------------------
def test_the_configured_model_is_the_one_marked_row() -> None:
    """One tick in the listing, on the model this console is actually running."""

    lines = _render(_WIDE)
    body = _below_the_frame(lines)

    marked = [line for line in body if line.startswith("✓")]
    assert len(marked) == 1, f"the mark is not unique: {marked}"
    assert "gpt-oss-120b" in marked[0]
    # Stated in words too, so the row survives a terminal with no colour.
    assert "active" in marked[0]
    # And the frame above names it, because a bound or a filter can leave the
    # configured model off the rows entirely.
    assert any(line.startswith("│") and f"✓ {_ACTIVE}" in line for line in lines)


def test_a_configured_model_the_backend_does_not_carry_is_not_ticked() -> None:
    """The mark states what the fetch found, not what the config asked for."""

    lines = _render(_WIDE, model="mixtral:8x7b", base_url=_OLLAMA)

    assert any(line.startswith("│") and "○ mixtral:8x7b" in line for line in lines)
    assert not any("✓ mixtral:8x7b" in line for line in lines)
    # And the absence gets its own section rather than passing in silence.
    assert any("Configured but not installed" in line for line in lines)


# ---------------------------------------------------------------------------
# what a heading says once
# ---------------------------------------------------------------------------
def test_no_row_repeats_what_a_heading_already_carries() -> None:
    """The verdict is the section's, the prefix is the group's, the unit is the
    column's. None of the three belongs on every row underneath."""

    body = _below_the_frame(_render(_WIDE, selector="all"))
    listing = "\n".join(body)

    # The capability glyph marked every capable row of a section titled "Can
    # run an investigation"; it now means the one thing it cannot say twice.
    assert listing.count("✓") == 1
    # Every refused model carried the identical sentence. The section says it.
    assert "Cannot run an investigation: no tool calling" in listing
    assert "does not advertise tool calling" not in listing
    # The column headings are the sheet's, not each group's.
    headings = [line for line in body if re.match(r"^ {4}Model(\s|$)", line)]
    assert len(headings) == 2, (
        f"one heading row per section was expected, got {headings}"
    )


# ---------------------------------------------------------------------------
# the width it is given
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("width", [_WIDE, _NARROW])
@pytest.mark.parametrize(
    ("model", "base_url", "selector"),
    [
        (_ACTIVE, _OPENROUTER, ""),
        (_ACTIVE, _OPENROUTER, "all"),
        ("llama3.1:8b", _OLLAMA, ""),
    ],
)
def test_nothing_runs_past_the_edge_of_the_window(
    width: int, model: str, base_url: str, selector: str
) -> None:
    for line in _render(width, selector=selector, model=model, base_url=base_url):
        assert len(line) <= width, f"{len(line)} cells at width {width}: {line!r}"


@pytest.mark.parametrize("width", [_WIDE, _NARROW])
def test_every_model_identifier_survives_at_either_width(width: int) -> None:
    """Degrading is re-laying out, never dropping a model or cutting its name."""

    listed = _listed_identifiers(_below_the_frame(_render(width, selector="all")))

    assert set(listed) == set(_CAPABLE) | set(_INCAPABLE)
    assert len(listed) == len(_CAPABLE) + len(_INCAPABLE)


@pytest.mark.parametrize("width", [_WIDE, _NARROW])
def test_no_measure_is_dropped_when_the_window_will_not_hold_a_column_each(
    width: int,
) -> None:
    """Three fixed numeric columns wider than the window used to lose the prices.

    Rich drops what it cannot fit, so the narrow window rendered the input price
    truncated and the output price not at all. Below the width one column per
    measure needs, the measures share a column instead — every figure still
    there, in the order the heading states.
    """

    listing = "\n".join(_below_the_frame(_render(width)))

    for figure in ("131,072", "1,048,576", "0.030", "0.130", "15.000", "6.000"):
        assert figure in listing, f"{figure} was lost at width {width}"
    # The unit is still named, and still only in the heading.
    assert "USD / 1M tokens" in listing
    assert listing.count("USD / 1M tokens") <= 3


def test_the_sheet_stretches_into_a_narrow_window_rather_than_folding() -> None:
    """The window is the constraint until the content is: below the width the
    columns want, the sheet takes all of it rather than wrapping inside a
    column of its own choosing."""

    for width in (_NARROW, 80, 88):
        rendered = _below_the_frame(_render(width))
        rule = next(line for line in rendered if line.startswith("─"))
        assert len(rule) == width, (
            f"at {width} columns the sheet drew a {len(rule)}-cell rule"
        )


# ---------------------------------------------------------------------------
# colour
# ---------------------------------------------------------------------------
def test_the_listing_is_drawn_in_the_palette_it_is_handed() -> None:
    """The console has several themes; a listing with a colour of its own has none."""

    console = Console(
        width=_WIDE,
        record=True,
        file=io.StringIO(),
        force_terminal=True,
        color_system="truecolor",
    )
    show_model_catalog(
        console,
        "",
        model=_ACTIVE,
        base_url=_OPENROUTER,
        api_key="k",
        palette={
            "ACCENT": "#ff00ff",
            "DIM": "#00ff00",
            "DIM_BRIGHT": "#00ffff",
            "TEXT": "#ffff00",
            "SUCCESS": "#123456",
        },
    )
    painted = console.export_text(styles=True)

    assert "255;0;255" in painted, "the accent the caller handed in was not used"
    assert "0;255;255" in painted, "the group headings kept a colour of their own"
    assert "18;52;86" in painted, "the mark on the configured model was not themed"
    # No background is painted at all: the sheet takes the ground it is on.
    assert "48;2;" not in painted, "the listing painted a background of its own"
