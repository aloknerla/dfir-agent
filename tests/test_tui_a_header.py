"""The opening header: the wordmark, the tagline, and what the panel says it is.

The defect these are written against is a screenshot: the block-letter wordmark
sliced through its last letters at the right edge of the CONVERSATION pane, the
letter-spaced tagline broken after ``a s s i s`` with ``t a n t`` alone on the
next line, and the Session panel cut off at the bottom of the pane. All three
are the same mistake — drawing something without measuring the room for it —
so they are asserted the same way: render the header at a range of sizes and
look at the characters that actually came out.
"""

from __future__ import annotations

import asyncio
import io

import pytest

pytest.importorskip("textual")

from textual.containers import VerticalScroll  # noqa: E402

from forensic_agent.tui import build_app  # noqa: E402
from forensic_agent.tui import model as M  # noqa: E402
from forensic_agent.tui.app import (  # noqa: E402
    _BANNER_SUBTITLE,
    _TAGLINE_WIDTH,
    _WORDMARK_COMPACT,
    _WORDMARK_FULL,
    _WORDMARK_PLAIN,
    _WORDMARKS,
    _wordmark_for,
    _wordmark_text,
)
from forensic_agent.tui.controller import DemoController  # noqa: E402


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr("forensic_agent.tui.controller.time.sleep", lambda *_: None)


def _lines(renderable, width: int) -> list[str]:
    """The rows a renderable actually produces at ``width`` columns."""

    from rich.console import Console as RichConsole

    console = RichConsole(width=width, record=True, file=io.StringIO())
    console.print(renderable)
    return [line.rstrip() for line in console.export_text().rstrip("\n").split("\n")]


def _header_lines(app, width: int) -> list[str]:
    """What the mounted banner widget is actually showing.

    Textual 8 wraps a Rich renderable in a RichVisual and plain text in a
    Content; a header that fits nowhere is the latter, and that case has to be
    readable here too or the narrowest sizes go untested.
    """

    rendered = app._banner_widget.render()
    renderable = getattr(rendered, "_renderable", None)
    if renderable is None:
        plain = getattr(rendered, "plain", None) or str(rendered)
        return [line.rstrip() for line in plain.rstrip("\n").split("\n")]
    return _lines(renderable, max(width, 1))


# ---------------------------------------------------------------------------
# the variants themselves
# ---------------------------------------------------------------------------
def test_the_variants_are_built_once_and_know_their_own_size():
    """Fixed renderings with fixed widths: nothing is generated per resize."""

    assert [mark.name for mark in _WORDMARKS] == ["full", "compact", "plain"]
    # Widest first, so the cascade takes the first that fits.
    widths = [mark.width for mark in _WORDMARKS]
    assert widths == sorted(widths, reverse=True)
    for mark in _WORDMARKS:
        assert mark.width == max(len(row) for row in mark.rows)
        assert mark.height == len(mark.rows)
        # rstripped at build time, so a trailing space cannot make a rendering
        # look wider than it is and push the cascade down a step.
        assert all(row == row.rstrip() for row in mark.rows)


def test_the_smallest_variant_renders_however_narrow_the_pane_is():
    """There is no width at which the header disappears for want of a fit."""

    for width in (200, _WORDMARK_FULL.width, _WORDMARK_COMPACT.width, 12, 4, 1, 0):
        assert _wordmark_for(width, 10) is not None
    assert _wordmark_for(0, 10) is _WORDMARK_PLAIN


def test_a_pane_too_short_drops_the_wordmark_rather_than_the_panel():
    """Height is the constraint the panes below actually compete for."""

    assert _wordmark_for(200, 6) is _WORDMARK_FULL
    assert _wordmark_for(200, 5) is _WORDMARK_COMPACT
    assert _wordmark_for(200, 2) is _WORDMARK_PLAIN
    assert _wordmark_for(200, 0) is None


@pytest.mark.parametrize("width", [200, 120, 86, 77, 76, 60, 40, 36, 35, 20, 11, 9, 4])
def test_no_rendering_ever_exceeds_the_width_it_was_chosen_for(width):
    """The wordmark must never render clipped, at any width."""

    mark = _wordmark_for(width, 12)
    assert mark is not None
    tagline = width >= _TAGLINE_WIDTH
    rendered = _lines(_wordmark_text(mark, tagline=tagline), max(width, 1))
    for line in rendered:
        # Below the plain variant's own ten cells there is nothing left to cut
        # down to, so that one row is allowed to be as wide as the name is.
        assert len(line) <= max(width, _WORDMARK_PLAIN.width), (
            f"{mark.name} at {width} produced a {len(line)}-cell line: {line!r}"
        )


@pytest.mark.parametrize("width", [200, 120, 86, 77, 70, 69, 68, 67, 60, 40, 20])
def test_the_tagline_is_drawn_whole_or_not_at_all(width):
    """Letter-spaced text that wraps is worse than no tagline."""

    mark = _wordmark_for(width, 12)
    assert mark is not None
    tagline = width >= _TAGLINE_WIDTH
    rendered = _lines(_wordmark_text(mark, tagline=tagline), max(width, 1))
    joined = "\n".join(rendered)
    if tagline:
        # One line holds the whole of it; no row carries a fragment.
        assert any(_BANNER_SUBTITLE in line for line in rendered)
    else:
        assert "a s s i s" not in joined
        assert _BANNER_SUBTITLE not in joined


# ---------------------------------------------------------------------------
# the running console
# ---------------------------------------------------------------------------
SIZES = ((180, 54), (140, 44), (120, 40), (110, 34), (100, 30), (96, 28))


def test_the_header_fits_the_pane_at_every_size_the_console_admits():
    """Driven through the pilot: resize, then read the characters on screen."""

    async def scenario():
        app = build_app(DemoController())
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.3)
            for width, height in SIZES:
                await pilot.resize_terminal(width, height)
                await pilot.pause(0.15)
                await pilot.pause(0.15)
                pane = app.query_one("#conversation", VerticalScroll)
                room = pane.content_size.width
                banner = app._banner_widget
                assert banner is not None and banner.is_mounted
                for line in _header_lines(app, room):
                    assert len(line) <= room, (
                        f"at {width}x{height} the header ran to {len(line)} "
                        f"cells in a {room}-cell pane: {line!r}"
                    )
                    assert "a s s i s" not in line or _BANNER_SUBTITLE in line

    asyncio.run(scenario())


def test_shrinking_quickly_after_enlarging_still_narrows_the_header():
    """A layout that only measures on mount keeps drawing the wide variant.

    Enlarge, let it settle on the full art, then snap down: the header has to
    follow, and it has to follow from the pane's own new size rather than from
    the size the resize event carried.
    """

    async def scenario():
        app = build_app(DemoController())
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.3)
            await pilot.resize_terminal(200, 60)
            await pilot.pause(0.15)
            await pilot.pause(0.15)
            assert app._header_shown == ("full", True)
            # Several events in quick succession, the way a drag arrives.
            for width in (180, 160, 140, 120, 100):
                await pilot.resize_terminal(width, 30)
                await pilot.pause(0.01)
            await pilot.pause(0.2)
            await pilot.pause(0.2)
            name, _tagline = app._header_shown
            assert name != "full"
            pane = app.query_one("#conversation", VerticalScroll)
            for line in _header_lines(app, pane.content_size.width):
                assert len(line) <= pane.content_size.width

    asyncio.run(scenario())


def test_maximizing_rescales_the_wordmark_even_when_the_layout_is_slow():
    """Maximize, then restore, with a settle delay that every layout outruns.

    The defect this pins: the mark used to be re-chosen from a timer a fixed
    50 ms after the app's OWN resize event, and the check that decided the
    layout had finished compared that measurement against the previous one. A
    maximize whose layout took longer than the delay was measured at the pane's
    old size; that reading agreed with the previous reading, the header
    concluded it had settled, and it never looked again — so the mark kept the
    variant chosen for the old width. Clicking maximize is the whole of the
    interaction, so nothing arrived afterwards to correct it, and the same held
    for a restore from minimised.

    The delay is set to a millisecond here, which every layout outruns, so this
    passes only if the mark is chosen from the pane's own laid-out size.
    """

    async def scenario():
        app = build_app(DemoController())
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.3)
            assert app._header_shown == ("compact", False)
            narrow = _header_lines(app, app._header_room()[0])
            assert narrow[0] == _WORDMARK_COMPACT.rows[0]

            # No delay chosen in advance can be right about this; only the pane
            # itself knows when it has been laid out at the new size.
            app._HEADER_SETTLE_S = 0.001

            await pilot.resize_terminal(240, 67)  # the maximize button
            await pilot.pause(0.2)
            await pilot.pause(0.2)
            assert app._header_shown == ("full", True)
            pane = app.query_one("#conversation", VerticalScroll)
            wide = _header_lines(app, pane.content_size.width)
            # The full art, laid out for the pane it is now in: drawn from its
            # left edge rather than at the offset the narrow rendering left,
            # and inside the pane rather than sliced by it.
            assert wide[0] == _WORDMARK_FULL.rows[0]
            assert max(len(line) for line in wide) <= pane.content_size.width
            assert any(_BANNER_SUBTITLE in line for line in wide)

            await pilot.resize_terminal(120, 40)  # and restore down again
            await pilot.pause(0.2)
            await pilot.pause(0.2)
            assert app._header_shown == ("compact", False)
            pane = app.query_one("#conversation", VerticalScroll)
            back = _header_lines(app, pane.content_size.width)
            assert back[0] == _WORDMARK_COMPACT.rows[0]
            assert max(len(line) for line in back) <= pane.content_size.width
            assert not any(_BANNER_SUBTITLE in line for line in back)

    asyncio.run(scenario())


def test_a_drag_inside_one_variant_costs_no_repaints():
    """Following every resize must not mean rendering on every resize.

    A drag emits an event per cell. Each one re-measures the pane and re-runs
    the cascade, which is a handful of integer comparisons over three fixed
    renderings; only a width that crosses from one of them into another is
    allowed to reach the render.
    """

    async def scenario():
        app = build_app(DemoController())
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.4)
            assert app._header_shown == ("compact", False)
            painted: list[int] = []
            banner = app._banner_widget
            original = banner.update
            banner.update = lambda *a, **k: (painted.append(1), original(*a, **k))[1]
            # A drag across widths that all hold the same rendering.
            for width in (118, 116, 114, 112, 110, 108, 106, 104, 102, 100):
                await pilot.resize_terminal(width, 40)
                await pilot.pause(0.01)
            await pilot.pause(0.2)
            await pilot.pause(0.2)
            assert painted == [], (
                f"{len(painted)} repaints for a drag that never left the "
                f"compact rendering"
            )
            assert app._header_shown == ("compact", False)
            # The one that does cross a boundary costs exactly one.
            await pilot.resize_terminal(240, 67)
            await pilot.pause(0.2)
            await pilot.pause(0.2)
            assert len(painted) == 1
            assert app._header_shown == ("full", True)

    asyncio.run(scenario())


def test_a_repeat_measurement_that_changes_nothing_does_not_repaint():
    """The equality check is what keeps a fast drag from stuttering."""

    async def scenario():
        app = build_app(DemoController())
        async with app.run_test(size=(140, 44)) as pilot:
            await pilot.pause(0.4)
            settled = app._header_shown
            painted: list[int] = []
            banner = app._banner_widget
            original = banner.update
            banner.update = lambda *a, **k: (painted.append(1), original(*a, **k))[1]
            for _ in range(20):
                app._refresh_header()
            assert painted == []
            assert app._header_shown == settled

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# what the Session panel says it is
# ---------------------------------------------------------------------------
def test_the_session_panel_says_nothing_about_which_build_is_running():
    """The panel says what the CASE is. Which binary is running is not that.

    It used to carry the build identity, rendered as "code dated 2026-08-11
    14:19" — a sentence about the modification time of a source file, on the
    screen of somebody investigating a disk image. The need behind it was real
    (defects reported again from an image older than the code) and it is met
    now by /doctor and by a warning that fires only when the build IS old.
    """

    async def scenario():
        app = build_app(DemoController())
        async with app.run_test(size=(140, 44)) as pilot:
            await pilot.pause(0.3)
            renderable = app._session_widget.render()._renderable
            rendered = chr(10).join(_lines(renderable, 100))
            from forensic_agent.tui.app import _build_label, _version_label

            assert _version_label() in rendered
            assert "code dated" not in rendered
            build = _build_label()
            assert build, "the build identity is unknown even from a source tree"
            assert build not in rendered
            assert "layout" not in rendered, "layout is a preference, not a case fact"

    asyncio.run(scenario())


def test_the_panel_subtitle_is_the_version_and_only_the_version():
    from forensic_agent.tui.app import _build_label, _version_label

    async def scenario():
        app = build_app(DemoController())
        async with app.run_test(size=(140, 44)) as pilot:
            await pilot.pause(0.2)
            version = _version_label()
            # The same answer at every width; there is nothing left to drop.
            for width in (20, 72, 140):
                assert app._panel_subtitle(width).plain == version
            assert _build_label() not in app._panel_subtitle(140).plain

    asyncio.run(scenario())


def test_doctor_is_where_the_build_answers_for_itself():
    """The capability moved rather than went."""

    async def scenario():
        app = build_app(DemoController())
        async with app.run_test(size=(140, 44)) as pilot:
            await pilot.pause(0.2)
            from forensic_agent.tui.app import _build_label, _version_label

            block = chr(10).join(_lines(app._build_block(), 100))
            assert _version_label() in block
            assert _build_label() in block
            # Silence about age is the normal answer for a current build.
            assert "Rebuild" not in block

    asyncio.run(scenario())


def test_the_palette_gradient_reaches_every_variant():
    """Each rendering is coloured from the active theme, not a frozen ramp."""

    for theme in M.available_palettes():
        M.set_active_palette(theme)
        for mark in _WORDMARKS:
            text = _wordmark_text(mark, tagline=False)
            styles = {str(span.style) for span in text.spans}
            assert styles, f"{mark.name} rendered with no colour under {theme}"
            assert any(
                colour in " ".join(styles) for colour in M.banner_colours(theme)
            )
    M.set_active_palette(M.DEFAULT_PALETTE)
