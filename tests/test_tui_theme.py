"""The console's themes, and the contrast floor every one of them must clear.

Legibility is an acceptance criterion here, not a matter of taste: a forensic
console that renders a verdict colour the operator cannot read is telling them
nothing. So the WCAG 2.1 relative-luminance contrast ratio of every foreground
role against its own ground is computed and asserted for every shipped theme.
A theme that fails is not shipped; the colour is changed, never the threshold.

The rest of the file holds the theme machinery honest: the palette resolves
through the module so the Rich renderables follow a switch, the Textual theme
and the palette agree about what the ground and the ink are, the choice
survives a restart, and a live switch repaints the console that is already on
screen rather than half of it.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

import pytest

pytest.importorskip("textual")

from forensic_agent.tui import build_app  # noqa: E402
from forensic_agent.tui import model as M  # noqa: E402
from forensic_agent.tui.controller import DemoController  # noqa: E402

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"

# --- the floor, role by role -------------------------------------------------
#: Minimum contrast ratio each foreground role must reach. AAA body text for
#: TEXT; AA for every signal colour, for PURPLE (the secondary accent, which
#: carries the tagline and the demo notice) and for both tiers of metadata;
#: 3:1 for BORDER.
#:
#: BORDER is held to the component floor rather than to "visible" because of a
#: measured fact about these palettes: BACKGROUND and PANEL_BG sit within
#: 1.10:1 of each other in all three themes, so a panel is distinguished from
#: the ground by its edge and by nothing else. That makes the edge a user
#: interface component boundary, which WCAG 1.4.11 puts at 3:1.
#:
#: There is no exemption list. One existed, naming the two dfir-tokyo greys
#: that missed the floor and freezing their shortfall so it could not get
#: worse; what it actually did was keep the shipped console below the floor
#: indefinitely, and it hid the fact that the failures were worse than
#: recorded, because everything was measured against BACKGROUND alone.
FLOOR: dict[str, float] = {
    "TEXT": 7.0,
    "ACCENT": 4.5,
    "PURPLE": 4.5,
    "SUCCESS": 4.5,
    "ORANGE": 4.5,
    "RED": 4.5,
    "DIM_BRIGHT": 4.5,
    "DIM": 4.5,
    "BORDER": 3.0,
}

#: The grounds text is actually drawn on. PANEL_BG is the raised surface (the
#: input, the overlays) and PANEL_RAISED the second step (chips, the selected
#: row in every list), so a role that is legible on the terminal ground and
#: not on a selected row is a role the operator cannot read at the moment they
#: are pointing at it.
GROUNDS: tuple[str, ...] = ("BACKGROUND", "PANEL_BG", "PANEL_RAISED")

#: PURPLE answers for the two grounds it is drawn on, like BORDER, and for the
#: same kind of reason: a measured fact about where it appears, not a wish to
#: exempt it. PURPLE has exactly two call sites in the whole console — the
#: wordmark's tagline and the demo notice in the Session panel — and both
#: render on the terminal ground. It never fills a chip, never colours a
#: selected row, and never lands on PANEL_RAISED.
#:
#: This matters because PURPLE is a LOGO colour: it is the second step of the
#: wordmark's gradient, and #9d7cd8 is the value that gradient was designed
#: around. Holding it to a ground it never touches is what pushed it to
#: #a98ae0 and flattened the mark. ``test_purple_is_only_ever_drawn_on_the
#: _ground`` pins the two call sites, so a third one forces this back open.
PURPLE_GROUNDS: tuple[str, ...] = ("BACKGROUND", "PANEL_BG")

#: BORDER never touches a chip fill — a panel edge is drawn on the ground it
#: separates — so it answers for the two grounds it actually meets. Requiring
#: 3:1 against PANEL_RAISED as well would force a bright cage around every
#: panel for a pairing that does not occur.
BORDER_GROUNDS: tuple[str, ...] = ("BACKGROUND", "PANEL_BG")

#: Which grounds each role answers for. Everything meets all three unless it is
#: measurably never drawn on one of them; the two exceptions are stated above.
_GROUNDS_FOR: dict[str, tuple[str, ...]] = {
    "BORDER": BORDER_GROUNDS,
    "PURPLE": PURPLE_GROUNDS,
}

#: The shipped look, frozen. These are the values the console actually renders.
TOKYO = {
    "ACCENT": "#bb9af7",
    "PURPLE": "#9d7cd8",
    "SUCCESS": "#73daca",
    "ORANGE": "#e0af68",
    "RED": "#f7768e",
    "DIM": "#868eb3",
    "DIM_BRIGHT": "#9da2be",
    "BORDER": "#5c6797",
    "PANEL_BG": "#1a1b26",
    "PANEL_RAISED": "#24283b",
    "BACKGROUND": "#16161e",
    "TEXT": "#c0caf5",
    "ACCENT_MUTED": "#3a334e",
    "SUCCESS_MUTED": "#2a4144",
    "ORANGE_MUTED": "#42382e",
    "RED_MUTED": "#482b37",
}


def relative_luminance(colour: str) -> float:
    """WCAG 2.1 relative luminance of an ``#rrggbb`` colour."""

    digits = colour.lstrip("#")
    channels = [int(digits[index:index + 2], 16) / 255 for index in (0, 2, 4)]
    linear = [
        value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4
        for value in channels
    ]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def contrast_ratio(foreground: str, background: str) -> float:
    """WCAG 2.1 contrast ratio between two ``#rrggbb`` colours."""

    lighter = max(relative_luminance(foreground), relative_luminance(background))
    darker = min(relative_luminance(foreground), relative_luminance(background))
    return (lighter + 0.05) / (darker + 0.05)


@pytest.fixture(autouse=True)
def _restore_palette():
    """No test may leave another one rendering in a palette it did not choose."""

    active = M.active_palette_name()
    yield
    M.set_active_palette(active)


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr("forensic_agent.tui.controller.time.sleep", lambda *_: None)


# ---------------------------------------------------------------------------
# contrast
# ---------------------------------------------------------------------------
#: Every theme the console ships, in listing order. The three the console
#: designed for itself first, then the five taken from published terminal
#: palettes — Nord, Gruvbox, Solarized, Catppuccin Mocha and Dracula, each cited
#: to its source in model.py, and each held to exactly the same floors as the
#: three above it rather than shipped at its published values and excused.
SHIPPED: tuple[str, ...] = (
    "dfir-tokyo", "dfir-light", "dfir-contrast",
    "dfir-nord", "dfir-gruvbox", "dfir-solarized", "dfir-mocha", "dfir-dracula",
)


def test_the_console_ships_the_themes_it_says_it_does():
    assert M.available_palettes() == SHIPPED
    assert M.DEFAULT_PALETTE == "dfir-tokyo"
    # The three dicts are keyed together; a theme missing from any one of them
    # is a theme that renders in another theme's chrome or has no wordmark.
    for theme in SHIPPED:
        assert set(M.palette(theme)) == set(M.COLOUR_ROLES), theme
        assert set(M.chrome(theme)) == {"secondary", "footer", "scrollbar", "scrim"}
        assert len(M.banner_colours(theme)) == 6, theme


def test_no_two_themes_are_the_same_theme_under_two_names():
    """A palette added by copying another one is not a choice, it is a duplicate."""

    seen: dict[tuple[str, ...], str] = {}
    for theme in SHIPPED:
        key = tuple(M.palette(theme)[role] for role in M.COLOUR_ROLES)
        assert key not in seen, f"{theme} is identical to {seen.get(key)}"
        seen[key] = theme


@pytest.mark.parametrize("theme", M.available_palettes())
def test_every_palette_states_every_role(theme):
    assert sorted(M.palette(theme)) == sorted(M.COLOUR_ROLES)
    assert all(
        re.fullmatch(r"#[0-9a-f]{6}", value) for value in M.palette(theme).values()
    )


@pytest.mark.parametrize("theme", M.available_palettes())
def test_every_foreground_clears_its_contrast_floor(theme):
    palette = M.palette(theme)
    failures = []
    for role, floor in FLOOR.items():
        grounds = _GROUNDS_FOR.get(role, GROUNDS)
        for ground_role in grounds:
            ground = palette[ground_role]
            measured = contrast_ratio(palette[role], ground)
            if measured < floor:
                failures.append(
                    f"{theme} {role} {palette[role]} on {ground_role} {ground} "
                    f"is {measured:.2f}:1, below the {floor}:1 floor"
                )
    assert failures == []


@pytest.mark.parametrize("theme", M.available_palettes())
def test_a_panel_is_told_from_the_ground_by_its_edge_alone(theme):
    """Why BORDER answers to the component floor and not to "visible".

    The raised surfaces are deliberately barely raised, and this measures how
    barely: if PANEL_BG ever separated from BACKGROUND on its own, the border
    would become decoration and 3:1 would stop applying to it.
    """

    palette = M.palette(theme)
    separation = contrast_ratio(palette["PANEL_BG"], palette["BACKGROUND"])
    assert separation < 1.5, (
        f"{theme} raises PANEL_BG to {separation:.2f}:1 above BACKGROUND; the "
        "border is no longer the only thing bounding a panel, so revisit "
        "BORDER_GROUNDS"
    )


@pytest.mark.parametrize("theme", M.available_palettes())
def test_each_muted_chip_carries_its_own_signal_legibly(theme):
    """A badge is a signal colour on its own fill; that pair has to be readable."""

    palette = M.palette(theme)
    for signal in ("ACCENT", "SUCCESS", "ORANGE", "RED"):
        measured = contrast_ratio(palette[signal], palette[f"{signal}_MUTED"])
        assert measured >= 4.5, f"{theme} {signal} on its chip fill is {measured:.2f}:1"


@pytest.mark.parametrize("theme", M.available_palettes())
def test_the_stylesheet_only_colours_are_readable_too(theme):
    """The footer legend is text, and the wordmark is large text — both count."""

    ground = M.palette(theme)["BACKGROUND"]
    assert contrast_ratio(M.chrome(theme)["footer"], ground) >= 4.5
    for step in M.banner_colours(theme):
        assert contrast_ratio(step, ground) >= 3.0


def test_dfir_tokyo_is_frozen():
    """The shipped look is byte-identical; this palette is what users see."""

    assert M.palette("dfir-tokyo") == TOKYO


def test_the_tokyo_wordmark_matches_the_line_cli():
    from forensic_agent.cli.terminal import BANNER_COLORS

    assert M.banner_colours("dfir-tokyo") == tuple(BANNER_COLORS)


def test_the_two_consoles_agree_about_the_secondary_accent():
    """PURPLE carries the wordmark's tagline in both front ends; one value."""

    from forensic_agent.cli.terminal import PURPLE

    assert PURPLE == M.palette("dfir-tokyo")["PURPLE"] == "#9d7cd8"


def test_purple_is_only_ever_drawn_on_the_ground():
    """Why PURPLE answers for two grounds and not three.

    PURPLE_GROUNDS excludes PANEL_RAISED on a claim about where the colour is
    used, and a claim like that rots the moment somebody adds a third call
    site. So the call sites are counted. Both of the two render on the terminal
    ground — the wordmark's tagline, and the demo notice in the Session panel,
    which is inside a Rich Panel whose own background is $background.

    A third use is not forbidden; it just has to be looked at. If it lands on a
    chip or a selected row, PURPLE has to clear 4.5:1 on PANEL_RAISED, and
    #9d7cd8 reaches only 4.38:1 there.
    """

    console = (SOURCE_ROOT / "forensic_agent" / "tui" / "app.py").read_text(
        encoding="utf-8"
    )
    uses = re.findall(r"^.*\bM\.PURPLE\b.*$", console, flags=re.MULTILINE)
    assert len(uses) == 2, (
        "PURPLE has a call site this exemption has not been measured against:\n"
        + "\n".join(uses)
    )
    assert any("_BANNER_SUBTITLE" in use for use in uses)
    assert any('row("mode"' in use for use in uses)


# ---------------------------------------------------------------------------
# the palette resolves through the module
# ---------------------------------------------------------------------------
def test_role_reads_follow_the_active_palette():
    M.set_active_palette("dfir-tokyo")
    assert (M.ACCENT, M.TEXT, M.BACKGROUND) == ("#bb9af7", "#c0caf5", "#16161e")
    assert M.STATUS_STYLE["ok"][1] == "#73daca"
    assert M.answer_frame(M.ANSWER_VERIFIED)[0] == "#73daca"

    M.set_active_palette("dfir-light")
    light = M.palette("dfir-light")
    assert (M.ACCENT, M.TEXT, M.BACKGROUND) == (
        light["ACCENT"],
        light["TEXT"],
        light["BACKGROUND"],
    )
    assert M.STATUS_STYLE["ok"][1] == light["SUCCESS"]
    assert M.OUTCOME_STYLE[M.OUTCOME_FAILED][1] == light["ORANGE"]
    assert M.answer_frame(M.ANSWER_ASSEMBLED)[0] == light["ORANGE"]


def test_an_unknown_palette_is_refused_and_changes_nothing():
    M.set_active_palette("dfir-contrast")
    with pytest.raises(ValueError):
        M.set_active_palette("solarized")
    assert M.active_palette_name() == "dfir-contrast"
    with pytest.raises(AttributeError):
        M.NOT_A_ROLE  # noqa: B018


def test_no_module_snapshots_a_colour_with_a_from_import():
    """``from ...model import DIM`` would freeze one theme's value at import."""

    pattern = re.compile(
        r"from\s+[\w.]*\btui\.model\s+import\s+\(?([^)\n]*(?:\n[^)]*)?)\)?"
    )
    offenders = []
    for source in SOURCE_ROOT.rglob("*.py"):
        text = source.read_text(encoding="utf-8")
        for match in pattern.finditer(text):
            imported = {name.strip().strip(",") for name in match.group(1).split(",")}
            leaked = imported & set(M.COLOUR_ROLES)
            if leaked:
                offenders.append(f"{source}: {sorted(leaked)}")
    assert offenders == []


# ---------------------------------------------------------------------------
# the two layers agree
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("theme", M.available_palettes())
def test_the_textual_theme_matches_the_palette(theme):
    from forensic_agent.tui.app import _THEMES

    palette = M.palette(theme)
    registered = _THEMES[theme]
    assert registered.name == theme
    assert registered.background == palette["BACKGROUND"]
    assert registered.foreground == palette["TEXT"]
    assert registered.surface == palette["BACKGROUND"]
    assert registered.accent == palette["ACCENT"]
    assert registered.success == palette["SUCCESS"]
    assert registered.warning == palette["ORANGE"]
    assert registered.error == palette["RED"]
    assert registered.variables["dfir-dim"] == palette["DIM"]
    assert registered.variables["dfir-dim-bright"] == palette["DIM_BRIGHT"]


# ---------------------------------------------------------------------------
# the choice survives a restart
# ---------------------------------------------------------------------------
def test_the_theme_is_persisted_and_read_back(tmp_path):
    from forensic_agent.cli.preferences import load_console_theme, save_console_theme

    store = tmp_path / "preferences.json"
    assert load_console_theme(path=store) == "dfir-tokyo"

    save_console_theme("dfir-light", path=store)
    assert load_console_theme(path=store) == "dfir-light"

    # Additive, like every other setting in this file.
    save_console_theme("dfir-contrast", path=store)
    assert '"console_theme": "dfir-contrast"' in store.read_text(encoding="utf-8")

    with pytest.raises(ValueError):
        save_console_theme("solarized", path=store)


@pytest.mark.parametrize("content", ["", "{", '{"console_theme": 7}', '{"console_theme": "gone"}'])
def test_a_corrupt_or_unknown_stored_theme_falls_back(tmp_path, content):
    from forensic_agent.cli.preferences import load_console_theme

    store = tmp_path / "preferences.json"
    store.write_text(content, encoding="utf-8")
    assert load_console_theme(path=store) == "dfir-tokyo"


# ---------------------------------------------------------------------------
# /theme
# ---------------------------------------------------------------------------
def test_theme_is_a_registered_system_command_with_a_handler():
    from forensic_agent.cli.commands import COMMAND_REGISTRY, CommandCategory
    from forensic_agent.tui.app import InvestigationApp

    spec = COMMAND_REGISTRY.resolve("theme")
    assert spec is not None
    assert spec.category is CommandCategory.SYSTEM
    assert spec.usage == "/theme [name]"
    assert spec.description == "Show or switch the console colour theme."
    assert hasattr(InvestigationApp, "_cmd_theme")


def test_bare_and_unknown_theme_both_list_the_choices(monkeypatch, tmp_path):
    """A bare /theme is a chooser opened on the active theme; an unknown name
    is refused and still shows what is valid. Esc changes nothing either way."""

    from textual.widgets import ListView

    from forensic_agent.tui.app import ChoiceScreen, OverlayScreen

    monkeypatch.setenv("DFA_RUNS_DIR", str(tmp_path))

    async def scenario():
        app = build_app(DemoController())
        async with app.run_test(size=(120, 40)) as pilot:
            app.dispatch_command("theme", "")
            await pilot.pause(0.05)
            assert isinstance(app.screen, ChoiceScreen)
            names = M.available_palettes()
            highlighted = app.screen.query_one("#choice-list", ListView).index
            assert names[highlighted] == M.active_palette_name()
            await pilot.press("escape")
            await pilot.pause(0.05)
            assert M.active_palette_name() == "dfir-tokyo"

            # An unknown name must say so and still show what is valid.
            app.dispatch_command("theme", "solarized")
            await pilot.pause(0.05)
            assert isinstance(app.screen, OverlayScreen)
            listing = app.screen.query_one("#overlay-body").render_str("")
            assert M.active_palette_name() == "dfir-tokyo"
            assert listing is not None
            await pilot.press("escape")
            await pilot.pause(0.05)

    asyncio.run(scenario())


def test_switching_repaints_the_whole_console(monkeypatch, tmp_path):
    """A switch redraws the transcript and the panes, not the stylesheet alone."""

    monkeypatch.setenv("DFA_RUNS_DIR", str(tmp_path))
    shots: dict[str, str] = {}

    async def scenario():
        app = build_app(DemoController())
        async with app.run_test(size=(160, 44)) as pilot:
            assert M.active_palette_name() == "dfir-tokyo"
            app.query_one("#prompt").value = "which USB device was connected?"
            await pilot.press("enter")
            for _ in range(120):
                await pilot.pause(0.02)
                if not app.running:
                    break
            assert app.running is False
            # Accepted findings put Rich renderables in the EVIDENCE pane too.
            for exchange, card in list(app._pending_review):
                await app._accept_finding(exchange, card)
            app._pending_review.clear()
            # A focused prompt draws its cursor cell in inverse video, which
            # is a legitimate use of the ground as a foreground; the screenshot
            # is taken from the browsing state so the check stays exact.
            app.query_one("#conversation").focus()
            await pilot.pause(0.1)

            for theme in M.available_palettes():
                app.dispatch_command("theme", theme)
                await pilot.pause(0.2)
                assert M.active_palette_name() == theme
                assert app.theme == theme
                assert app.current_theme.background == M.palette(theme)["BACKGROUND"]
                target = tmp_path / f"{theme}.svg"
                app.save_screenshot(str(target))
                shots[theme] = target.read_text(encoding="utf-8")

    asyncio.run(scenario())

    # Every theme drew a different screen, and each one drew its own ground.
    assert len(set(shots.values())) == len(SHIPPED)
    for theme, svg in shots.items():
        palette = M.palette(theme)
        ground = palette["BACKGROUND"]
        painted = _text_fills(svg)
        assert ground in _rect_fills(svg), f"{theme} did not paint its own ground"
        assert palette["TEXT"] in painted, f"{theme} did not draw in its own ink"
        assert ground not in painted, (
            f"{theme} drew text in its background colour: "
            f"{sorted(_glyphs_with_fill(svg, ground))[:6]}"
        )
        # Nothing may survive from another theme's ink or ground.
        for other in M.available_palettes():
            if other == theme:
                continue
            stale = {M.palette(other)["TEXT"], M.palette(other)["SUCCESS"]}
            assert not (stale & painted), f"{theme} kept {other} colours on screen"


#: Box-drawing (U+2500-U+257F) and block elements (U+2580-U+259F) are chrome,
#: not text: a scrollbar thumb and a half-block are drawn as a character
#: painted in the colour BEHIND them, so such a cell legitimately carries the
#: ground as its fill. Only prose is asked to contrast with the ground.
_CHROME_GLYPHS = re.compile(r"[\s─-▟]*")


def _readable_runs(svg: str) -> list[tuple[set[str], str]]:
    """Every rendered run of real text in an exported screenshot, with its classes."""

    runs = []
    for match in re.finditer(r'<text[^>]*class="([^"]*)"[^>]*>(.*?)</text>', svg, re.S):
        body = match.group(2).replace("&#160;", " ")
        if not body.strip() or _CHROME_GLYPHS.fullmatch(body):
            continue
        runs.append((set(match.group(1).split()), body.strip()))
    return runs


def _class_fills(svg: str) -> dict[str, str]:
    return dict(re.findall(r"\.([\w-]+)\s*\{[^}]*fill:\s*(#[0-9a-fA-F]{6})", svg))


def _text_fills(svg: str) -> set[str]:
    """Every fill a run of real text was drawn in."""

    fills = _class_fills(svg)
    return {
        fills[name]
        for classes, _body in _readable_runs(svg)
        for name in classes
        if name in fills
    }


def _rect_fills(svg: str) -> set[str]:
    return set(re.findall(r'<rect[^>]*fill="(#[0-9a-fA-F]{6})"', svg))


def _glyphs_with_fill(svg: str, fill: str) -> set[str]:
    """What a screenshot wrote in one colour — the evidence behind a failure."""

    fills = _class_fills(svg)
    wanted = {name for name, value in fills.items() if value.lower() == fill.lower()}
    return {body for classes, body in _readable_runs(svg) if classes & wanted}
