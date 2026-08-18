"""Presentation-neutral view model for the investigation console.

The TUI renders these plain dataclasses; it does not reach into the forensic
core directly. Both controllers (:mod:`forensic_agent.tui.controller`) populate
the *same* cards: the demo controller builds them literally, the live
controller builds them from the existing ``presentation`` projections over a
real ``ControlledRun``. Keeping one contract between the two means the demo the
reviewer sees exercises the identical rendering path a live case would.

This module holds no forensic logic and imports nothing from the core, so
``dfir-agent tui --demo`` starts without a provider, Docker, or evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final

# ---------------------------------------------------------------------------
# Palettes — one family at a time, resolved through the module.
#
# Every colour on screen is one of the sixteen roles below, and the console
# reads them as ``model.ACCENT``, ``model.DIM`` and so on from some 260 Rich
# renderables. Those reads land in :func:`__getattr__` (PEP 562), which
# answers from whichever palette is active, so switching the theme repaints
# every one of them without a single call site knowing a theme exists.
#
# The semantic roles are the one place a verdict/grounding state becomes a
# colour, so the transcript, the findings sidebar, the flight recorder and the
# oversight pane all speak the same visual language whatever the palette.
# ---------------------------------------------------------------------------

#: The sixteen roles a palette must state, with the meaning each carries:
#: ACCENT identity/headings, PURPLE the secondary accent, SUCCESS verified ·
#: complete · approved · executed, ORANGE caution (partial coverage, degraded,
#: refused-by-tool), RED failed · blocked · refused-by-oversight, DIM secondary
#: metadata, DIM_BRIGHT metadata that must stay readable at small sizes, BORDER
#: a quiet panel edge, PANEL_BG the raised surface (input, overlays),
#: PANEL_RAISED the second elevation step (chips, selections), BACKGROUND the
#: terminal ground, TEXT the ordinary foreground, and the four *_MUTED chip
#: fills that carry their own signal colour as legible text.
COLOUR_ROLES: Final[tuple[str, ...]] = (
    "ACCENT", "ACCENT_MUTED", "BACKGROUND", "BORDER", "DIM", "DIM_BRIGHT",
    "ORANGE", "ORANGE_MUTED", "PANEL_BG", "PANEL_RAISED", "PURPLE", "RED",
    "RED_MUTED", "SUCCESS", "SUCCESS_MUTED", "TEXT",
)

#: The shipped look. An unknown or corrupt stored name falls back to it.
DEFAULT_PALETTE: Final[str] = "dfir-tokyo"

_PALETTES: Final[dict[str, dict[str, str]]] = {
    # Tokyo Night, the console's own family: the signal accents mirror the
    # line CLI in src/forensic_agent/cli/terminal.py and the grounds and greys
    # come from the same ramp, so nothing on screen falls outside one palette.
    #
    # The greys are Tokyo Night's own ramp lifted until they are readable here.
    # Text renders on three grounds, not one — BACKGROUND, the raised PANEL_BG
    # and the second step PANEL_RAISED that fills chips and selected rows — and
    # the three sit within 1.25:1 of each other, so a panel is told apart from
    # the ground by its border and by nothing else. That makes BORDER a real
    # component boundary rather than decoration, which is why it is held to
    # 3:1 rather than to "visible". Three greys were below their floor: DIM at
    # 2.91:1, DIM_BRIGHT at 4.31:1 and BORDER at 1.83:1.
    #
    # Only lightness was raised. Hue and saturation are the Tokyo Night values
    # to a tenth of a degree and a tenth of a percent, because a grey lifted
    # off its own ramp stops being this theme's grey: the first pass at this
    # doubled DIM_BRIGHT's saturation from 20.2% to 40.3% and the console
    # stopped reading as Tokyo Night. Each is the LOWEST value on its own ramp
    # that clears its floor on every ground it meets, so the theme keeps as
    # much of its character as legibility leaves it.
    #
    # PURPLE was NOT changed. It is the colour the wordmark's tagline is drawn
    # in, and a logo is not a contrast problem to be solved; it measures 5.40:1
    # on BACKGROUND and 5.13:1 on PANEL_BG, the only two grounds it is ever
    # drawn on. See PURPLE_GROUNDS in tests/test_tui_theme.py.
    "dfir-tokyo": {
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
    },
    # Paper: the same roles inverted onto a light ground. Every signal is
    # darkened until it clears 4.5:1 on all three of that theme's grounds,
    # which is why the accents are deeper rather than merely the dark theme's
    # colours on white. The claim used to be made against BACKGROUND alone and
    # was false even there: DIM measured 3.72:1, and SUCCESS and ORANGE fell to
    # 4.47:1 and 4.43:1 on PANEL_RAISED. All three are darker now.
    "dfir-light": {
        "ACCENT": "#6d28d9",
        "PURPLE": "#7c3aed",
        "SUCCESS": "#0d6b63",
        "ORANGE": "#8f5400",
        "RED": "#c11d3f",
        "DIM": "#5f6780",
        "DIM_BRIGHT": "#4c5470",
        "BORDER": "#7d86a8",
        "PANEL_BG": "#ffffff",
        "PANEL_RAISED": "#e5e8f2",
        "BACKGROUND": "#f3f4f9",
        "TEXT": "#1b1e2b",
        "ACCENT_MUTED": "#e7defc",
        "SUCCESS_MUTED": "#dcefea",
        "ORANGE_MUTED": "#f7ead2",
        "RED_MUTED": "#fbdfe4",
    },
    # Maximum separation: pure black ground, pure white body text, and signal
    # colours pushed bright enough that none of them drops below 8:1.
    "dfir-contrast": {
        "ACCENT": "#d0a9ff",
        "PURPLE": "#b98cff",
        "SUCCESS": "#4ce0b3",
        "ORANGE": "#ffb454",
        "RED": "#ff7a90",
        "DIM": "#a8a8bc",
        "DIM_BRIGHT": "#d8d8e8",
        "BORDER": "#6f6f88",
        "PANEL_BG": "#0a0a0e",
        "PANEL_RAISED": "#1c1c26",
        "BACKGROUND": "#000000",
        "TEXT": "#ffffff",
        "ACCENT_MUTED": "#34234f",
        "SUCCESS_MUTED": "#0e3d33",
        "ORANGE_MUTED": "#3e2e10",
        "RED_MUTED": "#4e1724",
    },
    # Nord, from nordtheme.com's own sixteen numbered colours. BACKGROUND is
    # nord0, PANEL_RAISED nord1, TEXT nord6, and the signals are the Aurora
    # group with nord8 (Frost) as the accent. Four values were raised: on a
    # ground this light, Nord's Aurora red and its nord3 grey are well under
    # the floor in the original.
    #
    # Raised from the published value, hue and saturation kept, measured
    # against the raised panel fill before and after:
    #   RED        #bf616a -> #d9a0a6   (2.46 -> 4.57)
    #   DIM        #8a94a6 -> #a8afbc   (3.29 -> 4.56)
    #   PURPLE     #b48ead -> #bd9bb6   (3.97 -> 4.57)
    #   BORDER     #4c566a -> #79869f   (1.53 -> 3.07)
    "dfir-nord": {
        "ACCENT": "#88c0d0",
        "PURPLE": "#bd9bb6",
        "SUCCESS": "#a3be8c",
        "ORANGE": "#ebcb8b",
        "RED": "#d9a0a6",
        "DIM": "#a8afbc",
        "DIM_BRIGHT": "#d8dee9",
        "BORDER": "#79869f",
        "PANEL_BG": "#333b4a",
        "PANEL_RAISED": "#3b4252",
        "BACKGROUND": "#2e3440",
        "TEXT": "#eceff4",
        "ACCENT_MUTED": "#324b52",
        "SUCCESS_MUTED": "#3f4936",
        "ORANGE_MUTED": "#67542d",
        "RED_MUTED": "#5a383b",
    },
    # Gruvbox dark, from morhetz/gruvbox. BACKGROUND is bg0_h (the "hard"
    # variant, the darkest the palette publishes), PANEL_RAISED bg0_s, TEXT
    # fg1, and the signals are the bright set rather than the neutral one,
    # because the neutral reds and greens do not clear 4.5:1 on bg0_s.
    #
    # Raised from the published value, hue and saturation kept, measured
    # against the raised panel fill before and after:
    #   RED        #fb4934 -> #fc6958   (3.82 -> 4.56)
    #   DIM        #928374 -> #a3978a   (3.58 -> 4.60)
    #   BORDER     #665c54 -> #7c7066   (2.26 -> 3.07)
    "dfir-gruvbox": {
        "ACCENT": "#fabd2f",
        "PURPLE": "#d3869b",
        "SUCCESS": "#b8bb26",
        "ORANGE": "#fe8019",
        "RED": "#fc6958",
        "DIM": "#a3978a",
        "DIM_BRIGHT": "#bdae93",
        "BORDER": "#7c7066",
        "PANEL_BG": "#282828",
        "PANEL_RAISED": "#32302f",
        "BACKGROUND": "#1d2021",
        "TEXT": "#ebdbb2",
        "ACCENT_MUTED": "#634f1f",
        "SUCCESS_MUTED": "#474721",
        "ORANGE_MUTED": "#513118",
        "RED_MUTED": "#521f19",
    },
    # Solarized dark, from Ethan Schoonover's published specification.
    # BACKGROUND is base03, PANEL_RAISED base02, TEXT base2 — base0, the
    # nominal body text, reaches only 5.9:1 and this console holds body text
    # to 7:1. Solarized is built to a much lower contrast target than the rest
    # of this file, so more of it moved than any other palette here.
    #
    # Raised from the published value, hue and saturation kept, measured
    # against the raised panel fill before and after:
    #   ACCENT     #2aa198 -> #2daba1   (4.12 -> 4.61)
    #   SUCCESS    #859900 -> #8ea300   (4.06 -> 4.57)
    #   ORANGE     #b58900 -> #c19200   (4.05 -> 4.57)
    #   RED        #dc322f -> #e87876   (2.81 -> 4.57)
    #   DIM        #839496 -> #8d9d9e   (4.11 -> 4.61)
    #   PURPLE     #6c71c4 -> #8a8ed0   (3.22 -> 4.61)
    #   BORDER     #586e75 -> #617981   (2.62 -> 3.06)
    "dfir-solarized": {
        "ACCENT": "#2daba1",
        "PURPLE": "#8a8ed0",
        "SUCCESS": "#8ea300",
        "ORANGE": "#c19200",
        "RED": "#e87876",
        "DIM": "#8d9d9e",
        "DIM_BRIGHT": "#93a1a1",
        "BORDER": "#617981",
        "PANEL_BG": "#02303b",
        "PANEL_RAISED": "#073642",
        "BACKGROUND": "#002b36",
        "TEXT": "#eee8d5",
        "ACCENT_MUTED": "#1b3432",
        "SUCCESS_MUTED": "#2f330f",
        "ORANGE_MUTED": "#392f11",
        "RED_MUTED": "#4e2322",
    },
    # Catppuccin Mocha, from catppuccin/catppuccin. Base, surface0, text,
    # mauve, lavender, green, peach, red, subtext0 and subtext1, verbatim: the
    # ONLY palette here that clears every floor with nothing changed at all,
    # which is what a palette designed against a contrast target looks like.
    #
    # Nothing was raised. Every published value clears its floor as it is.
    "dfir-mocha": {
        "ACCENT": "#cba6f7",
        "PURPLE": "#b4befe",
        "SUCCESS": "#a6e3a1",
        "ORANGE": "#fab387",
        "RED": "#f38ba8",
        "DIM": "#a6adc8",
        "DIM_BRIGHT": "#bac2de",
        "BORDER": "#7f849c",
        "PANEL_BG": "#232334",
        "PANEL_RAISED": "#313244",
        "BACKGROUND": "#1e1e2e",
        "TEXT": "#cdd6f4",
        "ACCENT_MUTED": "#593288",
        "SUCCESS_MUTED": "#365e33",
        "ORANGE_MUTED": "#734326",
        "RED_MUTED": "#69283a",
    },
    # Dracula, from draculatheme.com's specification. Background, current line,
    # foreground, purple, pink, green, orange and red are the published values.
    # Dracula's "comment" grey is the problem case in this file: at 1.94:1 on
    # the current-line fill it is the least legible metadata colour of any
    # palette here, and lifting it is what makes this theme usable rather than
    # merely recognisable.
    #
    # Raised from the published value, hue and saturation kept, measured
    # against the raised panel fill before and after:
    #   ACCENT     #bd93f9 -> #caa8fa   (3.79 -> 4.57)
    #   RED        #ff5555 -> #ff9c9c   (2.91 -> 4.57)
    #   DIM        #6272a4 -> #afb7d1   (1.94 -> 4.58)
    #   BORDER     #6272a4 -> #6978a8   (2.81 -> 3.06)
    "dfir-dracula": {
        "ACCENT": "#caa8fa",
        "PURPLE": "#ff79c6",
        "SUCCESS": "#50fa7b",
        "ORANGE": "#ffb86c",
        "RED": "#ff9c9c",
        "DIM": "#afb7d1",
        "DIM_BRIGHT": "#c9cbe0",
        "BORDER": "#6978a8",
        "PANEL_BG": "#2d2f3d",
        "PANEL_RAISED": "#44475a",
        "BACKGROUND": "#282a36",
        "TEXT": "#f8f8f2",
        "ACCENT_MUTED": "#593190",
        "SUCCESS_MUTED": "#226b34",
        "ORANGE_MUTED": "#6f4920",
        "RED_MUTED": "#822626",
    },
    # Carbon: the console with the colour taken out of its identity. ACCENT is
    # white, so a command name, a heading and a pane title are white rather
    # than tinted, and the only colours left on screen are the four that carry
    # a verdict. It is the theme for reading a command sheet or a long
    # transcript, where every accent competing for the eye is one more thing to
    # ignore.
    #
    # The greys are neutral to a tenth of a percent of saturation rather than
    # cooled towards blue, because a white accent on a blue-grey ground reads
    # as a mistake in the accent rather than as a choice about the ground. The
    # signal four keep their hues — a verdict is the one thing this theme does
    # not desaturate — and each is lifted until it clears the floor on the
    # darkest ground it meets, which on a carbon ground is generous headroom.
    "dfir-carbon": {
        "ACCENT": "#fafaff",
        "PURPLE": "#cfcfe4",
        "SUCCESS": "#7fd6a4",
        "ORANGE": "#e2b673",
        "RED": "#f39a9a",
        "DIM": "#a3a3a8",
        "DIM_BRIGHT": "#c2c2c8",
        "BORDER": "#6f6f78",
        "PANEL_BG": "#17171a",
        "PANEL_RAISED": "#26262b",
        "BACKGROUND": "#121214",
        "TEXT": "#e8e8ec",
        "ACCENT_MUTED": "#3d3d45",
        "SUCCESS_MUTED": "#1f4030",
        "ORANGE_MUTED": "#453720",
        "RED_MUTED": "#4a2626",
    },
}

#: Colours the stylesheet needs that carry no semantic role: the Textual
#: ``$secondary``, the footer's quiet foreground, the scrollbar track and the
#: veil a modal draws over the console behind it.
_CHROME: Final[dict[str, dict[str, str]]] = {
    "dfir-tokyo": {
        "secondary": "#7aa2f7",
        "footer": "#a9b1d6",
        "scrollbar": "#2f334d",
        "scrim": "#0c0c14",
    },
    "dfir-light": {
        "secondary": "#2e5fd9",
        "footer": "#4c5470",
        "scrollbar": "#b9bfd6",
        "scrim": "#1b1e2b",
    },
    "dfir-contrast": {
        "secondary": "#7ab8ff",
        "footer": "#d8d8e8",
        "scrollbar": "#55556a",
        "scrim": "#000000",
    },
    "dfir-nord": {
        "secondary": "#81a1c1",
        "footer": "#d8dee9",
        "scrollbar": "#3b4252",
        "scrim": "#101216",
    },
    "dfir-gruvbox": {
        "secondary": "#83a598",
        "footer": "#bdae93",
        "scrollbar": "#32302f",
        "scrim": "#0a0b0c",
    },
    "dfir-solarized": {
        "secondary": "#3194da",
        "footer": "#93a1a1",
        "scrollbar": "#073642",
        "scrim": "#000f13",
    },
    "dfir-mocha": {
        "secondary": "#89b4fa",
        "footer": "#bac2de",
        "scrollbar": "#313244",
        "scrim": "#0a0a10",
    },
    "dfir-dracula": {
        "secondary": "#8be9fd",
        "footer": "#c9cbe0",
        "scrollbar": "#44475a",
        "scrim": "#0e0f13",
    },
    "dfir-carbon": {
        "secondary": "#b8b8c4",
        "footer": "#bcbcc4",
        "scrollbar": "#3a3a42",
        "scrim": "#08080a",
    },
}

#: The wordmark's gradient, one colour per row of the art. The tokyo tuple is
#: ``cli.terminal.BANNER_COLORS`` verbatim — tests/test_tui_theme.py asserts
#: the two stay identical, so the shipped mark cannot drift from the line CLI.
_BANNER: Final[dict[str, tuple[str, ...]]] = {
    "dfir-tokyo": ("#7aa2f7", "#8a9cf6", "#9a95f5", "#aa8ef4", "#b58cf6", "#bb9af7"),
    "dfir-light": ("#2e5fd9", "#3d54d7", "#4c4ad6", "#5a41d5", "#6535d7", "#6d28d9"),
    "dfir-contrast": ("#7ab8ff", "#8fb4ff", "#a4b0ff", "#b3adff", "#c2abff", "#d0a9ff"),
    # Each new theme's mark is a short sweep between two colours of its OWN
    # palette, so the wordmark belongs to the theme rather than being recoloured
    # from somewhere else.
    "dfir-nord": ("#81a1c1", "#82a7c4", "#84adc7", "#85b4ca", "#87bacd", "#88c0d0"),
    "dfir-gruvbox": ("#fe8019", "#fd8c1d", "#fc9822", "#fca526", "#fbb12b", "#fabd2f"),
    "dfir-solarized": ("#268bd2", "#278fc6", "#2894bb", "#2898af", "#299da4", "#2aa198"),
    "dfir-mocha": ("#89b4fa", "#96b1f9", "#a3aef9", "#b1acf8", "#bea9f8", "#cba6f7"),
    "dfir-dracula": ("#8be9fd", "#95d8fc", "#9fc7fb", "#a9b5fb", "#b3a4fa", "#bd93f9"),
    # White to a quiet silver: the mark keeps its shape and gives up its hue,
    # which is the whole of what this theme is.
    "dfir-carbon": ("#fafaff", "#ebebf2", "#d8d8e2", "#c5c5d2", "#b2b2c2", "#9f9fb2"),
}

_active_palette = DEFAULT_PALETTE


def available_palettes() -> tuple[str, ...]:
    """Every theme name this console ships, in listing order."""

    return tuple(_PALETTES)


def active_palette_name() -> str:
    """The theme the colour roles currently resolve against."""

    return _active_palette


def set_active_palette(name: str) -> str:
    """Make ``name`` the active theme and return its canonical name."""

    canonical = (name or "").strip().casefold()
    if canonical not in _PALETTES:
        raise ValueError(f"Unknown theme: {name}")
    global _active_palette
    _active_palette = canonical
    return canonical


def palette(name: str | None = None) -> dict[str, str]:
    """The sixteen colour roles of one theme, or of the active one."""

    return dict(_PALETTES[name or _active_palette])


def chrome(name: str | None = None) -> dict[str, str]:
    """The stylesheet-only colours of one theme, or of the active one."""

    return dict(_CHROME[name or _active_palette])


def banner_colours(name: str | None = None) -> tuple[str, ...]:
    """The wordmark gradient of one theme, or of the active one."""

    return _BANNER[name or _active_palette]


if TYPE_CHECKING:  # resolved at runtime by __getattr__ below
    ACCENT: str
    ACCENT_MUTED: str
    BACKGROUND: str
    BORDER: str
    DIM: str
    DIM_BRIGHT: str
    ORANGE: str
    ORANGE_MUTED: str
    PANEL_BG: str
    PANEL_RAISED: str
    PURPLE: str
    RED: str
    RED_MUTED: str
    SUCCESS: str
    SUCCESS_MUTED: str
    TEXT: str
    STATUS_STYLE: dict[str, tuple[str, str]]
    OUTCOME_STYLE: dict[str, tuple[str, str, str]]
    ANSWER_STYLE: dict[str, tuple[str, str, str]]

# Glyphs — one terminal cell each, identical to the line CLI.
GLYPH_OK = "✓"       # ✓ verified · approved · executed
GLYPH_WARN = "▲"     # ▲ partial · degraded · refused-by-tool
GLYPH_ERROR = "✗"    # ✗ failed · blocked · refused-by-oversight
GLYPH_UNKNOWN = "·"  # · never established
GLYPH_ABSENT = "○"   # ○ optional and not present
GLYPH_POINT = "›"    # › pointer in a hint / sub-step

# Recorded outcome vocabulary (mirrors oversight/audit.py + presentation.py).
OUTCOME_EXECUTED = "executed"
OUTCOME_FAILED = "failed"
OUTCOME_REFUSED_BY_OVERSIGHT = "refused_by_oversight"
OUTCOME_REFUSED_BY_TOOL = "refused_by_tool"

# finding status -> (glyph, colour)   (mirrors findings_view.STATUS_GLYPH)
def _status_style() -> dict[str, tuple[str, str]]:
    active = _PALETTES[_active_palette]
    return {
        "ok": (GLYPH_OK, active["SUCCESS"]),
        "partial": (GLYPH_WARN, active["ORANGE"]),
        "error": (GLYPH_ERROR, active["RED"]),
        "blocked": (GLYPH_ERROR, active["RED"]),
        "unknown": (GLYPH_UNKNOWN, active["DIM"]),
    }


# recorded outcome -> (glyph, colour, word)  (mirrors RECORDED_OUTCOME_DISPLAY)
def _outcome_style() -> dict[str, tuple[str, str, str]]:
    active = _PALETTES[_active_palette]
    return {
        OUTCOME_EXECUTED: (GLYPH_OK, active["SUCCESS"], "ok"),
        OUTCOME_FAILED: (GLYPH_WARN, active["ORANGE"], "failed"),
        OUTCOME_REFUSED_BY_OVERSIGHT: (GLYPH_ERROR, active["RED"], "BLOCKED"),
        OUTCOME_REFUSED_BY_TOOL: (GLYPH_ERROR, active["RED"], "refused"),
    }

# answer source -> (colour, glyph, qualifier)  (mirrors exchange_view._ANSWER_FRAMING)
ANSWER_VERIFIED = "verified model report"
ANSWER_VERIFIED_WITH_BOUND = "verified model report, coverage bound stated"
ANSWER_UNVERIFIED_DRAFT = "unverified model draft"
ANSWER_DRAFT_VERIFICATION_INCOMPLETE = "model draft, verification incomplete"
ANSWER_ASSEMBLED = "runtime-assembled answer"
ANSWER_NONE = "no accepted answer"
#: An answer read back out of a stored run rather than produced by one now.
#:
#: It needs a state of its own because the run's OWN verdict is not on disk:
#: whether the answer was verified, and against what, lives in the run's
#: telemetry and is never written for a run that succeeded. Replaying such a
#: turn as ANSWER_VERIFIED would be a claim nothing supports, and replaying it
#: as ANSWER_NONE would say the answer was not accepted when it plainly was —
#: it is the answer the operator was given. So it says what is true: this text
#: is what was saved, and the verdict that went with it was not.
ANSWER_REPLAYED = "restored from the record"

def _answer_style() -> dict[str, tuple[str, str, str]]:
    active = _PALETTES[_active_palette]
    success, orange = active["SUCCESS"], active["ORANGE"]
    return {
        ANSWER_VERIFIED: (success, GLYPH_OK, ""),
        ANSWER_VERIFIED_WITH_BOUND: (success, GLYPH_OK, "coverage bound stated"),
        ANSWER_UNVERIFIED_DRAFT: (orange, GLYPH_WARN, "unverified draft"),
        ANSWER_DRAFT_VERIFICATION_INCOMPLETE: (
            orange, GLYPH_WARN, "verification incomplete",
        ),
        ANSWER_ASSEMBLED: (orange, GLYPH_WARN, "assembled; not verified"),
        ANSWER_NONE: (orange, GLYPH_WARN, "not accepted by the run"),
        # Neither a pass nor a failure: a restored answer is not being judged
        # here, so it carries the metadata colour rather than a verdict one.
        ANSWER_REPLAYED: (
            active["DIM_BRIGHT"], GLYPH_POINT, "restored; the run's verdict was not saved",
        ),
    }


#: The style maps are palette-derived too, so they cannot be plain constants:
#: a module attribute would freeze the colours of whichever theme was active
#: when this module was first imported.
_DERIVED: Final[dict[str, object]] = {
    "STATUS_STYLE": _status_style,
    "OUTCOME_STYLE": _outcome_style,
    "ANSWER_STYLE": _answer_style,
}


def __getattr__(name: str) -> object:
    """Resolve the colour roles and style maps against the active palette.

    PEP 562: the sixteen role names are deliberately absent from the module
    namespace so every ``model.ACCENT`` read arrives here and answers from the
    palette in force. A ``from ... import ACCENT`` would snapshot one theme's
    value instead and is why no such import exists.
    """

    active = _PALETTES[_active_palette]
    if name in active:
        return active[name]
    derived = _DERIVED.get(name)
    if derived is not None:
        return derived()  # type: ignore[operator]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def answer_frame(answer_source: str) -> tuple[str, str, str]:
    """Return (colour, glyph, qualifier) for a run's answer-source verdict."""

    styles = _answer_style()
    return styles.get(answer_source, styles[ANSWER_NONE])


def is_grounded(answer_source: str) -> bool:
    """Whether the run's answer stands on evidence it actually read."""

    return answer_source in (ANSWER_VERIFIED, ANSWER_VERIFIED_WITH_BOUND)


# Verb-ish prefixes stripped when turning an operation name into plain words.
_LEAD_WORDS = (
    "read_", "list_", "enumerate_", "resolve_", "carve_", "scan_", "get_",
    "load_", "parse_", "extract_", "fetch_", "query_", "check_", "find_",
)


def humanize(name: str) -> str:
    """Turn a machine name (``read_setupapi_log``) into words (``setupapi log``)."""

    text = (name or "").strip()
    for prefix in _LEAD_WORDS:
        if text.startswith(prefix):
            text = text[len(prefix):]
            break
    return text.replace("_", " ").strip()


# ---------------------------------------------------------------------------
# The cards the panes render.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class StatusState:
    """What the status bar shows: the standing frame of the investigation."""

    mode: str  # "DEMO" or "LIVE"
    model: str
    provider: str
    case_label: str
    case_id: str
    evidence_sources: tuple[str, ...]  # e.g. ("disk: laptop.E01", "memory: mem.raw")
    max_steps: int
    max_tool_calls: int
    #: Seconds of wall clock one message may spend. No default: a status this
    #: console shows must state the clock it actually runs under, and a
    #: fallback here would be a fourth place the number lives.
    max_wall_time_s: int
    max_model_requests: int
    reasoning_effort: str


@dataclass(slots=True)
class ToolEvent:
    """One row of the live flight recorder, as a tool call runs.

    Emitted by a controller's ``on_tool`` callback. ``status`` is one of
    ``running`` (in flight), ``approved`` / ``refused`` (from the live oversight
    gate) or, once the run's oversight rows are read back, promoted to an
    ``OUTCOME_*`` value so a completed call reads as executed / failed /
    refused. Rows are keyed by ``sequence``.
    """

    sequence: int
    function: str
    operation: str
    args_summary: str
    status: str  # running | approved | refused | executed | failed | refused_by_*
    duration_s: float | None = None
    evidence_id: str = ""


@dataclass(frozen=True, slots=True)
class OversightCard:
    """One deterministic capability decision — the oversight-pane atom."""

    sequence: int
    function: str
    operation: str
    outcome: str  # OUTCOME_*
    requested_caps: tuple[str, ...]
    granted_caps: tuple[str, ...]
    allowed_tools: tuple[str, ...] | None
    write_scope: tuple[str, ...]
    risk_name: str
    reasons: tuple[str, ...]
    duration_s: float | None
    arguments: tuple[tuple[str, str], ...]
    output_digests: tuple[tuple[str, str], ...] = ()
    #: The sentence the refusing layer wrote, read back out of the recorded
    #: output.  ``reasons`` names a refusal by its code and puts it last; this
    #: is the readable form, and the pane leads with it.
    refusal_message: str = ""
    #: What the tool itself declared when a call reached it and came back
    #: unsuccessful — the error code, or the tool's own one-line prose where the
    #: surface predates the error contract. This is the only place a *failed*
    #: call (as against a refused one) says why: the oversight record classifies
    #: the outcome, and this is the ground it classified on. Empty for a policy
    #: denial, whose whole ground is already in ``reasons``.
    outcome_detail: str = ""


@dataclass(frozen=True, slots=True)
class FindingCard:
    """One standardized finding — list row and detail in a single struct."""

    sequence: int
    status: str  # ok | partial | error | blocked | unknown
    function: str
    operation: str
    data_type: str
    records: str
    coverage_label: str
    coverage_complete: bool | None
    coverage_scope: str
    coverage_reason: str
    receipt_full: str  # 64-hex SHA-256 the result was recorded under, or "—"
    arguments: tuple[tuple[str, str], ...]
    result_summary: str
    source_id: str
    source_uri: str
    evidence_class: str
    warnings: tuple[str, ...]
    oversight_sequence: int | None
    #: A short plain-language name for the pane ("USB device", "setup log").
    #: Falls back to a humanized operation/data-type when not set.
    label: str = ""

    @property
    def display_label(self) -> str:
        if self.label:
            return self.label
        base = self.operation or self.data_type.split(".")[-1]
        plain = humanize(base)
        return plain or self.function or self.data_type

    @property
    def receipt_short(self) -> str:
        if self.receipt_full in ("", "—"):
            return "—"
        return self.receipt_full[:12] + "…"

    @property
    def evidence_id(self) -> str:
        return self.source_id or "—"


@dataclass(frozen=True, slots=True)
class ControlCard:
    """The run summary: what the answer on screen amounts to, and its cost."""

    verification: str
    answer_source: str
    tool_calls: int
    findings: int
    model_requests: int | None
    trace_id: str
    elapsed_s: float


@dataclass(frozen=True, slots=True)
class InvestigationResult:
    """Everything one answered question produces, ready to render."""

    question: str
    answer_markdown: str
    answer_source: str
    evidence_ids: tuple[str, ...]  # sources supporting the published answer
    findings: tuple[FindingCard, ...]
    oversight: tuple[OversightCard, ...]
    controls: ControlCard
    incomplete: bool = False
    note: str = ""  # a short line shown when the run published nothing


@dataclass(slots=True)
class ScriptedToolStep:
    """A demo flight-recorder step: how it looks running, then how it lands."""

    function: str
    operation: str
    args_summary: str
    final_status: str  # OUTCOME_* (or "approved" for a refused-by-oversight demo)
    duration_s: float
    evidence_id: str = ""
    run_delay_s: float = 0.35  # dwell in the "running" state, for the live feel


@dataclass(slots=True)
class DemoInvestigation:
    """A fully canned case: the status frame, a tool script, and the result."""

    status: StatusState
    question: str
    tool_script: tuple[ScriptedToolStep, ...]
    result: InvestigationResult
    followups: tuple[str, ...] = field(default_factory=tuple)
