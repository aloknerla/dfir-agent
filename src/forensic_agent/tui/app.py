"""The investigation console — a full-screen Textual TUI over the DFIR agent.

A presentation layer only. It drives an
:class:`~forensic_agent.tui.controller.InvestigationController` (demo or live)
and renders what comes back:

* **A standing frame** at the top — mode, model, provider, case and evidence,
  always visible, labelled fields rather than separator chains.
* **The conversation on the left** — the line CLI's banner and Session panel
  open it, then each exchange is a pair of bordered message panels: the
  question under a quiet ``❯ you`` frame, the answer under a frame whose
  border and subtitle carry the verdict.
* **The live instruments on the right** — ACTIVITY streams every tool call as
  it runs (name, arguments, outcome, duration), EVIDENCE lists the findings
  (Enter opens *where this came from*), GUARDRAILS states what was blocked.
* **Command parity** — the slash commands the line shell understands are
  dispatched here with their arguments; ``/case`` opens evidence at runtime,
  including the multi-source selection the shell resolves interactively.

The palette is one Tokyo Night family (model.py), shared between the TCSS
variables and every Rich renderable, and it stays legible with no colour at
all — the glyphs ✓ ▲ ✗ carry the meaning on their own.
"""

from __future__ import annotations

import io
import re
import threading
from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from functools import partial
from typing import Any, ClassVar, Final, cast

from rich import box
from rich.console import Console as RichConsole
from rich.console import Group, RenderableType
from rich.markdown import Markdown
from rich.padding import Padding
from rich.panel import Panel
from rich.rule import Rule
from rich.style import Style
from rich.table import Table
from rich.text import Text
from rich.theme import Theme as RichTheme
from textual import events, on, work
from textual.app import App, ComposeResult
from textual.binding import Binding, BindingType
from textual.command import DiscoveryHit, Hit, Hits, Provider
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.css.query import NoMatches
from textual.geometry import Size
from textual.message import Message
from textual.reactive import Reactive, reactive
from textual.screen import ModalScreen
from textual.suggester import SuggestFromList
from textual.theme import Theme
from textual.widget import Widget
from textual.widgets import (
    Collapsible,
    Footer,
    Input,
    Label,
    ListItem,
    ListView,
    Static,
)

from forensic_agent.cli.i18n import t as _t
from forensic_agent.cli.terminal import BANNER_ART as _BANNER_ART
from forensic_agent.cli.terminal import BANNER_SUBTITLE as _BANNER_SUBTITLE
from forensic_agent.core.durations import format_duration
from forensic_agent.tui import model as M
from forensic_agent.tui.controller import InvestigationController
from forensic_agent.tui.model import FindingCard, InvestigationResult, OversightCard, ToolEvent

_RECORDS_RE = re.compile(r"([\d,]+)\s*/\s*([\d,]+)\s*([A-Za-z]+)?")

#: The class every widget the SIMPLE layout adds to the conversation carries.
#: The two layouts each own an activity surface — the pane on the right, or
#: these inline rows — and switching between them must leave exactly one of
#: them on screen, so the layout that takes over removes the other's widgets
#: by this class instead of leaving them behind for the operator to read twice.
_INLINE_ACTIVITY_CLASS = "inline-activity"

# Each palette in model.py gets a Textual theme built from the same hex
# values, so the $variables of the stylesheet below and the Rich renderables
# above them can never disagree about what colour anything is: $background IS
# the palette's BACKGROUND and $foreground IS its TEXT. The four roles the
# stylesheet needs that carry no semantic meaning ($secondary, the footer
# foreground, the scrollbar track, the modal veil) come from model.chrome().
def _build_theme(name: str) -> Theme:
    palette = M.palette(name)
    chrome = M.chrome(name)
    ground, ink = palette["BACKGROUND"], palette["TEXT"]
    accent, muted = palette["ACCENT"], palette["ACCENT_MUTED"]
    return Theme(
        name=name,
        primary=accent,
        secondary=chrome["secondary"],
        accent=accent,
        foreground=ink,
        background=ground,
        # Surface deliberately equals the ground and the boost layer is fully
        # transparent: depth comes from borders, not lighter fills, and widgets
        # that render on $surface / $boost stay seamless.
        surface=ground,
        boost="#ffffff00",
        panel=palette["PANEL_RAISED"],
        success=palette["SUCCESS"],
        warning=palette["ORANGE"],
        error=palette["RED"],
        dark=name != "dfir-light",
        variables={
            "footer-background": ground,
            "footer-item-background": ground,
            "footer-key-background": ground,
            "footer-key-foreground": accent,
            "footer-description-background": ground,
            "footer-description-foreground": chrome["footer"],
            "footer-foreground": chrome["footer"],
            "block-cursor-foreground": ink,
            "block-cursor-background": muted,
            "block-cursor-text-style": "none",
            "block-cursor-blurred-foreground": ink,
            "block-cursor-blurred-background": f"{muted} 45%",
            "block-hover-background": f"{muted} 30%",
            "input-cursor-background": accent,
            "input-cursor-foreground": ground,
            "input-selection-background": f"{accent} 35%",
            "border": accent,
            "border-blurred": palette["BORDER"],
            # The stylesheet's own names, so the TCSS below never has to bake
            # a hex value in and can follow a theme change like everything else.
            "dfir-dim": palette["DIM"],
            "dfir-dim-bright": palette["DIM_BRIGHT"],
            "dfir-chip": muted,
            "dfir-scrollbar": chrome["scrollbar"],
            "dfir-scrim": chrome["scrim"],
        },
    )


_THEMES: dict[str, Theme] = {name: _build_theme(name) for name in M.available_palettes()}


def _saved_theme() -> str:
    """The operator's stored theme, or the shipped one if it cannot be read."""

    try:
        from forensic_agent.cli.preferences import load_console_theme

        return load_console_theme()
    except Exception:
        return M.DEFAULT_PALETTE


def _painted(build: Callable[[], RenderableType], **attributes) -> Static:
    """A ``Static`` that keeps the recipe for what it shows.

    Rich bakes its colours in when a renderable is built, so a re-themed
    console would keep every line it had already drawn. Holding the builder
    beside the result is what lets ``/theme`` redraw each line — from the same
    question, result and cards it was first written from — instead of leaving
    the transcript in the previous palette.
    """

    widget = Static(build(), **attributes)
    widget._dfir_build = build  # type: ignore[attr-defined]
    return widget


def _paint(widget: Static, build: Callable[[], RenderableType]) -> Static:
    """Redraw a mounted widget from a new recipe and keep that one instead."""

    widget._dfir_build = build  # type: ignore[attr-defined]
    widget.update(build())
    return widget


# ---------------------------------------------------------------------------
# the clipboard: OSC 52, and saying so when it cannot work
# ---------------------------------------------------------------------------
#: The width a copied card is rendered at. Deliberately far wider than the
#: modal: the reason to copy a card is the identifiers on it, and a receipt
#: folded across two lines by the renderer is a receipt that has to be repaired
#: by hand after pasting. Nothing this console prints is longer than this, so
#: nothing in a copy is ever broken across lines.
_COPY_WIDTH = 200


def _copy_obstacles(driver: object | None) -> tuple[str, str]:
    """What stands between an OSC 52 copy and the operator's clipboard.

    Returns ``(refusal, caveat)``. A refusal means the copy cannot arrive and
    is not attempted; a caveat means it is sent but something downstream may
    still drop it. Both are said on screen — a clipboard action that silently
    does nothing is worse than no clipboard action, because the operator walks
    away believing they have the hash.

    OSC 52 is the right mechanism here and the checks below are the ones worth
    making. It travels in the terminal's own output stream, so it crosses SSH
    and a container boundary exactly as the rest of the drawing does — there is
    no clipboard daemon, no X display and no host tool involved, which is why
    ``xclip``-style copying is not an option in this image at all. What it
    cannot do is force a terminal that ignores the sequence to honour it, and
    the sequence carries no reply, so the honest checks are the known refusers
    and the known interceptors rather than a handshake that does not exist.
    """

    import os as _os

    if driver is None:
        # Headless: there is no terminal to write the sequence to.
        return ("this console is not attached to a terminal", "")
    environment = _os.environ
    term = (environment.get("TERM") or "").strip().casefold()
    if not term or term == "dumb":
        return ("this terminal declares no capabilities (TERM is unset or 'dumb')", "")
    if (environment.get("TERM_PROGRAM") or "").strip() == "Apple_Terminal":
        return ("macOS Terminal ignores OSC 52 clipboard writes", "")
    if environment.get("TMUX"):
        return ("", "tmux passes it on only with set-clipboard on")
    if term.startswith("screen") and environment.get("STY"):
        return ("", "GNU screen passes it on only if it was built for it")
    return ("", "")


def _as_copy_text(renderable: RenderableType) -> str:
    """One renderable as the plain text a paste should produce.

    The card is built out of Rich renderables, so the text is taken from the
    same objects that were drawn rather than assembled a second time from the
    finding — a copy that says something the card does not is a worse defect
    than no copy at all.
    """

    console = RichConsole(
        width=_COPY_WIDTH,
        file=io.StringIO(),
        record=True,
        no_color=True,
        highlight=False,
    )
    console.print(renderable)
    lines = [line.rstrip() for line in console.export_text().splitlines()]
    return "\n".join(lines).strip("\n") + "\n"


class ThemedMarkdown:
    """Markdown whose code spans follow the palette instead of Rich's default.

    Rich styles ``markdown.code`` cyan on black, which is a dark blot on a light
    ground. An answer names tools, files and addresses in backticks on almost
    every line, so the default would decide the look of the whole transcript.
    """

    def __init__(self, markup: str) -> None:
        self._markup = markup

    def __rich_console__(self, console: Any, options: Any) -> Iterator[Any]:
        code = Style(color=M.SUCCESS, bgcolor=M.SUCCESS_MUTED)
        with console.use_theme(
            RichTheme(
                {"markdown.code": code + Style(bold=True), "markdown.code_block": code}
            )
        ):
            yield from console.render(Markdown(self._markup), options)


# ---------------------------------------------------------------------------
# plain-language helpers (no jargon reaches the main view through these)
# ---------------------------------------------------------------------------
def _verdict(answer_source: str) -> tuple[str, str, str]:
    """(glyph, colour, word) for a run's answer — plain, not 'answer_source'."""

    if M.is_grounded(answer_source):
        return (M.GLYPH_OK, M.SUCCESS, "grounded")
    return ("⚠", M.ORANGE, "unverified")


def _plain_coverage(card: FindingCard, subject: str = "") -> str:
    """"read first 4000 of 18213 bytes — more remains" — never 'coverage bound'.

    ``subject`` names what was read, and the phrase is built around it. Without
    it the sentence has no object at all — "read in full" leaves the reviewer
    to guess what was read in full — so the caller passes whatever the record
    says the call actually examined, and only a card whose record names nothing
    falls back to the bare form.
    """

    if card.coverage_complete is None:
        # Unknown is not "partial": the record does not say how much was read,
        # and claiming a bound the record never stated would be a fabrication.
        return (
            f"how much of {subject} was read was not recorded"
            if subject
            else "how much was read was not recorded"
        )
    if card.coverage_complete:
        return f"read {subject} in full" if subject else "read in full"
    match = _RECORDS_RE.match(card.records or "")
    where = f" of {subject}" if subject else ""
    if match:
        seen, total, unit = match.group(1), match.group(2), (match.group(3) or "items")
        return f"read the first {seen} of {total} {unit}{where}, and more remains"
    return f"only part{where} was read, and more remains"


def _recorded_clause(recorded: str) -> str:
    """What the call recorded, as a clause that finishes someone else's sentence.

    A clause rather than a sentence of its own: the review card says what the
    call examined and what it brought back in ONE sentence, and two fragments
    ("… examined the evidence source." / "It recorded 44/179 records.") is what
    that sentence was before. The record keeps the count as "seen/total", which
    reads as a fraction when the two agree, so it is read out rather than
    printed; the numbers themselves are never changed here.
    """

    match = _RECORDS_RE.match(recorded)
    if match:
        seen, total, unit = match.group(1), match.group(2), (match.group(3) or "records")
        if seen == total:
            singular = seen in ("1", "1,")
            noun = unit[:-1] if singular and unit.endswith("s") else unit
            return f"recorded {seen} {noun}, which was all there was"
        return f"recorded {seen} of {total} {unit}"
    return f"recorded {recorded}"


def _blocked_reason(card: OversightCard) -> str:
    """A denial in plain words, from what the step reached for."""

    caps = {c.lower() for c in card.requested_caps}
    if "network" in caps:
        return "reached the internet — denied"
    if any("write" in c for c in caps):
        return "tried to change a file — denied"
    return "needed more access than this case allows — denied"


def _blocked_action(card: OversightCard) -> str:
    caps = {c.lower() for c in card.requested_caps}
    if "network" in caps:
        return "reach the internet"
    if any("write" in c for c in caps):
        return "change a file"
    return "use more access than this case grants"


#: A call that never reported back because the run ended under it — settled,
#: so no row is left spinning, but never claimed to have succeeded.
_STATUS_UNFINISHED = "unfinished"

def _status_glyph(status: str) -> tuple[str, str]:
    """The glyph and colour one feed status wears, in the palette in force.

    Built per call rather than held in a module constant: a constant would
    freeze whichever theme was active when this module was first imported,
    and every ACTIVITY row would keep that theme's colours after a switch.
    """

    return {
        "running": (M.GLYPH_POINT, M.ACCENT),
        _STATUS_UNFINISHED: (M.GLYPH_UNKNOWN, M.DIM_BRIGHT),
        "approved": (M.GLYPH_OK, M.SUCCESS),
        M.OUTCOME_EXECUTED: (M.GLYPH_OK, M.SUCCESS),
        "refused": (M.GLYPH_ERROR, M.RED),
        M.OUTCOME_REFUSED_BY_OVERSIGHT: (M.GLYPH_ERROR, M.RED),
        M.OUTCOME_REFUSED_BY_TOOL: (M.GLYPH_WARN, M.ORANGE),
        M.OUTCOME_FAILED: (M.GLYPH_WARN, M.ORANGE),
    }.get(status, (M.GLYPH_UNKNOWN, M.DIM))


def _live_status_cell(status: str) -> Text:
    """The one-glyph state cell of an ACTIVITY row."""

    glyph, colour = _status_glyph(status)
    return Text(glyph, style=colour)


def _pair_cards_to_events(events, cards):
    """The recorder's cards reordered to match the feed's arrivals.

    Sequential runs already agree on order; when several calls of the
    same shape run concurrently they can settle out of their recorded
    order, so argument overlap decides which card describes which
    arrival. On any length mismatch the cards come back untouched and
    the caller falls back to the raw feed.
    """

    if len(events) != len(cards) or not events:
        return list(cards)
    remaining = list(cards)
    paired = []
    for event in events:
        best_index = 0
        best_score = float("-inf")
        for index, card in enumerate(remaining):
            score = 0.0
            if card.function == event.function:
                score += 4.0
            if card.operation and event.operation and card.operation == event.operation:
                score += 2.0
            for name, value in card.arguments:
                if value and f"{name}={value}" in event.args_summary:
                    score += 1.0
            # Among equals, keep the recorded order.
            score -= 0.01 * index
            if score > best_score:
                best_score = score
                best_index = index
        paired.append(remaining.pop(best_index))
    return paired


def _recorded_scopes(result) -> dict[int, str]:
    """What each call actually read, keyed by the oversight number it ran under.

    A finding knows the scope of the read it came from ("all USBSTOR subkeys in
    ControlSet001"); linking it back through ``oversight_sequence`` answers
    "which registry path" even for plugin operations whose arguments never
    carried one.
    """

    return {
        card.oversight_sequence: card.coverage_scope
        for card in result.findings
        if card.oversight_sequence is not None and card.coverage_scope
    }


def _recorded_reasons(result) -> dict[int, str]:
    """Why each call did not simply succeed, keyed the same way as the scopes.

    Read off what the tool itself reported and nothing else: its own warning
    first, because that is the sentence naming the condition (the archive is
    password protected, the hive was locked), and the coverage reason second,
    which says why only part of a source could be read. A call that recorded
    neither contributes no entry, and the row then says nothing about why.
    """

    reasons: dict[int, str] = {}
    for card in result.findings:
        if card.oversight_sequence is None:
            continue
        stated = ""
        for warning in card.warnings:
            stated = " ".join(str(warning).split())
            if stated:
                break
        stated = stated or " ".join((card.coverage_reason or "").split())
        if stated:
            reasons.setdefault(card.oversight_sequence, stated)
    return reasons


def _row_reason(card: OversightCard, reasons: dict[int, str]) -> str:
    """One call's reason, from the nearest place that recorded one.

    Three sources, nearest first. The finding's own warning is the sentence a
    tool wrote about a result it did produce. The refusal message is the
    sentence the layer that refused the call wrote. Last, what the tool declared
    when it came back unsuccessful — which is the ONLY one of the three a failed
    call has, because a call that failed filed no finding.
    """

    return (
        reasons.get(card.sequence, "")
        or (card.refusal_message or "").strip()
        or (card.outcome_detail or "").strip()
    )


#: The argument names that say what a call was pointed AT, in the order a
#: recorded call is searched for one. A tool call carries several arguments and
#: only one of them names the thing examined, and which name that is depends on
#: the tool: a registry query calls it ``key``, a log reader ``log``, a file
#: reader ``path``. One list, read by everything that has to name the target of
#: a call — the ACTIVITY row and the finding detail card — because two lists
#: would eventually disagree about which argument a row was describing.
_TARGET_ARGUMENTS: tuple[str, ...] = ("path", "key", "file", "log", "query", "hive")

#: Statuses a row wears while it is still nothing but "in flight" or "over".
#: The outcome word and the reason are only written beside a settled outcome.
_UNSETTLED_STATUSES = frozenset({"running", _STATUS_UNFINISHED})

#: Outcomes that mean the call did what it was asked. Everything else earns the
#: word naming what happened instead, and the reason if one was recorded.
_CLEAN_OUTCOMES = frozenset({"approved", M.OUTCOME_EXECUTED})


def _target_argument(arguments) -> str:
    """The argument naming what one call examined, or "" if none of them does.

    ``arguments`` is a sequence of ``(name, value)`` pairs as the recorder kept
    them. The first name from :data:`_TARGET_ARGUMENTS` that carries a value
    wins, so the search order is the priority order and a call passing both a
    ``hive`` and a ``key`` is described by its key.
    """

    for wanted in _TARGET_ARGUMENTS:
        for name, value in arguments:
            if name == wanted and str(value).strip():
                return str(value).strip()
    return ""


def _same_target(scope: str, target: str) -> bool:
    """Whether a recorded scope and a call's target name the same place.

    Compared as resolved locations rather than as strings: a registry path
    written with backslashes and the same path written with forward slashes are
    one place, as are a directory with and without its trailing separator. Only
    a real difference is worth a line on the row — ``registry_query
    key=/Policy/Lsa`` that actually reached ``\\Policy`` is the case the line
    exists for, and it is invisible if a trailing slash also prints one.
    """

    def resolved(value: str) -> str:
        text = str(value).strip().replace("\\", "/").casefold()
        while "//" in text:
            text = text.replace("//", "/")
        return text.rstrip("/")

    return resolved(scope) == resolved(target)


def _activity_row(
    event: ToolEvent,
    status: str | None = None,
    scope: str = "",
    *,
    arguments: tuple[tuple[str, str], ...] = (),
    reason: str = "",
):
    """One ACTIVITY entry: the call, then the full arguments wrapping beneath,
    then what is left to say about it. Nothing is ever clipped, whatever the
    pane width.

    Three things can follow the arguments, and each is printed only when it
    carries information the two lines above do not:

    * **The outcome word.** The glyph and the Guardrails pane answer different
      questions — how the call turned out, and whether it was permitted — and
      an operator reading ``▲`` beside "all 9 steps were allowed" has no way to
      tell that those are two axes rather than a contradiction. The word from
      :data:`model.OUTCOME_STYLE` (``failed``, ``refused``, ``BLOCKED``) says
      which axis the mark is on, and it is the same vocabulary the line CLI and
      the oversight pane use for the same outcomes.
    * **The reason.** A warning mark with no reason beside it sends the operator
      into the review card to learn that the archive needed a password. It is
      whatever the tool itself reported (its warning, or the reason coverage was
      incomplete, or the refusing layer's own sentence); nothing is composed
      here, and a call that reported no reason simply gets no line.
    * **The scope.** What the call actually read, which matters exactly when it
      differs from what the call asked for. Where they agree the line was pure
      repetition of the arguments directly above it.
    """

    settled = status or event.status
    glyph, colour = _status_glyph(settled)
    head = Text()
    head.append(f"{glyph} ", style=colour)
    head.append_text(_call_name(event.function, event.operation))
    if settled == "running":
        head.append("  running…", style=M.DIM_BRIGHT)
    elif settled == _STATUS_UNFINISHED:
        head.append("  did not complete", style=M.DIM_BRIGHT)
    else:
        outcome = M.OUTCOME_STYLE.get(settled)
        if outcome is not None and settled not in _CLEAN_OUTCOMES:
            head.append(f"  {outcome[2]}", style=outcome[1])
        if event.duration_s is not None:
            head.append(
                f"  {format_duration(event.duration_s, compact=True)}", style=M.DIM
            )
    parts = [head]
    if event.args_summary:
        args = Text("   ", style=M.DIM)
        args.append(event.args_summary, style=M.DIM)
        parts.append(args)
    explanation = " ".join(str(reason).split())[:200]
    if explanation and settled not in _UNSETTLED_STATUSES | _CLEAN_OUTCOMES:
        why = Text("   ", style=M.DIM)
        why.append(f"{M.GLYPH_POINT} ", style=M.DIM)
        why.append(explanation, style=colour)
        parts.append(why)
    if scope and not _same_target(scope, _target_argument(arguments)):
        read = Text("   ", style=M.DIM)
        read.append(f"{M.GLYPH_POINT} read ", style=M.DIM)
        read.append(scope, style=M.DIM_BRIGHT)
        parts.append(read)
    return parts[0] if len(parts) == 1 else Group(*parts)


def _version_label() -> str:
    try:
        from forensic_agent import __version__

        return f"v{__version__}"
    except Exception:
        return ""


def _build_label() -> str:
    """Which build is running, as a short string, or "" if nothing is known.

    The package version answers a different question — it is chosen by hand and
    two images built a week apart carry the same one — and the cost of that gap
    has been measured in days: defects already fixed in the tree were reported
    again from an older image, and nothing on screen said which build it was.
    Best-effort by construction; a console that cannot name itself still starts.
    """

    try:
        from forensic_agent.cli.build_identity import build_label

        return build_label()
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# the wordmark: three fixed renderings, chosen by measuring the pane
# ---------------------------------------------------------------------------
# One rendering scaled to the pane is what clipped: the width was read from a
# container that had not been laid out yet, the fallback assumed a hundred
# columns, and the full 77-cell art was drawn into a pane some twenty cells
# narrower, sliced through the last letters. The shape every comparable console
# uses instead is a cascade over a few fixed variants, Gemini CLI among three by
# terminal width and other terminal front ends among two block forms plus a
# plain-text fallback, and it has the property that matters here: the smallest
# variant always fits, so there is no width at which the mark renders clipped
# or vanishes.
#
# The variants are built once, at import, and choosing between them is a pair of
# integer comparisons. Nothing is rasterised at runtime and nothing is cached by
# width bucket, because there is no work to debounce; the one thing a fast drag
# must not do is repaint, and _refresh_header does not when the choice is
# unchanged. Only ▀ ▄ █ and box drawing are used, which the full mark already
# needs — quadrant and braille art scales more smoothly and depends on glyphs a
# substituted font may not carry.
@dataclass(frozen=True)
class _Wordmark:
    """One fixed rendering of the mark, with the room it needs."""

    name: str
    rows: tuple[str, ...]
    width: int
    height: int


def _wordmark(name: str, rows: tuple[str, ...]) -> _Wordmark:
    trimmed = tuple(row.rstrip() for row in rows)
    return _Wordmark(name, trimmed, max(len(row) for row in trimmed), len(trimmed))


#: The mark at half height, for a pane too narrow or too short for the art.
#: Hand-drawn rather than resampled from it: downsampling the outlined art
#: floods the counters between the letters, and this has to look deliberate.
_COMPACT_ART: tuple[str, ...] = (
    "█▀▄ █▀▀ █ █▀▄   ▄▀█ █▀▀ █▀▀ █▄ █ ▀█▀",
    "█ █ █▀▀ █ █▀▄ ▀ █▀█ █ █ █▀▀ █ ▀█  █ ",
    "▀▀  ▀   ▀ ▀ ▀   ▀ ▀ ▀▀▀ ▀▀▀ ▀  ▀  ▀ ",
)

_WORDMARK_FULL = _wordmark("full", _BANNER_ART)
_WORDMARK_COMPACT = _wordmark("compact", _COMPACT_ART)
_WORDMARK_PLAIN = _wordmark("plain", ("DFIR-AGENT",))

#: Widest first: the cascade takes the first one the pane can hold.
_WORDMARKS: tuple[_Wordmark, ...] = (
    _WORDMARK_FULL,
    _WORDMARK_COMPACT,
    _WORDMARK_PLAIN,
)

#: The tagline is drawn with one leading space, and only when the whole of it
#: fits on one line. Letter-spaced text that wraps is worse than no tagline:
#: "a s s i s" on one row and "t a n t" alone on the next does not read as a
#: word at all.
_TAGLINE_WIDTH = len(_BANNER_SUBTITLE) + 1


def _wordmark_for(width: int, height: int) -> _Wordmark | None:
    """The largest rendering that fits, or ``None`` when not even one row does.

    Width never removes the mark — below the smallest variant's own width the
    plain name is still drawn, and the pane is wide enough for it long before
    the size guard takes the screen. Height does remove it, which is the one
    rule the terminal consoles this follows do not need: the panes below the
    wordmark carry the actual content, and on a short terminal the mark was
    pushing the Session panel off the bottom of the pane.
    """

    for mark in _WORDMARKS:
        if mark.width <= width and mark.height <= height:
            return mark
    if _WORDMARK_PLAIN.height <= height:
        return _WORDMARK_PLAIN
    return None


def _wordmark_text(mark: _Wordmark, *, tagline: bool) -> Text:
    """One rendering, in the palette's gradient, with no trailing blank row."""

    gradient = M.banner_colours()
    text = Text(no_wrap=True, overflow="crop")
    for index, line in enumerate(mark.rows):
        if index:
            text.append("\n")
        step = min(len(gradient) - 1, index * len(gradient) // max(1, mark.height))
        text.append(line, style=f"bold {gradient[step]}")
    if tagline:
        text.append("\n ")
        text.append(_BANNER_SUBTITLE, style=f"italic {M.PURPLE}")
    return text


class ConversationPane(VerticalScroll):
    """The CONVERSATION pane, which says when it has been laid out anew.

    The wordmark is chosen by measuring this pane, so the only moment worth
    measuring at is the one Textual already announces here: a widget is sent
    :class:`~textual.events.Resize` AFTER the compositor has given it its new
    region, so ``content_size`` read from this handler is the size the pane
    actually has rather than the one it is on its way to.

    The app cannot use its own resize event for this. That one arrives BEFORE
    the layout runs, which is why the header used to be corrected from a timer
    a fixed delay later — a guess about how fast Textual lays out, and a guess
    that a maximize on a full screen loses. When it lost, the deferred look
    measured the pane at its PREVIOUS size, that reading matched the previous
    reading, the header concluded it had settled and never looked again: the
    mark kept the variant chosen for the old width until some later resize
    happened to arrive.  :class:`~textual.events.Resize` does not bubble, so it
    is re-announced as a message the app can subscribe to.
    """

    class Resized(Message):
        """This pane has a new content box. Carries the pane, not its size.

        The size is read at the moment the app handles this, never captured
        here: two layouts in a row post two messages, and acting on the older
        one's captured size would put the header back a step. The freshest
        reading is always the pane's own.
        """

        def __init__(self, pane: ConversationPane) -> None:
            self.pane = pane
            super().__init__()

    def on_resize(self, event: events.Resize) -> None:
        self.post_message(self.Resized(self))


#: The four pane names, uppercased at the point of use rather than stored that
#: way: the console's style is uppercase pane titles, but a translation belongs
#: in the catalog in its own ordinary form, and "GUARDRAILS" is not a word a
#: translator should be handed. Read through the language layer at call time,
#: never bound to a constant, so a switch reaches them.
def _pane_title(name: str) -> str:
    return _t(name).upper()


#: The prompt's resting text, named once. It is applied at compose time and
#: again when the language changes, and a second copy of the literal is a
#: second catalog key waiting to drift out of step with the first.
_PROMPT_PLACEHOLDER = "type a message \u2014 Enter sends, Esc browses"


def _call_name(function: str, operation: str) -> Text:
    name = Text()
    name.append(function, style=M.ACCENT)
    if operation:
        name.append(f".{operation}", style=M.TEXT)
    return name


def _section_heading(title: str) -> Rule:
    """A section heading inside a detail card: named in the accent, ruled quietly.

    ACCENT is the identity/heading role, so the title reads as a label rather
    than as more content; the rule itself stays on BORDER so it recedes. The
    colours are read at call time — binding either to a constant would freeze
    one palette.

    Uppercased here rather than at each call site, so every heading the console
    draws is the same kind of object as the pane titles it sits between —
    CONVERSATION, ACTIVITY, EVIDENCE, GUARDRAILS are already uppercase, and a
    lowercase heading inside a card read as a stray line of content rather than
    as the label of the block beneath it.
    """

    return Rule(
        Text(title.upper(), style=f"bold {M.ACCENT}"), style=M.BORDER, align="left"
    )


def _section_body(*lines: RenderableType) -> Padding:
    """A section's content, indented as one block beneath its heading.

    The indent is what separates a heading from what it introduces; without it
    a label and its content sit in the same column and read as one block. It
    has to be real padding rather than two spaces glued to the front of the
    string: a prefix only moves the first visual row, so the moment a line is
    long enough to soft-wrap — a sentence, a path, a receipt — the continuation
    snaps back to column 0 and reads as a new item. Padding indents every row
    the renderable produces, so a wrapped line stays inside its section.

    The whole section is padded once rather than line by line, which also keeps
    the lines a single renderable and so guarantees no stray blank rows creep
    in between them.
    """

    body = lines[0] if len(lines) == 1 else Group(*lines)
    return Padding(body, (0, 0, 0, 2))


#: Attributes that record how the run was wired together rather than what the
#: call observed: which capture components were available to be selected, and
#: which of them the selection resolved to. They belong to the run record, which
#: keeps them untouched; an examiner deciding whether to accept a finding is
#: not helped by a redacted artifact URI, and on a 44-row DNS result they were
#: the first thing on screen and the table was the last.
_RUN_PLUMBING_ATTRIBUTES: frozenset[str] = frozenset(
    {"available_sources", "source_component", "source_input_component_ids"}
)

#: Attributes carrying the rows themselves, in the order the card looks for
#: them. They are rendered as the table, never also as a serialised value —
#: printing a page of ``named_rows=[{…},{…}`` above the same rows is what made
#: the block unreadable.
_ROW_ATTRIBUTES: tuple[str, ...] = ("named_rows", "rows")

#: Attributes naming the row fields. They become the table's column headings,
#: so they are not printed a second time as a value of their own.
_COLUMN_ATTRIBUTES: tuple[str, ...] = ("fields", "columns")

#: How many recorded rows the card draws before it stops and says how many are
#: left. A review card is read on screen; a thousand rows scroll past the
#: decision rather than informing it, and the whole result is in the record.
_RECORDS_SHOWN = 100


def _is_empty_value(value: object) -> bool:
    """Whether an attribute said nothing: ``""``, ``[]``, ``{}`` or absent.

    ``False`` and ``0`` are not empty — ``cardinality_truncated=False`` is an
    answer, and dropping it would turn "the tool said no" into "the tool said
    nothing".
    """

    if value is None:
        return True
    if isinstance(value, bool | int | float):
        return False
    return not value


def _column_names(candidate: object) -> list[str]:
    """A recorded ``fields``-style value as column names, or ``[]``."""

    if isinstance(candidate, list) and candidate and all(
        isinstance(field, str) for field in candidate
    ):
        return [str(field) for field in candidate]
    return []


def _tabular(value: object) -> tuple[list, list[str]] | None:
    """A recorded value that is really a table, as ``(rows, column names)``.

    Two shapes qualify, and both turn up in real envelopes: a list of mappings,
    where the keys are the column names, and a list of equal-length sequences,
    where the columns have no names of their own and the position is all there
    is. Anything else — a scalar, a string, a single row — is not a table and
    is left to be printed as the ``name=value`` line it is.
    """

    if not isinstance(value, list) or len(value) < 2:
        return None
    if all(isinstance(row, dict) for row in value):
        ordered: dict[str, None] = {}
        for row in value:
            for key in row:
                ordered.setdefault(str(key), None)
        return list(value), list(ordered)
    if all(isinstance(row, list | tuple) and len(row) >= 2 for row in value):
        widths = {len(row) for row in value}
        if len(widths) != 1:
            return None
        return [list(row) for row in value], [""] * widths.pop()
    return None


def _recorded_table_parts(
    records: dict | None,
) -> tuple[list, list[str], dict[str, object], list[tuple[str, list, list[str]]]]:
    """One recorded result, split into the four things the card draws.

    Returns ``(rows, column names, plain attributes, further tables)``.

    The rows are the recorded page. An envelope commonly carries that page
    TWICE — ``items`` as bare positional lists and ``named_rows`` as the same
    rows with the field names attached — and the named form is the one a reader
    can use, so it wins whenever the two are the same page. When only the
    positional form exists, the recorded ``fields`` supply the column names by
    position, which is precisely the mapping the tool itself made.

    Everything consumed here is taken out of the attributes, so nothing is
    drawn twice; and any attribute that is itself a table (a top-N
    distribution, a per-endpoint tally) is handed back as one rather than
    serialised into a paragraph, because that is the same defect one level
    down.
    """

    data = records or {}
    attributes = dict(data.get("attributes") or {})
    consumed: set[str] = set()

    items = data.get("items")
    rows: list = list(items) if isinstance(items, list) and items else []
    for name in _ROW_ATTRIBUTES:
        candidate = attributes.get(name)
        if not isinstance(candidate, list) or not candidate:
            continue
        if not all(isinstance(row, dict) for row in candidate):
            continue
        if rows and len(candidate) != len(rows):
            # A different length is a different observation, not this page
            # under another name; it keeps its own table further down.
            continue
        rows = list(candidate)
        consumed.add(name)
        break

    columns: list[str] = []
    for name in _COLUMN_ATTRIBUTES:
        named = _column_names(attributes.get(name))
        if named:
            columns = named
            consumed.add(name)
            break
    # The recorded field list decides the ORDER, never the contents: a row
    # carrying a key the field list does not name still gets a column, because
    # a column the card leaves out is a value the reviewer never sees.
    ordered_columns: dict[str, None] = dict.fromkeys(columns)
    for row in rows:
        if isinstance(row, dict):
            for key in row:
                ordered_columns.setdefault(str(key), None)
    columns = list(ordered_columns)

    kept: dict[str, object] = {}
    tables: list[tuple[str, list, list[str]]] = []
    for name, value in attributes.items():
        if name in consumed or name in _RUN_PLUMBING_ATTRIBUTES:
            continue
        if _is_empty_value(value):
            continue
        shape = _tabular(value)
        if shape is None:
            kept[name] = value
        else:
            tables.append((name, shape[0], shape[1]))
    return rows, columns, kept, tables


def _table_overflow_note(total: int) -> list[RenderableType]:
    """What a table left out, said under it — or nothing when it left out none."""

    if total <= _RECORDS_SHOWN:
        return []
    return [
        Text(
            f"… and {total - _RECORDS_SHOWN} more rows, not shown here",
            style=M.TEXT,
        )
    ]


def _records_table(rows: list, columns: list[str]) -> Table:
    """The recorded rows as a table, which is what they are.

    Every row of a tool result has the same fields, so the field names belong
    in one heading row and not repeated in front of every value: as
    ``name=value`` pairs folded into a paragraph, forty-four DNS records ran to
    a screen and a half in which no two records lined up. Columns fold rather
    than elide — a truncated address or query name is one a reviewer cannot
    check.

    Rows arrive as mappings or as positional sequences; ``columns`` names them
    in either case, and a table whose columns have no recorded names draws no
    heading row rather than a row of blanks.
    """

    names = columns or ["record"]
    table = Table(
        box=box.SIMPLE_HEAD,
        show_edge=False,
        pad_edge=False,
        padding=(0, 1),
        show_header=any(name for name in names),
        header_style=f"bold {M.ACCENT}",
        border_style=M.BORDER,
    )
    table.add_column("#", justify="right", no_wrap=True, style=M.TEXT)
    for name in names:
        table.add_column(name, overflow="fold", style=M.TEXT)

    def cell(value: object) -> str:
        return "" if value is None else str(value)

    for position, row in enumerate(rows[:_RECORDS_SHOWN], start=1):
        if isinstance(row, dict):
            values = [cell(row.get(name)) for name in names]
        elif isinstance(row, list | tuple):
            values = [cell(value) for value in row][: len(names)]
            values += [""] * (len(names) - len(values))
        else:
            values = [cell(row)] + [""] * (len(names) - 1)
        table.add_row(str(position), *values)
    return table


# ---------------------------------------------------------------------------
# command palette (Ctrl+P) — surfaces the slash-command registry
# ---------------------------------------------------------------------------
def slash_completions() -> tuple[str, ...]:
    """Every name a slash command answers to, longest-priority first.

    Aliases are included: ``/guardrails`` is typed by operators who learned
    it, and a completion list that omitted it would quietly teach that it no
    longer exists. Sorted so a shorter name is offered before a longer one
    that extends it, which is the order the suggester consumes.
    """

    from forensic_agent.cli.commands import COMMAND_REGISTRY

    names: set[str] = set()
    for spec in COMMAND_REGISTRY.commands:
        names.add(spec.name)
        names.update(spec.aliases)
    return tuple(f"/{name}" for name in sorted(names))


#: How many commands the list under the prompt shows before it says how many
#: more there are. Eight rows plus the counter fit above the prompt without
#: pushing the conversation off a short terminal.
_HINTS_SHOWN: Final[int] = 8


def matching_commands(typed: str) -> tuple[tuple[str, str, str], ...]:
    """The commands a half-typed slash matches: (name, usage, description).

    A bare ``/`` matches everything, so the operator who knows a command exists
    but not what it is called can see the whole surface. After that the prefix
    narrows it. Aliases match too and are answered by the command they belong
    to, listed under the alias the operator is actually typing — ``/guardrails``
    has to find something, or the completion quietly teaches that it is gone.

    Empty once a space has been typed: from there the operator is writing the
    argument, the command is settled, and the usage line on the input's border
    is the thing that helps.
    """

    from forensic_agent.cli.commands import COMMAND_REGISTRY

    if not typed.startswith("/") or " " in typed:
        return ()
    prefix = typed[1:].casefold()
    hits: list[tuple[str, str, str]] = []
    for spec in COMMAND_REGISTRY.commands:
        for offered in (spec.name, *spec.aliases):
            if offered.startswith(prefix):
                usage = spec.usage if offered == spec.name else f"/{offered}"
                hits.append((offered, usage, spec.description))
                break
    # Registry order, which is the order /help lists them in and the order they
    # are grouped by category. Sorting here would give the operator one order
    # while typing and another when they went to read about it.
    return tuple(hits)



def _literal_markup(text: str) -> str:
    r"""``text`` encoded so a markup-parsing label renders it character for character.

    A usage line is mostly square brackets and a border subtitle is parsed as
    markup, so ``/clear [all]`` renders as ``/clear`` with the one part the
    operator needed eaten as a style tag.

    ``rich.markup.escape`` is not enough here, because it escapes only the
    brackets that LOOK like tags. ``/model [list [all|<text>]|<model-id>]`` has
    one of each: the inner ``[all|<text>]`` is tag-shaped and gets a backslash,
    the outer ``[list`` is not and does not, and what reached the screen was
    ``/model [list \[all|<text>]|<model-id>]``, a usage line with a stray
    backslash in the middle of it. Escaping EVERY bracket makes the parser
    leave all of them alone, which is the only outcome that is right for every
    usage line rather than for most of them.
    """

    return text.replace("\\", "\\\\").replace("[", "\\[")


class PromptInput(Input):
    """The message line, with slash-command completion that never captures it.

    Typing ``/`` used to open the command palette, which took the keyboard: the
    palette matched a command and Enter ran the bare form of it, so ``/clear
    all`` could not be typed at all — the argument had nowhere to go. The
    completion here is a SUGGESTION and nothing more. It is drawn after the
    cursor, Enter submits the typed value and never the suggested one, and the
    line stays a line the operator is writing rather than a list they are
    picking from.
    """

    BINDINGS = [
        Binding("tab", "accept_completion", "complete the command", show=False),
        # Only ever live while the command list is open — see check_action.
        # Bound unconditionally they would take the two keys an Input has no
        # use for on one line but the console does elsewhere, and Esc above all:
        # Esc is how the operator leaves the prompt for the panes.
        Binding("down", "hint_next", "next command", show=False),
        Binding("up", "hint_previous", "previous command", show=False),
        Binding("escape", "hint_close", "close the list", show=False),
    ]

    # ``Input`` already declares this reactive as ``Reactive[str]``; it is
    # restated here so the type is stated in THIS class as well, which is what
    # a type-check run without textual installed has to go on. Such a run —
    # the project's own lint job installs the checker and nothing else — sees
    # the base class as ``Any``, so ``value`` is declared nowhere;
    # ``action_accept_completion`` below then reads ``self.value`` and later
    # assigns to it, the checker tries to infer the attribute from that
    # assignment, reaches the earlier read while the inference is still in
    # flight, and reports "Cannot determine type of value" [has-type]. This is
    # an annotation and not an assignment, so no class attribute is created
    # and the inherited reactive descriptor is exactly the one that runs.
    value: Reactive[str]

    def _owner(self) -> InvestigationApp | None:
        """The console this line belongs to, or None if it is mounted elsewhere.

        Named ``_owner`` rather than ``_console``: ``Widget._console`` is
        Textual's own Rich console, and shadowing it with something else
        entirely is how a widget stops being able to render itself.

        The list being moved through lives on the app, because it is the app
        that knows which commands the typed prefix still matches. Asked for
        rather than assumed, so a PromptInput in a test harness or another
        screen degrades to an ordinary input instead of raising.
        """

        app = self.app
        return app if isinstance(app, InvestigationApp) else None

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        """The list keys exist only while there is a list.

        This is what keeps the fix that matters intact. The suggestion list may
        never take the keyboard: it once did, and the console could not be
        typed in. Up, Down and Esc are bound on the line rather than on the
        list, and they are live only while the list is open — so with it closed
        Esc still leaves the prompt for the panes, and every printable key
        reaches the line at every moment, open or closed.
        """

        if action in ("hint_next", "hint_previous", "hint_close"):
            console = self._owner()
            return console is not None and console.command_hints_open
        return True

    def action_hint_next(self) -> None:
        console = self._owner()
        if console is not None:
            console.move_command_hint(1)

    def action_hint_previous(self) -> None:
        console = self._owner()
        if console is not None:
            console.move_command_hint(-1)

    def action_hint_close(self) -> None:
        console = self._owner()
        if console is not None:
            console.close_command_hints()

    def action_accept_completion(self) -> None:
        """Take the offered completion and stand ready for an argument.

        The command name is completed and a separator is placed after it, so the
        very next keystroke is the argument. Without the separator the operator
        has to notice the cursor is welded to the name and type the space
        themselves, which is the same interruption in a smaller form.

        Which command is taken is whichever one the list is pointing at, which
        with an untouched list is the first match — the same command the ghost
        after the cursor already offered. Enter is deliberately NOT this key:
        Enter sends the characters in the line and nothing else, which is the
        whole reason this is a suggestion list and not the command palette.
        """

        console = self._owner()
        selected = console.selected_command_hint() if console is not None else None
        if selected is not None and self.cursor_at_end:
            completed = f"/{selected}"
            if completed != self.value.strip():
                self.value = f"{completed} "
                self.cursor_position = len(self.value)
                return
        suggestion = self._suggestion
        if not suggestion or not self.cursor_at_end or len(suggestion) <= len(self.value):
            return
        self.value = suggestion + " "
        self.cursor_position = len(self.value)


class SlashCommandProvider(Provider):
    """Exposes the console's slash-commands through the command palette."""

    def _specs(self):
        from forensic_agent.cli.commands import COMMAND_REGISTRY

        yield from COMMAND_REGISTRY.commands

    async def discover(self) -> Hits:
        # This provider is only ever installed on the console's own app, which
        # is where palette_insert lives; ``Provider.app`` is declared as the
        # generic ``App``.
        app = cast("InvestigationApp", self.app)
        for spec in self._specs():
            yield DiscoveryHit(
                f"/{spec.name}",
                partial(app.palette_insert, spec.name),
                help=spec.description,
            )

    async def search(self, query: str) -> Hits:
        app = cast("InvestigationApp", self.app)
        matcher = self.matcher(query)
        for spec in self._specs():
            candidate = f"/{spec.name}"
            score = matcher.match(candidate)
            if score > 0:
                yield Hit(
                    score,
                    matcher.highlight(candidate),
                    partial(app.palette_insert, spec.name),
                    help=spec.description,
                )


# ---------------------------------------------------------------------------
# overlays: one thing on demand, and one choice when a case needs it
# ---------------------------------------------------------------------------
class _CopyableCard:
    """The copy actions a card-shaped drawer offers, shared by both drawers.

    A review card and an accepted finding's detail are the same card seen at
    two moments, and the reason to copy one — the receipt, the bundle digest,
    the source URI, a decoded value — does not change between them. So the
    keys live here once: ``c`` takes the whole card, ``C`` takes the receipt on
    its own, which is the single value most often wanted and the one most
    easily mistyped. A modifier rather than a menu, because both are one
    keystroke away from a decision the operator is in the middle of making.
    """

    _renderable: Any
    _card: FindingCard | None

    COPY_HINT = "c copy card   C receipt"

    def action_copy_card(self) -> None:
        if self._card is None:
            return
        cast(Any, self).app.copy_text(_as_copy_text(self._renderable), "The card")

    def action_copy_receipt(self) -> None:
        if self._card is None:
            return
        receipt = (self._card.receipt_full or "").strip()
        app = cast(Any, self).app
        if receipt in ("", "—"):
            app.notify("This finding recorded no receipt.", title="copy")
            return
        app.copy_text(receipt, "The receipt")


class OverlayScreen(ModalScreen, _CopyableCard):
    """A centred drawer that shows one thing on demand, dismissed with Esc."""

    BINDINGS = [
        Binding("escape", "dismiss", "close"),
        Binding("q", "dismiss", "close", show=False),
        Binding("c", "copy_card", "copy", show=False),
        Binding("C", "copy_receipt", "copy the receipt", show=False),
    ]

    def __init__(
        self,
        title: str,
        renderable,
        *,
        card: FindingCard | None = None,
        wide: bool = False,
    ) -> None:
        super().__init__()
        self._title = title
        self._renderable = renderable
        # Only a drawer showing a finding has anything to copy; /help and
        # /status offer no keys they cannot honour.
        self._card = card
        # Reference material — the command sheet — is read across, not down: a
        # drawer a hundred cells wide on a two-hundred-cell screen folded every
        # description into three lines with half the window unused beside it.
        # A finding card keeps the narrow measure, which is what makes a
        # paragraph readable.
        self._wide = wide

    def compose(self) -> ComposeResult:
        box_ = Vertical(id="overlay-box", classes="wide" if self._wide else None)
        box_.border_title = self._title
        box_.border_subtitle = (
            f"esc closes   {self.COPY_HINT}" if self._card is not None else "esc closes"
        )
        with box_:
            with VerticalScroll(id="overlay-body"):
                yield Static(self._renderable)

    # Textual dispatches a bound action through ``await_me_maybe``, so a plain
    # synchronous action method is supported; the base class declares only the
    # coroutine form.
    def action_dismiss(self) -> None:  # type: ignore[override]
        self.dismiss(None)


class ChoiceScreen(ModalScreen[int | None]):
    """One decision: pick a row, or Esc to leave the setting as it was.

    ``initial`` is which row the highlight opens on, and for a setting it is
    the row holding the value in force. A chooser that always opens on the
    first row asks the operator to change something without telling them what
    it currently is, and Enter on the row under the cursor then silently sets
    a value they never chose.

    Options are plain strings, or :class:`~rich.text.Text` where the row has to
    carry colour of its own — a theme is named by what it looks like, so its
    row shows the palette rather than describing it.
    """

    BINDINGS = [Binding("escape", "cancel", "cancel")]

    def __init__(
        self,
        title: str,
        options: list[str] | list[Text] | list[Any],
        *,
        initial: int = 0,
    ) -> None:
        super().__init__()
        self._title = title
        self._options = list(options)
        self._initial = initial

    def compose(self) -> ComposeResult:
        box_ = Vertical(id="choice-box")
        box_.border_title = self._title
        box_.border_subtitle = "Enter picks   esc cancels"
        with box_:
            yield ListView(
                *[
                    ListItem(
                        Label(
                            option
                            if isinstance(option, Text)
                            else Text(str(option), style=M.TEXT)
                        )
                    )
                    for option in self._options
                ],
                id="choice-list",
            )

    def on_mount(self) -> None:
        view = self.query_one("#choice-list", ListView)
        view.focus()
        if self._options and 0 <= self._initial < len(self._options):
            view.index = self._initial
        else:
            view.index = 0

    @on(ListView.Selected, "#choice-list")
    def _picked(self, event: ListView.Selected) -> None:
        event.stop()
        view = self.query_one("#choice-list", ListView)
        self.dismiss(view.index)

    def action_cancel(self) -> None:
        self.dismiss(None)


class ReviewScreen(ModalScreen[bool | None], _CopyableCard):
    """One finding under review: the operator accepts it as evidence or not."""

    BINDINGS = [
        Binding("y", "accept", "accept"),
        Binding("enter", "accept", "accept", show=False),
        Binding("n", "reject", "reject"),
        Binding("escape", "later", "later"),
        Binding("c", "copy_card", "copy", show=False),
        Binding("C", "copy_receipt", "copy the receipt", show=False),
    ]

    def __init__(self, title: str, renderable, *, card: FindingCard | None = None) -> None:
        super().__init__()
        self._title = title
        self._renderable = renderable
        self._card = card

    def compose(self) -> ComposeResult:
        box_ = Vertical(id="overlay-box")
        box_.border_title = self._title
        box_.border_subtitle = (
            f"y accept   n reject   esc later   {self.COPY_HINT}"
            if self._card is not None
            else "y accept   n reject   esc later"
        )
        with box_:
            with VerticalScroll(id="overlay-body"):
                yield Static(self._renderable)

    def action_accept(self) -> None:
        self.dismiss(True)

    def action_reject(self) -> None:
        self.dismiss(False)

    def action_later(self) -> None:
        self.dismiss(None)


class PromptScreen(ModalScreen[str | None]):
    """One value the console needs, asked in place: type it, Enter, done."""

    BINDINGS = [Binding("escape", "cancel", "cancel")]

    def __init__(
        self,
        title: str,
        *,
        hint: str = "",
        value: str = "",
        password: bool = False,
    ) -> None:
        super().__init__()
        self._title = title
        self._hint = hint
        self._value = value
        self._password = password

    def compose(self) -> ComposeResult:
        box_ = Vertical(id="choice-box")
        box_.border_title = self._title
        box_.border_subtitle = "Enter confirms   esc cancels"
        with box_:
            if self._hint:
                yield Static(Text(self._hint, style=M.DIM), classes="modal-hint")
            yield Input(value=self._value, password=self._password, id="prompt-entry")

    def on_mount(self) -> None:
        entry = self.query_one("#prompt-entry", Input)
        entry.focus()
        entry.cursor_position = len(entry.value)

    @on(Input.Submitted, "#prompt-entry")
    def _confirmed(self, event: Input.Submitted) -> None:
        self.dismiss(event.value)

    def action_cancel(self) -> None:
        self.dismiss(None)


class ContextScreen(ModalScreen[tuple[str, str] | None]):
    """The non-evidentiary case brief: the current text above, a rewrite below."""

    BINDINGS = [
        Binding("escape", "cancel", "close"),
        Binding("ctrl+x", "clear", "clear the brief"),
    ]

    def __init__(self, current: str) -> None:
        super().__init__()
        self._current = current

    def compose(self) -> ComposeResult:
        box_ = Vertical(id="overlay-box")
        box_.border_title = "case brief (non-evidence)"
        box_.border_subtitle = "Enter saves   Ctrl+X clears   esc closes"
        with box_:
            with VerticalScroll(id="overlay-body"):
                if self._current:
                    yield Static(Text(self._current, style=M.TEXT))
                else:
                    yield Static(
                        Text(
                            "No brief is set. It travels with every message of "
                            "this investigation and is never treated as evidence.",
                            style=M.DIM,
                        )
                    )
            yield Input(
                value=self._current,
                placeholder="rewrite the brief and press Enter",
                id="context-entry",
            )

    def on_mount(self) -> None:
        entry = self.query_one("#context-entry", Input)
        entry.focus()
        entry.cursor_position = len(entry.value)

    @on(Input.Submitted, "#context-entry")
    def _saved(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        if not text or text == self._current.strip():
            self.dismiss(None)
            return
        self.dismiss(("set", text))

    def action_clear(self) -> None:
        self.dismiss(("clear", ""))

    def action_cancel(self) -> None:
        self.dismiss(None)


class BudgetScreen(ModalScreen[None]):
    """The resources one message may spend, edited where they are shown.

    Three rows — time, steps and tool calls — and Enter opens the matching
    editor; the fixed model-request ceiling is stated beneath. Nothing about
    the model's reasoning appears here: that is a property of how the model
    thinks rather than a ceiling on what a run may consume, and it has its own
    command. Every row is a limit that ends a run with no finding when it is
    reached, which is what makes them one screen.
    """

    #: (row id, label, session setter, what the editor asks for). The order is
    #: the order on screen, and the index the editor works from, so a row can
    #: be added or moved here alone.
    ROWS: ClassVar[tuple[tuple[str, str, str, str], ...]] = (
        ("budget-time", "time", "change_time", "seconds per message"),
        ("budget-steps", "steps", "change_steps", "steps per message"),
        (
            "budget-toolcalls",
            "tool calls",
            "change_tool_calls",
            "tool calls per message",
        ),
    )

    BINDINGS = [
        Binding("escape", "dismiss", "close"),
        Binding("q", "dismiss", "close", show=False),
    ]

    def compose(self) -> ComposeResult:
        box_ = Vertical(id="choice-box")
        box_.border_title = "budget for the next message"
        box_.border_subtitle = "Enter edits   esc closes"
        with box_:
            yield ListView(
                *(ListItem(Label(""), id=row[0]) for row in self.ROWS),
                id="budget-list",
            )
            yield Static("", id="budget-note")

    def on_mount(self) -> None:
        self.refresh_rows()
        view = self.query_one("#budget-list", ListView)
        view.focus()
        view.index = 0

    @staticmethod
    def _settings(status) -> tuple[int, int, int]:
        """The three limits as the commands take them, in row order.

        One tuple, read by both the drawing and the editor, so a row cannot
        end up showing one budget and editing another.
        """

        return (status.max_wall_time_s, status.max_steps, status.max_tool_calls)

    @classmethod
    def _row_values(cls, status) -> tuple[str, ...]:
        """The same three limits as the operator reads them.

        The clock is shown as a duration rather than as a seconds count: 900
        is a number the operator has to divide by sixty before it means
        anything, and every other duration in this console is already written
        the same way.
        """

        seconds, steps, tool_calls = cls._settings(status)
        return (format_duration(seconds), str(steps), str(tool_calls))

    def refresh_rows(self) -> None:
        status = self.app._controller.status()  # type: ignore[attr-defined]
        values = self._row_values(status)
        for (item_id, label, _setter, _asks), value in zip(
            self.ROWS, values, strict=True
        ):
            text = Text()
            text.append(f"{label:>18}  ", style=M.DIM)
            text.append(value, style=f"bold {M.ACCENT}")
            self.query_one(f"#{item_id}", ListItem).query_one(Label).update(text)
        # Model requests is a fact, not a control, and it says so by where and
        # how it is drawn: outside the pickable list, in the metadata colour
        # rather than the accent the three editable values carry. It used to
        # say "fixed by the runner" instead, which named a component the
        # operator has no way to see and could not have acted on if they had.
        note = Text()
        note.append(f"{'model requests':>18}  ", style=M.DIM)
        note.append(str(status.max_model_requests), style=M.DIM_BRIGHT)
        self.query_one("#budget-note", Static).update(note)

    @on(ListView.Selected, "#budget-list")
    def _picked(self, event: ListView.Selected) -> None:
        event.stop()
        index = self.query_one("#budget-list", ListView).index
        self.app.run_worker(self._edit(index), exclusive=False)

    async def _edit(self, index: int | None) -> None:
        app = self.app
        if app._controller.is_demo:  # type: ignore[attr-defined]
            app.notify("Not available in demo mode.", title="/budget")
            return
        if app.running:  # type: ignore[attr-defined]
            app.notify(
                "A message is being investigated. Ctrl+C cancels it first.",
                title="/budget",
                severity="warning",
            )
            return
        if index is None or not 0 <= index < len(self.ROWS):
            return
        status = app._controller.status()  # type: ignore[attr-defined]
        _item_id, label, setter, asks = self.ROWS[index]
        # The editor takes the raw number the command takes, seconds included:
        # the row above it reads "15m 00s", but what is typed here is what
        # /budget time takes, and an editor that accepted a different spelling
        # from the command would be a second grammar for one setting.
        current = self._settings(status)[index]
        value = await app.push_screen_wait(
            PromptScreen(
                asks,
                hint="A whole number of at least 1; it applies to your next message.",
                value=str(current),
            )
        )
        if value is None or not value.strip():
            return
        app._set_limit(setter, label, value.strip())  # type: ignore[attr-defined]
        self.refresh_rows()


#: Where the console remembers the operator's own last case folder, in the
#: shared preferences file. A host path, and deliberately so: the container it
#: was typed into is replaced on every launcher handoff, and a value kept in
#: this process would be lost on exactly the relaunch that needs it most.
_LAST_CASE_DIRECTORY_KEY = "last_case_directory"

#: How many entries of one directory the picker will show. A case folder holds
#: a handful of sources; a directory with tens of thousands of files is one the
#: operator navigated into by mistake, and reading all of it into a modal only
#: makes the mistake slower to undo.
_BROWSE_ENTRY_LIMIT = 500


def _host_separator(path: str) -> str:
    """The separator a host path is written with, judged from the path itself."""

    if "\\" in path or (len(path) > 1 and path[1] == ":"):
        return "\\"
    return "/"


def _same_host_path(left: str, right: str) -> bool:
    """Whether two host paths name the same place, as that host would judge it.

    Deliberately separator- and case-insensitive. The container is comparing a
    Windows path an operator typed against one a launcher exported, and it has
    no way to ask that host how it would compare them, so the comparison that
    can only be too generous is the safe one here: the worst it can do is offer
    a listing of a directory that is in fact mounted.
    """

    def normalize(value: str) -> str:
        return value.strip().replace("\\", "/").rstrip("/").casefold()

    return normalize(left) == normalize(right)


def _container_view_of(host_path: str) -> str | None:
    """The container path whose contents ARE the host directory's, if there is one.

    This is the whole honest answer to "what can this screen list". Outside a
    container the two are the same path. Inside one the container's file system
    is the image plus its mounts, so exactly one host directory is enumerable:
    the one the launcher bind-mounted at ``/evidence``, and whatever lies under
    it. A host path outside that tree is not hidden or unreadable, it is simply
    absent, and no amount of walking the container's own file system will find
    it — which is why the answer for it is ``None`` and the only route to it is
    the launcher handoff.
    """

    import os as _os

    from forensic_agent.cli.host_display import (
        CONTAINER_EVIDENCE,
        containerized,
        host_evidence_root,
    )

    candidate = host_path.strip().rstrip("/\\")
    if not candidate:
        return None
    if not containerized():
        return candidate if _os.path.isdir(candidate) else None
    root = host_evidence_root()
    if not root:
        # The launcher did not state which host directory it mounted, so
        # nothing here may claim that a given host path is the one at
        # /evidence. The mounted listing is still offered separately, under
        # its own name, where it is a true statement about the container.
        return None
    if _same_host_path(candidate, root):
        return CONTAINER_EVIDENCE
    prefix = root.strip().replace("\\", "/").rstrip("/").casefold() + "/"
    normalized = candidate.replace("\\", "/")
    if not normalized.casefold().startswith(prefix):
        return None
    inside = f"{CONTAINER_EVIDENCE}/{normalized[len(prefix):]}"
    return inside if _os.path.isdir(inside) else None


def _browse_entries(directory: str) -> tuple[list[tuple[str, bool]], bool]:
    """One directory's entries as (name, is_directory), folders first.

    Returns the entries and whether the listing was cut short. Never raises:
    a directory that cannot be read is an empty listing plus the sentence the
    screen already has for "nothing to show here".
    """

    import os as _os

    try:
        with _os.scandir(directory) as scan:
            found = [(entry.name, entry.is_dir()) for entry in scan]
    except OSError:
        return [], False
    found.sort(key=lambda item: (not item[1], item[0].casefold()))
    return found[:_BROWSE_ENTRY_LIMIT], len(found) > _BROWSE_ENTRY_LIMIT


class FileBrowserScreen(ModalScreen[str | None]):
    """Choose evidence by naming a folder on the operator's OWN computer.

    The console usually runs in a container, and a container has no file picker
    to offer: the only file system it can walk is the image plus whatever the
    launcher bind-mounted into it. The screen this replaced walked that file
    system under a heading that read like the operator's own disk, opened on
    ``/evidence``, and asked in the same breath for a path from their computer.
    Everything it listed was therefore the one thing they were not being asked
    for.

    So the host path is the subject here and the container's mounts are a
    footnote. The field on top takes a folder from the operator's machine and
    starts on the last one they used. What the list below it can show depends
    entirely on whether that folder is reachable, and the screen says which
    case it is rather than leaving the operator to infer it from an empty list:

    * Outside a container, or under the directory the launcher mounted, the
      folder is enumerated and the operator picks from it instead of typing.
    * Anywhere else the container genuinely cannot see it. That is not an error
      to correct, it is what a bind mount is; the launcher handoff exists for
      exactly this, and confirming sends the path to it. Because the handoff
      ends this console process, it takes a second Enter — a typo must not cost
      the operator their session.

    Whatever IS mounted is listed separately underneath, under its own heading.
    It is a true and occasionally useful thing to show, and it is not what the
    screen is for.
    """

    DEFAULT_CSS = """
    #browse-state { margin: 0 0 1 0; }
    #browse-list { height: 1fr; min-height: 3; background: transparent; }
    #browse-mounted-label { margin: 1 0 0 0; }
    #browse-mounted { height: auto; max-height: 8; background: transparent; }
    """

    BINDINGS = [
        Binding("escape", "cancel", "cancel"),
        Binding("o", "choose_folder", "open this folder", show=False),
    ]

    def __init__(self, title: str, *, root: str, pick: str) -> None:
        super().__init__()
        self._title = title
        self._root = root
        self._pick = pick  # "folder" | "file"
        #: The host path each row of the primary list stands for.
        self._entries: list[tuple[str, bool]] = []
        #: The container path each row of the mounted list stands for.
        self._mounted: list[tuple[str, bool]] = []
        #: The unreachable path a second Enter would hand to the launcher.
        self._armed_handoff = ""

    # -- composition -----------------------------------------------------
    def compose(self) -> ComposeResult:
        box_ = Vertical(id="browse-box")
        box_.border_title = self._title
        box_.border_subtitle = self._subtitle()
        with box_:
            yield Input(
                value=self._root,
                placeholder=self._placeholder(),
                id="browse-root",
            )
            yield Static(id="browse-state", classes="modal-hint")
            yield ListView(id="browse-list")
            yield from self._mounted_widgets()

    def _subtitle(self) -> str:
        return (
            "Enter opens the folder   o takes the one in the field   esc cancels"
            if self._pick == "folder"
            else "Enter opens a folder or picks a file   esc cancels"
        )

    def _placeholder(self) -> str:
        """An example in the shape of the host's own paths, never the mount's."""

        import os as _os

        from forensic_agent.cli.host_display import containerized

        if not containerized():
            return _os.path.join(_os.path.expanduser("~"), "cases", "case-001")
        if _os.environ.get("DFA_HOST_PLATFORM", "").casefold().startswith("win"):
            return "D:\\Cases\\case-001"
        return "the folder on your computer that holds the evidence"

    def _mounted_widgets(self) -> Iterator[Widget]:
        """The secondary listing, and nothing at all when there is none."""

        import os as _os

        from forensic_agent.cli.host_display import CONTAINER_EVIDENCE, containerized

        if not containerized():
            return
        entries, _ = _browse_entries(CONTAINER_EVIDENCE)
        if not entries:
            return
        self._mounted = [
            (f"{CONTAINER_EVIDENCE}/{name}", is_directory)
            for name, is_directory in entries
        ]
        label = _os.environ.get("DFA_CASE_LABEL", "").strip()
        heading = Text()
        heading.append("ALREADY ATTACHED TO THIS SESSION", style=f"bold {M.DIM_BRIGHT}")
        if label:
            heading.append(f"  {label}", style=M.TEXT)
        heading.append("   read-only", style=M.DIM)
        yield Static(heading, id="browse-mounted-label")
        yield ListView(
            *[
                ListItem(Label(self._row(name.rsplit("/", 1)[-1], is_directory)))
                for name, is_directory in self._mounted
            ],
            id="browse-mounted",
        )

    @staticmethod
    def _row(name: str, is_directory: bool) -> Text:
        row = Text()
        row.append("▸ " if is_directory else "  ", style=M.ACCENT)
        row.append(name, style=M.TEXT if is_directory else M.DIM_BRIGHT)
        return row

    def on_mount(self) -> None:
        if self._root.strip():
            self._show(self._root)
            self.query_one("#browse-list", ListView).focus()
            return
        self._state(
            "Type the folder on your computer that holds the evidence, "
            "then press Enter.",
            style=M.DIM,
        )
        self.query_one("#browse-root", Input).focus()

    # -- the primary listing ---------------------------------------------
    @on(Input.Submitted, "#browse-root")
    def _reroot(self, event: Input.Submitted) -> None:
        event.stop()
        self._show(_unquote(event.value))

    def _show(self, host_path: str) -> None:
        """List one host directory, or say plainly why this container cannot."""

        from forensic_agent.cli.host_display import containerized

        candidate = host_path.strip()
        if not candidate:
            self._state("Name a folder first.", style=M.ORANGE)
            return
        if self._armed_handoff and _same_host_path(self._armed_handoff, candidate):
            # Confirmed. The launcher owns everything from here: it validates
            # the path, mounts it read-only, and starts the console again.
            self.dismiss(candidate)
            return
        container_view = _container_view_of(candidate)
        if container_view is None:
            self._armed_handoff = candidate
            self._entries = []
            self._fill([])
            # Nothing of the operator's is listed now, so what IS attached is
            # worth seeing again.
            self._show_mounted("")
            if not containerized():
                self._state("There is no folder at that path.", style=M.ORANGE)
                self._armed_handoff = ""
                return
            self._state(
                f"The console cannot see {candidate}. Only folders attached "
                "when it started are visible here, so there is nothing to "
                "list. Press Enter again to attach it: the console restarts "
                "with the folder open, read-only, and the case loaded.",
                style=M.ORANGE,
            )
            return
        self._armed_handoff = ""
        self.query_one("#browse-root", Input).value = candidate
        entries, truncated = _browse_entries(container_view)
        separator = _host_separator(candidate)
        base = candidate.rstrip("/\\")
        self._entries = [
            (f"{base}{separator}{name}", is_directory) for name, is_directory in entries
        ]
        self._fill(entries)
        self._show_mounted(container_view)
        self._state(self._listing_note(candidate, entries, truncated), style=M.DIM)

    def _show_mounted(self, container_view: str) -> None:
        """Hide the secondary list while the primary one is showing the mount.

        The two are the same directory whenever the operator is looking at the
        folder this session was started on, and the same names printed twice
        under two headings invite the reader to work out how they differ. They
        do not; there is only one of them.
        """

        from forensic_agent.cli.host_display import CONTAINER_EVIDENCE

        duplicated = container_view == CONTAINER_EVIDENCE
        for identifier in ("#browse-mounted-label", "#browse-mounted"):
            for widget in self.query(identifier).results(Widget):
                widget.display = not duplicated

    def _listing_note(
        self, candidate: str, entries: list[tuple[str, bool]], truncated: bool
    ) -> str:
        if not entries:
            return f"{candidate} is empty."
        folders = sum(1 for _, is_directory in entries if is_directory)
        counted = (
            f"{len(entries)} entries in {candidate}"
            if not truncated
            else f"the first {len(entries)} entries in {candidate}"
        )
        held = f"{folders} folders" if folders != 1 else "1 folder"
        picking = (
            "Enter opens a folder; o takes the one named above as the case."
            if self._pick == "folder"
            else "Enter opens a folder or picks a file."
        )
        return f"{counted} — {held}. {picking}"

    def _fill(self, entries: list[tuple[str, bool]]) -> None:
        view = self.query_one("#browse-list", ListView)
        view.clear()
        for name, is_directory in entries:
            view.append(ListItem(Label(self._row(name, is_directory))))
        view.index = 0 if entries else None

    def _state(self, message: str, *, style: str) -> None:
        self.query_one("#browse-state", Static).update(Text(message, style=style))

    # -- picking ---------------------------------------------------------
    @on(ListView.Selected, "#browse-list")
    def _picked(self, event: ListView.Selected) -> None:
        event.stop()
        index = self.query_one("#browse-list", ListView).index
        if index is None or not 0 <= index < len(self._entries):
            return
        path, is_directory = self._entries[index]
        if is_directory:
            self._show(path)
            return
        if self._pick != "file":
            self._state(
                "That is a file. A case is opened from the folder that holds "
                "it. Press o to take the folder named above.",
                style=M.ORANGE,
            )
            return
        self.dismiss(path)

    @on(ListView.Selected, "#browse-mounted")
    def _picked_mounted(self, event: ListView.Selected) -> None:
        event.stop()
        index = self.query_one("#browse-mounted", ListView).index
        if index is None or not 0 <= index < len(self._mounted):
            return
        path, is_directory = self._mounted[index]
        if is_directory == (self._pick == "folder"):
            self.dismiss(path)
            return
        self._state(
            "This attached source is not the kind this step is asking for."
            if self._pick == "file"
            else "That is an attached file, not a case folder.",
            style=M.ORANGE,
        )

    def action_choose_folder(self) -> None:
        if self._pick != "folder":
            return
        self._show_or_take(self.query_one("#browse-root", Input).value)

    def _show_or_take(self, value: str) -> None:
        """Take the named folder as the case, listing it first if it is new."""

        candidate = _unquote(value).strip()
        if not candidate:
            self._state("Name a folder first.", style=M.ORANGE)
            return
        if _container_view_of(candidate) is None:
            # Unreachable from here: confirming is the handoff, exactly as
            # Enter on the field does it, and for the same reason.
            self._show(candidate)
            return
        self.dismiss(candidate)

    def action_cancel(self) -> None:
        self.dismiss(None)


class _CaseStep:
    """One long step of opening a case, as the console is currently showing it.

    Held as state rather than rendered where it is reported, because the three
    steps of an open report at completely different rates: the evidence digest
    streams a byte count, the entity index states its name once and then blocks
    inside a scanner subprocess, and the dfVFS resolution after the digest says
    nothing at all. Kept here, the slowest of them still has a name, a clock and
    a spinner that a renderer can redraw on its own frame — which is the entire
    difference between a console that looks like it is working and one that
    looks like it has stopped.

    ``done``/``total`` are bytes and ``fraction`` is a proportion someone else
    measured. Both are optional and neither is ever invented: a step that can
    say nothing about how far it has to go shows no bar at all.
    """

    __slots__ = ("label", "done", "total", "fraction", "started")

    def __init__(
        self,
        label: str,
        *,
        done: int | None = None,
        total: int | None = None,
        fraction: float | None = None,
    ) -> None:
        import time

        self.label = label
        self.done = done
        self.total = total
        self.fraction = fraction
        self.started = time.monotonic()

    def elapsed(self) -> float:
        import time

        return max(0.0, time.monotonic() - self.started)

    def measured(self) -> float | None:
        """How far along this step is, or ``None`` when nothing measured it."""

        if self.total:
            return min(1.0, max(0.0, (self.done or 0) / self.total))
        if self.fraction is None:
            return None
        return min(1.0, max(0.0, self.fraction))


# The animated working indicator's frames, one per tick.
_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


# ---------------------------------------------------------------------------
# the app
# ---------------------------------------------------------------------------
class InvestigationApp(App):
    """The investigation console."""

    TITLE = "dfir-agent"

    CSS = """
    *:focus {
        background-tint: $foreground 0%;
    }
    * {
        scrollbar-size-vertical: 1;
        scrollbar-background: $background;
        scrollbar-background-hover: $background;
        scrollbar-background-active: $background;
        scrollbar-color: $dfir-scrollbar;
        scrollbar-color-hover: $accent 60%;
        scrollbar-color-active: $accent;
        scrollbar-corner-color: $background;
    }
    Screen {
        background: $background;
        color: $foreground;
        layout: vertical;
        layers: base guard;
    }
    #body { height: 1fr; padding: 1 1 0 1; }
    #leftcol { width: 3fr; min-width: 46; padding: 0 1 0 0; }
    #rightcol { width: 2fr; min-width: 30; }

    #conversation {
        height: 1fr;
        background: $background;
        border: round $border-blurred;
        border-title-color: $foreground;
        border-title-style: bold;
        padding: 0 2;
        overflow-x: hidden;
    }
    #conversation:focus { border: round $accent 70%; }

    #activity {
        height: 2fr;
        min-height: 8;
        background: $background;
        border: round $border-blurred;
        border-title-color: $foreground;
        border-title-style: bold;
        border-subtitle-color: $dfir-dim;
        padding: 0 1;
        overflow-x: hidden;
    }
    #activity:focus { border: round $accent 70%; border-title-color: $accent; }
    #activity Static { height: auto; padding: 0 1; }

    #evidence-pane, #guardrails-pane {
        height: 1fr;
        min-height: 6;
        background: $background;
        border: round $border-blurred;
        border-title-color: $foreground;
        border-title-style: bold;
        border-subtitle-color: $dfir-dim;
        padding: 0 1;
    }
    #guardrails-pane { height: auto; max-height: 9; min-height: 5; }
    #evidence-pane:focus-within {
        border: round $accent 70%;
        border-title-color: $accent;
    }
    ListView { background: transparent; height: 1fr; }
    .evidence-list { height: auto; }
    Collapsible.denial CollapsibleTitle { color: $error; }
    ListItem { background: transparent; padding: 0 1; }
    ListItem Label { width: 100%; }
    ListView > ListItem.-highlight, ListView > ListItem.--highlight {
        background: $dfir-chip 50%;
    }
    ListView:focus > ListItem.-highlight, ListView:focus > ListItem.--highlight {
        background: $dfir-chip;
    }
    #guardrails { background: transparent; padding: 0 1; }

    #conversation Static { height: auto; }
    #prompt {
        height: 3;
        margin: 0 1;
        padding: 0 2;
        border: round $border-blurred;
        background: $surface;
        color: $foreground;
    }
    #prompt:focus { border: round $accent; }
    #prompt:disabled { opacity: 0.5; }

    /* The matching-command list. Height follows its content so it takes only
       the room it needs, and it is docked in the ordinary flow directly above
       the prompt, where what is being typed is. */
    #command-hints {
        height: auto;
        max-height: 11;
        margin: 0 1;
        padding: 0 2;
        background: $surface;
        border: round $border-blurred;
        border-title-color: $dfir-dim-bright;
        border-subtitle-color: $dfir-dim;
    }

    /* Textual draws both the placeholder and the ghost completion in
       $text-disabled, which is `auto 38%` — 2.66:1 in dfir-light, 3.55:1 in
       dfir-tokyo, 3.34:1 in dfir-contrast, below the floor in all three. The
       placeholder is the only sentence that tells a new operator what this
       line is for, and the ghost is the command they are about to accept, so
       both answer to the palette and to the contrast test with it. */
    #prompt > .input--placeholder, #prompt > .input--suggestion {
        color: $dfir-dim;
    }
    #prompt-entry > .input--placeholder, #context-entry > .input--placeholder,
    #browse-root > .input--placeholder {
        color: $dfir-dim;
    }

    Footer {
        background: $background;
        height: 1;
        padding: 0 2;
    }
    FooterKey { background: $background; }
    FooterKey:hover { background: $dfir-chip 40%; }
    FooterKey .footer-key--key { color: $accent; text-style: bold; }

    #size-guard {
        layer: guard;
        dock: top;
        width: 100%;
        height: 100%;
        background: $background;
        content-align: center middle;
        display: none;
    }

    OverlayScreen, ChoiceScreen, ReviewScreen, PromptScreen, ContextScreen,
    FileBrowserScreen, BudgetScreen { align: center middle; background: $dfir-scrim 60%; }
    #browse-box {
        width: 100; max-width: 95%;
        height: 80%;
        border: round $accent 70%;
        border-title-color: $accent;
        border-title-style: bold;
        /* $text-muted is `auto 60%`: Textual picks black or white against
           the ground it thinks the widget sits on. A modal's ground is the
           scrim, which is dark in every theme, so `auto` chose white and
           then drew it on this box's own light fill — in dfir-light the
           hint under a dialog measured 1.05:1 and was simply not there.
           A palette colour is answerable to the contrast test; `auto` is
           not. */
        border-subtitle-color: $dfir-dim;
        background: $surface;
        padding: 1 3;
    }
    #browse-root {
        height: 3;
        margin: 0 0 1 0;
        border: round $border-blurred;
        background: $surface;
    }
    #browse-root:focus { border: round $accent; }
    #browse-tree { height: 1fr; background: transparent; }
    #prompt-entry, #context-entry {
        height: 3;
        margin: 1 0 0 0;
        border: round $border-blurred;
        background: $surface;
    }
    #prompt-entry:focus, #context-entry:focus { border: round $accent; }
    .modal-hint { margin: 0 0 1 0; }
    #budget-list { height: auto; }
    #budget-note { margin: 1 0 0 1; }
    #activity .pane-hint, #evidence-pane .pane-hint,
    #guardrails-pane .pane-hint {
        height: 100%;
        content-align: center middle;
        text-align: center;
        padding: 0 3;
    }
    /* The guardrails pane is height:auto, where a 100%-tall child
       collapses and centering never happens; an auto child with a small
       min-height centers there for real. */
    #guardrails-pane .pane-hint { height: auto; min-height: 3; }
    /* The reference sheets: as wide as the window allows, because what is in
       them is a table. max-width keeps a line of prose from running past the
       measure at which it stops being readable on a very wide screen. */
    #overlay-box.wide { width: 96%; max-width: 200; }
    #overlay-box, #choice-box {
        width: 100; max-width: 95%;
        height: auto; max-height: 84%;
        border: round $accent 70%;
        border-title-color: $accent;
        border-title-style: bold;
        /* $text-muted is `auto 60%`: Textual picks black or white against
           the ground it thinks the widget sits on. A modal's ground is the
           scrim, which is dark in every theme, so `auto` chose white and
           then drew it on this box's own light fill — in dfir-light the
           hint under a dialog measured 1.05:1 and was simply not there.
           A palette colour is answerable to the contrast test; `auto` is
           not. */
        border-subtitle-color: $dfir-dim;
        background: $surface;
        padding: 1 3;
    }
    #choice-box { width: 76; }
    #choice-list { height: auto; max-height: 18; }
    #overlay-body { height: auto; max-height: 34; }
    Collapsible {
        background: transparent;
        border: none;
        padding: 0;
        margin: 0;
    }
    Collapsible > Contents { padding: 0 0 0 2; }
    CollapsibleTitle {
        background: transparent;
        color: $dfir-dim-bright;
        padding: 0;
    }
    CollapsibleTitle:hover { background: $dfir-chip 40%; color: $accent; }
    CollapsibleTitle:focus { background: transparent; color: $accent; }
    """

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("ctrl+c", "interrupt", "cancel", priority=True, show=False),
        Binding("e", "evidence", "evidence"),
        Binding("a", "activity", "activity"),
        Binding("g", "guardrails", "guardrails"),
        Binding("question_mark", "help", "help"),
        Binding("q", "quit", "quit"),
        Binding("v", "review", "review"),
        Binding("escape", "browse", "browse", show=False),
        Binding("m", "mark", "mark", show=False),
        Binding("i", "ask", "ask", show=False),
        Binding("t", "transcript", "transcript", show=False),
        Binding("ctrl+l", "clear", "clear", show=False),
        *(
            Binding(str(digit), f"jump({digit})", "jump", show=False)
            for digit in range(10)
        ),
    ]

    # Only the investigation commands: Textual's stock palette entries
    # ("Quit the application as soon as possible", theme switching, …) do
    # not belong in a forensic console.
    COMMANDS = {SlashCommandProvider}

    #: Commands a palette pick must NOT run, because their bare form has no
    #: meaning and the value can only be typed. Empty, and measured to be: every
    #: command in the registry answers a bare call with something the operator
    #: can act on — a chooser (/theme, /model, /language, /layout, /reasoning,
    #: /budget, /resume), a chooser followed by a file browser (/attach, /case), or a
    #: listing (/tools, /findings, /oversight, /history, /context). A command
    #: added later that genuinely needs free text belongs here, and
    #: tests/test_tui_console.py asserts every name in it is a real command.
    _NEEDS_ARGUMENT: set[str] = set()

    #: The evidence row armed for removal and when it was armed. Declared but
    #: not assigned: removal reads it through ``getattr`` with a never-armed
    #: default, so the attribute exists only once a row has actually been armed.
    _removal_armed: tuple[Widget | None, float]

    running = reactive(False)

    def __init__(self, controller: InvestigationController) -> None:
        super().__init__()
        for theme in _THEMES.values():
            self.register_theme(theme)
        # The palette has to be in force before anything is drawn: the Rich
        # renderables read model.ACCENT at build time, so a theme applied
        # later would leave the welcome banner in the previous colours.
        saved = _saved_theme()
        M.set_active_palette(saved)
        self.theme = saved
        self._controller = controller
        self._status = controller.status()
        self._exchange = 0
        self._elapsed = 0.0
        self._run_token = 0
        self._phase_started = 0.0
        self._model_phase = True
        self._quit_armed_at = -10.0
        self._spin = 0
        self._current_call = ""
        self._current_args = ""
        self._activity_rows: set[str] = set()
        self._activity_log: dict[int, ToolEvent] = {}
        #: The commands the typed prefix still matches, and which of them the
        #: list is pointing at. Held rather than recomputed per keystroke of an
        #: arrow key: moving through the list must not re-scan the registry.
        self._hint_matches: tuple[tuple[str, str, str], ...] = ()
        self._hint_index = 0
        #: What each finished exchange did, kept so the simple layout can show
        #: it whenever it is switched to rather than only for the exchanges
        #: that happened to finish while it was already active. The feed itself
        #: cannot answer this later: ``_activity_log`` is emptied by the next
        #: run. Two references and a tuple of events per exchange, built from
        #: values the exchange had already assembled.
        self._exchange_record: dict[
            int, tuple[InvestigationResult, tuple[ToolEvent, ...]]
        ] = {}
        #: The blank row that closes each exchange, by exchange number. It is
        #: what an inline activity block is mounted in front of, so a block
        #: added by a layout switch lands inside its own exchange rather than
        #: at the end of the conversation.
        self._exchange_end: dict[int, Static] = {}
        #: Which exchanges currently have an inline activity block mounted.
        #: Tracked rather than read back from the DOM because removal in
        #: Textual is deferred: a fast toggle would find the widget still there
        #: and skip a mount, or mount a second one beside it.
        self._inline_exchanges: set[int] = set()
        self._evidence_cards: list[FindingCard] = []
        self._evidence_lists: dict[int, ListView] = {}
        self._guardrail_groups: dict[int, Vertical] = {}
        self._pending_review: list[tuple[int, FindingCard]] = []
        self._review_stats: dict[int, list[int]] = {}
        self._evidence_last_group = 0
        self._guardrail_blocks: list = []
        self._guardrail_allowed_total = 0
        #: Everything this case's oversight record has said so far, kept because
        #: the pane states the CASE and a result object only knows its own
        #: message. Counts and a bounded sample, never the whole record: the
        #: record is on disk and this is a panel.
        self._guardrail_checked_total = 0
        self._guardrail_refusals: list[OversightCard] = []
        self._guardrail_guessed: list[tuple[str, str]] = []
        self._guardrail_guessed_calls = 0
        self._guardrail_caps: set[str] = set()
        self._layout = "full"
        # How much room the opening screen's Session panel is taking, and which
        # wordmark was chosen for what was left. The count starts generous: the
        # very first draw happens before the panel it is reserving for has been
        # built, and reserving too much only draws a smaller mark, while
        # reserving too little cuts the panel off, which is the defect.
        self._session_rows = 12
        self._header_shown: tuple[str, bool] | None = None
        self._header_room_seen: tuple[int, int] | None = None
        self._header_recheck_queued = False
        self._marked: set[int] = set()
        self._last_result: InvestigationResult | None = None
        # A cancelled run's thread cannot be interrupted — it finishes on its
        # own, orphaned by the token. This flag is the truth about whether
        # that thread is still inside session.ask(); a second ask() on the
        # same session while it runs would race the session's own state.
        self._ask_thread_alive = False
        #: Held for as long as a question is inside session.ask(). A cancelled
        #: run keeps it until its thread unwinds, so the next question waits
        #: here rather than being refused at the prompt.
        self._ask_gate = threading.Lock()
        #: What each key binding's description said in the language it was
        #: declared in. Taken once, and translated from every time, so a switch
        #: back and forth does not ask the catalog to translate its own output.
        self._binding_descriptions: dict[tuple[str, int], str] | None = None
        #: How many external tools the last cancel had to stop. Read by the
        #: cancelled line, which says so rather than leaving the operator to
        #: wonder whether a scan is still running somewhere.
        self._cancelled_children = 0
        #: Commands taken while a message was in flight, waiting for it to end.
        self._deferred_commands: list[tuple[str, str]] = []
        self._deferred_drain_queued = False
        self._reviewing = False
        # A case operation (open, attach, continue, complete) mutating the
        # session on its own worker thread; asks and other commands wait.
        self._case_op_alive = False

    # -- composition -----------------------------------------------------
    def compose(self) -> ComposeResult:
        with Horizontal(id="body"):
            with Vertical(id="leftcol"):
                conversation = ConversationPane(id="conversation")
                conversation.can_focus = True
                yield conversation
            with Vertical(id="rightcol"):
                activity = VerticalScroll(id="activity")
                activity.can_focus = True
                yield activity
                evidence_pane = VerticalScroll(id="evidence-pane")
                evidence_pane.border_title = _pane_title("Evidence")
                yield evidence_pane
                guardrails_pane = VerticalScroll(id="guardrails-pane")
                guardrails_pane.border_title = _pane_title("Guardrails")
                yield guardrails_pane
        # The commands a half-typed slash matches, listed above the prompt. A
        # Static, so it cannot take focus and cannot take a keystroke: it is
        # something to read while typing, never something being picked from.
        hints = Static(id="command-hints")
        hints.display = False
        yield hints
        yield PromptInput(
            id="prompt",
            placeholder=_t(_PROMPT_PLACEHOLDER),
            # Slash commands complete inline. Nothing is captured: the ghost
            # text is a suggestion, Tab takes it, and Enter always sends the
            # characters actually in the line.
            suggester=SuggestFromList(slash_completions(), case_sensitive=False),
        )
        yield Footer()
        yield Static(id="size-guard")

    def on_mount(self) -> None:
        conversation = self.query_one("#conversation", VerticalScroll)
        conversation.border_title = _pane_title("Conversation")
        activity = self.query_one("#activity", VerticalScroll)
        activity.border_title = _pane_title("Activity")
        self._rest_panes()
        self.set_interval(0.12, self._tick)
        # The case-opening row is driven by a clock of its own rather than by
        # the events that feed it. Two of the three long steps of an open
        # report once and then block for minutes, so a row repainted only on an
        # event would sit frozen for exactly the wait it exists to explain.
        self._case_step: _CaseStep | None = None
        self._case_spin = 0
        # Whether the open now in flight is replacing a case that was already
        # open. Read before the open, acted on after it: the previous case's
        # conversation must not be left on screen under the new one's name.
        self._case_replaces_open_case = False
        self.set_interval(0.12, self._case_step_tick)
        self.query_one("#prompt", Input).focus()
        self.call_after_refresh(self._startup)

    def _startup(self) -> None:
        if getattr(self, "_exit", False):
            # A handoff (or an immediate quit) can end the app before this
            # deferred callback lands; welcoming a dying screen only crashes.
            return
        self._welcome()
        if not self._controller.is_demo:
            # The session's quiet console cannot animate; the console's own
            # progress observers take over the digest and index reporting.
            self._install_session_hooks()
            # Evidence named on the command line is deferred by run_live_tui so
            # the screen exists BEFORE the image hashes and indexes for minutes;
            # it opens here, through the same worker and the same progress rows
            # /case and /attach use. The case directory goes first and the typed
            # sources follow it one at a time, which is the order the session
            # constructor applied them in.
            self._pending_sources = list(getattr(self, "_initial_sources", ()) or ())
            self._initial_sources = ()
            deferred = getattr(self, "_initial_case", None)
            if deferred:
                self._initial_case = None
                self._case_worker("open", "", str(deferred))
                return
            if self._pending_sources:
                self._open_next_pending_source()
                return
            # A --case that stages a multi-source selection is resolved here,
            # the way the shell resolved it at startup; the console must
            # never drop it silently.
            try:
                pending = self._controller.session.pending_case_selection()
            except Exception:
                pending = None
            if pending is not None:
                self._resolve_selection(pending)

    # -- the animated working line, inside the conversation flow ----------
    def watch_running(self, _old: bool, _new: bool) -> None:
        # ``App.is_mounted`` asks whether a GIVEN widget is mounted, so reading
        # it bare was always truthy and guarded nothing; the question this
        # watcher means to ask is whether the app loop is still up, because
        # refreshing queries the DOM.
        if self.is_running:
            self._refresh_working_line()
        # A finished run is the moment anything taken for the next one applies.
        # Watched here rather than called from each of the four places that
        # clear the flag, because one of them would be forgotten: the reactive
        # is the single fact "a message is in flight".
        if not _new:
            self._drain_deferred_soon()

    def _tick(self) -> None:
        if self.running:
            self._elapsed += 0.12
            self._spin = (self._spin + 1) % len(_SPINNER)
            self._refresh_working_line()

    def _working_line(self) -> Text:
        import time as _time

        phase_s = max(0.0, _time.monotonic() - self._phase_started)
        text = Text(no_wrap=True, overflow="ellipsis")
        text.append(_SPINNER[self._spin] + " ", style=M.ACCENT)
        text.append("Investigating", style=f"bold {M.ACCENT}")
        # Right-aligned to the width each form already occupied, so the spinner
        # column does not jitter as the run crosses into minutes.
        text.append(
            f"  {format_duration(self._elapsed, compact=True):>6}", style=M.DIM_BRIGHT
        )
        if self._current_call and not self._model_phase:
            phase = format_duration(phase_s, compact=True, decimals=0)
            text.append(f"   {self._current_call}  {phase:>5}", style=M.TEXT)
            if self._current_args:
                text.append(f"  {self._current_args}", style=M.DIM)
        return text

    def _refresh_working_line(self) -> None:
        for widget in self.query(f"#work-{self._exchange}").results(Static):
            widget.update(self._working_line())

    def _remove_working_line(self) -> None:
        for widget in self.query(f"#work-{self._exchange}").results(Static):
            widget.remove()
        self._settle_unfinished_rows()

    def _settle_unfinished_rows(self) -> None:
        """A run that ends under a call in flight must not leave it spinning.

        Cancelled and errored runs stop before the call announces its outcome;
        the row is settled as unfinished rather than left saying "running…"
        for the rest of the session.
        """

        for sequence, event in self._activity_log.items():
            if event.status != "running":
                continue
            row_id = f"act-{self._exchange}-{sequence}"
            if row_id not in self._activity_rows:
                continue
            try:
                row = self.query_one(f"#{row_id}", Static)
            except NoMatches:
                continue
            _paint(row, partial(_activity_row, event, status=_STATUS_UNFINISHED))

    # -- the conversation is a widget stack ------------------------------
    def _say(
        self,
        renderable,
        *,
        widget_id: str | None = None,
        classes: str | None = None,
    ) -> Static:
        """Mount one renderable at the end of the conversation and reveal it.

        A callable is taken as the line's recipe rather than its result: it is
        kept on the widget and re-run on a theme change, so the transcript is
        redrawn in the new palette instead of keeping the colours it was
        written in. Lines that carry no colour are passed as plain
        renderables — there is nothing about them to repaint.
        """

        pane = self.query_one("#conversation", VerticalScroll)
        widget = (
            _painted(renderable, id=widget_id, classes=classes)
            if callable(renderable)
            else Static(renderable, id=widget_id, classes=classes)
        )
        if getattr(self, "_exit", False) or not pane.is_attached:
            # The app is closing under this write; an unmounted widget is
            # returned so callers keep their references without crashing.
            return widget
        pane.mount(widget)
        pane.scroll_end(animate=False)
        return widget

    # -- welcome: the CLI's own identity ---------------------------------
    #: Rows the opening screen needs below the wordmark: the Session panel's
    #: own rows, its border and padding, and the blank lines around it. The
    #: panel's row count is whatever the session currently has to say, so it is
    #: read from the last one drawn (see :meth:`_session_grid`); the rest is
    #: fixed by the panel's own frame. The wordmark gets what is left, and when
    #: that is nothing it is not drawn — the panel is the half of the opening
    #: screen that carries information, and it was the half being cut off.
    _SESSION_PANEL_CHROME = 4
    _WELCOME_BLANK_ROWS = 3

    def _header_room(self, content: Size | None = None) -> tuple[int, int]:
        """The cells the wordmark may occupy: (width, height).

        Measured off the conversation's own content box, never off the terminal:
        the pane is three fifths of the screen less its border and padding, and
        assuming otherwise is what drew the 77-cell art into a 63-cell pane.
        A pane that has not been laid out yet reports zero, and zero is taken at
        its word — the smallest rendering is drawn and :meth:`_refresh_header`
        corrects it once the layout lands, which is the safe direction to be
        wrong in.

        ``content`` is the pane's own box when the pane itself is what asked;
        passing it keeps a resize off the DOM entirely, which is the difference
        between a drag costing one attribute read per event and one query.
        """

        if content is None:
            try:
                content = self.query_one("#conversation", ConversationPane).content_size
            except NoMatches:
                # A deferred recheck can outlive the console it was measuring; a
                # header that cannot find its pane simply has no room.
                return (0, 0)
        reserved = (
            self._session_rows + self._SESSION_PANEL_CHROME + self._WELCOME_BLANK_ROWS
        )
        return content.width, max(0, content.height - reserved)

    def _header_choice(self, room: tuple[int, int] | None = None) -> tuple[str, bool]:
        """Which rendering the pane can hold, as (variant name, tagline).

        The identity of what is on screen, so a resize that does not change it
        can skip the repaint entirely. "" names the case where no wordmark fits.

        ``room`` is an already-taken measurement; re-measuring here would read
        the same pane twice for one decision.
        """

        width, height = self._header_room() if room is None else room
        mark = _wordmark_for(width, height)
        if mark is None:
            return ("", False)
        tagline = width >= _TAGLINE_WIDTH and mark.height + 1 <= height
        return (mark.name, tagline)

    def _banner_renderable(self):
        """The wordmark at whichever of its three renderings the pane can hold.

        Kept as the banner widget's recipe rather than a one-off result, so a
        theme switch redraws it in the new gradient (see :func:`_painted`).
        """

        return self._banner_for(self._header_choice())

    def _banner_for(self, choice: tuple[str, bool]):
        """One rendering, drawn from a choice that has already been made.

        Split from :meth:`_banner_renderable` so the resize path can decide and
        draw from a single measurement: the decision is what says whether to
        draw at all, and re-deriving it inside the drawing would measure again.
        """

        name, tagline = choice
        self._header_shown = choice
        if not name:
            return Text("")
        mark = next(mark for mark in _WORDMARKS if mark.name == name)
        return _wordmark_text(mark, tagline=tagline)

    #: How long after a mount the pane has been laid out and the Session panel
    #: has been built, so the room the wordmark was first drawn into can be
    #: measured for real. A mount is the only thing this delay covers; a resize
    #: is announced by the pane itself, after its layout, so no delay chosen
    #: here can be wrong about it.
    _HEADER_SETTLE_S = 0.05

    def _recheck_header_soon(self) -> None:
        """Look again once the mount has settled, at most once per burst."""

        if self._header_recheck_queued:
            return
        self._header_recheck_queued = True
        self.set_timer(self._HEADER_SETTLE_S, self._refresh_header)

    @on(ConversationPane.Resized)
    def _conversation_resized(self, message: ConversationPane.Resized) -> None:
        """The pane has been laid out anew, so the mark is re-chosen for it.

        Every resize reaches the header through here — a drag, a maximize, a
        restore from minimised — because every one of them ends in a layout and
        the layout is what posts this. Nothing is polled, and nothing is assumed
        about how long a layout takes.
        """

        self._refresh_header(message.pane.content_size)

    def _refresh_header(self, content: Size | None = None) -> None:
        """Redraw the wordmark, but only if the pane now holds a different one.

        This is the whole of the resize cost, and on the common path it is two
        comparisons. The pane's box is checked against the last one measured
        first, because a drag emits an event per cell and almost none of them
        change the box at all; then the variant is chosen, which is a handful
        of integer comparisons over three fixed renderings; and only a width
        that crosses a boundary between them reaches the repaint. A drag across
        the whole range therefore costs two renders however many events it
        emitted, and a height-only change costs none.
        """

        self._header_recheck_queued = False
        banner = getattr(self, "_banner_widget", None)
        if banner is None or not banner.is_mounted:
            return
        room = self._header_room(content)
        if room == self._header_room_seen:
            # Nothing measured has moved: nothing to decide, nothing to draw.
            return
        self._header_room_seen = room
        choice = self._header_choice(room)
        if choice == self._header_shown:
            return
        banner.update(self._banner_for(choice))

    # Below this, panes collapse into uselessness; the guard takes over the
    # screen and says exactly what size the console needs.
    MIN_WIDTH = 96
    MIN_HEIGHT = 28

    def on_resize(self, event) -> None:
        # The event's size is the truth; self.size still holds the PREVIOUS
        # terminal size when this handler runs, so reading it left the guard
        # one resize behind — hidden over crushed panes after a snap down,
        # covering a full-size terminal after a snap back up.
        size = getattr(event, "size", None) or self.size
        # The wordmark is deliberately NOT chosen here. The panes have not been
        # re-laid-out yet, so the conversation still reports the width it had
        # before this event, and a delay long enough to wait that out on one
        # machine is too short on another — a maximize that outran the delay
        # left the mark at the width it had before. It is chosen instead when
        # the pane itself says it has been laid out (ConversationPane.Resized).
        self._keep_the_end_in_view()
        for guard in self.query("#size-guard").results(Static):
            too_small = size.width < self.MIN_WIDTH or size.height < self.MIN_HEIGHT
            guard.styles.display = "block" if too_small else "none"
            if too_small:
                _paint(guard, partial(self._too_small_message, size))

    def _keep_the_end_in_view(self) -> None:
        """A resize must not strand a scrolling pane in the middle of itself.

        Re-wrapping at a new width changes how many rows the SAME transcript
        occupies — narrowing a six-exchange conversation from 110 to 62 columns
        grew it from 141 rows to 162 here — while the scroll offset stays the
        number it was. A pane that was showing the newest exchange therefore
        comes back showing an older one, with everything since below the fold,
        which reads as the console having lost the answer it just gave.

        Only panes that WERE at the end are moved. An operator who had scrolled
        back to read exchange 02 is reading exchange 02, and a resize is not a
        reason to take that away from them.

        Measured here, before the layout runs, because "was it at the end" is a
        question about the pane as it stood; acted on afterwards, because the
        end it has to return to is the one the new width produces. Two attempts:
        a wide transcript can take more than one frame to re-wrap, and pinning
        to a half-finished layout would leave the same defect a few rows
        smaller.
        """

        at_end = [
            pane
            for pane_id in ("#conversation", "#activity")
            for pane in self.query(pane_id).results(VerticalScroll)
            if pane.scroll_y >= pane.max_scroll_y - 1
        ]
        if not at_end:
            return

        def repin() -> None:
            for pane in at_end:
                if pane.is_attached:
                    pane.scroll_end(animate=False)

        self.set_timer(self._HEADER_SETTLE_S, repin)
        self.set_timer(self._HEADER_SETTLE_S * 6, repin)

    def _too_small_message(self, size) -> Text:
        message = Text(justify="center")
        # The guard owns the whole screen, so it measures the screen; it still
        # goes through the same cascade, because a guard that clipped its own
        # wordmark would be the defect it exists to report.
        mark = _wordmark_for(max(0, size.width - 6), max(0, size.height - 6))
        if mark is not None:
            message.append_text(_wordmark_text(mark, tagline=False))
            message.append("\n\n")
        message.append("The terminal is too small\n\n", style=M.TEXT)
        message.append(
            f"Needs at least {self.MIN_WIDTH}×{self.MIN_HEIGHT}"
            f" — now {size.width}×{size.height}\n",
            style=M.DIM_BRIGHT,
        )
        message.append("Enlarge the window or reduce the font size", style=M.DIM)
        return message

    def _welcome(self, with_status: bool = True) -> None:
        self._say(Text(""))
        # Id-less on purpose: a fixed id here once let two racing welcomes
        # crash the console with DuplicateIds; the resize handler reaches the
        # banner through this reference instead of a DOM query.
        self._banner_widget = self._say(self._banner_renderable)
        self._say(Text(""))
        if with_status:
            self._session_widget = self._say(self._session_renderable)
        if self._controller.is_demo:
            self._say(self._demo_hint)
        self._say(Text(""))
        # The pane's own size is not known until this mount has been laid out,
        # and the Session panel's row count is not known until the panel has
        # been built — which happens two lines above, after the wordmark was
        # sized. Both are settled by the time the deferred recheck runs, and it
        # redraws only if the first guess was wrong.
        self._recheck_header_soon()

    def _demo_hint(self) -> Text:
        from forensic_agent.tui.demo_data import DEMO_QUESTION

        tail = Text()
        tail.append("\nTry: ", style=M.DIM_BRIGHT)
        tail.append(DEMO_QUESTION, style=M.ACCENT)
        return tail

    def _session_renderable(self):
        """The Session panel — the line CLI's own in live mode, a mirror in demo.

        Live mode renders ``session.config_panel()`` verbatim, so the tools
        count, the case-context row and the *open evidence* hint match the
        shell exactly; demo mode builds the equivalent from the status frame.
        """

        # Always the console's own frame: the shell panel's colours were
        # tuned for a different ground and read as noise on this one.
        return self._session_panel()

    def _refresh_session_panel(self) -> None:
        """The Session panel is standing state, not a log line.

        Whatever changed that state — a case opening, a model switch, a
        completed case — the ONE panel on screen is redrawn in place, so it
        never shows "not loaded" above a case that just opened. A second
        printed copy would leave the first one lying about the present.
        """

        self._status = self._controller.status()
        widget = getattr(self, "_session_widget", None)
        if widget is not None and widget.is_mounted:
            widget.update(self._session_renderable())
        # A panel that grew or shrank changed what is left for the wordmark; a
        # case opening adds four rows, which is a whole compact mark's worth.
        self._refresh_header()

    def _session_grid(self) -> Table:
        """The Session rows themselves: label, value, command — no frame.

        The overlay draws its own titled border, so /status shows these rows
        bare; in the conversation the same rows go inside the Session panel.
        """

        status = self._status
        grid = Table.grid(padding=(0, 2))
        grid.add_column(justify="right", no_wrap=True)
        grid.add_column(overflow="fold", ratio=1)
        grid.add_column(justify="right", no_wrap=True)

        def row(label: str, value: Text, command: str = "") -> None:
            # The label goes through the language layer; the value does not,
            # unless the caller translated it. A value here is usually an
            # identifier -- a model id, a case label, a theme name, a trace id
            # -- and an identifier that changes with the interface language is
            # one the operator can no longer type back in.
            grid.add_row(
                Text(_t(label), style=M.DIM_BRIGHT), value, Text(command, style=M.DIM)
            )

        row("model", Text((status.model or "—"), style=f"bold {M.ACCENT}"), "/model")
        row("provider", Text(status.provider, style=M.TEXT))
        row("reasoning", Text(status.reasoning_effort, style=M.TEXT), "/reasoning")
        # No "layout" row. This panel says what the CASE is — the evidence, the
        # model that will read it, the budget it may spend. How the console
        # arranges itself on screen is a display preference and belongs with
        # the other preferences, not among the facts of the investigation.
        if self._controller.is_demo:
            # Bound first so the row fits on one line. The secondary accent is
            # exempt from the raised-surface contrast floor only for as long as
            # both of its uses render on the terminal ground, and
            # tests/test_tui_theme.py holds that exemption honest by counting
            # those uses and reading this one off the row it sits on.
            demo = _t("demo — a replayed case; nothing real is needed")
            row("mode", Text(demo, style=M.PURPLE))
        has_evidence = bool(status.evidence_sources)
        row(
            "active case",
            Text(status.case_label if has_evidence else _t("not loaded"),
                 style=(f"bold {M.ACCENT}" if has_evidence else M.DIM_BRIGHT)),
            "/case",
        )
        for source in status.evidence_sources:
            kind, _, name = source.partition(": ")
            row(kind, Text(name or source, style=M.SUCCESS))
        if has_evidence:
            row(
                "sources",
                Text(
                    f"{M.GLYPH_OK} {len(status.evidence_sources)} {_t('attached')}",
                    style=M.SUCCESS,
                ),
                "/sources",
            )
        if not self._controller.is_demo:
            try:
                count = len(self._controller.session._visible_tool_names())
                row(
                    "tools",
                    Text(
                        f"{count} {_t('available')}",
                        style=(f"bold {M.ACCENT}" if count else M.DIM_BRIGHT),
                    ),
                    "/tools",
                )
            except Exception:
                pass
            try:
                brief = self._current_case_context()
                row(
                    "case context",
                    (
                        Text(f"{M.GLYPH_OK} {_t('set')}", style=M.SUCCESS)
                        if brief
                        else Text(_t("not set"), style=M.DIM_BRIGHT)
                    ),
                    "/context",
                )
            except Exception:
                pass
        if not has_evidence:
            # A row like every other, so "open evidence" sits in the label
            # column in the label colour instead of floating under the grid
            # in a shade of its own.
            row("open evidence", Text("/case <folder-or-file>", style=M.ACCENT))
        # What the panel costs the opening screen in rows, so the wordmark
        # above it can be sized against what is actually left.
        self._session_rows = len(grid.rows)
        return grid

    def _panel_subtitle(self, width: int) -> Text:
        """What the Session panel says about itself: the version, and no more.

        The build identity used to sit here too, as ``code dated 2026-08-11
        14:19``. It was put here to solve a real problem — defects reported
        again from an image older than the code, with nothing on screen saying
        so — and it solved it in the wrong place and in the wrong words. This
        panel says what the CASE is; which binary is running is not part of
        that, and "code dated" is a sentence about source files rather than
        anything an operator can act on.

        The capability moved rather than went: /doctor names the build, and
        :func:`~forensic_agent.cli.build_identity.staleness_note` says so in
        plain words when, and only when, the build is actually old.
        """

        del width  # the version alone always fits
        return Text(_version_label(), style=M.DIM)

    def _session_panel(self) -> Panel:
        """The Session rows in the console's own frame."""

        try:
            pane = self.query_one("#conversation", VerticalScroll).content_size.width
        except NoMatches:
            pane = 0
        width = min(72, max(48, pane or 72))
        return Panel(
            self._session_grid(),
            title=Text(f"{M.GLYPH_POINT} {_t('Session')}", style=f"bold {M.ACCENT}"),
            title_align="left",
            subtitle=self._panel_subtitle(width),
            subtitle_align="right",
            border_style=M.BORDER,
            box=box.ROUNDED,
            padding=(1, 2),
            width=width,
        )

    # -- input / commands ------------------------------------------------
    @on(Input.Changed, "#prompt")
    def _slash_shows_its_usage(self, event: Input.Changed) -> None:
        """Say what the command being typed takes, without taking the line.

        The usage line is the one place the argument shape is written down, so
        it is shown WHILE the argument is being typed rather than afterwards in
        an error. It rides the input's own subtitle: a label cannot swallow a
        keystroke, which is exactly what the palette this replaced did.
        """

        typed = event.value
        self._show_command_hints(typed)
        if not typed.startswith("/"):
            event.input.border_subtitle = ""
            return
        name = typed[1:].split(maxsplit=1)[0] if len(typed) > 1 else ""
        usage = self._command_usage(name) if name else ""
        event.input.border_subtitle = _literal_markup(usage) if usage else ""

    def _show_command_hints(self, typed: str) -> None:
        """Draw the commands the typed prefix still matches, or hide the list.

        The ghost completion the input carries offers exactly one command, and
        one is not a list: an operator who types ``/`` is asking what there is,
        and a single greyed ``/attach`` after the cursor answers a different
        question. So the matches are written out where they can be read, with
        each command's own usage beside it, and the list narrows keystroke by
        keystroke until the argument starts.

        Nothing here has focus and nothing here can take a keystroke — it is a
        Static. It is moved through from the line instead: Up and Down are
        bound on the input, live only while this is on screen, so typing goes
        on working at every moment. That is not a detail. This list replaced a
        command palette that took the keyboard, and the console could not be
        typed in while it was open.
        """

        try:
            hints = self.query_one("#command-hints", Static)
        except NoMatches:
            return
        matches = matching_commands(typed)
        if not matches:
            self._hint_matches = ()
            self._hint_index = 0
            hints.display = False
            return
        if tuple(name for name, _u, _d in matches) != tuple(
            name for name, _u, _d in self._hint_matches
        ):
            # A different set of commands is a different list, so the cursor
            # goes back to the top of it. Narrowing to the SAME set — another
            # character of an argument — leaves the operator's choice alone.
            self._hint_index = 0
        self._hint_matches = matches
        self._hint_index = max(0, min(self._hint_index, len(matches) - 1))
        self._paint_command_hints()
        hints.display = True

    @property
    def command_hints_open(self) -> bool:
        """Whether there is a list on screen to be moved through."""

        if not self._hint_matches:
            return False
        try:
            return bool(self.query_one("#command-hints", Static).display)
        except NoMatches:
            return False

    def selected_command_hint(self) -> str | None:
        """The name of the command the list is pointing at, or None."""

        if not self.command_hints_open:
            return None
        return self._hint_matches[self._hint_index][0]

    def move_command_hint(self, delta: int) -> None:
        """Move the cursor through the list and scroll it into view.

        Stops at the ends rather than wrapping, which is what every other list
        in this console does — the budget rows, the evidence list, the choosers
        are all Textual lists, and none of them wraps.

        Cheap by construction: the matches are already held, so this is one
        addition, one clamp and one repaint of at most eight rows. Nothing is
        re-matched against the registry and nothing is measured.
        """

        if not self.command_hints_open:
            return
        moved = max(0, min(self._hint_index + delta, len(self._hint_matches) - 1))
        if moved == self._hint_index:
            return
        self._hint_index = moved
        self._paint_command_hints()

    def close_command_hints(self) -> None:
        """Esc takes the list down and leaves the typed characters alone."""

        self._hint_matches = ()
        self._hint_index = 0
        self._hide_command_hints()

    def _paint_command_hints(self) -> None:
        """Draw the window of the list that holds the selected row.

        Eight rows at a time out of as many as the registry has, scrolled so
        the cursor is always one of them, with the count above and below
        stated on the frame — an operator who cannot see row nine has to be
        told there is a row nine.
        """

        try:
            hints = self.query_one("#command-hints", Static)
        except NoMatches:
            return
        matches = self._hint_matches
        total = len(matches)
        # The window slides only as far as it must to hold the cursor, so a
        # list that fits does not move at all.
        first = max(0, min(self._hint_index - _HINTS_SHOWN + 1, total - _HINTS_SHOWN))
        first = max(0, min(first, self._hint_index))
        window = matches[first : first + _HINTS_SHOWN]
        rows = Table.grid(padding=(0, 1))
        rows.add_column(no_wrap=True)
        rows.add_column(style=f"bold {M.ACCENT}", no_wrap=True)
        rows.add_column(style=M.DIM, no_wrap=True)
        rows.add_column(style=M.TEXT, overflow="ellipsis")
        for offset, (name, usage, description) in enumerate(window):
            selected = first + offset == self._hint_index
            argument = usage[len(f"/{name}"):].strip()
            # A usage line is mostly square brackets, and a Table cell given a
            # str is parsed as markup: unescaped, /model's ``[list [all|<text>]
            # |<model-id>]`` renders with the nested part eaten as a style tag.
            pointer = Text(
                f"{M.GLYPH_POINT} " if selected else "  ",
                style=f"bold {M.ACCENT}" if selected else M.DIM,
            )
            row_style = f"on {M.ACCENT_MUTED}" if selected else ""
            rows.add_row(
                pointer,
                Text(f"/{name}"),
                Text(argument),
                Text(description),
                style=row_style,
            )
        hints.update(rows)
        hints.border_title = f"{total} commands" if total > 1 else "1 command"
        above = first
        below = total - (first + len(window))
        marks: list[str] = []
        if above:
            marks.append(f"{above} above")
        if below:
            marks.append(f"{below} below")
        hints.border_subtitle = (
            f"{'   '.join(marks)}   ↑↓ moves   Tab takes it"
            if marks
            else "↑↓ moves   Tab takes it"
        )

    def _hide_command_hints(self) -> None:
        """Take the list down: the line was sent, cleared or handed elsewhere."""

        self._hint_matches = ()
        self._hint_index = 0
        try:
            self.query_one("#command-hints", Static).display = False
        except NoMatches:
            pass

    @staticmethod
    def _takes_argument(name: str) -> bool:
        """Whether this command's own usage line declares anything after it.

        Read off the declaration rather than kept in a list beside it: a list
        drifts, and when it does, the command that drifted out of it is one the
        operator can no longer pass an argument to at all.
        """

        from forensic_agent.cli.commands import COMMAND_REGISTRY

        spec = COMMAND_REGISTRY.resolve(name)
        if spec is None:
            return False
        return spec.usage.strip() != f"/{spec.name}"

    def palette_insert(self, name: str) -> None:
        """A palette pick RUNS the command. The palette is a menu, not a hint.

        The bare form of every argument-taking command in this console is
        already the menu for it: /theme, /model, /language, /layout,
        /reasoning, /budget and /resume open a chooser, /attach and /case open
        a chooser and then a file browser, /tools and /findings and /oversight
        and /history open the listing the argument narrows. So running the
        bare form on a pick is what puts the operator in front of the values
        they were going to type, which is both quicker and safer than spelling
        a path or a model id out by hand.

        This replaced a version that inserted the name and only notified, on
        the theory that running a command with an argument would strand the
        argument. It stranded the operator instead: picking `tools` from the
        palette said "run /tools" and did nothing, and every command behaved
        that way. Nothing is lost by running it — the chooser is where the
        argument is chosen — and typing the command out by hand still works
        exactly as before, arguments and all.

        Only a command in :attr:`_NEEDS_ARGUMENT` (empty; see there) has no
        usable bare form, and that one is placed in the prompt with the cursor
        after it, ready for the text that has to be typed.
        """

        if name in self._NEEDS_ARGUMENT:
            prompt = self.query_one("#prompt", Input)
            prompt.value = f"/{name} "
            prompt.cursor_position = len(prompt.value)
            prompt.focus()
            self.notify(self._usage_line(name), title=f"/{name}", timeout=8)
            return
        self.dispatch_command(name, "")

    @staticmethod
    def _canonical_command(name: str) -> str:
        """The command an alias belongs to, or the name unchanged."""

        try:
            from forensic_agent.cli.commands import COMMAND_REGISTRY

            spec = COMMAND_REGISTRY.resolve(name)
            return spec.name if spec is not None else name
        except Exception:
            return name

    def _command_usage(self, name: str) -> str:
        """The usage line of one command, by its name OR one of its aliases.

        Empty for anything the registry does not know, including a name still
        half typed: a hint that appears for a prefix and then vanishes reads as
        the console losing track of the command, and an operator two letters
        into ``/clear`` is not asking a question yet.
        """

        try:
            from forensic_agent.cli.commands import COMMAND_REGISTRY

            wanted = name.casefold()
            for spec in COMMAND_REGISTRY.commands:
                if wanted == spec.name or wanted in spec.aliases:
                    return spec.usage or spec.description
        except Exception:
            pass
        return ""

    def _usage_line(self, name: str) -> str:
        return self._command_usage(name) or f"/{name}"

    @on(Input.Submitted, "#prompt")
    def _on_submit(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        # Whatever the line turns out to be, the list of things it could still
        # have become is over.
        self._hide_command_hints()
        if not text:
            return
        if text.startswith("/"):
            event.input.value = ""
            self._handle_slash(text)
            return
        if self.running:
            # The typed question survives; only the send is refused.
            self.notify(
                "A message is already being investigated. Ctrl+C cancels it.",
                title="busy",
                severity="warning",
            )
            return
        event.input.value = ""
        self._ask(text)

    def _handle_slash(self, text: str) -> None:
        from forensic_agent.cli.commands import UnknownCommandError, parse_command

        try:
            parsed = parse_command(text)
        except UnknownCommandError:
            self.notify("Unknown command. Press ? or type /help.", title="unknown command")
            return
        if parsed is not None:
            self.dispatch_command(parsed.name, parsed.argument_text)

    #: Commands safe while a message is being investigated. One test decides
    #: membership: the command may not change what the session holds, may not
    #: start work of its own, and may not touch the evidence. What is left is
    #: reading already-recorded state and setting the console's own
    #: appearance, neither of which the running thread can notice.
    #: /reasoning and /budget belong here for a further reason: a cancelled
    #: run's winding-down thread holds its OWN runner reference, so changing
    #: the default for the NEXT question never touches the orphan — and
    #: without this, the operator who just pressed Ctrl+C is told to press
    #: Ctrl+C.
    _SAFE_WHILE_RUNNING = {
        "budget",
        "clear",
        "findings",
        "help",
        "history",
        "language",
        "layout",
        "oversight",
        "quit",
        "reasoning",
        "sources",
        "status",
        "theme",
        "tools",
    }

    #: Why each blocked command is blocked, in its own words. A refusal that
    #: says only that the console is busy leaves the operator guessing whether
    #: the command or the timing was wrong; this names the thing about THIS
    #: command that cannot happen beside a running investigation.
    _BLOCKED_WHILE_RUNNING: ClassVar[dict[str, str]] = {
        "attach": "attaches another evidence source",
        "case": "opens other evidence",
        "complete": "closes the case and detaches its evidence",
        "context": "rewrites the case brief the next message carries",
        "continue": "reopens a previous investigation and its evidence",
        "doctor": "probes the model connection this run is using",
        "export": "writes a report from a history this run is still adding to",
        "model": "switches the model this run is talking to",
        "new": "starts a new investigation history",
        "resume": "loads a saved investigation over this one",
        "retry": "starts a second investigation",
        "setup": "reconfigures the model connection",
        "undo": "takes the last answer out of the model's context",
        "verify": "streams the whole medium the run is reading from",
    }

    #: Commands whose whole effect is on the NEXT question, and which therefore
    #: do not have to be refused while one is in flight — they are taken now and
    #: run when the run ends.
    #:
    #: Membership is not "it looks harmless". Each of these was traced to the
    #: point where the running ask() reads what it changes, and each is read
    #: ONCE, as an argument at the call: ``runner.ask(...)`` takes
    #: ``case_context`` by value, and the runner itself is built by
    #: ``_controlled_runner()`` before the question starts and held in a local
    #: for the rest of it. Nothing either command changes can reach a run that
    #: has already begun.
    #:
    #: That is why they are DEFERRED rather than simply admitted. Running them
    #: now would be safe for the run's inputs and unsafe for everything else
    #: about them: ``change_model`` builds a replacement conversation and
    #: activates it (``session.change_model`` -> ``_activate_model_context``),
    #: which swaps the history the run is still writing into, and both of them
    #: print into the session console that the run's own thread is printing to.
    #: Waiting until the run is over removes both hazards and keeps the promise
    #: the operator was given: it applies to the next message.
    _DEFERRABLE_WHILE_RUNNING: ClassVar[dict[str, str]] = {
        "model": "the model your next message runs on",
        "context": "the case brief your next message carries",
    }

    def _deferrable_form(self, name: str, argument: str) -> str | None:
        """What this exact invocation would set, or None if it is not a setting.

        Only the forms that CHANGE something are taken and held. A bare /model
        or /context opens a view or a chooser, and holding one of those for the
        end of the run answers a question the operator asked now; /model list
        goes further and ends in a picker whose whole point is that it is in
        front of them. Those keep the refusal they had.
        """

        text = argument.strip()
        if name == "model":
            first = text.split(None, 1)[0].casefold() if text else ""
            if not text or first == "list":
                return None
            return self._DEFERRABLE_WHILE_RUNNING["model"]
        if name == "context":
            if not text:
                return None
            action = text.split(None, 1)[0].casefold()
            if action == "show":
                return None
            return self._DEFERRABLE_WHILE_RUNNING["context"]
        return None

    def _defer_command(self, name: str, argument: str, sets: str) -> None:
        """Take a command now and run it when the console is free.

        Said out loud, because a command that is silently held is a command the
        operator believes did not register. The queue keeps its order: two
        /model calls apply in the order they were typed, and the last one wins
        for the same reason it would have if they had been typed a minute apart.
        """

        self._deferred_commands.append((name, argument))
        typed = f"/{name} {argument}".strip()
        self.notify(
            f"{typed} is accepted and sets {sets}. It applies when this message "
            "is finished, not to this one.",
            title=f"/{name}",
        )
        self._drain_deferred_soon()

    #: How long after the console looks free the queue is looked at again. Only
    #: ever armed while something is queued, so an idle console runs no timer.
    _DEFERRED_SETTLE_S = 0.25

    def _drain_deferred_soon(self) -> None:
        if self._deferred_commands and not self._deferred_drain_queued:
            self._deferred_drain_queued = True
            self.set_timer(self._DEFERRED_SETTLE_S, self._drain_deferred)

    def _drain_deferred(self) -> None:
        """Run what was taken while the console was busy, once it is free.

        "Free" is all three of the conditions the refusal above tests, not just
        ``running``: Ctrl+C clears ``running`` immediately while the orphaned
        thread is still inside session.ask(), and applying a model change into
        that window is exactly the race the deferral exists to avoid.
        """

        self._deferred_drain_queued = False
        if not self._deferred_commands:
            return
        if self.running or self._ask_thread_alive or self._case_op_alive:
            self._drain_deferred_soon()
            return
        pending, self._deferred_commands = self._deferred_commands, []
        for name, argument in pending:
            self.dispatch_command(name, argument)

    def dispatch_command(self, name: str, argument: str = "") -> None:
        # An alias answers here too. Handlers are named for the CANONICAL
        # command (`_cmd_resume`), so a caller that reached this method with
        # `sessions` or `guardrails` — the command palette, a key binding, a
        # test — would otherwise find no handler and get "unknown command" for
        # a name the console itself offers.
        name = self._canonical_command(name)
        if (
            not self._controller.is_demo
            and name not in self._SAFE_WHILE_RUNNING
            # _ask_thread_alive covers the window after Ctrl+C: the orphaned
            # thread is still inside session.ask(), and /case mid-run could
            # close the disk under it; /new would clear the history it is
            # writing into. _case_op_alive covers the same hazard from the
            # other side — a case opening or completing on its own worker.
            and (self.running or self._ask_thread_alive or self._case_op_alive)
        ):
            deferred_as = self._deferrable_form(name, argument)
            if deferred_as is not None:
                # Nothing it changes can reach the run in flight, so there is
                # no reason to make the operator wait, watch, and type it again.
                self._defer_command(name, argument, deferred_as)
                return
            reason = self._BLOCKED_WHILE_RUNNING.get(name, "changes the session")
            self.notify(
                (
                    f"/{name} {reason}, which cannot happen while a message is "
                    "being investigated. Ctrl+C cancels the run first."
                    if (self.running or self._ask_thread_alive)
                    else f"/{name} {reason}, and a case operation is still in "
                    "progress. Give it a moment."
                ),
                title=f"/{name}",
                severity="warning",
            )
            return
        handler = getattr(self, f"_cmd_{name}", None)
        if handler is None:
            # Every registry command has a handler here; reaching this means
            # the registry grew without the console keeping up.
            self.notify(
                f"/{name} is not implemented in this console yet.",
                title=f"/{name}",
                severity="warning",
            )
            return
        handler(argument.strip())

    def _demo_blocked(self, name: str) -> bool:
        """True (with the standard notice) when a live-only command runs in demo."""

        if self._controller.is_demo:
            self.notify("Not available in demo mode.", title=f"/{name}")
            return True
        return False

    # -- commands --------------------------------------------------------
    def _cmd_help(self, argument: str = "") -> None:
        """/help renders the line CLI's own command menu into the conversation."""

        from forensic_agent.cli.commands import UnknownCommandError
        from forensic_agent.cli.terminal import build_help_renderable

        try:
            self.push_screen(
                OverlayScreen(
                    "Commands",
                    build_help_renderable(argument or None, palette=M.palette()),
                    # One command's block is a paragraph; the whole sheet is a
                    # reference table and is given the window to be one.
                    wide=not argument,
                )
            )
        except UnknownCommandError:
            # A mistyped name deserves the truth, not the generic sheet.
            self.notify(f"Unknown command: /{argument.strip()}", title="/help")
        except Exception:
            self.action_help()

    def _cmd_quit(self, _argument: str = "") -> None:
        self.exit()

    def _cmd_clear(self, argument: str = "") -> None:
        # "all" is the only thing /clear accepts, so anything else is refused by
        # name rather than quietly treated as a bare /clear — an operator who
        # typed "/clear evidence" was shown a cleared screen and left believing
        # the evidence had gone with it.
        wanted = argument.strip().lower()
        if wanted and wanted != "all":
            self._unrecognised("clear", argument.strip(), ("all",))
            return
        # action_clear is async (it must await the unmounts); from a sync
        # dispatcher it runs as a worker so the coroutine actually executes.
        # Passed as a callable, not as an already-created coroutine: an
        # exclusive worker cancels the one before it, and a cancelled worker
        # never awaits the coroutine it was handed, which Python then reports as
        # "coroutine was never awaited". A callable is only called once the
        # worker actually starts.
        # Exclusive: two clears interleaving their remove/welcome halves mint
        # two #banner widgets and crash the console with DuplicateIds.
        # "/clear all" additionally drops the Session panel, as documented.
        self.run_worker(
            # cast: run_worker's overloads infer the callable form's result as
            # Never, so a perfectly valid ``() -> Coroutine[None]`` does not
            # match any of them. The call is correct; only the signature cannot
            # express it.
            cast(Any, partial(self.action_clear, with_status=wanted != "all")),
            exclusive=True,
            group="clear",
        )

    def _cmd_status(self, _argument: str = "") -> None:
        # The overlay is already a titled frame; the panel's own frame inside
        # it would draw a "Session" box around a "› Session" box.
        self._status = self._controller.status()
        self.push_screen(OverlayScreen("Session", self._status_renderable()))

    def _status_renderable(self) -> Group:
        """What /status answers: the standing frame, then this session's own run.

        The standing frame is the Session panel's rows, and on its own that is
        all /status ever said — which made it a second copy of a panel already
        on screen, opened by a command whose whole purpose is to tell the
        operator something. What the panel cannot carry is what has HAPPENED
        since it was drawn, because the panel is standing state and gets redrawn
        in place rather than accumulating. That is the second section.

        Every row below comes from something the console already holds. A figure
        nobody records is not estimated here; it is left out, which is why there
        is no row for whether the entity index was built (the outcome is
        announced when the case opens and then discarded) and none for budget
        spent beyond the last run's own counts.
        """

        return Group(
            self._session_grid(),
            Text(""),
            _section_heading("this session"),
            _section_body(self._session_history_grid()),
        )

    def _session_history_grid(self) -> Table:
        """The rows /status adds, each read off state the console really keeps."""

        grid = Table.grid(padding=(0, 2))
        grid.add_column(justify="right", no_wrap=True)
        grid.add_column(overflow="fold", ratio=1)
        grid.add_column(justify="right", no_wrap=True)

        def row(label: str, value: Text, command: str = "") -> None:
            # The label goes through the language layer; the value does not,
            # unless the caller translated it. A value here is usually an
            # identifier -- a model id, a case label, a theme name, a trace id
            # -- and an identifier that changes with the interface language is
            # one the operator can no longer type back in.
            grid.add_row(
                Text(_t(label), style=M.DIM_BRIGHT), value, Text(command, style=M.DIM)
            )

        # No build row. Which binary is running is a question about the
        # installation, not about this session, and /doctor is where the
        # installation answers for itself.
        row("version", Text(_version_label() or _t("unknown"), style=M.DIM_BRIGHT))
        row("theme", Text(M.active_palette_name(), style=M.TEXT), "/theme")
        try:
            from forensic_agent.cli import i18n

            code = i18n.current_language()
            row(
                "language",
                Text(f"{i18n.language_display_name(code)} ({code})", style=M.TEXT),
                "/language",
            )
        except Exception:
            pass
        # Exchanges: the console's own count of messages it has numbered. A
        # discarded exchange gives its number back, so this is messages that
        # produced an answer and not messages typed.
        row(
            "messages",
            Text(str(self._exchange), style=M.TEXT if self._exchange else M.DIM_BRIGHT),
            "/history",
        )
        # Findings, from the two lists the review queue actually keeps: the
        # cards accepted into the EVIDENCE pane, and the ones still queued.
        accepted, waiting = len(self._evidence_cards), len(self._pending_review)
        findings = Text()
        findings.append(
            f"{accepted} {_t('accepted')}",
            style=M.SUCCESS if accepted else M.DIM_BRIGHT,
        )
        findings.append(", ", style=M.DIM)
        findings.append(
            f"{waiting} {_t('awaiting review')}",
            style=M.ORANGE if waiting else M.DIM_BRIGHT,
        )
        row("findings", findings, "/findings")
        # The last run's own accounting, exactly as the ControlCard recorded it.
        last = self._last_result
        if last is not None:
            counts = Text()
            counts.append(
                f"{last.controls.tool_calls} {_t('tool calls')}", style=M.TEXT
            )
            requests = last.controls.model_requests
            if requests is not None:
                counts.append(f", {requests} {_t('model requests')}", style=M.TEXT)
            counts.append(
                f", {format_duration(last.controls.elapsed_s)}", style=M.DIM
            )
            row("last message", counts)
            if last.controls.trace_id:
                row("trace", Text(last.controls.trace_id, style=M.DIM_BRIGHT))
        # No "run record" row. It named a directory the operator could not
        # open — inside the container it rendered as "/runtime (inside the
        # container)", which is a path plus an apology for the path — and
        # /export already reports where it wrote, in words, at the moment it
        # writes. A location nobody can visit is not a fact worth a row.
        return grid

    #: The budgets /budget sets, as argument name → session setter. Every one
    #: of them is a ceiling that ends a run when it is reached; the reasoning
    #: level is not one of them and lives under /reasoning.
    _BUDGET_LIMITS: ClassVar[dict[str, str]] = {
        "time": "change_time",
        "steps": "change_steps",
        "toolcalls": "change_tool_calls",
    }

    _BUDGET_USAGE = "Usage: /budget [time S|steps N|toolcalls N]"

    def _cmd_reasoning(self, argument: str = "") -> None:
        """How much reasoning the model spends on one request, and nothing else.

        Split back out of /effort, which had merged it with the budgets on the
        reading that both governed how much work a message may spend. The
        levels here change how the model thinks and travel to the provider
        with every request; the budgets are ceilings this console places on a
        run and end it when they are reached. The environment variable
        DFA_REASONING_EFFORT is untouched by the rename — only the command is
        this console's to name.
        """

        from forensic_agent.cli.reasoning import REASONING_EFFORTS, normalize_effort

        text = argument.strip()
        if not text:
            self._reasoning_chooser()
            return
        first = text.split(None, 1)[0]
        try:
            # The same spellings the setting itself accepts, so "off" and
            # "none" cannot mean different things in the two places.
            level = normalize_effort(first)
        except ValueError:
            self._unrecognised("reasoning", first, REASONING_EFFORTS)
            return
        self._set_reasoning(level)

    @work
    async def _reasoning_chooser(self) -> None:
        """The four levels, the active one marked and under the cursor.

        The same shape as every other fixed-set chooser in this console, and
        the same one the merged screen used for its reasoning row.
        """

        from forensic_agent.cli.reasoning import REASONING_EFFORTS

        if self._demo_blocked("reasoning"):
            return
        status = self._controller.status()
        options = list(REASONING_EFFORTS)
        marked = [
            option + ("   ● active" if option == status.reasoning_effort else "")
            for option in options
        ]
        initial = (
            options.index(status.reasoning_effort)
            if status.reasoning_effort in options
            else 0
        )
        pick = await self.push_screen_wait(
            ChoiceScreen("reasoning for the next message", marked, initial=initial)
        )
        if pick is None:
            return
        self._set_reasoning(options[pick])

    def _cmd_budget(self, argument: str = "") -> None:
        """The resources one message may spend: its clock, its steps, its calls.

        Three ceilings and one command, because reaching any of them ends the
        run the same way — with no finding. The clock is the one that had no
        console control at all until now: a run that stopped on
        budget_exhausted:max_wall_time_s could only be given more time by
        relaunching, which is exactly the case the operator is least able to
        wait for.
        """

        text = argument.strip()
        if not text:
            self.push_screen(BudgetScreen())
            return
        parts = text.split(None, 1)
        target = parts[0].casefold()
        value = parts[1].strip() if len(parts) == 2 else ""
        if target not in self._BUDGET_LIMITS:
            self._unrecognised(
                "budget", parts[0], ("time S", "steps N", "toolcalls N")
            )
            return
        if not value:
            self.push_screen(BudgetScreen())
            return
        self._set_limit(self._BUDGET_LIMITS[target], target, value)

    def _set_limit(self, method: str, label: str, argument: str) -> None:
        if self._controller.is_demo:
            self.notify("Not available in demo mode.", title="/budget")
            return
        if self.running:
            self.notify(
                "A message is being investigated. Ctrl+C cancels it first.",
                title="/budget",
                severity="warning",
            )
            return
        # Refused here rather than passed on: zero and negative numbers are
        # the shapes an operator reaches for when they mean "no limit", and a
        # budget of zero is a run that cannot take its first step. isdigit()
        # alone let "0" through to the session, which refused it in the
        # transcript the console does not show for this command.
        cleaned = argument.strip()
        if not cleaned.isdigit() or int(cleaned) < 1:
            self.notify(self._BUDGET_USAGE, title="/budget")
            return
        # The session's own setter validates, saves the new default, and drops
        # the cached runner: a limit set on the attribute alone would leave
        # the next message running under the old one.
        with self._recording() as recorder:
            try:
                getattr(self._controller.session, method)(cleaned)
            except Exception as exc:
                self.notify(str(exc)[:240], severity="error", title="/budget")
                return
        self._refresh_session_panel()
        note = " ".join(recorder.export_text(styles=False).split())
        self.notify(note[:240] or f"{label} budget updated.", title="/budget")

    def _cmd_new(self, argument: str = "") -> None:
        """Start a fresh investigation history, and clear what belonged to the
        old one off the screen with it.

        ``/new`` used to change the session and leave the screen alone, so the
        operator went on reading six exchanges, their tool calls and their
        guardrail decisions while the agent answered the next question from
        nothing. A display that outlives the state that produced it is not a
        record of anything.

        The teardown is ``/complete``'s, not a second copy of it: the same
        :meth:`_reset_instruments` and the same :meth:`action_clear`, minus
        detaching the evidence and minus writing the closing artifacts, which
        is exactly what ``/new`` is as against ``/complete``. The one argument
        between them is whether the findings go, and that is the argument the
        method takes.
        """

        if self._demo_blocked("new"):
            return
        try:
            with self._recording() as recorder:
                self._controller.session.new_conversation(argument.strip() or None)
        except Exception as exc:
            self.notify(str(exc)[:240], severity="error", title="/new")
            return
        # The engine names the new session's id; the toast carries it.
        note = " ".join(recorder.export_text(styles=False).split())
        self.notify(
            note[:240] or "A new investigation history was started.",
            title="/new",
        )
        self._start_new_history()

    @work(group="newhistory")
    async def _start_new_history(self) -> None:
        # The message number keeps counting even though the history restarts.
        # The findings that survive are filed under the numbers they were found
        # at — the EVIDENCE pane groups them by exactly that — so restarting at
        # 01 would put a new exchange's evidence into a group already called 01
        # and holding somebody else's finding. A number that is unique across
        # the console's life is worth more here than one that agrees with the
        # new history's turn count.
        waiting = len(self._pending_review)
        accepted = len(self._evidence_cards)
        await self._reset_instruments(keep_findings=True)
        # say_pending=False: the note below already accounts for the findings
        # that survived, and two lines saying it would read as two facts.
        await self.action_clear(say_pending=False)
        self._say(partial(self._new_history_note, waiting, accepted))
        self._end_exchange()
        self.query_one("#prompt", Input).focus()

    def _new_history_note(self, waiting: int, accepted: int) -> Text:
        """What ``/new`` did, said on the screen it just emptied.

        A list that silently changes length teaches an operator not to trust
        it, so the two things that did NOT go are named here rather than left
        to be inferred: the case is still open, and the findings — accepted or
        still waiting — are still there, because accepting a finding is a
        statement about the evidence and ``/new`` keeps the evidence.
        """

        note = Text()
        note.append(f"{M.GLYPH_OK} New investigation history — ", style=M.SUCCESS)
        note.append(
            "the previous questions, their tool calls and their guardrail "
            "decisions were cleared; the case and its evidence stay open",
            style=M.TEXT,
        )
        kept: list[str] = []
        if accepted:
            kept.append(f"{accepted} accepted as evidence")
        if waiting:
            kept.append(f"{waiting} still awaiting review (v)")
        if kept:
            note.append(f"\n   Findings kept: {', '.join(kept)}.", style=M.TEXT)
        return note

    def _cmd_undo(self, _argument: str = "") -> None:
        if self._demo_blocked("undo"):
            return
        try:
            with self._recording() as recorder:
                self._controller.session.undo_context()
            note = " ".join(recorder.export_text(styles=False).split())
            self.notify(note[:240] or "The last answer left the model's context.", title="/undo")
        except Exception as exc:
            self.notify(str(exc)[:240], severity="error", title="/undo")

    def _cmd_export(self, argument: str = "") -> None:
        """/export writes the case report and leaves the case exactly as it was.

        Unlike /complete it asks nothing, detaches nothing and declares
        nothing — the session's own writer runs through the read-only
        overlay, which shows the paths it reports.
        """

        if self._controller.is_demo:
            self.notify(
                "The demo replays a recorded case; a report is written from a "
                "live one.",
                title="/export",
            )
            return
        self._cli_overlay("/export", "export_report", _unquote(argument) or None)

    def _cmd_complete(self, argument: str = "") -> None:
        if self._demo_blocked("complete"):
            return
        session = self._controller.session
        # The same three preconditions complete_case itself states — the two
        # guards must agree, or the worker runs its follow-up steps on a no-op.
        if (
            getattr(session, "last_run", None) is None
            or not getattr(session, "last_report", None)
            or not getattr(session, "last_q", None)
        ):
            self.notify(
                "Nothing to complete yet. No investigation has been run in "
                "this case.",
                title="/complete",
            )
            return
        self._complete_flow(_unquote(argument))

    @work
    async def _complete_flow(self, path: str) -> None:
        """Completing is the operator's declaration, and it ends the case.

        Confirmed first; then every artifact is written — the full case
        report, the completion bundle — and the evidence is detached.

        ``/complete [path]`` has always taken a destination, and the
        confirmation never offered one, so the only way to file a closed case
        somewhere of your own choosing was to know the argument existed. It is
        the middle option now, which costs the operator who wants the default
        nothing: the confirming answer is still the first row, still under the
        cursor, still one Enter.
        """

        session = self._controller.session
        if getattr(session, "completion_declaration_path", None) is not None:
            index = await self.push_screen_wait(
                ChoiceScreen(
                    "this case was already completed — overwrite its declaration?",
                    ["yes — complete it again", "no, keep the recorded completion"],
                )
            )
            if index != 0:
                return
        index = await self.push_screen_wait(
            ChoiceScreen(
                "complete the case — write every artifact and close it?",
                [
                    "yes — complete and close the case",
                    "choose where the artifacts are filed",
                    "not yet",
                ],
            )
        )
        if index == 1:
            chosen = await self._completion_destination(path)
            if chosen is None:
                return
            path = chosen
        elif index != 0:
            return
        self._complete_worker(path)

    def _completion_default(self, path: str):
        """The destination bare /complete would use, as a Path.

        Asked of the same resolver the session itself uses, so the folder and
        the name offered are the ones that would have been written anyway and
        the operator is editing the real default rather than a guess at it.
        """

        from pathlib import Path

        session = self._controller.session
        try:
            from forensic_agent.cli.case_completion import completion_destination

            return completion_destination(
                path or None,
                str(getattr(getattr(session, "last_run", None), "run_id", "") or "run"),
                run_root=Path(getattr(session, "run_root", ".")),
            )
        except Exception:
            # The resolver refuses a destination outside the container's own
            # runtime, and it is the only thing that knows the rule; a default
            # it will not resolve is still worth showing so the operator can
            # correct it, and the worker refuses it again if they do not.
            return Path(path or "case_completion.md")

    async def _completion_destination(self, path: str) -> str | None:
        """The folder and the base name the three artifacts share, or ``None``.

        One name for all three: the report, the diagram and the declaration
        differ only in their extension, and asking three times for one filing
        decision is how an operator ends up with a bundle split across two
        directories. Nothing is overwritten without being told: an existing
        file of that name is named, and the operator picks another or says
        plainly that overwriting is what they meant.
        """

        from pathlib import Path

        default = self._completion_default(path)
        folder = await self.push_screen_wait(
            PromptScreen(
                "where the completed case is filed",
                hint="The folder the report, the diagram and the declaration go into.",
                value=str(default.parent),
            )
        )
        if folder is None:
            return None
        directory = Path(folder.strip() or str(default.parent)).expanduser()
        name = default.stem
        while True:
            typed = await self.push_screen_wait(
                PromptScreen(
                    "the name the three files share",
                    hint=".md, .svg and .json are added to it.",
                    value=name,
                )
            )
            if typed is None:
                return None
            name = typed.strip() or default.stem
            stem = directory / Path(name).name
            existing = [
                stem.with_suffix(suffix)
                for suffix in (".md", ".svg", ".json")
                if stem.with_suffix(suffix).exists()
            ]
            if not existing:
                return str(stem.with_suffix(".md"))
            listed = ", ".join(found.name for found in existing)
            index = await self.push_screen_wait(
                ChoiceScreen(
                    f"{listed} already exists there",
                    [
                        "pick another name",
                        "overwrite it",
                        "cancel — complete nothing",
                    ],
                )
            )
            if index == 1:
                return str(stem.with_suffix(".md"))
            if index != 0:
                return None

    @work(thread=True, exclusive=True, group="caseop")
    def _complete_worker(self, path: str) -> None:
        """Write every artifact, step by step, then detach — and if a step
        fails, still show what WAS written rather than discarding the
        inventory of a half-closed case."""

        session = self._controller.session
        failed_step = ""
        self._case_op_alive = True
        try:
            with self._recording() as recorder:
                completed = False
                try:
                    completed = bool(session.complete_case(path or None))
                except Exception as exc:
                    failed_step = f"completion bundle: {str(exc)[:200]}"
                if not completed and not failed_step:
                    # Nothing was attempted (the engine said so); exporting
                    # and detaching after a no-op would announce a closed
                    # case that never closed.
                    failed_step = "nothing to complete. No investigation has run"
                # complete_case does the whole job: the case report covering
                # EVERY exchange, its oversight companion, the page a browser
                # opens, the investigation diagram and the declaration, all on
                # one stem. Exporting again here is what produced two more
                # files under a second stem, one of them a report of the last
                # exchange alone wearing the name of the case report.
                if not failed_step:
                    session.clear_evidence()
                    # clear_evidence detaches sources but leaves the closed
                    # case's name on the session; the frame must not keep
                    # showing a case that no longer exists.
                    session.case_label = "none"
                    session.case_id = "interactive-unbound"
        finally:
            self._case_op_alive = False
        rendered = Text.from_ansi(recorder.export_text(styles=True))
        self.call_from_thread(self._completed, rendered, failed_step)

    def _completed(self, rendered: Text, failed_step: str) -> None:
        self._refresh_session_panel()
        if failed_step:
            # The case is still open and its transcript is still the record of
            # a live investigation; nothing is cleared away from under it.
            if rendered.plain.strip():
                self.push_screen(OverlayScreen("Completion did not finish", rendered))
            self.notify(failed_step[:240], severity="error", title="/complete")
            self._say(partial(self._completion_note, failed_step))
            self._say(Text(""))
            return
        self._completion_receipt(rendered)

    @work(group="completion")
    async def _completion_receipt(self, rendered: Text) -> None:
        """Show what was written, wait for it to be read, then start over.

        A completed case is finished: the evidence is detached, and the console
        that goes on showing its conversation is showing a case that no longer
        exists. So the closing artifacts are ACKNOWLEDGED rather than kept — the
        inventory of what was written is a modal the operator dismisses, and the
        clear happens only after they have. The alternative, letting the paths
        survive the clear, would leave a receipt for a closed case sitting above
        the opening screen of the next one, which is the same defect /status had.

        Nothing on disk is touched. The run record, the report, the diagram and
        the declaration are all still where the overlay said they were, and
        /status names the directory holding them.
        """

        if rendered.plain.strip():
            await self.push_screen_wait(OverlayScreen("Case completed", rendered))
        await self._reset_instruments()
        # The startup path itself, not a second copy of it: the same clear, the
        # same welcome, the same Session panel — which now reads "open evidence
        # /case <folder-or-file>", because that is the true state.
        await self.action_clear()
        self._say(partial(self._completion_note, ""))
        self._say(Text(""))
        self.query_one("#prompt", Input).focus()

    async def _reset_instruments(self, *, keep_findings: bool = False) -> None:
        """Empty the instrument panes back to their opening hints.

        The conversation is not the only thing carrying a history. The
        ACTIVITY feed, the accepted EVIDENCE and the GUARDRAILS decisions all
        belong to it, and leaving them mounted would put one case's evidence
        beside the next case's questions — which in a forensic console is worse
        than an untidy screen.

        ``keep_findings`` is what separates the two callers. ``/complete``
        closes the case and detaches its evidence, so every finding about that
        evidence goes with it. ``/new`` keeps the case and its evidence and
        discards only the conversation, and a finding is a statement about the
        evidence rather than about the conversation that happened to surface
        it — so the accepted EVIDENCE and the findings still awaiting review
        survive, and the note ``/new`` writes says how many are still waiting.

        The message number is deliberately NOT reset by either: the session's
        own history keeps counting, and renumbering here would make the console
        disagree with the record about which message was which.
        """

        panes = ("#activity", "#guardrails-pane") + (
            () if keep_findings else ("#evidence-pane",)
        )
        for pane_id in panes:
            for pane in self.query(pane_id).results(VerticalScroll):
                await pane.remove_children()
        for pane_id in panes:
            for pane in self.query(pane_id).results(VerticalScroll):
                pane.border_subtitle = ""
        self._activity_rows.clear()
        self._activity_log.clear()
        # The transcript these described has just been emptied, so the record
        # of what each exchange did goes with it; keeping it would let a later
        # layout switch mount a block for an exchange no longer on screen.
        self._exchange_record.clear()
        self._exchange_end.clear()
        self._inline_exchanges.clear()
        self._guardrail_groups.clear()
        self._guardrail_blocks.clear()
        self._guardrail_allowed_total = 0
        self._guardrail_checked_total = 0
        self._guardrail_refusals.clear()
        self._guardrail_guessed.clear()
        self._guardrail_guessed_calls = 0
        self._guardrail_caps.clear()
        self._last_result = None
        if not keep_findings:
            self._evidence_cards.clear()
            self._evidence_lists.clear()
            self._pending_review.clear()
            self._review_stats.clear()
            self._marked.clear()
            self._evidence_last_group = 0
        self._rest_panes()

    def _completion_note(self, failed_step: str) -> Text:
        note = Text()
        if failed_step:
            note.append(f"{M.GLYPH_ERROR} Completion stopped — ", style=M.RED)
            note.append(failed_step, style=M.ORANGE)
            note.append(
                "  the evidence stays attached; the popup lists what was written",
                style=M.DIM_BRIGHT,
            )
        else:
            note.append(f"{M.GLYPH_OK} Case completed and closed — ", style=M.SUCCESS)
            note.append(
                "the evidence was detached; /case opens the next one",
                style=M.DIM_BRIGHT,
            )
        return note

    #: What each layout is, in one line, for the chooser and the Session panel.
    LAYOUTS: ClassVar[tuple[tuple[str, str], ...]] = (
        ("full", "the conversation with the instrument panes beside it"),
        ("simple", "one column; each answer carries its own tool activity"),
    )

    def _cmd_layout(self, argument: str = "") -> None:
        """One column when reading matters, the full instruments otherwise.

        A bare /layout opens the chooser rather than toggling: two layouts
        that swap on an unnamed command are a switch with no label, and an
        operator who has never seen the other one has no way to find out
        what it is. Named directly (/layout simple) it still switches at once.
        """

        choice = argument.strip().lower()
        names = tuple(name for name, _what in self.LAYOUTS)
        if choice and choice not in names:
            self._unrecognised("layout", argument.strip(), names)
            return
        if not choice:
            self._layout_chooser()
            return
        self._set_layout(choice)

    @work
    async def _layout_chooser(self) -> None:
        """Both layouts by name, each with what it is for, and the active one
        marked and under the cursor — the same shape as the reasoning chooser."""

        names = tuple(name for name, _what in self.LAYOUTS)
        options = [
            f"{name}{'   ● active' if name == self._layout else ''} — {what}"
            for name, what in self.LAYOUTS
        ]
        initial = names.index(self._layout) if self._layout in names else 0
        pick = await self.push_screen_wait(
            ChoiceScreen("layout", options, initial=initial)
        )
        if pick is None:
            return
        self._set_layout(self.LAYOUTS[pick][0])

    def _set_layout(self, choice: str) -> None:
        """Move to one layout and leave exactly that layout's surfaces mounted.

        Switching is idempotent in both directions: whichever layout takes
        over, the other one's inline activity blocks are taken out of the
        conversation first. Without that they accumulated there, so the same
        calls were rendered twice — once inline and once in the ACTIVITY pane
        — with the inline copy drawing over whatever the pane was showing.
        """

        simple = choice == "simple"
        already = choice == self._layout
        self._layout = choice
        self.query_one("#rightcol").styles.display = "none" if simple else "block"
        if simple:
            self._restore_inline_activity()
        else:
            self._clear_inline_activity()
        if already:
            self.notify(f"The {choice} layout is already active.", title="/layout")
            return
        self.notify(
            (
                "Simple layout: each answer carries its activity. "
                "/layout brings the panes back."
                if simple
                else "Full layout: the instrument panes are back."
            ),
            title="/layout",
        )
        self._refresh_session_panel()

    def _clear_inline_activity(self) -> None:
        """Take the simple layout's activity blocks out of the conversation."""

        self._inline_exchanges.clear()
        for widget in self.query(f".{_INLINE_ACTIVITY_CLASS}"):
            widget.remove()

    def _show_inline_activity(self, exchange: int) -> None:
        """Write one finished exchange's calls under its own answer.

        Mounted before that exchange's separator rather than at the end of the
        conversation, so a block added by a layout switch lands where the block
        written live would have: under the answer it belongs to, inside its own
        exchange. An exchange that already has one is left alone, which is what
        makes switching back and forth cost nothing after the first time.
        """

        if self._layout != "simple" or exchange in self._inline_exchanges:
            return
        record = self._exchange_record.get(exchange)
        if record is None:
            return
        result, events = record
        if not (result.oversight or events):
            return
        pane = self.query_one("#conversation", VerticalScroll)
        anchor = self._exchange_end.get(exchange)
        if exchange in self._exchange_end and (
            anchor is None or anchor.parent is None
        ):
            # The exchange ended and its separator has since been removed —
            # discarded, or cleared away. There is nothing left for its
            # activity to sit under, and appending it would put an old
            # exchange's calls at the bottom of a newer one.
            return
        # Marked as the simple layout's own surface. The full layout has the
        # ACTIVITY pane for this, and the two must never be on screen at once,
        # so the class is what the layout teardown removes them by. No id:
        # removal is deferred, and a re-mount racing a pending removal of the
        # same id crashes the console with DuplicateIds.
        widget = _painted(
            partial(self._inline_activity, result, events),
            classes=_INLINE_ACTIVITY_CLASS,
        )
        if anchor is None:
            # The exchange is still being written: the end of the conversation
            # IS the end of this exchange, so appending puts the block exactly
            # where mounting in front of the separator will put it a moment
            # later. Both paths therefore leave it in the same place.
            pane.mount(widget)
        else:
            pane.mount(widget, before=anchor)
        self._inline_exchanges.add(exchange)

    def _restore_inline_activity(self) -> None:
        """Give the simple layout every exchange, not only the ones since the switch.

        The inline block used to be written at the moment an exchange finished
        and only when the simple layout was already active, so switching to it
        showed the activity of exchanges that had not happened yet and nothing
        of the ones the operator had actually run. Nothing was lost from the
        record — only from the screen — so the switch rebuilds them.

        Done on the switch and never per frame; the blocks that exist already
        are skipped, so toggling twice costs one mount each way.
        """

        for exchange in sorted(self._exchange_record):
            self._show_inline_activity(exchange)

    def _inline_activity(
        self, result: InvestigationResult, events: tuple[ToolEvent, ...]
    ):
        """The simple view's record: the run's calls printed under the answer.

        Built from the same settled facts the ACTIVITY pane holds — the
        oversight outcomes and the feed's own rows — so the two views can
        never tell two different stories about one run.
        """

        scopes = _recorded_scopes(result)
        reasons = _recorded_reasons(result)
        # The recorder numbers actions on its own chain (2, 7, 12…) while
        # the feed counts arrivals (1, 2, 3…): the nth settled card
        # describes the nth emitted call, so the two are paired by ORDER —
        # refined by argument overlap, because concurrent identical-shaped
        # calls can settle in a different order than they were recorded.
        # Looking events up by card.sequence garbled multi-call runs —
        # first calls vanished and later ones appeared twice.
        cards = _pair_cards_to_events(
            list(events), sorted(result.oversight, key=lambda entry: entry.sequence)
        )
        rows: list = [Rule("activity", style=M.BORDER, align="left")]
        if events and len(events) == len(cards):
            for event, card in zip(events, cards, strict=True):
                rows.append(
                    _activity_row(
                        event,
                        status=card.outcome,
                        scope=scopes.get(card.sequence, ""),
                        arguments=card.arguments,
                        reason=_row_reason(card, reasons),
                    )
                )
        elif events:
            # Counts disagree: show the feed exactly as it arrived rather
            # than guess a pairing — its statuses are already settled.
            rows.extend(_activity_row(event) for event in events)
        else:
            for card in cards:
                event = ToolEvent(
                    card.sequence,
                    card.function,
                    card.operation,
                    "  ".join(f"{name}={value}" for name, value in card.arguments),
                    card.outcome,
                    card.duration_s,
                )
                rows.append(
                    _activity_row(
                        event,
                        status=card.outcome,
                        scope=scopes.get(card.sequence, ""),
                        arguments=card.arguments,
                        reason=_row_reason(card, reasons),
                    )
                )
        return Group(*rows)

    def _set_reasoning(self, level: str) -> None:
        if self._demo_blocked("reasoning"):
            return
        if self.running:
            self.notify(
                "A message is being investigated. Ctrl+C cancels it first.",
                title="/reasoning",
                severity="warning",
            )
            return
        with self._recording() as recorder:
            try:
                self._controller.session.change_reasoning(level)
            except Exception as exc:
                self.notify(str(exc)[:240], severity="error", title="/reasoning")
                return
        self._refresh_session_panel()
        note = " ".join(recorder.export_text(styles=False).split())
        self.notify(note[:240] or "Reasoning updated.", title="/reasoning")

    def _cmd_findings(self, argument: str = "") -> None:
        # A bare /findings is the standardized findings list of the last run,
        # not the EVIDENCE pane: the pane holds accepted findings only, and is
        # empty right after a run. The e key still opens that pane.
        if self._controller.is_demo:
            self.action_evidence()
            return
        self._cli_overlay(
            "/findings", "show_findings", argument.strip() or None, live_safe=True
        )

    def _cmd_oversight(self, argument: str = "") -> None:
        # One concept, one surface, one name: /oversight (with /guardrails as
        # the pane's own word) IS the g-key view. The argument forms open
        # the deeper record behind that same surface.
        text = argument.strip()
        if not text or self._controller.is_demo:
            self.action_guardrails()
            return
        if text.casefold() == "calls":
            self._cli_overlay(
                "Oversight — executed calls",
                "show_executed_commands",
                live_safe=True,
            )
        elif text.casefold() == "prompt":
            self._cli_overlay(
                "Oversight — the message the model received",
                "show_oversight_prompt",
                live_safe=True,
            )
        elif text.isdigit():
            self._cli_overlay(
                f"Oversight — call {text}", "show_oversight_call", text, live_safe=True
            )
        else:
            # Not a fixed set on its own: "calls" and "prompt" are, but a call
            # number is not, so there is nothing to put in a chooser and the
            # refusal names both shapes.
            self._unrecognised(
                "oversight", text, ("calls", "prompt", "a call number")
            )

    def _cmd_tools(self, argument: str = "") -> None:
        if self._controller.is_demo:
            self.notify("The demo replays a fixed tool script.", title="/tools")
            return
        self._cli_overlay(
            "Tools", "show_tools", argument.strip() or None, live_safe=True
        )

    def _cmd_sources(self, _argument: str = "") -> None:
        # No argument: /sources says what is attached and nothing else, which
        # is what its usage line declares.
        self._show_sources_overlay()

    def _cmd_case(self, argument: str = "") -> None:
        if self._controller.is_demo:
            self.notify(
                "The demo replays a recorded case; run without --demo to open "
                "real evidence.",
                title="/case",
            )
            return
        if not argument:
            self._case_browse_flow()
            return
        parts = argument.split(None, 1)
        kinds = ("disk", "memory", "network")
        if parts[0].lower() in kinds and len(parts) == 2:
            self._case_worker("typed", parts[0].lower(), _unquote(parts[1]))
        else:
            self._case_worker("open", "", _unquote(argument))

    def _browse_root(self) -> str:
        """Where the path field starts: a folder of the OPERATOR'S, or nothing.

        Never a container path. ``/evidence`` is a mount point that exists only
        inside this process's file system, and offering it as the starting
        point of a field that asks for a path from the operator's computer was
        the defect: it looked like an answer, and every folder reachable from
        it was the wrong one.

        The last folder they opened is the best guess, then the host directory
        the launcher says it mounted, then — outside a container, where the
        console is looking at the operator's own disk — their home. When none
        of those holds, the field is empty, which is honest: the console does
        not know where this operator keeps their evidence.
        """

        import os as _os

        from forensic_agent.cli.host_display import containerized, host_evidence_root

        remembered = self._remembered_case_directory()
        if remembered:
            return remembered
        if containerized():
            return host_evidence_root()
        home = _os.path.expanduser("~")
        return home if _os.path.isdir(home) else ""

    def _remembered_case_directory(self) -> str:
        """The host folder this console last opened a case from, if any.

        Kept in the console's own preferences file, beside the theme and the
        language: it is a fact about this operator's habits and nothing about
        the evidence, and it must survive the container being replaced or the
        preference would be lost on the very relaunch the handoff performs.
        A store that cannot be read (or written) costs the convenience and
        nothing else, so every failure here falls back to the session value.
        """

        remembered = getattr(self, "_last_case_directory", "")
        if remembered:
            return str(remembered)
        try:
            from forensic_agent.cli.preferences import read_preference

            return read_preference(_LAST_CASE_DIRECTORY_KEY) or ""
        except Exception:
            return ""

    def _remember_case_directory(self, path: str) -> None:
        """Record the folder a case was opened from, for the next /case."""

        import os as _os

        directory = path.strip().rstrip("/\\")
        if not directory:
            return
        if _container_view_of(directory) is None and not _os.path.isdir(directory):
            # A file was picked, or a folder handed to the launcher: the
            # folder that holds it is what the operator will look in next.
            separator = "\\" if "\\" in directory else "/"
            head = directory.rsplit(separator, 1)[0]
            directory = head or directory
        self._last_case_directory = directory
        try:
            from forensic_agent.cli.preferences import save_preference

            save_preference(_LAST_CASE_DIRECTORY_KEY, directory)
        except Exception:
            # A read-only preferences directory is a deployment fact, not an
            # error the operator opening a case should be shown.
            return

    @work
    async def _case_browse_flow(self) -> None:
        """/case with nothing typed: name the case folder and pick from it.

        Whatever the folder holds is exactly what ``open_case`` discovery
        would find for a typed path — including the multi-source selection.
        """

        path = await self.push_screen_wait(
            FileBrowserScreen(
                "open a case — name the folder on your computer",
                root=self._browse_root(),
                pick="folder",
            )
        )
        if path is None:
            return
        self._remember_case_directory(path)
        self._case_worker("open", "", path)

    def _cmd_attach(self, argument: str = "") -> None:
        if self._demo_blocked("attach"):
            return
        parts = argument.split(None, 1)
        kinds = ("disk", "memory", "network")
        if len(parts) == 2 and parts[0].lower() in kinds:
            self._case_worker("attach", parts[0].lower(), _unquote(parts[1]))
            return
        if argument.strip():
            self.notify("Usage: /attach <disk|memory|network> <path>", title="/attach")
            return
        self._attach_browse_flow()

    @work
    async def _attach_browse_flow(self) -> None:
        """/attach with nothing typed: say what it is, then pick the file."""

        kinds = ("disk", "memory", "network")
        index = await self.push_screen_wait(
            ChoiceScreen(
                "attach evidence — what kind?",
                ["a disk image", "a memory dump", "a network capture"],
            )
        )
        if index is None:
            return
        path = await self.push_screen_wait(
            FileBrowserScreen(
                f"attach a {kinds[index]} — pick the file",
                root=self._browse_root(),
                pick="file",
            )
        )
        if path is None:
            return
        self._remember_case_directory(path)
        self._case_worker("attach", kinds[index], path)

    def _cmd_verify(self, _argument: str = "") -> None:
        """/verify: read the whole medium again, on the operator's say-so.

        The size is established here, before anything is offered, because the
        confirmation has nothing to say without it. A prompt that asks whether
        to stream the evidence and cannot say how much evidence there is asks
        the operator to agree to an unknown wait.
        """

        if self._demo_blocked("verify"):
            return
        medium = self._controller.session.verifiable_medium()
        if medium is None:
            self.notify(
                "No disk image is open. /verify reads the medium the active "
                "case was opened from.",
                title="/verify",
            )
            return
        path, size = medium
        self._verify_flow(path, size)

    @work
    async def _verify_flow(self, path: str, size: int) -> None:
        """Say what the pass costs, then run it only if the operator says so.

        Confirmed for the same reason /complete is: this is minutes of reading
        that the operator asked for and can decide against once they see what
        it comes to. Cancelling here must leave the medium untouched, which is
        why the confirmation is awaited before the worker is started at all
        rather than inside it.
        """

        import os as _os

        from rich.filesize import decimal as _decimal

        name = _os.path.basename(path) or path
        measured = _decimal(size) if size else "an unstated size"
        index = await self.push_screen_wait(
            ChoiceScreen(
                f"read all {measured} of {name} again?",
                [
                    "yes, stream the medium and check its digest",
                    "no, leave the evidence unread",
                ],
            )
        )
        if index != 0:
            self.notify(
                "Nothing was read. The evidence was not touched.",
                title="/verify",
            )
            return
        self._verify_worker()

    def _watch_integrity_stream(self, resolved: str):
        """Follow a verification pass, from the thread it is running on.

        The same row, the same spinner, the same measured bar the case open
        paints: :meth:`_begin_case_step` and :meth:`_advance_case_step` are
        the display, and this only feeds them. A second progress display for
        a second long read would be one more thing for an operator to learn
        about a console that is doing the same work it already showed them.

        It is not :meth:`_watch_case_open` because that one renames its step
        when the byte count runs out: an open continues into a dfVFS
        resolution that reports nothing, and a verification does not. Reusing
        it would announce a step that never happens.
        """

        import os as _os
        import time as _time

        name = _os.path.basename(resolved) or resolved
        total: int | None = None
        done = 0
        last = 0.0

        self._from_case_thread(self._begin_case_step, f"Reading {name}")

        def advance(byte_count: int) -> None:
            nonlocal done, last
            done += byte_count
            now = _time.monotonic()
            if now - last < 0.1:
                return
            last = now
            self._from_case_thread(self._advance_case_step, done, total)

        def declare_total(byte_count: int) -> None:
            nonlocal total
            total = byte_count
            self._from_case_thread(
                self._begin_case_step, f"Verifying {name}", byte_count
            )

        return advance, declare_total

    @work(thread=True, exclusive=True, group="caseop")
    def _verify_worker(self) -> None:
        """Stream the medium off the app's thread, painting the row as it goes.

        On the caseop group with the case worker, because both hold the same
        evidence: a verification running beside an open would be two readers
        of one medium and two writers of one progress row.
        """

        session = self._controller.session
        session._integrity_watcher = self._watch_integrity_stream
        self._case_op_alive = True
        failure = ""
        result: dict = {}
        try:
            # The session console is silenced for the length of the pass rather
            # than recorded: the verdict is mounted here from the same
            # renderables the shell prints, so replaying a recording of them
            # would put the verdict on screen twice, once wrapped to a width
            # this pane does not have.
            with self._recording():
                try:
                    result = dict(session.verify_evidence_integrity())
                except Exception as exc:
                    failure = str(exc)[:240]
        finally:
            self._case_op_alive = False
            session._integrity_watcher = None
            self.call_from_thread(self._clear_case_progress)
        self.call_from_thread(self._verified, result, failure)

    def _verified(self, result: dict, failure: str) -> None:
        """Put the verdict where it stays, not in a toast that fades.

        A verification the operator waited minutes for is a finding about the
        evidence, so it is written into the conversation, which is the record
        they scroll back through. A differing digest additionally raises an
        error notification, because that one must not be missed by an operator
        who looked away while it ran.

        The verdict is mounted as the shell's own renderables rather than as a
        recording of them. The recording console is 94 columns wide and this
        pane is narrower, so replayed text arrives already wrapped and wraps a
        second time, which throws away the indent that keeps a supporting line
        reading as one. Mounted, each line lays itself out at this pane's width.
        """

        if failure:
            self.notify(failure, severity="error", title="/verify")
            return
        if not result:
            return
        from forensic_agent.cli.session import integrity_verdict_lines

        for line in integrity_verdict_lines(result):
            self._say(line)
        self._say(Text(""))
        if result.get("error"):
            self.notify(
                "The medium could not be read to the end. Nothing is "
                "established either way.",
                severity="error",
                title="/verify",
                timeout=30,
            )
        elif result.get("matches_recorded"):
            self.notify("The evidence is unchanged.", title="/verify", timeout=10)
        else:
            self.notify(
                "The evidence digest has changed. These are not the bytes "
                "the case was opened over.",
                severity="error",
                title="/verify",
                timeout=30,
            )

    def _cmd_context(self, argument: str = "") -> None:
        if self._demo_blocked("context"):
            return
        session = self._controller.session
        parts = argument.split(None, 1)
        action = (parts[0].lower() if parts else "show")
        value = parts[1] if len(parts) == 2 else ""
        if action not in ("show", "set", "load", "clear") and argument.strip():
            # "/context you are investigating …" means set — requiring the
            # word "set" and failing otherwise would teach the syntax
            # through an error while discarding the operator's text.
            action, value = "set", argument.strip()
        try:
            if action == "show" or not action:
                self._context_flow()
            elif action == "set" and value:
                with self._recording():
                    session.set_case_context(value)
                self._refresh_session_panel()
                self.notify("Case context updated.", title="/context")
            elif action == "load" and value:
                with self._recording():
                    session.load_case_context(_unquote(value))
                self._refresh_session_panel()
                self.notify("Case context loaded.", title="/context")
            elif action == "clear":
                with self._recording():
                    session.clear_case_context()
                self._refresh_session_panel()
                self.notify("Case context cleared.", title="/context")
            else:
                self.notify("Usage: /context [show|set <text>|load <path>|clear]", title="/context")
        except Exception as exc:
            self.notify(str(exc)[:240], severity="error", title="/context")

    def _current_case_context(self) -> str:
        """The brief as the history holds it — the session has no such attribute.

        Reading ``session.case_context`` was how the old bare /context always
        ended in a "No case context" toast: that attribute never existed.
        """

        try:
            conversation = self._controller.session._history.ensure_started()
            return str(getattr(conversation, "case_context", "") or "")
        except Exception:
            return ""

    @work
    async def _context_flow(self) -> None:
        """The case brief on one screen: read it, rewrite it, or clear it."""

        session = self._controller.session
        if not self._controller.has_evidence():
            self.notify(
                "Open a case first. The brief belongs to an investigation.",
                title="/context",
            )
            return
        outcome = await self.push_screen_wait(
            ContextScreen(self._current_case_context())
        )
        if outcome is None:
            return
        action, text = outcome
        try:
            if action == "set":
                with self._recording():
                    session.set_case_context(text)
                self.notify("Case context updated.", title="/context")
            elif action == "clear":
                with self._recording():
                    session.clear_case_context()
                self.notify("Case context cleared.", title="/context")
        except Exception as exc:
            self.notify(str(exc)[:240], severity="error", title="/context")

    # -- console settings, diagnostics, history ---------------------------
    def _unrecognised(self, name: str, value: str, accepted) -> None:
        """One refusal for every fixed-set command: what was not understood.

        Naming only the accepted values leaves the operator comparing their own
        typing against a list to find the difference; naming what was rejected
        makes a typo obvious at a glance. Nothing is changed by this call, which
        is the other half of the rule — a command given an argument it does not
        recognise acts on nothing, and does not fall through to the chooser as
        though the argument had not been typed.
        """

        self.notify(
            f"/{name} does not recognise {value!r}. "
            f"It takes {' or '.join(accepted)}, or nothing at all to choose.",
            title=f"/{name}",
            severity="warning",
            timeout=8,
        )

    def _cmd_language(self, argument: str = "") -> None:
        """Show or switch the console language — a preference, not case state.

        Two languages ship, so this is a fixed set and follows the same rule as
        every other: bare opens the chooser on the language in force, a valid
        code switches at once, and anything else is refused by name. It used to
        demand a typed ``hr`` or ``en`` and answer a bare /language with a toast
        listing them, which is a chooser drawn as a message the operator cannot
        act on.
        """

        from forensic_agent.cli import i18n

        text = argument.strip()
        if not text:
            self._language_chooser()
            return
        try:
            code = i18n.normalize_language(text)
        except ValueError:
            self._unrecognised("language", text, i18n.SUPPORTED_LANGUAGES)
            return
        self._set_language(code)

    @work
    async def _language_chooser(self) -> None:
        """Both languages by name, in their own name, the active one marked."""

        from forensic_agent.cli import i18n

        codes = tuple(i18n.SUPPORTED_LANGUAGES)
        current = i18n.current_language()
        options = [
            f"{code} — {i18n.language_display_name(code)}"
            + ("   ● active" if code == current else "")
            for code in codes
        ]
        initial = codes.index(current) if current in codes else 0
        pick = await self.push_screen_wait(
            ChoiceScreen("terminal language", options, initial=initial)
        )
        if pick is None:
            return
        self._set_language(codes[pick])

    def _set_language(self, code: str) -> None:
        """Switch and persist through the shell's own setter, and say what it said."""

        import io as _io

        from rich.console import Console as _Console

        from forensic_agent.cli import console_settings

        recorder = _Console(
            record=True, width=94, file=_io.StringIO(), force_terminal=True
        )
        try:
            console_settings.change_language(recorder, code)
        except Exception as exc:
            self.notify(str(exc)[:240], severity="error", title="/language")
            return
        note = " ".join(recorder.export_text(styles=False).split())
        self._apply_language()
        self.notify(note[:240] or "Language updated.", title="/language", timeout=8)

    def _apply_language(self) -> None:
        """Redraw the console in the language now in force.

        The setter above changes the language and persists it, and that used
        to be all that happened: the console went on showing every word it
        had already drawn, because a Rich renderable carries its text exactly
        as a themed one carries its colours. So /language hr translated the
        popups that are rendered through the shell's own views and left the
        console's own frame in English, which reads as the setting not having
        worked at all.

        The mechanism is the one /theme already uses. Every line that can
        change was mounted with the recipe that produced it, and re-running
        each recipe redraws it in place. What is NOT a recipe is re-applied
        by hand here: a border title and a placeholder are plain attributes,
        set once at mount, and nothing would otherwise go back for them.
        """

        for pane_id, name in (
            ("#conversation", "Conversation"),
            ("#activity", "Activity"),
            ("#evidence-pane", "Evidence"),
            ("#guardrails-pane", "Guardrails"),
        ):
            for pane in self.query(pane_id).results(VerticalScroll):
                pane.border_title = _pane_title(name)
        for prompt in self.query("#prompt").results(Input):
            prompt.placeholder = _t(_PROMPT_PLACEHOLDER)
        # The evidence pane's own subtitle, under the same condition that put it
        # there: a pane still holding findings keeps the subtitle that names
        # them, and must not have the resting hint written back over it.
        for evidence in self.query("#evidence-pane").results(VerticalScroll):
            if not list(evidence.query(Collapsible)):
                evidence.border_subtitle = _t("You accept findings with v")
        self._retranslate_bindings()
        self._repaint_console()

    def _retranslate_bindings(self) -> None:
        """Rewrite the key descriptions the footer legend shows.

        A binding is declared on the class and read at import, long before a
        language is chosen, so the legend could not follow a switch by routing
        a string the way everything else here does. What makes it possible is
        that the map is per instance: a DOMNode copies the class's merged
        bindings into ``self._bindings`` when it is built, so this app's copy
        can be rewritten without touching the class or any other node.

        It is the instance's OWN map that is rewritten, never a fresh copy of
        the class's. That distinction is the whole of the bug this was written
        against twice: ``App.__init__`` adds the command palette's ctrl+p to
        the instance map and not to the class one, so rebuilding from the class
        dropped it and the legend went from seven keys to none.

        Each description is translated from the English it was DECLARED with,
        kept in a snapshot taken the first time through, which is what makes
        switching hr → en → hr work: translating in place would ask the catalog
        on the second pass to translate a Croatian phrase it has never seen.

        Six of the seven descriptions on the legend are this console's own
        (evidence, activity, guardrails, help, quit, review); the seventh is
        Textual's command palette, whose English is left alone by the catalog
        simply having no entry for it. Textual's Input bindings never appear
        here at all: they are declared ``show=False`` and the footer skips
        them, so nothing reaches into another library's class.

        Guarded, and deliberately: it touches a private attribute and a
        dataclass field, and a Textual release that moves either must cost the
        operator a translated legend and nothing else.
        """

        try:
            from dataclasses import replace

            bindings = self._bindings
            if self._binding_descriptions is None:
                self._binding_descriptions = {
                    (key, index): binding.description
                    for key, declared in bindings.key_to_bindings.items()
                    for index, binding in enumerate(declared)
                }
            originals = self._binding_descriptions
            for key, declared in list(bindings.key_to_bindings.items()):
                # A NEW list per key: the instance map shares its lists with
                # the class map, and translating one in place would translate
                # every future console's bindings with it.
                bindings.key_to_bindings[key] = [
                    replace(
                        binding,
                        description=_t(originals.get((key, index), binding.description)),
                    )
                    if binding.description
                    else binding
                    for index, binding in enumerate(declared)
                ]
        except Exception:
            return
        self.refresh_bindings()

    def _cmd_theme(self, argument: str = "") -> None:
        """Show or switch the console colour theme — a preference, like /language."""

        wanted = argument.strip().casefold()
        if not wanted:
            self._theme_chooser()
            return
        if wanted not in M.available_palettes():
            # The listing carries the swatches, so the refusal shows what the
            # accepted values look like rather than only what they are called.
            self.push_screen(OverlayScreen("Theme", self._theme_listing(unknown=wanted)))
            return
        if wanted == M.active_palette_name():
            self.notify(f"{wanted} is already active.", title="/theme")
            return
        self._apply_theme(wanted)

    @work
    async def _theme_chooser(self) -> None:
        """Every shipped theme as a row that can be picked, the active one first
        under the cursor and drawn in its own colours."""

        names = M.available_palettes()
        active = M.active_palette_name()
        options: list[Text] = []
        for name in names:
            palette = M.palette(name)
            row = Text()
            row.append(f"{M.GLYPH_OK} " if name == active else "  ", style=M.SUCCESS)
            row.append(
                f"{name:<16}", style=f"bold {M.ACCENT}" if name == active else M.TEXT
            )
            # A miniature of the theme: its own colours ON ITS OWN GROUND. They
            # used to be drawn on whatever ground was current, which made the
            # swatch a lie in both directions — every light theme vanished into
            # a dark console, and in dfir-light five of the eight showed a row
            # of white blocks on white. A theme is picked by what it looks
            # like, so the swatch has to look like it.
            for role in ("TEXT", "ACCENT", "SUCCESS", "ORANGE", "RED"):
                row.append("██", style=f"{palette[role]} on {palette['BACKGROUND']}")
            row.append(f"  ground {palette['BACKGROUND']}", style=M.DIM)
            options.append(row)
        initial = names.index(active) if active in names else 0
        pick = await self.push_screen_wait(
            ChoiceScreen("colour theme", options, initial=initial)
        )
        if pick is None or names[pick] == active:
            return
        self._apply_theme(names[pick])

    def _theme_listing(self, unknown: str = "") -> Group:
        """Every shipped theme, the active one marked — the answer to a bare /theme."""

        lines: list = []
        if unknown:
            lines.extend(
                (
                    Text(f"{M.GLYPH_ERROR} No theme called {unknown}.", style=M.RED),
                    Text(""),
                )
            )
        table = Table.grid(padding=(0, 2))
        table.add_column(width=1)
        table.add_column(no_wrap=True)
        table.add_column(no_wrap=True)
        table.add_column(ratio=1)
        active = M.active_palette_name()
        for name in M.available_palettes():
            here = name == active
            palette = M.palette(name)
            # The theme's own colours on its own ground; see _theme_chooser.
            swatch = Text()
            for role in ("TEXT", "ACCENT", "SUCCESS", "ORANGE", "RED"):
                swatch.append("██", style=f"{palette[role]} on {palette['BACKGROUND']}")
            table.add_row(
                Text(M.GLYPH_OK if here else "", style=M.SUCCESS),
                Text(name, style=f"bold {M.ACCENT}" if here else M.TEXT),
                swatch,
                Text(f"ground {palette['BACKGROUND']}", style=M.DIM),
            )
        lines.extend(
            (
                table,
                Text(""),
                Text("/theme <name> switches; the choice is kept.", style=M.DIM_BRIGHT),
            )
        )
        return Group(*lines)

    def _apply_theme(self, name: str) -> None:
        """Move both layers at once: the palette Rich draws from, and the TCSS."""

        M.set_active_palette(name)
        try:
            from forensic_agent.cli.preferences import save_console_theme

            save_console_theme(name)
        except Exception:
            # A preference store that cannot be written must not cost the
            # operator the theme they asked for; it simply will not survive.
            self.notify("The theme could not be saved for next time.", title="/theme")
        # Setting App.theme repaints the stylesheet layer; refresh_css lands
        # the new $variables on every screen already on the stack.
        self.theme = name
        self.refresh_css()
        self._repaint_console()
        self.notify(f"Theme {name}.", title="/theme")

    def _repaint_console(self) -> None:
        """Redraw everything already on screen from the data it was drawn from.

        Rich renderables carry the colours they were built with, so the panes
        and the transcript would otherwise keep the previous palette. Every
        line that can change colour was mounted with the recipe that produced
        it (see :func:`_painted`), and this re-runs each one in place — the
        transcript is redrawn, not rebuilt, so nothing scrolls away and no
        exchange is lost.
        """

        for screen in self.screen_stack:
            for widget in screen.query(Static):
                build = getattr(widget, "_dfir_build", None)
                if build is not None:
                    widget.update(build())
        self._refresh_review_hints()

    def _cmd_retry(self, _argument: str = "") -> None:
        """Send the previous message again, with its old answer set aside."""

        if self._demo_blocked("retry"):
            return
        # Every precondition BEFORE question_to_retry: it excludes the old
        # answer from context as a side effect, and a retry that is then
        # refused would have silently rewritten the context anyway.
        if self.running or self._ask_thread_alive:
            self.notify(
                "A message is already being investigated. Ctrl+C cancels it.",
                title="/retry",
                severity="warning",
            )
            return
        if not self._controller.has_evidence():
            self.notify(
                "No evidence is loaded. Open a case with /case first.",
                title="/retry",
            )
            return
        with self._recording():
            try:
                question = self._controller.session._history.question_to_retry()
            except Exception as exc:
                self.notify(str(exc)[:240], severity="error", title="/retry")
                return
        if not question:
            self.notify("There is no previous message to retry.", title="/retry")
            return
        self._ask(question)

    def _cmd_continue(self, _argument: str = "") -> None:
        if self._demo_blocked("continue"):
            return
        self._continue_worker(self._controller.status().evidence_sources)

    @work(thread=True, exclusive=True, group="caseop")
    def _continue_worker(self, sources_before: tuple[str, ...]) -> None:
        """Take up the saved investigation, reopening its evidence if needed."""

        self._case_op_alive = True
        try:
            with self._recording() as recorder:
                try:
                    self._controller.session.continue_investigation()
                except Exception as exc:
                    self.call_from_thread(
                        self.notify, str(exc)[:240], severity="error", title="/continue"
                    )
                    return
        finally:
            self._case_op_alive = False
        rendered = Text.from_ansi(recorder.export_text(styles=True))
        self.call_from_thread(self._continued, rendered, sources_before)

    def _continued(self, rendered: Text, sources_before: tuple[str, ...]) -> None:
        del sources_before  # the standing panel redraws either way
        self._refresh_session_panel()
        if rendered.plain.strip():
            self.push_screen(OverlayScreen("Continue", rendered))

    def _cmd_doctor(self, _argument: str = "") -> None:
        if self._demo_blocked("doctor"):
            return
        self.notify("checking the model connection and dependencies…", title="/doctor", timeout=4)
        self._doctor_worker()

    @work(thread=True, exclusive=False, group="cliview")
    def _doctor_worker(self) -> None:
        import io as _io

        from rich.console import Console as _Console

        from forensic_agent.cli.terminal import render_doctor

        session = self._controller.session
        recorder = _Console(
            record=True, width=94, file=_io.StringIO(), force_terminal=True
        )
        try:
            render_doctor(
                session.model, session.base_url, session.api_key, console=recorder
            )
        except Exception as exc:
            self.call_from_thread(
                self.notify, str(exc)[:240], severity="error", title="/doctor"
            )
            return
        rendered = Text.from_ansi(recorder.export_text(styles=True))
        self.call_from_thread(
            self.push_screen,
            OverlayScreen("Environment check", Group(self._build_block(), rendered)),
        )

    def _build_block(self) -> RenderableType:
        """Which build is running, and a warning only if it is an old one.

        This is where the build identity lives now. It was on the Session panel,
        as "code dated 2026-08-11 14:19", which is a sentence about the mtime of
        a source file offered to somebody investigating a disk image. /doctor is
        the screen an operator opens to ask what they are running, so the answer
        belongs here and only here.

        The warning is the half that earns its keep. It fires when the build is
        genuinely old and says nothing at all otherwise, so an operator on a
        current build is not taught to scroll past a line that is always there.
        """

        from forensic_agent.cli.build_identity import build_label, staleness_note

        lines: list[RenderableType] = []
        head = Text()
        head.append("version   ", style=M.DIM)
        head.append(_version_label() or "unknown", style=M.TEXT)
        build = build_label()
        if build:
            head.append("     ", style=M.DIM)
            head.append(build, style=M.DIM_BRIGHT)
        lines.append(head)
        note = staleness_note()
        if note:
            lines.append(Text(f"{M.GLYPH_WARN} {note}", style=M.ORANGE))
        lines.append(Text(""))
        return Group(*lines)

    def _cmd_history(self, argument: str = "") -> None:
        if self._demo_blocked("history"):
            return
        text = argument.strip()
        if text and not text.isdigit():
            # A limit, not a fixed set: there is no list to choose from, so the
            # refusal says what shape the argument has to be.
            self._unrecognised("history", text, ("a whole number of messages",))
            return
        arguments = (max(1, int(text)),) if text else ()
        self._cli_overlay("/history", "show_history", *arguments, live_safe=True)

    # -- saved investigations ---------------------------------------------
    def _cmd_resume(self, argument: str = "") -> None:
        """/resume, and /sessions, which is the same command under its old name.

        With an id it goes straight to that investigation; without one it opens
        the picker. Either way the investigation comes back ON SCREEN, panes
        included, rather than only into the model's context.
        """

        if self._demo_blocked("resume"):
            return
        if argument.strip():
            self._resume_saved(argument.strip())
            return
        self._sessions_flow()

    def _saved_investigations(self) -> list:
        session = self._controller.session
        history = session._history
        case = history._case()
        return list(
            history._store.list_sessions(
                case_id=case.case_id, source_identity=case.source_identity
            )
        )

    @work
    async def _sessions_flow(self) -> None:
        """Saved investigations as a list screen: pick one and it resumes."""

        import asyncio

        try:
            rows = await asyncio.to_thread(self._saved_investigations)
        except Exception as exc:
            self.notify(str(exc)[:240], severity="error", title="/resume")
            return
        unreadable = getattr(
            self._controller.session._history._store, "last_unreadable", ()
        )
        if unreadable:
            self.notify(
                f"{len(unreadable)} saved investigation file(s) could not be "
                f"read and were skipped: {', '.join(unreadable[:3])}",
                severity="warning",
                title="/resume",
            )
        if not rows:
            self.notify("No saved investigations for the active case.", title="/resume")
            return
        active = getattr(self._controller.session._history, "active_session_id", None)
        active_model = getattr(self._controller.session, "model", "")
        options = []
        resumable: list[bool] = []
        for row in rows:
            identity = row.get("inference_identity")
            if isinstance(identity, dict):
                model = str(identity.get("model"))
                ok = True
                mismatch = "" if model == active_model else "   ▲ other model"
            else:
                model = "legacy — not resumable"
                ok = False
                mismatch = ""
            resumable.append(ok)
            marker = "   ● active" if active and row["session_id"] == active else ""
            turns = int(row.get("retained_turns") or 0)
            options.append(
                f"{str(row['session_id'])[:16]}   {model}{mismatch}   "
                f"{turns} message{'' if turns == 1 else 's'}   "
                f"{row['updated_at']}{marker}"
            )
        index = await self.push_screen_wait(
            ChoiceScreen("saved investigations — Enter resumes one", options)
        )
        if index is None:
            return
        if not resumable[index]:
            self.notify(
                "That investigation was saved before the console recorded "
                "which model produced each answer, so it cannot be reopened. "
                "It stays readable with /history.",
                severity="warning",
                title="/resume",
            )
            return
        self._resume_saved(str(rows[index]["session_id"]))

    def _resume_saved(self, identifier: str) -> None:
        with self._recording() as recorder:
            try:
                # strict: a failure must surface as the error it is, not as
                # narration inside an information toast.
                self._controller.session.resume_conversation(identifier, strict=True)
            except Exception as exc:
                self.notify(str(exc)[:300], severity="error", title="/resume")
                return
        note = " ".join(recorder.export_text(styles=False).split())
        self.notify(
            note[:240] or f"Investigation resumed: {identifier[:16]}", title="/resume"
        )
        self._replay_resumed(identifier)

    @work(exclusive=True, group="clear")
    async def _replay_resumed(self, identifier: str) -> None:
        """Put the resumed investigation back ON SCREEN, not just in context.

        Resuming restored what the model remembers and left the console empty,
        so the operator could carry on asking questions about an investigation
        they could no longer see: no exchanges, no activity rows, no evidence,
        no guardrail decisions. Everything needed to draw them is on disk, in
        the same two files the live panes are built from, so each turn is
        rebuilt through the same projections and rendered through the same
        methods a live answer goes through.

        Exclusive on the ``clear`` group because it clears first, and two
        interleaved clears mint two banners and crash the console.
        """

        import asyncio

        turns = self._resumed_turns()
        await self.action_clear()
        await self._reset_instruments()
        self._exchange = 0
        self._say(self._replay_banner, widget_id="replay-banner")
        if not turns:
            self._say(
                Text(
                    "This investigation has no saved messages.",
                    style=M.DIM_BRIGHT,
                )
            )
            return
        for turn in turns:
            try:
                result = await asyncio.to_thread(self._controller.replay, turn)
            except Exception:
                continue
            self._exchange += 1
            self._elapsed = 0.0
            self._write_you(result.question)
            self._begin_run_panes()
            self._replay_activity(result)
            self._render_result(result)
            # One frame between exchanges, so a long history paints in order
            # rather than arriving as one jump.
            await asyncio.sleep(0)
        self.query_one("#prompt", Input).focus()

    def _replay_activity(self, result: InvestigationResult) -> None:
        """Rebuild the ACTIVITY rows for a replayed exchange.

        The live path fills this pane from the ``on_tool`` feed as calls run,
        and :meth:`_finalize_activity` only SETTLES rows that feed already
        created — so a replay, which has no feed, produced an empty ACTIVITY
        pane beside a full GUARDRAILS one. The rows are emitted here through
        the identical :meth:`_apply_tool_event` the live feed uses, so a
        restored row is built by the same code and looks like what it is.

        Every row arrives already settled. Nothing is spun or animated: the
        record says what each call did, not what it was doing, and a replay
        that pretended otherwise would show work happening that finished days
        ago.
        """

        for card in sorted(result.oversight, key=lambda entry: entry.sequence):
            self._apply_tool_event(
                ToolEvent(
                    sequence=card.sequence,
                    function=card.function,
                    operation=card.operation,
                    args_summary="  ".join(
                        f"{name}={value}" for name, value in card.arguments
                    ),
                    status=card.outcome,
                    duration_s=card.duration_s,
                )
            )

    def _resumed_turns(self) -> tuple:
        """The restored investigation's messages, oldest first."""

        try:
            active = self._controller.session._history.active
            return tuple(active.history()) if active is not None else ()
        except Exception:
            return ()

    def _replay_banner(self) -> Text:
        """Say plainly that this screen is a record, not a run happening now.

        Without it the panes are indistinguishable from a live investigation,
        and in a forensic console the difference between "this is what the
        agent just found" and "this is what it found last week" is the whole
        point of keeping a record at all.
        """

        text = Text()
        text.append(f"{M.GLYPH_POINT} ", style=M.DIM)
        text.append("Restored from the record. ", style=f"bold {M.DIM_BRIGHT}")
        text.append(
            "These messages, tool calls, evidence and decisions were read back "
            "from the saved run. Nothing here is running now. Ask a question to "
            "carry on.",
            style=M.DIM,
        )
        return text

    # -- the model and its provider ---------------------------------------
    def _cmd_model(self, argument: str = "") -> None:
        if self._demo_blocked("model"):
            return
        text = argument.strip()
        if not text:
            self._cli_overlay("/model", "show_model")
            return
        parts = text.split(None, 1)
        if parts[0].casefold() == "list":
            self._model_catalog_flow(parts[1].strip() if len(parts) == 2 else "")
            return
        self._change_model_worker(text)

    @work(thread=True, exclusive=True, group="modelop")
    def _change_model_worker(self, model_id: str) -> None:
        self.call_from_thread(
            self.notify, f"checking {model_id}…", title="/model", timeout=4
        )
        with self._recording() as recorder:
            try:
                self._controller.session.change_model(model_id)
            except Exception as exc:
                self.call_from_thread(
                    self.notify, str(exc)[:240], severity="error", title="/model"
                )
                return
        note = " ".join(recorder.export_text(styles=False).split())
        self.call_from_thread(self._model_changed, note)

    def _model_changed(self, note: str) -> None:
        self._refresh_session_panel()
        self.notify((note or "Model updated.")[:300], title="/model", timeout=8)

    @work
    async def _model_catalog_flow(self, selector: str = "") -> None:
        """The catalogue as a picker: choose a row and the console switches to it."""

        import asyncio

        session = self._controller.session
        self.notify("reading the model catalogue…", title="/model list", timeout=4)

        def fetch() -> tuple[list[str], list[str]]:
            from forensic_agent.cli.model_listing import (
                context_tokens,
                select_models,
                usd_per_million_tokens,
            )
            from forensic_agent.core.environ import (
                backend_kind,
                catalog_models,
                local_models,
            )

            if backend_kind(session.base_url) == "ollama":
                entries = [
                    e for e in local_models(session.base_url) if e.get("supports_tools")
                ]
                needle = selector.casefold()
                if needle and needle != "all":
                    entries = [
                        e for e in entries if needle in str(e.get("name", "")).casefold()
                    ]
                ids = [str(e["name"]) for e in entries]
                labels = []
                for e in entries:
                    detail = "  ".join(
                        v
                        for v in (
                            str(e.get("parameter_size") or ""),
                            str(e.get("quantization") or ""),
                        )
                        if v
                    )
                    labels.append(f"{e['name']}   {detail}".rstrip())
                return ids, labels
            selection = select_models(
                catalog_models(session.base_url, session.api_key), selector
            )
            ids = [str(e.get("id")) for e in selection.capable]
            labels = [
                f"{e.get('id')}   ctx {context_tokens(e.get('context_length'))}   "
                f"in {usd_per_million_tokens(e.get('prompt_usd_per_token'))}   "
                f"out {usd_per_million_tokens(e.get('completion_usd_per_token'))} per 1M"
                for e in selection.capable
            ]
            return ids, labels

        try:
            ids, labels = await asyncio.to_thread(fetch)
        except Exception as exc:
            detail = str(exc)
            key = getattr(session, "api_key", "") or ""
            if key:
                detail = detail.replace(key, "[REDACTED]")
            self.notify(detail[:240], severity="error", title="/model list")
            return
        if not ids:
            self.notify(
                "No model in this view can run an investigation.", title="/model list"
            )
            return
        current = getattr(session, "model", "")
        labels = [
            label + ("   ● active" if ids[i] == current else "")
            for i, label in enumerate(labels)
        ]
        index = await self.push_screen_wait(
            ChoiceScreen("models that can run an investigation — Enter switches", labels)
        )
        if index is None:
            return
        if ids[index] == current:
            self.notify("That model is already active.", title="/model")
            return
        self._change_model_worker(ids[index])

    def _cmd_setup(self, _argument: str = "") -> None:
        if self._demo_blocked("setup"):
            return
        self._setup_flow()

    @work
    async def _setup_flow(self) -> None:
        """Provider configuration inside the console: choose, check, apply.

        The line flow reads the API key straight off the tty (prompt_toolkit),
        which can never run under Textual — so the same validated building
        blocks run here behind modal screens instead.
        """

        import asyncio
        import os as _os

        from forensic_agent.cli.setup import (
            OPENROUTER_MODEL,
            ProviderConfiguration,
            _default_ollama_url,
            apply_configuration,
            configuration_path,
            save_configuration,
        )
        from forensic_agent.core.environ import (
            OPENROUTER_BASE_URL,
            backend_status,
            local_models,
        )

        cancelled = "Setup cancelled; configuration was not changed."
        provider = await self.push_screen_wait(
            ChoiceScreen(
                "configure the model provider",
                ["OpenRouter (remote)", "Ollama (local)"],
            )
        )
        if provider is None:
            self.notify(cancelled, title="/setup")
            return
        if provider == 0:
            model = await self.push_screen_wait(
                PromptScreen(
                    "OpenRouter model",
                    hint="Enter keeps the default; any current OpenRouter model ID works.",
                    value=OPENROUTER_MODEL,
                )
            )
            if model is None:
                self.notify(cancelled, title="/setup")
                return
            model = model.strip()
            if not model or any(ch.isspace() for ch in model):
                self.notify(
                    "The OpenRouter model ID is invalid.", severity="error", title="/setup"
                )
                return
            key = await self.push_screen_wait(
                PromptScreen(
                    "OpenRouter API key",
                    hint="Paste the key; only masking characters are shown. It is never displayed or logged.",
                    password=True,
                )
            )
            if key is None or not key.strip():
                self.notify(cancelled, title="/setup")
                return
            key = key.strip()
            self.notify("checking the model and key…", title="/setup", timeout=6)
            try:
                status = await asyncio.to_thread(
                    backend_status, OPENROUTER_BASE_URL, model=model, api_key=key
                )
            except Exception as exc:
                self.notify(
                    str(exc).replace(key, "[REDACTED]")[:240],
                    severity="error",
                    title="/setup",
                )
                return
            problem = ""
            if status.get("authenticated") is False:
                problem = "OpenRouter rejected the API key."
            elif not status.get("reachable"):
                problem = "OpenRouter could not be reached."
            elif status.get("has_model") is not True:
                problem = f"OpenRouter does not advertise model {model}."
            elif status.get("model_supports_tools") is not True:
                problem = (
                    f"Model {model} does not advertise tool-call support; "
                    "choose one whose supported parameters include tools."
                )
            if problem:
                self.notify(problem[:240], severity="error", title="/setup")
                return
            configuration = ProviderConfiguration(
                backend="openrouter",
                base_url=OPENROUTER_BASE_URL,
                model=model,
                api_key=key,
            )
        else:
            base_url = _default_ollama_url(_os.environ)
            self.notify(
                "looking for local models with tool support…", title="/setup", timeout=6
            )
            try:
                discovered = await asyncio.to_thread(local_models, base_url)
            except Exception as exc:
                self.notify(str(exc)[:240], severity="error", title="/setup")
                return
            usable = [e for e in discovered if e.get("supports_tools")]
            if not usable:
                self.notify(
                    "No local Ollama model with tool-call support was found. "
                    "Start Ollama and install one.",
                    severity="error",
                    title="/setup",
                )
                return
            labels = []
            for e in usable:
                detail = "  ".join(
                    v
                    for v in (
                        str(e.get("parameter_size") or ""),
                        str(e.get("quantization") or ""),
                    )
                    if v
                )
                labels.append(f"{e['name']}   {detail}".rstrip())
            index = await self.push_screen_wait(
                ChoiceScreen("local models with tool support", labels)
            )
            if index is None:
                self.notify(cancelled, title="/setup")
                return
            configuration = ProviderConfiguration(
                backend="ollama",
                base_url=base_url,
                model=str(usable[index]["name"]),
            )

        def apply() -> None:
            save_configuration(configuration, configuration_path(_os.environ))
            apply_configuration(configuration, _os.environ)
            with self._recording():
                self._controller.session.reconfigure_provider(
                    base_url=configuration.base_url,
                    api_key=configuration.api_key or "ollama",
                    model=configuration.model,
                )

        try:
            await asyncio.to_thread(apply)
        except Exception as exc:
            detail = str(exc)
            if configuration.api_key:
                detail = detail.replace(configuration.api_key, "[REDACTED]")
            self.notify(detail[:240], severity="error", title="/setup")
            return
        self._refresh_session_panel()
        self.notify(
            f"Provider configured — {configuration.backend}, model "
            f"{configuration.model}. The key is never displayed or logged.",
            title="/setup",
            timeout=8,
        )

    @contextmanager
    def _recording(self):
        """Patch every console the session writes through onto one recorder.

        The session and its investigation history each hold their own Console
        reference; capturing only the session's lets history output (saved
        investigations, past messages, brief confirmations) print behind the
        Textual screen instead of into the popup.
        """

        recorder = self._recorder_console()
        session = self._controller.session
        history = getattr(session, "_history", None)
        original = session._console
        original_history = getattr(history, "_console", None)
        session._console = recorder
        if history is not None:
            history._console = recorder
        try:
            yield recorder
        finally:
            session._console = original
            if history is not None and original_history is not None:
                history._console = original_history

    @staticmethod
    def _recorder_console():
        """A console of this view's own, at the width the shell renders to."""

        import io as _io

        from rich.console import Console as _Console

        return _Console(record=True, width=94, file=_io.StringIO(), force_terminal=True)

    @work(thread=True, exclusive=True, group="cliview")
    def _cli_overlay(
        self, title: str, method: str, *arguments, live_safe: bool = False
    ) -> None:
        """Run one of the shell's own view methods and show its output.

        The session renders to a recording console; the exported output is
        the same thing the line shell would print, shown as a popup so the
        conversation is never touched. Exclusive: two overlapping overlays
        would each capture the other's console swap and strand the session
        writing into a dead recorder.

        ``live_safe`` is for the views that may be read while a message is
        being investigated. They are handed a console of their own instead of
        the session's being swapped for one: swapping is what made a view
        unsafe mid-run — the running thread prints into the session console —
        and a read that never touches that attribute cannot race the restore.
        """

        session = self._controller.session
        if live_safe:
            recorder = self._recorder_console()
            try:
                getattr(session, method)(*arguments, console=recorder)
            except Exception as exc:
                self.call_from_thread(
                    self.notify, str(exc)[:240], severity="error", title=title
                )
                return
            self._show_view(title, recorder)
            return
        if self.running or self._ask_thread_alive:
            # The run prints into the session console on its own thread; a
            # swap now would leak its output into the popup and race the
            # restore. The orphaned thread of a cancelled run counts too.
            self.call_from_thread(
                self.notify,
                "A message is being investigated, so this view waits for it.",
                title=title,
                severity="warning",
            )
            return
        with self._recording() as recorder:
            try:
                getattr(session, method)(*arguments)
            except Exception as exc:
                self.call_from_thread(
                    self.notify, str(exc)[:240], severity="error", title=title
                )
                return
        self._show_view(title, recorder)

    def _show_view(self, title: str, recorder) -> None:
        rendered = Text.from_ansi(recorder.export_text(styles=True))
        if not rendered.plain.strip():
            self.call_from_thread(self.notify, "Nothing to show.", title=title)
            return
        self.call_from_thread(
            self.push_screen, OverlayScreen(title, rendered)
        )

    # -- case opening ----------------------------------------------------
    def _install_session_hooks(self) -> None:
        """Give the live session the console's own progress observers.

        The session's quiet console can animate nothing, so the digest pass
        and the entity index report into these hooks instead; both are read
        at call time (the `_tool_line` pattern) and both merely update the
        one progress row a case operation keeps in the conversation.
        """

        if self._controller.is_demo:
            return
        session = self._controller.session
        session._case_open_watcher = self._watch_case_open
        session._index_progress = self._index_progress_sink

    def _watch_case_open(self, resolved: str):
        """Follow one image's open, from the thread the case is opening on.

        The two halves of preparing a disk are consecutive rather than
        concurrent, and only the first of them can be measured: the medium is
        streamed through SHA-256, and then dfVFS resolves partitions and file
        systems while reporting nothing at all. The byte count reaching the
        total IS the moment the second half begins, which is why this is where
        the row is renamed — a bar left standing at 100% for the minute after
        the digest finished said the open was done when it was not.

        An open that reuses a stored attestation streams no bytes whatsoever,
        so the step opens under a name that claims nothing about bytes and
        becomes the digest only once the pass states the total it will read.
        """

        import os as _os
        import time as _time

        name = _os.path.basename(resolved) or resolved
        total: int | None = None
        done = 0
        last = 0.0
        resolving = False

        self._from_case_thread(self._begin_case_step, f"Opening {name}")

        def advance(byte_count: int) -> None:
            nonlocal done, last, resolving
            done += byte_count
            if resolving:
                return
            if total is not None and done >= total:
                resolving = True
                self._from_case_thread(
                    self._begin_case_step, "Resolving partitions and file systems"
                )
                return
            now = _time.monotonic()
            if now - last < 0.1:
                return
            last = now
            self._from_case_thread(self._advance_case_step, done, total)

        def declare_total(byte_count: int) -> None:
            nonlocal total
            total = byte_count
            self._from_case_thread(self._begin_case_step, f"Verifying {name}", byte_count)

        return advance, declare_total

    def _index_progress_sink(
        self, fraction: float | None = None, detail: str | None = None
    ) -> None:
        """Every long step of an open that is not the digest reports here.

        ``detail`` is the step's NAME rather than a note about it. Hashing a
        memory image and building the entity index both arrive through this one
        sink, and a row that called both of them "indexing evidence" told the
        operator the console was doing something it was not.

        Nothing is decided on this side: the sink is called from the case
        worker's thread, so the event is handed straight across and the state
        it changes is only ever touched on the app's own thread.
        """

        self._from_case_thread(self._report_case_step, detail, fraction)

    def _from_case_thread(self, callback: Callable[..., Any], *arguments: Any) -> None:
        """Run one repaint on the app's thread, from the thread opening the case.

        The case worker owns the session, not the DOM, so every paint has to
        cross back. It is guarded twice: a console shutting down under a long
        open must never turn a display fault into a failed case, and a caller
        that is already on the app's thread (a test driving the session
        directly) is served rather than refused.
        """

        try:
            self.call_from_thread(callback, *arguments)
        except Exception:
            try:
                callback(*arguments)
            except Exception:
                pass

    def _begin_case_step(self, label: str, total: int | None = None) -> None:
        """Name what the console is waiting on now, and restart that step's clock."""

        self._case_step = _CaseStep(label, done=0 if total else None, total=total)
        self._paint_case_step()

    def _advance_case_step(self, done: int, total: int | None) -> None:
        """Move the byte count of the step already on screen."""

        step = getattr(self, "_case_step", None)
        if step is None:
            return
        step.done = done
        step.total = total
        self._paint_case_step()

    def _report_case_step(self, label: str | None, fraction: float | None) -> None:
        """Apply one named-step event, on the thread that owns the row."""

        name = (label or "").strip()
        step = getattr(self, "_case_step", None)
        if step is None or (name and step.label != name):
            self._begin_case_step(name or (step.label if step else "Working"))
            step = self._case_step
        if fraction is not None and step is not None:
            step.fraction = fraction
        self._paint_case_step()

    def _case_step_tick(self) -> None:
        """Repaint the case row on the frame clock, never on its events.

        This is the whole fix for a console that looked hung while it worked.
        Two of the three long steps of an open report once, at their start, and
        then block: the memory digest inside a single read, the entity index
        inside a scanner subprocess whose output is captured rather than
        streamed. A row drawn only when an event arrived therefore froze for
        exactly the wait it existed to explain. Drawn on the clock, the spinner
        and the elapsed time keep saying the true thing — this step is still
        running — with no event required and no percentage invented.
        """

        if getattr(self, "_case_step", None) is None:
            return
        self._case_spin = (self._case_spin + 1) % len(_SPINNER)
        self._paint_case_step()

    def _paint_case_step(self) -> None:
        step = getattr(self, "_case_step", None)
        if step is None:
            return
        self._update_case_progress(self._case_step_line(step))

    def _case_step_line(self, step: _CaseStep) -> Text:
        """The one row a case operation keeps, in the console's live vocabulary.

        Deliberately the shape of the working line a message runs under: the
        same spinner, the same bold accent name, the same elapsed time
        right-aligned to a fixed column so it does not jitter as an open
        crosses into minutes. A second visual language for "the console is
        busy" would be one more thing for an operator to learn.

        The bar appears only where something measured the fraction. A step that
        can say nothing about how far it has to go shows its name and its clock
        and stops there, because a percentage nobody measured is worse than no
        percentage at all.
        """

        from rich.filesize import decimal as _decimal

        text = Text(no_wrap=True, overflow="ellipsis")
        text.append(_SPINNER[self._case_spin] + " ", style=M.ACCENT)
        text.append(step.label, style=f"bold {M.ACCENT}")
        text.append(
            f"  {format_duration(step.elapsed(), compact=True):>6}", style=M.DIM_BRIGHT
        )
        fraction = step.measured()
        if fraction is None:
            return text
        filled = int(fraction * 24)
        text.append("   ")
        text.append("█" * filled, style=M.SUCCESS)
        text.append("░" * (24 - filled), style=M.BORDER)
        text.append(f"  {fraction * 100:3.0f}%", style=M.TEXT)
        if step.total:
            text.append(
                f"  {_decimal(step.done or 0)} / {_decimal(step.total)}", style=M.DIM
            )
        return text

    def _update_case_progress(self, line: Text) -> None:
        for widget in self.query("#caseprog").results(Static):
            widget.update(line)
            return
        self._say(line, widget_id="caseprog")

    def _clear_case_progress(self) -> None:
        self._case_step = None
        for widget in self.query("#caseprog"):
            widget.remove()

    def _surface_case_narration(self, narration: str) -> None:
        """Show what the engine said while the case changed hands.

        History rotation, the open cost, the entity-index announcement and
        its consequence line all print through the session console; swallowed,
        the operator cannot tell an indexed case from an unindexed one.
        """

        lines = [line.rstrip() for line in narration.splitlines() if line.strip()]
        if not lines:
            return
        self._say(partial(self._narration_block, tuple(lines)))

    def _narration_block(self, lines: tuple[str, ...]):
        """The session's recorded lines, each keeping the indent it was given.

        Built as one renderable per line rather than as one ``Text`` carrying
        newlines. A recorded line arrives already wrapped to the recording
        console's width and is wrapped again to this pane's, and a continuation
        produced by that second wrap returns to column zero: the indent that
        marked it as detail belonging to the line above is gone, and so is the
        glyph this method colours by. ``Padding`` restores the indent as a
        property of the renderable, so it survives any width.
        """

        from rich.padding import Padding

        rendered: list[RenderableType] = []
        for line in lines[:12]:
            # The recording stripped the shell's colours; the glyph each
            # line carries says which one it had — a good outcome (the
            # index line among them) stays green here exactly like the
            # "case opened" line, a warning stays orange.
            stripped = line.lstrip()
            if stripped.startswith(M.GLYPH_OK):
                style = M.SUCCESS
            elif stripped.startswith(M.GLYPH_WARN):
                style = M.ORANGE
            elif stripped.startswith(M.GLYPH_ERROR):
                # A failed check reaches this block too, and the one line the
                # operator must not skim past would otherwise arrive in the
                # grey reserved for supporting detail.
                style = M.RED
            else:
                style = M.DIM
            indent = len(line) - len(stripped)
            rendered.append(
                Padding(Text(stripped, style=style), (0, 0, 0, min(indent, 8)))
            )
        if len(lines) > 12:
            rendered.append(
                Text(f"… and {len(lines) - 12} more lines", style=M.DIM)
            )
        return Group(*rendered)

    @work(thread=True, exclusive=True, group="caseop")
    def _case_worker(self, action: str, kind: str, path: str) -> None:
        session = self._controller.session
        # Whether a case is already open is read HERE, before the open replaces
        # it: once it has, nothing left can say whether the conversation on
        # screen belongs to this case or to the one before it.
        try:
            replaces = bool(session.has_evidence()) and action != "attach"
        except Exception:
            replaces = False
        self._case_replaces_open_case = replaces
        # Opening can hash a large image for minutes; the console must say it
        # is working somewhere that does not vanish like a toast does.
        self.call_from_thread(
            self._write_note, partial(self._opening_note, self._display_case_path(path))
        )
        narration = ""
        self._case_op_alive = True
        try:
            with self._recording() as recorder:
                try:
                    if action == "typed":
                        session.open_typed_case(kind, path)
                        pending = None
                    elif action == "attach":
                        method = {
                            "disk": session.attach_disk,
                            "memory": session.attach_memory,
                            "network": session.attach_pcap,
                        }[kind]
                        method(path)
                        pending = None
                    else:
                        pending = session.open_case(path)
                except SystemExit as exc:
                    # A host path typed in the container: the handoff request
                    # is already written, and the LAUNCHER owns the next step
                    # — mount the path and relaunch the console. A thread's
                    # SystemExit ends only the thread, so the exit code is
                    # carried to the app loop by hand.
                    self.call_from_thread(self._host_handoff_exit, exc.code)
                    return
                except Exception as exc:
                    try:
                        session.cancel_pending_case()
                    except Exception:
                        pass
                    self.call_from_thread(self._case_failed, str(exc))
                    return
            narration = recorder.export_text(styles=False)
        finally:
            self._case_op_alive = False
            self.call_from_thread(self._clear_case_progress)
        if pending is not None:
            self.call_from_thread(self._resolve_selection, pending)
        else:
            self.call_from_thread(self._case_opened, narration)

    def _display_case_path(self, path: str) -> str:
        """What the operator typed, not the container's mount point.

        Inside the container every case lives at /evidence; showing that
        path back to an operator who typed a real folder of theirs reads
        as the console opening something else entirely.
        """

        import os as _os

        if _os.environ.get("DFA_CONTAINERIZED") == "1":
            cleaned = path.strip().rstrip("/\\")
            if cleaned in ("/evidence", ""):
                label = _os.environ.get("DFA_CASE_LABEL", "").strip()
                return label or "the attached evidence"
        return path

    def _host_handoff_exit(self, code: int | str | None) -> None:
        """Exit so the host launcher can mount the requested path and relaunch."""

        try:
            numeric = int(code) if code is not None else 0
        except (TypeError, ValueError):
            numeric = 1
        self.exit(return_code=numeric)

    def _opening_note(self, shown_path: str) -> Text:
        return Text(
            f"{M.GLYPH_POINT} Opening {shown_path}. "
            "Verifying a large image can take a while",
            style=M.DIM,
        )

    def _case_failed(self, message: str) -> None:
        self._clear_case_progress()
        self.notify(message[:240], severity="error", title="case not opened")
        self._write_note(partial(self._case_failed_line, message[:200]))

    def _case_failed_line(self, message: str) -> Text:
        return Text(f"{M.GLYPH_ERROR} Case not opened — {message}", style=M.RED)

    def _case_opened(self, narration: str = "") -> None:
        replaced = getattr(self, "_case_replaces_open_case", False)
        self._case_replaces_open_case = False
        self._refresh_session_panel()
        if not replaced:
            self._announce_case_opened(narration)
            return
        # A second case is not a continuation of the first, and the first one's
        # questions and answers left standing above the new "case opened" line
        # read as though they were asked of this evidence. /clear is already the
        # primitive that empties the pane and reopens it with the banner and the
        # Session panel; a startup path of this method's own would be a second
        # thing to keep in step with it. Exclusive on the same group as /clear,
        # because two interleaved clears mint two banners and crash the console.
        self.run_worker(
            self._reopen_for_new_case(narration),
            exclusive=True,
            group="clear",
        )

    async def _reopen_for_new_case(self, narration: str) -> None:
        """Empty the previous case's conversation, then announce this one."""

        await self.action_clear()
        self._announce_case_opened(narration)

    def _announce_case_opened(self, narration: str) -> None:
        self._surface_case_narration(narration)
        self._say(partial(self._opened_line, self._status.case_label))
        self._say(Text(""))
        self.notify("Case opened.", title="/case")
        # A launch that named a case AND typed sources applies them one after
        # the other, each through this same worker, so each gets its own hash
        # and index rows instead of the whole set opening in silence.
        if getattr(self, "_pending_sources", None):
            self._open_next_pending_source()

    def _open_next_pending_source(self) -> None:
        """Open the next source the command line named, if any is left."""

        pending = getattr(self, "_pending_sources", None)
        if not pending:
            return
        kind, path = pending.pop(0)
        # "typed" when it stands alone (it becomes the case), "attach" when a
        # case is already open — the two verbs the session itself uses.
        try:
            standing = bool(self._controller.session.has_evidence())
        except Exception:
            standing = False
        self._case_worker("attach" if standing else "typed", kind, path)

    def _opened_line(self, case_label: str) -> Text:
        opened = Text()
        opened.append(f"{M.GLYPH_OK} Case opened  ", style=M.SUCCESS)
        opened.append(case_label, style=f"bold {M.TEXT}")
        return opened

    @work
    async def _resolve_selection(self, selection) -> None:
        """Walk the choices a multi-source case needs, then commit it."""

        import asyncio

        session = self._controller.session

        async def pick(title: str, paths) -> str | None:
            names = [str(p) for p in paths]
            index = await self.push_screen_wait(ChoiceScreen(title, names))
            return None if index is None else names[index]

        try:
            kwargs: dict = {}
            if len(selection.disks) > 1:
                choice = await pick("this case has several disk images — open which?", selection.disks)
                if choice is None:
                    raise _SelectionCancelled()
                kwargs["selected_disk"] = choice
            if len(selection.memories) > 1:
                choice = await pick("several memory dumps — use which?", selection.memories)
                if choice is None:
                    raise _SelectionCancelled()
                kwargs["selected_memory"] = choice
            default_pcap = None
            if len(selection.pcaps) > 1:
                choice = await pick("several network captures — default to which?", selection.pcaps)
                if choice is None:
                    raise _SelectionCancelled()
                default_pcap = choice
                kwargs["pcap_roles"] = {str(p): "pcap" for p in selection.pcaps}
            ambiguous_roles: dict[str, str] = {}
            for path in selection.ambiguous:
                index = await self.push_screen_wait(
                    ChoiceScreen(
                        f"what is {path}?",
                        ["a disk image", "a memory dump", "do not attach it"],
                    )
                )
                if index is None:
                    raise _SelectionCancelled()
                ambiguous_roles[str(path)] = ("disk", "memory", "ignore")[index]
            if ambiguous_roles:
                kwargs["ambiguous_roles"] = ambiguous_roles
            # The commit is where the case actually opens — history rotation,
            # entity indexing and its announcement happen here, so this leg
            # records and reports exactly like the direct open does.
            self._case_op_alive = True
            try:
                with self._recording() as recorder:
                    await asyncio.to_thread(
                        session.resolve_pending_case, default_pcap, **kwargs
                    )
                commit_narration = recorder.export_text(styles=False)
            finally:
                self._case_op_alive = False
                self._clear_case_progress()
        except _SelectionCancelled:
            try:
                session.cancel_pending_case()
            except Exception:
                pass
            self.notify("Case opening cancelled. The active case was not changed.", title="/case")
            return
        except Exception as exc:
            try:
                session.cancel_pending_case()
            except Exception:
                pass
            self._case_failed(str(exc))
            return
        self._case_opened(commit_narration)

    def _show_sources_overlay(self) -> None:
        if not self._controller.is_demo:
            self._cli_overlay("Evidence sources", "show_sources", live_safe=True)
            return
        self.push_screen(OverlayScreen("Evidence sources", self._sources_renderable()))

    def _sources_renderable(self):
        status = self._controller.status()
        self._status = status
        if not status.evidence_sources:
            hint = Text()
            hint.append("No evidence is attached.  ", style=M.DIM_BRIGHT)
            hint.append("/case <folder-or-file>", style=M.ACCENT)
            hint.append(" opens a case.", style=M.DIM_BRIGHT)
            return hint
        grid = Table.grid(padding=(0, 2))
        grid.add_column(justify="right", no_wrap=True)
        grid.add_column(ratio=1, overflow="fold")
        grid.add_column(no_wrap=True)
        for source in status.evidence_sources:
            kind, _, name = source.partition(": ")
            grid.add_row(
                Text(kind, style=M.DIM),
                Text(name or source, style=M.SUCCESS),
                Text("read only", style=M.DIM),
            )
        return grid

    def _write_note(self, note: Callable[[], RenderableType] | Text) -> None:
        self._say(note)
        self._say(Text(""))

    # -- asking ----------------------------------------------------------
    def _ask(self, question: str) -> None:
        if self.running:
            return
        # A cancelled run whose thread has not returned yet does NOT cost the
        # operator their next question. It used to: a second ask() would race
        # the first inside one session, so the console refused and told them to
        # try again in a moment, which is the console asking the operator to
        # poll it. The race is real and is answered where it lives — the worker
        # below takes the session's gate before entering ask(), so the second
        # question starts the moment the first thread is out of it. Cancelling
        # now stops that thread at its next dispatch, so the wait is the tail of
        # one call rather than the rest of an investigation.
        if self._case_op_alive and not self._controller.is_demo:
            self.notify(
                "A case operation is still in progress. Give it a moment.",
                title="busy",
                severity="warning",
            )
            return
        if not self._controller.is_demo and not self._controller.has_evidence():
            self.notify(
                "No evidence is loaded. Open a case with /case <folder-or-file>.",
                severity="warning",
                title="cannot investigate",
            )
            return
        import time as _time

        self._exchange += 1
        self._elapsed = 0.0
        self._model_phase = True
        self._phase_started = _time.monotonic()
        self._run_token += 1
        self.running = True
        self._write_you(question)
        self._begin_run_panes()
        self._investigate(question, self._run_token)

    #: How long a new question waits for a cancelled one to leave the session.
    #: A cancelled run stops at its next dispatch, so what is being waited for
    #: is the tail of one call and the unwinding after it. Generous enough to
    #: cover a slow tool that was already killed and is being reaped, short
    #: enough that a run which somehow never leaves is reported rather than
    #: leaving the operator with a console that says nothing.
    _ASK_GATE_WAIT_S = 30.0

    @work(thread=True, exclusive=True, group="investigate")
    def _investigate(self, question: str, token: int) -> None:
        def on_tool(event: ToolEvent) -> None:
            if token == self._run_token:
                self.call_from_thread(self._apply_tool_event, event)

        # One question inside session.ask() at a time. The session carries the
        # history, the last run and the record paths for the question it is
        # answering, and two threads inside it would interleave all three. The
        # gate is what lets the prompt accept a question the moment it is typed
        # while still guaranteeing that.
        if not self._ask_gate.acquire(timeout=self._ASK_GATE_WAIT_S):
            if token == self._run_token:
                self.call_from_thread(
                    self._render_error,
                    "The previous run has not let go of the session. Nothing "
                    "was asked, and nothing was changed.",
                )
            return
        try:
            self._ask_thread_alive = True
            try:
                result = self._controller.run(question, on_tool)
            except Exception as exc:  # a worker crash must not take down the UI
                if token == self._run_token:
                    self.call_from_thread(self._render_run_fault, exc)
                return
            finally:
                self._ask_thread_alive = False
        finally:
            self._ask_gate.release()
        if token == self._run_token:
            self.call_from_thread(self._render_result, result)

    def action_interrupt(self) -> None:
        """Ctrl+C stops the message in flight; it never quits the console.

        Three things have to happen, and the run's own thread cannot be one of
        them — a thread worker cannot be interrupted from outside.

        The run is told to stop dispatching. Every execution cell is asked, and
        the cell refuses the next model request or tool call it is asked to
        make, which is the same check it already makes for a budget that ran
        out. So the run stops at the next boundary rather than working on to
        its natural end with nobody waiting for it.

        Anything already running is killed. A packet scan carries a three-minute
        ceiling and a memory scan far more, and one left to finish reads the
        evidence at full speed for as long as it takes with the answer going
        nowhere.

        The late result is discarded. The token bump orphans it: the worker
        checks the token before reporting, so whatever the cancelled run
        eventually returns is never published.

        With nothing in flight, Ctrl+C clears a half-typed question; on an empty
        prompt it arms quit like ``q``.
        """

        if self.running:
            from forensic_agent.agent.execution_budget import cancel_active_cells
            from forensic_agent.core.toolkit import terminate_live_children

            self._run_token += 1
            self.workers.cancel_group(self, "investigate")
            # Stop dispatching first, then kill what is already dispatched. The
            # other order leaves a window in which the run answers the killed
            # tool by starting the next one.
            cancel_active_cells()
            self._cancelled_children = terminate_live_children()
            self.running = False
            self._remove_working_line()
            self._say(self._cancelled_line)
            self._end_exchange()
            prompt = self.query_one("#prompt", Input)
            prompt.disabled = False
            prompt.focus()
            return
        prompt = self.query_one("#prompt", Input)
        if prompt.value:
            prompt.value = ""
            return
        self.action_quit()

    def _cancelled_line(self) -> Text:
        """What the cancel did, and what the run had already put on the record.

        It used to say the run "may still finish and be saved", which was true
        and unhelpful: the operator was told the thing they had just stopped
        might not have stopped. It stops now, so this says what happened and
        what survives — the calls it had already made are on the record, under
        their own run, and the answer it never reached is not.
        """

        calls = len(self._activity_log)
        killed = getattr(self, "_cancelled_children", 0)
        line = Text()
        line.append(f"{M.GLYPH_ERROR} cancelled", style=f"bold {M.ORANGE}")
        if calls:
            line.append(
                f" after {calls} tool call{'' if calls == 1 else 's'}",
                style=M.ORANGE,
            )
        if killed:
            line.append(
                f", {killed} still running and stopped", style=M.ORANGE
            )
        line.append(
            ". What it had already recorded is kept; no answer was published.",
            style=M.DIM_BRIGHT,
        )
        return line

    # -- live activity ---------------------------------------------------
    def _apply_tool_event(self, event: ToolEvent) -> None:
        import time as _time

        self._activity_log[event.sequence] = event
        self._current_call = event.function + (
            f".{event.operation}" if event.operation else ""
        )
        self._current_args = event.args_summary
        # Phase bookkeeping: a running event means a tool has the clock; a
        # settled one hands it back to the model.
        self._model_phase = event.status != "running"
        self._phase_started = _time.monotonic()
        pane = self.query_one("#activity", VerticalScroll)
        try:
            group = self.query_one(f"#grp-{self._exchange}", Vertical)
        except Exception:
            # The group's Collapsible has not composed yet (its mount is
            # deferred); losing the race must delay the row, never drop it —
            # and never abort the run with an unhandled query error.
            self.call_after_refresh(self._apply_tool_event, event)
            return
        # Row ids carry the exchange number so a cleared run's pending removals
        # can never collide with the next run's rows.
        row_id = f"act-{self._exchange}-{event.sequence}"
        build = partial(_activity_row, event)
        if row_id in self._activity_rows:
            _paint(group.query_one(f"#{row_id}", Static), build)
        else:
            self._activity_rows.add(row_id)
            group.mount(_painted(build, id=row_id))
            pane.scroll_end(animate=False)

    def _render_result(self, result: InvestigationResult) -> None:
        self.running = False
        self._elapsed = result.controls.elapsed_s
        self.query_one("#evidence-pane").border_subtitle = ""
        self.query_one("#guardrails-pane").border_subtitle = ""
        prompt = self.query_one("#prompt", Input)
        if not result.answer_markdown and not result.findings and not result.oversight:
            # Nothing ran — the input was screened out. Such an exchange is
            # discarded entirely: the bubble, the working line and the
            # activity group go, and the number is given back.
            self._discard_exchange(result.note)
            prompt.focus()
            return
        if (
            result.answer_markdown
            and not result.incomplete
            and not result.findings
            and not result.oversight
            and not result.evidence_ids
            and result.controls.tool_calls == 0
        ):
            # The model itself declined: it answered without touching the
            # evidence at all. The reply is shown as a plain note and the
            # message number is given back, because the numbered record is for
            # work on the case and a declined question did none.
            #
            # An INCOMPLETE result is excluded whatever its counts say. A run
            # that examined the evidence and spent its budget without stating a
            # conclusion can end with nothing recorded against it, and it is not
            # a decline: giving its number back and calling it one would file an
            # outcome of the investigation as a question that was never asked.
            self._discard_exchange(result.note, reply=result.answer_markdown)
            prompt.focus()
            return
        self._last_result = result
        self._finalize_activity(result)
        self._write_agent(result)
        # The feed is snapshotted here whatever the layout: _activity_log is
        # emptied by the next run, so this is the last moment at which what
        # this exchange did can still be written down. Recording it in both
        # layouts is what lets a switch to the simple one show the exchanges
        # that ran before the switch.
        self._exchange_record[self._exchange] = (
            result,
            tuple(event for _seq, event in sorted(self._activity_log.items())),
        )
        self._show_inline_activity(self._exchange)
        self._queue_findings_review(result)
        self._end_exchange()
        self._populate_guardrails(result)
        self.query_one("#conversation", VerticalScroll).focus()

    def _discard_exchange(self, note: str, reply: str = "") -> None:
        self.run_worker(self._discard_exchange_now(note, reply), exclusive=False)

    async def _discard_exchange_now(self, note: str, reply: str = "") -> None:
        # Removals are deferred; the number is only given back once they have
        # really left the DOM, or the next message would mint duplicate ids.
        removals = [
            widget
            for widget_id in (
                f"q-{self._exchange}",
                f"work-{self._exchange}",
                f"sep-{self._exchange}",
            )
            for widget in self.query(f"#{widget_id}")
        ]
        for widget in removals:
            await widget.remove()
        # The removed separator took this exchange's activity rows with it; the
        # ids must go too, or the next run — which reuses this number and
        # restarts its sequence — would take them for rows already mounted.
        self._activity_rows = {
            row
            for row in self._activity_rows
            if not row.startswith(f"act-{self._exchange}-")
        }
        self._exchange -= 1
        # The number went back, so the pane must stop claiming it.
        self.query_one("#activity", VerticalScroll).border_subtitle = (
            self._activity_marker(self._exchange) if self._exchange > 0 else ""
        )
        if reply:
            self._say(partial(self._declined_block, reply))
            self._end_exchange()
            self.notify(
                "The agent declined that one without examining the evidence.",
                title="not investigated",
            )
            return
        self.notify(note or "Nothing ran for that input.", title="nothing to investigate")

    def _declined_block(self, reply: str) -> Text:
        """The model's own decline, kept readable but unnumbered."""

        block = Text()
        block.append(
            f"{M.GLYPH_POINT} Declined. No message number was spent\n",
            style=M.DIM_BRIGHT,
        )
        for line in reply.strip().splitlines()[:8]:
            block.append(line + "\n", style=M.DIM)
        return block

    def _render_error(self, message: str) -> None:
        self.running = False
        self.query_one("#evidence-pane").border_subtitle = ""
        self.query_one("#guardrails-pane").border_subtitle = ""
        self._remove_working_line()
        self.notify(message, severity="error", title="that run did not finish")

    def _render_run_fault(self, error: BaseException) -> None:
        """Something in this program raised, and it is reported as exactly that.

        A run that examines the evidence and publishes no finding never reaches
        here: the session catches that case and narrates it as an outcome, which
        is what it is. What is left is a genuine fault, and the words say so
        rather than leaving the operator to work out whether they hit a limit or
        found a bug.

        ``repr`` is not what an operator reads. The exception type is kept
        because it is the one part a bug report needs, and the message follows
        it in the words the exception was raised with, not in Python's quoting.
        """

        if isinstance(error, self._incomplete_examination_type()):
            # Defensive: the session owns this case and renders it properly. If
            # one ever escapes, it must not arrive dressed as a crash.
            self._render_error(
                "The run finished without a publishable finding. That is an "
                "outcome of the investigation, not a fault in this program."
            )
            return
        detail = " ".join(str(error).split())[:240] or type(error).__name__
        self.running = False
        self.query_one("#evidence-pane").border_subtitle = ""
        self.query_one("#guardrails-pane").border_subtitle = ""
        self._remove_working_line()
        self.notify(
            f"{type(error).__name__}: {detail}",
            severity="error",
            title="this program raised, please report it",
        )

    @staticmethod
    def _incomplete_examination_type() -> type[BaseException]:
        """The unanswered-run exception, imported where it is compared.

        Named at call time rather than at module scope for the same reason the
        session names it there: the agent runtime must not be loaded to draw the
        console.
        """

        from forensic_agent.cli.controlled import IncompleteExaminationError

        return IncompleteExaminationError

    def _finalize_activity(self, result: InvestigationResult) -> None:
        """Settle each row's outcome, and add what the run recorded about it.

        The live feed can only say that a call ran and how long it took. The
        settled record adds the three things the row is missing: which outcome
        the call reached, what it actually read, and — when it did not simply
        succeed — the reason the tool gave."""

        scopes = _recorded_scopes(result)
        reasons = _recorded_reasons(result)
        # Paired by ORDER, never by number: the recorder's sequences (2, 7,
        # 12…) are not the feed's (1, 2, 3…), and indexing rows with them
        # settled the wrong rows on multi-call runs. Argument overlap
        # refines the order, because concurrent identical-shaped calls can
        # settle out of their recorded order.
        events = sorted(self._activity_log.items())
        ordered_cards = _pair_cards_to_events(
            [event for _seq, event in events],
            sorted(result.oversight, key=lambda entry: entry.sequence),
        )
        if len(events) != len(ordered_cards):
            return
        for (feed_sequence, event), card in zip(events, ordered_cards, strict=True):
            row_id = f"act-{self._exchange}-{feed_sequence}"
            if row_id not in self._activity_rows:
                continue
            try:
                row = self.query_one(f"#{row_id}", Static)
            except NoMatches:
                # Settling a row is decoration; a row that left the DOM must
                # never stop the answer from being written.
                continue
            _paint(
                row,
                partial(
                    _activity_row,
                    event,
                    status=card.outcome,
                    scope=scopes.get(card.sequence, ""),
                    arguments=card.arguments,
                    reason=_row_reason(card, reasons),
                ),
            )

    # -- conversation ----------------------------------------------------
    def _panel_width(self) -> int:
        """Message panels cap at a readable measure however wide the screen."""

        width = self.query_one("#conversation", VerticalScroll).content_size.width or 100
        return min(100, width)

    def _write_you(self, question: str) -> None:
        self._say(
            partial(self._you_bubble, question, self._exchange),
            widget_id=f"q-{self._exchange}",
        )
        # The animated working line follows on the left, where the answer
        # will land — the agent's typing indicator.
        self._say(self._working_line, widget_id=f"work-{self._exchange}")

    def _you_bubble(self, question: str, number: int) -> Table:
        # The operator's bubble sits on the right with its tail arrow, like
        # any chat: ▶ marks what you sent, ◀ marks what the agent answered.
        #
        # Both arrows are placed by hand inside their two-cell column rather
        # than left to the column's own alignment: the two columns sit on
        # opposite sides of the bubble, so one alignment there produces two
        # different gaps — the ▶ ended up flush against the border with a
        # spare cell behind it while the ◀ had its blank cell in front. The
        # pair has to agree on both axes, the gap and the row: the arrow marks
        # the row carrying the FIRST line of text, which is one row further
        # down in the answer bubble because that one is padded at the top.
        bubble_width = min(self._panel_width() - 2, max(24, len(question) + 6))
        bubble = Panel(
            Text(question, style=f"bold {M.TEXT}"),
            subtitle=Text(f"{number:02d} ", style=M.TEXT),
            subtitle_align="right",
            border_style=M.BORDER,
            box=box.ROUNDED,
            padding=(0, 2),
            width=bubble_width,
        )
        grid = Table.grid(expand=True)
        grid.add_column(ratio=1)
        grid.add_column()
        grid.add_column(width=2)
        grid.add_row(Text(""), bubble, Text("\n ▶", style=M.ACCENT))
        return grid

    def _write_agent(self, result: InvestigationResult) -> None:
        self._remove_working_line()
        self._say(partial(self._agent_bubble, result, self._exchange))
        # The run's own accounting, the way the line shell closed every
        # answer: what it cost in calls, findings, model requests and time.
        self._say(partial(self._run_counts, result.controls))
        if result.note:
            self._say(partial(self._result_note, result.note))

    def _end_exchange(self) -> None:
        """Close one exchange with the separator, written in ONE place.

        Every part of an exchange used to end itself: the answer wrote a blank
        row, the review queue wrote a second blank around its hint, the simple
        layout's inline activity wrote a third, and a cancelled run wrote one
        of its own. So the space between one exchange and the next was not a
        separator at all — it was the sum of whatever that exchange happened to
        produce, four rows after an answer with findings and two after an
        answer without any. The separator is one blank row, written here, after
        everything the exchange had to say, so the distance from the end of
        exchange N to the start of exchange N+1 is the same at every N by
        construction rather than by coincidence.
        """

        # Kept by reference and never by id. _end_exchange runs on more paths
        # than one per number — a discarded run ends its exchange too — and a
        # fixed id here would crash the console with DuplicateIds the first
        # time two of them met. This is the same reason the welcome banner is
        # reached through a reference.
        self._exchange_end[self._exchange] = self._say(Text(""))

    def _agent_bubble(self, result: InvestigationResult, number: int) -> Table:
        _glyph, verdict_colour, _word = _verdict(result.answer_source)
        # Orange means the check ran and could not confirm the answer. With
        # the final check switched off no answer can ever be confirmed, so
        # painting each one as a warning would only be noise: the bubble
        # keeps the console's answer colour.
        if verdict_colour == M.ORANGE:
            from forensic_agent.cli.controlled import _console_runs_the_final_check

            if not _console_runs_the_final_check():
                verdict_colour = M.SUCCESS
        # The finding, then its evidence under a heading the CONSOLE owns, in
        # the console's own palette. The same reading the line shell prints:
        # one implementation, so the two surfaces cannot label the same part of
        # an answer with two different words the way the model used to.
        from forensic_agent.cli.exchange_view import answer_renderable

        bubble = Panel(
            answer_renderable(
                result.answer_markdown,
                markdown=ThemedMarkdown,
                accent=M.ACCENT,
                dim=M.DIM,
            ),
            subtitle=Text(f"{number:02d} ", style=M.TEXT),
            subtitle_align="left",
            border_style=verdict_colour,
            box=box.ROUNDED,
            padding=(1, 2),
            width=self._panel_width() - 2,
        )
        grid = Table.grid(expand=True)
        grid.add_column(width=2)
        grid.add_column()
        grid.add_column(ratio=1)
        # Two blank lines, not one: this bubble is padded at the top, so its
        # first line of text is the third row and an arrow on the second row
        # would point at the padding.
        grid.add_row(Text("\n\n◀", style=verdict_colour), bubble, Text(""))
        return grid

    def _run_counts(self, controls) -> Text:
        counts = Text("  ")
        # A count nobody recorded is left out, not printed as "None". A
        # replayed exchange has no model-request count, because the number is
        # telemetry and telemetry only reaches disk when a run fails.
        parts = [
            f"{controls.tool_calls} tool calls",
            f"{controls.findings} findings",
        ]
        if controls.model_requests is not None:
            parts.append(f"{controls.model_requests} model requests")
        parts.append(format_duration(controls.elapsed_s))
        counts.append("   ".join(parts), style=M.DIM)
        return counts

    def _result_note(self, note: str) -> Text:
        return Text(note, style=M.ORANGE)

    # -- the instrument panes --------------------------------------------
    def _pane_hint(self, headline: str, hint: str) -> Text:
        """An empty pane's state: what it is, then how to reach it — no more."""

        # Translated here rather than at the call site, because this is the
        # recipe the widget keeps: a language switch re-runs it (see
        # _repaint_console) and the pane changes language in place, exactly
        # as a theme switch changes its colours.
        text = Text(justify="center")
        text.append(_t(headline), style=M.DIM_BRIGHT)
        text.append("\n\n")
        text.append(_t(hint), style=M.DIM)
        return text

    @staticmethod
    def _activity_marker(exchange: int) -> str:
        """The exchange the ACTIVITY pane is collecting for, as the digit keys
        name it."""

        return f"message {exchange:02d}"

    def _rest_panes(self) -> None:
        """Put the opening hint back in each instrument pane that has nothing.

        Guarded on the hint's own id as well as on the pane's content: a pane
        that is already resting has its hint mounted under a fixed id, and
        mounting a second one raises DuplicateIds and takes the console down.
        That could not happen while the only caller emptied every pane first;
        ``/new`` keeps the EVIDENCE pane, so the guard has to be true of a pane
        nobody emptied.
        """

        evidence = self.query_one("#evidence-pane", VerticalScroll)
        if not list(evidence.query(Collapsible)):
            # Only a pane with nothing in it is invited to fill itself; a pane
            # still holding accepted findings keeps the subtitle that says what
            # to do with them.
            evidence.border_subtitle = _t("You accept findings with v")
        for pane_id, hint_id, headline, detail in (
            (
                "#activity",
                "activity-hint",
                "Tool calls appear here as they run.",
                "Grouped per message.  Digit keys jump between them.",
            ),
            (
                "#evidence-pane",
                "evidence-hint",
                "Findings you accept become the case evidence.",
                "Press v to review.  Enter opens a detail.",
            ),
            (
                "#guardrails-pane",
                "guardrails-hint",
                "Each step needs the case's permission.",
                "Denials appear here.",
            ),
        ):
            pane = self.query_one(pane_id, VerticalScroll)
            resting = list(pane.query(f"#{hint_id}").results(Static))
            if list(pane.query(Collapsible)) or resting:
                continue
            pane.mount(
                _painted(
                    partial(self._pane_hint, headline, detail),
                    id=hint_id,
                    classes="pane-hint",
                )
            )

    def _begin_run_panes(self) -> None:
        """A new run continues the instruments — nothing is cleared away.

        From the second exchange on, a dim numbered separator marks where the
        new run starts in ACTIVITY and FINDINGS; the full history stays
        scrollable, exactly like the shell's scrollback.
        """

        pane = self.query_one("#activity", VerticalScroll)
        for hint in self.query("#activity-hint"):
            hint.remove()
        # Earlier groups stay open: every numbered exchange remains readable
        # in place, and the digit keys jump rather than unfold.
        group = Collapsible(
            Vertical(id=f"grp-{self._exchange}"),
            title=f"{self._exchange:02d}",
            collapsed=False,
            id=f"sep-{self._exchange}",
        )
        pane.mount(group)
        # The group's own header is the first line of a scrolling pane, and
        # every arriving row scrolls the pane to its end — so the number left
        # the top of the view as soon as the first call landed, which is
        # exactly when the operator starts needing to know which exchange
        # they are watching. The border carries it instead: a subtitle cannot
        # scroll away, and it names the exchange for the whole of its life.
        pane.border_subtitle = self._activity_marker(self._exchange)
        pane.scroll_end(animate=False)
        self._activity_log.clear()
        self._activity_rows.clear()
        self._current_call = ""
        self._current_args = ""

    def _findings_row(self, card: FindingCard, marked: bool) -> Table:
        row = Table.grid(expand=True, padding=(0, 1))
        row.add_column(width=1)
        row.add_column(no_wrap=True)
        row.add_column(ratio=1, no_wrap=True, overflow="ellipsis")
        row.add_column(justify="right", no_wrap=True)
        meta = Text()
        if card.records:
            meta.append(card.records, style=M.DIM)
        if card.coverage_complete is False:
            meta.append(f"  {M.GLYPH_WARN} more remains", style=M.ORANGE)
        # The label says what was examined; the summary says what was FOUND —
        # that is what separates this pane from ACTIVITY. The star is the
        # only mark: everything here was accepted by the operator.
        row.add_row(
            Text("★", style=M.ACCENT) if marked else Text(""),
            Text(card.display_label, style=f"bold {M.TEXT}"),
            Text(card.result_summary, style=M.DIM),
            meta,
        )
        return row

    def _queue_findings_review(self, result: InvestigationResult) -> None:
        """The tool never decides what is evidence — the operator reviews.

        Unreviewed findings survive across messages: the queue keeps each
        one tagged with its message number, review works through them
        oldest-first, and every message's hint line updates to say exactly
        how many of its findings still wait.
        """

        if not result.findings:
            return
        self._pending_review.extend(
            (self._exchange, card) for card in result.findings
        )
        self._review_stats[self._exchange] = [len(result.findings), 0]
        self._say(Text(""), widget_id=f"review-{self._exchange}")
        self._refresh_review_hints()

    def _refresh_review_hints(self) -> None:
        outstanding: dict[int, int] = {}
        for exchange, _card in self._pending_review:
            outstanding[exchange] = outstanding.get(exchange, 0) + 1
        for exchange, (total, accepted) in self._review_stats.items():
            remaining = outstanding.get(exchange, 0)
            line = Text()
            if remaining:
                line.append(
                    f"{remaining} of {total} findings to review, press ",
                    style=M.DIM_BRIGHT,
                )
                line.append("v", style=f"bold {M.ACCENT}")
            else:
                line.append(f"{M.GLYPH_OK} Review complete", style=M.SUCCESS)
                line.append(
                    f"   {accepted} of {total} accepted as evidence",
                    style=M.DIM_BRIGHT,
                )
            for widget in self.query(f"#review-{exchange}").results(Static):
                widget.update(line)

    async def _accept_finding(self, exchange: int, card: FindingCard) -> None:
        pane = self.query_one("#evidence-pane", VerticalScroll)
        for hint in self.query("#evidence-hint"):
            hint.remove()
        item = ListItem(_paint(Label(), partial(self._findings_row, card, True)))
        item.card = card  # type: ignore[attr-defined]
        self._evidence_cards.append(card)
        view = self._evidence_lists.get(exchange)
        if view is None:
            for previous in pane.query(Collapsible):
                previous.collapsed = True
            view = ListView(id=f"ev-{exchange}", classes="evidence-list")
            self._evidence_lists[exchange] = view
            await pane.mount(
                Collapsible(
                    view,
                    title=f"{exchange:02d}",
                    collapsed=False,
                    id=f"evgrp-{exchange}",
                )
            )
        await view.append(item)
        pane.scroll_end(animate=False)
        self.query_one("#evidence-pane").border_subtitle = "Enter detail   m twice removes"

    @work
    async def _review_findings(self) -> None:
        self._reviewing = True
        try:
            while self._pending_review:
                exchange, card = self._pending_review[0]
                verdict = await self.push_screen_wait(
                    ReviewScreen(
                        # One sentence, not a question mark stuck in front of
                        # a payload kind: the title has to read as the thing
                        # the operator is being asked.
                        f"Accept {card.display_label} as evidence?",
                        self._review_detail(card),
                        card=card,
                    )
                )
                if verdict is None:
                    break
                self._pending_review.pop(0)
                if verdict:
                    await self._accept_finding(exchange, card)
                    self._review_stats.setdefault(exchange, [0, 0])[1] += 1
                self._refresh_review_hints()
        finally:
            self._reviewing = False

    def copy_text(self, text: str, what: str) -> bool:
        """Put ``text`` on the operator's clipboard and say what happened.

        The transport is OSC 52: the sequence travels in the terminal's own
        output stream, so it works over SSH and out of this container, where
        there is no clipboard daemon, no X display and no host tool to call.
        What it cannot do is make a terminal that ignores the sequence honour
        it, and it carries no acknowledgement, so a copy that never arrives is
        indistinguishable from one that did — unless the console says which it
        believes it was. It says so either way, because the whole point of the
        key is to stop an examiner retyping a 64-character hash, and silently
        not copying it is the one outcome that wastes their time twice.
        """

        payload = (text or "").strip()
        if not payload:
            self.notify(f"{what} is empty; nothing was copied.", title="copy")
            return False
        refusal, caveat = _copy_obstacles(self._driver)
        if refusal:
            self.notify(
                f"{what} could not be copied — {refusal}.",
                title="copy",
                severity="warning",
                timeout=6,
            )
            return False
        self.copy_to_clipboard(payload)
        length = len(payload)
        unit = "character" if length == 1 else "characters"
        note = f"{what} copied — {length} {unit}."
        self.notify(
            f"{note}  {caveat}." if caveat else note,
            title="copy",
            severity="warning" if caveat else "information",
        )
        return True

    def action_review(self) -> None:
        if self._reviewing:
            # v reaches through the modal; a second worker would show the
            # same finding twice and misfile one verdict.
            return
        if not self._pending_review:
            self.notify("Nothing awaits review.", title="review")
            return
        self._review_findings()

    def action_mark(self) -> None:
        """Removing accepted evidence takes m twice on the same row.

        An accepted finding is part of the case's record; one stray
        keypress must not silently shorten it, so the first press only
        arms the removal and says so, and moving to another row disarms.
        """

        import time as _time

        view = self.focused if isinstance(self.focused, ListView) else None
        if view is None or "evidence-list" not in view.classes or view.index is None:
            self.notify("Select an evidence row first (press e).", title="evidence")
            return
        if view.index >= len(view.children):
            return
        item = view.children[view.index]
        card = getattr(item, "card", None)
        if card is None:
            return
        now = _time.monotonic()
        armed_item, armed_at = getattr(self, "_removal_armed", (None, -10.0))
        if armed_item is not item or now - armed_at > 3.5:
            self._removal_armed = (item, now)
            self.notify(
                f"Press m again to remove {card.display_label} from the evidence.",
                title="evidence",
                timeout=4,
            )
            return
        self._removal_armed = (None, -10.0)
        try:
            self._evidence_cards.remove(card)
        except ValueError:
            pass
        self.notify(
            f"{card.display_label} was removed from the evidence.",
            title="evidence",
            timeout=4,
        )

        async def _remove(view: ListView = view, item=item) -> None:
            await item.remove()
            # Direct child removal bypasses ListView's index upkeep; clamp so
            # the next m/Enter cannot index past the end.
            if view.children:
                view.index = min(view.index or 0, len(view.children) - 1)
            else:
                view.index = None

        self.run_worker(_remove(), exclusive=False)

    def _jump_group(
        self,
        pane_id: str,
        prefix: str,
        number: int,
        *,
        solo: bool = False,
    ) -> bool:
        """Open one numbered group in a pane, by the last digit of its number.

        One implementation for every pane that groups by exchange: the group's
        id carries the number, so the search is the same wherever it is asked.
        ``solo`` collapses the rest, which is what narrowing a pane to a single
        exchange means for a pane short enough that the others crowd it out.
        """

        try:
            pane = self.query_one(pane_id, VerticalScroll)
        except Exception:
            return False
        groups = []
        for widget in pane.query(Collapsible):
            identity = (widget.id or "")
            if not identity.startswith(prefix):
                continue
            identity = identity.removeprefix(prefix)
            if identity.isdigit():
                groups.append((int(identity), widget))
        target = None
        for value, widget in groups:
            if value % 10 == number:
                target = widget  # document order: the last match is newest
        if target is None:
            return False
        if solo:
            for _value, widget in groups:
                widget.collapsed = widget is not target
        target.collapsed = False
        pane.scroll_to_widget(target, top=True)
        return True

    def action_jump(self, number: int) -> None:
        """A digit jumps ACTIVITY to the newest message ending in that digit.

        Group titles are the message numbers (…08, 09, 10, 11…), so the key
        IS the number's last digit — with more than nine messages every one
        of the latest ten stays reachable (9 → 09, 0 → 10, 1 → 11), instead
        of nine fixed keys that strand everything past the ninth.

        GUARDRAILS follows the same key to the same exchange, and there it
        narrows: that pane is a few lines tall, so leaving every other
        exchange's decisions unfolded beside the chosen one is the same as not
        having narrowed at all. ACTIVITY keeps its scrollback, which is what it
        is for.
        """

        self._jump_group("#guardrails-pane", "guardsep-", number, solo=True)
        if self._jump_group("#activity", "sep-", number):
            self.query_one("#activity", VerticalScroll).focus()

    def _record_guardrail_facts(self, result: InvestigationResult) -> None:
        """Add this message's oversight record to what the case has said so far.

        Read off the cards rather than recomputed anywhere else, and read for
        the three things that actually differ between runs: what was refused,
        where the model guessed a location instead of following a finding, and
        which capabilities the run genuinely exercised. The last of those
        separates a disk case, where nearly every call only reads, from memory
        and network work, where nearly every call spawns an external tool.
        """

        for card in result.oversight:
            self._guardrail_checked_total += 1
            self._guardrail_caps.update(card.requested_caps)
            guessed_here = False
            for reason in card.reasons:
                text = str(reason)
                if not text.startswith("ungrounded-path:"):
                    continue
                guessed_here = True
                key, _, value = text[len("ungrounded-path:"):].partition("=")
                pair = (key, value)
                # Distinct locations, in the order they were first guessed. The
                # same path asked for twice is one thing to look at, not two.
                if pair not in self._guardrail_guessed:
                    self._guardrail_guessed.append(pair)
            if guessed_here:
                self._guardrail_guessed_calls += 1

    def _refresh_guardrail_summary(self) -> None:
        """Redraw the standing summary, and say on the frame what is in it."""

        pane = self.query_one("#guardrails-pane", VerticalScroll)
        for hint in self.query("#guardrails-hint"):
            hint.remove()
        for allclear in self.query("#guardrails-allclear"):
            allclear.remove()
        mounted = list(self.query("#guardrails-summary").results(Static))
        if mounted:
            _paint(mounted[0], self._guardrail_summary)
        else:
            summary = _painted(self._guardrail_summary, id="guardrails-summary")
            if pane.children:
                pane.mount(summary, before=pane.children[0])
            else:
                pane.mount(summary)
        # The counts go on the frame as well as in the body: the pane is a few
        # rows tall and scrolls, and the one thing that must not scroll away is
        # how much there is.
        marks: list[str] = []
        if self._guardrail_refusals:
            marks.append(f"{len(self._guardrail_refusals)} refused")
        if self._guardrail_guessed_calls:
            marks.append(f"{self._guardrail_guessed_calls} guessed")
        pane.border_subtitle = "  ".join(marks)

    def _populate_guardrails(self, result: InvestigationResult) -> None:
        """What this case's oversight record says, led by whatever varied.

        The pane opens with a standing summary rewritten each message, and
        keeps the denials themselves below it: one row per refusal, grouped per
        message, expanding to the full arguments, the capabilities it wanted and
        every recorded reason.
        """

        pane = self.query_one("#guardrails-pane", VerticalScroll)
        blocked = [
            o for o in result.oversight if o.outcome == M.OUTCOME_REFUSED_BY_OVERSIGHT
        ]
        self._guardrail_allowed_total += max(0, len(result.oversight) - len(blocked))
        self._guardrail_refusals.extend(blocked)
        self._record_guardrail_facts(result)
        if result.oversight:
            self._refresh_guardrail_summary()
        if not blocked:
            return
        if result.oversight and not self._guardrail_blocks:
            granted = result.oversight[0].granted_caps
            if granted:
                pane.mount(_painted(partial(self._authority_line, granted)))
                self._guardrail_blocks.append("authority")
        denial_rows = [
            Collapsible(
                _painted(partial(self._denial_detail, card)),
                title=f"{M.GLYPH_ERROR} {card.function}.{card.operation}",
                collapsed=True,
                classes="denial",
            )
            for card in blocked
        ]
        group_body = self._guardrail_groups.get(self._exchange)
        if group_body is None:
            for previous in pane.query(Collapsible):
                previous.collapsed = True
            group_body = Vertical(*denial_rows, id=f"guardgrp-{self._exchange}")
            self._guardrail_groups[self._exchange] = group_body
            pane.mount(
                Collapsible(
                    group_body,
                    title=f"{self._exchange:02d}",
                    collapsed=False,
                    # Ided like ACTIVITY's own groups, so the digit keys can
                    # narrow this pane to one exchange through exactly the
                    # mechanism that pane already uses.
                    id=f"guardsep-{self._exchange}",
                )
            )
        else:
            for row in denial_rows:
                if group_body.is_mounted:
                    group_body.mount(row)
                else:
                    self.call_after_refresh(group_body.mount, row)
        pane.scroll_end(animate=False)

    #: Refusal codes in the words an examiner would use. The vocabulary is the
    #: oversight layer's own (``outcome_detail``); nothing is invented here and
    #: an unknown code is shown as itself rather than guessed at, because a
    #: panel that paraphrases a code it does not know is a panel that will one
    #: day paraphrase it wrongly.
    _REFUSAL_WORDS: ClassVar[dict[str, str]] = {
        "invalid_operation_arguments": (
            "arguments the operation does not accept"
        ),
        "ungrounded_path": "a path not grounded in an earlier finding",
        "evidence_source_integrity_violation": (
            "an evidence source that did not match its recorded digest"
        ),
        "repeated_deterministic_tool_error": (
            "a call that had already failed the same way"
        ),
    }

    #: How many guessed paths the pane names before it stops listing them. The
    #: rest are counted, not hidden: on one measured run this advisory fired
    #: 187 times in 312 calls, and a pane that tried to list all of them would
    #: be a log rather than a panel.
    _GUESSED_PATHS_SHOWN = 6

    def _refusal_words(self, card: OversightCard) -> str:
        """Why this call was refused, in words, from what was recorded."""

        code = (card.outcome_detail or "").strip()
        if code in self._REFUSAL_WORDS:
            return self._REFUSAL_WORDS[code]
        if code:
            return code.replace("_", " ")
        for reason in card.reasons:
            text = str(reason)
            head, _, tail = text.partition(":")
            if head == "invalid-arguments" and tail in self._REFUSAL_WORDS:
                return self._REFUSAL_WORDS[tail]
        return "a reason the record does not name"

    def _guardrail_lead(self) -> Text:
        """The one line the pane leads with, chosen by what actually varied.

        The pane used to lead with "All N steps were allowed" whatever had
        happened, and that sentence is true in almost every run: across 506
        recorded calls on one case, 13 were refused, none for a capability,
        none for a path outside the case roots, and nothing was ever classified
        above low risk. A line that is nearly always the same carries nothing.

        So the lead is whichever of the three states the record is actually in,
        strongest first, and it says what was refused rather than implying what
        was repelled. What this layer stopped were malformed calls; a panel that
        let that read as an intrusion would misdescribe the system it reports on.
        """

        line = Text()
        if self._guardrail_refusals:
            count = len(self._guardrail_refusals)
            words = Counter(
                self._refusal_words(card) for card in self._guardrail_refusals
            )
            reason, dominant = words.most_common(1)[0]
            line.append(f"{M.GLYPH_ERROR} ", style=M.RED)
            line.append(
                f"{count} call{'' if count == 1 else 's'} refused", style=f"bold {M.RED}"
            )
            line.append(
                f"  {reason}" if dominant == count else f"  mostly {reason}",
                style=M.TEXT,
            )
            return line
        if self._guardrail_guessed_calls:
            calls = self._guardrail_guessed_calls
            line.append(f"{M.GLYPH_WARN} ", style=M.ORANGE)
            # The qualifier is deliberately NOT appended here. This pane is a
            # third of a narrow column, and a lead that wraps mid-phrase reads
            # as two half-sentences; what follows it says "allowed" plainly.
            line.append(
                f"{calls} of {self._guardrail_checked_total} calls guessed a location",
                style=f"bold {M.ORANGE}",
            )
            return line
        checked = self._guardrail_checked_total
        noun = "step" if checked == 1 else "steps"
        line.append(f"{M.GLYPH_OK} ", style=M.SUCCESS)
        line.append(f"Nothing was stopped in {checked} checked {noun}", style=M.SUCCESS)
        return line

    def _guardrail_summary(self) -> RenderableType:
        """The lead, then only what the lead did not already say.

        Quiet by construction. A run with nothing notable in it gets one line
        and gives the rest of the pane back, because the pane is read for what
        varies and there is nothing here that does.
        """

        blocks: list[RenderableType] = [self._guardrail_lead()]
        if self._guardrail_guessed and self._guardrail_refusals:
            # The refusals took the lead, so the advisory says its own count
            # here instead of going unmentioned.
            calls = self._guardrail_guessed_calls
            note = Text()
            note.append(f"{M.GLYPH_WARN} ", style=M.ORANGE)
            note.append(
                f"{calls} call{'' if calls == 1 else 's'} also guessed a location",
                style=M.ORANGE,
            )
            blocks.append(note)
        if self._guardrail_guessed:
            explanation = Text(
                "A guessed location is one the model asked for without an "
                "earlier finding placing it there. Nothing was blocked.",
                style=M.DIM,
            )
            blocks.append(explanation)
            shown = self._guardrail_guessed[: self._GUESSED_PATHS_SHOWN]
            for key, value in shown:
                row = Text(no_wrap=True, overflow="ellipsis")
                row.append("   ", style=M.DIM)
                row.append(f"{key}=", style=M.DIM)
                row.append(value, style=M.DIM_BRIGHT)
                blocks.append(row)
            remaining = len(self._guardrail_guessed) - len(shown)
            if remaining > 0:
                blocks.append(
                    Text(f"   {remaining} more", style=M.DIM)
                )
        if self._guardrail_caps:
            used = Text(no_wrap=True, overflow="ellipsis")
            used.append("exercised  ", style=M.DIM)
            used.append(
                "  ".join(
                    cap.replace("_", " ") for cap in sorted(self._guardrail_caps)
                ),
                style=M.DIM_BRIGHT,
            )
            blocks.append(used)
        return blocks[0] if len(blocks) == 1 else Group(*blocks)

    def _allclear_line(self) -> Text:
        steps = self._guardrail_allowed_total
        noun = "step" if steps == 1 else "steps"
        line = Text(justify="center")
        line.append(f"{M.GLYPH_OK} ", style=M.SUCCESS)
        line.append(f"All {steps} {noun} so far were allowed", style=M.SUCCESS)
        return line

    def _authority_line(self, granted: tuple[str, ...]) -> Text:
        allowed = Text()
        allowed.append("This case allows  ", style=M.DIM)
        allowed.append("  ".join(cap.replace("_", " ") for cap in granted), style=M.TEXT)
        return allowed

    def _denial_detail(self, card: OversightCard) -> Group:
        """A refused call, cause first.

        The recorded ``reasons`` list mixes two kinds of entry and puts the
        deciding one LAST, so a short pane truncated away the only line that
        said why. Worse, the describing entries — "writes to host disk",
        "spawns external process" — are written by ``evaluate()`` only where it
        PERMITTED the call, so leading with them under a ✗ told the reader the
        opposite of what happened. The record is untouched: this reorders and
        restyles it at render time, and drops nothing.
        """

        from forensic_agent.oversight.policy import partition_reasons

        deciding, describing = partition_reasons(card.reasons)
        detail: list = []
        # The refusing layer's own sentence, which is where the tool's schema
        # actually reached.
        shown: set[str] = set()
        for line in card.refusal_message.splitlines():
            text = line.strip()
            if text:
                detail.append(Text(text, style=M.RED))
                shown.add(text)
        for reason in deciding:
            # The record now LEADS with that same sentence, so the two sources
            # overlap by exactly the line that matters and printing both put the
            # cause on screen twice. The reason list is still the fallback for a
            # refusal that recorded no readable sentence at all.
            if str(reason).strip() in shown:
                continue
            detail.append(Text(str(reason), style=M.RED))
        if not detail:
            # Nothing named a ground. Say so, rather than opening with a
            # capability description that reads like one.
            detail.append(Text("no ground recorded for this refusal", style=M.RED))
        for name, value in card.arguments:
            argument = Text()
            argument.append(f"{name}=", style=M.DIM)
            argument.append(str(value), style=M.TEXT)
            detail.append(argument)
        if card.requested_caps:
            wanted = Text()
            wanted.append("wanted  ", style=M.DIM)
            wanted.append(
                "  ".join(cap.replace("_", " ") for cap in card.requested_caps),
                style=M.DIM,
            )
            detail.append(wanted)
        # Below the cause and subdued: what the tool WOULD have done, which is
        # a description of its authority and never the ground of a refusal.
        detail.extend(Text(str(reason), style=M.DIM) for reason in describing)
        return Group(*detail)

    # -- overlays (details on demand) ------------------------------------
    @on(ListView.Selected, ".evidence-list")
    def _evidence_selected(self, event: ListView.Selected) -> None:
        card = getattr(event.item, "card", None)
        if card is not None:
            self.push_screen(
                OverlayScreen(
                    card.display_label, self._review_detail(card), card=card
                )
            )

    # An accepted row's Enter opens _review_detail — the FULL record (the
    # exact command, its arguments, coverage, the recorded records and the
    # complete provenance receipt). A thinner summary popup used to live
    # here; two depths for one card only taught operators the pane hides
    # things.
    def _examined(self, card: FindingCard) -> str:
        """What one call looked at, named the way the operator would name it.

        The call's own target argument when it has one — a registry key, a log,
        a path — because that is narrower than the source and is what the
        reviewer is checking. When the call took no such argument, the thing it
        looked at is the whole evidence source, and the source has a NAME:
        ``promet.pcap``, the one already on the Session panel. "the evidence
        source" was a placeholder standing where that name belongs.

        The source is chosen by the kind of evidence the finding's own data
        type belongs to (``network.…`` from the capture, ``memory.…`` from the
        memory image, everything else from the disk), so a case with all three
        attached still names the right one. A case with exactly one source
        attached needs no matching at all.
        """

        target = _target_argument(card.arguments)
        # A target that only repeats the operation names nothing new: the call
        # is already "pcap_query.dns", and "pcap_query.dns examined dns" is the
        # placeholder over again in a different costume.
        if target and target.casefold() != (card.operation or "").casefold():
            return target
        try:
            sources = tuple(self._controller.status().evidence_sources)
        except Exception:
            sources = ()
        if not sources:
            return ""
        named = [
            (kind.strip(), (name or source).strip())
            for source in sources
            for kind, _, name in (source.partition(": "),)
        ]
        if len(named) == 1:
            return named[0][1]
        domain = (card.data_type or "").split(".")[0].casefold()
        wanted = {"network": "network", "memory": "memory"}.get(domain, "disk")
        for kind, name in named:
            if kind.casefold() == wanted:
                return name
        return ""

    def _review_detail(self, card: FindingCard):
        """Everything the record holds about one finding, in readable sections.

        The reviewer decides whether this is evidence; that takes the full
        result, the exact command in one unbroken line, the coverage with
        its reason, the recorded records themselves, and the complete
        provenance receipt.

        One colour rule holds across the whole card, and it is the opposite of
        the one it replaces: **names are ACCENT, everything that carries
        information is TEXT, and nothing a reviewer has to read is dim.** The
        call name, the section headings, the argument names and the table's
        column headings are names; the values, the counts, the sentences, the
        digests and the receipt are information. The only other colour on the
        card is the coverage verdict's own status colour, which is a signal
        rather than emphasis. Before this, ``examined`` was dim inside an
        otherwise bright line, record keys were dim while their values were
        bright, and a value that happened to follow an ``=`` went bright again;
        three conventions in one card is none.
        """

        # An unrecognised status keeps the reading colour rather than dropping
        # to DIM: the · glyph already says the status was never established,
        # and the rule this card holds to is that nothing a reviewer reads is
        # dim, a status among the rest of it.
        glyph, colour = M.STATUS_STYLE.get(card.status, (M.GLYPH_UNKNOWN, M.TEXT))
        parts: list = []

        # The reader's first line is the finding in words, not machinery: which
        # call looked at what, and what it brought back — one sentence, because
        # "It recorded 44/179 records." on a line of its own is a fragment
        # whose subject is on the line above. The hashes below only certify
        # this; they never explain it.
        examined = self._examined(card)
        deed = Text()
        deed.append_text(_call_name(card.function, card.operation))
        deed.append(" examined ", style=M.TEXT)
        deed.append(examined or "the evidence source", style=f"bold {M.TEXT}")
        recorded = (card.records or "").strip()
        if recorded.startswith("0"):
            deed.append(" and recorded no entries.", style=M.TEXT)
            parts.append(deed)
            parts.append(
                Text(
                    "The empty result is itself the finding: the tool looked, "
                    "and there was nothing there to report.",
                    style=M.TEXT,
                )
            )
        elif recorded:
            deed.append(f" and {_recorded_clause(recorded)}.", style=M.TEXT)
            parts.append(deed)
        else:
            deed.append(".", style=M.TEXT)
            parts.append(deed)

        args_join = "  ".join(f"{name}={value}" for name, value in card.arguments)
        summary = (card.result_summary or "").strip()
        if summary and summary != args_join:
            parts.append(Text(summary, style=f"bold {M.TEXT}"))

        parts.append(Text(""))
        parts.append(_section_heading("command"))
        # fold, never elide: an argument may be one unbroken path, and the
        # reviewer has to be able to read and copy all of it.
        command = Text(overflow="fold")
        command.append_text(_call_name(card.function, card.operation))
        for name, value in card.arguments:
            command.append(f"  {name}=", style=M.ACCENT)
            command.append(str(value), style=M.TEXT)
        parts.append(_section_body(command))

        parts.append(Text(""))
        parts.append(_section_heading("coverage"))
        coverage = Text()
        coverage.append(f"{glyph} ", style=colour)
        if card.coverage_complete is None:
            coverage_style = M.TEXT
        else:
            coverage_style = M.SUCCESS if card.coverage_complete else M.ORANGE
        # The scope is what was read; when the record states one it is the
        # subject of the sentence, and "✓ read in full" stops being a phrase
        # with no object. A scope that says something the source name does not
        # still gets its own line beneath.
        scope = (card.coverage_scope or "").strip()
        subject = scope or examined
        coverage.append(_plain_coverage(card, subject), style=coverage_style)
        coverage_lines: list[RenderableType] = [coverage]
        if scope and scope != subject:
            coverage_lines.append(Text(scope, style=M.TEXT))
        parts.append(_section_body(*coverage_lines))

        records = None
        try:
            records = self._controller.finding_records(card)
        except Exception:
            records = None
        rows, columns, attributes, tables = _recorded_table_parts(records)
        if rows or attributes or tables:
            parts.append(Text(""))
            # The count is of the recorded rows, and this block also renders
            # the call's other recorded attributes, which are not rows and are
            # not counted. A call that recorded attributes but no rows
            # therefore printed "recorded records (0)" directly above a screen
            # of them, which reads as the console contradicting itself. Where
            # there is nothing to count, the heading says what is there instead.
            parts.append(
                _section_heading(
                    f"recorded records ({len(rows)})"
                    if rows
                    else "what this call recorded"
                )
            )
            record_lines: list[RenderableType] = []
            for attribute_name, attribute_value in list(attributes.items())[:12]:
                attribute = Text(overflow="fold")
                attribute.append(f"{attribute_name}=", style=M.ACCENT)
                attribute.append(str(attribute_value), style=M.TEXT)
                record_lines.append(attribute)
            if rows:
                if attributes:
                    record_lines.append(Text(""))
                record_lines.append(_records_table(rows, columns))
                record_lines.extend(_table_overflow_note(len(rows)))
            for table_name, table_rows, table_columns in tables:
                record_lines.append(Text(""))
                label = Text()
                label.append(f"{table_name} ", style=f"bold {M.ACCENT}")
                label.append(f"({len(table_rows)})", style=M.TEXT)
                record_lines.append(label)
                record_lines.append(_records_table(table_rows, table_columns))
                record_lines.extend(_table_overflow_note(len(table_rows)))
            parts.append(_section_body(*record_lines))

        parts.append(Text(""))
        parts.append(_section_heading("where this came from"))
        provenance_lines: list[RenderableType] = []
        # The bundle identifier and the same bundle as a URI are two long
        # strings that look alike, so they are introduced before they are
        # printed. A run that recorded no bundle prints neither them nor the
        # lead: a bare label above two hashes explains nothing.
        bundle = card.source_id.strip()
        if bundle or card.source_uri:
            provenance_lines.append(
                Text(
                    "Read from the case evidence bundle, named below by its "
                    "digest and again as a URI.",
                    style=M.TEXT,
                )
            )
        # Folded, never elided: these are one long token each, and a reviewer
        # checking the record needs every character of them.
        if bundle:
            provenance_lines.append(Text(bundle, style=M.TEXT, overflow="fold"))
        if card.source_uri:
            provenance_lines.append(Text(card.source_uri, style=M.TEXT, overflow="fold"))
        receipt = Text(overflow="fold")
        receipt.append("receipt ", style=M.ACCENT)
        receipt.append(card.receipt_full, style=M.TEXT)
        provenance_lines.append(receipt)
        provenance_lines.append(
            Text(
                "The receipt is the SHA-256 fingerprint of this result. If "
                "it is ever recomputed and comes out different, the result "
                "was changed after it was written.",
                style=M.TEXT,
            )
        )
        parts.append(_section_body(*provenance_lines))

        message_parts: list[RenderableType] = []
        if card.coverage_reason:
            message_parts.append(Text(card.coverage_reason, style=M.TEXT))
        for warning in card.warnings:
            message_parts.append(Text(str(warning), style=M.ORANGE))
        if message_parts:
            parts.append(Text(""))
            parts.append(_section_heading("tool message"))
            parts.append(_section_body(*message_parts))

        return Group(*parts)

    def action_guardrails(self) -> None:
        result = self._last_result
        blocked = (
            [o for o in result.oversight if o.outcome == M.OUTCOME_REFUSED_BY_OVERSIGHT]
            if result
            else []
        )
        lines: list = [
            Text("Guardrails keep the agent inside what this case allows.", style=M.TEXT),
            Text(""),
        ]
        if blocked:
            for card in blocked:
                row = Text()
                row.append(f"{M.GLYPH_ERROR} ", style=M.RED)
                row.append(f"It tried to {_blocked_action(card)}. ", style=M.TEXT)
                row.append("Not allowed here, so it was stopped.", style=M.DIM_BRIGHT)
                lines.append(row)
            lines.append(Text(""))
            lines.append(Text(f"{M.GLYPH_OK} Everything else it did was allowed.", style=M.SUCCESS))
        elif result and result.oversight:
            lines.append(Text(f"{M.GLYPH_OK} Every step was allowed. Nothing was stopped.", style=M.SUCCESS))
        else:
            lines.append(Text("Send a message first, then this shows what was allowed.", style=M.DIM))
        self.push_screen(OverlayScreen("Guardrails", Group(*lines)))

    def action_help(self) -> None:
        from forensic_agent.cli.commands import COMMAND_REGISTRY

        keys = Table.grid(padding=(0, 2))
        keys.add_column(style=M.ACCENT, justify="right")
        keys.add_column(style=M.TEXT)
        for key, what in (
            ("e", "the accepted evidence — opens the selected finding's detail"),
            ("a", "the live activity feed — every tool call as it runs"),
            ("g", "what the safety layer allowed or blocked (Guardrails)"),
            ("?", "this help"),
            ("q", "quit"),
            ("Enter", "send your message"),
            ("Esc", "switch between typing and browsing"),
            ("Ctrl+P", "search the full command list"),
        ):
            keys.add_row(key, what)

        terms = Table.grid(padding=(0, 2))
        terms.add_column(style=M.SUCCESS, justify="right")
        terms.add_column(style=M.TEXT)
        for term, meaning in (
            ("grounded", "the answer is backed by evidence the agent actually read"),
            ("unverified", "the agent could not confirm the answer against evidence"),
            ("blocked", "the safety layer stopped a step"),
            ("partly read", "the agent read only part of a source; more remains"),
            ("receipt", "a short fingerprint of the exact data, so a result can be re-checked"),
        ):
            terms.add_row(term, meaning)

        run = Table.grid(padding=(0, 2))
        run.add_column(style=M.DIM, justify="right")
        run.add_column(style=M.TEXT)
        status = self._status
        run.add_row("model", f"{status.model}  {status.provider}")
        run.add_row("reasoning", status.reasoning_effort)
        run.add_row(
            "limits per message",
            f"{format_duration(status.max_wall_time_s)}   "
            f"{status.max_steps} steps   {status.max_tool_calls} tool-calls   "
            f"{status.max_model_requests} model-requests",
        )
        if self._last_result is not None:
            c = self._last_result.controls
            run.add_row("last run", f"{c.tool_calls} steps   {c.findings} findings   trace {c.trace_id}")

        body = Group(
            Text("dfir-agent — a forensic assistant with a built-in safety layer.", style=M.TEXT),
            Text(""),
            Rule("keys", style=M.BORDER, align="left"),
            keys,
            Text(""),
            Rule("what the words mean", style=M.BORDER, align="left"),
            terms,
            Text(""),
            Rule("this run", style=M.BORDER, align="left"),
            run,
            Text(""),
            Rule("full command list (Ctrl+P)", style=M.BORDER, align="left"),
            Text(COMMAND_REGISTRY.help_text(title="commands"), style=M.DIM),
        )
        self.push_screen(OverlayScreen("Help", body))

    # -- focus / lifecycle actions ---------------------------------------
    def action_evidence(self) -> None:
        """One press shows the thing, the way g shows Guardrails.

        e unfolds the newest evidence group, focuses its list AND opens the
        selected row's detail at once; Esc lands back on the focused list,
        where the arrows browse, Enter reopens a detail and m removes.
        """

        lists = list(self.query(".evidence-list").results(ListView))
        if not lists:
            # Nothing accepted yet — but the key must still ANSWER, the way
            # g answers with an empty Guardrails: say what this pane is and
            # what stands between the operator and its first row.
            self._evidence_empty_overlay()
            self.query_one("#evidence-pane", VerticalScroll).focus()
            return
        view = lists[-1]
        for group in self.query(f"#evgrp-{view.id.split('-')[-1] if view.id else ''}").results(Collapsible):
            group.collapsed = False
        view.focus()
        if view.index is None and view.children:
            view.index = 0
        card = None
        if view.index is not None and view.index < len(view.children):
            card = getattr(view.children[view.index], "card", None)
        if card is not None:
            self.push_screen(
                OverlayScreen(
                    card.display_label, self._review_detail(card), card=card
                )
            )
        else:
            # A list emptied with m answers the same way as no list at all.
            self._evidence_empty_overlay()

    def _evidence_empty_overlay(self) -> None:
        pending = len(self._pending_review)
        lines: list = [
            Text(
                "Findings become evidence only when you accept them.",
                style=M.TEXT,
            ),
            Text(""),
        ]
        if pending:
            waiting = Text()
            waiting.append(
                f"{pending} finding{'' if pending == 1 else 's'} to review. Press ",
                style=M.DIM_BRIGHT,
            )
            waiting.append("v", style=f"bold {M.ACCENT}")
            waiting.append(".", style=M.DIM_BRIGHT)
            lines.append(waiting)
        else:
            lines.append(
                Text(
                    "Findings appear after a message runs; review them "
                    "with v and the accepted ones are kept here.",
                    style=M.DIM,
                )
            )
        self.push_screen(OverlayScreen("Evidence", Group(*lines)))

    def _activity_block(self) -> RenderableType:
        """Every call the feed has recorded, as one block, newest exchange last.

        Read off the rows already on screen rather than from a second copy of
        the feed: ``_activity_log`` holds the exchange in flight and is emptied
        between messages, so a record built from it would show the newest
        message and nothing before it. The rows carry their own recipe (see
        :func:`_painted`), so re-running it draws them in the palette in force
        now, at the width the drawer gives them rather than the pane's.

        Built when the key is pressed and not before: a feed of several hundred
        rows costs nothing until somebody asks to read it whole.
        """

        try:
            pane = self.query_one("#activity", VerticalScroll)
        except NoMatches:
            # The simple layout has no pane; its rows are in the transcript.
            return Text(
                "This layout writes the activity into the conversation itself, "
                "under each answer. /layout full puts it back in a pane.",
                style=M.TEXT,
            )
        blocks: list[RenderableType] = []
        exchange = ""
        for row in pane.query(Static).results(Static):
            identifier = row.id or ""
            if not identifier.startswith("act-"):
                continue
            parts = identifier.split("-")
            if len(parts) > 1 and parts[1] != exchange:
                exchange = parts[1]
                if blocks:
                    blocks.append(Text(""))
                blocks.append(
                    Rule(
                        Text(f"MESSAGE {exchange}", style=f"bold {M.ACCENT}"),
                        style=M.BORDER,
                        align="left",
                    )
                )
            # The recipe when the row has one, so the drawer draws it in the
            # palette in force now; otherwise whatever the row was built from.
            # Read through getattr because a colourless row is a plain Static
            # and carries no recipe at all.
            build = getattr(row, "_dfir_build", None)
            if callable(build):
                blocks.append(build())
                continue
            drawn = getattr(row, "_renderable", None)
            if drawn is not None:
                blocks.append(cast(RenderableType, drawn))
        if not blocks:
            return Text(
                "Every tool call the agent makes lands here as it runs, "
                "grouped per message. Send a message first.",
                style=M.TEXT,
            )
        return Group(*blocks)

    def action_activity(self) -> None:
        """a opens the whole feed, the way g opens Guardrails and e evidence.

        The three panes answer their key the same way: the key shows the thing,
        expanded, in a drawer that scrolls and closes on Esc. This one used to
        do half of that — it unfolded the newest group in the pane and focused
        it, so the feed could be read only through a pane a few rows tall, and
        only one message at a time. The pane is still unfolded and focused, so
        Esc lands the operator where the arrows browse, exactly as e does.
        """

        self.push_screen(
            OverlayScreen("Activity", self._activity_block(), wide=True)
        )
        try:
            pane = self.query_one("#activity", VerticalScroll)
        except NoMatches:
            return
        groups = list(pane.query(Collapsible))
        if groups:
            groups[-1].collapsed = False
        pane.scroll_end(animate=False)
        titles = list(pane.query("CollapsibleTitle"))
        if titles:
            titles[-1].focus()
        else:
            pane.focus()

    def action_transcript(self) -> None:
        self.query_one("#conversation", VerticalScroll).focus()

    def action_ask(self) -> None:
        self.query_one("#prompt", Input).focus()

    def action_browse(self) -> None:
        prompt = self.query_one("#prompt", Input)
        if prompt.has_focus:
            self.query_one("#conversation", VerticalScroll).focus()
        else:
            prompt.focus()

    async def action_clear(
        self, with_status: bool = True, *, say_pending: bool = True
    ) -> None:
        """/clear wipes the chat and nothing else.

        ACTIVITY, EVIDENCE and GUARDRAILS keep their full history, the session
        keeps its investigation history, and the next message continues from
        the number where the chat left off — clearing the scrollback never
        rewrites the investigation. That is the whole difference from ``/new``,
        which starts a new history and empties the instruments to match, and it
        is why the one line ``/clear`` can lose is put back below: the review
        hints live in the conversation, so clearing the screen took the only
        statement that findings were still waiting with it, while the findings
        themselves stayed in the queue.

        (remove_children is deferred; the welcome must wait for it or the
        fresh #banner collides with the one still being unmounted.)
        """

        await self.query_one("#conversation", VerticalScroll).remove_children()
        self._welcome(with_status=with_status)
        if say_pending and self._pending_review:
            self._say(partial(self._still_awaiting_note, len(self._pending_review)))
            self._end_exchange()
        self.query_one("#prompt", Input).focus()

    def _still_awaiting_note(self, waiting: int) -> Text:
        note = Text()
        note.append(f"{M.GLYPH_POINT} ", style=M.ACCENT)
        note.append(
            f"{waiting} finding{'' if waiting == 1 else 's'} from the cleared "
            "screen are still awaiting review — press ",
            style=M.TEXT,
        )
        note.append("v", style=f"bold {M.ACCENT}")
        return note

    # Synchronous by design: Textual runs a bound action through
    # ``await_me_maybe``, while ``App.action_quit`` is declared async.
    def action_quit(self) -> None:  # type: ignore[override]
        """Quitting takes two presses within two seconds, like the shell."""

        import time

        now = time.monotonic()
        if now - self._quit_armed_at < 2.0:
            self.exit()
            return
        self._quit_armed_at = now
        self.notify("Press again to quit.", title="quit", timeout=2)


class _SelectionCancelled(Exception):
    """The operator backed out of a multi-source case selection."""


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value
