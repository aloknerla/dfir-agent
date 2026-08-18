"""Puni popis naredbi koje je model izveo tijekom jednog izvođenja.

Traka aktivnosti krati poziv jer mora stati u jedan redak dok istraga još
teče. Za provjeru nakon izvođenja to nije dovoljno: operater koji utvrđuje što
je model doista pokrenuo mora vidjeti cijeli poziv — funkciju, operaciju i
svaku vrijednost argumenta onako kako ju je model poslao. Zato /oversight calls
čita iste zapise koje je izvođenje već upisalo u oversight.jsonl i ispisuje ih
bez skraćivanja; ništa se pritom ne zapisuje niti mijenja.

Testovi štite ono što razlikuje nadzor od dojma nadzora: nijedna vrijednost
nije tiho odrezana, odbijen poziv se vidi kao odbijen, vrijednost čije ime nosi
tajnu se uskraćuje umjesto da se ispiše, a tehnički identifikatori ostaju
bajtovno isti na oba jezika dok se oznake prevode.
"""

from __future__ import annotations

import io
import json
import types
from pathlib import Path

import pytest
from rich.console import Console

from forensic_agent.cli import i18n
from forensic_agent.cli.commands import COMMAND_REGISTRY, render_help
from forensic_agent.cli.presentation import (
    MAX_LISTED_ARGUMENT_VALUE,
    RECORDED_EXECUTED,
    RECORDED_FAILED,
    RECORDED_REFUSED_BY_OVERSIGHT,
    executed_calls,
)
from forensic_agent.cli.session import InteractiveSession

_MODEL = "openai/gpt-oss-120b"
_CASE_ID = "case-0123456789ab"
_OK_PREVIEW = '{"schema_version": "forensic.tool-result.v1", "status": "ok", "data": {}}'
_ERROR_PREVIEW = (
    '{"schema_version": "forensic.tool-result.v1", "status": "error", "data": {}}'
)
#: Dulja putanja koja se u traci aktivnosti kratila u sredini; ovdje mora
#: preživjeti cijela, jer se upravo po repu dva susjedna poziva razlikuju.
_LONG_PATH = (
    "/mount/volume-1/users/profile-directory/application data/"
    "cache/index-store.dat"
)


@pytest.fixture(autouse=True)
def _restore_language() -> object:
    """Jezik je proces-globalno stanje; vraćamo ga da test ne curi u drugi."""

    previous = i18n.current_language()
    i18n.set_language(i18n.DEFAULT_LANGUAGE)
    try:
        yield
    finally:
        i18n.set_language(previous)


def _args(tmp_path: Path) -> types.SimpleNamespace:
    return types.SimpleNamespace(
        model=_MODEL,
        base_url="https://openrouter.ai/api/v1",
        api_key="k",
        image=None,
        case=None,
        memory=None,
        pcap=None,
        max_steps=10,
        run_dir=str(tmp_path / "runs"),
    )


def _action(
    sequence: int,
    tool: str,
    args: dict[str, object],
    *,
    allowed: bool = True,
    duration_s: float | None = 0.42,
    preview: str = _OK_PREVIEW,
    reasons: tuple[str, ...] = (),
) -> dict[str, object]:
    """Jedan zapis radnje u obliku u kojem ga izvođenje već upisuje."""

    return {
        "ts": 1.0,
        "seq": sequence,
        "case_id": _CASE_ID,
        "event": "action",
        "tool": tool,
        "args": args,
        "allowed": allowed,
        "blocked": not allowed,
        "risk": 0 if allowed else 3,
        "risk_name": "low" if allowed else "high",
        "reasons": list(reasons),
        "output_preview": preview,
        "duration_s": duration_s,
    }


_CALLS = (
    _action(
        1,
        "filesystem_query",
        {"operation": "list_directory", "path": "/Users", "max_results": 50},
    ),
    _action(
        3,
        "filesystem_query",
        {"operation": "read_file", "path": _LONG_PATH, "offset": 4096},
    ),
    _action(
        5,
        "memory_query",
        {"operation": "plugin", "plugin": "windows.pslist", "keyword": "evidence"},
        preview=_ERROR_PREVIEW,
        duration_s=12.5,
    ),
    _action(
        7,
        "archive_query",
        {"operation": "extract", "archive_path": "/evidence/secret.7z", "password": "hunter2"},
        allowed=False,
        duration_s=0.0,
        reasons=("policy:capability-not-granted",),
    ),
)


def _entries() -> tuple[dict[str, object], ...]:
    opened = {
        "ts": 0.0,
        "seq": 0,
        "case_id": _CASE_ID,
        "event": "case_open",
        "question": "Which processes were running?",
    }
    return (opened, *_CALLS)


def _log(tmp_path: Path, entries=None) -> str:
    path = tmp_path / "oversight.jsonl"
    rows = _entries() if entries is None else entries
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )
    return str(path)


def _rendered(tmp_path: Path, *, language: str = "en", width: int = 200) -> str:
    console = Console(record=True, width=width, color_system=None)
    session = InteractiveSession(_args(tmp_path), console=console)
    try:
        session.oversight_path = _log(tmp_path)
        i18n.set_language(language)
        session.show_executed_commands()
    finally:
        session.close()
    return console.export_text(styles=False)


# --- Projekcija: zapis izvođenja postaje redak popisa, bez gubitka -----------


def test_every_recorded_call_becomes_one_row_with_all_its_arguments() -> None:
    """Popis je popis: koliko je poziva zapisano, toliko redaka i svi argumenti."""

    calls = executed_calls(_entries())

    assert len(calls) == len(_CALLS)
    for call, recorded in zip(calls, _CALLS, strict=True):
        arguments = {argument.name: argument for argument in call.arguments}
        assert tuple(arguments) == tuple(recorded["args"])
        assert call.function == recorded["tool"]
        assert call.operation == recorded["args"]["operation"]
        # Redni broj je onaj koji lanac nadzora nosi, da se redak može spojiti
        # s odgovarajućim zapisom u oversight.jsonl.
        assert call.sequence == recorded["seq"]


def test_a_long_argument_value_survives_whole() -> None:
    """Rep duge putanje razlikuje dva poziva; projekcija ga ne smije odrezati."""

    call = executed_calls(_entries())[1]
    values = {argument.name: argument.value for argument in call.arguments}

    assert values["path"] == _LONG_PATH
    assert "…" not in values["path"]
    assert values["offset"] == "4096"


def test_the_outcome_of_each_call_is_read_from_the_record() -> None:
    """Ishod nije nagađanje: nosi ga zapis, i to imenom koje zapisničar koristi."""

    calls = executed_calls(_entries())

    assert [call.outcome for call in calls] == [
        RECORDED_EXECUTED,
        RECORDED_EXECUTED,
        RECORDED_FAILED,
        RECORDED_REFUSED_BY_OVERSIGHT,
    ]
    assert calls[2].duration_s == 12.5


def test_an_argument_whose_name_carries_a_secret_is_withheld() -> None:
    """Ime argumenta odlučuje, ne duljina: tajna se uskraćuje, ne skraćuje."""

    refused = executed_calls(_entries())[3]
    withheld = {
        argument.name: argument for argument in refused.arguments if argument.withheld
    }

    assert set(withheld) == {"password"}
    assert withheld["password"].value == ""
    for argument in refused.arguments:
        assert "hunter2" not in argument.value


def test_an_enormous_value_is_bounded_visibly_and_never_silently() -> None:
    """Ako se vrijednost mora omeđiti, redak to mora reći, inače laže o cjelini."""

    enormous = "a" * (MAX_LISTED_ARGUMENT_VALUE + 500)
    entries = (_action(1, "filesystem_query", {"operation": "search_keyword", "keyword": enormous}),)

    argument = executed_calls(entries)[0].arguments[1]

    assert argument.total_characters == len(enormous)
    assert len(argument.value) == MAX_LISTED_ARGUMENT_VALUE


# --- Ispis: cijeli poziv u terminalu ----------------------------------------


def test_the_listing_prints_every_call_with_its_full_arguments(tmp_path: Path) -> None:
    """Operater na ekranu vidi svaki poziv i svaku vrijednost, bez elizije."""

    text = _rendered(tmp_path)

    for call in _CALLS:
        assert str(call["tool"]) in text
        assert str(call["args"]["operation"]) in text
    assert "path=/Users" in text
    assert "max_results=50" in text
    assert "plugin=windows.pslist" in text
    # Znak elizije je potpis skraćivanja; u punom popisu ga ne smije biti.
    assert "…" not in text


def test_a_refused_call_is_listed_under_the_word_the_reconstruction_uses(
    tmp_path: Path,
) -> None:
    """Odbijanje se mora vidjeti, i to istom riječju kojom ga /oversight imenuje."""

    text = _rendered(tmp_path)

    # Vrata su odbila archive_query; /oversight to zove BLOCKED, pa i popis mora.
    assert "BLOCKED" in text
    assert "failed" in text
    assert "archive_query" in text
    # Ranije je isti zapis ovdje pisao REFUSED, a u rekonstrukciji BLOCKED.
    assert "REFUSED" not in text


def test_a_withheld_argument_is_named_but_its_value_is_not_printed(
    tmp_path: Path,
) -> None:
    """Uskraćena vrijednost mora nedostajati na ekranu, a argument ostati vidljiv."""

    text = _rendered(tmp_path)

    assert "password=" in text
    assert "hunter2" not in text
    assert "[withheld]" in text


def test_a_bounded_value_states_its_real_length_on_the_row(tmp_path: Path) -> None:
    """Omeđivanje se mora vidjeti u retku; nevidljivo omeđivanje je isto što i rez."""

    enormous = "z" * (MAX_LISTED_ARGUMENT_VALUE + 321)
    entries = (
        _action(1, "filesystem_query", {"operation": "search_keyword", "keyword": enormous}),
    )
    console = Console(record=True, width=120, color_system=None)
    session = InteractiveSession(_args(tmp_path), console=console)
    try:
        session.oversight_path = _log(tmp_path, entries=entries)
        session.show_executed_commands()
    finally:
        session.close()

    text = console.export_text(styles=False)
    assert "shortened; characters in total: 4321" in " ".join(text.split())


def test_an_empty_oversight_trace_says_so_instead_of_printing_an_empty_table(
    tmp_path: Path,
) -> None:
    """Prazan trag nije prazan popis: konzola mora reći da zapisa nema."""

    console = Console(record=True, width=120, color_system=None)
    session = InteractiveSession(_args(tmp_path), console=console)
    try:
        session.oversight_path = _log(tmp_path, entries=())
        session.show_executed_commands()
    finally:
        session.close()

    assert "No recorded tool calls" in console.export_text(styles=False)


# --- Jezik: oznake se prevode, identifikatori ne ----------------------------


def test_identifiers_are_byte_identical_while_the_labels_translate(
    tmp_path: Path,
) -> None:
    """Ime funkcije, operacije, argumenta i putanja ostaju isti; zaglavlja ne."""

    english = _rendered(tmp_path, language="en")
    croatian = _rendered(tmp_path, language="hr")

    identifiers = (
        "filesystem_query",
        "memory_query",
        "archive_query",
        "list_directory",
        "read_file",
        "windows.pslist",
        "max_results=50",
        "offset=4096",
        # Vrijednost koja je slučajno i ključ kataloga mora ostati vrijednost.
        "keyword=evidence",
    )
    for identifier in identifiers:
        assert identifier in english
        assert identifier in croatian

    assert "Outcome" in english and "Ishod" in croatian
    assert "Duration" in english and "Trajanje" in croatian
    assert "Arguments" in english and "Argumenti" in croatian
    assert "BLOCKED" in english and "BLOKIRANO" in croatian
    assert "Ishod" not in english
    assert "Outcome" not in croatian


# --- Naredba i pomoć --------------------------------------------------------


def test_the_console_routes_the_calls_form_to_the_full_listing(tmp_path: Path) -> None:
    """Goli /oversight ostaje sažetak; /oversight calls vodi do punog popisa."""

    pytest.importorskip("textual")
    import asyncio

    from forensic_agent.tui import build_app
    from forensic_agent.tui.app import OverlayScreen

    class _Recorder:
        def __init__(self, root: Path) -> None:
            self.run_root = root
            self._console = Console(file=__import__("io").StringIO(), width=100)
            self.seen: list[str] = []

        def show_executed_commands(self, *, console=None) -> None:
            # The console reads this view while a message may be running, so
            # it is handed a console of its own instead of the session's being
            # swapped for one.
            self.seen.append("listing")
            (console or self._console).print("full listing")

    class _Controller:
        is_demo = False

        def __init__(self, root: Path) -> None:
            self.session = _Recorder(root)

        def status(self):
            from forensic_agent.tui.model import StatusState

            return StatusState(
                mode="LIVE",
                model=_MODEL,
                provider="OpenRouter",
                case_label="dfir-agent",
                case_id=_CASE_ID,
                evidence_sources=("disk: image.E01",),
                max_steps=20,
                max_tool_calls=20,
                max_wall_time_s=900,
                max_model_requests=23,
                reasoning_effort="high",
            )

        def has_evidence(self):
            return True

        def finding_records(self, card):
            return None

    async def scenario() -> None:
        app = build_app(_Controller(tmp_path))
        async with app.run_test(size=(120, 40)) as pilot:
            # Goli /oversight je nativni sažetak, bez metode sesije.
            app.dispatch_command("oversight", "")
            await pilot.pause(0.2)
            assert isinstance(app.screen, OverlayScreen)
            assert app._controller.session.seen == []
            await pilot.press("escape")
            await pilot.pause(0.1)
            # /oversight calls otvara puni popis izvršenih naredbi.
            app.dispatch_command("oversight", "calls")
            for _ in range(40):
                await pilot.pause(0.05)
                if isinstance(app.screen, OverlayScreen):
                    break
            assert app._controller.session.seen == ["listing"]
            assert isinstance(app.screen, OverlayScreen)

    asyncio.run(scenario())


def test_the_help_text_describes_the_new_form() -> None:
    """Naredba koja se ne spominje u /help ne postoji za operatera."""

    spec = COMMAND_REGISTRY.resolve("guardrails")
    assert spec is not None
    assert spec.name == "oversight"  # the project's own word is the command
    assert spec.usage == "/oversight [n|calls|prompt]"

    detail = render_help("oversight")
    assert "/oversight [n|calls|prompt]" in detail
    assert "executed commands" in detail
    assert "/oversight prompt" in detail

    assert "/oversight [n|calls|prompt]" in render_help()


# ---------------------------------------------------------------------------
# the command sheet: /help's own listing, at the width it is given
# ---------------------------------------------------------------------------
def _sheet_lines(width: int, **kwargs) -> list[str]:
    """The rows the command sheet actually produces at ``width`` columns.

    The width is pinned rather than taken from the environment: the ambient
    terminal is not the same here as it is in CI, and this sheet chooses its
    layout by the width it is handed.
    """

    from forensic_agent.cli.terminal import build_help_renderable

    console = Console(width=width, record=True, file=io.StringIO())
    console.print(build_help_renderable(None, **kwargs))
    return [line.rstrip() for line in console.export_text().rstrip("\n").split("\n")]


def test_the_command_sheet_states_its_headings_once() -> None:
    """A heading repeated every eight rows reads as content, not as a label.

    Each category is its own table so the groups stay findable, and every one
    of them used to carry its own "Command" / "What it does" head — five
    headings down one screen for one sheet of three columns.
    """

    for width in (200, 140, 116, 100, 60):
        lines = _sheet_lines(width)
        headings = [line for line in lines if line.startswith("Command")]
        assert len(headings) == 1, (
            f"at {width} columns the sheet carried {len(headings)} column "
            f"headings: {headings}"
        )
        # The groups themselves are still each named, so the sheet has not
        # simply been flattened into one undifferentiated list.
        titles = [line for line in lines if line.startswith("\u203a ")]
        assert len(titles) >= 5, f"at {width} the groups lost their titles: {titles}"


def test_the_command_sheet_fills_the_width_it_is_given() -> None:
    """Wide is read across. A fixed column down the middle wastes the window."""

    wide = _sheet_lines(200)
    assert max(len(line) for line in wide) > 150
    # And nothing runs past the edge at any width.
    for width in (200, 140, 116, 100, 72, 48):
        for line in _sheet_lines(width):
            assert len(line) <= width, f"{len(line)} cells at width {width}: {line!r}"


def test_every_command_keeps_its_description_however_narrow_the_sheet() -> None:
    """Degrading must not mean dropping a column.

    Three fixed columns whose widths together exceeded the window left the
    third nothing at all, and Rich then omitted it: a command reference with
    the descriptions missing. Below the width three columns need, the name and
    its syntax share one column that flexes instead.
    """

    for width in (200, 116, 100, 72, 48):
        body = "\n".join(_sheet_lines(width))
        for command_spec in COMMAND_REGISTRY.commands:
            assert f"/{command_spec.name}" in body, (width, command_spec.name)
        # A description from each end of the sheet, wrapped or not.
        assert "Show all commands" in body.replace("\n", " "), width


def test_the_sheet_is_drawn_in_the_palette_it_is_handed() -> None:
    """The console has several themes; a sheet with a colour of its own has none.

    The alternating row fill was exactly that — a value from this module's
    fixed palette, painted behind every second command whatever theme the
    full-screen console was running.
    """

    from forensic_agent.cli.terminal import build_help_renderable

    console = Console(
        width=160, record=True, file=io.StringIO(), force_terminal=True,
        color_system="truecolor",
    )
    console.print(
        build_help_renderable(
            None, palette={"ACCENT": "#ff00ff", "DIM": "#00ff00",
                           "DIM_BRIGHT": "#00ffff", "TEXT": "#ffff00"}
        )
    )
    painted = console.export_text(styles=True)
    assert "255;0;255" in painted, "the accent the caller handed in was not used"
    # No background is painted at all: the sheet takes the ground it is on.
    assert "48;2;" not in painted, "the sheet painted a background of its own"
