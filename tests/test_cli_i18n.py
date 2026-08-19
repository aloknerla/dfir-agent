"""Prebacivanje jezika terminala između engleskog i hrvatskog.

Ovi testovi postoje jer operater mora moći voditi istragu na hrvatskom, a da
se pritom ne pomakne niti jedan zapečaćeni digest niti jedan tehnički
identifikator: prijevod je isključivo prezentacijski sloj terminala. Zato se
provjerava i ono što se PREVODI (naslovi, zaglavlja, /help) i ono što se
NIKADA ne smije prevesti (ime alata, putanja, hash, model-facing tekst).
"""

from __future__ import annotations

import ast
import json
import tomllib
import types
from pathlib import Path

import pytest
from rich.console import Console

from forensic_agent.agent.runtime import preflight_model_surface
from forensic_agent.cli import i18n
from forensic_agent.cli.commands import (
    COMMAND_REGISTRY,
    parse_command,
    render_help,
)
from forensic_agent.cli.session import InteractiveSession
from forensic_agent.core.audit import AuditLog

_MODEL = "openai/gpt-oss-120b"


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


def _disk_stub(tmp_path: Path) -> types.SimpleNamespace:
    """Minimalna slika diska: preflight gradi sheme, ne otvara datoteku."""

    return types.SimpleNamespace(
        image_path=str(tmp_path / "x.dd"),
        image_sha="x",
        audit=AuditLog(str(tmp_path / "audit.jsonl")),
        extract_file=lambda *args, **kwargs: None,
    )


def test_language_command_is_registered_and_routed() -> None:
    """/language mora postojati u registru i primati oblike en/hr i prazan."""

    spec = COMMAND_REGISTRY.resolve("language")
    assert spec is not None
    assert spec.description.strip()

    parsed = parse_command("/language hr")
    assert parsed is not None
    assert parsed.name == "language"
    assert parsed.argument_text == "hr"

    bare = parse_command("/language")
    assert bare is not None
    assert bare.name == "language"
    assert bare.argument_text == ""


def test_default_language_is_english_and_lookup_is_identity() -> None:
    """Na engleskom prijevodni sloj vraća izvor nepromijenjen."""

    assert i18n.current_language() == "en"
    assert i18n.t("Final answer") == "Final answer"
    assert i18n.t("Active tools") == "Active tools"


def test_switching_to_croatian_translates_titles_headers_and_help() -> None:
    """Reprezentativan skup naslova, zaglavlja i /help prelazi na hrvatski."""

    i18n.set_language("hr")
    assert i18n.current_language() == "hr"

    assert i18n.t("Final answer") == "Konačni odgovor"
    assert i18n.t("Evidence summary") == "Sažetak dokaza"
    assert i18n.t("Run summary") == "Sažetak izvođenja"
    assert i18n.t("Active tools") == "Aktivni alati"
    assert i18n.t("Function") == "Funkcija"
    assert i18n.t("External tool") == "Vanjski alat"
    # Zaglavlje stupca s primitkom nosi naziv u prijevodu, a algoritam u
    # drugom retku ostaje identifikator i ne prevodi se.
    assert i18n.t("Evidence ID") == "ID dokaza"
    assert i18n.t("(SHA-256)") == "(SHA-256)"
    assert i18n.t(
        "The evidence ID links a row to the exact stored result, "
        "and changes if that result is altered."
    ) == (
        "ID dokaza povezuje redak s točnim pohranjenim rezultatom "
        "i mijenja se ako se taj rezultat izmijeni."
    )
    assert i18n.t("Reason") == "Razlog"

    croatian_help = render_help()
    assert "Sustav i integracije" in croatian_help
    assert (
        "Prikaži sve naredbe ili detaljnu pomoć za jednu naredbu." in croatian_help
    )

    i18n.set_language("en")
    english_help = render_help()
    assert "System and integrations" in english_help
    assert "Show all commands or detailed help for one command." in english_help
    assert "Sustav i integracije" not in english_help


def test_technical_identifiers_and_model_text_are_never_translated() -> None:
    """Ime alata, putanja i hash ostaju bajtovno isti na oba jezika."""

    identifiers = (
        "memory_query",
        "registry_query",
        "D:/Cases/case-001/image.dd",
        "/evidence/mem.raw",
        "a" * 64,
        "interactive-0123456789abcdef",
    )
    for language in ("en", "hr"):
        i18n.set_language(language)
        for identifier in identifiers:
            assert i18n.t(identifier) == identifier

    # Niz bez unosa u katalogu mora se vratiti na engleski izvor (pošteni fallback).
    i18n.set_language("hr")
    assert i18n.t("A phrase with no curated translation.") == (
        "A phrase with no curated translation."
    )


def test_rendered_tool_table_translates_chrome_only(tmp_path: Path) -> None:
    """Tablica /tools na hrvatskom: zaglavlja prevedena, imena funkcija nisu."""

    console = Console(record=True, width=120, color_system=None)
    session = InteractiveSession(_args(tmp_path), console=console)
    try:
        i18n.set_language("hr")
        session.show_tools()
        text = console.export_text()
    finally:
        session.close()

    assert "Aktivni alati" in text
    assert "Funkcija" in text
    assert "Vanjski alat" in text
    assert "Razlog" in text
    # Domenske funkcije se ispisuju kao identifikatori i moraju ostati engleske.
    assert "memory_query" in text
    assert "registry_query" in text


def test_rendered_evidence_summary_keeps_identifiers_and_hash(tmp_path: Path) -> None:
    """Sažetak dokaza: naslov i zaglavlja hrvatski, ime alata i hash nepromijenjeni."""

    console = Console(record=True, width=120, color_system=None)
    session = InteractiveSession(_args(tmp_path), console=console)
    try:
        session.last_findings = [
            {
                "tool": "memory_query",
                "payload_sha256": "a" * 64,
                "result": {
                    "status": "ok",
                    "data": {"type": "process_list", "items": [1, 2, 3]},
                    "page": {"returned": 3, "total": 3},
                    "coverage": {"complete": True},
                },
            }
        ]
        i18n.set_language("hr")
        panel = session._evidence_summary_panel()
    finally:
        session.close()

    rendered = Console(record=True, width=120, color_system=None)
    rendered.print(panel)
    text = rendered.export_text()

    assert "Sažetak dokaza" in text
    assert "Funkcija" in text
    # Zaglavlje je u dva retka: naziv stupca prevedeni, algoritam ne.
    assert "ID dokaza" in text
    assert "(SHA-256)" in text
    # Tehnički sadržaj retka ostaje netaknut na hrvatskom.
    assert "memory_query" in text
    assert "aaaaaaaaaaaa" in text


def test_language_choice_persists_across_reload(tmp_path: Path) -> None:
    """Zapisan izbor mora preživjeti ponovno čitanje (restart konzole)."""

    preferences = tmp_path / "preferences.json"
    i18n.save_language("hr", path=preferences)

    assert i18n.load_saved_language(path=preferences) == "hr"
    stored = json.loads(preferences.read_text(encoding="utf-8"))
    assert stored["ui_language"] == "hr"


def test_saving_language_preserves_unrelated_preferences(tmp_path: Path) -> None:
    """Dodavanje jezika ne smije pregaziti druge zapisane postavke."""

    preferences = tmp_path / "preferences.json"
    preferences.write_text(
        json.dumps({"unrelated_setting": "keep-me"}), encoding="utf-8"
    )

    i18n.save_language("hr", path=preferences)

    stored = json.loads(preferences.read_text(encoding="utf-8"))
    assert stored["unrelated_setting"] == "keep-me"
    assert stored["ui_language"] == "hr"


def test_preferences_are_a_separate_file_from_provider_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Jezik ide u zaseban preferences.json, ne u .env s provider shemom."""

    env_file = tmp_path / ".dfir-agent" / ".env"
    monkeypatch.setenv("DFA_ENV_FILE", str(env_file))
    monkeypatch.delenv("DFA_RUNS_DIR", raising=False)

    i18n.save_language("hr")

    resolved = i18n.preferences_path()
    assert resolved == env_file.parent / "preferences.json"
    assert resolved.is_file()
    assert not env_file.exists()
    assert i18n.load_saved_language() == "hr"


def test_the_choice_is_written_where_the_deployment_can_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """U spremniku je mapa s vjerodajnicama namjerno samo za čitanje.

    Preferencija ondje ne bi preživjela nijednu sesiju, a poruka o neuspjelom
    zapisu nije rješenje nego simptom. Ondje gdje je mapa izvođenja objavljena,
    ona je zapisiva i trajna, i o dokazu ne govori ništa — pa izbor ide onamo.
    """

    read_only_config = tmp_path / "config" / ".env"
    run_root = tmp_path / "runtime"
    run_root.mkdir()
    monkeypatch.setenv("DFA_ENV_FILE", str(read_only_config))
    monkeypatch.setenv("DFA_RUNS_DIR", str(run_root))

    i18n.save_language("hr")

    assert i18n.preferences_path() == run_root / "preferences.json"
    assert (run_root / "preferences.json").is_file()
    assert not read_only_config.parent.exists()
    assert i18n.load_saved_language() == "hr"


def test_missing_or_invalid_preferences_fall_back_to_english(tmp_path: Path) -> None:
    """Bez datoteke ili s nevažećom vrijednošću, jezik je engleski."""

    missing = tmp_path / "absent.json"
    assert i18n.load_saved_language(path=missing) == "en"

    garbage = tmp_path / "garbage.json"
    garbage.write_text("{ not json", encoding="utf-8")
    assert i18n.load_saved_language(path=garbage) == "en"

    wrong = tmp_path / "wrong.json"
    wrong.write_text(json.dumps({"ui_language": "fr"}), encoding="utf-8")
    assert i18n.load_saved_language(path=wrong) == "en"


def test_normalize_language_rejects_unsupported_values() -> None:
    """Nepodržani kod se odbija; podržani se normaliziraju neovisno o velikim slovima."""

    assert i18n.normalize_language(" HR ") == "hr"
    assert i18n.normalize_language("EN") == "en"
    with pytest.raises(ValueError):
        i18n.normalize_language("fr")
    with pytest.raises(ValueError):
        i18n.normalize_language("")


def test_language_command_switches_and_persists_through_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """/language hr mijenja živo stanje i sprema izbor; nevažeći kod ništa ne mijenja."""

    env_file = tmp_path / ".dfir-agent" / ".env"
    monkeypatch.setenv("DFA_ENV_FILE", str(env_file))
    console = Console(record=True, width=120, color_system=None)
    session = InteractiveSession(_args(tmp_path), console=console)
    try:
        session.change_language("hr")
        assert i18n.current_language() == "hr"
        stored = json.loads(
            (env_file.parent / "preferences.json").read_text(encoding="utf-8")
        )
        assert stored["ui_language"] == "hr"

        session.change_language("fr")
        # Nevažeći kod ostavlja aktivni jezik netaknut.
        assert i18n.current_language() == "hr"

        session.change_language("en")
        assert i18n.current_language() == "en"
    finally:
        session.close()


def test_switching_language_does_not_move_sealed_digests(tmp_path: Path) -> None:
    """Zapečaćeni digesti se ne pomiču: ništa od ovoga nije model-facing.

    Ako bi se model-facing tekst greškom provukao kroz prijevodni sloj,
    system_prompt_sha256 ili tool_registry_sha256 bi se razlikovali između
    engleske i hrvatske postavke — pa ih računamo na oba jezika i tražimo
    bajtovno jednake vrijednosti.
    """

    disk = _disk_stub(tmp_path)
    question = "Which processes were running at the time of acquisition?"

    i18n.set_language("en")
    english = preflight_model_surface(disk, question, model=_MODEL)
    i18n.set_language("hr")
    croatian = preflight_model_surface(disk, question, model=_MODEL)

    assert english.system_prompt_sha256 == croatian.system_prompt_sha256
    assert english.tool_registry_sha256 == croatian.tool_registry_sha256


def test_every_data_file_in_the_package_is_declared_as_package_data() -> None:
    """Katalog mora doći s instaliranim paketom, inače konzola tiho govori engleski.

    ``_catalog`` čita ``i18n_hr.json`` pokraj svojeg modula i hvata OSError,
    vraćajući prazan katalog. Datoteka koja nije deklarirana kao package data ne
    uđe u wheel, pa instalirana konzola prijavi hrvatski i renderira engleski, bez
    ijedne poruke o grešci. Tvrdnja je općenita namjerno: svaka nekôdna datoteka
    unutar paketa mora biti deklarirana, jer bi ista rupa bila jednako tiha i za
    sljedeću.
    """

    root = Path(__file__).resolve().parent.parent
    manifest = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    declared = manifest["tool"]["setuptools"]["package-data"]

    patterns: list[tuple[Path, str]] = [
        ((root / "src" / package.replace(".", "/")), pattern)
        for package, entries in declared.items()
        for pattern in entries
    ]

    package_root = root / "src" / "forensic_agent"
    undeclared = sorted(
        str(path.relative_to(root).as_posix())
        for path in package_root.rglob("*")
        if path.is_file()
        and path.suffix not in {".py", ".pyc", ".pyo"}
        and "__pycache__" not in path.parts
        and not any(
            path.is_relative_to(base) and path.relative_to(base).match(pattern)
            for base, pattern in patterns
        )
    )
    assert undeclared == []


def test_every_command_description_and_detail_has_a_croatian_rendering() -> None:
    """Ključ kataloga JEST engleski izvorni tekst, pa uređivanje teksta gasi prijevod.

    Ovo je jedini način na koji se prijevod tiho izgubi. ``t`` vraća izvor
    nepromijenjen kad ključa nema, što je ispravno ponašanje za tehnički
    identifikator i katastrofalno za opis naredbe: dotjerivanje engleske
    rečenice (uklanjanje crtice, preformuliranje) čini staru hrvatsku natuknicu
    nedostupnom, a konzola na hrvatskom počne prikazivati englesku rečenicu bez
    ijedne poruke o grešci. Zato se ovdje traži da SVAKI opis i SVAKI detalj iz
    registra naredbi ima svoj hrvatski parnjak: tko promijeni englesku kopiju,
    mora u istom koraku premjestiti i ključ.
    """

    i18n.set_language("hr")
    untranslated = [
        f"/{command.name} {field}"
        for command in COMMAND_REGISTRY.commands
        for field, text in (
            ("description", command.description),
            ("detail", command.detail),
        )
        if text and i18n.t(text) == text
    ]
    assert untranslated == []


def test_no_long_croatian_entry_is_keyed_to_text_the_code_no_longer_writes() -> None:
    """Zaostali ključ jednako je štetan kao ključ koji nedostaje.

    Kad se engleska rečenica dotjera, stara natuknica ostaje u katalogu i
    izgleda kao pokriven prijevod, a ne renderira se nigdje: ``t`` više nikada
    ne dobije taj ključ. Sljedeći čitatelj kataloga zaključi da je površina
    prevedena, a operater na hrvatskom vidi englesku rečenicu.

    Provjeravaju se ključevi od 60 i više znakova. Kratke natuknice ("Model",
    "Usage:") konzola ponegdje sklapa unutar f-stringa, pa se ne pojavljuju kao
    doslovna konstanta; duga rečenica se uvijek ispisuje doslovno, pa se za nju
    smije tražiti da postoji u izvoru točno onako kako stoji u katalogu.
    """

    package = Path(i18n.__file__).parent.parent
    literals: set[str] = set()
    for module in package.rglob("*.py"):
        for node in ast.walk(ast.parse(module.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                literals.add(node.value)

    catalog = json.loads(
        Path(i18n.__file__).with_name("i18n_hr.json").read_text(encoding="utf-8")
    )
    stale = sorted(
        key
        for key in catalog
        if not key.startswith("_") and len(key) >= 60 and key not in literals
    )
    assert stale == []


# ---------------------------------------------------------------------------
# the full-screen console follows the setting too
# ---------------------------------------------------------------------------
def test_the_console_frame_changes_language_and_changes_back(tmp_path, monkeypatch):
    """/language hr used to leave the console itself in English.

    The setting was stored and the shell's own views translated, because those
    render through modules that route their strings through this layer. The
    full-screen console routed none of its own: it drew its pane titles, its
    prompt and its resting hints as literals, so the one surface the operator
    is looking at did not change and the setting read as broken.

    Switching now redraws the console the way a theme switch does — from the
    recipe each line was mounted with — and re-applies the attributes that are
    not recipes at all.
    """

    import asyncio

    pytest.importorskip("textual")

    from textual.widgets import Input

    from forensic_agent.tui import build_app
    from forensic_agent.tui.controller import DemoController

    monkeypatch.setattr(
        "forensic_agent.tui.controller.time.sleep", lambda *_: None, raising=False
    )
    # The preference is a real file; a test must not rewrite the operator's.
    monkeypatch.setenv("DFA_RUN_DIR", str(tmp_path))

    def titles(app) -> dict:
        return {
            pane_id: str(app.query_one(pane_id).border_title or "")
            for pane_id in (
                "#conversation",
                "#activity",
                "#evidence-pane",
                "#guardrails-pane",
            )
        }

    async def scenario():
        app = build_app(DemoController())
        # Pinned, as every console test here pins it: the ambient terminal is
        # not the same on this machine as in CI.
        async with app.run_test(size=(140, 44)) as pilot:
            await pilot.pause(0.3)
            english = titles(app)
            assert english["#conversation"] == "CONVERSATION"
            assert english["#guardrails-pane"] == "GUARDRAILS"
            english_placeholder = app.query_one("#prompt", Input).placeholder

            app._set_language("hr")
            await pilot.pause(0.3)
            croatian = titles(app)
            assert croatian["#conversation"] == "RAZGOVOR"
            assert croatian["#activity"] == "AKTIVNOST"
            assert croatian["#evidence-pane"] == "DOKAZI"
            assert croatian["#guardrails-pane"] != english["#guardrails-pane"]
            assert app.query_one("#prompt", Input).placeholder != english_placeholder

            # A border subtitle is a plain attribute, like the titles: nothing
            # goes back for it unless the switch does.
            subtitle = str(app.query_one("#evidence-pane").border_subtitle or "")
            assert subtitle and "You accept findings" not in subtitle, subtitle

            # A pane's resting hint is a recipe, so it is redrawn in place
            # rather than left in the language it was mounted in.
            hint = app.query_one("#activity-hint")
            rendered = hint.render()
            rendered = getattr(rendered, "_renderable", rendered)
            shown = getattr(rendered, "plain", str(rendered))
            assert "Tool calls appear here" not in shown, shown
            assert "Pozivi alata" in shown, shown

            # And back, so the switch is a switch and not a one-way door.
            app._set_language("en")
            await pilot.pause(0.3)
            assert titles(app) == english
            assert app.query_one("#prompt", Input).placeholder == english_placeholder

    # The autouse fixture above restores the process language; nothing to
    # undo here.
    asyncio.run(scenario())
