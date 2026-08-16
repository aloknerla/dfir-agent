"""Nadzorni izvještaj mora obračunati svaki poziv, a ne samo one koje su vrata odbila.

Zabilježeno u stvarnoj sesiji: vrata su propustila poziv, funkcija ga je zatim
odbila zbog argumenata, a ``/oversight`` je taj poziv prikazao kao ``ok`` uz
``blocked: 0``. Brojka je bila točna za ono što mjeri — odbijanja politike — ali
je odgovarala na pitanje "koliko ih je odbijeno", pa je odbijanje postalo
nevidljivo. Ovdje se traži da svaki zabilježeni poziv bude prebrojan točno
jednom i da izvještaj imenuje koji ga je sloj odbio.

Drugi dio: redak ``question:`` mora nositi pitanje, a ne cijelu složenu poruku.
Ono što je poslano oko pitanja i dalje je činjenica o izvođenju, pa se broji i
ostaje dostupno, ali ne pretrpava sažetak.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from rich.console import Console

from forensic_agent.cli import presentation
from forensic_agent.cli.presentation import (
    RECORDED_EXECUTED,
    RECORDED_REFUSED_BY_OVERSIGHT,
    RECORDED_REFUSED_BY_TOOL,
    executed_calls,
    project_recorded_question,
)
from forensic_agent.cli.session import InteractiveSession
from forensic_agent.oversight import OversightLog, Policy, reconstruct
from forensic_agent.oversight.audit import (
    ACTION_EXECUTED,
    ACTION_FAILED,
    ACTION_OUTCOMES,
    ACTION_REFUSED_BY_OVERSIGHT,
    ACTION_REFUSED_BY_TOOL,
    classify_action_outcome,
)
from forensic_agent.oversight.enforcement import OversightGate, enforce

_ARGUMENT_REFUSAL = {
    "error": {
        "code": "invalid_operation_arguments",
        "tool": "registry_ripper",
        "message": "operation 'profile' is not defined",
    },
    "deterministic_error": True,
}


def _recorded_run(tmp_path: Path, *, question: str = "What does the evidence show?") -> str:
    """Jedno izvođenje: dva izvedena poziva, jedno odbijanje po sloju, jedan pad."""

    path = str(tmp_path / "oversight.jsonl")
    policy = Policy.secure(path_roots=[str(tmp_path)])
    recorder = OversightLog(path)
    gate = OversightGate(policy, recorder)
    recorder.open_case(question=question, policy=policy, model="m", engine="langgraph")

    enforce(gate, "list_directory", {"path": str(tmp_path)}, lambda: {"entries": []})
    enforce(
        gate,
        "artifact_reference_query",
        {"operation": "hardware_vendor", "address": "00:1B:21:3A:4B:5C"},
        lambda: {"hits": 2},
    )
    # Vrata propuštaju; funkcija odbija vlastite argumente i ne čita ništa.
    enforce(gate, "registry_ripper", {"operation": "profile"}, lambda: _ARGUMENT_REFUSAL)
    # Izvelo se i palo — ni jedno ni drugo odbijanje.
    enforce(gate, "memory_query", {"plugin": "pslist"}, lambda: {"error": "parser failed"})
    # Vrata odbijaju: putanja je izvan opsega slučaja.
    enforce(gate, "read_text_file", {"path": "C:/Users/victim/secrets.txt"}, lambda: {})
    recorder.close_case(final="done")
    return path


def _summary(tmp_path: Path, **kwargs: str) -> dict:
    return reconstruct(OversightLog.load(_recorded_run(tmp_path, **kwargs)))


def test_a_call_the_tool_refused_is_not_counted_as_a_call_that_ran(tmp_path) -> None:
    """Poziv koji je funkcija odbila ne smije se voditi kao uspješan."""

    summary = _summary(tmp_path)

    assert summary["tool_calls"] == 5
    assert summary["executed_calls"] == 2
    assert summary["failed_calls"] == 1
    assert summary["refused_calls"] == 2
    # Stara brojka zadržava svoje značenje: samo odbijanja politike.
    assert summary["blocked_calls"] == 1
    assert summary["outcome_counts"][ACTION_REFUSED_BY_TOOL] == 1


def test_every_recorded_call_is_counted_exactly_once(tmp_path) -> None:
    """Zbroj ishoda mora biti jednak broju poziva; nijedan se ne smije izgubiti."""

    summary = _summary(tmp_path)

    assert sum(summary["outcome_counts"].values()) == summary["tool_calls"]
    assert set(summary["outcome_counts"]) == ACTION_OUTCOMES


def test_the_timeline_names_which_layer_refused_and_on_what_ground(tmp_path) -> None:
    """Odbijanje politike i odbijanje funkcije nisu isti događaj i ne smiju se stopiti."""

    timeline = {row["tool"]: row for row in _summary(tmp_path)["timeline"]}

    refused = timeline["registry_ripper"]
    assert refused["outcome"] == ACTION_REFUSED_BY_TOOL
    assert refused["detail"] == "invalid_operation_arguments"
    # Vrata su ga propustila, i izvještaj to i dalje kaže.
    assert refused["decision"] == "allowed"

    blocked = timeline["read_text_file"]
    assert blocked["outcome"] == ACTION_REFUSED_BY_OVERSIGHT
    assert blocked["decision"] == "BLOCKED"
    assert blocked["reasons"]

    assert timeline["memory_query"]["outcome"] == ACTION_FAILED
    assert timeline["list_directory"]["outcome"] == ACTION_EXECUTED


def test_every_refusal_reaches_the_refusal_summary(tmp_path) -> None:
    """Sažetak odbijanja mora nositi oba sloja, inače opet nedostaje jedno."""

    refusals = _summary(tmp_path)["refusal_summary"]

    assert [row["tool"] for row in refusals] == ["registry_ripper", "read_text_file"]
    assert refusals[0]["outcome"] == ACTION_REFUSED_BY_TOOL
    assert refusals[1]["outcome"] == ACTION_REFUSED_BY_OVERSIGHT


def test_a_trace_written_before_the_outcome_field_is_still_read_correctly() -> None:
    """Stariji zapis nema polje ishoda, pa se čita iz onoga što je zadržao."""

    legacy_refusal = {
        "event": "action",
        "tool": "registry_ripper",
        "allowed": True,
        "blocked": False,
        "reasons": [],
        "output_preview": (
            '{"error": {"code": "invalid_operation_arguments"}, '
            '"deterministic_error": true}'
        ),
    }
    legacy_block = {"event": "action", "tool": "read_text_file", "blocked": True}
    legacy_raise = {
        "event": "action",
        "tool": "memory_query",
        "allowed": True,
        "reasons": ["tool-raised-exception"],
    }

    assert classify_action_outcome(legacy_refusal) == ACTION_REFUSED_BY_TOOL
    assert classify_action_outcome(legacy_block) == ACTION_REFUSED_BY_OVERSIGHT
    assert classify_action_outcome(legacy_raise) == ACTION_FAILED
    assert classify_action_outcome({"event": "action", "allowed": True}) == ACTION_EXECUTED


def test_the_console_vocabulary_matches_the_recorders_own(tmp_path) -> None:
    """Konzola imena ishoda drži kao literale; ona se ne smiju razići od zapisničara."""

    assert presentation.RECORDED_EXECUTED == ACTION_EXECUTED
    assert presentation.RECORDED_FAILED == ACTION_FAILED
    assert presentation.RECORDED_REFUSED_BY_OVERSIGHT == ACTION_REFUSED_BY_OVERSIGHT
    assert presentation.RECORDED_REFUSED_BY_TOOL == ACTION_REFUSED_BY_TOOL


def test_the_executed_command_listing_agrees_with_the_reconstruction(tmp_path) -> None:
    """/oversight calls i /oversight moraju o istom pozivu reći isto."""

    calls = {
        call.function: call
        for call in executed_calls(OversightLog.load(_recorded_run(tmp_path)))
    }

    # Oba su odbijena, ali ne istim slojem, i popis to više ne stapa u jednu riječ.
    assert calls["registry_ripper"].outcome == RECORDED_REFUSED_BY_TOOL
    assert calls["read_text_file"].outcome == RECORDED_REFUSED_BY_OVERSIGHT
    assert calls["list_directory"].outcome == RECORDED_EXECUTED


#: Svaki oblik koji stariji zapis može zadržati u omeđenom pregledu izlaza, i
#: ishod koji se iz njega smije pročitati. Tri tiha oblika stoje ovdje jer je
#: prvi popravak upravo njih proglasio padom: ``\s*`` vraća pojedeni razmak, pa
#: je negativni pogled unaprijed bio zadovoljen na razmaku ispred vrijednosti.
_LEGACY_PREVIEW_SHAPES = (
    (
        '{"hive": "SYSTEM", "error": "could not open hive: '
        '/Windows/System32/config/SYSTEM"}',
        ACTION_FAILED,
    ),
    ('{"values": [], "error": null}', ACTION_EXECUTED),
    ('{"values": [], "error": ""}', ACTION_EXECUTED),
    ('{"values": [], "error": false}', ACTION_EXECUTED),
    (
        '{"schema_version": "forensic.tool-result.v1", "status": "error", "data": {}}',
        ACTION_FAILED,
    ),
    (
        '{"error": {"code": "invalid_operation_arguments"}, '
        '"deterministic_error": true}',
        ACTION_REFUSED_BY_TOOL,
    ),
)


@pytest.mark.parametrize(("preview", "expected"), _LEGACY_PREVIEW_SHAPES)
def test_a_legacy_preview_is_read_for_what_it_actually_declares(
    preview: str, expected: str
) -> None:
    """Stariji alat pad prijavljuje članom ``error``; nema ``status`` da se traži."""

    entry = {
        "event": "action",
        "tool": "registry_query",
        "allowed": True,
        "blocked": False,
        "reasons": [],
        "output_preview": preview,
    }

    assert classify_action_outcome(entry) == expected


def _legacy_run(tmp_path: Path) -> str:
    """Zapis kakav ``runs/`` već sadrži: bez polja ishoda, s članom ``error``."""

    path = tmp_path / "oversight.jsonl"
    rows: list[dict[str, object]] = [
        {"seq": 0, "case_id": "legacy", "event": "case_open", "question": "q"}
    ]
    for index, preview in enumerate(
        (
            '{"values": []}',
            '{"hive": "SYSTEM", "error": "could not open hive"}',
            '{"hive": "SOFTWARE", "error": "could not open hive"}',
        ),
        start=1,
    ):
        rows.append(
            {
                "seq": index,
                "case_id": "legacy",
                "event": "action",
                "tool": "registry_query",
                "args": {"operation": "read_key"},
                "allowed": True,
                "blocked": False,
                "reasons": [],
                "risk": 0,
                "risk_name": "low",
                "output_preview": preview,
            }
        )
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )
    return str(path)


def test_a_stored_run_of_legacy_shape_no_longer_reports_zero_failures(tmp_path) -> None:
    """Zapisi u ``runs/`` nose član ``error``; sažetak ih je brojao kao izvedene."""

    summary = reconstruct(OversightLog.load(_legacy_run(tmp_path)))

    assert summary["tool_calls"] == 3
    assert summary["executed_calls"] == 1
    assert summary["failed_calls"] == 2


def _console_session(path: str) -> tuple[InteractiveSession, Console]:
    """Sesija dovoljna za crtanje; ništa se ne otvara i ništa ne izvodi."""

    console = Console(record=True, width=110, color_system=None)
    session = InteractiveSession.__new__(InteractiveSession)
    session._console = console
    session.oversight_path = path
    session.last_run = object()
    session.last_findings = []
    return session, console


def test_the_oversight_view_shows_the_refusal_it_used_to_call_ok(tmp_path) -> None:
    """Ono što je prije pisalo 'ok' sada mora pisati odbijeno, i reći tko ga je odbio."""

    session, console = _console_session(_recorded_run(tmp_path))
    session.show_oversight()
    rendered = console.export_text(styles=False)

    assert "ran: 2" in rendered
    assert "refused: 2" in rendered
    assert "failed: 1" in rendered
    assert "1 blocked by the oversight policy" in rendered
    assert "1 refused by the tool before it read anything" in rendered
    assert "registry_ripper ✗ refused" in rendered
    assert "invalid_operation_arguments" in rendered
    assert "read_text_file ✗ BLOCKED" in rendered


def _finding_bound_to(path: str, tool: str) -> tuple[dict[str, object], int]:
    """Nalaz vezan na zabilježeni poziv imenovane funkcije, preko njegova rednog broja."""

    action = next(
        row
        for row in OversightLog.load(path)
        if row.get("event") == "action" and row.get("tool") == tool
    )
    sequence = int(action["seq"])
    return {
        "tool": tool,
        "payload_sha256": "b" * 64,
        "result": {
            "schema_version": "forensic.tool-result.v2",
            "status": "error",
            "data": {"type": "unknown_type", "attributes": {}, "items": []},
            "page": {"returned": 0, "total": 0, "truncated": False},
            "coverage": {"complete": False, "reason": "refused"},
            "warnings": [],
            "error": {"code": "legacy_error", "message": "refused"},
            "provenance": {"oversight_sequence": sequence},
            "receipt": {"payload_sha256": "b" * 64},
        },
    }, sequence


def test_one_refused_call_gets_one_name_in_all_three_views(tmp_path) -> None:
    """Isti zapis je pisao BLOCKED, REFUSED i ERROR — tri prikaza, tri riječi."""

    path = _recorded_run(tmp_path)
    finding, _sequence = _finding_bound_to(path, "read_text_file")

    session, console = _console_session(path)
    session.last_findings = [finding]
    session.show_oversight()
    session.show_executed_commands()
    session.show_findings("01")
    rendered = console.export_text(styles=False)

    # Vrata su odbila poziv; sva tri prikaza to sada kažu istom riječju.
    assert rendered.count("BLOCKED") == 3
    # Omotnica rezultata i dalje prijavljuje svoj status, jer je to druga
    # činjenica o drugom zapisu — ali više nije jedino što /findings kaže.
    assert "ERROR" in rendered
    assert "legacy_error" in rendered


def test_a_view_with_no_run_bound_says_there_is_no_run(tmp_path, monkeypatch) -> None:
    """Prikaz bez vezanog izvođenja ne smije pročitati tuđi zapis iz radnog direktorija."""

    stray = tmp_path / "elsewhere"
    stray.mkdir()
    unrelated = _recorded_run(stray)
    (stray / "oversight.jsonl").write_text(
        Path(unrelated).read_text(encoding="utf-8"), encoding="utf-8"
    )
    monkeypatch.chdir(stray)

    # Točno ono što je konzola držala prije prvog pitanja: golo relativno ime.
    session, console = _console_session("oversight.jsonl")
    session.show_oversight()
    session.show_oversight_prompt()
    session.show_executed_commands()
    rendered = console.export_text(styles=False)

    assert rendered.count("No oversight trace is available") == 2
    assert "No recorded tool calls" in rendered
    # Ništa iz nevezanog izvođenja ne smije se pripisati ovoj sesiji.
    assert "What does the evidence show?" not in rendered
    assert "registry_ripper" not in rendered


def test_the_question_line_carries_the_question_not_the_whole_prompt(tmp_path) -> None:
    """Sažetak nosi pitanje; ono što je poslano oko njega broji se i ostaje dostupno."""

    composed = InteractiveSession._question_with_context(
        _StubbedContext("SESSION CONTEXT NON_EVIDENCE\nprior answers\nEND"),
        "What does the evidence show?",
    )
    session, console = _console_session(_recorded_run(tmp_path, question=composed))
    session.show_oversight()
    rendered = console.export_text(styles=False)

    assert "question: What does the evidence show?" in rendered
    assert "prior answers" not in rendered
    assert "/oversight prompt" in rendered

    session.show_oversight_prompt()
    assert "prior answers" in console.export_text(styles=False)


class _StubbedContext:
    """Razgovor koji vraća samo zadani kontekst, da se sastavljanje ne mijenja."""

    def __init__(self, context: str) -> None:
        self._history = SimpleNamespace(active=self)
        self._context = context

    def history_prompt_context(self) -> str:
        return self._context


def test_a_message_with_no_delimiter_is_the_question_and_hides_nothing() -> None:
    """Pitanje bez omotača ostaje pitanje; nema što biti zatajeno."""

    projected = project_recorded_question("What does the evidence show?")

    assert projected.asked == "What does the evidence show?"
    assert projected.withheld_characters == 0
    assert projected.has_context is False


def test_an_unrecognised_composition_is_shortened_rather_than_poured_out() -> None:
    """Neprepoznat oblik smije stajati operatera skraćen redak, ne zaslone teksta."""

    projected = project_recorded_question("x" * 5000)

    assert len(projected.asked) <= 400
    assert projected.withheld_characters > 4000
