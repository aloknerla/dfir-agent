"""Argumenti se odlučuju u nadzornom sloju, a ne jedan korak iza njegove odluke.

Mjereno u stvarnoj sesiji: politika je poziv PROPUSTILA, funkcija ga je zatim
odbila zbog argumenata prije nego što je išta otvorila, a zapis je za taj isti
poziv već nosio ``allowed=True, blocked=False``. Izvještaj je otad pošten — zna
imenovati sloj koji je odbio — ali odluka je i dalje bila razdvojena: politika je
odlučivala jednu vrstu dopuštenja, a ugovor o argumentima drugu, na sasvim drugom
mjestu.

Ovdje se traži da poziv bude dopušten samo ako ga prihvate OBOJE, i to prije nego
što funkcija bude dosegnuta. Ugovor ostaje vlasništvo funkcija — čita se s
površine koja je stvarno izgrađena — pa nadzorni sloj ne nosi drugi prijepis
njihovih shema, a poruka koju model dobije ostaje doslovno ona koju je funkcija i
prije pisala, iz iste sheme.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from langchain_core.tools import StructuredTool
from langchain_core.utils.function_calling import convert_to_openai_tool

from forensic_agent.agent.execution_budget import _CellExecutionBudget, _DispatchDenied
from forensic_agent.agent.execution_dispatch import ARGUMENT_REFUSAL, _bound_tool_dispatches
from forensic_agent.agent.tool_bindings.context import ToolBuildContext
from forensic_agent.agent.tool_bindings.output_guard import _capture_tool_outputs
from forensic_agent.agent.tool_bindings.tool_interface import (
    FACADE_FUNCTION_METADATA_KEY,
    INVALID_OPERATION_ARGUMENTS,
    LegacyToolIndex,
    _validation_refusal,
    build_domain_facade,
    build_tool_interface,
    domain_argument_contract,
)
from forensic_agent.agent.tool_operations import (
    OperationValidationError,
    RegistryValuesArguments,
    argument_guidance,
    domain_function,
    validate_operation_arguments,
)
from forensic_agent.oversight import OversightLog, Policy, reconstruct
from forensic_agent.oversight.audit import (
    ACTION_OUTCOMES,
    ACTION_REFUSED_BY_OVERSIGHT,
    ACTION_REFUSED_BY_TOOL,
    OVERSIGHT_RECORD_SCHEMA_ID,
    classify_action_outcome,
)
from forensic_agent.oversight.enforcement import (
    ArgumentContract,
    OversightGate,
    wrap_with_oversight,
)
from forensic_agent.oversight.policy import partition_reasons

#: Funkcija bez ijedne vanjske ovisnosti i bez vezanog dokaza, pa se cijela
#: putanja poziva može izmjeriti offline.
_REFERENCE = "artifact_reference_query"
#: Funkcija koja bi, da je izvedena, pokrenula vanjski program i pisala na disk.
#: Bira se za mjere rizika: odbijenica nad njom ne smije ispasti iz obračuna.
_SPAWNING = "registry_ripper"
#: Funkcija čije odbijeno polje nosi vlastiti opis i primjere u shemi.
_REGISTRY = "registry_query"

#: Poziv koji nijedna operacija ne definira — oblik izmjerene greške, napisan
#: generički da nijedno ime iz slučaja ne uđe u paket.
_UNDEFINED_OPERATION = {"operation": "definitely-not-real"}

#: Izmjereni krivi oblik: putanja ondje gdje ide simbolički selektor. Polje koje
#: ga odbija nosi vlastiti opis i primjere, pa se na njemu mjeri uputa.
_A_PATH_NOT_A_SELECTOR = {
    "operation": "registry_values",
    "hive": "/Users/someone/NTUSER.DAT",
}


def _context(on_tool: Any = None) -> ToolBuildContext:
    return ToolBuildContext(
        disk=None,
        memory_path=None,
        pcap_path=None,
        controlled_scratch=None,
        tool_argument_allowlists=None,
        pcap_sources=None,
        on_tool=on_tool,
    )


def _facade(name: str, on_tool: Any = None, *, reachable: bool = True) -> StructuredTool:
    """Jedna fasada, sagrađena bez ijednog vezanog izvora dokaza.

    ``reachable=False`` daje prazan indeks: funkcija tada nema što izvesti, što je
    dovoljno za mjere u kojima poziv ionako ne smije doći do nje.
    """

    context = _context(on_tool)
    index = None if reachable else LegacyToolIndex()
    return build_domain_facade(name, context, index)


def _policy(tmp_path, *, scratch: bool = False) -> Policy:
    """Ista least-privilege politika, sa ili bez ovlasti za ograničeni scratch.

    Funkcije koje stažiraju kopiju traže tu ovlast, pa bez nje politika odbija
    poziv prije nego što ugovor o argumentima uopće dođe na red — što je i
    redoslijed koji se ovdje mjeri.
    """

    return Policy.secure(
        path_roots=[str(tmp_path)],
        controlled_scratch_attestation_sha256="0" * 64 if scratch else None,
    )


def _gate(
    tmp_path,
    tools: list[StructuredTool],
    *,
    contract: bool = True,
    policy: Policy | None = None,
) -> OversightGate:
    recorder = OversightLog(str(tmp_path / "oversight.jsonl"))
    policy = policy or _policy(tmp_path)
    gate = OversightGate(
        policy,
        recorder,
        argument_contract=domain_argument_contract(tools) if contract else None,
    )
    recorder.open_case(question="q", policy=policy, model="m", engine="langgraph")
    return gate


def _actions(gate: OversightGate) -> list[dict]:
    return [
        row
        for row in OversightLog.load(gate.recorder.path)
        if row.get("event") == "action"
    ]


def _supervised(
    tmp_path,
    name: str,
    *,
    contract: bool = True,
    on_tool: Any = None,
    reachable: bool = True,
    policy: Policy | None = None,
) -> tuple[StructuredTool, OversightGate]:
    tools = [_facade(name, on_tool, reachable=reachable)]
    gate = _gate(tmp_path, tools, contract=contract, policy=policy)
    return wrap_with_oversight(tools, gate)[0], gate


# --- the decision --------------------------------------------------------- #


def test_a_malformed_call_never_reaches_the_function(tmp_path) -> None:
    """Odluka pada prije funkcije, pa funkcija ne smije biti ni dotaknuta."""

    feed: list[tuple[str, object, bool]] = []
    tool, gate = _supervised(
        tmp_path,
        _REFERENCE,
        on_tool=lambda name, args, dt, refused: feed.append((name, args, refused)),
    )

    tool.invoke(dict(_UNDEFINED_OPERATION))

    # Fasada javlja svaki poziv koji je dosegne, i odbijen i izveden; tišina je
    # ovdje mjera da je nije dosegnuo nijedan.
    assert feed == []


def test_the_refusal_is_recorded_once_as_a_denial_of_this_layer(tmp_path) -> None:
    """Jedan poziv, jedan zapis, i taj zapis imenuje tko ga je odbio i zašto."""

    tool, gate = _supervised(tmp_path, _REFERENCE)

    tool.invoke(dict(_UNDEFINED_OPERATION))
    actions = _actions(gate)

    assert len(actions) == 1
    entry = actions[0]
    assert entry["outcome"] == ACTION_REFUSED_BY_OVERSIGHT
    assert entry["outcome_detail"] == INVALID_OPERATION_ARGUMENTS
    assert any(
        reason == f"invalid-arguments:{INVALID_OPERATION_ARGUMENTS}"
        for reason in entry["reasons"]
    )


def test_a_refused_call_is_recorded_as_refused_by_whichever_gate_stopped_it(
    tmp_path,
) -> None:
    """``allowed`` mjeri je li poziv smio proći, a ne što je rekla samo politika.

    Polje je nekoć nosilo odluku POLITIKE, uz obrazloženje da se krivo napisan
    argument ne smije brojati kao pokušaj neovlaštene radnje. Posljedica je bila
    zapis koji o pozivu koji se nikada nije izveo tvrdi ``allowed: true,
    blocked: false``. Izmjereno na zapisanom korpusu, tim je putem prošlo 98 od
    100 odbijenica nadzornog sloja, pa je polje bilo netočno mnogo češće nego
    točno.

    Zabrinutost zbog koje je stajalo kako je stajalo i dalje vrijedi, ali se
    rješava razdvajanjem, a ne netočnim poljem: koji je od dvaju vratara odbio
    poziv i dalje se čita iz ``outcome_detail`` i iz vodećeg razloga.
    """

    tool, gate = _supervised(tmp_path, _REFERENCE)

    tool.invoke(dict(_UNDEFINED_OPERATION))
    entry = _actions(gate)[0]
    summary = reconstruct(OversightLog.load(gate.recorder.path))

    assert entry["allowed"] is False
    assert entry["blocked"] is True
    # Poziv koji nije prošao broji se među zaustavljenima, u oba brojača.
    assert summary["blocked_calls"] == 1
    assert summary["refused_calls"] == 1
    assert summary["outcome_counts"][ACTION_REFUSED_BY_OVERSIGHT] == 1
    # Odbijenica zbog argumenata i dalje se razlikuje od uskrate ovlasti:
    # uskrata ovlasti ne nosi ``outcome_detail``, a ova ga imenuje.
    assert entry["outcome_detail"] == INVALID_OPERATION_ARGUMENTS


def test_the_readable_cause_leads_the_recorded_reasons(tmp_path) -> None:
    """Prvi razlog mora reći ZAŠTO, riječima koje je ugovor već napisao.

    Razlog je nekoć stajao posljednji, iza redaka koji opisuju što bi alat radio
    (``spawns external process``, ``writes to host disk``). Ti se retci pišu
    isključivo u grani u kojoj je politika poziv PROPUSTILA, pa je odbijenica
    bila objašnjena ovlašću koju bi poziv iskoristio — a ograničeni prikaz koji
    pokaže samo prvih nekoliko redaka pokazao bi upravo njih.
    """

    tool, gate = _supervised(tmp_path, _SPAWNING, policy=_policy(tmp_path, scratch=True))

    tool.invoke(dict(_UNDEFINED_OPERATION))
    entry = _actions(gate)[0]
    reasons = entry["reasons"]

    deciding, describing = partition_reasons(reasons)
    # Vodeći razlog je rečenica ugovora, ne opis ovlasti.
    assert reasons[0] == deciding[0]
    assert reasons[0] not in describing
    assert "operation" in reasons[0]
    # Šifra i dalje stoji, strojno čitljiva, odmah iza rečenice.
    assert f"invalid-arguments:{INVALID_OPERATION_ARGUMENTS}" in reasons
    # Opisi ovlasti su zadržani, ali na kraju.
    assert describing
    assert reasons[-len(describing):] == list(describing)
    # Rizik je zadržan: odbijeni poziv nad alatom koji pokreće vanjski program
    # ne smije ispasti iz obračuna rizika izvođenja.
    assert entry["risk"] >= 1


def test_the_recorded_cause_is_the_sentence_the_model_received(tmp_path) -> None:
    """Jedna rečenica, na oba mjesta: u zapisu i u odgovoru koji je model dobio.

    Rečenica se čita iz sheme polja u trenutku odbijanja. Da je zapis nosi
    prepisanu, dvije bi se kopije razišle čim se shema promijeni, i zapis bi
    tvrdio da polje prima nešto što više ne prima.
    """

    tool, gate = _supervised(tmp_path, _REGISTRY, policy=_policy(tmp_path, scratch=True))

    refused = tool.invoke(dict(_A_PATH_NOT_A_SELECTOR))
    entry = _actions(gate)[0]

    guidance = refused["error"]["guidance"]
    assert guidance  # polje s vlastitim opisom i primjerima u shemi
    assert entry["reasons"][: len(guidance)] == list(guidance)
    # I dalje ista odbijenica, s istim ishodom i istom šifrom.
    assert entry["outcome"] == ACTION_REFUSED_BY_OVERSIGHT
    assert entry["outcome_detail"] == INVALID_OPERATION_ARGUMENTS
    assert entry["allowed"] is False and entry["blocked"] is True


def test_the_run_record_stamps_the_convention_it_was_written_under(tmp_path) -> None:
    """Značenje polja ``allowed`` se promijenilo, pa zapis mora reći koje nosi.

    Ništa se ne migrira: stariji zapis nema ovo polje, i to je ono što ga
    imenuje kao zapis prve konvencije. Usporedba brojeva odbijenica preko te
    granice nije valjana dok se ne pročita.
    """

    _, gate = _supervised(tmp_path, _REFERENCE)
    opened = [
        row
        for row in OversightLog.load(gate.recorder.path)
        if row.get("event") == "case_open"
    ]

    assert len(opened) == 1
    assert opened[0]["schema_id"] == OVERSIGHT_RECORD_SCHEMA_ID
    assert OVERSIGHT_RECORD_SCHEMA_ID.endswith(".v2")
    # Zapis bez polja je zapis prve konvencije, i čitači ga i dalje čitaju.
    assert classify_action_outcome({"outcome": ACTION_REFUSED_BY_OVERSIGHT}) == (
        ACTION_REFUSED_BY_OVERSIGHT
    )


def test_a_contract_refusal_records_that_nothing_ran(tmp_path) -> None:
    """Zapis i stvarnost o istom pozivu: alat nije dosegnut, i tako i piše."""

    reached: list[object] = []
    tool, gate = _supervised(
        tmp_path,
        _REFERENCE,
        on_tool=lambda name, args, dt, refused: reached.append(name),
    )

    tool.invoke(dict(_UNDEFINED_OPERATION))
    entry = _actions(gate)[0]

    assert reached == []  # funkcija nije dotaknuta
    assert entry["allowed"] is False  # i zapis o tome ne tvrdi suprotno
    assert entry["blocked"] is True


def test_no_gate_is_weakened_by_moving_the_decision(tmp_path) -> None:
    """Bez vezanog ugovora funkcija odbija sama, kao i prije — nitko ne prolazi."""

    tool, gate = _supervised(tmp_path, _REFERENCE, contract=False)

    refused = tool.invoke(dict(_UNDEFINED_OPERATION))
    actions = _actions(gate)

    assert refused["error"]["code"] == INVALID_OPERATION_ARGUMENTS
    assert len(actions) == 1
    # Ista odbijenica, samo je sada izrekla funkcija; poziv ni tada nije prošao.
    assert actions[0]["outcome"] == ACTION_REFUSED_BY_TOOL


def test_the_policy_still_decides_first(tmp_path) -> None:
    """Ugovor je dodan uz politiku, a ne pred nju.

    Poziv koji politika odbija mora dobiti razlog politike, čak i kad su mu i
    argumenti neispravni: inače bi nova provjera odgovarala na pitanje o ovlasti
    porukom o obliku, a odbijenica bi izgubila svoj pravi razlog.
    """

    tool, gate = _supervised(tmp_path, _REGISTRY, reachable=False)

    blocked = tool.invoke(dict(_UNDEFINED_OPERATION))
    entry = _actions(gate)[0]

    assert blocked["error"] == "BLOCKED by oversight policy"
    assert entry["outcome"] == ACTION_REFUSED_BY_OVERSIGHT
    assert entry["outcome_detail"] is None
    assert entry["blocked"] is True
    assert any("ungranted capability" in reason for reason in entry["reasons"])
    assert not any(reason.startswith("invalid-arguments:") for reason in entry["reasons"])


# --- what the model reads ------------------------------------------------- #


def test_the_refusal_the_model_receives_is_the_functions_own(tmp_path) -> None:
    """Poruka se ne prepisuje u nadzornom sloju: to je ista odbijenica."""

    function = domain_function(_REFERENCE)
    with pytest.raises(OperationValidationError) as caught:
        validate_operation_arguments(function, _UNDEFINED_OPERATION)
    expected = _validation_refusal(function, caught.value)

    tool, _gate_ = _supervised(tmp_path, _REFERENCE)
    refused = tool.invoke(dict(_UNDEFINED_OPERATION))

    assert refused == expected


def test_the_guidance_still_comes_from_the_schema(tmp_path) -> None:
    """Uputa ostaje pročitana iz sheme u trenutku odbijanja, ne prepisana uz nju."""

    tool, _gate_ = _supervised(
        tmp_path,
        _REGISTRY,
        reachable=False,
        policy=_policy(tmp_path, scratch=True),
    )

    refused = tool.invoke(dict(_A_PATH_NOT_A_SELECTOR))

    assert refused["deterministic_error"] is True
    expected = argument_guidance(_REGISTRY, _A_PATH_NOT_A_SELECTOR)
    assert refused["error"]["guidance"] == expected
    # Rečenica dolazi iz opisa polja, a primjeri iz istog polja; ni jedno ni drugo
    # ne postoji drugdje da bi se moglo razići s onim što funkcija prima.
    hive = next(line for line in expected if line.startswith("hive:"))
    described = RegistryValuesArguments.model_fields["hive"]
    assert described.description and described.description in hive
    for example in described.examples or ():
        assert example in hive


# --- what the contract covers --------------------------------------------- #


def test_the_contract_answers_only_for_the_functions_on_this_surface() -> None:
    """Ugovor se čita s izgrađene površine, pa ne sudi tuđim pozivima."""

    contract = domain_argument_contract(build_tool_interface(_context()))

    assert contract is not None
    # Ono što nadzorni sloj traži je protokol, ne ova klasa.
    assert isinstance(contract, ArgumentContract)
    assert contract.refusal(_REFERENCE, dict(_UNDEFINED_OPERATION)) is not None
    # Funkcija koja na ovoj površini ne postoji nema što ovdje reći.
    assert contract.refusal("read_text_file", {"path": "/somewhere"}) is None


def test_a_surface_that_declares_no_facade_binds_no_contract() -> None:
    """Povijesna površina dijeli imena, ali ne i potpise, pa se ne smije suditi.

    Nekoliko imena iz registra postoji i na povijesnoj površini s posve drugim
    argumentima. Ugovor se zato veže na ono što je funkcija OBJAVILA o sebi, a ne
    na golo ime; inače bi povijesni poziv bio odbijen po shemi koja nikad nije
    bila njegova.
    """

    def registry_query(hive: str = "SYSTEM") -> dict:
        """A historical binding that shares a name and nothing else."""

        return {"hive": hive}

    historical = StructuredTool.from_function(registry_query, name="registry_query")

    assert domain_argument_contract([historical]) is None


def test_the_declaration_survives_the_wrappers_between_build_and_the_gate() -> None:
    """Ugovor se veže poslije omotača, pa izjava mora preživjeti svaki od njih."""

    built = build_tool_interface(_context())

    wrapped = _capture_tool_outputs(built, capture_store=None)
    contract = domain_argument_contract(wrapped)
    assert contract is not None
    assert contract.refusal(_REFERENCE, dict(_UNDEFINED_OPERATION)) is not None

    supervised = wrap_with_oversight(wrapped, OversightGate(Policy.permissive()))
    still_declared = domain_argument_contract(supervised)
    assert still_declared is not None
    assert still_declared.refusal(_REFERENCE, dict(_UNDEFINED_OPERATION)) is not None


def test_the_declaration_is_not_part_of_the_model_visible_surface() -> None:
    """Izjava je za slojeve, ne za model: ne smije ući u zapečaćeni sažetak."""

    published = json.dumps(
        [convert_to_openai_tool(tool) for tool in build_tool_interface(_context())],
        sort_keys=True,
    )

    assert FACADE_FUNCTION_METADATA_KEY not in published


# --- what the run accounts for -------------------------------------------- #


def test_a_refused_call_hands_back_its_forensic_reservation(tmp_path) -> None:
    """Odbijenica ne čita dokaz, pa ne smije potrošiti dopuštenje za čitanje."""

    budget = _CellExecutionBudget(
        started_monotonic=100.0,
        deadline_monotonic=1000.0,
        max_investigation_requests=4,
        max_model_requests=6,
        max_tool_calls=1,
        clock=lambda: 100.0,
    )
    tool, _gate_ = _supervised(tmp_path, _REFERENCE)
    metered = _bound_tool_dispatches([tool], budget)[0]

    metered.invoke(dict(_UNDEFINED_OPERATION))

    metrics = budget.metrics()
    assert metrics["refused_call_count"] == 1
    assert metrics["evidence_reading_dispatch_count"] == 0
    assert metrics["refusal_reasons"] == [ARGUMENT_REFUSAL]
    # Dopušteno očitanje dokaza i dalje stoji na raspolaganju, i strop se ne diže.
    metered.invoke({"operation": "hardware_vendor", "address": "00:1B:21:3A:4B:5C"})
    assert budget.metrics()["evidence_reading_dispatch_count"] == 1
    # Drugi argumenti su drugo pitanje, pa jedino ono može posvjedočiti o stropu:
    # bajt-identično ponavljanje uspješnog poziva sada se poslužuje iz zapisa bez
    # rezervacije i strop ne dotiče.
    with pytest.raises(_DispatchDenied, match="max_tool_calls"):
        metered.invoke({"operation": "hardware_vendor", "address": "00:1B:21:3A:4B:5D"})


def test_a_refused_call_still_counts_towards_the_runs_maximum_risk(tmp_path) -> None:
    """Odbijen pokušaj nad funkcijom koja piše i pokreće program ne ispada iz rizika.

    Rizik iskazuje ovlast koju bi poziv iskoristio. Poništiti ga zato što je poziv
    zaustavljen značilo bi tiho izbrisati pokušaj iz najviše izmjerene razine.
    """

    tool, gate = _supervised(tmp_path, _SPAWNING, reachable=False)

    tool.invoke(dict(_UNDEFINED_OPERATION))
    summary = reconstruct(OversightLog.load(gate.recorder.path))

    assert summary["max_risk"] == "low"
    assert summary["timeline"][0]["risk"] == "low"


def test_the_reconstruction_counts_the_refusal_exactly_once(tmp_path) -> None:
    """Zbroj ishoda mora ostati jednak broju poziva; odbijenica se ne gubi."""

    tool, gate = _supervised(tmp_path, _REFERENCE)

    tool.invoke(dict(_UNDEFINED_OPERATION))
    summary = reconstruct(OversightLog.load(gate.recorder.path))

    assert summary["tool_calls"] == 1
    assert sum(summary["outcome_counts"].values()) == 1
    assert set(summary["outcome_counts"]) == ACTION_OUTCOMES
    assert summary["outcome_counts"][ACTION_REFUSED_BY_OVERSIGHT] == 1
    assert [row["outcome"] for row in summary["refusal_summary"]] == [
        ACTION_REFUSED_BY_OVERSIGHT
    ]
    assert summary["refusal_summary"][0]["detail"] == INVALID_OPERATION_ARGUMENTS
