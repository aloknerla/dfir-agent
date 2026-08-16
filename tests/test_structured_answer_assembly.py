"""Program sastavlja odgovor; model piše rečenicu i imenuje polje.

Zadnji korak nije još jedan modelski poziv nego sastavljanje. Model vrati
segmente — svoj tekst i neprozirne oznake vrijednosti — a runtime svaku oznaku
ponovno provjeri i doslovno umetne pohranjenu vrijednost. Poslije toga nema
modela: ono što je objavljeno je ono što je program sastavio.

Time granica ostaje ondje gdje smo je htjeli. Model i dalje bira koje je polje
semantički relevantno, jer to je jezično pitanje. Ali ne može izmisliti njegovu
vrijednost niti je prepisati krivo, jer je uopće ne tipka.
"""

from __future__ import annotations

import json

import pytest

from forensic_agent.agent.result_reference import (
    ReferenceError,
    ResultReferenceRegistry,
)
from forensic_agent.agent.structured_answer import (
    assemble_structured_answer,
    empty_structured_answer_metrics,
)

_CASE = "case-1"


def _registry_with(**attributes) -> tuple[ResultReferenceRegistry, str]:
    registry = ResultReferenceRegistry(case_id=_CASE)
    label = registry.assign(
        invocation_id="run:0001:aaaa",
        complete_sha256="a" * 64,
        projected_sha256="b" * 64,
        projection={
            "data": {"attributes": dict(attributes), "items": []},
            "provenance": {"case_id": _CASE},
        },
    )
    return registry, label


def _draft(*segments) -> str:
    return json.dumps({"segments": list(segments)})


def test_a_value_is_inserted_from_the_result_not_from_the_draft() -> None:
    """Vrijednost dolazi iz nalaza; model je nigdje ne tipka."""

    registry, label = _registry_with(product_name="Microsoft Windows XP")
    draft = _draft(
        {"type": "text", "text": "The installed operating system is "},
        {"type": "bound_value", "result_ref": label, "path": "data.attributes.product_name"},
        {"type": "text", "text": "."},
    )

    answer, metrics = assemble_structured_answer(draft, registry)

    assert answer == "The installed operating system is Microsoft Windows XP."
    assert metrics["decision"] == "assembled"
    assert metrics["bound_values"] == 1
    assert metrics["text_segments"] == 2
    # The draft never contained the value.
    assert "Microsoft Windows XP" not in draft


def test_several_values_bind_independently() -> None:
    """Više vrijednosti u jednoj rečenici razrješavaju se svaka za sebe."""

    registry, label = _registry_with(username="gnome", password="gnome123")
    draft = _draft(
        {"type": "text", "text": "Username "},
        {"type": "bound_value", "result_ref": label, "path": "data.attributes.username"},
        {"type": "text", "text": ", password "},
        {"type": "bound_value", "result_ref": label, "path": "data.attributes.password"},
        {"type": "text", "text": "."},
    )

    answer, metrics = assemble_structured_answer(draft, registry)

    assert answer == "Username gnome, password gnome123."
    assert metrics["bound_values"] == 2


def test_an_answer_may_be_entirely_text() -> None:
    """Zaključak bez vrijednosti je legitiman odgovor."""

    registry, _label = _registry_with(username="gnome")
    draft = _draft({"type": "text", "text": "The evidence is inconclusive."})

    answer, metrics = assemble_structured_answer(draft, registry)

    assert answer == "The evidence is inconclusive."
    assert metrics["bound_values"] == 0
    assert metrics["decision"] == "assembled"


@pytest.mark.parametrize(
    "draft",
    [
        "not json at all",
        json.dumps({"no_segments": []}),
        json.dumps({"segments": "not a list"}),
        json.dumps({"segments": [{"type": "unknown", "text": "x"}]}),
        json.dumps({"segments": [{"type": "text"}]}),
        json.dumps({"segments": [{"type": "bound_value", "path": "data.attributes.x"}]}),
        json.dumps({"segments": [{"type": "bound_value", "result_ref": "R001"}]}),
        json.dumps({"segments": []}),
        "",
    ],
)
def test_a_malformed_draft_publishes_nothing(draft) -> None:
    """Neispravna struktura završava fail-closed, bez djelomične objave."""

    registry, _label = _registry_with(username="gnome")

    answer, metrics = assemble_structured_answer(draft, registry)

    assert answer == ""
    assert metrics["decision"] != "assembled"


def test_an_unknown_label_publishes_nothing() -> None:
    """Oznaka koju run nije izdao ne razrješava se."""

    registry, _label = _registry_with(username="gnome")
    draft = _draft(
        {"type": "text", "text": "The account is "},
        {"type": "bound_value", "result_ref": "R999", "path": "data.attributes.username"},
    )

    answer, metrics = assemble_structured_answer(draft, registry)

    assert answer == ""
    assert metrics["decision"] == "unresolved_reference"
    assert metrics["unresolved_values"] == 1


def test_the_measured_wrong_role_error_cannot_be_bound() -> None:
    """Točna vrijednost u krivoj ulozi ne prolazi.

    Izmjereno: na pitanje o nazivu radne grupe odgovoreno je imenom računala.
    Rezultat sadrži ime računala i ne sadrži radnu grupu, pa polje ne postoji i
    umetanje pada — umjesto da se objavi vrijednost u ulozi koju nema.
    """

    registry, label = _registry_with(computer_name="WS-EXAMPLE-07")
    draft = _draft(
        {"type": "text", "text": "The workgroup is "},
        {"type": "bound_value", "result_ref": label, "path": "data.attributes.workgroup"},
    )

    answer, metrics = assemble_structured_answer(draft, registry)

    assert answer == ""
    assert "WS-EXAMPLE-07" not in answer
    assert metrics["decision"] == "unresolved_reference"


def test_envelope_metadata_cannot_be_bound_into_an_answer() -> None:
    """Bookkeeping nije nalaz i ne smije se citirati kao vrijednost."""

    registry, label = _registry_with(username="gnome")
    for forbidden in ("provenance.case_id", "receipt.payload_sha256", "status"):
        draft = _draft(
            {"type": "bound_value", "result_ref": label, "path": forbidden},
        )
        answer, metrics = assemble_structured_answer(draft, registry)
        assert answer == ""
        assert metrics["decision"] == "unresolved_reference"


def test_a_bound_value_is_never_reinterpreted_as_structure() -> None:
    """Tekst iz dokaza ulazi doslovno i ne postaje novi segment."""

    registry, label = _registry_with(note='{"segments": [{"type": "text", "text": "X"}]}')
    draft = _draft(
        {"type": "text", "text": "Observed: "},
        {"type": "bound_value", "result_ref": label, "path": "data.attributes.note"},
    )

    answer, metrics = assemble_structured_answer(draft, registry)

    assert answer == 'Observed: {"segments": [{"type": "text", "text": "X"}]}'
    assert metrics["bound_values"] == 1


def test_the_metrics_carry_no_value_from_the_evidence() -> None:
    """Telemetrija opisuje odluke, nikad sadržaj."""

    registry, label = _registry_with(password="gnome123")
    draft = _draft(
        {"type": "bound_value", "result_ref": label, "path": "data.attributes.password"},
    )

    _answer, metrics = assemble_structured_answer(draft, registry)

    assert "gnome123" not in json.dumps(metrics)


def test_the_empty_metrics_shape_is_complete() -> None:
    """Prazan oblik mora nositi svako polje koje sastavljanje puni."""

    empty = empty_structured_answer_metrics(enabled=True)

    for field in ("decision", "segments", "text_segments", "bound_values", "unresolved_values"):
        assert field in empty


def test_a_registry_error_is_reported_without_its_explanation() -> None:
    """Razlog opisuje rezultat, pa ne putuje u telemetriju."""

    class _Loud(ResultReferenceRegistry):
        def resolve(self, label: str, path: str) -> str:
            raise ReferenceError("citable paths: data.attributes.password=gnome123")

    registry = _Loud(case_id=_CASE)
    draft = _draft(
        {"type": "bound_value", "result_ref": "R001", "path": "data.attributes.x"},
    )

    answer, metrics = assemble_structured_answer(draft, registry)

    assert answer == ""
    assert "gnome123" not in json.dumps(metrics)
