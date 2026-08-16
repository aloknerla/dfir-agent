"""Hardware-address prefix to registered organisation.

Two runs of this project over identical recorded bytes once reached opposite
conclusions about which adapter an address belonged to, because nothing in the
tool surface performed the lookup and each run guessed. A registry lookup is not
an inference, so it is pinned here as one: same address, same table, same answer,
with the table's digest carried in the result so the reading stays attributable.

The second half of this file is about the other side of the same failure: a
lookup nothing on the model surface can call is a lookup no run will make. What
is pinned there is that the operation reaches a model by default, that it reaches
the SEALED palette never, that an address is judged before the table is opened,
and that nothing the table does escapes as an exception.
"""

import hashlib
from pathlib import Path

import pytest

from forensic_agent.agent.evidence_regions import operation_region
from forensic_agent.agent.tool_bindings.tool_interface import executed_backend
from forensic_agent.agent.tool_operations import (
    DOMAIN_FUNCTIONS,
    OperationValidationError,
    validate_operation_arguments,
)
from forensic_agent.agent.tool_registry import ToolRegistrySnapshot, build_tool_registry
from forensic_agent.core.result_contract import EvidenceClass
from forensic_agent.tools import hardware_vendor as hv

#: The registry's own layout: prefix, short name, and an optional long name,
#: separated by tabs, with comment lines and an assignment narrower than a full
#: block.
_TABLE = (
    "# a comment line\n"
    "\n"
    "00:10:A4\tXircomRe\tXircom\t# RealPort 10/100 PC Card\n"
    "00:50:8B\tCompaq\tCompaq Computer Corporation\n"
    "00:1B:C5:00:00:00/36\tSmallReg\tA Small Registrant\n"
    "AA:BB:CC\tShortOnly\n"
)


@pytest.fixture
def table(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "manuf"
    path.write_text(_TABLE, encoding="utf-8")
    monkeypatch.setenv("DFA_OUI_TABLE", str(path))
    hv.reset_cache()
    yield path
    hv.reset_cache()


# --- the reading itself ------------------------------------------------------ #


def test_a_prefix_resolves_to_the_registered_organisation(table):
    out = hv.hardware_vendor("00:10:A4:93:3E:09")
    assert out["vendor"] == "Xircom"
    assert out["prefix"] == "0010A4"
    assert "error" not in out


def test_separators_do_not_change_the_reading(table):
    forms = ("0010a4933e09", "00-10-A4-93-3E-09", "00:10:a4:93:3e:09", "0010.a493.3e09")
    readings = {hv.hardware_vendor(form)["vendor"] for form in forms}
    assert readings == {"Xircom"}


def test_a_prefix_alone_is_enough(table):
    """An examiner often has only the assignment block, not a whole address."""

    assert hv.hardware_vendor("00:50:8B")["vendor"] == "Compaq Computer Corporation"


def test_a_narrower_assignment_wins_over_the_block_containing_it(table):
    """Reporting the owner of the surrounding range would name the wrong organisation."""

    out = hv.hardware_vendor("00:1B:C5:00:00:01")
    assert out["vendor"] == "A Small Registrant"
    assert len(out["prefix"]) > 6


def test_a_row_without_a_long_name_still_answers(table):
    out = hv.hardware_vendor("AA:BB:CC:11:22:33")
    assert out["vendor"] == "ShortOnly"
    assert out["vendor_short"] == "ShortOnly"


# --- what the result carries ------------------------------------------------- #


def test_the_answering_table_is_identified_by_digest(table):
    """A reading is attributable to a version of the registry, not to whatever was installed."""

    out = hv.hardware_vendor("00:10:A4:93:3E:09")
    registry = out["registry"]
    assert registry["path"] == str(table)
    assert len(registry["sha256"]) == 64
    assert registry["entries"] >= 4


def test_the_same_address_reads_the_same_way_every_time(table):
    first = hv.hardware_vendor("00:10:A4:93:3E:09")
    second = hv.hardware_vendor("00:10:A4:93:3E:09")
    assert first == second


# --- refusals and absences --------------------------------------------------- #


def test_an_unassigned_prefix_is_reported_as_unassigned_not_guessed(table):
    out = hv.hardware_vendor("FF:FF:FF:11:22:33")
    assert out["vendor"] is None
    assert "no assignment" in out["note"]
    assert "error" not in out


def test_an_address_too_short_to_carry_a_prefix_is_refused(table):
    assert "error" in hv.hardware_vendor("00:10")
    assert "error" in hv.hardware_vendor("")


def test_a_missing_registry_is_reported_rather_than_raised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("DFA_OUI_TABLE", str(tmp_path / "absent"))
    hv.reset_cache()
    try:
        out = hv.hardware_vendor("00:10:A4:93:3E:09")
        assert "error" in out
        assert "registry" in out["error"]
    finally:
        hv.reset_cache()


def test_an_unreadable_registry_is_reported_rather_than_raised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """A directory where a file was expected must not surface as a stack trace."""

    directory = tmp_path / "manuf-dir"
    directory.mkdir()
    monkeypatch.setenv("DFA_OUI_TABLE", str(directory))
    hv.reset_cache()
    try:
        assert "error" in hv.hardware_vendor("00:10:A4:93:3E:09")
    finally:
        hv.reset_cache()


# --- on the model-facing surface --------------------------------------------- #


def _surface() -> ToolRegistrySnapshot:
    """The palette a caller gets by default."""

    return build_tool_registry(None, capture=False, project=False)


def _reference_facade() -> object:
    return next(
        tool
        for tool in _surface().tools
        if str(tool.name) == "artifact_reference_query"
    )


def test_the_lookup_is_reachable_by_default_on_the_reference_facade():
    """Sposobnost stiže modelu kroz fasadu artifact_reference_query po zadanom."""

    assert "hardware_vendor" in DOMAIN_FUNCTIONS["artifact_reference_query"].operation_names()
    assert "hardware_vendor" in _reference_facade().description


def test_the_registry_lookup_reads_no_evidence_and_says_so_where_that_is_recorded():
    """Odgovor dolazi iz generičke tablice, pa ne otvara nijednu regiju medija.

    Da je pripisan regiji, pokretanje koje je samo pročitalo proizvođača tvrdilo
    bi da je pogledalo u dokaz — a adresu je pročitalo nešto drugo, i to je
    čitanje koje se broji.
    """

    assert operation_region("artifact_reference_query", "hardware_vendor") is None
    definition = DOMAIN_FUNCTIONS["artifact_reference_query"].operation("hardware_vendor")
    # OBSERVED, not DERIVED: the registrant's name is the table's own value, not
    # anything computed here, and the component that ships the table is declared
    # so a reading can be tied to the version that produced it.
    assert definition.evidence_class is EvidenceClass.OBSERVED
    assert definition.method is None
    assert [(b.name, b.role) for b in definition.backends] == [("tshark", "producer")]
    assert executed_backend("artifact_reference_query", "hardware_vendor", {}) == "tshark"


@pytest.mark.parametrize(
    "address",
    ["00:1B:21:3A:4B:5C", "001b21", "00-1B-21-3A-4B-5C", "0010.a493.3e09", "00 10 A4"],
)
def test_every_written_form_of_an_address_validates(address: str):
    validated = validate_operation_arguments(
        "artifact_reference_query", {"operation": "hardware_vendor", "address": address}
    )
    assert str(validated.operation) == "hardware_vendor"


@pytest.mark.parametrize(
    "address",
    [
        "",
        "0",
        "not-an-address",
        "../../etc/passwd",
        "00:1B:21; id",
        "00:1B:21 && $(whoami)",
        "00:1B:21\n00:50:8B",
    ],
)
def test_a_value_that_is_not_an_address_is_refused_before_the_table_is_opened(address: str):
    """Obrazac prima heksadekadske znamenke i četiri razdjelnika — i ništa drugo.

    Vrijednost koja bi drugdje bila putanja ili naredba ovdje ne prolazi kroz
    validaciju, pa nikad ne stigne ni do datoteke ni do usporedbe.
    """

    with pytest.raises(OperationValidationError):
        validate_operation_arguments(
            "artifact_reference_query",
            {"operation": "hardware_vendor", "address": address},
        )


def test_an_argument_of_the_sibling_operation_is_refused():
    """Dijeliti funkciju nije dijeliti argumente: katalog i registar su dva pitanja."""

    for call in (
        {"operation": "hardware_vendor", "address": "00:1B:21", "name_or_keyword": "x"},
        {"operation": "lookup", "name_or_keyword": "Prefetch", "address": "00:1B:21"},
    ):
        with pytest.raises(OperationValidationError):
            validate_operation_arguments("artifact_reference_query", call)


def test_a_lookup_that_raises_comes_back_as_a_structured_result(
    monkeypatch: pytest.MonkeyPatch,
):
    """Iznimka iz tablice ne smije izaći u petlju agenta nego se vraća kao rezultat."""

    def _explode(address: str) -> dict:
        raise RuntimeError("the registry blew up " + "x" * 400)

    monkeypatch.setattr(hv, "hardware_vendor", _explode)

    result = _reference_facade().invoke(
        {"operation": "hardware_vendor", "address": "00:1B:21:3A:4B:5C"}
    )

    assert isinstance(result, dict)
    assert "error" in result
    assert len(str(result["error"])) <= 2000


def test_the_answering_table_reaches_the_caller_through_the_facade(table):
    """Pripisivost preživljava granicu: pečat tablice putuje s očitanjem."""

    result = _reference_facade().invoke(
        {"operation": "hardware_vendor", "address": "00:10:A4:93:3E:09"}
    )

    assert result["vendor"] == "Xircom"
    assert result["registry"]["sha256"] == hashlib.sha256(
        Path(table).read_bytes()
    ).hexdigest()
