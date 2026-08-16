"""Run mora znati koje je regije medija pročitao, a koje nije ni dotaknuo.

Mjereni promašaj: run je izlistao direktorije, našao traženu mapu praznom i
zaključio da odgovor nije utvrđen — a izbrisane zapise i prostor na koji nijedan
direktorijski unos ne pokazuje nije ni otvorio. Znanje mu nije nedostajalo;
nedostajala mu je činjenica o vlastitom radu: pročitao je jednu regiju medija, a
zaključio o mediju.

Regija se veže uz OPERACIJU, ne uz funkciju. Ista funkcija zna čitati i ono što
datotečni sustav navodi i ono što ne navodi, pa bi tvrdnja na razini funkcije
bila neistinita za dio njezinih operacija.

Neuspjelo čitanje ne pokriva ništa. Jedino ``not_found`` znači da je medij
odgovorio; svaka druga klasifikacija znači da pročitan nije, pa regija ostaje
nepročitana.

Ono što nijedan raspoloživi alat ne može doseći nije propust i ne smije se
prijaviti kao propust — inače bi svaki run nad memorijom optuživao sam sebe za
neizvedivo.
"""

from __future__ import annotations

from forensic_agent.agent.evidence_regions import (
    EVIDENCE_REGIONS,
    REGION_DELETED_ENTRIES,
    REGION_FILESYSTEM_LISTED,
    REGION_UNREFERENCED,
    operation_region,
    reachable_regions,
    region_of_call,
    regions_read,
    unread_regions,
    unread_regions_statement,
)
from forensic_agent.agent.tool_operations import DOMAIN_FUNCTIONS
from forensic_agent.core.tool_failure import tool_failure_result
from forensic_agent.core.tool_result import (
    ProvenanceType,
    adapt_legacy_result,
    make_provenance,
)

#: Every disk-side function, so a run is judged against what it could reach.
_DISK_TOOLS = ("filesystem_query", "recover_deleted", "bulk_extract")

_LIST_DIRECTORY = {"operation": "list_directory", "path": "/"}
_LIST_DELETED = {"operation": "list_deleted", "path": "/"}
_LIST_FEATURES = {"operation": "list_features"}


def _ok(tool: str, arguments: dict) -> dict:
    return {
        "tool": tool,
        "arguments": dict(arguments),
        "result": {"status": "ok", "data": {"attributes": {}, "items": []}},
    }


def _failed(tool: str, arguments: dict, error: BaseException) -> dict:
    """One call that ran and failed, carrying the classification the run recorded."""

    legacy = tool_failure_result(error, subject="/x", backend="dfvfs")
    standardized = adapt_legacy_result(
        legacy,
        data_type="filesystem.directory_listing",
        provenance=make_provenance(
            provenance_type=ProvenanceType.CASE_EVIDENCE,
            invocation_id="inv-1",
            source_id="src-1",
            artifact_locator="artifact://image",
            tool_name=tool,
            tool_version="test",
            case_id="case",
        ),
    )
    return {
        "tool": tool,
        "arguments": dict(arguments),
        "result": standardized.model_dump(mode="json"),
    }


def test_the_operation_decides_the_region_not_the_function() -> None:
    """Jedna funkcija čita i ono što sustav navodi i ono što ne navodi."""

    assert operation_region("filesystem_query", "list_directory") == REGION_FILESYSTEM_LISTED
    assert operation_region("filesystem_query", "search_in_file") == REGION_FILESYSTEM_LISTED
    assert operation_region("recover_deleted", "list_deleted") == REGION_DELETED_ENTRIES
    assert operation_region("recover_deleted", "recover_content") == REGION_DELETED_ENTRIES
    assert operation_region("bulk_extract", "list_features") == REGION_UNREFERENCED


def test_every_registered_operation_declares_what_it_reads() -> None:
    """Nova operacija ne smije tiho postati operacija bez regije."""

    for function in DOMAIN_FUNCTIONS.values():
        for operation in function.operations:
            # ``None`` is a declaration too — it says this operation opens no
            # region of the evidence image — but it must be a declared one.
            operation_region(function.name, operation.name)


def test_a_successful_read_covers_its_region() -> None:
    """Pročitano je ono što je alat stvarno pročitao, ne ono što je pozvano."""

    read = regions_read([_ok("filesystem_query", _LIST_DIRECTORY)])

    assert read == frozenset({REGION_FILESYSTEM_LISTED})


def test_a_failed_read_covers_nothing() -> None:
    """Čitanje koje nije isporučilo bajtove nije pregledalo regiju."""

    records = [_failed("recover_deleted", _LIST_DELETED, OSError("unable to read buffer"))]

    assert regions_read(records) == frozenset()
    unread = {region.name for region in unread_regions(records, tools=_DISK_TOOLS)}
    assert REGION_DELETED_ENTRIES in unread


def _partial(
    tool: str, arguments: dict, *, examined: int | None, items: list | None = None
) -> dict:
    """One call that ran, reported incomplete coverage, and states what it read."""

    coverage: dict = {"complete": False, "reason": "bounded or unreadable"}
    if examined is not None:
        coverage["examined"] = examined
    return {
        "tool": tool,
        "arguments": dict(arguments),
        "result": {
            "status": "partial",
            "data": {"attributes": {}, "items": list(items or [])},
            "coverage": coverage,
        },
    }


def test_a_partial_read_that_examined_nothing_covers_nothing() -> None:
    """Obilazak kojemu se nijedan direktorij nije otvorio nije pročitao regiju.

    Djelomično je jedna riječ za dvije činjenice. Hod koji je pregledao dio
    opsega jest otvorio regiju; hod kojemu se svaki direktorij odbio otvoriti
    nije pregledao ništa, a regija pripisana takvom čitanju dopustila bi tvrdnju
    "nema izbrisanih zapisa" na temelju čitanja koje se nije dogodilo.
    """

    records = [_partial("recover_deleted", _LIST_DELETED, examined=0)]

    assert regions_read(records) == frozenset()
    unread = {region.name for region in unread_regions(records, tools=_DISK_TOOLS)}
    assert REGION_DELETED_ENTRIES in unread


def test_a_partial_read_that_examined_part_of_its_scope_covers_its_region() -> None:
    """Omeđen run nije slijep run: ono što jest pročitano ostaje pročitano."""

    bounded = [_partial("recover_deleted", _LIST_DELETED, examined=320)]
    assert regions_read(bounded) == frozenset({REGION_DELETED_ENTRIES})

    # Rows settle it whatever the count says, and a tool that states no count at
    # all keeps the benefit of the doubt rather than being read as zero.
    with_rows = [
        _partial("recover_deleted", _LIST_DELETED, examined=0, items=[{"name": "x"}])
    ]
    assert regions_read(with_rows) == frozenset({REGION_DELETED_ENTRIES})
    silent = [_partial("recover_deleted", _LIST_DELETED, examined=None)]
    assert regions_read(silent) == frozenset({REGION_DELETED_ENTRIES})


def test_a_read_that_established_absence_covers_its_region() -> None:
    """Medij koji je odgovorio 'nema ga' je pročitan medij."""

    absent = FileNotFoundError("no such file or directory")
    records = [_failed("recover_deleted", _LIST_DELETED, absent)]

    assert regions_read(records) == frozenset({REGION_DELETED_ENTRIES})


def test_a_region_never_attempted_is_reported_unread() -> None:
    """Regija koju run nije ni pokušao otvoriti mora biti imenovana."""

    records = [_ok("filesystem_query", _LIST_DIRECTORY)]
    unread = {region.name for region in unread_regions(records, tools=_DISK_TOOLS)}

    assert unread == {REGION_DELETED_ENTRIES, REGION_UNREFERENCED}


def test_a_region_no_available_tool_can_reach_is_not_an_omission() -> None:
    """Neizvedivo se ne prijavljuje kao propust."""

    memory_only = ("memory_query", "memory_malware_scan")

    assert reachable_regions(memory_only) == frozenset()
    assert unread_regions([], tools=memory_only) == ()
    assert unread_regions_statement([], tools=memory_only) is None

    # Half a disk toolset reaches half the medium, and is judged on that half.
    # ``filesystem_query`` is deliberately not the example any more: its content
    # search reads the raw image whole, so it reaches the very region a
    # directory walk cannot open, and a run holding it is judged on that too.
    deleted_only = ("recover_deleted",)
    assert reachable_regions(deleted_only) == frozenset({REGION_DELETED_ENTRIES})
    assert REGION_UNREFERENCED not in {
        region.name for region in unread_regions([], tools=deleted_only)
    }
    assert reachable_regions(("filesystem_query",)) == frozenset(
        {REGION_FILESYSTEM_LISTED, REGION_UNREFERENCED}
    )


def test_a_run_that_read_everything_reachable_states_nothing() -> None:
    """Kad nema propusta, nema ni rečenice."""

    records = [
        _ok("filesystem_query", _LIST_DIRECTORY),
        _ok("recover_deleted", _LIST_DELETED),
        _ok("bulk_extract", _LIST_FEATURES),
    ]

    assert unread_regions(records, tools=_DISK_TOOLS) == ()
    assert unread_regions_statement(records, tools=_DISK_TOOLS) is None


def test_the_statement_names_regions_and_asks_for_nothing() -> None:
    """Iskaz je činjenica o runu, ne uputa i ne nagovještaj gdje je odgovor."""

    statement = unread_regions_statement(
        [_ok("filesystem_query", _LIST_DIRECTORY)], tools=_DISK_TOOLS
    )

    assert statement is not None
    assert "\n" not in statement
    assert EVIDENCE_REGIONS[REGION_DELETED_ENTRIES].label in statement
    assert EVIDENCE_REGIONS[REGION_UNREFERENCED].label in statement
    # A region that WAS read is not named: the line states omissions only.
    assert EVIDENCE_REGIONS[REGION_FILESYSTEM_LISTED].label not in statement
    # No verb that would turn the fact into an order, and no tool named to run.
    lowered = statement.lower()
    for imperative in ("must", "should", "call ", "run ", "use ", "continue", "search"):
        assert imperative not in lowered
    for tool in DOMAIN_FUNCTIONS:
        assert tool not in lowered


def test_a_call_that_is_not_a_registered_operation_covers_nothing() -> None:
    """Poziv koji registar ne bi prihvatio nije pročitao ništa."""

    assert region_of_call("filesystem_query", {"operation": "no_such_operation"}) is None
    assert region_of_call("no_such_tool", {"operation": "list_directory"}) is None
    # An operation the function does not define is refused before it is keyed.
    assert region_of_call("recover_deleted", {"operation": "list_directory"}) is None
    # An argument the model would have been refused on covers nothing either.
    refused = [_ok("filesystem_query", {"operation": "list_directory", "path": ""})]
    assert regions_read(refused) == frozenset()


def test_reading_back_this_run_s_own_cache_reads_no_region() -> None:
    """Ponovno čitanje već izvučenog nije novo čitanje medija."""

    assert operation_region("archive_query", "list") is None
    assert operation_region("transform_query", "base64") is None
    # And a whole-image hash examines no content, so it establishes no coverage.
    assert operation_region("verify_image_integrity", "verify_image") is None
