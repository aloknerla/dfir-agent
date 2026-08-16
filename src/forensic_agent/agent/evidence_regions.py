"""Which region of the evidence each operation reads, and which a run left alone.

A run listed directories, found the folder it was looking in genuinely empty, and
concluded that nothing was established — having never opened a deleted entry or a
byte no directory entry points at.  Its forensic knowledge was not the problem.
The missing fact was about its own work: it had read ONE region of the medium and
concluded about the medium.

Two rules keep that fact honest.

The first is that a region belongs to an OPERATION, not to a function.  One
function reads both what the filesystem lists and, through other operations, what
it does not; a claim made at function granularity would be false for half of what
that function can do.  So the table below is keyed by ``function.operation`` —
the same qualified name the provenance record and the frontier reader already use
— and ``resolved_operation`` decides which one a recorded call executed, because
an omitted operation means the function's declared default and only the registry
knows which.

The second is that only what a tool ITSELF states about what it reads may be
declared here.  "The scan reads the whole raw image, including regions no
directory entry points at" is the scanner's own description and is a property
of the tool.  Where a given kind of answer tends to live is not, and no
declaration in this module may be keyed to a question's subject matter.

Coverage requires a read that delivered.  A call that failed covers nothing, with
one exception decided in :mod:`forensic_agent.core.tool_failure`: NOT_FOUND is the
only classification where the medium actually answered, and an answer of "it is
not there" is a read of the region.  Every other kind — the container that could
not deliver bytes, the refused call, the malformed arguments — examined nothing,
so crediting it with a region would let a broken read silence the omission it
caused.

Regions here are regions of ONE medium, the disk image.  Whether a run touched a
bound memory image or capture at all is a different question with its own answer
already in the run (the cross-source coverage stage), and two answers to one
question is how a report starts contradicting itself.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final

from forensic_agent.agent.tool_operations import DOMAIN_FUNCTIONS, resolved_operation
from forensic_agent.core.tool_failure import FailureKind, establishes_absence
from forensic_agent.core.tool_result import ToolStatus

REGION_FILESYSTEM_LISTED: Final[str] = "filesystem_listed"
REGION_DELETED_ENTRIES: Final[str] = "deleted_entries"
REGION_UNREFERENCED: Final[str] = "unreferenced"


@dataclass(frozen=True, slots=True)
class EvidenceRegion:
    """One region of the medium, named by what it IS and nothing more.

    ``label`` is the phrase the runtime states to the model.  It describes the
    region as a property of the medium — a reader learns where a tool would have
    looked, never what looking there might have turned up.
    """

    name: str
    label: str


_REGIONS: tuple[EvidenceRegion, ...] = (
    #: What the filesystem's own directory entries name, and the content they
    #: point at.  Every read that goes THROUGH the filesystem lands here.
    EvidenceRegion(REGION_FILESYSTEM_LISTED, "filesystem-listed content"),
    #: Entries the filesystem no longer lists but still holds metadata for.
    EvidenceRegion(REGION_DELETED_ENTRIES, "deleted filesystem entries"),
    #: Image content no directory entry points at.  Reached only by a reader
    #: that scans the raw image instead of walking the filesystem.
    EvidenceRegion(REGION_UNREFERENCED, "image content no directory entry points at"),
)

#: Declaration order, not alphabetical: the line reads the medium from the part
#: a listing shows outwards to the part it cannot.
EVIDENCE_REGIONS: Mapping[str, EvidenceRegion] = MappingProxyType(
    {region.name: region for region in _REGIONS}
)

#: ``function.operation`` -> the region that operation opens.  An operation is
#: declared by what it OPENS, not by where its content originally came from: a
#: read-back of something this run already extracted opens a cache, and crediting
#: it with the region the extraction covered would count one read twice.
_OPERATION_REGIONS: Mapping[str, str] = MappingProxyType(
    {
        "filesystem_query.list_directory": REGION_FILESYSTEM_LISTED,
        "filesystem_query.read_file": REGION_FILESYSTEM_LISTED,
        "filesystem_query.file_metadata": REGION_FILESYSTEM_LISTED,
        "filesystem_query.find_files": REGION_FILESYSTEM_LISTED,
        "filesystem_query.search_in_file": REGION_FILESYSTEM_LISTED,
        # The odd one of its family: the content search reads the raw image
        # rather than the namespace its siblings walk, so what it OPENS is the
        # part no directory entry points at. Declaring it beside the listings
        # would let a run that only ever searched claim it had looked nowhere
        # else, and a run that never searched escape saying so.
        "filesystem_query.search_image_content": REGION_UNREFERENCED,
        # Staged copies of files the filesystem lists: the hive, the log and the
        # database are reached by path through the filesystem like any other file.
        "registry_query.registry_values": REGION_FILESYSTEM_LISTED,
        "registry_query.value_readings": REGION_FILESYSTEM_LISTED,
        "registry_ripper.plugin": REGION_FILESYSTEM_LISTED,
        "registry_ripper.profile": REGION_FILESYSTEM_LISTED,
        "evtx_query.query": REGION_FILESYSTEM_LISTED,
        "sqlite_query.schema": REGION_FILESYSTEM_LISTED,
        "sqlite_query.table_info": REGION_FILESYSTEM_LISTED,
        "sqlite_query.select": REGION_FILESYSTEM_LISTED,
        "sqlite_query.pragma": REGION_FILESYSTEM_LISTED,
        "evidence_file_hash.sha256": REGION_FILESYSTEM_LISTED,
        "recover_deleted.list_deleted": REGION_DELETED_ENTRIES,
        "recover_deleted.recover_content": REGION_DELETED_ENTRIES,
        # The scanner reads the raw image whole rather than walking a
        # directory, which is what reaches content nothing points at.
        "bulk_extract.list_features": REGION_UNREFERENCED,
        "bulk_extract.read_feature": REGION_UNREFERENCED,
        # A literal search over the same pass, over the same bytes.
        "bulk_extract.find_literal": REGION_UNREFERENCED,
    }
)

#: Operations that open no region of the evidence image, declared rather than
#: left to fall through: a new operation must state which of the two it is.
_NO_REGION_OPERATIONS: frozenset[str] = frozenset(
    {
        # A whole-image digest examines no content.  Crediting it with a region
        # would let an integrity check stand in for having looked.
        "verify_image_integrity.verify_image",
        # Host paths and cited earlier results, not the image.
        "archive_query.list",
        "archive_query.extract_inspect",
        "host_file_hash.sha256",
        "host_file_hash.hashset_lookup",
        "ocr_image.read_text",
        "transform_query.base64",
        "transform_query.base32",
        "transform_query.hex",
        "transform_query.rot13",
        "transform_query.url",
        "transform_query.utf16le",
        "transform_query.gzip",
        "transform_query.filetime",
        "transform_query.epoch",
        # A generic table keyed by a prefix the CALLER already read somewhere
        # else. The reading that opened a region is the one that produced the
        # address; naming a region here would count that read twice.
        "artifact_reference_query.hardware_vendor",
        # Other media.  Whether they were touched is the cross-source coverage
        # stage's question, and it is not re-answered here.
        "memory_query.plugin_rows",
        "memory_query.process_parentage",
        "memory_query.external_connections",
        "memory_query.injection_candidates",
        "memory_query.field_distribution",
        "memory_malware_scan.scan_pid",
        "memory_malware_scan.scan_all_candidates",
        "pcap_query.dns",
        "pcap_query.http",
        "pcap_query.http_auth",
        "pcap_query.ftp",
        "pcap_query.telnet",
        "pcap_query.protocols",
        "pcap_query.conversations",
        "pcap_query.endpoints",
        "pcap_query.stat",
        "pcap_query.fields",
        "pcap_query.dns_exfil",
        "pcap_query.ftp_objects",
        "pcap_query.http_objects",
        "pcap_query.export",
        "pcap_query.follow",
        "pcap_query.cross_capture_linkage",
    }
)


class EvidenceRegionError(ValueError):
    """The region declarations and the operation registry disagree."""


def operation_region(function: str, operation: str) -> str | None:
    """The region one registered operation opens, or ``None`` if it opens none.

    Raises rather than guessing for an operation nothing declares: silence would
    make an undeclared operation indistinguishable from one that reads nothing,
    and a new reader of unallocated content would then be invisible to every run.
    """

    key = f"{function}.{operation}"
    region = _OPERATION_REGIONS.get(key)
    if region is not None:
        return region
    if key in _NO_REGION_OPERATIONS:
        return None
    raise EvidenceRegionError(f"{key} declares no evidence region")


def region_of_call(tool: object, arguments: Mapping[str, Any] | None) -> str | None:
    """The region one recorded call opened, or ``None``.

    The registry decides which operation ran, so a defaulted ``operation`` is
    resolved the same way here as everywhere else in the run.  A call the
    registry would have refused reads nothing: it could not have run.
    """

    operation = resolved_operation(tool, arguments)
    if operation is None:
        return None
    return operation_region(str(tool), operation)


def reachable_regions(tools: Iterable[object]) -> frozenset[str]:
    """Every region the tools available to this run could have opened.

    A region no available tool reaches is not an omission and must never be
    reported as one — a run over memory alone would otherwise accuse itself of
    failing to walk a filesystem it was never given.
    """

    reachable: set[str] = set()
    for name in tools:
        function = DOMAIN_FUNCTIONS.get(name) if isinstance(name, str) else None
        if function is None:
            continue
        for operation in function.operations:
            region = _OPERATION_REGIONS.get(f"{function.name}.{operation.name}")
            if region is not None:
                reachable.add(region)
    return frozenset(reachable)


def _partial_examined_any_of_its_scope(result: Mapping[str, Any]) -> bool:
    """Whether a partial result read any of the region it was pointed at.

    PARTIAL carries two different facts under one word.  A walk that covered part
    of its scope did open the region, and a run that goes no further is bounded
    rather than blind.  A walk whose every directory refused to open covered none
    of it, and crediting that with the region would let a run publish "no deleted
    entries" on the strength of a read that never happened — the one conclusion
    this module exists to withhold.

    Recovered items settle it outright.  Otherwise the tool's own examined count
    does, and silence is not a claim of zero: a result that states no count keeps
    the benefit of the doubt it has always had here.
    """

    data = result.get("data")
    items = data.get("items") if isinstance(data, Mapping) else None
    if isinstance(items, Sequence) and not isinstance(items, (str, bytes)) and items:
        return True
    coverage = result.get("coverage")
    examined = coverage.get("examined") if isinstance(coverage, Mapping) else None
    if isinstance(examined, int) and not isinstance(examined, bool):
        return examined > 0
    return True


def _read_delivered(result: object) -> bool:
    """Whether one recorded result is a read that covered anything.

    A result whose shape this cannot recognise counts as no read at all: an
    unreadable record is not evidence that a region was examined, and treating it
    as one would suppress the omission it should have exposed.
    """

    if not isinstance(result, Mapping):
        return False
    status = result.get("status")
    if status == ToolStatus.OK.value:
        return True
    if status == ToolStatus.PARTIAL.value:
        return _partial_examined_any_of_its_scope(result)
    if status != ToolStatus.ERROR.value:
        return False
    data = result.get("data")
    attributes = data.get("attributes") if isinstance(data, Mapping) else None
    failure = attributes.get("failure") if isinstance(attributes, Mapping) else None
    if not isinstance(failure, Mapping):
        return False
    raw_kind = failure.get("kind")
    if not isinstance(raw_kind, str):
        # A record with no readable kind is an unreadable record, which this
        # function already refuses to count as a read.
        return False
    try:
        kind = FailureKind(raw_kind)
    except ValueError:
        return False
    # The classification is re-derived rather than read off the record's own
    # ``establishes_absence`` flag, so what a failure may be taken to mean stays
    # decided in the one module that decides it.
    return establishes_absence(kind)


def regions_read(records: Sequence[Mapping[str, Any]]) -> frozenset[str]:
    """Every region this run actually read, accumulated over its recorded calls."""

    read: set[str] = set()
    for record in records:
        if not isinstance(record, Mapping):
            continue
        region = region_of_call(record.get("tool"), record.get("arguments"))
        if region is None or region in read:
            continue
        if _read_delivered(record.get("result")):
            read.add(region)
    return frozenset(read)


def unread_regions(
    records: Sequence[Mapping[str, Any]], *, tools: Iterable[object]
) -> tuple[EvidenceRegion, ...]:
    """The reachable regions this run did not read, in declaration order."""

    reachable = reachable_regions(tools)
    read = regions_read(records)
    return tuple(
        region
        for name, region in EVIDENCE_REGIONS.items()
        if name in reachable and name not in read
    )


def unread_regions_statement(
    records: Sequence[Mapping[str, Any]], *, tools: Iterable[object]
) -> str | None:
    """One line stating which regions this run left unread, or ``None``.

    A fact about the run, deliberately not an instruction and deliberately not a
    hint: it names the region and stops there.  Saying more would be this project
    telling the model where an answer lives, which is the one thing the runtime
    must never do.
    """

    regions = unread_regions(records, tools=tools)
    if not regions:
        return None
    named = "; ".join(region.label for region in regions)
    return f"Regions of this evidence not read in this run: {named}."


def _verify_declarations() -> None:
    """Every registered operation declares a region or declares it opens none."""

    declared = set(_OPERATION_REGIONS) | _NO_REGION_OPERATIONS
    overlap = set(_OPERATION_REGIONS) & _NO_REGION_OPERATIONS
    if overlap:
        raise EvidenceRegionError(
            f"operations declared both with and without a region: {', '.join(sorted(overlap))}"
        )
    unknown_regions = set(_OPERATION_REGIONS.values()) - set(EVIDENCE_REGIONS)
    if unknown_regions:
        raise EvidenceRegionError(
            f"undefined regions declared: {', '.join(sorted(unknown_regions))}"
        )
    registered = {
        f"{function.name}.{operation.name}"
        for function in DOMAIN_FUNCTIONS.values()
        for operation in function.operations
    }
    missing = registered - declared
    if missing:
        raise EvidenceRegionError(
            f"operations with no region declaration: {', '.join(sorted(missing))}"
        )
    stale = declared - registered
    if stale:
        raise EvidenceRegionError(
            f"regions declared for operations that do not exist: {', '.join(sorted(stale))}"
        )


_verify_declarations()


__all__ = [
    "EVIDENCE_REGIONS",
    "REGION_DELETED_ENTRIES",
    "REGION_FILESYSTEM_LISTED",
    "REGION_UNREFERENCED",
    "EvidenceRegion",
    "EvidenceRegionError",
    "operation_region",
    "reachable_regions",
    "region_of_call",
    "regions_read",
    "unread_regions",
    "unread_regions_statement",
]
