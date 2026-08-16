"""The approved model-visible palette per loaded evidence source.

Two palettes live here, and they never mix.  The DEFAULT one names the
consolidated domain functions and is derived against the shared operation
registry (:mod:`forensic_agent.agent.tool_operations`), so a function cannot be
offered here without being defined there.  The HISTORICAL one is the frozenset
declaration of what each evidence source ever supported — withdrawn functions
included — because a recorded run pins the palette it ran with and that
record must stay readable; it is returned only for the explicit opt-in.

The default palette carries one function that is not a domain function: the
navigation function, which serves the next page of a result the run ALREADY
HOLDS.  It belongs on the palette rather than in the registry because it opens
no evidence and runs no backend, and it belongs on the palette at all because
without it the only way to see the withheld remainder of a result is to run the
producing tool a second time — an observation that never happened, recorded as
though it had.

Neither palette accepts a task ID, question, category, expected answer or
scoring metadata: membership follows from loaded evidence sources alone.

This sits beside the operation registry rather than in ``cli/`` because the
console is not its only caller: other callers derive the same palette without
importing ``forensic_agent/cli``, so a palette owned by the console would be one
they could not import.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Literal

from forensic_agent.agent.result_navigator import RESULT_PAGE_TOOL_NAME
from forensic_agent.agent.tool_operations import DOMAIN_FUNCTIONS
from forensic_agent.agent.tool_taxonomy import (
    MEMORY_TOOLS as _TAXONOMY_MEMORY_TOOLS,
)
from forensic_agent.agent.tool_taxonomy import (
    PCAP_TOOLS as _TAXONOMY_PCAP_TOOLS,
)

DISK_TOOLS = frozenset(
    {
        "list_directory",
        "file_metadata",
        "read_file",
        "search_in_file",
        "search_keyword",
        "find_files",
        "sqlite_query",
        "configuration_query",
        "find_email_addresses",
        "evidence_file_hash",
        "verify_image_integrity",
        "recover_deleted_files",
        "registry_query",
        "registry_ripper",
        "evtx_query",
        "windows_domain_identity",
        "windows_local_accounts",
        "windows_network_config",
        "usb_storage_history",
        "installed_applications",
        "google_drive_sync_events",
        "printing_activity_events",
        "printing_job_sessions",
        "gcode_metadata",
    }
)

WINDOWS_DISK_TOOLS = frozenset(
    {
        "registry_query",
        "registry_ripper",
        "evtx_query",
        "windows_domain_identity",
        "windows_local_accounts",
        "windows_network_config",
        "usb_storage_history",
        "installed_applications",
        "google_drive_sync_events",
    }
)

# The historical memory and network palettes are a NARROWER record than the
# runtime taxonomy: the historical surface never offered ``memory_strings`` or
# ``reconstruct_http_exfil``, so these are exactly the members it carried.  They
# therefore keep their own declaration — under a distinct name, so they no longer
# collide with the taxonomy sets of the same name that carry different members —
# and the subset guard below proves each stays within what the taxonomy classifies.
HISTORICAL_MEMORY_TOOLS = frozenset({"memory_query", "memory_malware_scan"})
HISTORICAL_PCAP_TOOLS = frozenset({"pcap_query"})

# Import-time proof that the historical palette never names a memory or network
# tool the runtime taxonomy does not classify.  The relation is subset, not
# equality, because the historical sets are a frozen, narrower record; a rename
# or withdrawal on either side that broke it fails here at import.
if not HISTORICAL_MEMORY_TOOLS <= _TAXONOMY_MEMORY_TOOLS:
    raise RuntimeError(
        "the historical memory palette names a tool the taxonomy does not classify: "
        f"{sorted(HISTORICAL_MEMORY_TOOLS - _TAXONOMY_MEMORY_TOOLS)}"
    )
if not HISTORICAL_PCAP_TOOLS <= _TAXONOMY_PCAP_TOOLS:
    raise RuntimeError(
        "the historical network palette names a tool the taxonomy does not classify: "
        f"{sorted(HISTORICAL_PCAP_TOOLS - _TAXONOMY_PCAP_TOOLS)}"
    )

# ---------------------------------------------------------------------------
# The default palette: consolidated domain functions per evidence source.
# ---------------------------------------------------------------------------

DOMAIN_DISK_FUNCTIONS = frozenset(
    {
        "filesystem_query",
        "recover_deleted",
        "sqlite_query",
        "evidence_file_hash",
        "verify_image_integrity",
        # The reference lookup rides with disk evidence; widening it to other
        # profiles is a separate decision for the reference surface as a whole.
    }
)
DOMAIN_WINDOWS_DISK_FUNCTIONS = frozenset(
    {
        "registry_query",
        "registry_ripper",
        "evtx_query",
    }
)
DOMAIN_MEMORY_FUNCTIONS = frozenset({"memory_query", "memory_malware_scan"})
DOMAIN_PCAP_FUNCTIONS = frozenset({"pcap_query"})
#: Final functions that exist on the registry surface but are deliberately not
#: offered on the interactive case palette, mirroring their predecessors:
#: the host-side and inline functions read objects outside the case evidence
#: chain, and bulk_extract was never palette-approved for the console.  The two
#: recovery mediators join it: extraction-scoped like bulk_extract, they are
#: offered on the registry surface but not auto-added to the console case palette.
DOMAIN_OFF_PALETTE_FUNCTIONS = frozenset(
    {
        # It hashes a file on the HOST, which is not part of any case's evidence
        # chain, so no case palette offers it.
        "host_file_hash",
    }
)

#: Functions that belong to every case, whatever it was opened with.
#:
#: A named transformation reads a value out of a result THIS run already
#: produced and states which scheme it applies; a reference lookup reads a
#: published catalogue. Neither touches an evidence source, so neither has a
#: modality — and binding them to one is how a capture-only case came to have no
#: way to decode a value it had just recovered, and no way to resolve a hardware
#: address it had just read.
DOMAIN_ANY_CASE_FUNCTIONS = frozenset({"transform_query", "artifact_reference_query"})

#: Functions that read what the run itself reconstructed, offered beside whatever
#: the loaded evidence supports.  They were kept off the palette while a
#: reconstruction could land anywhere; one now lands only in the run's declared
#: payload root, so what they read is material this run produced from evidence
#: under its own containment.
DOMAIN_DERIVED_ARTIFACT_FUNCTIONS = frozenset({"archive_query", "ocr_image"})

#: Feature extraction over whatever raw evidence image the run holds: the scanner
#: reads bytes, and what it recovers from unallocated disk space it recovers from
#: a process's working memory in the same way.
DOMAIN_RAW_IMAGE_FUNCTIONS = frozenset({"bulk_extract"})

#: Offered beside whatever the loaded evidence supports, because reading more of
#: a result the run already retained is not a property of the evidence type: the
#: stored records are the same records whichever function produced them.  It is
#: tied to the palette being non-empty rather than to any one source, since a
#: palette with no function on it can produce no result to page.
NAVIGATION_FUNCTIONS = frozenset({RESULT_PAGE_TOOL_NAME})

# Import-time proof that the palette declaration and the shared operation
# registry cannot drift: every declared name is a defined domain function, and
# every defined domain function is either offered by some evidence source or
# deliberately kept off the palette — never simply forgotten.
_DOMAIN_PALETTE_DECLARATION = frozenset().union(
    DOMAIN_DISK_FUNCTIONS,
    DOMAIN_WINDOWS_DISK_FUNCTIONS,
    DOMAIN_MEMORY_FUNCTIONS,
    DOMAIN_PCAP_FUNCTIONS,
    DOMAIN_DERIVED_ARTIFACT_FUNCTIONS,
    DOMAIN_RAW_IMAGE_FUNCTIONS,
    DOMAIN_ANY_CASE_FUNCTIONS,
)
if NAVIGATION_FUNCTIONS & frozenset(DOMAIN_FUNCTIONS):
    # A navigation function that became a domain function would be built by the
    # registry, supervised and standardized like an observation — and would mint
    # an invocation id for a page the run had already observed.
    raise RuntimeError(
        "a navigation function must not be a domain function: "
        f"{sorted(NAVIGATION_FUNCTIONS & frozenset(DOMAIN_FUNCTIONS))}"
    )
if _DOMAIN_PALETTE_DECLARATION & DOMAIN_OFF_PALETTE_FUNCTIONS:
    raise RuntimeError(
        "a domain function cannot be both offered and kept off the palette: "
        f"{sorted(_DOMAIN_PALETTE_DECLARATION & DOMAIN_OFF_PALETTE_FUNCTIONS)}"
    )
if _DOMAIN_PALETTE_DECLARATION | DOMAIN_OFF_PALETTE_FUNCTIONS != frozenset(DOMAIN_FUNCTIONS):
    raise RuntimeError(
        "the palette declaration does not account for every domain function: "
        f"unplaced {sorted(frozenset(DOMAIN_FUNCTIONS) - _DOMAIN_PALETTE_DECLARATION - DOMAIN_OFF_PALETTE_FUNCTIONS)}, "
        f"undefined {sorted((_DOMAIN_PALETTE_DECLARATION | DOMAIN_OFF_PALETTE_FUNCTIONS) - frozenset(DOMAIN_FUNCTIONS))}"
    )

DiskFamily = Literal["windows", "posix", "unknown"]


def classify_disk_family(disk: object | None) -> DiskFamily:
    """Classify a loaded filesystem without using the investigation question."""

    if disk is None:
        return "unknown"
    inventory = getattr(disk, "filesystems", ())
    if isinstance(inventory, Sequence) and not isinstance(inventory, (str, bytes)):
        selected = [
            row
            for row in inventory
            if isinstance(row, Mapping) and row.get("selected") is True
        ]
        if len(selected) == 1:
            root_score = selected[0].get("root_score")
            if root_score == 2:
                return "windows"
            if root_score == 1:
                return "posix"

    filesystem = str(getattr(disk, "fs_type", "") or "").strip().casefold()
    if "ntfs" in filesystem:
        return "windows"
    if any(
        marker in filesystem
        for marker in ("ext2", "ext3", "ext4", "xfs", "btrfs", "apfs", "hfs")
    ):
        return "posix"
    return "unknown"


def tools_for_evidence_sources(
    *,
    disk_available: bool,
    disk_family: DiskFamily = "unknown",
    memory_available: bool,
    pcap_available: bool,
    include_quarantined_tools: bool = False,
) -> frozenset[str]:
    """Return the approved palette supported by loaded source types.

    The function deliberately accepts no task ID, question, category, expected
    answer, or scoring metadata.  Therefore two questions over the same loaded
    source types receive the same model-visible functions.

    ``include_quarantined_tools`` is not about the question either: it selects
    the HISTORICAL palette — the pre-consolidation function names, including the
    ones withdrawn in ``QUARANTINED_MODEL_TOOLS`` — which is what a recorded run
    pins.  It defaults to False, so a caller that does not reproduce a historical
    run gets the consolidated domain functions, exactly the names the default
    registry build carries, plus the navigation function.
    The historical palette gets no navigation function: it is the record of what
    those runs were offered, and they were not offered one.
    """

    selected: set[str] = set()
    if include_quarantined_tools:
        if disk_available:
            selected.update(DISK_TOOLS)
            if disk_family != "windows":
                selected.difference_update(WINDOWS_DISK_TOOLS)
        if memory_available:
            selected.update(HISTORICAL_MEMORY_TOOLS)
        if pcap_available:
            selected.update(HISTORICAL_PCAP_TOOLS)
        return frozenset(selected)

    if disk_available:
        selected.update(DOMAIN_DISK_FUNCTIONS)
        if disk_family == "windows":
            selected.update(DOMAIN_WINDOWS_DISK_FUNCTIONS)
    if memory_available:
        selected.update(DOMAIN_MEMORY_FUNCTIONS)
    if disk_available or memory_available:
        selected.update(DOMAIN_RAW_IMAGE_FUNCTIONS)
    if pcap_available:
        selected.update(DOMAIN_PCAP_FUNCTIONS)
    if selected:
        # Only where something can produce a result to page.  Offering it over an
        # empty palette would advertise a continuation of nothing.
        selected.update(NAVIGATION_FUNCTIONS)
        # Same condition, same reason: with nothing loaded there is nothing a run
        # could have reconstructed for these to read.
        selected.update(DOMAIN_DERIVED_ARTIFACT_FUNCTIONS)
        selected.update(DOMAIN_ANY_CASE_FUNCTIONS)
    return frozenset(selected)


def tools_for_loaded_evidence(
    *,
    disk: object | None,
    memory_path: object | None,
    pcap_path: object | None,
    pcap_sources: object | None = None,
    include_quarantined_tools: bool = False,
) -> frozenset[str]:
    """Derive the model-visible palette from concrete loaded evidence only."""

    return tools_for_evidence_sources(
        disk_available=disk is not None,
        disk_family=classify_disk_family(disk),
        memory_available=bool(memory_path),
        pcap_available=bool(pcap_path) or pcap_sources is not None,
        include_quarantined_tools=include_quarantined_tools,
    )
