"""Presentation metadata for the interactive forensic tool catalog.

The runtime remains authoritative for deciding which tools are model-visible.
This module only explains that decision to the investigator, and it reads the
shared operation registry so the listing cannot name a function, or an
operation, that validation would not accept.
"""

from __future__ import annotations

from dataclasses import dataclass

from forensic_agent.agent.result_navigator import (
    RESULT_PAGE_DESCRIPTION,
    RESULT_PAGE_TOOL_NAME,
)
from forensic_agent.agent.tool_operations import DOMAIN_FUNCTIONS, DomainFunction
from forensic_agent.agent.tool_palette import (
    DOMAIN_MEMORY_FUNCTIONS,
    DOMAIN_OFF_PALETTE_FUNCTIONS,
    DOMAIN_PCAP_FUNCTIONS,
    DOMAIN_WINDOWS_DISK_FUNCTIONS,
)
from forensic_agent.core.tool_availability import SCOPE_ALWAYS

#: What the navigation function needs, worded so it reads the same in the active
#: listing (the "Evidence" column) and in the withheld one ("requires …").  It
#: names no source type because none applies: whatever produced the result is
#: what it continues.
NAVIGATION_SOURCE = "any loaded evidence"


@dataclass(frozen=True, slots=True)
class ToolCatalogEntry:
    name: str
    source: str
    description: str
    #: The function's closed operation enum, straight from the registry.
    operations: tuple[str, ...]


def _source_for(function: DomainFunction) -> str:
    if function.name in DOMAIN_MEMORY_FUNCTIONS:
        return "memory dump"
    if function.name in DOMAIN_PCAP_FUNCTIONS:
        return "network capture"
    if function.name in DOMAIN_WINDOWS_DISK_FUNCTIONS:
        return "Windows disk image"
    if function.name in DOMAIN_OFF_PALETTE_FUNCTIONS:
        # Registry-buildable but never offered on the interactive case palette:
        # these read host-side objects or a cited earlier result, not the case.
        return "outside the case palette"
    if function.scope == SCOPE_ALWAYS:
        # A function the registry offers whatever is loaded: it reads a cited
        # result or something this run produced, not the medium.  Taken from
        # the declared scope rather than left to the disk fallback below, which
        # told an operator with only a capture open that four of the six
        # available functions required a disk image.
        return NAVIGATION_SOURCE
    return "disk image"


def _first_sentence(text: str) -> str:
    """The summary's opening claim; the full text lives in the schema itself."""

    compact = " ".join(text.split())
    head, separator, _rest = compact.partition(". ")
    return head + ("." if separator else "")


def native_tool_catalog() -> tuple[ToolCatalogEntry, ...]:
    """Every function the interactive palette can offer, with its operations.

    The navigation function is listed beside the domain functions and described
    from the same text the model is given.  It carries no operations because it
    has none: it observes nothing, so it has nothing to choose between.  Leaving
    it out would make the listing state that the console offers one function
    fewer than it does.
    """

    entries = [
        ToolCatalogEntry(
            name=function.name,
            source=_source_for(function),
            description=_first_sentence(function.summary),
            operations=function.operation_names(),
        )
        for function in DOMAIN_FUNCTIONS.values()
    ]
    entries.append(
        ToolCatalogEntry(
            name=RESULT_PAGE_TOOL_NAME,
            source=NAVIGATION_SOURCE,
            description=_first_sentence(RESULT_PAGE_DESCRIPTION),
            operations=(),
        )
    )
    return tuple(sorted(entries, key=lambda item: item.name))
