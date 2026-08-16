"""Shared immutable tool classifications used by the agent runtime.

Keeping these names in one dependency-light module prevents evidence descriptors
from importing the full LangGraph runtime merely to classify a tool call.
"""

from __future__ import annotations

from typing import Final

REFERENCE_TOOLS: Final[frozenset[str]] = frozenset(
    {
        # The consolidated reference surface. Its membership here is what keeps
        # every name-keyed reference rule applying to it: it opens no case
        # evidence, so it is exempt from the case-evidence source binding.
        "artifact_reference_query",
    }
)
#: Functions that read a result this run already produced and stored, rather
#: than reading the evidence.  They start no process, open no source and create
#: no upstream invocation, so they are metered separately: charging a page of a
#: retained result against the forensic ceiling makes reading what was already
#: gathered cost as much as gathering it again.
STORED_RESULT_NAVIGATION_TOOLS: Final[frozenset[str]] = frozenset({"result_page"})
#: Retained after the timeline source was withdrawn because the frozen result
#: contract still asks every result whether it came from one; the set is now
#: empty, so the question is answered without a branch of its own.
TIMELINE_TOOLS: Final[frozenset[str]] = frozenset()
MEMORY_TOOLS: Final[frozenset[str]] = frozenset(
    {"memory_query", "memory_malware_scan", "memory_strings"}
)
PCAP_TOOLS: Final[frozenset[str]] = frozenset({"pcap_query", "reconstruct_http_exfil"})
#: Functions that read a RAW evidence image of whichever kind the case holds.
RAW_IMAGE_TOOLS: Final[frozenset[str]] = frozenset({"bulk_extract"})
PCAP_COMPONENT_ROLES: Final[frozenset[str]] = frozenset(
    {"pcap", "derived_pcap", "merged_pcap", "pcap_merged"}
)
HOST_PATH_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "archive_query",
        "ocr_image",
        "read_text_file",
        "hash_file",
        "hash_lookup",
        "vision_read",
        # The consolidated host-side hashing function reads the same kind of
        # host path its two predecessors did; listing it here keeps every rule
        # keyed on this membership working when that surface is wired in.
        "host_file_hash",
    }
)

# Runtime-facing aliases retain the historical private graph names without
# duplicating mutable collections or coupling this module to LangGraph.
_REFERENCE_TOOLS = REFERENCE_TOOLS
_TIMELINE_TOOLS = TIMELINE_TOOLS
_MEMORY_TOOLS = MEMORY_TOOLS
_PCAP_TOOLS = PCAP_TOOLS
#: Functions whose input is a value from a result THIS run already produced,
#: named in the call itself by invocation id and payload digest. Their
#: provenance is that parent, never a component of the case bundle.
CITED_RESULT_INPUT_TOOLS: Final[frozenset[str]] = frozenset({"transform_query", "decode"})

_HOST_PATH_TOOLS = HOST_PATH_TOOLS
