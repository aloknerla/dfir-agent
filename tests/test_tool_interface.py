"""The domain facades: one registry drives surface, schema, text and dispatch.

Cross-cutting properties live here — which facades a binding offers, what the
model reads about them, that the dispatch tables cannot drift from the registry,
and the executed-backend seam.  Per-operation dispatch and the rejection proofs
live in ``test_domain_facade_dispatch.py``.
"""

from __future__ import annotations

from pathlib import Path
from types import MappingProxyType

import pytest

import forensic_agent.core.tool_availability as availability
from forensic_agent.agent.tool_bindings.context import ToolBuildContext
from forensic_agent.agent.tool_bindings.tool_interface import (
    _DISPATCH_TABLE,
    FacadeConfigurationError,
    _verify_facade_tables,
    build_tool_interface,
    executed_backend,
)
from forensic_agent.agent.tool_operations import (
    DOMAIN_FUNCTIONS,
    function_description,
    operation_names,
)
from forensic_agent.agent.tool_taxonomy import HOST_PATH_TOOLS, REFERENCE_TOOLS
from forensic_agent.core.tool_availability import QUARANTINED_MODEL_TOOL_NAMES

#: The previous model surface.  Not one of these names may appear as a
#: model-visible function on the facade surface: each is an operation now.
_LEGACY_SURFACE = frozenset(
    {
        "archive_query",
        "bulk_extract",
        "decode",
        "evidence_file_hash",
        "evtx_query",
        "file_metadata",
        "find_files",
        "hash_file",
        "hash_lookup",
        "list_directory",
        "lookup_artifact",
        "memory_malware_scan",
        "memory_query",
        "ocr_image",
        "pcap_query",
        "read_file",
        "recover_deleted_files",
        "registry_query",
        "registry_ripper",
        "search_in_file",
        "search_keyword",
        "sqlite_query",
        "verify_image_integrity",
    }
)
#: Legacy names that do NOT survive as domain-function names.
_RETIRED_NAMES = _LEGACY_SURFACE - set(DOMAIN_FUNCTIONS)


@pytest.fixture
def every_binary_present(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Resolve every declared external tool at the single probe seam."""

    stand_in = tmp_path / "stand-in"
    stand_in.write_text("", encoding="utf-8")
    monkeypatch.setattr(availability, "_resolve_spec", lambda _spec: str(stand_in))


class _Disk:
    """A minimal disk stub; ``extract`` selects the disk_extract scope."""

    def __init__(self, *, extract: bool) -> None:
        self.image_path = "evidence.dd"
        self.image_sha = "0" * 64
        self.fs_offset = 0
        if extract:
            self.extract_file = lambda *args, **kwargs: None


def _context(
    *,
    disk: _Disk | None = None,
    memory_path: str | None = None,
    pcap_path: str | None = None,
    on_tool=None,
) -> ToolBuildContext:
    return ToolBuildContext(
        disk=disk,
        memory_path=memory_path,
        pcap_path=pcap_path,
        controlled_scratch=None,
        tool_argument_allowlists=None,
        pcap_sources=None,
        on_tool=on_tool,
    )


def _names(context: ToolBuildContext) -> list[str]:
    return [str(tool.name) for tool in build_tool_interface(context)]


def test_the_facade_surface_is_scope_driven_and_deterministically_ordered(
    every_binary_present: None,
) -> None:
    """Which facades exist follows the bound evidence sources alone."""

    everything = _context(
        disk=_Disk(extract=True),
        memory_path="memory.mem",
        pcap_path="capture.pcap",
    )
    assert _names(everything) == [
        "filesystem_query",
        "recover_deleted",
        "sqlite_query",
        "verify_image_integrity",
        "evidence_file_hash",
        "registry_query",
        "registry_ripper",
        "evtx_query",
        "memory_query",
        "memory_malware_scan",
        # Raw-image scope: feature extraction reads bytes, so it follows the
        # image the case holds rather than the disk alone, and is assembled
        # after the modality families it may serve.
        "bulk_extract",
        "pcap_query",
        "archive_query",
        "transform_query",
        "host_file_hash",
        "ocr_image",
        "artifact_reference_query",
    ]

    # A read-only disk carries no extraction scope, so the extract family is
    # absent; no evidence at all leaves exactly the always-available family.
    read_only = set(_names(_context(disk=_Disk(extract=False))))
    assert "filesystem_query" in read_only
    assert read_only.isdisjoint({"registry_ripper", "registry_query", "evtx_query"})
    assert set(_names(_context())) == {
        "archive_query",
        "transform_query",
        "host_file_hash",
        "ocr_image",
        "artifact_reference_query",
    }


def test_no_retired_legacy_name_is_model_visible(every_binary_present: None) -> None:
    """The previous functions became operations: callable inside, absent outside."""

    names = set(
        _names(
            _context(
                disk=_Disk(extract=True),
                memory_path="memory.mem",
                pcap_path="capture.pcap",
            )
        )
    )
    assert names == set(DOMAIN_FUNCTIONS)
    assert names.isdisjoint(_RETIRED_NAMES)
    assert names.isdisjoint(QUARANTINED_MODEL_TOOL_NAMES)


def test_descriptions_are_generated_from_the_registry(every_binary_present: None) -> None:
    """The text the model reads and the validator that judges it share a source.

    Every operation the registry defines must appear in the description with its
    epistemic class, so an operation cannot exist in code and be missing from
    the text.
    """

    tools = build_tool_interface(
        _context(
            disk=_Disk(extract=True),
            memory_path="memory.mem",
            pcap_path="capture.pcap",
        )
    )
    for tool in tools:
        function = DOMAIN_FUNCTIONS[str(tool.name)]
        description = str(tool.description)
        assert description.startswith(function_description(function)), tool.name
        for operation in function.operations:
            assert f"- {operation.name} [" in description, (tool.name, operation.name)
            assert operation.evidence_class.value in description


def test_the_transport_judges_nothing_so_refusals_stay_structured() -> None:
    """Invalid input must reach the facade, not raise in the transport layer.

    The wire schema is a JSON Schema rather than a pydantic model, and LangChain
    passes a mapping input to the wrapped function unchanged when the schema is
    one: the transport therefore judges nothing, the registry's strict
    discriminated union judges every call first, and its verdict comes back as a
    deterministic structured error.  What the schema DOES do is publish that
    union, so the model reads the operation enum instead of guessing it.
    """

    tools = {str(tool.name): tool for tool in build_tool_interface(_context())}
    schema = tools["transform_query"].args_schema
    assert isinstance(schema, dict)
    assert schema["type"] == "object"
    assert schema["properties"]["operation"]["enum"] == list(
        operation_names("transform_query")
    )
    for operation in operation_names("transform_query"):
        assert operation in schema["properties"]["operation"]["description"]

    # A call the union rejects returns a structured refusal, never an exception.
    refused = tools["transform_query"].invoke({"operation": "no_such_transform"})
    assert refused["deterministic_error"] is True
    assert refused["error"]["code"] == "invalid_operation_arguments"
    assert refused["error"]["operations"] == list(operation_names("transform_query"))


def test_dispatch_tables_cannot_drift_from_the_registry() -> None:
    """Every registry operation dispatches; nothing undispatched can exist."""

    _verify_facade_tables()  # the shipped tables verify

    incomplete = {name: table for name, table in _DISPATCH_TABLE.items()}
    del incomplete["evtx_query"]
    with pytest.raises(FacadeConfigurationError, match="missing.*evtx_query"):
        _verify_facade_tables(MappingProxyType(incomplete))

    narrowed = {name: table for name, table in _DISPATCH_TABLE.items()}
    narrowed["sqlite_query"] = MappingProxyType(
        {
            name: entry
            for name, entry in _DISPATCH_TABLE["sqlite_query"].items()
            if name != "pragma"
        }
    )
    with pytest.raises(FacadeConfigurationError, match="sqlite_query.*pragma"):
        _verify_facade_tables(MappingProxyType(narrowed))

    memory_narrowed = {name: table for name, table in _DISPATCH_TABLE.items()}
    memory_narrowed["memory_query"] = MappingProxyType(
        {
            name: entry
            for name, entry in _DISPATCH_TABLE["memory_query"].items()
            if name != "plugin_rows"
        }
    )
    with pytest.raises(FacadeConfigurationError, match="memory_query.*plugin_rows"):
        _verify_facade_tables(MappingProxyType(memory_narrowed))


def test_executed_backend_is_read_from_the_result_not_the_table() -> None:
    """Ruling B7's seam: a fallback set answers from the executed path only."""

    # One declared producer: no fallback exists, so the producer is the answer.
    assert executed_backend("memory_query", "plugin_rows", {}) == "volatility3"
    assert executed_backend("pcap_query", "dns", {}) == "tshark"

    assert (
        executed_backend("evtx_query", "query", {"parser_backend": "libyal-pyevtx"})
        == "pyevtx"
    )
    assert (
        executed_backend("evtx_query", "query", {"parser_backend": "python-evtx"})
        == "python_evtx"
    )
    assert executed_backend("evtx_query", "query", {}) is None

    # The archive reader names the one of its three readers that opened the
    # archive.  ``format`` is what the archive IS and is never consulted: a 7z
    # archive read by the 7-Zip program because py7zr is absent is exactly where
    # the two would disagree.
    assert (
        executed_backend("archive_query", "list", {"engine": "cpython_zipfile"})
        == "cpython_zipfile"
    )
    assert (
        executed_backend("archive_query", "list", {"engine": "seven_zip", "format": "cli"})
        == "seven_zip"
    )
    assert executed_backend("archive_query", "list", {"format": "zip"}) is None
    # A reader that is not a declared producer of this operation is refused.
    assert (
        executed_backend("archive_query", "extract_inspect", {"engine": "seven_zip"})
        is None
    )
    # A call that never reached a reader states none, and stays unattested.
    assert executed_backend("archive_query", "list", {"ok": True}) is None


def test_every_call_reaches_the_activity_feed_exactly_once_under_the_domain_name() -> None:
    """A dispatched call must not surface twice, and never under a legacy name."""

    feed: list[tuple[str, object, bool]] = []
    context = _context(
        on_tool=lambda name, args, dt, refused: feed.append((name, args, refused))
    )
    tools = {str(tool.name): tool for tool in build_tool_interface(context)}

    tools["artifact_reference_query"].invoke(
        {"operation": "hardware_vendor", "address": "00:1B:21:3A:4B:5C"}
    )
    assert [name for name, _, _ in feed] == ["artifact_reference_query"]
    assert feed[0][2] is False

    feed.clear()
    refused = tools["artifact_reference_query"].invoke({"operation": "no_such"})
    assert refused["error"]["code"] == "invalid_operation_arguments"
    assert [name for name, _, _ in feed] == ["artifact_reference_query"]
    # Odbijanje je vlastita činjenica, a ne argument koji model nikad nije poslao.
    assert feed[0][1] == {"operation": "no_such"}
    assert feed[0][2] is True


def test_password_never_reaches_the_activity_feed() -> None:
    """The feed is UI-only, but a recovered password still must not travel there."""

    feed: list[tuple[str, dict, bool]] = []
    context = _context(
        on_tool=lambda name, args, dt, refused: feed.append((name, args, refused))
    )
    tools = {str(tool.name): tool for tool in build_tool_interface(context)}

    tools["archive_query"].invoke(
        {"operation": "list", "archive_path": "gone.zip", "password": "s3cret"}
    )
    assert len(feed) == 1
    assert "password" not in feed[0][1]
    assert feed[0][1]["archive_path"] == "gone.zip"


def test_name_keyed_runtime_taxonomies_cover_the_new_names() -> None:
    """Wrappers keyed on function names keep working for the facade names."""

    assert "host_file_hash" in HOST_PATH_TOOLS
    assert "artifact_reference_query" in REFERENCE_TOOLS
    # The names that stayed identical keep their existing memberships.
    assert "archive_query" in HOST_PATH_TOOLS
    assert "ocr_image" in HOST_PATH_TOOLS
