"""What performs a transformation, and what this project may claim to have done.

The transformations used to be carried out here: base64 through the interpreter's
codecs, and RC4, XOR and OpenSSL key derivation through cryptography written in
this repository.  Orchestrating established forensic tools and shipping one's own
cipher are different claims, and only the first one is this project's.  Every
operation now runs through `chepy <https://github.com/securisec/chepy>`_, and the
two that convert a moment run through dfDateTime, the timestamp library the plaso
stack in this image already runs on.
"""

from __future__ import annotations

import pytest

from forensic_agent.agent.tool_bindings.tool_interface import (
    _epoch_from_stated_unit,
    _filetime_from_stated_form,
)
from forensic_agent.agent.tool_operations import operation_definition
from forensic_agent.tools import decode_tool

#: The value a network capture carried, and what it decodes to. Synthetic: it
#: was a real archive password from a competition task that is still running,
#: which a public repository would have handed out. What the decoder is asked
#: to do is identical either way. The pair is base64-consistent; changing one
#: without the other leaves a test that decodes one string and asserts another.
ENCODED = "RVhBTVBMRS1QVzE="
DECODED = "EXAMPLE-PW1"

_CODEC_OPERATIONS = ("base64", "base32", "hex", "rot13", "url", "utf16le", "gzip")


def test_the_decoder_names_the_component_that_performed_the_transformation():
    """A decoded value carries the name of the project that decoded it."""

    result = decode_tool.decode(ENCODED, "base64")
    assert result["text"] == DECODED
    assert result["backend"] == "chepy"


@pytest.mark.parametrize("operation", _CODEC_OPERATIONS)
def test_every_codec_operation_is_declared_as_the_decoder_s_work(operation):
    """The registry attributes each operation to chepy, so receipts do too."""

    definition = operation_definition("transform_query", operation)
    producers = [
        backend.name for backend in definition.backends if backend.role == "producer"
    ]
    assert producers == ["chepy"]


@pytest.mark.parametrize("operation", ("filetime", "epoch"))
def test_the_time_conversions_are_declared_as_dfdatetime_s_work(operation):
    definition = operation_definition("transform_query", operation)
    producers = [
        backend.name for backend in definition.backends if backend.role == "producer"
    ]
    assert producers == ["dfdatetime"]


def test_a_filetime_is_converted_by_dfdatetime():
    """The moment comes back from the library, not from arithmetic written here."""

    converted = _filetime_from_stated_form("133000000000000000", "decimal_ticks")
    assert converted["backend"] == "dfdatetime"
    assert converted["utc"].startswith("2022-06-18 04:26:40")


def test_a_unix_timestamp_is_converted_by_dfdatetime():
    converted = _epoch_from_stated_unit("1700000000", "seconds")
    assert converted["backend"] == "dfdatetime"
    assert converted["utc"].startswith("2023-11-14 22:13:20")


@pytest.mark.parametrize("operation", ("rc4", "xor"))
def test_this_project_s_own_cryptography_stays_withdrawn(operation):
    """Not re-homed onto the new decoder: withdrawn, and the refusal says why."""

    refusal = decode_tool.decode("anything", operation)["error"]
    assert "withdrawn" in refusal
    assert operation not in decode_tool._CHEPY_OPERATIONS


def test_the_decoder_still_refuses_to_detect_a_scheme():
    """Naming the scheme remains the caller's job; nothing is sniffed."""

    refusal = decode_tool.decode(ENCODED, "auto")["error"]
    assert "does not detect an encoding" in refusal


def test_the_catalog_does_not_ask_for_a_disk_that_is_not_needed():
    """Functions offered whatever is loaded say so, instead of naming a disk.

    With only a capture open, the listing told the operator that archive_query,
    ocr_image, transform_query and artifact_reference_query required a disk
    image: the label fell through to a default rather than reading the declared
    scope, and the four functions the run actually depends on read as unusable.
    """

    from forensic_agent.cli.tool_catalog import NAVIGATION_SOURCE, native_tool_catalog

    sources = {entry.name: entry.source for entry in native_tool_catalog()}
    for name in ("archive_query", "ocr_image", "transform_query", "artifact_reference_query"):
        assert sources[name] == NAVIGATION_SOURCE, name
    assert sources["pcap_query"] == "network capture"
    assert sources["filesystem_query"] == "disk image"


def test_an_empty_session_states_a_state_rather_than_a_count():
    """With nothing loaded the row said "0 attached", which reads as a fault."""

    from rich.console import Console

    from forensic_agent.cli.session_facts import session_panel

    panel = session_panel(
        model="deepseek/deepseek-v4-flash",
        provider="OpenRouter",
        reasoning_effort="high",
        max_steps=20,
        max_tool_calls=40,
        case_label="none",
        has_evidence=False,
        disk=None,
        disk_label="",
        memory=None,
        pcap=None,
        pcap_sources=None,
        tools=0,
        case_context_set=False,
    )
    console = Console(record=True, width=120, no_color=True)
    console.print(panel)
    rendered = console.export_text()
    assert "none attached" in rendered
    assert "0 attached" not in rendered


def test_the_prompt_names_what_the_run_produces_as_evidence_too():
    """A capability the evidence listing does not name is one the model will not use.

    Two runs over the same capture reassembled an archive and then decoded a
    value out of the capture without calling the decoder at all: the listing
    named the medium and nothing else, so the functions that read what the run
    itself produced were never presented as a way to reach anything.
    """

    from forensic_agent.agent.system_prompt import case_available_evidence

    listed = case_available_evidence(
        ["pcap_query", "transform_query", "archive_query", "ocr_image"],
        disk_available=False,
        memory_available=False,
        pcap_available=True,
    )
    sentence = "; ".join(listed)
    assert "pcap_query" in sentence
    for name in ("transform_query", "archive_query", "ocr_image"):
        assert name in sentence, name
