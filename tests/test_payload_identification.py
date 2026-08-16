"""Payload identification is libmagic's, and every result says whose it is."""

from __future__ import annotations

import gzip
import io
import struct
import zipfile
from collections.abc import Iterator
from typing import Any

import pytest

from forensic_agent.tools import payload_identification
from forensic_agent.tools.payload_identification import (
    LEADING_BYTE_READER,
    LEADING_BYTE_SIGNATURES,
    LIBMAGIC_READER,
    PayloadIdentification,
    extract_embedded_strings,
    identification_field_names,
    identify_payload,
    leading_byte_signature,
    reset_payload_reader,
)


@pytest.fixture(autouse=True)
def _forget_resolved_reader() -> Iterator[None]:
    """No test may inherit or leave behind another test's resolved host."""

    reset_payload_reader()
    yield
    reset_payload_reader()


def _libmagic_is_reachable() -> bool:
    reset_payload_reader()
    reader, _ = payload_identification._resolve_reader()
    reset_payload_reader()
    return reader is not None


requires_libmagic = pytest.mark.skipif(
    not _libmagic_is_reachable(),
    reason="no libmagic shared library can be loaded on this host",
)


def _real_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("evidence/report.txt", "x" * 4000)
    return buffer.getvalue()


def _real_gzip() -> bytes:
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", filename="report.txt") as member:
        member.write(b"y" * 4000)
    return buffer.getvalue()


def _real_pe() -> bytes:
    dos = bytearray(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"\x00" * 48)
    struct.pack_into("<I", dos, 0x3C, 0x80)
    stub = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd!This program cannot be run in DOS mode.\r\r\n$"
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x8664, 3, 0, 0, 0, 0xF0, 0x0022)
    return bytes(dos) + stub[:64].ljust(64, b"\x00") + coff + struct.pack("<H", 0x020B) + b"\x00" * 512


#: The nine formats the in-house table used to name, each as the leading bytes a
#: reassembler actually holds, against the media types libmagic answers for them.
#: Where two are accepted they are the two spellings libmagic's own versions use
#: — 5.44 and 5.46 renamed RAR — and never a choice made here.
NINE_FORMATS: tuple[tuple[str, bytes, frozenset[str]], ...] = (
    (
        "7-Zip",
        b"7z\xbc\xaf\x27\x1c\x00\x04" + b"\x00" * 40,
        frozenset({"application/x-7z-compressed"}),
    ),
    (
        "PNG",
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00@\x00\x00\x00@\x08\x02\x00\x00\x00",
        frozenset({"image/png"}),
    ),
    ("ZIP", _real_zip(), frozenset({"application/zip"})),
    (
        "RAR",
        b"Rar!\x1a\x07\x00\xcf\x90s\x00\x00\r\x00\x00\x00\x00\x00\x00\x00" + b"\x00" * 32,
        frozenset({"application/x-rar", "application/vnd.rar"}),
    ),
    (
        "PDF",
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        frozenset({"application/pdf"}),
    ),
    (
        "JPEG",
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xdb\x00C\x00",
        frozenset({"image/jpeg"}),
    ),
    ("GIF", b"GIF89a@\x00@\x00\xf7\x00\x00" + b"\x00" * 32, frozenset({"image/gif"})),
    (
        "PE",
        _real_pe(),
        frozenset({"application/vnd.microsoft.portable-executable", "application/x-dosexec"}),
    ),
    ("gzip", _real_gzip(), frozenset({"application/gzip"})),
)

#: The constructed head `docs/TOOL_VALIDATION.md` records as the one disagreement
#: between the former nine-entry table and libmagic 5.46.
ZIP_FRAGMENT_31 = b"PK\x03\x04\x14\x00\x00\x00\x00\x00" + b"\x00" * 21


@pytest.mark.parametrize(
    ("name", "head", "media_types"),
    NINE_FORMATS,
    ids=[entry[0] for entry in NINE_FORMATS],
)
@requires_libmagic
def test_libmagic_identifies_every_format_the_in_house_table_used_to_name(
    name: str,
    head: bytes,
    media_types: frozenset[str],
) -> None:
    identification = identify_payload(head)

    assert identification.identified, f"libmagic identified no format in the {name} head"
    assert identification.mime_type in media_types
    assert identification.description
    # The description is libmagic's own sentence, not a label chosen here.
    assert identification.description not in {label for _, label in LEADING_BYTE_SIGNATURES}


@requires_libmagic
def test_every_identification_names_the_reader_that_supplied_it() -> None:
    row = identify_payload(_real_zip()).fields()

    assert row["detected_type_reader"] == LIBMAGIC_READER
    assert row["detected_type_reader_version"]
    assert row["detected_type_reader_route"] == "libmagic shared library"
    assert row["detected_type_mime"] == "application/zip"
    assert "leading_byte_signature" not in row


@requires_libmagic
def test_libmagic_declines_the_31_byte_zip_fragment_and_says_that_it_did() -> None:
    identification = identify_payload(ZIP_FRAGMENT_31)

    assert identification.identified is False
    assert identification.description is None
    assert identification.mime_type is None
    # libmagic answered; what it answered is that it recognises no format. The
    # reader is still named, because a decline is that reader's finding.
    assert identification.reader == LIBMAGIC_READER
    assert identification.unidentified_reason is not None
    assert LIBMAGIC_READER in identification.unidentified_reason


def test_the_leading_bytes_of_the_31_byte_zip_fragment_are_read_and_labelled_here() -> None:
    identification = identify_payload(ZIP_FRAGMENT_31)
    row = identification.fields()

    assert identification.leading_byte_signature == "ZIP archive (zip/docx/xlsx)"
    assert row["leading_byte_signature"] == "ZIP archive (zip/docx/xlsx)"
    assert row["leading_byte_signature_reader"] == LEADING_BYTE_READER
    # The two facts never merge: the leading-byte reading is never the type.
    assert row["detected_type"] is None


@requires_libmagic
def test_the_same_zip_at_full_length_is_libmagics_answer_not_the_signatures() -> None:
    identification = identify_payload(_real_zip())

    assert identification.mime_type == "application/zip"
    assert identification.leading_byte_signature is None


@pytest.mark.parametrize(
    ("head", "expected"),
    [
        (b"PK\x03\x04payload", "ZIP archive (zip/docx/xlsx)"),
        (b"MZpayload", None),
        (b"\x89PNG\r\n\x1a\npayload", None),
        (b"%PDFpayload", None),
        (b"7z\xbc\xaf\x27\x1cpayload", None),
        (b"Rar!\x1a\x07payload", None),
        (b"\xff\xd8\xffpayload", None),
        (b"GIF8payload", None),
        (b"\x1f\x8bpayload", None),
        (b"not a known payload", None),
    ],
)
def test_the_leading_byte_reader_holds_only_the_one_libmagic_declines_on(
    head: bytes,
    expected: str | None,
) -> None:
    assert leading_byte_signature(head) == expected


def test_the_leading_byte_table_is_one_signature_and_no_more() -> None:
    assert LEADING_BYTE_SIGNATURES == ((b"PK\x03\x04", "ZIP archive (zip/docx/xlsx)"),)


def test_a_host_without_libmagic_states_that_rather_than_answering(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(payload_identification, "_RESOLVED", (None, "no libmagic here"))

    identification = identify_payload(ZIP_FRAGMENT_31)
    row = identification.fields()

    assert identification.reader is None
    assert identification.unidentified_reason == "no libmagic here"
    assert row["detected_type"] is None
    assert row["detected_type_reader"] is None
    assert row["detected_type_unidentified"] == "no libmagic here"
    # The leading bytes are still reported, under the reader that read them.
    assert row["leading_byte_signature_reader"] == LEADING_BYTE_READER


def test_no_shared_library_is_reported_with_every_candidate_that_was_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        payload_identification,
        "_load_shared_library",
        lambda: (None, ["libmagic.so.1: refused for this test"]),
    )

    identification = identify_payload(_real_gzip())

    assert identification.reader is None
    assert identification.unidentified_reason is not None
    assert "libmagic.so.1: refused for this test" in identification.unidentified_reason


def test_a_reader_that_raises_is_reported_as_an_unidentified_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Raising:
        route = "test double"
        version = "9.99"

        def read(self, raw: bytes) -> Any:
            return payload_identification._Reading(None, None, "libmagic raised: no database")

    monkeypatch.setattr(payload_identification, "_RESOLVED", (_Raising(), None))

    identification = identify_payload(ZIP_FRAGMENT_31)

    assert identification.identified is False
    assert identification.reader == LIBMAGIC_READER
    assert identification.unidentified_reason == "libmagic raised: no database"
    assert identification.leading_byte_signature == "ZIP archive (zip/docx/xlsx)"


def test_identification_field_names_cover_everything_a_result_can_emit() -> None:
    complete = PayloadIdentification(
        reader=LIBMAGIC_READER,
        reader_version="5.44",
        reader_route="libmagic shared library",
        description="Zip archive data",
        mime_type="application/zip",
        leading_byte_signature="ZIP archive (zip/docx/xlsx)",
        unidentified_reason="a reason",
    )

    assert set(complete.fields("type")) == set(identification_field_names("type"))


def test_extract_embedded_strings_finds_utf16le_and_ascii_in_stable_order() -> None:
    raw = (
        b"\x00\x01"
        + "evidence.txt".encode("utf-16-le")
        + b"\x00\x00"
        + b"ASCII finding"
        + b"\x00"
    )

    assert extract_embedded_strings(raw) == ["evidence.txt", "ASCII finding"]


def test_extract_embedded_strings_deduplicates_and_caps_output() -> None:
    raw = b"\x00".join([b"duplicate", b"duplicate", *[f"item-{i}".encode() for i in range(20)]])
    strings = extract_embedded_strings(raw)

    assert strings.count("duplicate") == 1
    assert len(strings) == 15


def test_pcap_private_names_remain_compatible_aliases() -> None:
    from forensic_agent.tools import pcap_tool

    assert pcap_tool._embedded_strings is extract_embedded_strings
