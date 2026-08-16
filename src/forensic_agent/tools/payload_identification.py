"""Identify a reconstructed payload with libmagic, and name the reader that answered.

Deciding what a run of bytes is, from its leading bytes, is what libmagic exists
to do, and it is what ``file`` ships. This module hands the bytes to libmagic and
reports **libmagic's own description**, so the type a carved, reassembled or
archived payload carries is an upstream observation of a validated tool rather
than a label this project invented for it. Nothing here decodes a format.

libmagic is reached through its own C entry points, so no ``python-magic`` is
needed. The ``file`` subprocess is deliberately not used: it will not seek in
bytes handed on stdin, so it answers ``data`` for a payload it identifies from a
path, and making it equivalent would mean writing the payload to a file, which is
what this project's payload containment exists to prevent.

A host where the library cannot be loaded therefore has no libmagic, and that is
not an error: the identification states that libmagic was not reachable and why,
per payload, rather than leaving a reader to infer it from a missing field.

libmagic declines on a fragment it cannot validate, and that is correct — a
31-byte local file header beginning ``PK\\x03\\x04`` is not a ZIP archive. That is
still less than a carver wants, so a decline is reported as a decline and the
leading bytes are reported beside it under their own name and their own reader.
The two facts never merge into one label.

ZIP is the only signature that both installed libmagic versions (5.44 and 5.46)
decline below 64 bytes, so ZIP is the only leading-byte signature read here, and
the reassemblers that hold such a fragment are reassembling ZIP-based containers.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import re
import threading
from dataclasses import dataclass
from typing import Final, NamedTuple

#: Names a result uses for the two readers, so a consumer never has to infer
#: which one supplied an identification from the shape of the fields.
LIBMAGIC_READER: Final = "libmagic"
LEADING_BYTE_READER: Final = "in-house.leading-byte-signature"

#: The one leading-byte signature this project still reads itself, and the only
#: one a consumer needs: it is the only format both installed libmagic versions
#: decline on below 64 bytes, and the reassemblers that hold such a fragment are
#: reassembling ZIP-based containers.
LEADING_BYTE_SIGNATURES: Final[tuple[tuple[bytes, str], ...]] = (
    (b"PK\x03\x04", "ZIP archive (zip/docx/xlsx)"),
)

_MAGIC_MIME_TYPE: Final = 0x000010
_MAGIC_ERROR: Final = 0x000200

#: Tried in order after :func:`ctypes.util.find_library`, which resolves nothing
#: on a host with no development symlink even where the runtime library is present.
_LIBRARY_CANDIDATES: Final[tuple[str, ...]] = (
    "libmagic.so.1",
    "libmagic.so",
    "libmagic.1.dylib",
    "libmagic.dylib",
)

#: What libmagic answers when it read the buffer and recognised no format. It is
#: an answer, not a failure, and is reported as one.  Both halves are checked
#: because the description varies with the buffer's length — a one-byte buffer is
#: ``very short file (no magic)`` — while the media type does not.
_DECLINED_DESCRIPTION: Final = "data"
_DECLINED_MEDIA_TYPE: Final = "application/octet-stream"


class _Reading(NamedTuple):
    """One reader's answer about one buffer."""

    description: str | None
    mime_type: str | None
    failure: str | None = None


@dataclass(frozen=True, slots=True)
class PayloadIdentification:
    """What a payload is, and which reader said so.

    ``description`` and ``mime_type`` are libmagic's own strings, never this
    project's. ``leading_byte_signature`` is this project's own reading and is
    present only where libmagic supplied no identification, so the two are never
    read as one answer.
    """

    #: The reader that answered. ``libmagic`` whenever libmagic was reachable —
    #: including when its answer was that it recognises no format — and ``None``
    #: only where no libmagic could be reached at all.
    reader: str | None = None
    reader_version: str | None = None
    reader_route: str | None = None
    description: str | None = None
    mime_type: str | None = None
    leading_byte_signature: str | None = None
    #: Why no format was identified. Set whenever ``description`` is ``None``.
    unidentified_reason: str | None = None

    @property
    def identified(self) -> bool:
        return self.description is not None

    def fields(self, key: str = "detected_type") -> dict[str, object]:
        """The identification as result fields, each naming its own reader."""

        row: dict[str, object] = {key: self.description, f"{key}_reader": self.reader}
        if self.reader_version is not None:
            row[f"{key}_reader_version"] = self.reader_version
        if self.reader_route is not None:
            row[f"{key}_reader_route"] = self.reader_route
        if self.mime_type is not None:
            row[f"{key}_mime"] = self.mime_type
        if self.unidentified_reason is not None:
            row[f"{key}_unidentified"] = self.unidentified_reason
        if self.leading_byte_signature is not None:
            row["leading_byte_signature"] = self.leading_byte_signature
            row["leading_byte_signature_reader"] = LEADING_BYTE_READER
        return row


def identification_field_names(key: str = "detected_type") -> tuple[str, ...]:
    """Every field :meth:`PayloadIdentification.fields` can emit under ``key``.

    A result that carries an identification forward into another row copies it
    by this list, so a field added to the identification is carried without the
    second row having to learn about it.
    """

    return (
        key,
        f"{key}_reader",
        f"{key}_reader_version",
        f"{key}_reader_route",
        f"{key}_mime",
        f"{key}_unidentified",
        "leading_byte_signature",
        "leading_byte_signature_reader",
    )


class _SharedLibraryReader:
    """libmagic through its own C entry points, opened once for this process.

    A magic cookie carries the parse state of the call in progress and is not
    safe to use from two threads at once, so both cookies are held behind one
    lock. The cost quoted in the module docstring is the cost under it.
    """

    route: Final = "libmagic shared library"

    def __init__(self, library: ctypes.CDLL) -> None:
        self._library = library
        self._lock = threading.Lock()
        library.magic_open.restype = ctypes.c_void_p
        library.magic_open.argtypes = [ctypes.c_int]
        library.magic_load.restype = ctypes.c_int
        library.magic_load.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        library.magic_buffer.restype = ctypes.c_char_p
        library.magic_buffer.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
        library.magic_error.restype = ctypes.c_char_p
        library.magic_error.argtypes = [ctypes.c_void_p]
        library.magic_version.restype = ctypes.c_int
        library.magic_version.argtypes = []
        self._describe_cookie = self._open(_MAGIC_ERROR)
        self._mime_cookie = self._open(_MAGIC_ERROR | _MAGIC_MIME_TYPE)
        self.version = self._version()

    def _open(self, flags: int) -> int:
        cookie = self._library.magic_open(flags)
        if not cookie:
            raise OSError("magic_open returned no cookie")
        if self._library.magic_load(ctypes.c_void_p(cookie), None) != 0:
            error = self._library.magic_error(ctypes.c_void_p(cookie))
            raise OSError(
                f"magic_load refused the compiled magic database: "
                f"{error.decode('utf-8', 'replace') if error else 'no reason given'}"
            )
        return int(cookie)

    def _version(self) -> str:
        # magic_version() reports the library's own version as an integer of the
        # form MMmm, which is the only version statement that cannot disagree
        # with the library actually loaded.
        raw = int(self._library.magic_version())
        return f"{raw // 100}.{raw % 100:02d}"

    def _ask(self, cookie: int, raw: bytes) -> str | None:
        answer = self._library.magic_buffer(ctypes.c_void_p(cookie), raw, len(raw))
        if answer is None:
            return None
        return bytes(answer).decode("utf-8", "replace")

    def read(self, raw: bytes) -> _Reading:
        try:
            with self._lock:
                description = self._ask(self._describe_cookie, raw)
                mime_type = self._ask(self._mime_cookie, raw)
        except Exception as error:  # noqa: BLE001 - a foreign call fails in its own way
            return _Reading(None, None, f"libmagic raised while reading the buffer: {error}")
        if description is None:
            return _Reading(None, None, "libmagic returned no description for the buffer")
        return _Reading(description, mime_type)


_RESOLUTION_LOCK = threading.Lock()
_RESOLVED: tuple[_SharedLibraryReader | None, str | None] | None = None


def _load_shared_library() -> tuple[_SharedLibraryReader | None, list[str]]:
    attempts: list[str] = []
    found = ctypes.util.find_library("magic")
    for name in ((found,) if found else ()) + _LIBRARY_CANDIDATES:
        try:
            return _SharedLibraryReader(ctypes.CDLL(name)), attempts
        except Exception as error:  # noqa: BLE001 - every loader failure is a candidate rejection
            attempts.append(f"{name}: {str(error)[:120]}")
    return None, attempts


def _resolve_reader() -> tuple[_SharedLibraryReader | None, str | None]:
    """The libmagic this host offers, resolved once and reused.

    A host either ships the library or does not, so the outcome is held either
    way: re-probing per payload would put the loader in the middle of a carver's
    loop for an answer that cannot have changed.
    """

    global _RESOLVED
    if _RESOLVED is not None:
        return _RESOLVED
    with _RESOLUTION_LOCK:
        if _RESOLVED is None:
            library, attempts = _load_shared_library()
            _RESOLVED = (
                (library, None)
                if library is not None
                else (
                    None,
                    "libmagic is not reachable from this process: "
                    f"{'; '.join(attempts) or 'no library candidate was tried'}",
                )
            )
    return _RESOLVED


def reset_payload_reader() -> None:
    """Forget the resolved reader, so a test can install a different host."""

    global _RESOLVED
    with _RESOLUTION_LOCK:
        _RESOLVED = None


def leading_byte_signature(raw: bytes) -> str | None:
    """This project's own reading of the leading bytes, for the two it still reads."""

    for signature, label in LEADING_BYTE_SIGNATURES:
        if raw.startswith(signature):
            return label
    return None


def identify_payload(raw: bytes) -> PayloadIdentification:
    """What libmagic makes of these bytes, and what the leading bytes look like."""

    reader, unreachable = _resolve_reader()
    if reader is None:
        return PayloadIdentification(
            leading_byte_signature=leading_byte_signature(raw),
            unidentified_reason=unreachable,
        )
    reading = reader.read(raw)
    version = reader.version
    named = f"{LIBMAGIC_READER} {version}" if version else LIBMAGIC_READER
    if reading.failure is not None:
        return PayloadIdentification(
            reader=LIBMAGIC_READER,
            reader_version=version,
            reader_route=reader.route,
            leading_byte_signature=leading_byte_signature(raw),
            unidentified_reason=reading.failure,
        )
    declined = (
        reading.description is None
        or reading.description.strip() == _DECLINED_DESCRIPTION
        or reading.mime_type == _DECLINED_MEDIA_TYPE
    )
    if declined:
        return PayloadIdentification(
            reader=LIBMAGIC_READER,
            reader_version=version,
            reader_route=reader.route,
            leading_byte_signature=leading_byte_signature(raw),
            unidentified_reason=(
                f"{named} read {len(raw)} byte(s) and recognised no file format"
            ),
        )
    return PayloadIdentification(
        reader=LIBMAGIC_READER,
        reader_version=version,
        reader_route=reader.route,
        description=reading.description,
        mime_type=reading.mime_type,
    )


def extract_embedded_strings(raw: bytes) -> list[str]:
    """Return up to 15 distinct printable UTF-16LE and ASCII strings."""

    utf16_strings = [
        match.decode("utf-16-le", "replace")
        for match in re.findall(rb"(?:[\x20-\x7e]\x00){3,}", raw)
    ]
    ascii_strings = [
        match.decode("ascii", "replace")
        for match in re.findall(rb"[\x20-\x7e]{4,}", raw)
    ]
    seen: set[str] = set()
    strings: list[str] = []
    for value in utf16_strings + ascii_strings:
        value = value.strip()
        if value and value not in seen:
            seen.add(value)
            strings.append(value)
    return strings[:15]
