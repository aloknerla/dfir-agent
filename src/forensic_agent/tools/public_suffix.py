"""Split a domain name into its registrable part and its public suffix.

Where one name ends and the next organisation begins is not a property of the
name. ``evil.co.uk`` and ``evil.com`` have the same shape and different answers,
and no rule over label counts gets both right: a two-label rule reports ``co.uk``
as the domain and hides the registrant. The boundary is published, as the Public
Suffix List, and reading it is a lookup rather than an inference.

The reader used here is libpsl, the reference implementation the same list is
consumed through by curl and by every library that follows it. It is present in
the project image, it carries the list itself rather than fetching one, and it
reports the list's own digest and date, so a reading made today and the same
reading made years from now are attributable to one version of one list. That is
the same disposition the hardware-address registry has in
:mod:`forensic_agent.tools.hardware_vendor`: an installed, versioned, digested
table, cited in every result it answers.

Nothing here decides anything about a name. The library is asked, the answer and
the identity of the list that gave it are returned together, and a host with no
reader installed produces no answer at all rather than a guessed one — a domain
boundary invented locally would be indistinguishable in the output from one the
list actually publishes.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import threading
from pathlib import Path
from typing import Any

from forensic_agent.core.repro import sha256_hex

#: An operator outside the project image can name their own build of the library,
#: and pin an explicit list file rather than the one compiled into it. Nothing
#: else is consulted: a reader that cannot be found is reported, never replaced.
_LIBRARY_ENVIRONMENT_VARIABLE = "DFA_PSL_LIBRARY"
_LIST_ENVIRONMENT_VARIABLE = "DFA_PSL_LIST"

_DEFAULT_LIBRARY_NAMES = ("libpsl.so.5", "libpsl.so", "libpsl.5.dylib", "libpsl.dylib")

#: The identity of the list that answered, as libpsl reports it for its built-in
#: copy. The digest is the list's own, not one computed here.
_BUILTIN_LIST_SOURCE = "libpsl-builtin"

_LOAD_LOCK = threading.Lock()
_READER: _PublicSuffixReader | None = None
_LOAD_ATTEMPTED = False


class _PublicSuffixReader:
    """A loaded libpsl and the identity of the list it answers from."""

    def __init__(self, library: ctypes.CDLL, path: str) -> None:
        self._library = library
        self._declare_signatures()
        self._context, self._list = self._open_list()
        self._library_path = path
        version = library.psl_get_version()
        self._library_version = version.decode("utf-8", "replace") if version else None

    def _declare_signatures(self) -> None:
        """Declare the C prototypes ctypes cannot discover from the object."""

        library = self._library
        library.psl_builtin.restype = ctypes.c_void_p
        library.psl_builtin.argtypes = []
        library.psl_builtin_sha1sum.restype = ctypes.c_char_p
        library.psl_builtin_sha1sum.argtypes = []
        library.psl_builtin_file_time.restype = ctypes.c_long
        library.psl_builtin_file_time.argtypes = []
        library.psl_get_version.restype = ctypes.c_char_p
        library.psl_get_version.argtypes = []
        library.psl_load_file.restype = ctypes.c_void_p
        library.psl_load_file.argtypes = [ctypes.c_char_p]
        library.psl_suffix_count.restype = ctypes.c_int
        library.psl_suffix_count.argtypes = [ctypes.c_void_p]
        library.psl_suffix_exception_count.restype = ctypes.c_int
        library.psl_suffix_exception_count.argtypes = [ctypes.c_void_p]
        library.psl_registrable_domain.restype = ctypes.c_char_p
        library.psl_registrable_domain.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        library.psl_unregistrable_domain.restype = ctypes.c_char_p
        library.psl_unregistrable_domain.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

    def _open_list(self) -> tuple[int, dict[str, Any]]:
        """Open the pinned list file when one is named, else the built-in copy."""

        configured = os.environ.get(_LIST_ENVIRONMENT_VARIABLE)
        if configured:
            path = Path(configured)
            handle = self._library.psl_load_file(str(path).encode("utf-8"))
            if not handle:
                raise OSError(f"libpsl could not load the list file {configured!r}")
            return handle, {
                "source": str(path),
                "sha256": sha256_hex(path.read_bytes()),
            }
        handle = self._library.psl_builtin()
        if not handle:
            raise OSError("this build of libpsl carries no built-in Public Suffix List")
        digest = self._library.psl_builtin_sha1sum()
        return handle, {
            "source": _BUILTIN_LIST_SOURCE,
            "sha1": digest.decode("ascii", "replace") if digest else None,
            "updated_posix_time": int(self._library.psl_builtin_file_time()) or None,
        }

    def identity(self) -> dict[str, Any]:
        """Describe the reader and the list, for citation beside every answer."""

        return {
            "reader": "libpsl",
            "library": self._library_path,
            "library_version": self._library_version,
            "list": dict(self._list),
            "suffix_entries": int(self._library.psl_suffix_count(self._context)),
            "suffix_exceptions": int(
                self._library.psl_suffix_exception_count(self._context)
            ),
        }

    def split(self, name: str) -> tuple[str | None, str | None]:
        """Return (registrable domain, public suffix) as the list defines them."""

        encoded = name.encode("idna") if not name.isascii() else name.encode("ascii")
        registrable = self._library.psl_registrable_domain(self._context, encoded)
        suffix = self._library.psl_unregistrable_domain(self._context, encoded)
        return (
            registrable.decode("ascii", "replace") if registrable else None,
            suffix.decode("ascii", "replace") if suffix else None,
        )


def _library_paths() -> tuple[str, ...]:
    configured = os.environ.get(_LIBRARY_ENVIRONMENT_VARIABLE)
    if configured:
        return (configured,)
    discovered = ctypes.util.find_library("psl")
    candidates = list(_DEFAULT_LIBRARY_NAMES)
    if discovered:
        candidates.insert(0, discovered)
    return tuple(candidates)


def _reader() -> _PublicSuffixReader | None:
    """Load the reader once per process; a reader that cannot be loaded is absent."""

    global _READER, _LOAD_ATTEMPTED
    with _LOAD_LOCK:
        if _LOAD_ATTEMPTED:
            return _READER
        _LOAD_ATTEMPTED = True
        for candidate in _library_paths():
            try:
                library = ctypes.CDLL(candidate)
                _READER = _PublicSuffixReader(library, candidate)
            except (AttributeError, OSError, ValueError):
                continue
            return _READER
        return None


def reset_cache() -> None:
    """Forget the loaded reader, so a different library or list can be consulted."""

    global _READER, _LOAD_ATTEMPTED
    with _LOAD_LOCK:
        _READER = None
        _LOAD_ATTEMPTED = False


def reader_identity() -> dict[str, Any]:
    """Describe the available reader, or state that none is."""

    reader = _reader()
    if reader is None:
        return {
            "available": False,
            "reason": (
                "no Public Suffix List reader is installed. Install libpsl or set "
                f"{_LIBRARY_ENVIRONMENT_VARIABLE} to a copy."
            ),
        }
    return {"available": True, **reader.identity()}


def registrable_domain(name: str) -> dict[str, Any]:
    """Name the registrable domain and public suffix of one domain name.

    The result carries the identity of the list that answered, so the split is
    attributable to a specific version of the Public Suffix List rather than to
    whatever happened to be installed.
    """

    candidate = str(name or "").strip().strip(".").lower()
    if not candidate:
        return {"error": "a domain name is required", "name": str(name)[:253]}

    reader = _reader()
    if reader is None:
        return {"error": reader_identity()["reason"], "name": candidate[:253]}

    try:
        registrable, suffix = reader.split(candidate)
    except (UnicodeError, ValueError):
        return {
            "error": "the name is not a resolvable domain name",
            "name": candidate[:253],
        }
    return {
        "name": candidate[:253],
        "registrable_domain": registrable,
        "public_suffix": suffix,
        "public_suffix_list": reader.identity(),
    }
