"""Resolve a hardware address to the organisation that registered its prefix.

An adapter's hardware address begins with a prefix the IEEE assigns to one
organisation, and reading it is a routine step: it is how an examiner decides
which of several installed adapters a recorded address belongs to. Without it a
recorded address is an opaque number, and two examinations of the same bytes can
reach opposite conclusions about the hardware.

The mapping is a registry, not an inference, so it is looked up in a table rather
than reasoned about. The table used here is the one the installed packet
analyser already ships: it is present in the image, it is versioned with that
package, and its digest can be recorded alongside every other backend version, so
a lookup made today and the same lookup made years from now return the same
answer. Reaching for an online registry instead would make the result depend on
when it was asked, which is the one thing a reproducible examination cannot
afford.

The table is generic. It knows nothing about any case: the same file answers
every question about every adapter, which is why consulting it adds no knowledge
of the evidence that the evidence did not already carry.
"""

from __future__ import annotations

import os
import re
import threading
from pathlib import Path

from forensic_agent.core.repro import sha256_hex

#: Where the packet analyser installs its registry. An operator running outside
#: the project image can point at their own copy; nothing else is consulted, so a
#: missing table is reported rather than silently worked around.
_TABLE_ENVIRONMENT_VARIABLE = "DFA_OUI_TABLE"
_DEFAULT_TABLE_PATHS = (
    Path("/usr/share/wireshark/manuf"),
    Path("/usr/local/share/wireshark/manuf"),
)

#: A hardware address is written half a dozen ways in practice. Everything that
#: is not a hexadecimal digit is separator noise, so the address is reduced to
#: its digits before anything is compared.
_NON_HEX = re.compile(r"[^0-9A-Fa-f]")

#: Prefix lengths the registry assigns, longest first: a 36-bit assignment must
#: win over the 24-bit block it sits inside, or a small registrant is reported as
#: the large one that owns the surrounding range.
_PREFIX_DIGITS = (9, 7, 6)

_LOAD_LOCK = threading.Lock()
_TABLE: dict[str, tuple[str, str]] | None = None
_TABLE_SOURCE: tuple[str, str] | None = None


def _table_path() -> Path | None:
    configured = os.environ.get(_TABLE_ENVIRONMENT_VARIABLE)
    if configured:
        candidate = Path(configured)
        return candidate if candidate.is_file() else None
    for candidate in _DEFAULT_TABLE_PATHS:
        if candidate.is_file():
            return candidate
    return None


def _parse(text: str) -> dict[str, tuple[str, str]]:
    """Map normalised prefix -> (short name, long name) from the registry's layout.

    Rows are ``prefix<TAB>short<TAB>long``, the long name being absent on many
    rows. A prefix may carry a bit-length suffix for assignments smaller than a
    full 24-bit block.
    """

    table: dict[str, tuple[str, str]] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        prefix, _, bits = parts[0].partition("/")
        digits = _NON_HEX.sub("", prefix).upper()
        if not digits:
            continue
        if bits:
            # A bit length only ever narrows the block, and the registry writes
            # those in whole nibbles, so the digit count follows directly.
            try:
                digits = digits[: max(6, int(bits) // 4)]
            except ValueError:
                continue
        short = parts[1].strip()
        long = parts[2].strip() if len(parts) > 2 else ""
        if short:
            table.setdefault(digits, (short, long or short))
    return table


def _loaded() -> tuple[dict[str, tuple[str, str]], tuple[str, str]] | None:
    """Load the registry once per process; a table that cannot be read is absent."""

    global _TABLE, _TABLE_SOURCE
    with _LOAD_LOCK:
        if _TABLE is not None and _TABLE_SOURCE is not None:
            return _TABLE, _TABLE_SOURCE
        path = _table_path()
        if path is None:
            return None
        try:
            raw = path.read_bytes()
        except OSError:
            return None
        _TABLE = _parse(raw.decode("utf-8", errors="replace"))
        _TABLE_SOURCE = (str(path), sha256_hex(raw))
        return _TABLE, _TABLE_SOURCE


def reset_cache() -> None:
    """Forget the loaded registry, so a different table can be consulted."""

    global _TABLE, _TABLE_SOURCE
    with _LOAD_LOCK:
        _TABLE = None
        _TABLE_SOURCE = None


def hardware_vendor(address: str) -> dict:
    """Name the organisation registered for one hardware address's prefix.

    The result carries the digest of the table that answered, so the reading is
    attributable to a specific version of the registry rather than to whatever
    happened to be installed.
    """

    digits = _NON_HEX.sub("", str(address or "")).upper()
    if len(digits) < 6:
        return {
            "error": "a hardware address needs at least six hexadecimal digits; "
                     f"received {str(address)[:40]!r}",
        }

    loaded = _loaded()
    if loaded is None:
        return {
            "error": "no hardware-address registry is available. Install the packet "
                     f"analyser's table or set {_TABLE_ENVIRONMENT_VARIABLE} to a copy.",
        }
    table, (source, digest) = loaded

    for length in _PREFIX_DIGITS:
        if len(digits) < length:
            continue
        hit = table.get(digits[:length])
        if hit is None:
            continue
        short, long = hit
        return {
            "address": str(address)[:64],
            "prefix": digits[:length],
            "vendor": long,
            "vendor_short": short,
            "registry": {"path": source, "sha256": digest, "entries": len(table)},
        }

    return {
        "address": str(address)[:64],
        "prefix": digits[:6],
        "vendor": None,
        "note": "the registry records no assignment for this prefix",
        "registry": {"path": source, "sha256": digest, "entries": len(table)},
    }
