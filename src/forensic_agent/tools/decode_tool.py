"""Named transformations, performed by an established open-source decoder.

Lets the agent decode evidence (base64, base32, hex, gzip, ROT13, URL, UTF-16LE)
by CALLING a structured tool with parameters — never by writing or running a
script, and never through an implementation of this project's own.  Every
operation is carried out by `chepy <https://github.com/securisec/chepy>`_, the
same way the disk, memory and network functions are carried out by dfVFS,
Volatility 3 and tshark: this module selects the operation the caller named,
hands the value over and reports what came back.

One operation per call; the agent chains operations by citing one result from
the next.  The operation, and nothing about the value, decides what runs: the
entry points that inferred a scheme from printable-text ratios were withdrawn,
and so were this project's hand-written RC4, XOR and key derivation — exactly
the code an orchestrator has no business owning.
"""
from __future__ import annotations

import os
from typing import Literal

#: Closed set of transformations. Each one is applied exactly as named, by the
#: decoder operation named beside it.  A scheme with no entry here is not
#: performed at all rather than approximated by a neighbouring one.
DecodeOp = Literal[
    "base64",
    "base32",
    "hex",
    "gzip",
    "rot13",
    "url",
    "utf16le",
]

#: Operation name -> the method of ``chepy.Chepy`` that performs it.  Stated as
#: data so the whole mapping is readable in one place, and so nothing here can
#: quietly become an implementation instead of a call.
_CHEPY_OPERATIONS: dict[str, str] = {
    "base64": "from_base64",
    "base32": "from_base32",
    "hex": "from_hex",
    "gzip": "gzip_decompress",
    "rot13": "rot_13",
    "url": "from_url_encoding",
}

#: The decoder behind every operation, named in each result so a reader knows
#: which component did the work.
BACKEND = "chepy"

_OPS = "|".join(_CHEPY_OPERATIONS) + "|utf16le"

#: Withdrawn guessing entry points. They named a scheme the tool had inferred
#: from printable-text ratios, which is a claim it cannot substantiate.
_WITHDRAWN_OPS = frozenset({"auto", "magic"})

#: Withdrawn implementations. They were this project's own cryptography rather
#: than a call to anyone's, which is what put them outside what an orchestrator
#: may claim to have done.
_WITHDRAWN_IMPLEMENTATIONS = frozenset({"rc4", "xor"})


def _present(raw: bytes) -> dict:
    """The decoded bytes in the forms a reader and a later citation both need."""

    printable = "".join(chr(c) if 32 <= c < 127 else "." for c in raw[:600])
    return {
        "bytes": len(raw),
        "magic_hex": raw[:8].hex(),
        "text": raw.decode("utf-8", "replace")[:1500],
        "printable": printable,
    }


def _decoder_home() -> None:
    """Make sure the decoder's own configuration directory can be created.

    chepy writes its plugin configuration under the home directory at import.
    A sealed container is entitled to have no home directory yet, and the
    failure that follows is a filesystem error about a path that has nothing to
    do with the evidence.  Creating the directory here keeps the refusal, when
    there is one, about the decoding.
    """

    from pathlib import Path

    try:
        Path(os.path.expanduser("~")).mkdir(parents=True, exist_ok=True)
    except OSError:
        # Read-only or unset home: let the decoder report it in its own words.
        pass


def _decoded_bytes(data: str, op: str) -> bytes:
    """Run one chepy operation over the cited value and return its output."""

    _decoder_home()
    from chepy import Chepy

    if op == "utf16le":
        # chepy exposes the interpreter's codecs under one operation, which is
        # why the encoding is NAMED here rather than decoded here.
        return bytes(Chepy(data).decode("utf-16-le").o)
    return bytes(getattr(Chepy(data), _CHEPY_OPERATIONS[op])().o)


def decode(data: str, op: DecodeOp) -> dict:
    """Apply one named transformation to a cited value, through chepy.

    State which decoding you are applying; nothing is inferred from the value.
    Chain operations by citing one result from the next call.

    Input: `data` is the value taken from the cited result; `op` is one of
    base64, base32, hex, gzip, rot13, url, utf16le.

    Returns: {"op", "backend", "bytes", "magic_hex", "text", "printable"}.
    On failure returns {"error"} naming what the decoder refused.
    """

    operation = str(op)
    if operation in _WITHDRAWN_OPS:
        return {
            "error": (
                f"op '{operation}' no longer exists: this tool does not detect an "
                f"encoding for you. Name the decoding you are applying: {_OPS}"
            )
        }
    if operation in _WITHDRAWN_IMPLEMENTATIONS:
        return {
            "error": (
                f"op '{operation}' was withdrawn: it was this project's own "
                f"implementation rather than a call to an established decoder"
            )
        }
    if operation != "utf16le" and operation not in _CHEPY_OPERATIONS:
        return {"error": f"unknown op '{operation}'. Use: {_OPS}"}
    try:
        raw = _decoded_bytes(str(data), operation)
    except ImportError:
        return {
            "error": (
                "the decoder is not installed on this host, so no transformation "
                "was performed"
            )
        }
    except Exception as error:  # the decoder's own refusal, reported as it came
        return {"error": f"{operation} failed: {str(error)[:150]}"}
    return {"op": operation, "backend": BACKEND, **_present(raw)}
