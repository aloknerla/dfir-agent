"""Which FILE a raw-image byte offset came from.

A disk-wide search reads the medium as bytes, so all it can say about a hit is
where the bytes sit — ``723449639``, or ``598631936-GZIP-1450`` for one recovered
out of a compressed stream. "somewhere in this 40 GB image" is not a finding;
"in /Users/Alice/.../History" is, and the distance between those two sentences
is the evidentiary value of the hit.

The Sleuth Kit holds the answer in two steps: ``ifind`` names the inode claiming
a data unit and ``ffind`` names the entry pointing at that inode. This module
runs them over a BATCH, because a search returns hundreds of hits landing in a
handful of files and one subprocess pair per hit is paid for nothing. It is
equally its job to refuse an answer: bytes in unallocated space belong to no file,
and saying so is the result, never a nearby path offered as the source. Read-only.
"""

from __future__ import annotations

import os
import re
from collections.abc import Sequence
from typing import Any

from forensic_agent.core.tool_availability import resolve_tool
from forensic_agent.core.tool_failure import tool_failure_result
from forensic_agent.core.toolkit import run_external

#: Distinct offsets resolved per call: each unseen data unit costs an ifind/ffind
#: pair, so an unbounded batch is an unbounded number of processes.
_OFFSET_CAP = 256
#: Both binaries read bounded metadata: a slow answer means the medium is not
#: delivering, not that the work is large.
_TIMEOUT = 120
#: TSK reads ``-o`` in 512-byte sectors unless ``-b`` overrides it, and nothing here
#: passes ``-b``, so this is the unit the caller's sector count is in.
_SECTOR_BYTES = 512
#: An inode address is a number, on NTFS the triple ``48-128-4``; anything else on
#: ifind's stdout is one of its sentences.
_INODE = re.compile(r"\d+(?:-\d+)*")
#: ifind exits 0 whether or not it found an inode, so the return code establishes
#: nothing: these two sentences ARE its answers, and neither may widen to a path.
_IFIND_STATES: dict[str, tuple[str, str]] = {
    "inode not found": ("unallocated", "no inode claims this data unit, so the bytes lie in "
                                       "unallocated space and no allocated file contains them"),
    "meta data": ("filesystem_metadata", "the data unit belongs to the file system's own "
                                         "structures, not to file content"),
}
#: ffind's way of saying the inode is real but no directory entry points at it.
_UNNAMED = "file name not found"
#: ffind marks a deleted name with a leading asterisk — the difference between "this
#: file holds the bytes" and "this name pointed at the inode that holds them" — so it
#: becomes a field instead of being stripped in silence.
_DELETED = "*"

_FS_TYPE = re.compile(r"^File System Type:\s*(\S.*?)\s*$", re.M)
_UNIT_SIZES = {n: re.compile(rf"^{n} Size:\s*(\d+)", re.M) for n in ("Block", "Cluster", "Sector")}
_SCOPE = ("each row names the file the file system currently maps that data unit to; a unit in "
          "unallocated space carries no path and is reported as unallocated rather than "
          "attributed to a neighbouring file")


def _tsk(argv: list[str], *, subject: str, backend: str) -> tuple[str, dict[str, Any] | None]:
    """Run one TSK binary, turning any failure into a record instead of an exception."""

    try:
        proc = run_external(argv, timeout=_TIMEOUT)
    except Exception as exc:
        return "", {"attribution": "error",
                    **tool_failure_result(exc, subject=subject, backend=backend)}
    return str(proc.stdout or "").strip(), None


def _unit_bytes(given: int | None, image: str, sectors: int) -> tuple[int, dict[str, Any] | None]:
    """How many bytes ``ifind -d`` counts per data unit, from the caller or from fsstat.

    Deliberately not one fsstat field: ext/UFS address in blocks, NTFS in clusters,
    and FAT reports both while TSK addresses its data units in SECTORS. Dividing a
    FAT offset by the cluster size does not fail — it resolves a different inode and
    names a different file.
    """

    if given is not None:
        if isinstance(given, bool) or not isinstance(given, int) or given < 1:
            return 0, {"error": "block_size must be a positive byte count."}
        return given, None
    fsstat = resolve_tool(("fsstat",), "DFA_FSSTAT")
    if not fsstat:
        return 0, {"error": "block_size was not supplied and The Sleuth Kit's fsstat is not "
                            "available to read it. Install sleuthkit, set DFA_FSSTAT, or pass "
                            "block_size."}
    text, failure = _tsk([fsstat, "-o", str(sectors), image], subject=image, backend="fsstat")
    if failure is not None:
        return 0, {key: value for key, value in failure.items() if key != "attribution"}
    family = _FS_TYPE.search(text)
    fat = "FAT" in (family.group(1).upper() if family else "")
    for name in ("Block", "Sector", "Cluster") if fat else ("Block", "Cluster", "Sector"):
        found = _UNIT_SIZES[name].search(text)
        if found and int(found.group(1)) > 0:
            return int(found.group(1)), None
    return 0, {"error": "fsstat reported no data unit size here; pass block_size."}


def _split_offset(raw: str) -> tuple[int, str | None] | None:
    """Split a search hit's offset into its image offset and its in-stream part.

    ``598631936-GZIP-1450`` locates a compressed stream at 598631936 and the hit 1450
    bytes into what it decompresses to. Only the part before the first dash addresses
    the image, so it is the only part TSK can be asked about.
    """

    base, dash, inner = raw.partition("-")
    if not base.isdigit():
        return None
    return int(base), ((inner.strip() or None) if dash else None)


def _attribute_unit(ifind: str, ffind: str, image: str, sectors: int, unit: int) -> dict[str, Any]:
    """Resolve ONE data unit to a path, or to the reason it has none."""

    answer, failure = _tsk([ifind, "-o", str(sectors), "-d", str(unit), image],
                           subject=f"data unit {unit}", backend="ifind")
    if failure is not None:
        return failure
    if not _INODE.fullmatch(answer):
        state = _IFIND_STATES.get(answer.casefold())
        return ({"attribution": state[0], "note": state[1]} if state else
                {"attribution": "unattributed",
                 "note": f"ifind named no inode and said: {answer[:120]!r}"})
    named, failure = _tsk([ffind, "-o", str(sectors), image, answer],
                          subject=f"inode {answer}", backend="ffind")
    if failure is not None:
        return {**failure, "inode": answer}
    first = next((line.strip() for line in named.splitlines() if line.strip()), "")
    if not first or first.casefold().startswith(_UNNAMED):
        return {"attribution": "unnamed", "inode": answer,
                "note": "the inode holds the bytes but no directory entry names it, so the "
                        "content is orphaned rather than filed under a path"}
    return {"attribution": "path", "inode": answer, "path": first.lstrip(_DELETED).strip(),
            "deleted": first.startswith(_DELETED)}


def attribute_offsets(image_path: str, offsets: Sequence[object], *,
                      partition_offset_sectors: int = 0,
                      block_size: int | None = None) -> dict[str, Any]:
    """Map raw-image byte offsets to the in-image paths that hold those bytes.

    `offsets` are the offsets a disk-wide search reported, plain (``723449639``) or
    composite (``598631936-GZIP-1450``); a composite one resolves on the stream's own
    offset and the row says so, because the path then names the file CARRYING the
    compressed stream rather than one holding the hit as stored.
    `partition_offset_sectors` is the file system's start in 512-byte sectors, as
    TSK's ``-o`` takes it: TSK addresses within the file system while the search
    reports within the image, so the unit is relative to that start. `block_size`
    overrides fsstat. At most 256 DISTINCT offsets resolve per call, and a repeated
    data unit is looked up once.

    Returns {"image", "data_unit_bytes", "distinct_offsets", "data_unit_lookups",
    "lookup_cap", "truncated", "scope", rows:[{offset, image_offset, data_unit,
    attribution, path, inode, deleted, in_compressed_stream}]}. Never raises.
    """

    ifind = resolve_tool(("ifind",), "DFA_IFIND")
    ffind = resolve_tool(("ffind",), "DFA_FFIND")
    if not ifind or not ffind:
        return {"error": "The Sleuth Kit's ifind and ffind are what map an offset to a file. "
                         "Install sleuthkit, add it to PATH, or set DFA_IFIND / DFA_FFIND."}
    if not image_path or not os.path.exists(image_path):
        return {"error": "image not available."}
    if isinstance(offsets, str) or not isinstance(offsets, Sequence) or not offsets:
        return {"error": "offsets must be a non-empty sequence of image byte offsets."}
    sectors = partition_offset_sectors
    if isinstance(sectors, bool) or not isinstance(sectors, int) or sectors < 0:
        return {"error": "partition_offset_sectors must be a non-negative sector count."}
    unit_bytes, refusal = _unit_bytes(block_size, image_path, sectors)
    if refusal is not None:
        return refusal

    distinct = list(dict.fromkeys(str(value).strip() for value in offsets))
    truncated = len(distinct) > _OFFSET_CAP
    start = sectors * _SECTOR_BYTES
    known: dict[int, dict[str, Any]] = {}
    rows: list[dict[str, Any]] = []
    for text in distinct[:_OFFSET_CAP]:
        parsed = _split_offset(text)
        if parsed is None:
            rows.append({"offset": text[:120], "attribution": "invalid_offset",
                         "note": "not an image byte offset, so no lookup was performed"})
            continue
        image_offset, inner = parsed
        row: dict[str, Any] = {"offset": text[:120], "image_offset": image_offset}
        if image_offset < start:
            row["attribution"] = "outside_filesystem"
            row["note"] = "the offset lies before this file system starts, so nothing in it holds it"
        else:
            unit = (image_offset - start) // unit_bytes
            row["data_unit"] = unit
            if unit not in known:
                known[unit] = _attribute_unit(ifind, ffind, image_path, sectors, unit)
            row.update(known[unit])
        row["in_compressed_stream"] = inner is not None
        if inner is not None:
            row["stream_position"] = inner[:60]
            row["stream_note"] = ("resolved on the compressed stream's own offset: the path "
                                  "names the file carrying that stream and the hit was inside "
                                  "its decompressed bytes")
        rows.append(row)

    result: dict[str, Any] = {
        "image": image_path, "data_unit_bytes": unit_bytes,
        "partition_offset_sectors": sectors, "requested": len(offsets),
        "distinct_offsets": len(distinct), "data_unit_lookups": len(known),
        "lookup_cap": _OFFSET_CAP, "truncated": truncated, "scope": _SCOPE, "rows": rows,
    }
    if truncated:
        result["note"] = (f"{len(distinct)} distinct offsets were given and only the first "
                          f"{_OFFSET_CAP} were resolved; pass the rest in a further call")
    return result
