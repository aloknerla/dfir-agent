"""Deterministic evidence-source probe based on file signatures.

Before the agent plans anything, a cheap, model-free probe inspects the evidence
file's magic bytes and key structures to classify the container (raw/dd vs EWF/E01)
and the filesystem (NTFS, FAT, exFAT, ext). The result both narrows the relevant
tool palette and is handed to the agent as a factual starting summary, so the
investigation begins from detected facts rather than from the model's guess.
"""
from __future__ import annotations

import os
from typing import BinaryIO, TypedDict

# Container signatures (file header).
_EWF1 = b"EVF\x09\x0d\x0a\xff\x00"      # EnCase EWF / .E01
_EWF2 = b"EVF2\x0d\x0a\x81"             # EWF2 / .Ex01

_SECTOR_SIZE = 512
_MBR_PARTITION_TABLE_OFFSET = 446
_MBR_PARTITION_ENTRY_SIZE = 16
_GPT_HEADER_SIGNATURE = b"EFI PART"
_EXTENDED_MBR_TYPES = {0x05, 0x0F, 0x85}


class PartitionInfo(TypedDict):
    """A partition discovered during deterministic evidence probing."""

    index: int
    offset_bytes: int
    length_bytes: int
    filesystem: str
    scheme: str
    type: str


class EvidenceInfo(TypedDict):
    """Stable result shape returned by :func:`detect_evidence`."""

    path: str
    container: str
    filesystem: str
    size_bytes: int | None
    partition_scheme: str | None
    partitions: list[PartitionInfo]
    notes: list[str]


def _filesystem_from_header(header: bytes) -> str:
    """Return a filesystem label for bytes starting at a volume's byte zero."""
    if header[3:11] == b"NTFS    ":
        return "NTFS"
    if header[3:11] == b"EXFAT   ":
        return "exFAT"
    if header[54:59] in (b"FAT12", b"FAT16") or header[82:87] == b"FAT32":
        return "FAT"
    if len(header) >= 1082 and header[1080:1082] == b"\x53\xef":
        return "ext2/3/4"
    return "unknown"


def _read_at(stream: BinaryIO, offset: int, length: int, image_size: int) -> bytes:
    if offset < 0 or offset >= image_size or length <= 0:
        return b""
    stream.seek(offset)
    return stream.read(min(length, image_size - offset))


def _partition_record(*, index: int, offset: int, length: int, filesystem: str,
                      scheme: str, type_code: str) -> PartitionInfo:
    return {
        "index": index,
        "offset_bytes": offset,
        "length_bytes": length,
        "filesystem": filesystem,
        "scheme": scheme,
        "type": type_code,
    }


def _gpt_partitions(stream: BinaryIO, image_size: int, peek: int) -> list[PartitionInfo]:
    """Read a bounded GPT entry array. Invalid/truncated structures yield no entries."""
    header = _read_at(stream, _SECTOR_SIZE, _SECTOR_SIZE, image_size)
    if len(header) < 92 or not header.startswith(_GPT_HEADER_SIGNATURE):
        return []
    entry_lba = int.from_bytes(header[72:80], "little")
    entry_count = min(int.from_bytes(header[80:84], "little"), 128)
    entry_size = int.from_bytes(header[84:88], "little")
    if entry_lba < 2 or not 128 <= entry_size <= 4096 or entry_count <= 0:
        return []
    table_offset = entry_lba * _SECTOR_SIZE
    table = _read_at(stream, table_offset, entry_count * entry_size, image_size)
    partitions: list[PartitionInfo] = []
    for index in range(entry_count):
        entry = table[index * entry_size:(index + 1) * entry_size]
        if len(entry) < 48:
            break
        type_guid = entry[:16]
        if type_guid == b"\x00" * 16:
            continue
        first_lba = int.from_bytes(entry[32:40], "little")
        last_lba = int.from_bytes(entry[40:48], "little")
        if first_lba <= 0 or last_lba < first_lba:
            continue
        offset = first_lba * _SECTOR_SIZE
        if offset >= image_size:
            continue
        length = min((last_lba - first_lba + 1) * _SECTOR_SIZE, image_size - offset)
        volume_header = _read_at(stream, offset, max(peek, 1082), image_size)
        partitions.append(_partition_record(
            index=index + 1,
            offset=offset,
            length=length,
            filesystem=_filesystem_from_header(volume_header),
            scheme="GPT",
            type_code=type_guid.hex(),
        ))
    return partitions


def _mbr_partitions(stream: BinaryIO, header: bytes, image_size: int,
                    peek: int) -> tuple[str | None, list[PartitionInfo], bool]:
    """Read primary MBR partitions, or GPT entries behind a protective MBR."""
    if len(header) < _SECTOR_SIZE or header[510:512] != b"\x55\xaa":
        return None, [], False
    entries: list[PartitionInfo] = []
    has_partition_entry = False
    has_extended = False
    has_protective_gpt = False
    for index in range(4):
        start = _MBR_PARTITION_TABLE_OFFSET + index * _MBR_PARTITION_ENTRY_SIZE
        entry = header[start:start + _MBR_PARTITION_ENTRY_SIZE]
        if len(entry) != _MBR_PARTITION_ENTRY_SIZE:
            continue
        partition_type = entry[4]
        first_lba = int.from_bytes(entry[8:12], "little")
        sectors = int.from_bytes(entry[12:16], "little")
        if partition_type == 0 or first_lba == 0 or sectors == 0:
            continue
        offset = first_lba * _SECTOR_SIZE
        if offset >= image_size:
            continue
        has_partition_entry = True
        if partition_type == 0xEE:
            has_protective_gpt = True
            continue
        if partition_type in _EXTENDED_MBR_TYPES:
            has_extended = True
            continue
        length = min(sectors * _SECTOR_SIZE, image_size - offset)
        volume_header = _read_at(stream, offset, max(peek, 1082), image_size)
        entries.append(_partition_record(
            index=index + 1,
            offset=offset,
            length=length,
            filesystem=_filesystem_from_header(volume_header),
            scheme="MBR",
            type_code=f"0x{partition_type:02x}",
        ))
    if has_protective_gpt:
        gpt_entries = _gpt_partitions(stream, image_size, peek)
        if gpt_entries:
            return "GPT", gpt_entries, has_extended
    return ("MBR" if has_partition_entry else None), entries, has_extended


def detect_evidence(path: str, *, peek: int = 4096) -> EvidenceInfo:
    """Classify an evidence image by its on-disk signatures (read-only).

    Returns container, filesystem, size and any notes. Filesystem detection works
    on a raw/dd image; inside an EWF/E01 container the bytes are compressed, so the
    filesystem is reported as resolved after opening rather than from the header."""
    info: EvidenceInfo = {
        "path": os.path.basename(path),
        "container": "unknown",
        "filesystem": "unknown",
        "size_bytes": None,
        "partition_scheme": None,
        "partitions": [],
        "notes": [],
    }
    if not path or not os.path.exists(path) or not os.path.isfile(path):
        info["notes"].append("evidence file not found")
        return info
    try:
        image_size = os.path.getsize(path)
        info["size_bytes"] = image_size
        with open(path, "rb") as f:
            hdr = f.read(max(peek, 4096))
            partition_scheme, partitions, has_extended = _mbr_partitions(
                f, hdr, image_size, peek)
    except Exception as e:
        info["notes"].append(f"read failed: {str(e)[:120]}")
        return info

    if hdr.startswith(_EWF1):
        info["container"] = "EWF/E01"
    elif hdr.startswith(_EWF2):
        info["container"] = "EWF2/Ex01"
    else:
        info["container"] = "raw/dd"

    if info["container"].startswith("EWF"):
        info["filesystem"] = "(inside EWF container — determined after opening)"
        return info

    # raw/dd: read filesystem signatures directly
    fs = _filesystem_from_header(hdr)
    info["partition_scheme"] = partition_scheme
    info["partitions"] = partitions
    if fs == "unknown":
        detected = [p["filesystem"] for p in partitions if p["filesystem"] != "unknown"]
        # Prefer NTFS when present so the scope fallback does not incorrectly suppress
        # registry analysis merely because the same image also has a FAT boot volume.
        fs = "NTFS" if "NTFS" in detected else (detected[0] if detected else "unknown")
    if has_extended:
        info["notes"].append(
            "MBR contains an extended partition; the full inventory is determined after opening")
    if fs == "unknown" and partition_scheme:
        info["notes"].append(
            f"{partition_scheme} partition table detected, but the filesystem is unknown")
    elif fs == "unknown" and hdr[510:512] == b"\x55\xaa":
        info["notes"].append("boot signature 0x55AA detected, but the filesystem is unknown")
    info["filesystem"] = fs
    return info


# Which tool categories are relevant for a given filesystem (palette narrowing hint).
_FS_RELEVANT = {
    "NTFS": ["filesystem", "Windows registry"],
    "FAT": ["filesystem"],
    "exFAT": ["filesystem"],
    "ext2/3/4": ["filesystem"],
}


def summarize(info: EvidenceInfo) -> str:
    """Return a concise English summary for the interactive terminal."""
    size = info.get("size_bytes")
    size_s = f"{size / (1024 * 1024):.0f} MB" if isinstance(size, int) else "unknown"
    filesystem = info.get("filesystem")
    filesystem_s = (
        "determined after opening"
        if isinstance(filesystem, str) and filesystem.startswith("(inside EWF container")
        else str(filesystem)
    )
    rel = _FS_RELEVANT.get(filesystem, [])
    rel_s = (" Relevant categories: " + ", ".join(rel) + ".") if rel else ""
    partitions = info.get("partitions") or []
    part_s = ""
    if partitions:
        labels = ", ".join(
            f"#{p.get('index')} {p.get('filesystem')}@{p.get('offset_bytes')}"
            for p in partitions)
        part_s = f" Partitions ({info.get('partition_scheme')}): {labels}."
    notes = (" Notes: " + "; ".join(info["notes"]) + ".") if info.get("notes") else ""
    return (
        f"Evidence source {info.get('path')}: container {info.get('container')}, "
        f"file system {filesystem_s}, size {size_s}."
        f"{rel_s}{part_s}{notes}"
    )
