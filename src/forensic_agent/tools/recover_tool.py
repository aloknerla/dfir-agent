"""Deleted-file recovery via TSK plus validated residual FAT directory records.

Walks the filesystem for directory entries whose NAME slot is unallocated (deleted)
— including, where the filesystem exposes them, TSK $OrphanFiles whose directory
entry is gone but whose metadata survives — and reports their names/metadata. With
`recover=<meta_addr>` it reads back a specific deleted file's content in memory
(icat) and returns a hash + preview, without writing to disk. Read-only on the image.

For a FAT volume whose allocation metadata was reset, a bounded fallback also
validates surviving LFN ordinal chains and short-name checksums in clusters the
current FAT marks unallocated. This complements dfVFS navigation without treating
the residual pattern as unique proof of one anti-forensic operation.
"""
from __future__ import annotations

import hashlib
import os
import re
import time
from collections import deque
from dataclasses import dataclass, replace
from typing import Any, BinaryIO

import pytsk3

from forensic_agent.core.tool_failure import tool_failure, tool_failure_result
from forensic_agent.core.toolio import shape

_PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")
_CHUNK = 1 << 20
_FAT_SCAN_CHUNK = 8 << 20
_MAX_FAT_RESIDUAL_SCAN_BYTES = 2 << 30
_MAX_FAT_TABLE_BYTES = 64 << 20
_MAX_LFN_SLOTS = 20
_MAX_RESIDUAL_FILE_BYTES = 256 << 20
_MAX_RESIDUAL_BATCH_BYTES = 512 << 20
_MAX_RESIDUAL_RECOVERY_IDS = 100


class _EwfImg(pytsk3.Img_Info):
    """pytsk3 image backed by a pyewf handle, so TSK can read E01 evidence."""

    def __init__(self, ewf_handle):
        self._h = ewf_handle
        super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self):
        self._h.close()

    def read(self, offset, size):
        self._h.seek(offset)
        return self._h.read(size)

    def get_size(self):
        return self._h.get_media_size()


def _open_fs(image_path: str, fs_offset: int = 0):
    """Open a pytsk3 FS_Info over a raw image or an E01 (via pyewf glue)."""
    ext = os.path.splitext(image_path)[1].lower()
    if ext in (".e01", ".ewf"):
        import pyewf
        h = pyewf.handle()
        h.open(pyewf.glob(image_path))
        img = _EwfImg(h)
    else:
        img = pytsk3.Img_Info(image_path)
    return pytsk3.FS_Info(img, offset=int(fs_offset or 0))


def _name_of(fs_file) -> str | None:
    try:
        n = fs_file.info.name.name
        return n.decode("utf-8", "replace") if isinstance(n, (bytes, bytearray)) else n
    except Exception:
        return None


def _is_deleted(fs_file) -> bool:
    try:
        return bool(int(fs_file.info.name.flags) & pytsk3.TSK_FS_NAME_FLAG_UNALLOC)
    except Exception:
        return False


def _is_dir(fs_file) -> bool:
    try:
        return fs_file.info.meta is not None and \
            fs_file.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR
    except Exception:
        return False


#: The traversal bound that stopped a deleted-entry walk short of the subtree.
_STOPPED_BY_DIRECTORY_BOUND = "max_dirs"
_STOPPED_BY_ENTRY_BOUND = "max_entries"

#: Failed directory opens described individually in the result. The count is
#: always exact; only the per-directory classifications are sampled, so a volume
#: failing wholesale cannot bury the rest of the envelope under its own failures.
_MAX_RECORDED_UNREADABLE_DIRECTORIES = 20


@dataclass(frozen=True, slots=True)
class _TraversalCoverage:
    """What the deleted-entry walk examined, and every way it fell short.

    The walk can fall short in two unrelated ways, and each keeps its own field.
    A bound ends it with directories still queued, which a caller answers by
    raising that bound. A directory it reached can also refuse to open, which no
    bound governs and no retry of the same call repairs; those entries were never
    examined, so the listing cannot say they hold nothing. Reported as one flag
    the two would be indistinguishable, and only one of them is actionable.
    """

    directories_visited: int
    directories_read: int
    max_dirs: int
    max_entries: int
    stopped_by: str | None
    unreadable_directory_count: int
    unreadable_directories: tuple[dict[str, Any], ...]

    @property
    def complete(self) -> bool:
        return self.stopped_by is None and self.unreadable_directory_count == 0

    def statement(self) -> dict[str, Any]:
        return {
            "order": "breadth_first_in_filesystem_directory_order",
            "directories_visited": self.directories_visited,
            "directories_read": self.directories_read,
            "directories_unreadable": self.unreadable_directory_count,
            "unreadable_directories": list(self.unreadable_directories),
            "max_dirs": self.max_dirs,
            "max_entries": self.max_entries,
            "stopped_by": self.stopped_by,
            "complete": self.complete,
        }

    def incomplete_reasons(self) -> list[str]:
        reasons: list[str] = []
        if self.stopped_by == _STOPPED_BY_DIRECTORY_BOUND:
            reasons.append(
                f"deleted-entry traversal stopped at its max_dirs bound after reaching "
                f"{self.directories_visited} of the subtree's directories; directories it "
                f"never opened may hold further deleted entries. Raise max_dirs (currently "
                f"{self.max_dirs}) or scope path to a subtree to enumerate the rest"
            )
        elif self.stopped_by == _STOPPED_BY_ENTRY_BOUND:
            reasons.append(
                f"deleted-entry traversal stopped at its max_entries bound of "
                f"{self.max_entries} rows after reaching {self.directories_visited} "
                f"directories; entries beyond it were never examined. Raise max_entries "
                f"or scope path to a subtree to enumerate the rest"
            )
        if self.unreadable_directory_count:
            kinds = ", ".join(
                sorted({str(record.get("kind")) for record in self.unreadable_directories})
            )
            reasons.append(
                f"{self.unreadable_directory_count} of the {self.directories_visited} "
                f"directories the traversal reached could not be opened ({kinds}); nothing "
                f"in them was examined, so this listing does not establish that they hold "
                f"no deleted entries. This is a read failure rather than a bound, and "
                f"raising max_dirs does not recover it"
            )
        return reasons


@dataclass(frozen=True, slots=True)
class _OrphanListingCoverage:
    """What TSK's $OrphanFiles pseudo-directory contributed, or why it did not."""

    present: bool
    entries_added: int
    entry_cap_reached: bool
    failure: dict[str, Any] | None

    @property
    def complete(self) -> bool:
        return self.failure is None

    def statement(self) -> dict[str, Any]:
        return {
            "present": self.present,
            "entries_added": self.entries_added,
            "read_failure": self.failure,
            "complete": self.complete,
        }

    def reason(self) -> str | None:
        if self.failure is None:
            return None
        return (
            f"TSK's $OrphanFiles listing could not be read ({self.failure['kind']}), so "
            "entries whose directory slot is gone but whose metadata survives were never "
            "examined; their absence from these rows is not evidence that there are none"
        )


def _collect_deleted(
    fs: Any,
    start: str,
    recursive: bool,
    max_entries: int,
    max_dirs: int,
) -> tuple[list[dict[str, Any]], _TraversalCoverage]:
    """Breadth-first walk for deleted directory entries under two stated bounds.

    Directories are opened in the order the filesystem reports them; no name is
    preferred and none is deferred. Under `max_dirs`/`max_entries` a preference
    would decide which deletions the result can contain rather than the order it
    presents them in — the rows are name-sorted before they are returned — so an
    ordering rule here would be this project's judgement about where evidence
    lives, silently deciding the answer. The returned coverage names the bound
    that ended the walk and every directory that would not open, so a caller can
    tell a short enumeration from a whole one, and a failed read from a bound.
    """

    rows: list[dict[str, Any]] = []
    pending: deque[str] = deque([start or "/"])
    seen: set[str] = set()
    visited = 0
    unreadable_count = 0
    unreadable: list[dict[str, Any]] = []
    stopped_by: str | None = None
    while pending:
        if visited >= max_dirs:
            stopped_by = _STOPPED_BY_DIRECTORY_BOUND
            break
        if len(rows) >= max_entries:
            stopped_by = _STOPPED_BY_ENTRY_BOUND
            break
        directory_path = pending.popleft()
        if directory_path in seen:
            continue
        seen.add(directory_path)
        visited += 1
        try:
            directory = fs.open_dir(path=directory_path)
        except Exception as error:
            unreadable_count += 1
            if len(unreadable) < _MAX_RECORDED_UNREADABLE_DIRECTORIES:
                unreadable.append(
                    tool_failure(error, subject=directory_path, backend="sleuthkit")
                )
            continue
        for fs_file in directory:
            name = _name_of(fs_file)
            if not name or name in (".", ".."):
                continue
            meta = fs_file.info.meta
            if _is_deleted(fs_file):
                if len(rows) >= max_entries:
                    stopped_by = _STOPPED_BY_ENTRY_BOUND
                    break
                rows.append({
                    "name": name,
                    "meta_addr": getattr(fs_file.info.name, "meta_addr", None),
                    "size": (meta.size if meta else None),
                    "type": ("dir" if _is_dir(fs_file) else "file"),
                    "deleted": True,
                    "recoverable": bool(meta and getattr(meta, "size", 0)),
                    "mtime": (getattr(meta, "mtime", None) if meta else None),
                })
            elif recursive and _is_dir(fs_file) and not name.startswith("$"):
                child = (
                    directory_path.rstrip("/") + "/" + name
                    if directory_path != "/"
                    else "/" + name
                )
                if child not in seen:
                    pending.append(child)
        if stopped_by is not None:
            break
    return rows, _TraversalCoverage(
        directories_visited=visited,
        directories_read=visited - unreadable_count,
        max_dirs=max_dirs,
        max_entries=max_entries,
        stopped_by=stopped_by,
        unreadable_directory_count=unreadable_count,
        unreadable_directories=tuple(unreadable),
    )


def _append_orphan_entries(
    rows: list[dict[str, Any]],
    fs: Any,
    *,
    max_entries: int,
) -> _OrphanListingCoverage:
    """Append TSK's $OrphanFiles listing and state what became of it."""

    try:
        orphan_dir = fs.open_dir(path="/$OrphanFiles")
    except Exception as error:
        failure = tool_failure(error, subject="/$OrphanFiles", backend="sleuthkit")
        # TSK materialises this pseudo-directory only where it recovered orphaned
        # metadata, so a plain absence is that answer and not a gap in coverage.
        # Any other failure is a read that did not happen and must say so.
        absent = failure["establishes_absence"] is True
        return _OrphanListingCoverage(
            present=False,
            entries_added=0,
            entry_cap_reached=False,
            failure=None if absent else failure,
        )
    added = 0
    for fs_file in orphan_dir:
        name = _name_of(fs_file)
        if not name or name in (".", ".."):
            continue
        if len(rows) >= max_entries:
            return _OrphanListingCoverage(
                present=True,
                entries_added=added,
                entry_cap_reached=True,
                failure=None,
            )
        meta = fs_file.info.meta
        rows.append({
            "name": name,
            "meta_addr": getattr(fs_file.info.name, "meta_addr", None),
            "size": (meta.size if meta else None),
            "type": "file",
            "deleted": True,
            "recoverable": bool(meta and getattr(meta, "size", 0)),
            "mtime": (getattr(meta, "mtime", None) if meta else None),
        })
        added += 1
    return _OrphanListingCoverage(
        present=True,
        entries_added=added,
        entry_cap_reached=False,
        failure=None,
    )


def _icat_summary(fs, meta_addr: int) -> dict[str, object]:
    """Stream one metadata entry without retaining the recovered file in RAM."""

    fs_file = fs.open_meta(inode=int(meta_addr))
    size = fs_file.info.meta.size or 0
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    preview_data = bytearray()
    off = 0
    while off < size:
        chunk = fs_file.read_random(off, min(_CHUNK, size - off))
        if not chunk:
            break
        md5.update(chunk)
        sha256.update(chunk)
        if len(preview_data) < 65536:
            preview_data.extend(chunk[: 65536 - len(preview_data)])
        off += len(chunk)
    preview_parts = _PRINTABLE.findall(bytes(preview_data))
    preview = " ".join(part.decode("ascii", "replace") for part in preview_parts)[:1200]
    return {
        "size": off,
        "md5": md5.hexdigest(),
        "sha256": sha256.hexdigest(),
        "content_preview": preview,
    }


@dataclass(frozen=True, slots=True)
class _FatLayout:
    fat_type: int
    bytes_per_sector: int
    sectors_per_cluster: int
    total_sectors: int
    fat_offset: int
    fat_size_bytes: int
    data_offset: int
    data_size_bytes: int
    cluster_count: int


class _RawReader:
    def __init__(self, path: str) -> None:
        self._stream: BinaryIO = open(path, "rb")
        self.size = os.path.getsize(path)

    def read_at(self, offset: int, size: int) -> bytes:
        self._stream.seek(offset)
        return self._stream.read(size)

    def close(self) -> None:
        self._stream.close()


class _EwfReader:
    def __init__(self, path: str) -> None:
        import pyewf

        self._handle = pyewf.handle()
        self._handle.open(pyewf.glob(path))
        self.size = int(self._handle.get_media_size())

    def read_at(self, offset: int, size: int) -> bytes:
        self._handle.seek(offset)
        return self._handle.read(size)

    def close(self) -> None:
        self._handle.close()


def _open_random_reader(image_path: str):
    extension = os.path.splitext(image_path)[1].lower()
    return _EwfReader(image_path) if extension in {".e01", ".ewf"} else _RawReader(image_path)


def _fat_layout(reader, fs_offset: int) -> _FatLayout | None:
    boot = reader.read_at(fs_offset, 512)
    if len(boot) < 90 or boot[510:512] != b"\x55\xaa":
        return None
    bytes_per_sector = int.from_bytes(boot[11:13], "little")
    sectors_per_cluster = boot[13]
    reserved = int.from_bytes(boot[14:16], "little")
    fat_count = boot[16]
    root_entries = int.from_bytes(boot[17:19], "little")
    total_sectors = int.from_bytes(boot[19:21], "little") or int.from_bytes(
        boot[32:36], "little"
    )
    fat_sectors = int.from_bytes(boot[22:24], "little") or int.from_bytes(
        boot[36:40], "little"
    )
    if (
        bytes_per_sector not in {512, 1024, 2048, 4096}
        or sectors_per_cluster < 1
        or sectors_per_cluster & (sectors_per_cluster - 1)
        or reserved < 1
        or fat_count not in {1, 2, 3, 4}
        or total_sectors < 1
        or fat_sectors < 1
    ):
        return None
    root_dir_sectors = (
        root_entries * 32 + (bytes_per_sector - 1)
    ) // bytes_per_sector
    first_data_sector = reserved + fat_count * fat_sectors + root_dir_sectors
    if first_data_sector >= total_sectors:
        return None
    cluster_count = (total_sectors - first_data_sector) // sectors_per_cluster
    fat_type = 12 if cluster_count < 4085 else 16 if cluster_count < 65525 else 32
    fat_size_bytes = fat_sectors * bytes_per_sector
    data_offset = fs_offset + first_data_sector * bytes_per_sector
    data_size_bytes = min(
        (total_sectors - first_data_sector) * bytes_per_sector,
        max(0, reader.size - data_offset),
    )
    return _FatLayout(
        fat_type=fat_type,
        bytes_per_sector=bytes_per_sector,
        sectors_per_cluster=sectors_per_cluster,
        total_sectors=total_sectors,
        fat_offset=fs_offset + reserved * bytes_per_sector,
        fat_size_bytes=fat_size_bytes,
        data_offset=data_offset,
        data_size_bytes=data_size_bytes,
        cluster_count=cluster_count,
    )


def _fat_entry(table: bytes, fat_type: int, cluster: int) -> int | None:
    if fat_type == 12:
        offset = cluster + cluster // 2
        if offset + 2 > len(table):
            return None
        value = int.from_bytes(table[offset : offset + 2], "little")
        return (value >> 4) & 0xFFF if cluster & 1 else value & 0xFFF
    width = 2 if fat_type == 16 else 4
    offset = cluster * width
    if offset + width > len(table):
        return None
    value = int.from_bytes(table[offset : offset + width], "little")
    return value & (0xFFFF if fat_type == 16 else 0x0FFFFFFF)


def _lfn_checksum(short_name: bytes) -> int:
    checksum = 0
    for value in short_name:
        checksum = (((checksum & 1) << 7) + (checksum >> 1) + value) & 0xFF
    return checksum


def _lfn_fragment(entry: bytes) -> str | None:
    payload = entry[1:11] + entry[14:26] + entry[28:32]
    units = [int.from_bytes(payload[index : index + 2], "little") for index in range(0, 26, 2)]
    output: list[int] = []
    for unit in units:
        if unit == 0:
            break
        if unit == 0xFFFF:
            continue
        if unit < 0x20 or 0xD800 <= unit <= 0xDFFF:
            return None
        output.append(unit)
    try:
        return b"".join(unit.to_bytes(2, "little") for unit in output).decode("utf-16le")
    except UnicodeDecodeError:
        return None


def _short_name(entry: bytes) -> str:
    raw = bytearray(entry[:11])
    if raw and raw[0] == 0x05:
        raw[0] = 0xE5
    base = bytes(raw[:8]).decode("cp437", "replace").rstrip()
    extension = bytes(raw[8:11]).decode("cp437", "replace").rstrip()
    return f"{base}.{extension}" if extension else base


def _residual_recovery_id(
    *,
    fs_offset: int,
    filesystem_byte_offset: int,
    start_cluster: int,
    size: int,
    name: str,
) -> str:
    """Bind recovery selection to one validated residual directory record."""

    identity = "\x00".join(
        (
            str(fs_offset),
            str(filesystem_byte_offset),
            str(start_cluster),
            str(size),
            name,
        )
    ).encode("utf-8")
    return f"fat-residual-sha256:{hashlib.sha256(identity).hexdigest()}"


def _residual_range_support(
    layout: _FatLayout,
    table: bytes,
    *,
    start_cluster: int,
    size: int,
) -> tuple[bool, str | None, int]:
    """Validate that a contiguous candidate range is bounded and unallocated."""

    cluster_size = layout.bytes_per_sector * layout.sectors_per_cluster
    if start_cluster < 2 or size < 1:
        return False, "residual record has no positive file extent", 0
    cluster_count = (size + cluster_size - 1) // cluster_size
    last_cluster = start_cluster + cluster_count - 1
    if last_cluster > layout.cluster_count + 1:
        return False, "residual extent exceeds the FAT data region", cluster_count
    for cluster in range(start_cluster, last_cluster + 1):
        if _fat_entry(table, layout.fat_type, cluster) != 0:
            return (
                False,
                "one or more candidate clusters are currently allocated",
                cluster_count,
            )
    return True, None, cluster_count


def _fat_residual_entries(
    image_path: str,
    fs_offset: int,
    *,
    max_entries: int,
) -> tuple[list[dict], dict]:
    """Find strict FAT LFN chains left in currently unallocated clusters.

    A quick format can reset the FAT/root metadata while leaving old directory
    clusters intact. TSK correctly omits those now-unreachable records, so this
    bounded fallback validates the LFN ordinal chain and checksum directly. The
    pattern is consistent with metadata reset/reformatting, but is not unique
    proof of how the cluster became unallocated.
    """

    reader = _open_random_reader(image_path)
    try:
        layout = _fat_layout(reader, fs_offset)
        if layout is None:
            return [], {"supported": False, "reason": "filesystem is not a supported FAT volume"}
        if layout.fat_size_bytes > _MAX_FAT_TABLE_BYTES:
            return [], {
                "supported": True,
                "coverage_complete": False,
                "reason": "FAT table exceeds the bounded parser cap",
                "fat_type": f"FAT{layout.fat_type}",
            }
        table = reader.read_at(layout.fat_offset, layout.fat_size_bytes)
        if len(table) != layout.fat_size_bytes:
            return [], {
                "supported": True,
                "coverage_complete": False,
                "reason": "FAT table could not be read completely",
                "fat_type": f"FAT{layout.fat_type}",
            }

        scan_bytes = min(layout.data_size_bytes, _MAX_FAT_RESIDUAL_SCAN_BYTES)
        cluster_size = layout.bytes_per_sector * layout.sectors_per_cluster
        rows: list[dict] = []
        seen_offsets: set[int] = set()
        carry = b""
        cursor = 0
        entry_cap_reached = False
        while cursor < scan_bytes and not entry_cap_reached:
            chunk = reader.read_at(
                layout.data_offset + cursor,
                min(_FAT_SCAN_CHUNK, scan_bytes - cursor),
            )
            if not chunk:
                break
            combined = carry + chunk
            combined_base = cursor - len(carry)
            pending: list[tuple[int, int, str, int]] = []
            for relative in range(0, len(combined) - 31, 32):
                entry = combined[relative : relative + 32]
                absolute_data_offset = combined_base + relative
                if entry[11] == 0x0F:
                    ordinal = entry[0]
                    sequence = ordinal & 0x1F
                    fragment = _lfn_fragment(entry)
                    if (
                        fragment is None
                        or sequence < 1
                        or sequence > _MAX_LFN_SLOTS
                        or entry[12] != 0
                        or entry[26:28] != b"\x00\x00"
                    ):
                        pending = []
                        continue
                    if ordinal & 0x40:
                        pending = [(sequence, entry[13], fragment, absolute_data_offset)]
                    elif pending and sequence == pending[-1][0] - 1 and entry[13] == pending[0][1]:
                        pending.append((sequence, entry[13], fragment, absolute_data_offset))
                    else:
                        pending = []
                    continue

                if not pending:
                    continue
                first_byte = entry[0]
                attributes = entry[11]
                sequence_ok = pending[-1][0] == 1 and len(pending) == pending[0][0]
                checksum_ok = first_byte not in {0x00, 0xE5} and (
                    _lfn_checksum(entry[:11]) == pending[0][1]
                )
                name = "".join(item[2] for item in reversed(pending))
                chain_offset = pending[0][3]
                pending = []
                if (
                    not sequence_ok
                    or not checksum_ok
                    or attributes & 0x08
                    or not name
                    or name in {".", ".."}
                    or any(character in name for character in "/\\\x00")
                    or absolute_data_offset in seen_offsets
                ):
                    continue
                containing_cluster = 2 + absolute_data_offset // cluster_size
                allocation = _fat_entry(table, layout.fat_type, containing_cluster)
                if allocation != 0:
                    continue
                high_cluster = int.from_bytes(entry[20:22], "little") if layout.fat_type == 32 else 0
                start_cluster = (high_cluster << 16) | int.from_bytes(entry[26:28], "little")
                size = int.from_bytes(entry[28:32], "little")
                recovery_supported, recovery_reason, recovery_clusters = (
                    _residual_range_support(
                        layout,
                        table,
                        start_cluster=start_cluster,
                        size=size,
                    )
                )
                recovery_id = _residual_recovery_id(
                    fs_offset=fs_offset,
                    filesystem_byte_offset=absolute_data_offset,
                    start_cluster=start_cluster,
                    size=size,
                    name=name,
                )
                seen_offsets.add(absolute_data_offset)
                rows.append(
                    {
                        "name": name,
                        "short_name": _short_name(entry),
                        "meta_addr": None,
                        "size": size,
                        "type": "dir" if attributes & 0x10 else "file",
                        "deleted": True,
                        "recoverable": recovery_supported and not bool(attributes & 0x10),
                        "mtime": None,
                        "recovery_method": "fat_residual_directory_entry",
                        "recovery_id": recovery_id,
                        "recovery_clusters": recovery_clusters,
                        "recovery_assumption": (
                            "contiguous original cluster extent because the previous FAT chain is absent"
                        ),
                        "recovery_unavailable_reason": (
                            "residual record describes a directory"
                            if attributes & 0x10
                            else recovery_reason
                        ),
                        "filesystem_byte_offset": absolute_data_offset,
                        "lfn_chain_byte_offset": chain_offset,
                        "containing_cluster": containing_cluster,
                        "start_cluster": start_cluster,
                        "cluster_allocation_state": "unallocated",
                    }
                )
                if len(rows) >= max_entries:
                    entry_cap_reached = True
                    break
            carry = combined[-((_MAX_LFN_SLOTS + 1) * 32) :]
            cursor += len(chunk)

        bytes_scanned = min(cursor, scan_bytes)
        coverage_complete = (
            bytes_scanned >= layout.data_size_bytes and not entry_cap_reached
        )
        return rows, {
            "supported": True,
            "fat_type": f"FAT{layout.fat_type}",
            "bytes_scanned": bytes_scanned,
            "data_region_bytes": layout.data_size_bytes,
            "coverage_complete": coverage_complete,
            "entry_cap_reached": entry_cap_reached,
            "records_found": len(rows),
            "method": "strict_lfn_chain_checksum_in_unallocated_cluster",
        }
    finally:
        reader.close()


def _recover_residual_content(
    reader: Any,
    layout: _FatLayout,
    table: bytes,
    row: dict[str, Any],
) -> dict[str, Any]:
    """Hash and preview one validated contiguous residual FAT byte range."""

    recovery_id = str(row["recovery_id"])
    name = str(row.get("name") or "")
    start_cluster = int(row.get("start_cluster") or 0)
    expected_size = int(row.get("size") or 0)
    supported, reason, cluster_count = _residual_range_support(
        layout,
        table,
        start_cluster=start_cluster,
        size=expected_size,
    )
    base = {
        "recovery_id": recovery_id,
        "name": name,
        "expected_size": expected_size,
        "start_cluster": start_cluster,
        "cluster_count": cluster_count,
        "recovery_method": "fat_residual_contiguous_unallocated_extent",
        "source_record_method": "strict_lfn_chain_checksum_in_unallocated_cluster",
        "original_cluster_chain_available": False,
        "reconstruction_assumption": (
            "the original file occupied a contiguous extent; the prior FAT chain is absent"
        ),
    }
    if not supported:
        return {
            **base,
            "recovered": False,
            "coverage_complete": False,
            "error": reason or "residual extent is not recoverable",
        }
    if expected_size > _MAX_RESIDUAL_FILE_BYTES:
        return {
            **base,
            "recovered": False,
            "coverage_complete": False,
            "error": "residual file exceeds the per-file recovery byte cap",
        }

    cluster_size = layout.bytes_per_sector * layout.sectors_per_cluster
    absolute_offset = layout.data_offset + (start_cluster - 2) * cluster_size
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    preview_data = bytearray()
    recovered_size = 0
    while recovered_size < expected_size:
        chunk = reader.read_at(
            absolute_offset + recovered_size,
            min(_CHUNK, expected_size - recovered_size),
        )
        if not chunk:
            break
        md5.update(chunk)
        sha256.update(chunk)
        if len(preview_data) < 16_384:
            preview_data.extend(chunk[: 16_384 - len(preview_data)])
        recovered_size += len(chunk)
    preview_parts = _PRINTABLE.findall(bytes(preview_data))
    preview = " ".join(
        part.decode("ascii", "replace") for part in preview_parts
    )[:256]
    complete = recovered_size == expected_size
    result = {
        **base,
        "recovered": complete,
        "coverage_complete": complete,
        "recovered_size": recovered_size,
        "filesystem_byte_offset": absolute_offset - layout.data_offset,
        "md5": md5.hexdigest(),
        "sha256": sha256.hexdigest(),
        "content_preview": preview,
        "current_cluster_allocation": "all candidate clusters unallocated",
    }
    if not complete:
        result["error"] = "candidate byte range ended before the recorded file size"
    return result


def _recover_residual_ids(
    image_path: str,
    fs_offset: int,
    recovery_ids: list[str],
    *,
    max_scan_entries: int,
) -> dict[str, Any]:
    """Resolve stable IDs by rescanning validated records, then read only those extents."""

    requested = list(dict.fromkeys(recovery_ids))
    if not requested:
        return {"error": "recover_ids must contain at least one recovery ID"}
    if len(requested) > _MAX_RESIDUAL_RECOVERY_IDS:
        return {
            "error": (
                f"recover_ids exceeds the {_MAX_RESIDUAL_RECOVERY_IDS}-record batch cap"
            )
        }
    if any(
        not isinstance(value, str)
        or re.fullmatch(r"fat-residual-sha256:[0-9a-f]{64}", value) is None
        for value in requested
    ):
        return {"error": "recover_ids contains an invalid residual recovery ID"}

    residual_rows, scan = _fat_residual_entries(
        image_path,
        fs_offset,
        max_entries=max_scan_entries,
    )
    indexed = {
        str(row.get("recovery_id")): row
        for row in residual_rows
        if isinstance(row.get("recovery_id"), str)
    }
    reader = _open_random_reader(image_path)
    try:
        layout = _fat_layout(reader, fs_offset)
        if layout is None:
            return {"error": "filesystem is not a supported FAT volume"}
        if layout.fat_size_bytes > _MAX_FAT_TABLE_BYTES:
            return {"error": "FAT table exceeds the bounded recovery cap"}
        table = reader.read_at(layout.fat_offset, layout.fat_size_bytes)
        if len(table) != layout.fat_size_bytes:
            return {"error": "FAT table could not be read completely"}

        rows: list[dict[str, Any]] = []
        batch_bytes = 0
        for recovery_id in requested:
            source = indexed.get(recovery_id)
            if source is None:
                rows.append(
                    {
                        "recovery_id": recovery_id,
                        "recovered": False,
                        "coverage_complete": False,
                        "error": "recovery ID was not found among validated residual records",
                    }
                )
                continue
            expected_size = int(source.get("size") or 0)
            if batch_bytes + expected_size > _MAX_RESIDUAL_BATCH_BYTES:
                rows.append(
                    {
                        "recovery_id": recovery_id,
                        "name": source.get("name"),
                        "expected_size": expected_size,
                        "recovered": False,
                        "coverage_complete": False,
                        "error": "residual recovery batch reached its byte cap",
                    }
                )
                continue
            recovered = _recover_residual_content(reader, layout, table, source)
            rows.append(recovered)
            if recovered.get("recovered") is True:
                batch_bytes += expected_size
    finally:
        reader.close()

    complete = len(rows) == len(requested) and all(
        row.get("recovered") is True and row.get("coverage_complete") is True
        for row in rows
    )
    reason = None if complete else "one or more requested residual records were not recovered"
    return shape(
        rows,
        offset=0,
        limit=len(rows) or 1,
        _prefix={
            "recovery_mode": "stable_residual_ids",
            "requested": len(requested),
            "coverage_complete": complete,
            "coverage": {
                "complete": complete,
                "scope": "requested residual recovery IDs",
                "reason": reason,
            },
            "fat_residual_scan": scan,
            "batch_recovered_bytes": batch_bytes,
            "batch_byte_cap": _MAX_RESIDUAL_BATCH_BYTES,
        },
    )


def recover_deleted_files(
    disk,
    path: str = "/",
    recursive: bool = True,
    recover: int | None = None,
    recover_ids: list[str] | None = None,
    offset: int = 0,
    limit: int = 100,
    filter: str | None = None,
    max_entries: int = 500,
    max_dirs: int = 800,
    *,
    include_fat_residual: bool = True,
) -> dict:
    """Recover deleted files via TSK metadata (read-only).

    Listing mode returns a paged envelope of deleted directory entries
    {path,fs_offset,traversal_capped,deleted_entry_traversal,orphan_listing,
    total_matching,returned,offset,truncated,note,
    rows:[{name,meta_addr,size,type,deleted,recoverable,mtime}]}.
    The walk is breadth-first in the filesystem's own directory order and bounded by
    `max_dirs`/`max_entries`; `deleted_entry_traversal` reports how many directories it
    reached, how many it could not open, and which bound, if either, ended it, while
    `traversal_capped` keeps its old meaning of a bound alone. A directory that would
    not open is classified rather than skipped, so an enumeration that read nothing can
    never report itself complete. On FAT, the result can also include checksum-validated
    residual LFN records from unallocated clusters.
    Those records receive stable recovery IDs rather than exposing arbitrary offsets.
    With `recover=<meta_addr>` it streams that deleted file and returns
    {meta_addr,size,md5,sha256,content_preview}.
    With `recover_ids=[...]` it rescans and validates the named residual records,
    then hashes bounded, read-only candidate byte extents. Because a reset FAT no
    longer contains the original chain, each result explicitly records the
    contiguous-extent assumption.

    `include_fat_residual=False` confines the call to what The Sleuth Kit itself
    reports (the deleted-name walk plus $OrphanFiles), and refuses `recover_ids`
    for the same reason, since the read-back runs the same residual parser. The
    consolidated surface asks for exactly that, because its listing must never
    mix this project's own FAT parsing into TSK's result set; the default keeps
    the historical surface byte-identical.
    """
    t0 = time.time()
    image_path = getattr(disk, "image_path", None)
    if not image_path or not os.path.exists(image_path):
        return {"error": f"image not available: {image_path}"}
    fs_offset = int(getattr(disk, "fs_offset", 0) or 0)
    audit = getattr(disk, "audit", None)
    image_sha = getattr(disk, "image_sha", None)
    if recover is not None and recover_ids:
        return {"error": "recover and recover_ids are mutually exclusive"}
    # The switch has to cover both entry points or it does not mean what it says:
    # a read-back by recovery ID runs the same residual parser the listing does,
    # so a caller that asked for The Sleuth Kit's view alone must not reach it.
    if recover_ids is not None and not include_fat_residual:
        return {
            "error": (
                "recover_ids reads residual FAT directory records with this project's "
                "own parser, and this call asked for The Sleuth Kit's view only"
            )
        }
    if recover_ids is not None:
        result = _recover_residual_ids(
            image_path,
            fs_offset,
            recover_ids,
            max_scan_entries=max(1, int(max_entries)),
        )
        if audit is not None:
            try:
                audit.record(
                    tool="recover.fat_residual",
                    args={"recovery_ids_sha256": hashlib.sha256(
                        "\n".join(recover_ids).encode("utf-8")
                    ).hexdigest(), "count": len(recover_ids)},
                    output=result,
                    input_sha=image_sha,
                    duration_s=time.time() - t0,
                )
            except Exception:
                pass
        return result

    try:
        fs = _open_fs(image_path, fs_offset)
    except Exception as e:
        return tool_failure_result(e, subject=str(getattr(disk, "image_path", "image")), backend="sleuthkit")

    if recover is not None:
        try:
            summary = _icat_summary(fs, recover)
        except Exception as e:
            return {"error": f"recover failed for meta_addr {recover}: {str(e)[:120]}"}
        out = {"meta_addr": recover, **summary}
        if audit is not None:
            try:
                audit.record(tool="recover.icat", args={"meta_addr": recover},
                             output={k: out[k] for k in ("meta_addr", "size", "md5", "sha256")},
                             input_sha=image_sha, duration_s=time.time() - t0)
            except Exception:
                pass
        return out

    rows, traversal = _collect_deleted(
        fs,
        path or "/",
        bool(recursive),
        int(max_entries),
        int(max_dirs),
    )
    # TSK $OrphanFiles: entries whose directory slot is gone but metadata survives
    orphans = _append_orphan_entries(rows, fs, max_entries=int(max_entries))
    if orphans.entry_cap_reached and traversal.stopped_by is None:
        traversal = replace(traversal, stopped_by=_STOPPED_BY_ENTRY_BOUND)
    # Kept meaning exactly what earlier callers read it as — a BOUND stopped the
    # walk — so a directory that would not open cannot arrive disguised as one.
    capped = traversal.stopped_by is not None

    fat_scan: dict = {"supported": False, "reason": "scan not requested for a scoped path"}
    if not include_fat_residual:
        # The caller asked for TSK's view alone, so the residual scan is not an
        # incomplete-coverage condition: it is out of scope, and saying so keeps
        # the absence of residual rows from reading as an exhausted search.
        fat_scan = {
            "supported": False,
            "reason": "residual FAT scanning is not part of this operation",
        }
    elif (path or "/") == "/" and len(rows) < int(max_entries):
        try:
            residual_rows, fat_scan = _fat_residual_entries(
                image_path,
                fs_offset,
                max_entries=max(1, int(max_entries) - len(rows)),
            )
        except Exception as exc:
            residual_rows = []
            fat_scan = {
                "supported": True,
                "coverage_complete": False,
                "reason": f"bounded FAT residual scan failed: {str(exc)[:160]}",
            }
        existing = {
            (str(row.get("name") or "").casefold(), row.get("filesystem_byte_offset"))
            for row in rows
        }
        for row in residual_rows:
            identity = (
                str(row.get("name") or "").casefold(),
                row.get("filesystem_byte_offset"),
            )
            if identity not in existing:
                rows.append(row)
                existing.add(identity)

    rows.sort(
        key=lambda row: (
            str(row.get("name") or "").casefold(),
            str(row.get("name") or ""),
            str(row.get("recovery_id") or ""),
            int(row.get("meta_addr") or -1),
        )
    )
    fat_incomplete = bool(
        fat_scan.get("supported") is True
        and fat_scan.get("coverage_complete") is not True
    )
    source_complete = traversal.complete and orphans.complete and not fat_incomplete
    incomplete_reasons: list[str] = traversal.incomplete_reasons()
    orphan_reason = orphans.reason()
    if orphan_reason is not None:
        incomplete_reasons.append(orphan_reason)
    if fat_incomplete:
        incomplete_reasons.append(
            str(fat_scan.get("reason") or "residual FAT scan was incomplete")
        )
    coverage: dict[str, Any] = {
        "complete": source_complete,
        "scope": path,
        "reason": "; ".join(incomplete_reasons) if incomplete_reasons else None,
        # Directories, because a directory is the unit this walk covers its scope
        # in. The count is what separates a listing that examined part of the
        # deleted-entry region from one that examined none of it, and downstream
        # a region credited to a read that never happened would licence exactly
        # the absence claim this listing cannot support.
        "examined": traversal.directories_read,
    }
    if traversal.stopped_by is None:
        # Only a walk no bound stopped knows how many directories its scope holds;
        # under a bound the total is precisely what went unmeasured.
        coverage["expected"] = traversal.directories_visited
    prefix: dict[str, Any] = {
        "path": path,
        "fs_offset": fs_offset,
        "traversal_capped": capped,
        "deleted_entry_traversal": traversal.statement(),
        "orphan_listing": orphans.statement(),
        "fat_residual_scan": fat_scan,
        "coverage_complete": source_complete,
        "coverage": coverage,
        "source_records_examined": len(rows),
    }
    # The residual FAT scan is reported as an upstream-attributable fact
    # (``fat_residual_scan``) only. Interpreting what a residual scan means is the
    # agent's work, not this tool's, so no first-party assessment rides on it.
    result = shape(
        rows,
        offset=max(0, int(offset or 0)),
        limit=max(1, min(int(limit or 100), 500)),
        filter=filter,
        _prefix=prefix,
    )
    if audit is not None:
        try:
            audit.record(
                tool="recover.list_deleted",
                args={
                    "path": path,
                    "recursive": recursive,
                    "offset": offset,
                    "limit": limit,
                    "filter": filter,
                    "max_dirs": int(max_dirs),
                    "max_entries": int(max_entries),
                },
                output=result,
                input_sha=image_sha,
                duration_s=time.time() - t0,
            )
        except Exception:
            pass
    return result
