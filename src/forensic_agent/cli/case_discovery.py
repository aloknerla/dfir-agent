"""Conservative discovery of forensic sources stored in one case directory."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

# Suffixes that name a disk image the analysis backend can open. dfVFS is that
# backend (the disk tools run on it), and its analyzer classifies a storage
# media image by the file's own content signature, not by its extension, so
# this table is only a fast pre-filter for discovery, not the authority. It is
# widened here to the formats dfVFS's storage-media-image analyzer helpers
# support — EWF, QCOW, VHDI, VMDK, MODI and PHDI (category
# FORMAT_CATEGORY_STORAGE_MEDIA_IMAGE) plus split RAW — rather than the narrower
# hand list it used to carry, which refused images the backend can read.
# .raw and .bin are deliberately absent: they stay in _AMBIGUOUS_SUFFIXES
# because a raw dump can be either a disk or a memory image, and discovery
# resolves that with the operator. Deriving the openable set from dfVFS per
# file (its Analyzer over an OS path spec) is left out deliberately, so no dfVFS
# import edge is forced into this discovery layer here.
_DISK_SUFFIXES = {
    # EWF (Expert Witness Format): image, its split segments, and logical files.
    ".e01",
    ".ex01",
    ".s01",
    ".l01",
    ".lx01",
    # Split RAW / dd, and the ISO9660 image TSK opens.
    ".dd",
    ".img",
    ".001",
    ".iso",
    # Virtual disk images.
    ".vhd",
    ".vhdx",
    ".vmdk",
    ".qcow",
    ".qcow2",
    # Apple (MODI) and Parallels (PHDI) storage-media images.
    ".dmg",
    ".hdd",
}
_COMPOUND_ARCHIVE_SUFFIXES = {
    ".7z",
    ".bz2",
    ".gz",
    ".rar",
    ".tar",
    ".xz",
    ".zip",
}
_MEMORY_SUFFIXES = {".mem", ".vmem", ".dmp"}
_PCAP_SUFFIXES = {".pcap", ".pcapng"}
#: First four bytes of the capture formats libpcap and Wireshark write: classic
#: libpcap in either byte order, its nanosecond variant, and a pcapng section
#: header block. Documented format identifiers, not a guess about content.
_PCAP_MAGIC = frozenset(
    {
        b"\xd4\xc3\xb2\xa1",
        b"\xa1\xb2\xc3\xd4",
        b"\x4d\x3c\xb2\xa1",
        b"\xa1\xb2\x3c\x4d",
        b"\x0a\x0d\x0d\x0a",
    }
)


def _is_packet_capture(path: Path) -> bool:
    """Whether this file's own bytes declare it a packet capture."""

    try:
        with open(path, "rb") as handle:
            return handle.read(4) in _PCAP_MAGIC
    except OSError:
        # An unreadable candidate is simply not classified here; the caller
        # already reports a source it cannot open.
        return False
_AMBIGUOUS_SUFFIXES = {".raw", ".bin"}
_MEMORY_NAME_HINTS = ("memory", "memdump", "ramdump", "ram_dump", "physicalmemory")
_IGNORED_DIRECTORIES = {
    ".git",
    ".pytest_cache",
    "__pycache__",
    "config",
    "runs",
}
_MAX_FILES = 10_000


@dataclass(frozen=True, slots=True)
class DiscoveredCase:
    """Supported sources found without opening or modifying their contents."""

    root: Path
    disk: Path | None = None
    memory: Path | None = None
    pcap: Path | None = None
    pcaps: tuple[Path, ...] = ()
    ambiguous: tuple[Path, ...] = ()
    disks: tuple[Path, ...] = ()
    memories: tuple[Path, ...] = ()

    def __post_init__(self) -> None:
        """Keep legacy singular fields consistent with source inventories."""

        for singular_name, inventory_name in (
            ("disk", "disks"),
            ("memory", "memories"),
        ):
            singular = getattr(self, singular_name)
            inventory = getattr(self, inventory_name)
            if not inventory and singular is not None:
                inventory = (singular,)
                object.__setattr__(self, inventory_name, inventory)
            compatible = inventory[0] if len(inventory) == 1 else None
            if singular != compatible:
                object.__setattr__(self, singular_name, compatible)

    @property
    def count(self) -> int:
        return sum(
            (
                bool(self.disks),
                bool(self.memories),
                bool(self.pcaps),
            )
        )


def is_compound_archive_volume(path: Path) -> bool:
    """Return whether ``*.001`` belongs to a multipart archive, not a disk."""

    return (
        path.suffix.casefold() == ".001"
        and Path(path.stem).suffix.casefold() in _COMPOUND_ARCHIVE_SUFFIXES
    )


def discover_case_directory(
    path: str | Path,
    *,
    excluded_paths: Iterable[str | Path] = (),
) -> DiscoveredCase:
    """Discover supported evidence without guessing ambiguous raw files.

    Discovery classifies on names and extensions. Where every declared suffix
    has failed it reads the first four bytes to recognise a documented capture
    format, because a real case carries captures written as ``.log`` or with no
    suffix at all, and a source classified on its name alone would be invisible
    rather than merely misnamed. It never parses evidence and never modifies it.
    Ambiguous ``.raw`` and ``.bin`` files are classified as memory only when
    their filename says so; otherwise they are reported and left unattached.
    """

    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"Case directory not found: {root}")
    excluded = {
        Path(item).expanduser().resolve()
        for item in excluded_paths
    }

    candidates: dict[str, list[Path]] = {
        "disk": [],
        "memory": [],
        "pcap": [],
    }
    ambiguous: list[Path] = []
    visited = 0

    for candidate in sorted(root.rglob("*"), key=lambda item: str(item).casefold()):
        relative_parts = candidate.relative_to(root).parts
        if any(part.casefold() in _IGNORED_DIRECTORIES for part in relative_parts):
            continue
        if not candidate.is_file():
            continue
        if candidate.resolve() in excluded:
            continue
        visited += 1
        if visited > _MAX_FILES:
            raise ValueError(
                f"The case directory contains more than {_MAX_FILES} files. "
                "Attach the intended evidence source explicitly."
            )

        suffix = candidate.suffix.casefold()
        if suffix in _DISK_SUFFIXES and not is_compound_archive_volume(candidate):
            candidates["disk"].append(candidate)
        elif suffix in _MEMORY_SUFFIXES:
            candidates["memory"].append(candidate)
        elif suffix in _PCAP_SUFFIXES:
            candidates["pcap"].append(candidate)
        elif suffix in _AMBIGUOUS_SUFFIXES:
            stem = candidate.stem.casefold()
            if any(hint in stem for hint in _MEMORY_NAME_HINTS):
                candidates["memory"].append(candidate)
            else:
                ambiguous.append(candidate)
        elif _is_packet_capture(candidate):
            # A capture is what its bytes say it is, not what it was named. Real
            # cases carry captures written as .log, .dump, or with no suffix at
            # all, and classifying on the suffix alone makes such a source
            # invisible rather than merely misnamed. The magic number is read
            # only after every declared suffix has failed, so a correctly named
            # file never pays for the extra open.
            candidates["pcap"].append(candidate)

    disk_candidates = tuple(candidates["disk"])
    memory_candidates = tuple(candidates["memory"])
    pcap_candidates = tuple(candidates["pcap"])
    discovered = DiscoveredCase(
        root=root,
        disk=disk_candidates[0] if len(disk_candidates) == 1 else None,
        disks=disk_candidates,
        memory=memory_candidates[0] if len(memory_candidates) == 1 else None,
        memories=memory_candidates,
        # Do not merge, discard, or infer relationships between captures.
        # A single capture is unambiguous; several require an explicit choice.
        pcap=pcap_candidates[0] if len(pcap_candidates) == 1 else None,
        pcaps=pcap_candidates,
        ambiguous=tuple(ambiguous),
    )
    if discovered.count == 0 and not discovered.ambiguous:
        raise ValueError("No supported forensic source was found.")
    return discovered
