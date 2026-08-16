"""Read-only forensic evidence access via dfVFS (Digital Forensics Virtual File System).

dfVFS is the verified, widely-used forensic abstraction (the foundation of Plaso /
log2timeline) for opening storage media images. It is used here so that opening the
image, resolving the partition table and locating + opening the filesystem are handled
by a validated library rather than by hand-rolled code — and so the same code path
supports NTFS, FAT, exFAT, ext2/3/4 (and, where present, LVM/APFS/VSS) uniformly.

``DiskImage`` keeps a small, stable read-only API (``list_directory``, ``file_metadata``,
``read_file``, ``iter_file_chunks``, ``extract_file``) over whatever filesystem dfVFS
resolves; paths are
POSIX-style ("/Windows/System32") and are normalised to the filesystem's own separator
(dfVFS native NTFS uses "\\"). The image is never modified; a custody hash is recorded.

NOTE: ``read_file`` returns the artifact's raw text — the "injection carrier" the
oversight layer treats as untrusted data, never as instructions.
"""

from __future__ import annotations

import datetime as dt
import os
import posixpath
import threading
import time
from typing import Any, cast

from forensic_agent.core.audit import AuditLog
from forensic_agent.core.evidence_locator import normalize_evidence_path
from forensic_agent.core.evidence_source import (
    EvidenceHashProgress,
    EvidenceHashTotal,
    EvidenceSourceAttestation,
    EvidenceSourceError,
    EvidenceSourceRuntimeGuard,
    VerifiedPhysicalDiskSource,
    VerifiedPhysicalFileAttestation,
    assert_evidence_source_current,
    attest_evidence_source_retaining_file_digests,
)
from forensic_agent.core.tool_failure import UnreadableEvidenceError

try:
    from dfvfs.helpers import volume_scanner
    from dfvfs.lib import definitions as dfvfs_definitions
    from dfvfs.path import factory as path_spec_factory
    from dfvfs.resolver import resolver as dfvfs_resolver

    HAVE_DFVFS = True
except Exception:
    HAVE_DFVFS = False

# dfVFS type indicator -> short filesystem label (for scope derivation / reporting).
_FS_LABEL = {}
if HAVE_DFVFS:
    _FS_LABEL = {
        dfvfs_definitions.TYPE_INDICATOR_NTFS: "NTFS",
        dfvfs_definitions.TYPE_INDICATOR_TSK: "TSK",
        getattr(dfvfs_definitions, "TYPE_INDICATOR_EXT", "EXT"): "ext",
        getattr(dfvfs_definitions, "TYPE_INDICATOR_FAT", "FAT"): "FAT",
        getattr(dfvfs_definitions, "TYPE_INDICATOR_APFS", "APFS"): "APFS",
        getattr(dfvfs_definitions, "TYPE_INDICATOR_HFS", "HFS"): "HFS",
    }


def allocated_enumeration_coverage(
    *,
    path: str,
    entry_count: int,
    complete: bool = True,
) -> dict[str, object]:
    """State what a directory enumeration covers, and what it does not.

    A filesystem enumeration answers what the filesystem allocates under one
    path.  It is silent about content the filesystem no longer references:
    unallocated space, unreferenced remnants, and anything the volume structure
    does not point at.  Both facts are true at once, and publishing only the
    first makes a complete enumeration read as a complete account of the medium.

    Deliberately names no function that would reach the rest.  Which one applies
    depends on the source and the question, and stating one here would turn a
    statement of coverage into a routing instruction that arrives with every
    listing whether or not it is the right next step.
    """

    return {
        "complete": complete,
        "scope": (
            f"{entry_count} allocated directory entries under {path}; this "
            "enumeration describes what the filesystem currently allocates and "
            "does not describe unallocated space or content the filesystem no "
            "longer references, so it cannot establish that the medium holds "
            "nothing else"
        ),
        "examined": entry_count,
        "expected": entry_count,
    }


def _root_os_score(names) -> int:
    """Score a filesystem's root by whether it looks like a real OS root — so a large,
    flat FAT boot partition (many root files, no OS layout) never beats the real OS
    filesystem. `names` = lowercase names of the root's direct children.
      2 = Windows OS root (has 'windows'/'winnt'); 1 = Linux/Unix OS root ('etc' plus one
      of bin/usr/home/var/root/boot); 0 = no OS marker (boot/removable/data)."""
    names = set(names)
    if "windows" in names or "winnt" in names:
        return 2
    if "etc" in names and (names & {"bin", "usr", "home", "var", "root", "boot"}):
        return 1
    return 0


def _partition_offset(path_spec) -> int | None:
    """Resolve a partition offset that dfVFS stores behind a virtual path.

    GPT and APM path specs identify partitions as locations such as ``/p1``;
    unlike TSK partition specs, they do not expose ``start_offset`` directly.
    Their filesystem adapters provide the underlying partition object and its
    byte offset.
    """
    type_indicator = getattr(path_spec, "type_indicator", None)
    if not isinstance(type_indicator, str):
        return None
    getter_name = {
        "APM": "GetAPMPartitionByPathSpec",
        "GPT": "GetGPTPartitionByPathSpec",
    }.get(type_indicator)
    if not getter_name:
        return None
    try:
        volume_system = dfvfs_resolver.Resolver.OpenFileSystem(path_spec)
        partition = getattr(volume_system, getter_name)(path_spec)
        if partition is None:
            return None
        get_offset = getattr(partition, "get_volume_offset", None)
        value = get_offset() if callable(get_offset) else getattr(partition, "volume_offset", None)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
    except Exception:
        return None
    return None


def _path_spec_offsets(path_spec) -> tuple[int, ...]:
    """Return distinct byte offsets found in a dfVFS path-spec parent chain.

    Partition, volume-system and container path specs can be nested. Walking the
    chain avoids assuming that the filesystem's immediate parent is always the
    object carrying ``start_offset``.
    """
    offsets = []
    seen = set()
    current = path_spec
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        value = getattr(current, "start_offset", None)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            if value not in offsets:
                offsets.append(value)
        value = _partition_offset(current)
        if value is not None and value not in offsets:
            offsets.append(value)
        current = getattr(current, "parent", None)
    return tuple(offsets)


def _filesystem_offset(path_spec) -> int:
    """Return the nearest non-zero byte offset for a resolved filesystem."""
    return next((offset for offset in _path_spec_offsets(path_spec) if offset), 0)


def _scan_options(*, volumes_only: bool = False):
    """Build consistent dfVFS options, optionally excluding snapshot systems."""
    options = volume_scanner.VolumeScannerOptions()
    options.partitions = ["all"]
    options.volumes = ["all"]
    options.snapshots = ["none"]
    if volumes_only:
        options.scan_mode = options.SCAN_MODE_VOLUMES_ONLY
    return options


def _epoch(value):
    """dfVFS dfdatetime value -> POSIX epoch seconds (int) or None."""
    if not value:
        return None
    try:
        return value.CopyToPosixTimestamp()
    except Exception:
        return None


def _epoch_iso_utc(value: object) -> str | None:
    """Render a numeric POSIX timestamp deterministically as ISO-8601 UTC."""

    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    try:
        return dt.datetime.fromtimestamp(float(value), dt.UTC).isoformat().replace(
            "+00:00", "Z"
        )
    except (OSError, OverflowError, ValueError):
        return None


_LOCAL_TIME_BASIS = "local_without_offset"
_UTC_TIME_BASIS = "utc"
_UNAVAILABLE_TIME_BASIS = "unavailable"
_UTC_TIMESTAMP_SEMANTICS = "Unix epoch seconds and ISO-8601 UTC"
_LOCAL_TIMESTAMP_SEMANTICS = (
    "Filesystem wall-clock time whose UTC offset the source format never "
    "recorded, so no UTC instant exists and no *_iso_utc is offered. The numeric "
    "fields are the values the upstream backend reported, unchanged, and are not "
    "Unix timestamps. The derived_local_wall_clock block of a file_metadata "
    "result carries this tool's separate reconstruction of the recorded "
    "components."
)
_MIXED_TIMESTAMP_SEMANTICS = (
    "Per-field timestamp_bases apply; local_without_offset values have no "
    "recorded UTC offset and therefore no defensible UTC instant."
)
_NUMERIC_TIMESTAMP_COMPATIBILITY = (
    "Every numeric field is the value the upstream backend reported, unchanged. "
    "Read timestamp_bases before interpreting one: utc values are Unix epoch "
    "seconds; local_without_offset values are the backend's own encoding of a "
    "zone-less wall-clock reading and must not be read as an instant."
)
#: The reconstruction below is genuinely useful — a FAT record's wall clock is
#: what an investigator asks about — so it stays, but as its own DERIVED result
#: that names the upstream value it started from. It must never be written back
#: into mtime/atime/ctime/crtime: a consumer that reads those without reading
#: timestamp_bases would then receive our reconstruction believing it is the
#: backend's observation.
_WALL_CLOCK_METHOD = "host_timezone_reversal_of_the_upstream_local_value"
_WALL_CLOCK_RATIONALE = (
    "libtsk builds its number from a FAT record's zone-less wall-clock "
    "components using the timezone of the process that read the evidence. "
    "Reversing that conversion with the same host timezone recovers the "
    "components as the filesystem recorded them. This is a reconstruction from "
    "the cited upstream value, not a reading any backend reported, and it states "
    "no UTC offset because the source format records none. Each field reports "
    "whether re-encoding the recovered clock reproduces the backend's number, so "
    "a value the reversal could not invert is visible rather than assumed."
)
_UNRECORDED_OFFSET = "unrecorded_by_the_source_format"

#: One reader at a time on the decoded medium.
#:
#: dfVFS resolves through a process-global resolver context — its own docstring
#: calls the built-in context "not multi process safe" — and caches the file
#: object it opens for a path spec.  Every reader of one image therefore shares
#: ONE ``pyewf`` handle, with one current offset and one chunk-decode state, and
#: the filesystem parser above it shares the file objects opened through that
#: handle.  A run executes the tool calls of one model response concurrently
#: (langgraph's ToolNode maps them over a pool), so two calls interleave their
#: seeks and reads on that single handle.
#:
#: Interleaved access corrupts reads: ``libewf_chunk_data_unpack: invalid chunk
#: data``, ``invalid index entry signature``, directory listings that silently
#: come back EMPTY, and hive extractions returning the right byte count under a
#: different SHA-256 each time. The failure is a wrong answer, not an error.
#:
#: The cost is that overlapping tool calls are serialised. Nothing finer works: a
#: lock around each individual backend call still truncates reads, because the
#: file object those calls advance is itself shared.
#:
#: The guard is taken ONLY at the public operation boundary.  It is not
#: reentrant, so no method that holds it may call another that takes it.
_EVIDENCE_ACCESS = threading.Lock()

#: How many children the absence check enumerates before it stops corroborating.
#: A directory larger than this establishes nothing here: the check simply cannot
#: finish, and an unfinished enumeration falls to the unreadable side like any
#: other.  Deliberately the same ceiling the bounded listing already uses, so the
#: check is never weaker than a listing the tool would have performed anyway.
_ABSENCE_CORROBORATION_CAP = 100_000


def _host_zone_reading(epoch: int | float) -> tuple[dt.datetime, str | None, int | None]:
    """Return the wall clock this host's timezone maps ``epoch`` back to, and that zone.

    The zone is reported beside the value because it is an INPUT to the
    reconstruction: another host with another timezone would have to be told
    which one was reversed before it could judge the result.
    """

    wall_clock = dt.datetime.fromtimestamp(float(epoch))
    parts = time.localtime(float(epoch))
    zone = getattr(parts, "tm_zone", None)
    offset = getattr(parts, "tm_gmtoff", None)
    return (
        wall_clock,
        zone if isinstance(zone, str) and zone else None,
        offset if isinstance(offset, int) and not isinstance(offset, bool) else None,
    )


def _reversal_inverts_cleanly(epoch: int | float, wall_clock: dt.datetime) -> bool:
    """Whether re-encoding the recovered clock reproduces the backend's number.

    The conversion being reversed is not injective: a wall clock inside the
    reading zone's daylight-saving discontinuity has no epoch of its own, and one
    inside the repeated hour has two, so a FAT record written in either cannot be
    recovered by reversing one number. The test is the re-encoding itself rather
    than a table of transitions, so it holds for whatever zone the host is in.
    """

    try:
        return int(time.mktime(wall_clock.timetuple())) == int(epoch)
    except (OSError, OverflowError, ValueError):
        return False


def _timestamp_precision(value: object) -> str | None:
    """Return the source timestamp precision when dfVFS exposes it."""

    precision = getattr(value, "precision", None)
    return precision if isinstance(precision, str) and precision else None


def _local_iso(value: dt.datetime, precision: str | None) -> str:
    """Render a local wall-clock value without claiming absent precision."""

    if precision == "1d":
        return value.date().isoformat()
    return value.isoformat()


def _utc_iso(epoch: int | float, precision: str | None) -> str | None:
    """Render an absolute timestamp without claiming absent precision."""

    if precision != "1d":
        return _epoch_iso_utc(epoch)
    try:
        value = dt.datetime.fromtimestamp(float(epoch), dt.UTC)
    except (OSError, OverflowError, ValueError):
        return None
    return value.date().isoformat()


def _timestamp_fields(
    value: object,
) -> tuple[int | float | None, str | None, str, str | None]:
    """Report one dfVFS timestamp without reinterpreting what the backend said.

    A dfdatetime value flagged as local time with no recorded UTC offset (FAT)
    identifies no instant: libtsk built its number from zone-less wall-clock
    components using the timezone of the process that read the evidence. The
    number is therefore kept exactly as reported and labelled, and no UTC
    rendering is offered for it. Substituting a scalar of our own would put a
    reconstruction into a field a consumer reads as the backend's observation.
    """

    precision = _timestamp_precision(value)
    epoch = _epoch(value)
    if epoch is None:
        return None, None, _UNAVAILABLE_TIME_BASIS, precision
    is_unresolved_local = bool(getattr(value, "is_local_time", False)) and getattr(
        value, "time_zone_offset", None
    ) is None
    if is_unresolved_local:
        return epoch, None, _LOCAL_TIME_BASIS, precision
    return epoch, _utc_iso(epoch, precision), _UTC_TIME_BASIS, precision


def _derived_local_wall_clock(
    numeric: dict[str, int | float | None],
    bases: dict[str, str],
    precisions: dict[str, str | None],
) -> dict[str, Any] | None:
    """Reconstruct the recorded wall clock of every zone-less field, separately.

    Returns ``None`` when no field has an unrecorded offset, so a result whose
    timestamps are genuine instants gains nothing derived at all.
    """

    entries: dict[str, Any] = {}
    for field, basis in bases.items():
        if basis != _LOCAL_TIME_BASIS:
            continue
        reported = numeric.get(field)
        if reported is None:
            continue
        try:
            wall_clock, zone, offset = _host_zone_reading(reported)
        except (OSError, OverflowError, ValueError):
            continue
        entries[field] = {
            "from_field": field,
            "from_value": reported,
            "reconstructed_wall_clock": _local_iso(wall_clock, precisions.get(field)),
            "utc_offset": _UNRECORDED_OFFSET,
            "reversed_host_timezone": zone,
            "reversed_host_utc_offset_seconds": offset,
            "reversal_inverts_the_upstream_value": _reversal_inverts_cleanly(
                reported, wall_clock
            ),
        }
    if not entries:
        return None
    return {
        "role": "derived_analysis",
        "produced_by": "forensic_agent.tools.tsk_tool",
        "is_upstream_observation": False,
        "method": _WALL_CLOCK_METHOD,
        "rationale": _WALL_CLOCK_RATIONALE,
        "fields": entries,
    }


def _timestamp_semantics(bases: dict[str, str]) -> str:
    """Describe the time basis represented by one metadata result."""

    available = {basis for basis in bases.values() if basis != _UNAVAILABLE_TIME_BASIS}
    if available == {_LOCAL_TIME_BASIS}:
        return _LOCAL_TIMESTAMP_SEMANTICS
    if _LOCAL_TIME_BASIS in available:
        return _MIXED_TIMESTAMP_SEMANTICS
    return _UTC_TIMESTAMP_SEMANTICS


class DiskImage:
    """Read-only handle to a disk image, opened through dfVFS. Never writes to the image."""

    def __init__(
        self,
        image_path: str,
        audit: AuditLog | None = None,
        fs_offset: int | None = None,
        *,
        preverified_source: EvidenceSourceAttestation | None = None,
        evidence_source_guard: EvidenceSourceRuntimeGuard | None = None,
        preverified_physical_source: VerifiedPhysicalDiskSource | None = None,
        progress: EvidenceHashProgress | None = None,
        progress_total: EvidenceHashTotal | None = None,
    ) -> None:
        if not HAVE_DFVFS:
            raise RuntimeError(
                "dfVFS not installed (comes with plaso). "
                "Install plaso/dfvfs or run with --dummy. See README."
            )
        self.image_path = os.path.normpath(os.path.abspath(image_path))
        self.audit = audit or AuditLog()
        self.scan_warnings: list[str] = []
        self.evidence_source_attestation: EvidenceSourceAttestation | None
        self.evidence_source: EvidenceSourceAttestation | None
        self.physical_source_attestation: VerifiedPhysicalDiskSource | None
        #: The MD5 and SHA-1 the case-open stream computed alongside its SHA-256,
        #: kept rather than discarded so a question about them costs no second
        #: pass over the medium.  ``None`` whenever this open did not itself
        #: stream one raw file: a reused attestation was streamed by whoever
        #: issued it, and split-raw and EWF sources carry different semantics.
        self.streamed_file_digests: VerifiedPhysicalFileAttestation | None = None

        # Bind custody identity before dfVFS opens anything by path.  The
        # post-scan metadata check below then proves that dfVFS resolution did
        # not straddle a path/segment replacement (TOCTOU).
        if (preverified_source is None) is not (evidence_source_guard is None):
            raise EvidenceSourceError(
                "preverified source and evidence guard must be supplied together"
            )
        if preverified_physical_source is not None and (
            preverified_source is not None or evidence_source_guard is not None
        ):
            raise EvidenceSourceError(
                "physical-component reuse cannot be combined with a logical-media guard"
            )
        physical_source: VerifiedPhysicalDiskSource | None = None
        source: EvidenceSourceAttestation | None = None
        self.evidence_attestation_reused = False
        self.attested_at = ""
        if preverified_physical_source is not None:
            if type(preverified_physical_source) is not VerifiedPhysicalDiskSource:
                raise EvidenceSourceError(
                    "physical-component reuse requires an exact verified disk source"
                )
            if os.path.normcase(os.path.normpath(preverified_physical_source.primary_path)) != (
                os.path.normcase(self.image_path)
            ):
                raise EvidenceSourceError(
                    "verified physical disk path differs from the DiskImage path"
                )
            preverified_physical_source.assert_current_for_disk_open()
            physical_source = preverified_physical_source
            # This mode attests exact physical container files, not decoded EWF
            # logical-media bytes.  Keep it on a separate attribute so no caller
            # can mistake the physical commitment for EvidenceSourceAttestation.
            self.evidence_source_attestation = None
            self.evidence_source = None
            self.physical_source_attestation = physical_source
            self.image_sha = physical_source.sha256
            self.image_size = physical_source.size_bytes
        elif preverified_source is None:
            # This is the one long step of opening a case: the whole medium is
            # streamed here — ONCE per source, ever. A stored attestation from
            # an earlier verified pass is reused when every physical segment
            # still matches its recorded identity (device, inode, size,
            # timestamps), which is how the established tools treat evidence
            # they have already verified; verify_image_integrity remains the
            # on-demand full re-check. ``progress`` lets an interactive
            # console watch the streaming pass advance.
            from forensic_agent.core.evidence_attestation_store import (
                load_reusable_attestation,
                store_open_attestation,
                verification_reuse_enabled,
            )

            reused = (
                load_reusable_attestation(self.image_path)
                if verification_reuse_enabled()
                else None
            )
            if reused is not None:
                source, self.attested_at = reused[0], reused[1]
                self.streamed_file_digests = None
                self.evidence_attestation_reused = True
            else:
                source, self.streamed_file_digests = (
                    attest_evidence_source_retaining_file_digests(
                        self.image_path,
                        progress=progress,
                        progress_total=progress_total,
                    )
                )
                self.attested_at = ""
                self.evidence_attestation_reused = False
                companion = self.streamed_file_digests
                store_open_attestation(
                    source,
                    md5=companion.md5 if companion is not None else None,
                    sha1=companion.sha1 if companion is not None else None,
                )
        else:
            if type(preverified_source) is not EvidenceSourceAttestation:
                raise EvidenceSourceError(
                    "DiskImage requires an exact preverified source attestation"
                )
            if type(evidence_source_guard) is not EvidenceSourceRuntimeGuard:
                raise EvidenceSourceError("DiskImage requires an exact preverified evidence guard")
            evidence_source_guard = cast(EvidenceSourceRuntimeGuard, evidence_source_guard)
            if os.path.normcase(os.path.normpath(preverified_source.primary_path)) != (
                os.path.normcase(self.image_path)
            ):
                raise EvidenceSourceError("preverified source path differs from the DiskImage path")
            evidence_source_guard.authorize_preverified_disk_open(preverified_source)
            source = preverified_source
        if source is not None:
            self.evidence_source_attestation = source
            self.evidence_source = source
            self.physical_source_attestation = None
            self.image_sha = source.sha256
            self.image_size = source.size_bytes

        # 1) + 2) verified open, partition/FS resolution and selection via dfVFS.
        #    Opening resolves through the same process-global context every read
        #    goes through and the inventory walks each candidate root, so this is
        #    one reader of the medium like any other.
        with _EVIDENCE_ACCESS:
            self._open_filesystems(fs_offset)

        # 3) Re-check the exact physical raw file or ordered EWF segment set
        #    after dfVFS resolution.  This is deliberately metadata-only: the
        #    complete raw/logical medium was already streamed once above, while
        #    device/inode/size/timestamps and EWF membership catch replacement
        #    without re-hashing multi-gigabyte evidence for every run.
        if physical_source is not None:
            physical_source.assert_current_for_disk_open()
        elif source is not None:
            assert_evidence_source_current(source)
        else:  # pragma: no cover - the mutually exclusive setup above always assigns one
            raise AssertionError("DiskImage lacks an evidence-source attestation")

    def _open_filesystems(self, fs_offset: int | None) -> None:
        """Resolve, inventory and select the filesystem this handle will read.

        Split out of ``__init__`` so the one section that touches dfVFS is the
        one section the evidence guard is taken around; attestation above it
        streams the medium through its own handle and must not hold it.
        """

        # 1) verified open + partition/FS resolution via dfVFS volume scanner
        try:
            scanner = volume_scanner.VolumeScanner()
            base_specs = scanner.GetBasePathSpecs(self.image_path, options=_scan_options())
        except Exception as initial_error:
            # A corrupt VSS catalog can abort dfVFS's default scan even when no
            # snapshots were requested. Retry with the documented volumes-only
            # mode so the current/base filesystem remains available.
            try:
                scanner = volume_scanner.VolumeScanner()
                base_specs = scanner.GetBasePathSpecs(
                    self.image_path, options=_scan_options(volumes_only=True)
                )
            except Exception as fallback_error:
                raise RuntimeError(
                    "dfVFS scan failed, including the retry with snapshots disabled: "
                    f"initial={str(initial_error)[:240]}; "
                    f"volumes-only={str(fallback_error)[:240]}"
                ) from fallback_error
            self.scan_warnings.append(
                "dfVFS snapshot scan failed; opened the base filesystem with "
                f"snapshots disabled ({str(initial_error)[:240]})"
            )
        if not base_specs:
            raise RuntimeError(f"dfVFS found no filesystem in {self.image_path}")

        # 2) inventory every filesystem. Unless the caller selected an exact byte
        #    offset, pick the OS-root filesystem by layout score and then entry count.
        #    A flat FAT boot partition must not beat the real ext4/NTFS root.
        candidates = []
        for spec in base_specs:
            try:
                fsys = dfvfs_resolver.Resolver.OpenFileSystem(spec)
                root = fsys.GetFileEntryByPathSpec(spec)
            except Exception:
                continue
            names, n = set(), 0
            try:
                for e in root.sub_file_entries:
                    n += 1
                    nm = (getattr(e, "name", "") or "").lower()
                    if nm:
                        names.add(nm)
            except Exception as root_error:
                # A damaged directory/MFT entry can stop lazy root enumeration
                # after yielding valid entries. The opened filesystem remains a
                # usable candidate; only its OS-root score is incomplete.
                self.scan_warnings.append(
                    f"dfVFS root inventory was partial for {spec.type_indicator} "
                    f"({str(root_error)[:240]})"
                )
            key = (_root_os_score(names), n)
            offsets = _path_spec_offsets(spec)
            candidates.append(
                {
                    "key": key,
                    "spec": spec,
                    "fsys": fsys,
                    "offset": _filesystem_offset(spec),
                    "offsets": offsets,
                    "type": _FS_LABEL.get(spec.type_indicator, str(spec.type_indicator)),
                    "root_score": key[0],
                    "root_entries": key[1],
                }
            )
        if not candidates:
            raise RuntimeError(f"dfVFS could not open any filesystem in {self.image_path}")

        requested_offset = None if fs_offset is None else int(fs_offset)
        if requested_offset is not None and requested_offset < 0:
            raise ValueError("fs_offset must be a non-negative byte offset")
        eligible = candidates
        if requested_offset is not None:
            eligible = [
                candidate
                for candidate in candidates
                if requested_offset == candidate["offset"]
                or requested_offset in candidate["offsets"]
            ]
            if not eligible:
                available = sorted({candidate["offset"] for candidate in candidates})
                raise ValueError(
                    f"No filesystem found at byte offset {requested_offset}; "
                    f"available offsets: {available}"
                )

        selected = max(eligible, key=lambda candidate: candidate["key"])
        self._base = selected["spec"]
        self._fsys = selected["fsys"]
        self._sep = self._fsys.PATH_SEPARATOR
        # Path -> dfVFS file entry cache. A recursive walk lists a directory and
        # then descends into each child; without this, resolving every child path
        # re-walks it from the filesystem root (O(path depth) per directory), which
        # is what makes a root-wide find_files take thousands of seconds. Populated
        # when a directory's children are enumerated; a miss falls back to a full
        # root resolution, so results are identical -- this is purely a speed-up.
        self._entry_cache: dict[str, Any] = {}
        self._entry_cache_cap = 50_000
        self.fs_type = selected["type"]
        self.fs_offset = requested_offset if requested_offset is not None else selected["offset"]
        self.filesystems = [
            {
                "offset_bytes": candidate["offset"],
                "type": candidate["type"],
                "root_score": candidate["root_score"],
                "root_entries": candidate["root_entries"],
                "selected": candidate is selected,
            }
            for candidate in sorted(candidates, key=lambda candidate: candidate["offset"])
        ]

    # -- path handling ----------------------------------------------------- #
    def _spec(self, path: str):
        """Build a dfVFS path spec for a POSIX-style in-image path, normalised to the
        filesystem's own separator (NTFS uses '\\', ext/TSK use '/')."""
        parts = [p for p in str(path or "/").strip("/").split("/") if p]
        location = self._sep + self._sep.join(parts) if parts else self._sep
        return path_spec_factory.Factory.NewPathSpec(
            self._base.type_indicator, location=location, parent=self._base.parent
        )

    def _norm(self, path: str) -> str:
        """Canonical POSIX cache key for an in-image path (leading slash, no
        trailing slash, collapsed separators), independent of the fs separator."""
        parts = [p for p in str(path or "/").strip("/").split("/") if p]
        return "/" + "/".join(parts)

    def _cache_entry(self, key: str, entry) -> None:
        if entry is None:
            return
        cache = self._entry_cache
        if key not in cache and len(cache) >= self._entry_cache_cap:
            # Bounded: drop the oldest key (dict preserves insertion order). An
            # evicted path simply falls back to a root resolution next time.
            cache.pop(next(iter(cache)), None)
        cache[key] = entry

    def _entry(self, path: str):
        key = self._norm(path)
        cached = self._entry_cache.get(key)
        if cached is not None:
            return cached
        entry = self._fsys.GetFileEntryByPathSpec(self._spec(path))
        self._cache_entry(key, entry)
        return entry

    def _listed_child_names(self, path: str) -> frozenset[str] | None:
        """The casefolded names one directory lists, or ``None`` if it did not deliver.

        Deliberately does not go through ``_list_directory``: this runs inside the
        decision about a read that already failed and must not recurse into it,
        and it records nothing in the audit log because it checks this tool's own
        reasoning rather than answering anything an examiner asked.

        A path that resolves to something other than a directory lists no names at
        all, which is a complete answer and returns an empty set; only a directory
        that could not be opened or could not be enumerated to the end returns
        ``None``, because a partial list proves nothing about a name not in it.
        """

        try:
            entry = self._entry(path)
            if entry is None:
                return None
            if not entry.IsDirectory():
                return frozenset()
            names: set[str] = set()
            for child in entry.sub_file_entries:
                name = getattr(child, "name", None)
                if not name or name in (".", ".."):
                    continue
                if len(names) >= _ABSENCE_CORROBORATION_CAP:
                    return None
                names.add(name.casefold())
        except Exception:
            return None
        return frozenset(names)

    def _missing_entry_error(self, path: str) -> Exception:
        """Say what a lookup that returned nothing actually established.

        dfVFS answers a path lookup with ``None`` both for an entry the filesystem
        does not have and for one its backend could not read: the TSK adapter
        discards the backend's ``OSError`` and returns ``None``, and a read that
        comes back wrong is parsed as a directory index that does not name what
        was asked for.  Reporting that as an absence is what let a failed read
        credit a run with having looked where it never successfully looked.

        So the directory that would name the entry is asked directly, and absence
        is claimed only where an enumeration that finished did not name the next
        component.  A directory that could not be opened, one whose enumeration
        stopped early, and one that DOES name an entry the lookup could not open
        all leave both possibilities standing — and standing means unreadable,
        because that is the answer which establishes nothing.

        Names are compared without case for the same reason: on a case-insensitive
        filesystem a differing case is the same entry, and on a case-sensitive one
        this only declines to conclude.
        """

        components = [part for part in str(path or "/").strip("/").split("/") if part]
        if not components:
            return UnreadableEvidenceError(
                f"the filesystem root did not open, so nothing about it is established: {path}"
            )
        # Outwards from the containing directory: the nearest ancestor that
        # delivered a complete listing is the one entitled to answer.
        for depth in range(len(components) - 1, -1, -1):
            listed = self._listed_child_names("/" + "/".join(components[:depth]))
            if listed is None:
                continue
            if components[depth].casefold() in listed:
                return UnreadableEvidenceError(
                    f"the containing directory lists {components[depth]} but it could "
                    f"not be opened, which is a read failure and not an absence: {path}"
                )
            return FileNotFoundError(path)
        return UnreadableEvidenceError(
            f"no directory containing it could be enumerated, so its absence is not "
            f"established: {path}"
        )

    def _dereference_file_entry(self, file_entry, path: str, *, max_hops: int = 16):
        """Return the readable target of a dfVFS symbolic-link entry.

        dfVFS deliberately exposes a link as its own file entry.  Opening that
        entry's file object on ext-family images can fail with an invalid inode,
        ``GetLinkedFileEntry`` itself can fail for a relative ext target because
        it builds a target path spec without resolving it against the link's
        parent. Resolve textual link targets inside this same image first, then
        retain ``GetLinkedFileEntry`` as a fallback for other dfVFS backends. A
        bounded walk supports chained links and fails closed on dangling/cyclic
        or pathological chains.
        """

        current = file_entry
        current_path = normalize_evidence_path(path, allow_root=False)
        seen: set[str] = set()
        for _hop in range(max_hops + 1):
            if current is None:
                # The hop that produced nothing is the one to ask about: whether
                # the link dangles or the target merely would not open is decided
                # the same way as any other lookup that came back empty.
                raise self._missing_entry_error(current_path)
            is_link = getattr(current, "IsLink", None)
            if not callable(is_link) or not is_link():
                return current
            identity = f"{current_path}\0{repr(getattr(current, 'path_spec', None))}"
            if identity in seen:
                raise RuntimeError(f"symbolic-link cycle while resolving {path}")
            seen.add(identity)
            target = getattr(current, "link", None)
            if isinstance(target, str) and target.strip():
                target = target.replace("\\", "/")
                if target.startswith("/"):
                    linked_path = posixpath.normpath(target)
                else:
                    linked_path = posixpath.normpath(
                        posixpath.join(posixpath.dirname(current_path), target)
                    )
                current_path = normalize_evidence_path(linked_path, allow_root=False)
                current = self._entry(current_path)
                continue
            linked = getattr(current, "GetLinkedFileEntry", None)
            try:
                current = linked() if callable(linked) else None
            except Exception as error:
                # The word was already right and the class was wrong: a target
                # that could not be read was raised as the class that means the
                # artifact is not there, and the classification reads the class.
                raise UnreadableEvidenceError(
                    f"the symbolic-link target could not be read: {current_path}"
                ) from error
        raise RuntimeError(f"symbolic-link chain exceeds {max_hops} hops for {path}")

    @staticmethod
    def _inode(file_entry):
        ps = getattr(file_entry, "path_spec", None)
        for attr in ("inode", "mft_entry", "identifier"):
            v = getattr(ps, attr, None)
            if v is not None:
                return v
        return None

    def close(self) -> None:
        return None  # dfVFS file systems are reference-counted by the resolver cache

    def filesystem_inventory(self) -> list[dict]:
        """Return resolved filesystems and the selected filesystem's byte offset.

        This is metadata only; it does not change the active filesystem. Pass
        ``fs_offset`` to the constructor to open a specific inventory entry.
        """
        return [dict(item) for item in self.filesystems]

    # -- read-only operations --------------------------------------------- #
    def list_directory(self, path: str = "/") -> dict:
        """List the entries of one directory on the disk image (read-only). Use to
        enumerate a known directory; to find files by term across the tree use
        search_keyword, and to read a file's content use read_file.

        Example: list_directory("/Users/Alice/Desktop")

        Input: `path` is an absolute POSIX-style path inside the image (default "/").

        Returns: {"path", "entries"} where each entry is {"name", "inode",
        "type" ("3" for a directory), "size" (bytes)}.
        """
        return self._list_directory(path, max_entries=None)

    def list_directory_bounded(self, path: str = "/", *, max_entries: int = 10_000) -> dict:
        """Enumerate at most ``max_entries`` direct children.

        Recursive evidence tools use this primitive so a single pathological
        directory cannot materialize an unbounded Python list before their own
        traversal cap is enforced. An additional child is observed only to prove
        that the directory listing was capped; that child is not returned.
        """

        if (
            isinstance(max_entries, bool)
            or not isinstance(max_entries, int)
            or max_entries < 1
            or max_entries > 100_000
        ):
            raise ValueError("max_entries must be between 1 and 100000")
        return self._list_directory(path, max_entries=max_entries)

    def _list_directory(self, path: str, *, max_entries: int | None) -> dict:
        t0 = time.time()
        entries: list[dict[str, object]] = []
        with _EVIDENCE_ACCESS:
            fe = self._entry(path)
            if fe is None:
                raise self._missing_entry_error(path)
            enumeration_error = None
            enumeration_capped = False
            base = self._norm(path)
            try:
                for child in fe.sub_file_entries:
                    name = child.name
                    if not name or name in (".", ".."):
                        continue
                    # Cache the child's entry under its full path so a later descent
                    # into it resolves in O(1) instead of re-walking from the root.
                    self._cache_entry(base + "/" + name if base != "/" else "/" + name, child)
                    if max_entries is not None and len(entries) >= max_entries:
                        enumeration_capped = True
                        break
                    entries.append(
                        {
                            "name": name,
                            "inode": self._inode(child),
                            "type": "3" if child.IsDirectory() else "1",
                            "size": getattr(child, "size", None),
                        }
                    )
            except Exception as error:
                if not entries:
                    raise RuntimeError(
                        f"Unable to enumerate directory {path}: {str(error)[:1000]}"
                    ) from error
                enumeration_error = error
        result: dict[str, Any] = {"path": path, "entries": entries}
        if max_entries is not None:
            result.update(
                {
                    "enumeration_limit": max_entries,
                    "enumeration_complete": not enumeration_capped and enumeration_error is None,
                }
            )
        if enumeration_capped:
            result.update(
                {
                    "incomplete": True,
                    "warning": f"Directory enumeration reached its {max_entries}-entry cap",
                }
            )
        if enumeration_error is not None:
            result.update(
                {
                    "incomplete": True,
                    "warning": f"Directory enumeration stopped after {len(entries)} entries",
                    "error": {
                        "type": type(enumeration_error).__name__,
                        "message": str(enumeration_error)[:1000],
                    },
                }
            )
        # A directory enumeration is an account of what the filesystem allocates,
        # not of what the medium holds.  Both statements are true and only one of
        # them used to be published, so a complete listing read as a complete
        # picture and content outside the allocated tree was never looked for.
        # The scope names what was covered and what was not; which function
        # reaches the rest is left to the reader, because naming one here would
        # turn a statement of coverage into a routing instruction.
        result.setdefault(
            "coverage",
            allocated_enumeration_coverage(
                path=path,
                entry_count=len(entries),
                complete=not enumeration_capped and enumeration_error is None,
            ),
        )
        audit_args: dict[str, object] = {"path": path}
        if max_entries is not None:
            audit_args["max_entries"] = max_entries
        self.audit.record(
            tool="tsk.list_directory",
            args=audit_args,
            output=result,
            input_sha=self.image_sha,
            duration_s=time.time() - t0,
        )
        return result

    def file_metadata(self, path: str) -> dict:
        """Return filesystem metadata and MAC(b) timestamps for one path on the image
        (read-only). Every numeric timestamp is the value the backend reported;
        ``timestamp_bases`` says whether it is a UTC instant or a wall-clock
        reading whose UTC offset the source format never recorded, and only the
        former carries a ``*_iso_utc`` rendering. ``derived_local_wall_clock``
        holds this tool's separate reconstruction for the latter.

        Example: file_metadata("/Windows/System32/config/SOFTWARE")

        Returns: {"path", "inode", "size", "mtime", "atime", "ctime", "crtime"}.
        """
        t0 = time.time()
        timestamp_bases: dict[str, str] = {}
        timestamp_precisions: dict[str, str | None] = {}
        reported: dict[str, int | float | None] = {}
        # Every attribute below is read out of the backend, timestamps included,
        # so the whole read is one reader and not just the lookup that opens it.
        with _EVIDENCE_ACCESS:
            fe = self._entry(path)
            if fe is None:
                raise self._missing_entry_error(path)
            result: dict[str, Any] = {
                "path": path,
                "inode": self._inode(fe),
                "size": getattr(fe, "size", None),
            }
            for field, attribute in (
                ("mtime", "modification_time"),
                ("atime", "access_time"),
                ("ctime", "change_time"),
                ("crtime", "creation_time"),
            ):
                numeric, iso_utc, basis, precision = _timestamp_fields(
                    getattr(fe, attribute, None)
                )
                result[field] = numeric
                result[f"{field}_iso_utc"] = iso_utc
                reported[field] = numeric
                timestamp_bases[field] = basis
                timestamp_precisions[field] = precision
        result["timestamp_bases"] = timestamp_bases
        result["timestamp_precisions"] = timestamp_precisions
        result["timestamp_semantics"] = _timestamp_semantics(timestamp_bases)
        result["timestamp_numeric_semantics"] = _NUMERIC_TIMESTAMP_COMPATIBILITY
        # Kept out of the four numeric fields and out of *_iso_utc: it is ours,
        # and the key it arrives under says so.
        result["derived_local_wall_clock"] = _derived_local_wall_clock(
            reported, timestamp_bases, timestamp_precisions
        )
        self.audit.record(
            tool="tsk.file_metadata",
            args={"path": path},
            output=result,
            input_sha=self.image_sha,
            duration_s=time.time() - t0,
        )
        return result

    def read_file(self, path: str, max_bytes: int = 4096, offset: int = 0) -> dict:
        """Read up to max_bytes of a file's content starting at byte `offset` (read-only)
        — the artifact's "injection carrier" content. Large files are PAGED: use the
        returned `next_offset`/`eof` to read further, or search_in_file to jump to a term.
        For a byte-accurate full copy use extract_file; for a host-side file outside the
        image use read_text_file.

        Example: read_file("/Users/Alice/app.log", max_bytes=8192, offset=8192)

        Returns: {"path", "size", "offset", "returned_bytes", "next_offset", "eof",
        "content_text"}.
        """
        t0 = time.time()
        offset = max(0, int(offset or 0))
        mb = max(1, int(max_bytes or 4096))
        data = b""
        # The seek and the read that follows it must not be separable: the file
        # object they advance is shared with every other reader of this medium.
        with _EVIDENCE_ACCESS:
            fe = self._entry(path)
            if fe is None:
                raise self._missing_entry_error(path)
            fe = self._dereference_file_entry(fe, path)
            size = getattr(fe, "size", 0) or 0
            if size and offset < size:
                fo = fe.GetFileObject()
                try:
                    fo.seek(offset)
                    data = fo.read(min(size - offset, mb))
                finally:
                    fo.close() if hasattr(fo, "close") else None
        page_end = offset + len(data)
        eof = page_end >= size
        # At end of file there is no next page.  Advertising one makes the
        # standardized page declare a remainder that does not exist, so the caller
        # spends a call reading zero bytes past the end.
        result = {
            "path": path,
            "size": size,
            "offset": offset,
            "returned_bytes": len(data),
            "next_offset": None if eof else page_end,
            "eof": eof,
            "content_text": data.decode("utf-8", "replace"),
        }
        self.audit.record(
            tool="tsk.read_file",
            args={"path": path, "max_bytes": max_bytes, "offset": offset},
            output=result,
            input_sha=self.image_sha,
            duration_s=time.time() - t0,
        )
        return result

    def extract_file(self, path: str, out_path: str) -> dict:
        """Copy a full file out of the image to a local path, byte-for-byte (read-only
        on the image). Use when a tool needs a real on-disk file (e.g. a registry hive
        for registry_query, an .evtx for evtx_query).

        Example: extract_file("/Windows/System32/config/SYSTEM", "C:/tmp/SYSTEM")

        Returns: {"path", "out_path", "size", "written"}.
        """
        t0 = time.time()
        written = 0
        # Held for the whole copy.  A hive extraction interleaved with a listing
        # is exactly the shape that returned the right byte count under a
        # different digest on every attempt.
        with _EVIDENCE_ACCESS:
            fe = self._entry(path)
            if fe is None:
                raise self._missing_entry_error(path)
            fe = self._dereference_file_entry(fe, path)
            size = getattr(fe, "size", 0) or 0
            fo = fe.GetFileObject()
            try:
                with open(out_path, "wb") as out:
                    while True:
                        chunk = fo.read(1 << 20)
                        if not chunk:
                            break
                        out.write(chunk)
                        written += len(chunk)
            finally:
                fo.close() if hasattr(fo, "close") else None
        result = {"path": path, "out_path": out_path, "size": size, "written": written}
        self.audit.record(
            tool="tsk.extract_file",
            args={"path": path, "out_path": out_path},
            output={"size": size, "written": written},
            input_sha=self.image_sha,
            duration_s=time.time() - t0,
        )
        return result

    def iter_file_chunks(self, path: str, *, chunk_size: int = 1 << 20):
        """Yield every byte of one in-image regular file in bounded chunks.

        This deliberately returns no host path and performs no text decoding.  It
        is the byte-accurate primitive used by evidence hashing and trusted
        in-process parsers.  Callers remain responsible for recording the
        semantic operation in the audit log.

        The evidence guard is held for the whole walk, not around each chunk: the
        file object being advanced belongs to the process-global resolver cache,
        so a competing reader of the same path moves THIS read's offset.  Locking
        each chunk separately still truncates the result.  The
        guard is acquired and released by hand rather than with ``with`` so that
        closing an abandoned generator releases it whichever thread finalises it.
        """

        normalized = normalize_evidence_path(path, allow_root=False)
        if (
            isinstance(chunk_size, bool)
            or not isinstance(chunk_size, int)
            or chunk_size < 1
            or chunk_size > (4 << 20)
        ):
            raise ValueError("chunk_size must be between 1 and 4194304 bytes")
        _EVIDENCE_ACCESS.acquire()
        try:
            file_entry = self._entry(normalized)
            if file_entry is None:
                raise self._missing_entry_error(normalized)
            file_entry = self._dereference_file_entry(file_entry, normalized)
            if file_entry.IsDirectory():
                raise IsADirectoryError(normalized)
            file_object = file_entry.GetFileObject()
            try:
                while True:
                    chunk = file_object.read(chunk_size)
                    if not chunk:
                        break
                    if not isinstance(chunk, bytes):
                        raise RuntimeError("dfVFS returned a non-byte file chunk")
                    yield chunk
            finally:
                file_object.close() if hasattr(file_object, "close") else None
        finally:
            _EVIDENCE_ACCESS.release()

    def extract_file_to(self, path: str, out: object) -> dict:
        """Copy a full image file to an already-open trusted binary stream.

        Controlled scratch creates the destination with exclusive semantics and
        retains its identity.  Accepting that stream here avoids reopening a
        pathname with ``wb`` (which would follow or truncate a replaced target).
        The destination path is deliberately absent from audit/output records.
        """
        write = getattr(out, "write", None)
        if not callable(write):
            raise TypeError("out must be an open writable binary stream")
        t0 = time.time()
        written = 0
        with _EVIDENCE_ACCESS:
            fe = self._entry(path)
            if fe is None:
                raise self._missing_entry_error(path)
            fe = self._dereference_file_entry(fe, path)
            size = getattr(fe, "size", 0) or 0
            fo = fe.GetFileObject()
            try:
                while True:
                    chunk = fo.read(1 << 20)
                    if not chunk:
                        break
                    write(chunk)
                    written += len(chunk)
            finally:
                fo.close() if hasattr(fo, "close") else None
        result = {"path": path, "size": size, "written": written}
        self.audit.record(
            tool="tsk.extract_file_to",
            args={"path": path, "destination": "controlled-scratch"},
            output={"size": size, "written": written},
            input_sha=self.image_sha,
            duration_s=time.time() - t0,
        )
        return result
