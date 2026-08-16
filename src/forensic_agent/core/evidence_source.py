"""Canonical, fail-closed identity for forensic evidence sources.

One evidence SHA-256 is used across the study lock, the opened disk object, and
tool provenance.  The digest has deliberately precise semantics:

* a raw/single-file image is SHA-256 over the exact file bytes;
* a split raw image is SHA-256 over the ordered concatenation of every physical
  segment, while every segment identity is retained; and
* an EWF segment set is SHA-256 over the decoded logical media byte stream that
  libewf exposes after opening the complete ordered segment set.

The EWF digest therefore does not trust the acquisition MD5 stored in the
container and does not hash only the ``.E01`` segment.  It is representation
independent: an EWF and a raw clone with identical logical media have the same
evidence SHA-256.  Runtime-only segment descriptors bind that digest to the
paths and stable file metadata which were actually opened; paths are omitted
from portable attestations.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import threading
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

EVIDENCE_HASH_CHUNK_BYTES = 1024 * 1024
EVIDENCE_SOURCE_SCHEMA_ID = "forensic.evidence-source.v1"
EVIDENCE_RUNTIME_INTEGRITY_SCHEMA_ID = "forensic.evidence-runtime-integrity.v3"
RAW_FILE_DIGEST_SEMANTICS = "sha256-exact-file-bytes-v1"
RAW_SEGMENT_SET_DIGEST_SEMANTICS = "sha256-concatenated-raw-segments-v1"
EWF_LOGICAL_DIGEST_SEMANTICS = "sha256-libewf-decoded-logical-media-v1"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
_MD5_RE = re.compile(r"^[0-9a-f]{32}$")
_EWF_SUFFIX_RE = re.compile(
    r"\.(?:e(?:x)?\d{2}|e[a-z]{2}|[ls]\d{2}|ewf)$",
    flags=re.IGNORECASE,
)
_RAW_SEGMENT_NAME_RE = re.compile(r"^(?P<base>.+)\.(?P<index>\d{3,})$")
_MAX_RAW_SEGMENTS = 10_000
_MAX_RAW_DIRECTORY_ENTRIES = 100_000

EvidenceSourceType = Literal["raw_file", "raw_segment_set", "ewf_logical_media"]
EwfGlob = Callable[[str], Sequence[str | os.PathLike[str]]]
EwfHandleFactory = Callable[[], Any]

#: Optional observer of a streaming attestation, invoked with the number of
#: bytes just read.  It exists so a console can show that a multi-gigabyte
#: digest is progressing rather than hung; it is never consulted, so it cannot
#: influence the block size, the read order, or what reaches the digest.
EvidenceHashProgress = Callable[[int], None]

#: Optional observer of how much a streaming attestation will read altogether,
#: stated once before the first block.  Only the pass can know that number, and
#: only after it has resolved the source: an EWF medium's size comes from libewf
#: once the container is open, and a split raw set's from every discovered
#: segment.  Measuring the file on disk would measure something else, since a
#: compressed EWF decodes to more than its container holds and a split set
#: continues past its first segment, so the total is stated here beside the loop
#: it bounds.
EvidenceHashTotal = Callable[[int], None]


class EvidenceSourceError(RuntimeError):
    """An evidence source cannot be safely and completely attested."""


class EvidenceSourceChangedError(EvidenceSourceError):
    """An evidence source changed while or after it was attested."""


RUNTIME_METADATA_CHECK = "metadata"
RUNTIME_FULL_CONTENT_CHECK = "full_content_sha256"
RUNTIME_STUDY_PINNED_CONTENT_CHECK = "study_session_pinned_content_sha256"
WINDOWS_READ_LEASE_MODE = "windows-share-read-only"
WINDOWS_STUDY_READ_LEASE_MODE = "windows-study-session-share-read-only"
NO_READ_LEASE_MODE = "none-platform-not-supported"
EVIDENCE_STUDY_LEASE_SCHEMA_ID = "forensic.evidence-study-lease.v1"
VERIFIED_PHYSICAL_DISK_SOURCE_SCHEMA_ID = "forensic.verified-physical-disk-source.v1"


@dataclass(frozen=True)
class EvidenceSegmentDescriptor:
    """Runtime identity of one physical source file in an evidence source."""

    path: str
    size_bytes: int
    device: int
    inode: int
    mtime_ns: int
    ctime_ns: int

    def __post_init__(self) -> None:
        if not isinstance(self.path, str) or not self.path:
            raise EvidenceSourceError("evidence segment path must be non-empty text")
        if not Path(self.path).is_absolute():
            raise EvidenceSourceError("evidence segment path must be absolute")
        for name, value in (
            ("size_bytes", self.size_bytes),
            ("device", self.device),
            ("inode", self.inode),
            ("mtime_ns", self.mtime_ns),
            ("ctime_ns", self.ctime_ns),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise EvidenceSourceError(f"evidence segment {name} must be an integer")
        if self.size_bytes < 0 or self.device < 0 or self.inode < 0:
            raise EvidenceSourceError("evidence segment size/device/inode cannot be negative")

    @classmethod
    def from_stat(cls, path: Path, metadata: os.stat_result) -> EvidenceSegmentDescriptor:
        return cls(
            path=str(path),
            size_bytes=int(metadata.st_size),
            device=int(metadata.st_dev),
            inode=int(metadata.st_ino),
            mtime_ns=int(metadata.st_mtime_ns),
            ctime_ns=int(metadata.st_ctime_ns),
        )

    def identity(self) -> tuple[int, int, int, int, int]:
        return (
            self.device,
            self.inode,
            self.size_bytes,
            self.mtime_ns,
            self.ctime_ns,
        )


@dataclass(frozen=True)
class EvidenceSourceAttestation:
    """Verified digest plus runtime-only physical source descriptor."""

    source_type: EvidenceSourceType
    digest_semantics: str
    sha256: str
    size_bytes: int
    primary_path: str
    segments: tuple[EvidenceSegmentDescriptor, ...]
    schema_id: str = EVIDENCE_SOURCE_SCHEMA_ID

    def __post_init__(self) -> None:
        if self.schema_id != EVIDENCE_SOURCE_SCHEMA_ID:
            raise EvidenceSourceError("unknown evidence-source attestation schema")
        expected_semantics = {
            "raw_file": RAW_FILE_DIGEST_SEMANTICS,
            "raw_segment_set": RAW_SEGMENT_SET_DIGEST_SEMANTICS,
            "ewf_logical_media": EWF_LOGICAL_DIGEST_SEMANTICS,
        }.get(self.source_type)
        if expected_semantics is None or self.digest_semantics != expected_semantics:
            raise EvidenceSourceError("evidence-source digest semantics are inconsistent")
        if _SHA256_RE.fullmatch(self.sha256) is None:
            raise EvidenceSourceError("evidence-source SHA-256 must be 64 lowercase hex characters")
        if (
            isinstance(self.size_bytes, bool)
            or not isinstance(self.size_bytes, int)
            or self.size_bytes < 0
        ):
            raise EvidenceSourceError("evidence-source size must be a non-negative integer")
        if not self.segments:
            raise EvidenceSourceError("evidence-source attestation has no physical segments")
        if not isinstance(self.primary_path, str) or not Path(self.primary_path).is_absolute():
            raise EvidenceSourceError("primary evidence path must be absolute text")
        segment_keys = tuple(_path_key(item.path) for item in self.segments)
        if len(set(segment_keys)) != len(segment_keys):
            raise EvidenceSourceError("evidence-source segment paths must be unique")
        if _path_key(self.primary_path) not in segment_keys:
            raise EvidenceSourceError("primary evidence path is absent from its source descriptor")
        if self.source_type == "raw_file" and (
            len(self.segments) != 1 or self.segments[0].size_bytes != self.size_bytes
        ):
            raise EvidenceSourceError("raw evidence descriptor is inconsistent with its byte size")
        if self.source_type == "raw_segment_set" and (
            len(self.segments) < 2
            or sum(segment.size_bytes for segment in self.segments) != self.size_bytes
            or _path_key(self.primary_path) != _path_key(self.segments[0].path)
        ):
            raise EvidenceSourceError(
                "split raw evidence descriptor is inconsistent with its ordered segments"
            )

    @property
    def container_size_bytes(self) -> int:
        """Total bytes occupied by physical source files (not EWF logical size)."""

        return sum(segment.size_bytes for segment in self.segments)

    def portable_record(self) -> dict[str, object]:
        """Return portable identity metadata without local paths."""

        return {
            "schema_id": self.schema_id,
            "source_type": self.source_type,
            "digest_semantics": self.digest_semantics,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "segment_count": len(self.segments),
            "container_size_bytes": self.container_size_bytes,
        }


_PHYSICAL_PROOF_SECRET = secrets.token_bytes(32)


def _physical_file_proof(
    attestation: EvidenceSourceAttestation,
    *,
    md5: str,
    sha1: str,
) -> str:
    payload = json.dumps(
        {
            "schema_id": "forensic.verified-physical-file.v2",
            "source_attestation_sha256": evidence_source_attestation_sha256(attestation),
            "md5": md5,
            "sha1": sha1,
            "sha256": attestation.sha256,
        },
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("ascii")
    return hmac.new(_PHYSICAL_PROOF_SECRET, payload, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class VerifiedPhysicalFileAttestation:
    """Opaque multi-hash proof for one completely streamed physical file.

    The MD5, SHA-1 and SHA-256 values are updated during the same stable-file
    stream.  The process-local proof binds all three digests to the exact path,
    size and stat identity in ``attestation``; callers cannot add weaker hashes
    to a previously issued SHA-256-only object.
    """

    attestation: EvidenceSourceAttestation
    md5: str
    sha1: str
    _proof: str = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.attestation) is not EvidenceSourceAttestation:
            raise EvidenceSourceError("verified physical file requires an exact source attestation")
        if (
            self.attestation.source_type != "raw_file"
            or self.attestation.digest_semantics != RAW_FILE_DIGEST_SEMANTICS
            or len(self.attestation.segments) != 1
        ):
            raise EvidenceSourceError("verified physical file must attest exact file bytes")
        if _MD5_RE.fullmatch(self.md5) is None:
            raise EvidenceSourceError("verified physical file MD5 must be lowercase hexadecimal")
        if _SHA1_RE.fullmatch(self.sha1) is None:
            raise EvidenceSourceError("verified physical file SHA-1 must be lowercase hexadecimal")
        expected = _physical_file_proof(
            self.attestation,
            md5=self.md5,
            sha1=self.sha1,
        )
        if not isinstance(self._proof, str) or not hmac.compare_digest(self._proof, expected):
            raise EvidenceSourceError(
                "verified physical file was not issued by the full-hash verifier"
            )

    @property
    def primary_path(self) -> str:
        return self.attestation.primary_path

    @property
    def sha256(self) -> str:
        return self.attestation.sha256

    @property
    def size_bytes(self) -> int:
        return self.attestation.size_bytes

    @property
    def segment(self) -> EvidenceSegmentDescriptor:
        return self.attestation.segments[0]


def _physical_disk_proof(
    primary_path: str,
    components: Sequence[VerifiedPhysicalFileAttestation],
) -> str:
    payload = json.dumps(
        {
            "schema_id": VERIFIED_PHYSICAL_DISK_SOURCE_SCHEMA_ID,
            "primary_path": _path_key(primary_path),
            "component_proofs": [component._proof for component in components],
        },
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hmac.new(_PHYSICAL_PROOF_SECRET, payload, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class VerifiedPhysicalDiskSource:
    """One disk's already-hashed physical files, reusable without re-streaming.

    Every component must carry an opaque exact-file proof minted by
    :func:`attest_physical_file`.  The object deliberately does not claim EWF
    logical-media digest semantics: it binds the exact container segments that a
    caller has already hashed.  ``assert_current_for_disk_open`` rechecks canonical
    paths, the complete EWF segment set, and every strong stat identity before and
    after a parser open.

    The normal :class:`~forensic_agent.tools.tsk_tool.DiskImage` path does not use
    this type.  It exists for an evidence resolver that has already fully hashed
    each unique physical component once.
    """

    primary_path: str
    components: tuple[VerifiedPhysicalFileAttestation, ...]
    _proof: str = field(repr=False)
    schema_id: str = VERIFIED_PHYSICAL_DISK_SOURCE_SCHEMA_ID

    def __post_init__(self) -> None:
        if self.schema_id != VERIFIED_PHYSICAL_DISK_SOURCE_SCHEMA_ID:
            raise EvidenceSourceError("unknown verified-physical-disk schema")
        if not isinstance(self.primary_path, str) or not Path(self.primary_path).is_absolute():
            raise EvidenceSourceError("verified physical disk primary path must be absolute")
        if not self.components:
            raise EvidenceSourceError("verified physical disk has no components")
        for component in self.components:
            if type(component) is not VerifiedPhysicalFileAttestation:
                raise EvidenceSourceError(
                    "verified physical disk requires exact component attestations"
                )
            # Re-run the issuer proof check rather than trusting construction-time
            # validation of an object supplied by another caller.
            component.__post_init__()
        keys = tuple(_path_key(component.primary_path) for component in self.components)
        if len(set(keys)) != len(keys):
            raise EvidenceSourceError("verified physical disk component paths are not unique")
        if keys[0] != _path_key(self.primary_path):
            raise EvidenceSourceError(
                "verified physical disk primary path must be its first component"
            )
        expected_proof = _physical_disk_proof(self.primary_path, self.components)
        if not isinstance(self._proof, str) or not hmac.compare_digest(self._proof, expected_proof):
            raise EvidenceSourceError(
                "verified physical disk was not issued by the binding factory"
            )

    @property
    def size_bytes(self) -> int:
        """Return total physical container bytes (not EWF logical-media bytes)."""

        return sum(component.size_bytes for component in self.components)

    @property
    def sha256(self) -> str:
        """Commit to expected digests, canonical paths, and strong stat identities."""

        fields = {
            "schema_id": self.schema_id,
            "primary_path": _path_key(self.primary_path),
            "components": [
                {
                    "path": _path_key(component.primary_path),
                    "md5": component.md5,
                    "sha1": component.sha1,
                    "sha256": component.sha256,
                    "size_bytes": component.size_bytes,
                    "identity": list(component.segment.identity()),
                }
                for component in self.components
            ],
        }
        payload = json.dumps(
            fields,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def assert_current_for_disk_open(self, *, ewf_glob: EwfGlob | None = None) -> None:
        """Fail if path identity, bytes metadata, or disk segment membership drifted."""

        self.__post_init__()
        for component in self.components:
            component.__post_init__()
            assert_evidence_source_current(component.attestation)
        expected_paths = tuple(_path_key(component.primary_path) for component in self.components)
        primary = _absolute_path(self.primary_path)
        if is_ewf_source(primary):
            if ewf_glob is None:
                ewf_glob, _ = _pyewf_bindings()
            observed = _discover_ewf_segments(primary, ewf_glob)
            if tuple(_path_key(path) for path in observed) != expected_paths:
                raise EvidenceSourceChangedError(
                    "verified physical EWF segment membership or ordering changed"
                )
        elif len(expected_paths) > 1 or len(_discover_raw_segments(primary)) > 1:
            observed = _discover_raw_segments(primary)
            if tuple(_path_key(path) for path in observed) != expected_paths:
                raise EvidenceSourceChangedError(
                    "verified physical split raw membership or ordering changed"
                )
        elif expected_paths != (_path_key(primary),):
            raise EvidenceSourceError(
                "a non-EWF verified disk cannot declare auxiliary disk segments"
            )


def bind_verified_physical_disk_source(
    primary_path: str | os.PathLike[str],
    components: Sequence[VerifiedPhysicalFileAttestation],
) -> VerifiedPhysicalDiskSource:
    """Bind only full-hash-issued component proofs into a reusable disk source."""

    primary = str(_absolute_path(primary_path))
    exact_components = tuple(components)
    for component in exact_components:
        if type(component) is not VerifiedPhysicalFileAttestation:
            raise EvidenceSourceError(
                "physical disk binding requires full-hash-issued component proofs"
            )
        component.__post_init__()
    proof = _physical_disk_proof(primary, exact_components)
    return VerifiedPhysicalDiskSource(
        primary_path=primary,
        components=exact_components,
        _proof=proof,
    )


def evidence_source_attestation_sha256(
    attestation: EvidenceSourceAttestation,
) -> str:
    """Content-address the complete runtime descriptor without publishing paths.

    The portable evidence digest deliberately omits local paths and file metadata.
    Runtime custody checks need the stronger identity, including every normalized
    segment path and stable stat field.  Only this digest is emitted in telemetry.
    """

    if type(attestation) is not EvidenceSourceAttestation:
        raise EvidenceSourceError("evidence source attestation has an unsupported type")
    fields = {
        "schema_id": attestation.schema_id,
        "source_type": attestation.source_type,
        "digest_semantics": attestation.digest_semantics,
        "sha256": attestation.sha256,
        "size_bytes": attestation.size_bytes,
        "primary_path": _path_key(attestation.primary_path),
        "segments": [
            {
                "path": _path_key(segment.path),
                "size_bytes": segment.size_bytes,
                "device": segment.device,
                "inode": segment.inode,
                "mtime_ns": segment.mtime_ns,
                "ctime_ns": segment.ctime_ns,
            }
            for segment in attestation.segments
        ],
    }
    # repr() is not used: a compact, explicitly ordered byte encoding prevents
    # implementation-specific dataclass formatting from changing this identity.
    payload = json.dumps(
        fields,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _load_windows_kernel32() -> Any:
    """Load ``kernel32`` without exposing a Windows-only symbol to POSIX mypy."""

    import ctypes

    win_dll = getattr(ctypes, "WinDLL", None)
    if not callable(win_dll):
        raise EvidenceSourceError("Windows handle APIs are unavailable on this platform")
    return win_dll("kernel32", use_last_error=True)


def _close_windows_handles(handles: Sequence[int]) -> tuple[int, ...]:
    """Close raw Windows handles, returning only handles that failed to close."""

    if os.name != "nt" or not handles:
        return ()
    import ctypes

    kernel32 = _load_windows_kernel32()
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [ctypes.c_void_p]
    close_handle.restype = ctypes.c_int
    return tuple(handle for handle in handles if not close_handle(ctypes.c_void_p(handle)))


def _open_verified_windows_read_handles(
    segments: Sequence[EvidenceSegmentDescriptor],
) -> list[int]:
    """Pin exact segment file IDs while denying write/delete sharing.

    Rejecting reparse-point ancestors before ``CreateFileW`` is not enough by
    itself: an attacker could replace a normal directory with a junction in the
    small interval before the file is opened.  The handle's NTFS file index and
    size are therefore compared with the attested descriptor.  Once the exact
    file is held without ``FILE_SHARE_DELETE``, Windows also prevents renaming
    any ordinary ancestor directory for the lifetime of the handle.
    """

    if os.name != "nt":
        raise EvidenceSourceError("Windows evidence handles require Windows")
    import ctypes

    class _ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", ctypes.c_uint32),
            ("ftCreationTimeLow", ctypes.c_uint32),
            ("ftCreationTimeHigh", ctypes.c_uint32),
            ("ftLastAccessTimeLow", ctypes.c_uint32),
            ("ftLastAccessTimeHigh", ctypes.c_uint32),
            ("ftLastWriteTimeLow", ctypes.c_uint32),
            ("ftLastWriteTimeHigh", ctypes.c_uint32),
            ("dwVolumeSerialNumber", ctypes.c_uint32),
            ("nFileSizeHigh", ctypes.c_uint32),
            ("nFileSizeLow", ctypes.c_uint32),
            ("nNumberOfLinks", ctypes.c_uint32),
            ("nFileIndexHigh", ctypes.c_uint32),
            ("nFileIndexLow", ctypes.c_uint32),
        ]

    kernel32 = _load_windows_kernel32()
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    create_file.restype = ctypes.c_void_p
    get_information = kernel32.GetFileInformationByHandle
    get_information.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_ByHandleFileInformation),
    ]
    get_information.restype = ctypes.c_int
    invalid_handle = ctypes.c_void_p(-1).value
    handles: list[int] = []
    try:
        for segment in segments:
            if type(segment) is not EvidenceSegmentDescriptor:
                raise EvidenceSourceError(
                    "Windows evidence lease requires exact segment descriptors"
                )
            current = _inspect_regular(_absolute_path(segment.path))
            if _metadata_identity(current) != segment.identity():
                raise EvidenceSourceChangedError(
                    "an evidence segment changed before its Windows lease opened"
                )
            handle_value = create_file(
                segment.path,
                0x80000000,  # GENERIC_READ
                0x00000001,  # FILE_SHARE_READ (deny write/delete sharing)
                None,
                3,  # OPEN_EXISTING
                # SEQUENTIAL_SCAN | NORMAL | OPEN_REPARSE_POINT.  The final flag
                # prevents a last-component symlink swap from being followed.
                0x08200080,
                None,
            )
            handle = int(handle_value or 0)
            if not handle or handle == invalid_handle:
                raise EvidenceSourceError("a Windows evidence read lease could not be acquired")
            handles.append(handle)
            information = _ByHandleFileInformation()
            if not get_information(
                ctypes.c_void_p(handle),
                ctypes.byref(information),
            ):
                raise EvidenceSourceError(
                    "a Windows evidence handle identity could not be verified"
                )
            file_index = (int(information.nFileIndexHigh) << 32) | int(information.nFileIndexLow)
            file_size = (int(information.nFileSizeHigh) << 32) | int(information.nFileSizeLow)
            if (
                information.dwFileAttributes & 0x00000400  # REPARSE_POINT
                or segment.inode <= 0
                or file_index <= 0
                or file_index != segment.inode
                or file_size != segment.size_bytes
            ):
                raise EvidenceSourceChangedError(
                    "a Windows evidence handle differs from its attested file identity"
                )
            # Re-read the path only after the exact handle is held.  A correct
            # ordinary path can no longer be renamed; a transient junction race
            # is caught by the handle identity comparison above.
            current = _inspect_regular(_absolute_path(segment.path))
            if _metadata_identity(current) != segment.identity():
                raise EvidenceSourceChangedError(
                    "an evidence segment changed while its Windows lease opened"
                )
    except BaseException:
        _close_windows_handles(handles)
        raise
    return handles


@contextmanager
def _verified_windows_source_handles(
    segments: Sequence[EvidenceSegmentDescriptor],
) -> Iterator[None]:
    """Temporarily pin EWF segment identities while libewf opens by path."""

    if os.name != "nt":
        yield
        return
    handles = _open_verified_windows_read_handles(segments)
    body_error: BaseException | None = None
    try:
        yield
    except BaseException as exc:
        body_error = exc
        raise
    finally:
        failures = _close_windows_handles(handles)
        if failures:
            if body_error is not None:
                body_error.add_note("one or more Windows evidence handles failed to close")
            else:
                raise EvidenceSourceError(
                    "a temporary Windows evidence read lease could not be released"
                )


class EvidenceSourceRuntimeGuard:
    """Sticky runtime custody guard for one exact physical evidence source.

    Every checkpoint invokes :func:`assert_evidence_source_current`.  Once any
    checkpoint fails, the guard stays violated even if the physical files are later
    restored.  Its telemetry intentionally contains no local path or exception text.
    """

    def __init__(
        self,
        attestation: EvidenceSourceAttestation,
        *,
        study_lease: EvidenceStudyLease | None = None,
    ) -> None:
        if type(attestation) is not EvidenceSourceAttestation:
            raise EvidenceSourceError(
                "runtime evidence guard requires an exact evidence-source attestation"
            )
        if study_lease is not None:
            # Exact types are intentional here: the guard must not accept a
            # duck-typed object that merely claims to hold an immutable source.
            if type(study_lease) is not EvidenceStudyLease:
                raise EvidenceSourceError("runtime evidence guard requires an exact study lease")
            study_lease.assert_source(attestation)
            study_lease.register_runtime_guard(attestation)
        self.attestation = attestation
        self._study_lease = study_lease
        self._source_attestation_sha256 = evidence_source_attestation_sha256(attestation)
        self._checks: list[dict[str, object]] = []
        self._violation_detected = False
        self._first_violation_checkpoint: str | None = None
        self._lease_handles: list[int] = []
        self._lease_mode = (
            WINDOWS_STUDY_READ_LEASE_MODE
            if study_lease is not None
            else (WINDOWS_READ_LEASE_MODE if os.name == "nt" else NO_READ_LEASE_MODE)
        )
        self._lease_acquired = False
        self._lease_started = False
        self._lease_closed = False
        self._preverified_disk_open_authorized = False
        self._lock = threading.Lock()

    @property
    def violation_detected(self) -> bool:
        with self._lock:
            return self._violation_detected

    def acquire_read_lease(self) -> None:
        """Deny new Windows write/delete opens while the graph uses the source.

        POSIX has no equivalent mandatory share-mode primitive, so cryptographic
        boundary verification remains the control there.  On Windows every
        physical segment is opened with ``FILE_SHARE_READ`` only.
        """

        with self._lock:
            if self._lease_started or self._lease_acquired or self._lease_handles:
                raise EvidenceSourceError("runtime evidence read lease is already active")
            if self._lease_closed:
                raise EvidenceSourceError("runtime evidence read lease cannot be reopened")
            # Track the lifecycle on every platform.  POSIX has no mandatory
            # share-mode lease, but a second acquire must still be rejected and
            # telemetry must prove that the pre-open lifecycle ran.
            self._lease_started = True
            if self._study_lease is not None:
                self._study_lease.assert_active(self.attestation)
                self._lease_acquired = True
                return
            if os.name != "nt":
                return
            try:
                handles = _open_verified_windows_read_handles(self.attestation.segments)
            except BaseException:
                self._lease_handles = []
                self._violation_detected = True
                if self._first_violation_checkpoint is None:
                    self._first_violation_checkpoint = "read_lease_acquire"
                raise
            self._lease_handles = handles
            self._lease_acquired = True

    def close(self) -> None:
        """Release every platform lease exactly once."""

        with self._lock:
            if self._lease_closed:
                return
            if self._study_lease is not None:
                # The per-run guard releases only its delegated capability.  The
                # exact study lease keeps the Windows share-mode handles open until
                # every cell in this execution session has finished.
                self._study_lease.release_runtime_guard(self.attestation)
                self._lease_closed = True
                return
            if os.name == "nt" and self._lease_handles:
                failures = _close_windows_handles(self._lease_handles)
                self._lease_handles = []
                self._lease_closed = True
                if failures:
                    self._violation_detected = True
                    if self._first_violation_checkpoint is None:
                        self._first_violation_checkpoint = "read_lease_close"
                    raise EvidenceSourceError("a Windows evidence read lease could not be released")
            self._lease_handles = []
            self._lease_closed = True

    def check(self, checkpoint: str, *, full_content: bool = False) -> None:
        """Check the exact source now, retaining any violation permanently."""

        if not isinstance(checkpoint, str) or not checkpoint.strip():
            raise EvidenceSourceError("runtime evidence checkpoint must be non-empty text")
        normalized = checkpoint.strip()
        check_type = (
            RUNTIME_STUDY_PINNED_CONTENT_CHECK
            if full_content and self._study_lease is not None
            else (RUNTIME_FULL_CONTENT_CHECK if full_content else RUNTIME_METADATA_CHECK)
        )
        with self._lock:
            index = len(self._checks)
            if self._violation_detected:
                self._checks.append(
                    {
                        "index": index,
                        "checkpoint": normalized,
                        "check_type": check_type,
                        "status": "sticky_violation",
                    }
                )
                raise EvidenceSourceChangedError(
                    "evidence source runtime integrity was previously violated"
                )
            try:
                if self._study_lease is not None:
                    self._study_lease.assert_active(self.attestation)
                assert_evidence_source_current(self.attestation)
                if full_content and self._study_lease is None:
                    assert_evidence_source_content_current(self.attestation)
            except EvidenceSourceError as exc:
                self._violation_detected = True
                self._first_violation_checkpoint = normalized
                self._checks.append(
                    {
                        "index": index,
                        "checkpoint": normalized,
                        "check_type": check_type,
                        "status": "violation",
                    }
                )
                raise EvidenceSourceChangedError(
                    "evidence source changed during guarded execution"
                ) from exc
            self._checks.append(
                {
                    "index": index,
                    "checkpoint": normalized,
                    "check_type": check_type,
                    "status": "ok",
                }
            )

    def authorize_preverified_disk_open(
        self,
        attestation: EvidenceSourceAttestation,
    ) -> None:
        """Authorize one hash-free parser open under an active Windows read lease.

        ``DiskImage`` normally computes the complete raw/EWF logical-media digest
        in its constructor.  A study lease already performs that expensive check
        at the study boundary and then keeps every physical segment under a
        Windows share-mode lease that denies write/delete opens.
        This method is the narrow capability check which permits ``DiskImage`` to
        reuse the exact attestation without re-reading the whole image for every
        cell.

        The authorization is deliberately unavailable on POSIX: a metadata check
        cannot replace a mandatory immutable-source lease there.  It also requires
        the immediately preceding ``pre_disk_open`` checkpoint to be either a
        complete content hash or a content hash delegated to the active study
        lease.  Merely constructing a guard is never sufficient.
        """

        if type(attestation) is not EvidenceSourceAttestation:
            raise EvidenceSourceError(
                "preverified disk open requires an exact evidence-source attestation"
            )
        if os.name != "nt":
            raise EvidenceSourceError("preverified disk open requires Windows share-mode custody")
        with self._lock:
            if attestation != self.attestation:
                raise EvidenceSourceError(
                    "preverified disk open requested a different evidence source"
                )
            if self._violation_detected:
                raise EvidenceSourceChangedError(
                    "preverified disk open cannot use a violated evidence guard"
                )
            if self._preverified_disk_open_authorized:
                raise EvidenceSourceError(
                    "preverified disk open authorization was already consumed"
                )
            if not self._lease_started or not self._lease_acquired or self._lease_closed:
                raise EvidenceSourceError("preverified disk open requires an active read lease")
            if self._study_lease is not None:
                self._study_lease.assert_active(attestation)
            elif len(self._lease_handles) != len(attestation.segments):
                raise EvidenceSourceError(
                    "preverified disk open is not holding every source segment"
                )
            if not self._checks:
                raise EvidenceSourceError(
                    "preverified disk open lacks its content-boundary checkpoint"
                )
            boundary = self._checks[-1]
            expected_check_type = (
                RUNTIME_STUDY_PINNED_CONTENT_CHECK
                if self._study_lease is not None
                else RUNTIME_FULL_CONTENT_CHECK
            )
            if (
                boundary.get("checkpoint") != "pre_disk_open"
                or boundary.get("check_type") != expected_check_type
                or boundary.get("status") != "ok"
            ):
                raise EvidenceSourceError(
                    "preverified disk open lacks the exact successful pre-open boundary"
                )
            # A fresh runtime guard represents one exact cell and may authorize
            # only one parser construction.  A failed dfVFS open therefore cannot
            # silently retry against a path whose parser state is no longer known.
            self._preverified_disk_open_authorized = True

    def telemetry(self) -> dict[str, object]:
        """Return a path-free deterministic snapshot suitable for run telemetry."""

        with self._lock:
            checks = [dict(item) for item in self._checks]
            read_lease: dict[str, object] = {
                "mode": self._lease_mode,
                "started": self._lease_started,
                "acquired": self._lease_acquired,
                "closed": self._lease_closed,
                "open_handle_count": len(self._lease_handles),
            }
            if self._study_lease is not None:
                read_lease.update(
                    {
                        "delegated": True,
                        "study_session_sha256": self._study_lease.session_sha256,
                    }
                )
            return {
                "schema_id": EVIDENCE_RUNTIME_INTEGRITY_SCHEMA_ID,
                "enabled": True,
                "source_attestation_sha256": self._source_attestation_sha256,
                "source_sha256": self.attestation.sha256,
                "source_type": self.attestation.source_type,
                "segment_count": len(self.attestation.segments),
                "check_count": len(checks),
                "checks": checks,
                "violation_detected": self._violation_detected,
                "first_violation_checkpoint": self._first_violation_checkpoint,
                "read_lease": read_lease,
            }


class EvidenceStudyLease:
    """One cryptographic content boundary and immutable Windows lease per study session.

    A study session may execute hundreds of cells over the same image.  Re-reading
    every byte before and after every cell is correct but needlessly multiplies I/O.  On
    Windows we can establish the same invariant more efficiently:

    1. acquire share-mode handles that deny every new write/delete open;
    2. verify the complete raw/EWF logical-media SHA-256 once while those handles are held;
    3. give each cell a fresh :class:`EvidenceSourceRuntimeGuard` that performs the exact
       metadata/tool lifecycle checks while delegating content immutability to this lease;
    4. re-verify the complete content before releasing the handles.

    The optimization deliberately fails closed outside Windows.  POSIX does not provide an
    equivalent mandatory share-mode primitive, so callers there must retain the original
    per-cell full-content boundaries or introduce a separately attested read-only mount.
    """

    def __init__(self, attestation: EvidenceSourceAttestation) -> None:
        if type(attestation) is not EvidenceSourceAttestation:
            raise EvidenceSourceError(
                "study evidence lease requires an exact evidence-source attestation"
            )
        if os.name != "nt":
            raise EvidenceSourceError(
                "study evidence lease optimization requires Windows share-mode custody"
            )
        self.attestation = attestation
        nonce = secrets.token_bytes(32)
        payload = (
            EVIDENCE_STUDY_LEASE_SCHEMA_ID.encode("ascii")
            + bytes.fromhex(evidence_source_attestation_sha256(attestation))
            + nonce
        )
        self._session_sha256 = hashlib.sha256(payload).hexdigest()
        self._boundary_guard = EvidenceSourceRuntimeGuard(attestation)
        self._started = False
        self._completion_verified = False
        self._closed = False
        self._run_guard_count = 0
        self._active_run_guard_count = 0
        self._lock = threading.RLock()

    @property
    def session_sha256(self) -> str:
        return self._session_sha256

    @property
    def active(self) -> bool:
        with self._lock:
            return self._started and not self._closed

    @property
    def active_run_guard_count(self) -> int:
        with self._lock:
            return self._active_run_guard_count

    def assert_source(self, attestation: EvidenceSourceAttestation) -> None:
        if type(attestation) is not EvidenceSourceAttestation:
            raise EvidenceSourceError("study lease source has an unsupported type")
        if attestation != self.attestation:
            raise EvidenceSourceError("study lease was created for a different source")

    def start(self) -> None:
        """Acquire the immutable share lease and verify the pinned content once."""

        with self._lock:
            if self._started or self._closed:
                raise EvidenceSourceError("study evidence lease cannot be started twice")
            try:
                self._boundary_guard.acquire_read_lease()
                self._boundary_guard.check(
                    "study_session_start",
                    full_content=True,
                )
            except BaseException as exc:
                try:
                    self._boundary_guard.close()
                except EvidenceSourceError:
                    exc.add_note("the Windows study lease cleanup also failed")
                self._closed = True
                raise
            self._started = True

    def assert_active(self, attestation: EvidenceSourceAttestation) -> None:
        """Require this exact, violation-free lease while a cell is executing."""

        with self._lock:
            self.assert_source(attestation)
            if not self._started or self._closed:
                raise EvidenceSourceError("study evidence lease is not active")
            boundary = self._boundary_guard.telemetry()
            if boundary.get("violation_detected") is not False:
                raise EvidenceSourceChangedError(
                    "study evidence lease previously detected a source violation"
                )
            lease = boundary.get("read_lease")
            if not isinstance(lease, dict):
                raise EvidenceSourceError("study evidence lease telemetry is missing")
            if (
                lease.get("mode") != WINDOWS_READ_LEASE_MODE
                or lease.get("started") is not True
                or lease.get("acquired") is not True
                or lease.get("closed") is not False
                or lease.get("open_handle_count") != len(self.attestation.segments)
            ):
                raise EvidenceSourceError("study evidence lease is not holding every segment")

    def register_runtime_guard(self, attestation: EvidenceSourceAttestation) -> None:
        """Register one exact live cell so the parent lease cannot close beneath it."""

        with self._lock:
            self.assert_active(attestation)
            self._run_guard_count += 1
            self._active_run_guard_count += 1

    def release_runtime_guard(self, attestation: EvidenceSourceAttestation) -> None:
        """Release one delegated cell capability without releasing source handles."""

        with self._lock:
            self.assert_source(attestation)
            if not self._started or self._closed:
                raise EvidenceSourceError("study evidence lease is not active")
            if self._active_run_guard_count < 1:
                raise EvidenceSourceError("study evidence lease guard count underflow")
            self._active_run_guard_count -= 1

    def new_runtime_guard(self) -> EvidenceSourceRuntimeGuard:
        """Create and register a fresh per-cell telemetry guard."""

        with self._lock:
            self.assert_active(self.attestation)
            return EvidenceSourceRuntimeGuard(
                self.attestation,
                study_lease=self,
            )

    def close(self) -> None:
        """Verify the completion boundary, then release all share-mode handles."""

        with self._lock:
            if self._closed:
                return
            if not self._started:
                self._closed = True
                raise EvidenceSourceError("study evidence lease was never started")
            if self._active_run_guard_count:
                raise EvidenceSourceError("study evidence lease still has active runtime guards")
            failure: EvidenceSourceError | None = None
            interruption: BaseException | None = None
            try:
                self._boundary_guard.check(
                    "study_session_completion",
                    full_content=True,
                )
                self._completion_verified = True
            except EvidenceSourceError as exc:
                failure = exc
            except BaseException as exc:
                interruption = exc
            try:
                self._boundary_guard.close()
            except EvidenceSourceError as exc:
                failure = failure or exc
            self._closed = True
            if interruption is not None:
                if failure is not None:
                    interruption.add_note("the Windows study lease cleanup also failed")
                raise interruption
            if failure is not None:
                raise EvidenceSourceChangedError(
                    "study evidence lease completion boundary failed"
                ) from failure

    def telemetry(self) -> dict[str, object]:
        """Return a path-free record for a caller-held custody journal."""

        with self._lock:
            return {
                "schema_id": EVIDENCE_STUDY_LEASE_SCHEMA_ID,
                "session_sha256": self._session_sha256,
                "source_attestation_sha256": evidence_source_attestation_sha256(self.attestation),
                "source_sha256": self.attestation.sha256,
                "source_type": self.attestation.source_type,
                "segment_count": len(self.attestation.segments),
                "started": self._started,
                "completion_verified": self._completion_verified,
                "closed": self._closed,
                "run_guard_count": self._run_guard_count,
                "active_run_guard_count": self._active_run_guard_count,
                "boundary": self._boundary_guard.telemetry(),
            }


def _absolute_path(value: str | os.PathLike[str]) -> Path:
    try:
        raw = os.fspath(value)
    except TypeError as exc:
        raise EvidenceSourceError("evidence source path is not path-like") from exc
    if not isinstance(raw, str) or not raw:
        raise EvidenceSourceError("evidence source path must be non-empty text")
    return Path(os.path.normpath(os.path.abspath(raw)))


def _path_key(value: str | os.PathLike[str]) -> str:
    return os.path.normcase(str(_absolute_path(value)))


def _reject_unsafe_path_ancestry(path: Path) -> None:
    """Reject symlink/reparse traversal in every non-root path component.

    ``lstat`` of only the final evidence file follows parent junctions on
    Windows.  A lease would then pin the junction target while dfVFS later
    reopens the mutable lexical path.  Inspect each ancestor without following
    its final component and reject all reparse points, including directory
    junctions that are not reported as POSIX-style symlinks.
    """

    absolute = _absolute_path(path)
    anchor = os.path.normcase(os.path.normpath(absolute.anchor))
    components = tuple(reversed(absolute.parents)) + (absolute,)
    for component in components:
        if os.path.normcase(os.path.normpath(str(component))) == anchor:
            continue
        try:
            metadata = component.lstat()
        except OSError as exc:
            raise EvidenceSourceError(
                "evidence source path ancestry could not be inspected"
            ) from exc
        reparse_attributes = int(getattr(metadata, "st_file_attributes", 0))
        is_junction = False
        junction_check = getattr(component, "is_junction", None)
        if callable(junction_check):
            try:
                is_junction = bool(junction_check())
            except OSError as exc:
                raise EvidenceSourceError(
                    "evidence source path ancestry could not be inspected"
                ) from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or is_junction
            or reparse_attributes & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        ):
            raise EvidenceSourceError(
                "evidence source paths must not traverse symlinks or reparse points"
            )
        if component != absolute and not stat.S_ISDIR(metadata.st_mode):
            raise EvidenceSourceError("an evidence source ancestor is not a directory")


def is_ewf_source(path: str | os.PathLike[str]) -> bool:
    """Return whether ``path`` names a supported EWF segment/container suffix."""

    return _EWF_SUFFIX_RE.search(os.fspath(path)) is not None


def ewf_segment_paths(path: str | os.PathLike[str]) -> tuple[Path, ...]:
    """Return the complete ordered EWF segment set for any supplied segment."""

    primary = _absolute_path(path)
    globber, _factory = _pyewf_bindings()
    return _discover_ewf_segments(primary, globber)


def _discover_raw_segments(primary: Path) -> tuple[Path, ...]:
    """Return one raw file or its complete ordered ``.001`` segment set.

    Only a numeric segment ending in index one can be the primary path.  A lone
    ``.001`` remains a normal single-file raw image for backwards compatibility.
    If any later segment exists, membership must be contiguous so an incomplete
    acquisition fails closed instead of receiving a misleading digest.
    """

    primary = _absolute_path(primary)
    _reject_unsafe_path_ancestry(primary)
    match = _RAW_SEGMENT_NAME_RE.fullmatch(primary.name)
    if match is None:
        return (primary,)
    if int(match.group("index")) != 1:
        raise EvidenceSourceError(
            "split raw sources must be opened from their lead .001 segment"
        )
    base = match.group("base")
    base_key = os.path.normcase(base)
    width = len(match.group("index"))
    members: dict[int, Path] = {1: primary}
    try:
        children = primary.parent.iterdir()
    except OSError as exc:
        raise EvidenceSourceError("split raw segment directory could not be inspected") from exc
    entries_seen = 0
    for candidate in children:
        entries_seen += 1
        if entries_seen > _MAX_RAW_DIRECTORY_ENTRIES:
            raise EvidenceSourceError(
                "split raw segment directory exceeds the inspection safety limit"
            )
        candidate_match = _RAW_SEGMENT_NAME_RE.fullmatch(candidate.name)
        if candidate_match is None:
            continue
        if os.path.normcase(candidate_match.group("base")) != base_key:
            continue
        index_text = candidate_match.group("index")
        index = int(index_text)
        if index < 1:
            continue
        if index > _MAX_RAW_SEGMENTS:
            raise EvidenceSourceError("split raw segment index exceeds the safety limit")
        # Preserve the width of the lead segment while allowing the natural
        # rollover from .999 to .1000.  Alternate zero padding (for example
        # .002 and .0002) is ambiguous and must not be ignored silently.
        expected_name = f"{index:0{width}d}"
        if index_text != expected_name:
            raise EvidenceSourceError(
                "split raw segment names use ambiguous numeric padding"
            )
        candidate = _absolute_path(candidate)
        existing = members.get(index)
        if existing is not None and _path_key(existing) != _path_key(candidate):
            raise EvidenceSourceError("split raw segment indexes must be unique")
        members[index] = candidate
        if len(members) > _MAX_RAW_SEGMENTS:
            raise EvidenceSourceError("split raw source exceeds the segment safety limit")
    if set(members) == {1}:
        return (primary,)
    ordered_indexes = sorted(members)
    for expected_index, observed_index in enumerate(ordered_indexes, start=1):
        if observed_index == expected_index:
            continue
        gap_end = min(observed_index, expected_index + 8)
        missing = tuple(range(expected_index, gap_end))
        formatted = ", ".join(f"{index:0{width}d}" for index in missing)
        suffix = " ..." if observed_index - expected_index > len(missing) else ""
        raise EvidenceSourceError(
            f"split raw source is missing segment(s): {formatted}{suffix}"
        )
    ordered = tuple(members[index] for index in ordered_indexes)
    if _path_key(ordered[0]) != _path_key(primary):
        raise EvidenceSourceError("split raw primary path must identify the first segment")
    return ordered


def raw_segment_paths(path: str | os.PathLike[str]) -> tuple[Path, ...]:
    """Return the validated ordered physical files behind a raw image path."""

    return _discover_raw_segments(_absolute_path(path))


def _inspect_regular(path: Path) -> os.stat_result:
    _reject_unsafe_path_ancestry(path)
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise EvidenceSourceError("evidence source file could not be inspected") from exc
    if stat.S_ISLNK(metadata.st_mode) or int(getattr(metadata, "st_file_attributes", 0)) & int(
        getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    ):
        raise EvidenceSourceError(
            "evidence source files must not be symbolic links or reparse points"
        )
    if not stat.S_ISREG(metadata.st_mode):
        raise EvidenceSourceError("evidence source path is not a regular file")
    return metadata


def _metadata_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(metadata.st_ctime_ns),
    )


def _opened_path_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    """Fields comparable between Windows path-stat and descriptor-stat results."""

    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
    )


def _open_flags() -> int:
    flags = os.O_RDONLY
    for optional in ("O_BINARY", "O_CLOEXEC", "O_NOINHERIT", "O_NOFOLLOW", "O_NONBLOCK"):
        flags |= int(getattr(os, optional, 0))
    return flags


StableFileIdentity = tuple[int, int, int, int, int]


def stable_file_identity(metadata: os.stat_result) -> StableFileIdentity:
    """Return the strong stat identity of one file that this layer trusts.

    The tuple is ``(st_dev, st_ino, st_size, st_mtime_ns, st_ctime_ns)`` — the
    same identity :func:`assert_evidence_source_current` compares — and it
    carries ``st_ctime_ns`` on every platform.  ``ctime`` is the field that
    moves when a same-size overwrite restores ``mtime``; an identity that drops
    it (or zeroes it on Windows) cannot see that change, which is precisely the
    weaker check the scattered stat-identity copies were making.
    """

    return _metadata_identity(metadata)


def _read_stable_bounded(
    target: Path,
    maximum_bytes: int,
    *,
    consume: Callable[[bytes], object],
) -> tuple[int, StableFileIdentity]:
    """Read one bounded regular file, failing closed on any mid-read mutation.

    The strong stat identity is compared across a pre-open ``lstat``, the opened
    ``fstat``, a post-read ``fstat`` and a post-read ``lstat``, and the byte
    count must equal the opened size.  ``consume`` receives each block in order
    so a caller can buffer the bytes or fold them into a running digest without
    the loop being copied a fourth time.
    """

    if isinstance(maximum_bytes, bool) or not isinstance(maximum_bytes, int) or maximum_bytes <= 0:
        raise EvidenceSourceError("bounded read requires a positive maximum byte count")
    descriptor: int | None = None
    try:
        path_metadata = os.lstat(target)
        if (
            not stat.S_ISREG(path_metadata.st_mode)
            or stat.S_ISLNK(path_metadata.st_mode)
            or int(getattr(path_metadata, "st_file_attributes", 0))
            & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        ):
            raise EvidenceSourceError("bounded read source must be one regular non-link file")
        if not 0 < int(path_metadata.st_size) <= maximum_bytes:
            raise EvidenceSourceError("bounded read source is empty or exceeds its byte bound")
        descriptor = os.open(target, _open_flags())
        opened = os.fstat(descriptor)
        # A path-stat and a handle-stat of the same file agree on device, inode,
        # size and mtime but NOT on ctime on every platform (Windows reports the
        # creation time here, and it is not stable across the two calls), so the
        # inspection-to-open comparison uses the ctime-free identity — exactly as
        # the streaming attestation does.  ctime is still checked below, but only
        # between two stats of the same kind, where it is meaningful.
        if not stat.S_ISREG(opened.st_mode) or _opened_path_identity(
            path_metadata
        ) != _opened_path_identity(opened):
            raise EvidenceSourceChangedError(
                "bounded read source changed between inspection and opening"
            )
        total = 0
        while True:
            chunk = os.read(descriptor, min(EVIDENCE_HASH_CHUNK_BYTES, maximum_bytes + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum_bytes:
                raise EvidenceSourceError("bounded read source exceeds its byte bound")
            consume(chunk)
        after_fd = os.fstat(descriptor)
        current = os.lstat(target)
        if (
            _metadata_identity(opened) != _metadata_identity(after_fd)
            or _metadata_identity(path_metadata) != _metadata_identity(current)
            or _opened_path_identity(after_fd) != _opened_path_identity(current)
            or total != int(opened.st_size)
        ):
            raise EvidenceSourceChangedError("bounded read source changed while it was read")
        return total, stable_file_identity(after_fd)
    except EvidenceSourceError:
        raise
    except OSError as exc:
        raise EvidenceSourceError("bounded read source could not be read safely") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def read_bounded_stable_file(
    path: str | os.PathLike[str],
    *,
    maximum_bytes: int,
) -> tuple[bytes, StableFileIdentity]:
    """Return the exact bytes of one bounded regular file plus their stat identity.

    Raises :class:`EvidenceSourceChangedError` if the file is swapped, grown,
    truncated or rewritten while it is read.  The identity is the strong stat
    identity the bytes were read under, for a caller that freezes it and
    revalidates the same file later.
    """

    chunks: list[bytes] = []
    _total, identity = _read_stable_bounded(_absolute_path(path), maximum_bytes, consume=chunks.append)
    return b"".join(chunks), identity


def hash_bounded_stable_file(
    path: str | os.PathLike[str],
    *,
    maximum_bytes: int,
) -> tuple[str, int, StableFileIdentity]:
    """Stream the SHA-256 of one bounded regular file without buffering it whole.

    Shares the exact fail-closed read of :func:`read_bounded_stable_file`, but
    folds the bytes into a running digest so a multi-gigabyte checkpoint is
    identified without holding it in memory.  Returns the hex digest, the byte
    count, and the strong stat identity the digest was computed under.
    """

    digest = hashlib.sha256()
    total, identity = _read_stable_bounded(
        _absolute_path(path), maximum_bytes, consume=digest.update
    )
    return digest.hexdigest(), total, identity


def _attest_raw_multihash(
    path: Path,
    *,
    progress: EvidenceHashProgress | None = None,
    progress_total: EvidenceHashTotal | None = None,
) -> tuple[EvidenceSourceAttestation, str, str]:
    """Stream one stable physical file once and return SHA-256, MD5 and SHA-1."""

    path_metadata = _inspect_regular(path)
    try:
        descriptor = os.open(path, _open_flags())
    except OSError as exc:
        raise EvidenceSourceError("evidence source file could not be opened") from exc
    try:
        stream = os.fdopen(descriptor, "rb", buffering=0)
    except (OSError, ValueError) as exc:
        os.close(descriptor)
        raise EvidenceSourceError("evidence source stream could not be created") from exc

    digest = hashlib.sha256()
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    bytes_read = 0
    try:
        with stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise EvidenceSourceError("opened evidence source is not a regular file")
            if _opened_path_identity(path_metadata) != _opened_path_identity(before):
                raise EvidenceSourceChangedError(
                    "evidence source changed between inspection and opening"
                )
            if progress_total is not None:
                # The loop below reads exactly this many bytes — the size of the
                # descriptor that was just opened and identity-checked — and the
                # post-stream comparison against ``before.st_size`` proves it.
                progress_total(int(before.st_size))
            while True:
                chunk = stream.read(EVIDENCE_HASH_CHUNK_BYTES)
                if not chunk:
                    break
                digest.update(chunk)
                md5.update(chunk)
                sha1.update(chunk)
                bytes_read += len(chunk)
                # Reported after the block has already been consumed, so an
                # observer can never sit between a read and its digest update.
                if progress is not None:
                    progress(len(chunk))
            after = os.fstat(stream.fileno())
    except EvidenceSourceError:
        raise
    except OSError as exc:
        raise EvidenceSourceError("evidence source could not be read completely") from exc

    try:
        current = _inspect_regular(path)
    except EvidenceSourceError as exc:
        raise EvidenceSourceChangedError("evidence source changed after streaming") from exc
    if (
        _metadata_identity(before) != _metadata_identity(after)
        or _metadata_identity(path_metadata) != _metadata_identity(current)
        or _opened_path_identity(after) != _opened_path_identity(current)
        or bytes_read != int(before.st_size)
    ):
        raise EvidenceSourceChangedError("evidence source changed while SHA-256 was streamed")

    segment = EvidenceSegmentDescriptor.from_stat(path, current)
    return (
        EvidenceSourceAttestation(
            source_type="raw_file",
            digest_semantics=RAW_FILE_DIGEST_SEMANTICS,
            sha256=digest.hexdigest(),
            size_bytes=bytes_read,
            primary_path=str(path),
            segments=(segment,),
        ),
        md5.hexdigest(),
        sha1.hexdigest(),
    )


def _attest_raw_segment_set_multihash(
    primary: Path,
    *,
    progress: EvidenceHashProgress | None = None,
    progress_total: EvidenceHashTotal | None = None,
) -> tuple[EvidenceSourceAttestation, str, str]:
    """Stream a stable raw source once and return SHA-256, MD5 and SHA-1."""

    segments = _discover_raw_segments(primary)
    if len(segments) == 1:
        return _attest_raw_multihash(
            primary,
            progress=progress,
            progress_total=progress_total,
        )
    before = tuple(_inspect_regular(path) for path in segments)
    descriptors = tuple(
        EvidenceSegmentDescriptor.from_stat(path, metadata)
        for path, metadata in zip(segments, before, strict=True)
    )
    if progress_total is not None:
        # Every discovered segment is streamed as one logical medium, so the
        # work is the whole set.  The primary segment's own size is not a
        # measure of it, and treating it as one is what made a display count
        # a split source past its own total.
        progress_total(sum(int(metadata.st_size) for metadata in before))
    digest = hashlib.sha256()
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    bytes_read = 0
    with _verified_windows_source_handles(descriptors):
        for path, expected_metadata in zip(segments, before, strict=True):
            try:
                descriptor = os.open(path, _open_flags())
            except OSError as exc:
                raise EvidenceSourceError("split raw segment could not be opened") from exc
            try:
                stream = os.fdopen(descriptor, "rb", buffering=0)
            except (OSError, ValueError) as exc:
                os.close(descriptor)
                raise EvidenceSourceError("split raw segment stream could not be created") from exc
            segment_bytes = 0
            try:
                with stream:
                    opened = os.fstat(stream.fileno())
                    if not stat.S_ISREG(opened.st_mode):
                        raise EvidenceSourceError("opened split raw segment is not a regular file")
                    if _opened_path_identity(expected_metadata) != _opened_path_identity(opened):
                        raise EvidenceSourceChangedError(
                            "split raw segment changed between inspection and opening"
                        )
                    while True:
                        chunk = stream.read(EVIDENCE_HASH_CHUNK_BYTES)
                        if not chunk:
                            break
                        digest.update(chunk)
                        md5.update(chunk)
                        sha1.update(chunk)
                        segment_bytes += len(chunk)
                        bytes_read += len(chunk)
                        # The observer sees one continuous logical stream: it is
                        # told how much was just read, never which segment.
                        if progress is not None:
                            progress(len(chunk))
                    after_stream = os.fstat(stream.fileno())
            except EvidenceSourceError:
                raise
            except OSError as exc:
                raise EvidenceSourceError("split raw segment could not be read completely") from exc
            if (
                _metadata_identity(opened) != _metadata_identity(after_stream)
                or segment_bytes != int(opened.st_size)
            ):
                raise EvidenceSourceChangedError(
                    "split raw segment changed while SHA-256 was streamed"
                )
        try:
            observed_segments = _discover_raw_segments(primary)
            current = tuple(_inspect_regular(path) for path in observed_segments)
        except EvidenceSourceError as exc:
            raise EvidenceSourceChangedError(
                "a split raw segment changed while logical media was streamed"
            ) from exc
        if tuple(_path_key(path) for path in observed_segments) != tuple(
            _path_key(path) for path in segments
        ):
            raise EvidenceSourceChangedError(
                "split raw segment membership or ordering changed while hashing"
            )
        if any(
            _metadata_identity(first) != _metadata_identity(last)
            for first, last in zip(before, current, strict=True)
        ):
            raise EvidenceSourceChangedError(
                "a split raw segment changed while logical media was streamed"
            )

    return (
        EvidenceSourceAttestation(
            source_type="raw_segment_set",
            digest_semantics=RAW_SEGMENT_SET_DIGEST_SEMANTICS,
            sha256=digest.hexdigest(),
            size_bytes=bytes_read,
            primary_path=str(primary),
            segments=descriptors,
        ),
        md5.hexdigest(),
        sha1.hexdigest(),
    )


def _attest_raw_segment_set(
    primary: Path,
    *,
    progress: EvidenceHashProgress | None = None,
    progress_total: EvidenceHashTotal | None = None,
) -> EvidenceSourceAttestation:
    attestation, _md5, _sha1 = _attest_raw_segment_set_multihash(
        primary,
        progress=progress,
        progress_total=progress_total,
    )
    return attestation


def attest_raw_media_multihash(
    path: str | os.PathLike[str],
    *,
    progress: EvidenceHashProgress | None = None,
    progress_total: EvidenceHashTotal | None = None,
) -> tuple[EvidenceSourceAttestation, str, str]:
    """Return a stable SHA-256/MD5/SHA-1 attestation for raw logical media.

    Split RAW members are streamed in numeric order as one logical byte stream.
    Membership and metadata are checked before and after streaming, and every
    physical member is opened through the same fail-closed path protections as
    the canonical evidence-source attestation.

    ``progress`` and ``progress_total`` are the pair
    :func:`attest_evidence_source` already takes, forwarded unchanged to the
    single stream below. They exist for the operator-driven re-hash of a whole
    medium, which runs for minutes: the pass that reads every block is the only
    place that can honestly say how far it has got. Omitting them leaves the
    attestation byte for byte identical.
    """

    primary = _absolute_path(path)
    if is_ewf_source(primary):
        raise EvidenceSourceError("raw-media hashing does not accept EWF sources")
    return _attest_raw_segment_set_multihash(
        primary,
        progress=progress,
        progress_total=progress_total,
    )


def _pyewf_bindings() -> tuple[EwfGlob, EwfHandleFactory]:
    try:
        import pyewf
    except Exception as exc:
        raise EvidenceSourceError("libewf-python is required to attest EWF logical media") from exc
    return pyewf.glob, pyewf.handle


def _discover_ewf_segments(primary: Path, globber: EwfGlob) -> tuple[Path, ...]:
    _reject_unsafe_path_ancestry(primary)
    try:
        discovered = tuple(_absolute_path(item) for item in globber(str(primary)))
    except EvidenceSourceError:
        raise
    except Exception as exc:
        raise EvidenceSourceError("libewf could not discover the EWF segment set") from exc
    if not discovered:
        raise EvidenceSourceError("libewf returned an empty EWF segment set")
    keys = tuple(_path_key(item) for item in discovered)
    if len(set(keys)) != len(keys):
        raise EvidenceSourceError("libewf returned duplicate EWF segments")
    if _path_key(primary) not in keys:
        raise EvidenceSourceError("the supplied EWF path is absent from its discovered segment set")
    return discovered


def _attest_ewf(
    primary: Path,
    *,
    globber: EwfGlob,
    handle_factory: EwfHandleFactory,
    progress: EvidenceHashProgress | None = None,
    progress_total: EvidenceHashTotal | None = None,
) -> EvidenceSourceAttestation:
    segments = _discover_ewf_segments(primary, globber)
    before = tuple(_inspect_regular(path) for path in segments)
    descriptors = tuple(
        EvidenceSegmentDescriptor.from_stat(path, metadata)
        for path, metadata in zip(segments, before, strict=True)
    )
    digest = hashlib.sha256()
    bytes_read = 0
    with _verified_windows_source_handles(descriptors):
        handle = None
        try:
            handle = handle_factory()
            handle.open([str(path) for path in segments])
            media_size = handle.get_media_size()
            if isinstance(media_size, bool) or not isinstance(media_size, int) or media_size < 0:
                raise EvidenceSourceError("libewf returned an invalid logical media size")
            if progress_total is not None:
                # The decoded logical media the loop below is bounded by. Only
                # libewf can state it, and only now that the container is open:
                # the compressed segments on disk say nothing about how much
                # this pass will actually read.
                progress_total(media_size)
            seek = getattr(handle, "seek", None)
            if callable(seek):
                seek(0)
            while bytes_read < media_size:
                requested = min(EVIDENCE_HASH_CHUNK_BYTES, media_size - bytes_read)
                chunk = handle.read(requested)
                if not isinstance(chunk, bytes | bytearray | memoryview):
                    raise EvidenceSourceError("libewf returned a non-binary logical media chunk")
                payload = bytes(chunk)
                if not payload:
                    raise EvidenceSourceError("libewf ended before the declared logical media size")
                if len(payload) > requested:
                    raise EvidenceSourceError(
                        "libewf returned more logical media bytes than requested"
                    )
                digest.update(payload)
                bytes_read += len(payload)
                # Decoded logical media, not container bytes: this is the pass
                # that decompresses, and therefore the one worth watching.
                if progress is not None:
                    progress(len(payload))
        except EvidenceSourceError:
            raise
        except Exception as exc:
            raise EvidenceSourceError("EWF logical media could not be opened and streamed") from exc
        finally:
            if handle is not None:
                close = getattr(handle, "close", None)
                if callable(close):
                    try:
                        close()
                    except Exception:
                        pass

        try:
            after = tuple(_inspect_regular(path) for path in segments)
        except EvidenceSourceError as exc:
            raise EvidenceSourceChangedError(
                "an EWF segment changed while logical media was streamed"
            ) from exc
        if any(
            _metadata_identity(first) != _metadata_identity(last)
            for first, last in zip(before, after, strict=True)
        ):
            raise EvidenceSourceChangedError(
                "an EWF segment changed while logical media was streamed"
            )

    return EvidenceSourceAttestation(
        source_type="ewf_logical_media",
        digest_semantics=EWF_LOGICAL_DIGEST_SEMANTICS,
        sha256=digest.hexdigest(),
        size_bytes=bytes_read,
        primary_path=str(primary),
        segments=descriptors,
    )


def attest_physical_file(
    path: str | os.PathLike[str],
) -> VerifiedPhysicalFileAttestation:
    """Hash exact physical file bytes, even when ``path`` is an EWF segment.

    This is intentionally narrower than :func:`attest_evidence_source`, whose EWF
    digest covers decoded logical media.  A preparation manifest pins container
    files individually, so its one-time verifier needs exact-file semantics for
    ``.E01``/``.E02`` as well as raw, PCAP and memory files.
    """

    attestation, md5, sha1 = _attest_raw_multihash(_absolute_path(path))
    return VerifiedPhysicalFileAttestation(
        attestation=attestation,
        md5=md5,
        sha1=sha1,
        _proof=_physical_file_proof(attestation, md5=md5, sha1=sha1),
    )


def attest_evidence_source(
    path: str | os.PathLike[str],
    *,
    ewf_glob: EwfGlob | None = None,
    ewf_handle_factory: EwfHandleFactory | None = None,
    progress: EvidenceHashProgress | None = None,
    progress_total: EvidenceHashTotal | None = None,
) -> EvidenceSourceAttestation:
    """Stream a raw file, split raw set, or EWF medium into canonical SHA-256.

    ``progress`` is an optional observer, called with the size of each block
    after that block has been read and hashed.  ``progress_total`` is its
    companion, called once with the number of bytes this pass will read in
    total, before the first block, so the two report the same measurement.  Both
    change nothing about the pass itself, so omitting them leaves the
    attestation byte-for-byte identical.
    """

    primary = _absolute_path(path)
    if not is_ewf_source(primary):
        return _attest_raw_segment_set(
            primary,
            progress=progress,
            progress_total=progress_total,
        )
    if ewf_glob is None or ewf_handle_factory is None:
        default_glob, default_factory = _pyewf_bindings()
        ewf_glob = ewf_glob or default_glob
        ewf_handle_factory = ewf_handle_factory or default_factory
    return _attest_ewf(
        primary,
        globber=ewf_glob,
        handle_factory=ewf_handle_factory,
        progress=progress,
        progress_total=progress_total,
    )


def attest_evidence_source_retaining_file_digests(
    path: str | os.PathLike[str],
    *,
    progress: EvidenceHashProgress | None = None,
    progress_total: EvidenceHashTotal | None = None,
) -> tuple[EvidenceSourceAttestation, VerifiedPhysicalFileAttestation | None]:
    """Attest a source and keep the MD5 and SHA-1 the same pass already computed.

    :func:`_attest_raw_multihash` has always updated MD5, SHA-1 and SHA-256 over
    one stream, and :func:`attest_evidence_source` has always discarded the first
    two.  A consumer that needed them therefore streamed the medium a second time,
    which on a 20 GiB image is a whole extra pass for bytes the custody pass had
    already digested and thrown away.

    Retaining them is not a weaker check than recomputing them.  It is a stronger
    one: these digests come from the stream that carried the stat-identity
    comparison before and after reading, so they are bound to the same proven-
    stable bytes as the canonical SHA-256, whereas a second pass is a second race
    against the file.  The proof minted here is the same process-local HMAC that
    :func:`attest_physical_file` mints, so a caller cannot attach digests to an
    attestation that was issued without them.

    The companion is returned only for a single raw file, whose exact-file digest
    semantics the companion asserts.  A split raw set is not one file, and an EWF
    container's logical-media digest is not its physical bytes; both return
    ``None`` rather than a companion whose semantics would be a lie.
    """

    primary = _absolute_path(path)
    if is_ewf_source(primary) or len(_discover_raw_segments(primary)) != 1:
        return (
            attest_evidence_source(
                primary,
                progress=progress,
                progress_total=progress_total,
            ),
            None,
        )
    attestation, md5, sha1 = _attest_raw_multihash(
        primary,
        progress=progress,
        progress_total=progress_total,
    )
    return attestation, VerifiedPhysicalFileAttestation(
        attestation=attestation,
        md5=md5,
        sha1=sha1,
        _proof=_physical_file_proof(attestation, md5=md5, sha1=sha1),
    )


def describe_pinned_evidence_source(
    path: str | os.PathLike[str],
    *,
    source_type: EvidenceSourceType,
    digest_semantics: str,
    sha256: str,
    size_bytes: int,
    segment_count: int,
    container_size_bytes: int,
    ewf_glob: EwfGlob | None = None,
) -> EvidenceSourceAttestation:
    """Build an exact physical descriptor around caller-pinned portable identity.

    This function deliberately does **not** verify content and must never replace
    :func:`attest_evidence_source` for a standalone attestation.  Its only use is
    the handoff from an already sealed StudyLock into
    :class:`EvidenceStudyLease`: the caller first compares the complete physical
    descriptor digest with its caller-held pin, and ``EvidenceStudyLease.start``
    then verifies the full raw/EWF logical SHA-256 while exact Windows handles are
    held.  This avoids an otherwise redundant pre-session logical-media scan.
    """

    primary = _absolute_path(path)
    descriptors: tuple[EvidenceSegmentDescriptor, ...]
    if source_type == "raw_file":
        if is_ewf_source(primary):
            raise EvidenceSourceError("pinned raw evidence path has an EWF suffix")
        if len(_discover_raw_segments(primary)) != 1:
            raise EvidenceSourceError(
                "pinned split raw evidence must use raw_segment_set semantics"
            )
        metadata = _inspect_regular(primary)
        descriptors = (EvidenceSegmentDescriptor.from_stat(primary, metadata),)
        observed_container_size = int(metadata.st_size)
        if (
            segment_count != 1
            or container_size_bytes != observed_container_size
            or size_bytes != observed_container_size
        ):
            raise EvidenceSourceChangedError(
                "pinned raw evidence geometry differs from its physical descriptor"
            )
    elif source_type == "raw_segment_set":
        if is_ewf_source(primary):
            raise EvidenceSourceError("pinned split raw evidence path has an EWF suffix")
        paths = _discover_raw_segments(primary)
        if len(paths) < 2:
            raise EvidenceSourceError(
                "pinned raw_segment_set source does not contain multiple segments"
            )
        descriptors = tuple(
            EvidenceSegmentDescriptor.from_stat(segment_path, _inspect_regular(segment_path))
            for segment_path in paths
        )
        observed_container_size = sum(item.size_bytes for item in descriptors)
        if (
            segment_count != len(descriptors)
            or container_size_bytes != observed_container_size
            or size_bytes != observed_container_size
        ):
            raise EvidenceSourceChangedError(
                "pinned split raw geometry differs from its physical descriptor"
            )
    elif source_type == "ewf_logical_media":
        if not is_ewf_source(primary):
            raise EvidenceSourceError("pinned EWF evidence path lacks an EWF suffix")
        if ewf_glob is None:
            ewf_glob, _ = _pyewf_bindings()
        paths = _discover_ewf_segments(primary, ewf_glob)
        descriptors = tuple(
            EvidenceSegmentDescriptor.from_stat(segment_path, _inspect_regular(segment_path))
            for segment_path in paths
        )
        observed_container_size = sum(item.size_bytes for item in descriptors)
        if segment_count != len(descriptors) or container_size_bytes != observed_container_size:
            raise EvidenceSourceChangedError(
                "pinned EWF segment geometry differs from its physical descriptor"
            )
    else:
        raise EvidenceSourceError("pinned evidence source type is unsupported")

    return EvidenceSourceAttestation(
        source_type=source_type,
        digest_semantics=digest_semantics,
        sha256=sha256,
        size_bytes=size_bytes,
        primary_path=str(primary),
        segments=descriptors,
    )


def assert_evidence_source_current(
    attestation: EvidenceSourceAttestation,
    *,
    ewf_glob: EwfGlob | None = None,
) -> None:
    """Fail if paths, segment membership, or stable metadata changed since hashing."""

    if not isinstance(attestation, EvidenceSourceAttestation):
        raise EvidenceSourceError("disk source attestation has an unsupported type")
    if attestation.source_type == "ewf_logical_media":
        if ewf_glob is None:
            ewf_glob, _ = _pyewf_bindings()
        current_paths = _discover_ewf_segments(_absolute_path(attestation.primary_path), ewf_glob)
        if tuple(_path_key(path) for path in current_paths) != tuple(
            _path_key(segment.path) for segment in attestation.segments
        ):
            raise EvidenceSourceChangedError("EWF segment membership or ordering changed")
    elif attestation.source_type == "raw_segment_set":
        current_paths = _discover_raw_segments(_absolute_path(attestation.primary_path))
        if tuple(_path_key(path) for path in current_paths) != tuple(
            _path_key(segment.path) for segment in attestation.segments
        ):
            raise EvidenceSourceChangedError(
                "split raw segment membership or ordering changed"
            )
    elif attestation.source_type == "raw_file":
        current_paths = _discover_raw_segments(_absolute_path(attestation.primary_path))
        if tuple(_path_key(path) for path in current_paths) != tuple(
            _path_key(segment.path) for segment in attestation.segments
        ):
            raise EvidenceSourceChangedError(
                "raw source became a split segment set after attestation"
            )
    for segment in attestation.segments:
        try:
            current = _inspect_regular(_absolute_path(segment.path))
        except EvidenceSourceError as exc:
            raise EvidenceSourceChangedError(
                "an attested evidence source segment is no longer available"
            ) from exc
        if _metadata_identity(current) != segment.identity():
            raise EvidenceSourceChangedError(
                "an attested evidence source segment changed before model execution"
            )


def assert_evidence_source_content_current(
    attestation: EvidenceSourceAttestation,
    *,
    ewf_glob: EwfGlob | None = None,
    ewf_handle_factory: EwfHandleFactory | None = None,
) -> None:
    """Re-stream and cryptographically compare the exact raw/EWF evidence content.

    This boundary check closes the Windows same-size overwrite gap where creation
    time is stable and an attacker can restore ``mtime``.  EWF comparison uses the
    decoded logical-media SHA-256, identical to initial attestation semantics.
    """

    if type(attestation) is not EvidenceSourceAttestation:
        raise EvidenceSourceError("disk source attestation has an unsupported type")
    current = attest_evidence_source(
        attestation.primary_path,
        ewf_glob=ewf_glob,
        ewf_handle_factory=ewf_handle_factory,
    )
    if (
        current.source_type != attestation.source_type
        or current.digest_semantics != attestation.digest_semantics
        or current.size_bytes != attestation.size_bytes
        or tuple(_path_key(segment.path) for segment in current.segments)
        != tuple(_path_key(segment.path) for segment in attestation.segments)
        or current.sha256 != attestation.sha256
    ):
        raise EvidenceSourceChangedError(
            "evidence source content differs from its pinned cryptographic digest"
        )
