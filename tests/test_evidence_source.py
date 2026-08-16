import hashlib
import os
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

import forensic_agent.core.evidence_source as evidence_source_module
from forensic_agent.core.evidence_source import (
    EWF_LOGICAL_DIGEST_SEMANTICS,
    RAW_FILE_DIGEST_SEMANTICS,
    RAW_SEGMENT_SET_DIGEST_SEMANTICS,
    RUNTIME_FULL_CONTENT_CHECK,
    RUNTIME_STUDY_PINNED_CONTENT_CHECK,
    WINDOWS_READ_LEASE_MODE,
    WINDOWS_STUDY_READ_LEASE_MODE,
    EvidenceSegmentDescriptor,
    EvidenceSourceChangedError,
    EvidenceSourceError,
    EvidenceSourceRuntimeGuard,
    EvidenceStudyLease,
    VerifiedPhysicalDiskSource,
    VerifiedPhysicalFileAttestation,
    assert_evidence_source_content_current,
    assert_evidence_source_current,
    attest_evidence_source,
    attest_physical_file,
    bind_verified_physical_disk_source,
)


class _DecodedSegmentHandle:
    """Small libewf-shaped fake whose logical media is both fixture segments."""

    def __init__(self) -> None:
        self.opened: tuple[str, ...] = ()
        self._media = b""
        self._offset = 0
        self.closed = False

    def open(self, paths):
        self.opened = tuple(paths)
        if len(self.opened) != 2:
            raise OSError("incomplete EWF segment set")
        self._media = b"".join(Path(path).read_bytes() for path in self.opened)

    def get_media_size(self):
        return len(self._media)

    def seek(self, offset):
        self._offset = offset

    def read(self, size):
        chunk = self._media[self._offset : self._offset + size]
        self._offset += len(chunk)
        return chunk

    def get_hash_value(self, _name):
        raise AssertionError("stored EWF acquisition hashes must not define source identity")

    def close(self):
        self.closed = True


def _create_windows_junction(link: Path, target: Path) -> None:
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)],
        capture_output=True,
        check=False,
        text=True,
    )
    if result.returncode:
        pytest.skip("Windows junction creation is unavailable in this environment")


def test_windows_kernel_loader_fails_closed_when_platform_api_is_missing(monkeypatch):
    import ctypes

    monkeypatch.delattr(ctypes, "WinDLL", raising=False)

    with pytest.raises(EvidenceSourceError, match="Windows handle APIs are unavailable"):
        evidence_source_module._load_windows_kernel32()


def test_raw_source_sha256_is_over_exact_file_bytes(tmp_path):
    path = tmp_path / "disk.raw"
    payload = b"raw\x00media\xffbytes"
    path.write_bytes(payload)

    source = attest_evidence_source(path)

    assert source.sha256 == hashlib.sha256(payload).hexdigest()
    assert source.size_bytes == len(payload)
    assert source.digest_semantics == RAW_FILE_DIGEST_SEMANTICS
    assert source.source_type == "raw_file"
    assert source.container_size_bytes == len(payload)


def test_split_raw_source_binds_every_ordered_segment(tmp_path):
    first = tmp_path / "disk.001"
    second = tmp_path / "disk.002"
    third = tmp_path / "disk.003"
    first.write_bytes(b"first-")
    second.write_bytes(b"second-")
    third.write_bytes(b"third")

    source = attest_evidence_source(first)

    payload = first.read_bytes() + second.read_bytes() + third.read_bytes()
    assert source.source_type == "raw_segment_set"
    assert source.digest_semantics == RAW_SEGMENT_SET_DIGEST_SEMANTICS
    assert source.sha256 == hashlib.sha256(payload).hexdigest()
    assert source.size_bytes == len(payload)
    assert source.container_size_bytes == len(payload)
    assert tuple(Path(segment.path).name for segment in source.segments) == (
        "disk.001",
        "disk.002",
        "disk.003",
    )


def test_single_dot_001_remains_a_single_raw_file(tmp_path):
    first = tmp_path / "disk.001"
    first.write_bytes(b"single raw image")

    source = attest_evidence_source(first)

    assert source.source_type == "raw_file"
    assert source.digest_semantics == RAW_FILE_DIGEST_SEMANTICS
    assert len(source.segments) == 1


def test_single_dot_001_detects_a_segment_added_after_attestation(tmp_path):
    first = tmp_path / "disk.001"
    first.write_bytes(b"first")
    source = attest_evidence_source(first)

    (tmp_path / "disk.002").write_bytes(b"second")

    with pytest.raises(EvidenceSourceChangedError, match="became a split segment set"):
        assert_evidence_source_current(source)


def test_split_raw_accepts_natural_numeric_width_rollover(tmp_path):
    # A four-digit member after .999 is canonical, not a different image set.
    for index in range(1, 1001):
        (tmp_path / f"disk.{index:03d}").write_bytes(b"")

    source = attest_evidence_source(tmp_path / "disk.001")

    assert source.source_type == "raw_segment_set"
    assert len(source.segments) == 1000
    assert Path(source.segments[-1].path).name == "disk.1000"


def test_split_raw_rejects_ambiguous_zero_padding(tmp_path):
    (tmp_path / "disk.001").write_bytes(b"first")
    (tmp_path / "disk.0002").write_bytes(b"second")

    with pytest.raises(EvidenceSourceError, match="ambiguous numeric padding"):
        attest_evidence_source(tmp_path / "disk.001")


def test_nonlead_split_raw_segment_cannot_be_attested_as_complete(tmp_path):
    (tmp_path / "disk.001").write_bytes(b"first")
    second = tmp_path / "disk.002"
    second.write_bytes(b"second")

    with pytest.raises(EvidenceSourceError, match="lead \\.001 segment"):
        attest_evidence_source(second)


def test_split_raw_rejects_an_adversarially_large_segment_index(tmp_path):
    first = tmp_path / "disk.001"
    first.write_bytes(b"first")
    (tmp_path / "disk.999999999").write_bytes(b"not a valid member")

    with pytest.raises(EvidenceSourceError, match="index exceeds the safety limit"):
        attest_evidence_source(first)


def test_split_raw_membership_parse_failure_during_stream_is_a_change(
    tmp_path, monkeypatch
):
    first = tmp_path / "disk.001"
    (tmp_path / "disk.002").write_bytes(b"second")
    first.write_bytes(b"first")
    original = evidence_source_module._discover_raw_segments
    calls = 0

    def changed_membership(path):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise EvidenceSourceError("simulated concurrent numbering change")
        return original(path)

    monkeypatch.setattr(
        evidence_source_module,
        "_discover_raw_segments",
        changed_membership,
    )

    with pytest.raises(EvidenceSourceChangedError, match="changed while logical media"):
        attest_evidence_source(first)


def test_split_raw_membership_change_is_detected(tmp_path):
    first = tmp_path / "disk.001"
    second = tmp_path / "disk.002"
    first.write_bytes(b"first")
    second.write_bytes(b"second")
    source = attest_evidence_source(first)

    (tmp_path / "disk.003").write_bytes(b"new segment")

    with pytest.raises(EvidenceSourceChangedError, match="membership or ordering"):
        assert_evidence_source_current(source)


def test_split_raw_with_a_numbering_gap_fails_closed(tmp_path):
    first = tmp_path / "disk.001"
    third = tmp_path / "disk.003"
    first.write_bytes(b"first")
    third.write_bytes(b"third")

    with pytest.raises(EvidenceSourceError, match="missing segment.*002"):
        attest_evidence_source(first)


def test_split_raw_content_change_is_detected(tmp_path):
    first = tmp_path / "disk.001"
    second = tmp_path / "disk.002"
    first.write_bytes(b"first")
    second.write_bytes(b"second")
    source = attest_evidence_source(first)
    original = second.stat()

    second.write_bytes(b"SECOND")
    os.utime(second, ns=(original.st_atime_ns, original.st_mtime_ns))

    with pytest.raises(EvidenceSourceChangedError):
        assert_evidence_source_content_current(source)


def test_verified_physical_disk_requires_full_hash_issued_unforgeable_proofs(
    tmp_path: Path,
) -> None:
    path = tmp_path / "disk.raw"
    path.write_bytes(b"fully hashed physical evidence")

    issued = attest_physical_file(path)
    assert issued.md5 == hashlib.md5(path.read_bytes()).hexdigest()
    assert issued.sha1 == hashlib.sha1(path.read_bytes()).hexdigest()
    disk = bind_verified_physical_disk_source(path, (issued,))
    disk.assert_current_for_disk_open()

    with pytest.raises(EvidenceSourceError, match="full-hash verifier"):
        VerifiedPhysicalFileAttestation(
            attestation=issued.attestation,
            md5=issued.md5,
            sha1=issued.sha1,
            _proof="0" * 64,
        )
    with pytest.raises(EvidenceSourceError, match="full-hash verifier"):
        replace(issued, md5="0" * 32)
    with pytest.raises(EvidenceSourceError, match="binding factory"):
        VerifiedPhysicalDiskSource(
            primary_path=str(path.absolute()),
            components=(issued,),
            _proof="0" * 64,
        )

    path.write_bytes(b"same-length changed evidence!!")
    # Windows may coalesce two immediate same-size writes into the same observed
    # last-write timestamp.  This test exercises the reusable metadata guard, so
    # make the intended metadata drift deterministic; the separate full-boundary
    # test below covers a same-size overwrite with restored mtime.
    current = path.stat()
    os.utime(
        path,
        ns=(current.st_atime_ns, issued.segment.mtime_ns + 1_000_000_000),
    )
    with pytest.raises(EvidenceSourceChangedError):
        disk.assert_current_for_disk_open()


def test_verified_physical_ewf_rechecks_exact_segment_membership_and_order(
    tmp_path: Path,
) -> None:
    first = tmp_path / "disk.E01"
    second = tmp_path / "disk.E02"
    first.write_bytes(b"segment-one")
    second.write_bytes(b"segment-two")
    disk = bind_verified_physical_disk_source(
        first,
        (attest_physical_file(first), attest_physical_file(second)),
    )

    disk.assert_current_for_disk_open(ewf_glob=lambda _path: (first, second))
    with pytest.raises(EvidenceSourceChangedError, match="membership or ordering"):
        disk.assert_current_for_disk_open(ewf_glob=lambda _path: (second, first))


@pytest.mark.skipif(os.name != "nt", reason="Windows junction semantics")
def test_attestation_rejects_a_parent_junction_before_open(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "disk.raw").write_bytes(b"original")
    junction = tmp_path / "evidence"
    _create_windows_junction(junction, target)
    try:
        with pytest.raises(EvidenceSourceError, match="symlinks or reparse points"):
            attest_evidence_source(junction / "disk.raw")
    finally:
        junction.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows junction semantics")
def test_study_lease_rejects_a_junction_inserted_after_attestation(tmp_path):
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    evidence_path = evidence_dir / "disk.raw"
    evidence_path.write_bytes(b"original")
    source = attest_evidence_source(evidence_path)
    original_dir = tmp_path / "evidence-original"
    replacement_dir = tmp_path / "replacement"
    replacement_dir.mkdir()
    (replacement_dir / "disk.raw").write_bytes(b"REPLACE")
    evidence_dir.rename(original_dir)
    _create_windows_junction(evidence_dir, replacement_dir)
    lease = EvidenceStudyLease(source)
    try:
        with pytest.raises(EvidenceSourceError, match="symlinks or reparse points"):
            lease.start()
        telemetry = lease.telemetry()
        assert telemetry["started"] is False
        assert telemetry["closed"] is True
        assert telemetry["boundary"]["read_lease"]["open_handle_count"] == 0
    finally:
        evidence_dir.rmdir()
        original_dir.rename(evidence_dir)


@pytest.mark.skipif(os.name != "nt", reason="Windows junction semantics")
def test_windows_lease_rejects_a_junction_race_by_opened_file_identity(
    tmp_path,
    monkeypatch,
):
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    evidence_path = evidence_dir / "disk.raw"
    evidence_path.write_bytes(b"ORIGINAL")
    source = attest_evidence_source(evidence_path)
    original_dir = tmp_path / "evidence-original"
    replacement_dir = tmp_path / "replacement"
    replacement_dir.mkdir()
    (replacement_dir / "disk.raw").write_bytes(b"REPLACE!")
    original_inspect = evidence_source_module._inspect_regular
    inspection_count = 0

    def swap_after_first_safe_inspection(path):
        nonlocal inspection_count
        metadata = original_inspect(path)
        inspection_count += 1
        if inspection_count == 1:
            evidence_dir.rename(original_dir)
            _create_windows_junction(evidence_dir, replacement_dir)
        return metadata

    monkeypatch.setattr(
        evidence_source_module,
        "_inspect_regular",
        swap_after_first_safe_inspection,
    )
    guard = EvidenceSourceRuntimeGuard(source)
    try:
        with pytest.raises(EvidenceSourceChangedError, match="attested file identity"):
            guard.acquire_read_lease()
        assert guard.telemetry()["violation_detected"] is True
        assert guard.telemetry()["read_lease"]["open_handle_count"] == 0
    finally:
        guard.close()
        if evidence_dir.is_junction():
            evidence_dir.rmdir()
        if original_dir.exists():
            original_dir.rename(evidence_dir)


def test_e01_and_e02_share_sha256_of_complete_decoded_logical_media(tmp_path):
    first = tmp_path / "case.E01"
    second = tmp_path / "case.E02"
    first_bytes = b"decoded logical block 1\x00"
    second_bytes = b"decoded logical block 2\xff"
    first.write_bytes(first_bytes)
    second.write_bytes(second_bytes)
    handles = []

    def globber(_primary):
        return [str(first), str(second)]

    def handle_factory():
        handle = _DecodedSegmentHandle()
        handles.append(handle)
        return handle

    from_e01 = attest_evidence_source(
        first,
        ewf_glob=globber,
        ewf_handle_factory=handle_factory,
    )
    from_e02 = attest_evidence_source(
        second,
        ewf_glob=globber,
        ewf_handle_factory=handle_factory,
    )
    expected = hashlib.sha256(first_bytes + second_bytes).hexdigest()

    assert from_e01.sha256 == expected
    assert from_e02.sha256 == expected
    assert from_e01.sha256 != hashlib.sha256(first_bytes).hexdigest()
    assert from_e01.size_bytes == len(first_bytes) + len(second_bytes)
    assert from_e01.digest_semantics == EWF_LOGICAL_DIGEST_SEMANTICS
    assert from_e01.source_type == "ewf_logical_media"
    assert len(from_e01.segments) == 2
    assert all(handle.opened == (str(first), str(second)) for handle in handles)
    assert all(handle.closed for handle in handles)


@pytest.mark.skipif(os.name != "nt", reason="Windows junction semantics")
def test_ewf_attestation_rejects_a_reparse_ancestor_on_any_segment(tmp_path):
    primary = tmp_path / "case.E01"
    primary.write_bytes(b"first")
    target = tmp_path / "target"
    target.mkdir()
    (target / "case.E02").write_bytes(b"second")
    junction = tmp_path / "segment-link"
    _create_windows_junction(junction, target)
    factory_calls = []
    try:
        with pytest.raises(EvidenceSourceError, match="symlinks or reparse points"):
            attest_evidence_source(
                primary,
                ewf_glob=lambda _primary: [primary, junction / "case.E02"],
                ewf_handle_factory=lambda: factory_calls.append(True),
            )
    finally:
        junction.rmdir()
    assert factory_calls == []


def test_e02_change_invalidates_complete_ewf_source_attestation(tmp_path):
    first = tmp_path / "case.E01"
    second = tmp_path / "case.E02"
    first.write_bytes(b"segment-one")
    second.write_bytes(b"segment-two")

    def globber(_primary):
        return [str(first), str(second)]

    source = attest_evidence_source(
        first,
        ewf_glob=globber,
        ewf_handle_factory=_DecodedSegmentHandle,
    )
    second.write_bytes(b"segment-two-was-changed")

    with pytest.raises(EvidenceSourceChangedError, match="changed before model execution"):
        assert_evidence_source_current(source, ewf_glob=globber)
    changed = attest_evidence_source(
        first,
        ewf_glob=globber,
        ewf_handle_factory=_DecodedSegmentHandle,
    )
    assert changed.sha256 != source.sha256


def test_ewf_full_boundary_hash_uses_decoded_logical_media(tmp_path):
    first = tmp_path / "case.E01"
    second = tmp_path / "case.E02"
    first.write_bytes(b"logical-one")
    second.write_bytes(b"logical-two")

    def globber(_primary):
        return [str(first), str(second)]

    source = attest_evidence_source(
        first,
        ewf_glob=globber,
        ewf_handle_factory=_DecodedSegmentHandle,
    )
    assert_evidence_source_content_current(
        source,
        ewf_glob=globber,
        ewf_handle_factory=_DecodedSegmentHandle,
    )
    second.write_bytes(b"tampered---")  # same container length, different logical bytes

    with pytest.raises(EvidenceSourceChangedError, match="cryptographic digest"):
        assert_evidence_source_content_current(
            source,
            ewf_glob=globber,
            ewf_handle_factory=_DecodedSegmentHandle,
        )


def test_runtime_guard_retains_detected_violation_after_source_is_restored(tmp_path, monkeypatch):
    path = tmp_path / "disk.raw"
    path.write_bytes(b"guarded evidence")
    source = attest_evidence_source(path)
    current = {"ok": True}

    def exact_current_check(attestation):
        assert attestation is source
        if not current["ok"]:
            raise EvidenceSourceChangedError("simulated transient replacement")

    monkeypatch.setattr(
        evidence_source_module,
        "assert_evidence_source_current",
        exact_current_check,
    )
    guard = EvidenceSourceRuntimeGuard(source)
    guard.check("graph_start")
    current["ok"] = False
    with pytest.raises(EvidenceSourceChangedError, match="guarded execution"):
        guard.check("post_tool_use")

    # Even a byte-for-byte/metadata restoration cannot make the attempt scoreable:
    # the guard no longer trusts a subsequent passing point check.
    current["ok"] = True
    with pytest.raises(EvidenceSourceChangedError, match="previously violated"):
        guard.check("graph_completion")

    telemetry = guard.telemetry()
    assert telemetry["violation_detected"] is True
    assert telemetry["first_violation_checkpoint"] == "post_tool_use"
    assert [item["status"] for item in telemetry["checks"]] == [
        "ok",
        "violation",
        "sticky_violation",
    ]
    assert str(path) not in str(telemetry)


def test_full_boundary_hash_rejects_same_size_overwrite_with_restored_mtime(tmp_path):
    path = tmp_path / "disk.raw"
    original = b"original-content"
    replacement = b"tampered-content"
    assert len(original) == len(replacement)
    path.write_bytes(original)
    pinned = attest_evidence_source(path)
    original_stat = path.stat()

    path.write_bytes(replacement)
    os.utime(
        path,
        ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns),
    )
    # Model the Windows metadata-equivalent state on every CI platform: Windows
    # creation time remains stable, while POSIX ctime cannot be restored by a user.
    current_stat = path.stat()
    metadata_equivalent = replace(
        pinned,
        segments=(EvidenceSegmentDescriptor.from_stat(path, current_stat),),
    )
    assert_evidence_source_current(metadata_equivalent)

    with pytest.raises(EvidenceSourceChangedError, match="cryptographic digest"):
        assert_evidence_source_content_current(metadata_equivalent)
    guard = EvidenceSourceRuntimeGuard(metadata_equivalent)
    with pytest.raises(EvidenceSourceChangedError, match="guarded execution"):
        guard.check("graph_completion", full_content=True)
    check = guard.telemetry()["checks"][0]
    assert check["check_type"] == RUNTIME_FULL_CONTENT_CHECK
    assert check["status"] == "violation"


@pytest.mark.skipif(os.name != "nt", reason="Windows share-mode lease")
def test_windows_read_lease_denies_write_until_closed(tmp_path):
    path = tmp_path / "disk.raw"
    path.write_bytes(b"leased evidence")
    guard = EvidenceSourceRuntimeGuard(attest_evidence_source(path))
    guard.acquire_read_lease()
    try:
        with pytest.raises(OSError):
            with open(path, "r+b") as stream:
                stream.write(b"X")
    finally:
        guard.close()

    with open(path, "r+b") as stream:
        stream.write(b"X")
    lease = guard.telemetry()["read_lease"]
    assert lease == {
        "mode": WINDOWS_READ_LEASE_MODE,
        "started": True,
        "acquired": True,
        "closed": True,
        "open_handle_count": 0,
    }


@pytest.mark.skipif(os.name != "nt", reason="Windows share-mode lease")
def test_windows_read_lease_fails_sticky_when_writer_is_already_open(tmp_path):
    path = tmp_path / "disk.raw"
    path.write_bytes(b"leased evidence")
    guard = EvidenceSourceRuntimeGuard(attest_evidence_source(path))

    with open(path, "r+b"):
        with pytest.raises(EvidenceSourceError, match="lease could not be acquired"):
            guard.acquire_read_lease()
    guard.close()

    telemetry = guard.telemetry()
    assert telemetry["violation_detected"] is True
    assert telemetry["first_violation_checkpoint"] == "read_lease_acquire"


def test_runtime_read_lease_cannot_be_acquired_twice(tmp_path):
    path = tmp_path / "disk.raw"
    path.write_bytes(b"leased evidence")
    guard = EvidenceSourceRuntimeGuard(attest_evidence_source(path))
    guard.acquire_read_lease()
    try:
        with pytest.raises(EvidenceSourceError, match="already active"):
            guard.acquire_read_lease()
    finally:
        guard.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows share-mode lease")
def test_preverified_disk_open_requires_exact_fresh_content_boundary(tmp_path):
    first = tmp_path / "first.raw"
    second = tmp_path / "second.raw"
    first.write_bytes(b"first source")
    second.write_bytes(b"second source")
    source = attest_evidence_source(first)
    other_source = attest_evidence_source(second)
    guard = EvidenceSourceRuntimeGuard(source)

    with pytest.raises(EvidenceSourceError, match="active read lease"):
        guard.authorize_preverified_disk_open(source)
    guard.acquire_read_lease()
    try:
        with pytest.raises(EvidenceSourceError, match="content-boundary checkpoint"):
            guard.authorize_preverified_disk_open(source)
        guard.check("pre_disk_open", full_content=True)
        with pytest.raises(EvidenceSourceError, match="different evidence source"):
            guard.authorize_preverified_disk_open(other_source)

        guard.authorize_preverified_disk_open(source)
        with pytest.raises(EvidenceSourceError, match="already consumed"):
            guard.authorize_preverified_disk_open(source)
    finally:
        guard.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows share-mode lease")
def test_preverified_disk_open_rejects_stale_or_closed_guard(tmp_path):
    path = tmp_path / "disk.raw"
    path.write_bytes(b"guarded source")
    source = attest_evidence_source(path)

    stale = EvidenceSourceRuntimeGuard(source)
    stale.acquire_read_lease()
    stale.check("pre_disk_open", full_content=True)
    stale.check("unrelated_checkpoint")
    with pytest.raises(EvidenceSourceError, match="exact successful pre-open boundary"):
        stale.authorize_preverified_disk_open(source)
    stale.close()

    closed = EvidenceSourceRuntimeGuard(source)
    closed.acquire_read_lease()
    closed.check("pre_disk_open", full_content=True)
    closed.close()
    with pytest.raises(EvidenceSourceError, match="active read lease"):
        closed.authorize_preverified_disk_open(source)


@pytest.mark.skipif(os.name != "nt", reason="Windows study-session share-mode lease")
def test_windows_study_lease_hashes_only_at_session_boundaries(tmp_path, monkeypatch):
    path = tmp_path / "disk.raw"
    path.write_bytes(b"study-leased evidence")
    source = attest_evidence_source(path)
    original_check = evidence_source_module.assert_evidence_source_content_current
    full_content_checks = []

    def counted_check(attestation):
        full_content_checks.append(attestation.sha256)
        return original_check(attestation)

    monkeypatch.setattr(
        evidence_source_module,
        "assert_evidence_source_content_current",
        counted_check,
    )
    lease = EvidenceStudyLease(source)
    lease.start()
    assert full_content_checks == [source.sha256]

    for _ in range(2):
        guard = lease.new_runtime_guard()
        guard.acquire_read_lease()
        guard.check("pre_disk_open", full_content=True)
        guard.check("graph_completion", full_content=True)
        guard.close()
        telemetry = guard.telemetry()
        assert [item["check_type"] for item in telemetry["checks"]] == [
            RUNTIME_STUDY_PINNED_CONTENT_CHECK,
            RUNTIME_STUDY_PINNED_CONTENT_CHECK,
        ]
        assert telemetry["read_lease"] == {
            "mode": WINDOWS_STUDY_READ_LEASE_MODE,
            "started": True,
            "acquired": True,
            "closed": True,
            "open_handle_count": 0,
            "delegated": True,
            "study_session_sha256": lease.session_sha256,
        }

    # A delegated per-cell close cannot release the parent evidence lease.
    with pytest.raises(OSError):
        with open(path, "r+b") as stream:
            stream.write(b"X")
    assert full_content_checks == [source.sha256]

    lease.close()
    assert full_content_checks == [source.sha256, source.sha256]
    session = lease.telemetry()
    assert session["started"] is True
    assert session["completion_verified"] is True
    assert session["closed"] is True
    assert session["run_guard_count"] == 2
    assert session["active_run_guard_count"] == 0
    assert str(path) not in str(session)

    with open(path, "r+b") as stream:
        stream.write(b"X")


@pytest.mark.skipif(os.name != "nt", reason="Windows study-session share-mode lease")
def test_windows_study_lease_releases_handles_when_start_is_interrupted(
    tmp_path,
    monkeypatch,
):
    path = tmp_path / "disk.raw"
    path.write_bytes(b"interruptible evidence")
    source = attest_evidence_source(path)
    lease = EvidenceStudyLease(source)

    def interrupt_content_check(_attestation):
        raise KeyboardInterrupt

    monkeypatch.setattr(
        evidence_source_module,
        "assert_evidence_source_content_current",
        interrupt_content_check,
    )

    with pytest.raises(KeyboardInterrupt):
        lease.start()

    telemetry = lease.telemetry()
    assert telemetry["started"] is False
    assert telemetry["closed"] is True
    assert telemetry["completion_verified"] is False
    assert telemetry["boundary"]["read_lease"] == {
        "mode": WINDOWS_READ_LEASE_MODE,
        "started": True,
        "acquired": True,
        "closed": True,
        "open_handle_count": 0,
    }
    # The original implementation leaked the raw Windows handle here and this
    # write failed until process exit.
    path.write_bytes(b"released after interruption")


@pytest.mark.skipif(os.name != "nt", reason="Windows study-session share-mode lease")
def test_windows_study_lease_releases_handles_when_completion_is_interrupted(
    tmp_path,
    monkeypatch,
):
    path = tmp_path / "disk.raw"
    path.write_bytes(b"interruptible completion")
    lease = EvidenceStudyLease(attest_evidence_source(path))
    lease.start()

    def interrupt_content_check(_attestation):
        raise KeyboardInterrupt

    monkeypatch.setattr(
        evidence_source_module,
        "assert_evidence_source_content_current",
        interrupt_content_check,
    )

    with pytest.raises(KeyboardInterrupt):
        lease.close()

    telemetry = lease.telemetry()
    assert telemetry["started"] is True
    assert telemetry["closed"] is True
    assert telemetry["completion_verified"] is False
    assert telemetry["boundary"]["read_lease"]["open_handle_count"] == 0
    path.write_bytes(b"released after completion interruption")


@pytest.mark.skipif(os.name != "nt", reason="Windows study-session share-mode lease")
def test_windows_study_lease_rejects_a_different_source(tmp_path):
    first = tmp_path / "first.raw"
    second = tmp_path / "second.raw"
    first.write_bytes(b"first")
    second.write_bytes(b"second")
    lease = EvidenceStudyLease(attest_evidence_source(first))
    lease.start()
    try:
        with pytest.raises(EvidenceSourceError, match="different source"):
            EvidenceSourceRuntimeGuard(
                attest_evidence_source(second),
                study_lease=lease,
            )
    finally:
        lease.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows study-session share-mode lease")
def test_windows_study_lease_cannot_close_beneath_an_active_cell(tmp_path):
    path = tmp_path / "disk.raw"
    path.write_bytes(b"active cell evidence")
    lease = EvidenceStudyLease(attest_evidence_source(path))
    lease.start()
    guard = lease.new_runtime_guard()
    guard.acquire_read_lease()

    with pytest.raises(EvidenceSourceError, match="active runtime guards"):
        lease.close()
    assert lease.active is True
    assert lease.active_run_guard_count == 1
    with pytest.raises(OSError):
        with open(path, "r+b") as stream:
            stream.write(b"X")

    guard.close()
    assert lease.active_run_guard_count == 0
    lease.close()
