"""Image-integrity verification: hash the DECODED media of a forensic image.

Streams the acquired content (pyewf-decoded for E01/EWF, the raw bytes for dd/raw)
through MD5+SHA-1+SHA-256 in a single pass and, for E01, compares the computed MD5
to the acquisition hash stored inside the EWF container. Read-only; the image is
never modified. This is what lets the agent answer "verify the image integrity"
(compute and confirm acquisition hashes) instead of guessing.
"""
from __future__ import annotations

import os
import time
from collections.abc import Callable
from typing import cast

from forensic_agent.core.evidence_source import (
    RAW_FILE_DIGEST_SEMANTICS,
    EvidenceSourceAttestation,
    EvidenceSourceError,
    VerifiedPhysicalDiskSource,
    VerifiedPhysicalFileAttestation,
    assert_evidence_source_current,
    attest_raw_media_multihash,
    is_ewf_source,
)

try:
    import pyewf
    HAVE_EWF = True
except Exception:
    HAVE_EWF = False

_CHUNK = 1 << 20  # 1 MiB


def hash_image(
    image_path: str,
    *,
    progress: Callable[[int], None] | None = None,
    progress_total: Callable[[int], None] | None = None,
) -> dict:
    """Stream the decoded media of `image_path` through md5+sha1+sha256 in one pass.

    Returns {"container","media_size","md5","sha1","sha256","ewf_stored_md5"?}.
    Raises FileNotFoundError if the path is missing.

    ``progress`` is called with the size of each block after that block has been
    read and hashed, and ``progress_total`` once with the number of bytes the
    pass will read, before the first block. They are the observer pair the
    evidence-source attestation already takes, carried here so an operator who
    asked for the medium to be streamed again can watch it happen instead of
    facing a console that says nothing for minutes. Neither changes what is
    read: with both omitted this is the call it has always been.
    """
    if not image_path or not os.path.exists(image_path):
        raise FileNotFoundError(image_path)
    out: dict[str, object] = {}
    if is_ewf_source(image_path):
        if not HAVE_EWF:
            raise RuntimeError(
                "EWF hashing support is unavailable because pyewf is not installed"
            )
        import hashlib

        md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
        h = pyewf.handle()
        h.open(pyewf.glob(image_path))
        try:
            size = h.get_media_size()
            if progress_total is not None:
                # The decoded logical media, which is the work; the container
                # files on disk are compressed and are not a measure of it.
                progress_total(int(size))
            h.seek(0)
            read = 0
            while read < size:
                chunk = h.read(min(_CHUNK, size - read))
                if not chunk:
                    break
                md5.update(chunk); sha1.update(chunk); sha256.update(chunk)
                read += len(chunk)
                if progress is not None:
                    progress(len(chunk))
            out["container"] = "ewf"
            out["media_size"] = read
            out["coverage_complete"] = read == size
            try:
                stored = h.get_hash_value("MD5")
                if stored:
                    out["ewf_stored_md5"] = stored.lower()
            except Exception:
                pass
        finally:
            h.close()
    else:
        attestation, md5_hex, sha1_hex = attest_raw_media_multihash(
            image_path,
            progress=progress,
            progress_total=progress_total,
        )
        out["container"] = (
            "split_raw" if attestation.source_type == "raw_segment_set" else "raw"
        )
        out["segment_count"] = len(attestation.segments)
        out["media_size"] = attestation.size_bytes
        out["coverage_complete"] = True
        out["md5"] = md5_hex
        out["sha1"] = sha1_hex
        out["sha256"] = attestation.sha256
        return out
    out["md5"] = md5.hexdigest()
    out["sha1"] = sha1.hexdigest()
    out["sha256"] = sha256.hexdigest()
    return out


def _normalized_path(value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return os.path.normcase(os.path.normpath(os.path.abspath(value)))


def _reusable_streamed_digests(disk) -> VerifiedPhysicalFileAttestation | None:
    """Return the digests THIS open streamed, when they are still current.

    The ordinary console open streams the medium once, updating MD5, SHA-1 and
    SHA-256 together, but retains only the SHA-256.  A question asking for the
    other two would otherwise pay a second whole-medium pass over bytes already
    digested.

    Reuse is admitted only for the exact companion this disk's own open minted,
    for the same single raw file at the same size and SHA-256, and only after
    ``assert_evidence_source_current`` re-establishes that the source has not
    changed since.  The check runs before and after the values are read, so a
    replacement racing the read fails closed rather than being reported.
    """

    from forensic_agent.tools.tsk_tool import DiskImage

    if type(disk) is not DiskImage:
        return None
    if getattr(disk, "_base", None) is None or getattr(disk, "_fsys", None) is None:
        return None
    streamed = getattr(disk, "streamed_file_digests", None)
    if type(streamed) is not VerifiedPhysicalFileAttestation:
        return None
    streamed = cast(VerifiedPhysicalFileAttestation, streamed)
    source = getattr(disk, "evidence_source_attestation", None)
    if type(source) is not EvidenceSourceAttestation or source is not streamed.attestation:
        return None
    image_path = _normalized_path(getattr(disk, "image_path", None))
    if (
        image_path is None
        or image_path != _normalized_path(streamed.primary_path)
        or is_ewf_source(streamed.primary_path)
    ):
        return None
    image_size = getattr(disk, "image_size", None)
    if (
        isinstance(image_size, bool)
        or not isinstance(image_size, int)
        or image_size != streamed.size_bytes
        or getattr(disk, "image_sha", None) != streamed.sha256
    ):
        return None

    assert_evidence_source_current(streamed.attestation)
    streamed.__post_init__()
    digests = (streamed.md5, streamed.sha1, streamed.sha256)
    assert_evidence_source_current(streamed.attestation)
    if digests != (streamed.md5, streamed.sha1, streamed.sha256):
        raise EvidenceSourceError("streamed raw-file digests changed during reuse")
    return streamed


def _reusable_raw_hash_attestation(disk) -> VerifiedPhysicalFileAttestation | None:
    """Return the exact current raw-file hash authority bound to ``disk``.

    Reuse is intentionally narrower than ordinary hashing.  It is available only
    for a fully constructed, read-only ``DiskImage`` that was opened from one
    exact preverified raw file, or from digests that same open streamed itself.
    EWF containers, multi-segment sources, foreign paths/sizes and logical-media
    attestations all fall back to a fresh stream.  A source that changed after
    attestation raises and therefore fails closed.
    """

    # The exact type check prevents a duck-typed object from asserting that it is
    # the parser instance to which this process-local authority was bound.
    from forensic_agent.tools.tsk_tool import DiskImage

    if type(disk) is not DiskImage:
        return None
    if getattr(disk, "_base", None) is None or getattr(disk, "_fsys", None) is None:
        return None
    streamed = _reusable_streamed_digests(disk)
    if streamed is not None:
        return streamed
    authority = getattr(disk, "physical_source_attestation", None)
    if type(authority) is not VerifiedPhysicalDiskSource:
        return None
    authority = cast(VerifiedPhysicalDiskSource, authority)
    if (
        getattr(disk, "evidence_source_attestation", None) is not None
        or getattr(disk, "evidence_source", None) is not None
    ):
        return None
    image_path = _normalized_path(getattr(disk, "image_path", None))
    primary_path = _normalized_path(authority.primary_path)
    if image_path is None or image_path != primary_path or is_ewf_source(authority.primary_path):
        return None
    if len(authority.components) != 1:
        return None
    component = authority.components[0]
    if type(component) is not VerifiedPhysicalFileAttestation:
        return None
    component_source = component.attestation
    if (
        component_source.source_type != "raw_file"
        or component_source.digest_semantics != RAW_FILE_DIGEST_SEMANTICS
        or len(component_source.segments) != 1
        or _normalized_path(component.primary_path) != image_path
    ):
        return None
    image_size = getattr(disk, "image_size", None)
    if (
        isinstance(image_size, bool)
        or not isinstance(image_size, int)
        or image_size != component.size_bytes
        or authority.size_bytes != component.size_bytes
        or component.segment.size_bytes != component.size_bytes
    ):
        return None
    if getattr(disk, "image_sha", None) != authority.sha256:
        return None

    # Revalidate both issuer proofs plus current path/segment identity immediately
    # before and after reading the already-computed values.  The DEV container
    # supplies this source through a read-only bind mount; DiskImage itself exposes
    # no mutating operation.
    authority.assert_current_for_disk_open()
    component.__post_init__()
    digests = (component.md5, component.sha1, component.sha256)
    authority.assert_current_for_disk_open()
    if digests != (component.md5, component.sha1, component.sha256):
        raise EvidenceSourceError("verified raw-file digest authority changed during reuse")
    return component


def verify_image_integrity(
    disk,
    expected: list[str] | None = None,
    *,
    force_full_stream: bool = False,
    progress: Callable[[int], None] | None = None,
    progress_total: Callable[[int], None] | None = None,
) -> dict:
    """Compute MD5+SHA-1+SHA-256 of the image's decoded media and verify integrity.

    Reads the image path from the open `disk` handle (never an argument, so this
    stays a pure read_evidence operation). A current process-issued multi-hash
    attestation may be reused only when it is bound to this exact single-file raw
    ``DiskImage``; every other source is streamed normally. For E01, compares the
    computed MD5 to the EWF-stored acquisition MD5 (`integrity_ok`). If `expected`
    hex digests are given, reports a per-digest match map.

    ``force_full_stream`` suppresses the reuse path outright, so every byte of
    the medium is read again. The reuse path is right for the agent, which asks
    this question inside a run that has already established the digest and would
    otherwise pay a second multi-gigabyte pass for an answer it holds. It is
    exactly wrong for an operator who typed a command in order to have the medium
    read: returning a stored digest there would print a hash and a reassurance
    while touching nothing, which is the one outcome a verification command must
    never produce. The flag is therefore what separates "tell me the digest" from
    "read it again and tell me", and the recorded ``attestation_reused`` stays
    truthful in both cases.

    ``progress`` and ``progress_total`` are forwarded to the stream, so a console
    that forced one can show it advancing.

    Returns {"image","container","media_size","md5","sha1","sha256",
    "ewf_stored_md5"?,"integrity_ok": bool|None,"matches"?,
    "coverage_complete": bool,"attestation_reused": bool} or {"error": ...}.
    """
    t0 = time.time()
    image_path = getattr(disk, "image_path", None)
    if not image_path or not os.path.exists(image_path):
        return {"error": f"image not available: {image_path}", "coverage_complete": False}
    try:
        attestation = (
            None if force_full_stream else _reusable_raw_hash_attestation(disk)
        )
        if attestation is None:
            r = hash_image(
                image_path,
                progress=progress,
                progress_total=progress_total,
            )
            r["attestation_reused"] = False
        else:
            r = {
                "container": "raw",
                "media_size": attestation.size_bytes,
                "coverage_complete": True,
                "md5": attestation.md5,
                "sha1": attestation.sha1,
                "sha256": attestation.sha256,
                "attestation_reused": True,
            }
    except EvidenceSourceError:
        return {
            "error": "preverified evidence source changed or its hash authority is invalid",
            "coverage_complete": False,
        }
    except Exception as e:
        return {"error": f"hashing failed: {str(e)[:150]}", "coverage_complete": False}
    r = {"image": os.path.basename(image_path), **r}
    stored = r.get("ewf_stored_md5")
    r["integrity_ok"] = (r["md5"] == stored) if stored else None
    if expected:
        want = {str(x).strip().lower() for x in expected}
        computed = {r["md5"], r["sha1"], r["sha256"]}
        r["matches"] = {x: (x in computed) for x in want}
    audit = getattr(disk, "audit", None)
    if audit is not None:
        try:
            audit.record(tool="integrity.verify",
                         args={
                             "expected": bool(expected),
                             "force_full_stream": bool(force_full_stream),
                         },
                         output=r, input_sha=getattr(disk, "image_sha", None),
                         duration_s=time.time() - t0)
        except Exception:
            pass
    return r
