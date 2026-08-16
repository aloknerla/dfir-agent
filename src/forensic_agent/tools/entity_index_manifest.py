"""Identity and attestation of one persistent entity index.

Split away from the store that builds an index so the rules deciding WHICH index
a reader is holding can be exercised without a scanner binary, a controlled root,
or a filesystem full of half-written directories.  Those rules are the whole
safety argument of a cache that outlives the run that filled it: an index served
for evidence it was not taken from, or for a scanner version that did not produce
it, is not a stale cache entry — it is a finding attributed to the wrong disk.

Two commitments are recorded and both are checkable later.  The identity says
what the index is of and what made it, and it is hashed into the key the index is
filed under, so a reader that computes a different identity looks in a different
place and never has to be trusted to compare fields.  The feature digests say
what the index held when it was published, so bytes that changed underneath it
are refused rather than read.

Nothing ambient enters a manifest: no wall-clock time, no host path, and no
filesystem enumeration order.  Two builds over the same evidence with the same
scanner therefore produce byte-identical manifests, which is what makes a
manifest comparable between hosts instead of merely present.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping, Sequence
from pathlib import Path

from forensic_agent.core.repro import canonical_json, sha256_hex

ENTITY_INDEX_SCHEMA_ID = "forensic.entity-index.v1"

#: The attestation lives inside the index it describes, so an index that is moved
#: or copied carries its own proof rather than depending on a register elsewhere.
INDEX_MANIFEST_NAME = "index-manifest.json"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
#: Scanner names reach the scanner's argv, so the accepted shape is narrow enough
#: that no name can be read as an option or a path.
_SCANNER_NAME = re.compile(r"^[a-z0-9_]{1,32}$")
#: The same version shape the backend inventory accepts, so a version that is
#: good enough to attest a result is good enough to identify an index.
_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+~:-]{0,63}$")

_FEATURE_SUFFIX = ".txt"
_HISTOGRAM_SUFFIX = "_histogram.txt"
_DIGEST_CHUNK_BYTES = 1 << 20
#: A manifest is a few kilobytes of names and digests.  A file far larger than
#: any plausible feature list is refused unparsed rather than decoded into memory.
_MANIFEST_LIMIT_BYTES = 8 << 20


class EntityIndexError(RuntimeError):
    """An entity index could not be identified, published, or verified."""


def normalized_scanners(scanners: Sequence[str] | None) -> list[str]:
    """One scanner set as the sorted list its identity is computed from.

    ``None`` means the set the scanner binary enables by itself, which cannot be
    spelled out here because only the binary knows it; it is recorded as the
    empty list.  An explicitly empty set is refused instead, because a scan that
    enables nothing produces nothing to index.
    """

    if scanners is None:
        return []
    if isinstance(scanners, str | bytes):
        raise EntityIndexError("scanners must be a sequence of scanner names, not one string")
    names = sorted({str(item) for item in scanners})
    if not names:
        raise EntityIndexError("an explicit scanner set must enable at least one scanner")
    for name in names:
        if _SCANNER_NAME.fullmatch(name) is None:
            raise EntityIndexError(
                f"refused scanner name {name[:40]!r}: a scanner is a plain recorder name, "
                "never an option or a path"
            )
    return names


def index_identity(
    *,
    evidence_sha256: str,
    scanner: str,
    scanner_version: str,
    scanners: Sequence[str] | None,
) -> dict[str, object]:
    """The facts that decide whether two indexes are the same index.

    A path is deliberately absent.  Evidence is copied between hosts and renamed
    on arrival, so an index matched on a path would eventually be served for
    different bytes carrying the same name — and a cache that outlives the run
    makes that a question of months rather than minutes.
    """

    if not isinstance(evidence_sha256, str) or _SHA256.fullmatch(evidence_sha256) is None:
        raise EntityIndexError(
            "evidence identity must be the 64 lowercase hex characters of its SHA-256"
        )
    if _SCANNER_NAME.fullmatch(str(scanner)) is None:
        raise EntityIndexError("the scanner name is not a plain scanner identifier")
    if _VERSION.fullmatch(str(scanner_version)) is None:
        raise EntityIndexError(
            "the scanner version is unusable; an index that cannot name the version that "
            "built it cannot be offered to a later run"
        )
    return {
        "schema_id": ENTITY_INDEX_SCHEMA_ID,
        "evidence_sha256": evidence_sha256,
        "scanner": str(scanner),
        "scanner_version": str(scanner_version),
        "scanners_enabled": normalized_scanners(scanners),
    }


def index_key(identity: Mapping[str, object]) -> str:
    """The identity as the one name its index is filed under."""

    return sha256_hex(canonical_json(dict(identity)))


def feature_names(directory: Path) -> list[str]:
    """The feature files one scan left behind, in a fixed order.

    Sorted because ``scandir`` reports whatever order the filesystem holds, and
    an order that varies by host would put a different digest on two identical
    indexes.  Histograms and the scanner's report are excluded: neither is served
    through this surface, and the report carries the scan's wall-clock times,
    which have no place in anything a manifest commits to.
    """

    names: list[str] = []
    with os.scandir(directory) as entries:
        for entry in entries:
            name = entry.name
            if not name.endswith(_FEATURE_SUFFIX) or name.endswith(_HISTOGRAM_SUFFIX):
                continue
            if not entry.is_file(follow_symlinks=False):
                continue
            names.append(name[: -len(_FEATURE_SUFFIX)])
    return sorted(names)


def feature_file(directory: Path, feature: str) -> Path:
    """Where one attested feature's bytes live inside its index."""

    return directory / f"{feature}{_FEATURE_SUFFIX}"


def file_sha256(path: Path) -> str:
    """Digest one feature file in bounded blocks; a feature file can be gigabytes."""

    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(_DIGEST_CHUNK_BYTES), b""):
            digest.update(block)
    return digest.hexdigest()


def build_manifest(directory: Path, *, identity: Mapping[str, object]) -> dict[str, object]:
    """Attest a finished index: what it is of, what made it, and what it holds."""

    features: list[dict[str, object]] = []
    for name in feature_names(directory):
        path = feature_file(directory, name)
        features.append(
            {"feature": name, "sha256": file_sha256(path), "size_bytes": path.stat().st_size}
        )
    record: dict[str, object] = dict(identity)
    record["index_key"] = index_key(identity)
    record["features"] = features
    # Covers the feature list itself, so an edited list is distinguishable from a
    # manifest that honestly describes a different index.
    record["features_sha256"] = sha256_hex(canonical_json(features))
    return record


def write_manifest(directory: Path, manifest: Mapping[str, object]) -> Path:
    """Write the attestation in canonical form, so two identical builds match byte for byte."""

    path = directory / INDEX_MANIFEST_NAME
    path.write_text(canonical_json(dict(manifest)) + "\n", encoding="utf-8")
    return path


def read_manifest(directory: Path) -> dict[str, object]:
    """Load an index's own attestation, refusing one that does not cover itself."""

    path = directory / INDEX_MANIFEST_NAME
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise EntityIndexError("this directory carries no index manifest") from error
    if len(raw) > _MANIFEST_LIMIT_BYTES:
        raise EntityIndexError("the index manifest is implausibly large and was not parsed")
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EntityIndexError("the index manifest is not readable JSON") from error
    if not isinstance(manifest, dict):
        raise EntityIndexError("the index manifest is not a manifest record")
    features = manifest.get("features")
    if not isinstance(features, list):
        raise EntityIndexError("the index manifest names no feature files")
    if sha256_hex(canonical_json(features)) != manifest.get("features_sha256"):
        raise EntityIndexError("the index manifest digest does not cover its own feature list")
    return manifest


def verify_identity(manifest: Mapping[str, object], *, identity: Mapping[str, object]) -> None:
    """Refuse a manifest describing an index other than the one that was asked for."""

    for field, expected in identity.items():
        if manifest.get(field) != expected:
            raise EntityIndexError(
                f"this index was built for a different {field}, so it is not the index that "
                "was asked for and is never served in its place"
            )
    if manifest.get("index_key") != index_key(identity):
        raise EntityIndexError("the index manifest key contradicts its own identity fields")


def attested_features(manifest: Mapping[str, object]) -> list[str]:
    """The feature names a manifest vouches for, which is what a reader may ask for.

    Read from the attestation rather than from the directory: a file that appeared
    beside the index after publication is not part of it, and listing it would
    invite a read of bytes nothing ever attested.
    """

    features = manifest.get("features")
    if not isinstance(features, list):
        return []
    names = [
        str(entry.get("feature")) for entry in features if isinstance(entry, Mapping)
    ]
    return sorted(names)


def enabled_scanners(record: Mapping[str, object]) -> list[str]:
    """The scanner set an identity or manifest names, as text a caller can pass on."""

    value = record.get("scanners_enabled")
    return [str(item) for item in value] if isinstance(value, list) else []


def verify_feature(directory: Path, manifest: Mapping[str, object], feature: str) -> None:
    """Refuse one feature whose bytes are no longer the bytes that were attested."""

    features = manifest.get("features")
    entry = None
    if isinstance(features, list):
        for candidate in features:
            if isinstance(candidate, Mapping) and str(candidate.get("feature")) == feature:
                entry = candidate
                break
    if entry is None:
        raise EntityIndexError(f"feature {feature[:60]!r} is not attested by this index")
    try:
        observed = file_sha256(feature_file(directory, feature))
    except OSError as error:
        raise EntityIndexError(
            f"feature {feature[:60]!r} is attested by this index but could not be read back"
        ) from error
    if observed != entry.get("sha256"):
        raise EntityIndexError(
            f"feature {feature[:60]!r} no longer matches the manifest that attested it, so "
            "the index is refused rather than read"
        )
