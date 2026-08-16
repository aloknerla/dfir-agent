"""Persistent, content-addressed entity index over one evidence item.

bulk_extractor's feature files — ``email``, ``url``, ``domain``, ``ether``,
``ip``, ``telephone``, ``windirs`` — are the only view of a disk that reaches
unallocated space and UTF-16 text at once, so they decide whether a "lost"
address or filename is truly gone.  The pass-through in
:mod:`forensic_agent.tools.bulk_extractor_tool` builds them lazily inside one
run's controlled scratch and loses them when that scratch closes.  Two things
break as a result.  Every session that wants one address pays a scan of a
multi-gigabyte image again, and because that scan is measured in tens of minutes
against a call budget measured in calls, the model never spends one on it: the
tool that would answer the question is simply never the tool it calls, and the
answer is reported absent when it was sitting in unallocated space the whole
time.

This store separates the scan from the run.  An index is built once into a
private staging directory, attested, and published under the identity of the
evidence it was taken from, the scanner binary that produced it and the scanners
that were enabled; every later run reads it instead of rescanning.  The identity
is what makes reuse safe rather than merely fast — see
:mod:`forensic_agent.tools.entity_index_manifest`, which owns it.

Only the scanners that record those seven features are enabled.  The binary's own
default set carves as well as records, and a carver's output is not readable
through this surface at all, so enabling one buys an index nothing can consult,
charges the whole scan for it, and writes executable content unpacked out of the
evidence to wherever the index lives.  Scoping the set is part of the identity,
not a tuning knob beside it: an index taken with one set is a different index from
one taken with another and is never served in its place.

Scoping costs something real, and the cost is published rather than absorbed.  The
scanners that expand archives are also the ones that reach values sealed inside
them, so this index holds fewer addresses than an exhaustive scan would — see
:data:`INDEX_COVERAGE_LIMIT`, which every reader is handed alongside the rows, so
a thin answer is never mistaken for an empty medium.

Containment is the pass-through's discipline: everything is written below ONE
caller-supplied controlled root, never below the ambient system temporary
directory, and without such a root the build is refused rather than run.  What
differs is lifetime.  This root deliberately outlives the run, so publication is
the only thing that makes an index readable: a scan that stopped half way leaves
a directory under a staging name that no reader resolves and no manifest that
would vouch for it, and the next build removes it rather than scanning into it.
"""

from __future__ import annotations

import os
import re
import threading
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from types import MappingProxyType

from forensic_agent.core.backend_versions import (
    BackendVersionError,
    BackendVersionRegistry,
    backend_versions_for_environment,
    session_backend_versions,
)
from forensic_agent.core.controlled_scratch import (
    ControlledScratchError,
    ControlledScratchSession,
    attest_controlled_scratch_root,
    provision_controlled_scratch_root,
    purge_controlled_directory,
)
from forensic_agent.core.environ import bulk_extractor_path
from forensic_agent.core.evidence_source import EvidenceSourceError, attest_evidence_source
from forensic_agent.core.storage_containment import (
    StorageContainmentError,
    require_declared_payload_root,
)
from forensic_agent.core.tool_failure import tool_failure_result
from forensic_agent.core.toolkit import ExternalToolError, run_external

# The containment predicates and the feature-name refusal belong to the
# pass-through this store persists the output of.  They are imported rather than
# restated: a second copy of a traversal refusal is a traversal waiting for the
# two copies to drift, and the model must see the same refusal whichever surface
# it reached the feature files through.
from forensic_agent.tools.bulk_extractor_tool import (
    _identity,
    _inside,
)
from forensic_agent.tools.entity_index_manifest import (
    EntityIndexError,
    attested_features,
    build_manifest,
    enabled_scanners,
    index_identity,
    index_key,
    read_manifest,
    verify_identity,
    write_manifest,
)

#: The scanner this store indexes with, named the way the backend inventory names
#: it so both surfaces mean the same binary.
_SCANNER = "bulk_extractor"

#: What each scanner this index enables records, as ``bulk_extractor -H`` reports
#: it for 2.1.1.  Declared as the mapping rather than as a bare list of names so
#: the set that is enabled and the recorders that are read cannot drift apart
#: without a test noticing: every recorder in :data:`ENTITY_INDEX_FEATURES` has to
#: be produced by something in here.
ENTITY_INDEX_RECORDERS: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "accts": ("ccn", "ccn_track2", "pii", "sin", "telephone"),
        "email": ("domain", "email", "ether", "rfc822", "url"),
        "net": ("ether", "ip", "tcp"),
        "windirs": ("windirs",),
    }
)

#: The recorders an entity question is answered from: addresses, the hosts they
#: name, network and hardware addresses, telephone numbers, and the filenames that
#: survive in unallocated directory entries after the metadata is gone.
ENTITY_INDEX_FEATURES: tuple[str, ...] = (
    "domain",
    "email",
    "ether",
    "ip",
    "telephone",
    "url",
    "windirs",
)

#: The scanners enabled for an entity index, which is every scanner that produces
#: one of those recorders and no other.
#:
#: The set is scoped not for the modest scan-time saving but because the binary's
#: own default set also carves.  ``winpe``, ``zip`` and ``rar`` unpack and write
#: out executable content found INSIDE the evidence, which on a host with an
#: on-access virus scanner is both a containment failure and a correctness one,
#: because files quarantined mid-scan leave an index that is short of entries and
#: says nothing about it.  No reader here consumes a carved recorder, so that
#: output is cost and risk against no answer.
ENTITY_INDEX_SCANNERS: tuple[str, ...] = tuple(sorted(ENTITY_INDEX_RECORDERS))

#: What this index does not reach.  Container expansion is deliberately absent: it
#: is what recovers values sealed inside archives, and it can be worth a great
#: deal, but the scanners that perform it are the same ones that unpack archive
#: members onto disk.  The cost of leaving it out is therefore stated to every
#: reader rather than absorbed silently, because an index that quietly holds a
#: fraction of the addresses answers "absent" in exactly the voice it uses for
#: "not present on the medium".
INDEX_COVERAGE_LIMIT = (
    "container interiors are not expanded: addresses, telephone numbers and hosts "
    "sealed inside ZIP, GZIP, base64, PDF or Office XML streams are not indexed, so "
    "absence from this index is not absence from the medium"
)

#: Every directory this module creates below the index root carries this prefix,
#: so nothing it did not create is ever a candidate for removal.
_INDEX_PREFIX = "entity-index-"
#: A build in progress is a different NAME, not a flag inside the directory.  A
#: reader resolves only the published name, so an interrupted build cannot be
#: read as a finished index even by a reader that never looks at a manifest.
_STAGING_SUFFIX = ".building"

_SCAN_TIMEOUT_SECONDS = 1800

#: bulk_extractor reports how far it has read as a bracketed percentage in lines
#: like ``Offset 67MB (0.16%) Done in 1:29:44``.
_PERCENT = re.compile(r"\(\s*([0-9]{1,3}(?:\.[0-9]+)?)\s*%\s*\)")

INDEX_STARTED = "started"
INDEX_SCANNING = "scanning"
INDEX_FINISHED = "finished"
INDEX_FAILED = "failed"

#: Optional observer of one index build, called with a stage and the percentage
#: of the evidence the scanner said it had read, where it said one.  It exists so
#: a console can tell a user that a scan measured in tens of minutes is
#: progressing; it is never consulted, so it changes nothing about the index.
IndexProgress = Callable[[str, float | None], None]

_NO_INDEX_ROOT = (
    "the entity index needs a controlled root to live below and none was supplied; "
    "nothing was scanned and nothing was written"
)
_RUN_SCOPED_ROOT = (
    "a run's controlled scratch session is removed when the run closes, so an index "
    "built below it would be destroyed exactly as the lazy scan already is; supply the "
    "case's own controlled index root instead"
)

#: Guards the lock registry below, and nothing else: a thread holding an index
#: lock never asks for this one while another thread holds it for a scan.
_REGISTRY_LOCK = threading.Lock()
#: One lock per (index root, index key).  At most one build runs for a given
#: index, and no directory is published or removed while another thread reads a
#: feature out of it.  There is no result cache beside it on purpose: the
#: published directory IS the cache, which is what makes it survive the process.
_INDEX_LOCKS: dict[tuple[str, str], threading.Lock] = {}


def _index_lock(key: tuple[str, str]) -> threading.Lock:
    with _REGISTRY_LOCK:
        lock = _INDEX_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _INDEX_LOCKS[key] = lock
        return lock


def _report(progress: IndexProgress | None, stage: str, percent: float | None) -> None:
    """Tell an observer where the build is, and never let it stop the build.

    An observer that raises is a defect in a display.  Letting it abort a scan
    that may already have read half a disk would make the display part of the
    forensic path, which it is not.
    """

    if progress is None:
        return
    try:
        progress(stage, percent)
    except Exception:
        return


def _controlled_root(index_root: str | os.PathLike[str] | None) -> Path:
    """Resolve the one directory an index may live below, or fail closed."""

    if isinstance(index_root, ControlledScratchSession):
        raise ControlledScratchError(_RUN_SCOPED_ROOT)
    if not isinstance(index_root, str | os.PathLike) or not str(os.fspath(index_root)).strip():
        raise ControlledScratchError(_NO_INDEX_ROOT)
    # Rejects a relative root, a traversal component and any symlink or reparse
    # point along the way, and proves the root is an existing directory.
    return attest_controlled_scratch_root(Path(os.fspath(index_root))).root_path


def _backend_inventory() -> BackendVersionRegistry:
    """The sealed inventory this index names its scanner version from.

    The session inventory is preferred so an index built during a run names the
    same version that run's receipts attest.  It is populated by an explicit call
    that only a session makes, so outside one — and, until a session makes that
    call, inside one too — the inventory for the executables this environment
    resolves to is used instead.  That is the same seam the model surface is built
    from, it is sealed per configuration rather than per call, and it refuses to
    run from inside an execution cell, so no forensic call can probe through it.
    """

    try:
        return session_backend_versions()
    except BackendVersionError:
        return backend_versions_for_environment()


#: Where persistent scan artifacts live when the operator has not said
#: otherwise. Moved here from the console layer so the tools that PRODUCE
#: those artifacts can resolve the same root without importing the console.
INDEX_ROOT_ENVIRONMENT_VARIABLE = "DFA_INDEX_ROOT"
_INDEX_DIRECTORY_NAME = "entity-index"


def index_root_for(runs_root: Path | None) -> Path | None:
    """Resolve the directory persistent indexes live below, provisioning it.

    An operator override wins; otherwise the deployment's container-private
    payload storage is preferred over a directory beside the run records,
    because the records directory is bind-mounted from the host. Returns
    ``None`` when no usable root can be established — an artifact that cannot
    be stored is a reason to carry on without one, never a reason to refuse
    the work that would have produced it.
    """

    import os as _os

    from forensic_agent.core.controlled_scratch import (
        ControlledScratchError as _ScratchError,
    )
    from forensic_agent.core.controlled_scratch import (
        attest_controlled_scratch_root as _attest,
    )
    from forensic_agent.core.controlled_scratch import (
        provision_controlled_scratch_root as _provision,
    )
    from forensic_agent.core.storage_containment import (
        EvidenceWriteScope as _Scope,
    )
    from forensic_agent.core.storage_containment import (
        StorageContainmentError as _ContainmentError,
    )
    from forensic_agent.core.storage_containment import (
        acquire_evidence_write_dir as _acquire,
    )
    from forensic_agent.core.storage_containment import (
        payload_scratch_root as _payload_root,
    )

    def _contained(root: Path) -> None:
        _attest(root)
        _acquire(
            root,
            subject="a persistent index derived from the evidence",
            scope=_Scope.NOT_HOST_SHARED,
        )

    configured = _os.environ.get(INDEX_ROOT_ENVIRONMENT_VARIABLE)
    payload_root = _payload_root()
    if configured:
        candidate = Path(configured)
    elif payload_root is not None:
        candidate = payload_root / _INDEX_DIRECTORY_NAME
    elif runs_root is not None:
        candidate = Path(runs_root) / _INDEX_DIRECTORY_NAME
    else:
        return None
    try:
        if candidate.is_dir():
            _contained(candidate)
            return candidate
        candidate.parent.mkdir(parents=True, exist_ok=True)
        root = _provision(candidate, anchor=candidate.parent).root_path
        _contained(root)
        return root
    except (_ScratchError, OSError, _ContainmentError):
        return None


def _scanner_version(supplied: str | None) -> str:
    """The version of the binary that produced, or will produce, this index.

    Taken from a sealed inventory rather than probed here: a probe from inside a
    tool call is exactly the per-call execution that inventory exists to prevent,
    and a version this module invented would let an index built by one binary be
    served for another.
    """

    if supplied is not None:
        return str(supplied)
    entry = _backend_inventory().entry(_SCANNER)
    if entry.version is None:
        raise EntityIndexError(
            f"the scanner is {entry.status.value} ({entry.reason}), so no index can be "
            "identified: an index that cannot name the version that built it cannot be reused"
        )
    return entry.version


def _evidence_sha256(image_path: str, supplied: str | None) -> str:
    """The evidence's content identity, taken from the caller or established here.

    A caller that has already bound this evidence knows the digest and passes it.
    Establishing it here instead means a full pass over the medium, which is
    correct but is a second multi-gigabyte read on the very path this store
    exists to keep short.
    """

    if supplied is not None:
        return str(supplied)
    return attest_evidence_source(image_path).sha256


def _prepare(
    image_path: str,
    index_root: str | os.PathLike[str] | None,
    evidence_sha256: str | None,
    scanners: Sequence[str] | None,
    scanner_version: str | None,
) -> tuple[Path, dict[str, object]]:
    """Resolve the root this index lives below and the identity it has.

    Every failure here becomes one exception type, because to a caller they are
    one answer: the index could not be identified, so nothing was read and
    nothing was scanned.
    """

    if not image_path or not os.path.exists(image_path):
        raise EntityIndexError("image not available")
    try:
        root = _controlled_root(index_root)
    except ControlledScratchError as error:
        raise EntityIndexError(str(error)) from error
    try:
        identity = index_identity(
            evidence_sha256=_evidence_sha256(image_path, evidence_sha256),
            scanner=_SCANNER,
            scanner_version=_scanner_version(scanner_version),
            scanners=scanners,
        )
    except (BackendVersionError, EvidenceSourceError, OSError) as error:
        raise EntityIndexError(str(error)) from error
    return root, identity


def _index_paths(root: Path, key: str) -> tuple[Path, Path]:
    """The published directory of one index and the private one it is built in."""

    name = f"{_INDEX_PREFIX}{key[:32]}"
    return root / name, root / f"{name}{_STAGING_SUFFIX}"


def _open_index(root: Path, published: Path, identity: Mapping[str, object]) -> dict[str, object] | None:
    """The verified manifest of a finished index for this identity, or nothing.

    Anything short of a manifest that verifies is treated as no index at all: a
    directory left by an older layout, a manifest describing other evidence, or
    one whose feature list was edited must cause a rebuild rather than a read.
    """

    if not published.is_dir() or not _inside(root, published):
        return None
    try:
        manifest = read_manifest(published)
        verify_identity(manifest, identity=identity)
    except EntityIndexError:
        return None
    return manifest


def _last_percent(stdout: str, stderr: str) -> float | None:
    """How far the scanner said it got, from the progress lines it printed."""

    found = _PERCENT.findall(f"{stdout}\n{stderr}")
    if not found:
        return None
    try:
        return min(100.0, max(0.0, float(found[-1])))
    except ValueError:  # pragma: no cover - the pattern only matches decimals
        return None


def _scan(
    image_path: str,
    binary: str,
    scanners: Sequence[str],
    outdir: Path,
    progress: IndexProgress | None,
) -> None:
    """Run the one scan this index costs, into the already provisioned directory.

    ``-E`` disables every scanner and enables one; the rest follow individually,
    so the index holds exactly the recorders its identity claims and no others.
    An empty set means the scanner's own defaults, which is the pass-through's
    invocation unchanged.

    The scan runs through the project's single subprocess boundary, which
    captures the scanner's output rather than streaming it, so the percentage
    reaches the observer when the scan ends.  It is still worth reporting: on a
    scan that timed out or died it is the only statement of how far it got.
    """

    argv = [binary]
    for position, name in enumerate(scanners):
        argv += ["-E" if position == 0 else "-e", name]
    argv += ["-o", str(outdir), image_path]
    # check=False so a failed scan's own output is read for a percentage before
    # the failure is raised; run_external would otherwise keep only its stderr.
    completed = run_external(argv, timeout=_SCAN_TIMEOUT_SECONDS, check=False)
    stdout = completed.stdout if isinstance(completed.stdout, str) else ""
    stderr = completed.stderr if isinstance(completed.stderr, str) else ""
    percent = _last_percent(stdout, stderr)
    if percent is not None:
        _report(progress, INDEX_SCANNING, percent)
    if int(completed.returncode) != 0:
        raise ExternalToolError(_SCANNER, completed.returncode, stderr)


def _assert_scan_is_containable(root: Path, scanners: Sequence[str]) -> None:
    """Refuse a scan that would carve, unless its output has somewhere private to go.

    Every scanner in :data:`ENTITY_INDEX_RECORDERS` records text and reconstructs
    nothing, so an index taken with those may live wherever the operator keeps
    its indexes: what it holds is inert.  Anything else — a set naming a carver,
    or ``None``, which asks for the binary's own default set — unpacks archive
    members and carves PE images out of the evidence and writes them beside the
    feature files.  This refusal is expressed where the bytes are about to be
    written, which is the only place a caller cannot decline to honour it.
    """

    requested = tuple(scanners)
    unreadable = tuple(name for name in requested if name not in ENTITY_INDEX_RECORDERS)
    if requested and not unreadable:
        return
    named = ", ".join(sorted(unreadable)) if unreadable else "the scanner's own default set"
    require_declared_payload_root(
        root,
        subject=f"an entity index scan enabling {named}",
    )


def _provision_staging(root: Path, staging: Path) -> None:
    """Give this build an empty private directory of its own.

    Leftovers from an interrupted build are removed rather than scanned into:
    mixing two passes' features would produce an index whose manifest attests
    bytes that no single scan ever produced.
    """

    if staging.exists():
        purge_controlled_directory(staging)
    provision_controlled_scratch_root(staging, anchor=root)


def _publish(staging: Path, published: Path) -> None:
    """Make a finished index readable, in one filesystem operation.

    The rename is what publication IS.  Until it happens the only directory on
    disk carries the staging suffix, so there is no window in which a reader can
    see a directory under the published name holding a partially written index.
    """

    if published.exists():
        purge_controlled_directory(published)
    os.rename(staging, published)


def _discard(staging: Path) -> None:
    """Remove the private directory of a build that did not finish.

    A failure to remove it is not raised over the failure that caused it: the
    next build purges the same directory before it provisions, so an unremoved
    staging directory costs disk, never correctness.
    """

    try:
        if staging.exists():
            purge_controlled_directory(staging)
    except (ControlledScratchError, OSError):
        return


def _index_record(identity: Mapping[str, object], manifest: Mapping[str, object]) -> dict[str, object]:
    """What an index is, in the terms a caller can compare two of them by."""

    return {
        "index_key": manifest.get("index_key"),
        "evidence_sha256": identity.get("evidence_sha256"),
        "scanner": identity.get("scanner"),
        "scanner_version": identity.get("scanner_version"),
        "scanners_enabled": enabled_scanners(identity),
        "features": attested_features(manifest),
        "coverage_limit": INDEX_COVERAGE_LIMIT,
    }


def build_entity_index(
    image_path: str,
    *,
    index_root: str | os.PathLike[str] | None = None,
    evidence_sha256: str | None = None,
    scanners: Sequence[str] | None = ENTITY_INDEX_SCANNERS,
    scanner_version: str | None = None,
    progress: IndexProgress | None = None,
    rebuild: bool = False,
) -> dict[str, object]:
    """Build this evidence item's entity index once, or report the one that exists.

    `index_root` is the ONE controlled directory the index may live below, and it
    must outlive the run: a run-scoped scratch session is refused, because an
    index destroyed with the run is the problem this store was written to fix.

    `scanners` defaults to :data:`ENTITY_INDEX_SCANNERS`, the recorders this store
    is read through; ``None`` asks for the binary's own default set instead, which
    costs a great deal more and produces nothing this store serves.

    Returns {"index": {index_key, evidence_sha256, scanner, scanner_version,
    scanners_enabled, features}, "state": "built" | "reused"}, or a structured
    error. Nothing raises to the caller.
    """

    binary = bulk_extractor_path()
    if not binary:
        return {
            "error": "bulk_extractor not found. Install it (github.com/simsong/bulk_extractor) "
            "or set DFA_BULK_EXTRACTOR. Run `dfir-agent --doctor`."
        }
    try:
        root, identity = _prepare(
            image_path, index_root, evidence_sha256, scanners, scanner_version
        )
        # Before the lock, before staging, before a single byte: a scan whose
        # output cannot be contained is not started and leaves nothing behind.
        _assert_scan_is_containable(root, enabled_scanners(identity))
    except EntityIndexError as error:
        return {"error": f"the entity index was refused: {str(error)[:200]}"}
    except StorageContainmentError as error:
        return {"error": f"the entity index was refused: {error}"}
    key = index_key(identity)
    published, staging = _index_paths(root, key)
    try:
        with _index_lock((_identity(root), key)):
            existing = _open_index(root, published, identity)
            if existing is not None and not rebuild:
                return {"index": _index_record(identity, existing), "state": "reused"}
            _report(progress, INDEX_STARTED, None)
            try:
                _provision_staging(root, staging)
                _scan(image_path, binary, enabled_scanners(identity), staging, progress)
                if not staging.is_dir() or not _inside(root, staging):
                    raise EntityIndexError(
                        "the scanner did not write inside the controlled index root"
                    )
                manifest = build_manifest(staging, identity=identity)
                write_manifest(staging, manifest)
                _publish(staging, published)
            except Exception as error:
                _discard(staging)
                _report(progress, INDEX_FAILED, None)
                return tool_failure_result(error, subject=str(image_path), backend=_SCANNER)
            _report(progress, INDEX_FINISHED, 100.0)
            return {"index": _index_record(identity, manifest), "state": "built"}
    except Exception as error:
        return tool_failure_result(error, subject=str(image_path), backend=_SCANNER)
