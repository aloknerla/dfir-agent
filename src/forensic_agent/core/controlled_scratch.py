"""Bounded scratch storage for ephemeral forensic parser copies.

The model never chooses or receives a host path.  A caller provisions one exact
root, records its path/volume/directory identity, and passes a per-run session to
trusted tool wrappers.  Workspaces and payload names come from a closed enum,
are created exclusively, and are removed before a successful session close.

This is an execution-integrity control, not secure erasure or an OS sandbox.  It
prevents accidental use of ambient TEMP/TMP, traversal, symlink/reparse roots,
name collisions, and silently ignored cleanup failures.  It does not defend
against a malicious local administrator racing filesystem operations.
"""

from __future__ import annotations

import hashlib
import os
import stat
import threading
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO, Literal

from forensic_agent.core.repro import canonical_json, sha256_hex

CONTROLLED_SCRATCH_ROOT_SCHEMA_ID = "forensic.controlled-scratch-root.v1"
CONTROLLED_SCRATCH_RUNTIME_SCHEMA_ID = "forensic.controlled-scratch-runtime.v1"
CONTROLLED_SCRATCH_LAYOUT_ID = "exclusive-run-call-fixed-payload.v1"
CONTROLLED_SCRATCH_CLEANUP_POLICY = "tracked-files-removed-workspace-removed-root-empty.v1"

_WINDOWS_REPARSE_POINT = 0x0400


class ControlledScratchError(RuntimeError):
    """The controlled scratch authority or lifecycle failed closed."""


class ScratchKind(StrEnum):
    """Closed set of trusted scratch consumers; never populated from model text."""

    REGISTRY_HIVE = "registry-hive"
    EVTX_LOG = "evtx-log"
    SQLITE_DB = "sqlite-db"

    @property
    def payload_name(self) -> str:
        return {
            ScratchKind.REGISTRY_HIVE: "payload.hive",
            ScratchKind.EVTX_LOG: "payload.evtx",
            ScratchKind.SQLITE_DB: "payload.sqlite",
        }[self]


class ScratchWorkspaceKind(StrEnum):
    """Closed set of tool-runtime directory names; never populated from model text."""

    TOOL_RUNTIME = "tool-runtime"
    SCAN_OUTPUTS = "scan-outputs"
    #: Hive copies the run's registry reads share.  An immutable hive extracted
    #: for one call answers every later identical extraction, so the copy must
    #: outlive the call that staged it: the session, not the caller, owns and
    #: purges it — the same reasoning SCAN_OUTPUTS states for a scan.
    REGISTRY_HIVE_CACHE = "registry-hive-cache"

    @property
    def retained(self) -> bool:
        """True when the session, not the caller, owns the workspace lifetime.

        A caller-owned workspace is released by its own ``with`` block and must be
        gone before the session may close.  A retained workspace deliberately
        outlives every individual call, so only the session can remove it.
        """

        return self is not ScratchWorkspaceKind.TOOL_RUNTIME


def _path_commitment(path: Path) -> str:
    normalized = os.path.normcase(os.path.normpath(os.path.realpath(path)))
    return hashlib.sha256(normalized.encode("utf-8", errors="strict")).hexdigest()


def _is_reparse(stat_result: os.stat_result) -> bool:
    attributes = int(getattr(stat_result, "st_file_attributes", 0) or 0)
    return bool(attributes & _WINDOWS_REPARSE_POINT)


def _absolute_local_path(path: Path, *, label: str) -> Path:
    if not isinstance(path, Path):
        raise ControlledScratchError(f"{label} must be an exact pathlib.Path")
    raw = os.fspath(path)
    if not raw or "\x00" in raw:
        raise ControlledScratchError(f"{label} is empty or malformed")
    if os.name == "nt":
        normalized = raw.replace("/", "\\")
        if normalized.startswith(("\\\\", "\\?\\", "\\.\\")):
            raise ControlledScratchError(f"{label} must be a local drive path")
        drive, tail = os.path.splitdrive(normalized)
        if not drive or not tail.startswith("\\"):
            raise ControlledScratchError(f"{label} must be drive-absolute")
    if not path.is_absolute():
        raise ControlledScratchError(f"{label} must be absolute")
    if any(part in {".", ".."} for part in path.parts):
        raise ControlledScratchError(f"{label} cannot contain traversal components")
    return Path(os.path.abspath(raw))


def _validate_components(path: Path, *, require_directory: bool) -> os.stat_result:
    """lstat every existing component and reject links/reparse points."""

    current = Path(path.anchor)
    components = path.parts[1:]
    if not current.exists():  # pragma: no cover - malformed/unmounted platform root
        raise ControlledScratchError("scratch path anchor does not exist")
    for part in components:
        current = current / part
        try:
            observed = os.lstat(current)
        except OSError as exc:
            raise ControlledScratchError("scratch path component does not exist") from exc
        if stat.S_ISLNK(observed.st_mode) or _is_reparse(observed):
            raise ControlledScratchError("scratch path contains a symlink or reparse point")
    try:
        final = os.lstat(path)
    except OSError as exc:  # pragma: no cover - covered by component walk in normal paths
        raise ControlledScratchError("scratch root cannot be inspected") from exc
    if stat.S_ISLNK(final.st_mode) or _is_reparse(final):
        raise ControlledScratchError("scratch root is a symlink or reparse point")
    if require_directory and not stat.S_ISDIR(final.st_mode):
        raise ControlledScratchError("scratch root is not a directory")
    return final


@dataclass(frozen=True, slots=True)
class ControlledScratchRootAttestation:
    """Portable commitment plus a runtime-only exact root path."""

    root_path: Path = field(repr=False, compare=False)
    path_sha256: str
    volume_anchor: str
    device_id: int
    directory_id: int
    schema_id: str = CONTROLLED_SCRATCH_ROOT_SCHEMA_ID
    layout_id: str = CONTROLLED_SCRATCH_LAYOUT_ID
    cleanup_policy: str = CONTROLLED_SCRATCH_CLEANUP_POLICY

    def __post_init__(self) -> None:
        if not isinstance(self.root_path, Path) or not self.root_path.is_absolute():
            raise ControlledScratchError("scratch attestation lacks an absolute runtime path")
        if len(self.path_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in self.path_sha256
        ):
            raise ControlledScratchError("scratch path commitment is not SHA-256")
        if not self.volume_anchor:
            raise ControlledScratchError("scratch volume anchor is empty")
        if isinstance(self.device_id, bool) or not isinstance(self.device_id, int):
            raise ControlledScratchError("scratch device identity is invalid")
        if isinstance(self.directory_id, bool) or not isinstance(self.directory_id, int):
            raise ControlledScratchError("scratch directory identity is invalid")
        if self.schema_id != CONTROLLED_SCRATCH_ROOT_SCHEMA_ID:
            raise ControlledScratchError("unknown scratch root schema")
        if self.layout_id != CONTROLLED_SCRATCH_LAYOUT_ID:
            raise ControlledScratchError("unknown scratch layout")
        if self.cleanup_policy != CONTROLLED_SCRATCH_CLEANUP_POLICY:
            raise ControlledScratchError("unknown scratch cleanup policy")

    def record(self) -> dict[str, object]:
        return {
            "schema_id": self.schema_id,
            "path_sha256": self.path_sha256,
            "path_digest_semantics": "sha256-utf8-realpath-normcase-normpath.v1",
            "volume_anchor": self.volume_anchor,
            "device_id": self.device_id,
            "directory_id": self.directory_id,
            "layout_id": self.layout_id,
            "cleanup_policy": self.cleanup_policy,
        }

    @property
    def sha256(self) -> str:
        return sha256_hex(canonical_json(self.record()).encode("utf-8"))


def attest_controlled_scratch_root(path: Path) -> ControlledScratchRootAttestation:
    absolute = _absolute_local_path(path, label="controlled scratch root")
    observed = _validate_components(absolute, require_directory=True)
    return ControlledScratchRootAttestation(
        root_path=absolute,
        path_sha256=_path_commitment(absolute),
        volume_anchor=os.path.normcase(absolute.anchor),
        device_id=int(observed.st_dev),
        directory_id=int(observed.st_ino),
    )


def assert_controlled_scratch_root_current(
    attestation: ControlledScratchRootAttestation,
) -> None:
    if type(attestation) is not ControlledScratchRootAttestation:
        raise ControlledScratchError("scratch authority must be an exact attestation")
    current = attest_controlled_scratch_root(attestation.root_path)
    if current.record() != attestation.record():
        raise ControlledScratchError("controlled scratch root identity changed")


def provision_controlled_scratch_root(
    path: Path,
    *,
    anchor: Path,
) -> ControlledScratchRootAttestation:
    """Create a dedicated root below an explicit existing safe anchor."""

    absolute_anchor = _absolute_local_path(anchor, label="scratch provisioning anchor")
    _validate_components(absolute_anchor, require_directory=True)
    absolute_path = _absolute_local_path(path, label="controlled scratch root")
    try:
        inside = os.path.commonpath((os.fspath(absolute_anchor), os.fspath(absolute_path)))
    except ValueError as exc:
        raise ControlledScratchError("scratch root is on a different volume") from exc
    if os.path.normcase(inside) != os.path.normcase(os.fspath(absolute_anchor)):
        raise ControlledScratchError("scratch root is outside its provisioning anchor")
    relative = absolute_path.relative_to(absolute_anchor)
    if not relative.parts:
        raise ControlledScratchError("scratch root must be below its provisioning anchor")
    current = absolute_anchor
    for part in relative.parts:
        if part in {"", ".", ".."}:
            raise ControlledScratchError("scratch provisioning path contains traversal")
        current = current / part
        try:
            os.mkdir(current, mode=0o700)
        except FileExistsError:
            pass
        except OSError as exc:
            raise ControlledScratchError("scratch directory could not be provisioned") from exc
        _validate_components(current, require_directory=True)
    return attest_controlled_scratch_root(absolute_path)


class ScratchArtifact:
    """One exclusively allocated fixed-name parser payload."""

    def __init__(
        self,
        session: ControlledScratchSession,
        kind: ScratchKind,
        sequence: int,
    ) -> None:
        self._session = session
        self.kind = kind
        self._closed = False
        self._sealed = False
        self._workspace = session._session_path / f"{sequence:06d}-{kind.value}"
        try:
            os.mkdir(self._workspace, mode=0o700)
        except OSError as exc:
            raise ControlledScratchError("scratch workspace creation was not exclusive") from exc
        _validate_components(self._workspace, require_directory=True)
        self.path = self._workspace / kind.payload_name
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        try:
            descriptor = os.open(self.path, flags, 0o600)
        except OSError as exc:
            try:
                os.rmdir(self._workspace)
            except OSError:
                pass
            raise ControlledScratchError("scratch payload creation was not exclusive") from exc
        self.writer: BinaryIO = os.fdopen(descriptor, "wb")
        identity = os.fstat(self.writer.fileno())
        if not stat.S_ISREG(identity.st_mode):  # pragma: no cover - exclusive create guarantees it
            self.writer.close()
            raise ControlledScratchError("scratch payload is not a regular file")
        self._identity = (int(identity.st_dev), int(identity.st_ino))

    def __enter__(self) -> ScratchArtifact:
        return self

    def seal(self) -> Path:
        if self._closed:
            raise ControlledScratchError("scratch artifact is already closed")
        if not self.writer.closed:
            self.writer.flush()
            os.fsync(self.writer.fileno())
            self.writer.close()
        observed = os.lstat(self.path)
        if (
            not stat.S_ISREG(observed.st_mode)
            or stat.S_ISLNK(observed.st_mode)
            or _is_reparse(observed)
            or (int(observed.st_dev), int(observed.st_ino)) != self._identity
        ):
            raise ControlledScratchError("scratch payload identity changed before parsing")
        self._sealed = True
        return self.path

    def _cleanup(self) -> None:
        if self._closed:
            return
        error: BaseException | None = None
        if not self.writer.closed:
            try:
                self.writer.close()
            except OSError as exc:
                error = exc
        try:
            entries = list(os.scandir(self._workspace))
        except OSError as exc:
            entries = []
            error = error or exc
        expected_name = self.path.name
        unexpected = [entry.name for entry in entries if entry.name != expected_name]
        if unexpected:
            error = error or ControlledScratchError(
                "scratch workspace contains an unexpected entry"
            )
        try:
            observed = os.lstat(self.path)
        except FileNotFoundError:
            observed = None
            error = error or ControlledScratchError("scratch payload disappeared before cleanup")
        except OSError as exc:
            observed = None
            error = error or exc
        if observed is not None:
            if (
                not stat.S_ISREG(observed.st_mode)
                or stat.S_ISLNK(observed.st_mode)
                or _is_reparse(observed)
                or (int(observed.st_dev), int(observed.st_ino)) != self._identity
            ):
                error = error or ControlledScratchError(
                    "scratch cleanup refused an untracked payload identity"
                )
            else:
                try:
                    os.unlink(self.path)
                except OSError as exc:
                    error = error or exc
        try:
            os.rmdir(self._workspace)
        except OSError as exc:
            error = error or exc
        self._closed = True
        self._session._artifact_closed(self, cleanup_ok=error is None)
        if error is not None:
            raise ControlledScratchError("scratch artifact cleanup was not verified") from error

    def __exit__(self, exc_type, exc, traceback) -> Literal[False]:
        del exc_type, traceback
        try:
            self._cleanup()
        except ControlledScratchError as cleanup_error:
            if exc is not None:
                raise cleanup_error from exc
            raise
        return False


class ToolRuntimeWorkspace:
    """One tracked DEV-only workspace for subprocess and ``tempfile`` outputs.

    Unlike :class:`ScratchArtifact`, a verified forensic subprocess legitimately
    creates an implementation-defined directory tree.  The tree is therefore
    confined below one exclusively created per-run directory, walked without
    following links, and removed completely before the owning session can close.
    The model receives paths produced by tools, but it never chooses this root.
    """

    def __init__(
        self,
        session: ControlledScratchSession,
        sequence: int,
        *,
        kind: ScratchWorkspaceKind,
    ) -> None:
        self._session = session
        self.kind = kind
        self._closed = False
        self.path = session._session_path / f"{sequence:06d}-{kind.value}"
        try:
            os.mkdir(self.path, mode=0o700)
        except OSError as exc:
            raise ControlledScratchError(
                "tool-runtime workspace creation was not exclusive"
            ) from exc
        observed = _validate_components(self.path, require_directory=True)
        self._identity = (int(observed.st_dev), int(observed.st_ino))

    def __enter__(self) -> ToolRuntimeWorkspace:
        return self

    @staticmethod
    def _remove_children(directory: Path) -> BaseException | None:
        """Remove a bounded tree without ever following a link or reparse point."""

        error: BaseException | None = None
        try:
            entries = list(os.scandir(directory))
        except OSError as exc:
            return exc
        for entry in entries:
            child = Path(entry.path)
            try:
                observed = os.lstat(child)
            except OSError as exc:
                error = error or exc
                continue
            is_link = stat.S_ISLNK(observed.st_mode) or _is_reparse(observed)
            if is_link:
                # A trusted tool is not expected to create links.  Remove the link
                # itself (never its target), but retain a failed-cleanup signal.
                error = error or ControlledScratchError(
                    "tool-runtime workspace contained a link or reparse point"
                )
                try:
                    if stat.S_ISDIR(observed.st_mode):
                        os.rmdir(child)
                    else:
                        os.unlink(child)
                except OSError as exc:
                    error = error or exc
                continue
            if stat.S_ISDIR(observed.st_mode):
                nested_error = ToolRuntimeWorkspace._remove_children(child)
                error = error or nested_error
                try:
                    os.rmdir(child)
                except OSError as exc:
                    error = error or exc
                continue
            if not stat.S_ISREG(observed.st_mode):
                error = error or ControlledScratchError(
                    "tool-runtime workspace contained a non-regular filesystem object"
                )
            try:
                os.unlink(child)
            except OSError as exc:
                error = error or exc
        return error

    def _cleanup(self) -> None:
        if self._closed:
            return
        error = _remove_pinned_directory(self.path, self._identity)
        self._closed = True
        self._session._tool_runtime_closed(self, cleanup_ok=error is None)
        if error is not None:
            raise ControlledScratchError(
                "tool-runtime workspace cleanup was not verified"
            ) from error

    def __exit__(self, exc_type, exc, traceback) -> Literal[False]:
        del exc_type, traceback
        try:
            self._cleanup()
        except ControlledScratchError as cleanup_error:
            if exc is not None:
                raise cleanup_error from exc
            raise
        return False


def _remove_pinned_directory(
    path: Path,
    identity: tuple[int, int],
) -> BaseException | None:
    """Remove one pinned directory tree, returning the first failure observed.

    Kept separate from the bookkeeping callback in
    :meth:`ToolRuntimeWorkspace._cleanup` so a caller that already holds the
    session lock performs only filesystem work here, and so every removal below a
    controlled root goes through the same identity pin and the same lstat-only
    walk instead of a second, weaker routine.
    """

    try:
        observed = os.lstat(path)
    except OSError as exc:
        return exc
    if (
        not stat.S_ISDIR(observed.st_mode)
        or stat.S_ISLNK(observed.st_mode)
        or _is_reparse(observed)
        or (int(observed.st_dev), int(observed.st_ino)) != identity
    ):
        return ControlledScratchError("controlled directory identity changed before removal")
    # Resolved on the class so a test double installed on it is honoured.
    error = ToolRuntimeWorkspace._remove_children(path)
    try:
        os.rmdir(path)
    except OSError as exc:
        error = error or exc
    return error


def purge_controlled_directory(path: Path) -> None:
    """Remove one directory tree below a controlled root, or fail closed.

    Trusted tool wrappers that provision their own output directory below a
    controlled root use this instead of ``shutil.rmtree``: the tree is pinned to
    the exact directory that was inspected, links and reparse points are refused
    rather than followed, and a removal that did not happen is raised instead of
    being reported as a successful release.
    """

    absolute = _absolute_local_path(path, label="controlled directory")
    try:
        observed = os.lstat(absolute)
    except OSError as exc:
        raise ControlledScratchError("controlled directory cannot be inspected") from exc
    if (
        not stat.S_ISDIR(observed.st_mode)
        or stat.S_ISLNK(observed.st_mode)
        or _is_reparse(observed)
    ):
        raise ControlledScratchError("controlled directory is not a plain directory")
    error = _remove_pinned_directory(absolute, (int(observed.st_dev), int(observed.st_ino)))
    if error is not None:
        raise ControlledScratchError("controlled directory removal was not verified") from error


class ControlledScratchSession:
    """Per-run scratch authority injected into trusted tool closures."""

    def __init__(
        self,
        attestation: ControlledScratchRootAttestation,
        *,
        namespace: str,
    ) -> None:
        if type(attestation) is not ControlledScratchRootAttestation:
            raise ControlledScratchError("scratch session requires an exact root attestation")
        if not isinstance(namespace, str) or not namespace:
            raise ControlledScratchError("scratch namespace must be non-empty text")
        assert_controlled_scratch_root_current(attestation)
        try:
            if any(attestation.root_path.iterdir()):
                raise ControlledScratchError("controlled scratch root is not empty at run start")
        except OSError as exc:
            raise ControlledScratchError("controlled scratch root cannot be enumerated") from exc
        self.attestation = attestation
        # Reentrant: close() purges the workspaces the session retains while
        # holding this lock, and each cleanup reports back through
        # _tool_runtime_closed, which takes the same lock on the same thread.
        self._lock = threading.RLock()
        self._sequence = 0
        self._active: set[ScratchArtifact | ToolRuntimeWorkspace] = set()
        # Separate from _active on purpose: _active means a caller currently owns
        # the workspace and must release it before close, while a retained
        # workspace is owned by the session and is purged by close itself.
        self._retained: dict[ScratchWorkspaceKind, ToolRuntimeWorkspace] = {}
        self._allocations = 0
        self._cleanups = 0
        self._cleanup_ok = True
        self._closed = False
        namespace_sha = hashlib.sha256(namespace.encode("utf-8")).hexdigest()
        self._namespace_sha256 = namespace_sha
        self._session_path = attestation.root_path / f"run-{namespace_sha[:32]}"
        try:
            os.mkdir(self._session_path, mode=0o700)
        except OSError as exc:
            raise ControlledScratchError(
                "scratch run workspace creation was not exclusive"
            ) from exc
        _validate_components(self._session_path, require_directory=True)

    def artifact(self, kind: ScratchKind) -> ScratchArtifact:
        if type(kind) is not ScratchKind:
            raise ControlledScratchError("scratch kind must come from the closed enum")
        with self._lock:
            if self._closed:
                raise ControlledScratchError("scratch session is closed")
            assert_controlled_scratch_root_current(self.attestation)
            self._sequence += 1
            artifact = ScratchArtifact(self, kind, self._sequence)
            self._active.add(artifact)
            self._allocations += 1
            return artifact

    @property
    def session_path(self) -> Path:
        """Exact private per-run root for policy confinement; never model supplied."""

        return self._session_path

    def tool_runtime_workspace(self) -> ToolRuntimeWorkspace:
        """Allocate the one tracked subtree used by DEV external-tool runtimes."""

        with self._lock:
            if self._closed:
                raise ControlledScratchError("scratch session is closed")
            assert_controlled_scratch_root_current(self.attestation)
            if any(isinstance(item, ToolRuntimeWorkspace) for item in self._active):
                raise ControlledScratchError("tool-runtime workspace is already active")
            self._sequence += 1
            workspace = ToolRuntimeWorkspace(
                self,
                self._sequence,
                kind=ScratchWorkspaceKind.TOOL_RUNTIME,
            )
            self._active.add(workspace)
            self._allocations += 1
            return workspace

    def retained_workspace(self, kind: ScratchWorkspaceKind) -> ToolRuntimeWorkspace:
        """Return the session-owned workspace for ``kind``, allocating it once.

        A tool whose output is expensive to reproduce needs that output to
        survive the call that produced it without any caller holding it open.
        The same workspace is therefore handed to every call for the whole
        session, and only :meth:`close` removes it.
        """

        if type(kind) is not ScratchWorkspaceKind or not kind.retained:
            raise ControlledScratchError("retained workspace kind must come from the closed enum")
        with self._lock:
            if self._closed:
                raise ControlledScratchError("scratch session is closed")
            existing = self._retained.get(kind)
            if existing is not None:
                return existing
            assert_controlled_scratch_root_current(self.attestation)
            self._sequence += 1
            workspace = ToolRuntimeWorkspace(self, self._sequence, kind=kind)
            self._retained[kind] = workspace
            self._allocations += 1
            return workspace

    def _artifact_closed(self, artifact: ScratchArtifact, *, cleanup_ok: bool) -> None:
        with self._lock:
            self._active.discard(artifact)
            self._cleanups += 1
            self._cleanup_ok = self._cleanup_ok and cleanup_ok

    def _tool_runtime_closed(
        self,
        workspace: ToolRuntimeWorkspace,
        *,
        cleanup_ok: bool,
    ) -> None:
        with self._lock:
            self._active.discard(workspace)
            self._cleanups += 1
            self._cleanup_ok = self._cleanup_ok and cleanup_ok

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            if self._active:
                self._cleanup_ok = False
                raise ControlledScratchError("scratch session has active parser artifacts")
            try:
                assert_controlled_scratch_root_current(self.attestation)
                # The session owns these, so it removes them here rather than
                # refusing to close over them.  No tool call can be in flight:
                # the check above already refused while any caller-owned
                # workspace was active.  The emptiness check below is unchanged
                # and still refuses anything the session never tracked.
                purge_error: ControlledScratchError | None = None
                for kind in sorted(self._retained):
                    # One tree that cannot be removed must not leave the others
                    # behind, so every retained workspace is attempted.
                    try:
                        self._retained.pop(kind)._cleanup()
                    except ControlledScratchError as exc:
                        purge_error = purge_error or exc
                if purge_error is not None:
                    raise purge_error
                if any(self._session_path.iterdir()):
                    raise ControlledScratchError("scratch run workspace is not empty")
                os.rmdir(self._session_path)
                if any(self.attestation.root_path.iterdir()):
                    raise ControlledScratchError("controlled scratch root is not empty after run")
            except (OSError, ControlledScratchError) as exc:
                self._cleanup_ok = False
                raise ControlledScratchError("scratch run cleanup was not verified") from exc
            self._closed = True

    def telemetry(self) -> dict[str, object]:
        with self._lock:
            return {
                "schema_id": CONTROLLED_SCRATCH_RUNTIME_SCHEMA_ID,
                "root_attestation_sha256": self.attestation.sha256,
                "layout_id": self.attestation.layout_id,
                "cleanup_policy": self.attestation.cleanup_policy,
                "namespace_sha256": self._namespace_sha256,
                "allocations": self._allocations,
                "cleanups": self._cleanups,
                "active_artifacts": len(self._active),
                "cleanup_ok": self._cleanup_ok,
                "closed": self._closed,
                "session_removed": self._closed and not self._session_path.exists(),
            }

    def __enter__(self) -> ControlledScratchSession:
        return self

    def __exit__(self, exc_type, exc, traceback) -> Literal[False]:
        del exc_type, traceback
        try:
            self.close()
        except ControlledScratchError as cleanup_error:
            if exc is not None:
                raise cleanup_error from exc
            raise
        return False
