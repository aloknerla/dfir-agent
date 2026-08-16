"""Whether a directory this process writes to is shared with the host filesystem.

Execution is isolated by the container; writes are not.  A bind mount puts bytes
on the host's own filesystem, so a tool that reconstructs file content out of the
evidence — a carver, an archive unpacker, a memory region dumper — writes real
executables onto the host the moment its output directory is a bind mount.  A
host on-access scanner can then quarantine those files underneath the running
tool, which both defeats the isolation and truncates the tool's output without
saying so, turning a partial scan into a smaller result that reads as complete.

This module answers one question: given a directory, is a write to it a write to
the host's filesystem.  The answer is taken from the mount table rather than from
a configuration value, because a configuration value states the intent and the
mount table states what is actually mounted.  It fails closed: inside a container
whose mount table cannot be read, every directory is host-shared.

Nothing here is a defence against a hostile container runtime.  It stops a
correct deployment from writing extracted payloads to the wrong side of its own
isolation boundary.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

WRITE_SCOPE_SCHEMA_ID = "forensic.evidence-write-scope.v1"

#: The directory a deployment sets aside for reconstructed evidence content.  It
#: is expected to be container-private storage — a named volume or a tmpfs —
#: and is ignored when it is not, so a misconfigured value degrades to "there is
#: no payload root" rather than to "payloads are written to the host".
PAYLOAD_ROOT_VARIABLE = "DFA_PAYLOAD_ROOT"

_MOUNTINFO = Path("/proc/self/mountinfo")
_DOCKER_MARKER = Path("/.dockerenv")
_PODMAN_MARKER = Path("/run/.containerenv")
_CONTAINERIZED_VARIABLE = "DFA_CONTAINERIZED"
_CONTAINERIZED_VALUES = frozenset({"1", "true", "yes", "on"})

#: Filesystems a container runtime projects a host directory through.  Docker
#: Desktop uses virtiofs (and, on older builds, gRPC-FUSE or 9p) for every bind
#: mount; the network filesystems are here because a bind whose host side is a
#: share is still a write that leaves this machine.
_HOST_PROJECTED_FILESYSTEMS = frozenset(
    {
        "9p",
        "cifs",
        "fuse.grpcfuse",
        "fuse.osxfs",
        "fuse.sshfs",
        "grpcfuse",
        "lofs",
        "nfs",
        "nfs4",
        "smb3",
        "vboxsf",
        "virtiofs",
    }
)

#: Filesystems that exist only for this container.  A tmpfs never reaches a
#: disk the host mounts, and the overlay is the container's own writable layer.
_CONTAINER_PRIVATE_FILESYSTEMS = frozenset(
    {
        "autofs",
        "binfmt_misc",
        "bpf",
        "cgroup",
        "cgroup2",
        "configfs",
        "debugfs",
        "devpts",
        "devtmpfs",
        "fusectl",
        "hugetlbfs",
        "mqueue",
        "nsfs",
        "overlay",
        "overlay2",
        "proc",
        "pstore",
        "ramfs",
        "securityfs",
        "sysfs",
        "tmpfs",
        "tracefs",
    }
)

#: Where a container runtime keeps the backing directory of a named volume.  On
#: an ordinary Linux engine a named volume and a host bind mount are the same
#: filesystem type, so the mount's root inside that filesystem is what separates
#: them: a named volume's root is the runtime's own data directory, and a bind
#: mount's root is whichever host directory the operator named.
_MANAGED_VOLUME_ROOTS = (
    "/var/lib/docker/volumes/",
    "/var/lib/containers/storage/volumes/",
    "/var/lib/containerd/",
    # Docker Desktop's WSL2 and LinuxKit backends keep the volume store under
    # /data, not /var/lib.  Without this the project's own named volume reaches
    # the final branch below and is read as a bind mount, so the one directory
    # provisioned to hold reconstructed payloads is classified host-shared and
    # every payload-producing tool refuses.  Observed on Docker Desktop:
    # /data/docker/volumes/<project>_payload-scratch/_data mounted at /payload,
    # ext4 on a VM-local disk, while the genuine host binds beside it are 9p.
    "/data/docker/volumes/",
)

#: A rootless engine keeps the same volume layout under the operator's home
#: (~/.local/share/docker/volumes/<name>/_data; podman under
#: ~/.local/share/containers/storage/volumes/<name>/_data), which no fixed
#: prefix can enumerate.  The layout itself is the runtime's signature: only a
#: container runtime roots a mount at .../volumes/<name>/_data of its own data
#: directory.  Matched on the mount ROOT, never the mount point, and only in
#: addition to the prefixes above — everything else stays fail-closed.
_MANAGED_VOLUME_ROOT_PATTERN = re.compile(
    r"/(?:docker|containers/storage)/volumes/[^/]+/_data$"
)


class StorageContainmentError(RuntimeError):
    """A write of reconstructed evidence content was refused, or misdirected."""


class StorageExposure(StrEnum):
    """Where the bytes written to a directory actually land."""

    #: Inside this container or its runtime's own storage.  The host filesystem
    #: does not see them and a scanner running on the host cannot remove them.
    CONTAINED = "contained"
    #: On the host's filesystem, through a bind mount or a network share.
    HOST_SHARED = "host-shared"


def _flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in _CONTAINERIZED_VALUES


def containerized() -> bool:
    """Whether this process runs inside a container that has a host to share with.

    Outside one there is no isolation boundary for a write to cross: the process
    already runs on the host, and every path it can name is the host's.
    """

    if _flag(_CONTAINERIZED_VARIABLE):
        return True
    return _DOCKER_MARKER.exists() or _PODMAN_MARKER.exists()


def _read_mount_table() -> str | None:
    """The kernel's view of what is mounted where, or nothing when unreadable."""

    try:
        return _MOUNTINFO.read_text(encoding="utf-8", errors="strict")
    except (OSError, ValueError):
        return None


def _unescape(field: str) -> str:
    """Decode the octal escapes ``mountinfo`` uses for space, tab, newline and backslash."""

    if "\\" not in field:
        return field
    out: list[str] = []
    index = 0
    while index < len(field):
        character = field[index]
        if character == "\\" and index + 3 < len(field) and field[index + 1 : index + 4].isdigit():
            out.append(chr(int(field[index + 1 : index + 4], 8)))
            index += 4
            continue
        out.append(character)
        index += 1
    return "".join(out)


def parse_mount_table(text: str) -> tuple[tuple[str, str, str], ...]:
    """Return ``(mount point, mount root, filesystem type)`` for every mount.

    ``mountinfo`` puts a variable number of optional fields before a ``-``
    separator, so the fixed fields are read from the front and the filesystem
    type from the first field after the separator.  A line that does not have
    that shape is skipped rather than guessed at; the caller's fail-closed
    default covers a table this cannot read.
    """

    entries: list[tuple[str, str, str]] = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 10 or "-" not in fields:
            continue
        separator = fields.index("-")
        if separator < 6 or separator + 1 >= len(fields):
            continue
        entries.append(
            (
                _unescape(fields[4]),
                _unescape(fields[3]),
                fields[separator + 1],
            )
        )
    return tuple(entries)


def host_shared_mount_points(text: str) -> tuple[str, ...]:
    """Every mount point in ``text`` below which a write reaches the host."""

    points: list[str] = []
    for mount_point, mount_root, filesystem in parse_mount_table(text):
        if filesystem in _HOST_PROJECTED_FILESYSTEMS:
            points.append(mount_point)
            continue
        if filesystem in _CONTAINER_PRIVATE_FILESYSTEMS:
            continue
        if (
            mount_root == "/"
            or mount_root.startswith(_MANAGED_VOLUME_ROOTS)
            or _MANAGED_VOLUME_ROOT_PATTERN.search(mount_root) is not None
        ):
            continue
        # A local filesystem mounted at a sub-path of itself is a bind mount, and
        # the only thing a container runtime binds is a host directory.
        points.append(mount_point)
    return tuple(points)


def _covers(mount_point: str, path: str) -> bool:
    if mount_point == path:
        return True
    prefix = mount_point if mount_point.endswith("/") else f"{mount_point}/"
    return path.startswith(prefix)


def _mount_table_path(path: str | os.PathLike[str]) -> str:
    """The candidate as the mount table would name it.

    Symlinks are resolved first, because a link that sits on the container's own
    filesystem but leads into a bind mount is still a write to the host.
    Separators are normalised so the comparison also holds on a development host
    whose native separator is not the mount table's; a literal backslash in a
    Linux path would be the only casualty, and no directory this project
    provisions carries one.
    """

    resolved = os.path.realpath(os.fspath(path))
    return resolved.replace("\\", "/") if os.sep != "/" else resolved


def classify_directory(path: str | os.PathLike[str]) -> StorageExposure:
    """Report where a write below ``path`` actually lands."""

    if not containerized():
        return StorageExposure.CONTAINED
    text = _read_mount_table()
    if text is None:
        # Containerized with no mount table to inspect.  The conservative answer
        # is the only safe one: a payload must never be written on an assumption
        # about where it will land.
        return StorageExposure.HOST_SHARED
    resolved = _mount_table_path(path)
    for mount_point in host_shared_mount_points(text):
        if _covers(mount_point, resolved):
            return StorageExposure.HOST_SHARED
    return StorageExposure.CONTAINED


def payload_scratch_root() -> Path | None:
    """The deployment's container-private root for reconstructed evidence content.

    Returns ``None`` when none is declared, when the declared one does not exist,
    or when it is host-shared after all.  A caller treats that as "there is
    nowhere contained to write", which is a reason to refuse a payload-producing
    tool — never a reason to write the payload to the host instead.
    """

    configured = os.environ.get(PAYLOAD_ROOT_VARIABLE, "").strip()
    if not configured:
        return None
    candidate = Path(configured)
    if not candidate.is_absolute() or not candidate.is_dir():
        return None
    if classify_directory(candidate) is not StorageExposure.CONTAINED:
        return None
    return candidate


def assert_payload_root_contained(path: str | os.PathLike[str], *, subject: str) -> None:
    """Refuse a directory that is demonstrably shared with the host filesystem.

    This is the weaker of the two checks here, and deliberately so: it fires on
    evidence from the mount table, so it changes nothing for a process that is
    not containerized at all and has no boundary to cross.  ``subject`` names the
    tool, because the refusal has to say which capability just became
    unavailable and why.
    """

    if classify_directory(path) is StorageExposure.CONTAINED:
        return
    raise StorageContainmentError(
        f"{subject} reconstructs file content out of the evidence, and its output "
        "directory is shared with the host filesystem. Executable payloads carved or "
        "unpacked from evidence must not be written where the host can reach them. "
        f"Point {PAYLOAD_ROOT_VARIABLE} at container-private storage (a named volume "
        "or a tmpfs) and re-run; nothing was scanned and nothing was written."
    )


def require_declared_payload_root(path: str | os.PathLike[str], *, subject: str) -> None:
    """Refuse unless ``path`` sits inside the deployment's declared contained root.

    The stronger check, for a write whose bytes are bulk reconstructed content
    that nothing afterwards reads — carved images, unpacked archive members.
    "The mount table shows no bind mount" is not good enough there, because a
    process running natively on the analyst's own machine has no bind mount and
    every byte it writes is on that machine.  Somewhere contained has to have
    been declared, and the write has to be going there.

    This is what stops a caller reaching the write at all: a written instruction
    not to run such a scan is not an enforcement control, since it can be ignored.
    """

    root = payload_scratch_root()
    if root is not None:
        candidate = _mount_table_path(path)
        if _covers(_mount_table_path(root), candidate):
            return
    raise StorageContainmentError(
        f"{subject} would reconstruct file content out of the evidence in bulk, and "
        "there is no container-private location to put it. Carved images and unpacked "
        "archive members are the executables the evidence is an investigation of, and "
        "they are not written to storage the host filesystem can see. Declare "
        f"{PAYLOAD_ROOT_VARIABLE} as a Docker named volume or a tmpfs and direct this "
        "output below it; nothing was scanned and nothing was written."
    )


class EvidenceWriteScope(StrEnum):
    """Which of the two containment checks the write-scope facade applied.

    The value is carried in the grant's record, so a caller that asked for the
    weaker check has had to name it and the record shows which check ran.
    """

    #: The default.  The directory must sit inside the deployment's declared
    #: container-private payload root, and there being no declared root is itself
    #: a refusal.  This is :func:`require_declared_payload_root`.
    DECLARED_ROOT = "require-declared-payload-root"

    #: Reachable only by naming it.  The directory must merely not be
    #: demonstrably shared with the host filesystem, which passes trivially on a
    #: non-containerized host.  This is :func:`assert_payload_root_contained`,
    #: and it is the right check only for a working directory whose bytes are not
    #: retained bulk payload — a subprocess scratch tree the container's rebind
    #: already lands inside contained storage, made explicit here.
    NOT_HOST_SHARED = "assert-not-host-shared"


@dataclass(frozen=True, slots=True)
class EvidenceWriteGrant:
    """Evidence that one directory passed the containment check named in it."""

    directory: Path
    subject: str
    scope: EvidenceWriteScope
    directory_sha256: str

    def record(self) -> dict[str, str]:
        """A portable record of the grant that never carries the raw path."""

        return {
            "schema_id": WRITE_SCOPE_SCHEMA_ID,
            "subject": self.subject,
            "write_scope": str(self.scope),
            "directory_sha256": self.directory_sha256,
        }


def acquire_evidence_write_dir(
    directory: str | os.PathLike[str],
    *,
    subject: str,
    scope: EvidenceWriteScope = EvidenceWriteScope.DECLARED_ROOT,
) -> EvidenceWriteGrant:
    """The single supported way to obtain a writable directory for evidence output.

    Every path that writes content reconstructed out of the evidence — a carved
    image, an unpacked archive member, a reconstructed exfiltration payload, a
    parser's staging copy — resolves its destination here first.  The default is
    the strong :func:`require_declared_payload_root`: the directory has to sit
    inside a declared container-private payload root, and there being no declared
    root is a refusal rather than a pass.  The weaker
    :func:`assert_payload_root_contained` is reachable only by passing ``scope``
    explicitly, and the scope the caller chose is written into the returned
    grant's :meth:`EvidenceWriteGrant.record`, so a weakened write is visible
    wherever that record is kept instead of being an invisible default.

    A refused directory raises :class:`StorageContainmentError`; the caller has
    then obtained nothing and writes nothing.  This does not create the directory
    — it decides whether the directory may receive the bytes and records the
    decision; the caller creates its own workspace below the returned path.
    """

    if not isinstance(subject, str) or not subject:
        raise StorageContainmentError("an evidence write must name its subject")
    if scope is EvidenceWriteScope.DECLARED_ROOT:
        require_declared_payload_root(directory, subject=subject)
    elif scope is EvidenceWriteScope.NOT_HOST_SHARED:
        assert_payload_root_contained(directory, subject=subject)
    else:  # pragma: no cover - the enum is closed
        raise StorageContainmentError("unknown evidence write scope")
    resolved = _mount_table_path(directory)
    digest = hashlib.sha256(resolved.encode("utf-8", errors="strict")).hexdigest()
    return EvidenceWriteGrant(
        directory=Path(directory),
        subject=subject,
        scope=scope,
        directory_sha256=digest,
    )
