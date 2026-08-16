"""Runtime-owned registry of the real versions of the forensic backends.

``provenance.tool.version`` is OUR package version: it identifies the wrapper the
model called.  It says nothing about the component that actually parsed the
evidence, and a reader who cannot tell dfVFS from The Sleuth Kit cannot reproduce
or challenge a finding.  This module supplies the missing half — the version of
the component underneath the wrapper — so an emitter can build the
:class:`~forensic_agent.core.result_contract.UpstreamBackend` record that a
result carries.

Three properties make the answers evidence rather than documentation:

* **Runtime facts only.**  A Python library states its version through its own
  API where it has one, otherwise through the metadata of the distribution that
  is actually installed.  A pin file is never consulted: a pin is an intent, and
  this project already ships a pin that disagrees with what is installed.  A
  hardcoded table would be worse still, since it cannot be wrong in a way anyone
  notices.
* **One controlled preflight for the command-line backends.**  A binary must be
  executed to state its version, so it is executed exactly once per session,
  before any evidence is bound, through the same availability registry every
  other surface uses, with fixed arguments, an empty working directory and a hard
  timeout.  No forensic call ever probes.
* **No placeholders.**  A backend is either resolved with a real version,
  installed with its version undeterminable, or not installed, and those three
  states stay distinguishable.  A :class:`BackendVersion` that is not resolved
  cannot carry a version at all (the invariant is enforced at construction), and
  converting it to an ``UpstreamBackend`` raises rather than inventing one.

The registry is populated explicitly — importing this module probes nothing — and
is immutable once sealed, so a manifest written into a run record always describes
a complete inventory taken at one point in time.  The manifest carries no host
path and no timing, so two runs on the same configuration produce byte-identical
output.
"""

from __future__ import annotations

import importlib
import re
from collections.abc import Iterator, Mapping, Sequence
from contextlib import ExitStack
from dataclasses import dataclass
from enum import StrEnum
from importlib import metadata
from types import MappingProxyType
from typing import Any, Literal, Protocol, runtime_checkable

from forensic_agent.core.repro import canonical_json, sha256_hex
from forensic_agent.core.result_contract import UpstreamBackend
from forensic_agent.core.tool_availability import tool_availability
from forensic_agent.core.toolkit import (
    effective_external_timeout,
    run_external,
    scratch_dir,
)

BACKEND_VERSIONS_SCHEMA_ID = "forensic.backend-versions.v1"


class BackendVersionError(RuntimeError):
    """The backend version registry was used in a way that would falsify a record."""


class BackendRegistrySealed(BackendVersionError):
    """A sealed registry was asked to change."""


class BackendVersionUnavailable(BackendVersionError):
    """A backend with no established version was asked to attest a result."""


class BackendKind(StrEnum):
    PYTHON = "python"
    CLI = "cli"


class BackendStatus(StrEnum):
    """How far this host got towards naming a backend as the working component.

    The three states are deliberately distinct.  ``NOT_INSTALLED`` and
    ``VERSION_UNDETERMINED`` have the same consequence for admissibility and
    entirely different consequences for the operator: the first is fixed by
    installing the component, the second means the component is there but refused
    to identify itself, which is a defect worth investigating.
    """

    RESOLVED = "resolved"
    VERSION_UNDETERMINED = "version_undetermined"
    NOT_INSTALLED = "not_installed"


#: Machine-stable reasons a backend is not evidentially usable.  Short codes
#: rather than prose, because they end up in a run record that is diffed across
#: hosts.
REASON_MODULE_NOT_INSTALLED = "module_not_installed"
REASON_MODULE_IMPORT_FAILED = "module_import_failed"
REASON_LIBRARY_STATES_NO_VERSION = "library_states_no_version"
REASON_DISTRIBUTION_METADATA_MISSING = "distribution_metadata_missing"
REASON_VERSION_VALUE_REJECTED = "version_value_rejected"
REASON_EXECUTABLE_NOT_FOUND = "executable_not_found"
REASON_PROBE_EXECUTION_FAILED = "probe_execution_failed"
REASON_PROBE_EXIT_STATUS_REJECTED = "probe_exit_status_rejected"
REASON_VERSION_NOT_IN_PROBE_OUTPUT = "version_not_found_in_probe_output"

#: Attribute names a Python forensic library conventionally states its own
#: version through, tried in this order when a backend does not name one.  Trying
#: them at runtime rather than declaring one per backend means a library that
#: gains a version API later is picked up without this file changing.
CONVENTIONAL_VERSION_ATTRIBUTES: tuple[str, ...] = (
    "__version__",
    "get_version",
    "version",
    "VERSION",
)

#: A version has to survive being written into a receipt and compared across
#: hosts, so the accepted shape is narrow: printable, bounded, and free of the
#: whitespace and control characters a mis-parsed banner would drag in.
_VERSION_VALUE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+~:-]{0,63}$")

#: Values a backend can hand back that carry no information.  The result contract
#: refuses these at construction; refusing them here as well means the registry
#: never *records* one in the first place, so the difference between "installed,
#: version X" and "installed, version undeterminable" survives all the way into
#: the manifest instead of being discovered later by a raising constructor.
_PLACEHOLDER_VERSIONS = frozenset(
    {"", "unknown", "unspecified", "undefined", "n/a", "na", "none", "null", "nil", "-", "?"}
)

#: Version banners are short.  Reading a bounded prefix of each stream keeps a
#: backend that floods its output from being copied whole through the regex.
_PROBE_OUTPUT_SCAN_LIMIT_BYTES = 64 * 1024

#: Default ceiling for one version probe.  Generous for a program that only has
#: to print a banner, small enough that a hung binary cannot stall a session.
_DEFAULT_PROBE_TIMEOUT_SECONDS = 20.0

#: Ceiling used only to ask whether an execution cell owns the current call.
#: :func:`forensic_agent.core.toolkit.effective_external_timeout` returns its
#: argument unchanged when no cell is active and clamps it to the cell's
#: remaining time otherwise, so a ceiling no real cell can reach turns that clamp
#: into a yes/no answer.  toolkit exposes the cell only through this clamp, and
#: reading its private context variable from here would tie this module to
#: toolkit's internals.
_CELL_DETECTION_CEILING_SECONDS = 1.0e9


def _execution_cell_is_active() -> bool:
    return (
        effective_external_timeout(_CELL_DETECTION_CEILING_SECONDS)
        != _CELL_DETECTION_CEILING_SECONDS
    )


def _is_usable_version(value: str) -> bool:
    return (
        bool(_VERSION_VALUE.match(value))
        and value.strip().casefold() not in _PLACEHOLDER_VERSIONS
    )


@dataclass(frozen=True, slots=True)
class BackendVersion:
    """What this host established about one forensic backend.

    ``version`` exists only in the ``RESOLVED`` state.  That is the whole point:
    an entry cannot be constructed that reports a not-installed or
    version-undeterminable backend as having a version, so no later reader has to
    remember to check the status before trusting the field.
    """

    backend: str
    display_name: str
    kind: BackendKind
    status: BackendStatus
    #: The real version, or ``None``.  Never a placeholder string.
    version: str | None = None
    #: How the version was established, for example ``library_api:dfvfs.__version__``,
    #: ``importlib_metadata:python-evtx`` or ``preflight_probe:--version``.  Free of
    #: host paths, so it is safe in a run record.
    source: str | None = None
    #: Machine-stable code explaining a non-resolved status.
    reason: str | None = None

    def __post_init__(self) -> None:
        if self.status is BackendStatus.RESOLVED:
            if self.version is None or not _is_usable_version(self.version):
                raise BackendVersionError(
                    f"backend {self.backend!r} was recorded as resolved with an unusable "
                    f"version {self.version!r}"
                )
            if not self.source:
                raise BackendVersionError(
                    f"backend {self.backend!r} was recorded as resolved without naming "
                    "how the version was established"
                )
            if self.reason is not None:
                raise BackendVersionError(
                    f"backend {self.backend!r} is resolved and cannot also carry a reason"
                )
        else:
            if self.version is not None:
                raise BackendVersionError(
                    f"backend {self.backend!r} is not resolved and must not carry a version"
                )
            if not self.reason:
                raise BackendVersionError(
                    f"backend {self.backend!r} is not resolved and must say why"
                )

    @property
    def evidentially_usable(self) -> bool:
        """Whether this backend may be named as the component that did the work."""

        return self.status is BackendStatus.RESOLVED

    def upstream_backend(
        self, *, operation: str, role: Literal["producer", "support"]
    ) -> UpstreamBackend:
        """Turn this entry into the record an emitter attaches to a result.

        Refuses for anything but a resolved backend.  A result that names a
        component without naming its version cannot be reproduced, so the failure
        belongs here, where the caller still knows which operation it was about
        to attest, rather than in the contract further downstream.
        """

        if self.version is None:
            raise BackendVersionUnavailable(
                f"backend {self.backend!r} is {self.status.value} ({self.reason}); it cannot "
                f"attest {operation!r} because no real version was established"
            )
        return UpstreamBackend(
            name=self.backend,
            version=self.version,
            operation=operation,
            role=role,
        )

    def to_manifest_entry(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "display_name": self.display_name,
            "kind": self.kind.value,
            "status": self.status.value,
            "version": self.version,
            "source": self.source,
            "reason": self.reason,
        }

    @classmethod
    def from_manifest_entry(cls, record: Mapping[str, Any]) -> BackendVersion:
        expected = {"backend", "display_name", "kind", "status", "version", "source", "reason"}
        if set(record) != expected:
            raise BackendVersionError(
                f"backend manifest entry has unexpected fields: {set(record)}"
            )
        try:
            kind = BackendKind(record["kind"])
            status = BackendStatus(record["status"])
        except ValueError as error:
            raise BackendVersionError(f"backend manifest entry is malformed: {error}") from error
        return cls(
            backend=str(record["backend"]),
            display_name=str(record["display_name"]),
            kind=kind,
            status=status,
            version=record["version"],
            source=record["source"],
            reason=record["reason"],
        )


@dataclass(frozen=True, slots=True)
class PythonBackendSpec:
    """One forensic library whose version is readable inside this interpreter."""

    backend: str
    display_name: str
    #: Import path of the module that does the work.
    module: str
    #: Version attributes to read, in order.  Empty means "try the conventional
    #: names", which is the honest default: the library, not this file, decides
    #: whether it has a version API.
    attributes: tuple[str, ...] = ()
    #: Installed distribution consulted when the library states no version.
    #: ``None`` means there is no legitimate fallback, because the distribution's
    #: version would be a different number than the one being attested.
    distribution: str | None = None


@dataclass(frozen=True, slots=True)
class CliBackendSpec:
    """One forensic binary that has to be executed to state its version.

    The probe recipe is declared; the version is not.  Naming the arguments and
    the banner shape is the same kind of knowledge as naming the executable
    candidates, and it cannot silently disagree with what is installed the way a
    hardcoded version table can.
    """

    backend: str
    display_name: str
    #: Key into :data:`forensic_agent.core.tool_availability.EXTERNAL_TOOLS`.  The
    #: probe never names a bare executable: it runs the absolute path the
    #: availability registry resolved, so it cannot execute a different binary
    #: than the one every other surface reports.
    tool_id: str
    #: Regular expression with a ``version`` group, searched in the probe output.
    pattern: re.Pattern[str]
    #: Arguments appended to the resolved executable.  Fixed constants: no
    #: caller-supplied value ever reaches a probe argv.
    arguments: tuple[str, ...] = ("--version",)
    #: Exit statuses whose output may still be read for a version.
    accepted_exit_statuses: frozenset[int] = frozenset({0})
    timeout_seconds: float = _DEFAULT_PROBE_TIMEOUT_SECONDS


_VERSION_TOKEN = r"(?P<version>[0-9][0-9A-Za-z.+~-]*)"


PYTHON_BACKENDS: tuple[PythonBackendSpec, ...] = (
    PythonBackendSpec(
        backend="dfvfs",
        display_name="dfVFS",
        module="dfvfs",
        distribution="dfvfs",
    ),
    PythonBackendSpec(
        backend="sleuthkit",
        display_name="The Sleuth Kit",
        module="pytsk3",
        # The Sleuth Kit is a separate component reached through pytsk3, and only
        # the binding can report which TSK it was built against.  There is no
        # distribution fallback on purpose: pytsk3's own distribution version is
        # the binding's release date, so falling back would attest a Sleuth Kit
        # version that does not exist.
        attributes=("TSK_VERSION_STR",),
    ),
    PythonBackendSpec(
        backend="pytsk3",
        display_name="pytsk3",
        module="pytsk3",
        attributes=("get_version",),
        distribution="pytsk3",
    ),
    PythonBackendSpec(
        backend="libewf",
        display_name="libewf",
        module="pyewf",
        attributes=("get_version",),
        distribution="libewf-python",
    ),
    PythonBackendSpec(
        backend="regipy",
        display_name="regipy",
        module="regipy",
        distribution="regipy",
    ),
    PythonBackendSpec(
        backend="python_evtx",
        display_name="python-evtx",
        module="Evtx",
        distribution="python-evtx",
    ),
    PythonBackendSpec(
        backend="py7zr",
        display_name="py7zr",
        module="py7zr",
        distribution="py7zr",
    ),
    # Bindings that arrive transitively with another distribution rather than
    # being installed for their own sake.  They still parse evidence, so a
    # result that names one has to be able to name its version too.
    PythonBackendSpec(
        backend="pyevtx",
        display_name="libevtx (pyevtx)",
        module="pyevtx",
        attributes=("get_version",),
        distribution="libevtx-python",
    ),
    PythonBackendSpec(
        backend="pyevt",
        display_name="libevt (pyevt)",
        module="pyevt",
        attributes=("get_version",),
        distribution="libevt-python",
    ),
    PythonBackendSpec(
        backend="libregf",
        display_name="libregf (pyregf)",
        module="pyregf",
        attributes=("get_version",),
        distribution="libregf-python",
    ),
    PythonBackendSpec(
        backend="pefile",
        display_name="pefile",
        module="pefile",
        distribution="pefile",
    ),
    # The decoder behind every transform_query operation, and the timestamp
    # library behind the two that convert a moment.  Both are here for the same
    # reason as every other entry: the transformation is theirs, so a converted
    # value names a released component instead of code this project wrote.
    PythonBackendSpec(
        backend="chepy",
        display_name="chepy",
        module="chepy",
        distribution="chepy",
    ),
    PythonBackendSpec(
        backend="dfdatetime",
        display_name="dfDateTime",
        module="dfdatetime",
        distribution="dfdatetime",
    ),
    # Components that ship WITH the interpreter.  Operations declare them as the
    # producer of real work — the engine that answered a SQLite query, the codec
    # that decoded a value — so leaving them outside the inventory would mean
    # every such result names a component whose version this host never
    # established, which the contract refuses at construction.  They are
    # resolved the same way as any other Python backend: by asking the running
    # interpreter, never a pin file and never a table.
    PythonBackendSpec(
        backend="cpython_sqlite3",
        display_name="SQLite (bundled with CPython)",
        module="sqlite3",
        # ``sqlite_version`` is the ENGINE's version; ``version`` is the DB-API
        # wrapper's.  The engine answered the query, so the engine is what a
        # result names.  There is deliberately no distribution fallback: sqlite3
        # ships with CPython and has no distribution of its own to consult.
        attributes=("sqlite_version",),
    ),
    # ``hashlib``, ``zipfile`` and the named codecs have no release of their
    # own: they are the interpreter's, and the interpreter's version is the
    # only honest identifier for the code that ran.  Each is inventoried under
    # its own name so a result still names the component that did the work
    # rather than a single undifferentiated "python" entry, and ``source``
    # records that the version came from the interpreter's own statement.
    PythonBackendSpec(
        backend="cpython_hashlib",
        display_name="CPython hashlib",
        module="platform",
        attributes=("python_version",),
    ),
    PythonBackendSpec(
        backend="cpython_zipfile",
        display_name="CPython zipfile",
        module="platform",
        attributes=("python_version",),
    ),
    PythonBackendSpec(
        backend="cpython_stdlib",
        display_name="CPython standard library",
        module="platform",
        attributes=("python_version",),
    ),
)


CLI_BACKENDS: tuple[CliBackendSpec, ...] = (
    CliBackendSpec(
        backend="volatility3",
        display_name="Volatility 3",
        tool_id="vol",
        # Volatility 3 has no version flag.  It prints the framework banner on
        # stdout while refusing to run without a plugin, and that refusal is the
        # one invocation that is guaranteed to open nothing, so it is the safest
        # path to a real version rather than a convenient one.
        arguments=(),
        pattern=re.compile(rf"Volatility\s+3\s+Framework\s+{_VERSION_TOKEN}", re.IGNORECASE),
        accepted_exit_statuses=frozenset({0, 2}),
    ),
    CliBackendSpec(
        backend="clamav",
        display_name="ClamAV",
        tool_id="clamscan",
        pattern=re.compile(rf"ClamAV\s+{_VERSION_TOKEN}", re.IGNORECASE),
    ),
    CliBackendSpec(
        backend="tshark",
        display_name="Wireshark tshark",
        tool_id="tshark",
        pattern=re.compile(
            rf"TShark(?:\s*\(Wireshark\))?\s+{_VERSION_TOKEN}", re.IGNORECASE
        ),
    ),
    CliBackendSpec(
        backend="mergecap",
        display_name="Wireshark mergecap",
        tool_id="mergecap",
        pattern=re.compile(
            rf"Mergecap(?:\s*\(Wireshark\))?\s+{_VERSION_TOKEN}", re.IGNORECASE
        ),
    ),
    CliBackendSpec(
        backend="regripper",
        display_name="RegRipper",
        tool_id="regripper",
        arguments=("-h",),
        pattern=re.compile(rf"Rip\s+v\.?\s*{_VERSION_TOKEN}", re.IGNORECASE),
    ),
    CliBackendSpec(
        backend="bulk_extractor",
        display_name="bulk_extractor",
        tool_id="bulk_extractor",
        arguments=("-V",),
        pattern=re.compile(rf"bulk_extractor\s+(?:version\s+)?{_VERSION_TOKEN}", re.IGNORECASE),
    ),
    CliBackendSpec(
        backend="seven_zip",
        display_name="7-Zip",
        tool_id="seven_zip",
        # 7-Zip has no version flag either; the banner precedes the usage text.
        arguments=("--help",),
        # The banner reads `7-Zip [64] 26.01 : Copyright ...`, where [64] is the
        # architecture tag, not a version. A pattern that skips to the first
        # version-looking token attests "64", and a wrong version is worse than
        # no version: it is a false claim about which code produced the bytes.
        # The bracketed tag is therefore consumed explicitly.
        pattern=re.compile(
            rf"7-Zip\s*(?:\[[^\]]*\]\s*)?{_VERSION_TOKEN}", re.IGNORECASE
        ),
    ),
    CliBackendSpec(
        backend="tesseract",
        display_name="Tesseract OCR",
        tool_id="tesseract",
        pattern=re.compile(rf"tesseract\s+v?{_VERSION_TOKEN}", re.IGNORECASE),
    ),
    CliBackendSpec(
        backend="john",
        display_name="John the Ripper",
        tool_id="john",
        # John (jumbo) has no --version flag. Invoked with no arguments it prints
        # its banner — "John the Ripper 1.9.0-jumbo-1 ..." — then the usage text,
        # and exits non-zero, so the banner is read off an accepted refusal path
        # rather than a success. Verify against the pinned build in the Dockerfile.
        arguments=(),
        pattern=re.compile(rf"John the Ripper\s+{_VERSION_TOKEN}", re.IGNORECASE),
        accepted_exit_statuses=frozenset({0, 1}),
    ),
)


@dataclass(frozen=True, slots=True)
class VersionProbeOutput:
    """What one version probe produced.  Deliberately not a forensic result."""

    exit_status: int
    stdout: str
    stderr: str


@runtime_checkable
class VersionProbeRunner(Protocol):
    """The subprocess boundary of the preflight, as a seam.

    Injecting it lets the preflight be exercised without the host's binaries, and
    keeps the single place a forensic binary is executed for identification
    visible in one signature.
    """

    def __call__(
        self, argv: Sequence[str], *, timeout_seconds: float, working_directory: str
    ) -> VersionProbeOutput: ...


def _run_version_probe(
    argv: Sequence[str], *, timeout_seconds: float, working_directory: str
) -> VersionProbeOutput:
    """Execute one version probe through the project's single subprocess boundary.

    ``run_external`` builds the sanitized child environment and spawns an argv
    list without a shell.  ``check=False`` because a backend may state its
    version on a refusal path; the exit status is judged by the caller against
    the statuses that backend actually documents.
    """

    completed = run_external(
        list(argv),
        timeout=timeout_seconds,
        text=True,
        check=False,
        cwd=working_directory,
    )
    return VersionProbeOutput(
        exit_status=int(completed.returncode),
        stdout=completed.stdout if isinstance(completed.stdout, str) else "",
        stderr=completed.stderr if isinstance(completed.stderr, str) else "",
    )


def _read_version_attribute(module: Any, attribute: str) -> str | None:
    """Read one version attribute, calling it when it is a callable accessor."""

    try:
        value = getattr(module, attribute)
    except Exception:
        return None
    if callable(value):
        try:
            value = value()
        except Exception:
            return None
    # A non-string (a version tuple, a submodule) is treated as absent rather than
    # as a rejected value: the library simply has no string version API here, and
    # the distribution metadata may still answer.
    return value.strip() if isinstance(value, str) else None


def resolve_python_backend(spec: PythonBackendSpec) -> BackendVersion:
    """Establish one Python backend's version from the running interpreter."""

    try:
        module = importlib.import_module(spec.module)
    except ModuleNotFoundError as error:
        if error.name == spec.module:
            return BackendVersion(
                backend=spec.backend,
                display_name=spec.display_name,
                kind=BackendKind.PYTHON,
                status=BackendStatus.NOT_INSTALLED,
                reason=REASON_MODULE_NOT_INSTALLED,
            )
        # The backend is installed but one of its own imports is not, so it is
        # present and unusable, which is a different problem from being absent.
        return BackendVersion(
            backend=spec.backend,
            display_name=spec.display_name,
            kind=BackendKind.PYTHON,
            status=BackendStatus.VERSION_UNDETERMINED,
            reason=REASON_MODULE_IMPORT_FAILED,
        )
    except Exception:
        return BackendVersion(
            backend=spec.backend,
            display_name=spec.display_name,
            kind=BackendKind.PYTHON,
            status=BackendStatus.VERSION_UNDETERMINED,
            reason=REASON_MODULE_IMPORT_FAILED,
        )

    attributes = spec.attributes or CONVENTIONAL_VERSION_ATTRIBUTES
    rejected = False
    for attribute in attributes:
        value = _read_version_attribute(module, attribute)
        if value is None:
            continue
        if _is_usable_version(value):
            return BackendVersion(
                backend=spec.backend,
                display_name=spec.display_name,
                kind=BackendKind.PYTHON,
                status=BackendStatus.RESOLVED,
                version=value,
                source=f"library_api:{spec.module}.{attribute}",
            )
        rejected = True

    if spec.distribution is not None:
        try:
            value = metadata.version(spec.distribution).strip()
        except Exception:
            return BackendVersion(
                backend=spec.backend,
                display_name=spec.display_name,
                kind=BackendKind.PYTHON,
                status=BackendStatus.VERSION_UNDETERMINED,
                reason=REASON_DISTRIBUTION_METADATA_MISSING,
            )
        if _is_usable_version(value):
            return BackendVersion(
                backend=spec.backend,
                display_name=spec.display_name,
                kind=BackendKind.PYTHON,
                status=BackendStatus.RESOLVED,
                version=value,
                source=f"importlib_metadata:{spec.distribution}",
            )
        rejected = True

    return BackendVersion(
        backend=spec.backend,
        display_name=spec.display_name,
        kind=BackendKind.PYTHON,
        status=BackendStatus.VERSION_UNDETERMINED,
        reason=(
            REASON_VERSION_VALUE_REJECTED if rejected else REASON_LIBRARY_STATES_NO_VERSION
        ),
    )


def _unresolved_cli(spec: CliBackendSpec, reason: str) -> BackendVersion:
    return BackendVersion(
        backend=spec.backend,
        display_name=spec.display_name,
        kind=BackendKind.CLI,
        status=BackendStatus.VERSION_UNDETERMINED,
        reason=reason,
    )


def _probe_cli_backend(
    spec: CliBackendSpec,
    executable: str,
    *,
    probe: VersionProbeRunner,
    working_directory: str,
) -> BackendVersion:
    argv = (executable, *spec.arguments)
    try:
        output = probe(
            argv,
            timeout_seconds=spec.timeout_seconds,
            working_directory=working_directory,
        )
    except Exception:
        # A probe that could not run has established nothing.  The backend is
        # recorded as unusable; it is never given the version it might have had.
        return _unresolved_cli(spec, REASON_PROBE_EXECUTION_FAILED)
    if output.exit_status not in spec.accepted_exit_statuses:
        return _unresolved_cli(spec, REASON_PROBE_EXIT_STATUS_REJECTED)
    scanned = (
        output.stdout[:_PROBE_OUTPUT_SCAN_LIMIT_BYTES]
        + "\n"
        + output.stderr[:_PROBE_OUTPUT_SCAN_LIMIT_BYTES]
    )
    found = spec.pattern.search(scanned)
    if found is None:
        return _unresolved_cli(spec, REASON_VERSION_NOT_IN_PROBE_OUTPUT)
    value = found.group("version").strip()
    if not _is_usable_version(value):
        return _unresolved_cli(spec, REASON_VERSION_VALUE_REJECTED)
    return BackendVersion(
        backend=spec.backend,
        display_name=spec.display_name,
        kind=BackendKind.CLI,
        status=BackendStatus.RESOLVED,
        version=value,
        # The arguments identify the probe; the resolved executable is a host
        # path and stays out of anything a run record may publish.
        source="preflight_probe" + (":" + " ".join(spec.arguments) if spec.arguments else ""),
    )


def resolve_cli_backend(
    spec: CliBackendSpec,
    *,
    probe: VersionProbeRunner | None = None,
    working_directory: str | None = None,
) -> BackendVersion:
    """Establish one command-line backend's version by executing it once.

    The executable comes from the availability registry, never from a bare name,
    so the probe identifies exactly the binary the rest of the system would run.
    """

    availability = tool_availability(spec.tool_id)
    if availability.path is None:
        return BackendVersion(
            backend=spec.backend,
            display_name=spec.display_name,
            kind=BackendKind.CLI,
            status=BackendStatus.NOT_INSTALLED,
            reason=REASON_EXECUTABLE_NOT_FOUND,
        )
    runner = probe if probe is not None else _run_version_probe
    with ExitStack() as stack:
        directory = working_directory
        if directory is None:
            # An empty throwaway directory, removed afterwards: a binary that
            # writes beside its working directory cannot reach the evidence tree,
            # and cannot pick up a file that happens to sit in the session's own
            # working directory.
            directory = stack.enter_context(scratch_dir("backend_version_probe_"))
        return _probe_cli_backend(
            spec, availability.path, probe=runner, working_directory=directory
        )


class BackendVersionRegistry:
    """The session's inventory of backend versions: append-only, then frozen.

    Sealing is what makes the inventory citable.  An unsealed registry is still
    being built and may not emit a manifest; a sealed one can never change, so a
    run record and the results emitted during that run necessarily describe the
    same host.
    """

    __slots__ = ("_entries", "_sealed")

    def __init__(self) -> None:
        self._entries: dict[str, BackendVersion] = {}
        self._sealed = False

    @property
    def sealed(self) -> bool:
        return self._sealed

    def record(self, entry: BackendVersion) -> None:
        if self._sealed:
            raise BackendRegistrySealed(
                f"the backend version registry is sealed; {entry.backend!r} cannot be recorded"
            )
        if entry.backend in self._entries:
            raise BackendVersionError(f"backend {entry.backend!r} is recorded twice")
        self._entries[entry.backend] = entry

    def seal(self) -> BackendVersionRegistry:
        """Freeze the inventory and return it, so a builder can end with ``.seal()``."""

        self._sealed = True
        return self

    def entries(self) -> Mapping[str, BackendVersion]:
        return MappingProxyType(dict(self._entries))

    def __contains__(self, backend: object) -> bool:
        return backend in self._entries

    def __iter__(self) -> Iterator[BackendVersion]:
        return iter(self._entries.values())

    def __len__(self) -> int:
        return len(self._entries)

    def entry(self, backend: str) -> BackendVersion:
        """The recorded entry for ``backend``.

        An undeclared backend raises rather than returning a not-installed
        placeholder: the caller asked about something this registry never
        inventoried, and answering "not installed" would be a claim it cannot
        support.
        """

        try:
            return self._entries[backend]
        except KeyError:
            raise BackendVersionError(f"backend {backend!r} is not declared") from None

    def upstream_backend(
        self, backend: str, *, operation: str, role: Literal["producer", "support"]
    ) -> UpstreamBackend:
        """The seam an emitter uses to attest the component that did the work."""

        return self.entry(backend).upstream_backend(operation=operation, role=role)

    def manifest(self) -> dict[str, Any]:
        """The inventory as a run-record fragment.

        Sorted, host-path-free and timing-free, with a digest over the entries so
        a later reader can tell that the inventory a run cited is the inventory it
        is holding.
        """

        if not self._sealed:
            raise BackendVersionError("a manifest may only be emitted from a sealed registry")
        backends = [
            self._entries[name].to_manifest_entry() for name in sorted(self._entries)
        ]
        return {
            "schema_id": BACKEND_VERSIONS_SCHEMA_ID,
            "backends": backends,
            "backends_sha256": sha256_hex(canonical_json(backends)),
        }

    @classmethod
    def from_manifest(cls, manifest: Mapping[str, Any]) -> BackendVersionRegistry:
        """Rebuild a sealed registry from a manifest, verifying its digest."""

        if manifest.get("schema_id") != BACKEND_VERSIONS_SCHEMA_ID:
            raise BackendVersionError(
                f"not a {BACKEND_VERSIONS_SCHEMA_ID} manifest: {manifest.get('schema_id')!r}"
            )
        backends = manifest.get("backends")
        if not isinstance(backends, list):
            raise BackendVersionError("backend manifest has no backends list")
        if sha256_hex(canonical_json(backends)) != manifest.get("backends_sha256"):
            raise BackendVersionError("backend manifest digest does not cover its backends")
        registry = cls()
        for record in backends:
            if not isinstance(record, Mapping):
                raise BackendVersionError("backend manifest entry is not a mapping")
            registry.record(BackendVersion.from_manifest_entry(record))
        return registry.seal()


def resolve_backend_versions(
    *, probe: VersionProbeRunner | None = None
) -> BackendVersionRegistry:
    """Run the whole preflight once and return the sealed inventory.

    Refused from inside an execution cell.  A cell owns a forensic call, so a
    preflight starting there is a call trying to populate the inventory lazily —
    exactly the per-call probing this design exists to prevent, and the one
    situation in which a probe could run while evidence is bound.
    """

    if _execution_cell_is_active():
        raise BackendVersionError(
            "backend versions are a preflight and cannot be established from inside an "
            "execution cell; establish them before any evidence is bound"
        )
    registry = BackendVersionRegistry()
    for python_spec in PYTHON_BACKENDS:
        registry.record(resolve_python_backend(python_spec))
    for cli_spec in CLI_BACKENDS:
        registry.record(resolve_cli_backend(cli_spec, probe=probe))
    return registry.seal()


#: The session's sealed inventory.  Deliberately populated by an explicit call:
#: importing this module executes nothing, so no import can cause a binary to run.
_SESSION_REGISTRY: BackendVersionRegistry | None = None


def establish_session_backend_versions(
    *, probe: VersionProbeRunner | None = None
) -> BackendVersionRegistry:
    """Establish the session inventory, probing at most once for the process.

    Idempotent on purpose: a second caller gets the registry the first one sealed
    without a single binary being executed again, which is what makes "once per
    session" hold across call sites that do not have the registry threaded to
    them.
    """

    global _SESSION_REGISTRY
    if _SESSION_REGISTRY is None:
        _SESSION_REGISTRY = resolve_backend_versions(probe=probe)
    return _SESSION_REGISTRY


def session_backend_versions() -> BackendVersionRegistry:
    """The sealed session inventory; raises when the preflight has not run.

    Raising beats returning an empty registry: an emitter that asked for backend
    versions before the preflight must not receive an inventory that would make
    every backend look absent.
    """

    if _SESSION_REGISTRY is None:
        raise BackendVersionError(
            "the backend version preflight has not been established; call "
            "establish_session_backend_versions() before any evidence is bound"
        )
    return _SESSION_REGISTRY


#: Sealed inventories, filed under the set of executables they were taken from.
_ENVIRONMENT_REGISTRIES: dict[tuple[tuple[str, str | None], ...], BackendVersionRegistry] = {}


def _cli_environment_fingerprint() -> tuple[tuple[str, str | None], ...]:
    """Which binary each command-line backend resolves to right now.

    Resolution is path arithmetic over the ``DFA_*`` variables, the interpreter's
    script directory and ``PATH``; it opens nothing and executes nothing, so it
    is cheap enough to ask before every preflight.  Two hosts — or one host under
    two configurations — that resolve the same executables run the same code, so
    the inventory taken from one of them describes both.
    """

    return tuple(
        (spec.backend, tool_availability(spec.tool_id).path) for spec in CLI_BACKENDS
    )


def backend_versions_for_environment(
    *, probe: VersionProbeRunner | None = None
) -> BackendVersionRegistry:
    """The sealed inventory for the backends this environment resolves to.

    A preflight per *session* is not enough for an emitter.  The session helper
    memoizes into a process-wide global, so the FIRST caller decides what every
    later one sees; a process that prepares a second evidence binding after the
    tool locations changed would then attest the first binding's inventory, which
    is a statement about code that did not run.  Filing each sealed registry under
    the executables it was taken from keeps "probe once" true for a stable
    configuration while letting a changed one be measured rather than assumed.

    Still a preflight in the sense that matters: it is called while a model
    surface is being built, before any evidence is bound, and never from inside an
    execution cell — :func:`resolve_backend_versions` refuses that outright.
    """

    fingerprint = _cli_environment_fingerprint()
    registry = _ENVIRONMENT_REGISTRIES.get(fingerprint)
    if registry is None:
        registry = resolve_backend_versions(probe=probe)
        _ENVIRONMENT_REGISTRIES[fingerprint] = registry
    return registry


__all__ = [
    "BACKEND_VERSIONS_SCHEMA_ID",
    "CLI_BACKENDS",
    "CONVENTIONAL_VERSION_ATTRIBUTES",
    "PYTHON_BACKENDS",
    "REASON_DISTRIBUTION_METADATA_MISSING",
    "REASON_EXECUTABLE_NOT_FOUND",
    "REASON_LIBRARY_STATES_NO_VERSION",
    "REASON_MODULE_IMPORT_FAILED",
    "REASON_MODULE_NOT_INSTALLED",
    "REASON_PROBE_EXECUTION_FAILED",
    "REASON_PROBE_EXIT_STATUS_REJECTED",
    "REASON_VERSION_NOT_IN_PROBE_OUTPUT",
    "REASON_VERSION_VALUE_REJECTED",
    "BackendKind",
    "BackendRegistrySealed",
    "BackendStatus",
    "BackendVersion",
    "BackendVersionError",
    "BackendVersionRegistry",
    "BackendVersionUnavailable",
    "CliBackendSpec",
    "PythonBackendSpec",
    "VersionProbeOutput",
    "VersionProbeRunner",
    "backend_versions_for_environment",
    "establish_session_backend_versions",
    "resolve_backend_versions",
    "resolve_cli_backend",
    "resolve_python_backend",
    "session_backend_versions",
]
