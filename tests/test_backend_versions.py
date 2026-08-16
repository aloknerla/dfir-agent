"""The runtime registry of real forensic backend versions.

Each test pins one property that makes the inventory evidence rather than
documentation: versions come from the running library or from one controlled
preflight execution, a backend that cannot state its version is recorded as
unusable instead of being given a placeholder, the inventory cannot change after
it is sealed, and only a resolved backend may attest a v2 result.

The Python-library tests deliberately read the real environment (pytsk3 is a
required dependency, python-evtx backs the EVTX tool).  Hardcoding an expected
version here would reintroduce exactly the static table the registry exists to
replace, so every expectation is read from the library at assertion time.
"""

from __future__ import annotations

import importlib
import json
import math
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from importlib import metadata
from types import ModuleType

import pytest

import forensic_agent.core.backend_versions as B
import forensic_agent.core.tool_availability as availability
from forensic_agent.core.repro import canonical_json, sha256_hex
from forensic_agent.core.result_contract import EvidenceClass, make_provenance
from forensic_agent.core.tool_result import ProvenanceType
from forensic_agent.core.toolkit import cell_deadline


@dataclass(frozen=True, slots=True)
class _ProbeCall:
    argv: tuple[str, ...]
    timeout_seconds: float
    working_directory: str
    #: Taken while the probe is running: the preflight removes its scratch
    #: directory afterwards, so it cannot be inspected once the call returns.
    working_directory_entries: tuple[str, ...]


class _RecordingProbe:
    """A version probe that records how it was called and never spawns anything."""

    def __init__(self, *, stdout="", stderr="", exit_status=0, error=None):
        self.stdout = stdout
        self.stderr = stderr
        self.exit_status = exit_status
        self.error = error
        self.calls: list[_ProbeCall] = []

    def __call__(self, argv, *, timeout_seconds, working_directory):
        self.calls.append(
            _ProbeCall(
                argv=tuple(argv),
                timeout_seconds=timeout_seconds,
                working_directory=working_directory,
                working_directory_entries=tuple(os.listdir(working_directory)),
            )
        )
        if self.error is not None:
            raise self.error
        return B.VersionProbeOutput(
            exit_status=self.exit_status, stdout=self.stdout, stderr=self.stderr
        )


VOLATILITY_BANNER = "Volatility 3 Framework 2.28.0\n"


def _only_installed_binary(monkeypatch, tool_id, executable):
    """Make the availability registry resolve exactly one declared binary.

    ``_resolve_spec`` is documented as the single probe every surface goes
    through, so replacing it is how a test states "this host has only that
    binary" for doctor, ``/tools`` and this registry at once.
    """

    monkeypatch.setattr(
        availability,
        "_resolve_spec",
        lambda spec: str(executable) if spec.id == tool_id else None,
    )


def _fake_executable(tmp_path, name):
    path = tmp_path / name
    path.write_text("", encoding="utf-8")
    return path


def _spec(backend):
    for spec in (*B.PYTHON_BACKENDS, *B.CLI_BACKENDS):
        if spec.backend == backend:
            return spec
    raise AssertionError(f"{backend!r} is not declared")


@pytest.fixture(autouse=True)
def _unestablished_session(monkeypatch):
    """Every test starts from a process that has not run the preflight."""

    monkeypatch.setattr(B, "_SESSION_REGISTRY", None)


# --- Python backends: the library's own API, then distribution metadata -------


def test_python_backend_resolves_through_the_librarys_own_version_api():
    pytsk3 = importlib.import_module("pytsk3")

    sleuthkit = B.resolve_python_backend(_spec("sleuthkit"))
    binding = B.resolve_python_backend(_spec("pytsk3"))

    assert sleuthkit.status is B.BackendStatus.RESOLVED
    assert sleuthkit.version == pytsk3.TSK_VERSION_STR
    assert sleuthkit.source == "library_api:pytsk3.TSK_VERSION_STR"
    assert sleuthkit.reason is None
    assert sleuthkit.evidentially_usable

    assert binding.status is B.BackendStatus.RESOLVED
    assert binding.version == pytsk3.get_version()
    assert binding.source == "library_api:pytsk3.get_version"

    # One module, two components with two different real versions.  Reporting the
    # binding's release date as The Sleuth Kit's version would be a false
    # attestation, which is why the sleuthkit spec has no metadata fallback.
    assert sleuthkit.version != binding.version
    assert _spec("sleuthkit").distribution is None


def test_python_backend_without_a_version_api_resolves_through_distribution_metadata():
    spec = _spec("python_evtx")
    module = importlib.import_module(spec.module)

    # The precondition this test is about: the library states nothing itself.
    assert not [
        attribute
        for attribute in B.CONVENTIONAL_VERSION_ATTRIBUTES
        if isinstance(getattr(module, attribute, None), str)
    ]

    entry = B.resolve_python_backend(spec)

    assert entry.status is B.BackendStatus.RESOLVED
    assert entry.version == metadata.version(spec.distribution)
    assert entry.source == f"importlib_metadata:{spec.distribution}"


def test_python_backend_that_is_absent_is_recorded_as_not_installed():
    spec = B.PythonBackendSpec(
        backend="absent",
        display_name="Absent",
        module="forensic_agent_absent_backend",
        distribution="forensic-agent-absent-backend",
    )

    entry = B.resolve_python_backend(spec)

    assert entry.status is B.BackendStatus.NOT_INSTALLED
    assert entry.reason == B.REASON_MODULE_NOT_INSTALLED
    assert entry.version is None
    assert not entry.evidentially_usable


def test_a_library_that_states_a_placeholder_version_is_not_believed(monkeypatch):
    module = ModuleType("forensic_agent_placeholder_backend")
    module.__version__ = "unknown"
    monkeypatch.setitem(sys.modules, module.__name__, module)
    spec = B.PythonBackendSpec(
        backend="placeholder",
        display_name="Placeholder",
        module=module.__name__,
        attributes=("__version__",),
    )

    entry = B.resolve_python_backend(spec)

    assert entry.status is B.BackendStatus.VERSION_UNDETERMINED
    assert entry.reason == B.REASON_VERSION_VALUE_REJECTED
    assert entry.version is None


# --- The command-line preflight ----------------------------------------------


def test_command_line_backend_is_probed_once_per_session_however_often_it_is_read(
    monkeypatch, tmp_path
):
    executable = _fake_executable(tmp_path, "vol.exe")
    _only_installed_binary(monkeypatch, "vol", executable)
    probe = _RecordingProbe(stdout=VOLATILITY_BANNER, exit_status=2)

    established = B.establish_session_backend_versions(probe=probe)
    for _ in range(5):
        assert B.session_backend_versions().entry("volatility3").version == "2.28.0"
    assert B.establish_session_backend_versions(probe=probe) is established

    assert len(probe.calls) == 1


def test_probe_runs_the_resolved_absolute_executable_in_an_empty_directory(
    monkeypatch, tmp_path
):
    executable = _fake_executable(tmp_path, "vol.exe")
    _only_installed_binary(monkeypatch, "vol", executable)
    probe = _RecordingProbe(stdout=VOLATILITY_BANNER, exit_status=2)

    B.resolve_backend_versions(probe=probe)

    (call,) = probe.calls
    # Never a bare name: a bare name would be resolved again at execution time and
    # could reach a different binary than the availability registry reported.
    assert call.argv == (str(executable),)
    assert os.path.isabs(call.argv[0])
    assert call.timeout_seconds > 0 and math.isfinite(call.timeout_seconds)
    assert call.working_directory_entries == ()
    assert os.path.realpath(call.working_directory) != os.path.realpath(os.getcwd())
    assert not os.path.exists(call.working_directory)


@pytest.mark.parametrize(
    ("outcome", "reason"),
    [
        ({"error": RuntimeError("timed out after 20s")}, B.REASON_PROBE_EXECUTION_FAILED),
        (
            {"stdout": VOLATILITY_BANNER, "exit_status": 1},
            B.REASON_PROBE_EXIT_STATUS_REJECTED,
        ),
        (
            {"stdout": "usage: vol [-h]\n", "exit_status": 2},
            B.REASON_VERSION_NOT_IN_PROBE_OUTPUT,
        ),
    ],
)
def test_failed_probe_is_recorded_as_unusable_instead_of_getting_a_placeholder(
    monkeypatch, tmp_path, outcome, reason
):
    executable = _fake_executable(tmp_path, "vol.exe")
    _only_installed_binary(monkeypatch, "vol", executable)

    probe = _RecordingProbe(**outcome)
    entry = B.resolve_backend_versions(probe=probe).entry("volatility3")

    assert entry.status is B.BackendStatus.VERSION_UNDETERMINED
    assert entry.reason == reason
    assert entry.version is None
    assert entry.source is None
    assert not entry.evidentially_usable


def test_the_three_backend_states_stay_distinguishable(monkeypatch, tmp_path):
    executable = _fake_executable(tmp_path, "vol.exe")
    _only_installed_binary(monkeypatch, "vol", executable)

    resolved = B.resolve_backend_versions(
        probe=_RecordingProbe(stdout=VOLATILITY_BANNER, exit_status=2)
    )
    undetermined = B.resolve_backend_versions(
        probe=_RecordingProbe(stdout="no banner here\n", exit_status=2)
    )

    assert resolved.entry("volatility3").status is B.BackendStatus.RESOLVED
    assert undetermined.entry("volatility3").status is B.BackendStatus.VERSION_UNDETERMINED
    assert resolved.entry("tshark").status is B.BackendStatus.NOT_INSTALLED

    for entry in resolved:
        assert entry.evidentially_usable is (entry.status is B.BackendStatus.RESOLVED)
        assert (entry.version is not None) is entry.evidentially_usable
        assert entry.version != "unknown"


def test_preflight_is_refused_from_inside_an_execution_cell(monkeypatch, tmp_path):
    executable = _fake_executable(tmp_path, "vol.exe")
    _only_installed_binary(monkeypatch, "vol", executable)
    probe = _RecordingProbe(stdout=VOLATILITY_BANNER, exit_status=2)

    with cell_deadline(time.monotonic() + 300.0):
        with pytest.raises(B.BackendVersionError, match="preflight"):
            B.resolve_backend_versions(probe=probe)

    assert probe.calls == []


def test_session_versions_are_refused_before_the_preflight_has_run():
    with pytest.raises(B.BackendVersionError, match="has not been established"):
        B.session_backend_versions()


def test_importing_the_module_probes_nothing():
    source = (
        "import forensic_agent.core.backend_versions as B;"
        "print(B._SESSION_REGISTRY)"
    )
    completed = subprocess.run(
        [sys.executable, "-c", source],
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "None"


# --- The sealed inventory -----------------------------------------------------


def _entry(backend="dfvfs", version="20260731"):
    return B.BackendVersion(
        backend=backend,
        # Deliberately different from the stable id: an upstream record has to
        # name the id a reader can match across runs, not the human label.
        display_name=backend.upper(),
        kind=B.BackendKind.PYTHON,
        status=B.BackendStatus.RESOLVED,
        version=version,
        source=f"library_api:{backend}.__version__",
    )


def test_registry_refuses_to_change_after_it_is_sealed():
    registry = B.BackendVersionRegistry()
    registry.record(_entry())
    assert not registry.sealed

    assert registry.seal() is registry
    assert registry.sealed

    with pytest.raises(B.BackendRegistrySealed):
        registry.record(_entry(backend="regipy", version="6.3.0"))
    assert "regipy" not in registry
    with pytest.raises(TypeError):
        registry.entries()["regipy"] = _entry()


def test_registry_refuses_a_duplicate_backend_and_an_unsealed_manifest():
    registry = B.BackendVersionRegistry()
    registry.record(_entry())

    with pytest.raises(B.BackendVersionError, match="twice"):
        registry.record(_entry())
    with pytest.raises(B.BackendVersionError, match="sealed"):
        registry.manifest()
    with pytest.raises(B.BackendVersionError, match="not declared"):
        registry.entry("photorec")


def test_manifest_round_trips_and_carries_no_host_path(monkeypatch, tmp_path):
    executable = _fake_executable(tmp_path, "vol.exe")
    _only_installed_binary(monkeypatch, "vol", executable)
    registry = B.resolve_backend_versions(
        probe=_RecordingProbe(stdout=VOLATILITY_BANNER, exit_status=2)
    )

    manifest = registry.manifest()
    serialized = json.dumps(manifest)
    restored = B.BackendVersionRegistry.from_manifest(json.loads(serialized))

    assert restored.sealed
    assert restored.entries() == registry.entries()
    assert restored.manifest() == manifest
    assert manifest["schema_id"] == B.BACKEND_VERSIONS_SCHEMA_ID
    assert [record["backend"] for record in manifest["backends"]] == sorted(
        record["backend"] for record in manifest["backends"]
    )
    assert str(executable) not in serialized
    assert str(tmp_path) not in serialized


def test_manifest_digest_rejects_an_edited_inventory():
    registry = B.BackendVersionRegistry()
    registry.record(_entry())
    manifest = registry.seal().manifest()

    tampered = json.loads(json.dumps(manifest))
    tampered["backends"][0]["version"] = "99.99"

    with pytest.raises(B.BackendVersionError, match="digest"):
        B.BackendVersionRegistry.from_manifest(tampered)


def test_manifest_cannot_smuggle_a_version_onto_an_unresolved_backend():
    registry = B.BackendVersionRegistry()
    registry.record(
        B.BackendVersion(
            backend="tshark",
            display_name="Wireshark tshark",
            kind=B.BackendKind.CLI,
            status=B.BackendStatus.NOT_INSTALLED,
            reason=B.REASON_EXECUTABLE_NOT_FOUND,
        )
    )
    manifest = registry.seal().manifest()
    # A forger who edits the inventory can recompute the digest, so the digest
    # alone is not the defence here: the entry invariant is.
    manifest["backends"][0]["version"] = "4.2.2"
    manifest["backends_sha256"] = sha256_hex(canonical_json(manifest["backends"]))

    with pytest.raises(B.BackendVersionError, match="must not carry a version"):
        B.BackendVersionRegistry.from_manifest(manifest)


# --- The seam into the v2 contract -------------------------------------------


def test_resolved_backend_becomes_an_upstream_backend_record():
    record = _entry().upstream_backend(
        operation="filesystem.list_directory", role="producer"
    )

    assert record.name == "dfvfs"
    assert record.version == "20260731"
    assert record.operation == "filesystem.list_directory"
    assert record.role == "producer"


def test_upstream_record_is_accepted_by_the_v2_provenance_contract():
    record = _entry().upstream_backend(
        operation="filesystem.list_directory", role="producer"
    )

    provenance = make_provenance(
        evidence_class=EvidenceClass.OBSERVED,
        provenance_type=ProvenanceType.CASE_EVIDENCE,
        invocation_id="run:0001",
        case_id="case-1",
        source_id="disk-1",
        artifact_locator="/x",
        tool_name="list_directory",
        tool_version="0.1.0",
        upstream_backends=[record],
    )

    assert provenance.upstream_backends == [record]
    # Two separate claims that must not be conflated: our wrapper's version, and
    # the version of the component that actually read the evidence.
    assert provenance.tool.version == "0.1.0"
    assert provenance.tool.version != record.version


@pytest.mark.parametrize(
    "status",
    [B.BackendStatus.NOT_INSTALLED, B.BackendStatus.VERSION_UNDETERMINED],
)
def test_upstream_backend_is_refused_when_no_version_was_established(status):
    entry = B.BackendVersion(
        backend="tshark",
        display_name="Wireshark tshark",
        kind=B.BackendKind.CLI,
        status=status,
        reason=B.REASON_EXECUTABLE_NOT_FOUND,
    )

    with pytest.raises(B.BackendVersionUnavailable, match="tshark"):
        entry.upstream_backend(operation="network.packet_summary", role="producer")

    registry = B.BackendVersionRegistry()
    registry.record(entry)
    with pytest.raises(B.BackendVersionUnavailable):
        registry.seal().upstream_backend(
            "tshark", operation="network.packet_summary", role="producer"
        )


def test_an_entry_can_never_be_constructed_with_a_placeholder_version():
    for version in ("unknown", "n/a", "none", "-", ""):
        with pytest.raises(B.BackendVersionError, match="unusable version"):
            B.BackendVersion(
                backend="tshark",
                display_name="Wireshark tshark",
                kind=B.BackendKind.CLI,
                status=B.BackendStatus.RESOLVED,
                version=version,
                source="preflight_probe:--version",
            )


# --- Declaration coherence ----------------------------------------------------


def test_declared_backends_are_coherent_with_the_availability_registry():
    ids = [spec.backend for spec in (*B.PYTHON_BACKENDS, *B.CLI_BACKENDS)]
    assert len(ids) == len(set(ids))

    for spec in B.CLI_BACKENDS:
        assert spec.tool_id in availability.EXTERNAL_TOOLS
        assert "version" in spec.pattern.groupindex
        assert spec.accepted_exit_statuses
        assert spec.timeout_seconds > 0


def test_every_backend_a_declared_operation_names_is_inventoried():
    """An operation may only name a component this preflight can actually version.

    The result contract refuses a backend record without a real version, so a
    declaration the inventory never covers is not a documentation gap: the first
    result that reached that operation would fail attestation on a host where
    nothing is wrong.
    """

    from forensic_agent.agent.tool_operations import DOMAIN_FUNCTIONS

    inventoried = {spec.backend for spec in (*B.PYTHON_BACKENDS, *B.CLI_BACKENDS)}
    declared = {
        backend.name
        for function in DOMAIN_FUNCTIONS.values()
        for operation in function.operations
        for backend in operation.backends
    }

    assert declared, "the registry declares no backends at all"
    assert not declared - inventoried, sorted(declared - inventoried)


def test_the_sqlite_engine_is_versioned_as_the_engine_not_as_its_binding():
    """``sqlite3.sqlite_version`` is the engine that answered; ``version`` is not.

    The DB-API wrapper's version identifies our access path, not the component
    that executed the query, so recording it would name the wrong producer.
    """

    import sqlite3

    entry = B.resolve_python_backend(_spec("cpython_sqlite3"))

    assert entry.status is B.BackendStatus.RESOLVED
    assert entry.version == sqlite3.sqlite_version
    assert entry.source == "library_api:sqlite3.sqlite_version"
    # Read from the spec rather than from the wrapper's own deprecated
    # ``sqlite3.version`` attribute, which is removed in a coming interpreter.
    assert _spec("cpython_sqlite3").attributes == ("sqlite_version",)
    assert (
        entry.upstream_backend(operation="sqlite.select", role="producer").version
        == sqlite3.sqlite_version
    )


@pytest.mark.parametrize(
    "backend", ["cpython_hashlib", "cpython_zipfile", "cpython_stdlib"]
)
def test_interpreter_bundled_components_are_versioned_by_the_interpreter(backend):
    """These ship with CPython and have no release of their own to cite."""

    import platform

    entry = B.resolve_python_backend(_spec(backend))

    assert entry.status is B.BackendStatus.RESOLVED
    assert entry.version == platform.python_version()
    assert entry.source == "library_api:platform.python_version"
    # The point of inventorying them is that they can attest a result at all.
    assert entry.upstream_backend(operation="transform.decode", role="producer")
