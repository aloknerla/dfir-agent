"""One availability registry must drive doctor, /tools and the model registry.

Each test here pins one property of that arrangement: no drift between the legacy
``*_path`` helpers and the registry, derivation of all three surfaces from it, and
fail-closed behaviour that stays distinguishable from a genuine programming error.
"""

from __future__ import annotations

import types
from io import StringIO
from pathlib import Path
from types import SimpleNamespace

import pytest
from rich.console import Console

import forensic_agent.agent.tool_registry as tool_registry
import forensic_agent.core.environ as environ
import forensic_agent.core.tool_availability as availability
from forensic_agent.cli import terminal
from forensic_agent.cli.session import InteractiveSession
from forensic_agent.core.audit import AuditLog

LEGACY_HELPERS = {
    "vol": "vol_path",
    "clamscan": "clamscan_path",
    "tshark": "tshark_path",
    "mergecap": "mergecap_path",
    "seven_zip": "seven_zip_path",
    "tesseract": "tesseract_path",
    "regripper": "regripper_path",
    "bulk_extractor": "bulk_extractor_path",
    # The recovery mediator added its binary to the same registry, and its
    # ``*_path`` helper must resolve through it without drifting like the rest.
    "john": "john_path",
}


def _console() -> Console:
    return Console(file=StringIO(), force_terminal=False, width=200, no_color=True)


def _rendered(console: Console) -> str:
    stream = console.file
    assert isinstance(stream, StringIO)
    return stream.getvalue()


def _make_unavailable(monkeypatch: pytest.MonkeyPatch, *tool_ids: str) -> None:
    """Fail resolution for exactly these tools, at the single probe seam."""

    original = availability._resolve_spec

    def probe(spec: availability.ExternalToolSpec) -> str | None:
        if spec.id in tool_ids:
            return None
        return original(spec)

    monkeypatch.setattr(availability, "_resolve_spec", probe)


def _offline_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep `doctor` off the network; only its tool rows matter here."""

    monkeypatch.setattr(
        environ,
        "backend_status",
        lambda *_args, **_kwargs: {
            "reachable": False,
            "models": [],
            "has_model": None,
            "kind": "openrouter",
            "authenticated": False,
            "error": "offline in tests",
        },
    )


def _disk(tmp_path: Path) -> SimpleNamespace:
    return types.SimpleNamespace(
        extract_file=lambda *args, **kwargs: None,
        image_path=str(tmp_path / "x.dd"),
        image_sha="x",
        audit=AuditLog(str(tmp_path / "audit.jsonl")),
    )


def _session_args(tmp_path: Path, **overrides: object) -> SimpleNamespace:
    values: dict[str, object] = {
        "model": "openai/gpt-oss-120b",
        "base_url": "https://openrouter.ai/api/v1",
        "api_key": "test-key",
        "memory": None,
        "pcap": None,
        "max_steps": 10,
        "image": None,
        "case": None,
        "run_dir": str(tmp_path / "runs"),
        "resume": None,
        "continue_session": False,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _tools_listing(tmp_path: Path) -> str:
    console = _console()
    session = InteractiveSession(_session_args(tmp_path), console=console)
    try:
        session.show_tools()
    finally:
        session.close()
    return _rendered(console)


def _tool_detail_listing(tmp_path: Path, name: str) -> str:
    """Render ``/tools <name>``, where the compact listing sends the long text.

    The default listing states only the evidence type that would activate a
    function; the override hint and the external-tool name now live in the
    per-function detail, so a test about their visibility reads the detail
    rather than the compact table.
    """

    console = _console()
    session = InteractiveSession(_session_args(tmp_path), console=console)
    try:
        session.show_tools(name)
    finally:
        session.close()
    return _rendered(console)


# 1 — the registry is the whole set, and the legacy helpers do not drift from it.


def test_registry_declares_every_legacy_tool_and_helpers_do_not_drift(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    assert set(availability.EXTERNAL_TOOLS) == set(LEGACY_HELPERS)

    stand_in = tmp_path / "stand-in-binary"
    stand_in.write_text("", encoding="utf-8")
    resolved = {
        tool_id: (str(stand_in) if index % 2 == 0 else None)
        for index, tool_id in enumerate(sorted(LEGACY_HELPERS))
    }
    monkeypatch.setattr(availability, "_resolve_spec", lambda spec: resolved[spec.id])

    for tool_id, helper_name in LEGACY_HELPERS.items():
        status = availability.tool_availability(tool_id)
        assert status.id == tool_id
        assert status.env_var == availability.EXTERNAL_TOOLS[tool_id].env_var
        assert status.available is (status.path is not None)
        # The helper must report exactly what the registry resolved: any
        # independent probing would produce the real host answer instead.
        assert getattr(environ, helper_name)() == status.path == resolved[tool_id]
        if not status.available:
            assert status.reason
            assert status.env_var in status.hint


# 2 — doctor is derived from the registry.


def test_doctor_reports_registry_unavailability_with_its_env_var(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _offline_backend(monkeypatch)
    monkeypatch.delenv("DFA_MEMORY_SCAN_DOCKER_IMAGE", raising=False)
    _make_unavailable(monkeypatch, "tshark")

    rows = environ.doctor(base_url="https://openrouter.ai/api/v1", model="m")
    tshark_row = next(row for row in rows if row.get("tool_id") == "tshark")
    assert tshark_row["ok"] is False
    assert tshark_row["env_var"] == "DFA_TSHARK"
    assert tshark_row["name"] == availability.EXTERNAL_TOOLS["tshark"].doctor_label

    console = _console()
    terminal.render_doctor("m", "https://openrouter.ai/api/v1", "k", console=console)
    output = _rendered(console)
    assert "DFA_TSHARK" in output
    assert "Wireshark — tshark" in output


# 3 — /tools reflects the same registry state.


def test_tools_listing_reflects_the_same_registry_state(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _make_unavailable(monkeypatch, "tshark")
    unavailable_listing = _tools_listing(tmp_path)
    # The compact listing names the function and the evidence that activates it;
    # the override hint moved to the per-function detail.
    assert "pcap_query()" in unavailable_listing
    assert "requires network capture" in unavailable_listing
    assert "DFA_TSHARK" not in unavailable_listing
    assert "DFA_TSHARK" in _tool_detail_listing(tmp_path, "pcap_query")

    stand_in = tmp_path / "tshark-stand-in"
    stand_in.write_text("", encoding="utf-8")
    monkeypatch.setattr(availability, "_resolve_spec", lambda spec: str(stand_in))
    available_detail = _tool_detail_listing(tmp_path, "pcap_query")
    assert "DFA_TSHARK" not in available_detail
    assert "tshark" in available_detail


# 4 — the agent registry's treatment of an unavailable tool is explicit.


def test_unavailable_dependency_fails_closed_and_is_recorded(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _make_unavailable(monkeypatch, "tshark", "regripper")
    capture = tmp_path / "x.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1")

    snapshot = tool_registry.build_tool_registry(
        _disk(tmp_path), pcap_path=str(capture), capture=False
    )

    # Exposed, so its disappearance can never be mistaken for a policy decision,
    # and failing closed on invocation without reaching a missing binary.
    assert "pcap_query" in snapshot.names
    record = snapshot.unavailable["pcap_query"]
    assert record.exposed is True
    assert record.missing == ("tshark",)
    assert record.env_vars == ("DFA_TSHARK",)

    pcap_tool = next(tool for tool in snapshot.tools if tool.name == "pcap_query")
    first = pcap_tool.func(query="dns")
    second = pcap_tool.func(query="http", proto="ftp")
    assert first == second  # deterministic: same configuration, same result
    assert first["error"]["code"] == "external_tool_unavailable"
    assert first["error"]["tool"] == "pcap_query"
    assert first["items"] == [] and first["coverage_complete"] is False
    assert [entry["env_var"] for entry in first["error"]["missing_dependencies"]] == ["DFA_TSHARK"]

    # On the default (domain-function) surface the RegRipper facade keeps its
    # schema and fails closed, and the record says which binary is missing.
    assert "registry_ripper" in snapshot.names
    withheld = snapshot.unavailable["registry_ripper"]
    assert withheld.exposed is True
    assert withheld.env_vars == ("DFA_REGRIPPER",)
    assert withheld.reason

    # Out-of-scope functions are not reported as unavailable: no memory dump is
    # bound here, so nothing claims a missing memory tool.
    assert "memory_query" not in snapshot.unavailable


# 5 — an env-var override is honoured and visible through all three surfaces.


def test_env_var_override_is_visible_through_every_surface(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _offline_backend(monkeypatch)
    override = tmp_path / "tshark-override.exe"
    override.write_text("", encoding="utf-8")
    override.chmod(0o700)
    monkeypatch.setenv("DFA_TSHARK", str(override))

    # registry
    status = availability.tool_availability("tshark")
    assert status.available is True and status.path == str(override)
    assert environ.tshark_path() == str(override)

    # doctor
    rows = environ.doctor(base_url="https://openrouter.ai/api/v1", model="m")
    tshark_row = next(row for row in rows if row.get("tool_id") == "tshark")
    assert tshark_row["ok"] is True and tshark_row["detail"] == str(override)

    # /tools — the override resolves, so the per-function detail names the tool
    # as ready and no longer prints the override hint.
    detail = _tool_detail_listing(tmp_path, "pcap_query")
    assert "tshark" in detail
    assert "DFA_TSHARK" not in detail

    # model-visible registry: no fail-closed shim, so the real function is bound
    capture = tmp_path / "x.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1")
    snapshot = tool_registry.build_tool_registry(
        _disk(tmp_path), pcap_path=str(capture), capture=False
    )
    assert "pcap_query" in snapshot.names
    assert "pcap_query" not in snapshot.unavailable
