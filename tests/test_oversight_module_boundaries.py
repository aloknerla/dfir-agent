"""Compatibility and dependency-boundary checks for the oversight split."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from forensic_agent import oversight
from forensic_agent.oversight import audit, core, detectors, enforcement, policy

EXPECTED_PUBLIC_API = [
    "ALL_CAPS",
    "CAP_CONTROLLED_SCRATCH",
    "CAP_DECODE",
    "CAP_NETWORK",
    "CAP_READ_EVIDENCE",
    "CAP_READ_HOST_PATH",
    "CAP_SPAWN",
    "CAP_WRITE",
    "DEFAULT_TOOL_CAPS",
    "Decision",
    "FORENSIC_CHECKLIST",
    "OversightBoundOutput",
    "OversightGate",
    "OversightLog",
    "PATH_ARG_NAMES",
    "Policy",
    "RISK_NAMES",
    "detect_injection",
    "detect_tool_poisoning",
    "enforce",
    "evaluate",
    "reconstruct",
    "scan_tools",
    "verify_chain",
    "wrap_with_oversight",
]

OWNERS = {
    "Policy": policy,
    "Decision": policy,
    "evaluate": policy,
    "detect_injection": detectors,
    "detect_tool_poisoning": detectors,
    "scan_tools": detectors,
    "OversightLog": audit,
    "reconstruct": audit,
    "verify_chain": audit,
    "OversightGate": enforcement,
    "OversightBoundOutput": enforcement,
    "enforce": enforcement,
    "wrap_with_oversight": enforcement,
}


def _top_level_imports(module) -> set[str]:
    path = Path(module.__file__).resolve()
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imported: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported.add(node.module)
    return imported


def test_public_facades_publish_one_explicit_api() -> None:
    assert core.__all__ == EXPECTED_PUBLIC_API
    assert oversight.__all__ == EXPECTED_PUBLIC_API
    for name in EXPECTED_PUBLIC_API:
        assert getattr(oversight, name) is getattr(core, name)


@pytest.mark.parametrize(("name", "owner"), OWNERS.items())
def test_moved_symbols_keep_identity_and_have_a_single_owner(name, owner) -> None:
    owned = getattr(owner, name)
    assert getattr(core, name) is owned
    assert getattr(oversight, name) is owned
    assert owned.__module__ == owner.__name__


def test_direct_imports_of_legacy_monolith_dependencies_still_work() -> None:
    from forensic_agent.oversight import GroundingLedger, sha256_hex
    from forensic_agent.oversight.core import (
        EvidenceSourceRuntimeGuard,
        canonical_json,
    )

    assert GroundingLedger.__module__ == "forensic_agent.oversight.grounding"
    assert sha256_hex.__module__ == "forensic_agent.core.repro"
    assert canonical_json.__module__ == "forensic_agent.core.repro"
    assert (
        EvidenceSourceRuntimeGuard.__module__
        == "forensic_agent.core.evidence_source"
    )


def test_owner_modules_do_not_import_the_compatibility_facade() -> None:
    forbidden = "forensic_agent.oversight.core"
    for module in (policy, detectors, audit, enforcement):
        assert forbidden not in _top_level_imports(module)


def test_dependency_direction_stays_acyclic() -> None:
    assert not {
        name
        for name in _top_level_imports(policy)
        if name.startswith("forensic_agent.oversight")
    }
    assert not {
        name
        for name in _top_level_imports(detectors)
        if name.startswith("forensic_agent.oversight")
    }
    assert "forensic_agent.oversight.policy" in _top_level_imports(audit)
    enforcement_imports = _top_level_imports(enforcement)
    assert {
        "forensic_agent.oversight.audit",
        "forensic_agent.oversight.detectors",
        "forensic_agent.oversight.grounding",
        "forensic_agent.oversight.policy",
    }.issubset(enforcement_imports)


def test_core_evaluate_monkeypatch_still_drives_gate(monkeypatch, tmp_path) -> None:
    expected = policy.Decision(
        allowed=False,
        risk=4,
        reasons=["patched-evaluator"],
        capabilities=[],
    )
    calls = []

    def patched_evaluate(current_policy, tool, args):
        calls.append((current_policy, tool, args))
        return expected

    monkeypatch.setattr(core, "evaluate", patched_evaluate)
    gate = enforcement.OversightGate(
        policy.Policy.permissive(),
        audit.OversightLog(str(tmp_path / "oversight.jsonl")),
    )

    assert gate.evaluate("read_file", {"path": "/"}) is expected
    assert calls == [(gate.policy, "read_file", {"path": "/"})]


def test_core_detector_monkeypatch_still_drives_enforcement(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setattr(
        core,
        "detect_injection",
        lambda _text: ["patched-injection"],
    )
    recorder = audit.OversightLog(str(tmp_path / "oversight.jsonl"))
    gate = enforcement.OversightGate(policy.Policy.permissive(), recorder)
    recorder.open_case(question="q", policy=gate.policy)

    output = enforcement.enforce(
        gate,
        "read_file",
        {"path": "/"},
        lambda: {"text": "benign"},
    )
    actions = [
        row
        for row in audit.OversightLog.load(recorder.path)
        if row.get("event") == "action"
    ]

    assert output == {"text": "benign"}
    assert "injection-signal:patched-injection" in actions[-1]["reasons"]


def test_core_scan_and_enforce_monkeypatches_still_drive_wrapper(
    monkeypatch, tmp_path
) -> None:
    structured_tools = pytest.importorskip("langchain_core.tools")

    def read_file(path: str) -> dict:
        """Read one evidence file."""
        return {"path": path}

    original = structured_tools.StructuredTool.from_function(read_file)
    original.metadata = {"read_only": True}
    recorder = audit.OversightLog(str(tmp_path / "oversight.jsonl"))
    gate = enforcement.OversightGate(policy.Policy.permissive(), recorder)
    scanner_calls = []
    enforcement_calls = []

    def patched_scan(tools):
        scanner_calls.append(tools)
        return []

    def patched_enforce(
        current_gate,
        name,
        args,
        run_fn,
        *,
        spotlight=False,
        bind_action=False,
    ):
        enforcement_calls.append(
            (current_gate, name, args, run_fn, spotlight, bind_action)
        )
        return {"patched": True}

    monkeypatch.setattr(core, "scan_tools", patched_scan)
    monkeypatch.setattr(core, "enforce", patched_enforce)
    wrapped = enforcement.wrap_with_oversight([original], gate)[0]

    assert wrapped.invoke({"path": "/evidence"}) == {"patched": True}
    assert wrapped.metadata == original.metadata
    assert scanner_calls == [[original]]
    assert enforcement_calls
    assert enforcement_calls[0][:3] == (
        gate,
        "read_file",
        {"path": "/evidence"},
    )
    assert enforcement_calls[0][4:] == (False, False)


def test_core_default_recorder_monkeypatch_still_drives_gate(monkeypatch) -> None:
    created = []

    class Recorder:
        def __init__(self):
            created.append(self)

    monkeypatch.setattr(core, "OversightLog", Recorder)
    gate = enforcement.OversightGate()

    assert gate.recorder is created[0]
    assert isinstance(gate.policy, policy.Policy)
    assert (
        gate.ledger.__class__.__module__
        == "forensic_agent.oversight.grounding"
    )
