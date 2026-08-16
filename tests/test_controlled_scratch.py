from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from forensic_agent.core.controlled_scratch import (
    ControlledScratchError,
    ControlledScratchSession,
    ScratchKind,
    attest_controlled_scratch_root,
    provision_controlled_scratch_root,
)


def _root(tmp_path: Path, name: str = "scratch"):
    root = tmp_path / name
    root.mkdir()
    return root, attest_controlled_scratch_root(root)


def test_root_record_commits_without_disclosing_host_path(tmp_path):
    root, attestation = _root(tmp_path)
    serialized = json.dumps(attestation.record(), sort_keys=True)
    assert str(root) not in serialized
    assert attestation.path_sha256 in serialized
    assert len(attestation.sha256) == 64


def test_session_uses_fixed_exclusive_payload_and_verifies_cleanup(tmp_path):
    root, attestation = _root(tmp_path)
    session = ControlledScratchSession(attestation, namespace="run-1")
    with session.artifact(ScratchKind.REGISTRY_HIVE) as artifact:
        assert artifact.path.name == "payload.hive"
        assert root in artifact.path.parents
        artifact.writer.write(b"registry")
        sealed = artifact.seal()
        assert sealed.read_bytes() == b"registry"
    session.close()
    telemetry = session.telemetry()
    assert telemetry["allocations"] == telemetry["cleanups"] == 1
    assert telemetry["cleanup_ok"] is True
    assert telemetry["closed"] is True
    assert telemetry["session_removed"] is True
    assert list(root.iterdir()) == []


def test_nonempty_root_and_second_same_namespace_fail_closed(tmp_path):
    root, attestation = _root(tmp_path)
    (root / "stale").write_text("leftover", encoding="utf-8")
    with pytest.raises(ControlledScratchError, match="not empty"):
        ControlledScratchSession(attestation, namespace="run")

    (root / "stale").unlink()
    first = ControlledScratchSession(attestation, namespace="run")
    with pytest.raises(ControlledScratchError, match="not empty"):
        ControlledScratchSession(attestation, namespace="run")
    first.close()


def test_cleanup_failure_propagates_and_marks_telemetry(monkeypatch, tmp_path):
    _root_path, attestation = _root(tmp_path)
    session = ControlledScratchSession(attestation, namespace="cleanup")
    artifact = session.artifact(ScratchKind.EVTX_LOG)
    artifact.writer.write(b"event")
    artifact.seal()
    real_unlink = os.unlink

    def fail_payload(path, *args, **kwargs):
        if Path(path) == artifact.path:
            raise PermissionError("locked")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", fail_payload)
    with pytest.raises(ControlledScratchError, match="cleanup was not verified"):
        artifact.__exit__(None, None, None)
    assert session.telemetry()["cleanup_ok"] is False
    with pytest.raises(ControlledScratchError):
        session.close()


def test_provision_rejects_escape_and_symlink_component(tmp_path):
    anchor = tmp_path / "anchor"
    anchor.mkdir()
    with pytest.raises(ControlledScratchError, match="outside"):
        provision_controlled_scratch_root(tmp_path / "outside", anchor=anchor)

    target = anchor / "target"
    target.mkdir()
    link = anchor / "link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink creation is unavailable on this host")
    with pytest.raises(ControlledScratchError, match="symlink or reparse"):
        attest_controlled_scratch_root(link)


def test_kind_cannot_be_model_selected_text(tmp_path):
    _root_path, attestation = _root(tmp_path)
    session = ControlledScratchSession(attestation, namespace="kind")
    with pytest.raises(ControlledScratchError, match="closed enum"):
        session.artifact("../../victim")  # type: ignore[arg-type]
    session.close()
