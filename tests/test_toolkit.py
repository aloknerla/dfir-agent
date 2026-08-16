"""Shared tool spine: one place to run an external forensic tool (returncode/timeout contract)
and one place for a transient working directory (guaranteed cleanup)."""

import os
import subprocess
import sys

import pytest

from forensic_agent.core.toolkit import ExternalToolError, run_external, scratch_dir


class _Proc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def test_run_external_success_returns_completed_process(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _Proc(returncode=0, stdout="ok"))
    proc = run_external(["tool", "-x"], timeout=5)
    assert proc.returncode == 0 and proc.stdout == "ok"


def test_run_external_replaces_invalid_utf8_and_preserves_binary_output():
    script = (
        "import sys; "
        "sys.stdout.buffer.write(b'out:\\xa2'); "
        "sys.stderr.buffer.write(b'err:\\xb8')"
    )

    decoded = run_external([sys.executable, "-c", script], timeout=5)
    binary = run_external([sys.executable, "-c", script], timeout=5, text=False)

    assert decoded.stdout == "out:\ufffd"
    assert decoded.stderr == "err:\ufffd"
    assert binary.stdout == b"out:\xa2"
    assert binary.stderr == b"err:\xb8"


def test_run_external_nonzero_raises_with_rc_and_stderr(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _Proc(returncode=2, stderr="boom"))
    with pytest.raises(ExternalToolError) as ei:
        run_external(["tool"], timeout=5)
    assert ei.value.returncode == 2 and "boom" in ei.value.stderr and "tool" in str(ei.value)


def test_run_external_timeout_raises(monkeypatch):
    def _boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="tool", timeout=5)

    monkeypatch.setattr(subprocess, "run", _boom)
    with pytest.raises(ExternalToolError) as ei:
        run_external(["tool"], timeout=5)
    assert "tim" in str(ei.value).lower()


def test_run_external_check_false_returns_nonzero(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _Proc(returncode=1, stdout="partial"))
    proc = run_external(["carver"], timeout=5, check=False)  # caller inspects rc itself
    assert proc.returncode == 1 and proc.stdout == "partial"


def test_run_external_forwards_cwd(monkeypatch):
    seen = {}
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: seen.update(k) or _Proc(returncode=0))
    run_external(["tool"], timeout=5, cwd="/work")
    assert seen.get("cwd") == "/work"


def test_run_external_preserves_runtime_environment_but_scrubs_credentials(monkeypatch):
    seen = {}
    monkeypatch.setenv("PATH", "tool-path")
    monkeypatch.setenv("TEMP", "cell-scratch")
    monkeypatch.setenv("OPENROUTER_API_KEY", "must-not-reach-parser")
    monkeypatch.setenv("DFA_JUDGE_KEY", "must-not-reach-parser")
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-reach-parser")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "must-not-reach-parser")
    monkeypatch.setenv("HTTPS_PROXY", "http://credentialed-proxy.invalid")
    monkeypatch.setenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: seen.update(k) or _Proc())

    run_external(["tool"], timeout=5)

    child = seen["env"]
    assert child["PATH"] == "tool-path"
    assert child["TEMP"] == "cell-scratch"
    for name in (
        "OPENROUTER_API_KEY",
        "DFA_JUDGE_KEY",
        "GITHUB_TOKEN",
        "AWS_ACCESS_KEY_ID",
        "HTTPS_PROXY",
        "OPENROUTER_BASE_URL",
    ):
        assert name not in child


def test_scratch_dir_creates_then_removes():
    with scratch_dir("t_") as d:
        assert os.path.isdir(d)
        open(os.path.join(d, "x"), "w").close()
        saved = d
    assert not os.path.exists(saved)  # cleaned on normal exit


def test_scratch_dir_removes_even_on_exception():
    saved = None
    with pytest.raises(ValueError):
        with scratch_dir("t_") as d:
            saved = d
            raise ValueError("boom")
    assert saved and not os.path.exists(saved)  # cleaned on exception too
