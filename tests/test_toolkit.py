"""Shared tool spine: one place to run an external forensic tool (returncode/timeout contract)
and one place for a transient working directory (guaranteed cleanup)."""

import os
import subprocess
import sys
import time

import pytest

from forensic_agent.core.toolkit import (
    ExternalToolError,
    cell_deadline,
    run_external,
    scratch_dir,
    stream_external,
)


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


# ---------------------------------------------------------------------------
# the streaming runner: the same containment, output handed over as it arrives
# ---------------------------------------------------------------------------
# A stand-in for the one tool that has something to say while it runs. It paints
# its progress in place — a carriage return and no newline, exactly as
# bulk_extractor does — and then holds the pipe open for most of a second, so a
# runner that only produced output after the exit would be caught by the clock.
_PAINTS_PROGRESS_IN_PLACE = (
    "import sys, time\n"
    "for megabytes in (10, 20, 30, 40):\n"
    "    sys.stdout.write('Offset %dMB (%d.00%%) Done in 0:00:01' % (megabytes, megabytes))\n"
    "    sys.stdout.write(chr(13))\n"
    "    sys.stdout.flush()\n"
    "    time.sleep(0.15)\n"
    "time.sleep(0.9)\n"
)


def test_stream_external_hands_over_carriage_returned_lines_while_the_child_runs():
    """The whole point: the lines arrive DURING the run, not after it.

    A scan of a real medium blocks for tens of minutes, so output collected at
    the exit is output nobody can be told about. A carriage return has to end a
    line here for the same reason: a scanner painting one progress line in place
    would otherwise deliver the lot of it as a single line at the end.
    """

    seen: list[tuple[float, str]] = []
    started = time.monotonic()
    code = stream_external(
        [sys.executable, "-c", _PAINTS_PROGRESS_IN_PLACE],
        timeout=30,
        on_line=lambda line: seen.append((time.monotonic() - started, line)),
    )
    finished = time.monotonic() - started

    assert code == 0
    assert [line for _, line in seen] == [
        "Offset 10MB (10.00%) Done in 0:00:01",
        "Offset 20MB (20.00%) Done in 0:00:01",
        "Offset 30MB (30.00%) Done in 0:00:01",
        "Offset 40MB (40.00%) Done in 0:00:01",
    ]
    assert seen[0][0] < finished - 0.5, f"nothing was handed over until the exit: {seen}"


def test_stream_external_reads_ordinary_newline_terminated_output_too():
    child = "import sys\nfor n in (1, 2):\n    print('line %d' % n)\n"
    seen: list[str] = []
    assert stream_external([sys.executable, "-c", child], timeout=30, on_line=seen.append) == 0
    assert seen == ["line 1", "line 2"]


def test_stream_external_nonzero_raises_with_rc_and_what_the_tool_said_last():
    child = (
        "import sys\n"
        "print('scanned 3 files')\n"
        "sys.stderr.write('bad sector at 0x40')\n"
        "sys.stderr.write(chr(10))\n"
        "sys.exit(3)\n"
    )
    with pytest.raises(ExternalToolError) as ei:
        stream_external([sys.executable, "-c", child], timeout=30, on_line=lambda line: None)
    assert ei.value.returncode == 3
    # stderr is merged into the one stream, so the reason still reaches the error.
    assert "bad sector at 0x40" in ei.value.stderr


def test_stream_external_check_false_returns_the_code_the_caller_decides_on():
    code = stream_external(
        [sys.executable, "-c", "raise SystemExit(4)"],
        timeout=30,
        on_line=lambda line: None,
        check=False,
    )
    assert code == 4


def test_stream_external_timeout_raises_and_leaves_no_scanner_running(tmp_path):
    """A killed tool must really be dead: a scan nobody is waiting for still reads."""

    marker = tmp_path / "still-reading"
    child = (
        "import sys, time\n"
        "for n in range(4000):\n"
        "    open(sys.argv[1], 'a').write('x')\n"
        "    sys.stdout.write('Offset %dMB (0.01%%)' % n + chr(10))\n"
        "    sys.stdout.flush()\n"
        "    time.sleep(0.02)\n"
    )
    started = time.monotonic()
    with pytest.raises(ExternalToolError) as ei:
        stream_external(
            [sys.executable, "-c", child, str(marker)],
            timeout=1,
            on_line=lambda line: None,
        )
    assert "timed out" in str(ei.value)
    assert time.monotonic() - started < 15, "the ceiling was not enforced"
    written = marker.stat().st_size
    time.sleep(0.4)
    assert marker.stat().st_size == written, "the child outlived the call that raised"


def test_stream_external_refuses_when_the_cell_has_no_time_left():
    with cell_deadline(time.monotonic() - 1):
        with pytest.raises(ExternalToolError) as ei:
            stream_external(["tool"], timeout=30, on_line=lambda line: None)
    assert "cell deadline" in str(ei.value)


def test_stream_external_survives_an_observer_that_raises():
    """The observer exists to draw a row. A display fault must not fail a scan."""

    def the_console_went_away(line: str) -> None:
        raise RuntimeError("no widget to paint into")

    child = "print('Offset 1MB (1.00%) Done in 0:00:01')"
    assert stream_external(
        [sys.executable, "-c", child], timeout=30, on_line=the_console_went_away
    ) == 0


def test_stream_external_scrubs_the_credentials_run_external_scrubs(monkeypatch):
    """Read out of the environment the child really got, not out of the kwargs."""

    monkeypatch.setenv("DFA_TOOLKIT_MARKER", "kept")
    monkeypatch.setenv("OPENROUTER_API_KEY", "must-not-reach-parser")
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-reach-parser")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "must-not-reach-parser")
    monkeypatch.setenv("HTTPS_PROXY", "http://credentialed-proxy.invalid")
    child = (
        "import os, sys\n"
        "for name in ('DFA_TOOLKIT_MARKER', 'OPENROUTER_API_KEY', 'GITHUB_TOKEN',\n"
        "             'AWS_ACCESS_KEY_ID', 'HTTPS_PROXY'):\n"
        "    print('%s=%s' % (name, os.environ.get(name, '')))\n"
    )
    seen: list[str] = []

    stream_external([sys.executable, "-c", child], timeout=30, on_line=seen.append)

    assert "DFA_TOOLKIT_MARKER=kept" in seen  # the runtime settings a tool needs
    for name in ("OPENROUTER_API_KEY", "GITHUB_TOKEN", "AWS_ACCESS_KEY_ID", "HTTPS_PROXY"):
        assert f"{name}=" in seen, f"{name} reached the child"


def test_stream_external_forwards_cwd(tmp_path):
    seen: list[str] = []
    stream_external(
        [sys.executable, "-c", "import os; print(os.getcwd())"],
        timeout=30,
        on_line=seen.append,
        cwd=str(tmp_path),
    )
    assert seen and os.path.realpath(seen[0]) == os.path.realpath(str(tmp_path))
