"""Shared tool spine: cross-cutting plumbing every external-tool wrapper flows through, so the
forensic tools (tools/*.py) keep ONLY their tool-specific logic (which tshark/regipy/vol call).

- run_external(): the single place external forensic tools are executed. It captures output and
  enforces the failure contract (non-zero exit or timeout -> ExternalToolError), so a failed tool
  surfaces as an error instead of a silent "no evidence".
- stream_external(): the same execution under the same contract for the one tool that has
  something to say WHILE it runs. It differs only in when the output is handed over — line by
  line as it is printed rather than in one piece after the exit — so a scan measured in tens of
  minutes can be reported honestly instead of appearing to hang.
- scratch_dir(): a transient working directory that is always removed, closing the temp-dir leak
  class for tools whose temp output is consumed internally.
Read-only orchestration; no shell is ever spawned (argv lists only).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar

from forensic_agent.core.storage_containment import (
    EvidenceWriteScope,
    acquire_evidence_write_dir,
)
from forensic_agent.core.telemetry_egress import TELEMETRY_EGRESS_VARIABLES

_CHILD_SECRET_SUFFIXES = (
    "_API_KEY",
    "_TOKEN",
    "_SECRET",
    "_PASSWORD",
    "_CREDENTIAL",
    "_CREDENTIALS",
)
_CHILD_BLOCKED_ENVIRONMENT = frozenset(
    {
        "ALL_PROXY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "DFA_BASE_URL",
        "DFA_JUDGE_BASE_URL",
        "DFA_JUDGE_KEY",
        # A container runtime that a child inherits can point at a remote
        # daemon.  Evidence must never leave this machine because an ambient
        # variable said so, so the child always talks to the local daemon.
        "DOCKER_CERT_PATH",
        "DOCKER_CONTEXT",
        "DOCKER_HOST",
        "DOCKER_TLS_VERIFY",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "OPENROUTER_BASE_URL",
        "PASSWORD",
    }
) | TELEMETRY_EGRESS_VARIABLES
# The telemetry set is unioned rather than restated so the two places that shut
# these channels can never disagree.  This layer covers CHILD processes only; the
# LangChain tracer runs in the parent, which is sealed at package import instead.
# A forensic binary has no use for any of them, and one inherited toggle would be
# enough for a child that happens to import the library to start uploading.


def _sanitized_child_environment(overlay: Mapping[str, str] | None = None) -> dict[str, str]:
    """Preserve tool/runtime settings but never delegate credentials to binaries.

    Model clients run in this Python process and receive their API key explicitly.
    External forensic parsers need PATH/TEMP/cache settings, not LLM, cloud, GitHub,
    Hugging Face, proxy, or endpoint credentials.  Sanitizing at the one subprocess
    boundary keeps those secrets out of every fixed-argv tool wrapper.

    ``overlay`` is applied last and is not sanitized: it is the caller's own
    settings for one tool, not something inherited from the ambient environment.
    """

    environment: dict[str, str] = {}
    for name, value in os.environ.items():
        normalized = name.upper()
        if normalized in _CHILD_BLOCKED_ENVIRONMENT or normalized.endswith(_CHILD_SECRET_SUFFIXES):
            continue
        environment[name] = value
    if overlay:
        environment.update({str(name): str(value) for name, value in overlay.items()})
    return environment


class ExternalToolError(Exception):
    """A wrapped external forensic tool failed (non-zero exit or timeout)."""

    def __init__(self, tool: str, returncode, stderr: str = ""):
        self.tool = tool
        self.returncode = returncode
        self.stderr = (stderr or "")[:300]
        super().__init__(f"{tool} failed (rc={returncode}): {self.stderr or 'no stderr'}")


#: Absolute monotonic deadline of the execution cell that owns the current call.
#: A per-tool timeout is a ceiling for one tool, not a promise about the run: a
#: tool with a fifteen minute ceiling would otherwise keep a three minute console
#: cell busy long after its own budget is gone.  No external process may outlive
#: the cell it belongs to.
_CELL_DEADLINE: ContextVar[float | None] = ContextVar("forensic_cell_deadline", default=None)
#: Below this the remaining time cannot produce a useful result, so the tool is
#: refused before spawning rather than started and killed moments later.
_MINIMUM_EXTERNAL_SECONDS = 1.0


@contextmanager
def cell_deadline(deadline_monotonic: float | None):
    """Bind every external process started inside the body to one cell deadline."""

    token = _CELL_DEADLINE.set(deadline_monotonic)
    try:
        yield
    finally:
        _CELL_DEADLINE.reset(token)


def effective_external_timeout(timeout: float) -> float | None:
    """Clamp a per-tool ceiling to the time the owning cell actually has left.

    Returns ``None`` when the cell has no usable time remaining.
    """

    deadline = _CELL_DEADLINE.get()
    if deadline is None:
        return timeout
    remaining = deadline - time.monotonic()
    if remaining < _MINIMUM_EXTERNAL_SECONDS:
        return None
    return min(float(timeout), remaining)


def _admit_external(cmd, timeout) -> tuple[str, float]:
    """Name the tool and settle how long it really has, or refuse to start it.

    Both runners open on exactly this: the tool's name for the failure message,
    the per-tool ceiling clamped to what the owning cell has left, and the
    refusal when there is no usable time. Shared rather than restated so the
    streaming path can never end up with a different notion of the deadline
    than the blocking one.
    """

    tool = cmd[0] if cmd else "external tool"
    effective = effective_external_timeout(timeout)
    if effective is None:
        raise ExternalToolError(tool, None, "cell deadline reached before the tool could start")
    return tool, effective


def run_external(
    cmd,
    *,
    timeout,
    text=True,
    check=True,
    cwd=None,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess:
    """Run an external forensic tool as a subprocess and return its CompletedProcess.

    On a timeout, or a non-zero exit when `check=True` (the default), raise ExternalToolError
    carrying the return code and stderr. Pass `check=False` for the rare tool that may exit
    non-zero yet still produce usable output (e.g. a scanner): it returns the CompletedProcess and
    the caller decides. `cmd` is an argv list (never a shell string).

    ``env`` overlays the sanitized child environment for this one call, for a
    tool whose result depends on a setting the ambient environment must not be
    allowed to decide. It adds to that environment rather than replacing it, so
    a wrapper cannot accidentally strip the PATH its own binary was found on.

    ``timeout`` is a ceiling. When an execution cell is active, the effective
    timeout is the smaller of that ceiling and the cell's remaining time."""
    tool, effective = _admit_external(cmd, timeout)
    proc: subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]
    try:
        if text:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=effective,
                cwd=cwd,
                env=_sanitized_child_environment(env),
            )
        else:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=False,
                timeout=effective,
                cwd=cwd,
                env=_sanitized_child_environment(env),
            )
    except subprocess.TimeoutExpired as e:
        raise ExternalToolError(tool, None, f"timed out after {effective:.0f}s") from e
    if check and proc.returncode != 0:
        stderr = proc.stderr if isinstance(proc.stderr, str) else ""
        raise ExternalToolError(tool, proc.returncode, stderr)
    return proc


#: How much of a streamed tool's output is kept for its failure message. The
#: output itself was already handed to the caller line by line, so holding the
#: whole of it a second time would buy nothing; what a failure needs is the end
#: of it, which is where a tool says why it stopped.
_STREAM_TAIL_LINES = 40


def _deliver_line(on_line: Callable[[str], None], line: str) -> None:
    """Hand one line to the observer, and never let the observer fail the tool.

    The only reason this callback exists is to say something on a screen. A
    console that has gone away, a widget removed under a repaint, or a caller
    that simply raised must not turn into a scan that did not finish: the tool
    is the work, and the observer is a description of it.
    """

    try:
        on_line(line)
    except Exception:
        pass


def stream_external(
    cmd: Sequence[str],
    *,
    timeout,
    on_line: Callable[[str], None],
    check: bool = True,
    cwd=None,
    env: Mapping[str, str] | None = None,
) -> int:
    """Run an external forensic tool and read its output WHILE it runs.

    Identical to :func:`run_external` in everything that contains the child —
    the same argv list and no shell, the same sanitized environment, the same
    clamp of the per-tool ceiling to the owning cell's remaining time, and the
    same :class:`ExternalToolError` on a timeout or (with ``check``) a non-zero
    exit. It differs in one thing only: stderr is merged into stdout and the
    merged stream is read line by line as it is printed, with each line handed
    to ``on_line``.

    That difference exists for the tool that blocks for tens of minutes and says
    how far it has got as it goes. Captured output arrives after the exit, which
    is exactly too late to tell anyone anything, so the whole-image scan behind
    a case open would otherwise be a spinner with no number for its whole
    length.

    ``on_line`` receives one line at a time with its terminator stripped, on the
    CALLING thread, so a caller's own state needs no lock it did not already
    need. Carriage returns count as line ends alongside newlines: a scanner that
    paints its progress in place would otherwise withhold every line of it until
    it exited.

    Returns the child's return code. The output is deliberately NOT accumulated
    and returned — the caller has already seen it, line by line. Only the last
    few lines are kept, and only so a failure can say what the tool said last.
    """

    tool, effective = _admit_external(cmd, timeout)
    proc = subprocess.Popen(
        list(cmd),  # an argv list, never a shell string — as everywhere else here
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=cwd,
        env=_sanitized_child_environment(env),
    )
    # The read below blocks in this thread, so the ceiling is enforced by a
    # timer that kills the child exactly as subprocess.run(timeout=...) does:
    # the pipe then reaches end of file, the loop ends, and the corpse is
    # reaped in the finally. Nothing is left running behind a raised timeout.
    expired = threading.Event()

    def _expire() -> None:
        expired.set()
        try:
            proc.kill()
        except Exception:  # pragma: no cover - already gone is the outcome wanted
            pass

    watchdog = threading.Timer(effective, _expire)
    watchdog.daemon = True
    watchdog.start()
    tail: deque[str] = deque(maxlen=_STREAM_TAIL_LINES)
    try:
        stream = proc.stdout
        if stream is not None:
            # Universal newline mode is what makes a carriage return a line
            # end here: readline() is fed by decoded chunks in which '\r' and
            # '\r\n' have both already become '\n'.
            while True:
                line = stream.readline()
                if not line:
                    break
                line = line.rstrip("\r\n")
                tail.append(line)
                _deliver_line(on_line, line)
        proc.wait()
    finally:
        watchdog.cancel()
        if proc.poll() is None:
            # The loop left early (the caller was interrupted, or the read
            # failed). Kill and drain rather than leak a scanner that would
            # keep reading the evidence with nobody left to receive it.
            try:
                proc.kill()
            except Exception:  # pragma: no cover
                pass
            proc.wait()
        if proc.stdout is not None:
            proc.stdout.close()
    if expired.is_set():
        raise ExternalToolError(tool, None, f"timed out after {effective:.0f}s")
    if check and proc.returncode != 0:
        raise ExternalToolError(tool, proc.returncode, "\n".join(tail)[-300:])
    return proc.returncode


@contextmanager
def scratch_dir(prefix: str = "forensic_agent_"):
    """Yield a fresh temporary directory, removed on exit (even if the body raises). Use ONLY for
    temp output consumed internally; do NOT use for a directory whose PATH is returned to the
    caller (extract caches are a deliberate persistent cache, not a leak).

    The base is resolved through the write-scope facade under the recorded weak
    scope before the directory is created: the production runner rebinds
    ``tempfile`` into controlled scratch for the whole tool-executing region, so
    this base is already contained on every model path, and routing it through
    the facade makes that mandatory and explicit rather than an implicit
    consequence a future caller could drop. A base demonstrably shared with the
    host (a bind-mounted TEMP inside a container) is refused."""
    base = tempfile.gettempdir()
    acquire_evidence_write_dir(
        base,
        subject="internal forensic tool scratch output",
        scope=EvidenceWriteScope.NOT_HOST_SHARED,
    )
    d = tempfile.mkdtemp(prefix=prefix, dir=base)
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)
