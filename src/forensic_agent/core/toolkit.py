"""Shared tool spine: cross-cutting plumbing every external-tool wrapper flows through, so the
forensic tools (tools/*.py) keep ONLY their tool-specific logic (which tshark/regipy/vol call).

- run_external(): the single place external forensic tools are executed. It captures output and
  enforces the failure contract (non-zero exit or timeout -> ExternalToolError), so a failed tool
  surfaces as an error instead of a silent "no evidence".
- scratch_dir(): a transient working directory that is always removed, closing the temp-dir leak
  class for tools whose temp output is consumed internally.
Read-only orchestration; no shell is ever spawned (argv lists only).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from collections.abc import Mapping
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
    tool = cmd[0] if cmd else "external tool"
    effective = effective_external_timeout(timeout)
    if effective is None:
        raise ExternalToolError(tool, None, "cell deadline reached before the tool could start")
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
