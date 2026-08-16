"""A backend's stderr, taken at the call boundary instead of the operator's console.

The libraries this project calls report their own trouble on ``stderr`` — a parser
that skipped a malformed record, a plugin that could not read a subkey. On the
operator's console that stream interleaves with the agent's own output, reads as
though the agent said it, and is lost as soon as the screen scrolls.

Capturing it is only half the fix; the other half is where it goes. A backend's
complaint is diagnostic information about the read that produced it, so it belongs
in that read's result — the artifact this project retains and hashes — never in a
discarding sink: a capture hands its text back and the caller must place it.

The capture is thread-scoped because a tool call runs on its own thread.
``sys.stderr`` is replaced once, by a router that sends each write to whichever
capture the WRITING thread has open and to the real stream when that thread has
none.  ``contextlib.redirect_stderr`` would instead have swallowed the output of
every concurrent call — and of every other subsystem — for as long as one call
held it, turning a noise problem into silent data loss.

This is not :mod:`forensic_agent.core.output_capture`, which hashes the value a
tool returned.  This module concerns only what a backend wrote beside that value.
"""

from __future__ import annotations

import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from io import StringIO
from typing import Any

#: Bound on the rendering of one complaint inside a result.  A backend that fails
#: in a loop can produce megabytes, and a result is meant to be read; a cut is
#: reported on the report itself so a shortened complaint never reads as a whole
#: one.
_MAX_DETAIL_CHARS = 800

#: Per-thread stack of open captures.  A stack rather than a single slot because
#: one backend call may sit inside another; the innermost one owns the writes,
#: which is the only attribution that can be right.
_OPEN_CAPTURES = threading.local()

_ROUTER_LOCK = threading.Lock()
_router: _ThreadScopedStderr | None = None
_router_depth = 0


class _ThreadScopedStderr:
    """A ``sys.stderr`` stand-in that routes every write by its writing thread."""

    def __init__(self, passthrough: Any) -> None:
        self.passthrough = passthrough

    def _target(self) -> Any:
        stack = getattr(_OPEN_CAPTURES, "stack", None)
        return stack[-1] if stack else self.passthrough

    def write(self, text: str) -> int:
        target = self._target()
        if target is None:
            # No capture is open and this host has no stderr at all (a windowed
            # interpreter).  There is nothing to retain and nowhere to write.
            return 0
        return target.write(text)

    def flush(self) -> None:
        target = self._target()
        flush = getattr(target, "flush", None)
        if callable(flush):
            flush()

    def __getattr__(self, name: str) -> Any:
        # Everything this router does not route — encoding, isatty, fileno — is a
        # property of the real stream and must keep answering for it.
        return getattr(self.passthrough, name)


def _install_router() -> None:
    """Put the router in place for the first open capture in this process."""

    global _router, _router_depth
    with _ROUTER_LOCK:
        if _router_depth == 0:
            # Read ``sys.stderr`` afresh: a CLI or a test harness may have replaced
            # it since the last capture closed, and the router must wrap what is
            # actually the console now.
            _router = _ThreadScopedStderr(sys.stderr)
            sys.stderr = _router
        _router_depth += 1


def _release_router() -> None:
    """Restore the console once no thread has a capture open any more."""

    global _router, _router_depth
    with _ROUTER_LOCK:
        _router_depth -= 1
        if _router_depth > 0:
            return
        _router_depth = 0
        router, _router = _router, None
        # Only undo our own substitution.  If something else took over stderr in
        # the meantime, putting the old stream back would silently revoke it.
        if router is not None and sys.stderr is router:
            sys.stderr = router.passthrough


@dataclass
class BackendStderr:
    """What one backend call wrote to stderr, held for the caller to place."""

    backend: str
    _buffer: StringIO = field(default_factory=StringIO, repr=False)

    @property
    def text(self) -> str:
        """Everything written so far in this capture, unmodified."""

        return self._buffer.getvalue()

    def report(self) -> dict[str, Any] | None:
        """The complaint as a result-ready record, or ``None`` when the backend was quiet.

        Line structure is collapsed because the destination is a result field, not
        a terminal, and the character count is reported alongside so a bounded
        rendering states its own incompleteness rather than passing for the whole.
        """

        collapsed = " ".join(self.text.split())
        if not collapsed:
            return None
        return {
            "backend": self.backend,
            "stderr": collapsed[:_MAX_DETAIL_CHARS],
            "characters": len(collapsed),
            "truncated": len(collapsed) > _MAX_DETAIL_CHARS,
        }


@contextmanager
def capture_backend_stderr(backend: str) -> Iterator[BackendStderr]:
    """Route what ``backend`` writes to stderr inside this block into a handle.

    Scoped to the calling thread and to this block: a write from any other thread
    goes where it would have gone anyway, and the console is restored on the way
    out whether the backend returned or raised.  A capture left open would keep
    taking output that belongs to whatever ran next.
    """

    handle = BackendStderr(backend=backend)
    stack = getattr(_OPEN_CAPTURES, "stack", None)
    if stack is None:
        stack = []
        _OPEN_CAPTURES.stack = stack
    _install_router()
    try:
        stack.append(handle._buffer)
        try:
            yield handle
        finally:
            stack.pop()
    finally:
        _release_router()


__all__ = ["BackendStderr", "capture_backend_stderr"]
