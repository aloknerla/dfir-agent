"""Operator-facing progress for operations that take long enough to look hung.

Opening a case now scans the evidence before the first question is asked, and a
scan of a multi-gigabyte image takes minutes. Without a visible signal that work
is happening, a console that is working correctly is indistinguishable from one
that has stopped, and the operator's only recourse is to interrupt it.

Two properties are load-bearing:

* **Nothing reported here reaches the model or a receipt.** Progress describes
  how far a local process has got, which depends on the host's speed and on when
  the operator happened to look. Letting that into the transcript would put
  ambient non-determinism inside the record a run claims is reproducible.
* **Reporting never fails the work it reports on.** A terminal that cannot render
  a bar, a redirected stream, a closed pipe: each of those is a reason to fall
  silent, never a reason to abandon a scan the operator is waiting for.

The renderer is chosen from the stream, not configured: an attached terminal gets
a live line that rewrites itself, and a redirected stream gets periodic plain
lines instead, so a batch log records that work advanced without filling with
thousands of redraws.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Protocol

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)

#: Seconds between plain-text updates when the stream is not a terminal. A batch
#: transcript should show that a long scan advanced without carrying a line for
#: every percent of it.
_PLAIN_INTERVAL_SECONDS = 15.0


class ProgressSink(Protocol):
    """What a long operation calls to report how far it has got.

    ``fraction`` is between 0 and 1 where the operation can estimate it, and
    ``None`` where it cannot: an operation that only knows it is still running
    reports that honestly rather than inventing a percentage.
    """

    def __call__(self, fraction: float | None = None, detail: str | None = None) -> None:
        ...


def _noop(fraction: float | None = None, detail: str | None = None) -> None:
    """The sink used when progress is switched off, so callers need no branch."""


#: How often a digest that is reporting says where it is. Fast enough that a
#: front end redrawing on its own frame clock never shows a stale byte count,
#: slow enough that a multi-gigabyte read is not a stream of cross-thread calls.
_DIGEST_INTERVAL_SECONDS = 0.1

#: The read size a reporting digest works in. The same block the plain digest
#: uses, so the two differ in what they say and never in what they read.
_DIGEST_BLOCK_BYTES = 1 << 20


def sha256_file_reporting(
    path: str,
    *,
    report: ProgressSink | None = None,
    detail: str | None = None,
) -> str:
    """The SHA-256 of one file, saying how far it has got while it computes it.

    Hashing a memory image is one of the three steps of opening a case that run
    for minutes, and it was the one with nothing to watch: the plain digest is a
    single call that returns when the whole file has been read, so a console
    could announce that hashing had started and then say nothing until it ended.
    An operator cannot tell that from a hang, which is the whole complaint.

    With no observer this IS the plain digest, called by name rather than
    reimplemented beside it: a host with a faster implementation, and every test
    that substitutes one, must keep working through this path unchanged. With an
    observer it is the same bytes through the same algorithm, read in blocks so
    the fraction it reports is measured rather than guessed, and throttled so a
    front end is told where the read is without being told thousands of times.

    ``detail`` names the step for the whole read, so the observer can say WHICH
    of a case's long steps is running instead of showing an anonymous bar.
    """

    if report is None:
        # Imported at call time so a substituted digest is honoured: the plain
        # read must stay exactly the call every other caller already makes.
        from forensic_agent.core.audit import sha256_file

        return sha256_file(path)

    import hashlib
    import os
    from time import monotonic

    try:
        total: int | None = os.path.getsize(path)
    except OSError:
        # A size the platform will not state is a reason to report elapsed
        # progress without a fraction, never a reason to refuse the digest.
        total = None
    digest = hashlib.sha256()
    read = 0
    last = float("-inf")
    with open(path, "rb") as handle:
        while True:
            block = handle.read(_DIGEST_BLOCK_BYTES)
            if not block:
                break
            digest.update(block)
            read += len(block)
            now = monotonic()
            if now - last < _DIGEST_INTERVAL_SECONDS:
                continue
            last = now
            # A display that breaks under a digest must not take the digest
            # with it: the evidence is the work, the bar is only the report.
            try:
                report(read / total if total else None, detail)
            except Exception:
                pass
    return digest.hexdigest()


class _PlainSink:
    """Periodic one-line updates for a stream no cursor can be moved on."""

    def __init__(self, console: Console, label: str, clock: Callable[[], float]) -> None:
        self._console = console
        self._label = label
        self._clock = clock
        # The first report always prints: a scan that has just started is exactly
        # when the operator most needs to see that it did.
        self._last = float("-inf")

    def __call__(self, fraction: float | None = None, detail: str | None = None) -> None:
        now = self._clock()
        if now - self._last < _PLAIN_INTERVAL_SECONDS:
            return
        self._last = now
        percent = f" {fraction * 100:.0f}%" if fraction is not None else ""
        suffix = f" — {detail}" if detail else ""
        self._console.print(f"{self._label}{percent}{suffix}")


@contextmanager
def reporting(
    console: Console,
    label: str,
    *,
    enabled: bool = True,
    clock: Callable[[], float] | None = None,
) -> Iterator[ProgressSink]:
    """Yield the sink a long operation reports through, for the length of it.

    The sink is safe to call from the thread doing the work and safe to ignore:
    an operation that reports nothing simply shows an unmoving spinner rather
    than failing.
    """

    if not enabled:
        yield _noop
        return

    if not console.is_terminal:
        from time import monotonic

        console.print(f"{label} …")
        yield _PlainSink(console, label, clock or monotonic)
        console.print(f"{label} — done")
        return

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )
    task_id = None
    try:
        progress.start()
        task_id = progress.add_task(label, total=100)

        def sink(fraction: float | None = None, detail: str | None = None) -> None:
            # A renderer that has already been torn down, or a terminal that
            # disappeared mid-scan, must not take the scan down with it.
            try:
                description = f"{label} — {detail}" if detail else label
                if fraction is None:
                    progress.update(task_id, description=description)
                else:
                    completed = max(0.0, min(1.0, fraction)) * 100
                    progress.update(task_id, completed=completed, description=description)
            except Exception:
                return

        yield sink
    finally:
        try:
            progress.stop()
        except Exception:
            pass
