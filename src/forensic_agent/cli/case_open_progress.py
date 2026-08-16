"""The live display that opening a forensic case runs behind.

One rule holds this module together, and it has three carriers: a bar may be
filled only against a total the attestation itself has stated. The two columns
enforce it by rendering nothing until that total arrives, and the observers this
module hands back to the caller are what make it arrive. Separated, one carrier
can be changed without the other two, and the display goes back to filling a bar
against the size of the container file on disk — which is how it once ran past
its own end on a compressed EWF source, whose decoded logical media is several
times the bytes the console can see in the directory.

This is also the one console view that must be replaceable from outside. The
tests that prove the bar never overstates the work it measures do so by
substituting Rich's :class:`~rich.progress.Progress` on the module that builds
the display, so building it here rather than on the session keeps that
substitution to the display alone, and lets those tests drive it without opening
a case.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

from rich.console import Console
from rich.filesize import decimal as _decimal_size
from rich.markup import escape
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    SpinnerColumn,
    Task,
    TaskID,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.text import Text

from forensic_agent.cli.i18n import t as _t
from forensic_agent.cli.terminal import ACCENT, BORDER, DIM, SUCCESS

# ---- one step that moves bytes, one that never does ------------------------
# Rich applies one column set to every row of a progress display, but the two
# steps of opening a case are not comparable: the digest moves bytes, while the
# dfVFS resolution moves none and finishes when it finishes. These two columns
# therefore render only for a byte-moving step, so the other one is left as a
# spinner and its name rather than as a bar that pretends to advance beside a
# byte counter frozen at zero.
_BYTE_STEP_FIELD = "moves_bytes"

#: What the case-opening display hands to the caller: the observer that advances
#: the bar, and the one through which the attestation states its total.
OpeningWatcher = tuple[Callable[[int], None], Callable[[int], None]]


class _ByteStepBarColumn(BarColumn):
    """A bar for a byte-moving step, and only once its total has been stated.

    A bar is a claim about how much work is left, so it must not be drawn until
    the attestation has said how far it has to go. Until then the row is a
    spinner and a byte count: "not known yet" is honest, whereas a bar filled
    against a size the console guessed is not — and that guess is exactly what
    once let this display run past its own end on a compressed EWF source.
    """

    def render(self, task: Task) -> Any:
        if not task.fields.get(_BYTE_STEP_FIELD) or task.total is None:
            return Text("")
        return super().render(task)


class _ByteStepBytesColumn(DownloadColumn):
    """Processed/total bytes only for a step that actually streams evidence."""

    def render(self, task: Task) -> Text:
        if not task.fields.get(_BYTE_STEP_FIELD):
            return Text("")
        return super().render(task)


@contextmanager
def case_opening_progress(
    console: Console,
    resolved: str,
) -> Iterator[OpeningWatcher | None]:
    """Show what opening a case is doing, without changing what it does.

    Binding evidence identity streams the entire medium through SHA-256, and
    on real evidence that runs for minutes; a console that said nothing at all
    would read as a hang, and get interrupted. So the two steps are shown as
    they are: the digest can be measured, and the dfVFS
    partition and file-system resolution that follows it cannot, so that one
    is a spinner with its name and elapsed time. Nothing here is consulted by
    the open itself; the display only watches.

    What the digest is measured *against* comes from the attestation, never
    from this side. The console can see only the file it was handed, and
    that file is not the work: a compressed EWF container decodes to far more
    logical media than it holds, and a split source continues into segments
    this path never named. So the row starts without a total, and adopts the
    one the pass states before its first block.

    A live region needs a terminal to live in. When the console writes to a
    file, a pipe, or a captured stream there is nothing to animate, so no
    display is built and the caller is told to open the case exactly the way
    it was opened before.
    """

    if not getattr(console, "is_terminal", False):
        yield None
        return

    source_label = os.path.basename(resolved) or resolved
    display = Progress(
        SpinnerColumn(style=ACCENT),
        TextColumn("{task.description}", style=DIM),
        _ByteStepBarColumn(
            bar_width=24,
            style=BORDER,
            complete_style=SUCCESS,
            finished_style=SUCCESS,
        ),
        TaskProgressColumn(),
        _ByteStepBytesColumn(),
        TimeRemainingColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )
    # The file name sits beside the bar so the reason this step is slow is
    # visible without asking; the size joins it once the pass has stated
    # one. The name is an identifier and is never translated.
    digest_description = f"{_t('evidence digest')}: {escape(source_label)}"
    digest_step = display.add_task(
        digest_description,
        total=None,
        **{_BYTE_STEP_FIELD: True},
    )
    resolution_step: TaskID | None = None
    expected_bytes: int | None = None
    hashed_bytes = 0
    display_usable = True

    def _guarded(action: Callable[[int], None]) -> Callable[[int], None]:
        """Wrap one observer so a broken display can only stop itself.

        The display watches the step that binds custody, so it is never
        allowed to be the reason that step fails. A console that breaks
        under us gives up its own animation and nothing else.
        """

        def observe(byte_count: int) -> None:
            nonlocal display_usable

            if not display_usable:
                return
            try:
                action(byte_count)
            except Exception:
                display_usable = False

        return observe

    def _start_resolution_when_the_digest_is_done() -> None:
        nonlocal resolution_step

        if resolution_step is not None or expected_bytes is None:
            return
        if hashed_bytes < expected_bytes:
            return
        resolution_step = display.add_task(
            _t("partition and file system resolution"),
            total=None,
            **{_BYTE_STEP_FIELD: False},
        )

    def _declare_total(byte_count: int) -> None:
        nonlocal expected_bytes

        # The pass has resolved its source and can now say how much it will
        # read. This is the only number the bar is ever filled against.
        expected_bytes = byte_count
        display.update(
            digest_step,
            total=byte_count,
            description=f"{digest_description}, {_decimal_size(byte_count)}",
        )
        _start_resolution_when_the_digest_is_done()

    def _advance(byte_count: int) -> None:
        nonlocal hashed_bytes

        hashed_bytes += byte_count
        display.update(digest_step, completed=hashed_bytes)
        _start_resolution_when_the_digest_is_done()

    display.start()
    try:
        yield _guarded(_advance), _guarded(_declare_total)
    finally:
        # Explicitly torn down before anything else can print: an error
        # message written underneath a live region is repainted over, and
        # the operator would be left with a hidden reason for the failure.
        display.stop()
