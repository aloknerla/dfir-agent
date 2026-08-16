"""Restating a finished investigation for a reader who was never at the console.

``/export`` and ``/trace`` produce the two files that leave the console: the
forensic report a reader outside the session can follow, and the drawing of what
actually ran to produce it. Both are the same shape of operation — take what the
last run recorded, write a file, and say where it went — and neither is a
question about the session's state. Once the answer is on screen the facts these
functions restate cannot change, which is what makes them checkable as functions
of those facts rather than as methods that reach for them.

The report is written here rather than at the call site for one specific reason:
it is not one file but two. An oversight companion lands beside it under a name
derived from the report's own, and that derivation has to happen wherever the
report is written or the pair silently comes apart — the reader gets a report
whose companion is somewhere else, or is missing, and nothing says so. Keeping
the pair in one function makes the second file impossible to forget.

Every path these functions say out loud goes through
:func:`forensic_agent.cli.host_display.display_path` first, and every path they
write to stays exactly as it was. Inside the container the exports land in
``/runtime/exports``, which is a mount point rather than a directory on the
operator's machine, so a function that prints back the path it just wrote to is
telling a person to open something that does not exist for them. The
translation is presentation and nothing else: the file went where the caller
sent it, and the records beside it store that path unchanged.

:mod:`forensic_agent.cli.case_completion` is the neighbouring module for the
artifacts ``/complete`` files. The split between them is the operator's
intent rather than the file format: exporting says "give me this to read", and
completing says "I am finished", which is a claim that has to be recorded as one.
"""

from __future__ import annotations

import itertools
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console
from rich.text import Text

from forensic_agent.cli.host_display import display_path
from forensic_agent.cli.terminal import DIM, GLYPH_OK, SUCCESS, glyphed_line


def _saved_line(label: str, note: str, path: str | Path) -> Text:
    """What one written file says: what it is, and where it went.

    The path is the longest thing on the line and is the part that wraps, so
    the three announcements below hand this to ``glyphed_line`` rather than
    printing a single string: a path that wrapped back to column zero read as a
    second, pathless message, and the glyph that said the write succeeded was
    left standing over only the first half of it.
    """

    body = Text(label, style=SUCCESS)
    if note:
        body.append(f" {note}", style=DIM)
    body.append(f" {display_path(path)}", style=DIM)
    return body

if TYPE_CHECKING:
    from forensic_agent.cli.controlled import ControlledRun


def oversight_companion_path(report: Path) -> Path:
    """The name the oversight companion takes beside a written report.

    The companion's name is derived from the report's own, and that derivation
    is stated once here so every writer and every reader of the pair names the
    second file the same way. A copy of this rule elsewhere is how a report and
    its companion silently come apart.
    """

    return report.with_name(f"{report.stem}.oversight.md")


def unique_destination(
    destination: Path,
    *,
    companion_suffixes: Sequence[str] = (),
) -> Path:
    """The destination itself, or its first ``-1``/``-2``… sibling not yet taken.

    An export must never destroy a previous export: the default name already
    carries a timestamp, so two files can collide only within one second, and
    the suffix settles exactly that case. The companion derives its name from
    the stem returned here, so the pair stays unique together.

    ``companion_suffixes`` names the other files that will be written on the
    returned stem — ``.svg``, ``.json``, ``.oversight.md`` and so on. A stem is
    free only when none of them is taken either, because a write that avoids
    clobbering the markdown and then clobbers the diagram beside it has moved
    the loss rather than prevented it. It defaults to empty, which is the
    single-file case and behaves exactly as before.
    """

    suffixes = (destination.suffix, *companion_suffixes)

    def taken(candidate: Path) -> bool:
        return any(
            candidate.with_name(f"{candidate.stem}{suffix}").exists()
            for suffix in suffixes
        )

    if not taken(destination):
        return destination
    for attempt in itertools.count(1):
        candidate = destination.with_name(
            f"{destination.stem}-{attempt}{destination.suffix}"
        )
        if not taken(candidate):
            return candidate
    raise AssertionError("unreachable")  # pragma: no cover - count() never ends


def write_case_report(
    console: Console,
    destination: Path,
    *,
    markdown: str,
    oversight_markdown: str,
    questions: int,
    announce: bool,
) -> None:
    """Write the whole-case report, and the oversight companion beside it.

    The companion holds one reconstruction per exported question and is
    written only when at least one question recorded an oversight chain — an
    empty companion would read as a case that was supervised and found nothing
    to say.
    """

    from forensic_agent.reporting import markdown as _report

    fp = _report.write_report(destination, markdown)
    if announce:
        # The count precedes the path rather than trailing it: inside a
        # container with no host root stated, display_path appends its own
        # parenthetical, and two parentheticals in a row read as one aside
        # about the other.
        console.print(
            glyphed_line(
                GLYPH_OK,
                SUCCESS,
                _saved_line(
                    "Case report saved", f"({questions} recorded questions):", fp
                ),
            )
        )
    if oversight_markdown:
        bpath = oversight_companion_path(destination)
        bfp = _report.write_report(bpath, oversight_markdown)
        if announce:
            console.print(
                glyphed_line(
                    GLYPH_OK, SUCCESS, _saved_line("Oversight report:", "", bfp)
                )
            )


def write_forensic_report(
    console: Console,
    destination: Path,
    *,
    question: str | None,
    report: str,
    tool_calls: list[dict[str, object]],
    model: str,
    engine: str,
    operation_mode: str,
    disk_label: str,
    oversight_path: str | None,
    findings: list[dict[str, object]] | None = None,
    announce: bool,
) -> None:
    """Write the standard report, and the oversight companion that belongs beside it.

    The companion is written only when the run recorded an oversight chain to
    reconstruct, because an empty companion would read as an investigation that
    was supervised and found nothing to say.

    ``findings`` carries the standardized rows, which are the only place the
    epistemic class of each reading survives: the oversight action rows say what
    was called, not whether what came back was an upstream observation or this
    project's own composition. Without them the report says so in place of the
    observation-and-interpretation split rather than presenting one it cannot
    support.
    """

    from forensic_agent.reporting import markdown as _report

    md = _report.build_standard_markdown(
        question,
        report,
        tool_calls,
        model=model,
        engine=engine,
        operation_mode=operation_mode,
        disk_label=disk_label,
        findings=findings,
    )
    fp = _report.write_report(destination, md)
    if announce:
        # Count before path, as in write_case_report and for the same reason.
        console.print(
            glyphed_line(
                GLYPH_OK,
                SUCCESS,
                _saved_line(
                    "Report saved", f"({len(tool_calls)} recorded tool calls):", fp
                ),
            )
        )
    from forensic_agent.oversight import OversightLog, reconstruct

    entries = OversightLog.load(oversight_path) if oversight_path else []
    if entries:
        bpath = oversight_companion_path(destination)
        bmd = _report.build_oversight_markdown(reconstruct(entries), model=model)
        bfp = _report.write_report(bpath, bmd)
        if announce:
            console.print(
                glyphed_line(
                    GLYPH_OK, SUCCESS, _saved_line("Oversight report:", "", bfp)
                )
            )


def write_execution_trace(
    console: Console,
    destination: Path,
    *,
    run: ControlledRun,
    question: str,
    model: str,
    provider: str,
) -> None:
    """Draw what the run executed, and name the file it was drawn into."""

    from forensic_agent.reporting.trace_svg import (
        controlled_run_trace_record,
        export_trace_svg,
    )

    record = controlled_run_trace_record(
        run,
        question=question,
        model=model,
        provider=provider,
    )
    output = export_trace_svg(record, destination)
    console.print(
        glyphed_line(
            GLYPH_OK, SUCCESS, _saved_line("Execution trace saved:", "", output)
        )
    )
