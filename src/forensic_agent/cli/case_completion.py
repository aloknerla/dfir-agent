"""Closing a case: the files it writes, and what the record does not claim.

"Complete" is something the operator says, not something the system finds. A
case that closed without saying who closed it would leave every later reader to
assume the software decided the investigation was finished — which is exactly
the confusion this project exists to avoid. So the declaration is written out as
its own file, carrying the limits of the statement in its own fields, and the
panel repeats those limits on screen.

Kept apart from the session because it is the one operation that files a case
rather than reporting on it: every artifact shares one stem, the stem has to be
derived from a run identifier that reaches the filesystem and has to be free
before anything is written to it, and none of that is the session's business
beyond asking for it.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from forensic_agent.cli.host_display import display_path
from forensic_agent.cli.host_paths import export_destination
from forensic_agent.cli.i18n import t as _t
from forensic_agent.cli.session_exports import (
    oversight_companion_path,
    unique_destination,
)
from forensic_agent.cli.terminal import (
    DIM,
    GLYPH_OK,
    PANEL_BOX,
    RAISED_SURFACE,
    SUCCESS,
)
from forensic_agent.oversight.audit import REFUSAL_OUTCOMES, classify_action_outcome

#: Schema of the operator's completion declaration. Named a declaration
#: rather than a certificate because that is precisely its weight: a record
#: of what the operator said, carrying the limits of the statement in its
#: own fields so nothing downstream can read the file as an attestation.
CASE_COMPLETION_SCHEMA = "forensic.case-completion-declaration.v1"

#: Extensions the completion artifacts occupy, and which a requested
#: destination may therefore carry without meaning to name just one of them.
_COMPLETION_SUFFIXES = frozenset({".md", ".html", ".svg", ".json"})

#: Every file one completion writes on its stem, as the tails that follow it.
#: Stated once so the stem is checked for all of them together: a completion
#: that stepped around an existing markdown and then overwrote the diagram
#: beside it would have destroyed the earlier completion just the same.
COMPLETION_ARTIFACT_SUFFIXES: tuple[str, ...] = (
    ".md",
    ".oversight.md",
    ".html",
    ".svg",
    ".json",
)


def completion_destination(path, run_id: str, *, run_root: Path) -> Path:
    """Resolve the one free stem every completion artifact shares.

    A closed case is filed rather than merely written, so an operator who
    names the destination once should not have to name it once per file, nor
    guess which extension went where.

    The stem is also required to be unoccupied. Completing twice — the same
    case reopened, a first attempt that failed halfway, an operator naming the
    same destination again — used to write straight over the previous
    completion, and the file it destroyed was the record of somebody declaring
    a case finished. The next free ``-1``/``-2`` stem is taken instead, and it
    is taken for the whole family at once so the artifacts of one completion
    never end up split across two stems.
    """

    requested: str | None = None
    if path:
        candidate = Path(str(path))
        stem = (
            candidate.with_suffix("")
            if candidate.suffix.casefold() in _COMPLETION_SUFFIXES
            else candidate
        )
        requested = f"{stem}.md"
    # The run identifier reaches the filesystem here, so it is reduced to
    # characters a filename can hold rather than trusted to be one.
    safe_run = re.sub(r"[^A-Za-z0-9._-]", "", str(run_id))[:12] or "run"
    return unique_destination(
        export_destination(
            requested,
            default_name=f"case_completion_{safe_run}.md",
            run_root=run_root,
        ),
        companion_suffixes=COMPLETION_ARTIFACT_SUFFIXES,
    )


def completion_declaration(
    record: Mapping[str, Any],
    *,
    report: Path,
    diagram: Path,
    case_label: str,
    model: str,
    provider: str,
    engine: str,
    operation_mode: str,
) -> dict[str, Any]:
    """Record what the operator declared, and what the declaration is not."""

    calls = [call for call in record.get("calls", []) if isinstance(call, Mapping)]
    return {
        "schema_id": CASE_COMPLETION_SCHEMA,
        "declared_by": "operator",
        "declaration": (
            "The operator marked this case complete in the interactive console."
        ),
        # Spelled out in the record itself, not only in the console, because
        # the file outlives the session that wrote it and will be read by
        # someone who never saw the screen.
        "declaration_does_not_assert": (
            "Completion is a statement about the operator's own work. It is "
            "not a finding of the system, it does not verify the report, and "
            "it establishes nothing about what the evidence supports."
        ),
        "declared_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "case_label": case_label,
        "case_id": record.get("case_id"),
        "run_id": record.get("task_id"),
        "question": record.get("question"),
        "model": model,
        "provider": provider,
        "engine": engine,
        "operation_mode": operation_mode,
        "recorded_tool_calls": len(calls),
        # Counted by the outcome the run recorded for the call, through the one
        # function that names it. Reading `blocked` instead missed every
        # argument-gate refusal, which leaves `allowed` true and `blocked` false
        # because the policy denied nothing — the call was the wrong shape. The
        # forensic report counts by outcome, so a second reading of the same
        # record made the two artifacts state different numbers for one run.
        "blocked_tool_calls": sum(
            1 for call in calls if classify_action_outcome(call) in REFUSAL_OUTCOMES
        ),
        "artifacts": {
            "forensic_report": str(report),
            "investigation_diagram": str(diagram),
        },
    }


def write_completion_declaration(
    destination: Path,
    declaration: Mapping[str, Any],
) -> None:
    """Write the declaration as a file a later reader can compare byte for byte.

    Sorted keys, indentation and a closing newline are not cosmetic here: the
    record of what an operator declared about their own work is exactly the kind
    of file that gets diffed against another run's, and a serialisation that
    reorders itself between two writes turns that comparison into noise. It is
    written beside the function that builds the declaration so the format cannot
    be chosen differently by a second caller.
    """

    destination.write_text(
        json.dumps(declaration, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def completion_panel(
    report: Path,
    diagram: Path,
    declaration: Path,
    *,
    html: Path | None = None,
    width: int,
) -> Panel:
    """Name what the completion actually wrote, and say what each file is for.

    Two things had to be true of this list and were not. The first is that a
    row must correspond to a file: every path is checked on disk, so a step
    that did not run cannot leave a filename on screen for an operator to hunt
    for. The second is that the list must not read as four reports. It is one
    report — the markdown covering every exchange in the case — plus a
    rendering of it, a reconstruction of the oversight decisions behind it, a
    drawing of the run, and a machine record of the declaration. The sentence
    above the table says which is which, because a column of similar filenames
    on one stem says nothing.

    The directory is stated once and the files by name, so a long export path
    cannot wrap through the middle of the filename the operator has to find on
    disk, and it is stated as a path they can actually open: inside a container
    ``/runtime/exports`` is a mount point, not a directory on their machine.
    """

    files = Table(box=None, show_header=False, pad_edge=False, padding=(0, 2, 0, 0))
    files.add_column(style=DIM, no_wrap=True)
    files.add_column(overflow="fold")
    for label, artifact in (
        (_t("Forensic report"), report),
        (_t("Report as a web page"), html),
        (_t("Oversight report"), oversight_companion_path(report)),
        (_t("Investigation diagram"), diagram),
        (_t("Completion record"), declaration),
    ):
        if artifact is not None and artifact.is_file():
            files.add_row(label, artifact.name)
    body = Group(
        Text(
            _t(
                "Marking a case complete is the operator's statement about "
                "their own work. It is not a finding of the system and "
                "establishes nothing about the evidence."
            ),
            style=DIM,
        ),
        Text(""),
        Text.assemble(
            (f"{_t('written to')}  ", DIM), (display_path(report.parent), "")
        ),
        Text(""),
        Text(
            _t(
                "There is one report here. The forensic report covers every "
                "exchange in this case; the files beside it are the same "
                "report as a page a browser can open, the reconstruction of "
                "the oversight decisions, the diagram of the closing run, and "
                "the machine record of this declaration."
            ),
            style=DIM,
        ),
        Text(""),
        files,
    )
    return Panel(
        body,
        title=f"[bold]{GLYPH_OK} {_t('Case marked complete')}[/]",
        title_align="left",
        border_style=SUCCESS,
        box=PANEL_BOX,
        style=RAISED_SURFACE,
        padding=(1, 2),
        width=width,
    )
