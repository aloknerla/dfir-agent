"""The three panels that describe a finished run: findings, summary, controls.

Two of them print under every answer and one is asked for by name, but they are
written together because they must not disagree. The same status appears in the
compact strip below an answer and in the detailed ``/findings`` view, and if
"blocked" were amber in one and red in the other the operator would reasonably
read them as two different states of two different things. One status vocabulary
therefore serves all of them, declared here beside its users.

The panels are built from the projections in
:mod:`forensic_agent.cli.presentation` and add nothing to them: no value shown
here is derived from the evidence a second time, and none of these views can
reach the evidence at all. They describe the reading; the reading itself stays
in the run record.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rich.console import Group
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from forensic_agent.cli.i18n import t as _t
from forensic_agent.cli.oversight_view import (
    call_arguments_cell,
    outcome_text,
    run_bound_entries,
)
from forensic_agent.cli.presentation import (
    ExecutedCall,
    FindingDetail,
    PageFacts,
    executed_calls,
    summarize_controls,
    summarize_findings,
)
from forensic_agent.cli.terminal import (
    ACCENT,
    BORDER,
    DIM,
    GLYPH_ERROR,
    GLYPH_OK,
    GLYPH_POINT,
    GLYPH_UNKNOWN,
    GLYPH_WARN,
    ORANGE,
    PANEL_BOX,
    RED,
    SUCCESS,
)
from forensic_agent.core.durations import format_duration

if TYPE_CHECKING:
    from collections.abc import Sequence

#: One status vocabulary for every finding projection: a single-cell glyph and
#: the colour that carries the same meaning wherever a status appears, so the
#: evidence summary and the detailed /findings view never disagree on how "ok"
#: or "blocked" reads.
STATUS_GLYPH: dict[str, tuple[str, str]] = {
    "ok": (GLYPH_OK, SUCCESS),
    "partial": (GLYPH_WARN, ORANGE),
    "error": (GLYPH_ERROR, RED),
    "blocked": (GLYPH_ERROR, RED),
    "unknown": (GLYPH_UNKNOWN, DIM),
}

#: What one shortened receipt occupies: twelve hexadecimal characters and the
#: elision mark that says the digest continues. The value never varies, so this
#: is one of the few columns a fixed width is honest about — the previous
#: twenty-two reserved nine cells no row could ever fill, and the tool name and
#: the finding type beside it were elided at eighty columns to pay for them.
_EVIDENCE_ID_WIDTH = 13
#: The algorithm, on the header's second line. Below the shortened digest it
#: would not fit on one line, and a header wide enough for it is a header the
#: rows pay for; it is an identifier, so it is not translated.
_SHA256_UNIT = "(SHA-256)"


def _add_evidence_id_column(table: Table) -> None:
    """Add the receipt column both findings views must present identically."""

    table.add_column(
        f"{_t('Evidence ID')}\n{_SHA256_UNIT}",
        width=_EVIDENCE_ID_WIDTH,
        no_wrap=True,
    )


def findings_panel(
    findings: Sequence[dict[str, object]],
    *,
    width: int,
) -> Panel:
    projection = summarize_findings(findings)
    table = Table(
        expand=True,
        show_edge=False,
        show_lines=False,
        header_style=f"bold {ACCENT}",
        padding=(0, 1),
    )
    table.add_column(_t("# / Tool"), min_width=14, max_width=25)
    table.add_column(_t("Finding type"), min_width=16, max_width=30)
    table.add_column(_t("Status"), min_width=17, max_width=24)
    # Same label as the evidence summary: one value shown in two views must
    # not arrive under two names, or the operator reads them as two things.
    _add_evidence_id_column(table)

    for finding in projection.rows:
        glyph, color = STATUS_GLYPH[finding.status]
        state = (
            f"[{color}]{glyph} {finding.status.upper()}[/]"
            f", {escape(str(finding.records))}\n"
            f"{escape(str(finding.coverage))}"
        )
        if finding.notes != "—":
            state += f"\n[{DIM}]{escape(str(finding.notes))}[/]"
        table.add_row(
            f"{finding.sequence:02d}  {escape(str(finding.tool))}",
            escape(str(finding.data_type)),
            state,
            escape(str(finding.receipt)),
        )

    if not projection.rows:
        table.add_row("—", _t("No findings"), "—", "—")

    notes: list[Text] = []
    if projection.omitted:
        notes.append(
            Text(
                f"{projection.omitted} more findings are not shown.",
                style=DIM,
            )
        )
    # Said in the words an operator already has: "receipt-bound metadata"
    # and "private execution trace" name internals, and a reader who does not
    # already know them learns nothing from the sentence meant to reassure.
    notes.append(
        Text(
            _t(
                "This view lists findings and the SHA-256 each was recorded "
                "under. The evidence content itself is not shown here."
            ),
            style=DIM,
        )
    )
    # A blank line marks the footnote as commentary; pressed against the last
    # row it reads as one more row of data.
    content: list[Table | Text] = [table, Text(""), *notes]
    return Panel(
        Group(*content),
        title=f"[bold]{GLYPH_POINT} {_t('Findings')}[/]",
        title_align="left",
        border_style=ACCENT,
        box=PANEL_BOX,
        padding=(0, 1),
        width=width,
    )


def recorded_call_for(
    detail: FindingDetail,
    *,
    oversight_path: str | None,
) -> ExecutedCall | None:
    """The recorded call that produced one finding, or ``None`` if unbound.

    A finding names the oversight entry it was standardized from, so the
    arguments the model passed are read from that entry rather than
    re-derived: the detail view must show the call the record holds, not a
    reconstruction of it. A result whose capture was cut short carries no
    such binding by design, and then no call is claimed.
    """

    if detail.oversight_sequence is None:
        return None
    entries = run_bound_entries(oversight_path)
    if entries is None:
        return None
    for call in executed_calls(entries):
        if call.sequence == detail.oversight_sequence:
            return call
    return None


def _two_line_cell(first: str, second: str) -> Text:
    """Two recorded values on their own lines, or the absence mark for neither.

    On separate lines rather than joined: an id and a URI are matched against
    the run record separately, and a joined pair wraps in the middle of
    whichever one is longer.
    """

    if not first and not second:
        return Text("—", style=DIM)
    cell = Text()
    if first:
        cell.append(first)
    if second:
        if first:
            cell.append("\n")
        cell.append(second, style=DIM if first else "")
    return cell


def _page_cell(page: PageFacts) -> Text | None:
    """The typed page record as recorded facts, or ``None`` when it holds none."""

    parts: list[str] = []
    if page.returned is not None:
        parts.append(f"{_t('returned')} {page.returned}")
    if page.total is not None:
        parts.append(f"{_t('total')} {page.total}")
    if page.truncated is not None:
        parts.append(_t("truncated") if page.truncated else _t("not truncated"))
    if page.next_offset is not None:
        parts.append(f"{_t('next offset')} {page.next_offset}")
    if page.unit:
        # The unit is an identifier of the result contract, never translated.
        parts.append(f"{_t('unit')} {page.unit}")
    return Text(", ".join(parts)) if parts else None


def _warnings_cell(detail: FindingDetail) -> Text:
    """Each warning as its code and, where recorded, its full message.

    The message is the tool's own statement of the bound it hit, printed whole:
    this detail is the operator's review surface, and a code alone cannot say
    how to continue a capped reading.
    """

    cell = Text()
    for index, code in enumerate(detail.warnings):
        if index:
            cell.append("\n")
        cell.append(code)
        message = (
            detail.warning_messages[index]
            if index < len(detail.warning_messages)
            else ""
        )
        if message:
            cell.append(": ", style=DIM)
            cell.append(message)
    return cell


def finding_detail_panel(
    detail: FindingDetail,
    call: ExecutedCall | None,
    *,
    width: int,
) -> Panel:
    """One finding in full: the call, what came back, where it was read from,
    and what binds it."""

    summary = detail.summary
    grid = Table.grid(padding=(0, 2))
    grid.add_column(justify="right", style=DIM, no_wrap=True)
    grid.add_column(overflow="fold")
    # Labels are operator chrome. The function, the operation, the argument
    # names and values, the data type and the digest are the record itself
    # and stay byte-identical in either language.
    grid.add_row(_t("function"), Text(summary.tool))
    grid.add_row(
        _t("operation"),
        Text(call.operation) if call and call.operation else Text("—", style=DIM),
    )
    grid.add_row(
        _t("arguments"),
        call_arguments_cell(call.arguments) if call else Text("—", style=DIM),
    )
    glyph, colour = STATUS_GLYPH[summary.status]
    grid.add_row(
        _t("result"),
        Text.from_markup(
            f"[{colour}]{glyph} {escape(summary.status.upper())}[/], "
            f"{escape(summary.records)}, {escape(summary.data_type)}"
        ),
    )
    # The record's own account of what the reading IS and where it came from.
    # The class name, the source id and URI, the locator and the component
    # versions are the record itself; only the absence sentence is chrome.
    grid.add_row(
        _t("classification"),
        Text(detail.evidence_class)
        if detail.evidence_class
        else Text(_t("class not established by the record"), style=DIM),
    )
    grid.add_row(_t("evidence source"), _two_line_cell(detail.source_id, detail.source_uri))
    grid.add_row(
        _t("artifact"), _two_line_cell(detail.artifact_type, detail.artifact_locator)
    )
    if detail.producers:
        grid.add_row(_t("producers"), Text("\n".join(detail.producers)))
    page_cell = _page_cell(detail.page)
    if page_cell is not None:
        grid.add_row(_t("page"), page_cell)
    grid.add_row(_t("coverage"), Text(summary.coverage))
    if detail.coverage.scope:
        grid.add_row(_t("coverage scope"), Text(detail.coverage.scope))
    if detail.coverage.reason:
        grid.add_row(_t("coverage reason"), Text(detail.coverage.reason))
    if summary.notes != "—":
        grid.add_row(_t("notes"), Text(summary.notes))
    if detail.warnings:
        grid.add_row(_t("warnings"), _warnings_cell(detail))
    if detail.error:
        grid.add_row(_t("declared error"), Text(detail.error, style=RED))
    # Whole, not shortened: this is the value an operator matches against
    # the run record, and half of a digest matches nothing.
    grid.add_row(_t("SHA-256 receipt"), Text(detail.receipt))
    if call is not None:
        # Two different facts, so both are stated: the row above is the status
        # the RESULT declares, this is what the record says became of the CALL.
        # Reading only the first left a call the oversight gate refused
        # described here as an ERROR, in a word no other view used for it.
        grid.add_row(_t("recorded outcome"), outcome_text(call.outcome))
        grid.add_row(
            _t("oversight entry"),
            Text(f"#{call.sequence}", style=DIM),
        )
    body = Group(
        grid,
        Text(""),
        Text(
            _t(
                "This view describes the reading. The evidence content "
                "itself is not shown here."
            ),
            style=DIM,
        ),
    )
    return Panel(
        body,
        title=(
            f"[bold]{GLYPH_POINT} {_t('Finding')} "
            f"{summary.sequence:02d}: {escape(summary.tool)}[/]"
        ),
        title_align="left",
        border_style=ACCENT,
        box=PANEL_BOX,
        padding=(0, 1),
        width=width,
    )


def evidence_summary_panel(
    findings: Sequence[dict[str, object]],
    *,
    width: int,
) -> Panel:
    """Return a compact default view of the collected forensic findings."""

    projection = summarize_findings(findings)
    table = Table(
        expand=True,
        show_edge=False,
        show_header=True,
        show_lines=False,
        # Dim, not accented: this table prints under every answer, and an
        # accented header row here put a second bright element on screen
        # for the eye to land on. The accent is spent on the exchange
        # heading and the answer; the audit strip below them recedes.
        header_style=f"bold {DIM}",
        padding=(0, 1),
    )
    # Four cells wide, because that is what the cell holds: a status glyph, a
    # space and the two-digit id. Declared as three, it cropped the id itself
    # to an ellipsis at eighty columns — and the id is what /findings <id>
    # takes, so the row stopped naming the thing it exists to be looked up by.
    table.add_column("#", no_wrap=True)
    table.add_column(_t("Function"), min_width=18, max_width=30)
    table.add_column(_t("Result"), min_width=18, max_width=34)
    # "SHA-256 receipt" named the mechanism, not the thing: operators read it
    # as a payment slip. The header now says what the value identifies and
    # keeps the algorithm for a reader who checks it by hand.
    _add_evidence_id_column(table)

    for finding in projection.rows:
        icon, color = STATUS_GLYPH[finding.status]
        result = f"{finding.records}, {finding.coverage}"
        if finding.notes != "—":
            result += f"\n[{DIM}]{escape(str(finding.notes))}[/]"
        table.add_row(
            f"[{color}]{icon}[/] {finding.sequence:02d}",
            escape(str(finding.tool)),
            result,
            escape(str(finding.receipt)),
        )

    if not projection.rows:
        table.add_row("—", _t("No findings"), "—", "—")

    notes: list[Text] = []
    if projection.omitted:
        notes.append(
            Text(
                f"{projection.omitted} additional finding(s); use /findings.",
                style=DIM,
            )
        )
    # The header names the value; this says what the operator does with it,
    # which is the part that was missing and left the column looking decorative.
    notes.append(
        Text(
            _t(
                "The evidence ID links a row to the exact stored result, "
                "and changes if that result is altered."
            ),
            style=DIM,
        )
    )
    content: list[Table | Text] = [table, Text(""), *notes]
    # A supporting panel: quiet border, no fill, and — since three equally
    # bold titles gave the eye three places to land where it needs one — an
    # unbold title in the quiet neutral. Only the answer is titled boldly.
    return Panel(
        Group(*content),
        title=f"[{DIM}]{GLYPH_POINT} {_t('Evidence summary')}[/]",
        title_align="left",
        border_style=BORDER,
        box=PANEL_BOX,
        padding=(0, 1),
        width=width,
    )


def run_summary_panel(
    run: Any,
    *,
    elapsed_s: float,
    tool_calls: int,
    findings: int,
    width: int,
) -> Panel:
    summary = summarize_controls(
        run.telemetry,
        run_id=run.run_id,
        tool_calls=tool_calls,
        findings=findings,
    )
    table = Table.grid(padding=(0, 2))
    table.add_column(justify="right", no_wrap=True, style=DIM)
    table.add_column()
    # The colour and glyph decisions key off the original English status, not
    # the rendered one, so a translated label never changes the signalling.
    verified = summary.verification == "completed"
    verification_color = SUCCESS if verified else ORANGE
    verification_glyph = GLYPH_OK if verified else GLYPH_WARN
    table.add_row(
        _t("final verification"),
        f"[{verification_color}]{verification_glyph} "
        f"{_t(summary.verification)}[/]",
    )
    table.add_row(_t("answer source"), escape(_t(summary.answer_source)))
    # "no accepted answer" is the one verdict that names no cause. The contract
    # reached it from three recorded outcomes, and which of them deviated decides
    # the repair: a run whose verifier refused the draft and one whose verifier
    # passed it and was then refused at publication read identically here, and
    # need opposite fixes. The values are shown rather than the conclusion alone.
    if summary.unaccepted_outcome is not None:
        source, verification_outcome, publication = summary.unaccepted_outcome
        table.add_row(
            "",
            f"[{DIM}]{escape(_t('accepted source'))}: {escape(source)}, "
            f"{escape(_t('verification'))}: {escape(verification_outcome)}, "
            f"{escape(_t('publication'))}: {escape(publication)}[/]",
        )
    model_requests = (
        str(summary.model_requests) if summary.model_requests is not None else "—"
    )
    table.add_row(
        _t("activity"),
        (
            f"{summary.tool_calls} {_t('tool calls')}, "
            f"{summary.findings} {_t('findings')}, "
            f"{model_requests} {_t('model requests')}, {format_duration(elapsed_s)}"
        ),
    )
    table.add_row(_t("trace id"), summary.trace_id)
    # Paired with the evidence summary: same quiet border, no fill, same
    # unbold title. Together they read as the audit strip below the answer,
    # never above it.
    return Panel(
        table,
        title=f"[{DIM}]{GLYPH_POINT} {_t('Run summary')}[/]",
        title_align="left",
        border_style=BORDER,
        box=PANEL_BOX,
        padding=(0, 1),
        width=width,
    )
