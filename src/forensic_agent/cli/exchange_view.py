"""One exchange as the operator watches it happen: the calls, the answer, the refusal.

Between the heading that opens a question and the panels that summarise what it
found, a question produces exactly three kinds of writing: a line for each tool
call the mediator let run, the answer when one arrives, and an account of why
none did when the provider would not serve the request. They are gathered here
because they are read as one thing — a single block of transcript that has to
hold together whichever way the question ended — and because none of them is
about the session's state.

That last point is what makes them worth separating. The activity feed is a live
audit of what ran: it is written while a question is in flight, from a callback
the tool layer invokes, and it must not be able to reach anything the
investigation is mutating at that moment. The failure account is a decision about
which of several overlapping diagnoses fits an exception, and the order those
diagnoses are tried in is the whole of its correctness — a provider's own wording
can contain any of the substrings the later guesses look for, so its own account
of itself is read first. Written as a function of the exception it can be checked
against a real error object; written inline in the question's ``except`` branch it
could only be checked by failing a real request.

The exchange *heading* deliberately stays in
:mod:`forensic_agent.cli.console_layout` with the rest of the shared layout
vocabulary, and the panels below an answer in
:mod:`forensic_agent.cli.findings_view`. The number this module prints on the
answer is the same number the heading printed, which is why both take it from
the caller rather than counting for themselves.
"""

from __future__ import annotations

from collections.abc import Callable

from rich.console import Console, Group, RenderableType
from rich.markdown import Markdown
from rich.markup import escape
from rich.padding import Padding
from rich.panel import Panel
from rich.text import Text

from forensic_agent.agent.answer_format import split_published_answer
from forensic_agent.cli.console_layout import ANSWER_MARKDOWN_THEME
from forensic_agent.cli.i18n import t as _t
from forensic_agent.cli.presentation import (
    ANSWER_ASSEMBLED,
    ANSWER_DRAFT_VERIFICATION_INCOMPLETE,
    ANSWER_UNVERIFIED_DRAFT,
    ANSWER_VERIFIED,
    ANSWER_VERIFIED_WITH_BOUND,
    IncompleteExamination,
    summarize_call_arguments,
)
from forensic_agent.cli.provider_notice import provider_failure_notice
from forensic_agent.cli.terminal import (
    ACCENT,
    DIM,
    GLYPH_ERROR,
    GLYPH_OK,
    GLYPH_WARN,
    ORANGE,
    PANEL_BOX,
    RAISED_SURFACE,
    RED,
    SUCCESS,
    glyphed_line,
)
from forensic_agent.core.durations import format_duration

#: How the answer panel frames what the run actually accepted: the border
#: colour, the glyph on the title, and the qualification that follows the title.
#: A verified report gets the console's one success colour; anything less gets
#: caution, because the panel is the most authoritative thing on the screen and
#: an operator reads its frame long before they reach the run summary.
#: An assembled answer is framed apart from both of the others, because it is
#: neither: its values were inserted by the runtime and never typed by the model,
#: and no final check read the sentences around them.  Framing it like a verified
#: report would claim a check that did not run, and framing it like prose would
#: hide the one guarantee the operator turned the flag on to get.
#: A report published with its coverage bound stated keeps the success colour,
#: because the check did run and did pass; what the qualification carries is
#: that the report states a limit on what was read, which the operator must
#: carry into anything the report says was not there.
_ANSWER_FRAMING: dict[str, tuple[str, str, str]] = {
    ANSWER_VERIFIED: (SUCCESS, GLYPH_OK, ""),
    ANSWER_VERIFIED_WITH_BOUND: (SUCCESS, GLYPH_OK, "coverage bound stated"),
    ANSWER_UNVERIFIED_DRAFT: (ORANGE, GLYPH_WARN, "unverified draft"),
    # The verifier ran and returned, and the part of the draft it could reach it
    # judged; what it could not reach is named in the answer itself. Warning
    # colour rather than success, because the operator must read that marker,
    # but an accepted answer nonetheless: it was published, and treating it as
    # none discarded correct findings.
    ANSWER_DRAFT_VERIFICATION_INCOMPLETE: (
        ORANGE,
        GLYPH_WARN,
        "verification incomplete",
    ),
    ANSWER_ASSEMBLED: (ORANGE, GLYPH_WARN, "assembled; not verified"),
}
#: Every other verdict the final-answer contract can reach, including the one
#: where the run accepted no answer at all and this text is a draft the console
#: is showing rather than a result the run stands behind.
_ANSWER_FRAMING_UNSETTLED = (ORANGE, GLYPH_WARN, "not accepted by the run")


def tool_call_line(
    console: Console,
    name: object,
    args: object,
    dt: float,
    refused: bool = False,
) -> None:
    """Write one approved call to the live feed, and say what became of it."""

    # The feed is a live audit of what the mediator let run. The tool's
    # identity is its name, carried in the accent; one glyph and one word
    # carry the state, instead of a different decorative picture per tool
    # that only jitters the column. Arguments and elapsed time stay dim so
    # the eye can scan the tool names down the left without the detail
    # pulling on it.
    #
    # Only a call the gate ALREADY approved ever reaches this feed — a
    # blocked one never gets as far as the tool that emits here — so the
    # word states what became of an approved call rather than repeating
    # "approved" on every line, which would leave a refused call reading as a
    # successful one with a stray "rejected=True" among its arguments.
    detail = summarize_call_arguments(args)
    elapsed = format_duration(dt, compact=True)
    trailing = f"{escape(detail)}, {elapsed}" if detail else elapsed
    glyph, colour, word = (
        (GLYPH_ERROR, RED, _t("refused"))
        if refused
        else (GLYPH_OK, SUCCESS, _t("approved"))
    )
    console.print(
        f"  [{colour}]{glyph}[/] [{DIM}]{word}[/]  "
        f"[bold {ACCENT}]{escape(str(name))}[/]  "
        f"[{DIM}]{trailing}[/]"
    )


def answer_renderable(
    report: str,
    *,
    markdown: Callable[[str], RenderableType] = Markdown,
    accent: str = ACCENT,
    dim: str = DIM,
) -> RenderableType:
    """Lay a published answer out as the finding, then the evidence under it.

    The heading over the evidence is written HERE and never by the model. That
    is the whole point of the function: the model was handed two words for the
    same part of an answer and picked between them, so one answer arrived headed
    ``Evidence:`` and the next ``Support:``. A label the console owns cannot
    vary, and it is translated with the rest of the interface instead of
    arriving in English inside a Croatian answer.

    The layout is the other half. A finding, a blank line, the heading, then one
    line per piece of evidence: the same text that used to arrive as an
    unbroken block is read in the order it should be read. Where the run
    published more evidence lines than the panel shows, the count of the rest is
    stated and the complete, receipt-bound record stays one ``/findings`` away —
    the answer panel is not the place to hold an inventory.

    ``markdown`` is the renderable the caller builds prose with, so a console
    with its own themed markdown passes that instead of taking this module's.
    ``accent`` and ``dim`` travel with it: the full-screen console carries its
    own palette, and its greys were raised to clear the contrast floor while
    this module's ``DIM`` is still the line shell's ``grey50``. Taking the
    caller's two styles keeps one implementation of the layout instead of a
    second copy that exists only to be a different colour.
    """

    answer = split_published_answer(report)
    if not answer.finding and not answer.support:
        # Nothing recognisable to lay out. Print exactly what the run published
        # rather than an empty panel with a heading over it.
        return markdown(report)
    if not answer.support and not answer.coverage_bound:
        return markdown(answer.finding)

    parts: list[RenderableType] = [markdown(answer.finding)]
    if answer.support:
        parts.append(Text(""))
        parts.append(Text(_t("Evidence"), style=f"bold {accent}"))
        parts.append(markdown("\n".join(f"- {item}" for item in answer.support)))
        if answer.omitted_support:
            # Indented into the bullet column so it reads as the tail of the
            # list rather than as a separate sentence of the answer, and dim
            # because it is the console talking, not the report.
            parts.append(
                Text(
                    "   "
                    + _t("{n} more").replace("{n}", str(answer.omitted_support))
                    + ". "
                    + _t("See")
                    + " /findings",
                    style=dim,
                )
            )
    if answer.coverage_bound:
        # Never capped and never abbreviated: this is the paragraph the runtime
        # appended to hold everything the report calls absent to what was
        # actually read, and an operator who does not see it reads an
        # unqualified negative.
        parts.append(Text(""))
        parts.append(markdown(answer.coverage_bound))
    return Group(*parts)


def print_final_answer(
    console: Console,
    report: str,
    *,
    number: int,
    width: int,
    answer_source: str,
) -> None:
    """Print the answer the run settled on, framed by how settled it actually is.

    ``answer_source`` is the verdict the run's own final-answer contract
    recorded, read through
    :func:`~forensic_agent.cli.presentation.summarize_controls`.  The panel's
    colour and glyph follow that verdict, so an unverified draft — and an answer
    the run accepted from neither path — does not arrive looking exactly like a
    verified report with the qualification left to a dim strip further down.
    """

    border, glyph, qualification = _ANSWER_FRAMING.get(
        answer_source, _ANSWER_FRAMING_UNSETTLED
    )
    qualifier = f" [{ORANGE}]({_t(qualification)})[/]" if qualification else ""
    with console.use_theme(ANSWER_MARKDOWN_THEME):
        console.print(
            Panel(
                answer_renderable(report),
                # The heading's number is repeated here because this is the
                # panel an operator scrolls back to: an answer found on its
                # own, with its heading already off the top of the screen,
                # still says which question it settles.
                title=(
                    f"[bold]{glyph} {number:02d}. "
                    f"{_t('Final answer')}[/]{qualifier}"
                ),
                title_align="left",
                border_style=border,
                box=PANEL_BOX,
                style=RAISED_SURFACE,
                padding=(1, 2),
                width=width,
            )
        )


def print_interim_finding(
    console: Console,
    examination: IncompleteExamination,
    *,
    number: int,
    width: int,
) -> None:
    """Print what a run that published no conclusion can state about itself.

    A run that read the evidence and stopped at a bound must not leave an operator
    one error line: the panels that show what it read are built from a returned
    run record, and a run that raises returns none.  The readings it had made can
    include the very file the question asked for.

    Deliberately not the answer panel and deliberately not its title: the frame
    is caution, the surface is flat rather than raised, and the words state that
    the examination did not complete.  Nothing that reads a transcript for a
    published answer can find one here, which is what keeps an incomplete
    examination from reading as a completed one.
    """

    console.print(
        Panel(
            Markdown(examination.statement),
            title=(
                f"[bold]{GLYPH_WARN} {number:02d}. {_t('Interim finding')}[/] "
                f"[{ORANGE}]({_t('examination did not complete')})[/]"
            ),
            title_align="left",
            border_style=ORANGE,
            box=PANEL_BOX,
            padding=(1, 2),
            width=width,
        )
    )


def unpublished_outcome_lines(
    *, run_id: str, diagnostics_path: str
) -> tuple[RenderableType, ...]:
    """Close an unanswered run as an outcome, never as a fault in this software.

    A run that read the evidence, recorded its oversight decisions, closed its
    run record and then spent its budget without the model stating a conclusion
    has not failed. It produced a result, and to anyone comparing models it is
    one of the more interesting results there is. Printed through the generic
    fault renderer it arrived as ``agent error:`` and a raw exception string,
    beside the genuine article, a keyword this code got wrong, under those same
    two words. The two must never be recorded under one name.

    So this says what happened and says nothing about what the operator should
    fix. The run id and the diagnostic file stay, because they are what makes
    the outcome checkable afterwards; the plain-language account of WHY is
    already in the interim-finding panel above, and a second copy here is the
    one that goes stale.
    """

    lead = glyphed_line(
        GLYPH_WARN,
        ORANGE,
        Text(
            _t(
                "The run finished without a publishable finding. That is an "
                "outcome of the investigation, not a fault in this program."
            ),
            style=ORANGE,
        ),
    )
    # Both go through the renderables that keep an indent across their own
    # wrap: a diagnostic path is long, and a path continuing at column zero
    # reads as a line of its own that names nothing.
    trail = Text()
    trail.append(f"{_t('run id')} {run_id}", style=DIM)
    trail.append(f"   {_t('diagnostics')} {diagnostics_path}", style=DIM)
    return (lead, Padding(trail, (0, 0, 0, 2)))


def request_failure_explanation(
    error: BaseException,
    *,
    model: str,
    api_key: str,
) -> str:
    """Say why a question produced no answer, in terms the operator can act on.

    The diagnoses are tried in the order they appear, and that order is the
    point: the router's own account of the outcome is read before any guess made
    from substrings, because a provider's own wording can contain every word
    those guesses look for.

    This is for faults in this software and for provider conditions an operator
    can act on. A run that completed and published nothing is neither, and goes
    through :func:`unpublished_outcome_lines` instead: the fallback at the end
    of this function is the generic "something in here broke" renderer, and an
    outcome sent through it is filed as a defect.
    """

    msg = str(error)
    if api_key:
        msg = msg.replace(api_key, "[REDACTED]")
    low = msg.lower()
    model_route_failure = (
        "model_not_found" in low
        or "no such model" in low
        or "no endpoints found" in low
        or (
            "model" in low
            and ("not found" in low or "404" in low or "unavailable" in low)
        )
    )
    authentication_failure = (
        "401" in low
        or "user not found" in low
        or "invalid api key" in low
        or "authentication" in low
    )
    if authentication_failure:
        return (
            f"[{ORANGE}]The configured API key is invalid or revoked.[/] "
            f"[{DIM}]Run /setup to enter a current key, then retry "
            "the question.[/]"
        )
    if model_route_failure:
        return (
            f"[{ORANGE}]The provider could not serve model[/] "
            f"[bold]{escape(model)}[/]. "
            f"[{DIM}]Run /doctor to check availability, /model "
            "<model-id> to switch models, or /setup to change "
            "provider settings.[/]"
        )
    if (notice := provider_failure_notice(error)) is not None:
        # The router's own account of the failure, said rather than
        # dumped, and read before the substring guesses below: a
        # provider's own wording can contain any of the words they look
        # for.  The whole object stays on the oversight chain the
        # transport wrote it to.
        return notice
    if "connection" in low or "refused" in low or "timed out" in low:
        return (
            f"[{ORANGE}]The model provider is unavailable.[/] "
            "Check the network connection and credentials."
        )
    return f"[{RED}]agent error:[/] {escape(msg[:300])}"
