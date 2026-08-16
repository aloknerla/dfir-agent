"""The shape a published answer takes on the operator's screen.

The defect these cover: an answer arrived headed ``Evidence:`` one time and
``Support:`` the next, because the prompt used both words for the same thing;
and a negative answer arrived as an unbroken block of five bullets about
searches that found nothing. Both are settled below the model — the heading is
the console's word, the layout is the console's, and the number of evidence
lines the panel prints has a ceiling the model cannot exceed by disobeying it.

Nothing here touches verification. The split runs over an ALREADY published,
already verified report, which is why every test that caps anything also checks
that the complete text is still the thing the claim splitter reads.
"""

import io

from rich.console import Console
from rich.panel import Panel

from forensic_agent.agent.answer_format import (
    SUPPORT_ITEM_LIMIT,
    split_published_answer,
)
from forensic_agent.agent.recovery.coverage_bound import bound_stated_for
from forensic_agent.cli import i18n
from forensic_agent.cli.exchange_view import answer_renderable
from forensic_agent.reliability.verify import build_verification_claims

POSITIVE = (
    "The registered owner of the system is Jane Doe.\n"
    "SOFTWARE hive, Microsoft\\Windows NT\\CurrentVersion: RegisteredOwner = Jane Doe.\n"
    "The same key records RegisteredOrganization = Acme Ltd."
)

NEGATIVE_WALL = (
    "No printing activity was found for the account jdoe. A keyword search of the raw "
    "image for spool artefacts returned nothing, and the PrintService operational log "
    "carries no entry for that account.\n"
    "- Evidence: the PrintService/Operational log holds 214 entries, none naming jdoe.\n"
    "- The SOFTWARE hive records no installed printer driver.\n"
    "- A raw-image keyword scan for '.spl' returned no hit in unallocated space.\n"
    "- No spool directory exists at /Windows/System32/spool/PRINTERS.\n"
    "- The memory image lists no spoolsv.exe working-set string for jdoe.\n"
    "\n"
    "Coverage for this run is incomplete: unallocated space of partition 2 was not "
    "read, so anything reported above as not present is bounded by that limit."
)

ATOMIC = "The registered owner is Jane Doe."


def render(report: str) -> str:
    """The answer exactly as the line console draws it, styles removed."""

    console = Console(record=True, width=88, file=io.StringIO())
    console.print(Panel(answer_renderable(report), padding=(1, 2), width=88))
    return console.export_text()


def test_the_finding_stands_alone_and_the_evidence_is_set_off_from_it() -> None:
    answer = split_published_answer(POSITIVE)

    assert answer.finding == "The registered owner of the system is Jane Doe."
    assert answer.support == (
        "SOFTWARE hive, Microsoft\\Windows NT\\CurrentVersion: RegisteredOwner = Jane Doe.",
        "The same key records RegisteredOrganization = Acme Ltd.",
    )
    assert answer.omitted_support == 0

    drawn = render(POSITIVE)
    lines = [
        line.strip("│ ")
        for line in drawn.splitlines()
        if line.startswith("│") and line.strip("│ ")
    ]
    # Finding, heading, then one line per piece of evidence: the claim is never
    # spliced onto the first evidence line the way an unbroken block splices it.
    assert lines[0] == "The registered owner of the system is Jane Doe."
    assert lines[1] == "Evidence"
    assert lines[2].endswith("RegisteredOwner = Jane Doe.")
    assert lines[3].startswith("•")


def test_a_wall_of_a_negative_answer_is_broken_up_and_bounded() -> None:
    answer = split_published_answer(NEGATIVE_WALL)

    assert answer.finding == "No printing activity was found for the account jdoe."
    assert len(answer.support) == SUPPORT_ITEM_LIMIT
    assert answer.omitted_support == 3

    drawn = render(NEGATIVE_WALL)
    assert "3 more" in drawn
    assert "/findings" in drawn
    # The inventory of empty searches is not in the panel; the strongest lines
    # are, and the run's own record holds the rest.
    assert "spoolsv.exe" not in drawn
    assert "spool/PRINTERS" not in drawn


def test_the_console_owns_the_heading_so_the_model_cannot_choose_one() -> None:
    """A label the model wrote anyway is dropped rather than printed twice."""

    labelled = (
        "No printing activity was found.\n"
        "Support: the PrintService/Operational log holds 214 entries, none naming jdoe."
    )
    other_word = labelled.replace("Support:", "Evidence:")

    assert split_published_answer(labelled).support == split_published_answer(
        other_word
    ).support
    for report in (labelled, other_word):
        drawn = render(report)
        assert drawn.count("Evidence") == 1
        assert "Support:" not in drawn


def test_the_heading_is_translated_with_the_rest_of_the_interface() -> None:
    """It used to arrive in English inside a Croatian answer, because the model
    wrote it. A word the console owns is a catalog key like any other."""

    original = i18n.current_language()
    try:
        i18n.set_language("hr")
        drawn = render(POSITIVE)
        assert "Dokazi" in drawn
        assert "Evidence" not in drawn
    finally:
        i18n.set_language(original)


def test_a_one_line_answer_is_left_exactly_as_it_was() -> None:
    """The atomic direct answer has no evidence part, so it gets no heading."""

    answer = split_published_answer(ATOMIC)

    assert answer.finding == ATOMIC
    assert answer.support == ()
    assert "Evidence" not in render(ATOMIC)


def test_the_stated_coverage_bound_is_never_capped_away() -> None:
    """The one paragraph the runtime wrote, and the one the cap must not reach.

    It is appended last, after the evidence, and it holds everything the report
    calls absent to what was actually read. A cap that counted it as just
    another trailing line would hide it behind ``/findings`` and leave an
    unqualified negative on the screen.
    """

    answer = split_published_answer(NEGATIVE_WALL)

    assert answer.coverage_bound.startswith("Coverage for this run is incomplete:")
    assert "partition 2" in answer.coverage_bound
    assert answer.coverage_bound not in answer.support
    assert "unallocated space of partition 2 was not" in render(NEGATIVE_WALL)


def test_the_recognised_bound_openings_are_the_ones_the_runtime_composes() -> None:
    """Pins the closed prefix set to its actual composer, in the other module.

    The detach step recognises the bound by how it opens. If the composer's
    wording changes and this recognition does not, a bound silently becomes a
    cappable evidence line — so the two are checked against each other here
    rather than trusted to stay in step.
    """

    regions = bound_stated_for(("unallocated space of partition 2",))
    truncated = bound_stated_for(
        (),
        bundle_truncated=True,
        bundle_included=4,
        bundle_source=9,
        bundle_shortened=2,
    )
    for composed in (regions, truncated):
        report = f"A finding.\nOne piece of evidence.\n\n{composed}"
        assert split_published_answer(report).coverage_bound == composed


def test_the_cap_shortens_the_panel_and_never_the_verified_text() -> None:
    """The render-time cap cannot hide anything a check depends on.

    Verification has already run, claim by claim, over the complete published
    report by the time anything here is called, and that same complete report is
    what the run recorded and what ``/findings`` shows. This asserts the
    relationship directly: the claim splitter still sees every line the cap took
    off the panel.
    """

    claims = build_verification_claims(NEGATIVE_WALL)
    claim_text = " ".join(claim.text for claim in claims)

    assert "spoolsv.exe" in claim_text
    assert "spool/PRINTERS" in claim_text
    assert "Coverage for this run is incomplete" in claim_text
    # And the split is a reading, not a rewrite: it derives from the report and
    # leaves it byte-identical for everything downstream.
    split_published_answer(NEGATIVE_WALL)
    assert build_verification_claims(NEGATIVE_WALL) == claims


def test_layout_the_line_split_would_destroy_is_left_whole() -> None:
    """A table or a fenced block is one unit of text, so it is not restructured."""

    table = (
        "Three accounts have interactive logons.\n"
        "| account | last logon |\n"
        "| --- | --- |\n"
        "| jdoe | 2024-03-01 |\n"
    )
    answer = split_published_answer(table)

    assert answer.support == ()
    assert answer.finding == table.strip()
    assert "| jdoe | 2024-03-01 |" in answer.finding


def test_an_empty_report_produces_no_heading_over_nothing() -> None:
    for report in ("", "   ", "\n\n"):
        answer = split_published_answer(report)
        assert answer.finding == ""
        assert answer.support == ()
        assert "Evidence" not in render(report)
