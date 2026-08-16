"""What a report covers, and where it is written, as two separate questions.

``/export`` conflates them on purpose: typing a path means "this one answer,
here", and that is the reading an operator expects at the prompt. The trouble
was that ``/complete`` reached the same function with a path and meant the
opposite — the closing document of a case is the case — and got the last
exchange under a filename claiming to be the case report.

``scope`` is the separation. These pin both readings: the interactive grammar
is unchanged under the default, and the whole-case document can now be written
to a named destination. The neighbouring file drives the completion bundle
itself; this one is about the function the bundle calls.
"""

from __future__ import annotations

from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console
from test_report_b_completion_bundle import _QUESTIONS, _investigated_session

from forensic_agent.cli import host_display as _host
from forensic_agent.cli.session import InteractiveSession
from forensic_agent.reporting.html_report import render_report_html


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (_host.ENV_HOST_RUNS, _host.ENV_HOST_EVIDENCE, "DFA_CONTAINERIZED"):
        monkeypatch.delenv(name, raising=False)


def _console() -> Console:
    return Console(file=StringIO(), force_terminal=False, width=110, no_color=True)


def _exported(session: InteractiveSession) -> list[str]:
    return sorted(path.name for path in (session.run_root / "exports").iterdir())


def test_a_named_path_still_exports_the_one_answer(tmp_path: Path) -> None:
    """The interactive reading of ``/export <path>`` is unchanged."""

    session = _investigated_session(tmp_path, _console())
    session.export_report("one-answer.md")

    text = (session.run_root / "exports" / "one-answer.md").read_text(encoding="utf-8")
    assert _QUESTIONS[-1][1] in text
    assert _QUESTIONS[0][1] not in text


def test_the_case_scope_writes_the_whole_case_to_the_named_path(
    tmp_path: Path,
) -> None:
    session = _investigated_session(tmp_path, _console())
    session.export_report("whole-case.md", scope="case")

    text = (session.run_root / "exports" / "whole-case.md").read_text(encoding="utf-8")
    assert all(question in text for _id, question, _answer in _QUESTIONS)


def test_the_case_scope_honours_the_named_path_exactly(tmp_path: Path) -> None:
    """No second uniquing at the write site.

    /complete resolves one free stem for every artifact it files. A destination
    uniqued a second time here would move the report off that stem and leave
    the diagram and the declaration behind on it.
    """

    session = _investigated_session(tmp_path, _console())
    (session.run_root / "exports").mkdir(parents=True, exist_ok=True)
    (session.run_root / "exports" / "fixed.md").write_text("older", encoding="utf-8")

    session.export_report(session.run_root / "exports" / "fixed.md", scope="case")

    assert "fixed-1.md" not in _exported(session)
    assert (session.run_root / "exports" / "fixed.md").read_text(
        encoding="utf-8"
    ) != "older"


def test_the_question_scope_narrows_a_bare_export(tmp_path: Path) -> None:
    session = _investigated_session(tmp_path, _console())
    session.export_report(scope="question")

    written = [name for name in _exported(session) if not name.endswith(".oversight.md")]
    assert len(written) == 1
    text = (session.run_root / "exports" / written[0]).read_text(encoding="utf-8")
    assert _QUESTIONS[0][1] not in text


def test_the_case_scope_falls_back_when_the_history_retains_nothing(
    tmp_path: Path,
) -> None:
    """A whole-case document listing zero questions is worse than a narrow one."""

    session = _investigated_session(tmp_path, _console())
    session._history.discard()

    session.export_report("fallback.md", scope="case")

    text = (session.run_root / "exports" / "fallback.md").read_text(encoding="utf-8")
    assert _QUESTIONS[-1][2] in text


def test_a_bare_export_writes_no_html(tmp_path: Path) -> None:
    """The page rides with the closing bundle, not with every restatement.

    /export is the operation an investigator repeats through a case, and each
    call already writes a report and its oversight companion. A third file per
    call would treble a directory an operator has to read, for a convenience
    that only matters when the report leaves the console — which is what
    /complete is.
    """

    session = _investigated_session(tmp_path, _console())
    session.export_report()

    assert not [name for name in _exported(session) if name.endswith(".html")]


def test_the_export_announcement_reads_correctly_inside_a_container(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The count precedes the path, so the container marker ends the sentence.

    With the count trailing, an untranslatable path produced two parentheticals
    in a row and the first of them read as an aside about the second.
    """

    monkeypatch.setenv("DFA_CONTAINERIZED", "1")
    console = _console()
    session = _investigated_session(tmp_path, console)
    session.export_report()

    printed = console.file.getvalue()
    assert "(3 recorded questions):" in printed
    assert printed.rstrip().endswith("(not reachable from your computer)")


def test_the_html_rendering_survives_the_shapes_these_reports_contain() -> None:
    """Headings, tables and fenced code all appear in a forensic report."""

    page = render_report_html(
        "# Forensic report\n\n"
        "## 1. Case identification\n\n"
        "| Field | Value |\n| --- | --- |\n| Case id | case-042 |\n\n"
        "```\nfilesystem_list /evidence/case\n```\n",
        title="report.md",
    )

    assert "Forensic report" in page
    assert "Case identification" in page
    assert "case-042" in page
    assert "filesystem_list /evidence/case" in page
    # The table is drawn rather than left as pipes a reader has to align.
    assert "─" in page


def test_the_html_title_cannot_carry_markup_out_of_a_filename() -> None:
    """A destination is operator text and reaches the page's own head."""

    page = render_report_html("# report\n", title='<script>x</script>"')

    assert "<script>x</script>" not in page
    assert "&lt;script&gt;" in page
