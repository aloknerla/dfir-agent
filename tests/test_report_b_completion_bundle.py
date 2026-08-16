"""What one ``/complete`` leaves on disk, and what the operator is told it is.

The complaint these pin is that closing a case produced seven files under three
different names, two of which were markdown reports with the same title. One of
those two was written by ``complete_case`` under the completion stem and covered
only the last exchange; the other was written afterwards by the caller in the
TUI, under an auto-generated stem, and covered the whole case. The file named
for the closed case was the narrower of the two, and nothing on screen said so.

Every test below drives the real :class:`InteractiveSession` against a real run
root: the runs are recorded through the real oversight recorder, the report is
built by the real report writer, and the assertions are made by listing the
directory afterwards and reading what is in it. A stubbed session cannot show
that four files landed instead of one, because the count is the defect.
"""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest
from rich.console import Console

from forensic_agent.cli import case_completion as _case_completion
from forensic_agent.cli import host_display as _host
from forensic_agent.cli.session import InteractiveSession
from forensic_agent.cli.session_exports import unique_destination
from forensic_agent.oversight.audit import OversightLog
from forensic_agent.oversight.policy import Policy, evaluate

_QUESTIONS = (
    ("aaaaaaaaaaaa1111", "who logged in last?", "The last interactive logon was USER-A."),
    ("bbbbbbbbbbbb2222", "what was mounted?", "One removable volume was mounted."),
    ("cccccccccccc3333", "which process wrote it?", "notepad.exe wrote the file."),
)


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (_host.ENV_HOST_RUNS, _host.ENV_HOST_EVIDENCE, "DFA_CONTAINERIZED"):
        monkeypatch.delenv(name, raising=False)


def _console() -> Console:
    return Console(file=StringIO(), force_terminal=False, width=110, no_color=True)


def _panel_body(printed: str) -> str:
    r"""The panel's body as one flowed line, with Rich's own wrapping undone.

    The panel is drawn at a pinned width, so WHERE each of its lines breaks is
    decided by the one thing this test does not choose: how long a temporary
    directory pytest handed it. ``/tmp/pytest-of-runner/pytest-0/
    test_completion_in_a_container0`` on a Linux runner and the
    ``C:\Users\...\AppData\Local\Temp\pytest-of-...`` equivalent on a Windows
    workstation are different lengths, so a line that fits whole on one host is
    split across two on the other, and a phrase looked for in the raw capture
    is really being looked for at a break position nobody picked. Rejoining the
    body puts the same question to the same panel on either host.

    The frame is dropped and what it held is joined by the single space the
    wrap took out. Both frames are recognised: Rich substitutes an ASCII box
    for the rounded one on a console that cannot draw it.
    """

    body: list[str] = []
    for line in printed.splitlines():
        stripped = line.strip()
        if not stripped or stripped[0] not in "\u2502|":
            continue
        body.append(stripped.strip("\u2502|").strip())
    return " ".join(part for part in body if part)


def _session_args(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        model="openai/gpt-oss-120b",
        base_url="https://openrouter.ai/api/v1",
        api_key="test-key",
        memory=None,
        pcap=None,
        max_steps=10,
        image=None,
        case=None,
        run_dir=str(tmp_path / "runs"),
        resume=None,
        continue_session=False,
    )


def _record_run(run_root: Path, turn_id: str, question: str, answer: str) -> Path:
    """Lay down one question's run directory the way a real run leaves it.

    The whole-case report reads each question's material back out of its own
    run directory rather than out of the conversation, so a history whose runs
    were never recorded exports a report with nothing in it. Recording through
    the real recorder is what makes the exported document the real shape.
    """

    run_dir = run_root / turn_id
    run_dir.mkdir(parents=True, exist_ok=True)
    recorder = OversightLog(str(run_dir / "oversight.jsonl"))
    arguments = {"path": "/evidence/case"}
    recorder.open_case(question=question, model="test-model", engine="LangGraph")
    recorder.record_action(
        tool="filesystem_list",
        args=arguments,
        decision=evaluate(Policy.permissive(), "filesystem_list", arguments),
        output={"entries": ["a.txt", "b.txt"]},
        duration_s=0.5,
    )
    recorder.close_case(final=answer, status="ok")
    (run_dir / "tool-results.jsonl").write_text("", encoding="utf-8")
    (run_dir / "audit.jsonl").write_text("", encoding="utf-8")
    return run_dir


def _investigated_session(tmp_path: Path, console: Console) -> InteractiveSession:
    """A session holding three completed exchanges, ready to be closed."""

    from forensic_agent.cli.controlled import ControlledRun

    session = InteractiveSession(_session_args(tmp_path), console=console)
    session.case_id = "case-042"
    session.case_label = "case-042"
    session._history.start("closing")
    active = session._history.active
    assert active is not None

    run_dir = tmp_path
    for turn_id, question, answer in _QUESTIONS:
        run_dir = _record_run(session.run_root, turn_id, question, answer)
        active.append(
            question,
            answer,
            audit_ref=str(run_dir / "audit.jsonl"),
            verification_ref=str(run_dir / "oversight.jsonl"),
            turn_id=turn_id,
        )

    last_id, last_question, last_answer = _QUESTIONS[-1]
    session.last_run = ControlledRun(
        report=last_answer,
        run_id=last_id,
        audit_path=run_dir / "audit.jsonl",
        oversight_path=run_dir / "oversight.jsonl",
        tool_result_trace_path=run_dir / "tool-results.jsonl",
        visible_tools=("filesystem_list",),
        telemetry={},
    )
    session.last_q = last_question
    session.last_report = last_answer
    session.last_provider = "openrouter"
    session.last_evidence = session.last_run.tool_calls()
    session.last_findings = []
    session.oversight_path = str(run_dir / "oversight.jsonl")
    return session


def _exports(session: InteractiveSession) -> list[Path]:
    return sorted((session.run_root / "exports").iterdir())


def test_completing_writes_one_report_on_one_stem(tmp_path: Path) -> None:
    """Five files, one stem, and the markdown is the whole case."""

    session = _investigated_session(tmp_path, _console())

    assert session.complete_case() is True

    written = _exports(session)
    assert [path.name for path in written] == [
        "case_completion_cccccccccccc.html",
        "case_completion_cccccccccccc.json",
        "case_completion_cccccccccccc.md",
        "case_completion_cccccccccccc.oversight.md",
        "case_completion_cccccccccccc.svg",
    ]
    # One stem for all of them: the oversight companion carries the stem plus
    # its own marker, everything else carries the stem alone.
    stems = {path.name.split(".", 1)[0] for path in written}
    assert stems == {"case_completion_cccccccccccc"}
    # Exactly one markdown report, plus its oversight companion. Two documents
    # both titled "forensic report" is the defect this pins.
    reports = [path for path in written if path.suffix == ".md"]
    assert len(reports) == 2
    assert sum(1 for path in reports if not path.name.endswith(".oversight.md")) == 1


def test_the_completion_report_covers_every_exchange(tmp_path: Path) -> None:
    """The document named for the closed case is the case, not its last minute."""

    session = _investigated_session(tmp_path, _console())
    session.complete_case()

    report = session.run_root / "exports" / "case_completion_cccccccccccc.md"
    text = report.read_text(encoding="utf-8")
    for _turn_id, question, answer in _QUESTIONS:
        assert question in text
        assert answer in text


def test_the_completion_panel_names_only_files_that_exist(tmp_path: Path) -> None:
    console = _console()
    session = _investigated_session(tmp_path, console)
    session.complete_case()

    printed = console.file.getvalue()
    for path in _exports(session):
        assert path.name in printed
    # And it says which of them is the report, rather than leaving five similar
    # filenames to be told apart by extension.
    assert "There is one report here." in printed


def test_the_completion_record_keeps_the_machine_paths(tmp_path: Path) -> None:
    """Presentation translation must not reach the record on disk.

    The declaration is read by machines and diffed against other runs, so the
    path it stores is the path the process actually wrote to. A host path
    substituted here would name a file this record's own writer never touched.
    """

    session = _investigated_session(tmp_path, _console())
    session.complete_case()

    declaration = json.loads(
        (session.run_root / "exports" / "case_completion_cccccccccccc.json").read_text(
            encoding="utf-8"
        )
    )
    artifacts = declaration["artifacts"]
    assert artifacts["forensic_report"] == str(
        session.run_root / "exports" / "case_completion_cccccccccccc.md"
    )
    assert artifacts["investigation_diagram"] == str(
        session.run_root / "exports" / "case_completion_cccccccccccc.svg"
    )
    assert "(not reachable from your computer)" not in json.dumps(declaration)


def test_a_second_completion_moves_the_whole_set_rather_than_clobbering(
    tmp_path: Path,
) -> None:
    """Completing twice must not destroy the first declaration.

    The stem is claimed as a family: stepping around an occupied markdown and
    then writing the diagram over the previous one would have moved the loss
    rather than prevented it.
    """

    session = _investigated_session(tmp_path, _console())
    session.complete_case()
    first = {path.name: path.read_bytes() for path in _exports(session)}

    session.complete_case()

    written = _exports(session)
    assert len(written) == 10
    for name, content in first.items():
        assert (session.run_root / "exports" / name).read_bytes() == content
    second = [path.name for path in written if "-1" in path.name]
    assert sorted(second) == [
        "case_completion_cccccccccccc-1.html",
        "case_completion_cccccccccccc-1.json",
        "case_completion_cccccccccccc-1.md",
        "case_completion_cccccccccccc-1.oversight.md",
        "case_completion_cccccccccccc-1.svg",
    ]


def test_a_requested_destination_still_carries_the_whole_set(tmp_path: Path) -> None:
    """``/complete <path>`` names one stem, and every artifact lands on it."""

    session = _investigated_session(tmp_path, _console())
    session.complete_case("closing-report")

    assert [path.name for path in _exports(session)] == [
        "closing-report.html",
        "closing-report.json",
        "closing-report.md",
        "closing-report.oversight.md",
        "closing-report.svg",
    ]
    text = (session.run_root / "exports" / "closing-report.md").read_text(
        encoding="utf-8"
    )
    assert all(question in text for _id, question, _answer in _QUESTIONS)


def test_a_requested_destination_that_is_taken_moves_the_whole_set(
    tmp_path: Path,
) -> None:
    session = _investigated_session(tmp_path, _console())
    session.complete_case("closing-report")
    session.complete_case("closing-report")

    names = [path.name for path in _exports(session)]
    assert "closing-report.md" in names
    assert "closing-report-1.md" in names
    assert "closing-report-1.svg" in names
    assert "closing-report-1.json" in names


def test_the_completion_html_is_a_self_contained_page(tmp_path: Path) -> None:
    """It has to open with a double click on a machine that fetches nothing."""

    session = _investigated_session(tmp_path, _console())
    session.complete_case()

    page = (session.run_root / "exports" / "case_completion_cccccccccccc.html").read_text(
        encoding="utf-8"
    )
    assert page.lstrip().startswith("<!DOCTYPE html>")
    assert page.rstrip().endswith("</html>")
    assert "<title>case_completion_cccccccccccc.md</title>" in page
    # Nothing to fetch: no remote stylesheet, script, font or image.
    for token in ("http://", "https://", "<link", "<script", "@import", "url("):
        assert token not in page
    # And the report is legible in it rather than merely embedded in it.
    for _turn_id, _question, answer in _QUESTIONS:
        assert answer.split(".")[0] in page


def test_completion_in_a_container_says_where_the_files_are_on_the_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A path only the container can open must be marked as such.

    The exports of this test do not live under ``/runtime``, which is the only
    thing the launcher's host root can be resolved against, so the honest
    answer is the container path named as a container path. That is a different
    instruction from printing it bare, and it is the branch an operator hits
    whenever the launcher did not state the mount.
    """

    monkeypatch.setenv("DFA_CONTAINERIZED", "1")
    monkeypatch.setenv(_host.ENV_HOST_RUNS, r"C:\Users\Adrian\dfir-runs")
    console = _console()
    session = _investigated_session(tmp_path, console)
    session.complete_case()

    printed = console.file.getvalue()
    assert "(not reachable from your computer)" in _panel_body(printed)


def test_the_panel_prints_the_host_directory_when_the_mount_is_known(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The translating branch, driven through the panel the operator sees.

    Inside the container every path the console prints is POSIX and rooted at
    the bind mount, and that is the only shape ``display_path`` can translate.
    A Windows test host cannot produce one from a real file, so the paths here
    stand in for the shape rather than for the files: the panel asks a path
    only for its name, its parent, and whether it is a file.
    """

    class _ContainerPath(PurePosixPath):
        def is_file(self) -> bool:
            return True

    monkeypatch.setenv("DFA_CONTAINERIZED", "1")
    monkeypatch.setenv(_host.ENV_HOST_RUNS, r"C:\Users\Adrian\dfir-runs")
    report = _ContainerPath("/runtime/exports/case_completion_ab12cd34ef56.md")
    console = _console()
    console.print(
        _case_completion.completion_panel(
            report,
            report.with_suffix(".svg"),
            report.with_suffix(".json"),
            html=report.with_suffix(".html"),
            width=108,
        )
    )

    printed = console.file.getvalue()
    assert r"C:\Users\Adrian\dfir-runs\exports" in printed
    assert "/runtime/exports" not in printed
    assert "(not reachable from your computer)" not in printed


def test_unique_destination_claims_the_stem_for_every_companion(
    tmp_path: Path,
) -> None:
    """A free markdown name is not a free stem when the diagram is taken."""

    taken = tmp_path / "bundle.svg"
    taken.write_text("<svg/>", encoding="utf-8")

    assert unique_destination(tmp_path / "bundle.md") == tmp_path / "bundle.md"
    assert (
        unique_destination(
            tmp_path / "bundle.md",
            companion_suffixes=_case_completion.COMPLETION_ARTIFACT_SUFFIXES,
        )
        == tmp_path / "bundle-1.md"
    )
