"""One lifecycle for every way evidence enters the session.

The complaint these pin is that the same file got two different treatments
depending on how it was opened: ``/case`` derived the entity index and said so,
while ``/attach`` and ``/continue`` bound the source silently. They now take the
same path, the index is built whenever a case opens rather than on request, and
the digest the open paid for is offered to the run instead of being paid twice.

Every bound source is digested, not only the one the entity scanner reads, so
the case can state for each of them the SHA-256 its bytes carried when it was
bound.
"""

from __future__ import annotations

from io import StringIO
from pathlib import Path
from types import SimpleNamespace

from rich.console import Console

import forensic_agent.cli.case_index as _case_index
import forensic_agent.cli.scope_check as _scope_check
import forensic_agent.core.audit as _audit
from forensic_agent.cli.session import InteractiveSession, _accepts_keyword


def _console() -> Console:
    return Console(file=StringIO(), force_terminal=False, width=200, no_color=True)


def _session_args(tmp_path: Path, **overrides: object) -> SimpleNamespace:
    values: dict[str, object] = {
        "model": "openai/gpt-oss-120b",
        "base_url": "https://openrouter.ai/api/v1",
        "api_key": "test-key",
        "memory": None,
        "pcap": None,
        "max_steps": 10,
        "image": None,
        "case": None,
        "run_dir": str(tmp_path / "runs"),
        "resume": None,
        "continue_session": False,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _memory_dump(tmp_path: Path, name: str = "memory.raw") -> Path:
    path = tmp_path / name
    path.write_bytes(b"physical memory sample" * 64)
    return path


def _capture(tmp_path: Path, name: str = "capture.pcap") -> Path:
    path = tmp_path / name
    path.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 96)
    return path


def _recorded_index(monkeypatch) -> list[dict[str, object]]:
    """Replace the scan itself; only which source it was asked for is at stake."""

    calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        _case_index,
        "index_opened_case",
        lambda console, **kwargs: calls.append(kwargs),
    )
    return calls


def _recorded_hashes(monkeypatch, digest: str = "ab" * 32) -> list[str]:
    hashed: list[str] = []
    monkeypatch.setattr(
        _audit,
        "sha256_file",
        lambda path, *args, **kwargs: hashed.append(str(path)) or digest,
    )
    return hashed


def test_attach_indexes_the_source_the_way_case_does(tmp_path, monkeypatch):
    calls = _recorded_index(monkeypatch)
    memory = _memory_dump(tmp_path)

    session = InteractiveSession(_session_args(tmp_path), console=_console())
    try:
        session.attach_memory(str(memory))
    finally:
        session.close()

    assert [Path(str(call["image_path"])) for call in calls] == [memory]


def test_attaching_beside_an_open_case_indexes_again(tmp_path, monkeypatch):
    """A second source is a change to the case, so the index is derived again."""

    calls = _recorded_index(monkeypatch)
    memory = _memory_dump(tmp_path)
    capture = _capture(tmp_path)

    session = InteractiveSession(_session_args(tmp_path), console=_console())
    try:
        session.open_typed_case("memory", str(memory))
        session.attach_pcap(str(capture))
    finally:
        session.close()

    # Once for the typed open and once for the attach, and the memory image is
    # the principal source both times — the capture carries its own parser.
    assert [Path(str(call["image_path"])) for call in calls] == [memory, memory]


def test_the_index_is_built_without_being_asked_for(tmp_path, monkeypatch):
    """There is no switch: opening a case prepays the scan, every time."""

    calls = _recorded_index(monkeypatch)
    hashed = _recorded_hashes(monkeypatch)
    memory = _memory_dump(tmp_path)

    session = InteractiveSession(_session_args(tmp_path), console=_console())
    try:
        session.attach_memory(str(memory))
    finally:
        session.close()

    assert [Path(str(call["image_path"])) for call in calls] == [memory]
    assert hashed == [str(memory)]
    assert not hasattr(_case_index, "INDEX_ON_OPEN_ENVIRONMENT_VARIABLE")
    assert not hasattr(_case_index, "INDEX_NOT_REQUESTED")


def test_the_source_is_hashed_once_however_often_the_case_reopens(tmp_path, monkeypatch):
    """The digest is cached per path, so a second bind re-reads nothing."""

    _recorded_index(monkeypatch)
    hashed = _recorded_hashes(monkeypatch)
    memory = _memory_dump(tmp_path)
    capture = _capture(tmp_path)

    session = InteractiveSession(_session_args(tmp_path), console=_console())
    try:
        session.attach_memory(str(memory))
        session.attach_pcap(str(capture))
    finally:
        session.close()

    # The memory dump is bound twice — once on its own, once beside the
    # capture — and hashed exactly once.
    assert hashed == [str(memory), str(capture)]


def test_every_bound_source_carries_a_digest(tmp_path, monkeypatch):
    """The capture is digested too, not only the image the scanner reads."""

    _recorded_index(monkeypatch)
    _recorded_hashes(monkeypatch)
    memory = _memory_dump(tmp_path)
    capture = _capture(tmp_path)

    session = InteractiveSession(_session_args(tmp_path), console=_console())
    try:
        session.attach_memory(str(memory))
        session.attach_pcap(str(capture))
        digests = session.source_digests()
        session.show_sources()
        rendered = session._console.file.getvalue()
    finally:
        session.close()

    assert digests[str(memory)] == "ab" * 32
    assert digests[str(capture)] == "ab" * 32
    assert "sha256:" in rendered
    # "not computed" postao je "none recorded": stara formulacija govorila je
    # o tome što je program (ne) izračunao, a operateru je važno samo da za
    # taj izvor nema zapisanog digesta.
    assert "none recorded" not in rendered


def test_a_source_that_cannot_be_hashed_still_opens_the_case(tmp_path, monkeypatch):
    """A digest is recorded or stated absent; it never refuses the case.

    Odsutnost se izriče s "none recorded". Ranije je pisalo "not computed",
    što je opisivalo unutarnji korak programa umjesto stanja zapisa koje
    operater čita.
    """

    _recorded_index(monkeypatch)
    monkeypatch.setattr(
        _audit,
        "sha256_file",
        lambda path, *args, **kwargs: (_ for _ in ()).throw(OSError("unreadable")),
    )
    capture = _capture(tmp_path)

    session = InteractiveSession(_session_args(tmp_path), console=_console())
    try:
        session.attach_pcap(str(capture))
        assert session.source_digests() == {}
        session.show_sources()
        rendered = session._console.file.getvalue()
    finally:
        session.close()

    assert "none recorded" in rendered


def test_continue_reopens_and_indexes(tmp_path, monkeypatch):
    calls = _recorded_index(monkeypatch)
    memory = _memory_dump(tmp_path)

    session = InteractiveSession(_session_args(tmp_path), console=_console())
    try:
        session.open_typed_case("memory", str(memory))
        session._history.ensure_started()
        session._history.record_answer(
            "what ran on this host?",
            "an answer",
            audit_ref=str(tmp_path / "audit.jsonl"),
            verification_ref=str(tmp_path / "oversight.jsonl"),
            turn_id="turn-1",
        )
        # The state /continue is typed in: the saved investigation is no longer
        # the active one and no evidence is open.
        session._history.discard()
        session.clear_evidence()
        calls.clear()
        session.continue_investigation()
        assert session.memory == str(memory), "the evidence was not reopened"
    finally:
        session.close()

    assert [Path(str(call["image_path"])) for call in calls] == [memory]


class _RunnerWithoutReuse:
    """A runtime built before the reuse keyword existed; it must still be called."""

    provider = "stub"

    def __init__(self) -> None:
        self.seen: dict[str, object] | None = None

    def ask(
        self,
        question,
        *,
        case_context=None,
        disk=None,
        memory_path=None,
        pcap_path=None,
        pcap_sources=None,
        case_id=None,
        case_evidence_source=None,
        case_roots=(),
        on_tool=None,
        tool_exposure="",
    ):
        self.seen = {"memory_path": memory_path}
        raise RuntimeError("stub runner")


class _RunnerWithReuse(_RunnerWithoutReuse):
    def ask(self, question, *, memory_sha256=None, **rest):
        self.seen = {"memory_sha256": memory_sha256}
        raise RuntimeError("stub runner")


def _asked_with(tmp_path, monkeypatch, runner) -> dict[str, object] | None:
    _recorded_index(monkeypatch)
    monkeypatch.setattr(_scope_check, "question_in_scope", lambda *a, **k: True)
    memory = _memory_dump(tmp_path)

    session = InteractiveSession(_session_args(tmp_path), console=_console())
    try:
        session.attach_memory(str(memory))
        session._runner = runner
        assert session.ask("what ran on this host?") is False
    finally:
        session.close()
    return runner.seen


def test_the_open_digest_reaches_a_runtime_that_takes_it(tmp_path, monkeypatch):
    runner = _RunnerWithReuse()
    seen = _asked_with(tmp_path, monkeypatch, runner)

    assert seen is not None
    assert seen["memory_sha256"]


def test_a_runtime_without_the_keyword_is_still_callable(tmp_path, monkeypatch):
    runner = _RunnerWithoutReuse()
    seen = _asked_with(tmp_path, monkeypatch, runner)

    assert seen == {"memory_path": seen["memory_path"]}
    assert not _accepts_keyword(runner.ask, "memory_sha256")


# ---------------------------------------------------------------------------
# What a front end is told while all of that runs
# ---------------------------------------------------------------------------
# The console was reporting every one of these steps under the single label
# "indexing evidence", so an operator watching a memory dump being hashed was
# told the console was doing something it had not started yet. Each step now
# names itself, once, for its whole duration.
def test_each_long_step_of_an_open_names_itself_to_the_front_end(tmp_path, monkeypatch):
    calls = _recorded_index(monkeypatch)
    memory = _memory_dump(tmp_path)
    capture = _capture(tmp_path)
    reported: list[tuple[float | None, str | None]] = []

    session = InteractiveSession(_session_args(tmp_path), console=_console())
    session._index_progress = lambda fraction=None, detail=None: reported.append(
        (fraction, detail)
    )
    try:
        session.open_typed_case("memory", str(memory))
        session.attach_pcap(str(capture))
    finally:
        session.close()

    assert calls, "the index was never asked for"
    names = {detail for _, detail in reported}
    assert "Hashing memory.raw" in names
    assert "Hashing capture.pcap" in names
    # One name per source, and never the index's name for a hash.
    assert "Indexing evidence" not in names


def test_the_index_build_is_named_before_the_scan_is_even_asked_for(tmp_path, monkeypatch):
    """Deciding whether a published scan can be reused already stats a tree.

    A row that appeared only once the scanner started would leave that part of
    the wait unaccounted for, which is the same silence in a smaller window.
    """

    from forensic_agent.cli.case_index import index_opened_case

    reported: list[tuple[float | None, str | None]] = []
    asked: list[str | None] = []
    monkeypatch.setattr(
        "forensic_agent.tools.bulk_extractor_tool.prewarm_default_scan",
        lambda image_path, *, evidence_sha256=None, progress=None: (
            asked.append(str(image_path))
            or {"state": "unavailable", "detail": "no scanner here"}
        ),
    )
    image = _memory_dump(tmp_path, "image.raw")

    index_opened_case(
        _console(),
        image_path=str(image),
        runs_root=tmp_path,
        evidence_sha256="ab" * 32,
        progress=lambda fraction=None, detail=None: reported.append((fraction, detail)),
    )

    assert asked == [str(image)]
    assert reported[0] == (None, "Indexing evidence")
