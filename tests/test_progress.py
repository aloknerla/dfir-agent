"""Progress reporting for long operations.

Two properties are pinned here because breaking either is silent. Progress
describes how fast this host happened to be, so it must never reach the model or
a receipt; and it must never be able to fail the work it is reporting on, since
an operator waiting on a scan would lose the scan to a rendering fault.
"""

from io import StringIO

import pytest
from rich.console import Console

import forensic_agent.core.audit as _audit
from forensic_agent.cli.progress import reporting, sha256_file_reporting


def _console(*, terminal: bool) -> tuple[Console, StringIO]:
    stream = StringIO()
    return Console(file=stream, force_terminal=terminal, width=100), stream


def test_a_disabled_reporter_still_yields_a_callable_and_prints_nothing():
    """Callers must not need a branch for the switched-off case."""

    console, stream = _console(terminal=False)
    with reporting(console, "Indexing evidence", enabled=False) as report:
        report(0.5, "half")
        report()
    assert stream.getvalue() == ""


def test_a_redirected_stream_records_that_work_advanced():
    console, stream = _console(terminal=False)
    clock = iter([0.0, 100.0, 200.0])
    with reporting(console, "Indexing evidence", clock=lambda: next(clock)) as report:
        report(0.25, "reading")
        report(0.75, "writing")
    text = stream.getvalue()
    assert "Indexing evidence" in text
    assert "25%" in text and "75%" in text
    assert "done" in text


def test_a_redirected_stream_is_not_filled_with_redraws():
    """A batch transcript records that a scan advanced, not every percent of it."""

    console, stream = _console(terminal=False)
    with reporting(console, "Indexing evidence", clock=lambda: 0.0) as report:
        for step in range(200):
            report(step / 200)
    # The opening line, the first sample, and the closing line: two hundred
    # updates inside one interval add nothing after that.
    assert stream.getvalue().count("Indexing evidence") == 3


def test_an_operation_that_cannot_estimate_reports_no_percentage():
    """An operation that only knows it is still running must not invent a number."""

    console, stream = _console(terminal=False)
    clock = iter([0.0, 100.0])
    with reporting(console, "Indexing evidence", clock=lambda: next(clock)) as report:
        report(None, "scanning")
    text = stream.getvalue()
    assert "scanning" in text
    assert "%" not in text


def test_a_terminal_renders_live_and_leaves_nothing_behind():
    console, stream = _console(terminal=True)
    with reporting(console, "Indexing evidence") as report:
        report(0.4, "reading")
    # The live renderer is transient, so the finished console carries no bar.
    assert "Indexing evidence" not in stream.getvalue().split("\n")[-1]


def test_a_failing_renderer_does_not_fail_the_work(monkeypatch):
    """A rendering fault is a reason to fall silent, never to abandon a scan."""

    console, _ = _console(terminal=True)
    import forensic_agent.cli.progress as progress_module

    class _Broken(progress_module.Progress):  # type: ignore[misc]
        def update(self, *args, **kwargs):  # noqa: ANN002, ANN003, ANN201
            raise RuntimeError("terminal went away")

    monkeypatch.setattr(progress_module, "Progress", _Broken)

    performed = []
    with reporting(console, "Indexing evidence") as report:
        report(0.5, "reading")
        performed.append("work continued")
    assert performed == ["work continued"]


def test_an_exception_in_the_work_still_tears_the_renderer_down():
    console, _ = _console(terminal=True)
    with pytest.raises(ValueError):
        with reporting(console, "Indexing evidence") as report:
            report(0.1)
            raise ValueError("the scan failed")


# ---------------------------------------------------------------------------
# A digest that says where it is
# ---------------------------------------------------------------------------
# Hashing a memory image is one of the three steps of opening a case that runs
# for minutes, and it was the one with nothing to watch: a single call that
# returned when the whole file had been read. The console could say that hashing
# had started and then nothing until it ended, which is exactly what a hang
# looks like.
def _sample(tmp_path, name="memory.raw", blocks=8):
    path = tmp_path / name
    path.write_bytes(b"m" * (blocks * 4096))
    return path


def test_with_no_observer_it_is_the_plain_digest_by_name(tmp_path, monkeypatch):
    """A substituted digest must still be the one that runs.

    The plain read is deliberately delegated rather than reimplemented beside
    the reporting one: a host with a faster implementation, and every test that
    replaces it, has to keep working through this path unchanged.
    """

    called: list[str] = []
    monkeypatch.setattr(
        _audit, "sha256_file", lambda path, *a, **k: called.append(str(path)) or "ab" * 32
    )
    sample = _sample(tmp_path)

    assert sha256_file_reporting(str(sample)) == "ab" * 32
    assert called == [str(sample)]


def test_the_reported_digest_is_the_same_digest(tmp_path):
    """Reporting changes what is said about the read, never what it read."""

    sample = _sample(tmp_path)
    plain = sha256_file_reporting(str(sample))
    reported = sha256_file_reporting(str(sample), report=lambda *_a, **_k: None)

    assert reported == plain


def test_the_fraction_is_measured_and_it_advances(tmp_path, monkeypatch):
    monkeypatch.setattr("forensic_agent.cli.progress._DIGEST_BLOCK_BYTES", 4096)
    monkeypatch.setattr("forensic_agent.cli.progress._DIGEST_INTERVAL_SECONDS", 0.0)
    seen: list[tuple[float | None, str | None]] = []
    sample = _sample(tmp_path, blocks=8)

    sha256_file_reporting(
        str(sample),
        report=lambda fraction=None, detail=None: seen.append((fraction, detail)),
        detail="Hashing memory.raw",
    )

    fractions = [fraction for fraction, _ in seen]
    assert len(fractions) > 1
    assert fractions == sorted(fractions)
    assert fractions[-1] == pytest.approx(1.0)
    # The step names itself for the whole read, so the console can say WHICH of
    # a case's long steps the operator is waiting on.
    assert {detail for _, detail in seen} == {"Hashing memory.raw"}


def test_a_report_that_raises_does_not_lose_the_digest(tmp_path, monkeypatch):
    """The evidence is the work; the bar is only the report of it."""

    monkeypatch.setattr("forensic_agent.cli.progress._DIGEST_INTERVAL_SECONDS", 0.0)
    sample = _sample(tmp_path)

    def broken(fraction=None, detail=None):
        raise RuntimeError("the console went away")

    assert sha256_file_reporting(str(sample), report=broken) == sha256_file_reporting(
        str(sample)
    )


def test_an_empty_file_reports_no_percentage_and_still_digests(tmp_path):
    """Nothing to measure is not a reason to invent a number, or to fail."""

    empty = tmp_path / "empty.raw"
    empty.write_bytes(b"")
    seen: list[float | None] = []

    digest = sha256_file_reporting(
        str(empty), report=lambda fraction=None, detail=None: seen.append(fraction)
    )

    assert digest == sha256_file_reporting(str(empty))
    assert seen == []
