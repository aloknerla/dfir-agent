"""What the console shows while a case opens, driven through the real app.

The complaint these pin is that opening a case said nothing for what could be
minutes and then produced a burst of completion lines. The hooks that were meant
to prevent that were installed and did fire; what they fed was a row rendered
only when an event arrived, and two of the three long steps of an open report
exactly once — at their start — and then block. The memory digest blocked inside
a single read with no callback at all, and the entity index blocks inside a
scanner subprocess whose output is captured rather than streamed. So the row
appeared, froze, and was indistinguishable from a hang for precisely the wait it
existed to explain.

Every test here therefore drives the real :class:`InvestigationApp` through
Textual's pilot against a real session and reads the rendered characters back
WHILE the open is in flight. A test that only checked a hook was installed is
the test that let this through.
"""

from __future__ import annotations

import asyncio
import io
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("textual")

from rich.console import Console  # noqa: E402

import forensic_agent.core.evidence_source as _evidence_source  # noqa: E402
import forensic_agent.tools.bulk_extractor_tool as _bulk  # noqa: E402
from forensic_agent.cli.session import InteractiveSession  # noqa: E402
from forensic_agent.tui import build_app  # noqa: E402
from forensic_agent.tui.app import _CaseStep  # noqa: E402
from forensic_agent.tui.controller import LiveController  # noqa: E402


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


def _live_app(tmp_path: Path):
    """The real console over a real session, with the session's console silent."""

    quiet = Console(file=io.StringIO(), force_terminal=False, width=100)
    session = InteractiveSession(_session_args(tmp_path), console=quiet)
    return build_app(LiveController(session)), session


def _screen(app) -> str:
    """The characters actually on screen, straight off the compositor."""

    return "\n".join(strip.text for strip in app.screen._compositor.render_strips())


def _progress_row(app) -> str:
    """The case-progress row as the operator would read it, or "" when absent."""

    from textual.widgets import Static

    for widget in app.query("#caseprog").results(Static):
        return str(getattr(widget, "content", ""))
    return ""


async def _drive(pilot, app, command: str, argument: str, *, samples: int = 300):
    """Run one case command and collect the progress row while it is in flight."""

    rows: list[str] = []
    screens: list[str] = []
    app.dispatch_command(command, argument)
    settled = 0
    for _ in range(samples):
        await pilot.pause(0.02)
        if app._case_op_alive:
            row = _progress_row(app)
            if row:
                rows.append(row)
                screens.append(_screen(app))
            continue
        # The worker hands the closing lines back across the thread boundary,
        # so the open is not over when the flag drops; tearing the app down
        # under that hand-off is a fault of the harness, not of the console.
        settled += 1
        if settled > 20 and "Case opened" in _screen(app):
            break
    return rows, screens


def _resolution_that_only_takes_time(monkeypatch, seconds: float = 0.4) -> None:
    """Stand the dfVFS half of the open in for what it is here: a wait.

    Preparing a disk is two consecutive halves. The medium is streamed through
    SHA-256, and then dfVFS resolves partitions and file systems — reporting
    nothing while it does, which is the whole reason the row has to be renamed
    when the byte count runs out. Everything this test reads is painted by the
    first half and by that rename; the second half contributes only its
    duration.

    Eight megabytes of zeroes hold no partition table and no file system, so
    dfVFS can never resolve anything here whether or not it is installed. What
    it would contribute is therefore replaced by the one thing it really does
    contribute — time on the clock — and that makes this test say the same
    thing on every host:

    * a checkout installing only the ``dev`` extra has no dfVFS at all, and
      ``DiskImage`` refuses to construct without it, so the open used to fail
      before a single byte was read and the row was never painted once;
    * a workstation carrying the ``forensics`` extra reaches a real scan that
      fails on the zeroes in a few milliseconds, which is shorter than the
      interval this test samples at, so the renamed step could vanish between
      two reads of the row.

    The digest above it is untouched: real bytes, the real attestation pass,
    the real observers, and every line they paint.
    """

    import forensic_agent.tools.tsk_tool as _tsk

    def resolve_nothing_slowly(self, fs_offset: int | None) -> None:
        time.sleep(seconds)

    monkeypatch.setattr(_tsk, "HAVE_DFVFS", True)
    monkeypatch.setattr(_tsk.DiskImage, "_open_filesystems", resolve_nothing_slowly)


def _stream_the_medium_at_a_watchable_pace(monkeypatch, per_block: float = 0.05) -> None:
    """Give the digest of a test-sized image the duration of a real one.

    The row is read by sampling the running console, so a step that begins and
    ends between two samples is a step this test cannot see — and eight
    megabytes of zeroes hash in less time than one frame takes to draw, which
    made the digest disappear on a fast host and left the row apparently
    stepping from "Opening" straight to "Resolving". The complaint being
    pinned is about a step that runs for minutes, so the medium is made to
    read at a pace an operator would actually be waiting through, exactly as
    the index-build test above holds its scanner open for 1.2 seconds.

    Only the pace is borrowed. The bytes, the digest, the observers and every
    line they paint are the real ones.
    """

    from forensic_agent.tui.app import InvestigationApp

    watch_case_open = InvestigationApp._watch_case_open

    def slowed(self, resolved: str):
        advance, declare_total = watch_case_open(self, resolved)

        def read_one_block(byte_count: int) -> None:
            time.sleep(per_block)
            advance(byte_count)

        return read_one_block, declare_total

    monkeypatch.setattr(InvestigationApp, "_watch_case_open", slowed)


def _distinct(values: list[str]) -> list[str]:
    seen: list[str] = []
    for value in values:
        if not seen or seen[-1] != value:
            seen.append(value)
    return seen


# ---------------------------------------------------------------------------
# the three long steps
# ---------------------------------------------------------------------------
def test_the_index_build_paints_a_moving_indicator_while_it_blocks(
    tmp_path, monkeypatch
):
    """The step that reports once and then blocks is the whole complaint.

    ``prewarm_default_scan`` announces itself and then waits inside a scanner
    subprocess whose output is captured, so no second event is possible. The row
    must still be visibly alive, and it must say WHICH step is running.
    """

    def slow_scan(image_path, *, evidence_sha256=None, progress=None):
        if progress is not None:
            progress(None, "scanning the whole image with bulk_extractor")
        time.sleep(1.2)
        return {"state": "unavailable", "detail": "no scanner in this test"}

    monkeypatch.setattr(_bulk, "prewarm_default_scan", slow_scan)
    memory = tmp_path / "memory.raw"
    memory.write_bytes(b"m" * (1 << 20))

    async def scenario():
        app, session = _live_app(tmp_path)
        try:
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause(0.1)
                rows, screens = await _drive(pilot, app, "case", f"memory {memory}")
        finally:
            session.close()
        return rows, screens

    rows, screens = asyncio.run(scenario())

    indexing = [row for row in rows if "Indexing evidence" in row]
    assert indexing, "the index build named no step at all"
    # The name reached the rendered screen, not merely a widget nobody drew.
    assert any("Indexing evidence" in screen for screen in screens)
    # Alive: the spinner turned, and the clock the operator reads went up.
    glyphs = {row.strip()[0] for row in indexing}
    assert len(glyphs) > 1, f"the indicator never moved: {_distinct(indexing)}"
    assert len(_distinct(indexing)) > 2
    # Nothing measured this step, so nothing claims to have.
    assert not any("%" in row for row in indexing)


def test_hashing_a_memory_image_reports_a_measured_fraction(tmp_path, monkeypatch):
    """The hash used to be one static line for the whole read; now it moves."""

    monkeypatch.setattr(
        "forensic_agent.cli.progress._DIGEST_BLOCK_BYTES", 4096, raising=True
    )
    monkeypatch.setattr(
        "forensic_agent.cli.progress._DIGEST_INTERVAL_SECONDS", 0.0, raising=True
    )
    memory = tmp_path / "memory.raw"
    memory.write_bytes(b"m" * (12 << 20))

    async def scenario():
        app, session = _live_app(tmp_path)
        try:
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause(0.1)
                rows, screens = await _drive(pilot, app, "case", f"memory {memory}")
        finally:
            session.close()
        return rows, screens

    rows, screens = asyncio.run(scenario())

    hashing = [row for row in rows if "Hashing memory.raw" in row]
    assert hashing, f"the memory hash named no step: {_distinct(rows)}"
    assert any("Hashing memory.raw" in screen for screen in screens)
    # A measured fraction, and more than one of them: a bar that never moved is
    # the same silence with extra characters.
    percentages = {row.split("%")[0][-4:] for row in hashing if "%" in row}
    assert len(percentages) > 1, f"the fraction never advanced: {_distinct(hashing)}"


def test_the_digest_names_its_step_and_then_names_the_one_after_it(
    tmp_path, monkeypatch
):
    """A bar standing at 100% while dfVFS still resolves says the work is done.

    The two halves of preparing a disk are consecutive, and only the first can
    be measured, so the row has to change its name when the bytes run out.
    """

    _resolution_that_only_takes_time(monkeypatch)
    _stream_the_medium_at_a_watchable_pace(monkeypatch)
    # Eight blocks for the eight megabytes below: enough of them for the bar to
    # be measured against the total and seen to advance, few enough that the
    # pace above costs a fraction of a second rather than the two minutes the
    # same pace over 4 kB blocks would.
    monkeypatch.setattr(_evidence_source, "EVIDENCE_HASH_CHUNK_BYTES", 1 << 20)
    image = tmp_path / "image.dd"
    image.write_bytes(b"\x00" * (8 << 20))

    async def scenario():
        app, session = _live_app(tmp_path)
        try:
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause(0.1)
                rows, screens = await _drive(pilot, app, "case", f"disk {image}")
        finally:
            session.close()
        return rows, screens

    rows, screens = asyncio.run(scenario())

    verifying = [row for row in rows if "Verifying image.dd" in row]
    resolving = [row for row in rows if "Resolving partitions and file systems" in row]
    assert verifying, f"the digest named no step: {_distinct(rows)}"
    assert resolving, f"the resolution step was never named: {_distinct(rows)}"
    assert any("Verifying image.dd" in screen for screen in screens)
    # The digest is measured against the total the attestation stated, and it
    # advances; the resolution is not measured and claims no percentage.
    assert any("%" in row for row in verifying)
    assert not any("%" in row for row in resolving)
    # And it happens in that order: the medium is read, then it is resolved.
    assert rows.index(verifying[0]) < rows.index(resolving[0])


# ---------------------------------------------------------------------------
# the rules the row is drawn under
# ---------------------------------------------------------------------------
def test_a_step_nothing_measured_shows_no_percentage_at_all():
    """"Still running" is honest; a number nobody measured is not."""

    step = _CaseStep("Indexing evidence")
    assert step.measured() is None


def test_a_measured_step_is_clamped_to_what_it_can_have_done():
    """A source that decodes to more than the console can see once ran past 100%."""

    step = _CaseStep("Verifying image.dd", done=0, total=100)
    step.done = 250
    assert step.measured() == 1.0
    step.done = -5
    assert step.measured() == 0.0


def test_a_stated_total_of_zero_is_not_a_division():
    step = _CaseStep("Verifying empty.dd", done=0, total=0)
    assert step.measured() is None


def test_the_clock_starts_when_the_step_does():
    step = _CaseStep("Indexing evidence")
    time.sleep(0.05)
    assert step.elapsed() >= 0.04
