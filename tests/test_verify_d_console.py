"""What ``/verify`` does, driven through the real console.

The command exists because the console has always told the operator it did: the
line printed on every reused attestation named ``/verify``, and typing it
answered "unknown command". A command added to answer that promise is worth
nothing unless it keeps the promise, and the promise is the READING. So the
trap these tests exist to pin is not a missing registry entry.

``verify_image_integrity`` carries a reuse path. Given a disk whose digests this
process already established, it returns them without opening the medium at all.
That is right for the agent, which asks the question inside a run that already
paid for the pass. It is exactly wrong for an operator who typed a command in
order to have the evidence read: the console would print a digest, say integrity
was verified, and have touched nothing. The first test below is therefore about
a fast path NOT being taken.

The rest drive :class:`InvestigationApp` headlessly through Textual's pilot and
read the characters off the compositor, because three earlier fixes in this
project were reported green while the console was broken in the owner's hands.
The digest-differs case is constructed rather than asserted at: the file's bytes
are replaced between the digest the case recorded and the digest the command
recomputes, which is the situation the red block is for.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("textual")

from rich.console import Console  # noqa: E402

import forensic_agent.core.evidence_source as _evidence_source  # noqa: E402
import forensic_agent.tools.integrity_tool as _integrity  # noqa: E402
from forensic_agent.cli.session import InteractiveSession  # noqa: E402
from forensic_agent.tui import build_app  # noqa: E402
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
    quiet = Console(file=io.StringIO(), force_terminal=False, width=100)
    session = InteractiveSession(_session_args(tmp_path), console=quiet)
    return build_app(LiveController(session)), session


def _bound_disk(path: Path, recorded_sha256: str):
    """The evidence binding ``/verify`` reads, without a filesystem parse.

    ``/verify`` asks the disk for three things: where the medium is, how large
    it is, and the digest the case was opened under. It never touches the
    partition table or the file system, and forcing the stream means the reuse
    path that inspects a real ``DiskImage`` is not consulted either. Binding
    those three facts directly keeps the test over the real streaming code
    rather than over dfVFS's ability to find a volume in a scratch file.
    """

    return SimpleNamespace(
        image_path=str(path),
        image_sha=recorded_sha256,
        image_size=path.stat().st_size,
        audit=None,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def _screen(app) -> str:
    return "\n".join(strip.text for strip in app.screen._compositor.render_strips())


def _progress_row(app) -> str:
    from textual.widgets import Static

    for widget in app.query("#caseprog").results(Static):
        return str(getattr(widget, "content", ""))
    return ""


def _distinct(values: list[str]) -> list[str]:
    seen: list[str] = []
    for value in values:
        if not seen or seen[-1] != value:
            seen.append(value)
    return seen


# ---------------------------------------------------------------------------
# the fast path that would make the command a lie
# ---------------------------------------------------------------------------
def test_a_forced_verification_never_answers_from_a_stored_attestation(
    tmp_path, monkeypatch
):
    """A reusable attestation must not stand in for the reading.

    The reuse branch is left in place and is deliberately made to look
    available here: if the flag did not suppress it, this test would get the
    stored digest back with ``attestation_reused`` set and no read at all.
    """

    image = tmp_path / "image.dd"
    image.write_bytes(b"\x01" * (1 << 16))
    stored = SimpleNamespace(
        size_bytes=image.stat().st_size,
        md5="0" * 32,
        sha1="0" * 40,
        sha256="0" * 64,
    )
    monkeypatch.setattr(
        _integrity, "_reusable_raw_hash_attestation", lambda disk: stored
    )
    disk = _bound_disk(image, _sha256(image))

    reused = _integrity.verify_image_integrity(disk)
    forced = _integrity.verify_image_integrity(disk, force_full_stream=True)

    assert reused["attestation_reused"] is True
    assert reused["sha256"] == "0" * 64
    # Forcing it read the medium: the digest is the file's own, and the record
    # of what happened says so rather than claiming a reading it did not do.
    assert forced["attestation_reused"] is False
    assert forced["sha256"] == _sha256(image)


def test_the_forced_pass_reports_the_bytes_it_reads(tmp_path):
    """Progress is measured off the stream, not estimated beside it."""

    image = tmp_path / "image.dd"
    image.write_bytes(b"\x02" * (1 << 20))
    seen: list[int] = []
    totals: list[int] = []

    _integrity.verify_image_integrity(
        _bound_disk(image, _sha256(image)),
        force_full_stream=True,
        progress=seen.append,
        progress_total=totals.append,
    )

    assert totals == [1 << 20]
    assert sum(seen) == 1 << 20


def test_verifying_without_a_disk_says_so_rather_than_reading_nothing(tmp_path):
    session = InteractiveSession(
        _session_args(tmp_path), console=Console(file=io.StringIO(), width=100)
    )
    try:
        assert session.verifiable_medium() is None
        with pytest.raises(ValueError):
            session.verify_evidence_integrity()
    finally:
        session.close()


# ---------------------------------------------------------------------------
# the console, driven
# ---------------------------------------------------------------------------
async def _await_confirmation(pilot, app, *, samples: int = 200) -> str:
    """Wait for the confirmation to be on screen, and return what it says."""

    for _ in range(samples):
        await pilot.pause(0.02)
        rendered = _screen(app)
        if "read all" in rendered:
            return rendered
    return _screen(app)


async def _settle(pilot, app, *, samples: int = 600):
    """Sample the progress row until the operation lets go of the console."""

    rows: list[str] = []
    screens: list[str] = []
    for _ in range(samples):
        await pilot.pause(0.02)
        row = _progress_row(app)
        if row:
            rows.append(row)
            screens.append(_screen(app))
        elif not app._case_op_alive and rows:
            break
    for _ in range(40):
        await pilot.pause(0.02)
    return rows, screens


def _hold_the_pass_open(monkeypatch, *, seconds: float = 0.004) -> None:
    """Make a scratch medium take as long to read as a real one does.

    Evidence this command is for runs to gigabytes and takes minutes; a
    two-megabyte temporary file is read in about eight milliseconds, which is
    less than one frame. A display cannot be observed in a window shorter than
    the act of looking, so the observer the console installs is wrapped to
    pause per block, holding the pass open for about a second.

    The delay is in the wrapper and nothing else is substituted: the wrapped
    observer is the console's own, driving the console's own row, called from
    inside the real streaming loop at the real block boundaries.
    """

    import time as _time

    from forensic_agent.tui.app import InvestigationApp

    original = InvestigationApp._watch_integrity_stream

    def watch(self, resolved):
        advance, declare_total = original(self, resolved)

        def slowed(byte_count: int) -> None:
            _time.sleep(seconds)
            advance(byte_count)

        return slowed, declare_total

    monkeypatch.setattr(InvestigationApp, "_watch_integrity_stream", watch)


def test_the_confirmation_states_the_size_and_cancelling_reads_nothing(
    tmp_path, monkeypatch
):
    """The operator is told what the pass costs, and may decline it.

    Declining has to mean the evidence was not touched. The hashing entry point
    is wrapped so a single read would be visible; the assertion is that no read
    happened at all, not that the command returned quickly.
    """

    image = tmp_path / "image.dd"
    image.write_bytes(b"\x03" * (4 << 20))
    calls: list[str] = []
    real = _integrity.hash_image
    monkeypatch.setattr(
        _integrity,
        "hash_image",
        lambda path, **kw: (calls.append(path), real(path, **kw))[1],
    )

    async def scenario():
        app, session = _live_app(tmp_path)
        try:
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause(0.1)
                session.disk = _bound_disk(image, _sha256(image))
                session.disk_label = image.name
                app.dispatch_command("verify", "")
                asked = await _await_confirmation(pilot, app)
                await pilot.press("escape")
                for _ in range(40):
                    await pilot.pause(0.02)
                return asked, _screen(app), _progress_row(app)
        finally:
            session.close()

    asked, after, row = asyncio.run(scenario())

    # The size is on screen, in the words the confirmation asks in.
    assert "image.dd" in asked
    assert "4.2 MB" in asked
    assert "read all" in asked
    # Cancelled: nothing was hashed, and no progress row was ever painted.
    assert calls == []
    assert row == ""
    assert "The evidence is unchanged" not in after


def test_confirming_streams_the_medium_and_paints_it_while_it_runs(
    tmp_path, monkeypatch
):
    """The defect Group C fixed everywhere else must not return here.

    A minutes-long read with a still screen is indistinguishable from a hang.
    The row is read back off the compositor WHILE the pass is in flight, and it
    has to name the step and carry a fraction that moves.
    """

    monkeypatch.setattr(_evidence_source, "EVIDENCE_HASH_CHUNK_BYTES", 4096)
    _hold_the_pass_open(monkeypatch)
    image = tmp_path / "image.dd"
    image.write_bytes(b"\x04" * (1 << 20))

    async def scenario():
        app, session = _live_app(tmp_path)
        try:
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause(0.1)
                session.disk = _bound_disk(image, _sha256(image))
                session.disk_label = image.name
                app.dispatch_command("verify", "")
                await _await_confirmation(pilot, app)
                await pilot.press("enter")
                rows, screens = await _settle(pilot, app)
                return rows, screens, _screen(app)
        finally:
            session.close()

    rows, screens, final = asyncio.run(scenario())

    verifying = [row for row in rows if "Verifying image.dd" in row]
    assert verifying, f"the verification named no step: {_distinct(rows)}"
    # It reached the rendered screen, not merely a widget nobody drew.
    assert any("Verifying image.dd" in screen for screen in screens)
    # Measured against the total the pass stated, and it advanced.
    percentages = {row.split("%")[0][-4:] for row in verifying if "%" in row}
    assert len(percentages) > 1, f"the fraction never moved: {_distinct(verifying)}"
    # And the verdict is the unchanged one, in its own words.
    assert "The evidence is unchanged." in final
    assert "THE EVIDENCE DIGEST HAS CHANGED" not in final


def test_a_changed_medium_is_not_reported_in_the_words_of_an_unchanged_one(
    tmp_path, monkeypatch
):
    """The bytes really change between the recorded digest and the read one.

    Constructed rather than stubbed: the file is written, its digest is what
    the case is bound to, and then the file is replaced. That is the situation
    the red block exists for, and it is the only way to see the block.
    """

    monkeypatch.setattr(_evidence_source, "EVIDENCE_HASH_CHUNK_BYTES", 4096)
    image = tmp_path / "image.dd"
    image.write_bytes(b"\x05" * (2 << 20))
    recorded = _sha256(image)

    async def scenario():
        app, session = _live_app(tmp_path)
        try:
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause(0.1)
                session.disk = _bound_disk(image, recorded)
                session.disk_label = image.name
                # The medium is altered after the case bound it.
                image.write_bytes(b"\x06" * (2 << 20))
                app.dispatch_command("verify", "")
                await _await_confirmation(pilot, app)
                await pilot.press("enter")
                await _settle(pilot, app)
                return _screen(app)
        finally:
            session.close()

    final = asyncio.run(scenario())

    assert "THE EVIDENCE DIGEST HAS CHANGED." in final
    # The two outcomes do not read alike: none of the reassuring sentence
    # survives into the alarming one.
    assert "The evidence is unchanged." not in final
    assert "still stand" not in final
    # Both digests are shown, so the operator can see where they part.
    assert recorded[:16] in final
    assert _sha256(image)[:16] in final
    assert "recorded when the case opened" in final
    assert "read from the medium just now" in final


def test_the_command_is_declared_where_the_console_looks_for_it():
    """A promise the console prints has to resolve to a command it has."""

    from forensic_agent.cli.commands import COMMAND_REGISTRY, parse_command

    spec = COMMAND_REGISTRY.resolve("verify")
    assert spec is not None
    # The description says what the command does to the medium, because the
    # cost is the thing an operator needs from the listing.
    assert "entire medium" in spec.description
    assert parse_command("/verify") is not None

    from forensic_agent.tui.app import InvestigationApp

    assert callable(getattr(InvestigationApp, "_cmd_verify", None))


# ---------------------------------------------------------------------------
# the line that names /verify, and the wrap that split it in two
# ---------------------------------------------------------------------------
def _reused_attestation_output(tmp_path: Path, *, width: int) -> str:
    """The reused-attestation announcement, rendered at a wrapping width."""

    console = Console(
        file=io.StringIO(),
        width=width,
        force_terminal=True,
        color_system="truecolor",
        legacy_windows=False,
        highlight=False,
    )
    session = InteractiveSession(_session_args(tmp_path), console=console)
    try:
        session._announce_disk_integrity(
            SimpleNamespace(
                evidence_attestation_reused=True,
                attested_at="2026-08-17T16:34:01+0000",
                image_sha="65e2002fed0b286f" + "0" * 48,
            )
        )
    finally:
        session.close()
    return console.file.getvalue()


def test_the_reused_attestation_line_survives_its_own_wrap(tmp_path):
    """One message must not arrive looking like two.

    The old line was a glyph and three statements in one sentence. At any
    ordinary width it wrapped, and the continuation began at column zero with
    no glyph: in the shell it read as a separate dim note, and in the
    full-screen console, which colours a recorded line by the glyph it starts
    with, it was literally painted as one. Every line after the lead therefore
    has to keep an indent of its own, wrap included.
    """

    import re

    rendered = _reused_attestation_output(tmp_path, width=64)
    lines = [
        re.sub(r"\x1b\[[0-9;]*m", "", line)
        for line in rendered.rstrip("\n").split("\n")
    ]

    assert len(lines) > 3, "the message should be several short statements"
    assert lines[0].startswith("✓ "), lines[0]
    # Every later line, wrap included, is indented under the lead. A line back
    # at column zero is the defect, whether it is a new statement or the tail
    # of one.
    assert all(line.startswith("  ") for line in lines[1:]), lines


def test_the_reused_attestation_line_states_a_readable_moment(tmp_path):
    """A machine stamp answers "when" in a form nobody reads at a glance."""

    import re

    plain = re.sub(r"\x1b\[[0-9;]*m", "", _reused_attestation_output(tmp_path, width=100))

    assert "2026-08-17T16:34:01+0000" not in plain
    assert "Aug 2026 at" in plain
    # The three statements are separate, and the command is still named.
    assert "Integrity verified on an earlier open." in plain
    assert "SHA-256 65e2002fed0b286f" in plain
    assert "/verify reads the whole medium again." in plain


def test_a_freshly_hashed_open_still_says_nothing(tmp_path):
    """The line exists to mark reuse; an open that streamed has nothing to add."""

    console = Console(file=io.StringIO(), width=100)
    session = InteractiveSession(_session_args(tmp_path), console=console)
    try:
        session._announce_disk_integrity(
            SimpleNamespace(evidence_attestation_reused=False, attested_at="", image_sha="x")
        )
    finally:
        session.close()
    assert console.file.getvalue() == ""
