"""The screen that opens a case, and what it can honestly show the operator.

The screen this replaced led with ``/evidence`` in its path field and walked the
container's own file system under a heading that read like the operator's disk,
while telling them in the same breath to type a path from their computer. Every
entry it listed was therefore the one thing they were not being asked for.

What is achievable is decided entirely by the bind mount, and these pin all
three cases of it:

* Outside a container the host file system IS the file system, so any folder is
  listed.
* Inside one, the host directory the launcher mounted at ``/evidence`` — and
  everything under it — is listed, because those really are the same bytes.
* Any other host path is absent rather than hidden. No walk of the container
  finds it, and the launcher handoff is the only route to it, so the screen
  says that and offers the handoff instead of an empty tree.
"""

from __future__ import annotations

import asyncio
import io
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("textual")

from rich.console import Console  # noqa: E402
from rich.text import Text  # noqa: E402

import forensic_agent.cli.host_display as _host_display  # noqa: E402
from forensic_agent.cli.session import InteractiveSession  # noqa: E402
from forensic_agent.tui import build_app  # noqa: E402
from forensic_agent.tui.app import (  # noqa: E402
    _LAST_CASE_DIRECTORY_KEY,
    FileBrowserScreen,
    _container_view_of,
)
from forensic_agent.tui.controller import LiveController  # noqa: E402

HOST_CASE = "D:\\Cases\\case-001"


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


def _mounted_container(tmp_path: Path, monkeypatch, *, host_root: str = HOST_CASE):
    """Stand a container up whose ``/evidence`` really is one host directory.

    The mount point is moved rather than simulated: the code under test asks the
    file system what is at ``/evidence``, and a test that stubbed that question
    would prove nothing about the answer.
    """

    mount = tmp_path / "evidence"
    (mount / "images").mkdir(parents=True)
    (mount / "images" / "laptop.E01").write_bytes(b"E")
    (mount / "promet.pcap").write_bytes(b"\xd4\xc3\xb2\xa1")
    (mount / "memory.raw").write_bytes(b"m")
    monkeypatch.setenv("DFA_CONTAINERIZED", "1")
    monkeypatch.setenv("DFA_HOST_EVIDENCE", host_root)
    monkeypatch.setenv("DFA_CASE_LABEL", "case-001")
    monkeypatch.setattr(_host_display, "CONTAINER_EVIDENCE", str(mount))
    return mount


def _screen_text(app) -> str:
    return "\n".join(strip.text for strip in app.screen._compositor.render_strips())


# ---------------------------------------------------------------------------
# what can be listed, in each of the three cases
# ---------------------------------------------------------------------------
def test_outside_a_container_every_folder_on_this_machine_is_listable(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("DFA_CONTAINERIZED", raising=False)
    assert _container_view_of(str(tmp_path)) == str(tmp_path)
    assert _container_view_of(str(tmp_path / "absent")) is None


def test_the_mounted_host_directory_is_the_one_a_container_can_list(
    tmp_path, monkeypatch
):
    mount = _mounted_container(tmp_path, monkeypatch)

    assert _container_view_of(HOST_CASE) == str(mount)
    # A trailing separator and the host's other slash name the same folder.
    assert _container_view_of("D:/Cases/case-001/") == str(mount)
    # And so does everything beneath it, because the bytes are the same bytes.
    assert _container_view_of("D:\\Cases\\case-001\\images") == f"{mount}/images"


def test_a_host_directory_that_was_never_mounted_cannot_be_listed(
    tmp_path, monkeypatch
):
    """Absent, not hidden. No walk of this container will ever find it."""

    _mounted_container(tmp_path, monkeypatch)

    assert _container_view_of("D:\\Cases\\case-002") is None
    assert _container_view_of("C:\\Users\\investigator") is None
    # A subdirectory of the mount that does not exist is equally unlistable.
    assert _container_view_of("D:\\Cases\\case-001\\absent") is None


def test_without_a_stated_mount_nothing_claims_to_be_the_host_directory(
    tmp_path, monkeypatch
):
    """A launcher that did not say what it mounted leaves the question open.

    Guessing would be worse than admitting it: the container would offer a
    listing of ``/evidence`` under the name of a host folder that may hold
    something else entirely.
    """

    _mounted_container(tmp_path, monkeypatch)
    monkeypatch.delenv("DFA_HOST_EVIDENCE", raising=False)

    assert _container_view_of(HOST_CASE) is None


# ---------------------------------------------------------------------------
# the screen itself
# ---------------------------------------------------------------------------
def test_the_path_field_never_opens_on_a_container_path(tmp_path, monkeypatch):
    """``/evidence`` looked like an answer to a question about the host."""

    _mounted_container(tmp_path, monkeypatch)
    monkeypatch.setenv("DFA_RUNS_DIR", str(tmp_path / "prefs"))

    async def scenario():
        app, session = _live_app(tmp_path)
        try:
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause(0.1)
                assert app._browse_root() == HOST_CASE
                app.dispatch_command("case", "")
                await pilot.pause(0.3)
                assert isinstance(app.screen, FileBrowserScreen)
                from textual.widgets import Input

                value = app.screen.query_one("#browse-root", Input).value
                rendered = _screen_text(app)
                await pilot.press("escape")
                await pilot.pause(0.1)
        finally:
            session.close()
        return value, rendered

    value, rendered = asyncio.run(scenario())

    assert value == HOST_CASE
    assert not value.startswith("/evidence")
    assert "/work" not in value


def test_the_mounted_host_folder_is_listed_so_the_operator_picks_rather_than_types(
    tmp_path, monkeypatch
):
    _mounted_container(tmp_path, monkeypatch)
    monkeypatch.setenv("DFA_RUNS_DIR", str(tmp_path / "prefs"))

    async def scenario():
        app, session = _live_app(tmp_path)
        try:
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause(0.1)
                app.dispatch_command("case", "")
                await pilot.pause(0.3)
                screen = app.screen
                assert isinstance(screen, FileBrowserScreen)
                entries = list(screen._entries)
                rendered = _screen_text(app)
                await pilot.press("escape")
                await pilot.pause(0.1)
        finally:
            session.close()
        return entries, rendered

    entries, rendered = asyncio.run(scenario())

    names = [path for path, _ in entries]
    # Every row is a HOST path, written the way that host writes them, so the
    # operator recognises what they are choosing between.
    assert "D:\\Cases\\case-001\\images" in names
    assert "D:\\Cases\\case-001\\promet.pcap" in names
    assert all(not name.startswith("/evidence") for name in names)
    # Folders first: a case is opened from one.
    assert entries[0] == ("D:\\Cases\\case-001\\images", True)
    assert "promet.pcap" in rendered


def test_what_is_already_attached_is_a_separate_labelled_list(tmp_path, monkeypatch):
    """True, occasionally useful, and not what the screen is for.

    It is also suppressed while the operator is looking at the mounted folder
    itself, because there the two lists are the same names under two headings
    and the reader is invited to work out how they differ. They do not.
    """

    _mounted_container(tmp_path, monkeypatch)
    monkeypatch.setenv("DFA_RUNS_DIR", str(tmp_path / "prefs"))

    async def scenario():
        app, session = _live_app(tmp_path)
        try:
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause(0.1)
                app.dispatch_command("case", "")
                await pilot.pause(0.3)
                screen = app.screen
                assert isinstance(screen, FileBrowserScreen)
                mounted = list(screen._mounted)
                on_the_mount = _screen_text(app)
                from textual.widgets import Input

                field = screen.query_one("#browse-root", Input)
                field.value = "D:\\Cases\\case-002"
                field.focus()
                await pilot.press("enter")
                await pilot.pause(0.2)
                elsewhere = _screen_text(app)
                await pilot.press("escape")
                await pilot.pause(0.1)
        finally:
            session.close()
        return mounted, on_the_mount, elsewhere

    mounted, on_the_mount, elsewhere = asyncio.run(scenario())

    assert mounted, "nothing was offered from the mount at all"
    assert all(path.startswith("/") or ":" in path for path, _ in mounted)
    assert "ALREADY ATTACHED TO THIS SESSION" not in on_the_mount
    assert "ALREADY ATTACHED TO THIS SESSION" in elsewhere
    # The launcher-supplied display name, because the directory's real name
    # does not survive the mount point.
    assert "case-001" in elsewhere


def test_an_unmounted_folder_is_explained_and_then_handed_to_the_launcher(
    tmp_path, monkeypatch
):
    """The handoff ends this process, so it is never one keystroke away.

    A typo that closed the console and failed a mount on the way back would
    cost the operator the session they were in the middle of.
    """

    _mounted_container(tmp_path, monkeypatch)
    monkeypatch.setenv("DFA_RUNS_DIR", str(tmp_path / "prefs"))
    opened: list[tuple[str, str, str]] = []

    async def scenario():
        app, session = _live_app(tmp_path)
        app._case_worker = lambda action, kind, path: opened.append((action, kind, path))
        try:
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause(0.1)
                app.dispatch_command("case", "")
                await pilot.pause(0.3)
                screen = app.screen
                assert isinstance(screen, FileBrowserScreen)
                from textual.widgets import Input

                field = screen.query_one("#browse-root", Input)
                field.value = "D:\\Cases\\case-002"
                field.focus()
                await pilot.press("enter")
                await pilot.pause(0.2)
                # Still here, and told why.
                assert isinstance(app.screen, FileBrowserScreen)
                explained = _screen_text(app)
                assert screen._entries == []
                await pilot.press("enter")
                await pilot.pause(0.3)
        finally:
            session.close()
        return explained

    explained = asyncio.run(scenario())

    assert "cannot see" in explained
    assert opened == [("open", "", "D:\\Cases\\case-002")]


def test_the_folder_last_opened_from_comes_back_next_time(tmp_path, monkeypatch):
    """Kept where the console keeps its other settings, so a relaunch keeps it.

    The launcher handoff replaces the container, so a value held only in this
    process would be lost on exactly the relaunch that needed it.
    """

    monkeypatch.delenv("DFA_CONTAINERIZED", raising=False)
    monkeypatch.setenv("DFA_RUNS_DIR", str(tmp_path / "prefs"))
    from forensic_agent.cli.preferences import read_preference

    sources = tmp_path / "sources"
    sources.mkdir()
    (sources / "laptop.E01").write_bytes(b"E")

    async def scenario():
        app, session = _live_app(tmp_path)
        try:
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause(0.1)
                app._remember_case_directory(str(tmp_path))
                # A file is remembered by the folder that holds it: that is
                # where the operator will look for the next source.
                app._remember_case_directory(str(sources / "laptop.E01"))
                stored = read_preference(_LAST_CASE_DIRECTORY_KEY)
                root = app._browse_root()
        finally:
            session.close()
        return stored, root

    stored, root = asyncio.run(scenario())

    assert stored == str(sources)
    assert root == str(sources)


# ---------------------------------------------------------------------------
# a second case is not a continuation of the first
# ---------------------------------------------------------------------------
def test_opening_a_second_case_does_not_leave_the_first_ones_chat_behind(
    tmp_path, monkeypatch
):
    """The previous case's questions read as though they were asked of this one."""

    monkeypatch.delenv("DFA_CONTAINERIZED", raising=False)
    first = tmp_path / "first.raw"
    first.write_bytes(b"f" * 4096)
    second = tmp_path / "second.raw"
    second.write_bytes(b"s" * 4096)

    async def open_case(pilot, app, argument: str) -> None:
        app.dispatch_command("case", argument)
        for _ in range(300):
            await pilot.pause(0.02)
            if not app._case_op_alive and "Case opened" in _screen_text(app):
                break
        for _ in range(10):
            await pilot.pause(0.02)

    async def scenario():
        app, session = _live_app(tmp_path)
        try:
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause(0.1)
                await open_case(pilot, app, f"memory {first}")
                # An answer from the first case, standing in the conversation.
                app._say(Text("AN ANSWER ABOUT THE FIRST CASE"))
                await pilot.pause(0.1)
                assert "AN ANSWER ABOUT THE FIRST CASE" in _screen_text(app)
                await open_case(pilot, app, f"memory {second}")
                await pilot.pause(0.2)
                after = _screen_text(app)
        finally:
            session.close()
        return after

    after = asyncio.run(scenario())

    assert "AN ANSWER ABOUT THE FIRST CASE" not in after
    # Cleared through the console's own /clear primitive, so the pane reopens
    # the way it opens at startup rather than through a second startup path.
    assert "Case opened" in after
    assert "second.raw" in after


def test_a_listed_folder_is_walked_and_a_listed_file_is_picked(tmp_path, monkeypatch):
    """The point of listing: the operator chooses instead of typing a filename."""

    mount = _mounted_container(tmp_path, monkeypatch)
    monkeypatch.setenv("DFA_RUNS_DIR", str(tmp_path / "prefs"))
    picked: list[tuple[str, str, str]] = []

    async def scenario():
        app, session = _live_app(tmp_path)
        app._case_worker = lambda action, kind, path: picked.append((action, kind, path))
        try:
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause(0.1)
                app.dispatch_command("attach", "")
                await pilot.pause(0.3)
                await pilot.press("enter")  # a disk image
                await pilot.pause(0.4)
                screen = app.screen
                assert isinstance(screen, FileBrowserScreen)
                # First row is the folder; opening it re-roots the listing.
                await pilot.press("enter")
                await pilot.pause(0.3)
                inside = list(screen._entries)
                # Back out, then take the file beside it.
                screen._show(HOST_CASE)
                await pilot.pause(0.2)
                await pilot.press("down")
                await pilot.pause(0.1)
                await pilot.press("enter")
                await pilot.pause(0.4)
        finally:
            session.close()
        return inside

    inside = asyncio.run(scenario())

    assert inside == [("D:\\Cases\\case-001\\images\\laptop.E01", False)]
    assert picked == [("attach", "disk", "D:\\Cases\\case-001\\memory.raw")]
    assert mount.is_dir()
