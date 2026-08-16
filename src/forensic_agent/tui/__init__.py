"""Full-screen Textual TUI — the DFIR agent's "investigation console".

An alternative front-end to the line-based rich CLI. It is a presentation layer
only: it wraps the existing :class:`~forensic_agent.cli.session.InteractiveSession`
and re-presents a real ``ControlledRun`` (live mode), or replays a recorded,
stubbed case (demo mode). No forensic logic is re-implemented here.

Launch:
    dfir-agent tui --demo     # recorded case, no Docker/model/evidence needed
    dfir-agent tui            # live, over a configured provider and open case
"""

from __future__ import annotations

__all__ = ("run_demo_tui", "run_live_tui", "build_app", "deferred_evidence")


#: The launch flags that name evidence, and the source kind each one opens as.
_EVIDENCE_FLAGS: tuple[tuple[str, str], ...] = (
    ("image", "disk"),
    ("memory", "memory"),
    ("pcap", "network"),
)


def deferred_evidence(args) -> tuple[str | None, tuple[tuple[str, str], ...]]:
    """Which evidence the console should open ITSELF, rather than the session.

    Returns ``(case_directory, ((kind, path), ...))``, and MUTATES ``args`` to
    remove whatever it claims, so :class:`InteractiveSession` no longer opens
    it in its constructor.

    That constructor runs before the screen exists and before the console has
    installed its progress observers, so anything opened there hashes and
    indexes against a devnull console: a blank terminal for minutes, then a
    console that appears with the case already loaded and nothing said about
    how. Deferring puts every one of those opens through the console's own
    worker, where hashing draws a measured bar and indexing draws a named row.

    Only ``--case`` was deferred before this, which is why ``--image`` showed
    nothing whatever.

    ``--resume`` and ``--continue`` claim nothing: they reopen a case as a side
    effect of restoring a conversation, and deferring that would move the case
    switch to after the console is already showing the previous one.
    """

    if getattr(args, "resume", None) or getattr(args, "continue_session", False):
        return None, ()
    case = getattr(args, "case", None)
    if case:
        args.case = None
    sources: list[tuple[str, str]] = []
    for flag, kind in _EVIDENCE_FLAGS:
        value = getattr(args, flag, None)
        if value:
            sources.append((kind, str(value)))
            setattr(args, flag, None)
    return (str(case) if case else None), tuple(sources)


def build_app(controller):
    """Build the console app around a controller (used by tests and launchers)."""

    from forensic_agent.tui.app import InvestigationApp

    return InvestigationApp(controller)


def run_demo_tui() -> None:
    """Launch the console over the canned investigation."""

    from forensic_agent.tui.controller import DemoController

    build_app(DemoController()).run()


def run_live_tui(args, *, console=None) -> None:
    """Launch the console over a live ``InteractiveSession`` built from ``args``.

    The session is given a quiet console: the console owns the terminal, and it
    reads the run's results back structurally rather than from printed output.
    """

    import os

    from rich.console import Console

    from forensic_agent.cli.session import InteractiveSession
    from forensic_agent.tui.controller import LiveController

    # devnull, not StringIO: the quiet console swallows narration for the
    # whole process lifetime, and a buffer would grow without bound.
    sink = open(os.devnull, "w", encoding="utf-8")
    quiet = Console(file=sink, force_terminal=False, width=100)
    # Opening evidence hashes and indexes it, which on a disk image is minutes
    # of work. Anything the session does in its CONSTRUCTOR happens before the
    # screen exists and before the console has installed its progress hooks, so
    # it runs against the devnull console above: a blank terminal for the whole
    # open, and then a console that appears with the case already loaded and
    # nothing said about how it got there.
    #
    # So every launch shape that opens evidence is deferred into the running
    # console, where it goes through the same worker and the same progress rows
    # that /case and /attach use. Only --case was deferred before, which is why
    # `--image` in particular showed nothing at all.
    #
    # --resume and --continue are NOT deferred: they reopen a case as a side
    # effect of restoring a conversation, and moving that after the screen is
    # up would change what the console is looking at while it is looking at it.
    # Those two still open quietly; see the report.
    deferred_case, deferred_sources = deferred_evidence(args)
    session = InteractiveSession(args, console=quiet)
    try:
        app = build_app(LiveController(session))
        if deferred_case is not None:
            app._initial_case = deferred_case
        if deferred_sources:
            app._initial_sources = deferred_sources
        app.run()
        # A host-path handoff exits the console deliberately: the launcher
        # reads this code, mounts the requested evidence, and relaunches.
        # It must survive the app's clean shutdown to reach it.
        code = getattr(app, "return_code", None)
        if code:
            raise SystemExit(code)
    finally:
        try:
            session.close()
        except Exception:
            pass
        try:
            sink.close()
        except Exception:
            pass
