"""What ``/export`` and ``/complete`` are declared to be.

The two were one command for a while — ``/export`` resolved to ``/complete``,
so the documented "write the report" ran the end-of-case act that detaches the
evidence. They are separate declarations again, and the properties that keep
them separate are pinned here: the alias is gone, ``/export`` carries its own
non-destructive description, and the usage the console reads back off the
registry is ``/export``'s own rather than ``/complete``'s.
"""

from __future__ import annotations

from io import StringIO

from rich.console import Console

from forensic_agent.cli.commands import COMMAND_REGISTRY, parse_command
from forensic_agent.cli.terminal import build_usage_renderable


def _rendered(renderable: object) -> str:
    console = Console(file=StringIO(), force_terminal=False, width=200, no_color=True)
    console.print(renderable)
    return console.file.getvalue()


def test_export_is_its_own_command_not_an_alias_of_complete():
    export = COMMAND_REGISTRY.resolve("export")
    complete = COMMAND_REGISTRY.resolve("complete")

    assert export is not None and complete is not None
    assert export.name == "export"
    assert export is not complete
    assert "export" not in complete.aliases


def test_export_is_documented_as_writing_the_report_and_closing_nothing():
    export = COMMAND_REGISTRY.resolve("export")

    assert export.usage == "/export [n|path]"
    assert "report" in export.description.casefold()
    # The word that would make it the end-of-case act must not appear in the
    # line the operator reads before typing it.
    assert "detach" not in export.description.casefold()


def test_export_usage_resolves_to_its_own_form():
    """The ordinal guidance inside /export must not print /complete's shape."""

    assert "/export [n|path]" in _rendered(build_usage_renderable("export"))


def test_both_commands_still_parse():
    assert parse_command("/export 2").name == "export"
    assert parse_command("/complete").name == "complete"
