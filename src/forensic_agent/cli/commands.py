"""Declarative registry for the interactive console commands.

This module contains metadata and parsing only. It does not perform I/O,
execute forensic tools, or call the language model.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from forensic_agent.cli.i18n import t as _t


class CommandCategory(StrEnum):
    """Stable command groups used by help and completion."""

    GENERAL = "General"
    CASE = "Case and evidence"
    INVESTIGATION = "Investigation"
    SESSION = "History and work"
    SYSTEM = "System and integrations"


CATEGORY_ORDER: tuple[CommandCategory, ...] = (
    CommandCategory.GENERAL,
    CommandCategory.CASE,
    CommandCategory.INVESTIGATION,
    CommandCategory.SESSION,
    CommandCategory.SYSTEM,
)


@dataclass(frozen=True, slots=True)
class CommandSpec:
    """Declaration of one canonical command and its aliases."""

    name: str
    description: str
    category: CommandCategory
    usage: str
    aliases: tuple[str, ...] = ()
    #: A second sentence that belongs to the command but not to the listing.
    #: The full listing is scanned, not read, so a row has to be taken in at a
    #: glance; anything that needs a second clause waits for ``/help <name>``.
    detail: str = ""

    @property
    def names(self) -> tuple[str, ...]:
        return (self.name, *self.aliases)

    @property
    def display_names(self) -> str:
        return ", ".join(f"/{name}" for name in self.names)


@dataclass(frozen=True, slots=True)
class ParsedCommand:
    """Recognized slash command with unmodified argument text."""

    spec: CommandSpec
    invoked_as: str
    argument_text: str = ""
    #: Whatever the operator wrote below the command line.  It belongs to the
    #: console, not to this command, and the caller is expected to run it as
    #: the next input rather than drop it.
    trailing_text: str = ""

    @property
    def name(self) -> str:
        return self.spec.name


class UnknownCommandError(ValueError):
    """Input begins with a slash but is not a registered command."""

    def __init__(self, name: str) -> None:
        super().__init__(f"Unknown command: /{name}")
        self.name = name


class CommandUsageError(ValueError):
    """A registered command was typed in a shape it does not take.

    Held apart from an ordinary failure because nothing was attempted: no path
    was opened, no tool ran, and nothing was refused. The console answers it
    with the command's own declared form rather than with an error, which is
    why the form is read back off the registry instead of being written out at
    the call site — the declaration stays the single source of the shape.
    """

    def __init__(self, name: str, *, detail: str = "") -> None:
        self.command_name = name.strip().removeprefix("/").casefold()
        self.detail = detail
        super().__init__(f"Usage: {self.usage}")

    @property
    def usage(self) -> str:
        command = COMMAND_REGISTRY.resolve(self.command_name)
        return command.usage if command is not None else f"/{self.command_name}"


_VALID_NAME = re.compile(r"^[a-z][a-z0-9-]*$")


class CommandRegistry:
    """Immutable index of command declarations."""

    def __init__(self, commands: Iterable[CommandSpec]) -> None:
        ordered = tuple(commands)
        by_name: dict[str, CommandSpec] = {}
        for command in ordered:
            self._validate_spec(command)
            for name in command.names:
                key = name.casefold()
                if key in by_name:
                    raise ValueError(f"Duplicate command name: {name}")
                by_name[key] = command

        self._commands = ordered
        self._by_name = by_name

    @staticmethod
    def _validate_spec(command: CommandSpec) -> None:
        if not _VALID_NAME.fullmatch(command.name):
            raise ValueError(f"Invalid command name: {command.name!r}")
        if not command.description.strip():
            raise ValueError(f"Command /{command.name} has no description")
        if not command.usage.startswith(f"/{command.name}"):
            raise ValueError(
                f"Usage for /{command.name} must begin with its canonical name"
            )
        for alias in command.aliases:
            if not _VALID_NAME.fullmatch(alias):
                raise ValueError(f"Invalid command alias: {alias!r}")
            if alias.casefold() == command.name.casefold():
                raise ValueError(f"Alias repeats the command name: {alias}")

    @property
    def commands(self) -> tuple[CommandSpec, ...]:
        return self._commands

    def resolve(self, name: str) -> CommandSpec | None:
        normalized = name.strip().removeprefix("/").casefold()
        if not normalized:
            return None
        return self._by_name.get(normalized)

    def parse(self, text: str) -> ParsedCommand | None:
        """Recognize a slash command without interpreting its arguments.

        A paste reaches the console as one input, line breaks included, so a
        command must end where its line ends: an argument that ran past the
        break turned the question written below ``/new`` into part of the case
        name.  The remainder is returned in ``trailing_text`` instead of being
        discarded, because the operator typed it and a console that drops
        typed input silently is worse than one that misreads it.
        """

        stripped = text.strip()
        if not stripped.startswith("/"):
            return None

        command_line, _break, remainder = stripped.partition("\n")
        parts = command_line.split(maxsplit=1)
        invoked_as = parts[0][1:].strip()
        if not invoked_as:
            return None

        spec = self.resolve(invoked_as)
        if spec is None:
            raise UnknownCommandError(invoked_as)
        return ParsedCommand(
            spec=spec,
            invoked_as=invoked_as.casefold(),
            argument_text=parts[1].strip() if len(parts) == 2 else "",
            trailing_text=remainder.strip(),
        )

    def command_help(self, name: str) -> str | None:
        command = self.resolve(name)
        if command is None:
            return None
        # Only the operator-facing chrome is rendered through the language layer;
        # display names and the usage syntax stay byte-identical because they are
        # the command's own identifiers.
        lines = [
            command.display_names,
            _t(command.description),
        ]
        # The detail exists precisely because it was too long for the listing;
        # this is the one place with room to print it.
        if command.detail:
            lines.append(_t(command.detail))
        lines.extend(
            (
                f"{_t('Usage:')} {command.usage}",
                f"{_t('Category:')} {_t(command.category.value)}",
            )
        )
        return "\n".join(lines)

    def help_text(self, *, title: str = "DFIR-AGENT commands") -> str:
        lines = [_t(title)]
        for category in CATEGORY_ORDER:
            members = tuple(
                command for command in self._commands if command.category is category
            )
            if not members:
                continue
            lines.extend(("", _t(category.value)))
            # Column width is derived from the display names, not the descriptions,
            # so a longer Croatian description never shifts the aligned columns.
            width = max(len(command.display_names) for command in members)
            for command in members:
                lines.append(
                    f"  {command.display_names:<{width}}  {_t(command.description)}"
                )
                if command.usage not in command.display_names:
                    lines.append(f"  {'':<{width}}  {_t('Usage:')} {command.usage}")
        return "\n".join(lines)


COMMANDS: tuple[CommandSpec, ...] = (
    CommandSpec(
        "help",
        "Show all commands or detailed help for one command.",
        CommandCategory.GENERAL,
        "/help [command]",
    ),
    CommandSpec(
        "status",
        "Show the active model, case, evidence sources, and tools.",
        CommandCategory.GENERAL,
        "/status",
    ),
    CommandSpec(
        "clear",
        "Clear the terminal without changing the investigation.",
        CommandCategory.GENERAL,
        "/clear [all]",
        detail=(
            "The screen and nothing else: the investigation history, the tool "
            "activity, the accepted evidence, the findings awaiting review and "
            "the message number all survive, and the next message continues "
            "from where the chat left off. Starting a new history instead is "
            "/new. /clear all additionally drops the status panel."
        ),
    ),
    CommandSpec(
        "layout",
        "Switch between the full layout and a simple one-column view.",
        CommandCategory.GENERAL,
        "/layout [simple|full]",
        detail=(
            "A bare /layout opens the chooser, which names both layouts and "
            "says what each is for. The full layout keeps the instrument "
            "panes beside the conversation; the simple one hides them and "
            "prints each answer's tool activity directly beneath it."
        ),
    ),
    # One way out, not two names for it. /quit is the name the console itself
    # teaches — it is what the Ctrl+C hint offers at the moment the operator is
    # looking for the exit — so the silent /exit alias is gone.
    CommandSpec(
        "quit",
        "Close the terminal; the investigation history is saved automatically.",
        CommandCategory.GENERAL,
        "/quit",
    ),
    CommandSpec(
        "case",
        "Open a case directory, evidence file, or explicitly typed RAW source.",
        CommandCategory.CASE,
        "/case [disk|memory|network] <path>",
    ),
    CommandSpec(
        "sources",
        "Show every evidence source currently attached to the case.",
        CommandCategory.CASE,
        "/sources",
    ),
    CommandSpec(
        "context",
        "Show or manage the non-evidentiary case brief.",
        CommandCategory.CASE,
        "/context [show|set <text>|load <path>|clear]",
    ),
    CommandSpec(
        "attach",
        "Attach another evidence source to the active case.",
        CommandCategory.CASE,
        "/attach <disk|memory|network> <path>",
    ),
    # The console has always told the operator that /verify existed. The line
    # printed on every reused attestation named it, and typing it answered
    # "unknown command", which is the worst of the three possible states: a
    # console that promises a check it cannot perform.
    CommandSpec(
        "verify",
        "Stream the entire medium again and check its digest against the one "
        "the case was opened under.",
        CommandCategory.CASE,
        "/verify",
        detail=(
            "Every byte of the evidence is read, so this costs what opening "
            "the case cost. The size is stated and the pass is confirmed "
            "before it starts. A digest that matches establishes that the "
            "medium still holds the bytes the case was opened over, which is "
            "what the image index and the recorded findings rest on: both are "
            "filed under that digest. A digest that differs means the medium "
            "was altered or the storage holding it is failing, and nothing "
            "read from it earlier describes what is there now."
        ),
    ),
    CommandSpec(
        "tools",
        "List active tools with their operation count and which external "
        "program each needs, or show one function's full detail with "
        "/tools <name>.",
        CommandCategory.INVESTIGATION,
        "/tools [name]",
    ),
    CommandSpec(
        "findings",
        "List the findings, or describe one with /findings <id>.",
        CommandCategory.INVESTIGATION,
        "/findings [id]",
        detail=(
            "The id is the number in the first column of the listing. The "
            "detail names the function and operation that ran, the arguments "
            "the model passed, what came back, how completely the source was "
            "examined, and the SHA-256 the result was recorded under. Evidence "
            "content is not shown here."
        ),
    ),
    CommandSpec(
        "oversight",
        "What the safety layer allowed or blocked; a number, calls or prompt "
        "shows the record in full.",
        CommandCategory.INVESTIGATION,
        "/oversight [n|calls|prompt]",
        aliases=("guardrails",),
        detail=(
            "The same surface the g key opens. A refusal by the oversight "
            "policy and a refusal by the tool are counted apart, because only "
            "the first is the gate stopping a call. /oversight <n> shows one "
            "call whole, by the number the summary prints: every argument "
            "value unabridged, the authority the call requested against the "
            "authority the case granted, and the decision reason or the exact "
            "denial ground. /oversight calls lists the executed commands "
            "with every argument in full. /oversight prompt shows the "
            "complete message the run sent to the model. /guardrails survives "
            "as another name for it, because the g-key pane keeps that word."
        ),
    ),
    CommandSpec(
        "retry",
        "Send the most recent investigation message again.",
        CommandCategory.INVESTIGATION,
        "/retry",
    ),
    CommandSpec(
        "complete",
        "Close the case: write the full report, the investigation diagram and "
        "the operator's completion record, then detach the evidence.",
        CommandCategory.INVESTIGATION,
        "/complete [path]",
        detail=(
            "Completing is the operator's declaration and it is confirmed "
            "first. It writes one report, covering every exchange in the case "
            "(message, answer, calls, findings and oversight decisions), with "
            "the complete oversight record beside it, the same report as a "
            "self-contained page a browser can open, the diagram of the "
            "closing run and the recorded declaration of who closed the case. "
            "All of them share one name, and a path names that shared stem. A "
            "completion never writes over an earlier one: an occupied name "
            "moves the whole set to the next free one. The evidence sources "
            "are detached afterwards."
        ),
    ),
    CommandSpec(
        "export",
        "Write the investigation report.",
        CommandCategory.INVESTIGATION,
        "/export [n|path]",
        detail=(
            "A bare /export covers every question this case's history retains "
            "(message, answer, calls, findings and oversight decisions) "
            "under a name carrying the case id and the moment it was asked "
            "for, so no export overwrites another. A number selects one "
            "question by its position in the history; a path writes the most "
            "recent question's report there. Nothing is closed and no evidence "
            "is detached: that is /complete."
        ),
    ),
    CommandSpec(
        "new",
        "Start a new investigation history for the active case.",
        CommandCategory.SESSION,
        "/new [name]",
        aliases=("reset",),
        detail=(
            "The next question starts from nothing, so the console clears what "
            "belonged to the discarded history with it: the previous messages, "
            "their tool calls and their guardrail decisions. The case stays "
            "open, its evidence stays attached, what was written to disk is "
            "untouched, and findings — accepted or still awaiting review — "
            "survive, because a finding is a statement about the evidence. "
            "Closing the case instead is /complete; clearing only the screen "
            "is /clear."
        ),
    ),
    CommandSpec(
        "history",
        "Show previous messages and answers in this investigation.",
        CommandCategory.SESSION,
        "/history [limit]",
    ),
    CommandSpec(
        "undo",
        "Exclude the latest answer from future model context.",
        CommandCategory.SESSION,
        "/undo",
    ),
    # One command, two names. /sessions and /resume were separate specs that
    # already ran the same code: a bare /resume opened the same picker
    # /sessions did, and picking from that picker resumed. Two names for one
    # intent taught the operator that there were two things to learn and left
    # them guessing which one restored anything. The id form skips the picker.
    CommandSpec(
        "resume",
        "Open a saved investigation and put it back on screen.",
        CommandCategory.SESSION,
        "/resume [id]",
        aliases=("sessions",),
    ),
    CommandSpec(
        "continue",
        "Continue the previous investigation and reopen its evidence.",
        CommandCategory.SESSION,
        "/continue",
    ),
    CommandSpec(
        "setup",
        "Configure OpenRouter or a local Ollama model.",
        CommandCategory.SYSTEM,
        "/setup",
    ),
    CommandSpec(
        "model",
        "Show the active model, list what the provider offers with /model "
        "list, or switch to one by id.",
        CommandCategory.SYSTEM,
        "/model [list [all|<text>]|<model-id>]",
    ),
    CommandSpec(
        "doctor",
        "Check the model connection and forensic dependencies.",
        CommandCategory.SYSTEM,
        "/doctor",
    ),
    CommandSpec(
        "language",
        "Show or switch the terminal language (English or Croatian).",
        CommandCategory.SYSTEM,
        "/language [en|hr]",
    ),
    CommandSpec(
        "theme",
        "Show or switch the console colour theme.",
        CommandCategory.SYSTEM,
        "/theme [name]",
        detail=(
            "A bare /theme lists the shipped themes and marks the active one. "
            "/theme <name> switches at once, redrawing the transcript and the "
            "panes in the new colours, and the choice is kept for the next "
            "launch. Every theme is held to a measured contrast floor, so none "
            "of them can render a colour that is unreadable on its ground."
        ),
    ),
    # One command for one subject. /reasoning and /budget opened the same
    # screen and governed the same thing — how much work one message is
    # allowed to spend — so they are a single command named for that subject
    # rather than for two halves of it.
    CommandSpec(
        "effort",
        "Show and set how much work one message may spend: the model's "
        "reasoning effort and the step and tool-call limits.",
        CommandCategory.SYSTEM,
        "/effort [none|low|medium|high|steps N|toolcalls N]",
        detail=(
            "A bare /effort opens the effort screen: pick a row and Enter "
            "edits it. The levels none, low, medium and high set how much "
            "reasoning the model spends per request, and none omits reasoning "
            "entirely. /effort steps 30 and /effort toolcalls 30 set a limit "
            "without the screen."
        ),
    ),
)


COMMAND_REGISTRY = CommandRegistry(COMMANDS)


def parse_command(text: str) -> ParsedCommand | None:
    return COMMAND_REGISTRY.parse(text)


def render_help(command: str | None = None) -> str:
    if command:
        detail = COMMAND_REGISTRY.command_help(command)
        if detail is not None:
            return detail
        raise UnknownCommandError(command)
    return COMMAND_REGISTRY.help_text()
