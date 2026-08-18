"""The two settings the operator changes about the console rather than the case.

Terminal language and reasoning effort have nothing to do with which evidence is
open, and they outlive the session: both are written to the operator's saved
configuration so the next console starts the way this one ended. They are kept
together, and away from the session's own state, because they share one rule
that is easy to get wrong in either — a change that cannot be *saved* must still
take effect *now*. The operator asked for this language, or this effort, in this
session; only its persistence is in doubt, and a failed write must never quietly
undo what they asked for.

Neither setting touches the model surface. The language governs console chrome
only, and the effort names travel to the provider unchanged.
"""

from __future__ import annotations

from collections.abc import Callable

from rich.console import Console
from rich.markup import escape

import forensic_agent.cli.reasoning as _reasoning
from forensic_agent.cli.i18n import t as _t
from forensic_agent.cli.terminal import (
    ACCENT,
    DIM,
    ORANGE,
    SUCCESS,
    build_usage_renderable,
)


def change_language(console: Console, argument: str) -> None:
    """Show or switch the terminal language, persisting the choice.

    Presentation only: the language governs the console chrome and never the
    model surface. An empty argument reports the current setting and the choices
    instead of changing anything.
    """

    import forensic_agent.cli.i18n as i18n

    requested = argument.strip()
    if not requested:
        current = i18n.current_language()
        choices = ", ".join(
            f"{code} ({i18n.language_display_name(code)})"
            for code in i18n.SUPPORTED_LANGUAGES
        )
        console.print(
            f"[{DIM}]{_t('Terminal language:')}[/] "
            f"[{ACCENT}]{i18n.language_display_name(current)} ({current})[/]"
        )
        console.print(f"[{DIM}]{_t('Choose one:')} {choices}[/]")
        return

    try:
        normalized = i18n.normalize_language(requested)
    except ValueError:
        # An unsupported code is a shape mistake, not a failed switch, so it
        # gets the same quiet guidance every other mistyped command gets.
        console.print(build_usage_renderable("language"))
        return

    i18n.set_language(normalized)
    try:
        i18n.save_language(normalized)
    except OSError as exc:
        # A failed write must not undo the live switch: the operator asked for
        # this language now, and only its persistence is in doubt.
        console.print(
            f"[{ORANGE}]The language was switched for this session but the "
            f"choice could not be saved:[/] {escape(str(exc)[:180])}"
        )
    console.print(
        f"[{SUCCESS}]{_t('Terminal language:')}[/] "
        f"[{ACCENT}]{i18n.language_display_name(normalized)} ({normalized})[/]"
    )


def change_reasoning(
    console: Console,
    argument: str,
    *,
    on_effort_changed: Callable[[], None],
) -> None:
    """Show or change the model's reasoning effort, persisting the choice.

    The effort is the difference between a question answered in seconds and
    one answered in minutes, and whether it buys forensic accuracy is
    something this project measures rather than assumes — so it is a setting
    rather than a constant. An empty argument reports the current choice and
    the alternatives instead of changing anything.

    Only the labels are translated: the effort names travel to the provider.

    ``on_effort_changed`` is called the moment the new effort takes hold, before
    anything can fail: whatever the session built under the old effort has to be
    let go of even if saving the choice then goes wrong.
    """

    requested = argument.strip()
    if not requested:
        console.print(
            f"[{DIM}]{_t('Reasoning effort:')}[/] "
            f"[{ACCENT}]{_reasoning.current_effort()}[/]"
        )
        console.print(
            f"[{DIM}]{_t('Choose one:')} "
            f"{', '.join(_reasoning.REASONING_EFFORTS)}[/]"
        )
        return

    try:
        normalized = _reasoning.normalize_effort(requested)
    except ValueError:
        # The form is built from the choices themselves so a refusal can never
        # name a vocabulary the console no longer accepts; the shape it is shown
        # in is the one every other mistyped command gets, which points to /help
        # rather than dressing a shape mistake as a fault.
        choices = "|".join(_reasoning.REASONING_EFFORTS)
        console.print(
            build_usage_renderable("reasoning", usage=f"/reasoning [{choices}]")
        )
        return

    _reasoning.set_effort(normalized)
    on_effort_changed()
    try:
        _reasoning.save_effort(normalized)
    except OSError as exc:
        # A failed write must not undo the live change: the operator asked
        # for this effort now, and only its persistence is in doubt.
        console.print(
            f"[{ORANGE}]{_t('The reasoning effort was changed for this session but the choice could not be saved:')}[/] "
            f"{escape(str(exc)[:180])}"
        )
    console.print(
        f"[{SUCCESS}]{_t('Reasoning effort:')}[/] [{ACCENT}]{normalized}[/] "
        f"[{DIM}]{_t('It applies to your next message.')}[/]"
    )


def change_budget(
    console: Console,
    argument: str,
    *,
    command_name: str,
    label: str,
    current: int,
    apply: Callable[[int], None],
    save: Callable[[int], None],
) -> None:
    """Show or set one per-question budget, applying to the next question.

    The budget bounds one question's investigation loop rather than the case, so
    it is a console control like the reasoning effort: it changes live and takes
    hold on the next question, and it is saved so the next console starts with
    it. An empty argument reports the current value; a whole number of at least
    one sets it; anything else gets the command's own declared form rather than
    an error.

    ``apply`` takes effect before ``save`` can fail: a value the operator set
    must hold for this session even if persisting it then goes wrong.
    """

    requested = argument.strip()
    if not requested:
        console.print(f"[{DIM}]{label}[/] [{ACCENT}]{current}[/]")
        console.print(f"[{DIM}]{_t('Set a whole number of at least 1.')}[/]")
        return

    try:
        value = int(requested)
    except ValueError:
        console.print(build_usage_renderable(command_name))
        return
    if value < 1:
        console.print(build_usage_renderable(command_name))
        return

    apply(value)
    try:
        save(value)
    except OSError as exc:
        console.print(
            f"[{ORANGE}]{_t('The budget changed for this session but could not be saved:')}[/] "
            f"{escape(str(exc)[:180])}"
        )
    console.print(
        f"[{SUCCESS}]{label}[/] [{ACCENT}]{value}[/] "
        f"[{DIM}]{_t('It applies to your next message.')}[/]"
    )
