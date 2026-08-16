"""How a session's saved investigations are shown on the terminal.

An investigation history is conversational context, not evidence, and every view
of it has to keep saying so — which is why the case-context panel prints its
digest under the word NON-EVIDENCE. A reader who finds one of these panels
transcribed a year later must not be able to mistake it for a forensic record.

The rendering lives here rather than beside the store in
:mod:`forensic_agent.cli.conversation`, which owns what a conversation *is*:
retention, context windows, and the turns themselves. This module only decides
how those turns read on a terminal or on the page.
"""

from __future__ import annotations

from collections.abc import Sequence

from rich.console import Console, Group
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from forensic_agent.cli.console_layout import ANSWER_MARKDOWN_THEME, short
from forensic_agent.cli.i18n import t as _t
from forensic_agent.cli.terminal import (
    ACCENT,
    DIM,
    GLYPH_ABSENT,
    GLYPH_OK,
    GLYPH_POINT,
    PANEL_BOX,
    SUCCESS,
    TABLE_BOX,
)


def saved_investigations_table(rows, *, active_session_id: str | None) -> Table:
    table = Table(
        title=Text(
            f"{GLYPH_POINT} {_t('Saved investigations for the active case')}",
            style=f"bold {ACCENT}",
        ),
        title_justify="left",
        box=TABLE_BOX,
        show_lines=False,
        header_style=f"bold {ACCENT}",
        pad_edge=False,
    )
    # Measured, not reserved: the cell is sixteen characters of session id plus
    # at most the two of the active marker, and the twenty this asked for came
    # out of the model id and the timestamp beside it, which are the two columns
    # a narrow terminal already has to shorten.
    table.add_column(_t("Unique prefix"), no_wrap=True)
    table.add_column(_t("Model"), overflow="fold")
    table.add_column(_t("Questions"), justify="right")
    table.add_column(_t("In context"), justify="right")
    table.add_column(_t("Updated"))
    for row in rows:
        marker = (
            " *"
            if active_session_id is not None
            and row["session_id"] == active_session_id
            else ""
        )
        inference_identity = row.get("inference_identity")
        saved_model = (
            str(inference_identity.get("model"))
            if isinstance(inference_identity, dict)
            else "legacy (not resumable)"
        )
        table.add_row(
            str(row["session_id"])[:16] + marker,
            saved_model,
            str(row["retained_turns"]),
            str(row["context_turns"]),
            str(row["updated_at"]),
        )
    if not rows:
        table.add_row("—", "—", "0", "0", "—")
    return table


def show_history(console: Console, turns: Sequence, *, width: int) -> None:
    """Print every retained turn, marked by whether the model still sees it.

    ``width`` is the one width every panel of a session shares. Without it these
    panels alone ran to the full console, so scrolling back through a wide
    terminal showed the history stepping out past the answers it belongs to.
    """

    for index, turn in enumerate(turns, start=1):
        in_context = turn.included_in_context
        state = "in context" if in_context else "out of context"
        glyph = GLYPH_OK if in_context else GLYPH_ABSENT
        with console.use_theme(ANSWER_MARKDOWN_THEME):
            console.print(
                Panel(
                    Group(
                        Text(turn.question, style=f"bold {ACCENT}"),
                        # The question and its answer are two things; pressed
                        # together they read as one paragraph whose first
                        # sentence happens to be bold.
                        Text(""),
                        Markdown(turn.verified_answer),
                    ),
                    title=Text(
                        f"{glyph} {index}. {short(turn.turn_id)} ({state})"
                    ),
                    title_align="left",
                    border_style=SUCCESS if in_context else DIM,
                    box=PANEL_BOX,
                    padding=(1, 2),
                    width=width,
                )
            )


def case_context_panel(value: str, digest: str, *, width: int) -> Panel:
    return Panel(
        Group(
            Text(value),
            Text(
                f"NON-EVIDENCE, sha256:{digest}",
                style=DIM,
            ),
        ),
        title=f"[bold]{GLYPH_POINT} Case context (NON-EVIDENCE)[/]",
        title_align="left",
        border_style=ACCENT,
        box=PANEL_BOX,
        padding=(1, 2),
        width=width,
    )


