"""The layout vocabulary every view of an interactive session shares.

A session prints a dozen different panels and tables, written in as many
places. Left to themselves each one would choose its own width, its own way of
laying a label beside a value, and its own treatment of the model's Markdown —
and the transcript would read as a dozen unrelated programs writing to the same
terminal. The four decisions that have to be made once therefore live here:
how wide a panel alongside an answer is, how one exchange opens, how one
labelled fact is laid out, and how an answer's headings render.

Separate from :mod:`forensic_agent.cli.terminal`, which owns the palette and the
box characters: that module says what the console *looks* like at all, this one
says how one investigation session arranges what it already has.
"""

from __future__ import annotations

from rich.markup import escape
from rich.text import Text
from rich.theme import Theme

from forensic_agent.cli.terminal import ACCENT, BORDER, DIM

#: One width for every panel that prints alongside the final answer, so their
#: edges align in a wide terminal instead of each choosing its own cap.
PANEL_WIDTH = 108

#: The rule an exchange opens on. Plain and unstyled it is still a visible line,
#: which is what keeps the boundary readable with colour turned off.
_EXCHANGE_RULE = "─"

#: However long the heading, this much rule always runs past its number. Without
#: a tail the line stops reading as a divider.
MIN_TRAILING_RULE = 4


def short(value: str, length: int = 12) -> str:
    return value if len(value) <= length else value[:length]


def exchange_heading(number: int, *, width: int) -> Text:
    """Open one exchange with a numbered rule.

    A session is a stream of similarly weighted panels, and an operator
    scrolling back could not see where one question's answer ended and the next
    began. One quiet rule per exchange draws that boundary, and the number gives
    the block a name the operator can refer to.

    The heading does not echo the question. The operator's own prompt line
    carries the same words directly above, so an echo would restate what is
    already on screen and make a transcript that is already tiring to follow one
    line longer per exchange. The number and the rule carry the boundary on
    their own.

    It is deliberately one line, and the rule colour stays in the border family
    so the boundary never competes with the accepted answer for the eye.
    """

    # No base style: one set here would compose under every appended span and
    # tint the number with the rule's own near-invisible neutral.
    heading = Text()
    heading.append(f"{_EXCHANGE_RULE * 3} ", style=BORDER)
    heading.append(f"{number:02d} ", style=f"bold {ACCENT}")
    heading.append(
        _EXCHANGE_RULE * max(MIN_TRAILING_RULE, width - heading.cell_len), style=BORDER
    )
    # A divider that wraps stops being a divider. Rich honours ``no_wrap`` only
    # when the caller passes it to ``print``, so the fit is settled here instead:
    # on a console too narrow even for the lead and the number, the line is cut
    # rather than folded onto a second row.
    heading.truncate(max(width, 0), overflow="crop")
    return heading


#: Rich underlines Markdown h1/h2 by default, which on a dark terminal reads
#: like a hyperlink rather than a heading. This override renders every heading
#: in the model's answer as plain bold. Presentation only — the answer text is
#: untouched.
ANSWER_MARKDOWN_THEME = Theme(
    {f"markdown.h{level}": "bold" for level in range(1, 7)},
    inherit=True,
)


def kv_row(t, label, value, color, command=""):
    """One session fact: what it is, what it says, and where to change it.

    The command sits in its own right-hand column rather than trailing the value
    after a separator. Read down, the commands form the list of moves available
    from here; read across, every value ends where the eye expects the next one
    to begin, instead of at a different place on each line.
    """

    t.add_row(
        f"[{DIM}]{escape(str(label))}[/]",
        f"[{color}]{escape(str(value))}[/]",
        f"[{DIM}]{escape(str(command))}[/]" if command else "",
    )
