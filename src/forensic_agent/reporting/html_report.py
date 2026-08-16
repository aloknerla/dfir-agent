"""The report as a page a browser can open, rendered from the record itself.

The markdown report is the record. Everything this module produces is a
rendering of it, and that ordering is the whole design: the page is built by
reading the markdown that was already written to disk, so it cannot state a
fact the record does not, and it cannot drift when the report changes. Nothing
downstream reads the HTML, no tool receives it, and deleting it would lose
nothing but convenience.

Convenience is still worth something. A closed case is handed to a reader who
was never at the console, often on a machine with no markdown viewer and no
appetite for installing one, and a ``.md`` file opened in a text editor turns
the evidence table into a wall of pipes. A page that opens with a double click
is the difference between a report being read and a report being filed.

Two constraints shape the implementation. The first is that no dependency may
be added for it: ``rich`` is already a pinned direct dependency, it already
renders markdown, and it can already record what it rendered as HTML, so the
rendering costs nothing new. The second is that the page must be self-contained
— no stylesheet, no font and no image fetched from anywhere — because a report
that silently phones home when a reader opens it is not an artifact anyone
should hand to a court. ``inline_styles=True`` puts every colour on the element
that uses it, and the only markup around it is written here, so there is
nothing left to fetch.

No PDF is produced. A PDF would need an engine this project does not ship, and
it would add a third file claiming to be the report when there is one report.
"""

from __future__ import annotations

import html as _html
import io
import os

from rich.console import Console
from rich.markdown import Markdown

#: Column width the report is laid out at before it is captured. The reports
#: carry tables whose widest column is a SHA-256, and rich lays a table out to
#: the console it is printed to, so a narrow width would fold hashes across
#: lines in a document whose whole point is that a hash can be compared. The
#: page scrolls the block horizontally rather than reflowing it, so a wide
#: layout costs a reader on a small screen a scrollbar, not a truncated digest.
RENDER_WIDTH = 140

#: The page rich's exporter fills in. ``{stylesheet}``, ``{foreground}``,
#: ``{background}`` and ``{code}`` are its placeholders and are substituted by
#: :meth:`rich.console.Console.export_html`; every literal brace around them is
#: doubled because that substitution runs :meth:`str.format` over this string.
#: ``%%TITLE%%`` is substituted here instead, for the same reason.
_PAGE_FORMAT = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%%TITLE%%</title>
<style>
{stylesheet}
body {{
    color: {foreground};
    background-color: {background};
    margin: 0;
    padding: 2rem 1rem;
}}
pre {{
    margin: 0 auto;
    max-width: 64rem;
    overflow-x: auto;
}}
</style>
</head>
<body>
<pre style="font-family:Menlo,'DejaVu Sans Mono',Consolas,'Courier New',monospace"><code style="font-family:inherit">{code}</code></pre>
</body>
</html>
"""


def render_report_html(markdown: str, *, title: str) -> str:
    """Render one markdown report as a complete, self-contained HTML page.

    The console it is rendered through writes to a discarded buffer and is
    never the session's own: recording onto a live console would capture
    whatever else the session had printed, and printing a whole report to the
    operator's terminal as a side effect of writing a file is not what the
    caller asked for.
    """

    console = Console(
        record=True,
        file=io.StringIO(),
        width=RENDER_WIDTH,
        # A console writing to a buffer detects no terminal and would drop
        # every colour, which is exactly the styling the export exists to
        # carry. Both are stated so the page does not depend on where the
        # process happens to be running.
        force_terminal=True,
        color_system="truecolor",
        legacy_windows=False,
    )
    console.print(Markdown(markdown))
    return console.export_html(
        code_format=_PAGE_FORMAT.replace("%%TITLE%%", _html.escape(title)),
        inline_styles=True,
    )


def write_html_report(path, markdown: str, *, title: str) -> str:
    """Write the rendering beside the record and return where it landed.

    Mirrors :func:`forensic_agent.reporting.markdown.write_report` in shape and
    return value so a caller writing the pair writes them the same way twice.
    """

    with open(path, "w", encoding="utf-8") as handle:
        handle.write(render_report_html(markdown, title=title))
    return os.path.abspath(path)
