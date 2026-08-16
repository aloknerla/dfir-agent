"""Transfer parameter descriptions from function documentation into argument schemas.

The model knows only what the supplied schema says about a parameter. Without a
description, it sees a name and a type but must guess what ``data_type`` or
``source`` means and which values are accepted. Those guesses waste calls that
return no useful result.

The description belongs beside the function in its ``Args:`` section, where it
remains coupled to the defining code. This module transfers it into the schema
without requiring changes at every tool-construction site.
"""

from __future__ import annotations

import re

_ARGS_HEADING = re.compile(r"^[ \t]*Args:[ \t]*$", re.MULTILINE)
#: ``name`` or ``name (type)``, followed by a colon and text; continuations are indented.
_ARG_ENTRY = re.compile(
    r"^(?P<indent>[ \t]*)(?P<name>[A-Za-z_][A-Za-z0-9_]*)[ \t]*(?:\([^)]*\))?[ \t]*:[ \t]*"
    r"(?P<text>.*)$"
)
_SECTION_HEADING = re.compile(
    r"^[ \t]*(?:Returns?|Raises?|Yields?|Examples?|Notes?|Warnings?):[ \t]*$",
    re.MULTILINE,
)


def _args_block(description: str) -> tuple[int, int, int] | None:
    """Locate the ``Args:`` section as (heading start, body start, block end).

    The section ends where the text dedents back to the heading's own column.
    Some descriptions are assembled at build time and append prose after the
    docstring, such as the bound capture inventory of ``pcap_query``; that prose
    is neither an argument nor part of one, and a rule that reads to the end of
    the string would swallow it.
    """

    heading = _ARGS_HEADING.search(description)
    if heading is None:
        return None
    heading_text = heading.group(0)
    heading_indent = len(heading_text) - len(heading_text.lstrip())
    body_start = heading.end()
    position = body_start
    end = len(description)
    for line in description[body_start:].splitlines(keepends=True):
        if line.strip() and len(line) - len(line.lstrip()) <= heading_indent:
            end = position
            break
        position += len(line)
    section = _SECTION_HEADING.search(description, body_start, end)
    if section is not None:
        end = section.start()
    return heading.start(), body_start, end


def parse_argument_docs(description: str | None) -> dict[str, str]:
    """Return one description per documented argument, in document order."""

    if not description:
        return {}
    bounds = _args_block(description)
    if bounds is None:
        return {}
    _start, body_start, block_end = bounds
    body = description[body_start:block_end]
    documented: dict[str, str] = {}
    current: str | None = None
    # Entries share one column.  Without that anchor a colon inside wrapped
    # prose ("Not a query expression: comparison syntax matches nothing", or an
    # example value such as "fs:stat") reads as the next argument and silently
    # cuts the description it belongs to in half.
    column: int | None = None
    for line in body.splitlines():
        if not line.strip():
            continue
        match = _ARG_ENTRY.match(line)
        if match is not None and (
            column is None or len(match.group("indent")) <= column
        ):
            column = len(match.group("indent"))
            current = match.group("name")
            documented[current] = match.group("text").strip()
            continue
        if current is not None:
            # A wrapped continuation line belongs to the argument above it.
            documented[current] = f"{documented[current]} {line.strip()}".strip()
    return {name: text for name, text in documented.items() if text}


def _apply(args_schema, description: str | None) -> bool:
    """Copy documented text onto matching fields; report whether any moved."""

    documented = parse_argument_docs(description)
    fields = getattr(args_schema, "model_fields", None)
    if not documented or not isinstance(fields, dict):
        return False
    changed = False
    for name, text in documented.items():
        field = fields.get(name)
        if field is None or getattr(field, "description", None):
            continue
        field.description = text
        changed = True
    if changed:
        rebuild = getattr(args_schema, "model_rebuild", None)
        if callable(rebuild):
            rebuild(force=True)
    return changed


def description_without_argument_docs(description: str | None) -> str | None:
    """Return the description with the ``Args:`` block removed.

    Text before and after the block is kept, so a ``Returns:`` or ``Notes:``
    section, or prose appended after the docstring, still reaches the model.
    """

    if not description:
        return description
    bounds = _args_block(description)
    if bounds is None:
        return description
    start, _body_start, block_end = bounds
    head = description[:start].rstrip()
    tail = description[block_end:].strip()
    return f"{head}\n\n{tail}".rstrip() if tail else head


def carry_argument_docs(args_schema, description: str | None):
    """Move each argument's documentation out of the prose and into the schema.

    The model reads a parameter's meaning from the schema, so leaving the same
    text in the tool description too would spend the context twice on it. The
    block is dropped only once its text has actually reached a field, so a
    docstring this module could not apply keeps everything it had.
    """

    if not _apply(args_schema, description):
        return args_schema, description
    return args_schema, description_without_argument_docs(description)
