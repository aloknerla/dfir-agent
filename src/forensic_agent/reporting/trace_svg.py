"""Deterministic SVG rendering of an agent's recorded execution trace.

The rendering deliberately neither reconstructs nor exposes private model
reasoning. It uses only verifiable events from the input JSONL record: the
question, recorded tool calls, standardized results, provenance, receipt
verification, and final synthesis.
"""

from __future__ import annotations

import argparse
import textwrap
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from html import escape
from pathlib import Path
from typing import Any

from forensic_agent.oversight.audit import (
    ACTION_EXECUTED,
    ACTION_FAILED,
    ACTION_REFUSED_BY_OVERSIGHT,
    ACTION_REFUSED_BY_TOOL,
    classify_action_outcome,
)
from forensic_agent.reporting.trace_record import (
    controlled_run_trace_record,
    load_trace_record,
)

__all__ = [
    "controlled_run_trace_record",
    "export_investigation_diagram",
    "export_trace_svg",
    "load_trace_record",
    "render_investigation_diagram",
    "render_trace_svg",
]


_ACTORS = (
    ("Investigator", "#6f8fb7", "#f3f7fc"),
    ("LLM agent", "#61738a", "#f4f6f9"),
    ("Oversight layer", "#e29a00", "#fff5d8"),
    ("Forensic tool", "#238a68", "#eef9f5"),
    ("Data source", "#7867ad", "#f4f1fb"),
    ("Findings verifier", "#497fae", "#eef6fd"),
)
_ACTOR_X = (100, 300, 500, 700, 900, 1100)
_SVG_WIDTH = 1200
_BOX_WIDTH = 154
_BOX_HEIGHT = 54

#: How each recorded outcome is spelled where a reader meets it. This is a
#: translation of the run's own four-word vocabulary into the words on the
#: drawing — never a fifth outcome, and never a decision this module makes.
_OUTCOME_PHRASE = {
    ACTION_EXECUTED: "executed",
    ACTION_FAILED: "failed",
    ACTION_REFUSED_BY_OVERSIGHT: "refused by the oversight policy",
    ACTION_REFUSED_BY_TOOL: "refused by the tool",
}


def _call_outcome(call: Mapping[str, Any]) -> str:
    """What became of one recorded call.

    Read from the call's own ``outcome`` where the record carries one. A trace
    written before that field existed is classified by the single shared
    function rather than by a predicate of this module's own, so every view of
    a run answers this question the same way.
    """

    return classify_action_outcome(call)


def _outcome_phrase(outcome: str) -> str:
    return _OUTCOME_PHRASE.get(outcome, outcome.replace("_", " "))


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _sequence(value: object) -> list[Any]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return list(value)
    return []


def _text(value: object, *, fallback: str = "—") -> str:
    text = " ".join(str(value or "").split())
    return text or fallback


#: What the final-answer contract's outcome triple reads as on a diagram: the
#: label, the colour, and the token the block header carries.  Written once
#: because two renderers ask the same question, and a single table cannot drift
#: from itself.
_ACCEPTED_ANSWER_VERDICTS: Mapping[tuple[str, str, str], tuple[str, str, str]] = {
    ("verifier", "verified", "published"): (
        "verified forensic report",
        "#238a68",
        "VERIFIED",
    ),
    ("investigation_model_draft", "not_requested", "published"): (
        "unverified model draft",
        "#b8860b",
        "UNVERIFIED",
    ),
    ("runtime_assembly", "not_requested", "published"): (
        "runtime-assembled answer",
        "#497fae",
        "ASSEMBLED",
    ),
    # The absence gate publishes a verified report with the regions it never
    # read stated beneath it, under its own publication outcome.  The check ran
    # and succeeded, so the verdict keeps the verified colour and says what was
    # appended; drawing it as no accepted answer contradicted the very record
    # the diagram is drawn from.
    ("verifier", "verified", "published_with_stated_bound"): (
        "verified forensic report, coverage bound stated",
        "#238a68",
        "VERIFIED · BOUNDED",
    ),
    # The keep-or-mark backstop publishes the draft where the bounded bundle
    # never carried the finding a value rests on, with a marker saying so. The
    # verifier ran; it simply could not judge that part. Drawn as published and
    # partly checked rather than as no accepted answer.
}

#: The keep-or-mark backstop publishes the grounded draft with the gap stated
#: under many ``verification_outcome`` reasons; the verdict is the same for all
#: of them and is identified by the published pair rather than enumerated per
#: reason (mirrors ``cli.presentation.is_verification_incomplete_publication``).
_VERIFICATION_INCOMPLETE_VERDICT: tuple[str, str, str] = (
    "model draft, verification incomplete",
    "#b8860b",
    "DRAFT · UNVERIFIED",
)

#: Read for every triple the table does not hold, contradictory ones included: a
#: partially matching outcome is not an accepted answer wearing a small defect.
_NO_ACCEPTED_ANSWER: tuple[str, str, str] = ("no accepted answer", "#b00020", "NOT ACCEPTED")


def _answer_verdict(final_answer: Mapping[str, Any]) -> tuple[str, str, str]:
    """Return the label, colour and token for what this run accepted."""

    accepted_source = _text(final_answer.get("accepted_source"), fallback="")
    publication_outcome = _text(final_answer.get("publication_outcome"), fallback="")
    if (
        accepted_source == "investigation_model_draft"
        and publication_outcome == "published_draft_verification_incomplete"
    ):
        return _VERIFICATION_INCOMPLETE_VERDICT
    return _ACCEPTED_ANSWER_VERDICTS.get(
        (
            accepted_source,
            _text(final_answer.get("verification_outcome"), fallback=""),
            publication_outcome,
        ),
        _NO_ACCEPTED_ANSWER,
    )


def _shorten(value: object, limit: int = 74) -> str:
    text = _text(value)
    if len(text) <= limit:
        return text
    return text[: max(1, limit - 1)].rstrip() + "…"


def _humanize(value: object) -> str:
    return _text(value).replace("_", " ")


def _format_scalar(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, float):
        return f"{value:.3f}".rstrip("0").rstrip(".")
    return _text(value)


def _format_arguments(arguments: object, *, limit: int = 88) -> str:
    args = _mapping(arguments)
    if not args:
        return ""
    preferred = ("name_or_keyword", "os", "hive", "key", "path", "query", "plugin")
    keys = [key for key in preferred if key in args]
    keys.extend(key for key in sorted(args) if key not in keys)
    parts: list[str] = []
    for key in keys:
        value = args[key]
        if value in (None, "", False, [], {}):
            continue
        rendered = _format_scalar(value)
        if isinstance(value, str):
            rendered = f'"{rendered}"'
        parts.append(f"{key}={rendered}")
        if len(", ".join(parts)) >= limit:
            break
    return _shorten(", ".join(parts), limit)


def _result_summary(output: Mapping[str, Any]) -> str:
    data = _mapping(output.get("data"))
    attributes = _mapping(data.get("attributes"))
    items = _sequence(data.get("items"))
    provenance = _mapping(output.get("provenance"))

    if provenance.get("type") == "reference_knowledge":
        if items:
            first = _mapping(items[0])
            name = _text(first.get("name"), fallback="reference entry")
            parser = _text(first.get("parser"), fallback="no recommended parser")
            count = attributes.get("count", len(items))
            return _shorten(f"{count} candidates • first: {name} • parser: {parser}", 92)
        return "reference catalog returned no match"

    pairs: list[str] = []
    for item in items[:3]:
        row = _mapping(item)
        if "name" in row and "value" in row:
            pairs.append(f"{_text(row['name'])}={_text(row['value'])}")
        elif "path" in row:
            pairs.append(_text(row["path"]))
        elif "filename" in row:
            pairs.append(_text(row["filename"]))
    if pairs:
        return _shorten(" • ".join(pairs), 92)

    page = _mapping(output.get("page"))
    returned = page.get("returned")
    data_type = _humanize(data.get("type"))
    if isinstance(returned, int):
        return _shorten(f"{data_type} • records returned: {returned}", 92)
    return _shorten(data_type, 92)


def _call_sort_key(call: Mapping[str, Any], index: int) -> tuple[int, int]:
    sequence = call.get("oversight_action_sequence")
    if isinstance(sequence, int):
        return (sequence, index)
    provenance = _mapping(_mapping(call.get("output")).get("provenance"))
    fallback = provenance.get("oversight_sequence")
    return (fallback if isinstance(fallback, int) else 1_000_000 + index, index)


def _ordered_calls(record: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    calls = [_mapping(item) for item in _sequence(record.get("calls"))]
    return [item for _, item in sorted(enumerate(calls), key=lambda row: _call_sort_key(row[1], row[0]))]


def _label_box(x: float, y: float, text: str, *, color: str = "#25364c") -> str:
    label = _shorten(text, 70)
    width = min(360.0, max(76.0, 5.45 * len(label) + 16.0))
    return (
        f'<rect x="{x - width / 2:.1f}" y="{y - 19:.1f}" width="{width:.1f}" height="17" '
        'rx="4" fill="#ffffff" fill-opacity="0.96"/>'
        f'<text x="{x:.1f}" y="{y - 7:.1f}" class="message" fill="{color}" '
        f'text-anchor="middle">{escape(label)}</text>'
    )


def _message(
    source: int,
    target: int,
    y: float,
    label: str,
    *,
    color: str = "#7f91a7",
    marker: str = "arrow-slate",
    dashed: bool = False,
) -> str:
    x1, x2 = _ACTOR_X[source], _ACTOR_X[target]
    direction = 1 if x2 > x1 else -1
    start = x1 + 9 * direction
    end = x2 - 12 * direction
    dash = ' stroke-dasharray="6 4"' if dashed else ""
    line = (
        f'<line x1="{start}" y1="{y}" x2="{end}" y2="{y}" stroke="{color}" '
        f'stroke-width="1.45"{dash} marker-end="url(#{marker})"/>'
    )
    return line + _label_box((x1 + x2) / 2, y, label, color=color)


def _self_message(actor: int, y: float, label: str, *, color: str = "#61738a") -> str:
    x = _ACTOR_X[actor]
    path = (
        f'<path d="M {x + 8} {y} H {x + 60} V {y + 26} H {x + 12}" fill="none" '
        f'stroke="{color}" stroke-width="1.4" marker-end="url(#arrow-blue)"/>'
    )
    return path + _label_box(x + 83, y + 17, label, color=color)


def _actor_layer(height: int) -> str:
    parts: list[str] = []
    for (name, stroke, fill), x in zip(_ACTORS, _ACTOR_X, strict=True):
        parts.append(
            f'<line x1="{x}" y1="122" x2="{x}" y2="{height - 88}" '
            'stroke="#cbd5e1" stroke-width="1" stroke-dasharray="5 5"/>'
        )
        parts.append(
            f'<rect x="{x - _BOX_WIDTH / 2}" y="67" width="{_BOX_WIDTH}" '
            f'height="{_BOX_HEIGHT}" rx="10" fill="#ffffff"/>'
        )
        parts.append(
            f'<rect x="{x - _BOX_WIDTH / 2}" y="67" width="{_BOX_WIDTH}" '
            f'height="{_BOX_HEIGHT}" rx="10" fill="{fill}" stroke="{stroke}" stroke-width="1.3"/>'
        )
        parts.append(
            f'<text x="{x}" y="99" class="actor" text-anchor="middle">{escape(name)}</text>'
        )
    return "".join(parts)


def _defs() -> str:
    markers = {
        "arrow-slate": "#7f91a7",
        "arrow-blue": "#497fae",
        "arrow-green": "#238a68",
        "arrow-amber": "#c98500",
        "arrow-violet": "#7867ad",
    }
    marker_svg = "".join(
        f'<marker id="{name}" markerWidth="9" markerHeight="7" refX="8" refY="3.5" '
        f'orient="auto"><polygon points="0 0, 9 3.5, 0 7" fill="{color}"/></marker>'
        for name, color in markers.items()
    )
    return f"""
    <defs>
      {marker_svg}
      <style>
        text {{ font-family: "Segoe UI", Arial, sans-serif; }}
        .title {{ font-size: 22px; font-weight: 700; fill: #17263a; }}
        .subtitle {{ font-size: 11px; fill: #607086; }}
        .actor {{ font-size: 12px; font-weight: 650; fill: #17263a; }}
        .message {{ font-size: 10px; font-weight: 560; }}
        .call-no {{ font-size: 10px; font-weight: 700; fill: #ffffff; }}
        .meta {{ font-size: 9px; fill: #607086; }}
        .legend {{ font-size: 9px; fill: #34465d; }}
      </style>
    </defs>
    """


def render_trace_svg(record: Mapping[str, Any]) -> str:
    """Render one run record as a standalone, Word-friendly SVG."""

    calls = _ordered_calls(record)
    event_count = 2 + len(calls) * 5 + 4
    height = max(620, int(176 + event_count * 36 + 128))
    y = 166.0
    gap = 30.0
    messages: list[str] = []
    frames: list[str] = []

    question = _shorten(record.get("question"), 64)
    messages.append(_message(0, 1, y, f"question: {question}", color="#497fae", marker="arrow-blue"))
    y += gap
    messages.append(_self_message(1, y, "select next verifiable step"))
    y += gap + 8

    for call_index, call in enumerate(calls, start=1):
        frame_y = y - 24
        name = _text(call.get("name"), fallback="unknown_tool")
        args = _format_arguments(call.get("args"))
        outcome = _call_outcome(call)
        executed = outcome == ACTION_EXECUTED
        call_color = "#c98500" if executed else "#c74646"
        call_marker = "arrow-amber" if executed else "arrow-slate"
        messages.append(
            _message(
                1,
                2,
                y,
                f"#{call_index} {name}({args})",
                color=call_color,
                marker=call_marker,
            )
        )
        messages.append(
            f'<circle cx="473" cy="{y}" r="10" fill="{call_color}"/>'
            f'<text x="473" y="{y + 3.5}" class="call-no" text-anchor="middle">{call_index}</text>'
        )
        y += gap

        if not executed:
            reasons = "; ".join(_text(reason) for reason in _sequence(call.get("reasons")))
            messages.append(
                _message(
                    2,
                    1,
                    y,
                    f"call {_outcome_phrase(outcome)}: {_shorten(reasons, 60)}",
                    color="#c74646",
                )
            )
            y += gap
            frames.append(
                f'<rect x="188" y="{frame_y}" width="624" height="{y - frame_y - 12}" rx="8" '
                'fill="#fff4f4" stroke="#e6a2a2" stroke-width="1" stroke-dasharray="5 4"/>'
            )
            continue

        messages.append(_message(2, 3, y, "approved call with validated arguments", color="#238a68", marker="arrow-green"))
        y += gap
        output = _mapping(call.get("output"))
        provenance = _mapping(output.get("provenance"))
        is_reference = provenance.get("type") == "reference_knowledge"
        source_label = "reference catalog" if is_reference else "evidence source • read only"
        source_color = "#c98500" if is_reference else "#7867ad"
        source_marker = "arrow-amber" if is_reference else "arrow-violet"
        messages.append(_message(3, 4, y, source_label, color=source_color, marker=source_marker))
        y += gap
        summary = _result_summary(output)
        messages.append(
            _message(4, 3, y, summary, color=source_color, marker=source_marker, dashed=True)
        )
        y += gap

        status = _humanize(output.get("status"))
        coverage = _mapping(output.get("coverage"))
        complete = coverage.get("complete") is True
        receipt_ok = call.get("output_receipt_verified") is True
        evidence_class = "reference knowledge • not evidence" if is_reference else "case evidence"
        result_label = (
            f"{status} • {evidence_class} • coverage {'complete' if complete else 'incomplete'} • "
            f"receipt {'OK' if receipt_ok else 'not verified'}"
        )
        messages.append(
            _message(3, 2, y, result_label, color=source_color, marker=source_marker, dashed=True)
        )
        y += gap
        messages.append(
            _message(2, 1, y, "standardized ToolResult", color="#497fae", marker="arrow-blue", dashed=True)
        )
        y += gap + 8
        frames.append(
            f'<rect x="188" y="{frame_y}" width="824" height="{y - frame_y - 12}" rx="8" '
            f'fill="{"#fffaf0" if is_reference else "#f5faf8"}" stroke="{source_color}" '
            'stroke-width="0.9" stroke-dasharray="5 4" opacity="0.78"/>'
        )

    telemetry = _mapping(record.get("telemetry"))
    verifier = _mapping(telemetry.get("verifier_metrics"))
    if verifier.get("activated") is True:
        messages.append(
            _message(1, 5, y, "draft + receipt-verified findings only", color="#497fae", marker="arrow-blue")
        )
        y += gap
        included = verifier.get("included_results", verifier.get("usable_case_results", 0))
        rejected = sum(
            int(verifier.get(key, 0) or 0)
            for key in (
                "rejected_non_case_evidence",
                "rejected_invalid_or_unreceipted",
                "rejected_error_or_blocked",
                "rejected_empty_or_metadata_only",
            )
        )
        messages.append(
            _message(
                5,
                1,
                y,
                f"accepted findings: {included} • rejected: {rejected}",
                color="#497fae",
                marker="arrow-blue",
                dashed=True,
            )
        )
        y += gap + 10

    final_answer = _mapping(telemetry.get("final_answer_metrics"))
    final_label, final_color, _token = _answer_verdict(final_answer)
    messages.append(_message(1, 0, y, final_label, color=final_color, marker="arrow-green"))
    y += 58
    height = max(height, int(y + 78))

    model = _text(record.get("model"), fallback="model not recorded")
    provider = _text(record.get("provider"), fallback="provider not recorded")
    task_id = _text(record.get("task_id"), fallback="task without an identifier")
    title = "Recorded forensic investigation flow"
    subtitle = f"{task_id}  •  {model}  •  {provider}"

    legend_y = height - 48
    legend = f"""
      <g>
        <circle cx="49" cy="{legend_y}" r="5" fill="#c98500"/>
        <text x="61" y="{legend_y + 3}" class="legend">reference knowledge — not evidence</text>
        <circle cx="264" cy="{legend_y}" r="5" fill="#238a68"/>
        <text x="276" y="{legend_y + 3}" class="legend">case evidence with a valid receipt</text>
        <text x="1160" y="{legend_y + 3}" class="meta" text-anchor="end">Source: recorded execution trace; private reasoning is not shown.</text>
      </g>
    """

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {_SVG_WIDTH} {height}" role="img"
     aria-labelledby="trace-title trace-desc">
  <title id="trace-title">{escape(title)}</title>
  <desc id="trace-desc">Sequence of recorded model requests, approved forensic tools,
  standardized findings, final verification, and report generation.</desc>
  {_defs()}
  <rect width="100%" height="100%" fill="#ffffff"/>
  <path d="M 0 52 H {_SVG_WIDTH}" stroke="#e5ebf2" stroke-width="1"/>
  <text x="40" y="31" class="title">{escape(title)}</text>
  <text x="1160" y="31" class="subtitle" text-anchor="end">{escape(subtitle)}</text>
  <g>{''.join(frames)}</g>
  <g>{_actor_layer(height)}</g>
  <g>{''.join(messages)}</g>
  {legend}
</svg>
"""


def export_trace_svg(record: Mapping[str, Any], output: str | Path) -> Path:
    """Write the rendering to ``output`` and return its absolute path."""

    destination = Path(output).expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_trace_svg(record), encoding="utf-8")
    return destination


# ---------------------------------------------------------------------------
# The investigation diagram: a page-width figure summarising one completed case
# ---------------------------------------------------------------------------
#
# WHY this is drawn here, by hand, instead of by a diagramming library:
#
#   Graphviz would do the layout for us, but ``dot`` is a system binary. The
#   shipped image would have to carry it, and its layout changes between
#   releases — two renderings of the same run would then differ, in a project
#   that hashes what it produces.
#   Mermaid needs Node (or a headless browser) in the image for the same reason,
#   and is versioned the same way.
#   A Python SVG library (svgwrite, drawsvg) needs no binary, but it only emits
#   the XML below: it solves none of the layout, and adds a dependency a
#   reader has to inspect in exchange for f-strings.
#   Extending this module costs nothing: standard library only, offline by
#   construction, and a pure function of the record — the same run renders the
#   same bytes.
#
# And what none of the alternatives would have supplied is the thing this figure
# actually needed: a page-width, achromatic layout that survives a monochrome
# print. That is a typographic decision, not a layout-engine one.
#
# The figure is rendered in the source language only. It is a report artifact,
# not terminal chrome: every label on it is either a recorded identifier or a
# caption printed beside one, so routing it through the terminal's language
# layer could only move bytes an artifact hash depends on.

_DIAGRAM_WIDTH = 700
_DIAGRAM_MARGIN = 28.0
_SPINE_X = 54.0
_BODY_X = 82.0
_BODY_WIDTH = _DIAGRAM_WIDTH - _BODY_X - _DIAGRAM_MARGIN
_BLOCK_PAD = 12.0
_LABEL_WIDTH = 76.0
_TITLE_WIDTH = _BODY_WIDTH - 2 * _BLOCK_PAD
_VALUE_WIDTH = _TITLE_WIDTH - _LABEL_WIDTH

_BLOCK_TOP = 11.0
_TOKEN_ROW = 15.0
_TITLE_LEADING = 19.0
_ROW_LEADING = 15.0
_BLOCK_BOTTOM = 13.0
_BLOCK_GAP = 24.0

_TITLE_SIZE = 14.5
_ROW_SIZE = 11.5
_TOKEN_SIZE = 9.5
_FOOTNOTE_SIZE = 10.0

#: Achromatic by construction. A report is read on paper as often as on a
#: screen, and a reader who prints it in greyscale must lose nothing: every
#: distinction the figure draws is also spelled out as a word, so the ink here
#: only ever carries emphasis.
_INK = "#111111"
_INK_SOFT = "#444444"
_INK_FAINT = "#707070"
_RULE = "#999999"
_HATCH = "#cccccc"
_SHADE = "#eeeeee"
_PAPER = "#ffffff"


@dataclass(frozen=True, slots=True)
class _DiagramRow:
    """One labelled line of evidence about a step."""

    label: str
    value: str
    mono: bool = True
    max_lines: int = 2


@dataclass(frozen=True, slots=True)
class _DiagramBlock:
    """One step in the recorded order, drawn as one box on the spine."""

    kind: str
    shape: str
    marker: str = ""
    title: str = ""
    title_mono: bool = True
    title_lines: int = 2
    tokens: tuple[str, ...] = ()
    rows: tuple[_DiagramRow, ...] = ()
    #: Two fills, two meanings, neither of them a hue: a flat tint marks material
    #: that is not case evidence, hatching marks a call that never ran.
    shaded: bool = False
    hatched: bool = False
    dashed: bool = False


def _wrapped(
    value: str, *, width: float, size: float, mono: bool, max_lines: int
) -> list[str]:
    """Break text to a column, estimating advance width from the font size.

    No font metrics are available without a rendering engine, so the column is
    computed from a conservative average advance. Erring narrow costs a little
    whitespace; erring wide would push a recorded argument past the box edge,
    where the reader would never know it had been cut.
    """

    advance = size * (0.60 if mono else 0.52)
    columns = max(8, int(width / advance))
    lines = textwrap.wrap(
        value, width=columns, break_long_words=True, break_on_hyphens=False
    ) or [""]
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        lines[-1] = lines[-1][: max(1, columns - 1)].rstrip() + "…"
    return lines


def _declared_operation(call: Mapping[str, Any]) -> tuple[str, bool]:
    """The operation a call executed, and whether the call itself recorded it.

    A call may leave ``operation`` out, and then the function's declared default
    ran. The registry is the only place that knows which one that is, so the
    answer is asked of :func:`resolved_operation` rather than guessed here —
    a second private copy of that rule would eventually disagree with the
    runtime about what a defaulted call did.
    """

    arguments = _mapping(call.get("args"))
    recorded = arguments.get("operation")
    if isinstance(recorded, str) and recorded.strip():
        return _text(recorded), True

    name = call.get("name")
    if not isinstance(name, str) or not name:
        return "", False
    try:
        from forensic_agent.agent.tool_operations import resolved_operation
    except ImportError:
        return "", False
    try:
        resolved = resolved_operation(name, dict(arguments))
    except (KeyError, TypeError, ValueError):
        return "", False
    if isinstance(resolved, str) and resolved.strip():
        return _text(resolved), False
    return "", False


def _call_block(call: Mapping[str, Any], ordinal: int) -> _DiagramBlock:
    name = _text(call.get("name"), fallback="unrecorded function")
    operation, was_written = _declared_operation(call)
    heading = name if not operation else f"{name} · {operation}"
    if operation and not was_written:
        heading = f"{heading} *"

    outcome = _call_outcome(call)
    arguments = _format_arguments(call.get("args"), limit=180) or "no arguments recorded"
    rows = [_DiagramRow("arguments", arguments)]
    output = _mapping(call.get("output"))
    status = _humanize(output.get("status")) or "no status recorded"

    if outcome != ACTION_EXECUTED:
        reasons = "; ".join(_text(reason) for reason in _sequence(call.get("reasons")))
        rows.append(_DiagramRow("reason", reasons or "no reason recorded", max_lines=3))
        if output:
            # The token states what became of the CALL; this row states what the
            # RESULT declared. A call refused for its arguments and a call whose
            # tool returned an error are different facts, and a block showing
            # only one of them under one word is how they came to be confused.
            rows.append(_DiagramRow("returned", status, max_lines=2))
        return _DiagramBlock(
            kind=f"TOOL CALL {ordinal}",
            shape="number",
            marker=str(ordinal),
            title=heading,
            tokens=(_outcome_phrase(outcome).upper(),),
            rows=tuple(rows),
            hatched=True,
            dashed=True,
        )

    provenance = _mapping(output.get("provenance"))
    is_reference = provenance.get("type") == "reference_knowledge"
    coverage = _mapping(output.get("coverage"))
    # One separator throughout the figure. The shared summary helper predates it
    # and reads correctly either way, so the character is normalised here rather
    # than changed underneath the sequence diagram that already ships with it.
    summary = _result_summary(output).replace(" • ", " · ")
    rows.append(_DiagramRow("returned", f"{status} · {summary}", max_lines=3))
    tokens = (
        _outcome_phrase(outcome).upper(),
        "REFERENCE KNOWLEDGE" if is_reference else "CASE EVIDENCE",
        "COVERAGE COMPLETE" if coverage.get("complete") is True else "COVERAGE INCOMPLETE",
        "RECEIPT VERIFIED"
        if call.get("output_receipt_verified") is True
        else "RECEIPT NOT VERIFIED",
    )
    return _DiagramBlock(
        kind=f"TOOL CALL {ordinal}",
        shape="number",
        marker=str(ordinal),
        title=heading,
        tokens=tokens,
        rows=tuple(rows),
        shaded=is_reference,
    )


def _answer_block(
    record: Mapping[str, Any], calls: Sequence[Mapping[str, Any]]
) -> _DiagramBlock:
    telemetry = _mapping(record.get("telemetry"))
    final_answer = _mapping(telemetry.get("final_answer_metrics"))
    title, _color, token = _answer_verdict(final_answer)

    route = " · ".join(
        f"{label} {_text(value, fallback='not recorded')}"
        for label, value in (
            ("accepted from", final_answer.get("accepted_source")),
            ("verification", final_answer.get("verification_outcome")),
            ("publication", final_answer.get("publication_outcome")),
            # Who produced the characters of the published text.  The three
            # outcomes above say which path accepted the answer; only this says
            # whether the answer was assembled or written, which is the fact a
            # reader of a published answer has to have.
            ("authorship", final_answer.get("published_text_authorship")),
        )
    )
    verifier = _mapping(telemetry.get("verifier_metrics"))
    if verifier.get("activated") is True:
        included = verifier.get("included_results", verifier.get("usable_case_results", 0))
        rejected = sum(
            int(verifier.get(key, 0) or 0)
            for key in (
                "rejected_non_case_evidence",
                "rejected_invalid_or_unreceipted",
                "rejected_error_or_blocked",
                "rejected_empty_or_metadata_only",
            )
        )
        findings = f"accepted {included} · rejected {rejected}"
    else:
        findings = "the findings verifier did not run for this answer"

    executed = sum(1 for call in calls if _call_outcome(call) == ACTION_EXECUTED)
    case_backed = sum(
        1
        for call in calls
        if _mapping(_mapping(call.get("output")).get("provenance")).get("type")
        == "case_evidence"
    )
    return _DiagramBlock(
        kind="ANSWER",
        shape="target",
        title=title,
        title_mono=False,
        tokens=(token,),
        rows=(
            _DiagramRow("route", route),
            _DiagramRow("findings", findings),
            _DiagramRow(
                "basis",
                f"{executed} executed calls · {case_backed} returned case evidence",
            ),
        ),
    )


def _diagram_blocks(record: Mapping[str, Any]) -> list[_DiagramBlock]:
    calls = _ordered_calls(record)
    blocks = [
        _DiagramBlock(
            kind="INVESTIGATIVE QUESTION",
            shape="square",
            title=_text(record.get("question"), fallback="no question recorded"),
            title_mono=False,
            title_lines=3,
        )
    ]
    for ordinal, call in enumerate(calls, start=1):
        blocks.append(_call_block(call, ordinal))
    if not calls:
        blocks.append(
            _DiagramBlock(
                kind="EVIDENCE ACCESS",
                shape="square",
                title="no recorded tool call",
                title_mono=False,
                rows=(
                    _DiagramRow(
                        "recorded",
                        "the execution trace holds no recorded tool call",
                    ),
                ),
            )
        )
    blocks.append(_answer_block(record, calls))
    return blocks


def _laid_out(
    block: _DiagramBlock,
) -> tuple[list[str], list[tuple[str, list[str]]], float]:
    """Wrap one block's text and measure the box it needs."""

    title = _wrapped(
        block.title,
        width=_TITLE_WIDTH,
        size=_TITLE_SIZE,
        mono=block.title_mono,
        max_lines=block.title_lines,
    )
    rows = [
        (
            row.label,
            _wrapped(
                row.value,
                width=_VALUE_WIDTH,
                size=_ROW_SIZE,
                mono=row.mono,
                max_lines=row.max_lines,
            ),
        )
        for row in block.rows
    ]
    height = (
        _BLOCK_TOP
        + _TOKEN_ROW
        + len(title) * _TITLE_LEADING
        + sum(len(lines) for _, lines in rows) * _ROW_LEADING
        + _BLOCK_BOTTOM
    )
    return title, rows, height


def _diagram_marker(shape: str, marker: str, centre_y: float) -> str:
    if shape == "square":
        return (
            f'<rect x="{_SPINE_X - 9:.1f}" y="{centre_y - 9:.1f}" width="18" height="18" '
            f'rx="2" fill="{_INK}"/>'
        )
    if shape == "target":
        return (
            f'<circle cx="{_SPINE_X:.1f}" cy="{centre_y:.1f}" r="11" fill="{_INK}"/>'
            f'<circle cx="{_SPINE_X:.1f}" cy="{centre_y:.1f}" r="4.5" fill="{_PAPER}"/>'
        )
    return (
        f'<circle cx="{_SPINE_X:.1f}" cy="{centre_y:.1f}" r="11" fill="{_INK}"/>'
        f'<text x="{_SPINE_X:.1f}" y="{centre_y + 3.8:.1f}" class="marker" '
        f'text-anchor="middle">{escape(marker)}</text>'
    )


def _diagram_block_svg(block: _DiagramBlock, top: float) -> tuple[str, float, float]:
    """Draw one block at ``top``; return its markup, height, and marker centre."""

    title, rows, height = _laid_out(block)
    if block.hatched:
        fill = "url(#diagram-hatch)"
    else:
        fill = _SHADE if block.shaded else _PAPER
    dash = ' stroke-dasharray="5 4"' if block.dashed else ""
    parts = [
        f'<rect x="{_BODY_X:.1f}" y="{top:.1f}" width="{_BODY_WIDTH:.1f}" '
        f'height="{height:.1f}" rx="3" fill="{fill}" stroke="{_RULE}" '
        f'stroke-width="1.1"{dash}/>'
    ]
    left = _BODY_X + _BLOCK_PAD
    right = _BODY_X + _BODY_WIDTH - _BLOCK_PAD
    token_baseline = top + _BLOCK_TOP + 9.5
    parts.append(
        f'<text x="{left:.1f}" y="{token_baseline:.1f}" class="kind">'
        f"{escape(block.kind)}</text>"
    )
    if block.tokens:
        parts.append(
            f'<text x="{right:.1f}" y="{token_baseline:.1f}" class="token" '
            f'text-anchor="end">{escape(" · ".join(block.tokens))}</text>'
        )

    baseline = top + _BLOCK_TOP + _TOKEN_ROW + 13.0
    title_class = "heading mono" if block.title_mono else "heading"
    for line in title:
        parts.append(
            f'<text x="{left:.1f}" y="{baseline:.1f}" class="{title_class}">'
            f"{escape(line)}</text>"
        )
        baseline += _TITLE_LEADING

    baseline += 1.0
    for label, lines in rows:
        first = True
        for line in lines:
            if first:
                parts.append(
                    f'<text x="{left:.1f}" y="{baseline:.1f}" class="label">'
                    f"{escape(label)}</text>"
                )
                first = False
            parts.append(
                f'<text x="{left + _LABEL_WIDTH:.1f}" y="{baseline:.1f}" '
                f'class="value mono">{escape(line)}</text>'
            )
            baseline += _ROW_LEADING

    return "".join(parts), height, top + _BLOCK_TOP + _TOKEN_ROW + 8.0


def _diagram_defs() -> str:
    return f"""
    <defs>
      <marker id="diagram-flow" markerWidth="8" markerHeight="8" refX="6.5" refY="3.2"
              orient="auto"><polygon points="0 0, 8 3.2, 0 6.4" fill="{_INK}"/></marker>
      <pattern id="diagram-hatch" width="7" height="7" patternUnits="userSpaceOnUse"
               patternTransform="rotate(45)">
        <rect width="7" height="7" fill="{_PAPER}"/>
        <line x1="0" y1="0" x2="0" y2="7" stroke="{_HATCH}" stroke-width="1.6"/>
      </pattern>
      <style>
        text {{ font-family: "DejaVu Sans", "Segoe UI", Arial, Helvetica, sans-serif; }}
        .mono {{ font-family: "DejaVu Sans Mono", Consolas, "Courier New", monospace; }}
        .title {{ font-size: 17px; font-weight: 700; fill: {_INK}; }}
        .subtitle {{ font-size: 11px; fill: {_INK_SOFT}; }}
        .kind {{ font-size: {_TOKEN_SIZE}px; font-weight: 700; letter-spacing: 1px;
                 fill: {_INK_SOFT}; }}
        .token {{ font-size: {_TOKEN_SIZE}px; font-weight: 700; letter-spacing: 0.6px;
                  fill: {_INK}; }}
        .heading {{ font-size: {_TITLE_SIZE}px; font-weight: 700; fill: {_INK}; }}
        .label {{ font-size: {_ROW_SIZE}px; font-weight: 600; fill: {_INK_FAINT}; }}
        .value {{ font-size: {_ROW_SIZE}px; fill: {_INK}; }}
        .marker {{ font-size: 11px; font-weight: 700; fill: {_PAPER}; }}
        .footnote {{ font-size: {_FOOTNOTE_SIZE}px; fill: {_INK_SOFT}; }}
      </style>
    </defs>
    """


def render_investigation_diagram(record: Mapping[str, Any]) -> str:
    """Render one run as a page-width, print-first investigation diagram.

    Reads top to bottom: the question as it was asked, every recorded call with
    the function and operation that ran, what each returned, and the route by
    which the answer was accepted. Nothing here is inferred — a fact the figure
    cannot read out of the record is printed as not recorded.
    """

    blocks = _diagram_blocks(record)
    drawn: list[str] = []
    markers: list[tuple[str, str, float]] = []
    top = 100.0
    for block in blocks:
        markup, height, centre = _diagram_block_svg(block, top)
        drawn.append(markup)
        markers.append((block.shape, block.marker, centre))
        top += height + _BLOCK_GAP

    spine: list[str] = []
    for (_shape, _marker, start), (_next_shape, _next_marker, end) in zip(
        markers, markers[1:], strict=False
    ):
        spine.append(
            f'<line x1="{_SPINE_X:.1f}" y1="{start + 12:.1f}" x2="{_SPINE_X:.1f}" '
            f'y2="{end - 14:.1f}" stroke="{_INK_FAINT}" stroke-width="1.2" '
            'marker-end="url(#diagram-flow)"/>'
        )
    spine.extend(
        _diagram_marker(shape, marker, centre) for shape, marker, centre in markers
    )

    footnotes = [
        "Read top to bottom. Every box names the function and the operation exactly as "
        "recorded; identifiers are never translated.",
        "EXECUTED / FAILED / REFUSED BY THE OVERSIGHT POLICY / REFUSED BY THE TOOL is what "
        "became of the call, as the run recorded it; the returned row is what the result "
        "itself declared, which is a separate fact. CASE EVIDENCE / REFERENCE KNOWLEDGE "
        "is the evidentiary role of what came back. RECEIPT VERIFIED means the recorded "
        "output hash matched the payload.",
        "Source: the run's own execution trace. Private model reasoning is not recorded "
        "and is not shown.",
    ]
    if any("*" in block.title for block in blocks):
        footnotes.append(
            "An operation marked * was not written in the call; the function's declared "
            "default is shown, read from the operation registry."
        )
    footnote_lines: list[str] = []
    for note in footnotes:
        footnote_lines.extend(
            _wrapped(
                note,
                width=_DIAGRAM_WIDTH - 2 * _DIAGRAM_MARGIN,
                size=_FOOTNOTE_SIZE,
                mono=False,
                max_lines=3,
            )
        )

    footer_top = top - _BLOCK_GAP + 26.0
    footer = [
        f'<path d="M {_DIAGRAM_MARGIN:.1f} {footer_top:.1f} '
        f'H {_DIAGRAM_WIDTH - _DIAGRAM_MARGIN:.1f}" stroke="{_RULE}" stroke-width="0.8"/>'
    ]
    baseline = footer_top + 16.0
    for line in footnote_lines:
        footer.append(
            f'<text x="{_DIAGRAM_MARGIN:.1f}" y="{baseline:.1f}" class="footnote">'
            f"{escape(line)}</text>"
        )
        baseline += 13.0
    height = int(baseline + 14.0)

    case_id = _text(record.get("case_id"), fallback="")
    identity = " · ".join(
        part
        for part in (
            f"case {case_id}" if case_id else "",
            f"run {_text(record.get('task_id'), fallback='not recorded')}",
        )
        if part
    )
    engine = (
        f"model {_text(record.get('model'), fallback='not recorded')} · "
        f"provider {_text(record.get('provider'), fallback='not recorded')}"
    )
    title = "Recorded investigation flow"

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {_DIAGRAM_WIDTH} {height}"
     role="img" aria-labelledby="diagram-title diagram-desc">
  <title id="diagram-title">{escape(title)}</title>
  <desc id="diagram-desc">The recorded question, every recorded tool call with its function
  and operation, what became of each call, what each returned, and the route by which the
  answer was accepted.</desc>
  {_diagram_defs()}
  <rect width="100%" height="100%" fill="{_PAPER}"/>
  <text x="{_DIAGRAM_MARGIN:.1f}" y="36" class="title">{escape(title)}</text>
  <text x="{_DIAGRAM_MARGIN:.1f}" y="56" class="subtitle mono">{escape(identity)}</text>
  <text x="{_DIAGRAM_MARGIN:.1f}" y="71" class="subtitle mono">{escape(engine)}</text>
  <path d="M {_DIAGRAM_MARGIN:.1f} 82 H {_DIAGRAM_WIDTH - _DIAGRAM_MARGIN:.1f}"
        stroke="{_RULE}" stroke-width="0.8"/>
  <g>{''.join(drawn)}</g>
  <g>{''.join(spine)}</g>
  <g>{''.join(footer)}</g>
</svg>
"""


def export_investigation_diagram(record: Mapping[str, Any], output: str | Path) -> Path:
    """Write the investigation diagram to ``output`` and return its absolute path."""

    destination = Path(output).expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_investigation_diagram(record), encoding="utf-8")
    return destination


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Export a verifiable agent execution flow from JSON/JSONL to SVG.",
    )
    parser.add_argument("input", type=Path, help="input JSON or JSONL result")
    parser.add_argument("--task-id", help="exact task_id when the input contains multiple records")
    parser.add_argument("--output", required=True, type=Path, help="destination .svg file")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = _parser().parse_args(list(argv) if argv is not None else None)
    record = load_trace_record(args.input, task_id=args.task_id)
    output = export_trace_svg(record, args.output)
    print(output)
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
