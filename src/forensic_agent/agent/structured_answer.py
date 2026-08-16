"""The last step is assembly, not another model call.

The model returns segments: its own sentences, and opaque references to values it
wants stated.  The runtime re-checks each reference and puts the stored value in.
After that there is no model — what is published is what the program assembled.

That places the boundary where it was meant to be.  Choosing which field answers
a question is a language problem and stays with the model; producing the value is
a lookup and stays with the runtime.  The model can still cite the wrong field,
and a wrong field is a wrong answer — but it cannot invent a value, and it cannot
mistype one, because it never types one.

Anything malformed publishes nothing.  A draft that is not the declared shape, a
reference this run never issued, a path outside the data the model was shown, or
a value that is not a single value: each ends the same way, because a sentence
assembled around a value that could not be produced is not a partial answer.

Which is why the shape is also declared to the PROVIDER, from the same table the
assembler reads.  A terminal request answered in prose used to end the run with
nothing published, and the value the model had found was thrown away over the
form of the sentence around it.  Constrained decoding removes the choice instead
of hoping for it; the schema derived here never becomes the only check, because
what it cannot express the assembler still refuses.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

from forensic_agent.core.config import structured_kwargs

_STRUCTURED_ANSWER_METRICS_SCHEMA_ID = "forensic.structured-answer-metrics.v1"

_SEGMENTS = "segments"
_TYPE = "type"
_TEXT = "text"
_BOUND_VALUE = "bound_value"

#: The declared shape, written once.  Every segment kind maps to the string
#: fields it is made of, and both readers of the shape come from here: the
#: assembler below, and the JSON Schema the provider is given to constrain the
#: model.  Two hand-written copies would eventually disagree, and a disagreement
#: here means the provider guarantees a document the runtime refuses — a
#: guarantee that has quietly stopped being one.
_SEGMENT_FIELDS: Mapping[str, tuple[str, ...]] = {
    _TEXT: (_TEXT,),
    _BOUND_VALUE: ("result_ref", "path"),
}

#: What the model is told about deliveries and about the shape its answer takes.
#: It is a section of the system prompt, and therefore part of the model surface:
#: a run that did not ask for the binding never sees it, so the base model
#: surface stays exactly what it was.
STRUCTURED_ANSWER_NOTE = (
    "MODEL ANSWER CONTRACT: every tool result reaches you inside a delivery envelope "
    '{"schema_version": "forensic.model-result.v1", "result_ref": "R001", "result": '
    "<the result>}. result_ref names THAT delivery, and each delivery has its own: two "
    "pages of one result are two deliveries, so a row index only means anything against "
    "the result_ref it was read in.\n"
    "Your FINAL ANSWER is not prose. Return one JSON object of the form "
    '{"segments": [...]}, where each segment is either {"type": "text", "text": "..."} '
    'for wording you write yourself, or {"type": "bound_value", "result_ref": "R001", '
    '"path": "data.attributes.<field>"} for an observed value you want stated. The '
    "runtime looks that value up in the delivery you named and inserts it verbatim; you "
    "never type it. A path may enter only data.attributes or data.items of that "
    "delivery, may index a list with [n], and must land on a single value rather than on "
    "an object or a list.\n"
    "Choosing which field answers the question is yours. Producing its characters is not: "
    "a value you retype is a value nobody can check afterwards, so never write an observed "
    "value into a text segment. If any segment does not resolve, nothing at all is "
    "published — so cite a field the named result actually has, and where the evidence "
    "does not answer the question, say that plainly in a text segment."
)

#: The reserved terminal request, in the form the binding requires.  The prose
#: wording it replaces stays where it is: a run without the binding must reach
#: the same request it always did.
STRUCTURED_TERMINAL_REQUEST = (
    "Stop investigating. Based ONLY on the tool results above, state your final "
    "conclusion now as the JSON segment object described in MODEL ANSWER CONTRACT, "
    "citing every observed value by the result_ref of the delivery you read it in. "
    "Return that object and nothing else. If the evidence is inconclusive, say so "
    "explicitly in a text segment."
)


def segment_document_schema() -> dict[str, Any]:
    """The declared shape as a JSON Schema, derived from :data:`_SEGMENT_FIELDS`.

    Written in the subset a provider enforcing ``strict`` accepts: every object
    is closed and lists all of its properties as required, and the kinds are an
    ``anyOf`` because that is the only union such a provider honours.

    It is a narrowing of what the assembler accepts, never a replacement for it.
    A strict schema cannot say ``minItems``, so an empty segment list passes here
    and is refused below — which is the reason the runtime keeps checking.
    """

    return {
        "type": "object",
        "additionalProperties": False,
        "required": [_SEGMENTS],
        "properties": {
            _SEGMENTS: {
                "type": "array",
                "items": {
                    "anyOf": [
                        {
                            "type": "object",
                            "additionalProperties": False,
                            "required": [_TYPE, *fields],
                            "properties": {
                                _TYPE: {"type": "string", "enum": [kind]},
                                **{name: {"type": "string"} for name in fields},
                            },
                        }
                        for kind, fields in _SEGMENT_FIELDS.items()
                    ]
                },
            }
        },
    }


def segment_document_response_format() -> dict[str, Any]:
    """The request parameter that holds one reply to the declared shape.

    Constrained decoding masks the tokens that would leave the schema, so the
    model does not have to CHOOSE to answer in segments — the failure it
    prevents being a terminal request answered in prose, and a run that
    published nothing because the value it had found could no longer be bound.

    The project already has one way of writing such a parameter, so this reuses
    it rather than restating the envelope a second time.
    """

    response_format = structured_kwargs(segment_document_schema())["response_format"]
    if not isinstance(response_format, dict):  # pragma: no cover - constructed above
        raise TypeError("a response format must be an object")
    return response_format


def empty_structured_answer_metrics(*, enabled: bool) -> dict[str, object]:
    """Content-free telemetry for the assembly step."""

    return {
        "schema_id": _STRUCTURED_ANSWER_METRICS_SCHEMA_ID,
        "enabled": enabled,
        "decision": "not_evaluated" if enabled else "arm_disabled",
        # What became of the decoding constraint on the terminal request.  A run
        # whose provider refused it and one that never asked both end up reading
        # whatever the model chose to return, and only this tells them apart.
        "response_format": "not_requested",
        "segments": 0,
        "text_segments": 0,
        "bound_values": 0,
        "unresolved_values": 0,
    }


def _segments_of(draft: object) -> list[Mapping[str, object]] | None:
    """The declared segment list, or ``None`` when the draft is not that shape."""

    document = draft
    if isinstance(document, str):
        text = document.strip()
        if not text:
            return None
        try:
            document = json.loads(text)
        except (TypeError, ValueError):
            return None
    if not isinstance(document, Mapping):
        return None
    segments = document.get(_SEGMENTS)
    if isinstance(segments, str) or not isinstance(segments, Sequence):
        return None
    if not segments or not all(isinstance(segment, Mapping) for segment in segments):
        return None
    return [segment for segment in segments if isinstance(segment, Mapping)]


def is_segment_document(draft: object) -> bool:
    """Whether a draft is the declared shape at all, before anything is resolved.

    Asked by the phase deciding whether the run still owes itself a conclusion it
    can publish: under the binding, prose assembles into nothing, so a run whose
    only draft is prose has no draft.  It reads through the same reader assembly
    reads through, because a second opinion about what counts as the shape would
    let the run skip the request for a draft it is then going to refuse.
    """

    return _segments_of(draft) is not None


def model_authored_text(draft: object) -> str:
    """The model's own sentences from a draft, without the values it cited.

    A ``bound_value`` segment is a lookup the runtime performed, so nothing in it
    was typed by the model and a check for fabricated identifiers has nothing to
    establish about it.  A ``text`` segment carries no such guarantee: it is
    ordinary model prose, and it is exactly what such a check exists to read.
    Separating the two is what lets grounding apply here without holding an
    answer against the values the runtime produced for it.

    The segments are joined by a newline rather than concatenated, because
    concatenation would splice the ends of two sentences into a token that occurs
    in neither and in the published answer only if the value between them were
    empty.  No form the grounding gate recognises can span a newline, so joining
    this way reads each sentence exactly as the model wrote it.

    Read through the same segment reader assembly reads through: a second opinion
    about what counts as a text segment would let the checked text and the
    published text describe different documents.
    """

    segments = _segments_of(draft)
    if segments is None:
        return ""
    return "\n".join(
        value
        for value in (
            segment.get(_TEXT) for segment in segments if segment.get(_TYPE) == _TEXT
        )
        if isinstance(value, str)
    )


def assemble_structured_answer(
    draft: object,
    references,
    *,
    enabled: bool = True,
) -> tuple[str, dict[str, object]]:
    """Build the published answer from segments and the values they reference.

    ``references`` is the run's naming of what it delivered — either the registry
    itself or the bound resolver it hands to the phase that publishes, which runs
    after the tool surface is gone and holds only the callable.

    Returns the text to publish and the telemetry for the step.  The text is
    empty whenever anything did not hold, which is what withholds publication:
    there is no partially assembled answer, because a sentence written around a
    value does not survive without it.
    """

    metrics = empty_structured_answer_metrics(enabled=enabled)
    resolve = getattr(references, "resolve", references)
    if not callable(resolve):
        # A run with no naming of its own deliveries can re-check nothing, so it
        # publishes nothing rather than a draft whose values went unverified.
        metrics["decision"] = "no_result_references"
        return "", metrics
    segments = _segments_of(draft)
    if segments is None:
        metrics["decision"] = "not_a_structured_draft"
        return "", metrics
    metrics["segments"] = len(segments)

    parts: list[str] = []
    text_segments = 0
    bound_values = 0
    unresolved = 0

    for segment in segments:
        kind = segment.get(_TYPE)
        fields = _SEGMENT_FIELDS.get(kind) if isinstance(kind, str) else None
        if fields is None:
            metrics["decision"] = "unknown_segment_type"
            return "", metrics
        # Read through the declared fields rather than by hand, so a kind cannot
        # gain a field the provider is told to require and this loop ignores.
        # The outcome NAMES stay spelled out below: the run's telemetry and the
        # subsystem document are both written from that vocabulary, and a name
        # composed at runtime is one neither an examiner nor a check can find.
        values = tuple(segment.get(name) for name in fields)
        malformed = not all(isinstance(value, str) for value in values)
        if kind == _TEXT:
            if malformed:
                metrics["decision"] = "malformed_text_segment"
                return "", metrics
            text_segments += 1
            parts.append(str(values[0]))
            continue
        if kind == _BOUND_VALUE:
            if malformed:
                metrics["decision"] = "malformed_bound_value_segment"
                return "", metrics
            label, path = (str(value) for value in values)
            try:
                value = resolve(label, path)
            except Exception:
                # A resolver explains itself by naming fields and candidate
                # paths of a result, and those describe the evidence.  The
                # decision travels; the explanation stays in the run's records.
                unresolved += 1
                continue
            if not isinstance(value, str):
                unresolved += 1
                continue
            bound_values += 1
            # Inserted verbatim and never re-read: text recovered from evidence
            # cannot become a segment of the answer that quotes it.
            parts.append(value)
            continue
        # A kind declared above but not handled here.  It contributes nothing to
        # the text, so publishing the rest would drop a segment the model wrote
        # and call the remainder its answer.
        metrics["decision"] = "unknown_segment_type"
        return "", metrics

    metrics["text_segments"] = text_segments
    metrics["bound_values"] = bound_values
    metrics["unresolved_values"] = unresolved
    if unresolved:
        metrics["decision"] = "unresolved_reference"
        return "", metrics
    assembled = "".join(parts)
    if not assembled.strip():
        metrics["decision"] = "empty_answer"
        return "", metrics
    metrics["decision"] = "assembled"
    return assembled, metrics
