"""How a result is delivered to the model, kept apart from what the result is.

A model that wants to cite a value needs a name for the document it read.  That
name is a fact about a delivery — this run handed the model this document — and
it is not a fact about the evidence.  Putting it inside the result would make the
forensic record carry a detail of its own transport, and would either break the
receipt that attests the payload or force the payload to be re-signed for a
reason that has nothing to do with what was observed.

So the name goes outside, in an envelope of its own:

    {"schema_version": "forensic.model-result.v1",
     "result_ref": "R001",
     "result": <the unchanged, receipt-verified ToolResult>}

The inner result is untouched.  A small result keeps the receipt its tool signed;
a shortened one keeps the receipt its projection signed.  Neither is re-signed to
carry a label, because the label is not theirs.

The envelope is not evidence.  It is never accepted as a result, never enters
lineage, and every reader of evidence reaches through ``result`` to the document
that actually was one.  What the envelope gets instead is its own digest in the
model-visible trace, because what the model received is the envelope and that is
the thing an examiner needs to be able to check.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

MODEL_RESULT_SCHEMA_ID = "forensic.model-result.v1"


def wrap_for_model(result: object, *, result_ref: str) -> dict[str, Any]:
    """Address one finished result to the model under a delivery name."""

    if not isinstance(result_ref, str) or not result_ref.strip():
        raise ValueError("a model-facing envelope must carry a delivery reference")
    return {
        "schema_version": MODEL_RESULT_SCHEMA_ID,
        "result_ref": result_ref.strip(),
        "result": result,
    }


def is_model_result_envelope(value: object) -> bool:
    """Whether this is a delivery envelope rather than a result."""

    return (
        isinstance(value, Mapping)
        and value.get("schema_version") == MODEL_RESULT_SCHEMA_ID
        and "result" in value
    )


def unwrap_result(value: object) -> object:
    """The result inside a delivery envelope, or the value itself.

    Every reader of evidence goes through here rather than through the envelope,
    so a delivery detail can never be mistaken for part of a finding.
    """

    if is_model_result_envelope(value):
        return value["result"]  # type: ignore[index]
    return value


def envelope_reference(value: object) -> str | None:
    """The delivery name on one envelope, when it is one."""

    if not is_model_result_envelope(value):
        return None
    reference = value["result_ref"]  # type: ignore[index]
    return reference if isinstance(reference, str) and reference.strip() else None
