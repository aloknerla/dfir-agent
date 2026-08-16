"""Short opaque names for the results a model saw, and what they may reach.

A model that wants a value in its answer has to be able to say WHICH value, and
the obvious handles are the wrong ones to give it.  A digest in the model's hands
is a digest it can retype; a store path is an authority it should not hold; and
neither is material anyone reasons from.  What it needs is a name — short enough
to write, meaningless outside this run, and bound privately to everything the
runtime will re-check before it inserts anything.

Every model-visible projection gets one label, and every page gets its own.  Two
pages of one result are not the same document: row 3 of the second page is a
different row from row 3 of the first, and a name shared between them would let
an index quietly point at the wrong record.

What a label reaches is deliberately narrow: the scalar values inside the data
the model was shown.  Not the provenance, not the receipt, not the warnings or
the error, and nothing from the complete result the projection left out.  The
model may cite what it read; it may not reach past it.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Mapping
from typing import Any

from forensic_agent.core.repro import canonical_json, sha256_hex
from forensic_agent.core.result_navigation import FieldPathError, resolve_field_path

_RESULT_REFERENCE_SCHEMA_ID = "forensic.result-reference.v1"

#: ``R`` and three digits.  Short enough to appear in a sentence the model
#: writes, and carrying nothing of the content it names.
_LABEL = re.compile(r"^R\d{3,}$")

#: The only roots a citation may enter.  Everything else in the envelope
#: describes the record rather than the evidence, and a value taken from it
#: would be a statement about bookkeeping presented as a finding.
_CITABLE_ROOTS = ("data.attributes", "data.items")


class ReferenceError(RuntimeError):
    """A label, a path, or the content behind them did not hold up."""


class ResultReferenceRegistry:
    """The run's own naming of the results its model was shown.

    Owned by one run and meaningful only inside it.  Nothing here grants access:
    a label is a key into a private mapping this run built while it worked, and a
    label from anywhere else names nothing.
    """

    def __init__(self, *, case_id: str) -> None:
        self._case_id = case_id
        self._lock = threading.Lock()
        self._bindings: dict[str, dict[str, Any]] = {}
        self._issued = 0

    @property
    def case_id(self) -> str:
        return self._case_id

    def assign(
        self,
        *,
        invocation_id: str,
        complete_sha256: str,
        projected_sha256: str,
        projection: Mapping[str, Any],
    ) -> str:
        """Name one model-visible projection, and remember what it was.

        A projection of another case is refused rather than named: a label is a
        promise that the runtime can re-check what stands behind it, and it can
        only make that promise about this run's own case.
        """

        provenance = projection.get("provenance")
        case_id = (
            provenance.get("case_id") if isinstance(provenance, Mapping) else None
        )
        if case_id is not None and case_id != self._case_id:
            raise ReferenceError(
                "a result of another case cannot be named by this run's registry"
            )
        content = canonical_json(projection.get("data"))
        with self._lock:
            self._issued += 1
            label = f"R{self._issued:03d}"
            self._bindings[label] = {
                "schema_id": _RESULT_REFERENCE_SCHEMA_ID,
                "label": label,
                "case_id": self._case_id,
                "invocation_id": invocation_id,
                "complete_sha256": complete_sha256,
                "projected_sha256": projected_sha256,
                # The exact document the label was issued for.  Held so a value
                # can be taken from what the model actually read, and so content
                # edited afterwards stops resolving instead of being quoted.
                "projection": projection,
                "content_sha256": sha256_hex(content),
            }
            return label

    def reserve(self) -> str:
        """Take the next delivery name, before the document it names exists.

        Reserved first because the projector has to budget for the envelope that
        will carry it, and because a name is issued per delivery: two pages of one
        result are two deliveries and never share one.  A name that is never bound
        refers to nothing.
        """

        with self._lock:
            self._issued += 1
            return f"R{self._issued:03d}"

    def bind(self, label: str, *, projection: Mapping[str, Any]) -> None:
        """Attach one reserved name to the result that was actually delivered.

        Bound against the final document, so a projection replaced on the way out
        leaves its name standing for nothing rather than for something the model
        never received.
        """

        provenance = projection.get("provenance")
        receipt = projection.get("receipt")
        case_id = provenance.get("case_id") if isinstance(provenance, Mapping) else None
        if case_id is not None and case_id != self._case_id:
            raise ReferenceError(
                "a result of another case cannot be named by this run's registry"
            )
        invocation_id = (
            provenance.get("invocation_id") if isinstance(provenance, Mapping) else None
        )
        if not isinstance(invocation_id, str) or not invocation_id.strip():
            raise ReferenceError("a named result must carry the invocation that produced it")
        with self._lock:
            self._bindings[label] = {
                "schema_id": _RESULT_REFERENCE_SCHEMA_ID,
                "label": label,
                "case_id": self._case_id,
                "invocation_id": invocation_id.strip(),
                "complete_sha256": str(
                    (provenance.get("raw_output_sha256") if isinstance(provenance, Mapping) else "")
                    or ""
                ),
                "projected_sha256": str(
                    (receipt.get("payload_sha256") if isinstance(receipt, Mapping) else "") or ""
                ),
                "projection": projection,
                "content_sha256": sha256_hex(canonical_json(projection.get("data"))),
            }

    def binding(self, label: str) -> dict[str, Any]:
        """The private record behind one label, for the runtime's own checks."""

        with self._lock:
            record = self._bindings.get(label)
        if record is None:
            raise ReferenceError(f"no result of this run is named {label!r}")
        return dict(record)

    def labels(self) -> list[str]:
        with self._lock:
            return sorted(self._bindings)

    def resolve(self, label: str, path: str) -> str:
        """Return the exact text one label and path name, or raise.

        Every step is checked here rather than trusted from the caller: that the
        label belongs to this run, that the path enters only the data the model
        was shown, that the content behind the label is still the content it was
        issued for, and that what the path lands on is a single value.
        """

        if not isinstance(label, str) or not _LABEL.match(label.strip()):
            raise ReferenceError(f"{label!r} is not a result reference of this run")
        record = self.binding(label.strip())
        cited = (path or "").strip()
        if not cited:
            raise ReferenceError("a result reference must name the field it means")
        if not any(
            cited == root or cited.startswith(root + ".") or cited.startswith(root + "[")
            for root in _CITABLE_ROOTS
        ):
            raise ReferenceError(
                f"{cited!r} is outside the model-visible data; only "
                f"{' and '.join(_CITABLE_ROOTS)} may be cited"
            )
        projection = record["projection"]
        if sha256_hex(canonical_json(projection.get("data"))) != record["content_sha256"]:
            raise ReferenceError(
                f"the content behind {label!r} is no longer what the label was issued for"
            )
        # One field-path resolver for the whole package: the citable-scalar rule
        # (a boolean is a structure, not a single citable value) and the path
        # grammar are owned by :mod:`forensic_agent.core.result_navigation`, so a
        # citation resolves here exactly as it does everywhere else it is checked.
        try:
            return resolve_field_path(projection, cited)
        except FieldPathError as exc:
            raise ReferenceError(str(exc)) from exc
