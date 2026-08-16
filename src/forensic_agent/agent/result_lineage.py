"""The run's own store of results, and the resolver a citation goes through.

A model that needs an earlier value in a later call has two ways to supply it.
It can retype the value, which turns evidence into a model assertion nobody can
later separate from a plausible guess; or it can cite the call it came from and
the path to the field, and let the runtime fetch it.  Only the second survives
review, so the citing operations take a handle and this is what turns a handle
back into the exact text.

Three facts are checked before any value is returned, and each one fails closed:

* the cited invocation exists in THIS run's retained results;
* the cited digest matches the content the run holds for it — so a handle minted
  over one payload cannot silently resolve against a different one; and
* the cited result's own receipt verifies.

The store keeps the COMPLETE standardized results, not the bounded projections
the model read, because the complete result is the artifact the receipt covers.
The projection the model actually saw is a different artifact with its own
digest, so its digest is accepted as an alternative identity for the same
invocation — a model quoting the receipt it can see is citing honestly, and
refusing it would leave the affordance unusable exactly when the result was
large enough to be worth citing.

Keeping the complete results is also what makes reading MORE of one possible
without running anything: the page a model was not shown is already here, so
:mod:`forensic_agent.agent.result_navigator` serves it from this store rather
than asking the tool to produce it a second time.  The call that produced each
result is retained beside it, because a page cursor has to be bound to the query
that produced the set — a page of a differently filtered query is a page of a
different set.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from forensic_agent.core.result_navigation import (
    FIELD_PATH_SYNTAX,
    FieldPathError,
    citable_field_paths,
    resolve_field_path,
)
from forensic_agent.core.result_reading import (
    UnreadableResult,
    read_result,
    receipt_is_valid,
)


class CitationError(ValueError):
    """A citation could not be resolved against this run's retained results."""


class DeferredCitedValueResolver:
    """A citation resolver bound AFTER the tools that call it were built.

    A caller that builds the executable registry itself — the controlled console
    does, to derive the palette and the policy from real function names — builds
    it before the run, and therefore before the run's lineage store exists.  The
    slot is what such a surface holds instead: it is a resolver from the moment
    it is created, and the run fills it in before the first model request.

    Without this the citing operations were on the palette but dead on that path:
    every citation refused with "no lineage resolver is bound to this surface",
    which reads like a policy decision and is in fact a missing wire.  An unbound
    slot still raises, so a surface nobody bound refuses exactly as before rather
    than resolving against a store from some other run.
    """

    __slots__ = ("_resolver",)

    def __init__(self) -> None:
        self._resolver: Callable[[str, str, str | None], str] | None = None

    @property
    def bound(self) -> bool:
        """Whether a run has filled this slot in."""

        return self._resolver is not None

    def bind(self, resolver: Callable[[str, str, str | None], str]) -> None:
        """Fill the slot once.  Rebinding is refused, not silently honoured.

        One slot belongs to one run's retained results.  Letting a second run
        rebind it would leave tools built for the first resolving citations
        against results the operator never saw in that case.
        """

        if self._resolver is not None:
            raise RuntimeError("this citation resolver is already bound to a run")
        self._resolver = resolver

    def __call__(
        self,
        source_invocation_id: str,
        source_payload_sha256: str,
        source_field: str | None = None,
    ) -> str:
        """Resolve through the bound run, or raise if no run bound this slot."""

        resolver = self._resolver
        if resolver is None:
            raise CitationError(
                "no run has bound its retained results to this surface yet"
            )
        return resolver(source_invocation_id, source_payload_sha256, source_field)


@dataclass(frozen=True, slots=True)
class RetainedResult:
    """One complete standardized result, together with the call that produced it.

    The result alone would be enough to resolve a citation, since a citation
    names a value inside it.  A page cursor needs more: it continues a QUERY, and
    two calls of the same function over the same source with different filters
    produce different sets.  Retaining the call beside its result is what lets a
    cursor be bound to the filters that were in force and refused when they were
    not.
    """

    tool: str
    arguments: Mapping[str, Any] = field(default_factory=dict)
    wire: Mapping[str, Any] = field(default_factory=dict)


class ResultLineageStore:
    """Retained results of one run, indexed by invocation, with a resolver.

    Thread-safe because tool calls and the recording callbacks they trigger are
    not guaranteed to be serialized by the graph runtime; a half-written index
    would make a legitimate citation fail for reasons that have nothing to do
    with the evidence.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._complete: dict[str, RetainedResult] = {}
        #: Additional payload digests accepted as identifying the same call —
        #: the digests of what the model was actually handed.
        self._projected_digests: dict[str, set[str]] = {}

    # -- recording ---------------------------------------------------------

    def record_complete_result(self, tool: object, arguments: object, wire: object) -> None:
        """Index one complete standardized result under its invocation id.

        The identity is still the result's own provenance, never the caller's
        claim about which tool it ran; the call is retained alongside because a
        continuation has to be bound to the query it continues, not merely to the
        result it continues from.
        """

        identity = _invocation_and_digest(wire)
        if identity is None:
            return
        invocation_id, _digest = identity
        assert isinstance(wire, Mapping)
        with self._lock:
            self._complete[invocation_id] = RetainedResult(
                tool=str(tool),
                arguments=dict(arguments) if isinstance(arguments, Mapping) else {},
                wire=dict(wire),
            )

    def record_model_visible_result(
        self, tool: object, arguments: object, wire: object
    ) -> None:
        """Accept the digest of what the model read as an identity for that call.

        Only the digest is kept.  The projection is a reduced view, so resolving
        a value from it could return a shortened string where the run retained a
        complete one; the complete result stays the only thing a citation reads.
        """

        del tool, arguments
        identity = _invocation_and_digest(wire)
        if identity is None:
            return
        invocation_id, digest = identity
        if digest is None:
            return
        with self._lock:
            self._projected_digests.setdefault(invocation_id, set()).add(digest)

    # -- resolving ---------------------------------------------------------

    def retained(self, invocation_id: str) -> RetainedResult | None:
        """The complete result this run holds for one invocation, or ``None``."""

        with self._lock:
            return self._complete.get(invocation_id)

    def cited_value(
        self,
        source_invocation_id: str,
        source_payload_sha256: str,
        source_field: str | None,
    ) -> str:
        """Return the exact text one handle names, or raise :class:`CitationError`.

        This is the callable the tool surface binds as its citation resolver, so
        its signature is the handle itself: which call, which content, which
        field.
        """

        with self._lock:
            retained = self._complete.get(source_invocation_id)
            accepted_projections = set(self._projected_digests.get(source_invocation_id, ()))
        if retained is None:
            raise CitationError(
                f"no retained result of this run has invocation id {source_invocation_id!r}"
            )
        wire = retained.wire
        try:
            result = read_result(wire)
        except (TypeError, UnreadableResult) as error:  # pragma: no cover - defensive
            raise CitationError("the cited result is no longer readable") from error
        if not receipt_is_valid(result):
            raise CitationError("the cited result's own receipt does not verify")
        receipt = result.receipt
        complete_digest = receipt.payload_sha256 if receipt is not None else None
        cited = str(source_payload_sha256 or "").casefold()
        if cited != complete_digest and cited not in accepted_projections:
            raise CitationError(
                "the cited digest does not match the retained content of "
                f"{source_invocation_id!r}"
            )
        path = source_field.strip() if isinstance(source_field, str) else None
        if not path:
            path = _unambiguous_field_path(wire)
        try:
            return resolve_field_path(wire, path)
        except FieldPathError as error:
            raise CitationError(
                f"{error} Citable paths in that result: "
                f"{', '.join(citable_field_paths(wire, limit=12)) or '(none)'}"
            ) from error


def _unambiguous_field_path(wire: Mapping[str, Any]) -> str:
    """The single citable path of a result, or raise naming the candidates.

    A handle without a field is accepted only when there is exactly one text
    value it could mean.  Uniqueness is a fact about the result, not a
    preference, which is what separates this from picking a likely field: with
    two candidates the caller is told both and asked to name one.
    """

    candidates = citable_field_paths(wire, limit=12)
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        raise CitationError("the cited result carries no citable text value")
    raise CitationError(
        "the cited result has more than one citable value, so source_field is "
        f"required ({FIELD_PATH_SYNTAX}). Candidates: {', '.join(candidates)}"
    )


def _invocation_and_digest(wire: object) -> tuple[str, str | None] | None:
    """Read a record's invocation id and receipt digest without validating it.

    Recording must never raise into a tool call: a value that is not a readable
    envelope simply is not indexed, and a later citation of it fails as an
    unknown invocation rather than as a crash in the middle of an investigation.
    """

    if not isinstance(wire, Mapping):
        return None
    provenance = wire.get("provenance")
    if not isinstance(provenance, Mapping):
        return None
    invocation_id = provenance.get("invocation_id")
    if not isinstance(invocation_id, str) or not invocation_id:
        return None
    receipt = wire.get("receipt")
    digest = receipt.get("payload_sha256") if isinstance(receipt, Mapping) else None
    return invocation_id, digest.casefold() if isinstance(digest, str) else None


__all__ = ["CitationError", "ResultLineageStore", "RetainedResult"]
