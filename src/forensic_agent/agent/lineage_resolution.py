"""What the run itself can attest about a standardized result, and nothing more.

The result contract states the rule a published claim has to survive: a receipt
proves only that a payload matches a digest anyone who edited that payload could
have recomputed, so integrity comes from binding the finished result to the
trusted, append-only oversight chain, and from resolving every source and every
cited parent against what the RUN established rather than against what the
result says about itself.  :class:`~forensic_agent.core.result_contract.
DerivationLineageResolver` is the seam that check goes through.  This module is
the run's implementation of it.

Three registries, and each one exists because the fact it holds cannot be taken
from the result under examination.

* **The case's evidence sources.**  Built once, from what the run opened and
  attested before any tool ran, and immutable afterwards.  A result naming a
  digest is not evidence that the digest is this case's — that is exactly the
  claim being checked — so the digest is compared against the registry and never
  the other way round.
* **The audit bindings.**  Written AFTER standardization, because the record has
  to carry the finished payload digest and the payload already carries the
  chain pointers; writing it before would make the two reference each other.
  Each one is appended to the oversight chain and retained here, so a later check
  compares a result's CURRENT content against a record it cannot recompute.
* **The run's retained results.**  Not duplicated: a cited parent is looked up in
  :class:`~forensic_agent.agent.result_lineage.ResultLineageStore`, which already
  holds every complete standardized result of the run under its invocation id.

The honest refusal is the point, not a fallback.  A result whose producing
backend was never established, and one whose source carries no digest, are
DIAGNOSTIC: stored, readable, displayable, and never an evidential basis.  No
producer is invented for them and no lineage is fabricated to make them pass;
instead the refusal is written to the same append-only chain, so the record shows
that the run saw the result and could not bind it, rather than showing nothing at
all.

Nothing here is specific to any question, tool or artifact type: every decision is
taken from the contract's own fields, the run's registries and the chain.
"""

from __future__ import annotations

import hmac
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from forensic_agent.agent.result_lineage import ResultLineageStore
from forensic_agent.core.result_contract import (
    AuditBindingRecord,
    EvidenceClass,
    ResultInput,
    SourceInput,
    ToolContractError,
    audit_binding_record,
    payload_sha256,
)
from forensic_agent.core.result_contract import (
    ToolResult as ActiveToolResult,
)
from forensic_agent.core.result_reading import (
    UnreadableResult,
    read_result,
    receipt_is_valid,
)

LINEAGE_BINDING_METRICS_SCHEMA_ID = "forensic.lineage-binding-metrics.v1"

#: Why a standardized result could not be bound as a possible evidential basis.
#: Each is a statement about what the run failed to ESTABLISH, never about what
#: the result claims, and each leaves the result stored and displayable.
NO_OVERSIGHT_CHAIN = "no_oversight_chain"
NOT_BOUND_TO_OVERSIGHT_CHAIN = "not_bound_to_oversight_chain"
FOREIGN_CASE_RESULT = "foreign_case_result"
PRODUCER_NOT_ESTABLISHED = "producer_not_established"
SOURCE_NOT_DIGESTED = "source_not_digested"

#: Why a citation inside a derivation was refused.  Kept apart from the codes
#: above because they answer different questions: one is about a result this run
#: produced, the other about an input an operation claims to have consumed.
SOURCE_NOT_ATTESTED = "source_not_attested"
PARENT_UNIDENTIFIABLE = "parent_unidentifiable"
PARENT_FOREIGN_CASE = "parent_foreign_case"
PARENT_NOT_EARLIER = "parent_not_earlier"
PARENT_CYCLIC = "parent_cyclic"


@dataclass(frozen=True, slots=True)
class AttestedSource:
    """One evidence source this case established before any operation ran.

    ``sha256`` is the digest the run computed or verified at ingestion.  It is the
    only digest a source citation is ever compared against, which is what keeps a
    result from attesting itself.
    """

    case_id: str
    source_id: str
    sha256: str


@dataclass(frozen=True, slots=True)
class BoundArtifact:
    """One traced artifact whose audit binding this run wrote to the chain.

    An invocation produces more than one artifact — the complete standardized
    result the run retained and the bounded projection the model was handed —
    and they have different payload digests whenever the projection reduced
    anything.  Each is bound separately, because each is judged separately: the
    verifier reads the projection, the publication gates read the complete
    result, and a record covering only one of them would refuse the other.
    """

    record: AuditBindingRecord
    #: Position of the ACTION entry that recorded the observation, taken from the
    #: result's own provenance and used as the run's ordering of observations.
    oversight_sequence: int
    #: Position and digest of the chain entry that recorded this binding.
    binding_sequence: int
    binding_entry_sha256: str


class AuditChainRecorder(Protocol):
    """The append-only chain, seen from here: a body goes in, an entry comes out.

    The body is built from the entry hash it will follow, which the recorder
    supplies while holding its own lock — so the position a record names is the
    position it occupies.
    """

    def record_result_binding(
        self, build_entry: Callable[[str | None], Mapping[str, Any]]
    ) -> Mapping[str, Any]: ...


def _valid_sha256(value: object) -> str | None:
    text = str(value or "").casefold()
    return text if len(text) == 64 and all(c in "0123456789abcdef" for c in text) else None


def attested_case_sources(
    *,
    case_id: str,
    case_evidence_source: Any = None,
    evidence_source_attestation: Any = None,
    disk: Any = None,
) -> tuple[AttestedSource, ...]:
    """The evidence sources one run established, in the identity it publishes them under.

    The identities are read from the same objects the standardizer publishes
    ``provenance.source`` from, so the registry and the results cannot drift into
    describing the same source two ways.  A source the run could not digest
    produces no entry at all: an undigested source is exactly the one this
    registry must not be able to confirm.
    """

    sources: dict[str, AttestedSource] = {}

    def add(source_id: str, digest: object) -> None:
        checked = _valid_sha256(digest)
        if checked is None or not source_id:
            return
        sources.setdefault(source_id, AttestedSource(case_id, source_id, checked))

    if case_evidence_source is not None:
        add(
            str(getattr(case_evidence_source, "source_id", "")),
            getattr(case_evidence_source, "case_bundle_sha256", None),
        )
    for attested in (evidence_source_attestation, disk):
        digest = getattr(attested, "sha256", None) or getattr(attested, "image_sha", None)
        checked = _valid_sha256(digest)
        if checked is not None:
            add(f"evidence-sha256:{checked}", checked)
    return tuple(sources[key] for key in sorted(sources))


class RunLineageResolver:
    """The run's trusted registry and audit chain, answering the final check.

    Thread-safe for the same reason the retained-result store is: tool calls and
    the callbacks that record them are not guaranteed to be serialized by the
    graph runtime, and a half-written binding table would refuse a legitimate
    result for reasons that have nothing to do with the evidence.

    Every method of the protocol is total: it returns a verdict and never raises,
    because the final check treats an exception as a refusal anyway and a
    resolver that could crash would turn a question about evidence into a
    question about this class.
    """

    def __init__(
        self,
        store: ResultLineageStore,
        *,
        case_id: str,
        sources: Iterable[AttestedSource] = (),
        recorder: AuditChainRecorder | None = None,
    ) -> None:
        self._store = store
        self._case_id = case_id
        # Frozen at construction, and there is deliberately no method to extend
        # it: a source that could be added while the run is executing could be
        # added by the same call that then cites it.
        self._sources: Mapping[str, AttestedSource] = {
            source.source_id: source for source in sources if source.case_id == case_id
        }
        self._recorder = recorder
        self._lock = threading.Lock()
        self._bound: dict[str, BoundArtifact] = {}
        self._observation_sequence: dict[str, int] = {}
        self._refusals: dict[str, int] = {}
        self._citation_refusals: dict[str, int] = {}
        self._unreadable = 0
        self._historical = 0

    def _count(self, counter: dict[str, int], code: str) -> None:
        with self._lock:
            counter[code] = counter.get(code, 0) + 1

    def _refuse_citation(self, code: str) -> bool:
        """Record which citation refusal happened, and return the verdict.

        A refusal that returned a bare ``False`` would leave a run unable to say
        whether a derivation was refused for citing another case or for citing
        nothing at all, and those call for completely different next moves.
        """

        self._count(self._citation_refusals, code)
        return False

    # -- wiring ------------------------------------------------------------

    def bind_recorder(self, recorder: AuditChainRecorder | None) -> None:
        """Attach the run's oversight chain once the gate that owns it exists.

        The chain is created with the model-visible surface, after this resolver
        has to exist so the surface can be built against it.  Until one is bound
        nothing can be bound to it, and every result is refused rather than
        admitted on its own receipt.
        """

        self._recorder = recorder

    # -- recording ---------------------------------------------------------

    def record_result(self, tool: object, arguments: object, wire: object) -> None:
        """Bind one traced artifact to the chain, or record why it cannot be.

        Called after standardization for each artifact a call produces, which is
        the ordering :func:`~forensic_agent.core.result_contract.
        audit_binding_record` requires: the record carries the finished payload
        digest, and the payload carries the chain pointers, so building the
        record first would leave the two waiting on each other.

        Never raises.  A callback that failed in the middle of an investigation
        would abort a call that had already produced its evidence, so anything
        unreadable is counted and left unbound, which fails closed at the final
        check instead.
        """

        del tool, arguments
        try:
            result = read_result(wire)
        except (TypeError, UnreadableResult):
            with self._lock:
                self._unreadable += 1
            return
        if not isinstance(result, ActiveToolResult):
            # The historical envelope carries no audit-binding record and keeps
            # its own historical verdict; there is nothing here to bind and
            # nothing about it that this resolver decides.
            with self._lock:
                self._historical += 1
            return
        refusal = self._binding_refusal(result)
        if refusal is not None:
            self._disclose(result, refusal)
            return
        self._bind(result)

    def _binding_refusal(self, result: ActiveToolResult) -> tuple[str, str] | None:
        """Why this result may never be an evidential basis, or ``None``.

        Each refusal states something the run failed to establish.  None of them
        is repaired by supplying a value: an invented producer or a fabricated
        lineage would make the result pass while making the record false, which
        is the failure this whole contract exists to prevent.
        """

        provenance = result.provenance
        if self._recorder is None:
            return (
                NO_OVERSIGHT_CHAIN,
                "this run records no append-only oversight chain, so there is no "
                "trusted record a result could be bound to",
            )
        if provenance.case_id != self._case_id:
            return (
                FOREIGN_CASE_RESULT,
                "this result is bound to another case, and a run may only attest "
                "what it observed in its own",
            )
        if (
            provenance.raw_output_sha256 is None
            or provenance.oversight_entry_sha256 is None
            or provenance.oversight_sequence is None
        ):
            return (
                NOT_BOUND_TO_OVERSIGHT_CHAIN,
                "the call was not recorded on the oversight chain with a complete "
                "raw-output digest, so its content cannot be anchored to anything",
            )
        if provenance.evidence_class is EvidenceClass.REFERENCE:
            # Procedural knowledge is never case evidence, so the two rules below
            # ask nothing of it: it names no producing forensic component and
            # reads no case source, and refusing it for either would report a
            # missing attestation where none was ever claimed.
            return None
        if not any(backend.role == "producer" for backend in provenance.upstream_backends):
            return (
                PRODUCER_NOT_ESTABLISHED,
                "no component was established as the producer of this result, so "
                "nobody can say what produced its values or reproduce them; it "
                "stays a diagnostic result",
            )
        if (
            provenance.evidence_class is EvidenceClass.OBSERVED
            and _valid_sha256(provenance.source.sha256) is None
        ):
            return (
                SOURCE_NOT_DIGESTED,
                "the source this reading was taken from carries no digest, so no "
                "registry can confirm it is this case's evidence; it stays a "
                "diagnostic result",
            )
        return None

    def _bind(self, result: ActiveToolResult) -> None:
        """Append this artifact's audit binding to the chain and retain it."""

        recorder = self._recorder
        if recorder is None:  # pragma: no cover - _binding_refusal already refused this
            return
        built: AuditBindingRecord | None = None

        def build(previous: str | None) -> Mapping[str, Any]:
            nonlocal built
            built = audit_binding_record(result, previous_oversight_entry_sha256=previous)
            return {"bound": True, "binding": built.model_dump(mode="json")}

        try:
            entry = recorder.record_result_binding(build)
        except (ToolContractError, OSError, ValueError):
            # Nothing was appended, so nothing may be treated as bound.  The
            # refusal is disclosed through the metrics rather than through the
            # chain, since the chain is precisely what was unavailable.
            self._count(self._refusals, NOT_BOUND_TO_OVERSIGHT_CHAIN)
            return
        if built is None:  # pragma: no cover - the recorder always calls the builder
            return
        sequence = entry.get("seq")
        digest = _valid_sha256(entry.get("entry_hash"))
        if isinstance(sequence, bool) or not isinstance(sequence, int) or digest is None:
            # An entry the chain cannot position or identify attests nothing.
            self._count(self._refusals, NOT_BOUND_TO_OVERSIGHT_CHAIN)
            return
        provenance = result.provenance
        artifact = BoundArtifact(
            record=built,
            oversight_sequence=int(provenance.oversight_sequence or 0),
            binding_sequence=sequence,
            binding_entry_sha256=digest,
        )
        with self._lock:
            self._bound[built.payload_sha256] = artifact
            # The FIRST observation wins: an invocation observes once, and a later
            # artifact of the same call must not be able to move that call's
            # position in the order of observations.
            self._observation_sequence.setdefault(
                provenance.invocation_id, artifact.oversight_sequence
            )

    def _disclose(self, result: ActiveToolResult, refusal: tuple[str, str]) -> None:
        """Record, in the run's own chain, that a result was seen and not bound."""

        code, reason = refusal
        self._count(self._refusals, code)
        recorder = self._recorder
        if recorder is None:
            return
        provenance = result.provenance
        body = {
            "bound": False,
            "binding": None,
            "refusal_code": code,
            "reason": reason,
            "invocation_id": provenance.invocation_id,
            "case_id": provenance.case_id,
            "evidence_class": provenance.evidence_class.value,
            "evidential_role": "diagnostic",
        }
        try:
            recorder.record_result_binding(lambda _previous: body)
        except (OSError, ValueError):  # pragma: no cover - the chain is already broken
            return

    # -- the protocol ------------------------------------------------------

    def validate_audit_binding(self, result: ActiveToolResult) -> bool:
        """Whether this result's CURRENT content is the content the chain recorded.

        The comparison is against the record written after standardization, not
        against the pointers the result carries: keeping the pointers, editing the
        payload and re-attaching a receipt yields a self-consistent result whose
        payload digest the recorded record does not contain.  Only the chain
        position is taken from the retained record — everything else is
        recomputed from the result under examination, so the record cannot supply
        the very fact it is being asked to confirm.
        """

        try:
            digest = payload_sha256(result)
        except Exception:  # pragma: no cover - a validated result always canonicalizes
            return False
        with self._lock:
            artifact = self._bound.get(digest)
        if artifact is None:
            return False
        try:
            recomputed = audit_binding_record(
                result,
                previous_oversight_entry_sha256=(
                    artifact.record.previous_oversight_entry_sha256
                ),
            )
        except ToolContractError:
            return False
        return recomputed == artifact.record

    def validate_source_input(self, source: SourceInput) -> bool:
        """Whether a cited source is one this case established before the operation ran.

        The registry was frozen at construction, before any tool executed, so
        "established first" is a property of when it was built rather than a
        timestamp anyone has to trust.
        """

        if source.case_id != self._case_id:
            return self._refuse_citation(SOURCE_NOT_ATTESTED)
        attested = self._sources.get(source.source_id)
        if attested is None:
            return self._refuse_citation(SOURCE_NOT_ATTESTED)
        cited = _valid_sha256(source.sha256)
        if cited is None or not hmac.compare_digest(attested.sha256, cited):
            return self._refuse_citation(SOURCE_NOT_ATTESTED)
        return True

    def validate_result_input(
        self, parent: ResultInput, *, current_invocation_id: str | None
    ) -> bool:
        """Whether a cited parent is an earlier, identifiable result of this case.

        Four refusals, and they are different failures rather than four spellings
        of one.  A parent of another case is evidence about something else; a
        parent this run cannot identify is a citation of nothing; a parent that
        did not precede the citing call cannot have been consumed by it; and a
        call citing itself is a derivation with no observation under it.

        Order is what makes a cycle impossible rather than merely detected: every
        parent must occupy a strictly EARLIER position in the append-only chain
        than the call citing it, and a set of positions where each is smaller than
        the next cannot close.  The direct self-citation is named separately only
        so the refusal says which failure it was.
        """

        if parent.case_id != self._case_id:
            return self._refuse_citation(PARENT_FOREIGN_CASE)
        if current_invocation_id is None or parent.invocation_id == current_invocation_id:
            return self._refuse_citation(PARENT_CYCLIC)
        with self._lock:
            parent_artifact = self._bound.get(parent.payload_sha256)
            parent_observed = self._observation_sequence.get(parent.invocation_id)
            current_observed = self._observation_sequence.get(current_invocation_id)
        # IDENTIFIABLE: the run holds a binding for exactly this content, filed
        # under exactly this invocation.  The citation's digest is a lookup key
        # here and never an authority: it is confirmed against the record, not
        # believed because it was supplied.
        if parent_artifact is None or parent_observed is None or current_observed is None:
            return self._refuse_citation(PARENT_UNIDENTIFIABLE)
        if (
            parent_artifact.record.invocation_id != parent.invocation_id
            or parent_artifact.record.case_id != parent.case_id
        ):
            return self._refuse_citation(PARENT_UNIDENTIFIABLE)
        # RETAINED AND STILL ITSELF: the complete result the run holds under that
        # invocation must still verify against its own receipt, or the content
        # the citation names is no longer the content the run has.
        retained = self._store.retained(parent.invocation_id)
        if retained is None:
            return self._refuse_citation(PARENT_UNIDENTIFIABLE)
        try:
            parent_result = read_result(retained.wire)
        except (TypeError, UnreadableResult):
            return self._refuse_citation(PARENT_UNIDENTIFIABLE)
        if not isinstance(parent_result, ActiveToolResult) or not receipt_is_valid(parent_result):
            return self._refuse_citation(PARENT_UNIDENTIFIABLE)
        if parent_result.provenance.invocation_id != parent.invocation_id:
            return self._refuse_citation(PARENT_UNIDENTIFIABLE)
        if parent_result.provenance.case_id != self._case_id:
            return self._refuse_citation(PARENT_FOREIGN_CASE)
        # EARLIER: strictly before the citing call in the run's own record of
        # observations, which is the append-only chain's ordering and not a
        # timestamp any component could restate.
        if parent_observed >= current_observed:
            return self._refuse_citation(PARENT_NOT_EARLIER)
        return True

    # -- observability -----------------------------------------------------

    def metrics(self) -> dict[str, object]:
        """Content-free telemetry: what was bound, what was refused, and why.

        No payload, no source digest and no message reaches this record.  A
        refusal that only showed up as an empty verifier bundle would be
        indistinguishable from a run that found nothing, which is the difference
        this exists to make visible.
        """

        with self._lock:
            refusals = dict(self._refusals)
            citation_refusals = dict(self._citation_refusals)
            bound = len(self._bound)
            unreadable = self._unreadable
            historical = self._historical
        return {
            "schema_id": LINEAGE_BINDING_METRICS_SCHEMA_ID,
            "oversight_chain_bound": self._recorder is not None,
            "attested_sources": len(self._sources),
            "bound_artifacts": bound,
            "diagnostic_artifacts": sum(refusals.values()),
            "refusals_by_code": {code: refusals[code] for code in sorted(refusals)},
            "citation_refusals_by_code": {
                code: citation_refusals[code] for code in sorted(citation_refusals)
            },
            "historical_envelope_artifacts": historical,
            "unreadable_artifacts": unreadable,
        }


__all__ = [
    "FOREIGN_CASE_RESULT",
    "LINEAGE_BINDING_METRICS_SCHEMA_ID",
    "NOT_BOUND_TO_OVERSIGHT_CHAIN",
    "NO_OVERSIGHT_CHAIN",
    "PARENT_CYCLIC",
    "PARENT_FOREIGN_CASE",
    "PARENT_NOT_EARLIER",
    "PARENT_UNIDENTIFIABLE",
    "PRODUCER_NOT_ESTABLISHED",
    "SOURCE_NOT_ATTESTED",
    "SOURCE_NOT_DIGESTED",
    "AttestedSource",
    "AuditChainRecorder",
    "BoundArtifact",
    "RunLineageResolver",
    "attested_case_sources",
]
