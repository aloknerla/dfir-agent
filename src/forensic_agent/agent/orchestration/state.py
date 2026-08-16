"""Typed configuration and state shared by investigation phases."""

from __future__ import annotations

from collections.abc import Callable, Collection
from dataclasses import dataclass
from typing import Any

from forensic_agent.agent.case_evidence import CaseEvidenceSource
from forensic_agent.agent.execution_budget import _CellExecutionBudget, _FrozenRequestTimeout
from forensic_agent.agent.lineage_resolution import RunLineageResolver
from forensic_agent.agent.model_surface import _PreparedModelSurface
from forensic_agent.agent.model_telemetry import _ModelRequestLedger
from forensic_agent.agent.model_transport import _RequestPayloadLedger
from forensic_agent.agent.result_lineage import DeferredCitedValueResolver
from forensic_agent.core.config import DecodingProfile
from forensic_agent.core.controlled_scratch import ControlledScratchSession
from forensic_agent.core.evidence_source import (
    EvidenceSourceAttestation,
    EvidenceSourceError,
    EvidenceSourceRuntimeGuard,
)
from forensic_agent.tools.pcap_sources import PcapSourceCatalog


@dataclass(frozen=True, slots=True)
class InvestigationConfig:
    """Frozen inputs for one investigation."""

    disk: Any
    question: str
    case_context: str | None
    prepared_tools: Collection[Any] | None
    model: str
    base_url: str
    api_key: str
    provider: str | None
    provider_quantizations: tuple[str, ...] | None
    decoding_profile: DecodingProfile
    decoding_parameters: Collection[str] | None
    max_steps: int
    memory_path: str | None
    pcap_path: str | None
    pcap_sources: PcapSourceCatalog | None
    verbose: bool
    guidance: str | None
    on_tool: Any
    verify: bool
    first_investigation_tool_choice: str | None
    verify_model: str | None
    verification_provider: str | None
    verification_provider_quantizations: tuple[str, ...] | None
    verification_fail_closed: bool
    spotlight: bool
    policy: Any
    oversight_path: str
    visible_tools: Collection[str] | None
    #: Whether this run may be handed a function withdrawn from the default
    #: surface. It is recorded here rather than resolved inside the builder so
    #: the frozen configuration states which palette the run actually used.
    include_quarantined_tools: bool
    standardize_tool_results: bool
    case_id: str | None
    invocation_namespace: str | None
    tool_result_trace_path: str | None
    telemetry: dict[str, object] | None
    sdk_max_retries: int
    request_timeout_s: float | None
    cell_started_monotonic: float | None
    cell_deadline_monotonic: float | None
    max_model_requests: int | None
    max_tool_calls: int | None
    evidence_source_attestation: EvidenceSourceAttestation | None
    evidence_source_guard: EvidenceSourceRuntimeGuard | None
    controlled_scratch: ControlledScratchSession | None
    expected_system_prompt_sha256: str | None
    expected_tool_registry_sha256: str | None
    case_evidence_source: CaseEvidenceSource | None
    system_prompt_override: str | None
    record_full_tool_outputs: bool
    recover_incomplete_run: bool
    autonomous_tool_selection: bool
    enforce_explicit_multisource_coverage: bool
    ambiguous_memory_candidate_corroboration: bool
    #: Whether results reach the model inside a delivery envelope carrying the
    #: name a final answer can cite.  Off by default; the production console
    #: opts in.
    deliver_model_result_envelope: bool
    #: The slot a caller that built its OWN executable registry put into that
    #: registry's citing operations. The run fills it in with its retained
    #: results before the first model request; a run that is handed none binds
    #: nothing, because it built the tools itself and bound them directly.
    citation_resolver_slot: DeferredCitedValueResolver | None = None
    #: Whether the recovery pass may state which reachable regions of the medium
    #: went unread before the run concludes.  On by default; when set False the
    #: arm sends no extra request and records itself as arm_disabled.  Defaulted
    #: here rather than at every call site so a run that never mentions it keeps
    #: the default behaviour unchanged.
    evidence_region_advisory: bool = True

    #: Whether the CONSOLE triaged this question for scope before opening the
    #: run.  The triage is the console's own rail and happens before any of this
    #: exists, so the run cannot observe it; the caller states it, and the run
    #: writes it into the ``case_open`` entry beside the rest of its
    #: configuration.  ``None`` for a caller that runs no such rail — an
    #: evaluation harness, the library API — which is a different fact from a
    #: console that ran with the rail switched off.
    scope_triage: bool | None = None

    #: Wall-time seconds held back from investigation so the reserved terminal
    #: path can still conclude when a long run spends the whole soft deadline
    #: reading evidence.  Defaulted to 0.0 so a run that never sets it keeps the
    #: default behaviour of investigating until the true deadline.
    reserved_terminal_wall_time_s: float = 0.0


@dataclass(slots=True)
class PreparedRuntime:
    """Resources created during setup and owned by one investigation."""

    config: InvestigationConfig
    prepared: _PreparedModelSurface
    tools: list[Any]
    gate: Any | None
    tools_available: bool
    tool_choice_policy: dict[str, object]
    effective_case_id: str
    effective_invocation_namespace: str
    runtime_evidence_guard: EvidenceSourceRuntimeGuard | None
    owns_evidence_guard: bool
    frozen_request_timeout: _FrozenRequestTimeout | None
    execution_budget: _CellExecutionBudget | None
    request_payload_ledger: _RequestPayloadLedger | None
    standardized_result_records: list[dict[str, object]]
    #: The run's own trusted registry and audit chain, and the authority the
    #: final check consults about a result of the active contract.  Owned here
    #: because it outlives the tool surface: the gates that decide what may be
    #: published run after the graph has finished.
    lineage: RunLineageResolver
    #: Turns one delivery name and field path into the stored value, with every
    #: check re-run.  Owned here because the answer is assembled after the graph
    #: has finished, where the tool surface no longer is.
    cited_value_resolver: Callable[[str, str], str] | None
    llm: Any
    agent: Any
    investigation_ledger: _ModelRequestLedger
    forced_final_ledger: _ModelRequestLedger


@dataclass(slots=True)
class InvestigationState:
    """Mutable execution result captured before transactional finalization."""

    messages: list[object]
    final: str
    evidence_integrity_error: EvidenceSourceError | None
    verification_telemetry: dict[str, object]
    verification_evidence_present: bool
    verifier_metrics: dict[str, object]
    final_answer_metrics: dict[str, object]
    #: What the assembly step did with the model's structured draft.  Content-free
    #: like every other row here: it counts segments and names a decision, and a
    #: value taken from the evidence never appears in it.
    structured_answer_metrics: dict[str, object]
    continuation_metrics: dict[str, object]
    pending_tool_recovery_metrics: dict[str, object]
    #: Call IDs closed by a control record because the tool ceiling refused them
    #: before dispatch.  Separate from the recovery metrics: nothing here was
    #: executed, so it must never be counted among readings of the evidence.
    tool_dispatch_closure_metrics: dict[str, object]
    reference_evidence_recovery_metrics: dict[str, object]
    match_with_continuation_metrics: dict[str, object]
    memory_injection_corroboration_metrics: dict[str, object]
    memory_pagination_metrics: dict[str, object]
    #: Stated, still-unfetched page frontiers across EVERY domain operation,
    #: read from the results themselves rather than from a per-tool rule.
    result_navigation_metrics: dict[str, object]
    multisource_coverage_metrics: dict[str, object]
    premature_absence_metrics: dict[str, object]
    #: Which regions of the medium this run read, and which of the ones its own
    #: toolset could reach it never opened.
    evidence_region_metrics: dict[str, object]
    #: What the run's own results said was left unfinished — a page that returned
    #: less than it reported, a read that declared its coverage incomplete — and
    #: how much of that nothing further could have closed.
    unfinished_examination_metrics: dict[str, object]
    #: What this run kept asking without learning anything by it, and whether it
    #: was told so.  Every other row here describes a run that concluded too
    #: early; this one describes a run that circled and never concluded at all.
    unproductive_repetition_metrics: dict[str, object]
    recursion_limited: bool
    #: How many times the first investigation pass was re-asked because the
    #: provider returned neither a tool call nor any text. Zero on a normal run.
    investigation_restarts: int
    forced_final: bool
    forced_final_requests: int
    transient_midrun_error: bool
    dispatch_exhaustion_reason: str | None
    multisource_coverage_blocked: bool
    match_with_continuation_blocked: bool
    reference_evidence_recovery_blocked: bool
    pending_tool_recovery_blocked: bool
    memory_injection_corroboration_blocked: bool
    memory_pagination_blocked: bool
    #: Whether this run ended still asserting that something is not there while a
    #: region of the medium that could have refuted it went unread, or while the
    #: evidence the final check actually examined had been truncated.  Either way
    #: the absence is not established, and an unestablished absence is not an
    #: answer this run may publish.
    evidence_region_blocked: bool
    #: Whether this run ended recording a conclusion while an examination its own
    #: results showed unfinished was still finishable and the budget still
    #: allowed finishing it.  Conceding the gap does not clear this: a limit that
    #: could have been closed is not disposed of by a sentence about it.
    unfinished_examination_blocked: bool
    identifier_grounding_blocked: bool
    identifier_grounding_metrics: dict[str, object]
    #: Why this run published nothing, when it published nothing.  Every other
    #: row here describes one stage; this one is the terminal reading across all
    #: of them, and it exists because ``no_final_answer`` alone cannot say
    #: whether the harness discarded a draft or the model never wrote one — the
    #: single distinction on which "harness defect" and "model failure" turn.
    unpublished_answer_metrics: dict[str, object]
