"""Entry point for one orchestrated forensic investigation."""

from __future__ import annotations

from collections.abc import Callable, Collection
from dataclasses import dataclass
from typing import Any

from forensic_agent.agent.case_evidence import CaseEvidenceSource
from forensic_agent.agent.model_surface import _PreparedModelSurface
from forensic_agent.agent.orchestration.coordinator import _execute_runtime
from forensic_agent.agent.orchestration.preparation import _prepare_runtime
from forensic_agent.agent.orchestration.state import InvestigationConfig
from forensic_agent.agent.result_lineage import DeferredCitedValueResolver
from forensic_agent.core.audit import default_log_path
from forensic_agent.core.config import (
    DEFAULT_MODEL,
    DETERMINISTIC,
    OPENROUTER_DEFAULT_QUANTIZATIONS,
    DecodingProfile,
)
from forensic_agent.core.controlled_scratch import ControlledScratchSession
from forensic_agent.core.evidence_source import (
    EvidenceSourceAttestation,
    EvidenceSourceRuntimeGuard,
)
from forensic_agent.tools.pcap_sources import PcapSourceCatalog


@dataclass(frozen=True, slots=True)
class InvestigationDependencies:
    """Patchable dependencies supplied by the public agent API."""

    chat_openai: Callable[..., Any]
    create_agent_runtime: Callable[..., Any]
    prepare_model_surface: Callable[..., _PreparedModelSurface]


def _execute_investigation(
    disk,
    question: str,
    *,
    case_context: str | None = None,
    prepared_tools: Collection | None = None,
    model: str = DEFAULT_MODEL,
    base_url: str = "https://openrouter.ai/api/v1",
    api_key: str = "",
    provider: str | None = None,
    provider_quantizations: tuple[str, ...] | None = OPENROUTER_DEFAULT_QUANTIZATIONS,
    decoding_profile: DecodingProfile = DETERMINISTIC,
    decoding_parameters: Collection[str] | None = None,
    max_steps: int = 20,
    memory_path: str | None = None,
    pcap_path: str | None = None,
    pcap_sources: PcapSourceCatalog | None = None,
    verbose: bool = True,
    guidance: str | None = None,
    on_tool=None,
    verify: bool = False,
    first_investigation_tool_choice: str | None = None,
    verify_model: str | None = None,
    verification_provider: str | None = None,
    verification_provider_quantizations: tuple[str, ...] | None = None,
    verification_fail_closed: bool = False,
    spotlight: bool = False,
    policy=None,
    oversight_path: str | None = None,
    visible_tools: Collection[str] | None = None,
    include_quarantined_tools: bool = False,
    standardize_tool_results: bool = False,
    case_id: str | None = None,
    invocation_namespace: str | None = None,
    tool_result_trace_path: str | None = None,
    telemetry: dict[str, object] | None = None,
    sdk_max_retries: int = 5,
    request_timeout_s: float | None = None,
    cell_started_monotonic: float | None = None,
    cell_deadline_monotonic: float | None = None,
    max_model_requests: int | None = None,
    max_tool_calls: int | None = None,
    evidence_source_attestation: EvidenceSourceAttestation | None = None,
    evidence_source_guard: EvidenceSourceRuntimeGuard | None = None,
    controlled_scratch: ControlledScratchSession | None = None,
    expected_system_prompt_sha256: str | None = None,
    expected_tool_registry_sha256: str | None = None,
    case_evidence_source: CaseEvidenceSource | None = None,
    system_prompt_override: str | None = None,
    record_full_tool_outputs: bool = False,
    recover_incomplete_run: bool = True,
    autonomous_tool_selection: bool = False,
    enforce_explicit_multisource_coverage: bool = False,
    ambiguous_memory_candidate_corroboration: bool = False,
    deliver_model_result_envelope: bool = False,
    reserved_terminal_wall_time_s: float = 0.0,
    citation_resolver_slot: DeferredCitedValueResolver | None = None,
    scope_triage: bool | None = None,
    dependencies: InvestigationDependencies,
) -> str | None:
    """Run one investigation through the typed orchestration phases."""

    # A run that was handed no destination for its oversight ledger used to get
    # the bare name `oversight.jsonl`, which resolves against the process working
    # directory: the ledger, and the tool-result trace derived from it by name,
    # were written wherever the caller happened to be started from. The default
    # is now placed the way `cli/controlled.py` places both of its logs.
    if oversight_path is None:
        oversight_path = default_log_path("oversight.jsonl")

    config = InvestigationConfig(
        disk=disk,
        question=question,
        case_context=case_context,
        prepared_tools=prepared_tools,
        model=model,
        base_url=base_url,
        api_key=api_key,
        provider=provider,
        provider_quantizations=provider_quantizations,
        decoding_profile=decoding_profile,
        decoding_parameters=decoding_parameters,
        max_steps=max_steps,
        memory_path=memory_path,
        pcap_path=pcap_path,
        pcap_sources=pcap_sources,
        verbose=verbose,
        guidance=guidance,
        on_tool=on_tool,
        verify=verify,
        first_investigation_tool_choice=first_investigation_tool_choice,
        verify_model=verify_model,
        verification_provider=verification_provider,
        verification_provider_quantizations=verification_provider_quantizations,
        verification_fail_closed=verification_fail_closed,
        spotlight=spotlight,
        policy=policy,
        oversight_path=oversight_path,
        visible_tools=visible_tools,
        include_quarantined_tools=include_quarantined_tools,
        standardize_tool_results=standardize_tool_results,
        case_id=case_id,
        invocation_namespace=invocation_namespace,
        tool_result_trace_path=tool_result_trace_path,
        telemetry=telemetry,
        sdk_max_retries=sdk_max_retries,
        request_timeout_s=request_timeout_s,
        cell_started_monotonic=cell_started_monotonic,
        cell_deadline_monotonic=cell_deadline_monotonic,
        max_model_requests=max_model_requests,
        max_tool_calls=max_tool_calls,
        evidence_source_attestation=evidence_source_attestation,
        evidence_source_guard=evidence_source_guard,
        controlled_scratch=controlled_scratch,
        expected_system_prompt_sha256=expected_system_prompt_sha256,
        expected_tool_registry_sha256=expected_tool_registry_sha256,
        case_evidence_source=case_evidence_source,
        system_prompt_override=system_prompt_override,
        record_full_tool_outputs=record_full_tool_outputs,
        recover_incomplete_run=recover_incomplete_run,
        autonomous_tool_selection=autonomous_tool_selection,
        enforce_explicit_multisource_coverage=enforce_explicit_multisource_coverage,
        ambiguous_memory_candidate_corroboration=ambiguous_memory_candidate_corroboration,
        deliver_model_result_envelope=deliver_model_result_envelope,
        reserved_terminal_wall_time_s=reserved_terminal_wall_time_s,
        citation_resolver_slot=citation_resolver_slot,
        scope_triage=scope_triage,
    )
    runtime = _prepare_runtime(
        config,
        chat_openai=dependencies.chat_openai,
        create_agent_runtime=dependencies.create_agent_runtime,
        prepare_model_surface=dependencies.prepare_model_surface,
    )
    return _execute_runtime(runtime)
