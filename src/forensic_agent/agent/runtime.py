"""Public API and model-surface preparation for the forensic agent."""

from __future__ import annotations

from collections.abc import Collection

from langchain.agents import create_agent

from forensic_agent.agent.case_evidence import (
    CaseEvidenceSource,
    validate_case_pcap_catalog,
)
from forensic_agent.agent.model_surface import (
    ModelSurfaceDependencies,
    ModelSurfacePreflight,
    _PreparedModelSurface,
)
from forensic_agent.agent.model_surface import (
    _prepare_model_surface as _prepare_model_surface_impl,
)
from forensic_agent.agent.model_transport import ChatOpenAI
from forensic_agent.agent.orchestration.runner import (
    InvestigationDependencies,
    _execute_investigation,
)
from forensic_agent.agent.result_lineage import DeferredCitedValueResolver
from forensic_agent.agent.tool_contract import _standardize_tool_outputs
from forensic_agent.agent.tool_registry import build_tools
from forensic_agent.core.backend_versions import BackendVersionRegistry
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

__all__ = (
    "build_tools",
    "preflight_model_surface",
    "preflight_publication_model_surface",
    "run_investigation",
)


def _create_agent_runtime(model, tools, *, prompt=None):
    """Build the investigation runtime through the supported LangChain factory."""

    return create_agent(model, tools, system_prompt=prompt)


def _model_surface_dependencies() -> ModelSurfaceDependencies:
    """Resolve patchable graph façade dependencies for one invocation."""
    return ModelSurfaceDependencies(
        build_tools=build_tools,
        standardize_tool_outputs=_standardize_tool_outputs,
        validate_case_pcap_catalog=validate_case_pcap_catalog,
    )


def _prepare_model_surface(
    disk,
    question: str,
    *,
    prepared_tools: Collection | None = None,
    case_context: str | None = None,
    model: str,
    memory_path: str | None,
    pcap_path: str | None,
    pcap_sources: PcapSourceCatalog | None,
    guidance: str | None,
    on_tool,
    spotlight: bool,
    policy,
    oversight_path: str,
    visible_tools: Collection[str] | None,
    include_quarantined_tools: bool = False,
    standardize_tool_results: bool,
    case_id: str,
    invocation_namespace: str,
    on_standardized_result,
    on_model_visible_result=None,
    record_oversight: bool,
    evidence_source_guard: EvidenceSourceRuntimeGuard | None,
    controlled_scratch: ControlledScratchSession | None,
    case_evidence_source: CaseEvidenceSource | None,
    system_prompt_override: str | None,
    record_full_tool_outputs: bool,
    cited_value_resolver=None,
    result_navigator=None,
    result_reference_issuer=None,
    backend_versions: BackendVersionRegistry | None = None,
    memory_sha256: str | None = None,
    scope_triage: bool | None = None,
) -> _PreparedModelSurface:
    """Construct the model surface through the current graph façade dependencies.

    Every keyword the orchestration passes has to be named here as well: this
    façade is what a run actually calls, so a parameter the implementation
    accepts and this wrapper does not is a console that dies on its first
    question. ``scope_triage`` is such a value — the state of the console's
    pre-run scope rail, which only the caller can state — and it is forwarded
    unchanged so the ``case_open`` record says which rail the run was taken
    under.
    """
    return _prepare_model_surface_impl(
        disk,
        question,
        prepared_tools=prepared_tools,
        case_context=case_context,
        model=model,
        memory_path=memory_path,
        pcap_path=pcap_path,
        pcap_sources=pcap_sources,
        guidance=guidance,
        on_tool=on_tool,
        spotlight=spotlight,
        policy=policy,
        oversight_path=oversight_path,
        visible_tools=visible_tools,
        include_quarantined_tools=include_quarantined_tools,
        standardize_tool_results=standardize_tool_results,
        case_id=case_id,
        invocation_namespace=invocation_namespace,
        on_standardized_result=on_standardized_result,
        on_model_visible_result=on_model_visible_result,
        record_oversight=record_oversight,
        evidence_source_guard=evidence_source_guard,
        controlled_scratch=controlled_scratch,
        case_evidence_source=case_evidence_source,
        system_prompt_override=system_prompt_override,
        record_full_tool_outputs=record_full_tool_outputs,
        cited_value_resolver=cited_value_resolver,
        result_navigator=result_navigator,
        result_reference_issuer=result_reference_issuer,
        backend_versions=backend_versions,
        memory_sha256=memory_sha256,
        scope_triage=scope_triage,
        dependencies=_model_surface_dependencies(),
    )


def _investigation_dependencies() -> InvestigationDependencies:
    """Resolve patchable dependencies for one investigation."""

    return InvestigationDependencies(
        chat_openai=ChatOpenAI,
        create_agent_runtime=_create_agent_runtime,
        prepare_model_surface=_prepare_model_surface,
    )


def preflight_model_surface(
    disk,
    question: str,
    *,
    model: str,
    case_context: str | None = None,
    memory_path: str | None = None,
    pcap_path: str | None = None,
    pcap_sources: PcapSourceCatalog | None = None,
    guidance: str | None = None,
    spotlight: bool = False,
    policy=None,
    visible_tools: Collection[str] | None = None,
    include_quarantined_tools: bool = False,
    standardize_tool_results: bool = False,
    case_id: str = "preflight-case",
    invocation_namespace: str = "preflight-run",
    case_evidence_source: CaseEvidenceSource | None = None,
    system_prompt_override: str | None = None,
    record_full_tool_outputs: bool = False,
) -> ModelSurfacePreflight:
    """Build and hash the publication model surface without any model invocation.

    ``include_quarantined_tools`` reaches the registry builder unchanged and
    defaults to False; a caller must pass the same value here that its run will
    pass, or the digests will not match.
    """
    prepared = _prepare_model_surface(
        disk,
        question,
        prepared_tools=None,
        case_context=case_context,
        model=model,
        memory_path=memory_path,
        pcap_path=pcap_path,
        pcap_sources=pcap_sources,
        guidance=guidance,
        on_tool=None,
        spotlight=spotlight,
        policy=policy,
        oversight_path="preflight-no-write.jsonl",
        visible_tools=visible_tools,
        include_quarantined_tools=include_quarantined_tools,
        standardize_tool_results=standardize_tool_results,
        case_id=case_id,
        invocation_namespace=invocation_namespace,
        on_standardized_result=None,
        record_oversight=False,
        evidence_source_guard=None,
        controlled_scratch=None,
        case_evidence_source=case_evidence_source,
        system_prompt_override=system_prompt_override,
        record_full_tool_outputs=record_full_tool_outputs,
    )
    return prepared.identity


def preflight_publication_model_surface(
    disk,
    question: str,
    *,
    model: str,
    policy,
    visible_tools: Collection[str],
    include_quarantined_tools: bool = False,
    memory_path: str | None = None,
    pcap_path: str | None = None,
    pcap_sources: PcapSourceCatalog | None = None,
    guidance: str | None = None,
    case_id: str = "preflight-case",
    invocation_namespace: str = "preflight-run",
    case_evidence_source: CaseEvidenceSource | None = None,
) -> ModelSurfacePreflight:
    """Preflight the fixed publication surface used by the OpenRouter adapter.

    Standardized receipt-verified results and structured spotlighting are deliberately not
    configurable here.
    """
    return preflight_model_surface(
        disk,
        question,
        model=model,
        memory_path=memory_path,
        pcap_path=pcap_path,
        pcap_sources=pcap_sources,
        guidance=guidance,
        spotlight=True,
        policy=policy,
        visible_tools=visible_tools,
        include_quarantined_tools=include_quarantined_tools,
        standardize_tool_results=True,
        case_id=case_id,
        invocation_namespace=invocation_namespace,
        case_evidence_source=case_evidence_source,
    )


def run_investigation(
    disk,
    question: str,
    *,
    prepared_tools: Collection | None = None,
    case_context: str | None = None,
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
) -> str | None:
    """Run one investigation using the active public API dependencies."""

    return _execute_investigation(
        disk,
        question,
        prepared_tools=prepared_tools,
        case_context=case_context,
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
        dependencies=_investigation_dependencies(),
    )
