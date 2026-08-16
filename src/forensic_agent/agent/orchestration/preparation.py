"""Validation and resource preparation for one investigation."""

from __future__ import annotations

import json
import threading
import time
import uuid
from collections.abc import Callable
from typing import Any

from pydantic import SecretStr

from forensic_agent.agent.evidence_custody import _validate_preopened_evidence_guard
from forensic_agent.agent.execution_budget import _CellExecutionBudget, _FrozenRequestTimeout
from forensic_agent.agent.execution_dispatch import _bound_tool_dispatches
from forensic_agent.agent.lineage_resolution import (
    RunLineageResolver,
    attested_case_sources,
)
from forensic_agent.agent.model_surface import _PreparedModelSurface
from forensic_agent.agent.model_telemetry import _ModelRequestLedger
from forensic_agent.agent.model_transport import _RequestPayloadLedger
from forensic_agent.agent.orchestration.state import (
    InvestigationConfig,
    PreparedRuntime,
)
from forensic_agent.agent.result_lineage import ResultLineageStore
from forensic_agent.agent.result_navigator import ResultNavigator
from forensic_agent.agent.result_reference import ResultReferenceRegistry
from forensic_agent.agent.tool_contract import _valid_sha256
from forensic_agent.agent.tool_trace import _append_tool_result_trace
from forensic_agent.core.config import agent_chat_openai_kwargs
from forensic_agent.core.evidence_source import (
    EvidenceSourceAttestation,
    EvidenceSourceRuntimeGuard,
)
from forensic_agent.core.repro import canonical_json


def _bind_caller_citation_slot(
    config: InvestigationConfig, result_lineage: ResultLineageStore
) -> None:
    """Give this run's retained results to a registry the CALLER built.

    A caller that builds the executable registry itself does so before the run
    exists — the controlled console derives its palette and its oversight policy
    from real function names — so the operations that consume an earlier result
    were bound to an empty slot.  Filling it here is what makes those operations
    work on that path at all: unfilled, every citation refuses, and the model is
    left to retype for itself the value it wanted to cite.

    A run that was handed no slot bound its tools directly and needs nothing.
    """

    slot = config.citation_resolver_slot
    if slot is None:
        return
    slot.bind(result_lineage.cited_value)


def _prepare_runtime(
    config: InvestigationConfig,
    *,
    chat_openai: Callable[..., Any],
    create_agent_runtime: Callable[..., Any],
    prepare_model_surface: Callable[..., _PreparedModelSurface],
) -> PreparedRuntime:
    """Validate controls and construct the exact model-visible runtime surface."""

    disk = config.disk
    question = config.question
    case_context = config.case_context
    prepared_tools = config.prepared_tools
    model = config.model
    base_url = config.base_url
    api_key = config.api_key
    provider = config.provider
    provider_quantizations = config.provider_quantizations
    decoding_profile = config.decoding_profile
    decoding_parameters = config.decoding_parameters
    max_steps = config.max_steps
    memory_path = config.memory_path
    pcap_path = config.pcap_path
    pcap_sources = config.pcap_sources
    guidance = config.guidance
    on_tool = config.on_tool
    verify = config.verify
    first_investigation_tool_choice = config.first_investigation_tool_choice
    spotlight = config.spotlight
    policy = config.policy
    oversight_path = config.oversight_path
    visible_tools = config.visible_tools
    include_quarantined_tools = config.include_quarantined_tools
    standardize_tool_results = config.standardize_tool_results
    case_id = config.case_id
    invocation_namespace = config.invocation_namespace
    tool_result_trace_path = config.tool_result_trace_path
    telemetry = config.telemetry
    sdk_max_retries = config.sdk_max_retries
    request_timeout_s = config.request_timeout_s
    cell_started_monotonic = config.cell_started_monotonic
    cell_deadline_monotonic = config.cell_deadline_monotonic
    max_model_requests = config.max_model_requests
    max_tool_calls = config.max_tool_calls
    evidence_source_attestation = config.evidence_source_attestation
    evidence_source_guard = config.evidence_source_guard
    controlled_scratch = config.controlled_scratch
    expected_system_prompt_sha256 = config.expected_system_prompt_sha256
    expected_tool_registry_sha256 = config.expected_tool_registry_sha256
    case_evidence_source = config.case_evidence_source
    system_prompt_override = config.system_prompt_override
    record_full_tool_outputs = config.record_full_tool_outputs
    recover_incomplete_run = config.recover_incomplete_run
    autonomous_tool_selection = config.autonomous_tool_selection
    enforce_explicit_multisource_coverage = config.enforce_explicit_multisource_coverage
    ambiguous_memory_candidate_corroboration = config.ambiguous_memory_candidate_corroboration

    if isinstance(sdk_max_retries, bool) or not isinstance(sdk_max_retries, int):
        raise ValueError("sdk_max_retries must be a non-negative integer")
    if sdk_max_retries < 0:
        raise ValueError("sdk_max_retries must be a non-negative integer")
    if first_investigation_tool_choice not in {None, "auto", "required"}:
        raise ValueError("first_investigation_tool_choice must be None, 'auto', or 'required'")
    if type(recover_incomplete_run) is not bool:
        raise TypeError("recover_incomplete_run must be a boolean")
    if type(autonomous_tool_selection) is not bool:
        raise TypeError("autonomous_tool_selection must be a boolean")
    if type(enforce_explicit_multisource_coverage) is not bool:
        raise TypeError("enforce_explicit_multisource_coverage must be a boolean")
    if type(ambiguous_memory_candidate_corroboration) is not bool:
        raise TypeError("ambiguous_memory_candidate_corroboration must be a boolean")
    if autonomous_tool_selection and (
        enforce_explicit_multisource_coverage or ambiguous_memory_candidate_corroboration
    ):
        raise ValueError(
            "autonomous tool selection is incompatible with deterministic new-tool routing"
        )
    if enforce_explicit_multisource_coverage and (
        not verify or not standardize_tool_results or case_evidence_source is None
    ):
        raise ValueError(
            "explicit multi-source coverage requires verified standardized case evidence"
        )
    if ambiguous_memory_candidate_corroboration and (not verify or not standardize_tool_results):
        raise ValueError(
            "ambiguous memory candidate corroboration requires verified standardized evidence"
        )
    if (
        evidence_source_attestation is not None or evidence_source_guard is not None
    ) and policy is None:
        raise ValueError("runtime evidence custody requires the centralized oversight policy")
    if controlled_scratch is not None and policy is None:
        raise ValueError("controlled scratch requires the centralized oversight policy")
    if (expected_system_prompt_sha256 is None) != (expected_tool_registry_sha256 is None):
        raise ValueError(
            "expected system-prompt and tool-registry hashes must be supplied together"
        )
    expected_prompt_sha256: str | None = None
    expected_registry_sha256: str | None = None
    if expected_system_prompt_sha256 is not None:
        expected_prompt_sha256 = _valid_sha256(expected_system_prompt_sha256)
        expected_registry_sha256 = _valid_sha256(expected_tool_registry_sha256)
        if expected_prompt_sha256 is None or expected_registry_sha256 is None:
            raise ValueError(
                "expected system-prompt and tool-registry hashes must be full SHA-256 values"
            )
    frozen_request_timeout = (
        _FrozenRequestTimeout.from_budget(request_timeout_s)
        if request_timeout_s is not None
        else None
    )
    supplied_deadline = cell_started_monotonic is not None or cell_deadline_monotonic is not None
    supplied_dispatch_limits = max_model_requests is not None or max_tool_calls is not None
    if (supplied_deadline or supplied_dispatch_limits) and frozen_request_timeout is None:
        raise ValueError("cell deadline and dispatch limits require request_timeout_s")
    if (cell_started_monotonic is None) != (cell_deadline_monotonic is None):
        raise ValueError("cell monotonic start and deadline must be supplied together")
    execution_budget: _CellExecutionBudget | None = None
    if frozen_request_timeout is not None:
        graph_started = time.monotonic()
        effective_started = (
            float(cell_started_monotonic) if cell_started_monotonic is not None else graph_started
        )
        effective_deadline = (
            float(cell_deadline_monotonic)
            if cell_deadline_monotonic is not None
            else effective_started + frozen_request_timeout.timeout_s
        )
        # The terminal path is not optional work the run may be denied: a run
        # that gathered evidence must still be able to conclude, and where
        # verification is enabled that conclusion must still be checked.  The
        # forced-final conclusion may itself take two model requests — the ordinary
        # attempt and one reserved reasoning-relieved re-issue when the first
        # returned no publishable draft — so the recovery path reserves two, not
        # one; otherwise the second attempt overruns the ceiling and a verified run
        # is downgraded to salvage.  The verifier likewise may make one initial
        # request and one bounded retry.  All draw on the same model-request
        # ceiling and are reserved here rather than left to whichever ceiling the
        # operator happened to choose.
        reserved_terminal_model_requests = 2 * int(recover_incomplete_run) + 2 * int(verify)
        execution_budget = _CellExecutionBudget(
            started_monotonic=effective_started,
            deadline_monotonic=effective_deadline,
            max_investigation_requests=max_steps,
            max_model_requests=(
                max_model_requests
                if max_model_requests is not None
                else max_steps + reserved_terminal_model_requests
            ),
            max_tool_calls=max_tool_calls if max_tool_calls is not None else max_steps,
            reserved_terminal_model_requests=reserved_terminal_model_requests,
            reserved_terminal_wall_time_s=config.reserved_terminal_wall_time_s,
        )
        # Fail before constructing a model client when evidence opening or surface
        # preparation has already consumed the absolute cell deadline.
        execution_budget.remaining()
    request_payload_ledger = _RequestPayloadLedger() if frozen_request_timeout is not None else None
    effective_case_id = case_id or uuid.uuid4().hex[:12]
    effective_invocation_namespace = invocation_namespace or effective_case_id
    # What the model READ is worth recording in every mode: a non-standardized run
    # still shapes its results, so without this trace there is no record of the
    # document the model actually saw.
    effective_tool_result_trace = tool_result_trace_path or (oversight_path + ".tool-results.jsonl")
    # Two distinct traces, because they answer different questions: the one above
    # records exactly the document the MODEL received (bounded, with its own
    # projection receipt), and this one records the COMPLETE standardized result
    # the run retained.  Keeping only one of them makes it impossible to tell what
    # the model actually read from what the tool actually produced.  The complete
    # trace exists only where standardization produces such a result.
    effective_complete_result_trace = (
        (effective_tool_result_trace + ".complete.jsonl") if standardize_tool_results else None
    )
    runtime_evidence_guard: EvidenceSourceRuntimeGuard | None = None
    owns_evidence_guard = False
    if evidence_source_guard is not None:
        if type(evidence_source_attestation) is not EvidenceSourceAttestation:
            raise ValueError("a pre-open evidence guard requires its exact source attestation")
        _validate_preopened_evidence_guard(
            evidence_source_guard,
            evidence_source_attestation,
        )
        disk_source = getattr(disk, "evidence_source_attestation", None)
        if disk_source is not None and disk_source != evidence_source_attestation:
            raise ValueError("pre-open evidence guard differs from the opened disk source")
        runtime_evidence_guard = evidence_source_guard
    elif evidence_source_attestation is not None:
        if type(evidence_source_attestation) is not EvidenceSourceAttestation:
            raise ValueError("runtime custody requires an exact evidence-source attestation")
        disk_source = getattr(disk, "evidence_source_attestation", None)
        if disk_source is not None and disk_source != evidence_source_attestation:
            raise ValueError("runtime custody attestation differs from the opened disk source")
        runtime_evidence_guard = EvidenceSourceRuntimeGuard(evidence_source_attestation)
        owns_evidence_guard = True

    standardized_result_records: list[dict[str, object]] = []
    standardized_result_lock = threading.Lock()
    # The run's citable lineage: every complete standardized result, indexed by
    # its invocation id, plus the digests of what the model was actually handed.
    # It is created BEFORE the surface so a citing operation can be bound to it
    # at build time; without that binding every citation refuses and a model has
    # no way to reference an earlier value except by retyping it.
    result_lineage = ResultLineageStore()
    _bind_caller_citation_slot(config, result_lineage)
    # Reading MORE of a result the run already retained goes through that same
    # store from the other side: the navigator issues the opaque cursor a
    # shortened projection carries, and serves the withheld records out of what is
    # held there.  It executes nothing and observes nothing, so it is bound to the
    # surface rather than threaded through the capture, oversight and
    # standardization chain that exists to record observations.
    result_navigator = ResultNavigator(result_lineage, case_id=effective_case_id)
    # Names each delivery to the model, so a final answer can point at one
    # without being handed a digest it could retype or a path it should not hold.
    result_references = (
        ResultReferenceRegistry(case_id=effective_case_id)
        if config.deliver_model_result_envelope
        else None
    )
    # The run's own trusted answer to what a published claim may rest on: the
    # evidence sources it established BEFORE any tool ran, the retained results
    # above, and the append-only oversight chain the binding records are written
    # to.  The chain is created with the model-visible surface below, so the
    # recorder is attached once it exists; until then nothing is bound to it and
    # every active-contract result is refused rather than admitted on its own
    # self-recomputable receipt.
    lineage = RunLineageResolver(
        result_lineage,
        case_id=effective_case_id,
        sources=attested_case_sources(
            case_id=effective_case_id,
            case_evidence_source=case_evidence_source,
            evidence_source_attestation=evidence_source_attestation,
            disk=disk,
        ),
    )

    def record_standardized_result(tool, args, result) -> None:
        frozen_record = {
            "tool": str(tool),
            "arguments": json.loads(canonical_json(dict(args))),
            "result": json.loads(canonical_json(result)),
        }
        with standardized_result_lock:
            standardized_result_records.append(frozen_record)
        # The FROZEN call, not the live kwargs: a page cursor binds to the
        # canonical arguments, and the deterministic recovery stages key their
        # records by the same frozen form, so the two must be comparing the same
        # thing or a legitimate continuation would look like a different query.
        result_lineage.record_complete_result(
            tool, frozen_record["arguments"], frozen_record["result"]
        )
        # AFTER standardization, which is the only order the audit binding can be
        # written in: it carries the finished payload digest, and that payload
        # already carries the chain pointers.
        lineage.record_result(tool, frozen_record["arguments"], frozen_record["result"])
        # The COMPLETE standardized result goes to its own trace.
        if effective_complete_result_trace is not None:
            _append_tool_result_trace(
                effective_complete_result_trace,
                case_id=effective_case_id,
                invocation_namespace=effective_invocation_namespace,
                tool=tool,
                args=args,
                result=result,
                artifact_kind="complete_result",
            )

    def record_model_visible_result(tool, args, result) -> None:
        """Record the exact document handed to the model, after projection."""

        # A shortened projection carries its OWN receipt, so the digest the model
        # can read is not the complete result's. Accept it as an identity for the
        # same invocation, or a citation quoting what the model actually saw
        # would be rejected precisely when the result was big enough to matter.
        result_lineage.record_model_visible_result(tool, args, result)
        if standardize_tool_results:
            # The projection is a SEPARATE artifact with its own payload digest,
            # and it is the one the verifier judges.  Binding only the complete
            # result would leave every reduced bundle unattested, so each traced
            # artifact of a call is bound on its own.  Where standardization is
            # off there is no envelope to bind and nothing is claimed.
            lineage.record_result(tool, args, result)
        if effective_tool_result_trace is None:
            return
        # Any JSON value, not just a mapping: a projection may legitimately be a
        # bounded scalar, and it still has to leave a traced, digested row.
        _append_tool_result_trace(
            effective_tool_result_trace,
            case_id=effective_case_id,
            invocation_namespace=effective_invocation_namespace,
            tool=str(tool),
            args=dict(args or {}),
            result=result,
            artifact_kind="model_visible_projection",
        )

    prepared = prepare_model_surface(
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
        case_id=effective_case_id,
        invocation_namespace=effective_invocation_namespace,
        on_standardized_result=(record_standardized_result if standardize_tool_results else None),
        on_model_visible_result=record_model_visible_result,
        record_oversight=True,
        evidence_source_guard=runtime_evidence_guard,
        controlled_scratch=controlled_scratch,
        case_evidence_source=case_evidence_source,
        system_prompt_override=system_prompt_override,
        record_full_tool_outputs=record_full_tool_outputs,
        cited_value_resolver=result_lineage.cited_value,
        result_navigator=result_navigator,
        result_reference_issuer=result_references,
        # Optional on the config: a caller that never hashed its memory dump
        # states nothing, and the whole-image scan of it stays per-run.
        memory_sha256=getattr(config, "memory_sha256", None),
        # A declared field, read as one: the console's pre-run scope rail is the
        # console's own and only the caller can say whether it ran, so the run
        # states it rather than looking for a switch of its own. It reaches the
        # record unchanged, so a run made with the rail switched off says so.
        scope_triage=config.scope_triage,
    )
    tools = prepared.tools
    gate = prepared.gate
    # The chain exists now, so the resolver can write to it.  A run with no
    # oversight gate binds none: without an append-only record there is nothing
    # left to check a result's content against except its own receipt, which
    # whoever edited the payload could have recomputed.
    lineage.bind_recorder(gate.recorder if gate is not None else None)
    tools_available = bool(tools)
    expected_first_tool_choice = "required" if verify and tools_available else "auto"
    if (
        first_investigation_tool_choice is not None
        and first_investigation_tool_choice != expected_first_tool_choice
    ):
        if gate is not None:
            gate.recorder.close_case(final="", status="invalid_controls")
        if owns_evidence_guard and runtime_evidence_guard is not None:
            runtime_evidence_guard.close()
        raise ValueError(
            "first_investigation_tool_choice differs from the deterministic arm policy"
        )
    tool_choice_policy: dict[str, object] = {
        "schema_id": "forensic.model-tool-choice-policy.v1",
        "tools_available": tools_available,
        "first_investigation": (expected_first_tool_choice if tools_available else "omitted"),
        "subsequent_investigation": "auto" if tools_available else "omitted",
        # The terminal request carries no functions at all, so there is no
        # palette for a tool_choice to constrain and the field is not sent.
        "forced_final": "omitted",
        "forced_final_tools": "omitted",
    }
    if execution_budget is not None:
        tools = _bound_tool_dispatches(tools, execution_budget)
    prompt = prepared.prompt
    if telemetry is not None:
        telemetry.update(
            {
                "system_prompt_sha256": prepared.identity.system_prompt_sha256,
                "tool_registry_sha256": prepared.identity.tool_registry_sha256,
                "sdk_max_retries": sdk_max_retries,
                "model_tool_choice_policy": dict(tool_choice_policy),
                "per_request_timeout_enforced": frozen_request_timeout is not None,
                "per_request_timeout_s": (
                    frozen_request_timeout.timeout_s if frozen_request_timeout is not None else None
                ),
                "request_timeout_policy": (
                    "remaining_absolute_cell_deadline" if execution_budget is not None else None
                ),
                "absolute_dispatch_deadline_enforced": execution_budget is not None,
                "cell_execution_metrics": (
                    execution_budget.metrics() if execution_budget is not None else None
                ),
                "evidence_source_runtime_integrity": (
                    runtime_evidence_guard.telemetry()
                    if runtime_evidence_guard is not None
                    else None
                ),
                "controlled_scratch_runtime": (
                    controlled_scratch.telemetry() if controlled_scratch is not None else None
                ),
                "incomplete_run_recovery_enabled": recover_incomplete_run,
                "autonomous_tool_selection": autonomous_tool_selection,
                **(
                    {"explicit_multisource_coverage_enabled": True}
                    if enforce_explicit_multisource_coverage
                    else {}
                ),
            }
        )
    if expected_prompt_sha256 is not None and (
        prepared.identity.system_prompt_sha256 != expected_prompt_sha256
        or prepared.identity.tool_registry_sha256 != expected_registry_sha256
    ):
        if gate is not None:
            gate.recorder.record_security(
                "model_surface_lock_mismatch",
                {
                    "expected_system_prompt_sha256": expected_prompt_sha256,
                    "realized_system_prompt_sha256": prepared.identity.system_prompt_sha256,
                    "expected_tool_registry_sha256": expected_registry_sha256,
                    "realized_tool_registry_sha256": prepared.identity.tool_registry_sha256,
                    "model_request_started": False,
                },
            )
            gate.recorder.close_case(final="", status="invalid_controls")
        if owns_evidence_guard and runtime_evidence_guard is not None:
            runtime_evidence_guard.close()
        raise ValueError(
            "realized model surface differs from the expected prompt/tool registry lock"
        )

    # Construct the SDK client only after the exact model-visible surface has
    # matched its publication lock. Client construction is not itself billable,
    # but this ordering makes the no-request boundary explicit and testable.
    try:
        llm = chat_openai(
            model=model,
            base_url=base_url,
            api_key=SecretStr(api_key),
            max_retries=sdk_max_retries,
            **agent_chat_openai_kwargs(
                decoding_profile,
                base_url=base_url,
                provider=provider,
                provider_quantizations=provider_quantizations,
                allowed_parameters=decoding_parameters,
            ),
        )
        if request_payload_ledger is not None and frozen_request_timeout is not None:
            llm.configure_request_attestation(
                request_payload_ledger,
                frozen_request_timeout,
                execution_budget,
            )
        # A control the transport has to weaken mid-run (a provider that refuses
        # a forced tool call) is a decision this run made, so it belongs on the
        # same append-only chain as the rest of them.
        configure_oversight = getattr(llm, "configure_oversight_recorder", None)
        if callable(configure_oversight) and gate is not None:
            configure_oversight(gate.recorder)
        configure_tool_choice = getattr(llm, "configure_tool_choice_policy", None)
        if callable(configure_tool_choice):
            configure_tool_choice(first_investigation=expected_first_tool_choice)
        agent = create_agent_runtime(llm, tools, prompt=prompt)
    except Exception:
        if gate is not None:
            gate.recorder.close_case(final="", status="pre_model_failure")
        if owns_evidence_guard and runtime_evidence_guard is not None:
            runtime_evidence_guard.close()
        raise

    return PreparedRuntime(
        config=config,
        prepared=prepared,
        tools=tools,
        gate=gate,
        tools_available=tools_available,
        tool_choice_policy=tool_choice_policy,
        effective_case_id=effective_case_id,
        effective_invocation_namespace=effective_invocation_namespace,
        runtime_evidence_guard=runtime_evidence_guard,
        owns_evidence_guard=owns_evidence_guard,
        frozen_request_timeout=frozen_request_timeout,
        execution_budget=execution_budget,
        request_payload_ledger=request_payload_ledger,
        standardized_result_records=standardized_result_records,
        lineage=lineage,
        cited_value_resolver=(result_references.resolve if result_references is not None else None),
        llm=llm,
        agent=agent,
        investigation_ledger=_ModelRequestLedger("investigation", execution_budget),
        forced_final_ledger=_ModelRequestLedger("forced_final", execution_budget),
    )
