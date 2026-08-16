"""Controlled execution service used by the interactive forensic console.

The console is intentionally a thin presentation layer.  This module binds an
interactive question to the same reliability controls used by evaluation runs,
while leaving the fixed evaluation manifests and protocol locks out of arbitrary
user cases.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import threading
import time
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from urllib.parse import urlsplit

from forensic_agent.agent.case_evidence import (
    CaseEvidenceSource,
    validate_case_pcap_catalog,
)
from forensic_agent.agent.execution_budget import BUDGET_EXHAUSTION_REASONS
from forensic_agent.agent.orchestration.finalization import UNPUBLISHED_ANSWER_CAUSES
from forensic_agent.agent.result_lineage import DeferredCitedValueResolver
from forensic_agent.agent.runtime import build_tools, run_investigation
from forensic_agent.agent.tool_palette import (
    NAVIGATION_FUNCTIONS,
    classify_disk_family,
    tools_for_loaded_evidence,
)
from forensic_agent.agent.tool_registry import TOOL_EXPOSURE_FAIL_CLOSED
from forensic_agent.cli.endpoint_validation import (
    ControlledConsoleError,
    validate_local_endpoint,
    validate_openrouter_endpoint,
)
from forensic_agent.cli.reasoning import (
    normalize_effort,
    request_effort,
)
from forensic_agent.core.audit import AuditLog
from forensic_agent.core.config import DETERMINISTIC, DecodingProfile
from forensic_agent.core.controlled_scratch import (
    ControlledScratchError,
    ControlledScratchSession,
    provision_controlled_scratch_root,
)
from forensic_agent.core.storage_containment import payload_scratch_root
from forensic_agent.core.tool_availability import (
    available_tools,
    missing_dependencies_for,
)
from forensic_agent.oversight import OversightLog, Policy
from forensic_agent.oversight.audit import ACTION_EXECUTED, classify_action_outcome
from forensic_agent.tools.pcap_sources import PcapSourceCatalog

DEFAULT_PROVIDER = "deepinfra/turbo"
DEFAULT_QUANTIZATIONS = ("bf16",)

#: Environment override for the console's answer-delivery path.
#:
#: Default OFF. Binding is the better guarantee — a value in a bound answer is
#: inserted by the runtime from the stored result, so it is never something a
#: model typed. But it requires the model to answer the terminal request with the
#: segment document, and the model this console ships with answers in prose: an
#: assembled run can report zero segments and publish NOTHING, discarding a
#: correct finding the run already held. A published answer whose values are
#: still checked against the evidence by identifier grounding is worth more than
#: no answer at all, so binding waits for a model that reliably emits segments.
#: Set the variable to 1 to turn it on.
_ENVELOPE_ENV_VARIABLE = "DFA_DELIVER_MODEL_RESULT_ENVELOPE"

#: The two closed vocabularies the variable is read through. Both are named so
#: the reader below and the diagnostic beside it cannot disagree about which
#: settings counted as an answer: a value in neither list is not an answer, and
#: telling that apart from an absent variable is the whole reason for two lists.
_ENVELOPE_ON_VALUES = frozenset({"1", "true", "on", "yes"})
_ENVELOPE_OFF_VALUES = frozenset({"", "0", "false", "off", "no"})


def _console_delivers_model_result_envelope() -> bool:
    """Whether the console assembles the answer from bound value names."""

    raw = os.environ.get(_ENVELOPE_ENV_VARIABLE)
    if raw is None:
        return False
    return raw.strip().lower() in _ENVELOPE_ON_VALUES


def envelope_setting_notice() -> str | None:
    """What to tell an operator whose delivery setting reads as neither on nor off.

    ``None`` for an unset variable and for either unambiguous answer: those are
    deliberate choices, and a console does not lecture an operator about a choice
    it made.

    A value the reader does not recognise is not a choice. It leaves the run
    publishing model prose with no value bound and nothing anywhere saying the
    setting had no effect — a guarantee silently not applying, to an operator who
    believes it did. A misspelling would otherwise cost the whole mechanism
    without a word, which is why it is reported.
    """

    raw = os.environ.get(_ENVELOPE_ENV_VARIABLE)
    if raw is None:
        return None
    value = raw.strip().lower()
    if value in _ENVELOPE_ON_VALUES or value in _ENVELOPE_OFF_VALUES:
        return None
    return (
        f"{_ENVELOPE_ENV_VARIABLE} is set to a value this console reads as neither "
        "on nor off, so answers are published as model prose and no value in them "
        "is inserted by the runtime. Set it to 1 to assemble answers from stored "
        "results, or to 0 to publish prose deliberately."
    )


#: Environment override that takes the final check OUT of a run.
#:
#: The check earns its place by catching a report the evidence does not support.
#: It can also do the opposite: overturn a finding the investigation had already
#: made, from a bundle whose byte ceiling had dropped the very results carrying
#: it — while being told the bundle was truncated. Whether it helps more than it
#: costs depends on the model and the evidence.
#:
#: Default ON, and it stays on, so a run cannot quietly skip its own check.
#: Turning it off is recorded in the run's configuration like every other
#: setting.
_VERIFICATION_ENV_VARIABLE = "DFA_FINAL_VERIFICATION"


def _console_runs_the_final_check() -> bool:
    """Whether the console asks a second pass to check the report before it ships."""

    raw = os.environ.get(_VERIFICATION_ENV_VARIABLE)
    if raw is None:
        return True
    return raw.strip().lower() not in ("0", "false", "off", "no")


REQUEST_PARAMETERS = (
    "temperature",
    "top_p",
    "seed",
    "frequency_penalty",
    "presence_penalty",
    "max_tokens",
    "reasoning",
    "tools",
    "tool_choice",
)


def _decoding_controls(effort: str) -> tuple[DecodingProfile, tuple[str, ...]]:
    """The decoding profile and request surface one console question runs under.

    Everything except the reasoning effort is the locked evidence-grade profile
    with the documented seed, exactly as before.

    Omission cannot be expressed by putting ``None`` in the profile: the agent
    request factories read an unset effort as "take the shared agent default"
    and fall back to ``DFA_REASONING_EFFORT``, whose own default is ``high``.
    An operator asking for no reasoning would get the slowest setting there is.
    So the omission is stated where this run states its request surface, by
    withholding ``reasoning`` from the allowlisted parameters — the mechanism
    this codebase already uses to say that a request does not carry a field.
    """

    resolved = request_effort(effort)
    profile = replace(DETERMINISTIC, seed=42, reasoning_effort=resolved)
    if resolved is None:
        return profile, tuple(name for name in REQUEST_PARAMETERS if name != "reasoning")
    return profile, REQUEST_PARAMETERS


_RUNTIME_ENVIRONMENT = (
    "TMPDIR",
    "TMP",
    "TEMP",
    "DFA_VOL_WORKDIR",
    "DFA_VOL_CACHE",
    "DFA_VOL_SYMBOL_DIRS",
    "HOME",
    "USERPROFILE",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "MPLCONFIGDIR",
)
_RUNTIME_LOCK = threading.RLock()


def tool_calls_from(oversight_path: str | Path) -> list[dict[str, object]]:
    """Return the recorded calls of one run's trace that ran and returned a result.

    This is what the forensic report counts as an evidence access and lists
    as a chain-of-custody row, so the selection states an outcome instead of
    inferring one from two gate flags.  ``allowed and not blocked`` answers
    only what the gate decided, and the argument gate refuses a call while
    leaving ``allowed`` true and ``blocked`` false: a refusal therefore
    passed that filter and was reported as an access that never happened.

    A module-level function of the path rather than a method of the live run,
    so a historic run directory reads through exactly the same code as the run
    that just finished.
    """

    rows = OversightLog.load(str(oversight_path))
    return [
        dict(row)
        for row in rows
        if row.get("event") == "action" and classify_action_outcome(row) == ACTION_EXECUTED
    ]


def standardized_findings_from(trace_path: str | Path) -> list[dict[str, object]]:
    """Return every standardized result one run's trace recorded, in order."""

    rows: list[dict[str, object]] = []
    trace = Path(trace_path)
    if not trace.exists():
        return rows
    with trace.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                row = json.loads(line)
            except (TypeError, json.JSONDecodeError):
                continue
            if isinstance(row, dict):
                rows.append(row)
    return rows


@dataclass(frozen=True, slots=True)
class ControlledRun:
    report: str
    run_id: str
    audit_path: Path
    oversight_path: Path
    tool_result_trace_path: Path
    visible_tools: tuple[str, ...]
    telemetry: Mapping[str, object]

    def tool_calls(self) -> list[dict[str, object]]:
        return tool_calls_from(self.oversight_path)

    def standardized_findings(self) -> list[dict[str, object]]:
        return standardized_findings_from(self.tool_result_trace_path)


class IncompleteExaminationError(ControlledConsoleError):
    """A run that read the evidence and reached its end with nothing to publish.

    It carries the run's own record — the oversight chain, the traced results and
    the control telemetry — because the caller has to be able to show what the
    examination established before it stopped.  Raised bare, the run's readings
    would become unreachable at the exact moment they are the only thing left:
    the panels that display them are built from the returned record, and a raise
    returns none.

    It remains an error and the run remains unanswered.  Nothing here is a
    conclusion, ``report`` is empty and stays empty, and callers that test for a
    published answer keep failing this run, which is the correct outcome.
    """

    def __init__(self, message: str, *, record: ControlledRun) -> None:
        super().__init__(message)
        self.record = record


_FAILURE_PHASE_METRICS = (
    "pending_tool_recovery_metrics",
    "reference_evidence_recovery_metrics",
    "continuation_metrics",
    "match_with_continuation_metrics",
    "memory_injection_corroboration_metrics",
    "memory_pagination_metrics",
    "identifier_grounding_metrics",
    "multisource_coverage_metrics",
    "premature_absence_metrics",
    "evidence_region_metrics",
    "unfinished_examination_metrics",
    "unproductive_repetition_metrics",
    "verifier_metrics",
    "final_answer_metrics",
    "structured_answer_metrics",
)
_FAILURE_PHASE_FIELDS = (
    "activated",
    "completed",
    "pending_call_count",
    "invalid_call_count",
    "ambiguous_candidate_count",
    # What the assembly step had to work with.  A draft that was never the
    # declared shape and one whose citation did not resolve both publish
    # nothing, and the counts are what tell those two apart.
    "segments",
    "bound_values",
    "unresolved_values",
)
_FAILURE_PHASE_STRING_FIELDS = ("decision", "activation_reason")
#: Outcomes recorded verbatim rather than as a digest.  They are a closed
#: vocabulary describing what the run decided, never anything it read, so
#: nothing about the evidence can travel in them.  Hashing them was what made a
#: run that reached the final check and was refused there indistinguishable from
#: one that never reached it: the diagnostic said an answer was absent without
#: saying why, and the same symptom was investigated three times over.
_FAILURE_PHASE_OUTCOME_FIELDS = (
    "verification_outcome",
    "publication_outcome",
    "accepted_source",
    # What the grounding gate was given to read, and who wrote the text that was
    # published. A failed run whose console never asked for assembly reads
    # exactly like one whose assembly was refused unless the record says which,
    # and these are the two fields that say it.
    "identifier_grounding",
    "published_text_authorship",
)
_PUBLICATION_GATE_NAMES = frozenset(
    {
        "pending_tool_recovery_blocked",
        "multisource_coverage_blocked",
        "match_with_continuation_blocked",
        "reference_evidence_recovery_blocked",
        "memory_injection_corroboration_blocked",
        "memory_pagination_blocked",
        "evidence_region_blocked",
        "unfinished_examination_blocked",
        "identifier_grounding_blocked",
    }
)
_BUDGET_FAILURE_FIELDS = (
    "wall_time_budget_s",
    "elapsed_s",
    "remaining_s",
    "max_investigation_requests",
    "investigation_dispatch_count",
    "investigation_dispatch_rejection_count",
    "max_model_requests",
    "model_dispatch_count",
    "model_dispatch_rejection_count",
    "max_tool_calls",
    "tool_dispatch_count",
    "tool_dispatch_rejection_count",
    # Reading a stored result is metered apart from reading the evidence, so the
    # diagnostic has to show both: a run that spent its time paging and one that
    # spent it re-reading the sources fail for different reasons.
    "max_navigation_calls",
    "navigation_dispatch_count",
    "navigation_dispatch_rejection_count",
    "control_closed_call_count",
    "deadline_exhausted",
)


_VERIFIER_VALIDATION_FAILURE_CODES = frozenset(
    {
        "missing_choice",
        "non_stop_finish",
        "provider_refusal",
        "unexpected_finish_reason",
        "empty_content",
        "invalid_json_or_schema",
        "invalid_json_syntax",
        "duplicate_json_key",
        "non_object_report",
        "invalid_report_contract",
        "claim_identity_mismatch",
        "missing_evidence_ref",
        "unknown_result_index",
        "missing_evidence_path",
        "non_scalar_evidence_path",
        "inconsistent_completion_state",
        "unknown_evidence_reference",
    }
)
_MODEL_REQUEST_FINISH_REASONS = frozenset(
    {
        "stop",
        "length",
        "content_filter",
        "tool_calls",
        "function_call",
        "error",
    }
)
_SAFE_TOKEN_USAGE_FIELDS = (
    "prompt_tokens",
    "completion_tokens",
    "total_tokens",
    "cost",
)


def _closed_verifier_failure_code(value: object) -> str | None:
    """Return a content-free verifier failure code from the runtime vocabulary."""

    if not isinstance(value, str) or not value:
        return None
    if value in _VERIFIER_VALIDATION_FAILURE_CODES:
        return value
    return "unattributed"


def _closed_model_finish_reason(value: object) -> str | None:
    """Return a bounded provider finish reason without trusting arbitrary text."""

    if not isinstance(value, str) or not value:
        return None
    if value in _MODEL_REQUEST_FINISH_REASONS:
        return value
    return "unknown"


#: Which telemetry row carries a coverage gate's own account of what closed it.
_GATE_METRIC_ROWS = {
    "evidence_region_blocked": "evidence_region_metrics",
    "unfinished_examination_blocked": "unfinished_examination_metrics",
}


def _blocked_gate_summary(telemetry: Mapping[str, object]) -> str:
    """Name the gates that withheld the report, so the reason is not just a code.

    Where a gate recorded WHICH finding closed it and what would satisfy it,
    both are stated: a block naming only its gate can send a model into hundreds
    of futile directory listings while telling the operator nothing.
    """

    publication = telemetry.get("publication_gate_metrics")
    if not isinstance(publication, Mapping):
        return ""
    blocked = publication.get("blocked_gates")
    if not isinstance(blocked, list):
        return ""
    names = sorted(
        {name for name in blocked if isinstance(name, str) and name in _PUBLICATION_GATE_NAMES}
    )
    if not names:
        return ""
    described: list[str] = []
    for name in names:
        row = telemetry.get(_GATE_METRIC_ROWS.get(name, ""))
        finding = row.get("blocking_finding") if isinstance(row, Mapping) else None
        satisfied = row.get("satisfied_by") if isinstance(row, Mapping) else None
        if isinstance(finding, str) and finding:
            detail = f" [{finding}"
            if isinstance(satisfied, str) and satisfied:
                detail += f"; satisfied by: {satisfied}"
            described.append(f"{name}{detail}]")
        else:
            described.append(name)
    return f"; blocked gates: {', '.join(described)}"


def _unpublished_answer_projection(telemetry: Mapping[str, object]) -> dict[str, object]:
    """Project the terminal publication cause onto the diagnostic's own schema.

    Read through the runtime's closed cause vocabulary rather than copied: this
    file writes a record an operator keeps, so a string that did not come from
    the runtime's own list is reported as unattributed instead of being trusted
    into the diagnostic.
    """

    source = telemetry.get("unpublished_answer_metrics")
    metrics = source if isinstance(source, Mapping) else {}
    cause = metrics.get("cause")
    gates = metrics.get("blocked_gates")
    readings = metrics.get("evidence_readings")
    bound = metrics.get("examination_bound")
    return {
        "schema_id": "forensic.unpublished-answer-metrics.v1",
        "cause": cause
        if isinstance(cause, str) and cause in UNPUBLISHED_ANSWER_CAUSES
        else "unattributed",
        # The one distinction the finish reason could never make, and the one a
        # reader of a failed run needs first: whether this system had a
        # conclusion in hand when it published nothing.
        "model_draft_present": metrics.get("model_draft_present") is True,
        "draft_reached_publication": metrics.get("draft_reached_publication") is True,
        "blocked_gates": (
            [name for name in gates if isinstance(name, str) and name in _PUBLICATION_GATE_NAMES]
            if isinstance(gates, list)
            else []
        ),
        "examination_bound": (
            bound if isinstance(bound, str) and bound in BUDGET_EXHAUSTION_REASONS else None
        ),
        "evidence_readings": (
            readings if isinstance(readings, int) and not isinstance(readings, bool) else 0
        ),
    }


def _unpublished_answer_summary(telemetry: Mapping[str, object]) -> str:
    """State the cause of an unpublished answer where the operator reads it.

    The finish reason names the outcome and never its cause, and that costs:
    runs that had found the answer and runs whose model wrote nothing end on the
    same word, so the operator cannot tell a defect in this system from a result
    about the model.  Both facts are stated here, in the same line, from a closed
    vocabulary that carries nothing read from the evidence.
    """

    projection = _unpublished_answer_projection(telemetry)
    draft = "draft held" if projection["model_draft_present"] else "no model draft"
    return f"; cause: {projection['cause']}; {draft}"


def _safe_failure_diagnostic(
    *,
    run_id: str,
    telemetry: Mapping[str, object],
    exception_type: str | None = None,
) -> dict[str, object]:
    """Project terminal telemetry onto a content-free diagnostic schema."""

    publication_source = telemetry.get("publication_gate_metrics")
    publication = publication_source if isinstance(publication_source, Mapping) else {}
    blocked_source = publication.get("blocked_gates")
    blocked_gates = (
        [
            name
            for name in blocked_source
            if isinstance(name, str) and name in _PUBLICATION_GATE_NAMES
        ]
        if isinstance(blocked_source, list)
        else []
    )
    publication_gate = {
        "schema_id": "forensic.publication-gate-metrics.v1",
        "publication_allowed": (
            exception_type is None and publication.get("publication_allowed") is True
        ),
        "blocked_gates": blocked_gates,
        "final_present": publication.get("final_present") is True,
        "evidence_integrity_failed": publication.get("evidence_integrity_failed") is True,
    }

    budget_source = telemetry.get("cell_execution_metrics")
    budget = budget_source if isinstance(budget_source, Mapping) else {}
    budget_projection = {
        field: budget[field]
        for field in _BUDGET_FAILURE_FIELDS
        if field in budget and isinstance(budget[field], bool | int | float)
    }
    exhaustion_source = budget.get("exhaustion_reasons")
    budget_projection["exhaustion_reasons"] = (
        [reason for reason in exhaustion_source if reason in BUDGET_EXHAUSTION_REASONS]
        if isinstance(exhaustion_source, list)
        else []
    )

    phase_metrics: dict[str, object] = {}
    for metric_name in _FAILURE_PHASE_METRICS:
        source = telemetry.get(metric_name)
        if not isinstance(source, Mapping):
            continue
        projection = {
            field: source[field]
            for field in _FAILURE_PHASE_FIELDS
            if field in source and isinstance(source[field], bool | int | float)
        }
        for field in _FAILURE_PHASE_STRING_FIELDS:
            value = source.get(field)
            if isinstance(value, str):
                projection[f"{field}_sha256"] = hashlib.sha256(value.encode("utf-8")).hexdigest()
        for field in _FAILURE_PHASE_OUTCOME_FIELDS:
            value = source.get(field)
            if isinstance(value, str) and value:
                projection[field] = value
        if metric_name == "verifier_metrics":
            failure_code = _closed_verifier_failure_code(source.get("validation_failure_code"))
            if failure_code is not None:
                projection["validation_failure_code"] = failure_code
        if metric_name in {"verifier_metrics", "final_answer_metrics"}:
            verification_row_count = source.get("verification_row_count")
            if (
                isinstance(verification_row_count, int)
                and not isinstance(verification_row_count, bool)
                and verification_row_count >= 0
            ):
                projection["verification_row_count"] = verification_row_count
        if projection:
            phase_metrics[metric_name] = projection

    # How each model request ended, which the totals below cannot show.  A run
    # that gathered its evidence and lost only the closing text reads exactly
    # like one that found nothing, unless the record says the terminal request
    # returned no text and states how the provider ended it.  Everything here is
    # a bounded provider vocabulary, a number, or a validated digest; response,
    # refusal and reasoning text stay out of the diagnostic.
    model_requests: list[dict[str, object]] = []
    request_count = 0
    usage_totals = {
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
        "cost_usd": 0.0,
    }
    request_ledger = telemetry.get("request_ledger")
    if isinstance(request_ledger, list):
        for request in request_ledger:
            if isinstance(request, Mapping):
                row: dict[str, object] = {}
                for field in ("role", "status", "error_type"):
                    value = request.get(field)
                    if isinstance(value, str) and value:
                        row[field] = value
                request_finish_reason = _closed_model_finish_reason(request.get("finish_reason"))
                if request_finish_reason is not None:
                    row["finish_reason"] = request_finish_reason
                response_digest = request.get("response_content_sha256")
                if isinstance(response_digest, str) and re.fullmatch(
                    r"[0-9a-f]{64}", response_digest
                ):
                    row["response_content_sha256"] = response_digest
                    row["response_text_present"] = True
                elif response_digest is None:
                    row["response_text_present"] = False
                response_byte_count = request.get("response_content_byte_count")
                if (
                    isinstance(response_byte_count, int)
                    and not isinstance(response_byte_count, bool)
                    and response_byte_count >= 0
                ):
                    row["response_content_byte_count"] = response_byte_count
                failure_code = _closed_verifier_failure_code(request.get("validation_failure_code"))
                if failure_code is not None:
                    row["validation_failure_code"] = failure_code
                refusal_present = request.get("refusal_present")
                if isinstance(refusal_present, bool):
                    row["refusal_present"] = refusal_present
                usage = request.get("token_usage")
                if isinstance(usage, Mapping):
                    numeric = {
                        name: usage[name]
                        for name in _SAFE_TOKEN_USAGE_FIELDS
                        if name in usage
                        for amount in (usage[name],)
                        if isinstance(amount, int | float) and not isinstance(amount, bool)
                    }
                    if numeric:
                        row["token_usage"] = numeric
                if row:
                    model_requests.append(row)
        for request in request_ledger:
            if not isinstance(request, Mapping):
                continue
            request_count += 1
            usage = request.get("token_usage")
            if not isinstance(usage, Mapping):
                continue
            for field in ("prompt_tokens", "completion_tokens", "total_tokens"):
                value = usage.get(field)
                if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                    usage_totals[field] += value
            cost = usage.get("cost")
            if isinstance(cost, int | float) and not isinstance(cost, bool) and cost >= 0:
                usage_totals["cost_usd"] += float(cost)

    model_usage = {
        "request_count": request_count,
        **usage_totals,
    }

    finish_reason = telemetry.get("finish_reason")
    if exception_type is not None:
        finish_reason = "runtime_error"
    elif not isinstance(finish_reason, str) or finish_reason not in {
        "completed",
        "completed_after_step_limit",
        "no_final_answer",
        "budget_exhausted:max_steps",
        "budget_exhausted:max_model_requests",
        "budget_exhausted:max_tool_calls",
        "budget_exhausted:max_wall_time_s",
    }:
        finish_reason = "unknown"
    diagnostic: dict[str, object] = {
        "schema_id": "forensic.controlled-run-failure.v1",
        "run_id": run_id,
        "finish_reason": finish_reason,
        "unpublished_answer_metrics": _unpublished_answer_projection(telemetry),
        "publication_gate_metrics": publication_gate,
        "cell_execution_metrics": budget_projection,
        "model_usage": model_usage,
        "model_requests": model_requests,
        "phase_metrics": phase_metrics,
    }
    if exception_type:
        diagnostic["exception_type"] = (
            exception_type
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", exception_type)
            else "UnknownError"
        )
    return diagnostic


def _write_failure_diagnostic(
    path: Path,
    *,
    run_id: str,
    telemetry: Mapping[str, object],
    exception_type: str | None = None,
) -> None:
    """Atomically persist one private, content-free failed-run diagnostic."""

    payload = json.dumps(
        _safe_failure_diagnostic(
            run_id=run_id,
            telemetry=telemetry,
            exception_type=exception_type,
        ),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".failure.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        temporary.unlink(missing_ok=True)


def _unusable_required_tools(
    required_tools: Sequence[str],
    visible_tools: Sequence[str],
) -> list[dict[str, object]]:
    """Describe every explicitly required function this host cannot execute.

    A required function is usable only if it reached the model-visible surface AND
    every external dependency it declares is resolved.  Both halves are needed:
    the interactive mode withholds a function whose binary is absent, while the
    locked evaluation keeps it on the surface and fails it closed, so neither
    membership nor dependency state alone would recognise the same defect in both
    modes.  Availability is read from ``core.tool_availability``, the same single
    registry the tool builder itself consults.
    """

    statuses = available_tools()
    visible = set(visible_tools)
    unusable: list[dict[str, object]] = []
    for name in dict.fromkeys(required_tools):
        missing = missing_dependencies_for(name, statuses)
        if name in visible and not missing:
            continue
        unusable.append(
            {
                "tool": name,
                "on_model_surface": name in visible,
                "missing_dependencies": [status.id for status in missing],
                "env_vars": [status.env_var for status in missing],
                "reason": "; ".join(status.reason for status in missing)
                or f"{name} is not part of the registry built for this evidence set",
            }
        )
    return unusable


def _refuse_unavailable_required_tools(
    required_tools: Sequence[str],
    visible_tools: Sequence[str],
    *,
    oversight_path: Path,
    question: str,
    case_id: str,
    model: str,
) -> None:
    """Stop a run whose explicitly required functions cannot execute here.

    The check is scoped to the names the caller declared as required.  An
    unscoped "abort when anything is missing" would abort every run on a host
    without 7-Zip or Tesseract, because ``archive_query`` and ``ocr_image`` are
    always in scope regardless of what the run needs.

    The refusal is recorded the way the orchestrator records a model-surface lock
    mismatch: one security event that states no model request was started, then an
    ``invalid_controls`` case close.  A run that stopped before reaching the model
    is then auditable, instead of being indistinguishable from one that never
    started.
    """

    unusable = _unusable_required_tools(required_tools, visible_tools)
    if not unusable:
        return
    recorder = OversightLog(str(oversight_path))
    recorder.open_case(
        question=question,
        # No policy was ever established: the run stops before the model surface
        # that would have carried one is built.
        policy=None,
        model=model,
        engine="langgraph",
        visible_tools=sorted(visible_tools),
        case_id=case_id,
    )
    recorder.record_security(
        "required_tool_unavailable",
        {
            "required_tools": list(dict.fromkeys(required_tools)),
            "unavailable_tools": unusable,
            "model_request_started": False,
        },
    )
    recorder.close_case(final="", status="invalid_controls")
    raise ControlledConsoleError(
        "Required forensic functions cannot run on this host: "
        + ", ".join(str(item["tool"]) for item in unusable)
        + ". No model request was made."
    )


@contextmanager
def _provider_routing_environment(provider: str | None) -> Iterator[None]:
    """Keep automatic interactive routing independent of stale study settings."""

    if provider is not None:
        yield
        return

    name = "DFA_OPENROUTER_PROVIDER"
    was_configured = name in os.environ
    previous = os.environ.pop(name, None)
    try:
        yield
    finally:
        if was_configured and previous is not None:
            os.environ[name] = previous


def _scratch_anchor(run_dir: Path, run_id: str) -> Path:
    """Choose the directory this run's controlled scratch is provisioned below.

    Everything a tool reconstructs out of the evidence is written below the
    controlled scratch: carved files, archive members a scanner unpacked, dumped
    memory regions, and every temporary file, because
    :func:`_controlled_tool_runtime` points TMPDIR and the per-tool output
    variables at a workspace inside it.  The run directory itself is on the
    records mount, which is bind-mounted from the host so the audit trail
    survives the container — and a bind mount puts those payloads on the host's
    own filesystem, where they are executables the host owns.

    A deployment that declares container-private storage therefore anchors the
    scratch there instead.  Only the scratch moves; the audit, oversight and
    tool-result records stay in the run directory, because those are inert text
    that has to be readable after the container is gone.

    Falling back to the run directory when no such storage is available is
    deliberate: the tools that reconstruct file content check their own output
    root and refuse, so the fallback costs those capabilities rather than the
    containment they exist inside.
    """

    payload_root = payload_scratch_root()
    if payload_root is None:
        return run_dir
    try:
        return provision_controlled_scratch_root(
            payload_root / run_id, anchor=payload_root
        ).root_path
    except ControlledScratchError:
        return run_dir


@contextmanager
def _controlled_tool_runtime(
    scratch: ControlledScratchSession,
    *,
    volatility_symbol_dir: Path | None = None,
    volatility_cache_seed: Path | None = None,
) -> Iterator[Path]:
    """Confine process-global temporary/output paths to one tracked run workspace."""

    with _RUNTIME_LOCK:
        with scratch.tool_runtime_workspace() as workspace:
            runtime_path = str(workspace.path)
            if volatility_cache_seed is not None:
                try:
                    shutil.copyfile(
                        volatility_cache_seed,
                        workspace.path / "identifier.cache",
                    )
                except OSError as exc:
                    raise ControlledConsoleError(
                        "The private Volatility cache could not be prepared."
                    ) from exc
            previous_environment = {name: os.environ.get(name) for name in _RUNTIME_ENVIRONMENT}
            previous_tempdir = tempfile.tempdir
            previous_cwd = os.getcwd()
            try:
                for name in _RUNTIME_ENVIRONMENT:
                    if name == "DFA_VOL_SYMBOL_DIRS":
                        if volatility_symbol_dir is not None:
                            os.environ[name] = str(volatility_symbol_dir)
                        elif previous_environment[name] is None:
                            os.environ.pop(name, None)
                        continue
                    os.environ[name] = runtime_path
                tempfile.tempdir = runtime_path
                os.chdir(workspace.path)
                yield workspace.path
            finally:
                os.chdir(previous_cwd)
                tempfile.tempdir = previous_tempdir
                for name, value in previous_environment.items():
                    if value is None:
                        os.environ.pop(name, None)
                    else:
                        os.environ[name] = value


class ControlledInvestigationSession:
    """Run independent, auditable interactive questions over attached evidence."""

    def __init__(
        self,
        *,
        model: str,
        base_url: str,
        api_key: str | None,
        output_root: Path,
        provider: str | None = DEFAULT_PROVIDER,
        provider_quantizations: tuple[str, ...] | None = DEFAULT_QUANTIZATIONS,
        max_steps: int = 20,
        max_tool_calls: int = 20,
        # max_steps investigation requests plus the reserved terminal path:
        # the forced-final conclusion may take two requests (ordinary + one
        # reasoning-relieved re-issue) and the verifier two (initial + retry).
        max_model_requests: int = 24,
        # A single legitimate call can legitimately take minutes: hashing the
        # decoded media of a 20 GB image in one streaming pass can take over
        # three minutes, which a 180 s ceiling would cut off, so an integrity
        # question would fail on the clock rather than on the evidence. The
        # ceiling exists to bound a runaway loop, not one honest pass over the
        # evidence.
        max_wall_time_s: float = 900.0,
        # The effort this session's questions run under. Deliberately the
        # LITERAL historical value rather than the console's default constant:
        # a caller that constructs a session without naming the effort must send
        # what it has always sent, whatever the operator's console defaults to
        # — and the console default has since moved to "high", which must not
        # leak into such a caller through a shared name.
        reasoning_effort: str = "low",
        volatility_symbol_dir: Path | None = None,
        volatility_cache_seed: Path | None = None,
        graph_runner: Callable[..., str | None] | None = None,
        id_factory: Callable[[], str] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        candidate_url = (base_url or "").strip()
        candidate_host = (urlsplit(candidate_url).hostname or "").casefold()
        local_hosts = {"localhost", "127.0.0.1", "::1", "host.docker.internal"}
        if candidate_host in local_hosts:
            self.base_url = validate_local_endpoint(candidate_url)
        else:
            self.base_url = validate_openrouter_endpoint(candidate_url, api_key)
        # Environment/file based launchers can leave a trailing newline on the
        # secret.  Validate first, then retain only the actual credential so a
        # perfectly valid OpenRouter key is not rejected by the HTTP endpoint.
        self.api_key = str(api_key or "ollama").strip()
        self.model = model
        self.provider = provider
        self.provider_quantizations = provider_quantizations
        self.output_root = Path(output_root).expanduser().resolve()
        self.output_root.mkdir(parents=True, exist_ok=True)
        self.max_steps = max_steps
        self.max_tool_calls = max_tool_calls
        self.max_model_requests = max_model_requests
        self.max_wall_time_s = float(max_wall_time_s)
        # Validated here rather than at the first question: an unusable choice
        # must fail before any evidence is opened or any request is spent.
        self.reasoning_effort = normalize_effort(reasoning_effort)
        self.volatility_symbol_dir = None
        if volatility_symbol_dir is not None:
            symbol_dir = Path(volatility_symbol_dir).expanduser().resolve()
            if not symbol_dir.is_dir():
                raise ControlledConsoleError(
                    "The configured Volatility symbol directory is unavailable."
                )
            self.volatility_symbol_dir = symbol_dir
        self.volatility_cache_seed = None
        if volatility_cache_seed is not None:
            try:
                cache_seed = Path(volatility_cache_seed).expanduser().resolve(strict=True)
            except (OSError, RuntimeError) as exc:
                raise ControlledConsoleError(
                    "The configured Volatility cache is unavailable."
                ) from exc
            if not cache_seed.is_file():
                raise ControlledConsoleError(
                    "The configured Volatility cache must be a regular file."
                )
            self.volatility_cache_seed = cache_seed
        self._graph_runner = graph_runner or run_investigation
        self._id_factory = id_factory or (lambda: uuid.uuid4().hex)
        self._monotonic = monotonic

    @staticmethod
    def _disk_family(disk) -> str:
        """Classify only the selected filesystem family for tool-surface routing.

        This is not an operating-system conclusion.  It prevents clearly
        Windows-only wrappers from appearing for a clearly non-Windows or
        unclassified filesystem. They are added only after Windows support is
        established from the selected filesystem metadata.
        """

        return classify_disk_family(disk)

    @classmethod
    def _relevant_tools(
        cls,
        *,
        disk,
        memory_path,
        pcap_path,
        pcap_sources=None,
        include_quarantined_tools: bool = False,
    ) -> set[str]:
        """The approved palette for this evidence, as the registry will build it.

        The flag must carry the SAME value the registry build receives. The two
        together decide the model surface: a palette naming a function the
        registry did not build would silently shrink the surface here and read as
        an active function in ``/tools``.
        """

        return set(
            tools_for_loaded_evidence(
                disk=disk,
                memory_path=memory_path,
                pcap_path=pcap_path,
                pcap_sources=pcap_sources,
                include_quarantined_tools=include_quarantined_tools,
            )
        )

    def _narrow_tool_palette(self, tools):
        """The tools a run is built from; the base narrows nothing.

        Exists so an interactive surface can shrink its palette (a shorter
        prompt is a faster prompt) without the evaluation harness — which
        instantiates this class directly — ever seeing a different set.
        """

        return tools

    @classmethod
    def _evidence_guidance(cls, disk) -> str | None:
        if disk is None or cls._disk_family(disk) != "posix":
            return None
        return (
            "EVIDENCE-SURFACE GUIDANCE: the selected filesystem is POSIX-like. "
            "Windows-only registry wrappers are intentionally absent. For an "
            "operating-system, distribution, or version question, locate and read "
            "the exact /etc/os-release or another discovered release file; do not "
            "identify a distribution from generic keyword references alone."
        )

    @classmethod
    def _scope_triage_state(cls) -> bool | None:
        """What this session did about scope BEFORE the run, for the run record.

        ``None`` here, and only the interactive subclass answers otherwise: the
        triage is the console's own pre-run rail and the evaluation harness runs
        none at all, so a harness run states that it triaged nothing rather than
        reporting the state of a switch it never consulted.
        """

        return None

    @staticmethod
    def _resolved_pcap_binding(
        pcap_path: str | None,
        pcap_sources: PcapSourceCatalog | None,
    ) -> tuple[str | None, PcapSourceCatalog | None]:
        """Bind a typed capture set to the exact default parser input.

        The tool layer requires the single capture path to equal the catalog
        default byte for byte, and it gates the network tools on that path being
        present at all.  Deriving one from the other here keeps the two from
        ever disagreeing, and compares them exactly the way the tool layer does
        so the console can neither accept what the tools reject nor the reverse.
        """

        if pcap_sources is None:
            return pcap_path, None
        if type(pcap_sources) is not PcapSourceCatalog:
            raise ControlledConsoleError(
                "Network sources must be provided as a typed source catalog."
            )
        default_path = pcap_sources.default.path
        if pcap_path and os.path.normcase(os.path.normpath(pcap_path)) != os.path.normcase(
            os.path.normpath(default_path)
        ):
            raise ControlledConsoleError(
                "The selected network capture does not match the catalog component "
                f"({pcap_sources.default_component_id})."
            )
        for binding in pcap_sources.bindings:
            candidate = Path(binding.path)
            if not candidate.is_absolute() or not candidate.is_file():
                raise ControlledConsoleError(
                    f"Bound network capture is unavailable: {binding.component_id}."
                )
        return default_path, pcap_sources

    @staticmethod
    def _assert_captures_within_roots(
        pcap_sources: PcapSourceCatalog | None,
        roots: Sequence[str],
    ) -> None:
        """Confine every bound capture to the roots the run already declares.

        These roots are the policy's READ scope, not its write scope: they hold
        the directory each evidence file sits in, while ``Policy.secure`` answers
        a write destination from ``work_dirs`` — the controlled scratch session —
        alone. A bound capture is another thing the run may read, so it must
        never widen the read scope; requiring it to lie inside the roots already
        declared, rather than extending them, is what keeps an additional capture
        from enlarging what any tool may reach.
        """

        if pcap_sources is None:
            return
        resolved_roots = [Path(root).expanduser().resolve() for root in roots]
        for binding in pcap_sources.bindings:
            candidate = Path(binding.path).expanduser().resolve()
            if not any(candidate.is_relative_to(root) for root in resolved_roots):
                raise ControlledConsoleError(
                    "The bound network capture is outside the declared case roots: "
                    f"{binding.component_id}."
                )

    @staticmethod
    def _validate_case_evidence_source(
        source: CaseEvidenceSource,
        *,
        case_id: str,
        disk,
        memory_path: str | None,
        pcap_path: str | None,
        pcap_sources: PcapSourceCatalog | None,
    ) -> None:
        """Ensure the path-free descriptor matches this console invocation."""

        if type(source) is not CaseEvidenceSource:
            raise ControlledConsoleError(
                "Case evidence must use the reviewed path-free descriptor type."
            )
        if source.case_id != case_id:
            raise ControlledConsoleError(
                "The case evidence descriptor belongs to a different case."
            )
        expected_modalities = {
            modality
            for modality, available in (
                ("disk", disk is not None),
                ("memory", bool(memory_path)),
                ("pcap", bool(pcap_path)),
            )
            if available
        }
        actual_modalities = {
            modality for modality, _component_ids in source.active_component_ids_by_modality
        }
        if actual_modalities != expected_modalities:
            raise ControlledConsoleError(
                "The case evidence descriptor does not match the loaded source types."
            )
        if pcap_sources is not None:
            try:
                validate_case_pcap_catalog(source, pcap_sources)
            except ValueError as exc:
                raise ControlledConsoleError(
                    "The network source catalog differs from the case evidence descriptor."
                ) from exc

    @staticmethod
    def _evidence_roots(
        *, disk, memory_path, pcap_path, case_roots: Sequence[str]
    ) -> list[str]:
        roots = {str(Path(root).expanduser().resolve()) for root in case_roots if root}
        for value in (
            getattr(disk, "image_path", None),
            memory_path,
            pcap_path,
        ):
            if value:
                roots.add(str(Path(value).expanduser().resolve().parent))
        return sorted(roots)

    def ask(
        self,
        question: str,
        *,
        case_context: str | None = None,
        disk=None,
        memory_path: str | None = None,
        memory_sha256: str | None = None,
        pcap_path: str | None = None,
        pcap_sources: PcapSourceCatalog | None = None,
        case_id: str | None = None,
        case_evidence_source: CaseEvidenceSource | None = None,
        case_roots: Sequence[str] = (),
        on_tool=None,
        tool_exposure: str = TOOL_EXPOSURE_FAIL_CLOSED,
        required_tools: Sequence[str] = (),
        include_quarantined_tools: bool = False,
    ) -> ControlledRun:
        """Run one controlled question over the attached evidence.

        ``tool_exposure`` selects the run mode.  It defaults to the locked
        evaluation behaviour, in which the palette never shrinks and the digests
        that a study pins stay reproducible across hosts; the interactive terminal
        passes the hiding policy explicitly.  ``required_tools`` names the
        functions this run cannot proceed without, and is the ONLY scope in which
        a missing external tool aborts the run.

        ``include_quarantined_tools`` re-admits the functions withdrawn from the
        default surface, to BOTH the palette and the registry, so a caller
        reproducing a historical run gets the surface that run had.  It defaults
        to False: an ordinary investigation is never handed one.
        """

        if not isinstance(question, str) or not question.strip():
            raise ControlledConsoleError("The investigation question must not be empty.")
        pcap_path, pcap_sources = self._resolved_pcap_binding(pcap_path, pcap_sources)
        if disk is None and not any((memory_path, pcap_path)):
            raise ControlledConsoleError("Load at least one forensic source first.")

        run_id = self._id_factory()
        if not isinstance(run_id, str) or not run_id or any(ch in run_id for ch in "/\\"):
            raise ControlledConsoleError("The run identifier generator returned an invalid value.")
        run_dir = self.output_root / run_id
        try:
            run_dir.mkdir(mode=0o700)
        except OSError as exc:
            raise ControlledConsoleError(
                "The private execution directory could not be opened."
            ) from exc

        audit_path = run_dir / "audit.jsonl"
        oversight_path = run_dir / "oversight.jsonl"
        tool_result_trace_path = run_dir / "tool-results.jsonl"
        scratch_anchor = _scratch_anchor(run_dir, run_id)
        scratch_attestation = provision_controlled_scratch_root(
            scratch_anchor / "scratch",
            anchor=scratch_anchor,
        )
        scratch = ControlledScratchSession(scratch_attestation, namespace=run_id)
        telemetry: dict[str, object] = {}
        started = self._monotonic()
        stable_case_id = case_id or f"interactive-{run_id[:12]}"
        if case_evidence_source is not None:
            self._validate_case_evidence_source(
                case_evidence_source,
                case_id=stable_case_id,
                disk=disk,
                memory_path=memory_path,
                pcap_path=pcap_path,
                pcap_sources=pcap_sources,
            )

        if disk is not None and hasattr(disk, "audit"):
            disk.audit = AuditLog(str(audit_path))

        relevant = self._relevant_tools(
            disk=disk,
            memory_path=memory_path,
            pcap_path=pcap_path,
            pcap_sources=pcap_sources,
            include_quarantined_tools=include_quarantined_tools,
        )
        # The registry is built HERE, before the run, so the palette and the
        # policy are derived from real function names.  The run's retained
        # results do not exist yet, so the operations that consume an earlier
        # result are bound to this slot and the run fills it in.
        citation_resolver_slot = DeferredCitedValueResolver()
        try:
            native_tools = build_tools(
                disk,
                memory_path=memory_path,
                memory_sha256=memory_sha256,
                pcap_path=pcap_path,
                pcap_sources=pcap_sources,
                on_tool=on_tool,
                controlled_scratch=scratch,
                cited_value_resolver=citation_resolver_slot,
                # Hand back RAW tools: the model surface owns the whole boundary
                # chain and applies capture (with the run's real oversight store),
                # oversight, standardization and finally the projection to every
                # tool it exposes.
                capture=False,
                project=False,
                tool_exposure=tool_exposure,
                include_quarantined_tools=include_quarantined_tools,
            )
            # A subclass may narrow the palette for its own surface; the base
            # returns the tools untouched, so every evaluation run keeps the
            # exact palette its pinned digests describe.
            native_tools = self._narrow_tool_palette(native_tools)
            tool_names = [str(getattr(tool, "name", "")) for tool in native_tools]
            if any(not name for name in tool_names):
                raise ControlledConsoleError("A registered function has no valid name.")
            if len(tool_names) != len(set(tool_names)):
                raise ControlledConsoleError("Registered function names must be unique.")
            # The navigation function is on the palette but is assembled by the
            # model surface, not by the registry: it opens no evidence and runs no
            # backend, so it has no entry among the executable names and this
            # intersection would silently drop it off the palette.
            executable_tools = tuple(sorted(relevant & set(tool_names)))
            if not executable_tools:
                raise ControlledConsoleError(
                    "No approved tool is available for the loaded evidence type."
                )
            visible_tools = tuple(sorted(set(executable_tools) | (relevant & NAVIGATION_FUNCTIONS)))
            # Before the model surface is prepared and therefore before any model
            # request: a run that needs a function this host cannot execute must
            # not spend a request only to discover it mid-investigation.
            _refuse_unavailable_required_tools(
                required_tools,
                visible_tools,
                oversight_path=oversight_path,
                question=question.strip(),
                case_id=run_id,
                model=self.model,
            )
            prepared_tools = [
                tool
                for tool, name in zip(native_tools, tool_names, strict=True)
                if name in executable_tools
            ]
            roots = self._evidence_roots(
                disk=disk,
                memory_path=memory_path,
                pcap_path=pcap_path,
                case_roots=case_roots,
            )
            # Bound captures must live inside the roots this run already
            # declares, so an extra capture may never widen the READ scope.
            # These roots are not the write scope: they contain the directory
            # each evidence file sits in, and the run's write scope is the
            # controlled scratch session below and nothing else.
            self._assert_captures_within_roots(pcap_sources, roots)
            policy = Policy.secure(
                path_roots=roots,
                work_dirs=[str(scratch.session_path)],
                # The executable names only.  The gate supervises observations,
                # and the navigation function makes none; naming it here would
                # record an allowlist entry for something the gate never sees.
                allowed_tools=set(executable_tools),
                allow_network=False,
                allow_write=True,
                allow_spawn=True,
                controlled_scratch_attestation_sha256=scratch.attestation.sha256,
                controlled_scratch_root=str(scratch.attestation.root_path),
            )
            profile, decoding_parameters = _decoding_controls(self.reasoning_effort)
            with (
                _controlled_tool_runtime(
                    scratch,
                    volatility_symbol_dir=self.volatility_symbol_dir,
                    volatility_cache_seed=self.volatility_cache_seed,
                ),
                _provider_routing_environment(self.provider),
            ):
                report = self._graph_runner(
                    disk,
                    question.strip(),
                    case_context=case_context,
                    prepared_tools=prepared_tools,
                    citation_resolver_slot=citation_resolver_slot,
                    model=self.model,
                    base_url=self.base_url,
                    api_key=self.api_key,
                    provider=self.provider,
                    provider_quantizations=self.provider_quantizations,
                    decoding_profile=profile,
                    decoding_parameters=decoding_parameters,
                    max_steps=self.max_steps,
                    memory_path=memory_path,
                    pcap_path=pcap_path,
                    pcap_sources=pcap_sources,
                    verbose=False,
                    guidance=self._evidence_guidance(disk),
                    on_tool=on_tool,
                    verify=_console_runs_the_final_check(),
                    # This pin is validated against the arm policy, which
                    # derives the first tool choice from ``verify``: required
                    # on the verified arm, auto otherwise. It must move with
                    # the switch or preparation refuses the run outright.
                    first_investigation_tool_choice=(
                        "required" if _console_runs_the_final_check() else "auto"
                    ),
                    verify_model=self.model,
                    verification_provider=self.provider,
                    verification_provider_quantizations=self.provider_quantizations,
                    verification_fail_closed=True,
                    spotlight=True,
                    policy=policy,
                    # Stated into the run's own record: a comparison taken with
                    # the scope triage switched off must not read like one taken
                    # with it on.
                    scope_triage=self._scope_triage_state(),
                    oversight_path=str(oversight_path),
                    visible_tools=set(visible_tools),
                    standardize_tool_results=True,
                    case_id=stable_case_id,
                    case_evidence_source=case_evidence_source,
                    invocation_namespace=run_id,
                    tool_result_trace_path=str(tool_result_trace_path),
                    telemetry=telemetry,
                    # The transport divides the reserved cell time across the
                    # attempts the SDK may make, so a large retry count buys
                    # resilience by shortening every single attempt below what a
                    # legitimate high-effort request needs. A small count keeps
                    # both: transient router failures are still retried, and one
                    # dispatch still cannot outlast the cell it was reserved from.
                    sdk_max_retries=3,
                    request_timeout_s=self.max_wall_time_s,
                    cell_started_monotonic=started,
                    cell_deadline_monotonic=started + self.max_wall_time_s,
                    # Hold back a slice of the wall-time for the terminal path so
                    # a long, over-investigating run still concludes from what it
                    # gathered instead of timing out empty.  A fifth of the
                    # budget, capped at three minutes; a caller that does not pass
                    # this keeps its deadline as a single hard wall.
                    reserved_terminal_wall_time_s=min(self.max_wall_time_s * 0.2, 180.0),
                    max_model_requests=self.max_model_requests,
                    max_tool_calls=self.max_tool_calls,
                    controlled_scratch=scratch,
                    recover_incomplete_run=True,
                    # Coverage enforcement is a property of the verified pass:
                    # preparation refuses the combination of coverage without
                    # verification outright. When the operator switches the
                    # final check off for speed, coverage goes with it rather
                    # than turning every question into that refusal.
                    enforce_explicit_multisource_coverage=(
                        case_evidence_source is not None
                        and _console_runs_the_final_check()
                    ),
                    # With this on, every result reaches the model under a name
                    # and the published answer is assembled from the names it
                    # cited, so the values in it stop being something a model
                    # typed. OFF by default, for the reason recorded on the
                    # variable itself: a run whose model answers the terminal
                    # request in prose assembles nothing and publishes nothing.
                    # A run that leaves it off therefore publishes model prose,
                    # and ``published_text_authorship`` in the run's own record
                    # says which of the two happened.
                    deliver_model_result_envelope=_console_delivers_model_result_envelope(),
                )
        except Exception as exc:
            try:
                _write_failure_diagnostic(
                    run_dir / "failure.json",
                    run_id=run_id,
                    telemetry=telemetry,
                    exception_type=type(exc).__name__,
                )
            except OSError:
                pass
            raise
        finally:
            scratch.close()

        if not report:
            try:
                _write_failure_diagnostic(
                    run_dir / "failure.json",
                    run_id=run_id,
                    telemetry=telemetry,
                )
            except OSError:
                pass
            finish_reason = str(telemetry.get("finish_reason") or "unknown")
            raise IncompleteExaminationError(
                "The agent did not produce a final finding "
                f"(reason: {finish_reason}{_blocked_gate_summary(telemetry)}"
                f"{_unpublished_answer_summary(telemetry)}; "
                f"run: {run_id}; diagnostics: failure.json).",
                record=ControlledRun(
                    # Empty, and it must stay empty: this run published no
                    # conclusion, and the record exists so what it DID read can
                    # be shown, never so an answer can be reconstructed from it.
                    report="",
                    run_id=run_id,
                    audit_path=audit_path,
                    oversight_path=oversight_path,
                    tool_result_trace_path=tool_result_trace_path,
                    visible_tools=visible_tools,
                    telemetry=telemetry,
                ),
            )
        return ControlledRun(
            report=report,
            run_id=run_id,
            audit_path=audit_path,
            oversight_path=oversight_path,
            tool_result_trace_path=tool_result_trace_path,
            visible_tools=visible_tools,
            telemetry=telemetry,
        )
