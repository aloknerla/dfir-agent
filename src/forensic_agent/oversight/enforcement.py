"""Policy gate and shared per-call enforcement pipeline."""

from __future__ import annotations

import json
import sys
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from forensic_agent.core.evidence_source import (
    EvidenceSourceError,
    EvidenceSourceRuntimeGuard,
)
from forensic_agent.core.repro import canonical_json
from forensic_agent.core.result_reading import claims_result_envelope, is_readable_result
from forensic_agent.oversight.audit import (
    ACTION_EXECUTED,
    ACTION_FAILED,
    ACTION_REFUSED_BY_OVERSIGHT,
    ACTION_REFUSED_BY_TOOL,
    OversightLog,
)
from forensic_agent.oversight.detectors import detect_injection, scan_tools
from forensic_agent.oversight.grounding import GroundingLedger
from forensic_agent.oversight.policy import RISK_NAMES, Decision, Policy, evaluate


def _facade_value(name: str, implementation: Any) -> Any:
    """Resolve a value overridden through the historical ``core`` module."""
    facade = sys.modules.get("forensic_agent.oversight.core")
    return implementation if facade is None else getattr(facade, name, implementation)


@dataclass(frozen=True, slots=True)
class ArgumentRefusal:
    """One call the argument contract declines, and the answer it owes its caller.

    ``output`` arrives already written and is returned unedited.  The oversight
    layer decides WHETHER a call may proceed; it does not compose the sentence
    that tells a caller what the refused field actually takes, because that
    sentence is read from the tool's own schema at refusal time and a second
    wording here would be a second copy of the rules, free to drift from what the
    tool accepts.  ``code`` names the refusal for the record, in the same
    vocabulary the payload carries.

    ``reasons`` carries that same sentence in the form the RECORD takes: one
    line per offending field, already readable.  It is a declared field of this
    object rather than something the gate digs out of ``output``, because
    ``output`` is the tool layer's payload and its shape is that layer's own; a
    gate that reached into it would be reading a schema it must not know.  The
    contract fills it from what it has already written, so the sentence in the
    record and the sentence the model received cannot come apart.  Empty for a
    contract that offers none, and the record then names the refusal by code
    alone, exactly as it did before this field existed.
    """

    code: str
    output: Mapping[str, Any]
    reasons: tuple[str, ...] = ()


@runtime_checkable
class ArgumentContract(Protocol):
    """The argument half of one permission decision.

    A call is permitted when the policy AND the argument contract accept it.  The
    two used to be decided a step apart — the policy here, the arguments inside
    the tool the gate had already approved — so the record said "allowed" about a
    call that never happened.

    ``refusal`` returns ``None`` both for a call the contract accepts and for a
    tool it makes no statement about: a tool with no declared argument contract
    is left exactly where it was rather than judged against somebody else's
    schema.
    """

    def refusal(
        self, tool: str, args: Mapping[str, Any]
    ) -> ArgumentRefusal | None: ...


class OversightGate:
    """Tie a :class:`Policy` to an :class:`OversightLog`."""

    def __init__(
        self,
        policy: Policy | None = None,
        recorder: OversightLog | None = None,
        *,
        evidence_source_guard: EvidenceSourceRuntimeGuard | None = None,
        argument_contract: ArgumentContract | None = None,
    ) -> None:
        policy_type = _facade_value("Policy", Policy)
        log_type = _facade_value("OversightLog", OversightLog)
        ledger_type = _facade_value("GroundingLedger", GroundingLedger)
        self.policy = policy or policy_type.permissive()
        self.recorder = recorder or log_type()
        self.ledger = ledger_type(roots=getattr(self.policy, "path_roots", []))
        self.evidence_source_guard = evidence_source_guard
        # Supplied by whoever built the surface, because the argument contract
        # belongs to the tools and this layer must not carry a second copy of
        # their schemas.  ``None`` leaves each tool to refuse its own arguments,
        # which is where that decision lived before and where it still lands for
        # any surface that declares no contract.
        self.argument_contract = argument_contract
        self._failed_call_lock = threading.Lock()
        self._deterministic_failed_calls: set[tuple[str, str]] = set()

    def evaluate(self, tool: str, args: dict) -> Decision:
        evaluator = _facade_value("evaluate", evaluate)
        return evaluator(self.policy, tool, args)

    def _failed_call_seen(self, tool: str, args: dict[str, Any]) -> bool:
        key = (tool, canonical_json(args))
        with self._failed_call_lock:
            return key in self._deterministic_failed_calls

    def _remember_failed_call(self, tool: str, args: dict[str, Any]) -> None:
        key = (tool, canonical_json(args))
        with self._failed_call_lock:
            self._deterministic_failed_calls.add(key)


@dataclass(frozen=True, slots=True)
class OversightBoundOutput:
    """Raw return value paired with the action entry that recorded it.

    ``capture`` is this invocation's own complete-output capture, carried
    alongside rather than looked up, so the standardizer downstream binds the
    result to the capture of exactly this call.
    """

    output: Any
    action: dict[str, Any]
    capture: Any = None


def _bind_output(
    output: Any, action: dict[str, Any], *, bind_action: bool, capture: Any = None
) -> Any:
    bound_output_type = _facade_value("OversightBoundOutput", OversightBoundOutput)
    if not bind_action:
        # Without the standardization transport the action is not bound, but the
        # CAPTURE still has to reach the projection: dropping it here would let a
        # failed or incomplete retention look like an ordinary result to the model.
        if capture is not None:
            from forensic_agent.core.output_capture import CapturedToolOutput

            return CapturedToolOutput(output=output, capture=capture)
        return output
    try:
        return bound_output_type(output=output, action=action, capture=capture)
    except TypeError:
        # A facade override may predate the capture field; the result contract
        # still functions, it simply has no capture to bind.
        return bound_output_type(output=output, action=action)


def _evidence_integrity_failure(
    gate: OversightGate,
    checkpoint: str,
) -> dict[str, Any] | None:
    """Run one physical-source checkpoint and emit sanitized audit detail."""
    guard = gate.evidence_source_guard
    if guard is None:
        return None
    try:
        guard.check(checkpoint)
    except EvidenceSourceError:
        detail = {
            "checkpoint": checkpoint,
            "source_attestation_sha256": guard.telemetry()[
                "source_attestation_sha256"
            ],
            "sticky": True,
        }
        gate.recorder.record_security(
            "evidence_source_integrity_violation", detail
        )
        risk_names = _facade_value("RISK_NAMES", RISK_NAMES)
        return {
            "error": "BLOCKED by evidence source integrity guard",
            "risk": risk_names[4],
            "reasons": [
                f"evidence-source-integrity-violation:{checkpoint}"
            ],
        }
    return None


def _is_deterministic_tool_error(result: Any) -> bool:
    """Return whether the tool explicitly marks this completed failure as stable."""
    if not isinstance(result, Mapping):
        return False
    if is_readable_result(result):
        # A standardized envelope states failure through ``status``; its ``error``
        # block is populated only then.  Reading ``error`` alone, as the
        # pre-envelope branch must, would call a successful result a failure the
        # moment a contract kept the field present and null.
        if result.get("status") != "error":
            return False
        error = result.get("error")
    else:
        error = result.get("error")
        if error in (None, "", False):
            return False
    nested_deterministic = isinstance(error, Mapping) and (
        error.get("deterministic_error") is True
    )
    return result.get("deterministic_error") is True or nested_deterministic


def _declared_error(result: Any) -> str | None:
    """Name the failure a completed call declares, or ``None`` if it declares none.

    Read exactly where :func:`_is_deterministic_tool_error` reads, so the two
    can never disagree about whether a call failed while disagreeing only about
    whether the failure was stable.  The code, not the message, is returned: the
    message is tool prose and may quote arguments, and this value is written to
    the record and shown to the operator.
    """

    if not isinstance(result, Mapping):
        return None
    if is_readable_result(result):
        if result.get("status") != "error":
            return None
        error = result.get("error")
    else:
        error = result.get("error")
        if error in (None, "", False):
            return None
    if isinstance(error, Mapping):
        code = error.get("code")
        return code if isinstance(code, str) and code.strip() else "error"
    # A surface that predates the error contract states its failure as prose.
    # Bounded and collapsed to one line: it is a diagnostic the report shows
    # beside the call, not a place for a tool to write a paragraph into.
    return " ".join(str(error).split())[:120] or "error"


def _completed_call_outcome(result: Any) -> tuple[str, str | None]:
    """Classify one call that reached the tool and came back without raising."""

    code = _declared_error(result)
    if code is None:
        return ACTION_EXECUTED, None
    if _is_deterministic_tool_error(result):
        return ACTION_REFUSED_BY_TOOL, code
    return ACTION_FAILED, code


def enforce(
    gate,
    name,
    args,
    run_fn,
    *,
    spotlight: bool = False,
    bind_action: bool = False,
):
    """Run one tool call through the complete oversight pipeline.

    ``run_fn`` is a zero-argument callable that performs the real invocation.
    Blocked calls and exceptions are converted to error dictionaries and
    recorded. ``bind_action`` is an internal transport mode that pairs the
    returned value with the exact oversight entry that recorded it.
    """
    # No ambient capture state is consulted anywhere in this pipeline: each
    # capture travels with the value it describes (see ``unwrap_captured``
    # below), so an entry recorded for a call that never reached the capture
    # boundary simply carries none.
    started_at = time.time()
    integrity_error = _evidence_integrity_failure(gate, "pre_tool_use")
    decision = gate.evaluate(name, args)
    if integrity_error is not None:
        decision.allowed = False
        decision.risk = 4
        decision.reasons = list(decision.reasons) + list(
            integrity_error["reasons"]
        )
        action = gate.recorder.record_action(
            tool=name,
            args=args,
            decision=decision,
            output=integrity_error,
            duration_s=time.time() - started_at,
            outcome=ACTION_REFUSED_BY_OVERSIGHT,
            outcome_detail="evidence_source_integrity_violation",
        )
        return _bind_output(
            integrity_error, action, bind_action=bind_action
        )
    if not decision.allowed:
        blocked_output = {
            "error": "BLOCKED by oversight policy",
            "risk": decision.risk_name,
            "reasons": decision.reasons,
        }
        action = gate.recorder.record_action(
            tool=name,
            args=args,
            decision=decision,
            output=blocked_output if bind_action else None,
            duration_s=0.0,
            outcome=ACTION_REFUSED_BY_OVERSIGHT,
        )
        return _bind_output(blocked_output, action, bind_action=bind_action)

    ungrounded = gate.ledger.check(args)
    if ungrounded:
        decision.reasons = list(decision.reasons) + [
            f"ungrounded-path:{key}={value}"
            for key, value, _basis in ungrounded
        ]
        if getattr(gate.policy, "ground_paths", False) and name not in (
            # Reference lookups take generic keys, not evidence paths, so
            # grounding them would block the very call the hint recommends.
            "artifact_reference_query",
        ):
            decision.allowed = False
            blocked_output = {
                "error": "BLOCKED by oversight policy (ungrounded path)",
                "risk": decision.risk_name,
                "reasons": decision.reasons,
                "hint": (
                    "Resolve the location with a reference lookup or discover it "
                    "by listing the parent directory before access."
                ),
            }
            action = gate.recorder.record_action(
                tool=name,
                args=args,
                decision=decision,
                output=blocked_output if bind_action else None,
                duration_s=time.time() - started_at,
                outcome=ACTION_REFUSED_BY_OVERSIGHT,
                outcome_detail="ungrounded_path",
            )
            return _bind_output(
                blocked_output, action, bind_action=bind_action
            )

    if gate._failed_call_seen(name, args):
        decision.allowed = False
        decision.risk = max(decision.risk, 1)
        decision.reasons = list(decision.reasons) + [
            "repeated-deterministic-tool-error"
        ]
        blocked_output = {
            "error": "BLOCKED: identical tool call already failed deterministically",
            "code": "repeated_deterministic_tool_error",
            "retryable": False,
            "hint": "Change the arguments or select a different tool; do not repeat this call.",
        }
        action = gate.recorder.record_action(
            tool=name,
            args=args,
            decision=decision,
            output=blocked_output,
            duration_s=time.time() - started_at,
            outcome=ACTION_REFUSED_BY_OVERSIGHT,
            outcome_detail="repeated_deterministic_tool_error",
        )
        return _bind_output(blocked_output, action, bind_action=bind_action)

    contract = getattr(gate, "argument_contract", None)
    argument_refusal = None if contract is None else contract.refusal(name, args)
    if argument_refusal is not None:
        # The last gate before the tool, and the only one that reads the call's
        # own arguments against the contract the tool publishes.  The tool is not
        # reached and nothing is opened, so the outcome is a refusal BY THIS
        # LAYER, named and detailed on the one entry this call gets.
        #
        # ``allowed`` is set to False HERE, on the gate's own decision object.
        # It once stayed as the policy left it, on the argument that the field
        # measured what the POLICY decided; the result was a record that read
        # ``allowed: true, blocked: false`` about a call that never ran, which
        # is untrue on its face however it is explained.  Measured across the
        # recorded corpus, 98 of 100 oversight refusals were this path, so the
        # field was wrong far more often than it was right.  ``allowed`` now
        # means what a reader takes it to mean: this call was permitted to
        # proceed.  Which of the two gates refused it is still recorded, and
        # still separable — ``outcome_detail`` is None for a policy denial and
        # names the refusal code for this one, and the leading reason below says
        # it in words.
        decision.allowed = False
        decision.reasons = [
            # The cause first, in the words the contract already wrote.  It used
            # to be appended last, behind reasons that describe what the tool
            # DOES, and a bounded view then showed a refusal explained by the
            # authority it would have used.
            *argument_refusal.reasons,
            f"invalid-arguments:{argument_refusal.code}",
            # Kept, and kept last.  These describe the authority the call would
            # have exercised, which is the same information that justifies
            # keeping the risk below; they are simply not the ground of anything
            # and must never lead.  ``policy.partition_reasons`` names them for
            # any view that has to tell the two apart.
            *decision.reasons,
        ]
        # The risk the policy computed is KEPT.  It states the authority this call
        # would have exercised, which is what the run's maximum risk summarises;
        # zeroing it because the call was stopped would quietly drop a refused
        # attempt at a spawning, writing tool out of that figure.
        refusal_output = dict(argument_refusal.output)
        # Remembered like any other stable failure, so a byte-identical retry
        # meets the repeat rule above instead of being validated to the same
        # answer a second time.
        gate._remember_failed_call(name, args)
        action = gate.recorder.record_action(
            tool=name,
            args=args,
            decision=decision,
            output=refusal_output,
            duration_s=time.time() - started_at,
            outcome=ACTION_REFUSED_BY_OVERSIGHT,
            outcome_detail=argument_refusal.code,
        )
        return _bind_output(refusal_output, action, bind_action=bind_action)

    from forensic_agent.core.output_capture import unwrap_captured

    tool_error: Exception | None = None
    result: Any = None
    invocation_capture = None
    try:
        # Only a failure of the TOOL itself becomes ``tool_error``.  Capture and
        # storage failures are handled inside the capture boundary and surface as
        # flags on the capture, never as a tool exception, so a result the tool
        # genuinely produced is not recorded as a tool failure because retaining
        # it failed.
        result, invocation_capture = unwrap_captured(run_fn())
    except Exception as error:
        tool_error = error

    post_integrity_error = _evidence_integrity_failure(
        gate, "post_tool_use"
    )
    if post_integrity_error is not None:
        decision.risk = 4
        decision.reasons = list(decision.reasons) + list(
            post_integrity_error["reasons"]
        )
        if tool_error is not None:
            decision.reasons.append("tool-raised-exception")
        action = gate.recorder.record_action(
            tool=name,
            args=args,
            decision=decision,
            output=post_integrity_error,
            duration_s=time.time() - started_at,
            capture=invocation_capture,
            # The tool DID run here; what failed is the source underneath it.
            # Calling that a refusal would credit the gate with stopping a call
            # it had already let through.
            outcome=ACTION_FAILED,
            outcome_detail="evidence_source_integrity_violation",
        )
        return _bind_output(
            post_integrity_error, action, bind_action=bind_action
        )

    if tool_error is not None:
        error_output = {
            "error": f"{type(tool_error).__name__}: {str(tool_error)[:200]}"
        }
        decision.reasons = list(decision.reasons) + [
            "tool-raised-exception"
        ]
        action = gate.recorder.record_action(
            tool=name,
            args=args,
            decision=decision,
            output=error_output,
            duration_s=time.time() - started_at,
            outcome=ACTION_FAILED,
            outcome_detail=type(tool_error).__name__,
        )
        return _bind_output(error_output, action, bind_action=bind_action)

    if _is_deterministic_tool_error(result):
        gate._remember_failed_call(name, args)
    outcome, outcome_detail = _completed_call_outcome(result)

    body = (
        result
        if isinstance(result, str)
        else json.dumps(result, ensure_ascii=False, default=str)
    )
    injection_detector = _facade_value(
        "detect_injection", detect_injection
    )
    injected = injection_detector(body)
    if injected:
        decision.reasons = list(decision.reasons) + [
            "injection-signal:" + ",".join(injected)
        ]
    action = gate.recorder.record_action(
        tool=name,
        args=args,
        decision=decision,
        output=result,
        duration_s=time.time() - started_at,
        capture=invocation_capture,
        outcome=outcome,
        outcome_detail=outcome_detail,
    )
    gate.ledger.observe(args, result)
    if spotlight and isinstance(result, dict) and claims_result_envelope(result):
        # Anything that declares one of our envelopes stays JSON-native, including
        # a version this build cannot read.  Wrapping such a value in the text
        # markers would leave the readers downstream unable to parse it at all, so
        # an unrecognised result would vanish without ever being counted; kept as
        # JSON, each reader refuses it explicitly and says so.
        return _bind_output(
        result, action, bind_action=bind_action, capture=invocation_capture
    )
    if spotlight:
        spotlighted = (
            "«EVIDENCE_DATA»\n" + body + "\n«END_EVIDENCE_DATA»"
        )
        return _bind_output(
            spotlighted, action, bind_action=bind_action, capture=invocation_capture
        )
    return _bind_output(
        result, action, bind_action=bind_action, capture=invocation_capture
    )


def wrap_with_oversight(
    tools: list,
    gate: OversightGate,
    *,
    spotlight: bool = False,
    bind_action: bool = False,
) -> list:
    """Wrap LangChain tools so every invocation passes through the gate."""
    from langchain_core.tools import StructuredTool

    scanner = _facade_value("scan_tools", scan_tools)
    poisoned = {
        finding["tool"]: finding["reasons"] for finding in scanner(tools)
    }
    for name, reasons in poisoned.items():
        gate.recorder.record_security(
            "tool_poisoning", {"tool": name, "reasons": reasons}
        )

    wrapped_tools = []
    for tool in tools:
        if tool.name in poisoned and getattr(
            gate.policy, "quarantine_poisoned_tools", False
        ):
            continue
        original = tool.func

        def make(function, tool_name):
            def wrapped(**kwargs):
                enforcement = _facade_value("enforce", enforce)
                return enforcement(
                    gate,
                    tool_name,
                    kwargs,
                    lambda: function(**kwargs),
                    spotlight=spotlight,
                    bind_action=bind_action,
                )

            return wrapped

        wrapped_tools.append(
            StructuredTool.from_function(
                make(original, tool.name),
                name=tool.name,
                description=tool.description,
                args_schema=tool.args_schema,
                metadata=getattr(tool, "metadata", None),
            )
        )
    return wrapped_tools


__all__ = [
    "ArgumentContract",
    "ArgumentRefusal",
    "OversightBoundOutput",
    "OversightGate",
    "enforce",
    "wrap_with_oversight",
]
