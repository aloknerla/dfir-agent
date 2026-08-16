"""Tamper-evident oversight recording, reconstruction, and chain verification."""

from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from typing import Any

from forensic_agent.core.audit import default_log_path, sha256_bytes
from forensic_agent.core.repro import canonical_json, sha256_hex
from forensic_agent.core.tool_result import canonical_raw_output_sha256
from forensic_agent.oversight.policy import RISK_NAMES, Decision, Policy


def _facade_value(name: str, implementation: Any) -> Any:
    """Resolve a value overridden through the historical ``core`` module."""
    facade = sys.modules.get("forensic_agent.oversight.core")
    return implementation if facade is None else getattr(facade, name, implementation)


# ---------------------------------------------------------------------------
# What became of one recorded call.
#
# The gate's decision and the call's outcome are two different facts, and the
# record used to carry only the first.  A call the gate permitted and the tool
# then refused on its own arguments therefore counted as an ordinary success:
# the refusal read nowhere in the reconstruction, and ``blocked`` — which counts
# gate denials and nothing else — reported zero while a call had in fact been
# refused.  These four names let the reconstruction say which of the four
# actually happened, for every call.
# ---------------------------------------------------------------------------

#: The call ran and returned a result.
ACTION_EXECUTED = "executed"
#: The call ran and did not return a result: the tool raised, or reported a
#: failure it did not declare deterministic.
ACTION_FAILED = "failed"
#: The gate denied the call — on the policy, or on the argument contract it
#: enforces beside the policy.  The tool was never reached and read no evidence.
ACTION_REFUSED_BY_OVERSIGHT = "refused_by_oversight"
#: The tool was reached and refused the call deterministically — invalid
#: operation arguments, an argument outside policy, an absent backing binary.
#: Nothing was opened and no evidence was read.
ACTION_REFUSED_BY_TOOL = "refused_by_tool"

#: The outcomes in which the call did not happen.  Two ways of refusing, one
#: fact for the operator: this call read no evidence and nobody let it.
REFUSAL_OUTCOMES = frozenset({ACTION_REFUSED_BY_OVERSIGHT, ACTION_REFUSED_BY_TOOL})

ACTION_OUTCOMES = frozenset({ACTION_EXECUTED, ACTION_FAILED, *REFUSAL_OUTCOMES})

#: Identity of the record convention one run's ``oversight.jsonl`` follows,
#: stamped on the ``case_open`` entry in the ``schema_id`` shape this codebase
#: already uses for a versioned record (``forensic.projection-sidecar.v1``,
#: ``forensic.model-tool-choice-policy.v1``).
#:
#: The field exists because ``allowed`` changed meaning. Under the first
#: convention it reported what the capability POLICY decided, so a call the
#: policy permitted and the argument contract then refused was recorded
#: ``allowed: true, blocked: false`` although it never ran; measured across the
#: written corpus that was 98 of every 100 oversight refusals. Under this one
#: ``allowed`` reports whether the call was permitted to proceed at all, so both
#: refusal points write ``allowed: false, blocked: true`` and ``blocked_calls``
#: counts every call the gate stopped rather than only the capability denials.
#:
#: NOTHING IS MIGRATED. An entry without this field follows the first
#: convention, and a reader comparing runs across the change must say which it
#: is reading before it compares any refusal count. The two remain separable
#: within either convention: a capability denial carries no ``outcome_detail``,
#: an argument refusal names its code there and states the offending field as
#: its leading reason.
OVERSIGHT_RECORD_SCHEMA_ID = "forensic.oversight-record.v2"

#: Reason the enforcement pipeline appends when the tool itself raised.
_TOOL_EXCEPTION_REASON = "tool-raised-exception"
#: Markers a pre-field trace can still be read for, in the bounded preview that
#: is all such a trace kept of the output.
_DETERMINISTIC_MARKER = '"deterministic_error": true'
_ERROR_STATUS_MARKER = '"status": "error"'
#: A tool that predates the result envelope declares its failure in an ``error``
#: member and carries no ``status`` at all, so a fallback reading only the status
#: marker reported every one of those runs as executed.  The value is captured
#: rather than excluded by a lookahead: ``\s*`` can give back what it consumed,
#: so a lookahead was satisfied by the space in front of the value and read every
#: ``"error": null`` as a failure.  The alternatives are ordered so the three
#: ways of saying NO error win over the catch-all, and the leading quote keeps
#: ``"deterministic_error"`` — a refusal, decided one branch earlier — out.
_ERROR_MEMBER_VALUE = re.compile(r'"error"\s*:\s*(null|false|""|\S)')
#: What that member holds when it reports nothing.
_QUIET_ERROR_MEMBER = frozenset({"null", "false", '""'})


def _declares_an_error_member(preview: str) -> bool:
    return any(
        match.group(1) not in _QUIET_ERROR_MEMBER
        for match in _ERROR_MEMBER_VALUE.finditer(preview)
    )


def classify_action_outcome(entry: Mapping[str, Any]) -> str:
    """Name what became of the call one action entry recorded.

    The outcome is decided where the tool's own return value is in hand — in
    :func:`~forensic_agent.oversight.enforcement.enforce` — and recorded on the
    entry, so it is read back here rather than inferred again.  A report that
    re-derived it could disagree with the moment it describes.

    The derivation below serves only traces written before the field existed.
    It can consult just what those traces kept: the decision, the reason list,
    and an output preview bounded to 500 characters, which is why it treats an
    unrecognisable entry as executed rather than inventing a refusal.
    """

    recorded = entry.get("outcome")
    if isinstance(recorded, str) and recorded in ACTION_OUTCOMES:
        return recorded
    if entry.get("blocked") is True or entry.get("allowed") is False:
        return ACTION_REFUSED_BY_OVERSIGHT
    reasons = entry.get("reasons")
    if isinstance(reasons, list) and _TOOL_EXCEPTION_REASON in reasons:
        return ACTION_FAILED
    preview = entry.get("output_preview")
    if isinstance(preview, str):
        if _DETERMINISTIC_MARKER in preview:
            return ACTION_REFUSED_BY_TOOL
        if _ERROR_STATUS_MARKER in preview or _declares_an_error_member(preview):
            return ACTION_FAILED
    return ACTION_EXECUTED


class OversightLog:
    """Append-only, per-case JSONL recorder of the agent's behaviour.

    The recorder is thread-safe because one instance can be shared by multiple
    agent sub-processes. Output bodies are hashed and previewed, never stored
    whole unless the caller explicitly enables the object store.
    """

    GENESIS = "0" * 64

    def __init__(
        self,
        path: str | None = None,
        *,
        store_full_outputs: bool = False,
        object_store_dir: str | None = None,
    ) -> None:
        path = default_log_path("oversight.jsonl") if path is None else path
        self.path = path
        self.store_full_outputs = store_full_outputs
        self.object_store_dir = object_store_dir or (path + ".objects")
        self._seq = 0
        self._case_id: str | None = None
        self._lock = threading.Lock()
        self._prev_hash = self.GENESIS

    def _emit(self, entry: dict) -> dict:
        """Append one entry to the tamper-evident hash chain."""
        with self._lock:
            return self._emit_locked(entry)

    def _emit_locked(self, entry: dict) -> dict:
        """Append one entry, with the chain lock already held by the caller.

        Split out of :meth:`_emit` so an entry whose CONTENT depends on the chain
        position it will occupy can be built and appended without releasing the
        lock in between; see :meth:`record_result_binding`.
        """
        entry = {
            "ts": time.time(),
            "seq": self._seq,
            "case_id": self._case_id,
            **entry,
        }
        entry["prev_hash"] = self._prev_hash
        hash_json = _facade_value("canonical_json", canonical_json)
        hash_text = _facade_value("sha256_hex", sha256_hex)
        entry["entry_hash"] = hash_text(self._prev_hash + hash_json(entry))
        self._prev_hash = entry["entry_hash"]
        self._seq += 1
        with open(self.path, "a", encoding="utf-8") as stream:
            stream.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
        return entry

    def record_result_binding(
        self, build_entry: Callable[[str | None], Mapping[str, Any]]
    ) -> dict:
        """Append what binds one standardized result to this chain.

        The body is BUILT from the entry hash it will actually follow, under the
        same lock that appends it: reading the head first and appending second
        would let a concurrent call slip in between and leave the record naming a
        position it does not occupy.  ``None`` is passed for the genesis head, so
        the first binding of a run states that it follows nothing rather than a
        placeholder digest.

        The shape of the body belongs to the caller, not here.  This recorder
        stays free of the result contract for the same reason it always hashed
        raw output rather than interpreting it: a chain that understood one
        envelope would have to be revised whenever that envelope was.
        """

        with self._lock:
            previous = None if self._prev_hash == self.GENESIS else self._prev_hash
            return self._emit_locked(
                {"event": "result_binding", **dict(build_entry(previous))}
            )

    def open_case(
        self,
        *,
        question: str,
        system_prompt: str = "",
        policy: Policy | None = None,
        model: str | None = None,
        engine: str | None = None,
        visible_tools: list[str] | None = None,
        case_id: str | None = None,
        scope_triage: bool | None = None,
    ) -> dict:
        self._case_id = case_id or uuid.uuid4().hex[:12]
        system_prompt_text = system_prompt or ""
        digest = _facade_value("sha256_bytes", sha256_bytes)
        return self._emit(
            {
                "event": "case_open",
                # Stamped first, and on the entry that opens the chain, so a
                # reader knows which convention the entries after it follow
                # before it reads any of them.
                "schema_id": OVERSIGHT_RECORD_SCHEMA_ID,
                "question": question,
                "system_prompt_sha256": (
                    digest(system_prompt_text.encode("utf-8"))
                    if system_prompt_text
                    else None
                ),
                "system_prompt_preview": system_prompt_text[:500],
                "policy": policy.summary() if policy else None,
                # Recorded beside the policy summary rather than inside it. The
                # summary is a portable design identity, while this is a runtime
                # fact about one run: the host locations this run was permitted
                # to write.
                "write_scope": list(policy.write_roots) if policy else None,
                "model": model,
                "engine": engine,
                "visible_tools": visible_tools,
                # Another runtime fact about this one run, recorded for the same
                # reason as the write scope above: a measurement made with the
                # console's pre-run scope triage switched off must not read like
                # one made with it on. The triage happens before this chain
                # exists, so the caller states what it did; ``None`` means the
                # caller runs no such rail at all, which is a third thing.
                "scope_triage": scope_triage,
            }
        )

    def record_action(
        self,
        *,
        tool: str,
        args: dict,
        decision: Decision,
        output: Any = None,
        duration_s: float | None = None,
        capture: Any = None,
        outcome: str | None = None,
        outcome_detail: str | None = None,
    ) -> dict:
        # Supplied by the caller that holds the tool's return value.  Without it
        # only the decision is known, and the entry says exactly that much: the
        # gate denied the call, or the gate permitted it — never that it ran.
        if outcome is None:
            outcome = ACTION_EXECUTED if decision.allowed else ACTION_REFUSED_BY_OVERSIGHT
        elif outcome not in ACTION_OUTCOMES:
            raise ValueError(f"unknown action outcome: {outcome!r}")
        output_text = (
            ""
            if output is None
            else (
                output
                if isinstance(output, str)
                else json.dumps(output, ensure_ascii=False, default=str)
            )
        )
        digest = _facade_value("sha256_bytes", sha256_bytes)
        output_sha256 = (
            digest(output_text.encode("utf-8")) if output_text else None
        )
        canonical_digest = _facade_value(
            "canonical_raw_output_sha256", canonical_raw_output_sha256
        )
        # ``output`` here is the bounded model-visible projection: the output
        # guard runs innermost and has already shaped it.  The complete
        # pre-truncation output was captured at that guard, so bind the audit
        # entry to THAT digest; hashing the projection and calling it the raw
        # output would attest a preview as if it were the tool's answer.
        # ``capture`` is passed in by the caller that actually ran this
        # invocation; it is never read from ambient state, so an entry recorded
        # for a call that never reached the capture boundary (a policy block, an
        # integrity failure, a raising tool) simply has none.
        #
        # NOTE: the model-facing projection now runs AFTER oversight, so the
        # value recorded here is the pre-projection output, not the model's copy.
        # The field is named for what it actually holds.
        recorded_output_sha256 = canonical_digest(output)
        # Bind the entry to the bytes actually captured before shaping.  Whether
        # those bytes are the WHOLE output is a separate, explicit fact recorded
        # in ``output_capture.capture_complete`` — a capture cut short by a safety
        # limit is never silently presented as the complete raw output.
        # Only a COMPLETE capture may be bound as the canonical output digest.
        # A prefix digest is retained too, but under a name that says it covers a
        # prefix, so no reader can mistake a fragment for the whole output.
        captured_prefix_sha256 = None
        if capture is not None and not capture.capture_complete:
            captured_prefix_sha256 = capture.captured_sha256
            canonical_output_sha256 = None
        elif capture is not None:
            canonical_output_sha256 = capture.captured_sha256
        else:
            canonical_output_sha256 = recorded_output_sha256
        capture_record = capture.metadata() if capture is not None else None
        output_ref = None
        if capture is not None and capture.object_sha256 is not None:
            # The complete pre-shaping output was already streamed into the store
            # atomically at capture time; reference THAT object.  Storing the
            # bounded projection here instead would leave the run with a preview
            # masquerading as the retained output.
            object_path = os.path.join(
                self.object_store_dir,
                capture.object_sha256 + (".txt" if capture.is_text else ".json"),
            )
            output_ref = {
                "algorithm": "sha256",
                "sha256": capture.object_sha256,
                "bytes": capture.object_bytes,
                "content": "complete_tool_output" if capture.capture_complete else (
                    "captured_prefix_only"
                ),
                "capture_complete": capture.capture_complete,
                "path": os.path.relpath(
                    object_path,
                    start=os.path.dirname(os.path.abspath(self.path)) or ".",
                ),
            }
        elif self.store_full_outputs and output_sha256:
            os.makedirs(self.object_store_dir, exist_ok=True)
            suffix = ".txt" if isinstance(output, str) else ".json"
            object_path = os.path.join(
                self.object_store_dir, output_sha256 + suffix
            )
            try:
                with open(
                    object_path, "x", encoding="utf-8", newline="\n"
                ) as stream:
                    stream.write(output_text)
                    stream.flush()
                    os.fsync(stream.fileno())
            except FileExistsError:
                pass
            output_ref = {
                "algorithm": "sha256",
                "sha256": output_sha256,
                "bytes": len(output_text.encode("utf-8")),
                "path": os.path.relpath(
                    object_path,
                    start=os.path.dirname(os.path.abspath(self.path)) or ".",
                ),
            }
        return self._emit(
            {
                "event": "action",
                "tool": tool,
                "args": args,
                "allowed": decision.allowed,
                "blocked": not decision.allowed,
                # What the gate decided is ``allowed``; what became of the call
                # is ``outcome``.  Both are recorded because neither implies the
                # other: a permitted call can still be refused by the tool it
                # reached, and counting only the first hid exactly that case.
                "outcome": outcome,
                "outcome_detail": outcome_detail,
                "risk": decision.risk,
                "risk_name": decision.risk_name,
                "reasons": decision.reasons,
                "capabilities": decision.capabilities,
                "output_sha256": output_sha256,
                "canonical_output_sha256": canonical_output_sha256,
                # Digest of the value this entry recorded (the pre-projection
                # result), kept separate from the capture digest so a reader can
                # never mistake one artifact for another.
                "recorded_output_sha256": recorded_output_sha256,
                # Present only when retention stopped early; explicitly scoped to
                # the retained prefix so it can never read as a whole-output digest.
                "captured_prefix_sha256": captured_prefix_sha256,
                "output_capture": capture_record,
                "output_ref": output_ref,
                "output_preview": output_text[:500],
                "duration_s": duration_s,
            }
        )

    def record_security(self, kind: str, detail: Any) -> dict:
        """Record a security event such as tool poisoning."""
        return self._emit({"event": "security", "kind": kind, "detail": detail})

    def record_model_request(
        self,
        *,
        role: str,
        status: str,
        finish_reason: str | None = None,
        reasoning_returned: bool = False,
        token_usage: Mapping[str, Any] | None = None,
        error_type: str | None = None,
    ) -> dict:
        """Record that one request to the model happened, and what it consumed.

        A trace made only of tool calls cannot answer the first two questions a
        an examiner asks about the agent itself: did the model reason at all, and
        how much did that reasoning cost.  Both are facts about this run's
        conduct, so they belong on the same chain as every other one.

        Only WHETHER reasoning came back is recorded, never the reasoning text.
        This log is read as the record of the case, and model-authored thought
        placed in it would be read as an observation about the evidence, which it
        is not; the token counts state how much of it there was, which is what a
        review of effort and cost actually needs.

        ``token_usage`` is reduced to its numbers here, so nothing a provider
        puts in that block can carry text into the record disguised as a
        measurement.  The field names are the ones the run's own failure
        diagnostic already uses for these facts, so two records of one request
        cannot disagree by wording alone.
        """

        numeric_usage = {
            name: amount
            for name, amount in (token_usage or {}).items()
            if isinstance(amount, int | float) and not isinstance(amount, bool)
        }
        return self._emit(
            {
                "event": "model_request",
                "role": role,
                "status": status,
                "finish_reason": finish_reason,
                "error_type": error_type,
                "reasoning_returned": bool(reasoning_returned),
                "token_usage": numeric_usage,
            }
        )

    def record_prompt(self, prompt: str, *, role: str = "user") -> dict:
        """Record a tamper-evident digest of an input prompt."""
        digest = _facade_value("sha256_bytes", sha256_bytes)
        return self._emit(
            {
                "event": "prompt",
                "role": role,
                "prompt_sha256": digest((prompt or "").encode("utf-8")),
                "prompt_preview": (prompt or "")[:500],
            }
        )

    def close_case(self, *, final: str = "", status: str = "ok") -> dict:
        digest = _facade_value("sha256_bytes", sha256_bytes)
        return self._emit(
            {
                "event": "case_close",
                "status": status,
                "final_sha256": (
                    digest((final or "").encode("utf-8")) if final else None
                ),
                "final_preview": (final or "")[:1000],
            }
        )

    @staticmethod
    def load(path: str) -> list:
        if not path or not os.path.exists(path):
            return []
        rows = []
        with open(path, encoding="utf-8", errors="replace") as stream:
            for line in stream:
                line = line.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except Exception:
                        pass
        return rows


def reconstruct(entries: list) -> dict:
    """Summarise the most recent case in an oversight trace."""
    opens = [entry for entry in entries if entry.get("event") == "case_open"]
    case = opens[-1] if opens else {}
    case_id = case.get("case_id")
    scoped = (
        [entry for entry in entries if entry.get("case_id") == case_id]
        if case_id
        else entries
    )

    actions = [entry for entry in scoped if entry.get("event") == "action"]
    outcomes = [classify_action_outcome(entry) for entry in actions]
    blocked = [entry for entry in actions if entry.get("blocked")]
    refused = [
        (entry, outcome)
        for entry, outcome in zip(actions, outcomes, strict=True)
        if outcome in REFUSAL_OUTCOMES
    ]
    counts = {name: outcomes.count(name) for name in sorted(ACTION_OUTCOMES)}
    security = [entry for entry in scoped if entry.get("event") == "security"]
    close: dict[str, Any] = next(
        (entry for entry in scoped if entry.get("event") == "case_close"), {}
    )
    max_risk = max((entry.get("risk", 0) for entry in actions), default=0)
    timeline = [
        {
            "seq": entry.get("seq"),
            "tool": entry.get("tool"),
            "decision": "BLOCKED" if entry.get("blocked") else "allowed",
            "outcome": outcome,
            "detail": entry.get("outcome_detail") or "",
            "risk": entry.get("risk_name"),
            "reasons": entry.get("reasons", []),
        }
        for entry, outcome in zip(actions, outcomes, strict=True)
    ]

    normalized = [
        {
            "event": "case_open",
            "question": case.get("question"),
            "system_prompt_sha256": case.get("system_prompt_sha256"),
            "model": case.get("model"),
            "engine": case.get("engine"),
            "visible_tools": case.get("visible_tools"),
        }
    ]
    for entry in scoped:
        if entry.get("event") == "action":
            normalized.append(
                {
                    "event": "action",
                    "seq": entry.get("seq"),
                    "tool": entry.get("tool"),
                    "args": entry.get("args"),
                    "allowed": entry.get("allowed"),
                    "output_sha256": entry.get("output_sha256"),
                }
            )
        elif entry.get("event") == "case_close":
            normalized.append(
                {
                    "event": "case_close",
                    "status": entry.get("status"),
                    "final_sha256": entry.get("final_sha256"),
                }
            )

    hash_json = _facade_value("canonical_json", canonical_json)
    hash_text = _facade_value("sha256_hex", sha256_hex)
    transcript_sha256 = hash_text(hash_json(normalized))
    risk_names = _facade_value("RISK_NAMES", RISK_NAMES)
    return {
        "case_id": case_id,
        "transcript_sha256": transcript_sha256,
        "question": case.get("question"),
        "policy": case.get("policy"),
        "model": case.get("model"),
        "engine": case.get("engine"),
        "visible_tools": case.get("visible_tools"),
        "status": close.get("status"),
        "tool_calls": len(actions),
        # ``blocked_calls`` counts the calls THE GATE STOPPED — both of its
        # refusal points, the capability policy and the argument contract.  It
        # once counted only the first, which is why it could read zero while
        # calls were being refused; the three counts beside it were added for
        # that, and the field itself now agrees with them.
        #
        # A run written under the first convention still counts the old way,
        # because nothing was migrated.  ``schema_id`` on the ``case_open``
        # entry says which convention produced the numbers, and no comparison
        # across the change is sound without reading it.
        "blocked_calls": len(blocked),
        "executed_calls": counts[ACTION_EXECUTED],
        "failed_calls": counts[ACTION_FAILED],
        "refused_calls": len(refused),
        "outcome_counts": counts,
        "security_events": [
            {"kind": entry.get("kind"), "detail": entry.get("detail")}
            for entry in security
        ],
        "max_risk": risk_names.get(max_risk, max_risk),
        "blocked_summary": [
            {
                "tool": entry.get("tool"),
                "args": entry.get("args"),
                "reasons": entry.get("reasons"),
            }
            for entry in blocked
        ],
        # Every refusal, whichever layer made it, with the ground it was made
        # on: the gate's reasons for its own, the tool's refusal code for the
        # ones the gate permitted and the tool then declined.
        "refusal_summary": [
            {
                "tool": entry.get("tool"),
                "args": entry.get("args"),
                "outcome": outcome,
                "reasons": entry.get("reasons"),
                "detail": entry.get("outcome_detail") or "",
            }
            for entry, outcome in refused
        ],
        "timeline": timeline,
    }


FORENSIC_CHECKLIST = (
    "[FORENSIC CHECKLIST] Follow these rules: "
    "(1) support every claim with concrete tool output, not an assumption; "
    "(2) make no claim without citing a recorded evidence access; "
    "(3) use only approved tools against read-only evidence; "
    "(4) when evidence is insufficient, state 'insufficient evidence' instead of guessing; "
    "(5) corroborate a correlation with at least two independent sources before concluding."
)


def verify_chain(entries: list) -> dict:
    """Validate the tamper-evident hash chain of an oversight log trace."""
    log_type = _facade_value("OversightLog", OversightLog)
    previous = log_type.GENESIS
    hash_json = _facade_value("canonical_json", canonical_json)
    hash_text = _facade_value("sha256_hex", sha256_hex)
    for entry in entries:
        record = {
            key: value for key, value in entry.items() if key != "entry_hash"
        }
        if entry.get("entry_hash") != hash_text(previous + hash_json(record)):
            return {
                "ok": False,
                "broken_at": entry.get("seq"),
                "n": len(entries),
            }
        previous = entry.get("entry_hash") or previous
    return {"ok": True, "broken_at": None, "n": len(entries)}


__all__ = [
    "FORENSIC_CHECKLIST",
    "OVERSIGHT_RECORD_SCHEMA_ID",
    "OversightLog",
    "reconstruct",
    "verify_chain",
]
