"""Constrained execution of forensic functions during an investigation."""

from __future__ import annotations

from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from contextvars import copy_context
from functools import partial

from langchain_core.tools import StructuredTool

from forensic_agent.agent.execution_budget import (
    _CellExecutionBudget,
    _DispatchDenied,
)
from forensic_agent.agent.recovery.pending_tool_recovery import (
    TOOL_DISPATCH_REFUSAL_SCHEMA_ID,
)
from forensic_agent.agent.tool_operations import argument_guidance
from forensic_agent.agent.tool_taxonomy import STORED_RESULT_NAVIGATION_TOOLS
from forensic_agent.core.repro import canonical_json, sha256_hex
from forensic_agent.core.toolkit import cell_deadline

# Both names are published in the attempt record, whose identifier form admits no
# underscore, so they are written the way that record can carry them.
#: A call the surface decided by validating its arguments, before opening anything.
ARGUMENT_REFUSAL = "deterministic-argument-refusal"
#: A call this cell had already refused under exactly the same arguments.
REPEATED_REFUSAL = "repeated-deterministic-refusal"
#: A call this cell had already executed successfully under exactly the same
#: arguments, answered from the record instead of being executed again.
REPEATED_SUCCESS = "repeated-identical-call"

#: Control record around a served repeat of a successful call.  Defined here
#: rather than beside :data:`TOOL_DISPATCH_REFUSAL_SCHEMA_ID` because a serve is
#: not a refusal: the call HAS an answer, and the record's job is to carry it.
TOOL_DISPATCH_CACHED_RESULT_SCHEMA_ID = "forensic.tool-dispatch-cached-result.v1"

#: What the oversight layer names an identical call it has seen fail
#: deterministically.  Read here so the two layers keep one vocabulary for it.
_OVERSIGHT_REPEAT_CODE = "repeated_deterministic_tool_error"


def _call_fingerprint(tool_name: str, arguments: Mapping[str, object]) -> str:
    """Identify one call by function and arguments, as the recovery stages do."""

    return sha256_hex(canonical_json({"tool": tool_name, "arguments": dict(arguments)}))


def _declared_refusal(result: object) -> str | None:
    """Name the refusal a returned value declares, or ``None`` for a real call.

    Nothing is judged here; the markers the surfaces already publish are only
    recognised.  A pre-envelope refusal carries them at the top level, and a
    standardized one carries them as attributes of a failed envelope, because
    that is where the legacy adapter puts a producer's own keys.  A projection
    that could not be published is deliberately not a refusal: it happens after
    the evidence has been read, so the reading has to be paid for.
    """

    if not isinstance(result, Mapping) or result.get("projection_failed") is True:
        return None
    if isinstance(result.get("schema_version"), str):
        if result.get("status") != "error":
            return None
        data = result.get("data")
        markers = data.get("attributes") if isinstance(data, Mapping) else None
    else:
        markers = result if result.get("error") not in (None, "", False) else None
    if not isinstance(markers, Mapping):
        return None
    if markers.get("code") == _OVERSIGHT_REPEAT_CODE:
        return REPEATED_REFUSAL
    if markers.get("deterministic_error") is True:
        return ARGUMENT_REFUSAL
    return None


def _declared_success(result: object) -> bool:
    """Whether a returned value declares a completed read of the evidence.

    Only such a result may answer a byte-identical repeat: the evidence is
    immutable for the life of a run, so an identical successful call has
    exactly one possible outcome.  A failure is deliberately excluded — an
    error can be transient (a busy parser, an interrupted extraction), so a
    repeated failed call must actually run and take its own chance to succeed;
    the deterministic failures are already covered by the refusal recall and
    the oversight layer's repeat block.  A projection failure is excluded for
    the same reason its stand-in is charged as a reading: what would be served
    is the stand-in, not the evidence that was read.
    """

    if not isinstance(result, Mapping) or result.get("projection_failed") is True:
        return False
    if isinstance(result.get("schema_version"), str):
        return result.get("status") in ("ok", "partial")
    return result.get("error") in (None, "", False)


def _result_invocation_id(result: object) -> str | None:
    """The invocation the recorded result answers for, where its envelope names one."""

    if not isinstance(result, Mapping):
        return None
    provenance = result.get("provenance")
    if isinstance(provenance, Mapping):
        identifier = provenance.get("invocation_id")
        if isinstance(identifier, str) and identifier:
            return identifier
    return None


def _cached_result_record(tool_name: str, recorded: object) -> dict[str, object]:
    """Answer a call this cell already executed successfully, without re-running it.

    The evidence source is immutable for the life of a run and the call is
    identified by function and canonical arguments, so a byte-identical repeat
    of a successful call has exactly one possible outcome and re-executing it
    only spends the run — the reasoning :func:`_repeated_refusal_record` states
    for a repeated refusal, applied to the call that succeeded.  Re-execution is
    not merely wasteful: concurrent re-extraction of one immutable source can let
    a half-written copy fail a read that had already succeeded, so serving the
    record is also what keeps identical questions from answering differently
    within one run.

    Nothing executes, nothing new is observed and no invocation is created, so
    — exactly as for the repeated refusal and the stored-result navigation
    function — there is nothing here for the oversight layer to supervise and
    nothing new to attest.  The earlier result is embedded exactly as it was
    returned, never edited: its receipt binds its own bytes, and a wrapper
    that rewrote them would break the digest that lets the embedded result
    still verify.  The record around it states in plain words that no
    operation ran, and names the earlier invocation so a reader can pair the
    serve with the execution it repeats.
    """

    return {
        "schema_id": TOOL_DISPATCH_CACHED_RESULT_SCHEMA_ID,
        "status": "served_from_record",
        "executed": False,
        "evidence": False,
        "reason": REPEATED_SUCCESS,
        "tool": tool_name,
        "note": (
            "this is the cached result of an identical earlier call in this run; "
            "the operation was not re-executed"
        ),
        "earlier_invocation_id": _result_invocation_id(recorded),
        "result": recorded,
    }


def _repeated_refusal_record(
    tool_name: str, arguments: Mapping[str, object]
) -> dict[str, object]:
    """Answer a call this cell already refused, without executing it again.

    Validation is deterministic, so the identical call has exactly one possible
    outcome and re-running it only spends the run.  Nothing executes, nothing is
    observed and no invocation is created, so — as for the stored-result
    navigation function — there is nothing here for the oversight layer to
    supervise and nothing to attest.  The control record therefore carries the
    schema that already exists for a call which was never dispatched, and no
    receipt, provenance or data of its own.

    The repeat carries the SAME lesson the first refusal did: the guidance is
    recomputed from the arguments so a byte-identical retry is not merely told it
    was already tried but is told, again, what the offending field actually takes
    — otherwise the second refusal teaches less than the first and the model
    keeps sending the form it was never corrected off.  Recomputing it reads the
    schema and nothing else: it executes no function, opens no evidence and
    creates no invocation, so it needs no new state and leaves the account of
    this cell exactly where the short-circuit found it.
    """

    return {
        "schema_id": TOOL_DISPATCH_REFUSAL_SCHEMA_ID,
        "status": "refused",
        "executed": False,
        "evidence": False,
        "reason": REPEATED_REFUSAL,
        "tool": tool_name,
        "detail": (
            "This exact call was already refused in this cell and was not executed "
            "again. No forensic operation was performed and this record is not "
            "evidence. Change the arguments or call a different function."
        ),
        # Read from the schema at refusal time, exactly as the first refusal read
        # it; an unresolved function or an error naming no field yields no lines
        # rather than raising, so the aid can never displace the refusal.
        "guidance": argument_guidance(tool_name, arguments),
    }


def _bound_tool_dispatches(tools: list, budget: _CellExecutionBudget) -> list:
    """Apply pre-dispatch ceilings and an isolation-safe synchronous timeout.

    Python offers no safe way to terminate an arbitrary running thread.  If the
    remaining-time wait expires, this wrapper records the deadline and then waits
    for the worker to finish before raising.  The cell can therefore overrun while
    a non-cooperative in-process parser quiesces, but that parser can never continue
    into the next cell.  Subprocess-backed forensic tools retain their own killable
    timeouts beneath this boundary.
    """

    wrapped_tools = []
    for tool in tools:
        original = tool.func
        name = tool.name

        def make(fn, tool_name):
            navigates_stored_results = tool_name in STORED_RESULT_NAVIGATION_TOOLS

            def complete(permit, *, status, error_type, quiescence_waited):
                if navigates_stored_results:
                    budget.complete_navigation(permit, status=status, error_type=error_type)
                    return
                budget.complete_tool(
                    permit,
                    status=status,
                    error_type=error_type,
                    quiescence_waited=quiescence_waited,
                )

            def wrapped(**kwargs):
                fingerprint = _call_fingerprint(tool_name, kwargs)
                # Only forensic calls are recalled and served below: a refused
                # page read is exactly the endless paging that the navigation
                # ceiling exists to bound, so it keeps paying for itself — and a
                # page read serves a stored result already, so caching it would
                # only put a second copy of the store in front of the store.
                if not navigates_stored_results:
                    if budget.recall_refusal(tool_name, fingerprint) is not None:
                        return _repeated_refusal_record(tool_name, kwargs)
                    recorded = budget.recall_success(tool_name, fingerprint)
                    if recorded is not None:
                        return _cached_result_record(tool_name, recorded)
                # Reading a result this run already stored is metered apart from
                # reading the evidence.  Both still answer to the cell deadline
                # below; only the ceilings differ.
                permit = (
                    budget.reserve_navigation(tool_name)
                    if navigates_stored_results
                    else budget.reserve_tool(tool_name)
                )
                # Bind the cell's wall deadline into the context this tool runs
                # under, rather than trusting it to have survived every thread
                # hop langgraph performs before dispatching here. When the
                # ambient _CELL_DEADLINE did propagate, this re-binds the
                # identical value coordinator._execute_runtime already set (a
                # no-op); when it did not, this is the floor that keeps an
                # external tool (psort, tshark) from being spawned with
                # its raw multi-minute ceiling and outliving the cell. It only
                # ever lowers an external timeout to the deadline already in
                # force; no sealed ceiling is read or raised.
                with cell_deadline(budget.deadline_monotonic):
                    context = copy_context()
                executor = ThreadPoolExecutor(
                    max_workers=1,
                    thread_name_prefix=f"dfir-tool-{permit.ordinal}",
                )
                call = partial(fn, **kwargs)
                future = executor.submit(context.run, call)
                timed_out = False
                try:
                    result = future.result(timeout=permit.remaining_s)
                except FutureTimeoutError as exc:
                    if future.done():
                        complete(
                            permit,
                            status="error",
                            error_type=type(exc).__name__,
                            quiescence_waited=False,
                        )
                        raise
                    timed_out = True
                    # Do not return while the parser still owns this cell's disk,
                    # trace, or scratch authorities.  Quiescence is a hard
                    # cross-cell isolation requirement even when it extends cleanup.
                    error_type: str | None = None
                    try:
                        future.result()
                    except BaseException as exc:
                        error_type = type(exc).__name__
                    complete(
                        permit,
                        status="deadline_exceeded",
                        error_type=error_type,
                        quiescence_waited=True,
                    )
                    raise _DispatchDenied("max_wall_time_s") from None
                except BaseException as exc:
                    complete(
                        permit,
                        status="error",
                        error_type=type(exc).__name__,
                        quiescence_waited=False,
                    )
                    raise
                else:
                    try:
                        budget.remaining()
                    except _DispatchDenied:
                        timed_out = True
                        complete(
                            permit,
                            status="deadline_exceeded",
                            error_type=None,
                            quiescence_waited=False,
                        )
                        raise
                    refusal = None if navigates_stored_results else _declared_refusal(result)
                    if refusal is not None:
                        budget.refuse_tool(permit, reason=refusal, fingerprint=fingerprint)
                        return result
                    complete(
                        permit,
                        status="success",
                        error_type=None,
                        quiescence_waited=False,
                    )
                    if not navigates_stored_results and _declared_success(result):
                        budget.record_success(tool_name, fingerprint, result)
                    return result
                finally:
                    # ``wait=True`` is deliberate: even a timeout must not leak a
                    # worker into evidence/scratch cleanup or the next cell.
                    executor.shutdown(wait=True, cancel_futures=timed_out)

            return wrapped

        wrapped_tools.append(
            StructuredTool.from_function(
                make(original, name),
                name=name,
                description=tool.description,
                args_schema=tool.args_schema,
            )
        )
    return wrapped_tools


def _ai_content_to_text(content) -> str:
    """Normalize one AI message's content to a single stripped text string.

    A message's ``.content`` may be a plain string OR a list of content blocks
    (some providers).  The model-request ledger digests the model's response with
    this same normalization so the accepted draft can be bound by digest to the
    actual final model response.
    """

    if isinstance(content, list):
        content = " ".join(b.get("text", "") if isinstance(b, dict) else str(b) for b in content)
    return (content or "").strip()


def _final_ai_text(messages) -> str:
    """Last AI message with non-empty textual content (skip tool-call-only / empty)."""

    for m in reversed(messages):
        if getattr(m, "type", "") != "ai":
            continue
        c = _ai_content_to_text(m.content)
        if c:
            return c
    return ""
