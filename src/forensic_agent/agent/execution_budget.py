"""Deterministic execution limits for a single investigation."""

from __future__ import annotations

import math
import threading
import time
import weakref
from dataclasses import dataclass, field
from typing import Final, Literal


@dataclass(frozen=True, slots=True)
class _FrozenRequestTimeout:
    """Validated timeout ceiling used as a fallback request timeout.

    When a :class:`_CellExecutionBudget` is supplied, the value sent to OpenRouter
    is never this full ceiling: it is the remaining time on one absolute monotonic
    per-cell deadline.
    """

    timeout_s: float

    @classmethod
    def from_budget(cls, max_wall_time_s: float) -> _FrozenRequestTimeout:
        if (
            isinstance(max_wall_time_s, bool)
            or not isinstance(max_wall_time_s, int | float)
            or not math.isfinite(float(max_wall_time_s))
            or float(max_wall_time_s) <= 0
        ):
            raise ValueError("request_timeout_s must be a positive finite number")
        return cls(float(max_wall_time_s))


class _DispatchDenied(RuntimeError):
    """A frozen resource ceiling rejected work before external dispatch."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"cell dispatch denied by {reason}")


#: Every ceiling this budget can exhaust, as a closed vocabulary. These are the
#: exact strings :class:`_DispatchDenied` is raised with and that
#: :meth:`_CellExecutionBudget.metrics` returns under ``exhaustion_reasons``, so
#: any consumer that classifies an exhaustion reason or an examination bound can
#: read the set from here rather than restating it and drifting from what the
#: budget actually raises.
BUDGET_EXHAUSTION_REASONS: frozenset[str] = frozenset(
    {
        "max_steps",
        "max_model_requests",
        "max_tool_calls",
        "max_navigation_calls",
        "max_wall_time_s",
    }
)

#: Why a run stopped when nobody's ceiling was reached: the operator asked it to.
#:
#: Deliberately OUTSIDE :data:`BUDGET_EXHAUSTION_REASONS`, and that is the whole
#: point of it existing. A cancellation is not a resource this run ran out of.
#: Filing it as ``max_wall_time_s`` — the obvious shortcut, since collapsing the
#: deadline is how the stop is delivered — would put every Ctrl+C into the same
#: bucket as a genuine time budget expiry, and anyone later counting how often
#: models exhaust their budget would be counting the operator's keystrokes as
#: model failures. The consumers in cli/controlled.py filter both the
#: ``exhaustion_reasons`` list and the ``examination_bound`` against the frozen
#: set above, so keeping this out of it is what keeps a cancelled run out of the
#: exhaustion statistics.
CANCELLED_REASON: Final[str] = "cancelled"

#: Every cell currently able to dispatch work, so a cancel can reach one from
#: the thread that did not start it.
#:
#: A cell is created deep inside run preparation, on the run's own thread, and
#: the console that has to cancel it runs on another. Weak references, so a
#: finished run's cell leaves this set by being collected rather than by
#: remembering to deregister on every path out of a run, including the ones that
#: raise.
_ACTIVE_CELLS: weakref.WeakSet[_CellExecutionBudget] = weakref.WeakSet()
_ACTIVE_CELLS_LOCK = threading.Lock()


def cancel_active_cells() -> int:
    """Ask every cell now running to stop at its next dispatch, and say how many.

    Every cell rather than one named cell: the console investigates one question
    at a time (its worker is exclusive), so "the run in flight" and "every cell
    that exists" are the same set, and asking for a handle to thread down
    through preparation would buy nothing this does not already give.

    The cells are only ASKED. Nothing is interrupted here, because nothing can
    be: the stop is delivered by the check every dispatch already makes, which
    is why a cancelled run unwinds down the path the codebase already has for a
    budget that ran out rather than down a new one written for this.
    """

    with _ACTIVE_CELLS_LOCK:
        cells = list(_ACTIVE_CELLS)
    for cell in cells:
        cell.cancel()
    return len(cells)


@dataclass(frozen=True, slots=True)
class _DispatchPermit:
    kind: Literal["model", "tool", "navigation"]
    ordinal: int
    role: str
    remaining_s: float
    started_elapsed_s: float
    started_monotonic: float = field(repr=False)

    def record(self) -> dict[str, object]:
        return {
            "schema_id": "forensic.cell-dispatch.v1",
            "kind": self.kind,
            "ordinal": self.ordinal,
            "role": self.role,
            "remaining_time_s": round(self.remaining_s, 6),
            "started_elapsed_s": round(self.started_elapsed_s, 6),
        }


class _CellExecutionBudget:
    """One monotonic deadline and pre-dispatch request/tool ceilings for a cell.

    The object intentionally exposes only relative timing in checkpoint records;
    absolute monotonic values are process-local implementation details.  Synchronous
    Python tools cannot be killed safely.  ``_bound_tool_dispatches`` therefore uses
    a timed worker but, on timeout, waits for that worker to quiesce before raising.
    This may extend wall-clock cleanup for a non-cooperative parser, but it prevents a
    late worker from touching the disk, traces, or scratch state of the next cell.
    """

    def __init__(
        self,
        *,
        started_monotonic: float,
        deadline_monotonic: float,
        max_investigation_requests: int,
        max_model_requests: int,
        max_tool_calls: int,
        max_navigation_calls: int | None = None,
        reserved_terminal_model_requests: int = 0,
        reserved_terminal_wall_time_s: float = 0.0,
        clock=None,
    ) -> None:
        self._clock = clock or time.monotonic
        values = (started_monotonic, deadline_monotonic)
        if any(
            isinstance(value, bool)
            or not isinstance(value, int | float)
            or not math.isfinite(float(value))
            for value in values
        ):
            raise ValueError("cell monotonic deadline values must be finite numbers")
        if float(deadline_monotonic) <= float(started_monotonic):
            raise ValueError("cell deadline must be later than its monotonic start")
        for name, value in (
            ("max_investigation_requests", max_investigation_requests),
            ("max_model_requests", max_model_requests),
            ("max_tool_calls", max_tool_calls),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if (
            isinstance(reserved_terminal_model_requests, bool)
            or not isinstance(reserved_terminal_model_requests, int)
            or reserved_terminal_model_requests < 0
        ):
            raise ValueError("reserved_terminal_model_requests must be a non-negative integer")
        if reserved_terminal_model_requests >= max_model_requests:
            raise ValueError(
                "reserved terminal model requests must leave at least one investigation request"
            )
        if (
            isinstance(reserved_terminal_wall_time_s, bool)
            or not isinstance(reserved_terminal_wall_time_s, int | float)
            or not math.isfinite(float(reserved_terminal_wall_time_s))
            or float(reserved_terminal_wall_time_s) < 0
        ):
            raise ValueError("reserved_terminal_wall_time_s must be a non-negative number")
        # Navigation is bounded so a model cannot page forever, but out of its own
        # pool: the loop it must not enter is unrelated to how many times the
        # evidence may be read.  Absent an explicit ceiling it is given the same
        # size as the forensic one, which is a stated allowance rather than an
        # unbounded one.
        effective_navigation_calls = (
            max_tool_calls if max_navigation_calls is None else max_navigation_calls
        )
        if (
            isinstance(effective_navigation_calls, bool)
            or not isinstance(effective_navigation_calls, int)
            or effective_navigation_calls < 1
        ):
            raise ValueError("max_navigation_calls must be a positive integer")
        self.max_navigation_calls = effective_navigation_calls
        self.reserved_terminal_model_requests = reserved_terminal_model_requests
        # Wall-time held back from investigation so the reserved terminal path
        # (forced-final, then verification) still has a clock even when a long
        # run spends the whole soft deadline reading evidence.  Default 0.0 keeps
        # the historical behaviour: investigation runs until the true deadline.
        self.reserved_terminal_wall_time_s = float(reserved_terminal_wall_time_s)
        self.started_monotonic = float(started_monotonic)
        self.deadline_monotonic = float(deadline_monotonic)
        self.max_investigation_requests = max_investigation_requests
        self.max_model_requests = max_model_requests
        self.max_tool_calls = max_tool_calls
        self._lock = threading.Lock()
        self._investigation_dispatches = 0
        self._model_dispatches = 0
        self._tool_dispatches = 0
        self._investigation_rejections = 0
        self._model_rejections = 0
        self._tool_rejections = 0
        self._deadline_exhausted = False
        self._exhaustion_reasons: set[str] = set()
        #: Asked to stop by the operator. Written by another thread and read
        #: under this cell's lock; a bool assignment is atomic, so the cancel
        #: path never takes the lock and can never deadlock against a dispatch
        #: that is holding it.
        self._cancelled = False
        #: Whether a dispatch was actually refused because of that, which is
        #: what the record should say happened.
        self._cancellation_observed = False
        # Model calls that were never dispatched but whose call ID had to be
        # closed with a control record so no unresolved call survives the run.
        self._control_closed_calls = 0
        self._control_closure_reasons: set[str] = set()
        # ToolNode may execute multiple calls from one model response concurrently.
        # Completions can therefore arrive in a different order from dispatches.
        # Key attempts by their dispatch ordinal so the published telemetry remains
        # deterministic without serializing otherwise independent forensic tools.
        self._tool_attempts: dict[int, dict[str, object]] = {}
        # Calls the surface refused before opening anything.  They gave their
        # forensic reservation back (see ``refuse_tool``) and are tallied here,
        # apart from the attempts, for the reason ``record_control_closure``
        # states for its own case.
        self._refused_tool_calls = 0
        self._repeated_refusals = 0
        self._refusal_reasons: set[str] = set()
        self._refused_call_signatures: dict[tuple[str, str], str] = {}
        # Successful calls, remembered under the same (name, fingerprint)
        # identity the refusals use, so a byte-identical repeat can be served
        # from the record instead of reading the same evidence again; see
        # ``record_success``.  Bounded by ``max_tool_calls`` distinct successes
        # per cell, so the retention cannot grow past the cell's own ceiling.
        self._successful_call_results: dict[tuple[str, str], object] = {}
        self._cached_result_serves = 0
        self._navigation_dispatches = 0
        self._navigation_rejections = 0
        self._navigation_attempts: dict[int, dict[str, object]] = {}
        with _ACTIVE_CELLS_LOCK:
            _ACTIVE_CELLS.add(self)

    def cancel(self) -> None:
        """Stop dispatching. Safe to call from any thread, and idempotent."""

        self._cancelled = True

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    def now(self) -> float:
        return float(self._clock())

    def elapsed(self) -> float:
        return max(0.0, self.now() - self.started_monotonic)

    def _remaining_locked(self) -> tuple[float, float]:
        # Cancellation is tested BEFORE the clock, so a run cancelled in its
        # last second is recorded as cancelled rather than as having run out of
        # time. It records nothing in _exhaustion_reasons: no ceiling was
        # reached, and the exhaustion statistics must not learn about this.
        if self._cancelled:
            self._cancellation_observed = True
            raise _DispatchDenied(CANCELLED_REASON)
        now = self.now()
        remaining = self.deadline_monotonic - now
        if remaining <= 0:
            self._deadline_exhausted = True
            self._exhaustion_reasons.add("max_wall_time_s")
            raise _DispatchDenied("max_wall_time_s")
        return now, remaining

    def remaining(self) -> float:
        with self._lock:
            _now, remaining = self._remaining_locked()
            return remaining

    def reserve_model(self, role: str) -> _DispatchPermit:
        if role not in {"investigation", "forced_final", "verification"}:
            raise ValueError("model dispatch role is invalid")
        with self._lock:
            now, remaining = self._remaining_locked()
            if (
                role == "investigation"
                and self.reserved_terminal_wall_time_s > 0.0
                and remaining <= self.reserved_terminal_wall_time_s
            ):
                # Only the reserve is left, and it belongs to the terminal path.
                # Investigation stops here so a run that spent the soft deadline
                # gathering evidence can still conclude from it and have that
                # conclusion checked, instead of publishing nothing.
                self._investigation_rejections += 1
                self._model_rejections += 1
                self._exhaustion_reasons.add("max_wall_time_s")
                raise _DispatchDenied("max_wall_time_s")
            if (
                role == "investigation"
                and self._investigation_dispatches >= self.max_investigation_requests
            ):
                self._investigation_rejections += 1
                self._model_rejections += 1
                self._exhaustion_reasons.add("max_steps")
                raise _DispatchDenied("max_steps")
            if (
                role == "investigation"
                and self._model_dispatches
                >= self.max_model_requests - self.reserved_terminal_model_requests
            ):
                # The terminal path is not optional: a run that gathered evidence
                # must still be able to conclude and to have that conclusion
                # checked.  Investigation therefore stops one or two requests
                # short of the ceiling rather than starving finalization.  The
                # reason stays "max_model_requests" so the finish-reason mapping
                # sees the same vocabulary.
                self._investigation_rejections += 1
                self._model_rejections += 1
                self._exhaustion_reasons.add("max_model_requests")
                raise _DispatchDenied("max_model_requests")
            if self._model_dispatches >= self.max_model_requests:
                self._model_rejections += 1
                self._exhaustion_reasons.add("max_model_requests")
                raise _DispatchDenied("max_model_requests")
            self._model_dispatches += 1
            if role == "investigation":
                self._investigation_dispatches += 1
            return _DispatchPermit(
                kind="model",
                ordinal=self._model_dispatches,
                role=role,
                remaining_s=remaining,
                started_elapsed_s=max(0.0, now - self.started_monotonic),
                started_monotonic=now,
            )

    def _evidence_readings_locked(self) -> int:
        """Reservations that became readings of the evidence, refusals excluded."""

        return self._tool_dispatches - self._refused_tool_calls

    def reserve_tool(self, name: str) -> _DispatchPermit:
        if not name.strip():
            raise ValueError("tool dispatch name must be non-empty")
        with self._lock:
            now, remaining = self._remaining_locked()
            # The ceiling meters readings of the evidence: a call the surface
            # refused handed its reservation back and is not among them.
            if self._evidence_readings_locked() >= self.max_tool_calls:
                self._tool_rejections += 1
                self._exhaustion_reasons.add("max_tool_calls")
                raise _DispatchDenied("max_tool_calls")
            self._tool_dispatches += 1
            return _DispatchPermit(
                kind="tool",
                ordinal=self._tool_dispatches,
                role=name,
                remaining_s=remaining,
                started_elapsed_s=max(0.0, now - self.started_monotonic),
                started_monotonic=now,
            )

    def reserve_navigation(self, name: str) -> _DispatchPermit:
        """Permit one read of a result this run already stored.

        Deliberately not ``reserve_tool``: nothing is executed, no source is
        opened and no upstream invocation is created, so this must not consume
        the allowance for reading the evidence.  A run that spent its forensic
        ceiling can still read the pages of what it gathered, and a run that
        paged a great deal has lost none of its ability to look again.
        """

        if not name.strip():
            raise ValueError("navigation dispatch name must be non-empty")
        with self._lock:
            now, remaining = self._remaining_locked()
            if self._navigation_dispatches >= self.max_navigation_calls:
                self._navigation_rejections += 1
                self._exhaustion_reasons.add("max_navigation_calls")
                raise _DispatchDenied("max_navigation_calls")
            self._navigation_dispatches += 1
            return _DispatchPermit(
                kind="navigation",
                ordinal=self._navigation_dispatches,
                role=name,
                remaining_s=remaining,
                started_elapsed_s=max(0.0, now - self.started_monotonic),
                started_monotonic=now,
            )

    def complete_navigation(
        self,
        permit: _DispatchPermit,
        *,
        status: Literal["success", "error", "deadline_exceeded"],
        error_type: str | None,
    ) -> None:
        """Record one finished navigation read, apart from the tool attempts."""

        completed = self.now()
        with self._lock:
            if (
                permit.kind != "navigation"
                or permit.ordinal < 1
                or permit.ordinal > self._navigation_dispatches
            ):
                raise RuntimeError("navigation completion does not match a reserved dispatch")
            if permit.ordinal in self._navigation_attempts:
                raise RuntimeError("navigation dispatch completion was recorded more than once")
            if status == "deadline_exceeded":
                self._deadline_exhausted = True
                self._exhaustion_reasons.add("max_wall_time_s")
            self._navigation_attempts[permit.ordinal] = {
                **permit.record(),
                "status": status,
                "duration_s": round(max(0.0, completed - permit.started_monotonic), 6),
                "error_type": error_type,
            }

    def tool_budget_exhausted(self) -> bool:
        """Whether no further forensic execution can be dispatched in this cell.

        Read by the terminal path, which must distinguish "no tool may run again"
        from "this run failed".  The first is a planned transition to the answer
        phase; only the second may withhold a report.
        """

        with self._lock:
            return self._evidence_readings_locked() >= self.max_tool_calls

    def record_control_closure(self, *, call_count: int, reason: str) -> None:
        """Record call IDs closed by a control record instead of an execution.

        A refused dispatch performs no forensic operation, so it is counted here
        rather than among tool attempts: the published telemetry must never let a
        refusal be mistaken for a reading of the evidence.
        """

        if isinstance(call_count, bool) or not isinstance(call_count, int) or call_count < 0:
            raise ValueError("closed call count must be a non-negative integer")
        if not reason.strip():
            raise ValueError("control closure reason must be non-empty")
        with self._lock:
            self._control_closed_calls += call_count
            if call_count:
                self._control_closure_reasons.add(reason.strip())

    def refuse_tool(self, permit: _DispatchPermit, *, reason: str, fingerprint: str) -> None:
        """Record a refused call and hand back the forensic reservation it took.

        The reasoning is the one :meth:`reserve_navigation` already states, only
        stronger: a refusal is decided by validating the arguments, so nothing is
        executed, no source is opened and no upstream invocation is created, and
        it must not consume the allowance for reading the evidence.  A navigation
        read at least serves a result the run holds; a refusal serves nothing.

        The attempt stays in the published list, which carries one entry per
        reservation in dispatch order: the refusal is SHOWN there, as an error
        naming it, never as a success.  Its tally is kept apart in
        ``refused_call_count`` for the reason :meth:`record_control_closure`
        gives for its own case — published telemetry must never let a refusal be
        mistaken for a reading of the evidence.  The call's signature is
        remembered so an identical repeat can be answered without executing
        anything; see :meth:`recall_refusal`.
        """

        if not reason.strip():
            raise ValueError("tool refusal reason must be non-empty")
        if not fingerprint.strip():
            raise ValueError("tool refusal fingerprint must be non-empty")
        completed = self.now()
        with self._lock:
            self._record_tool_attempt_locked(
                permit,
                status="error",
                error_type=reason.strip(),
                quiescence_waited=False,
                completed=completed,
            )
            self._refused_tool_calls += 1
            self._refusal_reasons.add(reason.strip())
            self._refused_call_signatures[(permit.role, fingerprint)] = reason.strip()

    def recall_refusal(self, name: str, fingerprint: str) -> str | None:
        """Name the refusal an identical call in this cell already received.

        The tally is taken here, where the answer is handed back, so the lookup
        and the count are one operation: concurrent calls may reach the same
        already-refused signature, and the cell must publish how often that
        happened rather than how often it was noticed.
        """

        with self._lock:
            reason = self._refused_call_signatures.get((name, fingerprint))
            if reason is None:
                return None
            self._repeated_refusals += 1
            return reason

    def record_success(self, name: str, fingerprint: str, result: object) -> None:
        """Remember one successful call's result for a byte-identical repeat.

        The evidence is immutable for the life of a run and the call is
        identified by function and canonical arguments, so an identical repeat
        has exactly one possible outcome and re-executing it only spends the
        run — the reasoning :meth:`refuse_tool` states for a repeated refusal,
        applied to the call that succeeded.  Only the first result is kept:
        the record must keep answering with the result the run actually
        observed first, not with whichever concurrent repeat happened to
        publish last, so the served result and every citation of its
        invocation stay one identity.
        """

        if not name.strip():
            raise ValueError("tool success name must be non-empty")
        if not fingerprint.strip():
            raise ValueError("tool success fingerprint must be non-empty")
        with self._lock:
            self._successful_call_results.setdefault((name, fingerprint), result)

    def recall_success(self, name: str, fingerprint: str) -> object | None:
        """Return the result an identical call in this cell already produced.

        The tally is taken here, where the answer is handed back, for the
        reason :meth:`recall_refusal` gives for its own case: concurrent calls
        may reach the same signature, and the cell must publish how often a
        repeat was served rather than how often it was noticed.  A serve is
        counted on its own counter and never as a reading of the evidence —
        nothing executes, no source is opened and no invocation is created,
        so telemetry that mistook a serve for a reading would let a run look
        as if it read the evidence more often than it did.
        """

        with self._lock:
            result = self._successful_call_results.get((name, fingerprint))
            if result is None:
                return None
            self._cached_result_serves += 1
            return result

    def _record_tool_attempt_locked(
        self,
        permit: _DispatchPermit,
        *,
        status: Literal["success", "error", "deadline_exceeded"],
        error_type: str | None,
        quiescence_waited: bool,
        completed: float,
    ) -> None:
        if permit.kind != "tool" or permit.ordinal < 1 or permit.ordinal > self._tool_dispatches:
            raise RuntimeError("tool completion does not match a reserved dispatch")
        if permit.ordinal in self._tool_attempts:
            raise RuntimeError("tool dispatch completion was recorded more than once")
        if status == "deadline_exceeded":
            self._deadline_exhausted = True
            self._exhaustion_reasons.add("max_wall_time_s")
        self._tool_attempts[permit.ordinal] = {
            **permit.record(),
            "status": status,
            "duration_s": round(max(0.0, completed - permit.started_monotonic), 6),
            "error_type": error_type,
            "quiescence_waited": quiescence_waited,
        }

    def complete_tool(
        self,
        permit: _DispatchPermit,
        *,
        status: Literal["success", "error", "deadline_exceeded"],
        error_type: str | None,
        quiescence_waited: bool,
    ) -> None:
        completed = self.now()
        with self._lock:
            self._record_tool_attempt_locked(
                permit,
                status=status,
                error_type=error_type,
                quiescence_waited=quiescence_waited,
                completed=completed,
            )

    def metrics(self) -> dict[str, object]:
        now = self.now()
        with self._lock:
            elapsed = max(0.0, now - self.started_monotonic)
            remaining = max(0.0, self.deadline_monotonic - now)
            if now >= self.deadline_monotonic:
                self._deadline_exhausted = True
                self._exhaustion_reasons.add("max_wall_time_s")
            attempt_ordinals = sorted(self._tool_attempts)
            if len(attempt_ordinals) == self._tool_dispatches and attempt_ordinals != list(
                range(1, self._tool_dispatches + 1)
            ):
                raise RuntimeError("completed tool dispatch ordinals are not contiguous")
            return {
                "schema_id": "forensic.cell-execution-metrics.v1",
                # Its own field, never an entry in exhaustion_reasons, so a
                # reader counting exhausted budgets cannot count this.
                "cancelled": self._cancellation_observed,
                "absolute_dispatch_deadline_enforced": True,
                "hard_wall_kill_enforced": False,
                "quiescent_cleanup_may_exceed_deadline": True,
                "wall_time_budget_s": round(self.deadline_monotonic - self.started_monotonic, 6),
                "elapsed_s": round(elapsed, 6),
                "remaining_s": round(remaining, 6),
                "max_investigation_requests": self.max_investigation_requests,
                "investigation_dispatch_count": self._investigation_dispatches,
                "investigation_dispatch_rejection_count": self._investigation_rejections,
                "max_model_requests": self.max_model_requests,
                "reserved_terminal_model_requests": self.reserved_terminal_model_requests,
                "reserved_terminal_wall_time_s": round(self.reserved_terminal_wall_time_s, 6),
                "model_dispatch_count": self._model_dispatches,
                "model_dispatch_rejection_count": self._model_rejections,
                "max_tool_calls": self.max_tool_calls,
                "tool_dispatch_count": self._tool_dispatches,
                "tool_dispatch_rejection_count": self._tool_rejections,
                # What the forensic ceiling actually meters, published beside the
                # refusals it does not: a reader must be able to separate the two
                # without inferring either.
                "evidence_reading_dispatch_count": self._evidence_readings_locked(),
                "refused_call_count": self._refused_tool_calls,
                "repeated_refusal_count": self._repeated_refusals,
                # Repeats of successful calls answered from the record, on
                # their own counter for the same reason the refusals are: a
                # serve executed nothing and must never read as an evidence
                # reading.
                "cached_result_serve_count": self._cached_result_serves,
                "refusal_reasons": sorted(self._refusal_reasons),
                "control_closed_call_count": self._control_closed_calls,
                "control_closure_reasons": sorted(self._control_closure_reasons),
                "max_navigation_calls": self.max_navigation_calls,
                "navigation_dispatch_count": self._navigation_dispatches,
                "navigation_dispatch_rejection_count": self._navigation_rejections,
                "navigation_attempts": [
                    dict(self._navigation_attempts[ordinal])
                    for ordinal in sorted(self._navigation_attempts)
                ],
                "deadline_exhausted": self._deadline_exhausted,
                "exhaustion_reasons": sorted(self._exhaustion_reasons),
                "synchronous_tool_timeout_policy": (
                    "timed_worker_then_wait_for_quiescence_before_cell_exit"
                ),
                "tool_attempts": [
                    dict(self._tool_attempts[ordinal]) for ordinal in attempt_ordinals
                ],
            }
