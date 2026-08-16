"""Which retained results still state that more of them exists.

The run already carries stage-specific continuation rules for two families of
result, and those stages execute calls.  This one executes nothing.  It reads,
for EVERY domain operation, the two facts the result itself states — does more
exist, and is there a safe way to ask for it — and reports the frontier that
remains.

Keeping it registry-driven is the point.  A stage that recognises one tool by
name cannot tell the run anything about the other sixty-two operations, so an
unfinished enumeration outside its family is simply invisible; and invisibility
is what lets a partial page be summarised as if it were the whole set.  Here the
operation is resolved from the shared registry, the continuation from the shared
page reader, and the next call from the operation's own declared cursor, so a
new operation is covered by the definition that introduces it.

A frontier is reported as CONSUMED when a later retained result carries the
exact continuation call this one asked for, over the same case, source and
query.  Anything else is left standing: "the model chose not to continue" and
"the model continued somewhere else" are different facts, and only the first is
an unfinished enumeration.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from forensic_agent.agent.recovery.common import _validated_continuation_result
from forensic_agent.agent.tool_operations import (
    continuation_arguments,
    resolved_operation,
)
from forensic_agent.core.repro import canonical_json
from forensic_agent.core.result_navigation import ContinuationKind, page_continuation
from forensic_agent.core.result_reading import UnreadableResult

RESULT_NAVIGATION_METRICS_SCHEMA_ID = "forensic.result-navigation-metrics.v1"


@dataclass(frozen=True, slots=True)
class ResultFrontier:
    """One retained page that stated more of its result set exists."""

    tool: str
    operation: str
    #: The exact next call, or ``None`` when the result states that more exists
    #: without offering a continuation this planner may take.  The distinction is
    #: reported rather than smoothed over: an unreachable remainder is a coverage
    #: limit the run has to disclose, not a page someone forgot to fetch.
    next_arguments: dict[str, Any] | None
    kind: ContinuationKind
    case_id: str | None
    source_id: str
    source_sha256: str | None

    def key(self) -> str:
        return canonical_json(
            {
                "tool": self.tool,
                "operation": self.operation,
                "next_arguments": self.next_arguments,
                "case_id": self.case_id,
                "source_id": self.source_id,
                "source_sha256": self.source_sha256,
            }
        )


def empty_result_navigation_metrics(*, enabled: bool) -> dict[str, object]:
    """The stable telemetry shape for stated, unconsumed result frontiers."""

    return {
        "schema_id": RESULT_NAVIGATION_METRICS_SCHEMA_ID,
        "enabled": enabled,
        "decision": "not_evaluated" if enabled else "arm_disabled",
        "pages_read": 0,
        "pages_stating_more": 0,
        "unconsumed_frontiers": 0,
        "resumable_frontiers": 0,
        "unreachable_frontiers": 0,
        "operations_with_unconsumed_frontier": [],
    }


def frontier_of(record: Mapping[str, Any]) -> ResultFrontier | None:
    """The stated frontier of one retained record, or ``None`` if it has none.

    Returns ``None`` for a record that is not a receipt-valid case-evidence
    result of a registered domain operation, and for one whose page states that
    nothing remains.  Reading an unverified record would let a forged page
    nominate the next call the run makes.
    """

    tool = record.get("tool")
    arguments = record.get("arguments")
    if not isinstance(tool, str) or not isinstance(arguments, Mapping):
        return None
    operation = resolved_operation(tool, arguments)
    if operation is None:
        return None
    result = _validated_continuation_result(record)
    if result is None:
        return None
    try:
        continuation = page_continuation(result)
    except (TypeError, UnreadableResult):  # pragma: no cover - result already parsed
        return None
    if not continuation.has_more:
        return None
    return ResultFrontier(
        tool=tool,
        operation=operation,
        next_arguments=continuation_arguments(tool, operation, arguments, continuation),
        kind=continuation.kind,
        case_id=result.provenance.case_id,
        source_id=result.provenance.source.id,
        source_sha256=result.provenance.source.sha256,
    )


def _consumed_calls(records: Sequence[Mapping[str, Any]]) -> set[str]:
    """Every call the run actually made, keyed the way a frontier states it."""

    made: set[str] = set()
    for record in records:
        tool = record.get("tool")
        arguments = record.get("arguments")
        if not isinstance(tool, str) or not isinstance(arguments, Mapping):
            continue
        operation = resolved_operation(tool, arguments)
        if operation is None:
            continue
        result = _validated_continuation_result(record)
        if result is None:
            continue
        made.add(
            canonical_json(
                {
                    "tool": tool,
                    "operation": operation,
                    "next_arguments": dict(arguments),
                    "case_id": result.provenance.case_id,
                    "source_id": result.provenance.source.id,
                    "source_sha256": result.provenance.source.sha256,
                }
            )
        )
    return made


def unconsumed_frontiers(
    records: Sequence[Mapping[str, Any]],
) -> tuple[tuple[ResultFrontier, ...], int, int]:
    """Every stated, still-unfetched frontier, plus pages read and pages stating more."""

    pages_read = 0
    frontiers: dict[str, ResultFrontier] = {}
    stated = 0
    for record in records:
        if _validated_continuation_result(record) is not None:
            pages_read += 1
        frontier = frontier_of(record)
        if frontier is None:
            continue
        stated += 1
        frontiers.setdefault(frontier.key(), frontier)
    consumed = _consumed_calls(records)
    remaining = [
        frontier
        for key, frontier in sorted(frontiers.items())
        if frontier.next_arguments is None or key not in consumed
    ]
    return tuple(remaining), pages_read, stated


def result_navigation_metrics(
    records: Sequence[Mapping[str, Any]], *, enabled: bool = True
) -> dict[str, object]:
    """Report the run's stated, unconsumed frontiers without executing anything.

    The counts separate a remainder the run COULD still fetch from one no page
    offers a safe continuation for, because those call for opposite conclusions:
    the first is an enumeration left unfinished, the second is a limit that has
    to be stated in the report.
    """

    metrics = empty_result_navigation_metrics(enabled=enabled)
    if not enabled:
        return metrics
    remaining, pages_read, stated = unconsumed_frontiers(records)
    resumable = [frontier for frontier in remaining if frontier.next_arguments is not None]
    metrics.update(
        {
            "pages_read": pages_read,
            "pages_stating_more": stated,
            "unconsumed_frontiers": len(remaining),
            "resumable_frontiers": len(resumable),
            "unreachable_frontiers": len(remaining) - len(resumable),
            "operations_with_unconsumed_frontier": sorted(
                {f"{frontier.tool}.{frontier.operation}" for frontier in remaining}
            ),
            "decision": "unconsumed_frontier" if remaining else "no_unconsumed_frontier",
        }
    )
    return metrics


__all__ = [
    "RESULT_NAVIGATION_METRICS_SCHEMA_ID",
    "ResultFrontier",
    "empty_result_navigation_metrics",
    "frontier_of",
    "result_navigation_metrics",
    "unconsumed_frontiers",
]
