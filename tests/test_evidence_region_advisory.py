"""The unread-region advisory nudges an absence claim, never a positive answer.

Measured on the NIST hacking-case disk image: the model queried the SYSTEM
ComputerName key, got WS-EXAMPLE-07, and then — because a disk always leaves
deleted entries and unreferenced space unread — the advisory re-invoked the
model with an "unread regions" statement, and the model's acknowledgement of
that statement REPLACED the computer name it had already given. The advisory
exists only to hold a claim of ABSENCE to what the run read; a positive finding
has no absence for an unread region to refute, so it must be turned away before
the re-invocation that clobbers it.
"""

from __future__ import annotations

from types import SimpleNamespace

from langchain_core.messages import AIMessage, HumanMessage

from forensic_agent.agent.recovery.evidence_region_advisory import (
    empty_evidence_region_metrics,
    state_unread_evidence_regions,
)
from forensic_agent.agent.recovery.premature_absence import report_asserts_absence

#: Disk-side tools, so the deleted-entries and unreferenced regions are reachable
#: (and, having only listed a directory, unread).
_DISK_TOOLS = ("filesystem_query", "recover_deleted", "carve_query", "bulk_extract")

_POSITIVE = "The computer name is WS-EXAMPLE-07."
_ABSENCE = "No hacking tools were found on the system."


def _listed_directory_record() -> dict:
    """One successful directory listing: filesystem-listed read, the rest unread."""

    return {
        "tool": "filesystem_query",
        "arguments": {"operation": "list_directory", "path": "/"},
        "result": {"status": "ok", "data": {"attributes": {}, "items": []}},
    }


class _TrackingAgent:
    """Records every re-invocation so a test can assert the advisory stayed silent."""

    def __init__(self, reply: str) -> None:
        self.calls: list[object] = []
        self._reply = reply

    def invoke(self, payload, config=None):
        self.calls.append(payload)
        messages = list(payload["messages"]) + [AIMessage(self._reply)]
        return {"messages": messages}


def _run(report: str, agent: _TrackingAgent):
    messages = [HumanMessage("Koje je ime računala?"), AIMessage(report)]
    metrics = empty_evidence_region_metrics(enabled=True)
    kept, exhaustion, omission = state_unread_evidence_regions(
        list(messages),
        [_listed_directory_record()],
        _DISK_TOOLS,
        report,
        metrics,
        llm=SimpleNamespace(),
        agent=agent,
        investigation_ledger=SimpleNamespace(),
        recursion_limit=8,
    )
    return kept, exhaustion, omission, metrics


def test_a_positive_finding_is_not_re_invoked_by_the_region_advisory() -> None:
    """A found value is never sent back through the model to be acknowledged away."""

    assert report_asserts_absence(_POSITIVE) is False
    agent = _TrackingAgent("Razumijem. Te regije nisu čitane; mogu koristiti carve_query.")

    kept, exhaustion, omission, metrics = _run(_POSITIVE, agent)

    assert agent.calls == []  # the model was never re-invoked
    assert metrics["decision"] == "no_absence_asserted"
    assert metrics.get("activated") is not True
    assert metrics.get("statement_delivered") is not True
    assert exhaustion is None
    assert omission is False
    # The message state — and therefore the published answer — is untouched.
    assert kept[-1].content == _POSITIVE


def test_an_unqualified_absence_still_receives_the_statement() -> None:
    """The advisory's designed nudge still fires when an absence is asserted."""

    assert report_asserts_absence(_ABSENCE) is True
    # Its reply drops the absence, so the loop concludes after one delivery.
    agent = _TrackingAgent("The system contains the hacking tool Cain.")

    kept, _exhaustion, _omission, metrics = _run(_ABSENCE, agent)

    assert len(agent.calls) >= 1  # the model WAS re-invoked with the statement
    assert metrics["statement_delivered"] is True
    assert metrics["decision"] != "no_absence_asserted"
