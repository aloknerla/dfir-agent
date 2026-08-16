"""A long call announces itself before it can report a result.

A Volatility scan over a multi-gigabyte image runs for minutes; without a
start signal the activity feed stays empty and a working console is
indistinguishable from a frozen one. The start travels on the same
``on_tool`` channel with ``elapsed_s=None`` — a marker a settled-only feed
ignores and a live pane renders as "running…".
"""

from __future__ import annotations

from forensic_agent.agent.tool_bindings.context import ToolBuildContext


def _context(on_tool):
    return ToolBuildContext(
        disk=None,
        memory_path="/evidence/memory.dmp",
        pcap_path=None,
        controlled_scratch=None,
        tool_argument_allowlists=None,
        pcap_sources=None,
        on_tool=on_tool,
    )


def test_begin_sends_a_none_duration_marker():
    events = []
    context = _context(lambda *a: events.append(a))
    context.begin("memory_query", {"plugin": "pstree"})
    assert events == [("memory_query", {"plugin": "pstree"}, None, False)]


def test_begin_is_silent_without_a_feed():
    # No on_tool bound (an evaluation run): begin must do nothing, not raise.
    context = _context(None)
    context.begin("memory_query", {"plugin": "pstree"})  # no exception


def test_begin_swallows_a_failing_feed():
    def broken(*_a):
        raise RuntimeError("feed is gone")

    context = _context(broken)
    context.begin("memory_query", {"plugin": "pstree"})  # never propagates


def test_the_settled_emit_still_carries_a_real_duration():
    events = []
    context = _context(lambda *a: events.append(a))
    context.begin("memory_query", {"plugin": "pstree"})
    context.emit("memory_query", {"plugin": "pstree"}, 0.0)
    assert events[0][2] is None  # the start
    assert isinstance(events[1][2], float)  # the settled duration
    assert events[1][3] is False
