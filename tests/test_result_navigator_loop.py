"""A stored page is served once; redeeming its cursor again breaks the loop.

Measured on the NIST hacking-case disk image: the model read a truncated
registry key, was handed a page cursor over the withheld records, read them, and
then — seeing the retained result's own truncated frontier restated with no new
cursor — kept re-passing the SAME cursor. Because a cursor's window is a fixed
slice, every redemption returned byte-identical records (the same evidence id),
and the run burned its whole tool-call budget looping instead of continuing the
tool. The navigator now serves each cursor once and, on the next redemption,
refuses with a directive to the tool's own continuation.
"""

from __future__ import annotations

from forensic_agent.agent.result_lineage import ResultLineageStore
from forensic_agent.agent.result_navigator import (
    PAGE_CURSOR_ALREADY_SERVED,
    PAGE_CURSOR_REFUSED,
    PageCursorExhausted,
    ResultNavigator,
    _binding_for,
    build_result_page_tool,
)
from forensic_agent.core import result_contract as contract
from forensic_agent.core.result_contract import PageMetadata, PageUnit

CASE = "case-loop"
_ARGS = {"operation": "registry_values", "hive": "SOFTWARE", "key": "\\Uninstall"}
_REGIPY = contract.UpstreamBackend(
    name="regipy", version="4.0", operation="windows.registry_values", role="producer"
)


def _provenance(invocation: str):
    return contract.make_provenance(
        evidence_class=contract.EvidenceClass.OBSERVED,
        provenance_type=contract.ProvenanceType.CASE_EVIDENCE,
        invocation_id=invocation,
        case_id=CASE,
        source_id="src-1",
        source_sha256="a" * 64,
        artifact_locator="path:/Windows/System32/config/SOFTWARE",
        tool_name="registry_query",
        tool_version="0.1",
        upstream_backends=(_REGIPY,),
        raw_output_sha256="c" * 64,
        oversight_entry_sha256="d" * 64,
        oversight_sequence=1,
    )


def _items(n: int):
    return [{"name": f"Program {i}", "value": f"v{i}"} for i in range(n)]


def _bound_navigator(*, truncated: bool, invocation: str = "run:0001"):
    """Retain a 10-item result and bind a cursor over records 5-9."""

    if truncated:
        result = contract.partial_result(
            data_type="windows.registry_values",
            provenance=_provenance(invocation),
            coverage_reason="the key holds more values than one read returned",
            items=_items(10),
            page=PageMetadata(
                unit=PageUnit.ITEM,
                offset=0,
                returned=10,
                total=None,
                next_offset=10,
                truncated=True,
            ),
        )
    else:
        result = contract.ok_result(
            data_type="windows.registry_values",
            provenance=_provenance(invocation),
            items=_items(10),
            page=PageMetadata(
                unit=PageUnit.ITEM,
                offset=0,
                returned=10,
                total=10,
                next_offset=None,
                truncated=False,
            ),
        )
    result = contract.attach_receipt(result)
    wire = result.model_dump(mode="json")

    store = ResultLineageStore()
    store.record_complete_result("registry_query", dict(_ARGS), wire)
    retained = store.retained(invocation)
    assert retained is not None
    navigator = ResultNavigator(store, case_id=CASE)
    token = "page:loop-test-token"
    binding = _binding_for(retained, case_id=CASE, offset=5, unit=PageUnit.ITEM)
    assert binding is not None
    navigator._bindings[token] = binding
    return navigator, token


def test_the_first_redemption_serves_the_withheld_window() -> None:
    navigator, token = _bound_navigator(truncated=True)

    served = navigator.page(token)

    items = served["data"]["items"]
    assert [item["name"] for item in items] == [f"Program {i}" for i in range(5, 10)]


def test_a_second_redemption_of_a_truncated_result_points_at_the_tool() -> None:
    navigator, token = _bound_navigator(truncated=True)
    navigator.page(token)  # first serve

    try:
        navigator.page(token)
    except PageCursorExhausted as exc:
        message = str(exc)
    else:
        raise AssertionError("the second redemption should have raised")

    assert "registry_query" in message
    assert "offset 10" in message


def test_a_second_redemption_of_a_complete_result_says_there_is_no_more() -> None:
    navigator, token = _bound_navigator(truncated=False)
    navigator.page(token)  # first serve

    try:
        navigator.page(token)
    except PageCursorExhausted as exc:
        message = str(exc)
    else:
        raise AssertionError("the second redemption should have raised")

    assert "complete set" in message
    assert "offset" not in message  # no tool frontier to point at


def test_the_facade_reports_the_loop_break_under_its_own_code() -> None:
    navigator, token = _bound_navigator(truncated=True)
    tool = build_result_page_tool(navigator)

    first = tool.func(cursor=token)
    # The window was served: a real ToolResult (error is None), not a refusal.
    assert first.get("deterministic_error") is not True
    assert first.get("error") is None

    second = tool.func(cursor=token)
    assert second["deterministic_error"] is True
    assert second["error"]["code"] == PAGE_CURSOR_ALREADY_SERVED
    assert second["error"]["code"] != PAGE_CURSOR_REFUSED
