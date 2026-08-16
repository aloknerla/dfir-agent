import pytest

from forensic_agent.cli.exchange_view import _ANSWER_FRAMING
from forensic_agent.cli.presentation import (
    ACCEPTED_ANSWER_SOURCES,
    ANSWER_NONE,
    ANSWER_VERIFIED_WITH_BOUND,
    MAX_DISPLAYED_FINDINGS,
    summarize_controls,
    summarize_finding,
    summarize_findings,
)
from forensic_agent.reporting.trace_svg import _ACCEPTED_ANSWER_VERDICTS


def _trace_row(**overrides):
    row = {
        "tool": "registry_query",
        "payload_sha256": "A" * 64,
        "result": {
            "status": "partial",
            "data": {
                "type": "windows.registry.values",
                "attributes": {"host_path": r"C:\private\evidence.E01"},
                "items": [{"secret": "raw evidence must not be projected"}],
            },
            "page": {"returned": 5, "total": 12, "truncated": True},
            "coverage": {"complete": False, "reason": r"C:\private\reason"},
            "warnings": [
                {"code": "bounded", "message": r"C:\private\warning"},
            ],
            "receipt": {"payload_sha256": "A" * 64},
        },
    }
    row.update(overrides)
    return row


def test_finding_projection_contains_only_bounded_typed_metadata():
    summary = summarize_finding(_trace_row(), sequence=2)

    assert summary.sequence == 2
    assert summary.tool == "registry_query"
    assert summary.status == "partial"
    assert summary.data_type == "windows.registry.values"
    assert summary.records == "5/12 records"
    assert summary.coverage == "truncated"
    assert summary.notes == "warnings: 1; continuation available"
    assert summary.receipt == "aaaaaaaaaaaa…"
    rendered = repr(summary)
    assert r"C:\private" not in rendered
    assert "raw evidence" not in rendered


def test_untrusted_display_identifiers_fail_closed():
    row = _trace_row(tool=r"read_file C:\private\evidence.E01")
    row["result"]["status"] = "ok\nsecret"
    row["result"]["data"]["type"] = "type /private/path"
    row["payload_sha256"] = "not-a-receipt"

    summary = summarize_finding(row, sequence=1)

    assert summary.tool == "unknown_tool"
    assert summary.status == "unknown"
    assert summary.data_type == "unknown_type"
    assert summary.receipt == "—"


def test_findings_projection_has_a_hard_row_limit():
    rows = [_trace_row() for _ in range(MAX_DISPLAYED_FINDINGS + 7)]

    projection = summarize_findings(rows, limit=999)

    assert len(projection.rows) == MAX_DISPLAYED_FINDINGS
    assert projection.omitted == 7


def test_successful_scalar_finding_is_not_rendered_as_zero_records():
    row = _trace_row()
    row["result"] = {
        "status": "ok",
        "data": {
            "type": "filesystem.metadata",
            "attributes": {
                "path": "/DCIM/100CANON/IMG_0001.JPG",
                "size": 2_834_018,
            },
            "items": [],
        },
        "page": {
            "unit": "item",
            "offset": 0,
            "returned": 0,
            "total": None,
            "truncated": False,
        },
        "coverage": {"complete": True},
        "warnings": [],
        "receipt": {"payload_sha256": "A" * 64},
    }

    summary = summarize_finding(row, sequence=1)

    assert summary.records == "1 result"
    assert summary.coverage == "complete"


def test_explicitly_empty_collection_remains_zero_records():
    row = _trace_row()
    row["result"] = {
        "status": "ok",
        "data": {
            "type": "filesystem.directory_listing",
            "attributes": {"path": "/empty"},
            "items": [],
        },
        "page": {
            "unit": "item",
            "offset": 0,
            "returned": 0,
            "total": 0,
            "truncated": False,
        },
        "coverage": {"complete": True},
        "warnings": [],
        "receipt": {"payload_sha256": "A" * 64},
    }

    summary = summarize_finding(row, sequence=1)

    assert summary.records == "0/0 records"


def test_successful_verifier_request_is_described_as_executed_not_passed():
    summary = summarize_controls(
        {
            "model_requests": 4,
            "verifier_metrics": {"activated": True, "request_status": "success"},
            "final_answer_metrics": {
                "accepted_source": "verifier",
                "verification_outcome": "verified",
                "publication_outcome": "published",
            },
        },
        run_id="abc123def4567890",
        tool_calls=3,
        findings=3,
    )

    assert summary.verification == "completed"
    assert "passed" not in summary.verification
    assert summary.answer_source == "verified model report"
    assert summary.model_requests == 4
    assert summary.trace_id == "abc123def456"
    assert not hasattr(summary, "deterministic_synthesis")


def test_nonactivated_verifier_without_accepted_answer_is_not_completed():
    summary = summarize_controls(
        {"verifier_metrics": {"activated": False, "request_status": "success"}},
        run_id=r"C:\private\trace",
        tool_calls=-1,
        findings=-1,
    )

    assert summary.verification == "not started"
    assert summary.answer_source == "no accepted answer"
    assert summary.tool_calls == 0
    assert summary.findings == 0
    assert summary.trace_id == "unavailable"


def test_raw_arm_published_draft_is_rendered_as_unverified():
    summary = summarize_controls(
        {
            "verifier_metrics": {"activated": False},
            "final_answer_metrics": {
                "accepted_source": "investigation_model_draft",
                "verification_outcome": "not_requested",
                "publication_outcome": "published",
            },
        },
        run_id="abc123def4567890",
        tool_calls=1,
        findings=1,
    )

    assert summary.answer_source == "unverified model draft"


@pytest.mark.parametrize(
    "final_answer_metrics",
    [
        # verifier accepted but publication blocked by grounding
        {
            "accepted_source": "verifier",
            "verification_outcome": "verified",
            "publication_outcome": "blocked_identifier_grounding",
        },
        # verifier "accepted" but the verification actually failed
        {
            "accepted_source": "verifier",
            "verification_outcome": "failed_ledger_binding",
            "publication_outcome": "published",
        },
        # published with no accepted source
        {
            "accepted_source": "none",
            "verification_outcome": "verified",
            "publication_outcome": "published",
        },
        # raw draft mislabeled as verified
        {
            "accepted_source": "investigation_model_draft",
            "verification_outcome": "verified",
            "publication_outcome": "published",
        },
    ],
)
def test_contradictory_final_answer_telemetry_is_never_verified(final_answer_metrics):
    summary = summarize_controls(
        {
            "verifier_metrics": {"activated": True, "request_status": "success"},
            "final_answer_metrics": final_answer_metrics,
        },
        run_id="abc123def4567890",
        tool_calls=1,
        findings=1,
    )

    assert summary.answer_source == "no accepted answer"


def test_answer_published_with_a_stated_bound_is_not_displayed_as_none():
    """A published answer must never be summarised as one the run did not accept.

    The absence gate publishes a verified report with the coverage it did not
    reach stated beneath it, under its own publication outcome. The console knew
    only the two unqualified outcomes, so every run that took this path told the
    operator it had accepted nothing while the record said it had published.
    """

    summary = summarize_controls(
        {
            "verifier_metrics": {"activated": True, "request_status": "success"},
            "final_answer_metrics": {
                "accepted_source": "verifier",
                "verification_outcome": "verified",
                "publication_outcome": "published_with_stated_bound",
                "published_text_authorship": "model_written",
            },
        },
        run_id="abc123def4567890",
        tool_calls=4,
        findings=2,
    )

    assert summary.verification == "completed"
    assert summary.answer_source == ANSWER_VERIFIED_WITH_BOUND
    assert summary.answer_source != ANSWER_NONE


@pytest.mark.parametrize(
    "verification_outcome",
    [
        "failed_insufficient_evidence",
        "failed_incomplete_verification",
        "failed_cited_evidence_projection",
        "failed_malformed_response",
        "failed_verifier_request",
    ],
)
def test_a_draft_published_after_an_incomplete_check_is_not_displayed_as_none(
    verification_outcome,
):
    """The keep-or-mark backstop publishes the grounded draft under many
    verification outcomes; every one must read as the same caveated answer, not
    as a run that accepted nothing — identified by the published pair, so a new
    inconclusive reason needs no new table row."""

    summary = summarize_controls(
        {
            "verifier_metrics": {"activated": True, "request_status": "error"},
            "final_answer_metrics": {
                "accepted_source": "investigation_model_draft",
                "verification_outcome": verification_outcome,
                "publication_outcome": "published_draft_verification_incomplete",
                "published_text_authorship": "model_written",
            },
        },
        run_id="abc123def4567890",
        tool_calls=4,
        findings=2,
    )

    assert summary.answer_source != ANSWER_NONE
    assert summary.answer_source in _ANSWER_FRAMING
    assert summary.unaccepted_outcome is None


def test_the_console_and_the_diagram_accept_exactly_the_same_outcomes():
    """Two renderers, one vocabulary: neither may know an outcome the other does not.

    Both hand-written copies of this table have now drifted the same way twice —
    first on ``runtime_assembly``, then on the bounded publication — and each
    time one surface reported an accepted answer while the other reported none
    for the same run. The keys are compared rather than the labels, which are
    each renderer's own wording.
    """

    assert set(ACCEPTED_ANSWER_SOURCES) == set(_ACCEPTED_ANSWER_VERDICTS)


def test_every_accepted_answer_has_a_frame_of_its_own_on_the_panel():
    """An accepted answer the panel cannot frame reads as one the run refused.

    The panel falls back to "not accepted by the run" for any verdict it does not
    know, so an accepted source added to the summary without a frame beside it
    reproduces the defect one layer down: the summary saying the run published
    and the panel above it saying the run stood behind nothing.
    """

    unframed = set(ACCEPTED_ANSWER_SOURCES.values()) - set(_ANSWER_FRAMING)
    assert not unframed
