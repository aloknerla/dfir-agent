from __future__ import annotations

import json

from forensic_agent.cli.controlled import _safe_failure_diagnostic

_SECRET = "DO_NOT_PROJECT_VERIFIER_RESPONSE_TEXT"


def test_failure_diagnostic_projects_safe_verifier_failure_metadata() -> None:
    response_digest = "a" * 64
    diagnostic = _safe_failure_diagnostic(
        run_id="run-safe-verifier",
        telemetry={
            "finish_reason": "no_final_answer",
            "verifier_metrics": {
                "validation_failure_code": "non_stop_finish",
                "verification_row_count": 1,
                "raw_response": _SECRET,
            },
            "final_answer_metrics": {"verification_row_count": 1},
            "request_ledger": [
                {
                    "role": "verification",
                    "status": "error",
                    "finish_reason": "length",
                    "error_type": "RuntimeError",
                    "validation_failure_code": "non_stop_finish",
                    "response_content_sha256": response_digest,
                    "response_content_byte_count": 812,
                    "refusal_present": False,
                    "response_content": _SECRET,
                    "reasoning_content": _SECRET,
                    "refusal": _SECRET,
                    "token_usage": {
                        "prompt_tokens": 31,
                        "completion_tokens": 17,
                        "total_tokens": 48,
                        "cost": 0.004,
                        _SECRET: 999,
                    },
                }
            ],
        },
    )

    assert diagnostic["finish_reason"] == "no_final_answer"
    assert diagnostic["phase_metrics"]["verifier_metrics"] == {
        "validation_failure_code": "non_stop_finish",
        "verification_row_count": 1,
    }
    assert diagnostic["phase_metrics"]["final_answer_metrics"] == {"verification_row_count": 1}
    assert diagnostic["model_requests"] == [
        {
            "role": "verification",
            "status": "error",
            "error_type": "RuntimeError",
            "finish_reason": "length",
            "response_content_sha256": response_digest,
            "response_text_present": True,
            "response_content_byte_count": 812,
            "validation_failure_code": "non_stop_finish",
            "refusal_present": False,
            "token_usage": {
                "prompt_tokens": 31,
                "completion_tokens": 17,
                "total_tokens": 48,
                "cost": 0.004,
            },
        }
    ]
    assert _SECRET not in json.dumps(diagnostic, sort_keys=True)


def test_failure_diagnostic_closes_untrusted_codes_and_preserves_runtime_finish() -> None:
    diagnostic = _safe_failure_diagnostic(
        run_id="run-untrusted-verifier",
        telemetry={
            "finish_reason": "completed",
            "verifier_metrics": {
                "validation_failure_code": _SECRET,
                "verification_row_count": True,
            },
            "request_ledger": [
                {
                    "role": "verification",
                    "status": "error",
                    "finish_reason": _SECRET,
                    "validation_failure_code": _SECRET,
                    "response_content_sha256": _SECRET,
                    "response_content_byte_count": -1,
                    "response_content": _SECRET,
                    "token_usage": {_SECRET: 7},
                }
            ],
        },
        exception_type="RuntimeError",
    )

    assert diagnostic["finish_reason"] == "runtime_error"
    assert diagnostic["phase_metrics"]["verifier_metrics"] == {
        "validation_failure_code": "unattributed"
    }
    assert diagnostic["model_requests"] == [
        {
            "role": "verification",
            "status": "error",
            "finish_reason": "unknown",
            "validation_failure_code": "unattributed",
        }
    ]
    assert _SECRET not in json.dumps(diagnostic, sort_keys=True)


def test_failure_diagnostic_preserves_closed_nonretryable_verifier_codes() -> None:
    diagnostic = _safe_failure_diagnostic(
        run_id="run-closed-verifier-codes",
        telemetry={
            "finish_reason": "no_final_answer",
            "verifier_metrics": {
                "validation_failure_code": "inconsistent_completion_state",
                "raw_response": _SECRET,
            },
            "request_ledger": [
                {
                    "role": "verification",
                    "status": "error",
                    "finish_reason": "tool_calls",
                    "validation_failure_code": "unexpected_finish_reason",
                    "response_content": _SECRET,
                    "refusal": _SECRET,
                }
            ],
        },
    )

    assert diagnostic["phase_metrics"]["verifier_metrics"] == {
        "validation_failure_code": "inconsistent_completion_state"
    }
    assert diagnostic["model_requests"] == [
        {
            "role": "verification",
            "status": "error",
            "finish_reason": "tool_calls",
            "response_text_present": False,
            "validation_failure_code": "unexpected_finish_reason",
        }
    ]
    assert _SECRET not in json.dumps(diagnostic, sort_keys=True)


def test_failure_diagnostic_preserves_granular_closed_parser_codes() -> None:
    closed_codes = (
        "invalid_json_syntax",
        "duplicate_json_key",
        "non_object_report",
        "invalid_report_contract",
        "unknown_evidence_reference",
    )

    for code in closed_codes:
        diagnostic = _safe_failure_diagnostic(
            run_id=f"run-{code}",
            telemetry={
                "finish_reason": "no_final_answer",
                "verifier_metrics": {
                    "validation_failure_code": code,
                    "raw_response": _SECRET,
                },
                "request_ledger": [
                    {
                        "role": "verification",
                        "status": "error",
                        "validation_failure_code": code,
                        "response_content": _SECRET,
                    }
                ],
            },
        )

        assert diagnostic["phase_metrics"]["verifier_metrics"] == {"validation_failure_code": code}
        assert diagnostic["model_requests"][0]["validation_failure_code"] == code
        assert _SECRET not in json.dumps(diagnostic, sort_keys=True)
