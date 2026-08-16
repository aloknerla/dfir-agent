"""Objavljeni odgovor ima jedan oblik: tvrdnja, potkrjepa, granice.

Izmjereno po runs/: 15 od 94 objavljena odgovora počinje naslovom ("## Final
Answer", "**Final answer:**", "**Answer: ...**"), jedan naslovom "**Corrected
answer ...**" koji je verifikatorov opis vlastitog zahvata; run 7f3a125b...
objavio je rečenicu unutarnjeg razgovora u drugom licu ("The coverage
limitation you noted does not affect this finding"); a rečenica o pokrivenosti
dodavana je i potvrdnim odgovorima kojima glavna tvrdnja ništa ne niječe.

Objavljeni tekst je normalizirani nacrt istražnog modela. Verifikator vraća samo
strukturirane odluke po tvrdnjama i ne može prepisati tekst odgovora.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from forensic_agent.agent.answer_format import (
    normalize_published_answer,
    reject_internal_model_output,
    reports_pagination_progress_instead_of_finding,
)
from forensic_agent.agent.execution_budget import _DispatchDenied
from forensic_agent.agent.lineage_resolution import RunLineageResolver
from forensic_agent.agent.orchestration import finalization
from forensic_agent.agent.orchestration.finalization import (
    _PUBLICATION_BLOCKERS,
    _empty_final_answer_metrics,
    _finalize_report,
)
from forensic_agent.agent.result_lineage import ResultLineageStore
from forensic_agent.agent.structured_answer import empty_structured_answer_metrics
from forensic_agent.agent.verifier_projection import _empty_verifier_metrics
from forensic_agent.core.repro import canonical_json, sha256_hex
from forensic_agent.reliability import verify as verify_module
from forensic_agent.reliability.verify import (
    VerifierClaimDecision,
    VerifierClaimReport,
    VerifierEvidenceReference,
    VerifierResponseError,
)

# --- the pure helper ---------------------------------------------------------


@pytest.mark.parametrize(
    ("published", "claim"),
    [
        ("## Final Answer\n\nThe value is X.", "The value is X."),
        ("**Final answer:** The value is X.", "The value is X."),
        ("**Answer: Jane Doe**\n\nSupport follows.", "Jane Doe"),
        ("**Corrected answer — 6 programs observed.**", "6 programs observed."),
        ("Final conclusion: The value is X.", "The value is X."),
        ("Answer: The value is X.", "The value is X."),
    ],
)
def test_a_leading_heading_token_is_stripped(published: str, claim: str) -> None:
    normalized, metrics = normalize_published_answer(published)

    assert normalized.startswith(claim)
    assert metrics["heading_stripped"] is True


def test_a_report_with_no_heading_is_untouched() -> None:
    text = "The value is X, recorded in the SOFTWARE hive."

    normalized, metrics = normalize_published_answer(text)

    assert normalized == text
    assert metrics["heading_stripped"] is False
    assert metrics["meta_dialogue_sentences_removed"] == 0


def test_internal_dialogue_sentences_are_removed() -> None:
    """Drugo lice unutarnje provjere ne smije do operatera."""

    text = (
        "The SMTP email address postmaster@mail.example.net was found in the "
        "registry. The coverage limitation you noted does not affect this "
        "finding."
    )

    normalized, metrics = normalize_published_answer(text)

    assert "you noted" not in normalized
    assert "postmaster@mail.example.net" in normalized
    assert metrics["meta_dialogue_sentences_removed"] == 1


def test_process_narration_is_removed_without_rewriting_the_finding() -> None:
    text = (
        "Sada imam dovoljno dokaza. Evo odgovora. "
        "Korisnički agent KRUGKIDGNRQWOIDJOMQHG23BOV2GG5 pronađen je u memoriji."
    )

    normalized, metrics = normalize_published_answer(text)

    assert normalized == ("Korisnički agent KRUGKIDGNRQWOIDJOMQHG23BOV2GG5 pronađen je u memoriji.")
    assert metrics["meta_dialogue_sentences_removed"] == 2


def test_process_phrase_inside_recovered_evidence_is_not_removed() -> None:
    text = (
        "Recovered chat transcript:\nEvo odgovora.\nThe next recovered line is evidentiary content."
    )

    normalized, metrics = normalize_published_answer(text)

    assert normalized == text
    assert metrics["meta_dialogue_sentences_removed"] == 0


@pytest.mark.parametrize(
    "draft",
    [
        # Leaks the raw page cursor "offset 50+" and asserts completeness,
        # while the value the run already held is never stated.
        "Svi preostali dohvaćeni podaci su sada pročitani. Preostale stavke u "
        "registru (offset 50+) odnosile su se samo na pomoćne imeničke unose "
        "– nema dodatnih računa ili postavki. Odgovor o postavkama "
        "poslužitelja je potpun.",
        # Defends coverage with tool-internal flags and names no finding.
        "Primljeno na znanje. Poziv find_files *.log završio je s "
        "coverage.complete=false (dosegnut max_entries uz 124 neobrađena "
        "direktorija). Međutim, konačni odgovor temelji se na potpunom "
        "(coverage.complete=true) izravnom očitanju direktorija.",
        # Pure pagination-completion bookkeeping, no substantive answer.
        "Sve nedovršene stranice su sada pročitane do kraja: svih 214 unosa je "
        "pročitano. Posljednja stranica nema next_offset, što potvrđuje da je "
        "iscrpljena. Nema više nepročitanih rezultata u ovoj sesiji.",
    ],
)
def test_a_pagination_progress_report_is_not_a_publishable_answer(draft: str) -> None:
    """A closing turn that reports only how the pages were read states no finding.

    The value the run gathered lives in a completed tool result; a terminal draft
    that instead recites the page cursor, the coverage flag or "all pages read"
    carries none of it to the operator and must be sent back for one restatement.
    """

    assert reports_pagination_progress_instead_of_finding(draft) is True


@pytest.mark.parametrize(
    "draft",
    [
        "The NNTP news server configured on the workstation is "
        "news.regional.example.net.",
        "The subscribed newsgroups are comp.os.research, sci.crypt.random "
        "and rec.radio.scanner.",
        "The deleted files remain recoverable; the recycle-bin payloads "
        "De5.exe and De6.exe are still allocated.",
        # A stated finding is untouched even when it recites how much was examined.
        "After examining all 214 deleted directory entries, three files are "
        "reported deleted by the file system.",
        # An honest unknown is a legitimate one-line answer, not a process report.
        "The web-based mail address could not be established from the available "
        "evidence.",
        # A bare mention of document pages is not pagination bookkeeping.
        "The exported document contains three pages of transaction records.",
        # A mailbox read-state is a finding about the EVIDENCE, not about the
        # reading of it — "nepročitanih" must stay closed to pagination nouns.
        "Nema više nepročitanih poruka u ulaznoj pošti korisničkog računa.",
    ],
)
def test_a_stated_finding_is_not_flagged_as_a_progress_report(draft: str) -> None:
    assert reports_pagination_progress_instead_of_finding(draft) is False


def test_removal_that_would_empty_the_answer_fails_closed() -> None:
    text = "As you noted, the draft is unsupported."

    normalized, metrics = normalize_published_answer(text)

    assert normalized == ""
    assert metrics["emptied_by_normalization"] is True


def test_normalization_removes_acknowledgement_and_terminal_meta_sentence() -> None:
    text = (
        "Understood. The computer name **`WS-EXAMPLE-07`** was obtained from "
        "the allocated SYSTEM registry hive. The question is answered."
    )

    normalized, metrics = normalize_published_answer(text)

    assert normalized == (
        "The computer name **`WS-EXAMPLE-07`** was obtained from the allocated "
        "SYSTEM registry hive."
    )
    assert metrics["meta_dialogue_sentences_removed"] == 2


def test_normalization_does_not_remove_understood_from_recovered_text() -> None:
    text = "Understood. was the exact recovered text."

    normalized, metrics = normalize_published_answer(text)

    assert normalized == text
    assert metrics["meta_dialogue_sentences_removed"] == 0


def test_normalization_preserves_legitimate_understood_sentence() -> None:
    text = "Understood. Transfer the files."

    assert normalize_published_answer(text)[0] == text


def test_question_answered_sentence_is_removed_only_when_terminal() -> None:
    text = "The question is answered. The observed value is X."

    assert normalize_published_answer(text)[0] == text


def test_question_answered_words_inside_a_factual_sentence_are_preserved() -> None:
    text = "The analyst confirmed the question is answered."

    assert normalize_published_answer(text)[0] == text


def test_complete_hidden_reasoning_block_is_removed() -> None:
    text = "<think>I should inspect the evidence first.</think>The process is svchost.exe."

    normalized, metrics = normalize_published_answer(text)

    assert normalized == "The process is svchost.exe."
    assert metrics["hidden_reasoning_blocks_removed"] == 1
    assert metrics["internal_reasoning_rejected"] is False


def test_publication_gate_rejects_even_a_complete_hidden_reasoning_block() -> None:
    text = "<think>private chain of thought</think>The observed account is alice."

    normalized, metrics = reject_internal_model_output(text)

    assert normalized == ""
    assert metrics["internal_reasoning_rejected"] is True


def test_unclosed_hidden_reasoning_block_fails_closed() -> None:
    normalized, metrics = normalize_published_answer(
        "<think>I should inspect the evidence first. The process is svchost.exe."
    )

    assert normalized == ""
    assert metrics["internal_reasoning_rejected"] is True
    assert metrics["emptied_by_normalization"] is True


def test_internal_protocol_marker_fails_closed() -> None:
    normalized, metrics = normalize_published_answer("<|analysis|>The process is svchost.exe.")

    assert normalized == ""
    assert metrics["internal_reasoning_rejected"] is True
    assert metrics["emptied_by_normalization"] is True


def test_leading_internal_reasoning_phrase_fails_closed() -> None:
    normalized, metrics = normalize_published_answer(
        "Let me analyze the evidence. The process is svchost.exe."
    )

    assert normalized == ""
    assert metrics["internal_reasoning_rejected"] is True
    assert metrics["emptied_by_normalization"] is True


@pytest.mark.parametrize(
    "text",
    [
        "Analysis: I should inspect another artifact. The address is analyst@example.test.",
        "Reasoning: The next step is to compare another result.",
        "**Analysis:** I should inspect another artifact.",
        "## Chain of thought: I should inspect another artifact.",
        (
            "The SMTP e-mail address is analyst@example.test.\n"
            "Reasoning: I selected it after reviewing the evidence."
        ),
        "> Analysis: I should inspect another artifact.",
        "- Reasoning: I should inspect another artifact.",
        "1. Analysis: I should inspect another artifact.",
        (
            "The SMTP e-mail address is analyst@example.test.\n"
            "> **Analysis:** I selected it after reviewing the evidence."
        ),
        "```analysis\nI should inspect another artifact.\n```",
        "~~~reasoning\nI should inspect another artifact.\n~~~",
        "## Analysis\nI should inspect another artifact.",
        "Reasoning — I should inspect another artifact.",
        (
            "The SMTP e-mail address is analyst@example.test.\n"
            "Chain of thought\nI selected it after reviewing the evidence."
        ),
    ],
)
def test_plaintext_internal_reasoning_label_fails_closed(text: str) -> None:
    normalized, metrics = reject_internal_model_output(text)

    assert normalized == ""
    assert metrics["internal_reasoning_rejected"] is True
    assert metrics["emptied_by_normalization"] is True


def test_plaintext_analysis_word_inside_forensic_prose_is_not_a_reasoning_label() -> None:
    text = "The analysis: registry parsing identified the configured account."

    normalized, metrics = reject_internal_model_output(text)

    assert normalized == text
    assert metrics["internal_reasoning_rejected"] is False


def test_ordinary_forensic_prose_remains_unchanged() -> None:
    text = "The process svchost.exe has PID 712 and was observed in memory."

    normalized, metrics = normalize_published_answer(text)

    assert normalized == text
    assert metrics["hidden_reasoning_blocks_removed"] == 0
    assert metrics["internal_reasoning_rejected"] is False


# --- the finalization path ---------------------------------------------------

_AFFIRMATIVE_WITH_SIDE_CLAUSE = (
    "The last recorded shutdown time is 2004-08-27 15:46:33 UTC, from the "
    "ShutdownTime value. No other shutdown records are present in the visible "
    "evidence."
)

_DISK_TOOLS = (
    SimpleNamespace(name="filesystem_query"),
    SimpleNamespace(name="recover_deleted"),
    SimpleNamespace(name="carve_query"),
)
_LISTED_RECORD = {
    "tool": "filesystem_query",
    "arguments": {"operation": "list_directory", "path": "/"},
    "result": {"status": "ok", "data": {"attributes": {}, "items": []}},
}


def _verifier_state(*, draft: str = "DRAFT ANSWER") -> SimpleNamespace:
    state = SimpleNamespace(
        final=draft,
        messages=[SimpleNamespace(type="ai", content=draft)],
        verifier_metrics=_empty_verifier_metrics(activation_reason="not_evaluated"),
        final_answer_metrics=_empty_final_answer_metrics(verification_mode="enabled"),
        structured_answer_metrics=empty_structured_answer_metrics(enabled=False),
        verification_telemetry={"request_ledger": []},
        verification_evidence_present=False,
        dispatch_exhaustion_reason=None,
        identifier_grounding_metrics={},
        evidence_integrity_error=None,
    )
    for blocker in _PUBLICATION_BLOCKERS:
        setattr(state, blocker, False)
    return state


def _verifier_runtime(*, tools=(), records=()) -> SimpleNamespace:
    return SimpleNamespace(
        config=SimpleNamespace(
            verify=True,
            question="Which address did the account use?",
            standardize_tool_results=True,
            verify_model=None,
            model="model-x",
            base_url="http://local",
            api_key="key",
            verification_provider=None,
            verification_provider_quantizations=None,
            decoding_profile=None,
            decoding_parameters=None,
            verification_fail_closed=False,
            sdk_max_retries=1,
            deliver_model_result_envelope=False,
        ),
        execution_budget=None,
        standardized_result_records=list(records),
        tools=list(tools),
        lineage=RunLineageResolver(ResultLineageStore(), case_id="case-1"),
        effective_case_id="case-1",
        cited_value_resolver=None,
        frozen_request_timeout=None,
        investigation_ledger=SimpleNamespace(entries=[]),
        forced_final_ledger=SimpleNamespace(entries=[]),
    )


def _patch_bundle(monkeypatch, *, omitted: int = 0) -> None:
    def fake(messages, *, focus_text, lineage=None, active_case_id=None, **kwargs):
        del messages, focus_text, lineage, active_case_id, kwargs
        metrics = _empty_verifier_metrics(activation_reason="receipt_valid_usable_case_evidence")
        metrics["bundle_omitted_result_count"] = omitted
        metrics["total_truncated"] = omitted > 0
        return canonical_json(
            {
                "schema_id": "forensic.verifier-evidence-bundle.v1",
                "_projection": {
                    "source_result_count": 1,
                    "included_result_count": 1,
                    "total_truncated": omitted > 0,
                    "projection_loss_free": omitted == 0,
                },
                "results": [
                    {
                        "status": "ok",
                        "warnings": [],
                        "data": {"attributes": {"support": "BOUND EVIDENCE"}},
                    }
                ],
            }
        ), metrics

    monkeypatch.setattr(finalization, "_compact_verifier_evidence", fake)


def _patch_bundle_with_citation_loss(
    monkeypatch,
    *,
    overflow: bool = False,
    omitted_citations: int = 0,
) -> None:
    def fake(messages, *, focus_text, lineage=None, active_case_id=None, **kwargs):
        del messages, focus_text, lineage, active_case_id, kwargs
        metrics = _empty_verifier_metrics(activation_reason="receipt_valid_usable_case_evidence")
        metrics["cited_token_overflow"] = overflow
        metrics["omitted_cited_token_count"] = omitted_citations
        return canonical_json(
            {
                "schema_id": "forensic.verifier-evidence-bundle.v1",
                "_projection": {
                    "source_result_count": 1,
                    "included_result_count": 1,
                    "total_truncated": False,
                },
                "results": [
                    {
                        "status": "ok",
                        "warnings": [],
                        "data": {"attributes": {"address": "198.51.100.7"}},
                    }
                ],
            }
        ), metrics

    monkeypatch.setattr(finalization, "_compact_verifier_evidence", fake)


def _patch_grounding(monkeypatch) -> None:
    def fake(final, records, *, case_id, lineage=None):
        del final, records, case_id, lineage
        return True, {"schema_id": "forensic.identifier-grounding.v1", "allowed": True}

    monkeypatch.setattr(finalization, "check_identifier_grounding", fake)


def _patch_verify(
    monkeypatch,
    *,
    verdict: str = "supported",
    answer_complete: bool = True,
    reason: str = "The visible evidence supports the complete claim.",
    output_hygiene: str = "clean",
) -> None:
    def fake(question, draft, claims, evidence, *, telemetry=None, **kwargs):
        attempt_ordinal = kwargs.get("attempt_ordinal", 1)
        response_mode = kwargs.get("response_mode", "json_schema")
        retry_trigger_code = kwargs.get("retry_trigger_code")
        user_content = verify_module.build_verifier_user_content(
            question,
            evidence,
            claims,
            response_mode=response_mode,
            attempt_ordinal=attempt_ordinal,
            retry_trigger_code=retry_trigger_code,
        )
        references = (
            (
                VerifierEvidenceReference(
                    result_index=0,
                    path="/data/attributes/support",
                ),
            )
            if verdict in {"supported", "contradicted"}
            else ()
        )
        report = VerifierClaimReport(
            schema_id="forensic.verifier-claim-report.v2",
            answer_complete=answer_complete,
            completion_reason="All supplied claim units were evaluated.",
            output_hygiene=output_hygiene,
            claims=tuple(
                VerifierClaimDecision(
                    claim_id=claim.claim_id,
                    verdict=verdict,
                    evidence_refs=references,
                    reason=reason,
                )
                for claim in claims
            ),
        )
        serialized_claims = canonical_json(
            {
                "schema_id": "forensic.verifier-claims.v1",
                "claims": [{"claim_id": claim.claim_id, "text": claim.text} for claim in claims],
            }
        )
        canonical_report = canonical_json(report.model_dump(mode="json"))
        rows = telemetry.setdefault("request_ledger", []) if telemetry is not None else None
        if rows is not None:
            rows.append(
                {
                    "role": "verification",
                    "status": "success",
                    "verification_question_sha256": sha256_hex(str(question)),
                    "verification_evidence_sha256": sha256_hex(str(evidence)),
                    "verification_draft_sha256": sha256_hex(str(draft)),
                    "verification_attempt_ordinal": attempt_ordinal,
                    "verification_response_mode": response_mode,
                    "verification_retry_trigger_code": retry_trigger_code,
                    "verification_user_content_sha256": sha256_hex(canonical_json(user_content)),
                    "verification_claims_sha256": sha256_hex(serialized_claims),
                    "verification_claim_report_sha256": sha256_hex(canonical_report),
                }
            )
        return report

    monkeypatch.setattr(verify_module, "verify_claims", fake)


def _patch_retry_verify(
    monkeypatch,
    *,
    first_failure_code: str = "non_stop_finish",
    second_failure_code: str | None = None,
    tamper_first_user_content_hash: bool = False,
):
    calls: list[dict[str, object]] = []

    def fake(
        question,
        draft,
        claims,
        evidence,
        *,
        telemetry=None,
        attempt_ordinal=1,
        response_mode="json_schema",
        retry_trigger_code=None,
        **kwargs,
    ):
        calls.append(
            {
                "attempt_ordinal": attempt_ordinal,
                "response_mode": response_mode,
                "retry_trigger_code": retry_trigger_code,
                "max_retries": kwargs.get("max_retries"),
            }
        )
        serialized_claims = canonical_json(
            {
                "schema_id": "forensic.verifier-claims.v1",
                "claims": [{"claim_id": claim.claim_id, "text": claim.text} for claim in claims],
            }
        )
        user_content = verify_module.build_verifier_user_content(
            question,
            evidence,
            claims,
            response_mode=response_mode,
            attempt_ordinal=attempt_ordinal,
            retry_trigger_code=retry_trigger_code,
        )
        common = {
            "role": "verification",
            "verification_question_sha256": sha256_hex(str(question)),
            "verification_evidence_sha256": sha256_hex(str(evidence)),
            "verification_draft_sha256": sha256_hex(str(draft)),
            "verification_claims_sha256": sha256_hex(serialized_claims),
            "verification_attempt_ordinal": attempt_ordinal,
            "verification_response_mode": response_mode,
            "verification_retry_trigger_code": retry_trigger_code,
            "verification_user_content_sha256": sha256_hex(canonical_json(user_content)),
        }
        if attempt_ordinal == 1 and tamper_first_user_content_hash:
            common["verification_user_content_sha256"] = "0" * 64
        failure_code = first_failure_code if attempt_ordinal == 1 else second_failure_code
        rows = telemetry.setdefault("request_ledger", [])
        if failure_code is not None:
            rows.append(
                {
                    **common,
                    "status": "error",
                    "validation_failure_code": failure_code,
                }
            )
            error = VerifierResponseError(
                failure_code,
                f"RAW_MALFORMED_VERIFIER_CONTENT_{attempt_ordinal}",
            )
            raise RuntimeError("verification model response failed validation") from error

        references = (
            VerifierEvidenceReference(
                result_index=0,
                path="/data/attributes/support",
            ),
        )
        report = VerifierClaimReport(
            schema_id="forensic.verifier-claim-report.v2",
            answer_complete=True,
            completion_reason="Every supplied claim was checked.",
            output_hygiene="clean",
            claims=tuple(
                VerifierClaimDecision(
                    claim_id=claim.claim_id,
                    verdict="supported",
                    evidence_refs=references,
                    reason="The visible evidence supports this claim.",
                )
                for claim in claims
            ),
        )
        canonical_report = canonical_json(report.model_dump(mode="json"))
        rows.append(
            {
                **common,
                "status": "success",
                "verification_claim_report_sha256": sha256_hex(canonical_report),
            }
        )
        return report

    monkeypatch.setattr(verify_module, "verify_claims", fake)
    return calls


@pytest.mark.parametrize(
    "first_failure_code",
    [
        "non_stop_finish",
        "empty_content",
        "invalid_json_or_schema",
        "claim_identity_mismatch",
        "missing_evidence_ref",
        "unknown_result_index",
        "missing_evidence_path",
        "non_scalar_evidence_path",
        "inconsistent_completion_state",
    ],
)
def test_retryable_strict_failure_gets_one_bounded_repair_retry(
    monkeypatch,
    first_failure_code,
) -> None:
    _patch_bundle(monkeypatch)
    _patch_grounding(monkeypatch)
    calls = _patch_retry_verify(monkeypatch, first_failure_code=first_failure_code)
    draft = "The account used the supported address."
    state = _verifier_state(draft=draft)

    _finalize_report(_verifier_runtime(), state)

    assert state.final == draft
    assert state.final_answer_metrics["publication_outcome"] == "published"
    assert state.final_answer_metrics["verification_row_count"] == 2
    assert calls == [
        {
            "attempt_ordinal": 1,
            "response_mode": "json_schema",
            "retry_trigger_code": None,
            "max_retries": 0,
        },
        {
            "attempt_ordinal": 2,
            "response_mode": verify_module.verifier_retry_response_mode(first_failure_code),
            "retry_trigger_code": first_failure_code,
            "max_retries": 0,
        },
    ]
    assert state.verifier_metrics["retry_attempted"] is True
    assert state.verifier_metrics["retry_outcome"] == "success"
    serialized = canonical_json(
        {
            "verifier": state.verifier_metrics,
            "ledger": state.verification_telemetry,
        }
    )
    assert "RAW_MALFORMED_VERIFIER_CONTENT" not in serialized


def test_retry_ledger_rejects_tampered_strict_user_content_hash(monkeypatch) -> None:
    _patch_bundle(monkeypatch)
    _patch_grounding(monkeypatch)
    calls = _patch_retry_verify(monkeypatch, tamper_first_user_content_hash=True)
    state = _verifier_state(draft="The account used the supported address.")

    _finalize_report(_verifier_runtime(), state)

    assert len(calls) == 2
    assert state.final == ""
    assert state.final_answer_metrics["verification_outcome"] == "failed_ledger_binding"
    assert state.final_answer_metrics["publication_outcome"] == "no_accepted_answer"


def test_failed_repair_retry_stays_fail_closed_without_a_third_attempt(
    monkeypatch,
) -> None:
    _patch_bundle(monkeypatch)
    calls = _patch_retry_verify(
        monkeypatch,
        second_failure_code="invalid_json_or_schema",
    )
    state = _verifier_state(draft="The account used the supported address.")

    _finalize_report(_verifier_runtime(), state)

    assert state.final == ""
    assert len(calls) == 2
    assert state.final_answer_metrics["verification_row_count"] == 2
    assert state.final_answer_metrics["verification_outcome"] == "failed_malformed_response"
    assert state.verifier_metrics["retry_outcome"] == "failed"


def test_a_terminal_verifier_failure_publishes_the_bound_draft_with_the_gap_stated(
    monkeypatch,
) -> None:
    """A truncated/refused verifier judged nothing: the grounded draft goes out.

    Izmjereno po runs/: široko pitanje natjera verifikator na izvještaj koji se
    prekine (non_stop_finish), a i retom padne; prije se cijeli gotov nalaz zbog
    toga gubio. Operativni kvar provjere nije presuda o odgovoru, pa se
    ledger-vezani nacrt objavljuje uz izrečenu prazninu.
    """

    _patch_bundle(monkeypatch)
    _patch_grounding(monkeypatch)
    _patch_retry_verify(
        monkeypatch,
        first_failure_code="non_stop_finish",
        second_failure_code="non_stop_finish",
    )
    draft = "The account used the supported address."
    state = _verifier_state(draft=draft)

    _finalize_report(_bound_runtime(draft), state)

    assert state.final.startswith(draft)
    assert "Verification of this answer could not be performed" in state.final
    assert state.final_answer_metrics["verification_outcome"] == "failed_malformed_response"
    assert (
        state.final_answer_metrics["publication_outcome"]
        == "published_draft_verification_incomplete"
    )
    assert state.final_answer_metrics["accepted_source"] == "investigation_model_draft"


def test_a_terminal_verifier_failure_still_withholds_an_unbound_draft(
    monkeypatch,
) -> None:
    """The salvage path binds the draft exactly as the raw arm does: a draft
    that is not a recorded model response is never published on a verifier
    failure either."""

    _patch_bundle(monkeypatch)
    _patch_grounding(monkeypatch)
    _patch_retry_verify(
        monkeypatch,
        first_failure_code="non_stop_finish",
        second_failure_code="non_stop_finish",
    )
    state = _verifier_state(draft="The account used the supported address.")

    _finalize_report(_verifier_runtime(), state)

    assert state.final == ""
    assert state.final_answer_metrics["publication_outcome"] == "no_accepted_answer"


@pytest.mark.parametrize(
    "first_failure_code",
    ["missing_choice", "provider_refusal", "unexpected_finish_reason"],
)
def test_nonretryable_verifier_failure_never_dispatches_compatibility_mode(
    monkeypatch,
    first_failure_code,
) -> None:
    _patch_bundle(monkeypatch)
    calls = _patch_retry_verify(
        monkeypatch,
        first_failure_code=first_failure_code,
    )
    state = _verifier_state(draft="The account used the supported address.")

    _finalize_report(_verifier_runtime(), state)

    assert state.final == ""
    assert len(calls) == 1
    assert state.final_answer_metrics["verification_row_count"] == 1
    assert "retry_attempted" not in state.verifier_metrics


def test_retry_reservation_denial_stops_before_a_second_model_request(
    monkeypatch,
) -> None:
    _patch_bundle(monkeypatch)
    calls = _patch_retry_verify(monkeypatch)

    class RetryDeniedBudget:
        started_monotonic = 0.0

        def __init__(self) -> None:
            self.reservations = 0

        def reserve_model(self, role):
            assert role == "verification"
            self.reservations += 1
            if self.reservations == 2:
                raise _DispatchDenied("max_model_requests")
            return SimpleNamespace(
                remaining_s=30.0,
                started_elapsed_s=0.0,
                started_monotonic=0.0,
                record=lambda: {
                    "schema_id": "forensic.cell-dispatch.v1",
                    "kind": "model",
                    "ordinal": 1,
                    "role": "verification",
                    "remaining_time_s": 30.0,
                    "started_elapsed_s": 0.0,
                },
            )

    runtime = _verifier_runtime()
    runtime.execution_budget = RetryDeniedBudget()
    state = _verifier_state(draft="The account used the supported address.")

    _finalize_report(runtime, state)

    assert state.final == ""
    assert len(calls) == 1
    assert runtime.execution_budget.reservations == 2
    assert state.dispatch_exhaustion_reason == "max_model_requests"
    assert state.final_answer_metrics["verification_outcome"] == "failed_model_budget_exhausted"
    assert state.verifier_metrics["retry_outcome"] == "budget_denied"
    assert state.verifier_metrics["verification_status"] == "failed"
    assert state.verifier_metrics["request_status"] == "not_dispatched"


def test_initial_verification_reservation_denial_marks_verification_failed(
    monkeypatch,
) -> None:
    _patch_bundle(monkeypatch)
    calls = _patch_retry_verify(monkeypatch)

    class AlwaysDeniedBudget:
        started_monotonic = 0.0

        @staticmethod
        def reserve_model(role):
            assert role == "verification"
            raise _DispatchDenied("max_model_requests")

    runtime = _verifier_runtime()
    runtime.execution_budget = AlwaysDeniedBudget()
    state = _verifier_state(draft="The account used the supported address.")

    _finalize_report(runtime, state)

    assert state.final == ""
    assert calls == []
    assert state.dispatch_exhaustion_reason == "max_model_requests"
    assert state.verifier_metrics["verification_status"] == "failed"
    assert state.verifier_metrics["request_status"] == "not_dispatched"
    assert state.final_answer_metrics["verification_outcome"] == "failed_model_budget_exhausted"


def test_the_published_answer_sheds_its_heading(monkeypatch) -> None:
    _patch_bundle(monkeypatch)
    _patch_grounding(monkeypatch)
    _patch_verify(monkeypatch)
    state = _verifier_state(draft="## Final Answer\n\nThe value is X.")

    _finalize_report(_verifier_runtime(), state)

    assert state.final_answer_metrics["publication_outcome"] == "published"
    assert state.final == "The value is X."
    assert state.final_answer_metrics["verification_row_count"] == 1


def test_the_published_answer_sheds_internal_dialogue(monkeypatch) -> None:
    _patch_bundle(monkeypatch)
    _patch_grounding(monkeypatch)
    _patch_verify(monkeypatch)
    state = _verifier_state(
        draft=(
            "The SMTP email address postmaster@mail.example.net was found in the "
            "registry. The coverage limitation you noted does not affect this "
            "finding."
        )
    )

    _finalize_report(_verifier_runtime(), state)

    assert "you noted" not in state.final
    assert "postmaster@mail.example.net" in state.final


def test_a_pure_affirmative_answer_carries_no_coverage_sentence(
    monkeypatch,
) -> None:
    """Rečenica o pokrivenosti ide samo uz odgovor koji sadrži tvrdnju o
    nepostojanju nečega; uz čisto potvrdan odgovor ne kaže ništa o tvrdnji."""

    _patch_bundle(monkeypatch)
    _patch_grounding(monkeypatch)
    _patch_verify(monkeypatch)
    state = _verifier_state(
        draft=(
            "The last recorded shutdown time is 2004-08-27 15:46:33 UTC, from "
            "the ShutdownTime value of the SYSTEM hive."
        )
    )

    _finalize_report(
        _verifier_runtime(tools=_DISK_TOOLS, records=[dict(_LISTED_RECORD)]),
        state,
    )

    assert state.final_answer_metrics["publication_outcome"] == "published"
    assert "Coverage for this run is incomplete" not in state.final


def test_an_answer_containing_a_nonexistence_claim_keeps_its_bound(
    monkeypatch,
) -> None:
    """I usputna niječnica je tvrdnja o nepostojanju: ograda uz nju ostaje.

    Rečenica granice omeđuje točno "anything reported above as not present",
    pa pripada svakom odgovoru koji takvu tvrdnju sadrži, ma gdje u njemu
    stajala.
    """

    _patch_bundle(monkeypatch)
    _patch_grounding(monkeypatch)
    _patch_verify(monkeypatch)
    state = _verifier_state(draft=_AFFIRMATIVE_WITH_SIDE_CLAUSE)

    _finalize_report(
        _verifier_runtime(tools=_DISK_TOOLS, records=[dict(_LISTED_RECORD)]),
        state,
    )

    assert state.final_answer_metrics["publication_outcome"] == "published_with_stated_bound"
    assert "Coverage for this run is incomplete" in state.final


def test_a_bare_absence_report_still_carries_its_bound(monkeypatch) -> None:
    """Prava tvrdnja o nepostojanju i dalje izlazi s izrečenom granicom."""

    _patch_bundle(monkeypatch)
    _patch_grounding(monkeypatch)
    _patch_verify(monkeypatch)
    state = _verifier_state(
        draft="The account's e-mail address could not be established from the evidence."
    )

    _finalize_report(
        _verifier_runtime(tools=_DISK_TOOLS, records=[dict(_LISTED_RECORD)]),
        state,
    )

    assert state.final_answer_metrics["publication_outcome"] == "published_with_stated_bound"
    assert "Coverage for this run is incomplete" in state.final


@pytest.mark.parametrize(
    ("verdict", "answer_complete", "expected_outcome"),
    [
        ("contradicted", True, "flagged_contradicted_claim"),
        ("insufficient_evidence", True, "failed_insufficient_evidence"),
        ("not_checked", True, "failed_incomplete_verification"),
        ("supported", False, "failed_incomplete_verification"),
    ],
)
def test_a_nonapproving_claim_report_withholds_an_unbound_draft(
    monkeypatch,
    verdict: str,
    answer_complete: bool,
    expected_outcome: str,
) -> None:
    """Every advisory verdict now reaches the keep-or-mark backstop, which
    refuses THIS draft only because no recorded model response carries it — the
    same binding the raw arm applies. The verifier itself discards nothing."""

    _patch_bundle(monkeypatch)
    _patch_grounding(monkeypatch)
    _patch_verify(monkeypatch, verdict=verdict, answer_complete=answer_complete)
    state = _verifier_state(draft="The account used the supported address.")

    _finalize_report(_verifier_runtime(), state)

    assert state.final == ""
    assert state.final_answer_metrics["verification_outcome"] == expected_outcome
    assert state.final_answer_metrics["accepted_source"] == "none"
    assert state.final_answer_metrics["publication_outcome"] == "no_accepted_answer"


def _bound_runtime(draft: str, **kwargs) -> SimpleNamespace:
    """A runtime whose ledger records the draft as a genuine model response."""

    runtime = _verifier_runtime(**kwargs)
    runtime.investigation_ledger = SimpleNamespace(
        entries=[{"status": "success", "response_content_sha256": sha256_hex(draft)}]
    )
    return runtime


@pytest.mark.parametrize(
    ("verdict", "answer_complete", "expected_outcome"),
    [
        ("insufficient_evidence", True, "failed_insufficient_evidence"),
        ("not_checked", True, "failed_incomplete_verification"),
        ("supported", False, "failed_incomplete_verification"),
    ],
)
def test_an_inconclusive_claim_report_publishes_the_bound_draft_with_the_gap_stated(
    monkeypatch,
    verdict: str,
    answer_complete: bool,
    expected_outcome: str,
) -> None:
    """Inconclusive is not a judgement: the bound draft goes out saying so.

    Izmjereno po runs/: 21 od 21 neuspjelog runa imalo je gotov nacrt koji je
    završna provjera odbacila, a nijedan zbog verdikta "contradicted" — svaki
    zbog provjere koja je završila bez presude. Nalaz ostaje operateru, s
    izrečenom prazninom umjesto prešućenog odgovora.
    """

    _patch_bundle(monkeypatch)
    _patch_grounding(monkeypatch)
    _patch_verify(monkeypatch, verdict=verdict, answer_complete=answer_complete)
    draft = "The account used the supported address."
    state = _verifier_state(draft=draft)

    _finalize_report(_bound_runtime(draft), state)

    assert state.final.startswith(draft)
    assert "Verification of this answer could not be performed" in state.final
    assert state.final_answer_metrics["verification_outcome"] == expected_outcome
    assert state.final_answer_metrics["verification_decision"] == "advisory"
    assert (
        state.final_answer_metrics["publication_outcome"]
        == "published_draft_verification_incomplete"
    )
    assert state.final_answer_metrics["accepted_source"] == "investigation_model_draft"
    assert state.final_answer_metrics["published_text_authorship"] == "model_written"


def test_a_contradicted_claim_is_published_with_a_strong_caveat(monkeypatch) -> None:
    """The LLM verifier is advisory: a contradicted verdict caveats, never
    discards. The check errs (it has flagged correct derived values), so the
    grounded finding is retained for the examiner with an explicit warning, and
    the deterministic identifier grounding still guards it (tested separately)."""

    _patch_bundle(monkeypatch)
    _patch_grounding(monkeypatch)
    _patch_verify(monkeypatch, verdict="contradicted")
    draft = "The account used the supported address."
    state = _verifier_state(draft=draft)

    _finalize_report(_bound_runtime(draft), state)

    assert state.final.startswith(draft)
    assert "evidence contradicts" in state.final
    assert "final assessment is yours" in state.final
    assert state.final_answer_metrics["verification_outcome"] == "flagged_contradicted_claim"
    assert (
        state.final_answer_metrics["publication_outcome"]
        == "published_draft_verification_incomplete"
    )
    assert state.final_answer_metrics["accepted_source"] == "investigation_model_draft"


def test_a_contradicted_claim_states_its_caveat_before_an_inconclusive_one(
    monkeypatch,
) -> None:
    """When a report carries both a contradicted and an inconclusive verdict, the
    more serious contradicted verdict is read first, so its stronger warning is
    the caveat the published answer carries.
    """

    _patch_bundle(monkeypatch)
    _patch_grounding(monkeypatch)

    def mixed_report(question, draft, claims, evidence, *, telemetry=None, **kwargs):
        attempt_ordinal = kwargs.get("attempt_ordinal", 1)
        response_mode = kwargs.get("response_mode", "json_schema")
        retry_trigger_code = kwargs.get("retry_trigger_code")
        user_content = verify_module.build_verifier_user_content(
            question, evidence, claims,
            response_mode=response_mode,
            attempt_ordinal=attempt_ordinal,
            retry_trigger_code=retry_trigger_code,
        )
        claim_list = list(claims)
        # First claim contradicted, the rest insufficient_evidence.
        decisions = []
        for index, claim in enumerate(claim_list):
            verdict = "contradicted" if index == 0 else "insufficient_evidence"
            refs = (
                (VerifierEvidenceReference(result_index=0, path="/data/attributes/support"),)
                if verdict == "contradicted"
                else ()
            )
            decisions.append(
                VerifierClaimDecision(
                    claim_id=claim.claim_id,
                    verdict=verdict,
                    evidence_refs=refs,
                    reason="A visible value refutes this claim."
                    if verdict == "contradicted"
                    else "The bundle does not carry the supporting value.",
                )
            )
        report = VerifierClaimReport(
            schema_id="forensic.verifier-claim-report.v2",
            answer_complete=True,
            completion_reason="All supplied claim units were evaluated.",
            output_hygiene="clean",
            claims=tuple(decisions),
        )
        rows = telemetry.setdefault("request_ledger", [])
        rows.append(
            {
                "role": "verification",
                "status": "success",
                "verification_question_sha256": sha256_hex(str(question)),
                "verification_evidence_sha256": sha256_hex(str(evidence)),
                "verification_draft_sha256": sha256_hex(str(draft)),
                "verification_claims_sha256": sha256_hex(
                    canonical_json(
                        {
                            "schema_id": "forensic.verifier-claims.v1",
                            "claims": [
                                {"claim_id": c.claim_id, "text": c.text} for c in claim_list
                            ],
                        }
                    )
                ),
                "verification_attempt_ordinal": attempt_ordinal,
                "verification_response_mode": response_mode,
                "verification_retry_trigger_code": retry_trigger_code,
                "verification_user_content_sha256": sha256_hex(canonical_json(user_content)),
                "verification_claim_report_sha256": sha256_hex(
                    canonical_json(report.model_dump(mode="json"))
                ),
            }
        )
        return report

    monkeypatch.setattr(verify_module, "verify_claims", mixed_report)
    draft = "The account used the supported address, and another detail is unclear."
    state = _verifier_state(draft=draft)

    _finalize_report(_bound_runtime(draft), state)

    assert state.final.startswith(draft)
    assert "evidence contradicts" in state.final  # the stronger caveat won
    assert state.final_answer_metrics["verification_outcome"] == "flagged_contradicted_claim"
    assert (
        state.final_answer_metrics["publication_outcome"]
        == "published_draft_verification_incomplete"
    )


def test_the_gap_path_still_blocks_an_ungrounded_identifier(monkeypatch) -> None:
    """The backstop passes the same grounding gate a verified answer passes."""

    _patch_bundle(monkeypatch)
    _patch_verify(monkeypatch, verdict="insufficient_evidence")

    def deny(final, records, *, case_id, lineage=None):
        del final, records, case_id, lineage
        return False, {"schema_id": "forensic.identifier-grounding.v1", "allowed": False}

    monkeypatch.setattr(finalization, "check_identifier_grounding", deny)
    draft = "The account used the supported address."
    state = _verifier_state(draft=draft)

    _finalize_report(_bound_runtime(draft), state)

    assert state.final == ""
    assert state.identifier_grounding_blocked is True
    assert (
        state.final_answer_metrics["publication_outcome"] == "blocked_identifier_grounding"
    )


def test_the_verifier_cannot_rewrite_the_published_draft(monkeypatch) -> None:
    _patch_bundle(monkeypatch)
    _patch_grounding(monkeypatch)
    _patch_verify(
        monkeypatch,
        reason="REWRITTEN REPLACEMENT TEXT that must never be published.",
    )
    draft = "The original finding is supported. Its wording must remain unchanged."
    state = _verifier_state(draft=draft)

    _finalize_report(_verifier_runtime(), state)

    assert state.final_answer_metrics["publication_outcome"] == "published"
    assert state.final_answer_metrics["published_text_origin"] == "investigation_model_draft"
    assert state.final == draft
    assert "REWRITTEN REPLACEMENT TEXT" not in state.final


def test_hidden_reasoning_in_a_draft_is_never_sent_or_published(monkeypatch) -> None:
    _patch_bundle(monkeypatch)

    def must_not_run(*args, **kwargs):
        del args, kwargs
        raise AssertionError("the verifier must not receive hidden reasoning")

    monkeypatch.setattr(verify_module, "verify_claims", must_not_run)
    state = _verifier_state(draft="<think>private reasoning</think>The observed account is alice.")

    _finalize_report(_verifier_runtime(), state)

    assert state.final == ""
    assert (
        state.final_answer_metrics["verification_outcome"] == "failed_internal_reasoning_exposure"
    )
    assert state.verifier_metrics["activated"] is False
    assert state.final_answer_metrics["verification_row_count"] == 0


def test_a_verifier_hygiene_flag_caveats_a_bound_answer_rather_than_discarding(
    monkeypatch,
) -> None:
    """The LLM verifier's own hygiene flag is advisory. The deterministic
    reject_internal_model_output already ran on the draft before the verifier, so
    real leaked reasoning was caught there; this softer second opinion caveats
    the grounded answer instead of withholding it."""

    _patch_bundle(monkeypatch)
    _patch_grounding(monkeypatch)
    _patch_verify(
        monkeypatch,
        output_hygiene="planning_or_self_talk",
    )
    draft = "The account used the supported address."
    state = _verifier_state(draft=draft)

    _finalize_report(_bound_runtime(draft), state)

    assert state.final.startswith(draft)
    assert "process or reasoning commentary" in state.final
    assert state.final_answer_metrics["verification_outcome"] == "flagged_output_hygiene"
    assert state.final_answer_metrics["verification_decision"] == "advisory"
    assert (
        state.final_answer_metrics["publication_outcome"]
        == "published_draft_verification_incomplete"
    )
    assert state.verifier_metrics["output_hygiene"] == "planning_or_self_talk"


@pytest.mark.parametrize(
    ("overflow", "omitted_citations", "expected"),
    [
        (True, 0, "failed_cited_value_bound"),
        (False, 1, "failed_cited_evidence_projection"),
    ],
)
def test_citation_retention_loss_withholds_an_unbound_draft(
    monkeypatch,
    overflow: bool,
    omitted_citations: int,
    expected: str,
) -> None:
    _patch_bundle_with_citation_loss(
        monkeypatch,
        overflow=overflow,
        omitted_citations=omitted_citations,
    )
    state = _verifier_state(draft="The address is 198.51.100.7.")

    _finalize_report(_verifier_runtime(), state)

    assert state.final == ""
    assert state.final_answer_metrics["verification_outcome"] == expected
    assert state.final_answer_metrics["verification_decision"] == "inconclusive"
    assert state.final_answer_metrics["publication_outcome"] == "no_accepted_answer"


@pytest.mark.parametrize(
    ("overflow", "omitted_citations", "expected"),
    [
        (True, 0, "failed_cited_value_bound"),
        (False, 1, "failed_cited_evidence_projection"),
    ],
)
def test_citation_retention_loss_publishes_the_bound_draft_with_the_gap_stated(
    monkeypatch,
    overflow: bool,
    omitted_citations: int,
    expected: str,
) -> None:
    """A projection that could not carry what the answer cites judged nothing:
    the bound draft is published stating that, and the verifier is never
    dispatched for it."""

    _patch_bundle_with_citation_loss(
        monkeypatch,
        overflow=overflow,
        omitted_citations=omitted_citations,
    )
    _patch_grounding(monkeypatch)

    def must_not_run(*args, **kwargs):
        del args, kwargs
        raise AssertionError("the verifier must not be dispatched on this path")

    monkeypatch.setattr(verify_module, "verify_claims", must_not_run)
    draft = "The address is 198.51.100.7."
    state = _verifier_state(draft=draft)

    _finalize_report(_bound_runtime(draft), state)

    assert state.final.startswith(draft)
    assert "Verification of this answer could not be performed" in state.final
    assert state.final_answer_metrics["verification_outcome"] == expected
    assert state.final_answer_metrics["verification_decision"] == "inconclusive"
    assert (
        state.final_answer_metrics["publication_outcome"]
        == "published_draft_verification_incomplete"
    )
    assert state.final_answer_metrics["verification_row_count"] == 0
