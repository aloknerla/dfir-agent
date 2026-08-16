"""Bounded projection of receipt-valid evidence for final verification."""

from __future__ import annotations

import json
from collections.abc import Collection, Mapping
from typing import TYPE_CHECKING, Any, cast

from forensic_agent.agent.draft_citations import select_cited_value_tokens
from forensic_agent.agent.verifier_projection_values import (  # noqa: F401
    _VERIFIER_COVERAGE_TEXT_LIMIT_BYTES,
    _VERIFIER_FOCUS_TOKEN_LIMIT,
    _VERIFIER_FOCUS_TOKEN_RE,
    _VERIFIER_ITEM_SELECTION_POLICY_ID,
    _VERIFIER_MAX_DEPTH,
    _VERIFIER_MAX_ITEMS,
    _VERIFIER_MAX_WARNINGS,
    _VERIFIER_METADATA_INTEGER_MAX,
    _VERIFIER_PRIMARY_COVERAGE_ITEMS,
    _VERIFIER_SOURCE_SCAN_LIMIT,
    _VERIFIER_STRING_LIMIT_BYTES,
    _VERIFIER_TYPE_LIMIT_BYTES,
    _VERIFIER_WARNING_CODE_LIMIT_BYTES,
    _VERIFIER_WARNING_MESSAGE_LIMIT_BYTES,
    _VERIFIER_WARNINGS_LIMIT_BYTES,
    _balanced_candidate_order,
    _bounded_utf8_text,
    _bounded_verifier_count,
    _compact_verifier_items,
    _compact_verifier_value,
    _compact_verifier_warnings,
    _interleave_candidate_orders,
    _text_contains_token,
    _verifier_focus_tokens,
)
from forensic_agent.core.repro import canonical_json

if TYPE_CHECKING:
    from forensic_agent.core.result_contract import DerivationLineageResolver

#: The bundle exists to bound the verifier's reading, not to starve it: a cap
#: the wide runs cannot fit turns their correct findings into "not verifiable
#: from the bounded projection" and the whole answer is lost with them.  The
#: verifier runs on the same long-context investigation model, so the total is
#: sized for the widest run the tool-call budget allows (20 results) to keep a
#: readable share for every result.  Telemetry records the realized values; a
#: result carrying a draft-cited value packs first and may use the full
#: per-result ceiling instead of its even share.
_VERIFIER_RESULT_LIMIT_BYTES = 32_768
_VERIFIER_TOTAL_LIMIT_BYTES = 262_144

#: The smallest per-result share the packer will aim for. Below roughly this size
#: a result carries its ``_projection`` counters and little else, so shrinking
#: further buys room without buying the verifier anything it can read.
_VERIFIER_RESULT_FLOOR_BYTES = 1_024

#: What the bundle wrapper costs before a single result is added: its schema id,
#: its ``_projection`` block and the surrounding punctuation. Computed against
#: ``_verifier_evidence_bundle([])`` and rounded up, because a share computed
#: from the total alone leaves no room for it and omits the last result.
_VERIFIER_BUNDLE_OVERHEAD_BYTES = 512

#: Conservative serialized cost of one result's projection bookkeeping.  Cited
#: payload sizing happens before the final counters are attached, so it reserves
#: this space rather than allowing a promoted value to crowd out its own
#: truncation and coverage metadata.
_VERIFIER_PROJECTION_BLOCK_BYTES = 1_024

#: How many refused or failed calls the bundle names, and how much of each one's
#: text it carries. Bounded for the same reason every projection here is: one
#: run's obstacles must not crowd out the evidence.
_VERIFIER_MAX_OBSTACLES = 8
_VERIFIER_OBSTACLE_TEXT_BYTES = 300

_VERIFIER_RESULT_SELECTION_POLICY_ID = "cited-first-share-balanced-result-coverage-v7"

#: How many dropped attributes one result's projection will name.  Naming is
#: the point — a silently vanished attribute is the defect this guards against — but the
#: list itself must not become the byte problem it documents.
_VERIFIER_MAX_OMITTED_ATTRIBUTE_RECORDS = 16


def _result_share_bytes(candidate_count: int) -> int:
    """The byte target one result is packed to when the run produced many.

    The failure this exists for: a run making twenty memory calls filled
    the bundle with four results at the full per-result ceiling and dropped the
    other sixteen whole. The verifier is instructed to decline a draft claim whose
    supporting row is outside the projection, so a bundle that omits most of a run
    turns correct findings into "not verifiable from the bounded projection" —
    which is what it did.

    A result the ceiling shortened is still in front of the verifier; a result the
    ceiling refused to carry at all is one it never saw. So the total is divided
    across the candidates rather than spent on the first few, and the floor keeps
    the share large enough to carry rows rather than counters alone.
    """

    room = _VERIFIER_TOTAL_LIMIT_BYTES - _VERIFIER_BUNDLE_OVERHEAD_BYTES
    share = room // max(1, candidate_count)
    return min(_VERIFIER_RESULT_LIMIT_BYTES, max(_VERIFIER_RESULT_FLOOR_BYTES, share))


def _cited_payload_bytes(
    *,
    status: str,
    warnings,
    compact_type: str,
    attributes,
    items,
    cited_tokens: tuple[str, ...],
) -> int:
    """What a result would cost carrying its cited material and nothing else.

    Promotion is sized, not granted. A run over a capture cited a value from each
    of many pages, every one was promoted to the full per-result ceiling, four of
    them exhausted the hard total on their own, and the fifth — which carried the
    cited row the answer rested on — was dropped whole at bundle level.
    """

    def carries(value: object) -> bool:
        serialized = canonical_json(value).casefold()
        return any(_text_contains_token(serialized, token) for token in cited_tokens)

    payload: dict[str, object] = {"type": compact_type}
    if isinstance(attributes, Mapping):
        cited_attributes = {
            key: value for key, value in attributes.items() if carries({key: value})
        }
        if cited_attributes:
            payload["attributes"] = cited_attributes
    if isinstance(items, list):
        cited_items = [value for _index, value in items if carries(value)]
        if cited_items:
            payload["items"] = cited_items
    document = {"status": status, "warnings": tuple(warnings), "data": payload}
    return len(canonical_json(document).encode("utf-8")) + _VERIFIER_PROJECTION_BLOCK_BYTES


def _admissible_result_estimate(messages) -> int:
    """How many tool results the bundle may have to carry, counted before packing.

    An upper bound, not the admitted count: admission validates receipts, case
    binding and lineage, and running that twice to size the share would double the
    cost of the check. Over-estimating shrinks each share slightly, which costs
    detail inside a result; under-estimating would let the ceiling drop whole
    results again, which is the failure this sizing exists to prevent.
    """

    total = 0
    for message in messages or []:
        if getattr(message, "type", None) == "tool":
            content = getattr(message, "content", None)
        elif isinstance(message, Mapping) and message.get("role") == "tool":
            content = message.get("content")
        else:
            continue
        total += len(_tool_content_candidates(content))
    return total


def _tool_content_candidates(content) -> list[Mapping[str, object]]:
    values: list[Mapping[str, object]] = []
    if isinstance(content, Mapping):
        values.append(content)
    elif isinstance(content, str):
        try:
            parsed = json.loads(content)
        except (TypeError, json.JSONDecodeError):
            return values
        if isinstance(parsed, Mapping):
            values.append(parsed)
    elif isinstance(content, Collection) and not isinstance(content, bytes | bytearray):
        for item in content:
            if isinstance(item, Mapping) and isinstance(item.get("text"), str):
                values.extend(_tool_content_candidates(item["text"]))
            else:
                values.extend(_tool_content_candidates(item))
    return values


def _empty_verifier_metrics(*, activation_reason: str) -> dict[str, object]:
    """Return the complete evidence-free verifier telemetry shape."""

    return {
        "schema_id": "forensic.verifier-input-metrics.v2",
        "results_seen": 0,
        "receipt_valid_case_results": 0,
        "usable_case_results": 0,
        "included_results": 0,
        "status_ok_results": 0,
        "status_partial_results": 0,
        "coverage_complete_results": 0,
        "coverage_incomplete_results": 0,
        "rejected_invalid_or_unreceipted": 0,
        "rejected_non_case_evidence": 0,
        "rejected_error_or_blocked": 0,
        "rejected_empty_or_metadata_only": 0,
        "source_incomplete_result_count": 0,
        "projection_truncated_result_count": 0,
        "bundle_omitted_result_count": 0,
        "per_result_truncated_count": 0,
        "omitted_attribute_count": 0,
        "cited_token_count": 0,
        "cited_token_overflow": False,
        "source_cited_token_count": 0,
        "retained_cited_token_count": 0,
        "omitted_cited_token_count": 0,
        "total_truncated": False,
        "input_bytes": 0,
        "per_result_limit_bytes": _VERIFIER_RESULT_LIMIT_BYTES,
        "per_result_share_bytes": _VERIFIER_RESULT_LIMIT_BYTES,
        "total_limit_bytes": _VERIFIER_TOTAL_LIMIT_BYTES,
        "activated": False,
        "activation_reason": activation_reason,
    }


def _verifier_evidence_bundle(
    results: list[dict[str, object]],
    *,
    source_result_count: int,
    total_truncated: bool,
    obstacles: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    per_result_projection_loss_free = all(
        isinstance(result.get("data"), Mapping)
        and isinstance(cast(Mapping[str, object], result["data"]).get("_projection"), Mapping)
        and cast(
            Mapping[str, object],
            cast(Mapping[str, object], result["data"])["_projection"],
        ).get("projection_loss_free")
        is True
        for result in results
    )
    return {
        "schema_id": "forensic.verifier-evidence-bundle.v1",
        "_projection": {
            "selection_policy_id": _VERIFIER_RESULT_SELECTION_POLICY_ID,
            "source_result_count": source_result_count,
            "included_result_count": len(results),
            "retained_source_order_preserved": True,
            "total_truncated": total_truncated,
            "projection_loss_free": (not total_truncated and per_result_projection_loss_free),
        },
        "results": results,
        # What the run TRIED and could not do. These are not evidence and can
        # support no claim, which is why they are kept out of ``results``; they
        # are here so a draft cannot deny an obstacle its own run met.
        #
        # Measured: a run called for extraction, the call came back saying the
        # archive was encrypted and no password had been supplied, and the
        # published answer stated there was no record of an error or of any
        # encryption. The check passed it, because a failed call is not
        # admissible evidence and never reached the bundle at all.
        "obstacles": list(obstacles or ()),
    }


def _record_obstacle(obstacles: list[dict[str, object]], result) -> None:
    """Keep a bounded note of one call the run could not complete."""

    if len(obstacles) >= _VERIFIER_MAX_OBSTACLES:
        return
    error = getattr(result, "error", None)
    reason = getattr(getattr(result, "coverage", None), "reason", None)
    note: dict[str, object] = {
        "tool": str(getattr(getattr(result, "provenance", None), "tool_name", "") or ""),
        "status": getattr(getattr(result, "status", None), "value", ""),
    }
    if error is not None:
        note["code"] = str(getattr(error, "code", "") or "")
        note["message"] = str(getattr(error, "message", "") or "")[:_VERIFIER_OBSTACLE_TEXT_BYTES]
    if reason:
        note["coverage_reason"] = str(reason)[:_VERIFIER_OBSTACLE_TEXT_BYTES]
    obstacles.append(note)


def _compact_verifier_evidence(
    messages,
    *,
    focus_text: str = "",
    citation_text: str | None = None,
    question_text: str | None = None,
    lineage: DerivationLineageResolver | None = None,
    active_case_id: str | None = None,
) -> tuple[str, dict[str, object]]:
    """Build a bounded, claim-aware projection of admissible case evidence.

    This is the final check for the verification pass: nothing the verifier is
    allowed to reason from enters the bundle without passing it.  The artifact
    judged here is the MODEL-VISIBLE projection, because that is the document
    these messages carry and therefore the one the decision is made from; the
    complete standardized result the run retained keeps its own receipt and is
    judged where it is used.

    ``question_text`` is control context for the closed bare-filename matcher;
    the question itself is removed from citation extraction. ``lineage`` and
    ``active_case_id`` bind the evidence check to the run: the resolver is the
    runtime authority over the trusted oversight chain and the case's attested
    sources. With no resolver bound, a result of the active contract is refused,
    because its own receipt is the only thing left to check it against and a
    receipt can be recomputed by whoever edited the payload.
    """

    # Both contracts are read here.  A candidate of the other contract would
    # otherwise fail validation and be counted as invalid, silently emptying the
    # verifier's evidence bundle while every telemetry check still balanced.
    from forensic_agent.core.result_admission import result_passes_final_check
    from forensic_agent.core.result_contract import ProvenanceType, ToolStatus
    from forensic_agent.core.result_reading import (
        UnreadableResult,
        is_candidate_case_evidence,
        read_result,
        receipt_is_valid,
    )

    metrics = cast(
        dict[str, Any],
        _empty_verifier_metrics(activation_reason="not_evaluated"),
    )
    focus_tokens = _verifier_focus_tokens(focus_text)
    # Value-shaped tokens the draft cites. A result, attribute, item or
    # string window carrying one is packed FIRST and may use the full per-result
    # ceiling: the residual failures this prevents were all a cited value silently
    # squeezed out by an even share, after which the verifier — correctly, by
    # its own rules — declined the claim that rested on it.
    cited_tokens, cited_token_overflow = select_cited_value_tokens(
        focus_text if citation_text is None else citation_text,
        question=question_text,
    )
    metrics["cited_token_count"] = len(cited_tokens)
    metrics["cited_token_overflow"] = cited_token_overflow
    result_share_bytes = _result_share_bytes(_admissible_result_estimate(messages))
    metrics["per_result_share_bytes"] = result_share_bytes
    candidate_results: list[tuple[int, dict[str, object]]] = []
    obstacles: list[dict[str, object]] = []
    source_cited_tokens: set[str] = set()
    for message in messages or []:
        if getattr(message, "type", None) == "tool":
            content = getattr(message, "content", None)
        elif isinstance(message, Mapping) and message.get("role") == "tool":
            content = message.get("content")
        else:
            continue
        for candidate in _tool_content_candidates(content):
            metrics["results_seen"] = int(metrics["results_seen"]) + 1
            structured = candidate.get("structuredContent")
            wire = structured if isinstance(structured, Mapping) else candidate
            try:
                result = read_result(wire)
            except (TypeError, UnreadableResult):
                metrics["rejected_invalid_or_unreceipted"] = (
                    int(metrics["rejected_invalid_or_unreceipted"]) + 1
                )
                continue
            if not receipt_is_valid(result):
                metrics["rejected_invalid_or_unreceipted"] = (
                    int(metrics["rejected_invalid_or_unreceipted"]) + 1
                )
                continue
            if (
                result.provenance.type is not ProvenanceType.CASE_EVIDENCE
                or not is_candidate_case_evidence(result)
            ):
                metrics["rejected_non_case_evidence"] = (
                    int(metrics["rejected_non_case_evidence"]) + 1
                )
                continue
            metrics["receipt_valid_case_results"] = int(metrics["receipt_valid_case_results"]) + 1
            # The final check.  It subsumes the status rule this branch used to
            # apply on its own and adds everything the historical envelope could
            # not express: the case binding, the trusted oversight binding over
            # this result's actual content, and the grounding of what it claims
            # to have observed or computed over.  A result that fails it is
            # blocked evidence, which is what this counter has always meant, so
            # the frozen runtime-fairness accounting still balances.
            if not result_passes_final_check(
                result, lineage=lineage, active_case_id=active_case_id
            ):
                metrics["rejected_error_or_blocked"] = int(metrics["rejected_error_or_blocked"]) + 1
                _record_obstacle(obstacles, result)
                continue
            # This is the frozen verifier-activation predicate.  Apply it to
            # the validated ToolResult itself, before bounded projection, so
            # compaction can never reclassify usable evidence.  Selecting only
            # ``status``, ``warnings`` and ``data`` below excludes envelope
            # receipt, provenance, implementation metadata, and envelope hashes;
            # hash fields inside evidentiary attributes/items remain legitimate
            # case data.
            if not bool(result.data.attributes or result.data.items):
                metrics["rejected_empty_or_metadata_only"] = (
                    int(metrics["rejected_empty_or_metadata_only"]) + 1
                )
                continue
            metrics["usable_case_results"] = int(metrics["usable_case_results"]) + 1
            if result.status is ToolStatus.OK:
                metrics["status_ok_results"] = int(metrics["status_ok_results"]) + 1
            else:
                metrics["status_partial_results"] = int(metrics["status_partial_results"]) + 1
            coverage_count_incomplete = (
                result.coverage.examined is not None
                and result.coverage.expected is not None
                and result.coverage.examined < result.coverage.expected
            )
            effective_source_coverage_complete = (
                result.coverage.complete and not coverage_count_incomplete
            )
            coverage_key = (
                "coverage_complete_results"
                if effective_source_coverage_complete
                else "coverage_incomplete_results"
            )
            metrics[coverage_key] = int(metrics[coverage_key]) + 1
            raw_data = result.data.model_dump(mode="json")
            # A result carrying a cited value is packed to the full per-result
            # ceiling rather than the even share; the bundle-level packing below
            # places it first, so the hard total still holds and only uncited
            # filler is squeezed.
            raw_citable_text = canonical_json(
                {
                    "attributes": raw_data.get("attributes"),
                    "items": raw_data.get("items"),
                }
            ).casefold()
            result_cited_tokens = {
                token for token in cited_tokens if _text_contains_token(raw_citable_text, token)
            }
            source_cited_tokens.update(result_cited_tokens)
            carries_cited = bool(result_cited_tokens)

            raw_warnings = [warning.model_dump(mode="json") for warning in result.warnings]
            warnings, warnings_truncated = _compact_verifier_warnings(
                raw_warnings,
                focus_tokens=focus_tokens,
            )
            attributes, attributes_truncated = _compact_verifier_value(
                raw_data.get("attributes"),
                focus_tokens=focus_tokens,
                cited_tokens=cited_tokens,
            )
            items, items_truncated, source_item_count = _compact_verifier_items(
                raw_data.get("items"),
                focus_tokens=focus_tokens,
                cited_tokens=cited_tokens,
            )
            compact_type, type_truncated = _bounded_utf8_text(
                result.data.type,
                _VERIFIER_TYPE_LIMIT_BYTES,
            )
            result_budget = result_share_bytes
            if carries_cited:
                result_budget = min(
                    _VERIFIER_RESULT_LIMIT_BYTES,
                    max(
                        result_share_bytes,
                        _cited_payload_bytes(
                            status=result.status.value,
                            warnings=warnings,
                            compact_type=compact_type,
                            attributes=attributes,
                            items=items,
                            cited_tokens=cited_tokens,
                        ),
                    ),
                )
            coverage_scope, coverage_scope_truncated = (
                (None, False)
                if result.coverage.scope is None
                else _bounded_utf8_text(
                    result.coverage.scope,
                    _VERIFIER_COVERAGE_TEXT_LIMIT_BYTES,
                    focus_tokens=focus_tokens,
                )
            )
            coverage_reason, coverage_reason_truncated = (
                (None, False)
                if result.coverage.reason is None
                else _bounded_utf8_text(
                    result.coverage.reason,
                    _VERIFIER_COVERAGE_TEXT_LIMIT_BYTES,
                    focus_tokens=focus_tokens,
                )
            )
            bounded_counts = {
                "coverage_examined": _bounded_verifier_count(result.coverage.examined),
                "coverage_expected": _bounded_verifier_count(result.coverage.expected),
                "page_offset": _bounded_verifier_count(result.page.offset),
                "page_returned": _bounded_verifier_count(result.page.returned),
                "page_total": _bounded_verifier_count(result.page.total),
                "page_next_offset": _bounded_verifier_count(result.page.next_offset),
                "source_item_count": _bounded_verifier_count(source_item_count),
            }
            metadata_count_truncated = any(
                was_truncated for _value, was_truncated in bounded_counts.values()
            )
            page_window_incomplete = (
                result.page.truncated
                or result.page.offset > 0
                or result.page.next_offset is not None
                or result.page.next_cursor is not None
                or (
                    result.page.total is not None
                    and result.page.offset + result.page.returned < result.page.total
                )
            )
            source_incomplete = not effective_source_coverage_complete or page_window_incomplete
            if source_incomplete:
                metrics["source_incomplete_result_count"] = (
                    int(metrics["source_incomplete_result_count"]) + 1
                )
            compact_data: dict[str, object] = {"type": compact_type}
            if isinstance(attributes, Mapping) and attributes:
                compact_data["attributes"] = dict(attributes)
            if items:
                compact_data["items"] = items
            projection_truncated = (
                type_truncated
                or attributes_truncated
                or items_truncated
                or coverage_scope_truncated
                or coverage_reason_truncated
                or warnings_truncated
                or metadata_count_truncated
            )
            # Preserve the original, model-visible projection semantics and
            # backward-compatible aggregate counter.  The additive telemetry
            # above separates source incompleteness from loss introduced by
            # this bounded verifier projection.
            per_result_truncated = (
                projection_truncated or coverage_count_incomplete or page_window_incomplete
            )
            projection: dict[str, object] = {
                "schema_id": "forensic.verifier-evidence-projection.v1",
                "selection_policy_id": _VERIFIER_ITEM_SELECTION_POLICY_ID,
                # A valid receipt authenticates the payload but cannot make
                # contradictory completeness counters semantically true.
                "source_coverage_complete": effective_source_coverage_complete,
                "coverage_scope": coverage_scope,
                "coverage_reason": coverage_reason,
                "coverage_examined": bounded_counts["coverage_examined"][0],
                "coverage_expected": bounded_counts["coverage_expected"][0],
                "page_unit": result.page.unit.value,
                "page_offset": bounded_counts["page_offset"][0],
                "page_returned": bounded_counts["page_returned"][0],
                "page_total": bounded_counts["page_total"][0],
                "page_next_offset": bounded_counts["page_next_offset"][0],
                "page_next_cursor_present": result.page.next_cursor is not None,
                "page_truncated": result.page.truncated,
                "page_window_complete": not page_window_incomplete,
                "source_warning_count": len(result.warnings),
                "retained_warning_count": len(warnings),
                "source_item_count": bounded_counts["source_item_count"][0],
                "retained_item_count": 0,
                "retained_source_order_preserved": True,
                "projection_truncated": per_result_truncated,
                "projection_loss_free": not per_result_truncated,
            }
            # Add deterministic fields incrementally so one result never exceeds
            # its byte ceiling, even after JSON escaping.
            bounded: dict[str, object] = {
                "type": compact_data["type"],
                "_projection": projection,
            }

            def projected_result(
                data: Mapping[str, object],
                *,
                status: str = result.status.value,
                retained_warnings: tuple[dict[str, object], ...] = tuple(warnings),
            ) -> dict[str, object]:
                return {
                    "status": status,
                    "warnings": retained_warnings,
                    "data": dict(data),
                }

            compact_attributes = compact_data.get("attributes")
            omitted_attributes: list[dict[str, object]] = []

            def _carries_cited_value(
                value: object,
                *,
                attribute_key: str | None = None,
            ) -> bool:
                serialized = canonical_json(
                    value if attribute_key is None else {attribute_key: value}
                ).casefold()
                return any(_text_contains_token(serialized, token) for token in cited_tokens)

            if isinstance(compact_attributes, Mapping):
                # Cited-first: the attribute carrying the value a claim rests on
                # is packed before any other spends the budget.  The
                # insertion-order loop would spend the share on eof/path/size and
                # drop the content_text holding the answer, leaving no trace.
                def _attribute_priority(entry: tuple[str, object]) -> int:
                    return (
                        0
                        if _carries_cited_value(
                            entry[1],
                            attribute_key=entry[0],
                        )
                        else 1
                    )

                # Attached before packing so every candidate serialization below
                # already accounts for the record's own bytes; an empty list is
                # removed again once packing is done.
                projection["omitted_attributes"] = omitted_attributes
                retained_attributes: dict[str, object] = {}
                for key, value in sorted(
                    compact_attributes.items(),
                    key=lambda entry: (_attribute_priority(entry), entry[0]),
                ):
                    candidate_data = {
                        **bounded,
                        "attributes": {**retained_attributes, key: value},
                    }
                    if len(canonical_json(projected_result(candidate_data)).encode("utf-8")) > (
                        result_budget
                    ):
                        projection_truncated = True
                        per_result_truncated = True
                        projection["projection_truncated"] = True
                        projection["projection_loss_free"] = False
                        # A dropped attribute leaves its name and source size:
                        # "content_text: 1759 bytes omitted" is a limitation the
                        # verifier can reason about, silence was the defect.
                        raw_attributes = raw_data.get("attributes")
                        source_value = (
                            raw_attributes.get(key) if isinstance(raw_attributes, Mapping) else None
                        )
                        if len(omitted_attributes) < _VERIFIER_MAX_OMITTED_ATTRIBUTE_RECORDS:
                            omitted_attributes.append(
                                {
                                    "name": key,
                                    "source_bytes": len(
                                        canonical_json(source_value).encode("utf-8")
                                    ),
                                }
                            )
                        continue
                    retained_attributes[key] = value
                if retained_attributes:
                    bounded["attributes"] = dict(sorted(retained_attributes.items()))
            compact_items = compact_data.get("items")
            if isinstance(compact_items, list):
                indexed_items = cast(list[tuple[int, object]], compact_items)
                retained_items: list[tuple[int, object]] = []
                for source_index, item in indexed_items:
                    candidate_items = sorted(
                        [*retained_items, (source_index, item)],
                        key=lambda retained: retained[0],
                    )
                    candidate_projection = {
                        **projection,
                        "retained_item_count": len(candidate_items),
                    }
                    candidate_data = {
                        **bounded,
                        "_projection": candidate_projection,
                        "items": [value for _index, value in candidate_items],
                    }
                    if len(canonical_json(projected_result(candidate_data)).encode("utf-8")) > (
                        result_budget
                    ):
                        projection_truncated = True
                        per_result_truncated = True
                        projection["projection_truncated"] = True
                        projection["projection_loss_free"] = False
                        continue
                    retained_items = candidate_items
                    projection["retained_item_count"] = len(retained_items)
                if retained_items:
                    bounded["items"] = [value for _index, value in retained_items]
            if omitted_attributes:
                metrics["omitted_attribute_count"] = int(metrics["omitted_attribute_count"]) + len(
                    omitted_attributes
                )
            elif "omitted_attributes" in projection:
                del projection["omitted_attributes"]
            if source_item_count:
                retained_count = projection.get("retained_item_count")
                if isinstance(retained_count, int):
                    projection["omitted_item_count"] = max(0, source_item_count - retained_count)
            projection["projection_truncated"] = per_result_truncated
            projection["projection_loss_free"] = not per_result_truncated
            candidate_result = projected_result(bounded)
            final_result_bytes = len(canonical_json(candidate_result).encode("utf-8"))
            if final_result_bytes > _VERIFIER_RESULT_LIMIT_BYTES:
                # The attribute and item loops above each budgeted a candidate
                # against result_budget, but this projection block is finalized
                # after them, so a result packed right up to the ceiling can
                # overshoot by the finalized projection's own trailing bytes — and
                # a single retained attribute (a whole named_rows page) can carry
                # most of that weight. Shed the heaviest retained payload — largest
                # attribute first, then items — until the finalized result fits,
                # rather than aborting the entire examination for one result. The
                # per-result ceiling is unchanged and every omission is declared.
                while final_result_bytes > _VERIFIER_RESULT_LIMIT_BYTES:
                    # Whatever the bounded projection still holds this pass;
                    # both keys are written above as a dict and a list, and an
                    # absent one is nothing left to shed.
                    held_attributes = bounded.get("attributes")
                    held_items = bounded.get("items")
                    bounded_attributes: dict[str, object] = (
                        held_attributes if isinstance(held_attributes, dict) else {}
                    )
                    bounded_items: list[object] = (
                        held_items if isinstance(held_items, list) else []
                    )
                    if projection.get("omitted_attributes"):
                        # Omission details are useful diagnostics but cannot
                        # support a claim. Discard them before evidentiary data.
                        projection.pop("omitted_attributes", None)
                    elif any(
                        not _carries_cited_value(value, attribute_key=key)
                        for key, value in bounded_attributes.items()
                    ):
                        removable_attributes = {
                            key: value
                            for key, value in bounded_attributes.items()
                            if not _carries_cited_value(
                                value,
                                attribute_key=key,
                            )
                        }
                        heaviest = max(
                            removable_attributes,
                            key=lambda key: len(
                                canonical_json(removable_attributes[key]).encode("utf-8")
                            ),
                        )
                        source_bytes = len(
                            canonical_json(bounded_attributes[heaviest]).encode("utf-8")
                        )
                        del bounded_attributes[heaviest]
                        if bounded_attributes:
                            bounded["attributes"] = bounded_attributes
                        else:
                            bounded.pop("attributes", None)
                        if (
                            isinstance(omitted_attributes, list)
                            and len(omitted_attributes) < _VERIFIER_MAX_OMITTED_ATTRIBUTE_RECORDS
                        ):
                            omitted_attributes.append(
                                {"name": heaviest, "source_bytes": source_bytes}
                            )
                    elif any(
                        not _carries_cited_value(value) for value in bounded_items
                    ):
                        removable_index = max(
                            (
                                index
                                for index, value in enumerate(bounded_items)
                                if not _carries_cited_value(value)
                            ),
                            key=lambda index: len(
                                canonical_json(bounded_items[index]).encode("utf-8")
                            ),
                        )
                        bounded_items = [
                            value
                            for index, value in enumerate(bounded_items)
                            if index != removable_index
                        ]
                        if bounded_items:
                            bounded["items"] = bounded_items
                        else:
                            bounded.pop("items", None)
                        projection["retained_item_count"] = len(bounded_items)
                        if source_item_count:
                            projection["omitted_item_count"] = max(
                                0, source_item_count - len(bounded_items)
                            )
                    else:
                        break
                    per_result_truncated = True
                    projection_truncated = True
                    projection["projection_truncated"] = True
                    projection["projection_loss_free"] = False
                    candidate_result = projected_result(bounded)
                    final_result_bytes = len(canonical_json(candidate_result).encode("utf-8"))
                if final_result_bytes > _VERIFIER_RESULT_LIMIT_BYTES:
                    raise RuntimeError(
                        "internal verifier projection exceeded its per-result byte ceiling"
                    )
            if per_result_truncated:
                metrics["per_result_truncated_count"] = (
                    int(metrics["per_result_truncated_count"]) + 1
                )
            if projection_truncated:
                metrics["projection_truncated_result_count"] = (
                    int(metrics["projection_truncated_result_count"]) + 1
                )
            source_result_index = len(candidate_results)
            candidate_results.append((source_result_index, candidate_result))

    candidate_text = {
        source_index: canonical_json(candidate).casefold()
        for source_index, candidate in candidate_results
    }
    document_frequency = {
        token: sum(token in text for text in candidate_text.values()) for token in focus_tokens
    }
    maximum_discriminative_frequency = max(1, len(candidate_text) // 3)

    def result_relevance(source_index: int) -> int:
        text = candidate_text[source_index]
        return sum(
            (len(token) ** 2 * 1_000_000) // document_frequency[token]
            for token in focus_tokens
            if (0 < document_frequency[token] <= maximum_discriminative_frequency and token in text)
        )

    relevant_results = sorted(
        (
            source_index
            for source_index, _candidate in candidate_results
            if result_relevance(source_index) > 0
        ),
        key=lambda source_index: (-result_relevance(source_index), source_index),
    )
    coverage_results = _balanced_candidate_order(
        [source_index for source_index, _candidate in candidate_results]
    )
    # Results carrying a cited value pack first, in source order, so the hard
    # total squeezes uncited filler and never the material a claim rests on.
    cited_results = [
        source_index
        for source_index, _candidate in candidate_results
        if any(_text_contains_token(candidate_text[source_index], token) for token in cited_tokens)
    ]
    cited_result_set = set(cited_results)
    packing_order = cited_results + [
        source_index
        for source_index in _interleave_candidate_orders(relevant_results, coverage_results)
        if source_index not in cited_result_set
    ]
    candidate_by_index = dict(candidate_results)
    retained_results: list[tuple[int, dict[str, object]]] = []
    for source_index in packing_order:
        proposed = sorted(
            [*retained_results, (source_index, candidate_by_index[source_index])],
            key=lambda retained: retained[0],
        )
        proposed_documents = [candidate for _index, candidate in proposed]
        proposed_bytes = max(
            len(
                canonical_json(
                    _verifier_evidence_bundle(
                        proposed_documents,
                        source_result_count=len(candidate_results),
                        total_truncated=total_truncated,
                        obstacles=obstacles,
                    )
                ).encode("utf-8")
            )
            for total_truncated in (False, True)
        )
        if proposed_bytes > _VERIFIER_TOTAL_LIMIT_BYTES:
            continue
        retained_results = proposed

    compact_results = [candidate for _index, candidate in retained_results]
    metrics["included_results"] = len(compact_results)
    metrics["bundle_omitted_result_count"] = len(candidate_results) - len(compact_results)
    metrics["total_truncated"] = int(metrics["bundle_omitted_result_count"]) > 0
    retained_cited_tokens: set[str] = set()
    for compact in compact_results:
        data = compact.get("data")
        if not isinstance(data, Mapping):
            continue
        citable_text = canonical_json(
            {
                "attributes": data.get("attributes"),
                "items": data.get("items"),
            }
        ).casefold()
        retained_cited_tokens.update(
            token for token in source_cited_tokens if _text_contains_token(citable_text, token)
        )
    metrics["source_cited_token_count"] = len(source_cited_tokens)
    metrics["retained_cited_token_count"] = len(retained_cited_tokens)
    metrics["omitted_cited_token_count"] = len(source_cited_tokens - retained_cited_tokens)
    evidence = (
        canonical_json(
            _verifier_evidence_bundle(
                compact_results,
                source_result_count=len(candidate_results),
                total_truncated=bool(metrics["total_truncated"]),
                obstacles=obstacles,
            )
        )
        if compact_results
        else ""
    )
    metrics["input_bytes"] = len(evidence.encode("utf-8"))
    if int(metrics["input_bytes"]) > _VERIFIER_TOTAL_LIMIT_BYTES:
        raise RuntimeError("internal verifier projection exceeded its total byte ceiling")
    return evidence, metrics
