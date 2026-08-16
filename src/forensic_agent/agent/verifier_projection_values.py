"""Deterministic value compaction used by the final verifier projection.

This module owns the bounded, data-only transformations applied before an
authenticated tool result is packed into the verifier input.  The orchestration
that validates receipts, selects complete results, and assembles telemetry
remains in :mod:`forensic_agent.agent.verifier_projection`.
"""

from __future__ import annotations

import math
import re
from collections.abc import Collection, Mapping

from forensic_agent.core.repro import canonical_json

_VERIFIER_STRING_LIMIT_BYTES = 2_048
_VERIFIER_TYPE_LIMIT_BYTES = 256
_VERIFIER_COVERAGE_TEXT_LIMIT_BYTES = 256
_VERIFIER_WARNING_CODE_LIMIT_BYTES = 128
_VERIFIER_WARNING_MESSAGE_LIMIT_BYTES = 768
_VERIFIER_WARNINGS_LIMIT_BYTES = 2_048
_VERIFIER_METADATA_INTEGER_MAX = (1 << 63) - 1
_VERIFIER_MAX_ITEMS = 64
_VERIFIER_MAX_WARNINGS = 16
_VERIFIER_MAX_DEPTH = 6
_VERIFIER_SOURCE_SCAN_LIMIT = 512
_VERIFIER_FOCUS_TOKEN_LIMIT = 128
#: How many disjoint focus windows one long string may keep.  One window can
#: land on a decoy match ("Friendly chat...") and exclude the cited value;
#: several windows keep every distinct matched token in view.
_VERIFIER_STRING_WINDOWS = 4
_VERIFIER_PRIMARY_COVERAGE_ITEMS = 16
_VERIFIER_FOCUS_TOKEN_RE = re.compile(r"[a-z0-9]{3,}")
_ATOMIC_CITED_TOKEN_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_VERIFIER_ITEM_SELECTION_POLICY_ID = "cited-first-focus-relevance-balanced-coverage-v3"


def _verifier_focus_tokens(value: str) -> tuple[str, ...]:
    """Return a small, deterministic token set derived only from question/draft text."""

    tokens: list[str] = []
    seen: set[str] = set()
    for match in _VERIFIER_FOCUS_TOKEN_RE.finditer(value.casefold()):
        token = match.group(0)
        if token in seen:
            continue
        seen.add(token)
        tokens.append(token)
        if len(tokens) >= _VERIFIER_FOCUS_TOKEN_LIMIT:
            break
    return tuple(tokens)


#: What one window separator costs in the serialized bundle: the ellipsis is
#: three UTF-8 bytes, framed by two spaces.
_WINDOW_SEPARATOR = " … "
_WINDOW_SEPARATOR_COST = 5


def _bounded_utf8_text(
    value: str,
    limit: int,
    *,
    focus_tokens: tuple[str, ...] = (),
    cited_tokens: tuple[str, ...] = (),
) -> tuple[str, bool]:
    """Return an exact or focus-windowed string bounded after JSON escaping.

    The verifier limits are limits on the serialized model input, not merely on
    the source string's UTF-8 representation.  JSON can expand one control byte
    to six bytes (``\\u0000``), so raw-byte clipping alone does not enforce the
    advertised result ceiling.  Per-character encoded costs let us choose the
    deterministic windows without repeatedly serializing prefixes.

    One window per distinct matched token, up to a small cap, rather than one
    window total: a single window centred on the longest match can land in a
    channel list ("Friendly chat...") and exclude the cited user section of the
    same complete file, so the verifier then sees only the channel list.
    ``cited_tokens`` — value-shaped tokens the
    draft states — are windowed before ordinary focus tokens, so the material a
    claim rests on is never the part a decoy match squeezes out.
    """

    if limit <= 0:
        return "", bool(value)

    def encoded_cost(character: str) -> int:
        codepoint = ord(character)
        if character in {'"', "\\"} or character in {"\b", "\f", "\n", "\r", "\t"}:
            return 2
        if codepoint < 0x20:
            return 6
        return len(character.encode("utf-8"))

    costs = [encoded_cost(character) for character in value]
    if sum(costs) <= limit:
        return value, False

    def first_match(token: str) -> tuple[int, int] | None:
        if not token.isascii():
            return None
        match = re.search(re.escape(token), value, flags=re.IGNORECASE | re.ASCII)
        return None if match is None else (match.start(), match.end())

    # Cited tokens first, longest first within each tier, so the selection is
    # deterministic and the material a claim rests on wins the window slots.
    candidates: list[tuple[int, int]] = []
    for tier in (cited_tokens, focus_tokens):
        for token in sorted(set(tier), key=lambda item: (-len(item), item)):
            span = first_match(token)
            if span is not None:
                candidates.append(span)

    if not candidates:
        end = 0
        used = 0
        while end < len(value) and used + costs[end] <= limit:
            used += costs[end]
            end += 1
        return value[:end], True

    selected: list[tuple[int, int]] = []
    for span in candidates:
        if len(selected) >= _VERIFIER_STRING_WINDOWS:
            break
        if any(
            span[0] < existing[1] + limit // (2 * _VERIFIER_STRING_WINDOWS)
            and existing[0] < span[1] + limit // (2 * _VERIFIER_STRING_WINDOWS)
            for existing in selected
        ):
            # Close enough to an already-selected match that one window will
            # cover both; a second slot there would buy nothing new.
            continue
        selected.append(span)
    selected.sort()

    window_budget = (limit - _WINDOW_SEPARATOR_COST * (len(selected) - 1)) // max(1, len(selected))

    windows: list[tuple[int, int]] = []
    for focus_start, focus_end in selected:
        focus_cost = sum(costs[focus_start:focus_end])
        if focus_cost > window_budget:
            end = focus_start
            used = 0
            while end < focus_end and used + costs[end] <= window_budget:
                used += costs[end]
                end += 1
            windows.append((focus_start, end))
            continue
        start = focus_start
        end = focus_end
        used = focus_cost
        before_budget = (window_budget - used) // 3
        used_before = 0
        while start > 0 and used_before + costs[start - 1] <= before_budget:
            start -= 1
            used_before += costs[start]
            used += costs[start]
        while end < len(value) and used + costs[end] <= window_budget:
            used += costs[end]
            end += 1
        while start > 0 and used + costs[start - 1] <= window_budget:
            start -= 1
            used += costs[start]
        windows.append((start, end))

    merged: list[tuple[int, int]] = []
    for start, end in windows:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return _WINDOW_SEPARATOR.join(value[start:end] for start, end in merged), True


def _bounded_verifier_count(value: int | None) -> tuple[int | None, bool]:
    """Keep projection counters finite-width so metadata cannot bypass byte caps."""

    if value is None:
        return None, False
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not (0 <= value <= _VERIFIER_METADATA_INTEGER_MAX)
    ):
        return None, True
    return value, False


def _text_contains_token(text: str, token: str) -> bool:
    """Whether serialized candidate text carries a cited token.

    Candidate text is canonical JSON, where a backslash arrives doubled, so a
    cited path has to be checked in both spellings or every Windows path would
    silently fail the containment test.
    """

    haystack = text.casefold()
    needle = token.casefold()
    if _ATOMIC_CITED_TOKEN_RE.fullmatch(needle):
        return (
            re.search(
                rf"(?<![a-z0-9]){re.escape(needle)}(?![a-z0-9])",
                haystack,
            )
            is not None
        )
    return needle in haystack or ("\\" in needle and needle.replace("\\", "\\\\") in haystack)


def _compact_verifier_value(
    value,
    *,
    depth: int = 0,
    focus_tokens: tuple[str, ...] = (),
    cited_tokens: tuple[str, ...] = (),
) -> tuple[object | None, bool]:
    """Return deterministic data-only JSON while dropping receipt/provenance noise."""

    if depth >= _VERIFIER_MAX_DEPTH:
        return None, True
    if value is None or isinstance(value, bool | int | float):
        if isinstance(value, float) and not math.isfinite(value):
            return None, True
        return value, False
    if isinstance(value, str):
        text, truncated = _bounded_utf8_text(
            value,
            _VERIFIER_STRING_LIMIT_BYTES,
            focus_tokens=focus_tokens,
            cited_tokens=cited_tokens,
        )
        return text, truncated
    if isinstance(value, Mapping):
        compact: dict[str, object] = {}
        truncated = False
        for raw_key in sorted(value, key=lambda item: str(item)):
            key = str(raw_key)
            nested, nested_truncated = _compact_verifier_value(
                value[raw_key],
                depth=depth + 1,
                focus_tokens=focus_tokens,
                cited_tokens=cited_tokens,
            )
            truncated = truncated or nested_truncated
            if nested is not None or not nested_truncated:
                compact[key] = nested
        return compact, truncated
    if isinstance(value, Collection) and not isinstance(value, bytes | bytearray):
        compact_items: list[object] = []
        truncated = False
        for index, item in enumerate(value):
            if index >= _VERIFIER_MAX_ITEMS:
                truncated = True
                break
            nested, nested_truncated = _compact_verifier_value(
                item,
                depth=depth + 1,
                focus_tokens=focus_tokens,
                cited_tokens=cited_tokens,
            )
            truncated = truncated or nested_truncated
            if nested is not None or not nested_truncated:
                compact_items.append(nested)
        return compact_items, truncated
    return None, True


def _compact_verifier_warnings(
    warnings: Collection[Mapping[str, object]],
    *,
    focus_tokens: tuple[str, ...],
) -> tuple[list[dict[str, object]], bool]:
    """Keep authenticated result limitations visible under a separate byte cap."""

    compact: list[dict[str, object]] = []
    truncated = len(warnings) > _VERIFIER_MAX_WARNINGS
    for warning in list(warnings)[:_VERIFIER_MAX_WARNINGS]:
        code, code_truncated = _bounded_utf8_text(
            str(warning.get("code", "warning")),
            _VERIFIER_WARNING_CODE_LIMIT_BYTES,
            focus_tokens=focus_tokens,
        )
        message, message_truncated = _bounded_utf8_text(
            str(warning.get("message", "warning")),
            _VERIFIER_WARNING_MESSAGE_LIMIT_BYTES,
            focus_tokens=focus_tokens,
        )
        truncated = truncated or code_truncated or message_truncated
        row: dict[str, object] = {"code": code, "message": message}
        details, details_truncated = _compact_verifier_value(
            warning.get("details", {}),
            depth=1,
            focus_tokens=focus_tokens,
        )
        truncated = truncated or details_truncated
        if isinstance(details, Mapping) and details:
            row["details"] = dict(details)

        candidate = [*compact, row]
        if len(canonical_json(candidate).encode("utf-8")) > _VERIFIER_WARNINGS_LIMIT_BYTES:
            if "details" in row:
                row.pop("details")
                truncated = True
                candidate = [*compact, row]
            if len(canonical_json(candidate).encode("utf-8")) > (_VERIFIER_WARNINGS_LIMIT_BYTES):
                truncated = True
                continue
        compact.append(row)
    return compact, truncated


def _balanced_candidate_order(indices: list[int]) -> list[int]:
    """Cover the source span first, then deterministically fill remaining positions."""

    if not indices:
        return []
    primary_count = min(len(indices), _VERIFIER_PRIMARY_COVERAGE_ITEMS)
    if primary_count == 1:
        primary_positions = [0]
    else:
        primary_positions = sorted(
            {
                round(index * (len(indices) - 1) / (primary_count - 1))
                for index in range(primary_count)
            }
        )
    primary_values = [indices[position] for position in primary_positions]
    ordered: list[int] = []
    left = 0
    right = len(primary_values) - 1
    while left <= right:
        ordered.append(primary_values[left])
        left += 1
        if left <= right:
            ordered.append(primary_values[right])
            right -= 1
    primary = set(ordered)
    remaining = [value for value in indices if value not in primary]
    left = 0
    right = len(remaining) - 1
    while left <= right:
        ordered.append(remaining[left])
        left += 1
        if left <= right:
            ordered.append(remaining[right])
            right -= 1
    return ordered


def _interleave_candidate_orders(*orders: list[int]) -> list[int]:
    """Merge ranking policies without letting any one policy consume every slot."""

    merged: list[int] = []
    seen: set[int] = set()
    for position in range(max((len(order) for order in orders), default=0)):
        for order in orders:
            if position >= len(order):
                continue
            source_index = order[position]
            if source_index in seen:
                continue
            seen.add(source_index)
            merged.append(source_index)
    return merged


def _compact_verifier_items(
    value: object,
    *,
    focus_tokens: tuple[str, ...],
    cited_tokens: tuple[str, ...] = (),
) -> tuple[list[tuple[int, object]], bool, int]:
    """Project list evidence with claim relevance and deterministic source coverage.

    Items carrying a cited value are selected FIRST, in source order, before the
    relevance/coverage interleave fills the remaining slots.  Relevance scoring
    zeroes any token common across candidates, which is right for prose words
    and measurably wrong for the one row a draft cites when its words also
    appear elsewhere — cited containment is exact and owes nothing to frequency.
    """

    if not isinstance(value, Collection) or isinstance(value, str | bytes | bytearray):
        return [], value not in (None, [], ()), 0
    source_items = list(value)
    source_count = len(source_items)
    # The ordinary coverage sample is bounded, but cited values must not depend
    # on landing on one of its evenly spaced indices. Scan source rows only for
    # the bounded cited-token set, then reserve at least one row for every token
    # actually present. Extra matching rows fill the remaining cited slots by
    # specificity before ordinary coverage candidates are considered.
    cited_matches: dict[int, tuple[str, ...]] = {}
    if cited_tokens:
        for source_index, source_item in enumerate(source_items):
            source_text = canonical_json(source_item).casefold()
            matches = tuple(
                token for token in cited_tokens if _text_contains_token(source_text, token)
            )
            if matches:
                cited_matches[source_index] = matches

    cited_scan_indices: list[int] = []
    covered_tokens: set[str] = set()
    for token in cited_tokens:
        if token in covered_tokens:
            continue
        options = [
            source_index
            for source_index, matches in cited_matches.items()
            if token in matches and source_index not in cited_scan_indices
        ]
        if not options:
            continue
        selected = min(
            options,
            key=lambda source_index: (
                -len(set(cited_matches[source_index]) - covered_tokens),
                source_index,
            ),
        )
        cited_scan_indices.append(selected)
        covered_tokens.update(cited_matches[selected])
    for source_index in sorted(
        (index for index in cited_matches if index not in cited_scan_indices),
        key=lambda index: (-len(cited_matches[index]), index),
    ):
        if len(cited_scan_indices) >= _VERIFIER_MAX_ITEMS:
            break
        cited_scan_indices.append(source_index)

    coverage_slots = max(
        0,
        _VERIFIER_SOURCE_SCAN_LIMIT - len(cited_scan_indices),
    )
    if source_count <= coverage_slots:
        coverage_indices = list(range(source_count))
    elif coverage_slots == 0:
        coverage_indices = []
    elif coverage_slots == 1:
        coverage_indices = [0]
    else:
        coverage_indices = sorted(
            {
                round(index * (source_count - 1) / (coverage_slots - 1))
                for index in range(coverage_slots)
            }
        )
    scanned_indices = sorted(set(coverage_indices).union(cited_scan_indices))

    candidates: dict[int, object] = {}
    candidate_text: dict[int, str] = {}
    nested_truncated = False
    for source_index in scanned_indices:
        compact, was_truncated = _compact_verifier_value(
            source_items[source_index],
            depth=1,
            focus_tokens=focus_tokens,
            cited_tokens=cited_tokens,
        )
        nested_truncated = nested_truncated or was_truncated
        if compact is None and was_truncated:
            continue
        candidates[source_index] = compact
        candidate_text[source_index] = canonical_json(compact).casefold()

    document_frequency = {
        token: sum(token in text for text in candidate_text.values()) for token in focus_tokens
    }
    maximum_discriminative_frequency = max(1, len(candidate_text) // 3)

    def relevance(source_index: int) -> int:
        text = candidate_text[source_index]
        return sum(
            (len(token) ** 2 * 1_000_000) // document_frequency[token]
            for token in focus_tokens
            if (0 < document_frequency[token] <= maximum_discriminative_frequency and token in text)
        )

    reserved_cited = [
        source_index for source_index in cited_scan_indices if source_index in candidates
    ]
    reserved_cited_set = set(reserved_cited)
    cited = reserved_cited + [
        source_index
        for source_index in sorted(candidates)
        if source_index not in reserved_cited_set
        if any(_text_contains_token(candidate_text[source_index], token) for token in cited_tokens)
    ]
    relevant = sorted(
        (source_index for source_index in candidates if relevance(source_index) > 0),
        key=lambda source_index: (-relevance(source_index), source_index),
    )
    coverage_order = _balanced_candidate_order(sorted(candidates))
    # Cited rows take their slots outright; only the remainder is shared by the
    # interleave.  An interleaved cited row could still lose its slot to a long
    # relevance tail, which is the guarantee this ordering exists to give.
    cited_set = set(cited)
    ordered_indices = cited + [
        source_index
        for source_index in _interleave_candidate_orders(relevant, coverage_order)
        if source_index not in cited_set
    ]
    retained_indices = ordered_indices[:_VERIFIER_MAX_ITEMS]
    projected = [(source_index, candidates[source_index]) for source_index in retained_indices]
    truncated = (
        nested_truncated
        or len(scanned_indices) < source_count
        or len(retained_indices) < len(candidates)
    )
    return projected, truncated, source_count
