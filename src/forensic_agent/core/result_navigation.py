"""Reading a result's own navigation state, and citing one field of it.

A model sees a bounded projection of a result whose complete payload lives
outside its context.  Working with the whole result therefore has to happen
through statements the result makes about itself, never through an impression of
how full the page looked.  Three such statements live here, and all are read from
the envelope rather than inferred:

* **whether more of the result set exists** — :func:`page_continuation`.  The
  page envelope already carries ``truncated``, ``next_offset``, ``next_cursor``,
  ``offset``, ``returned`` and ``total``; each says something slightly
  different, and a caller that consulted only one of them would conclude
  "complete" from a page that plainly is not.  One reader states the fact once,
  for both contracts, so the agent loop and the model-facing description cannot
  come to different answers about the same page.
* **WHICH KIND of continuation reaches it** — :func:`result_continuation`.  Two
  utterly different things are called "getting the next page".  Either the
  complete result is already held by the run and the model was simply shown less
  of it, in which case the rest is served from the store and nothing new is
  observed; or the TOOL stopped short of the requested scope, in which case
  reaching the rest means running it again and observing something new.  The
  route is decided from what the result states — the projection marker and the
  cursor the runtime issued with it — never from a guess about why a page looked
  short, because guessing wrong either invents observations that never happened
  or reports an unfinished analysis as a finished one.
* **which exact value a later call is talking about** — :class:`RecordReference`.
  A model that retypes a value has asserted it; a model that cites the
  invocation and the path to the field has pointed at evidence.  Only the second
  can be resolved, verified and audited afterwards, which is why the citation,
  not the text, is what travels.

Nothing here opens evidence, runs a tool or re-derives a result: it reads a
result that already exists.  Both envelope versions are accepted through
:mod:`forensic_agent.core.result_reading`, because a reader bound to one of them
would silently treat the other as "no page at all".
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from forensic_agent.core.result_contract import PageUnit
from forensic_agent.core.result_reading import (
    AnyToolResult,
    read_result,
    receipt_is_valid,
)

#: How the next page of a result set may be requested, as the envelope states it.
#:
#: ``exhausted`` — the envelope states that nothing remains.
#: ``offset`` — a strictly advancing numeric continuation is available.
#: ``cursor`` — the producer issued an opaque cursor; the offset is not usable.
#: ``nonresumable`` — more exists, but this envelope offers no safe way to ask
#: for it (a truncated page with no usable next offset, for instance).  This is
#: deliberately distinct from ``exhausted``: treating it as completeness is
#: exactly how a partial result becomes an "exhaustive" claim.
ContinuationKind = Literal["exhausted", "offset", "cursor", "nonresumable"]


class FieldPathError(ValueError):
    """A citation named a path this result does not resolve to a single value."""


@dataclass(frozen=True, slots=True)
class PageContinuation:
    """What one result states about the rest of its own result set."""

    unit: PageUnit
    offset: int
    returned: int
    total: int | None
    truncated: bool
    next_offset: int | None
    next_cursor: str | None
    #: Stated fact, not an impression: any one of a truncation flag, a
    #: continuation offset, a cursor, or a total that exceeds what this page
    #: covered is the producer saying that more of the set exists.
    has_more: bool
    kind: ContinuationKind
    #: The exact next offset, or ``None`` when this page offers no safe one.
    #: Strict by construction (see :func:`page_continuation`), so a caller may
    #: use it directly as the next call's cursor without re-checking it.
    resumable_offset: int | None


def page_continuation(value: Any) -> PageContinuation:
    """Read one result's stated page position, for either contract.

    ``has_more`` is the disjunction of everything the envelope can use to say
    that the set continues.  ``resumable_offset`` is deliberately much stricter
    than ``has_more``, because the two answer different questions: the first is
    "is this page the whole set?", the second is "may I ask for the next page by
    number, from this page alone?".  An offset is returned only when it advances
    by exactly the number of records this page returned, strictly increases, and
    stays below a known total — anything else would either re-request the page
    forever or step over records that were never read.
    """

    # ``read_result`` returns an already-parsed result unchanged and refuses
    # anything that declares no readable envelope, so an unreadable value fails
    # loudly here instead of being reported as a complete, single-page result.
    page = read_result(value).page
    minimum_total = page.offset + page.returned
    has_more = bool(
        page.truncated
        or page.next_offset is not None
        or page.next_cursor is not None
        or (page.total is not None and minimum_total < page.total)
    )
    resumable = _resumable_offset(
        offset=page.offset,
        returned=page.returned,
        total=page.total,
        truncated=page.truncated,
        next_offset=page.next_offset,
    )
    if not has_more:
        kind: ContinuationKind = "exhausted"
    elif resumable is not None:
        kind = "offset"
    elif page.next_cursor is not None:
        kind = "cursor"
    else:
        kind = "nonresumable"
    return PageContinuation(
        unit=page.unit,
        offset=page.offset,
        returned=page.returned,
        total=page.total,
        truncated=page.truncated,
        next_offset=page.next_offset,
        next_cursor=page.next_cursor,
        has_more=has_more,
        kind=kind,
        resumable_offset=resumable,
    )


def _resumable_offset(
    *,
    offset: int,
    returned: int,
    total: int | None,
    truncated: bool,
    next_offset: int | None,
) -> int | None:
    """Return a next offset that is safe to re-issue, or ``None``.

    ``bool`` is rejected explicitly before ``int``: in Python ``True`` is an
    ``int``, and a boolean smuggled into a continuation offset would be accepted
    as position 1 and silently skip the first record.
    """

    if not truncated:
        return None
    if isinstance(next_offset, bool) or not isinstance(next_offset, int):
        return None
    # The offset must land exactly after what this page delivered, and it must
    # move.  Together those two also rule out a page that returned nothing: its
    # only consistent next offset is its own, and re-issuing an identical call
    # is a loop rather than a continuation.
    if next_offset != offset + returned or next_offset <= offset:
        return None
    if total is not None and next_offset >= total:
        return None
    return next_offset


# ---------------------------------------------------------------------------
# Which KIND of continuation a result states is available for it.
# ---------------------------------------------------------------------------

#: What a projection states when it withheld part of a result the run holds in
#: full.  Written by the model-facing boundary, so a reader never has to infer
#: "the model saw less than the run retained" from how full the page looked.
PROJECTION_TRUNCATED_ATTRIBUTE = "projection_truncated"

#: The opaque cursor the runtime issued for that withheld remainder, when it
#: could issue one.  Its ABSENCE is meaningful and must not be read as "there is
#: nothing more": it says the remainder is not servable from the store, and the
#: page's own next offset is then the route — a new call, observing anew.
PAGE_CURSOR_ATTRIBUTE = "page_cursor"

#: What a served window states about itself, so "this document continues an
#: earlier one" is a fact on the record rather than something inferred from a
#: non-zero offset.
CONTINUED_VIEW_ATTRIBUTE = "continued_view"

#: How the rest of a result is reached, as the result itself states it.
#:
#: ``projection_page`` — the run holds the complete result and the model was
#: shown less of it; the remainder is READ FROM THE STORE, no tool runs, and no
#: new invocation exists because nothing new is observed.
#: ``analytical_call`` — the tool did not process the whole requested scope;
#: reaching the rest is a new supervised call, recorded as a new invocation.
#: ``unreachable`` — more exists and this result offers no safe way to ask for
#: it.  Deliberately not folded into either of the others: it is a coverage limit
#: the run has to disclose, not a page someone forgot to fetch.
#: ``exhausted`` — the result states that nothing remains.
ContinuationRoute = Literal[
    "projection_page", "analytical_call", "unreachable", "exhausted"
]


@dataclass(frozen=True, slots=True)
class ResultContinuation:
    """Which continuation one result states is available, and on what basis."""

    route: ContinuationRoute
    page: PageContinuation
    #: Stated by the projection marker: part of a result the run retained never
    #: reached the model.  Independent of ``page.has_more``, which after a
    #: projection describes the view rather than the tool's own window.
    projection_withheld: bool
    page_cursor: str | None
    #: The stated fact the route rests on, in words, so a refusal or a plan can
    #: quote why it went the way it did instead of asserting it.
    basis: str


def result_continuation(value: Any) -> ResultContinuation:
    """Read which kind of continuation one result states, for either contract.

    The order of the tests is the whole point.  A projection that withheld
    records ALSO carries a next offset, because the page describes what the model
    received; taking that offset would re-run the tool over material the run
    already holds, recording an observation that never happened.  So a stored
    remainder wins whenever the runtime issued a cursor for it, and the tool's
    own remainder is reached only once there is no stored one left.
    """

    result = read_result(value)
    page = page_continuation(result)
    attributes = result.data.attributes
    withheld = attributes.get(PROJECTION_TRUNCATED_ATTRIBUTE) is True
    raw_cursor = attributes.get(PAGE_CURSOR_ATTRIBUTE)
    cursor = raw_cursor.strip() if isinstance(raw_cursor, str) and raw_cursor.strip() else None
    if withheld and cursor is not None:
        route: ContinuationRoute = "projection_page"
        basis = (
            "the result states that its model-visible view was shortened and "
            "carries the cursor the runtime issued for the retained remainder"
        )
    elif page.resumable_offset is not None:
        route = "analytical_call"
        basis = (
            "the page states a next offset that follows exactly what it delivered, "
            "so the rest is reached by calling the function again"
        )
    elif page.has_more:
        route = "unreachable"
        basis = (
            "the page states that more of the set exists but offers no continuation "
            "that can be taken safely from it"
        )
    else:
        route = "exhausted"
        basis = "the page states that nothing of this result set remains"
    return ResultContinuation(
        route=route,
        page=page,
        projection_withheld=withheld,
        page_cursor=cursor,
        basis=basis,
    )


# ---------------------------------------------------------------------------
# Citing one field of one result.
# ---------------------------------------------------------------------------

#: The citation path grammar.  Deliberately tiny: dotted object keys and
#: bracketed array indices, nothing else.  There is no wildcard, no slice and no
#: predicate, because a citation must name exactly ONE value — a path that could
#: match several would let the resolved value change between two calls that
#: quoted the same handle.
_PATH_SEGMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_PATH_INDEX = re.compile(r"\[(\d+)\]")

FIELD_PATH_SYNTAX = (
    "dotted keys with bracketed array indices, rooted at the result envelope, "
    "for example data.items[3].command_line or data.attributes.content_text"
)


def parse_field_path(path: str) -> tuple[str | int, ...]:
    """Split a citation path into object keys and array indices, or raise."""

    if not isinstance(path, str) or not path.strip():
        raise FieldPathError("a citation path must be non-empty text")
    text = path.strip()
    steps: list[str | int] = []
    position = 0
    expect_key = True
    while position < len(text):
        if expect_key:
            match = _PATH_SEGMENT.match(text, position)
            if match is None:
                raise FieldPathError(f"citation path {path!r} is not valid: {FIELD_PATH_SYNTAX}")
            steps.append(match.group(0))
            position = match.end()
            expect_key = False
            continue
        index = _PATH_INDEX.match(text, position)
        if index is not None:
            steps.append(int(index.group(1)))
            position = index.end()
            continue
        if text[position] == ".":
            position += 1
            expect_key = True
            continue
        raise FieldPathError(f"citation path {path!r} is not valid: {FIELD_PATH_SYNTAX}")
    if expect_key:
        raise FieldPathError(f"citation path {path!r} is not valid: {FIELD_PATH_SYNTAX}")
    return tuple(steps)


def resolve_field_path(result: AnyToolResult | Mapping[str, Any], path: str) -> str:
    """Return the single scalar one citation path names, as text, or raise.

    A citation resolves to a scalar only.  Returning a subtree would let a later
    call consume a structure whose shape the citation never pinned, and the
    whole point of a handle is that what it names cannot drift.
    """

    wire = result if isinstance(result, Mapping) else result.model_dump(mode="json")
    current: Any = wire
    for step in parse_field_path(path):
        if isinstance(step, int):
            if not isinstance(current, Sequence) or isinstance(current, (str, bytes)):
                raise FieldPathError(f"citation path {path!r} indexes a value that is not an array")
            if step >= len(current):
                raise FieldPathError(f"citation path {path!r} indexes past the end of the array")
            current = current[step]
            continue
        if not isinstance(current, Mapping) or step not in current:
            raise FieldPathError(f"citation path {path!r} names a field this result does not have")
        current = current[step]
    if isinstance(current, bool) or not isinstance(current, (str, int, float)):
        raise FieldPathError(
            f"citation path {path!r} does not resolve to a single citable value"
        )
    return current if isinstance(current, str) else str(current)


def citable_field_paths(
    result: AnyToolResult | Mapping[str, Any], *, limit: int = 64
) -> tuple[str, ...]:
    """Every text-valued path of the evidence payload, in document order.

    Offered so a refused citation can name what WOULD have been citable instead
    of only saying no; the caller then quotes one of these rather than inventing
    a path or, worse, retyping the value.  Bounded, because a large page must not
    turn one refusal into an unbounded message.
    """

    wire = result if isinstance(result, Mapping) else result.model_dump(mode="json")
    data = wire.get("data")
    if not isinstance(data, Mapping):
        return ()
    found: list[str] = []

    def walk(node: Any, prefix: str) -> None:
        if len(found) >= limit:
            return
        if isinstance(node, str):
            found.append(prefix)
            return
        if isinstance(node, Mapping):
            for key, child in node.items():
                if isinstance(key, str) and _PATH_SEGMENT.fullmatch(key):
                    walk(child, f"{prefix}.{key}")
            return
        if isinstance(node, Sequence) and not isinstance(node, (str, bytes)):
            for index, child in enumerate(node):
                walk(child, f"{prefix}[{index}]")

    attributes = data.get("attributes")
    if isinstance(attributes, Mapping):
        walk(attributes, "data.attributes")
    items = data.get("items")
    if isinstance(items, Sequence) and not isinstance(items, (str, bytes)):
        walk(list(items), "data.items")
    return tuple(found[:limit])


@dataclass(frozen=True, slots=True)
class RecordReference:
    """A stable handle to one field of one earlier result.

    The identifier half (``invocation_id`` plus ``payload_sha256``) says WHICH
    call, and commits to that call's exact content; the ``field_path`` half says
    which value inside it.  Neither half carries the value, which is the point:
    a handle can be resolved and re-verified later, while a retyped value can
    only be believed.
    """

    invocation_id: str
    payload_sha256: str
    case_id: str | None
    field_path: str


def reference_to(result: AnyToolResult | Mapping[str, Any], field_path: str) -> RecordReference:
    """Build a citable handle to one field of a receipt-valid result, or raise.

    The receipt is verified first.  A handle minted over a result whose own
    receipt does not match its payload would commit to a digest that never
    described that content, so the handle would resolve to nothing — or, worse,
    to whatever a later payload happened to hold under the same path.
    """

    parsed = result if not isinstance(result, Mapping) else read_result(result)
    if not receipt_is_valid(parsed):
        raise FieldPathError("a citable handle requires a result whose receipt verifies")
    receipt = parsed.receipt
    if receipt is None:  # pragma: no cover - receipt_is_valid already rejects this
        raise FieldPathError("a citable handle requires a receipted result")
    resolve_field_path(parsed, field_path)
    return RecordReference(
        invocation_id=parsed.provenance.invocation_id,
        payload_sha256=receipt.payload_sha256,
        case_id=parsed.provenance.case_id,
        field_path=field_path.strip(),
    )


__all__ = [
    "CONTINUED_VIEW_ATTRIBUTE",
    "FIELD_PATH_SYNTAX",
    "PAGE_CURSOR_ATTRIBUTE",
    "PROJECTION_TRUNCATED_ATTRIBUTE",
    "ContinuationKind",
    "ContinuationRoute",
    "FieldPathError",
    "PageContinuation",
    "RecordReference",
    "ResultContinuation",
    "citable_field_paths",
    "page_continuation",
    "parse_field_path",
    "reference_to",
    "resolve_field_path",
    "result_continuation",
]
