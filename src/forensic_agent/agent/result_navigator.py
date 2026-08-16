"""Serving more of a result the run already holds, and the cursors that allow it.

Two continuations look alike from the model's seat and could not be more
different underneath.

* **Projection paging.** The tool ran once, its complete result was captured and
  retained, and only a bounded view of it reached the model.  The rest of that
  result is already in the run's own store, so handing it over observes nothing
  new: no tool executes, no oversight action is taken, and NO NEW INVOCATION is
  recorded, because there is no new observation to record.  The analytical
  coverage of that result cannot change either — reading more of what was
  already analysed does not make the analysis more complete.
* **Analytical continuation.** The tool itself did not process the whole
  requested scope.  Reaching the rest means calling the function again, which is
  a new supervised observation and is recorded as its own invocation.

Confusing the two costs something in both directions.  Re-running an analysis to
re-read records the run already holds fills the record with observations that
never happened; serving a stored page as though the tool had processed more of
the source turns a partial analysis into an exhaustive-looking one.

This module implements the first kind only, and refuses everything it cannot
prove.  The cursor a model presents is an OPAQUE token this runtime issued: it
carries no offset, no digest and no path, so there is nothing in it for a model
to compose, alter or guess, and no way to ask for a window that skips records.
Every fact the cursor stands for is held here and re-checked against the run's
own retained result when the cursor is redeemed — the case, the originating
invocation, that result's payload digest, the function and operation that
produced it, and the filters that were in force.  A cursor that disagrees with
any of them names a page this result does not have, so it is refused rather than
served.
"""

from __future__ import annotations

import secrets
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from langchain_core.tools import StructuredTool
from pydantic import ConfigDict, Field, create_model

from forensic_agent.agent.result_lineage import ResultLineageStore, RetainedResult
from forensic_agent.agent.tool_operations import resolved_operation
from forensic_agent.core.repro import canonical_json
from forensic_agent.core.result_contract import PageUnit
from forensic_agent.core.result_navigation import (
    CONTINUED_VIEW_ATTRIBUTE,
    PAGE_CURSOR_ATTRIBUTE,
    PROJECTION_TRUNCATED_ATTRIBUTE,
)
from forensic_agent.core.result_reading import (
    ACTIVE_SCHEMA_ID,
    AnyToolResult,
    UnreadableResult,
    read_result,
    receipt_is_valid,
)

#: The model-visible name of the navigation function.  It is deliberately not a
#: domain function: it opens no evidence, runs no backend and produces no new
#: observation, so it has no scope, no operations and no epistemic class of its
#: own — it re-serves a result that already has all three.
RESULT_PAGE_TOOL_NAME = "result_page"

#: Refusal codes.  Two of them, because "this run cannot serve stored pages at
#: all" and "this particular cursor names no page here" call for entirely
#: different next moves.
NO_RESULT_STORE_BOUND = "no_result_store_bound"
PAGE_CURSOR_REFUSED = "page_cursor_refused"
#: A stored page redeemed AGAIN after it was already served in full.  Distinct
#: from PAGE_CURSOR_REFUSED so the loop-break is countable apart from a cursor
#: that never named a page here: this one served correctly the first time.
PAGE_CURSOR_ALREADY_SERVED = "page_cursor_already_served"

#: What a served window says about itself, so no reader has to infer "this is a
#: continuation" from the fact that its offset is not zero.
CONTINUED_VIEW_NOTE_ATTRIBUTE = "continued_view_note"


class PageCursorError(ValueError):
    """A page cursor could not be redeemed against this run's retained results."""


class PageCursorExhausted(PageCursorError):
    """A stored page was redeemed again after it had already been served in full.

    A subclass, so the model-visible facade can give the loop-break its own
    refusal code while every existing ``except PageCursorError`` still catches
    it.  The first redemption of a cursor serves its window; a later redemption
    of the SAME cursor would serve byte-identical records the run already holds,
    so it is refused and the model is pointed at the tool's own continuation.
    """


@dataclass(frozen=True, slots=True)
class PageBinding:
    """Everything one issued cursor stands for.

    The model holds only the token; all of this is held here.  Every field is
    re-checked against the run's own retained result at redemption, so a cursor
    can never reach past what it was issued for: another case, another function,
    another result or another set of filters each fail closed.
    """

    case_id: str | None
    invocation_id: str
    #: The retained COMPLETE result's payload digest.  Binding to the content and
    #: not merely to the invocation id is what makes "another result" detectable
    #: at all when what a run holds for an invocation can be replaced.
    payload_sha256: str
    function: str
    operation: str | None
    #: Canonical form of the originating call's arguments: the filters in force
    #: when this page was produced.  A page of a differently filtered query is a
    #: page of a different set, however similar the two calls look.
    filters: str
    #: Where the withheld remainder starts, in the page unit of the result.  The
    #: model never sees or supplies this: it is the runtime's own record of how
    #: far this result has been served.
    offset: int
    unit: PageUnit


class ResultNavigator:
    """Issues page cursors, and serves the pages they stand for.

    Thread-safe for the same reason the lineage store is: tool calls and the
    callbacks that record them are not guaranteed to be serialized by the graph
    runtime, and a half-written cursor table would refuse a legitimate
    continuation for reasons that have nothing to do with the evidence.
    """

    def __init__(self, store: ResultLineageStore, *, case_id: str | None) -> None:
        self._store = store
        self._case_id = case_id
        self._lock = threading.Lock()
        self._bindings: dict[str, PageBinding] = {}
        #: How many times each cursor's window has been served.  A window is a
        #: FIXED slice of a retained result, so serving one twice reaches nothing
        #: new; the count is what turns the second serve into a refusal.
        self._served: dict[str, int] = {}

    # -- issuing -----------------------------------------------------------

    def reserve(self) -> str:
        """Mint an opaque token that is bound to nothing yet.

        Reserved before the projection is shaped and bound only once it has
        settled, because the window a cursor opens is not known until the
        projection has decided how much it could carry.  A token that is never
        bound simply never becomes a cursor: nothing is stored for it, and
        redeeming it fails closed like any other value this runtime did not
        issue.
        """

        return f"page:{secrets.token_urlsafe(24)}"

    def bind(self, token: str, *, projected: object) -> bool:
        """Turn a reserved token into a cursor, or leave it meaningless.

        Returns whether a cursor now exists.  One is issued only when all of the
        following hold, and each is read from a statement rather than inferred:

        * the document the model received STATES that it withheld part of the
          result, so there is a remainder at all, and states where the next
          record starts;
        * the run RETAINED the complete result of that invocation, its receipt
          verifies, it belongs to this case, both documents count the same unit
          and that unit is RECORDS, and the retained result really does hold
          records beyond the ones the model was shown.
        """

        projection = _as_result(projected)
        if projection is None:
            return False
        if projection.data.attributes.get(PROJECTION_TRUNCATED_ATTRIBUTE) is not True:
            return False
        offset = projection.page.next_offset
        if isinstance(offset, bool) or not isinstance(offset, int):
            return False
        retained = self._store.retained(projection.provenance.invocation_id)
        if retained is None:
            return False
        binding = _binding_for(
            retained, case_id=self._case_id, offset=offset, unit=projection.page.unit
        )
        if binding is None:
            return False
        with self._lock:
            self._bindings[token] = binding
        return True

    # -- redeeming ---------------------------------------------------------

    def page(self, cursor: object) -> dict[str, Any]:
        """Serve the page one cursor stands for, or raise :class:`PageCursorError`.

        Nothing executes and nothing is observed: the returned document is the
        retained result of the SAME invocation, windowed at the point this run
        has served that result up to.  Its provenance, coverage, status and
        warnings are the original's untouched, because none of them is a fact
        about the window.
        """

        if not isinstance(cursor, str) or not cursor.strip():
            raise PageCursorError(
                "a page cursor is required, exactly as the previous result gave it"
            )
        with self._lock:
            binding = self._bindings.get(cursor.strip())
        if binding is None:
            raise PageCursorError(
                "this cursor was not issued by this run, so it names no page here; "
                "re-issue the original call to start the enumeration over"
            )
        retained = self._store.retained(binding.invocation_id)
        if retained is None:
            raise PageCursorError(
                "the result this cursor continues is no longer retained by this run"
            )
        result = _as_result(retained.wire)
        if result is None or not receipt_is_valid(result):
            raise PageCursorError(
                "the retained result this cursor continues no longer verifies against "
                "its own receipt"
            )
        # ANOTHER CASE.  The case is re-read from the retained result and matched
        # against both the run and the cursor; the cursor's own claim is never the
        # authority, or a cursor would be able to assert its way across a case
        # boundary.
        if self._case_id not in {result.provenance.case_id, binding.case_id} or (
            result.provenance.case_id != binding.case_id
        ):
            raise PageCursorError(
                "the retained result this cursor continues belongs to another case"
            )
        if result.provenance.tool.name != binding.function:
            raise PageCursorError(
                f"this cursor continues {binding.function}, which is not the function "
                "the run retains under that invocation"
            )
        if resolved_operation(retained.tool, retained.arguments) != binding.operation:
            raise PageCursorError(
                f"this cursor continues the {binding.operation!r} operation, which is "
                "not the operation the run retains under that invocation"
            )
        if canonical_json(dict(retained.arguments)) != binding.filters:
            raise PageCursorError(
                "the filters in force when this cursor was issued are not the filters "
                "of the retained call, so it names a page of a different set"
            )
        receipt = result.receipt
        if receipt is None or receipt.payload_sha256 != binding.payload_sha256:
            # ANOTHER RESULT.  The invocation id still resolves, but not to the
            # content this cursor was cut from, and a window over different
            # content is a different set of records under the same name.
            raise PageCursorError(
                "this cursor was issued over different content than the run now "
                "retains for that invocation"
            )
        if result.page.unit is not binding.unit:  # pragma: no cover - digest implies it
            raise PageCursorError(
                "the retained result no longer pages the unit this cursor counts"
            )
        start = binding.offset - result.page.offset
        if start <= 0 or start >= len(
            result.data.items
        ):  # pragma: no cover - digest implies it
            # Unreachable while the digest above still matches, since the window
            # was checked against this very payload when the cursor was issued.
            # Kept so that no future change to what the store returns can end up
            # publishing an empty window as though it were a page of records.
            raise PageCursorError("no records remain beyond the window this cursor opens")
        # A cursor's window is served ONCE.  binding.offset is frozen, so the
        # window is a fixed slice of a retained result; redeeming the same cursor
        # again returns byte-identical records the run already holds — the paging
        # loop this guards against, where a model that read the final stored
        # window keeps re-passing the same cursor instead of continuing the tool.
        # The first redemption serves; a later one is refused and the model is
        # pointed at the only continuation that reaches NEW records: the tool's
        # own, restated from the retained page rather than invented.
        key = cursor.strip()
        with self._lock:
            served_before = self._served.get(key, 0)
            self._served[key] = served_before + 1
        if served_before:
            page = result.page
            if page.truncated and page.next_offset is not None:
                raise PageCursorExhausted(
                    "this stored page was already served in full; the run holds no "
                    "further stored pages of this result. To read the records beyond "
                    f"it, call {binding.function} again with offset {page.next_offset}, "
                    "which is a new observation and is recorded as one."
                )
            raise PageCursorExhausted(
                f"this stored page was already served in full, and {binding.function} "
                "returned the complete set, so there is nothing more of this result to "
                "read."
            )
        return _windowed_wire(retained.wire, binding)


# ---------------------------------------------------------------------------
# Reading the retained record.  Everything below refuses rather than guesses: a
# record it cannot fully account for yields no cursor and serves no page.
# ---------------------------------------------------------------------------


def _as_result(value: object) -> AnyToolResult | None:
    """Read a value as a result of either contract, or ``None`` if it is not one."""

    try:
        return read_result(value)
    except (TypeError, UnreadableResult):
        return None


def _binding_for(
    retained: RetainedResult, *, case_id: str | None, offset: int, unit: PageUnit
) -> PageBinding | None:
    """What a cursor over one retained result must be bound to, or ``None``.

    ``unit`` is what the document the MODEL received counted; ``page.unit`` is
    what the RETAINED result counts.  Both appear in one condition because the
    offset comes from the first and indexes into the second: if they disagree, a
    byte count would silently become a record index and step over everything
    between.  And both must be records, because a byte window's honest
    continuation is a new call — re-reading a byte range repeats no analysis, so
    offering a stored page for it as well would leave two routes to one
    remainder and nothing to tell them apart by.
    """

    result = _as_result(retained.wire)
    if result is None or not receipt_is_valid(result):
        return None
    receipt = result.receipt
    if receipt is None:  # pragma: no cover - receipt_is_valid already rejects this
        return None
    if result.provenance.case_id != case_id:
        # A cursor over another case's result must not exist, rather than exist
        # and be refused later: an issued cursor is an offer, and this one would
        # be an offer to read across a case boundary.
        return None
    page = result.page
    if page.unit is not unit or unit is not PageUnit.ITEM:
        return None
    start = offset - page.offset
    # The remainder has to EXIST in the retained payload.  ``start == len(items)``
    # is refused too: a window with nothing left in it is not a continuation, it
    # is an invitation to keep asking forever.
    if start <= 0 or start >= len(result.data.items):
        return None
    return PageBinding(
        case_id=result.provenance.case_id,
        invocation_id=result.provenance.invocation_id,
        payload_sha256=receipt.payload_sha256,
        function=result.provenance.tool.name,
        operation=resolved_operation(retained.tool, retained.arguments),
        filters=canonical_json(dict(retained.arguments)),
        offset=offset,
        unit=PageUnit.ITEM,
    )


def _windowed_wire(wire: Mapping[str, Any], binding: PageBinding) -> dict[str, Any]:
    """The retained result carrying only the records from ``binding.offset`` on.

    ``page`` describes what this document delivers, which is the one thing a
    window changes.  ``coverage`` is copied untouched: it states what the TOOL
    examined, and no amount of reading a result the run already holds makes the
    analysis behind it more complete.  Where the tool itself stopped short, its
    own continuation is restated on the last window rather than dropped, so
    paging a projection to its end still leaves the analytical remainder
    reachable.
    """

    result = read_result(wire)
    page = result.page
    window = list(result.data.items)[binding.offset - page.offset :]
    document: dict[str, Any] = {
        key: value for key, value in wire.items() if key != "receipt"
    }
    data = dict(document.get("data") or {})
    attributes = dict(data.get("attributes") or {})
    # A cursor belongs to the projection it was issued with, so any cursor the
    # retained result once carried is stale here; leaving it would hand back a
    # token naming a window the model has already been served.
    attributes.pop(PAGE_CURSOR_ATTRIBUTE, None)
    attributes[CONTINUED_VIEW_ATTRIBUTE] = True
    attributes[CONTINUED_VIEW_NOTE_ATTRIBUTE] = (
        "this view continues the same invocation from a result the run already "
        "held; no tool ran and nothing new was observed, so coverage is unchanged"
    )
    data["attributes"] = attributes
    data["items"] = window
    document["data"] = data
    total = page.total
    end = binding.offset + len(window)
    # Beyond the end of the retained records the only continuation left is the
    # TOOL's own, so it is restated verbatim rather than invented.
    tool_has_more = page.truncated and page.next_offset is not None
    document["page"] = {
        "unit": page.unit.value,
        "offset": binding.offset,
        "returned": len(window),
        "total": total,
        "next_offset": page.next_offset if tool_has_more else None,
        "next_cursor": None,
        "truncated": bool(tool_has_more or (total is not None and end < total)),
    }
    receipted = _receipted(document, schema_version=str(result.schema_version))
    if receipted is None:  # pragma: no cover - the source document already validated
        raise PageCursorError("the retained result could not be re-published as a page")
    return receipted


def _receipted(document: dict[str, Any], *, schema_version: str) -> dict[str, Any] | None:
    """Receipt a windowed document under the contract it came from.

    A window is a different artifact from the result it was cut out of, so it
    earns its own receipt — under the SAME contract, because each canonicalizes
    its own payload and the other one's verifier would attest a payload it never
    covered.
    """

    from forensic_agent.core.result_contract import ToolResult as ActiveResult
    from forensic_agent.core.result_contract import attach_receipt as attach_active
    from forensic_agent.core.tool_result import ToolResult as LegacyResult
    from forensic_agent.core.tool_result import attach_receipt as attach_legacy

    try:
        if schema_version == ACTIVE_SCHEMA_ID:
            return attach_active(ActiveResult.model_validate(document)).model_dump(
                mode="json"
            )
        return attach_legacy(LegacyResult.model_validate(document)).model_dump(mode="json")
    except Exception:
        return None


# ---------------------------------------------------------------------------
# The model-visible function.
# ---------------------------------------------------------------------------

#: Public because the interactive catalog explains this function to the
#: investigator from the SAME text the model is given.  A second description
#: written for ``/tools`` would be free to drift from what the model was told,
#: and the listing exists to state what the model was offered.
RESULT_PAGE_DESCRIPTION = (
    "Read the next records of a result THIS RUN ALREADY HOLDS. When a result you "
    "were given carries data.attributes.page_cursor, the function that produced "
    "it ran once and its complete result was retained; only a bounded view of it "
    "reached you. Passing that cursor here returns the next records of the SAME "
    "result from the run's own store: no tool runs, nothing new is observed, no "
    "new invocation is recorded, and the coverage of that result does not change. "
    "Pass the cursor exactly as it was given. It is opaque, there is no offset to "
    "supply, and a cursor issued for another case, another function or another "
    "result is refused. A result that instead states page.next_offset with no "
    "page_cursor is saying something different: the tool stopped short of the "
    "scope you asked for, so continue by calling THAT function again with the "
    "stated offset, which is a new observation and is recorded as one."
)


def build_result_page_tool(navigator: ResultNavigator | None) -> StructuredTool:
    """The model-visible navigation function, bound to this run's store.

    Built the same way with ``navigator=None``: the surface a preflight derives
    has to be the surface the run executes, and a function that appeared in only
    one of them would make the two disagree about what the model was offered.
    Without a store bound it refuses deterministically, which is the truthful
    answer rather than a silently missing capability.
    """

    def result_page(cursor: str | None = None, **unexpected: Any) -> dict[str, Any]:
        if unexpected:
            # Refused rather than ignored.  An ignored ``offset`` looks to the
            # caller like an offset that was honoured, and a caller who believes
            # it chose the window will believe it read the records in between.
            return _refusal(
                PAGE_CURSOR_REFUSED,
                "a stored page is continued by its cursor alone, and this call also "
                f"supplied {', '.join(sorted(unexpected))}; a window chosen by the "
                "caller could step over records that were never read, so the cursor "
                "is the only thing that decides where the next page starts",
            )
        if navigator is None:
            return _refusal(
                NO_RESULT_STORE_BOUND,
                "this run binds no retained-result store, so no stored page can be "
                "served; re-issue the original call instead",
            )
        try:
            return navigator.page(cursor)
        except PageCursorExhausted as error:
            # Caught before its base class: a page served twice is the paging
            # loop, and the model needs the distinct "continue the tool" steer,
            # not the generic "this cursor names no page here".
            return _refusal(PAGE_CURSOR_ALREADY_SERVED, str(error))
        except PageCursorError as error:
            return _refusal(PAGE_CURSOR_REFUSED, str(error))

    return StructuredTool.from_function(
        result_page,
        name=RESULT_PAGE_TOOL_NAME,
        description=RESULT_PAGE_DESCRIPTION,
        args_schema=create_model(
            "ResultPageCall",
            # Permissive on the wire and strict inside, exactly like the domain
            # facades: a malformed call must come back as a deterministic refusal
            # the model can act on, never as an exception into the agent loop.
            __config__=ConfigDict(extra="allow"),
            cursor=(
                str | None,
                Field(
                    default=None,
                    description=(
                        "The opaque page cursor from data.attributes.page_cursor of "
                        "the result you are continuing, copied exactly."
                    ),
                ),
            ),
        ),
    )


def _refusal(code: str, message: str) -> dict[str, Any]:
    return {
        "error": {
            "code": code,
            "tool": RESULT_PAGE_TOOL_NAME,
            "message": message[:2000],
        },
        "deterministic_error": True,
    }


__all__ = [
    "CONTINUED_VIEW_NOTE_ATTRIBUTE",
    "NO_RESULT_STORE_BOUND",
    "PAGE_CURSOR_ALREADY_SERVED",
    "PAGE_CURSOR_REFUSED",
    "RESULT_PAGE_DESCRIPTION",
    "RESULT_PAGE_TOOL_NAME",
    "PageBinding",
    "PageCursorError",
    "PageCursorExhausted",
    "ResultNavigator",
    "build_result_page_tool",
]
