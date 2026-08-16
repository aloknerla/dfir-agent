"""Capture the complete tool output, and project it for the model separately.

Two distinct boundaries live here, and keeping them apart is the point:

* **capture** runs innermost, immediately around the tool, where the complete
  output still exists.  It hashes and stores that output before anything shapes
  it, and publishes the capture for this invocation only.
* **projection** runs last, after oversight and standardization, because it is
  the final model-facing step.  Everything upstream — the audit entry and the
  standardized result with its full-payload receipt — therefore describes the
  complete output, and only the model's copy is bounded.
"""

from __future__ import annotations

from forensic_agent.agent.model_result_envelope import (
    MODEL_RESULT_SCHEMA_ID,
    envelope_reference,
    unwrap_result,
    wrap_for_model,
)


def _envelope_overhead(result_ref: str | None) -> int:
    """Serialized weight of the delivery envelope around a projected result.

    The budget applies to the document the model receives, and that document is
    the envelope.  Measuring the result alone would let every projection land
    just over the cap by exactly the wrapper's own bytes.
    """

    if not result_ref:
        return 0
    from forensic_agent.core.repro import canonical_json

    skeleton = {
        "schema_version": MODEL_RESULT_SCHEMA_ID,
        "result_ref": result_ref,
        "result": None,
    }
    return len(canonical_json(skeleton).encode("utf-8"))

from langchain_core.tools import StructuredTool


def _capturing_callable(function, *, capture_store=None, tool_name=None):
    """Capture and hash the complete output around one tool invocation."""

    del tool_name  # the capture travels with its value, so no ambient keying

    def wrapped(**arguments):
        from forensic_agent.core.output_capture import capture_for_invocation

        # The complete output exists only here.  Capture it and hand it onward
        # PAIRED with its own capture, so every consumer downstream is bound to
        # this invocation's capture and can never inherit another call's.
        return capture_for_invocation(function(**arguments), store=capture_store)

    # Marks this registry as already carrying the boundary chain, so a caller that
    # passes it back in as prepared_tools is rejected instead of double-wrapped.
    wrapped.__forensic_wrapped__ = True  # type: ignore[attr-defined]
    return wrapped


def _projecting_callable(
    function,
    boundary,
    *,
    recorder=None,
    tool_name=None,
    on_model_result=None,
    page_cursor_issuer=None,
    result_reference_issuer=None,
):
    """Bound the final model-facing value, whatever its shape.

    ``page_cursor_issuer`` is the run's result navigator, when one is bound.  A
    projection that withholds records leaves the rest of them in the run's own
    store, and a cursor is the only way for a model to ask for those records
    WITHOUT re-running the tool over material the run already holds.  The token
    is reserved before shaping and bound afterwards, because the window it opens
    is not known until the projection has settled on how much it could carry; a
    token that is never bound simply never becomes a cursor.
    """

    def _commit(source, published, *, arguments=None, **flags):
        """Persist the model artifact, then record exactly ONE sidecar for the call.

        Every exit routes through here so no path can emit two contradictory
        sidecars, and the sidecar is always written AFTER the artifact it attests
        — including on the failure paths, where recording first would claim a
        trace row that may never have landed.
        """

        trace_committed = None
        if on_model_result is not None:
            try:
                on_model_result(tool_name, arguments or {}, published)
                trace_committed = True
            except Exception:
                trace_committed = False
        if recorder is None:
            return
        record = getattr(recorder, "record_security", None)
        if not callable(record):
            return
        sidecar = {
            **projection_sidecar(source, published, tool_name=tool_name),
            "projection_committed": True,
            "model_visible_trace_committed": trace_committed,
            **flags,
        }
        try:
            record("tool_output_projection", sidecar)
        except Exception:
            # A recorder failure must not turn a produced result into a tool
            # failure, and must not leave a second, contradicting sidecar behind.
            pass

    def wrapped(**arguments):
        from forensic_agent.core.output_capture import unwrap_captured

        # Defensive: if no oversight/standardization layer consumed the capture
        # carrier, unwrap it here so the internal pairing never reaches the model.
        value, capture = unwrap_captured(function(**arguments))
        if capture is not None and (
            not capture.capture_complete or capture.storage_failed
        ):
            # Retention failed.  In the standardized path the contract already
            # publishes a non-admissible error; without standardization nothing
            # else would tell the model that this output was not retained, so say
            # it here rather than handing over an ordinary-looking result.
            failure = _within_budget(
                _projection_stand_in(
                    "the tool's complete output was not retained (capture was cut "
                    "short or its storage failed), so this result has no attestable "
                    "complete-output digest and cannot be used as case evidence",
                    error_type="output_retention_failed",
                )
            )
            _commit(value, failure, arguments=arguments, retention_failed=True)
            return failure
        try:
            token = (
                page_cursor_issuer.reserve() if page_cursor_issuer is not None else None
            )
            reference = (
                result_reference_issuer.reserve()
                if result_reference_issuer is not None
                else None
            )
            projected = _within_budget(
                project_for_model(
                    value,
                    boundary=boundary,
                    page_cursor=token,
                    envelope_reserve=_envelope_overhead(reference),
                )
            )
            if token is not None:
                try:
                    # Bound against the FINAL published document, so a projection
                    # that was replaced on the way out (by the budget backstop,
                    # say) leaves a token standing for nothing rather than a
                    # cursor pointing into a page the model never received.
                    page_cursor_issuer.bind(token, projected=projected)
                except Exception:
                    # Failing to offer a continuation must not turn a produced,
                    # recorded, retained result into a tool failure.  The cursor
                    # is then simply absent, which the model reads as "this view
                    # offers no stored page" — the same truthful answer it gets
                    # for every result that has no remainder to serve.
                    pass
            published = projected
            if reference is not None:
                # Addressed to the model under a delivery name.  The result
                # inside is untouched — a small one keeps the receipt its tool
                # signed, a shortened one keeps the receipt its projection
                # signed — because the name is a fact about this delivery and
                # not about the evidence.  A binding that fails leaves the name
                # naming nothing, and an unnamed result cannot be cited.
                published = wrap_for_model(projected, result_ref=reference)
                try:
                    result_reference_issuer.bind(reference, projection=projected)
                except Exception:
                    published = projected
            # Recorded for EVERY call, shortened or not: a missing sidecar would
            # otherwise be indistinguishable from a call that was never projected.
            _commit(value, published, arguments=arguments)
            return published
        except Exception as error:
            # A SHAPING failure is not a tool failure and not a capture failure.
            # The tool's result was produced, recorded and retained upstream; only
            # the model's copy could not be built.  Say exactly that, rather than
            # letting a shaping bug surface as though the tool had failed.
            failure = _within_budget(
                _projection_stand_in(
                    "the tool produced a result and it was recorded and retained; "
                    "only the bounded model-visible view failed to build",
                    error_type=type(error).__name__,
                )
            )
            # A failed projection is still a projection outcome and must leave a
            # trace, otherwise the run cannot tell "not shortened" from "never
            # produced".  It commits through the same single path, so the stand-in
            # the model received is what the sidecar attests.
            _commit(
                value,
                failure,
                arguments=arguments,
                projection_failed=True,
                projection_error=type(error).__name__,
            )
            return failure

    # Marks the OUTER boundary too, so a caller that hands a fully wrapped
    # registry back in as prepared_tools is rejected rather than double-wrapped.
    wrapped.__forensic_wrapped__ = True  # type: ignore[attr-defined]
    return wrapped


def _strip_bounded(value):
    """Remove the guard's internal ``_bounded`` marker at every depth.

    Returns ``(cleaned, found)``.  A nested row that was itself shrunk carries its
    own marker, so stripping only the top level would still expose the internal
    flag inside ``rows``/``items``.
    """

    from collections.abc import Mapping

    if isinstance(value, Mapping):
        found = "_bounded" in value
        cleaned = {}
        for key, item in value.items():
            if key == "_bounded":
                continue
            child, child_found = _strip_bounded(item)
            cleaned[key] = child
            found = found or child_found
        return cleaned, found
    if isinstance(value, (list, tuple)):
        # Tuples appear in results built from zipped rows; leaving them unvisited
        # let the internal marker survive inside them.
        found = False
        cleaned_list = []
        for item in value:
            child, child_found = _strip_bounded(item)
            cleaned_list.append(child)
            found = found or child_found
        return (
            (tuple(cleaned_list), found) if isinstance(value, tuple) else (cleaned_list, found)
        )
    return value, False


def _within_budget(value):
    """Final, unconditional guarantee that a model-facing value fits the budget.

    Every exit from the projection passes through here — including the error
    paths, whose own text (a long exception class name, for instance) could
    otherwise breach the cap the rest of the code works to respect.
    """

    from forensic_agent.core.repro import canonical_json
    from forensic_agent.core.toolio import MAX_TOTAL_BYTES

    if len(canonical_json(value).encode("utf-8")) <= MAX_TOTAL_BYTES:
        return value
    return {
        "error": "model projection could not be published",
        "projection_failed": True,
        "projection_note": (
            "the model-visible view exceeded the context budget and was replaced; "
            "the complete tool output was captured and hashed before shaping"
        ),
        "deterministic_error": True,
    }


def _receipted_projection_wire(candidate: dict, *, schema_version: str | None) -> dict | None:
    """Validate and receipt a reduced projection under the contract it came from.

    The projection is a different artifact from the result it was reduced from, so
    it earns its own receipt — but under the SAME contract, because each
    canonicalizes its own payload and a receipt computed by the other one would
    attest a payload it never covered.
    """

    from forensic_agent.core.result_reading import ACTIVE_SCHEMA_ID

    if schema_version == ACTIVE_SCHEMA_ID:
        from forensic_agent.core.result_contract import ToolResult as ActiveResult
        from forensic_agent.core.result_contract import attach_receipt as attach_active_receipt

        try:
            return attach_active_receipt(ActiveResult.model_validate(candidate)).model_dump(
                mode="json"
            )
        except Exception:
            return None
    from forensic_agent.core.tool_result import ToolResult as LegacyResult
    from forensic_agent.core.tool_result import attach_receipt as attach_legacy_receipt

    try:
        return attach_legacy_receipt(LegacyResult.model_validate(candidate)).model_dump(mode="json")
    except Exception:
        return None


def project_for_model(value, *, boundary, page_cursor=None, envelope_reserve=0):
    """Bound a value for the model without destroying a result envelope.

    ``bound`` alone treats a standardized result as one oversized row and caps it
    at the per-row limit, which drops ``provenance`` and ``receipt`` and
    rewrites ``data`` into a truncated string — leaving the model holding a
    document whose contract fields are gone.  A result envelope is therefore
    projected field-wise: the evidence payload absorbs the reduction while the
    contract fields the model is told to rely on survive intact, and the
    reduction is disclosed truthfully.

    Both contracts are recognised, because "not the one envelope I know" and "not
    an envelope" are decided here: getting that wrong sends a receipted result
    through the generic byte boundary, which strips exactly the fields that made
    it evidence.
    """

    from collections.abc import Mapping

    from forensic_agent.core.repro import canonical_json
    from forensic_agent.core.result_navigation import (
        PAGE_CURSOR_ATTRIBUTE,
        PROJECTION_TRUNCATED_ATTRIBUTE,
    )
    from forensic_agent.core.result_reading import (
        claims_result_envelope,
        declared_schema_version,
        is_readable_result,
        read_result,
        receipt_is_valid,
    )
    from forensic_agent.core.toolio import MAX_TOTAL_BYTES as _CAP

    # The cap belongs to what the model receives.  When the result will be
    # delivered inside an envelope, the envelope's own bytes come out of the
    # same budget, or every projection lands just over it by the wrapper.
    MAX_TOTAL_BYTES = max(64, _CAP - int(envelope_reserve or 0))

    def _size(candidate) -> int:
        return len(canonical_json(candidate).encode("utf-8"))

    if isinstance(value, str):
        # Measure the CANONICAL form the model actually receives: JSON quoting and
        # escaping can more than double a raw byte count, so budgeting raw bytes
        # let escaped text sail past the cap.
        if _size(value) <= MAX_TOTAL_BYTES:
            return value
        suffix = "…[projection truncated]"
        raw = value.encode("utf-8")
        low, high, best = 0, len(raw), ""
        while low <= high:
            middle = (low + high) // 2
            end = middle
            while end > 0 and end < len(raw) and raw[end] & 0xC0 == 0x80:
                end -= 1
            candidate = raw[:end].decode("utf-8", "ignore") + suffix
            if _size(candidate) <= MAX_TOTAL_BYTES:
                best = candidate
                low = middle + 1
            else:
                high = middle - 1
        return best

    schema_version = declared_schema_version(value) if isinstance(value, Mapping) else None
    claims_envelope = isinstance(value, Mapping) and claims_result_envelope(value)
    claims_readable_envelope = isinstance(value, Mapping) and is_readable_result(value)
    if claims_envelope and not claims_readable_envelope:
        # It claims one of OUR envelopes, under a version this build cannot read.
        # The generic branch would forward it to the model still wearing the claim
        # and with its receipt unchecked, so name the refusal instead.
        return _projection_stand_in(
            f"the value claimed tool-result envelope {schema_version!r}, which this "
            "build cannot read, so it was not projected and is not usable as evidence"
        )
    if claims_readable_envelope and not isinstance(value.get("data"), Mapping):
        # It CLAIMS to be a tool result but is not one.  Routing it through the
        # generic branch would forward a malformed document to the model
        # without ever validating its receipt, so reject it outright.
        return _projection_stand_in(
            f"the value claimed to be a {schema_version} document but has no "
            "valid data payload, so it was not projected and is not usable as "
            "evidence"
        )
    if not claims_readable_envelope:
        # Any other shape — a plain mapping, a list, bytes, or another scalar —
        # still has to obey the cap, so the boundary's result is verified rather
        # than trusted, and anything that still does not fit is replaced by a
        # bounded, explicitly-marked stand-in.
        def _swap_marker(shaped):
            # The guard's internal marker must not reach the model on ANY shape or
            # at ANY depth: a nested row that was itself shrunk carries its own
            # ``_bounded``, and stripping only the top level leaves those visible.
            found = _strip_bounded(shaped)
            if not found[1]:
                return shaped
            swapped = found[0]
            if isinstance(swapped, Mapping):
                swapped = dict(swapped)
                swapped["projection_truncated"] = True
            return swapped

        # ``bound`` fills its budget exactly, so swapping the short internal marker
        # for the longer truthful one can push the document just over the cap.
        # Re-bound against a reduced budget instead of discarding a perfectly good
        # paginated page and shipping an opaque preview blob.
        budget = MAX_TOTAL_BYTES
        for _attempt in range(8):
            projected = _swap_marker(boundary(value, max_bytes=budget))
            if _size(projected) <= MAX_TOTAL_BYTES:
                return projected
            budget -= max(_size(projected) - MAX_TOTAL_BYTES, 1) + 64
            if budget <= 512:
                break
        projected = _swap_marker(boundary(value, max_bytes=512))
        if _size(projected) <= MAX_TOTAL_BYTES:
            return projected
        return {
            "projection_truncated": True,
            "projection_note": (
                "this value exceeded the model context budget and could not be "
                "reduced in place; the complete tool output was captured and "
                "hashed before shaping"
            ),
            "value_preview": canonical_json(projected)[:1024],
        }

    # FAIL CLOSED FIRST, before any size shortcut: a result whose own receipt does
    # not verify must never pass through — neither unchanged because it happens to
    # be small, nor re-signed with a fresh valid-looking receipt, which would
    # launder a forged or unattested document into a signed projection.
    try:
        source_valid = receipt_is_valid(read_result(dict(value)))
    except Exception:
        source_valid = False
    if not source_valid:
        return {
            "error": "unverified tool result was not projected",
            "projection_failed": True,
            "projection_note": (
                "the result presented for projection did not carry a receipt that "
                "verifies against its own payload, so it was neither forwarded nor "
                "re-signed and is not usable as evidence"
            ),
            "deterministic_error": True,
        }

    if _size(value) <= MAX_TOTAL_BYTES:
        return value

    # The receipt on the incoming result covers the COMPLETE payload.  Once data
    # is reduced, that receipt no longer describes this document, so it must not
    # be carried over: the projection is a DIFFERENT artifact and gets its own
    # receipt.  Both digests are bound side by side in the audit sidecar, so the
    # complete payload remains independently verifiable.
    envelope: dict = {
        key: item for key, item in value.items() if key not in {"data", "receipt"}
    }
    marker: dict = {
        PROJECTION_TRUNCATED_ATTRIBUTE: True,
        "projection_note": (
            "this view was shortened to fit the model context; the complete tool "
            "output was captured and hashed before shaping. page describes THIS "
            "shortened view; coverage describes the tool's own analytical scope"
        ),
    }
    offered_cursor = page_cursor if isinstance(page_cursor, str) and page_cursor else None
    # Budget the WHOLE final wire: envelope, the disclosure marker and the fresh
    # receipt all consume bytes the model must receive, so reserve them before
    # deciding how much payload can survive.
    # Strip the guard's internal marker from the WHOLE payload, at every depth:
    # a valid result can carry ``_bounded`` inside a nested row or attribute
    # that a tool bounded upstream, and popping only the top-level key left those
    # visible to the model.
    stripped_data, _ = _strip_bounded(dict(value["data"]))
    source_data: dict = stripped_data if isinstance(stripped_data, dict) else {}
    raw_items = source_data.get("items")
    items: list = list(raw_items) if isinstance(raw_items, list) else []
    base_attributes: dict = dict(source_data.get("attributes") or {})
    base_attributes.update(marker)

    def _build(kept: int, attribute_cap: int | None = None) -> dict | None:
        attributes: dict = dict(base_attributes)
        if attribute_cap is not None:
            # The bulk of many results lives in attributes (a read_file's
            # ``content_text``, for example) with no items at all.  Reducing only
            # items would leave such a result entirely unbounded, so attributes
            # are capped too, keeping small scalars and truncating large text.
            from forensic_agent.core.toolio import _shrink_row

            shrunk: object = _shrink_row(dict(base_attributes), attribute_cap)
            # ``_shrink_row`` degrades an oversized row to a marker mapping or a
            # truncated scalar; only a mapping can carry attributes.
            attributes = dict(shrunk.items()) if isinstance(shrunk, dict) else {}
            attributes.update(marker)
        data = {**source_data, "attributes": attributes, "items": items[:kept]}
        page = dict(envelope.get("page") or {})
        # ONE rule for ``page``: it describes the MODEL-VISIBLE projection.
        # ``coverage`` remains the tool's own analytical scope.  Leaving a byte
        # page saying 300000 while the model received a few kilobytes would make
        # the same field mean different things depending on the unit.
        if page:
            unit = page.get("unit")
            if unit == "item":
                page["returned"] = len(data["items"])
            else:
                # ``returned``/``offset``/``total`` are quantities IN THIS UNIT
                # (source bytes for a byte page).  The serialized size of the
                # shaped envelope is a different quantity entirely — using it
                # would state an envelope measurement as a source offset and make
                # a continuation skip real source bytes.  Measure instead what the
                # model actually received in the source-bearing fields.
                delivered = sum(
                    len(item.encode("utf-8"))
                    for key, item in (data.get("attributes") or {}).items()
                    if isinstance(item, str) and key in (source_data.get("attributes") or {})
                )
                page["returned"] = min(int(page.get("returned") or 0), delivered)
            total = page.get("total")
            # Measured from the START of the whole set, not from this window:
            # ``total`` counts the set, so a window at a non-zero offset that
            # delivered the rest of it would otherwise keep declaring itself
            # truncated and invite a call for records that do not exist.
            offset_in_set = page.get("offset")
            covered = page["returned"] + (
                offset_in_set if isinstance(offset_in_set, int) else 0
            )
            page["truncated"] = not isinstance(total, int) or covered < total
            # Continuation must resume from what the model ACTUALLY received.
            # Leaving the tool's original next_offset would skip every record the
            # projection withheld, silently losing them from the investigation.
            offset = page.get("offset")
            if isinstance(offset, int) and isinstance(page.get("returned"), int):
                # A zero-length page cannot advance: emitting ``offset`` again
                # would tell the model to re-issue the identical call forever, so
                # no continuation is offered at all.
                page["next_offset"] = (
                    offset + page["returned"]
                    if page["truncated"] and page["returned"] > 0
                    else None
                )
            # An opaque cursor was issued for the tool's own window and cannot be
            # re-derived for a shorter one, so it must not be carried over.
            if page.get("next_cursor") is not None:
                page["next_cursor"] = None
        if (
            offered_cursor is not None
            and page.get("unit") == "item"
            and kept < len(items)
        ):
            # Offered only where the withheld part is COUNTABLE RECORDS the run
            # still holds.  A byte window is left out on purpose: re-reading a
            # byte range repeats no analysis, so its honest continuation is a new
            # call on the tool's own offset, and offering both routes for the same
            # remainder is exactly how the two stop being distinguishable.
            # ``attributes`` is the same mapping ``data`` carries, so this reaches
            # the published payload and the projection's receipt covers it; a
            # cursor attached after receipting would be an unattested instruction
            # travelling inside an attested document.
            attributes[PAGE_CURSOR_ATTRIBUTE] = offered_cursor
            attributes["page_cursor_note"] = (
                "the records this view left out are already held by this run: pass "
                "this cursor to result_page to read them without running the tool "
                "again. It continues THIS result only and cannot be edited"
            )
        candidate = {**envelope, **({"page": page} if page else {}), "data": data}
        # No silent fallback: a candidate that cannot be validated and receipted
        # must NOT be published as an unreceipted envelope.  Returning ``None``
        # lets the caller fall through to a controlled non-evidentiary stand-in.
        return _receipted_projection_wire(candidate, schema_version=schema_version)

    # Largest item count whose COMPLETE final wire — envelope, disclosure marker
    # and the fresh receipt included — still fits the cap.
    low, high, best_wire = 0, len(items), None
    while low <= high:
        middle = (low + high) // 2
        wire_candidate = _build(middle)
        if wire_candidate is not None and _size(wire_candidate) <= MAX_TOTAL_BYTES:
            best_wire = wire_candidate
            low = middle + 1
        else:
            high = middle - 1
    if best_wire is None:
        # Even with no items the document is over budget, so the weight is in the
        # attributes: shrink those, then search the item count AGAIN under that
        # smaller attribute cap.  Keeping ``kept=0`` here would throw away every
        # row while leaving a large part of the budget unused, and "no rows" read
        # off a shaping artifact is indistinguishable from a genuinely empty page.
        cap = MAX_TOTAL_BYTES
        while cap > 64:
            cap //= 2
            if _build(0, attribute_cap=cap) is None:
                continue
            if _size(_build(0, attribute_cap=cap)) > MAX_TOTAL_BYTES:
                continue
            low, high = 0, len(items)
            while low <= high:
                middle = (low + high) // 2
                wire_candidate = _build(middle, attribute_cap=cap)
                if wire_candidate is not None and _size(wire_candidate) <= MAX_TOTAL_BYTES:
                    best_wire = wire_candidate
                    low = middle + 1
                else:
                    high = middle - 1
            if best_wire is not None:
                break

    if best_wire is None or _size(best_wire) > MAX_TOTAL_BYTES:
        # The weight is in fields the reduction cannot touch (an oversized
        # provenance, warnings or error block), or no receipted candidate could be
        # built at all.  Either way, publish an explicit non-evidentiary stand-in
        # rather than an over-budget wire or an unreceipted envelope.
        return _projection_stand_in(
            "the standardized result could not be reduced below the model context "
            "budget while remaining a valid receipted result; the complete tool "
            "output was captured and hashed before shaping"
        )
    return best_wire


def _projection_stand_in(note: str, *, error_type: str | None = None) -> dict:
    """A bounded, explicitly non-evidentiary replacement for an unpublishable view.

    Deliberately carries no ``schema_version``: it is not a tool result and must
    never be mistaken for one, receipted or otherwise.  Fields are short and fixed
    so the stand-in itself cannot breach the context budget.
    """

    stand_in = {
        "error": "model projection could not be published",
        "projection_failed": True,
        "projection_note": note[:512],
        "deterministic_error": True,
    }
    if error_type is not None:
        stand_in["projection_error"] = str(error_type)[:128]
    return stand_in


def projection_sidecar(complete_wire, projected_wire, *, tool_name=None) -> dict:
    """Bind the complete and projected payload digests side by side.

    Written to the audit chain so both artifacts stay independently verifiable:
    the complete receipted result the run retained, and the smaller document the
    model actually read.

    When the result was delivered inside an envelope, three things are recorded
    rather than two.  The envelope gets its own digest, because the envelope is
    what the model received and that is what an examiner has to be able to check;
    the delivery name is written down, because it is what a published answer will
    cite; and the result digests still describe the RESULT, reached through the
    envelope, so "how much did the projection withhold" keeps comparing two
    results rather than a result against a wrapper.
    """

    from forensic_agent.core.repro import canonical_json, sha256_hex

    delivered = projected_wire
    projected_wire = unwrap_result(projected_wire)
    result_ref = envelope_reference(delivered)

    def _payload_digest(wire):
        if wire is None:
            return None
        # Any JSON value gets a digest, scalars included: a projection may
        # legitimately be a bounded string, and a sidecar without a digest cannot
        # attest what the model actually received.
        payload = (
            {key: item for key, item in wire.items() if key != "receipt"}
            if isinstance(wire, dict)
            else wire
        )
        return sha256_hex(canonical_json(payload))

    def _receipt_digest(wire):
        # A non-standardized result may carry a plain ``receipt`` field of any
        # type; treating it as an object would crash the sidecar and lose the
        # record of what the model was shown.
        if not isinstance(wire, dict):
            return None
        receipt = wire.get("receipt")
        return receipt.get("payload_sha256") if isinstance(receipt, dict) else None

    raw_provenance = complete_wire.get("provenance") if isinstance(complete_wire, dict) else None
    provenance = raw_provenance if isinstance(raw_provenance, dict) else {}
    return {
        "schema_id": "forensic.projection-sidecar.v1",
        # Identify WHICH call this sidecar belongs to, and tie it to the oversight
        # entry that recorded the same invocation; without these a sidecar cannot
        # be matched to its call or to the audit chain.
        "tool": tool_name,
        "invocation_id": provenance.get("invocation_id"),
        "case_id": provenance.get("case_id"),
        "oversight_entry_sha256": provenance.get("oversight_entry_sha256"),
        "oversight_sequence": provenance.get("oversight_sequence"),
        "raw_output_sha256": provenance.get("raw_output_sha256"),
        "complete_payload_sha256": _payload_digest(complete_wire),
        "complete_receipt_sha256": _receipt_digest(complete_wire),
        "projected_payload_sha256": _payload_digest(projected_wire),
        "projected_receipt_sha256": _receipt_digest(projected_wire),
        # ``None`` on an unwrapped delivery, which is the truthful answer: there
        # was no envelope and there is no name for an answer to cite.
        "result_ref": result_ref,
        "model_envelope_sha256": (
            sha256_hex(canonical_json(delivered)) if result_ref is not None else None
        ),
        "projection_applied": complete_wire != projected_wire,
    }


def _rebuild(tool: StructuredTool, function, *, carry_docs: bool = False) -> StructuredTool:
    """Rewrap a tool around ``function``, preserving its model-visible identity.

    ``carry_docs`` moves each argument's documented meaning into the schema and
    out of the prose.  It is applied by exactly ONE wrapper: doing it again in a
    second wrapper would rewrite the description a second time and silently change
    the tool-registry digest the run is locked to.

    Metadata travels with the tool, as it already does through the oversight
    wrapper.  It is not model-visible and not part of the registry digest; it is
    where a tool states what it IS to the layers it passes through, and a wrapper
    that dropped it would leave the surface unable to say which argument contract
    belongs to which function.
    """

    description = tool.description
    args_schema = tool.args_schema
    if carry_docs:
        from forensic_agent.agent.tool_bindings.argument_docs import carry_argument_docs

        args_schema, description = carry_argument_docs(args_schema, description)
    return StructuredTool.from_function(
        function,
        name=tool.name,
        description=description,
        args_schema=args_schema,
        metadata=getattr(tool, "metadata", None),
    )


def _capture_tool_outputs(
    tools: list[StructuredTool], *, capture_store=None
) -> list[StructuredTool]:
    """Wrap each tool so its complete output is captured before any shaping."""

    return [
        _rebuild(
            tool,
            _capturing_callable(
                tool.func, capture_store=capture_store, tool_name=tool.name
            ),
            # Capture is the innermost wrapper and therefore the single place that
            # carries argument documentation into the model-visible schema.
            carry_docs=True,
        )
        for tool in tools
    ]


def _project_tool_outputs(
    tools: list[StructuredTool],
    *,
    recorder=None,
    on_model_result=None,
    page_cursor_issuer=None,
    result_reference_issuer=None,
) -> list[StructuredTool]:
    """Apply the model-visible byte boundary as the last step before the model."""

    from forensic_agent.core.toolio import bound

    return [
        _rebuild(
            tool,
            _projecting_callable(
                tool.func,
                bound,
                recorder=recorder,
                tool_name=tool.name,
                on_model_result=on_model_result,
                page_cursor_issuer=page_cursor_issuer,
                result_reference_issuer=result_reference_issuer,
            ),
        )
        for tool in tools
    ]


def _guard_tool_outputs(
    tools: list[StructuredTool], *, capture_store=None, project: bool = True
) -> list[StructuredTool]:
    """Capture complete outputs, and optionally project them for the model.

    ``project=False`` defers the model-facing boundary to the caller, so a
    standardizer downstream still receives the COMPLETE result and can build a
    receipt over the whole payload rather than over a preview.
    """

    captured = _capture_tool_outputs(tools, capture_store=capture_store)
    return _project_tool_outputs(captured) if project else captured
