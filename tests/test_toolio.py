"""core.toolio.shape — the shared tool-output envelope: filter + pagination + BYTE
bounding so one giant row (e.g. a registry 'services' dump >1 MB) cannot overflow the
model context."""

from forensic_agent.core import toolio


def test_shape_shrinks_an_oversized_row():
    big = {"plugin": "services", "data": "x" * 50_000, "rid": 7}  # 50 KB firehose row
    env = toolio.shape([big], max_row_bytes=2000)
    row = env["rows"][0]
    assert row["rid"] == 7  # small scalar kept
    assert "…[truncated" in row["data"] and len(row["data"]) < 2000  # large field capped
    assert env["page_truncated"] is False
    assert toolio._row_bytes(row) <= 2200


def test_shape_total_byte_cap_stops_the_page():
    rows = [{"i": i, "blob": "y" * 1500} for i in range(100)]  # ~1.5 KB each
    env = toolio.shape(rows, limit=100, max_total_bytes=8000)
    assert env["truncated"] is True
    assert env["page_truncated"] is True
    assert env["returned"] < 100 and toolio._row_bytes(env["rows"]) <= 9000
    assert "offset=" in env["note"]


def test_shape_always_returns_at_least_one_row():
    giant = {"plugin": "services", "data": "z" * 2_000_000}  # 2 MB single row
    env = toolio.shape([giant], max_row_bytes=2000, max_total_bytes=1000)
    assert env["returned"] == 1  # never empty
    assert toolio._row_bytes(env["rows"][0]) <= 2200  # but bounded


def test_shape_filter_and_pagination_preserved():
    rows = [{"name": f"u{i}"} for i in range(10)]
    env = toolio.shape(rows, filter="u7")
    assert env["total_matching"] == 1 and env["rows"][0]["name"] == "u7"
    env2 = toolio.shape(rows, offset=8, limit=5)
    assert [r["name"] for r in env2["rows"]] == ["u8", "u9"] and env2["offset"] == 8


def test_shape_empty_filter_note():
    env = toolio.shape([{"a": 1}], filter="zzz")
    assert env["returned"] == 0 and "no rows matched" in env["note"]


# --------------------------- central guard: bound() ---------------------- #
def test_bound_passes_small_results_through_unchanged():
    small = {"path": "/x", "content_text": "hello"}
    assert toolio.bound(small) is small
    assert toolio.bound("a string") == "a string"  # non-dict/list untouched


def test_bound_caps_an_oversized_plain_dict():
    big = {"path": "/x", "content_text": "Z" * 200_000, "size": 9}  # 200 KB firehose
    out = toolio.bound(big, max_bytes=16000)
    assert out["size"] == 9 and out["_bounded"] is True
    assert "…[truncated" in out["content_text"]
    assert toolio._row_bytes(out) <= 16000


def test_bound_reshapes_an_oversized_row_envelope():
    rows = [{"i": i, "blob": "y" * 1500} for i in range(200)]
    out = toolio.bound({"hive": "SYSTEM", "rows": rows}, max_bytes=8000)
    assert out["hive"] == "SYSTEM" and out["_bounded"] is True
    assert out["truncated"] is True and toolio._row_bytes(out) <= 8000


def test_bound_recomputes_paging_for_an_already_paged_envelope():
    rows = [{"i": i, "blob": "y" * 1500} for i in range(100, 200)]
    source = {
        "rows": rows,
        "total_matching": 202,
        "returned": 100,
        "offset": 100,
        "next_offset": 200,
        "truncated": True,
        "page_truncated": True,
        "note": "stale source note",
    }

    out = toolio.bound(source, max_bytes=8000)

    assert out["total_matching"] == 202
    assert out["offset"] == 100
    assert 0 < out["returned"] < 100
    assert out["next_offset"] == 100 + out["returned"]
    assert f"offset={out['next_offset']}" in out["note"]
    assert out["next_offset"] != source["next_offset"]
    assert out["page_truncated"] is True
    assert toolio._row_bytes(out) <= 8000


def test_bound_counts_serialized_utf8_bytes_for_non_ascii_content():
    oversized = {"path": "/unicode", "content_text": "🙂" * 5000}

    assert toolio._row_bytes(oversized) > 16_000
    out = toolio.bound(oversized, max_bytes=16_000, max_row_bytes=16_000)

    assert out is not oversized
    assert out["_bounded"] is True
    assert "…[truncated" in out["content_text"]
    assert toolio._row_bytes(out) <= 16_000


def test_bound_enforces_row_cap_across_many_large_fields():
    oversized = {f"field_{index}": "x" * 2000 for index in range(100)}

    out = toolio.bound(oversized, max_bytes=16_000, max_row_bytes=2000)

    assert out["_bounded"] is True
    assert toolio._row_bytes(out) <= 2000
    assert len(out) < len(oversized)


def test_shape_hard_caps_complete_envelope_and_marks_truncated_row_content():
    rows = [{"id": 1, "value": "🙂" * 2000}]

    out = toolio.shape(rows, max_row_bytes=400, max_total_bytes=1000)

    assert out["returned"] == 1
    assert out["truncated"] is True
    assert out["page_truncated"] is False
    assert out["_bounded"] is True
    assert toolio._row_bytes(out["rows"][0]) <= 400
    assert toolio._row_bytes(out) <= 1000


def test_an_empty_expression_filter_explains_the_substring_contract():
    rows = [{"ForeignAddr": "203.0.113.7", "State": "ESTABLISHED", "PID": 3644}]

    note = toolio.shape(rows, filter="ForeignAddr != '*'")["note"]

    assert "substring" in note
    assert "cannot match" in note
    assert "ForeignAddr" in note


def test_an_empty_literal_filter_lists_the_available_fields():
    rows = [{"ForeignAddr": "203.0.113.7", "State": "ESTABLISHED", "PID": 3644}]

    note = toolio.shape(rows, filter="nothing-here")["note"]

    assert "substring" in note
    assert "Fields present in this result: ForeignAddr, State, PID." in note


def test_an_offset_past_the_last_row_states_the_valid_range():
    rows = [{"PID": 1}, {"PID": 2}]

    result = toolio.shape(rows, offset=15000)

    assert result["returned"] == 0
    assert "offset 15000 is past the last row" in result["note"]
    assert "valid offsets are 0 to 1" in result["note"]


def test_a_hopeless_page_chain_states_the_call_cost():
    rows = [{"PID": value, "Owner": f"svc-{value}.exe"} for value in range(5000)]

    note = toolio.shape(rows, offset=0, limit=100)["note"]

    assert "further calls" in note
    assert "do not page through them one by one" in note


def test_a_short_page_chain_stays_quiet_about_call_cost():
    rows = [{"PID": value} for value in range(300)]

    note = toolio.shape(rows, offset=0, limit=100)["note"]

    assert "more matching rows" in note
    assert "further calls" not in note


def test_an_apostrophe_in_a_literal_is_not_mistaken_for_an_expression():
    rows = [{"path": "/Users/A/Documents", "PID": 3644}]

    note = toolio.shape(rows, filter="John's Documents")["note"]

    assert "not a query expression" not in note
    assert "no rows matched the substring" in note


# ------------------- the cut that must not read as absence ---------------- #
def test_a_page_cut_at_the_row_count_says_so_in_its_own_field():
    """Rows dropped for COUNT get a field of their own, not a shared flag."""

    rows = [{"path": f"/Docs/{i}.txt", "term": "password"} for i in range(500)]

    env = toolio.shape(rows, offset=0, limit=50)

    assert env[toolio.CARDINALITY_TRUNCATED_KEY] is True
    assert env[toolio.ROWS_WITHHELD_KEY] == 450


def test_a_shortened_value_is_not_a_shortened_matching_set():
    """The distinction the flag exists for: one row, kept, with a capped field."""

    env = toolio.shape([{"id": 1, "blob": "z" * 50_000}], max_row_bytes=2000)

    assert env["truncated"] is True  # something WAS shortened
    assert toolio.CARDINALITY_TRUNCATED_KEY not in env  # but no row was withheld
    assert toolio.ROWS_WITHHELD_KEY not in env


def test_a_result_that_matched_nothing_declares_no_cut():
    """A genuine empty must stay distinguishable from a prefix, in both directions."""

    assert toolio.CARDINALITY_TRUNCATED_KEY not in toolio.shape([])
    assert toolio.CARDINALITY_TRUNCATED_KEY not in toolio.shape([{"a": 1}], filter="zzz")


def test_a_complete_page_declares_no_cut():
    rows = [{"i": i} for i in range(10)]

    assert toolio.CARDINALITY_TRUNCATED_KEY not in toolio.shape(rows, limit=50)


def test_the_note_on_a_prefix_says_what_the_prefix_cannot_be_used_for():
    rows = [{"path": f"/Docs/{i}.txt"} for i in range(500)]

    note = toolio.shape(rows, offset=0, limit=50)["note"]

    assert "cannot show that anything is absent" in note
    assert "narrow the query with 'filter'" in note
    assert "a search that reads the whole image" in note


def test_bound_declares_a_record_list_it_had_to_flatten():
    """A record list under any contract key, not only ``rows``.

    ``bound`` recognised a row page by the literal key ``rows`` alone.  Records
    under any other key the contract reads went through the plain-mapping branch,
    which serializes the whole list into one truncated string: the model got a
    prefix and the result kept no counter saying so.
    """

    hits = [{"path": f"/Docs/{i}.txt", "snippet": "…password…" * 4} for i in range(300)]

    out = toolio.bound({"keyword": "password", "hits": hits, "scan_complete": True})

    assert out[toolio.CARDINALITY_TRUNCATED_KEY] is True
    assert out[toolio.ROWS_WITHHELD_KEY] == 300
    assert "cannot show that anything is absent" in out["note"]


def test_bound_declares_no_cut_when_every_record_survives():
    """Bytes spent elsewhere are not a shortfall in the matching set."""

    out = toolio.bound({"hits": [{"i": i} for i in range(5)], "blob": "Z" * 200_000})

    assert toolio.CARDINALITY_TRUNCATED_KEY not in out
    assert toolio.ROWS_WITHHELD_KEY not in out


def test_bound_declares_no_cut_for_an_oversized_result_holding_no_records():
    out = toolio.bound({"path": "/x", "content_text": "Z" * 200_000, "size": 9})

    assert toolio.CARDINALITY_TRUNCATED_KEY not in out


def test_bound_reads_the_same_record_keys_the_contract_does():
    """Two lists of key names is how the one that matters stops being read."""

    from forensic_agent.core.tool_result import _ITEM_KEYS

    assert set(toolio._RECORD_LIST_KEYS) == set(_ITEM_KEYS)


def test_a_prefix_cannot_forge_the_cut_it_is_attached_to():
    rows = [{"i": i} for i in range(5)]

    env = toolio.shape(rows, _prefix={toolio.CARDINALITY_TRUNCATED_KEY: True})

    assert toolio.CARDINALITY_TRUNCATED_KEY not in env
