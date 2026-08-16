"""Tests for reproducibility primitives: manifests, hashing, record/replay."""

from forensic_agent.core import repro


def test_canonical_json_is_order_independent():
    a = repro.canonical_json({"b": 1, "a": 2})
    b = repro.canonical_json({"a": 2, "b": 1})
    assert a == b  # sorted keys => stable serialization


def test_sha256_hex_is_deterministic():
    assert repro.sha256_hex("abc") == repro.sha256_hex(b"abc")
    assert repro.sha256_hex("abc") != repro.sha256_hex("abd")


def test_environment_info_shape():
    env = repro.environment_info(hardware="RTX 5080")
    assert env["hardware"] == "RTX 5080"
    assert "python" in env and "platform" in env
    assert "openai" in env["libraries"]


def test_recorder_transcript_hash_stable_and_sensitive():
    r1 = repro.Recorder()
    r1.record("tool", "list_directory", {"path": "/"}, ["a", "b"])
    r1.record("tool", "read_file", {"path": "/a"}, "data")

    r2 = repro.Recorder()
    r2.record("tool", "list_directory", {"path": "/"}, ["a", "b"])
    r2.record("tool", "read_file", {"path": "/a"}, "data")

    assert r1.transcript_hash() == r2.transcript_hash()  # identical runs => same hash

    r2.record("tool", "read_file", {"path": "/b"}, "other")
    assert r1.transcript_hash() != r2.transcript_hash()  # divergence => different hash


def test_manifest_fingerprint_ignores_timing():
    m1 = repro.RunManifest(
        case_id="c1", model="qwen3:8b", engine="graph", backend="local",
        profile={"temperature": 0}, started_at="2026-06-29T10:00:00Z",
    )
    m2 = repro.RunManifest(
        case_id="c1", model="qwen3:8b", engine="graph", backend="local",
        profile={"temperature": 0}, started_at="2026-06-29T23:59:59Z",
    )
    assert m1.fingerprint() == m2.fingerprint()  # different time, same config


def test_trace_roundtrip_and_replay(tmp_path):
    rec = repro.Recorder()
    rec.record("tool", "registry_query", {"hive": "SYSTEM"}, {"computer": "ALBERTE-PC"})
    rec.record("tool", "evtx_query", {"window": "2017-05-01"}, ["evt1", "evt2"])
    manifest = repro.RunManifest(
        case_id="case-42", model="gpt-oss:20b", engine="scoped", backend="local",
        profile={"temperature": 0, "seed": 42},
    )
    path = str(tmp_path / "trace.jsonl")
    thash = rec.save(path, manifest)

    loaded_manifest, events = repro.load_trace(path)
    assert loaded_manifest is not None
    assert loaded_manifest["case_id"] == "case-42"
    assert loaded_manifest["transcript_sha256"] == thash
    assert len(events) == 2

    idx = repro.replay_index(events)
    key = repro.sha256_hex(
        repro.canonical_json(["tool", "registry_query", {"hive": "SYSTEM"}])
    )
    assert idx[key] == {"computer": "ALBERTE-PC"}


def test_oversight_log_reconstruct_has_stable_transcript_hash():
    """The oversight reconstruction carries a transcript hash that is stable across
    wall-clock differences but sensitive to behavioural changes."""
    from forensic_agent.oversight import reconstruct

    base = [
        {"event": "case_open", "case_id": "x", "question": "q",
         "system_prompt_sha256": "sp", "model": "m", "engine": "graph"},
        {"event": "action", "case_id": "x", "seq": 0, "tool": "list_directory",
         "args": {"path": "/"}, "allowed": True, "output_sha256": "h1", "ts": 1.0},
        {"event": "action", "case_id": "x", "seq": 1, "tool": "read_file",
         "args": {"path": "/a"}, "allowed": True, "output_sha256": "h2", "ts": 2.0},
        {"event": "case_close", "case_id": "x", "status": "ok", "final_sha256": "f"},
    ]
    r1 = reconstruct(base)
    assert r1["transcript_sha256"]

    base2 = [dict(e) for e in base]
    base2[1] = {**base2[1], "ts": 99.0}
    base2[2] = {**base2[2], "ts": 100.0}
    assert reconstruct(base2)["transcript_sha256"] == r1["transcript_sha256"]

    base3 = [dict(e) for e in base]
    base3[2] = {**base3[2], "output_sha256": "DIFFERENT"}
    assert reconstruct(base3)["transcript_sha256"] != r1["transcript_sha256"]
