import json

from forensic_agent.core.audit import AuditLog, sha256_bytes


def test_sha256_deterministic():
    assert sha256_bytes(b"abc") == sha256_bytes(b"abc")
    assert len(sha256_bytes(b"x")) == 64


def test_record_writes_jsonl_with_hash(tmp_path):
    p = tmp_path / "a.jsonl"
    entry = AuditLog(str(p)).record(tool="t", args={"x": 1}, output={"k": "v"})
    assert entry["tool"] == "t"
    assert len(entry["output_sha256"]) == 64
    lines = p.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["tool"] == "t"
