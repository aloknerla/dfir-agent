"""The whole-image scan is paid once per evidence, ever.

A run's bulk_extractor output used to live only in that run's scratch, so a
second entity question — or a second session on the same image — paid the full
scan again. A finished default scan is now published into the persistent index
root, content-addressed by the evidence's verified SHA-256 and the scanner's
sealed version, and later calls reuse it instead of rescanning.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from forensic_agent.core.controlled_scratch import provision_controlled_scratch_root
from forensic_agent.tools import bulk_extractor_tool as bet

_SHA = "a" * 64


@pytest.fixture()
def cache_env(tmp_path, monkeypatch):
    """A writable persistent root and a sealed scanner version."""

    index_root = tmp_path / "index-root"
    index_root.mkdir()
    monkeypatch.setenv("DFA_INDEX_ROOT", str(index_root))
    monkeypatch.setattr(
        "forensic_agent.tools.entity_index._scanner_version", lambda supplied: "9.9.9"
    )
    return index_root


def _fake_scan_output(base: Path) -> Path:
    outdir = base / "scan-output"
    outdir.mkdir(parents=True)
    (outdir / "email.txt").write_text(
        "# BANNER\n1000\talice@example.com\tctx\n2000\tbob@example.com\tctx\n",
        encoding="utf-8",
    )
    (outdir / "report.xml").write_text("<report></report>", encoding="utf-8")
    return outdir


def test_publish_then_reuse_round_trip(tmp_path, cache_env):
    outdir = _fake_scan_output(tmp_path)
    published = bet._publish_scan(outdir, _SHA, "fake-be")
    assert published is not None
    assert (published / "email.txt").read_text(encoding="utf-8").count("@") == 2
    # The identity is what is served, not the path: the same digest finds it,
    # a different digest does not.
    assert bet._published_scan(_SHA, "fake-be") == published
    assert bet._published_scan("b" * 64, "fake-be") is None
    # Without a verified digest nothing is published or served.
    assert bet._publish_scan(outdir, None, "fake-be") is None
    assert bet._published_scan(None, "fake-be") is None


def test_second_run_reads_the_published_scan_without_rescanning(
    tmp_path, cache_env, monkeypatch
):
    image = tmp_path / "image.E01"
    image.write_bytes(b"not really an image")
    monkeypatch.setattr(bet, "bulk_extractor_path", lambda: "fake-be")

    runs = {"count": 0}

    def fake_run(image_path, be, outdir):
        runs["count"] += 1
        if runs["count"] > 1:
            raise AssertionError("the image was rescanned despite a published scan")
        target = Path(outdir)
        (target / "email.txt").write_text(
            "# BANNER\n1000\talice@example.com\tctx\n", encoding="utf-8"
        )
        (target / "report.xml").write_text("<report></report>", encoding="utf-8")
        return outdir

    monkeypatch.setattr(bet, "_run", fake_run)

    def controlled(name: str) -> Path:
        base = tmp_path / name
        base.parent.mkdir(parents=True, exist_ok=True)
        return provision_controlled_scratch_root(base, anchor=tmp_path).root_path

    # First run: scans once, publishes.
    first = bet.bulk_extract(
        str(image), output_root=controlled("run-a"), evidence_sha256=_SHA
    )
    assert "error" not in first, first
    assert runs["count"] == 1

    # A LATER run (fresh controlled root, fresh in-process key): must serve
    # the published scan — fake_run raises if it is ever called again.
    second = bet.bulk_extract(
        str(image),
        feature="email",
        output_root=controlled("run-b"),
        evidence_sha256=_SHA,
    )
    assert "error" not in second, second
    assert runs["count"] == 1
    assert any("alice@example.com" in str(row) for row in second.get("rows", []))


def test_prewarm_builds_once_and_feeds_the_entity_search(
    tmp_path, cache_env, monkeypatch
):
    """Case-open ingest: the open pays the scan, the agent's first entity
    question then reuses it — the professional-tool flow."""

    image = tmp_path / "image.E01"
    image.write_bytes(b"not really an image")
    monkeypatch.setattr(bet, "bulk_extractor_path", lambda: "fake-be")

    runs = {"count": 0}

    def fake_run(image_path, be, outdir):
        runs["count"] += 1
        if runs["count"] > 1:
            raise AssertionError("rescanned despite the prewarmed publication")
        target = Path(outdir)
        (target / "email.txt").write_text(
            "# BANNER\n1000\talice@example.com\tctx\n", encoding="utf-8"
        )
        (target / "ip.txt").write_text(
            "# BANNER\n2000\t192.168.1.111\tctx\n", encoding="utf-8"
        )
        (target / "report.xml").write_text("<report></report>", encoding="utf-8")
        return outdir

    monkeypatch.setattr(bet, "_run", fake_run)

    phases = []
    first = bet.prewarm_default_scan(
        str(image),
        evidence_sha256=_SHA,
        progress=lambda fraction, detail: phases.append(detail),
    )
    assert first["state"] == "built"
    assert "email" in first["features"] and "ip" in first["features"]
    assert runs["count"] == 1 and phases

    again = bet.prewarm_default_scan(str(image), evidence_sha256=_SHA)
    assert again["state"] == "reused"

    # The agent's entity search now reads the prewarmed publication.
    root = provision_controlled_scratch_root(tmp_path / "run-x", anchor=tmp_path).root_path
    result = bet.bulk_extract(
        str(image), feature="email", output_root=root, evidence_sha256=_SHA
    )
    assert "error" not in result, result
    assert runs["count"] == 1  # never rescanned


def test_prewarm_is_honest_without_a_verified_digest(tmp_path, cache_env, monkeypatch):
    monkeypatch.setattr(bet, "bulk_extractor_path", lambda: "fake-be")
    image = tmp_path / "mem.raw"
    image.write_bytes(b"x")
    outcome = bet.prewarm_default_scan(str(image), evidence_sha256=None)
    assert outcome["state"] == "unavailable"
    assert "digest" in outcome["detail"]
