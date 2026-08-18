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

    def fake_run(image_path, be, outdir, *, on_percent=None):
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

    def fake_run(image_path, be, outdir, *, on_percent=None):
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


# ---------------------------------------------------------------------------
# how far the scan says it has read
# ---------------------------------------------------------------------------
#: One scanner's progress output, as bulk_extractor prints it: a banner, a
#: percentage per read, the same percentage said again on the next line, and a
#: phase line carrying none at all.
_SCANNER_OUTPUT = (
    "bulk_extractor version 2.1.1",
    "Offset 0MB (0.00%) Done in 1:29:44",
    "Offset 67MB (0.16%) Done in 1:29:44",
    "Offset 68MB (0.16%) Done in 1:29:40",
    "All data are read; waiting for threads to finish...",
    "Offset 2100MB (100.00%) Done in 0:00:00",
)


def test_only_a_percentage_that_moved_is_reported():
    """A scan prints a line per megabyte; a console must not repaint per line."""

    reported: list[float] = []
    read = bet._read_reported_percentage(reported.append)
    for line in _SCANNER_OUTPUT:
        read(line)
    # Three events for six lines: the repeat and the phase line say nothing new.
    assert reported == pytest.approx([0.0, 0.0016, 1.0])


def test_a_percentage_that_went_backwards_is_never_shown():
    """What is on the row is the furthest the scanner said it got."""

    reported: list[float] = []
    read = bet._read_reported_percentage(reported.append)
    for line in ("Offset 900MB (40.00%)", "Offset 100MB (4.00%)", "Offset 950MB (42.00%)"):
        read(line)
    assert reported == pytest.approx([0.4, 0.42])


def test_a_scanner_that_states_no_percentage_reports_nothing_at_all():
    """The honest case: nothing measured, so nothing is claimed."""

    reported: list[float] = []
    read = bet._read_reported_percentage(reported.append)
    for line in ("bulk_extractor version 2.1.1", "Phase 1. Uncompressing", "All data are read"):
        read(line)
    assert reported == []


def _scan_output_into(argv: list[str]) -> None:
    outdir = Path(argv[argv.index("-o") + 1])
    (outdir / "email.txt").write_text(
        "# BANNER\n1000\talice@example.com\tctx\n", encoding="utf-8"
    )
    (outdir / "report.xml").write_text("<report></report>", encoding="utf-8")


def test_prewarm_reports_the_fractions_the_scan_actually_printed(
    tmp_path, cache_env, monkeypatch
):
    """End to end from the scanner's stdout to the sink a console draws from.

    The subprocess is stood in for; everything between it and the caller is the
    real thing — the argv the scan is launched with, the pattern the progress
    lines are read by, and the sink prewarm hands the fraction to.
    """

    image = tmp_path / "image.E01"
    image.write_bytes(b"not really an image")
    monkeypatch.setattr(bet, "bulk_extractor_path", lambda: "fake-be")

    def fake_stream(argv, *, timeout, on_line, **kwargs):
        for line in _SCANNER_OUTPUT:
            on_line(line)
        _scan_output_into(list(argv))
        return 0

    def must_not_block(*args, **kwargs):
        raise AssertionError("a watched scan was run through the blocking runner")

    monkeypatch.setattr(bet, "stream_external", fake_stream)
    monkeypatch.setattr(bet, "run_external", must_not_block)

    reported: list[tuple[float | None, str | None]] = []
    outcome = bet.prewarm_default_scan(
        str(image),
        evidence_sha256=_SHA,
        progress=lambda fraction, detail: reported.append((fraction, detail)),
    )

    assert outcome["state"] == "built"
    fractions = [fraction for fraction, _ in reported]
    # Nothing is measured before the scanner has said anything, and the row
    # stays a spinner until it does.
    assert fractions[0] is None
    assert fractions[1:] == pytest.approx([0.0, 0.0016, 1.0])
    # One phase name for the whole step, whatever the fraction underneath it.
    assert {detail for _, detail in reported} == {
        "scanning the whole image with bulk_extractor"
    }


def test_a_scan_nobody_is_watching_stays_on_the_blocking_runner(
    tmp_path, cache_env, monkeypatch
):
    """Streaming is for the caller who asked to be told; nothing else changes."""

    image = tmp_path / "image.E01"
    image.write_bytes(b"not really an image")
    monkeypatch.setattr(bet, "bulk_extractor_path", lambda: "fake-be")

    def fake_run_external(argv, *, timeout, **kwargs):
        _scan_output_into(list(argv))
        return None

    def must_not_stream(*args, **kwargs):
        raise AssertionError("an unwatched scan was run through the streaming runner")

    monkeypatch.setattr(bet, "run_external", fake_run_external)
    monkeypatch.setattr(bet, "stream_external", must_not_stream)

    assert bet.prewarm_default_scan(str(image), evidence_sha256=_SHA)["state"] == "built"
