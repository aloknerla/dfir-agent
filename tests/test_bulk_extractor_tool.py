"""The whole-image literal search is paid once per (evidence, term), ever.

``find_literal`` used to cache its output only in the run's controlled scratch,
which is destroyed when the question ends: the identical search then paid the
full pass again on the next message and in every later session. A finished
search is now published under its own content identity, beside — never inside —
the default scan's, so a default scan already on disk is never orphaned by it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from forensic_agent.core.controlled_scratch import provision_controlled_scratch_root
from forensic_agent.tools import bulk_extractor_tool as bet

_SHA = "c" * 64


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


def test_find_identity_is_separate_from_the_default_scan_identity(cache_env):
    default = bet._scan_cache_identity(_SHA, "fake-be")
    find = bet._find_cache_identity(_SHA, "fake-be", "[nN]eedle")
    assert default is not None and find is not None
    assert find["schema"] != default["schema"]
    assert find["pattern"] == "[nN]eedle"
    # A published default scan keeps its own key, so the case-open publication
    # is still served after find results joined the same store.
    assert bet._scan_cache_key(find) != bet._scan_cache_key(default)
    assert bet._scan_cache_identity(_SHA, "fake-be") == default


def test_second_identical_search_never_reinvokes_the_scanner(
    tmp_path, cache_env, monkeypatch
):
    image = tmp_path / "image.E01"
    image.write_bytes(b"not really an image")
    monkeypatch.setattr(bet, "bulk_extractor_path", lambda: "fake-be")

    runs = {"count": 0}

    def fake_run_find(image_path, be, pattern, outdir):
        runs["count"] += 1
        target = Path(outdir)
        (target / "find.txt").write_text(
            "# BANNER\n4096\tneedle\tthe needle in context\n", encoding="utf-8"
        )
        (target / "report.xml").write_text("<report></report>", encoding="utf-8")
        return outdir

    monkeypatch.setattr(bet, "_run_find", fake_run_find)

    def controlled(name: str) -> Path:
        base = tmp_path / name
        base.parent.mkdir(parents=True, exist_ok=True)
        return provision_controlled_scratch_root(base, anchor=tmp_path).root_path

    first = bet.find_literal(
        str(image), "needle", output_root=controlled("run-a"), evidence_sha256=_SHA
    )
    assert "error" not in first, first
    assert runs["count"] == 1
    assert any("needle" in str(row) for row in first.get("rows", []))

    # The next message scans under a FRESH controlled root, so nothing of the
    # first question's scratch survives: only the publication can serve this.
    second = bet.find_literal(
        str(image), "needle", output_root=controlled("run-b"), evidence_sha256=_SHA
    )
    assert "error" not in second, second
    assert runs["count"] == 1
    assert any("needle" in str(row) for row in second.get("rows", []))

    # A DIFFERENT term is a different identity and is never served this one's
    # hits, so it scans.
    other = bet.find_literal(
        str(image), "haystack", output_root=controlled("run-c"), evidence_sha256=_SHA
    )
    assert "error" not in other, other
    assert runs["count"] == 2


def test_without_a_verified_digest_the_search_behaves_as_before(
    tmp_path, cache_env, monkeypatch
):
    image = tmp_path / "mem.raw"
    image.write_bytes(b"x")
    monkeypatch.setattr(bet, "bulk_extractor_path", lambda: "fake-be")

    runs = {"count": 0}

    def fake_run_find(image_path, be, pattern, outdir):
        runs["count"] += 1
        (Path(outdir) / "find.txt").write_text("# BANNER\n", encoding="utf-8")
        (Path(outdir) / "report.xml").write_text("<report></report>", encoding="utf-8")
        return outdir

    monkeypatch.setattr(bet, "_run_find", fake_run_find)

    def controlled(name: str) -> Path:
        return provision_controlled_scratch_root(tmp_path / name, anchor=tmp_path).root_path

    for name in ("run-a", "run-b"):
        result = bet.find_literal(
            str(image), "needle", output_root=controlled(name), evidence_sha256=None
        )
        assert "error" not in result, result
    assert runs["count"] == 2
    assert bet._published_find(None, "fake-be", "[nN]eedle") is None
