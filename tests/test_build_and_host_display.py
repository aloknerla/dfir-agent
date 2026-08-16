"""The two things a console has to be able to say about where it is running.

Both modules answer questions whose wrong answer is silent: a build identifier
that names the wrong build, and an export path the operator cannot open. Neither
failure raises, so neither is caught by anything except a test that reads the
string.
"""

from __future__ import annotations

import pytest

from forensic_agent.cli import build_identity as _build
from forensic_agent.cli import host_display as _host


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        _build.ENV_BUILD_ID,
        _build.ENV_BUILD_TIME,
        _host.ENV_HOST_RUNS,
        _host.ENV_HOST_EVIDENCE,
        "DFA_CONTAINERIZED",
    ):
        monkeypatch.delenv(name, raising=False)


def test_launcher_supplied_image_wins_over_every_local_guess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(_build.ENV_BUILD_ID, "sha256:fd659396c5f8a930bbd553ca8524")
    monkeypatch.setenv(_build.ENV_BUILD_TIME, "2026-08-17T17:39:28.334897553Z")
    identity = _build.build_identity()
    assert identity is not None
    assert identity.source == "image"
    # Twelve characters, as docker itself abbreviates an image id.
    assert "fd659396c5f8" in identity.label
    assert "sha256" not in identity.label
    # The nanosecond precision docker emits must not defeat the date.
    assert "2026-08-17" in identity.label


def test_a_build_with_no_launcher_still_says_something_true() -> None:
    identity = _build.build_identity()
    assert identity is not None
    assert identity.source in {"commit", "mtime"}
    assert identity.label


def test_the_label_reads_as_a_build_and_not_as_a_note_about_source_files(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """"code dated 2026-08-11 14:19" was developer language on an operator's
    screen. Whatever lookup answers, the label has to read as a build."""

    monkeypatch.setenv("DFA_CONTAINERIZED", "1")  # force the mtime lookup
    identity = _build.build_identity()
    assert identity is not None
    assert identity.label.startswith("build ")
    assert "code dated" not in identity.label
    assert "mtime" not in identity.label


def test_a_current_build_is_told_nothing_and_an_old_one_is_warned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The warning has to be rare to be read. Silence is the normal answer."""

    import time

    monkeypatch.setenv(_build.ENV_BUILD_ID, "abcdef1234567890")
    monkeypatch.setenv(_build.ENV_BUILD_TIME, "2026-08-01T09:00:00Z")
    fresh = time.mktime((2026, 8, 3, 9, 0, 0, 0, 0, -1))
    assert _build.staleness_note(now=fresh) == ""

    old = fresh + 40 * 86400
    warned = _build.staleness_note(now=old)
    assert warned
    assert "weeks old" in warned
    # Written for an operator: no mechanism, and something to do about it.
    for jargon in ("mtime", "image layer", "runner", "tree", "commit"):
        assert jargon not in warned
    assert "Rebuild" in warned


def test_a_build_that_cannot_be_dated_never_claims_to_be_stale(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(_build.ENV_BUILD_ID, "abcdef123456")
    monkeypatch.setenv(_build.ENV_BUILD_TIME, "not a date")
    identity = _build.build_identity()
    assert identity is not None and identity.moment is None
    assert _build.staleness_note(now=2 ** 31) == ""


def test_an_unparseable_timestamp_is_dropped_rather_than_printed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(_build.ENV_BUILD_TIME, "not a date")
    monkeypatch.setenv(_build.ENV_BUILD_ID, "abcdef123456")
    identity = _build.build_identity()
    assert identity is not None
    assert identity.label == "build abcdef123456"


def test_container_export_path_becomes_the_host_path_the_operator_typed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DFA_CONTAINERIZED", "1")
    monkeypatch.setenv(_host.ENV_HOST_RUNS, "D:\\dfir-agent-research\\diplomski-rad\\runs")
    shown = _host.display_path("/runtime/exports/case_completion_abc.md")
    assert shown == (
        "D:\\dfir-agent-research\\diplomski-rad\\runs\\exports\\case_completion_abc.md"
    )
    assert not _host.path_is_container_only("/runtime/exports/case_completion_abc.md")


def test_a_posix_host_root_keeps_posix_separators(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DFA_CONTAINERIZED", "1")
    monkeypatch.setenv(_host.ENV_HOST_RUNS, "/home/adrian/cases/runs")
    assert (
        _host.display_path("/runtime/exports/report.md")
        == "/home/adrian/cases/runs/exports/report.md"
    )


def test_an_unmapped_container_path_is_named_as_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DFA_CONTAINERIZED", "1")
    monkeypatch.setenv(_host.ENV_HOST_RUNS, "D:\\cases\\runs")
    shown = _host.display_path("/tmp/scratch.md")
    assert shown == "/tmp/scratch.md (not reachable from your computer)"
    assert _host.path_is_container_only("/tmp/scratch.md")


def test_without_a_declared_host_root_the_path_is_marked_not_guessed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DFA_CONTAINERIZED", "1")
    shown = _host.display_path("/runtime/exports/report.md")
    assert shown == "/runtime/exports/report.md (not reachable from your computer)"


def test_outside_a_container_nothing_is_rewritten(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(_host.ENV_HOST_RUNS, "D:\\cases\\runs")
    assert _host.display_path("/runtime/exports/report.md") == (
        "/runtime/exports/report.md"
    )


def test_the_evidence_mount_translates_too(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DFA_CONTAINERIZED", "1")
    monkeypatch.setenv(_host.ENV_HOST_EVIDENCE, "D:\\Cases\\case-001")
    assert _host.display_path("/evidence/disk.E01") == "D:\\Cases\\case-001\\disk.E01"
    assert _host.host_evidence_root() == "D:\\Cases\\case-001"
