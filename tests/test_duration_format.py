"""The one duration rendering shared by the console, the TUI and the report.

Under a minute a duration stays a seconds count; at sixty seconds and above it
becomes minutes and seconds, because that is the point past which a reader has
to do the division themselves. Both halves of that rule are pinned here, along
with the boundary, so no surface can quietly reintroduce a bare ``424.0 s``.
"""

from __future__ import annotations

import pytest

from forensic_agent.core.durations import MINUTE_THRESHOLD_S, format_duration


def test_the_threshold_is_one_whole_minute():
    assert MINUTE_THRESHOLD_S == 60.0


@pytest.mark.parametrize(
    ("seconds", "expected"),
    [
        (0.0, "0.0 s"),
        (8.7, "8.7 s"),
        (23.0, "23.0 s"),
        (59.9, "59.9 s"),
    ],
)
def test_under_a_minute_stays_a_seconds_count(seconds, expected):
    """Below the threshold nothing changed: one decimal, then the unit."""

    assert format_duration(seconds) == expected


@pytest.mark.parametrize(
    ("seconds", "expected"),
    [
        (60.0, "1m 00s"),
        (64.0, "1m 04s"),
        (65.4, "1m 05s"),
        (424.0, "7m 04s"),
        (599.0, "9m 59s"),
        (3600.0, "60m 00s"),
    ],
)
def test_a_minute_and_over_reads_as_minutes_and_seconds(seconds, expected):
    assert format_duration(seconds) == expected


@pytest.mark.parametrize("seconds", [60.0, 64.0, 424.0, 3600.0])
def test_the_seconds_remainder_is_always_two_digits(seconds):
    """``7m 4s`` would misread as a different quantity beside ``7m 40s``."""

    minutes, _, remainder = format_duration(seconds).partition(" ")
    assert minutes.endswith("m")
    assert len(remainder) == 3 and remainder.endswith("s")
    assert remainder[:2].isdigit()


def test_a_remainder_under_ten_keeps_its_leading_zero():
    assert format_duration(424.0) == "7m 04s"
    assert format_duration(305.0) == "5m 05s"
    assert format_duration(60.9) == "1m 01s"


def test_the_compact_form_drops_only_the_space_before_the_unit():
    """The activity columns write ``6.4s``; the statistics lines write ``6.4 s``.

    Each call site keeps the spacing it already had, so the flag may not change
    anything else — and the minutes form is identical either way.
    """

    assert format_duration(6.4, compact=True) == "6.4s"
    assert format_duration(6.4) == "6.4 s"
    assert format_duration(424.0, compact=True) == format_duration(424.0) == "7m 04s"


def test_the_precision_of_the_seconds_form_is_the_call_site_s_own():
    assert format_duration(1.234, compact=True, decimals=2) == "1.23s"
    assert format_duration(12.4, compact=True, decimals=0) == "12s"
    # Precision belongs to the sub-minute form alone; minutes are always whole.
    assert format_duration(424.0, compact=True, decimals=2) == "7m 04s"
    assert format_duration(424.0, compact=True, decimals=0) == "7m 04s"


def test_a_value_that_rounds_up_to_sixty_crosses_the_threshold():
    """``60.0 s`` is the one output the rule exists to prevent, so a duration
    that only reaches sixty by rounding must cross with it."""

    assert format_duration(59.96) == "1m 00s"
    assert format_duration(59.94) == "59.9 s"
    # With no decimals the same argument applies a whole second earlier.
    assert format_duration(59.6, decimals=0) == "1m 00s"


def test_a_negative_clock_reading_never_renders_as_a_negative_duration():
    """Wall-clock arithmetic across a step adjustment can go slightly negative;
    a run is never shown as having taken less than no time."""

    assert format_duration(-0.4) == "0.0 s"


def test_the_statistics_line_and_an_activity_row_agree_on_a_long_run():
    """The two sites the reader compares side by side must not disagree."""

    pytest.importorskip("textual")
    from rich.console import Console

    from forensic_agent.tui.app import _activity_row
    from forensic_agent.tui.model import ToolEvent

    row = _activity_row(
        ToolEvent(
            sequence=1,
            function="filesystem",
            operation="find_files",
            args_summary="",
            status="executed",
            duration_s=424.0,
        )
    )
    console = Console(width=100, no_color=True)
    with console.capture() as captured:
        console.print(row)
    assert "7m 04s" in captured.get()
    assert "424.0" not in captured.get()
