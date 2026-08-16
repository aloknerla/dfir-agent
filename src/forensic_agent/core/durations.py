"""One rendering of an elapsed duration, for every surface that shows one.

A run that took 424 seconds used to read ``424.0 s``, and the operator had to
divide by sixty in their head before the number meant anything. Past a minute a
seconds count stops being a quantity a reader can feel, so at and above
:data:`MINUTE_THRESHOLD_S` — sixty seconds, the point where the first whole
minute exists — the same value is written ``7m 04s`` instead. Below the
threshold the plain seconds count is already the faster read and is left exactly
as it was, decimal included, because a tool call that took ``0.3s`` says more
than ``0m 00s`` ever could.

The threshold lives here rather than at each call site so the TUI, the line
console and the written report can never drift into disagreeing about when a
duration becomes minutes. Call sites keep their own surrounding layout and pass
``compact`` and ``decimals`` to match the spacing and precision they already
used; only the sub-minute form varies between them, and the minutes form is the
same everywhere.
"""

from __future__ import annotations

#: Durations at or above this many seconds are written as minutes and seconds.
#: Sixty is the first value for which a whole minute exists, so it is also the
#: first value a reader would otherwise have to convert by hand.
MINUTE_THRESHOLD_S = 60.0


def format_duration(seconds: float, *, compact: bool = False, decimals: int = 1) -> str:
    """Render ``seconds`` as a duration, in minutes and seconds past a minute.

    Under :data:`MINUTE_THRESHOLD_S` (60 s) the result is a seconds count with
    ``decimals`` places and the ``s`` suffix — ``8.7 s``, or ``8.7s`` when
    ``compact`` is set for the tight activity columns. At or above the
    threshold it is whole minutes and zero-padded whole seconds, ``7m 04s``,
    with no decimal and no space variant: sixty seconds is where a bare seconds
    count stops being readable at a glance.

    The branch is taken on the *rounded* value, so a duration that rounds up to
    sixty is written ``1m 00s`` rather than the self-contradicting ``60.0 s``.
    """

    value = max(0.0, float(seconds))
    if round(value, decimals) < MINUTE_THRESHOLD_S:
        rendered = f"{value:.{decimals}f}"
        return f"{rendered}s" if compact else f"{rendered} s"
    whole_seconds = round(value)
    return f"{whole_seconds // 60}m {whole_seconds % 60:02d}s"
