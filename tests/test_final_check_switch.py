"""The final-check switch: off for speed must never mean unrunnable.

Preparation refuses explicit multi-source coverage without verification,
so the console has to drop both together. Turning the check off once made
every question fail with that refusal; the pairing below is the fix.
"""

from __future__ import annotations

import inspect

from forensic_agent.cli import controlled


def test_the_environment_switch_parses_the_usual_spellings(monkeypatch):
    for value, expected in [
        (None, True),
        ("", True),
        ("1", True),
        ("0", False),
        ("false", False),
        ("OFF", False),
        ("no", False),
    ]:
        if value is None:
            monkeypatch.delenv("DFA_FINAL_VERIFICATION", raising=False)
        else:
            monkeypatch.setenv("DFA_FINAL_VERIFICATION", value)
        assert controlled._console_runs_the_final_check() is expected


def test_coverage_enforcement_is_paired_with_the_final_check():
    """Regression: with the check off, ask() must not request coverage —
    preparation raises "explicit multi-source coverage requires verified
    standardized case evidence" on that combination and every question
    dies before it starts."""

    source = inspect.getsource(controlled.ControlledInvestigationSession.ask)
    coverage = source.index("enforce_explicit_multisource_coverage=(")
    clause = source[coverage : coverage + 250]
    assert "_console_runs_the_final_check()" in clause


def test_first_tool_choice_is_paired_with_the_final_check():
    """Regression: the arm policy derives the first tool choice from
    ``verify`` — required on the verified arm, auto otherwise. A pinned
    "required" with the check off makes preparation refuse every run with
    "first_investigation_tool_choice differs from the deterministic arm
    policy"."""

    source = inspect.getsource(controlled.ControlledInvestigationSession.ask)
    pin = source.index("first_investigation_tool_choice=(")
    clause = source[pin : pin + 200]
    assert '"required" if _console_runs_the_final_check() else "auto"' in clause
