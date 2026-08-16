"""Per-question step and tool-call budgets the interactive console remembers.

Both bound one question's investigation loop rather than the case, and both
outlive the session: they are written to the operator's saved configuration so
the next console starts on the budgets this one ended with, exactly like the
terminal language and the reasoning effort. A budget passed on the command line
still wins for that launch; only the standing default is stored here.

The value has no fixed upper bound. Twenty is the default an unconfigured
console uses, and the fallback whenever a saved value is missing or unreadable,
but the operator, not the tool, sets the ceiling.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Final

import forensic_agent.cli.preferences as _preferences

#: The budget an unconfigured console uses, and the fallback for an unreadable
#: saved value.
DEFAULT_BUDGET: Final[int] = 20

_MAX_STEPS_KEY: Final[str] = "max_steps"
_MAX_TOOL_CALLS_KEY: Final[str] = "max_tool_calls"


def normalize_budget(value: object) -> int:
    """Return a valid budget or raise ValueError.

    A budget is a whole number of at least one. Anything else is rejected rather
    than coerced, so a mistyped value never quietly leaves the console on a
    budget the operator did not choose.
    """

    if not isinstance(value, (int, float, str)):
        raise TypeError(
            f"budget must be a number or a numeric string, not {type(value).__name__}"
        )
    parsed = int(value)
    if parsed < 1:
        raise ValueError("budget must be at least 1")
    return parsed


def _load(key: str, environment: Mapping[str, str] | None, path: Path | None) -> int:
    stored = _preferences.read_preference(key, environment, path=path)
    if stored is not None:
        try:
            return normalize_budget(stored)
        except (ValueError, TypeError):
            return DEFAULT_BUDGET
    return DEFAULT_BUDGET


def load_saved_max_steps(
    environment: Mapping[str, str] | None = None, *, path: Path | None = None
) -> int:
    """Read the saved step budget, defaulting to twenty when absent or invalid."""

    return _load(_MAX_STEPS_KEY, environment, path)


def load_saved_max_tool_calls(
    environment: Mapping[str, str] | None = None, *, path: Path | None = None
) -> int:
    """Read the saved tool-call budget, defaulting to twenty when absent or invalid."""

    return _load(_MAX_TOOL_CALLS_KEY, environment, path)


def save_max_steps(
    value: object, environment: Mapping[str, str] | None = None, *, path: Path | None = None
) -> None:
    """Persist the step budget additively, preserving any other preferences."""

    _preferences.save_preference(
        _MAX_STEPS_KEY, str(normalize_budget(value)), environment, path=path
    )


def save_max_tool_calls(
    value: object, environment: Mapping[str, str] | None = None, *, path: Path | None = None
) -> None:
    """Persist the tool-call budget additively, preserving any other preferences."""

    _preferences.save_preference(
        _MAX_TOOL_CALLS_KEY, str(normalize_budget(value)), environment, path=path
    )
