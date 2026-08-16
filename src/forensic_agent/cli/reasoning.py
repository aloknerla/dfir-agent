"""How much reasoning effort the interactive console asks the model to spend.

This is a run-time control on purpose. Reasoning is the dominant term in what
an operator waits through: at a realistic turn size (~16k prompt tokens) a
request with reasoning takes tens of seconds against roughly two with the
parameter omitted, and one question costs several requests. Whether that spend
buys forensic accuracy depends on the case, so the effort is a setting the
operator moves between questions, exactly like the terminal language.

The vocabulary is not invented here. It is the contract
:func:`forensic_agent.core.config.agent_reasoning_effort` already states:
``low`` / ``medium`` / ``high`` are the efforts OpenRouter carries for the
reasoning-capable model families, and ``none`` / ``off`` / empty mean the
request carries no reasoning parameter at all. Those names are protocol tokens
travelling to the provider, so they are never translated; only the labels
around them are.

Scope: this setting belongs to the interactive console and nothing else. Other
callers state their own decoding profile at the call site, and
:class:`~forensic_agent.cli.controlled.ControlledInvestigationSession`
takes the effort as an ordinary argument defaulting to :data:`DEFAULT_REASONING_EFFORT`,
so a caller that does not ask for the setting can never inherit it. Nothing
here reads or writes ``DFA_REASONING_EFFORT`` either: that variable is the
agent engines' own default, and a console setting quietly reading or rewriting
it would entangle the two.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Final

import forensic_agent.cli.preferences as _preferences

#: The name that means "send no reasoning parameter". Distinct from the three
#: efforts because it is not a value the provider ever sees.
OMITTED_EFFORT: Final[str] = "none"

#: The choices the console offers, ordered from cheapest to most expensive so
#: the listing reads as the cost dial it is.
REASONING_EFFORTS: Final[tuple[str, ...]] = (OMITTED_EFFORT, "low", "medium", "high")

#: The effort an unconfigured console uses, and the fallback whenever a saved
#: choice is missing or unreadable. ``high``, matching the agent engines' own
#: default: a cheaper profile risks runs concluding "cannot be determined" after
#: a handful of shallow calls with budget to spare (e.g. nine directory listings
#: for an e-mail question, stopping inside the right folder without reading a
#: file). An operator who wants the cheap profile still has it, one
#: ``/effort low`` away.
DEFAULT_REASONING_EFFORT: Final[str] = "high"

#: Every spelling ``agent_reasoning_effort`` treats as "omit the parameter".
#: Accepted on input so the setting and the environment variable cannot mean
#: different things by the same word.
_OMISSION_SPELLINGS: Final[frozenset[str]] = frozenset({"none", "off", ""})

_REASONING_EFFORT_KEY: Final[str] = "reasoning_effort"

#: Process-global current effort. The console is single-threaded and the effort
#: is a whole-terminal setting, so a module-level value is the honest model:
#: one console, one active choice.
_current_effort: str = DEFAULT_REASONING_EFFORT


def normalize_effort(value: str) -> str:
    """Return the canonical name for a supported choice or raise ValueError.

    Accepts surrounding whitespace and any casing so ``/effort HIGH`` and the
    saved lowercase name both resolve. Anything else is rejected rather than
    silently coerced: a mistyped choice must not quietly leave the console on a
    setting the operator did not pick.
    """

    normalized = (value or "").strip().casefold()
    if normalized in _OMISSION_SPELLINGS:
        return OMITTED_EFFORT
    if normalized in REASONING_EFFORTS:
        return normalized
    raise ValueError(
        f"Unsupported reasoning effort: {value!r}. Choose one of: "
        + ", ".join(REASONING_EFFORTS)
    )


def current_effort() -> str:
    """Return the active reasoning-effort choice."""

    return _current_effort


def set_effort(value: str) -> str:
    """Set and return the active reasoning effort, validating the choice."""

    global _current_effort
    _current_effort = normalize_effort(value)
    return _current_effort


def request_effort(choice: str) -> str | None:
    """Return what a request carries for a choice; ``None`` omits the parameter.

    The distinction matters at the call site: a profile whose ``reasoning_effort``
    is ``None`` is read by the agent request factories as "unset", and they fall
    back to ``agent_reasoning_effort()`` — whose own default is ``high``. So
    ``None`` here states the intent only; the caller still has to keep the
    parameter off the request surface (see
    :func:`forensic_agent.cli.controlled._decoding_controls`).
    """

    normalized = normalize_effort(choice)
    return None if normalized == OMITTED_EFFORT else normalized


def load_saved_effort(
    environment: Mapping[str, str] | None = None,
    *,
    path: Path | None = None,
) -> str:
    """Read the saved choice, defaulting to today's effort when absent or invalid."""

    value = _preferences.read_preference(_REASONING_EFFORT_KEY, environment, path=path)
    if value is not None:
        try:
            return normalize_effort(value)
        except ValueError:
            return DEFAULT_REASONING_EFFORT
    return DEFAULT_REASONING_EFFORT


def save_effort(
    value: str,
    environment: Mapping[str, str] | None = None,
    *,
    path: Path | None = None,
) -> None:
    """Persist the reasoning effort additively, preserving any other preferences."""

    _preferences.save_preference(
        _REASONING_EFFORT_KEY, normalize_effort(value), environment, path=path
    )
