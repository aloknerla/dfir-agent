"""Load the local .env file independently of module import order.

Loading used to be a side effect of importing ``core.config``. Because
``core.environ`` resolves the endpoint and key without depending on that module,
importing it directly left the file unread. A valid .env file was consequently
reported as missing configuration without exposing the cause.

Loading now lives in an explicit, idempotent function called by both modules.
The result is retained so the environment preflight can report it.
"""

from __future__ import annotations

import os
from pathlib import Path

#: Populated on the first load and read by the environment preflight.
_STATE: dict[str, object] = {
    "attempted": False,
    "loaded": False,
    "path": None,
    "reason": None,
}

#: An explicit path overrides discovery. This is useful when the agent runs from
#: a case directory while credentials are stored elsewhere.
_ENV_PATH_VARIABLE = "DFA_ENV_FILE"


def _candidate_paths() -> list[Path]:
    """Return .env discovery locations in precedence order.

    The installed tool takes precedence over the working directory. Reversing
    that order would let an arbitrary launch directory silently supply an
    unrelated .env file. For a forensic tool, this is more than an inconvenience:
    credentials and tool paths would then come from outside the intended setup
    while still appearing to be valid configuration.
    """

    seen: set[Path] = set()
    candidates: list[Path] = []

    def _append(candidate: Path) -> None:
        if candidate not in seen:
            seen.add(candidate)
            candidates.append(candidate)

    package_root = Path(__file__).resolve().parent.parent
    for directory in [package_root, *package_root.parents]:
        _append(directory / ".env")

    # Per-user configuration supports installed packages that are not adjacent
    # to a repository checkout and remains stable across launch directories.
    _append(Path.home() / ".dfir-agent" / ".env")

    working_directory = Path.cwd()
    for directory in [working_directory, *working_directory.parents]:
        _append(directory / ".env")
    return candidates


def load_environment_file() -> dict[str, object]:
    """Load a .env file once per process and return its load state.

    Existing environment variables take precedence, so file contents never
    override an explicitly configured value.
    """

    if _STATE["attempted"]:
        return dict(_STATE)
    _STATE["attempted"] = True

    if os.environ.get("PYTHON_DOTENV_DISABLED"):
        _STATE["reason"] = "disabled by PYTHON_DOTENV_DISABLED"
        return dict(_STATE)

    try:
        from dotenv import load_dotenv
    except ImportError:
        # This is a required dependency. Record the reason because silently
        # skipping the import would otherwise look like missing configuration.
        _STATE["reason"] = "python-dotenv is not installed"
        return dict(_STATE)

    explicit = os.environ.get(_ENV_PATH_VARIABLE)
    if explicit:
        path = Path(explicit)
        if not path.is_file():
            _STATE["reason"] = f"{_ENV_PATH_VARIABLE} points to a missing file"
            return dict(_STATE)
        load_dotenv(path, override=False)
        _STATE.update({"loaded": True, "path": str(path)})
        return dict(_STATE)

    for candidate in _candidate_paths():
        if candidate.is_file():
            load_dotenv(candidate, override=False)
            _STATE.update({"loaded": True, "path": str(candidate)})
            return dict(_STATE)

    _STATE["reason"] = ".env file not found"
    return dict(_STATE)


def environment_file_state() -> dict[str, object]:
    """Return the most recent load state without attempting another load."""

    return dict(_STATE)
