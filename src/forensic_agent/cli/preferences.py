"""The small store of terminal settings this console keeps between sessions.

This module is TERMINAL PRESENTATION AND CONTROL only. Nothing stored here is
model-facing: it holds what the operator chose about their own console, keyed by
name in one small ``preferences.json``.

One file, not one per setting. The place a preference can be written is a
deployment fact rather than a matter of taste (see :func:`preferences_path`),
so every additional file is another directory a deployment has to keep
writable; none of these settings is worth that.

The store is deliberately separate from the provider ``.env`` so no console
setting can perturb the provider configuration schema, and every write is
atomic and additive so one setting can never truncate the file another one
wrote.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Final

_PREFERENCES_FILENAME: Final[str] = "preferences.json"
_CONSOLE_THEME_KEY: Final[str] = "console_theme"


def preferences_path(
    environment: Mapping[str, str] | None = None,
) -> Path:
    """Return the terminal preferences file, in a directory that can be written.

    A preference belongs to the operator, so it sits beside the provider
    configuration where an installed tool keeps its settings.  In a container
    that directory is mounted read-only on purpose — it carries the credential —
    and the choice would be lost every session.  Where a run directory is
    declared, the preference goes there instead: the writable, persistent place
    this deployment already owns, holding nothing about the evidence.
    """

    # Imported lazily: a render path that only needs to read one setting must
    # not pull in the heavier setup module to draw a prompt.
    from forensic_agent.cli.setup import configuration_path

    source = os.environ if environment is None else environment
    run_root = str(source.get("DFA_RUNS_DIR") or "").strip()
    if run_root:
        return Path(run_root) / _PREFERENCES_FILENAME
    return configuration_path(environment).parent / _PREFERENCES_FILENAME


def read_preferences(path: Path) -> dict[str, object]:
    """Return the stored preferences mapping, or an empty one if unreadable."""

    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return raw if isinstance(raw, dict) else {}


def read_preference(
    key: str,
    environment: Mapping[str, str] | None = None,
    *,
    path: Path | None = None,
) -> str | None:
    """Return one stored string setting, or ``None`` when it is absent.

    A stored value of the wrong type is reported as absent rather than coerced:
    the caller owns the vocabulary of its own setting and must be free to fall
    back to its documented default.
    """

    target = path if path is not None else preferences_path(environment)
    value = read_preferences(Path(target)).get(key)
    return value if isinstance(value, str) else None


def save_preference(
    key: str,
    value: str,
    environment: Mapping[str, str] | None = None,
    *,
    path: Path | None = None,
) -> None:
    """Persist one setting additively, preserving every other preference.

    The write is atomic so an interrupted console never leaves a half-written
    preferences file behind, and the read-modify-write keeps a second setting
    from being dropped when this one changes.
    """

    target = Path(path) if path is not None else preferences_path(environment)
    target.parent.mkdir(parents=True, exist_ok=True)

    stored = read_preferences(target) if target.is_file() else {}
    stored[key] = value
    payload = json.dumps(stored, ensure_ascii=False, indent=2, sort_keys=True) + "\n"

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.",
        suffix=".tmp",
        dir=target.parent,
        text=True,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


def load_console_theme(
    environment: Mapping[str, str] | None = None,
    *,
    path: Path | None = None,
) -> str:
    """Read the saved console theme, defaulting when absent, unknown or corrupt.

    A stored name that no longer exists — a theme removed between versions, a
    hand-edited file — is not an error the operator should meet at startup: the
    console falls back to the shipped palette and opens.
    """

    # Imported lazily, like every other reader here: the palette vocabulary
    # belongs to the console and must not be pulled in to draw a prompt.
    from forensic_agent.tui.model import DEFAULT_PALETTE, available_palettes

    value = (read_preference(_CONSOLE_THEME_KEY, environment, path=path) or "").strip()
    normalized = value.casefold()
    return normalized if normalized in available_palettes() else DEFAULT_PALETTE


def save_console_theme(
    value: str,
    environment: Mapping[str, str] | None = None,
    *,
    path: Path | None = None,
) -> None:
    """Persist the console theme additively, preserving any other preferences."""

    from forensic_agent.tui.model import available_palettes

    normalized = (value or "").strip().casefold()
    if normalized not in available_palettes():
        raise ValueError(f"Unknown console theme: {value}")
    save_preference(_CONSOLE_THEME_KEY, normalized, environment, path=path)
