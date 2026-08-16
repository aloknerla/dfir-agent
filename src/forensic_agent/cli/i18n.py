"""Terminal UI language layer for the interactive console.

This module is TERMINAL PRESENTATION only. It never touches model-facing text,
the transport schema, tool/operation descriptions, or anything that feeds a
sealed digest (``system_prompt_sha256`` / ``tool_registry_sha256``). English is
the source language and lives inline at the render sites; Croatian renderings
are a curated catalog keyed by the exact English string, shipped as data in
``i18n_hr.json`` beside this module. Keeping the catalog in a data file rather
than as literals here means every ``.py`` file in the package stays English-only,
so the accidental-Croatian guard still protects the render code.

The lookup is deliberately honest: a string with no catalog entry, and every
string while the language is English, renders unchanged. That is why passing a
technical identifier (a tool name, a path, a hash) through :func:`t` is safe —
none of them are catalog keys, so they are returned byte-identical on either
language. Render sites must still avoid routing identifiers through the layer;
the fallback is a safety net, not a licence.

The choice persists through :mod:`forensic_agent.cli.preferences`, the console's
shared settings store, kept separate from the provider ``.env`` so the provider
configuration schema is never touched by a language change.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Final

import forensic_agent.cli.preferences as _preferences

#: The languages the terminal can render. English is the source; Croatian is the
#: only curated translation. Order is stable for presenting the choice.
SUPPORTED_LANGUAGES: Final[tuple[str, ...]] = ("en", "hr")

#: The language an unconfigured console opens in, and the fallback whenever a
#: saved preference is missing or unreadable.
DEFAULT_LANGUAGE: Final[str] = "en"

#: Human names for the current-setting message, in each language's own words.
_LANGUAGE_DISPLAY_NAMES: Final[Mapping[str, Mapping[str, str]]] = {
    "en": {"en": "English", "hr": "Croatian"},
    "hr": {"en": "engleski", "hr": "hrvatski"},
}

_UI_LANGUAGE_KEY: Final[str] = "ui_language"

#: Process-global current language. The console is single-threaded and the
#: language is a whole-terminal setting, so a module-level value is the honest
#: model: one console, one active language.
_current_language: str = DEFAULT_LANGUAGE

#: Lazily loaded, then cached, per-language catalogs keyed by English source.
_catalogs: dict[str, Mapping[str, str]] = {}


def normalize_language(value: str) -> str:
    """Return the canonical code for a supported language or raise ValueError.

    Accepts surrounding whitespace and any casing so ``/language HR`` and the
    saved lowercase code both resolve; anything else is rejected rather than
    silently coerced, because a mistyped code should not quietly pick English.
    """

    normalized = (value or "").strip().casefold()
    if normalized in SUPPORTED_LANGUAGES:
        return normalized
    raise ValueError(
        f"Unsupported language: {value!r}. Choose one of: "
        + ", ".join(SUPPORTED_LANGUAGES)
    )


def current_language() -> str:
    """Return the active terminal language code."""

    return _current_language


def set_language(value: str) -> str:
    """Set and return the active terminal language, validating the code."""

    global _current_language
    _current_language = normalize_language(value)
    return _current_language


def language_display_name(language: str, *, in_language: str | None = None) -> str:
    """Name a language in the words of ``in_language`` (default: the active one)."""

    code = normalize_language(language)
    speaker = normalize_language(in_language) if in_language else _current_language
    return _LANGUAGE_DISPLAY_NAMES.get(speaker, {}).get(code, code)


def _catalog(language: str) -> Mapping[str, str]:
    """Return the cached catalog for a language; English carries no catalog."""

    if language == DEFAULT_LANGUAGE:
        return {}
    cached = _catalogs.get(language)
    if cached is not None:
        return cached
    resource = Path(__file__).with_name(f"i18n_{language}.json")
    try:
        raw = json.loads(resource.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raw = {}
    catalog = {
        key: value
        # The leading-underscore keys are notes for maintainers, not renderable
        # strings; excluding them keeps them from ever masking a real source.
        for key, value in raw.items()
        if isinstance(key, str)
        and not key.startswith("_")
        and isinstance(value, str)
    }
    _catalogs[language] = catalog
    return catalog


def t(text: str) -> str:
    """Return the active-language rendering of an English UI string.

    Falls back to ``text`` unchanged for English, for any string absent from the
    catalog, and for any technical identifier — none of which are catalog keys.
    """

    if _current_language == DEFAULT_LANGUAGE:
        return text
    return _catalog(_current_language).get(text, text)


def preferences_path(
    environment: Mapping[str, str] | None = None,
) -> Path:
    """Return the file the console keeps its settings in.

    Kept here under its established name so the language layer's callers do not
    have to know where the store moved; the placement rule itself belongs to
    :func:`forensic_agent.cli.preferences.preferences_path`.
    """

    return _preferences.preferences_path(environment)


def load_saved_language(
    environment: Mapping[str, str] | None = None,
    *,
    path: Path | None = None,
) -> str:
    """Read the saved UI language, defaulting to English when absent or invalid."""

    value = _preferences.read_preference(_UI_LANGUAGE_KEY, environment, path=path)
    if value is not None:
        try:
            return normalize_language(value)
        except ValueError:
            return DEFAULT_LANGUAGE
    return DEFAULT_LANGUAGE


def save_language(
    value: str,
    environment: Mapping[str, str] | None = None,
    *,
    path: Path | None = None,
) -> None:
    """Persist the UI language additively, preserving any other preferences."""

    _preferences.save_preference(
        _UI_LANGUAGE_KEY, normalize_language(value), environment, path=path
    )
