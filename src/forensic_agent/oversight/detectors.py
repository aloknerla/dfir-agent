"""Heuristic detectors for adversarial tool descriptions and outputs.

These detectors provide forensic annotations. They are not the structural
security control; capability policy enforcement remains the blocking boundary.
"""

from __future__ import annotations

import re
import sys
import unicodedata
from collections.abc import Callable
from typing import Any

_INJECTION_RULES = [
    (
        re.compile(
            r"ignore\s+(?:all\s+|any\s+|the\s+)?previous\s+(?:instructions|prompts|messages)",
            re.I,
        ),
        "override:ignore-previous",
    ),
    (
        re.compile(
            r"disregard\s+(?:all\s+|any\s+|the\s+|your\s+)?(?:previous|prior|above)",
            re.I,
        ),
        "override:disregard",
    ),
    (
        re.compile(
            r"\byou\s+are\s+now\b|new\s+instructions\s*:|change\s+your\s+(?:role|instructions)",
            re.I,
        ),
        "override:role-switch",
    ),
    (
        re.compile(
            r"\b(?:exfiltrat\w*|leak|upload|send)\b.{0,40}(?:https?://|ftp://|external|to\s+the\s+server)",
            re.I,
        ),
        "exfil",
    ),
    (
        re.compile(r"do\s+not\s+(?:flag|report|mention|tell|log|record|include)", re.I),
        "suppress-findings",
    ),
    (
        re.compile(
            r"mark\s+.{0,40}?\bas\s+(?:clean|safe|benign|not\s+suspicious|legitimate)",
            re.I,
        ),
        "force-clean",
    ),
    (
        re.compile(
            r"pre-?cleared|reviewed\s+and\s+(?:signed|approved)|authoriz\w+\s+by\b|forensic\s+team\s+(?:says|cleared|approved|confirmed)",
            re.I,
        ),
        "false-authority",
    ),
    (
        re.compile(r"<\s*important\s*>|\[\s*system\s*\]|###\s*system|<\s*system\s*>", re.I),
        "fake-system-tag",
    ),
]

# Format, zero-width and bidi characters commonly used to hide directives.
# Explicit escapes keep the security-sensitive character set reviewable and
# prevent an editor or source-code encoding from silently changing it.
_ZERO_WIDTH = re.compile(
    r"[\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]"
)
_POISON_LABELS = {
    "override:ignore-previous",
    "override:disregard",
    "override:role-switch",
    "fake-system-tag",
    "exfil",
    "suppress-findings",
    "force-clean",
}


def _facade_dependency(name: str, implementation: Callable[..., Any]) -> Callable[..., Any]:
    """Resolve an override applied through the historical ``core`` module."""
    facade = sys.modules.get("forensic_agent.oversight.core")
    if facade is None:
        return implementation
    candidate = getattr(facade, name, implementation)
    return candidate if callable(candidate) else implementation


def _normalize(text: Any) -> str:
    """Fold common encoding and whitespace evasions to a canonical form."""
    normalized = unicodedata.normalize("NFKC", str(text or ""))
    normalized = "".join(
        character
        for character in normalized
        if character in "\n\t\r" or unicodedata.category(character) not in ("Cf", "Cc")
    )
    normalized = (
        normalized.replace("\\n", " ").replace("\\t", " ").replace("\\r", " ")
    )
    return re.sub(r"\s+", " ", normalized)


def detect_injection(text: Any) -> list:
    """Return prompt-injection labels found in a tool output."""
    if not text:
        return []
    normalized = _normalize(text)
    return sorted(
        {label for expression, label in _INJECTION_RULES if expression.search(normalized)}
    )


def detect_tool_poisoning(name: str, description: str) -> list:
    """Return reasons a tool description looks poisoned."""
    del name  # The name is retained in the stable API for caller-side reporting.
    description_text = str(description or "")
    reasons = []
    if _ZERO_WIDTH.search(description_text):
        reasons.append("zero-width/hidden characters in description")
    injection_detector = _facade_dependency("detect_injection", detect_injection)
    reasons += [
        label
        for label in injection_detector(description_text)
        if label in _POISON_LABELS
    ]
    return sorted(set(reasons))


def scan_tools(tools: list) -> list:
    """Return ``[{tool, reasons}]`` records for poisoned tool descriptions."""
    output = []
    poisoning_detector = _facade_dependency(
        "detect_tool_poisoning", detect_tool_poisoning
    )
    for tool in tools:
        reasons = poisoning_detector(
            getattr(tool, "name", ""), getattr(tool, "description", "")
        )
        if reasons:
            output.append({"tool": getattr(tool, "name", ""), "reasons": reasons})
    return output


__all__ = [
    "detect_injection",
    "detect_tool_poisoning",
    "scan_tools",
]
