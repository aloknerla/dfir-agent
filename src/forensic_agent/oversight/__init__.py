"""Oversight policy, enforcement, detectors, and tamper-evident audit API."""

from __future__ import annotations

from typing import Any

from forensic_agent.oversight import core as core
from forensic_agent.oversight.core import (
    ALL_CAPS,
    CAP_CONTROLLED_SCRATCH,
    CAP_DECODE,
    CAP_NETWORK,
    CAP_READ_EVIDENCE,
    CAP_READ_HOST_PATH,
    CAP_SPAWN,
    CAP_WRITE,
    DEFAULT_TOOL_CAPS,
    FORENSIC_CHECKLIST,
    PATH_ARG_NAMES,
    RISK_NAMES,
    Decision,
    OversightBoundOutput,
    OversightGate,
    OversightLog,
    Policy,
    detect_injection,
    detect_tool_poisoning,
    enforce,
    evaluate,
    reconstruct,
    scan_tools,
    verify_chain,
    wrap_with_oversight,
)

__all__ = [
    "ALL_CAPS",
    "CAP_CONTROLLED_SCRATCH",
    "CAP_DECODE",
    "CAP_NETWORK",
    "CAP_READ_EVIDENCE",
    "CAP_READ_HOST_PATH",
    "CAP_SPAWN",
    "CAP_WRITE",
    "DEFAULT_TOOL_CAPS",
    "Decision",
    "FORENSIC_CHECKLIST",
    "OversightBoundOutput",
    "OversightGate",
    "OversightLog",
    "PATH_ARG_NAMES",
    "Policy",
    "RISK_NAMES",
    "detect_injection",
    "detect_tool_poisoning",
    "enforce",
    "evaluate",
    "reconstruct",
    "scan_tools",
    "verify_chain",
    "wrap_with_oversight",
]


def __getattr__(name: str) -> Any:
    """Keep direct imports of former monolith dependencies compatible."""
    return getattr(core, name)


def __dir__() -> list[str]:
    return sorted({*globals(), *dir(core)})
