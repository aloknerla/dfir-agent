"""Backward-compatible facade for the modular oversight implementation.

The oversight implementation is split by responsibility:

* :mod:`forensic_agent.oversight.policy` owns capability policy and evaluation;
* :mod:`forensic_agent.oversight.detectors` owns adversarial-content detectors;
* :mod:`forensic_agent.oversight.audit` owns the log and hash-chain utilities;
* :mod:`forensic_agent.oversight.enforcement` owns the gate and tool wrappers.

Imports through this historical module remain supported. Export lookup is
deliberately lazy: besides avoiding a dependency cycle, that means a test or
experiment which monkeypatches ``forensic_agent.oversight.core.<dependency>``
continues to affect the moved implementation at the same call sites as before.
"""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from forensic_agent.oversight.audit import (
        FORENSIC_CHECKLIST,
        OversightLog,
        reconstruct,
        verify_chain,
    )
    from forensic_agent.oversight.detectors import (
        detect_injection,
        detect_tool_poisoning,
        scan_tools,
    )
    from forensic_agent.oversight.enforcement import (
        OversightBoundOutput,
        OversightGate,
        enforce,
        wrap_with_oversight,
    )
    from forensic_agent.oversight.policy import (
        ALL_CAPS,
        CAP_CONTROLLED_SCRATCH,
        CAP_DECODE,
        CAP_NETWORK,
        CAP_READ_EVIDENCE,
        CAP_READ_HOST_PATH,
        CAP_SPAWN,
        CAP_WRITE,
        DEFAULT_TOOL_CAPS,
        PATH_ARG_NAMES,
        RISK_NAMES,
        Decision,
        Policy,
        evaluate,
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

_EXPORTS: dict[str, tuple[str, str | None]] = {
    "ALL_CAPS": ("forensic_agent.oversight.policy", "ALL_CAPS"),
    "CAP_CONTROLLED_SCRATCH": (
        "forensic_agent.oversight.policy",
        "CAP_CONTROLLED_SCRATCH",
    ),
    "CAP_DECODE": ("forensic_agent.oversight.policy", "CAP_DECODE"),
    "CAP_NETWORK": ("forensic_agent.oversight.policy", "CAP_NETWORK"),
    "CAP_READ_EVIDENCE": (
        "forensic_agent.oversight.policy",
        "CAP_READ_EVIDENCE",
    ),
    "CAP_READ_HOST_PATH": (
        "forensic_agent.oversight.policy",
        "CAP_READ_HOST_PATH",
    ),
    "CAP_SPAWN": ("forensic_agent.oversight.policy", "CAP_SPAWN"),
    "CAP_WRITE": ("forensic_agent.oversight.policy", "CAP_WRITE"),
    "DEFAULT_TOOL_CAPS": (
        "forensic_agent.oversight.policy",
        "DEFAULT_TOOL_CAPS",
    ),
    "Decision": ("forensic_agent.oversight.policy", "Decision"),
    "PATH_ARG_NAMES": ("forensic_agent.oversight.policy", "PATH_ARG_NAMES"),
    "Policy": ("forensic_agent.oversight.policy", "Policy"),
    "RISK_NAMES": ("forensic_agent.oversight.policy", "RISK_NAMES"),
    "evaluate": ("forensic_agent.oversight.policy", "evaluate"),
    "detect_injection": (
        "forensic_agent.oversight.detectors",
        "detect_injection",
    ),
    "detect_tool_poisoning": (
        "forensic_agent.oversight.detectors",
        "detect_tool_poisoning",
    ),
    "scan_tools": ("forensic_agent.oversight.detectors", "scan_tools"),
    "FORENSIC_CHECKLIST": (
        "forensic_agent.oversight.audit",
        "FORENSIC_CHECKLIST",
    ),
    "OversightLog": ("forensic_agent.oversight.audit", "OversightLog"),
    "reconstruct": ("forensic_agent.oversight.audit", "reconstruct"),
    "verify_chain": ("forensic_agent.oversight.audit", "verify_chain"),
    "OversightBoundOutput": (
        "forensic_agent.oversight.enforcement",
        "OversightBoundOutput",
    ),
    "OversightGate": (
        "forensic_agent.oversight.enforcement",
        "OversightGate",
    ),
    "enforce": ("forensic_agent.oversight.enforcement", "enforce"),
    "wrap_with_oversight": (
        "forensic_agent.oversight.enforcement",
        "wrap_with_oversight",
    ),
}

# Direct imports of names that leaked from the former monolith keep working,
# but they are intentionally excluded from the documented ``__all__``.
_COMPAT_EXPORTS: dict[str, tuple[str, str | None]] = {
    "Any": ("typing", "Any"),
    "EvidenceSourceError": (
        "forensic_agent.core.evidence_source",
        "EvidenceSourceError",
    ),
    "EvidenceSourceRuntimeGuard": (
        "forensic_agent.core.evidence_source",
        "EvidenceSourceRuntimeGuard",
    ),
    "GroundingLedger": (
        "forensic_agent.oversight.grounding",
        "GroundingLedger",
    ),
    "_ABS_PATH_RE": ("forensic_agent.oversight.policy", "_ABS_PATH_RE"),
    "_INJECTION_RULES": (
        "forensic_agent.oversight.detectors",
        "_INJECTION_RULES",
    ),
    "_NON_PATH_ARGUMENTS_BY_TOOL": (
        "forensic_agent.oversight.policy",
        "_NON_PATH_ARGUMENTS_BY_TOOL",
    ),
    "_POISON_LABELS": (
        "forensic_agent.oversight.detectors",
        "_POISON_LABELS",
    ),
    "_ZERO_WIDTH": ("forensic_agent.oversight.detectors", "_ZERO_WIDTH"),
    "_bind_output": (
        "forensic_agent.oversight.enforcement",
        "_bind_output",
    ),
    "_evidence_integrity_failure": (
        "forensic_agent.oversight.enforcement",
        "_evidence_integrity_failure",
    ),
    "_looks_like_path": (
        "forensic_agent.oversight.policy",
        "_looks_like_path",
    ),
    "_normalize": ("forensic_agent.oversight.detectors", "_normalize"),
    "_within_roots": ("forensic_agent.oversight.policy", "_within_roots"),
    "annotations": ("__future__", "annotations"),
    "canonical_json": ("forensic_agent.core.repro", "canonical_json"),
    "canonical_raw_output_sha256": (
        "forensic_agent.core.tool_result",
        "canonical_raw_output_sha256",
    ),
    "dataclass": ("dataclasses", "dataclass"),
    "field": ("dataclasses", "field"),
    "json": ("json", None),
    "os": ("os", None),
    "re": ("re", None),
    "sha256_bytes": ("forensic_agent.core.audit", "sha256_bytes"),
    "sha256_hex": ("forensic_agent.core.repro", "sha256_hex"),
    "threading": ("threading", None),
    "time": ("time", None),
    "unicodedata": ("unicodedata", None),
    "uuid": ("uuid", None),
}


def __getattr__(name: str) -> Any:
    target = _EXPORTS.get(name) or _COMPAT_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute_name = target
    module = import_module(module_name)
    return module if attribute_name is None else getattr(module, attribute_name)


def __dir__() -> list[str]:
    return sorted(
        {*globals(), *_EXPORTS, *_COMPAT_EXPORTS}
    )
