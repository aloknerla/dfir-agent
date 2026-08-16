"""Chain-of-custody verification for a previously opened evidence source."""

from __future__ import annotations

import os
from collections.abc import Mapping

from forensic_agent.core.evidence_source import (
    NO_READ_LEASE_MODE,
    RUNTIME_FULL_CONTENT_CHECK,
    RUNTIME_METADATA_CHECK,
    WINDOWS_READ_LEASE_MODE,
    EvidenceSourceAttestation,
    EvidenceSourceRuntimeGuard,
)


def _validate_preopened_evidence_guard(
    guard: EvidenceSourceRuntimeGuard,
    attestation: EvidenceSourceAttestation,
) -> None:
    """Require the adapter-owned guard that protected the physical disk open.

    Confirmatory execution must not construct a second guard after dfVFS has
    already opened the image.  The first guard is acquired and cryptographically
    checked by the adapter before ``DiskImage`` construction, then retained for
    the graph and its centralized tool oversight.
    """

    if type(guard) is not EvidenceSourceRuntimeGuard:
        raise ValueError("runtime custody requires an exact evidence-source guard")
    if guard.attestation != attestation:
        raise ValueError("pre-open evidence guard used a different source attestation")
    record = guard.telemetry()
    if record.get("violation_detected") is not False:
        raise ValueError("pre-open evidence guard already recorded a violation")
    checks = record.get("checks")
    expected_checks = (
        {
            "index": 0,
            "checkpoint": "pre_disk_open",
            "check_type": RUNTIME_FULL_CONTENT_CHECK,
            "status": "ok",
        },
        {
            "index": 1,
            "checkpoint": "post_disk_open",
            "check_type": RUNTIME_METADATA_CHECK,
            "status": "ok",
        },
    )
    if checks != list(expected_checks) or record.get("check_count") != 2:
        raise ValueError("pre-open evidence guard lacks the exact disk-open custody checkpoints")
    lease = record.get("read_lease")
    if not isinstance(lease, Mapping):
        raise ValueError("pre-open evidence guard lacks read-lease telemetry")
    expected_mode = WINDOWS_READ_LEASE_MODE if os.name == "nt" else NO_READ_LEASE_MODE
    if lease.get("mode") != expected_mode or lease.get("started") is not True:
        raise ValueError("pre-open evidence read lease was not started")
    if lease.get("closed") is not False:
        raise ValueError("pre-open evidence read lease was released before graph execution")
    expected_handles = len(attestation.segments) if os.name == "nt" else 0
    if lease.get("open_handle_count") != expected_handles:
        raise ValueError("pre-open evidence read-lease handle set is incomplete")
    expected_acquired = os.name == "nt"
    if lease.get("acquired") is not expected_acquired:
        raise ValueError("pre-open evidence read-lease acquisition state is inconsistent")
