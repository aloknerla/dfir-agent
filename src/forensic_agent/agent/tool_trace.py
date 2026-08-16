"""Recording standardized findings in the audit trail."""

from __future__ import annotations

import os
import threading
from collections.abc import Mapping

from forensic_agent.core.repro import canonical_json, sha256_hex

_TOOL_RESULT_TRACE_LOCK = threading.Lock()


def _append_tool_result_trace(
    path: str,
    *,
    case_id: str,
    invocation_namespace: str,
    tool: str,
    args: Mapping[str, object],
    result: object,
    artifact_kind: str = "complete_result",
) -> None:
    """Persist one traced artifact per call.

    ``artifact_kind`` distinguishes the COMPLETE standardized result the run
    retained from the PROJECTION the model actually read; without it the two
    traces are indistinguishable once separated from their file names.

    ``result`` may be any JSON value, not only a mapping: a projection can
    legitimately be a bounded scalar, and such a row still needs a digest of what
    was traced rather than a silent ``None``.
    """
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    receipt = result.get("receipt") if isinstance(result, Mapping) else None
    receipt_sha = receipt.get("payload_sha256") if isinstance(receipt, Mapping) else None
    row = {
        "schema_version": "forensic.tool-result-trace.v1",
        "case_id": case_id,
        "invocation_namespace": invocation_namespace,
        "tool": tool,
        "artifact_kind": artifact_kind,
        "parameters_sha256": sha256_hex(canonical_json(dict(args))),
        # The receipt digest exists only for a receipted envelope; the artifact
        # digest covers whatever was actually written, scalars included.
        "payload_sha256": receipt_sha,
        "artifact_sha256": sha256_hex(canonical_json(result)),
        "result": dict(result) if isinstance(result, Mapping) else result,
    }
    with _TOOL_RESULT_TRACE_LOCK:
        with open(path, "a", encoding="utf-8", newline="\n") as stream:
            stream.write(canonical_json(row) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
