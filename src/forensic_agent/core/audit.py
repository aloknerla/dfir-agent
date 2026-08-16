"""Chain-of-custody audit logging for forensic agent.

Every tool invocation is recorded append-only (JSONL) with SHA-256 of the
output (and of the source image), tool name, arguments, timestamp and
duration. This is the evidentiary backbone: every claim the agent makes can
later be traced to an audited tool result.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any

#: The run directory a log falls back to when the deployment declares none. It
#: matches the interactive session's own fallback, so a console run and a
#: library call that were both left unplaced land in one place rather than two.
_FALLBACK_RUN_DIRECTORY = "dfir-agent-runs"

#: The variable that names this deployment's run directory. The console reads it
#: to choose where a run is recorded and the containerised runner sets it to the
#: mounted record root, so a log that nobody placed belongs under it.
_RUN_DIRECTORY_VARIABLE = "DFA_RUNS_DIR"


def default_log_path(filename: str) -> str:
    """Return the absolute destination of a log whose caller named no place for it.

    A bare relative name such as ``audit.jsonl`` resolves against whatever
    directory the process happened to start in. That is not a location: it is
    wherever the operator's shell was, so a chain of custody could accumulate
    under no run any reader could identify. ``cli/controlled.py`` already places
    both of its logs inside the run's own directory; this is the same rule for
    the callers that let the destination default, and the path it returns is
    absolute for the same reason the console refuses to reconstruct a relative one
    (``cli/oversight_view.run_bound_entries``).
    """

    declared = str(os.environ.get(_RUN_DIRECTORY_VARIABLE) or "").strip()
    directory = (
        Path(declared)
        if declared
        else Path(tempfile.gettempdir()) / _FALLBACK_RUN_DIRECTORY
    )
    directory = directory.expanduser().resolve()
    directory.mkdir(parents=True, exist_ok=True)
    return str(directory / filename)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


class AuditLog:
    def __init__(self, path: str | None = None) -> None:
        self.path = default_log_path("audit.jsonl") if path is None else path

    def record(self, *, tool: str, args: dict, output: Any,
               input_sha: str | None = None, duration_s: float | None = None) -> dict:
        out_text = output if isinstance(output, str) else json.dumps(
            output, ensure_ascii=False, default=str)
        entry = {
            "ts": time.time(),
            "tool": tool,
            "args": args,
            "input_sha256": input_sha,
            "output_sha256": sha256_bytes(out_text.encode("utf-8")),
            "output_preview": out_text[:2000],
            "duration_s": duration_s,
        }
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
        return entry
