"""Entry point for memory scanning inside the container.

Extracted memory regions may contain the actual malicious payload and must not
be written to the host filesystem. The container keeps them in tmpfs storage
that disappears with the process, while the host sees only the result envelope.

This entry point runs the same :func:`offline_scan_pipeline` as the host path,
avoiding duplicate result contracts, receipts, and error classification. The
module is deliberately thin: parse two constrained arguments, seed the symbol
cache, invoke the pipeline, and emit the envelope.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from pathlib import Path

ENVELOPE_BEGIN = "<<<DFA-MEMORY-SCAN-ENVELOPE-V1>>>"
ENVELOPE_END = "<<<DFA-MEMORY-SCAN-ENVELOPE-END>>>"


def _seed_volatility_cache() -> None:
    """Copy a prebuilt symbol index so the scan is not spent indexing.

    A cold Volatility symbol index over the packaged Windows symbols does not
    finish inside any realistic budget, so the seed is load-bearing rather than
    an optimization. It is copied here, before the pipeline starts, because the
    container has no shell to do it.
    """

    seed = os.environ.get("DFA_VOL_CACHE_SEED", "").strip()
    cache = os.environ.get("DFA_VOL_CACHE", "").strip()
    if not seed or not cache:
        return
    source = Path(seed)
    if not source.is_file():
        return
    target = Path(cache)
    target.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target / "identifier.cache")


def _emit(envelope: dict) -> None:
    print(ENVELOPE_BEGIN)
    print(json.dumps(envelope, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    print(ENVELOPE_END)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dump-path", required=True)
    parser.add_argument("--pid", type=int, default=None)
    arguments = parser.parse_args(argv)

    from forensic_agent.core.environ import clamscan_path, vol_path
    from forensic_agent.core.toolkit import cell_deadline
    from forensic_agent.tools.memory_tool import offline_scan_pipeline

    try:
        budget = float(os.environ.get("DFA_MEMORY_SCAN_BUDGET_SECONDS", "") or 0.0)
    except ValueError:
        budget = 0.0
    deadline = time.monotonic() + budget if budget > 0 else None

    try:
        _seed_volatility_cache()
        volatility = vol_path()
        scanner = clamscan_path()
        if not volatility or not scanner:
            _emit(
                {
                    "schema_version": 1,
                    "status": "failed",
                    "attempts": 0,
                    "failure_stage": "runtime_configuration",
                    "failure_code": "dependency_unavailable",
                }
            )
            return 0
        with cell_deadline(deadline):
            envelope = offline_scan_pipeline(
                arguments.dump_path,
                arguments.pid,
                volatility=volatility,
                scanner=scanner,
            )
    except Exception:
        # The exit status must mean "transport", never "scan outcome", so an
        # unexpected failure here still leaves through the envelope.
        envelope = {
            "schema_version": 1,
            "status": "failed",
            "attempts": 0,
            "failure_stage": "internal",
            "failure_code": "internal_failure",
        }
    _emit(envelope)
    return 0


if __name__ == "__main__":
    sys.exit(main())
