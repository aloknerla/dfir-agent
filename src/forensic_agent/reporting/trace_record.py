"""Load and deterministically project forensic-investigation trace records."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol

from forensic_agent.oversight.audit import classify_action_outcome

__all__ = ["controlled_run_trace_record", "load_trace_record"]


class _ControlledRunLike(Protocol):
    @property
    def run_id(self) -> str: ...

    @property
    def report(self) -> str: ...

    @property
    def oversight_path(self) -> Path: ...

    @property
    def tool_result_trace_path(self) -> Path: ...

    @property
    def telemetry(self) -> Mapping[str, object]: ...


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _sequence(value: object) -> list[Any]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return list(value)
    return []


def _text(value: object, *, fallback: str = "—") -> str:
    text = " ".join(str(value or "").split())
    return text or fallback


def load_trace_record(path: str | Path, *, task_id: str | None = None) -> dict[str, Any]:
    """Load one result from a JSON or JSONL file.

    When a file contains multiple records, ``task_id`` is required. An
    ambiguous selection fails instead of silently displaying the wrong case.
    """

    source = Path(path)
    records: list[dict[str, Any]] = []
    with source.open(encoding="utf-8") as stream:
        if source.suffix.casefold() == ".json":
            parsed = json.load(stream)
            if isinstance(parsed, Mapping):
                records.append(dict(parsed))
            elif isinstance(parsed, list):
                records.extend(dict(item) for item in parsed if isinstance(item, Mapping))
        else:
            for line_number, line in enumerate(stream, start=1):
                if not line.strip():
                    continue
                try:
                    parsed = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"invalid JSONL record on line {line_number}") from exc
                if not isinstance(parsed, Mapping):
                    raise ValueError(f"JSONL line {line_number} is not an object")
                records.append(dict(parsed))

    if task_id is not None:
        records = [record for record in records if record.get("task_id") == task_id]
    if len(records) != 1:
        detail = "none found" if not records else f"{len(records)} found"
        raise ValueError(f"exactly one record is required ({detail}); specify --task-id")
    return records[0]


def _jsonl_objects(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open(encoding="utf-8", errors="strict") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid trace in {path.name} on line {line_number}") from exc
            if not isinstance(parsed, Mapping):
                raise ValueError(
                    f"record in {path.name} on line {line_number} is not an object"
                )
            rows.append(dict(parsed))
    return rows


def _traced_result(result: object) -> Any | None:
    """Read one traced record under the contract it declares, or ``None``.

    A trace file outlives the contract that wrote it, so both envelopes are read
    here.  Reporting a stored result as unreceipted merely because a later
    contract wrote it would misrepresent the run's own record of itself.
    """

    try:
        from forensic_agent.core.result_reading import read_result

        return read_result(result)
    except (ImportError, TypeError, ValueError):
        return None


def _receipt_is_valid(result: object) -> bool:
    """Whether a traced result carries a receipt matching its own payload."""

    read = _traced_result(result)
    if read is None:
        return False
    from forensic_agent.core.result_reading import receipt_is_valid

    return receipt_is_valid(read)


def controlled_run_trace_record(
    run: _ControlledRunLike,
    *,
    question: str,
    model: str,
    provider: str,
) -> dict[str, Any]:
    """Build a display record from one interactive ``ControlledRun``.

    Records are joined deterministically by the oversight sequence number stored
    in both ``oversight.jsonl`` and the standardized result provenance. An
    unbound result is never assigned to a call by position or text similarity.
    """

    oversight_path = Path(run.oversight_path)
    result_path = Path(run.tool_result_trace_path)
    oversight_rows = _jsonl_objects(oversight_path)
    result_rows = _jsonl_objects(result_path)

    # The JOIN key is read from the stored record as written, deliberately
    # without validating it first: a malformed traced result must still appear
    # against the call it belongs to, reported as unreceipted, rather than
    # vanishing from the trace of what the run actually recorded.  Every
    # CONTRACT fact below is then stated only about a record that satisfies its
    # contract.
    results_by_sequence: dict[int, Mapping[str, Any]] = {}
    for row in result_rows:
        result = _mapping(row.get("result"))
        provenance = _mapping(result.get("provenance"))
        sequence = provenance.get("oversight_sequence")
        if not isinstance(sequence, int) or sequence in results_by_sequence:
            continue
        results_by_sequence[sequence] = row

    calls: list[dict[str, Any]] = []
    traced_case_ids: list[str] = []
    for row in oversight_rows:
        if row.get("event") != "action":
            continue
        sequence = row.get("seq")
        trace = results_by_sequence.get(sequence) if isinstance(sequence, int) else None
        output = _mapping(trace.get("result")) if trace is not None else {}
        read = _traced_result(output) if output else None
        calls.append(
            {
                "name": row.get("tool"),
                "args": dict(_mapping(row.get("args"))),
                # What the gate DECIDED and what became of the CALL are two
                # separate facts, and only the second says whether the evidence
                # was ever read: the argument gate refuses a call while leaving
                # `allowed` true and `blocked` false. Carrying the recorded
                # outcome is what stops a reader of this record from inferring
                # the second fact from the first and captioning a refusal as an
                # approved access.
                "allowed": row.get("allowed") is True,
                "blocked": row.get("blocked") is True,
                "outcome": classify_action_outcome(row),
                "reasons": list(_sequence(row.get("reasons"))),
                "duration_s": row.get("duration_s"),
                "oversight_action_sequence": sequence,
                # A binding is a claim about provenance, so it is read off the
                # validated result: a record that does not satisfy the contract
                # it declares has no provenance to be believed, and must not be
                # displayed as bound to the trusted chain.
                "oversight_binding_verified": bool(
                    read is not None
                    and read.provenance.oversight_entry_sha256 == row.get("entry_hash")
                ),
                "output": dict(output),
                "output_receipt_verified": _receipt_is_valid(output) if output else False,
            }
        )
        if read is not None and read.provenance.case_id:
            traced_case_ids.append(read.provenance.case_id)

    telemetry = run.telemetry
    run_id = _text(run.run_id, fallback="interactive-run")
    report = _text(run.report, fallback="")
    # The case a trace belongs to is a provenance fact, so it is taken from the
    # first traced result that actually satisfies its contract.
    case_id = traced_case_ids[0] if traced_case_ids else None
    return {
        "schema_id": "forensic.interactive-trace-view.v1",
        "task_id": run_id,
        "case_id": case_id,
        "question": question,
        "model": model,
        "provider": provider,
        "status": "ok" if report else "error",
        "calls": calls,
        "telemetry": dict(telemetry) if isinstance(telemetry, Mapping) else {},
        "report": report,
    }
