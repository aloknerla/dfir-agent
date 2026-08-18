"""Controllers that feed the console — one demo, one live.

Both satisfy the same :class:`InvestigationController` protocol and produce the
same :class:`~forensic_agent.tui.model.InvestigationResult`. The app never
knows which one it is driving; the only difference the operator sees is the
``DEMO`` / ``LIVE`` tag in the status bar.

* :class:`DemoController` replays :mod:`forensic_agent.tui.demo_data` with
  realistic pacing and imports nothing from the forensic core.
* :class:`LiveController` wraps the existing
  :class:`~forensic_agent.cli.session.InteractiveSession`: it runs the real
  ``ask`` pipeline on a worker thread, streams the live ``on_tool`` feed to the
  flight recorder, and reads the standardized findings, capability decisions,
  and answer back through the existing ``presentation`` projections. It reuses
  the forensic machinery wholesale — it re-presents it, it does not re-implement
  it.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from typing import Any, Protocol

from forensic_agent.tui.model import (
    ANSWER_NONE,
    ANSWER_REPLAYED,
    OUTCOME_REFUSED_BY_OVERSIGHT,
    ControlCard,
    FindingCard,
    InvestigationResult,
    OversightCard,
    StatusState,
    ToolEvent,
)

OnTool = Callable[[ToolEvent], None]


class InvestigationController(Protocol):
    """The surface the app drives, identical for demo and live."""

    is_demo: bool

    #: The wrapped :class:`~forensic_agent.cli.session.InteractiveSession`, the
    #: console's command surface. The app reads it only behind an ``is_demo``
    #: guard, because the demo replays canned data and wraps no session at all.
    #: It stays ``Any`` because the console dispatches case and context commands
    #: onto it by name (``getattr(session, method)``), exactly as the line shell
    #: does, rather than through a fixed set of pass-throughs.
    session: Any

    def status(self) -> StatusState: ...

    def has_evidence(self) -> bool: ...

    def finding_records(self, card: FindingCard) -> dict | None:
        """The recorded observation behind one finding, or ``None`` if none was kept."""
        ...

    def run(self, question: str, on_tool: OnTool) -> InvestigationResult:
        """Answer one question. Blocking — the app calls this on a thread worker.

        ``on_tool`` is invoked once per tool call, possibly more than once for
        the same sequence as it moves from ``running`` to a settled status.
        """
        ...

    def replay(self, turn: Any) -> InvestigationResult:
        """Rebuild one stored turn's exchange from the record it left behind.

        Blocking, like :meth:`run`, and for the same reason: it reads files.
        The demo has no record to read and answers with an empty exchange.
        """
        ...


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------
class DemoController:
    """Replays the canned investigation with a live-looking cadence."""

    is_demo = True

    def __init__(self) -> None:
        from forensic_agent.tui import demo_data

        self._demo = demo_data.demo_investigation()
        self._served = 0

    def status(self) -> StatusState:
        return self._demo.status

    def has_evidence(self) -> bool:
        return True

    def replay(self, turn: Any) -> InvestigationResult:
        """The demo has no saved runs; /resume is refused before reaching here."""

        del turn
        return InvestigationResult(
            question="",
            answer_markdown="",
            answer_source=ANSWER_NONE,
            evidence_ids=(),
            findings=(),
            oversight=(),
            controls=ControlCard(
                verification="no run",
                answer_source=ANSWER_NONE,
                tool_calls=0,
                findings=0,
                model_requests=None,
                trace_id="-",
                elapsed_s=0.0,
            ),
            incomplete=True,
            note="The demo replays one recorded case; there is nothing saved to reopen.",
        )

    def run(self, question: str, on_tool: OnTool) -> InvestigationResult:
        script = self._demo.tool_script
        for index, step in enumerate(script, start=1):
            # Show the call in flight first, then settle it — this is what makes
            # the async worker visibly not block the UI.
            on_tool(
                ToolEvent(
                    sequence=index,
                    function=step.function,
                    operation=step.operation,
                    args_summary=step.args_summary,
                    status="running",
                    duration_s=None,
                    evidence_id=step.evidence_id,
                )
            )
            time.sleep(step.run_delay_s)
            settled = step.final_status
            # A call the oversight layer refuses never executes; the live feed
            # marks it "refused" while the oversight pane carries the full ground.
            live_status = (
                "refused"
                if settled == OUTCOME_REFUSED_BY_OVERSIGHT
                else settled
            )
            on_tool(
                ToolEvent(
                    sequence=index,
                    function=step.function,
                    operation=step.operation,
                    args_summary=step.args_summary,
                    status=live_status,
                    duration_s=step.duration_s,
                    evidence_id=step.evidence_id,
                )
            )
            time.sleep(0.12)

        self._served += 1
        base = self._demo.result
        # Echo whatever the operator typed as the question, but answer with the
        # recorded case data (the status bar's DEMO tag makes the replay plain).
        return InvestigationResult(
            question=question.strip() or base.question,
            answer_markdown=base.answer_markdown,
            answer_source=base.answer_source,
            evidence_ids=base.evidence_ids,
            findings=base.findings,
            oversight=base.oversight,
            controls=base.controls,
            incomplete=base.incomplete,
            note=base.note,
        )

    def followups(self) -> tuple[str, ...]:
        return self._demo.followups

    def finding_records(self, card) -> dict | None:
        """The demo replays summaries only; it records no payload."""

        return None


# ---------------------------------------------------------------------------
# Live
# ---------------------------------------------------------------------------
class LiveController:
    """Wraps ``InteractiveSession`` and re-presents its real run to the console."""

    is_demo = False

    def __init__(self, session) -> None:  # session: InteractiveSession
        self._session = session

    @property
    def session(self):
        """The wrapped ``InteractiveSession`` — the console's command surface.

        The console dispatches case and context commands (open_case,
        open_typed_case, resolve_pending_case, attach_*, …) straight onto the
        session, exactly as the line shell does; exposing it keeps those calls
        in one place instead of a pass-through per method.
        """

        return self._session

    # -- status ----------------------------------------------------------
    def status(self) -> StatusState:
        session = self._session
        try:
            from forensic_agent.cli import reasoning

            effort = reasoning.current_effort()
        except Exception:
            effort = "unknown"
        # Imported here rather than at module scope for the reason the effort
        # above is: the console must not pull the CLI package in at import
        # time, and this is only ever read while a live session exists.
        from forensic_agent.cli.budget import DEFAULT_MAX_WALL_TIME_S

        provider = self._provider_label()
        return StatusState(
            mode="LIVE",
            model=getattr(session, "model", "—"),
            provider=provider,
            case_label=getattr(session, "case_label", "none"),
            case_id=getattr(session, "case_id", "interactive-unbound"),
            evidence_sources=self._evidence_sources(),
            max_steps=int(getattr(session, "max_steps", 20)),
            max_tool_calls=int(getattr(session, "max_tool_calls", 20)),
            max_model_requests=int(getattr(getattr(session, "_runner", None), "max_model_requests", 24)),
            reasoning_effort=effort,
            max_wall_time_s=int(
                getattr(session, "max_wall_time_s", DEFAULT_MAX_WALL_TIME_S)
            ),
        )

    def _provider_label(self) -> str:
        try:
            from forensic_agent.core.environ import backend_kind

            if backend_kind(getattr(self._session, "base_url", "")) == "ollama":
                return "Ollama (local)"
        except Exception:
            pass
        return "OpenRouter"

    def _evidence_sources(self) -> tuple[str, ...]:
        import os

        session = self._session
        sources: list[str] = []
        if getattr(session, "disk", None) is not None:
            sources.append(f"disk: {getattr(session, 'disk_label', 'disk')}")
        if getattr(session, "memory", None):
            sources.append(f"memory: {os.path.basename(session.memory)}")
        if getattr(session, "pcap", None):
            sources.append(f"network: {os.path.basename(session.pcap)}")
        return tuple(sources)

    def has_evidence(self) -> bool:
        try:
            return bool(self._session.has_evidence())
        except Exception:
            return False

    def finding_records(self, card) -> dict | None:
        """The recorded observation behind one finding: attributes and items.

        Read from the run's tool-result trace, matched by position and — when
        both sides carry one — by receipt, so the reviewer sees exactly what
        was recorded, not a paraphrase.
        """

        run = getattr(self._session, "last_run", None)
        if run is None:
            return None
        try:
            rows = run.standardized_findings()
        except Exception:
            return None

        def digest(row: dict) -> str:
            # Trace rows nest the envelope under "result" and carry the
            # payload hash both beside it and inside the envelope receipt.
            for key in ("receipt", "recorded_output_sha256", "payload_sha256"):
                value = row.get(key)
                if isinstance(value, str) and value:
                    return value
            envelope = row.get("result")
            if isinstance(envelope, dict):
                receipt = envelope.get("receipt")
                if isinstance(receipt, str) and receipt:
                    return receipt
                if isinstance(receipt, dict):
                    value = receipt.get("payload_sha256")
                    if isinstance(value, str):
                        return value
            return ""

        row = None
        if 0 < card.sequence <= len(rows):
            candidate = rows[card.sequence - 1]
            fingerprint = digest(candidate)
            if (
                not fingerprint
                or fingerprint == card.receipt_full
                or card.receipt_full in ("", "—")
            ):
                row = candidate
        if row is None:
            for candidate in rows:
                fingerprint = digest(candidate)
                if fingerprint and fingerprint == card.receipt_full:
                    row = candidate
                    break
        if row is None:
            return None
        envelope = row.get("result") if isinstance(row.get("result"), dict) else row
        data = (
            envelope.get("data")
            if isinstance(envelope, dict) and isinstance(envelope.get("data"), dict)
            else envelope
        )
        items = data.get("items") if isinstance(data, dict) else None
        attributes = data.get("attributes") if isinstance(data, dict) else None
        return {
            "items": items if isinstance(items, list) else [],
            "attributes": attributes if isinstance(attributes, dict) else {},
        }

    # -- run -------------------------------------------------------------
    def run(self, question: str, on_tool: OnTool) -> InvestigationResult:
        from forensic_agent.cli import presentation

        session = self._session
        counter = {"seq": 0}
        # A call announces itself before it runs (dt is None) and again when it
        # settles (dt is a duration). Both carry the same sequence so the pane
        # updates one row from "running…" to its outcome rather than drawing two.
        pending: dict[str, int] = {}
        original_tool_line = getattr(session, "_tool_line", None)

        def tool_line(name, args, dt, refused: bool = False) -> None:
            fn, _, op = str(name).partition(".")
            key = str(name)
            starting = dt is None
            if starting:
                counter["seq"] += 1
                pending[key] = counter["seq"]
                sequence = counter["seq"]
            elif key in pending:
                sequence = pending.pop(key)
            else:
                counter["seq"] += 1
                sequence = counter["seq"]
            # The full arguments, not the shell's clipped summary: an operator
            # reading the feed must see the exact path, key or plugin a call
            # touched. The pane wraps, so length costs nothing but rows.
            try:
                if isinstance(args, Mapping):
                    summary = "  ".join(f"{k}={v}" for k, v in args.items())[:600]
                else:
                    summary = presentation.summarize_call_arguments(args)
            except Exception:
                summary = str(args)[:600]
            status = (
                "running" if starting else "refused" if refused else "approved"
            )
            on_tool(
                ToolEvent(
                    sequence=sequence,
                    function=fn or str(name),
                    operation=op,
                    args_summary=summary,
                    status=status,
                    duration_s=float(dt) if dt is not None else None,
                )
            )

        import io

        from rich.console import Console

        started = time.time()
        session._tool_line = tool_line  # non-invasive: read at call time in ask()
        # The session narrates refusals and failures through its console; in
        # the TUI that console is a quiet StringIO, so record the narration —
        # when nothing runs, what it says IS the reason the operator gets.
        recorder = Console(record=True, width=94, file=io.StringIO())
        original_console = session._console
        session._console = recorder
        try:
            answered = bool(session.ask(question))
        finally:
            session._console = original_console
            if original_tool_line is not None:
                session._tool_line = original_tool_line
        elapsed = time.time() - started

        run = getattr(session, "last_run", None)
        outcome = getattr(session, "last_ask_outcome", "")
        # A run that examined the evidence and published nothing is NOT the
        # empty case. It has a run record of its own, freshly bound by the
        # session, with the findings it read and the oversight decisions it
        # made; sending it down the empty path threw all of that away and left
        # the operator the first three hundred characters of a squashed
        # transcript. It is an outcome of the investigation and it gets the
        # panes an outcome gets.
        unpublished = outcome == "unpublished"
        # ask() returning False otherwise means nothing ran this time (screened
        # input or a reported failure); last_run then still holds the PREVIOUS
        # run and rendering it would replay an old answer as if it were new.
        if run is None or not (answered or unpublished):
            return self._empty_result(
                question, elapsed, narration=recorder.export_text(styles=False)
            )

        findings = self._build_findings(session)
        oversight = self._build_oversight(session)
        controls = self._build_controls(session, run, findings, elapsed)
        report = getattr(run, "report", "") or ""
        incomplete = not report.strip()
        evidence_ids = tuple(
            dict.fromkeys(f.source_id for f in findings if f.source_id)
        )
        note = self._incomplete_note(run) if incomplete else ""
        # A history-save failure never fails the answer — the session only
        # narrates it, into a console nobody can see here. An exchange the
        # operator believes is saved but is not must be said out loud.
        recorded = recorder.export_text(styles=False)
        if "could not be saved" in recorded:
            for line in recorded.splitlines():
                if "could not be saved" in line:
                    warning = " ".join(line.split())[:240]
                    note = f"{note}  {warning}".strip() if note else warning
                    break
        return InvestigationResult(
            question=question.strip(),
            answer_markdown=report or "_The run examined the evidence but published no answer._",
            answer_source=controls.answer_source,
            evidence_ids=evidence_ids,
            findings=findings,
            oversight=oversight,
            controls=controls,
            incomplete=incomplete,
            note=note,
        )

    @staticmethod
    def _incomplete_note(run) -> str:
        """What to say about a run that read the evidence and published nothing.

        Said in the run's own recorded terms and then said plainly to be an
        outcome, because the two are one sentence apart and the difference is
        the whole complaint: the operator has to be able to tell "the model
        spent its budget" from "this program broke", and for a while both
        arrived under the words ``agent error``.
        """

        from forensic_agent.cli.presentation import summarize_incomplete_examination

        try:
            statement = summarize_incomplete_examination(
                getattr(run, "telemetry", {}) or {}
            ).statement
        except Exception:
            statement = "This examination did not complete, and no conclusion was published."
        return (
            f"{statement} The run finished without a publishable finding, "
            "which is an outcome of the investigation and not a fault in this "
            "program."
        )

    # -- projections -----------------------------------------------------
    def _build_findings(self, session) -> tuple[FindingCard, ...]:
        from forensic_agent.cli import findings_view, presentation

        rows = list(getattr(session, "last_findings", []) or [])
        oversight_path = getattr(session, "oversight_path", None)
        cards: list[FindingCard] = []
        for index, row in enumerate(rows, start=1):
            try:
                detail = presentation.summarize_finding_detail(row, sequence=index)
            except Exception:
                continue
            call = None
            try:
                call = findings_view.recorded_call_for(
                    detail, oversight_path=oversight_path
                )
            except Exception:
                call = None
            cards.append(self._finding_card(detail, call))
        return tuple(cards)

    @staticmethod
    def _finding_card(detail, call) -> FindingCard:
        summary = detail.summary
        arguments: tuple[tuple[str, str], ...] = ()
        function = summary.tool
        operation = ""
        if call is not None:
            operation = call.operation or ""
            arguments = tuple(
                (a.name, ("[withheld]" if a.withheld else a.value))
                for a in call.arguments
            )
        return FindingCard(
            sequence=summary.sequence,
            status=summary.status,
            function=function,
            operation=operation,
            data_type=summary.data_type,
            records=summary.records,
            coverage_label=summary.coverage,
            coverage_complete=detail.coverage.complete,
            coverage_scope=detail.coverage.scope or "",
            coverage_reason=detail.coverage.reason or "",
            receipt_full=detail.receipt or "—",
            arguments=arguments,
            # What the row says it FOUND: the recorded call's real arguments
            # (which hive, which key, which plugin) — a records count alone
            # tells an operator nothing.
            result_summary=(
                "  ".join(f"{name}={value}" for name, value in arguments)
                if arguments
                else summary.data_type
            ),
            source_id=detail.source_id or "",
            source_uri=detail.source_uri or "",
            evidence_class=detail.evidence_class or "",
            warnings=tuple(detail.warning_messages or detail.warnings),
            oversight_sequence=detail.oversight_sequence,
        )

    def _build_oversight(self, session) -> tuple[OversightCard, ...]:
        from forensic_agent.cli import oversight_view, presentation

        oversight_path = getattr(session, "oversight_path", None)
        try:
            entries = oversight_view.run_bound_entries(oversight_path)
        except Exception:
            entries = None
        if not entries:
            return ()
        try:
            calls = presentation.executed_calls(entries)
        except Exception:
            return ()
        try:
            authority = presentation.granted_authority(entries)
        except Exception:
            authority = None
        granted = tuple(authority.granted_caps) if authority else ()
        allowed_tools = authority.allowed_tools if authority else None
        write_scope = tuple(authority.write_scope) if authority else ()
        cards: list[OversightCard] = []
        for call in calls:
            cards.append(
                OversightCard(
                    sequence=call.sequence,
                    function=call.function,
                    operation=call.operation,
                    outcome=call.outcome,
                    requested_caps=tuple(call.capabilities),
                    granted_caps=granted,
                    allowed_tools=allowed_tools,
                    write_scope=write_scope,
                    risk_name=call.risk_name,
                    reasons=tuple(call.reasons),
                    duration_s=call.duration_s,
                    arguments=tuple(
                        (a.name, ("[withheld]" if a.withheld else a.value))
                        for a in call.arguments
                    ),
                    output_digests=tuple(call.output_digests),
                    refusal_message=call.refusal_message,
                    # What the tool declared when it came back unsuccessful.
                    # A failed call produces no finding, so this is the only
                    # place the ACTIVITY row can learn why it failed without
                    # inventing a reason.
                    outcome_detail=call.outcome_detail,
                )
            )
        return tuple(cards)

    def _build_controls(self, session, run, findings, elapsed) -> ControlCard:
        from forensic_agent.cli import presentation

        tool_calls = len(getattr(session, "last_evidence", []) or [])
        try:
            summary = presentation.summarize_controls(
                run.telemetry,
                run_id=run.run_id,
                tool_calls=tool_calls,
                findings=len(findings),
            )
            return ControlCard(
                verification=summary.verification,
                answer_source=summary.answer_source,
                tool_calls=summary.tool_calls,
                findings=summary.findings,
                model_requests=summary.model_requests,
                trace_id=summary.trace_id,
                elapsed_s=elapsed,
            )
        except Exception:
            return ControlCard(
                verification="unknown",
                answer_source=ANSWER_NONE,
                tool_calls=tool_calls,
                findings=len(findings),
                model_requests=None,
                trace_id=getattr(run, "run_id", "—"),
                elapsed_s=elapsed,
            )

    def _empty_result(
        self, question: str, elapsed: float, narration: str = ""
    ) -> InvestigationResult:
        # The reason must match the actual state. A missing case gets the
        # console's own phrasing; anything else that stopped a run (a
        # provider failure, an incomplete examination) reported itself
        # through the session console — that recorded narration is the reason.
        if not self.has_evidence():
            note = "No evidence is loaded. Open a case with /case <folder-or-file>."
        else:
            note = " ".join((narration or "").split())[:300] or (
                "That run did not finish; nothing was published."
            )
        return InvestigationResult(
            question=question.strip(),
            answer_markdown="",
            answer_source=ANSWER_NONE,
            evidence_ids=(),
            findings=(),
            oversight=(),
            controls=ControlCard(
                verification="no run",
                answer_source=ANSWER_NONE,
                tool_calls=0,
                findings=0,
                model_requests=None,
                trace_id="—",
                elapsed_s=elapsed,
            ),
            incomplete=True,
            note=note,
        )

    # -- replaying a stored run -------------------------------------------
    #
    # What can honestly be rebuilt, and what cannot.
    #
    # Resuming a saved investigation used to restore the model's context and
    # nothing else: the operator got the conversation's MEANING back and an
    # empty screen, no activity rows, no evidence, no guardrail decisions,
    # which is the opposite of what a record is for.
    #
    # Almost all of it is on disk. Each turn's run directory is
    # ``run_root/<turn_id>/``, holding ``oversight.jsonl`` (every capability
    # decision, with the tool, its arguments, the outcome, the reasons and the
    # duration) and ``tool-results.jsonl`` (every standardized result). Those
    # are the same two files the LIVE panes are built from, through the same
    # ``presentation`` projections, so a replay reuses :meth:`_build_findings`
    # and :meth:`_build_oversight` verbatim rather than growing a second way to
    # read a run.
    #
    # Three things are NOT recorded and are therefore not reconstructed:
    #
    #   * the run's own verdict, whether the answer was verified and what the
    #     publication gate decided. That lives in the run's telemetry, which
    #     reaches disk only when a run FAILS. A replayed answer is marked
    #     ANSWER_REPLAYED, which says the text is what was saved and the verdict
    #     was not, rather than inventing either a pass or a failure.
    #   * the model's prose between tool calls, and the live feed's cadence.
    #     Only the settled outcome of each call survives, so the ACTIVITY rows
    #     come back settled; nothing is animated as if it were running now.
    #   * which findings the operator accepted. That was only ever screen state.
    #     Replayed findings come back unreviewed.
    #
    # Elapsed time is the run's own clock, its last oversight entry minus its
    # first, which is a different quantity from the wall clock the live path
    # measures around ask(). It is reported because it is true, not because it
    # is the same number.
    def replay(self, turn: Any) -> InvestigationResult:
        """Rebuild one stored turn's exchange from the run it left on disk."""

        from pathlib import Path

        question = str(getattr(turn, "question", "") or "").strip()
        answer = str(getattr(turn, "verified_answer", "") or "")
        run_id = str(getattr(turn, "turn_id", "") or "")
        run_dir = self._run_directory(run_id)
        if run_dir is None:
            # The conversation survived but its run directory did not: run
            # directories default to the operating system's temporary directory
            # and get swept. The text is still true and is still shown; the
            # panes say why they are empty instead of implying the run made no
            # tool calls.
            return self._replayed(
                question, answer, run_id, (), (), 0, 0.0,
                note=(
                    "The messages were restored. The tool calls and evidence "
                    "for this one were not: its run folder is no longer on "
                    "disk, so there is nothing left to show in the panes."
                ),
            )
        record = _StoredRun.at(Path(run_dir))
        findings = self._build_findings(record)
        oversight = self._build_oversight(record)
        return self._replayed(
            question, answer, run_id, findings, oversight,
            record.tool_call_count, record.elapsed_s,
        )

    def _run_directory(self, run_id: str) -> str | None:
        """Where a turn's run was written, if it is still there.

        Located from ``run_root`` and the turn id rather than from the turn's
        recorded ``audit_ref``: older conversations recorded container paths
        there, which do not exist on the machine reading them back.
        """

        from pathlib import Path

        if not run_id:
            return None
        root = getattr(self.session, "run_root", None)
        if not root:
            return None
        candidate = Path(str(root)) / run_id
        return str(candidate) if candidate.is_dir() else None

    def _replayed(
        self,
        question: str,
        answer: str,
        run_id: str,
        findings: tuple[FindingCard, ...],
        oversight: tuple[OversightCard, ...],
        tool_calls: int,
        elapsed: float,
        note: str = "",
    ) -> InvestigationResult:
        evidence_ids = tuple(
            dict.fromkeys(card.source_id for card in findings if card.source_id)
        )
        return InvestigationResult(
            question=question,
            answer_markdown=answer,
            answer_source=ANSWER_REPLAYED,
            evidence_ids=evidence_ids,
            findings=findings,
            oversight=oversight,
            controls=ControlCard(
                # "not recorded" is not a hedge, it is the fact; see the note
                # above this method. The counts ARE recorded and are real.
                verification="not recorded",
                answer_source=ANSWER_REPLAYED,
                tool_calls=tool_calls,
                findings=len(findings),
                model_requests=None,
                trace_id=run_id[:12] or "-",
                elapsed_s=elapsed,
            ),
            incomplete=not answer.strip(),
            note=note,
        )


class _StoredRun:
    """A finished run's two files, shaped like the session the builders read.

    :meth:`LiveController._build_findings` and ``_build_oversight`` ask a
    session for exactly two things, ``last_findings`` and ``oversight_path``,
    so a run directory can answer for itself and go through the identical code.
    That is deliberate: a historic run must render through the same projections
    as the run that just finished, or the two disagree and the record stops
    being a record.
    """

    __slots__ = ("elapsed_s", "last_findings", "oversight_path", "tool_call_count")

    def __init__(
        self,
        last_findings: list,
        oversight_path: str,
        tool_call_count: int,
        elapsed_s: float,
    ) -> None:
        self.last_findings = last_findings
        self.oversight_path = oversight_path
        self.tool_call_count = tool_call_count
        self.elapsed_s = elapsed_s

    @classmethod
    def at(cls, run_dir: Any) -> _StoredRun:
        from forensic_agent.cli.controlled import (
            standardized_findings_from,
            tool_calls_from,
        )

        # Absolute: oversight_view.run_bound_entries refuses a relative path.
        oversight = str((run_dir / "oversight.jsonl").resolve())
        results = run_dir / "tool-results.jsonl"
        try:
            findings = list(standardized_findings_from(str(results)))
        except Exception:
            findings = []
        try:
            calls = len(list(tool_calls_from(oversight)))
        except Exception:
            calls = 0
        return cls(findings, oversight, calls, _run_clock(oversight))


def _run_clock(oversight_path: str) -> float:
    """How long the run took by its OWN clock: last entry minus first.

    Not the same measurement as the live path's wall clock around ``ask()``,
    which includes time spent outside the recorded chain. It is what the record
    supports, so it is what a replay reports.
    """

    import json
    from pathlib import Path

    stamps: list[float] = []
    try:
        with Path(oversight_path).open(encoding="utf-8") as handle:
            for line in handle:
                text = line.strip()
                if not text:
                    continue
                try:
                    stamp = json.loads(text).get("ts")
                except Exception:
                    continue
                if isinstance(stamp, int | float):
                    stamps.append(float(stamp))
    except Exception:
        return 0.0
    return max(0.0, max(stamps) - min(stamps)) if len(stamps) > 1 else 0.0
