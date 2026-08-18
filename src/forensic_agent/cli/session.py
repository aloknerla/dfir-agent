"""State and operations of one interactive forensic investigation session.

:class:`InteractiveSession` is what the terminal loop holds: the evidence that
is open, the investigation history it is writing to, the provider it is
configured against, and the single operation that puts a question to the model.
Every command the operator can type ends up as a method here.

What those commands *render* does not live here. A console view is a decision
about how something reads, and it can be checked on its own the moment it is a
function of the facts rather than a method on the session, so the panels and
tables were moved out to modules named for what they show — the session facts
panel, the findings and run summaries, the tools listing, the model catalogue,
the oversight views, the completion record, the lines one exchange writes while
it runs, and the live display that opening a case runs behind. The same applies
to the validation that must not touch what is already open: resolving a path
inside the mounted evidence root, deriving the identity of an evidence set,
deciding what a recorded evidence set still amounts to on this host, turning what
was found on disk into one unambiguous case, and judging whether a provider may
be asked for a given model are all functions elsewhere. So are the two things a
question is assembled from — the controls the run is built under and the framing
carried with it — and the files an operator asks to be left behind.

Neither does the investigation history. Starting, resuming, continuing and saving
one are transitions on the active conversation and on the store it is persisted
to, and those two are owned together by ``InvestigationHistory``, which this
session holds and delegates to. The session tells that collaborator which case is
open; the collaborator decides nothing about evidence and never reaches back.

What remains is the state itself and the order in which it changes: which
evidence is open, which investigation is being written to, which provider the
console is configured against, and what each command does to those. Every one of
those methods is a state transition, and a transition is only correct in the
order it makes its changes, which is why they read as sequences of assignments
rather than as expressions.
"""

from __future__ import annotations

import inspect
import os
import re
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Protocol

from rich.console import Console, RenderableType
from rich.markup import escape
from rich.padding import Padding
from rich.panel import Panel
from rich.text import Text

import forensic_agent.cli.budget as _budget
import forensic_agent.cli.case_completion as _case_completion
import forensic_agent.cli.case_index as _case_index
import forensic_agent.cli.console_settings as _console_settings
import forensic_agent.cli.exchange_view as _exchange_view
import forensic_agent.cli.findings_view as _findings_view
import forensic_agent.cli.model_catalog_view as _model_view
import forensic_agent.cli.model_request as _model_request
import forensic_agent.cli.oversight_view as _oversight_view
import forensic_agent.cli.progress as _progress
import forensic_agent.cli.provider_selection as _provider_selection
import forensic_agent.cli.reasoning as _reasoning
import forensic_agent.cli.scope_check as _scope_check
import forensic_agent.cli.session_exports as _session_exports
import forensic_agent.cli.session_facts as _session_facts
import forensic_agent.cli.tools_view as _tools_view
from forensic_agent.cli.case_open_progress import case_opening_progress
from forensic_agent.cli.case_selection import (
    case_from_evidence_file,
    case_from_manifest,
    requires_source_resolution,
    resolve_staged_selection,
    stage_overlays,
)
from forensic_agent.cli.commands import CommandUsageError

# The layout vocabulary moved to cli.console_layout, but the console's geometry
# is still a property of a session, and callers — including the presentation
# tests — pin these names on this module, so they stay reachable from here.
from forensic_agent.cli.console_layout import (
    ANSWER_MARKDOWN_THEME as _ANSWER_MARKDOWN_THEME,  # noqa: F401
)
from forensic_agent.cli.console_layout import (
    MIN_TRAILING_RULE as _MIN_TRAILING_RULE,  # noqa: F401
)
from forensic_agent.cli.console_layout import (
    PANEL_WIDTH,
    exchange_heading,
)
from forensic_agent.cli.conversation import ConversationStore
from forensic_agent.cli.evidence_binding import (
    evidence_binding_record,
    restorable_sources,
    source_identity,
)
from forensic_agent.cli.host_paths import (
    existing_file,
    export_destination,
    handoff_host_path_if_needed,
    resolve_evidence_path,
)
from forensic_agent.cli.i18n import t as _t
from forensic_agent.cli.investigation_history import (
    ActiveCase,
    InvestigationHistory,
    read_case_context_file,
    recorded_binding,
)
from forensic_agent.cli.presentation import (
    resolve_finding_id,
    summarize_controls,
    summarize_finding_detail,
    summarize_incomplete_examination,
)
from forensic_agent.cli.terminal import (
    ACCENT,
    DIM,
    GLYPH_ERROR,
    GLYPH_OK,
    GLYPH_POINT,
    ORANGE,
    # The panel ground is the palette's, but the presentation tests pin it on
    # this module, so it stays reachable from here.
    PANEL_BG,  # noqa: F401
    RED,
    SUCCESS,
    build_usage_renderable,
    glyphed_line,
)
from forensic_agent.core.audit import AuditLog
from forensic_agent.core.config import DEFAULT_MODEL
from forensic_agent.core.durations import format_duration

if TYPE_CHECKING:
    from forensic_agent.agent.case_evidence import CaseEvidenceSource
    from forensic_agent.cli.case_discovery import DiscoveredCase
    from forensic_agent.cli.controlled import ControlledRun, IncompleteExaminationError
    from forensic_agent.cli.conversation import (
        ConversationEvidenceBinding,
        ConversationSession,
    )
    from forensic_agent.cli.presentation import ExecutedCall, FindingDetail
    from forensic_agent.tools.pcap_sources import PcapSourceCatalog

#: The model the interactive console selects when neither --model nor DFA_MODEL
#: says otherwise.  Aliased rather than re-declared so the banner, `doctor` and
#: the agent API cannot report different defaults.
INTERACTIVE_MODEL = DEFAULT_MODEL


def _readable_attestation_moment(value: object) -> str:
    """A stored verification stamp as a date and a time a person reads.

    The attestation store writes ``time.strftime("%Y-%m-%dT%H:%M:%S%z")``, which
    is the right shape for a file that has to sort and compare, and the wrong
    shape for a console line whose whole purpose is to let the operator judge
    whether the last verification was recent. It is rendered in the reader's own
    zone, because the question being asked is "how long ago", and an offset the
    operator has to subtract in their head is the machine form again.

    Anything unparseable returns "" and the caller simply omits the line: a
    stamp that cannot be read is not worth guessing at, and the fact that the
    attestation was reused is carried by the lead line regardless.
    """

    from datetime import datetime

    text = str(value or "").strip()
    if not text:
        return ""
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return ""
    if moment.tzinfo is not None:
        moment = moment.astimezone()
    return moment.strftime("%d %b %Y at %H:%M").lstrip("0")


def _lead(glyph: str, colour: str, text: str) -> RenderableType:
    """The line that says which outcome this is, wrap included."""

    return glyphed_line(glyph, colour, Text(text, style=colour))


def _detail(text: str, *, style: str = DIM) -> RenderableType:
    """One supporting line under a lead, indented across its own wrap.

    Writing two spaces into the string indents the FIRST line only: whatever
    renders it wraps the rest back to column zero, where it reads as a new
    statement rather than as the continuation of this one. The indent therefore
    belongs to the renderable, which is what ``Padding`` is for, and the style
    travels with the ``Text`` so it applies to every line the wrap produces.

    Returning a renderable rather than printing is what lets the full-screen
    console mount the same object into a pane of its own width. Text captured
    from a console at one width and replayed into a narrower pane has already
    been wrapped once, and the indent is lost in the second wrap.
    """

    return Padding(Text(text, style=style), (0, 0, 0, 2))


def integrity_verdict_lines(result: Mapping[str, object]) -> tuple[RenderableType, ...]:
    """Say which outcome of ``/verify`` happened, in words that do not read alike.

    The outcomes are not degrees of one thing. A matching digest means the
    evidence is the evidence, and everything derived from it stands. A differing
    digest means the bytes being read are not the bytes the case was opened
    over, and there are only two ways that happens: the medium was altered, or
    the storage carrying it is failing. Neither is a status update, so neither is
    worded as one, and no sentence is shared between them.

    What a match licenses is stated, because it is the reason an operator runs
    this at all. The image index is filed under a key derived from the evidence
    SHA-256 and the sealed scanner version, and the stored identity is compared
    against the wanted one before the index is served, so an unchanged digest
    means the index that was served is the index of these bytes. The findings
    hold for the same reason: each carries the digest of the source it was read
    from.

    Renderables rather than printed lines, so the two consoles show one verdict
    in one wording and each lays it out at its own width.
    """

    error = result.get("error")
    if error:
        return (
            _lead(GLYPH_ERROR, RED, _t("The medium could not be read to the end.")),
            _detail(str(error)),
            _detail(
                _t(
                    "Nothing is established either way. The source is "
                    "unreadable, not proven changed."
                )
            ),
        )

    computed = str(result.get("sha256", "") or "")
    recorded = str(result.get("recorded_sha256", "") or "")
    if result.get("matches_recorded"):
        return (
            _lead(GLYPH_OK, SUCCESS, _t("The evidence is unchanged.")),
            _detail(
                _t(
                    "Every byte of the medium was read again and the "
                    "SHA-256 is the one this case was opened under."
                )
            ),
            _detail(f"SHA-256 {computed}"),
            _detail(
                _t(
                    "The image index and the recorded findings still "
                    "stand: both are filed under this digest."
                )
            ),
        )

    return (
        _lead(GLYPH_ERROR, RED, _t("THE EVIDENCE DIGEST HAS CHANGED.")),
        _detail(
            _t(
                "These are not the bytes this case was opened over. "
                "The medium was altered, or the storage holding it is "
                "failing. Treat it as neither until you know which."
            ),
            style=RED,
        ),
        # Both digests in full and one under the other, so the operator can see
        # where they part company rather than take the verdict on trust.
        _detail(
            f"{_t('recorded when the case opened')}  {recorded or '?'}", style=RED
        ),
        _detail(
            f"{_t('read from the medium just now')}  {computed or '?'}", style=RED
        ),
        _detail(
            _t(
                "The image index and every finding recorded against this "
                "evidence were derived from the recorded digest, so none "
                "of them describes what is on the medium now."
            ),
            style=ORANGE,
        ),
    )


@dataclass(frozen=True, slots=True)
class CaseSourceSelection:
    """A staged source choice that does not replace the active case."""

    root: Path
    disks: tuple[Path, ...]
    memories: tuple[Path, ...]
    pcaps: tuple[Path, ...]
    ambiguous: tuple[Path, ...]


def _accepts_keyword(function: Any, name: str) -> bool:
    """Whether a callable takes this keyword argument.

    Asked before handing the runtime an optimisation it may not know about
    yet: the value only saves work, so a runtime built without the parameter
    must keep receiving the call it has always received rather than a
    TypeError.
    """

    try:
        parameters = inspect.signature(function).parameters
    except (TypeError, ValueError):
        return False
    return name in parameters or any(
        parameter.kind is inspect.Parameter.VAR_KEYWORD
        for parameter in parameters.values()
    )


class _Disk(Protocol):
    """Filesystem surface shared by real and in-memory evidence backends."""

    def list_directory(self, path: str = "/") -> dict: ...

    def file_metadata(self, path: str) -> dict: ...

    def read_file(self, path: str, max_bytes: int = 4096, offset: int = 0) -> dict: ...


class InteractiveSession:
    #: Schema of the operator's completion declaration, re-exported from the
    #: module that writes it so a caller holding a session can name it.
    CASE_COMPLETION_SCHEMA = _case_completion.CASE_COMPLETION_SCHEMA

    #: Where the last completion declaration was written. Absent until the
    #: operator marks the case complete: the console must never imply a case is
    #: finished before anyone has said so.
    completion_declaration_path: Path | None = None

    #: Which of the three things happened to the last question, as a word a
    #: caller can branch on.  ``ask`` answers with a bool because that is what
    #: every caller needs, and a bool cannot tell "the run completed and
    #: published nothing" from "this software raised".  Those two are the
    #: distinction a measurement harness is made of, so the outcome is recorded
    #: here beside the bool rather than encoded into it.
    ASK_ANSWERED = "answered"
    ASK_UNPUBLISHED = "unpublished"
    ASK_FAILED = "failed"
    #: Nothing was attempted: no evidence, or the input was not about the case.
    ASK_NOT_ATTEMPTED = "not_attempted"

    def __init__(self, args, *, console: Console) -> None:
        self._console = console
        # Deliberately the light module: reaching into cli.controlled here would
        # load the agent runtime, and with it LangChain and every tool-argument
        # model, before the first prompt is drawn — to check two URLs.
        from forensic_agent.cli.endpoint_validation import (
            validate_local_endpoint,
            validate_openrouter_endpoint,
        )
        from forensic_agent.core.environ import backend_kind

        requested_model = (
            getattr(args, "model", None)
            or os.environ.get("DFA_MODEL")
            or INTERACTIVE_MODEL
        )
        self.api_key = args.api_key
        if backend_kind(args.base_url) == "ollama":
            self.base_url = validate_local_endpoint(args.base_url)
            # The local service does not validate credentials, but the client
            # requires a value. Use a placeholder so a real credential is never
            # sent to a local endpoint.
            self.api_key = "ollama"
            _provider_selection.ensure_launch_model_is_usable(
                self.base_url,
                requested_model,
                default_model=INTERACTIVE_MODEL,
            )
            self.model = requested_model
        else:
            self.model = requested_model
            self.base_url = validate_openrouter_endpoint(args.base_url, self.api_key)
        # Keep orchestration technology separate from the operating policy.
        # Older reports exposed the ambiguous value "controlled" as an engine.
        self.engine = "LangGraph"
        self.operation_mode = "supervised"
        # A directory or manifest is the base case. Explicit typed sources are
        # overlays supplied by the launcher and must be applied only after the
        # base case has finished discovery; open_case() intentionally clears
        # the previous source set.
        initial_disk = args.image if getattr(args, "case", None) else None
        initial_memory = args.memory
        initial_pcap = getattr(args, "pcap", None)
        self.memory: str | None = None
        self.pcap: str | None = None
        self.pcap_sources: PcapSourceCatalog | None = None
        #: One SHA-256 per bound source path, so the digest a case states for
        #: a source is read back rather than recomputed on every reopen.
        self._source_digests: dict[str, str] = {}
        self._pending_discovered_case: DiscoveredCase | None = None
        # A budget on the command line wins for this launch; otherwise the
        # saved default applies, falling back to twenty when none is stored.
        cli_steps = getattr(args, "max_steps", None)
        self.max_steps = (
            max(1, int(cli_steps)) if cli_steps is not None else _budget.load_saved_max_steps()
        )
        cli_tool_calls = getattr(args, "max_tool_calls", None)
        self.max_tool_calls = (
            max(1, int(cli_tool_calls))
            if cli_tool_calls is not None
            else _budget.load_saved_max_tool_calls()
        )
        cli_wall_time = getattr(args, "max_wall_time_s", None)
        self.max_wall_time_s = (
            max(1, int(cli_wall_time))
            if cli_wall_time is not None
            else _budget.load_saved_max_wall_time_s()
        )
        self.disk: _Disk | None = None
        self.disk_label = "none"
        self.case_label = "none"
        self.case_id = "interactive-unbound"
        self.last_q: str | None = None
        self.last_report: str | None = None
        self.last_provider = "automatic"
        self.last_evidence: list[dict[str, object]] = []
        self.last_findings: list[dict[str, object]] = []
        self.last_run: ControlledRun | None = None
        self.last_ask_outcome: str = self.ASK_NOT_ATTEMPTED
        # Counts exchanges on screen, not turns kept in history: the number is
        # how the operator points at a block they scrolled back to, so it has to
        # keep rising for as long as the transcript does. A retention window
        # that drops an old turn, or a /new that starts a fresh investigation,
        # must never hand a second block the same number.
        self._exchange_number = 0
        # Until an investigation runs there is no record to point at. These were
        # bare relative names, which resolve against whatever directory the
        # process started in: a console with no case open reconstructed and
        # printed an unrelated run's oversight trace as its own, and the
        # analyzer log below wrote itself into that directory as well.
        self.audit_path: str | None = None
        self.case_roots = getattr(args, "case_root", None) or []
        configured_oversight = getattr(args, "oversight", None)
        self.oversight_path: str | None = (
            str(Path(configured_oversight).expanduser().resolve())
            if configured_oversight
            else None
        )
        default_run_root = Path(tempfile.gettempdir()) / "dfir-agent-runs"
        self.run_root = Path(getattr(args, "run_dir", None) or default_run_root)
        # Stated into the environment so the TOOLS layer can resolve the
        # persistent scan-cache root without importing the console. A PRIVATE
        # name on purpose: DFA_RUNS_DIR is operator-declared and other
        # resolutions key on its presence (preferences move into a declared
        # runs dir), so auto-exporting it would silently relocate them.
        os.environ["_DFA_RUNS_ROOT_HINT"] = str(self.run_root)
        self.run_root.mkdir(parents=True, exist_ok=True)
        configured_evidence_root = os.environ.get("DFA_EVIDENCE_ROOT")
        self.evidence_root = (
            Path(configured_evidence_root).expanduser().resolve()
            if configured_evidence_root
            else None
        )
        self._runner: Any | None = None
        self._case_evidence_source_cache: CaseEvidenceSource | None = None
        self._triage_summary: str | None = None
        self._initializing = True
        self._loading_case = False
        # Built before the first case is opened: opening one starts an
        # investigation, and there has to be somewhere to start it.
        self._history = InvestigationHistory(
            ConversationStore(self.run_root / "conversations"),
            console=console,
            case=self._active_case,
            evidence_binding=self._evidence_binding_record,
        )
        if getattr(args, "case", None):
            overlays = tuple(
                source
                for source in (
                    initial_disk,
                    initial_memory,
                    initial_pcap,
                )
                if source
            )
            selection = self.open_case(args.case, discovery_exclusions=overlays)
            if selection is not None and overlays:
                self._stage_pending_overlays(
                    disk_path=initial_disk,
                    memory_path=initial_memory,
                    pcap_path=initial_pcap,
                )
                # The overlays now belong to the staged case and must not be
                # attached to the old/empty active state before that case is
                # resolved by the terminal.
                initial_disk = None
                initial_memory = None
                initial_pcap = None
        elif args.image:
            self.open_image(args.image)
        if initial_disk:
            self.attach_disk(initial_disk, replace_existing=True)
        if initial_memory:
            self.attach_memory(initial_memory, replace_existing=True)
        if initial_pcap:
            self.attach_pcap(initial_pcap, replace_existing=True)
        if self.case_label == "none":
            first_source = self.memory or self.pcap
            if first_source:
                self._new_case(Path(first_source).name)

        self._initializing = False
        resume_id = getattr(args, "resume", None)
        continue_session = bool(getattr(args, "continue_session", False))
        if resume_id:
            self.resume_conversation(str(resume_id), strict=True)
        elif continue_session:
            self._resume_latest()
        else:
            self._history.start()

    def _active_case(self) -> ActiveCase:
        """Name the case, and the model, a saved investigation is written under.

        Read afresh on every transition rather than held: the evidence set, the
        provider and the model all change under an open console, and a history
        recorded against a stale identity is one the store will not resume.
        """

        return ActiveCase(
            case_id=self.case_id,
            source_identity=self._source_identity(),
            provider_endpoint=self.base_url,
            model=self.model,
        )

    def _clear_last_investigation(self) -> None:
        """Remove every model-visible and exportable result from the old source set."""

        self.last_q = None
        self.last_report = None
        self.last_evidence = []
        self.last_findings = []
        self.last_run = None
        self.audit_path = None
        self.oversight_path = None

    def _derived_case_id(self) -> str:
        identity = self._source_identity().removeprefix("sha256:")
        return f"interactive-{identity[:16]}"

    def _configured_display_label(self) -> str | None:
        """The operator-facing case name the launcher passed, if any.

        A directory mounted into the container always arrives at the fixed point
        ``/evidence``, so a label derived from the mount-point name is always
        ``evidence`` and the operator's real case directory name never reaches
        the console.  The launcher therefore forwards the host directory name in
        ``DFA_CASE_LABEL``, and it is used for DISPLAY only.  It is deliberately
        NOT the case identity: ``case_id`` stays the content-derived hash, so the
        name the operator reads on screen never enters the model's view — the
        model sees only the opaque identity, never this label.
        """

        configured = os.environ.get("DFA_CASE_LABEL", "").strip()
        return configured or None

    def _new_case(self, label: str) -> None:
        self._case_evidence_source_cache = None
        self.case_label = self._configured_display_label() or label
        self.case_id = self._derived_case_id()
        self._triage_summary = None
        self._runner = None
        self._history.discard()
        self._clear_last_investigation()
        if not getattr(self, "_initializing", True) and not getattr(
            self, "_loading_case", False
        ):
            self._history.start()

    def _source_set_changed(self) -> None:
        """Start a fresh context when evidence changes without changing the case."""

        preserved_context = self._history.case_context
        self._case_evidence_source_cache = None
        self._triage_summary = None
        self._runner = None
        self._history.discard()
        self._clear_last_investigation()
        if not getattr(self, "_initializing", True) and not getattr(
            self, "_loading_case", False
        ):
            self._history.start(case_context=preserved_context)
            self._console.print(
                f"[{DIM}]Evidence set updated. A new investigation context "
                "was started; the previous history remains saved.[/]"
            )

    def _resolve_evidence_path(self, path: str) -> Path:
        return resolve_evidence_path(path, evidence_root=self.evidence_root)

    def _handoff_host_path_if_needed(
        self,
        path: str,
        *,
        action: str = "case",
    ) -> None:
        handoff_host_path_if_needed(
            path,
            action=action,
            evidence_root=self.evidence_root,
            run_root=self.run_root,
            model=self.model,
            conversation_id=self._history.active_session_id,
        )

    def _existing_file(self, path: str, *, label: str) -> str:
        return existing_file(path, label=label, evidence_root=self.evidence_root)

    def _export_destination(
        self,
        path: str | Path | None,
        *,
        default_name: str,
    ) -> Path:
        return export_destination(
            path, default_name=default_name, run_root=self.run_root
        )

    def _close_disk(self) -> None:
        if self.disk is not None:
            close = getattr(self.disk, "close", None)
            if callable(close):
                close()
        self.disk = None
        self.disk_label = "none"

    def clear_evidence(self) -> None:
        self._close_disk()
        self.memory = None
        self.pcap = None
        self.pcap_sources = None
        self._pending_discovered_case = None
        self._case_evidence_source_cache = None

    def has_evidence(self) -> bool:
        return self.disk is not None or any((self.memory, self.pcap))

    def close(self) -> None:
        """Release the disk."""

        self._close_disk()

    def _source_identity(self) -> str:
        return source_identity(
            disk=self.disk,
            disk_label=self.disk_label,
            memory=self.memory,
            pcap=self.pcap,
            pcap_sources=self.pcap_sources,
        )

    def _case_evidence_binding(
        self,
    ) -> tuple[CaseEvidenceSource | None, PcapSourceCatalog | None]:
        """Return the path-free case descriptor and its optional PCAP catalog."""

        from forensic_agent.cli.evidence_identity import (
            build_interactive_case_evidence_source,
            build_interactive_pcap_catalog,
        )

        pcap_sources = self.pcap_sources or build_interactive_pcap_catalog(self.pcap)
        if self._case_evidence_source_cache is None:
            self._case_evidence_source_cache = build_interactive_case_evidence_source(
                case_id=self.case_id,
                disk=self.disk,
                memory_path=self.memory,
                pcap_path=self.pcap,
                pcap_sources=pcap_sources,
            )
        return self._case_evidence_source_cache, pcap_sources

    def _evidence_binding_record(self) -> ConversationEvidenceBinding | None:
        return evidence_binding_record(
            disk=self.disk,
            case_label=self.case_label,
            memory=self.memory,
            pcap=self.pcap,
            pcap_sources=self.pcap_sources,
        )

    def _restore_evidence_binding(
        self,
        binding: ConversationEvidenceBinding,
    ) -> tuple[str, ...]:
        """Reattach the recorded sources and report the ones out of reach.

        The container boundary is not crossed here. A path that no longer lies
        inside the mounted evidence root is reported as unreachable rather than
        handed to the host launcher: reopening what is still mounted is a
        restore, requesting a new mount on the operator's behalf is not — which
        is why the resolver handed to the sorting below is the one that only ever
        looks inside the evidence root.
        """

        restorable = restorable_sources(binding, resolve=self._existing_file)
        if not restorable.any_reachable:
            return restorable.unreachable
        catalog = restorable.pcap_sources

        # The disk is opened before anything is released, so a failure here
        # leaves the console exactly as it was.
        prepared_disk: _Disk | None = None
        disk_label = "none"
        if restorable.disk_path is not None:
            _, prepared_disk = self._prepare_disk(restorable.disk_path)
            disk_label = os.path.basename(restorable.disk_path)

        self._loading_case = True
        try:
            self.clear_evidence()
            self.disk = prepared_disk
            self.disk_label = disk_label
            self.memory = restorable.memory_path
            self.pcap_sources = catalog
            self.pcap = catalog.default.path if catalog is not None else None
            self.case_label = binding.case_label
            self.case_id = self._derived_case_id()
            self._triage_summary = None
            self._runner = None
            self._history.discard()
            self._clear_last_investigation()
        finally:
            self._loading_case = False
        return restorable.unreachable

    def continue_investigation(self, *, strict: bool = False) -> None:
        """Pick up the previous investigation together with the evidence it used.

        This restores context and nothing else: no tool call is replayed and no
        question is answered again. When an evidence set is already open the
        console stays on it, because an operator who has said which case they
        are looking at does not expect continuing to swap it for another.

        ``strict`` belongs to the launch flag, not to the command: a console
        started with ``--continue`` that cannot honour the request must fail
        rather than open quietly on a different footing than it was asked for.
        """

        evidence_open = self.has_evidence()
        row = self._history.continuable(evidence_open=evidence_open)
        if row is None:
            self._console.print(
                f"[{DIM}]{_t('There is no saved investigation to continue.')}[/]"
            )
            return

        session_id = str(row["session_id"])
        if not evidence_open:
            unreachable = self._restore_evidence_binding(recorded_binding(row))
            if self.has_evidence():
                self._console.print(self.status_line())
                self.show_sources()
                # Reopening the recorded sources is opening a case: the index,
                # and the line saying whether it exists, must not depend on
                # whether the operator typed /case or /continue.
                self._index_active_case()
            for description in unreachable:
                self._console.print(
                    f"[{ORANGE}]{_t('Evidence source could not be reopened:')}[/] "
                    f"[{DIM}]{escape(description)}[/]"
                )
            if unreachable:
                self._console.print(
                    f"[{ORANGE}]"
                    + _t(
                        "The previous investigation was not reloaded because "
                        "its evidence set is incomplete."
                    )
                    + "[/]"
                )
                self._history.ensure_started()
                return
            if str(row["source_identity"]) != self._source_identity():
                self._console.print(
                    f"[{ORANGE}]"
                    + _t(
                        "The evidence has changed since this investigation was "
                        "saved; it was reopened, but the previous investigation "
                        "was not reloaded."
                    )
                    + "[/]"
                )
                self._history.ensure_started()
                return
            # The reopened set is byte-for-byte the recorded one, so the case
            # keeps the identity it was investigated under — including a case_id
            # a manifest declared rather than one derived from the sources.
            self.case_id = str(row["case_id"])

        try:
            self._history.resume(session_id, quiet=True)
        except Exception as exc:
            if strict:
                raise
            self._console.print(
                f"[{RED}]{_t('The previous investigation could not be continued:')}[/] "
                f"{escape(str(exc)[:240])}"
            )
            self._history.ensure_started()
            return
        self._console.print(
            f"[{SUCCESS}]{_t('Investigation continued:')}[/] "
            f"[{DIM}]{self._history.active_session_id}[/]"
        )

    def _resume_latest(self) -> None:
        self.continue_investigation(strict=True)
        self._history.ensure_started()

    def new_conversation(self, title: str | None = None) -> None:
        self._history.start(title)
        self._console.print(
            f"[{SUCCESS}]New investigation:[/] [{DIM}]{self._history.active_session_id}[/]"
        )

    def resume_conversation(
        self,
        identifier: str,
        *,
        quiet: bool = False,
        strict: bool = False,
    ) -> None:
        self._history.resume(identifier, quiet=quiet, strict=strict)

    def show_sessions(self) -> None:
        self._history.show_saved_investigations()

    def show_history(
        self, limit: int | None = None, *, console: Console | None = None
    ) -> None:
        """The completed questions of this investigation; ``console`` as in
        :meth:`show_findings`."""

        self._history.show_completed_questions(limit, console=console)

    def _require_open_case_for_context(self) -> None:
        """Refuse case context while there is no case for it to be about.

        The brief is carried into every prompt of the investigation it belongs
        to, and an investigation is only started once evidence is open, so
        accepting one earlier would file it against nothing.
        """

        if not self.has_evidence():
            raise ValueError("Open a forensic case before setting case context.")

    def show_case_context(self) -> None:
        self._require_open_case_for_context()
        self._history.show_case_context()

    def set_case_context(self, value: str) -> None:
        self._require_open_case_for_context()
        self._history.set_case_context(value)

    def load_case_context(self, path: str) -> None:
        if not self.has_evidence():
            raise ValueError("Open a forensic case before loading case context.")
        self.set_case_context(read_case_context_file(self._resolve_evidence_path(path)))

    def clear_case_context(self) -> None:
        self._require_open_case_for_context()
        self._history.clear_case_context()

    def retry_last(self) -> None:
        question = self._history.question_to_retry()
        if question is None:
            return
        self.ask(question)

    def undo_context(self) -> None:
        self._history.undo_context()

    def open_image(self, path: str) -> None:
        started = time.perf_counter()
        resolved, prepared_disk = self._prepare_disk(path)
        self.clear_evidence()
        self.disk = prepared_disk
        self.disk_label = os.path.basename(resolved)
        self._new_case(self.disk_label)
        # Opening a case is the one interactive step that can run for minutes,
        # so what it cost is stated the way every other duration is stated in
        # this console — "· 12.4 s", or "· 7m 04s" once it passes a minute —
        # instead of being left to the operator's memory of when they pressed
        # Enter.
        self._console.print(
            f"[{SUCCESS}]{_t('disk image opened')}[/] "
            f"[{DIM}]{escape(self.disk_label)}, "
            f"{format_duration(time.perf_counter() - started)}[/]"
        )
        # Index it, like every other way of opening a disk does. This was the
        # one opener that did not: `dfir-agent --image disk.raw` opened a case
        # with no entity index at all and said nothing about it, so the agent's
        # first search paid for the full scan mid-investigation instead of the
        # open paying for it once, in front of a progress row.
        self._index_active_case()

    def _prepare_disk(self, path: str) -> tuple[str, _Disk]:
        """Open a disk image before replacing any active evidence state."""

        from forensic_agent.tools.tsk_tool import DiskImage

        resolved = self._existing_file(path, label="Disk image")
        audit = AuditLog(str(self.run_root / "case-open.audit.jsonl"))
        # A front-end may watch the digest itself (the console's quiet
        # StringIO is never a terminal, so the Rich display below would build
        # nothing there). Read at call time, like _tool_line: the watcher is
        # a callable taking the resolved path and returning either None or
        # the (advance, declare_total) observer pair the attestation drives.
        watcher_factory = getattr(self, "_case_open_watcher", None)
        if watcher_factory is not None:
            observers = watcher_factory(resolved)
            if observers is not None:
                report_hashed_bytes, declare_total = observers
                disk = DiskImage(
                    resolved,
                    audit=audit,
                    progress=report_hashed_bytes,
                    progress_total=declare_total,
                )
                self._announce_disk_integrity(disk)
                return resolved, disk
        with case_opening_progress(self._console, resolved) as watcher:
            if watcher is None:
                # Nothing is watching, so the open is issued exactly as it was
                # issued before this display existed, down to the argument list.
                disk = DiskImage(resolved, audit=audit)
            else:
                report_hashed_bytes, declare_total = watcher
                disk = DiskImage(
                    resolved,
                    audit=audit,
                    progress=report_hashed_bytes,
                    progress_total=declare_total,
                )
        self._announce_disk_integrity(disk)
        return resolved, disk

    def _announce_disk_integrity(self, disk) -> None:
        """Say out loud when an open reused the stored verification.

        A reused attestation must never be silent: the operator has to be
        able to tell a freshly hashed medium from one vouched for by an
        earlier pass, and to know the full re-check is one command away.

        Three separate statements, on three lines, rather than one sentence
        that wrapped. The wrap was not a tidiness complaint. The lead carries
        the success glyph and the glyph is what says "this line is good news";
        the continuation carried none, sat flush at column zero in the same
        dim grey as any other note, and the full-screen console, which colours
        a recorded line by the glyph it starts with, therefore painted the tail
        of a success message as an unrelated dim one.

        Short statements each on their own line cannot come apart that way, and
        the supporting ones go through :func:`_supporting_line`, whose indent
        survives a wrap of its own: a continuation returning to column zero is
        the same defect one size smaller.

        The moment is a date and a time a person can read. The stored form is
        ``2026-08-17T16:34:01+0000``, which is what a machine writes to sort
        by; an operator deciding whether the last verification was recent
        should not have to parse it.
        """

        if not getattr(disk, "evidence_attestation_reused", False):
            return
        when = _readable_attestation_moment(getattr(disk, "attested_at", ""))
        digest = str(getattr(disk, "image_sha", ""))[:16]
        self._console.print(
            f"[{SUCCESS}]{GLYPH_OK} "
            + escape(_t("Integrity verified on an earlier open."))
            + "[/]"
        )
        if when:
            self._supporting_line(_t("Last verified {when}.").format(when=when))
        self._supporting_line(f"SHA-256 {digest}…")
        self._supporting_line(
            _t(
                "The source identity was re-checked just now. "
                "/verify reads the whole medium again."
            )
        )

    def _supporting_line(self, text: str, *, style: str = DIM) -> None:
        """One line of detail under a lead line, indented across its own wrap."""

        self._console.print(_detail(text, style=style))

    # -- /verify ---------------------------------------------------------
    def verifiable_medium(self) -> tuple[str, int] | None:
        """The medium ``/verify`` would stream, and how many bytes that is.

        Asked BEFORE the command runs, because the operator has to be told what
        they are committing to. A full pass over evidence is minutes of reading
        on a real image, and a console that starts one without saying how large
        the medium is has taken that decision on the operator's behalf.

        ``None`` when there is no disk to stream. The byte count is the size the
        attestation stated for the decoded medium, not the size of the container
        on disk: a compressed EWF file is several times smaller than the media
        it decodes to, and quoting the file would understate the wait.
        """

        disk = getattr(self, "disk", None)
        if disk is None:
            return None
        path = getattr(disk, "image_path", None)
        size = getattr(disk, "image_size", None)
        if not path:
            return None
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            size = 0
        return str(path), size

    def verify_evidence_integrity(self) -> dict:
        """Read the whole medium again and say whether it is still the same bytes.

        This is the one operation in the console whose entire value is the
        reading. ``verify_image_integrity`` has a reuse path that answers from a
        stored multi-hash attestation without touching the medium, which is
        right for the agent asking a question mid-run and completely wrong here:
        it would print a digest, report that integrity was verified, and have
        read nothing. So the stream is forced, and what comes back is compared
        against the digest the case was opened under.

        The comparison is meaningful because both sides are the same
        measurement. ``disk.image_sha`` is the SHA-256 of the decoded logical
        medium under the source's declared digest semantics, and the pass forced
        here recomputes exactly that: the raw file's own bytes for a raw source,
        the ordered concatenation for a split set, libewf's decoded media for an
        EWF container. A comparison between two different semantics would differ
        every time and mean nothing.

        Progress is reported through ``_integrity_watcher`` when a front end
        installed one, exactly as the case open reads ``_case_open_watcher`` at
        call time; otherwise the console draws the display itself. Neither is
        consulted by the pass.
        """

        from forensic_agent.tools.integrity_tool import verify_image_integrity

        medium = self.verifiable_medium()
        if medium is None:
            raise ValueError(
                "Open a disk image before verifying it. /verify reads the "
                "medium the active case was opened from."
            )
        path, _size = medium
        recorded = str(getattr(self.disk, "image_sha", "") or "")

        watcher_factory = getattr(self, "_integrity_watcher", None)
        observers = watcher_factory(path) if watcher_factory is not None else None
        if observers is not None:
            advance, declare_total = observers
            result = verify_image_integrity(
                self.disk,
                force_full_stream=True,
                progress=advance,
                progress_total=declare_total,
            )
        else:
            result = self._verify_with_console_display(path)

        result["recorded_sha256"] = recorded
        computed = str(result.get("sha256", "") or "")
        result["matches_recorded"] = bool(
            recorded and computed and recorded == computed
        )
        self._announce_verification(result)
        return result

    def _verify_with_console_display(self, path: str) -> dict:
        """Stream the medium behind the console's own progress display.

        The display is the general one every long local step reports through,
        rather than a second bar built for this command: an operator who has
        watched a case open should recognise what a verification looks like
        without being taught it twice. Byte counts become the fraction that
        display takes, and the total arrives from the pass itself.
        """

        from forensic_agent.tools.integrity_tool import verify_image_integrity

        name = os.path.basename(path) or path
        total = 0
        done = 0

        with _progress.reporting(self._console, _t("Verifying evidence")) as report:

            def declare_total(byte_count: int) -> None:
                nonlocal total
                total = int(byte_count)

            def advance(byte_count: int) -> None:
                nonlocal done
                done += int(byte_count)
                report(done / total if total else None, name)

            return verify_image_integrity(
                self.disk,
                force_full_stream=True,
                progress=advance,
                progress_total=declare_total,
            )

    def _announce_verification(self, result: Mapping[str, object]) -> None:
        """Print the verdict this console reached about the medium."""

        for line in integrity_verdict_lines(result):
            self._console.print(line)

    def attach_disk(self, path: str, *, replace_existing: bool = False) -> None:
        """Attach a disk image without replacing the active case identity."""

        if getattr(self, "disk", None) is not None and not replace_existing:
            raise ValueError(
                "A disk image is already attached. Use /case disk <path> "
                "to replace it."
            )
        self._handoff_host_path_if_needed(path, action="attach-disk")
        if not self.has_evidence():
            self.open_image(path)
            self._index_active_case()
            return
        resolved, prepared_disk = self._prepare_disk(path)
        # The replaced image's handle must not leak: prepare the new disk
        # FIRST (a failed open must leave the old one attached), then close.
        self._close_disk()
        self.disk = prepared_disk
        self.disk_label = os.path.basename(resolved)
        self._source_set_changed()
        self._index_active_case()

    def attach_memory(self, path: str, *, replace_existing: bool = False) -> None:
        if getattr(self, "memory", None) and not replace_existing:
            raise ValueError(
                "A memory dump is already attached. Use /case memory <path> "
                "to replace it."
            )
        self._handoff_host_path_if_needed(path, action="attach-memory")
        starts_new_case = not self.has_evidence()
        self.memory = self._existing_file(path, label="Memory dump")
        if starts_new_case:
            self._new_case(Path(self.memory).name)
        else:
            self._source_set_changed()
        # An attached source is a case source like any other: the entity index
        # and the line naming it must not depend on whether the operator typed
        # /case or /attach for the same file.
        self._index_active_case()

    def attach_pcap(self, path: str, *, replace_existing: bool = False) -> None:
        self._handoff_host_path_if_needed(path, action="attach-network")
        starts_new_case = not self.has_evidence()
        resolved = self._existing_file(path, label="Network capture")
        if self.pcap_sources is None or replace_existing:
            from forensic_agent.cli.evidence_identity import (
                build_interactive_pcap_catalog,
            )

            self.pcap_sources = build_interactive_pcap_catalog(resolved)
            assert self.pcap_sources is not None
        else:
            self.pcap_sources = self.pcap_sources.add_original(resolved)
        self.pcap = self.pcap_sources.default.path
        if starts_new_case:
            self._new_case(Path(resolved).name)
        else:
            self._source_set_changed()
        self._index_active_case()

    def pending_case_selection(self) -> CaseSourceSelection | None:
        """Return staged source choices without changing the active case."""

        discovered = self._pending_discovered_case
        if discovered is None:
            return None
        return CaseSourceSelection(
            root=discovered.root,
            disks=discovered.disks,
            memories=discovered.memories,
            pcaps=discovered.pcaps,
            ambiguous=discovered.ambiguous,
        )

    def cancel_pending_case(self) -> None:
        """Cancel staged discovery while leaving the active case untouched."""

        self._pending_discovered_case = None

    def _stage_pending_overlays(
        self,
        *,
        disk_path: str | None,
        memory_path: str | None,
        pcap_path: str | None,
    ) -> None:
        """Bind startup overlays to a staged case without mutating active evidence."""

        discovered = self._pending_discovered_case
        if discovered is None:
            raise ValueError("No case source selection is pending.")

        def checked(path: str | None, *, label: str) -> Path | None:
            if path is None:
                return None
            return Path(self._existing_file(path, label=label))

        staged = stage_overlays(
            discovered,
            disk=checked(disk_path, label="Disk image"),
            memory=checked(memory_path, label="Memory dump"),
            pcap=checked(pcap_path, label="Network capture"),
        )
        self._pending_discovered_case = staged
        if not requires_source_resolution(staged):
            self._open_discovered_case(staged)

    def resolve_pending_case(
        self,
        default_pcap: str | None = None,
        *,
        selected_disk: str | None = None,
        selected_memory: str | None = None,
        pcap_roles: Mapping[str, str] | None = None,
        merged_inputs: Mapping[str, Sequence[str]] | None = None,
        ambiguous_roles: Mapping[str, str] | None = None,
    ) -> None:
        """Validate and atomically apply one staged multi-source case.

        This method never creates or merges captures. ``merged_pcap`` records
        only user-declared lineage for an existing derived capture.
        """

        discovered = self._pending_discovered_case
        if discovered is None:
            raise ValueError("No case source selection is pending.")

        resolved, catalog = resolve_staged_selection(
            discovered,
            default_pcap,
            selected_disk=selected_disk,
            selected_memory=selected_memory,
            pcap_roles=pcap_roles,
            merged_inputs=merged_inputs,
            ambiguous_roles=ambiguous_roles,
        )

        self._commit_discovered_case(
            resolved,
            pcap_sources=catalog,
        )

    def open_case(
        self,
        path: str,
        *,
        discovery_exclusions: tuple[str, ...] = (),
    ) -> CaseSourceSelection | None:
        """Attach a case directory, one evidence file, or an optional manifest."""

        raw_path = path.strip()
        self._handoff_host_path_if_needed(raw_path)
        candidate = self._resolve_evidence_path(path)
        if candidate.is_dir():
            manifest = candidate / "case.json"
            if manifest.is_file():
                candidate = manifest
            else:
                excluded = tuple(
                    self._resolve_evidence_path(source)
                    for source in discovery_exclusions
                )
                discovered = self._discover_case(
                    candidate,
                    excluded_paths=excluded,
                )
                if requires_source_resolution(discovered):
                    self._pending_discovered_case = discovered
                    return self.pending_case_selection()
                self._open_discovered_case(discovered)
                return None
        if not candidate.is_file():
            raise FileNotFoundError(f"Forensic case not found: {candidate}")

        if candidate.suffix.casefold() == ".json":
            (
                declared,
                pcap_catalog,
                declared_case_id,
                manifest_label,
            ) = case_from_manifest(candidate, evidence_root=self.evidence_root)
            self._commit_discovered_case(
                declared,
                pcap_sources=pcap_catalog,
                declared_case_id=declared_case_id,
                case_label=manifest_label,
            )
            return None

        single, catalog, case_label = case_from_evidence_file(candidate)
        if single.ambiguous:
            # A RAW or BIN image is a disk image or a memory dump and nothing in
            # the file says which, so it is staged for the operator to classify
            # rather than opened as one of the two.
            self._pending_discovered_case = single
            return self.pending_case_selection()
        self._commit_discovered_case(
            single,
            pcap_sources=catalog,
            case_label=case_label,
        )
        return None

    @staticmethod
    def _discover_case(
        directory: Path,
        *,
        excluded_paths: tuple[Path, ...] = (),
    ) -> DiscoveredCase:
        """Inspect a directory without mutating the active session."""

        from forensic_agent.cli.case_discovery import discover_case_directory

        return discover_case_directory(directory, excluded_paths=excluded_paths)

    def open_typed_case(self, kind: str, path: str) -> None:
        """Open one explicitly typed source as a new case."""

        normalized_kind = kind.strip().casefold()
        actions = {
            "disk": (self.open_image, "Disk image"),
            "memory": (self.attach_memory, "Memory dump"),
            "network": (self.attach_pcap, "Network capture"),
        }
        selected = actions.get(normalized_kind)
        if selected is None:
            raise ValueError(
                "Evidence type must be disk, memory, or network."
            )
        opener, label = selected

        raw_path = path.strip()
        self._handoff_host_path_if_needed(
            raw_path,
            action=normalized_kind,
        )

        resolved = self._existing_file(raw_path, label=label)
        if normalized_kind == "disk":
            self.open_image(resolved)
            # A typed source is a case like any discovered one: the entity index
            # (and the line announcing whether it exists) must not depend on
            # which of the two ways the operator used to open the same evidence.
            # The other openers are the /attach methods, which index themselves.
            self._index_active_case()
        else:
            self.clear_evidence()
            opener(resolved)

    def _open_discovered_case(self, discovered: DiscoveredCase) -> None:
        """Attach an already validated, unambiguous discovered case."""

        catalog = None
        if discovered.pcap is not None:
            from forensic_agent.cli.evidence_identity import (
                build_interactive_pcap_catalog,
            )

            catalog = build_interactive_pcap_catalog(str(discovered.pcap))
        self._commit_discovered_case(discovered, pcap_sources=catalog)

    def _source_digest(self, path: str) -> str | None:
        """The SHA-256 of one bound source, hashed at most once per path.

        Every source a case binds is digested, so a later examination can show
        the bytes read are the bytes bound; for a raw image the same digest is
        the key its entity index is content-addressed under, which is why one
        pass serves both. Cached on the session so a reopen in the same process
        pays nothing, and it never raises — a source that could not be hashed is
        carried without a digest rather than refusing the case.
        """

        cached = self._source_digests.get(path)
        if cached is not None:
            return cached
        try:
            from forensic_agent.cli.progress import sha256_file_reporting

            # Named rather than described: a front end shows this string as the
            # step it is waiting on, beside "Verifying <image>" and "Indexing
            # evidence", and the operator has to be able to tell the three
            # apart. Read at call time like _tool_line; with no front end the
            # sink is absent and this is the plain digest, unchanged.
            sink = getattr(self, "_index_progress", None)
            step = _t("Hashing {name}").format(name=os.path.basename(path))
            if sink is not None:
                try:
                    sink(None, step)
                except Exception:
                    pass
            digest = sha256_file_reporting(path, report=sink, detail=step)
        except Exception:
            return None
        self._source_digests[path] = digest
        return digest

    def source_digests(self) -> dict[str, str]:
        """The digest each bound source path was recorded under, if any."""

        return dict(self._source_digests)

    def _prewarmed_memory_digest(self) -> str | None:
        """The digest the open already paid for, never a fresh hash.

        This is what lets the run reuse the case-open scan for a memory-only
        case instead of rebuilding it: the index is content-keyed, and without
        the key the tool has nothing to look the prepared scan up under.
        Hashing here instead would move a multi-gigabyte read into the middle
        of a question, so an open that never hashed yields None and the tool
        derives what it needs itself, exactly as before.
        """

        return self._source_digests.get(self.memory) if self.memory else None

    def _index_active_case(self) -> None:
        """Derive the entity index for the case just opened, over its principal
        raw image.

        Failure here is reported and never raised. An index is one instrument
        among several, and a case that refused to open because one instrument
        could not be prepared would be worse than a case that opens without it.

        The whole-image entity search resolves its source to the disk image when
        one is present and to the memory image otherwise, so the same source is
        the one indexed here. The network capture carries its own parser and is
        examined through it rather than through the entity scanner.
        """

        image = getattr(self.disk, "image_path", None)
        evidence_sha256 = getattr(self.disk, "image_sha", None)
        # Every bound source is digested here, whether or not it is the one the
        # entity scanner reads: a case states for each of its sources the
        # SHA-256 its bytes carried when the case bound them. The disk brings
        # its own attested media digest and is not re-read.
        if self.memory:
            self._source_digest(self.memory)
        for binding in self.pcap_sources.bindings if self.pcap_sources else ():
            self._source_digest(str(binding.path))
        if not image and self.memory:
            image = self.memory
            # A memory dump carries no attestation digest, but the entity index
            # is content-keyed: hashing the dump once here lets the scan build
            # at open and be reused on every later question and reopen, instead
            # of the first bulk_extract rebuilding it in the middle of a run.
            evidence_sha256 = self._source_digests.get(self.memory)
        if not image:
            return
        _case_index.index_opened_case(
            self._console,
            image_path=str(image),
            runs_root=Path(self.run_root),
            evidence_sha256=evidence_sha256,
            # A front-end that renders its own progress (the console's quiet
            # StringIO cannot animate) supplies the sink here; read at call
            # time like _tool_line.
            progress=getattr(self, "_index_progress", None),
        )

    def _commit_discovered_case(
        self,
        discovered: DiscoveredCase,
        *,
        pcap_sources: PcapSourceCatalog | None,
        classified_disk: Path | None = None,
        classified_memory: Path | None = None,
        declared_case_id: str | None = None,
        case_label: str | None = None,
    ) -> None:
        """Open inputs first, then replace the active case in one atomic step."""

        disk_path = classified_disk or discovered.disk
        memory_path = classified_memory or discovered.memory
        resolved_memory = (
            self._existing_file(str(memory_path), label="Memory dump")
            if memory_path
            else None
        )
        if pcap_sources is not None:
            for binding in pcap_sources.bindings:
                self._existing_file(binding.path, label="Network capture")

        new_disk: _Disk | None = None
        resolved_disk: str | None = None
        if disk_path is not None:
            resolved_disk, new_disk = self._prepare_disk(str(disk_path))

        old_state = (
            self.disk,
            self.disk_label,
            self.memory,
            self.pcap,
            self.pcap_sources,
            self.case_id,
            self.case_label,
            list(self.case_roots),
        )
        old_disk = self.disk
        try:
            self.disk = new_disk
            self.disk_label = Path(resolved_disk).name if resolved_disk else "none"
            self.memory = resolved_memory
            self.pcap_sources = pcap_sources
            self.pcap = pcap_sources.default.path if pcap_sources else None
            if self.disk is None and not any((self.memory, self.pcap)):
                raise ValueError("The case directory has no usable evidence source.")
            self.case_id = declared_case_id or self._derived_case_id()
            # A manifest label is explicit operator intent and wins; otherwise the
            # launcher-supplied display name is used before the mount-point name,
            # which in the container is always "evidence".  Display only — never
            # the identity, so it never reaches the model.
            self.case_label = (
                case_label or self._configured_display_label() or discovered.root.name
            )
            root = str(discovered.root.resolve())
            if root not in self.case_roots:
                self.case_roots = [*self.case_roots, root]
            self._pending_discovered_case = None
        except BaseException as error:
            (
                self.disk,
                self.disk_label,
                self.memory,
                self.pcap,
                self.pcap_sources,
                self.case_id,
                self.case_label,
                self.case_roots,
            ) = old_state
            if new_disk is not None:
                close = getattr(new_disk, "close", None)
                if callable(close):
                    try:
                        close()
                    except BaseException as cleanup_error:
                        error.add_note(
                            "The newly opened disk also failed to close during rollback: "
                            f"{cleanup_error!r}"
                        )
            raise

        if old_disk is not None:
            close = getattr(old_disk, "close", None)
            if callable(close):
                close()
        self._case_evidence_source_cache = None
        self._history.discard()
        self._runner = None
        self._index_active_case()
        self._triage_summary = None
        self._clear_last_investigation()
        if not getattr(self, "_initializing", True):
            self._history.start()

    def status_line(self) -> str:
        return _session_facts.status_line(
            case_label=self.case_label,
            sources=self._source_count(),
            tools=len(self._visible_tool_names()),
        )

    def _source_count(self) -> int:
        return _session_facts.source_count(
            disk=self.disk,
            memory=self.memory,
            pcap=self.pcap,
            pcap_sources=self.pcap_sources,
        )

    def config_panel(self) -> Panel:
        from forensic_agent.core.environ import backend_kind

        provider = (
            "Ollama"
            if backend_kind(self.base_url) == "ollama"
            else "OpenRouter"
        )
        return _session_facts.session_panel(
            model=self.model,
            provider=provider,
            reasoning_effort=_reasoning.current_effort(),
            max_steps=self.max_steps,
            max_tool_calls=self.max_tool_calls,
            case_label=self.case_label,
            has_evidence=self.has_evidence(),
            disk=self.disk,
            disk_label=self.disk_label,
            memory=self.memory,
            pcap=self.pcap,
            pcap_sources=self.pcap_sources,
            tools=len(self._visible_tool_names()),
            case_context_set=bool(self._history.case_context),
        )

    def status_panel(self) -> Panel:
        return self.config_panel()

    def show_sources(self, *, console: Console | None = None) -> None:
        """Every evidence source attached to the case.

        ``console`` renders this view somewhere other than the session's
        own console. The interactive console reads it while an
        investigation is running, and the run is printing into the session
        console from its own thread at that moment; being handed a console
        is what makes that read safe.
        """

        (console or self._console).print(
            _session_facts.evidence_sources_table(
                case_label=self.case_label,
                has_evidence=self.has_evidence(),
                disk=self.disk,
                disk_label=self.disk_label,
                memory=self.memory,
                pcap=self.pcap,
                pcap_sources=self.pcap_sources,
                digests=self.source_digests(),
            )
        )

    def _visible_tool_names(self) -> tuple[str, ...]:
        from forensic_agent.cli.controlled import ControlledInvestigationSession
        from forensic_agent.cli.model_request import disabled_tool_names

        native = ControlledInvestigationSession._relevant_tools(
            disk=self.disk,
            memory_path=self.memory,
            pcap_path=self.pcap,
            pcap_sources=self.pcap_sources,
        )
        # Subtract the operator's disabled set so every count and listing
        # matches the palette questions actually ride with; the same
        # never-empty guard as the prompt-side narrowing.
        remaining = [name for name in native if name not in disabled_tool_names()]
        return tuple(sorted(remaining or native))

    def show_tools(
        self, name: str | None = None, *, console: Console | None = None
    ) -> None:
        """The active tools, or one function in full.

        ``console`` renders this view somewhere other than the session's
        own console. The interactive console reads it while an
        investigation is running, and the run is printing into the session
        console from its own thread at that moment; being handed a console
        is what makes that read safe.
        """

        _tools_view.show_tools(
            console or self._console,
            name,
            active_names=frozenset(self._visible_tool_names()),
            disk=self.disk,
            memory_path=self.memory,
            pcap_path=self.pcap,
            pcap_sources=self.pcap_sources,
        )

    def show_model(self) -> None:
        _model_view.show_model(
            self._console, model=self.model, base_url=self.base_url
        )

    def show_model_catalog(self, selector: str = "") -> None:
        _model_view.show_model_catalog(
            self._console,
            selector,
            model=self.model,
            base_url=self.base_url,
            api_key=self.api_key,
        )

    def change_language(self, argument: str) -> None:
        _console_settings.change_language(self._console, argument)

    def change_reasoning(self, argument: str) -> None:
        _console_settings.change_reasoning(
            self._console,
            argument,
            on_effort_changed=self._drop_cached_runner,
        )

    # command_name is the command whose declared form a mistyped value is
    # answered with, and all three budgets are arguments of /budget rather
    # than commands, so all three name it. Passing "steps" here would have
    # the console answer a mistyped step budget with "/steps", which is not
    # a command this console has.
    def change_steps(self, argument: str) -> None:
        _console_settings.change_budget(
            self._console,
            argument,
            command_name="budget",
            label=_t("Step budget:"),
            current=self.max_steps,
            apply=self._apply_max_steps,
            save=_budget.save_max_steps,
        )

    def _apply_max_steps(self, value: int) -> None:
        self.max_steps = value
        self._runner = None

    def change_tool_calls(self, argument: str) -> None:
        _console_settings.change_budget(
            self._console,
            argument,
            command_name="budget",
            label=_t("Tool-call budget:"),
            current=self.max_tool_calls,
            apply=self._apply_max_tool_calls,
            save=_budget.save_max_tool_calls,
        )

    def _apply_max_tool_calls(self, value: int) -> None:
        self.max_tool_calls = value
        self._runner = None

    def change_time(self, argument: str) -> None:
        """Set the wall clock one question may spend, in whole seconds.

        The same control as the other two budgets, and deliberately down the
        same path: validated by the same rule, saved as the standing default,
        and applied by dropping the cached runner so the next question is
        built under it. Until this existed a run that ended with
        ``budget_exhausted:max_wall_time_s`` could not be given more time from
        the console at all.
        """

        _console_settings.change_budget(
            self._console,
            argument,
            command_name="budget",
            label=_t("Time budget (s):"),
            current=self.max_wall_time_s,
            apply=self._apply_max_wall_time_s,
            save=_budget.save_max_wall_time_s,
        )

    def _apply_max_wall_time_s(self, value: int) -> None:
        self.max_wall_time_s = value
        self._runner = None

    def show_budget(self) -> None:
        """Show the per-question time, step and tool-call budgets together."""
        self._console.print(
            f"{_t('Time budget (s):')} [bold]{self.max_wall_time_s}[/]  ·  "
            f"{_t('Step budget:')} [bold]{self.max_steps}[/]  ·  "
            f"{_t('Tool-call budget:')} [bold]{self.max_tool_calls}[/]"
        )

    def _drop_cached_runner(self) -> None:
        """Let go of the runner so the next question is built under new controls.

        The runner carries the effort it was built with, so a change to that
        setting has to build a new one. Nothing investigative is lost: the runner
        holds no history, only the controls one question runs under.
        """

        self._runner = None

    def _activate_model_context(self, replacement: ConversationSession) -> None:
        """Activate a prepared empty conversation after configuration is saved."""

        self._history.activate(replacement)
        self._runner = None
        self._clear_last_investigation()

    def change_model(self, model: str) -> None:
        """Select one advertised tool-capable model without detaching evidence."""

        from forensic_agent.core.environ import backend_kind

        candidate = model.strip()
        if not candidate or any(character.isspace() for character in candidate):
            raise CommandUsageError("model")
        unchanged = candidate == self.model

        kind = backend_kind(self.base_url)
        _provider_selection.ensure_selected_model_is_usable(
            backend=kind,
            base_url=self.base_url,
            api_key=self.api_key,
            model=candidate,
        )

        if unchanged:
            _provider_selection.persist_provider_choice(
                backend=kind,
                base_url=self.base_url,
                model=candidate,
                api_key=self.api_key,
            )
            self._console.print(
                f"[{DIM}]Model already active and saved as the default:[/] "
                f"[{ACCENT}]{escape(candidate)}[/]"
            )
            return

        replacement = self._history.build(
            f"model-{candidate}",
            model=candidate,
        )
        _provider_selection.persist_provider_choice(
            backend=kind,
            base_url=self.base_url,
            model=candidate,
            api_key=self.api_key,
        )
        previous_model = self.model
        self._activate_model_context(replacement)
        self.model = candidate
        self._console.print(
            f"[{SUCCESS}]Model changed:[/] "
            f"[{DIM}]{escape(previous_model)}[/] → "
            f"[{ACCENT}]{escape(candidate)}[/]"
        )
        self._console.print(
            f"[{DIM}]Evidence remains attached. A new investigation history "
            "was started to keep model provenance separate. The model selection "
            "was saved for future starts.[/]"
        )

    def reconfigure_provider(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str,
    ) -> None:
        """Apply an already validated provider selection without losing evidence."""

        # Deliberately the light module: reaching into cli.controlled here would
        # load the agent runtime, and with it LangChain and every tool-argument
        # model, before the first prompt is drawn — to check two URLs.
        from forensic_agent.cli.endpoint_validation import (
            validate_local_endpoint,
            validate_openrouter_endpoint,
        )
        from forensic_agent.core.environ import backend_kind

        if backend_kind(base_url) == "ollama":
            validated_url = validate_local_endpoint(base_url)
            validated_key = "ollama"
        else:
            validated_url = validate_openrouter_endpoint(base_url, api_key)
            validated_key = api_key
        unchanged = (
            validated_url == self.base_url
            and validated_key == self.api_key
            and model == self.model
        )
        if unchanged:
            self._console.print(f"[{DIM}]Provider configuration is unchanged.[/]")
            return

        kind = backend_kind(validated_url)
        replacement = self._history.build(
            f"model-{model}",
            model=model,
            base_url=validated_url,
        )
        _provider_selection.persist_provider_choice(
            backend=kind,
            base_url=validated_url,
            model=model,
            api_key=validated_key,
        )
        self._activate_model_context(replacement)
        self.base_url = validated_url
        self.api_key = validated_key
        self.model = model
        self._console.print(
            f"[{SUCCESS}]Provider configuration applied.[/] "
            f"[{DIM}]Evidence remains attached; a new investigation history "
            "was started.[/]"
        )

    def _tool_line(
        self,
        name: object,
        args: object,
        dt: float | None,
        refused: bool = False,
    ) -> None:
        # A None duration is the "call started" marker for live panes; the
        # scrolling text feed shows only settled calls, so it ignores it.
        if dt is None:
            return
        _exchange_view.tool_call_line(self._console, name, args, dt, refused)

    def _panel_width(self) -> int:
        return min(self._console.width, PANEL_WIDTH)

    def _findings_panel(self) -> Panel:
        return _findings_view.findings_panel(
            self.last_findings, width=self._panel_width()
        )

    def _recorded_call_for(self, detail: FindingDetail) -> ExecutedCall | None:
        return _findings_view.recorded_call_for(
            detail, oversight_path=self.oversight_path
        )

    def _finding_detail_renderable(self, detail: FindingDetail) -> Panel:
        return _findings_view.finding_detail_panel(
            detail,
            self._recorded_call_for(detail),
            width=self._panel_width(),
        )

    def show_findings(
        self, identifier: str | None = None, *, console: Console | None = None
    ) -> None:
        """List the findings, or describe the single one that was named.

        ``console`` renders this view somewhere other than the session's own
        console. The interactive console reads it while an investigation is
        running, and the run is printing into the session console from its own
        thread at that moment; being handed a console is what makes that read
        safe.
        """

        out = console or self._console
        if self.last_run is None:
            out.print(
                f"[{DIM}]No completed investigation yet. Ask a question first.[/]"
            )
            return
        if identifier is None:
            out.print(self._findings_panel())
            return
        position = resolve_finding_id(identifier, count=len(self.last_findings))
        if position is None:
            # A number this run has no finding for is a shape mistake, not a
            # failure: nothing was opened and nothing refused, so it gets the
            # quiet guidance every other mistyped command gets.
            out.print(
                build_usage_renderable(
                    "findings",
                    detail=(
                        "The id is the number in the first column of /findings."
                        if self.last_findings
                        else "This investigation recorded no findings."
                    ),
                )
            )
            return
        out.print(
            self._finding_detail_renderable(
                summarize_finding_detail(
                    self.last_findings[position - 1], sequence=position
                )
            )
        )

    def _evidence_summary_panel(self) -> Panel:
        return _findings_view.evidence_summary_panel(
            self.last_findings, width=self._panel_width()
        )

    def _control_panel(self, run: Any, *, elapsed_s: float) -> Panel:
        return _findings_view.run_summary_panel(
            run,
            elapsed_s=elapsed_s,
            tool_calls=len(self.last_evidence),
            findings=len(self.last_findings),
            width=self._panel_width(),
        )

    def _answer_source(self, run: Any) -> str:
        """What the run's own contract says the answer on screen amounts to.

        The same pure projection the run summary reads, over the same recorded
        telemetry, so the frame the answer panel wears and the "answer source"
        row below it are one verdict shown twice rather than two readings that
        can drift apart.
        """

        return summarize_controls(
            run.telemetry,
            run_id=run.run_id,
            tool_calls=len(self.last_evidence),
            findings=len(self.last_findings),
        ).answer_source

    def _controlled_runner(self) -> Any:
        if self._runner is None:
            self._runner = _model_request.build_controlled_runner(
                model=self.model,
                base_url=self.base_url,
                api_key=self.api_key,
                output_root=self.run_root,
                max_steps=self.max_steps,
                max_tool_calls=self.max_tool_calls,
                max_wall_time_s=self.max_wall_time_s,
            )
        return self._runner

    def _question_with_context(self, question: str) -> str:
        conversation = self._history.active
        if conversation is None:
            return question
        return _model_request.question_with_history_context(
            question,
            conversation.history_prompt_context(),
        )

    def _report_incomplete_examination(self, error: IncompleteExaminationError) -> None:
        """Show what an unanswered run established, and why it published nothing.

        The findings are bound to this run so ``/findings`` still resolves them
        afterwards; the answer is not, because there is none.  ``last_report``
        stays empty for the same reason: every path that exports, records or
        re-reads an answer must find that this question has none.

        The closing line is an OUTCOME line, and that is the whole point of the
        separation. Everything above it was already right: an interim-finding
        panel under a heading saying the examination did not complete, then the
        record of what was read. The exception was then handed to the generic
        fault renderer, whose fallback prints ``agent error:`` and the raw
        message, so a run that behaved correctly and merely spent its budget was
        filed beside a keyword this code got wrong. A model comparison in which
        "the weaker model ran out of time" is a result and "our code crashed" is
        not cannot be written from a record that spells the two the same way.
        """

        record = error.record
        self.last_run = record
        self.audit_path = str(record.audit_path)
        self.oversight_path = str(record.oversight_path)
        self.last_q, self.last_report = "", ""
        self.last_evidence = record.tool_calls()
        self.last_findings = record.standardized_findings()
        self._console.print()
        _exchange_view.print_interim_finding(
            self._console,
            summarize_incomplete_examination(record.telemetry),
            number=self._exchange_number,
            width=self._panel_width(),
        )
        self._console.print()
        self._console.print(self._evidence_summary_panel())
        self._console.print()
        for line in _exchange_view.unpublished_outcome_lines(
            run_id=str(record.run_id),
            diagnostics_path=str(Path(record.audit_path).parent / "failure.json"),
        ):
            self._console.print(line)

    def ask(self, question: str) -> bool:
        self.last_ask_outcome = self.ASK_NOT_ATTEMPTED
        if not self.has_evidence():
            self._console.print(
                f"[{ORANGE}]{_t('No evidence is loaded. Use')}[/] "
                f"[{ACCENT}]/case <path>[/]."
            )
            return False
        # The scope decision is the model's, never a word list's: one small
        # triage request to the configured model asks whether the input is
        # about the loaded case, before a run directory, a trace id or a
        # budget exists. Fail-open — a triage that cannot be made never
        # blocks a question — and a refused input leaves no mark in any
        # evidence trail, exactly like empty input. Input the triage lets
        # through is still answered under the prompt's SCOPE OF SERVICE
        # rule and the publication gates.
        if not _scope_check.question_in_scope(
            question,
            model=self.model,
            base_url=self.base_url,
            api_key=self.api_key,
        ):
            self._console.print(
                f"[{DIM}]{_t(_scope_check.SCOPE_REFUSAL_NOTICE)}[/]"
            )
            return False
        # Printed before the work starts, so everything the question produces —
        # the triage note, the activity feed, the panels — falls under its own
        # heading. A refused question never reaches here and so never consumes a
        # number, which keeps the numbering equal to the blocks on screen.
        # No blank line above it: the heading sits directly under the line the
        # operator typed, so it reads as the console taking up that question
        # rather than as an unrelated block starting.
        self._exchange_number += 1
        self._console.print(
            exchange_heading(
                self._exchange_number,
                width=self._panel_width(),
            )
        )
        img_path = getattr(self.disk, "image_path", None)
        if img_path:
            try:
                from forensic_agent.core import evidence_probe

                # Shown once, when the summary is first computed for a newly
                # loaded disk — a standing fact about the source, not something
                # that changes between questions. Reprinting it under every
                # exchange heading was noise the operator reads past. Reloading
                # the case resets the cache, so a new source announces itself.
                if self._triage_summary is None:
                    self._triage_summary = evidence_probe.summarize(
                        evidence_probe.detect_evidence(img_path)
                    )
                    self._console.print(
                        f"[{DIM}]{GLYPH_POINT} {escape(self._triage_summary)}[/]"
                    )
            except Exception:
                pass

        t0 = time.time()
        # Imported here for the same reason the endpoint check is: naming it at
        # module scope would load the agent runtime before the first prompt is
        # drawn.  By the time this line runs the runner has loaded that module
        # anyway, so the import costs nothing and the handler below can name the
        # one failure that still carries a record worth showing.
        from forensic_agent.cli.controlled import IncompleteExaminationError

        try:
            from forensic_agent.agent.tool_registry import (
                TOOL_EXPOSURE_HIDE_UNAVAILABLE,
            )

            runner = self._controlled_runner()
            self.last_provider = (
                getattr(runner, "provider", None) or self.last_provider
            )
            case_evidence_source, pcap_sources = self._case_evidence_binding()
            prewarmed = self._prewarmed_memory_digest()
            # Passed only to a runtime that declares the keyword: the receiving
            # side gained it with the reuse it enables, and an older one must
            # keep taking the call it always took.
            memory_key = (
                {"memory_sha256": prewarmed}
                if prewarmed and _accepts_keyword(runner.ask, "memory_sha256")
                else {}
            )
            with self._console.status(
                f"[{DIM}]investigating…[/]",
                spinner="dots",
                spinner_style=ACCENT,
            ):
                run = runner.ask(
                    self._question_with_context(question),
                    case_context=self._history.case_context or None,
                    disk=self.disk,
                    memory_path=self.memory,
                    pcap_path=self.pcap,
                    pcap_sources=pcap_sources,
                    case_id=self.case_id,
                    case_evidence_source=case_evidence_source,
                    case_roots=self.case_roots,
                    on_tool=self._tool_line,
                    # The interactive terminal is not a locked evaluation: no
                    # digest is pinned across hosts here, so the model is better
                    # served by a palette it can actually execute. The functions
                    # withheld from it stay visible to the investigator in
                    # /tools.
                    tool_exposure=TOOL_EXPOSURE_HIDE_UNAVAILABLE,
                    **memory_key,
                )
        except IncompleteExaminationError as incomplete:
            # The run read the evidence and ended with nothing to publish. What
            # it read is receipt-bound and recorded, and the operator gets it —
            # under a heading that says the examination did not complete, and
            # never as an answer. The question still counts as unanswered.
            self._report_incomplete_examination(incomplete)
            self.last_ask_outcome = self.ASK_UNPUBLISHED
            return False
        except Exception as e:
            self._console.print(
                _exchange_view.request_failure_explanation(
                    e,
                    model=self.model,
                    api_key=self.api_key,
                )
            )
            self.last_ask_outcome = self.ASK_FAILED
            return False
        dt = time.time() - t0
        self.last_run = run
        self.audit_path = str(run.audit_path)
        self.oversight_path = str(run.oversight_path)
        self.last_q, self.last_report = question, run.report
        self.last_evidence = run.tool_calls()
        self.last_findings = run.standardized_findings()
        self._history.record_answer(
            question,
            run.report,
            audit_ref=str(run.audit_path),
            verification_ref=str(run.oversight_path),
            turn_id=run.run_id,
        )
        self._console.print()
        _exchange_view.print_final_answer(
            self._console,
            run.report,
            number=self._exchange_number,
            width=self._panel_width(),
            answer_source=self._answer_source(run),
        )
        self._console.print()
        self._console.print(self._evidence_summary_panel())
        # One blank line between every block of the answer, so no two borders
        # ever meet and read as a single taller panel.
        self._console.print()
        self._console.print(self._control_panel(run, elapsed_s=dt))
        self._console.print()
        self._console.print(
            f"[{DIM}]{GLYPH_POINT} {_t('Details:')} "
            f"/findings · /oversight · /trace · /export[/]"
        )
        self._console.print()
        self.last_ask_outcome = self.ASK_ANSWERED
        return True

    def _case_export_name(self) -> str:
        """An export name no two exports share: the case id plus a wall-clock stamp.

        The fixed default name meant every bare /export destroyed the previous
        one; a name carrying the sanitized case id and the second it was asked
        for cannot, and the remaining same-second collision is settled by the
        existing-file guard at the write site.
        """

        sanitized = re.sub(r"[^A-Za-z0-9._-]+", "-", self.case_id or "case")
        sanitized = sanitized.strip("-.") or "case"
        return f"forensic_case_{sanitized}_{time.strftime('%Y%m%d-%H%M%S')}.md"

    def _case_export_sources(self) -> list[str]:
        """One summary line per attached evidence source, for the report header."""

        lines: list[str] = []
        if self.disk is not None:
            lines.append(f"disk image: {self.disk_label}")
        if self.memory:
            lines.append(f"memory dump: {os.path.basename(self.memory)}")
        if self.pcap:
            lines.append(f"network capture: {os.path.basename(self.pcap)}")
        return lines

    def _case_turn_record(self, ordinal: int, turn: Any) -> dict[str, object]:
        """Read one recorded question's material from its own run directory.

        The run directory is resolved from the persistent run root and the
        turn id, never from the recorded ``audit_ref``: old conversations
        carry container paths there, which resolve nowhere outside the
        container. The duration is the run's own wall clock,
        ``case_close.ts - case_open.ts``, and "published" is what the run's
        closing entry states.
        """

        from forensic_agent.cli.controlled import (
            standardized_findings_from,
            tool_calls_from,
        )
        from forensic_agent.oversight import OversightLog, reconstruct

        run_dir = self.run_root / turn.turn_id
        entries = OversightLog.load(str(run_dir / "oversight.jsonl"))
        reconstruction: dict[str, object] = reconstruct(entries) if entries else {}
        opened = next(
            (
                entry.get("ts")
                for entry in entries
                if entry.get("event") == "case_open"
            ),
            None,
        )
        closed = next(
            (
                entry.get("ts")
                for entry in reversed(entries)
                if entry.get("event") == "case_close"
            ),
            None,
        )
        duration = (
            float(closed) - float(opened)
            if isinstance(opened, (int, float)) and isinstance(closed, (int, float))
            else None
        )
        return {
            "ordinal": ordinal,
            "question": turn.question,
            "answer": turn.verified_answer,
            "published": reconstruction.get("status") == "ok",
            "calls": tool_calls_from(run_dir / "oversight.jsonl"),
            "findings": standardized_findings_from(run_dir / "tool-results.jsonl"),
            "oversight": reconstruction,
            "duration_s": duration,
        }

    def export_report(
        self,
        path: str | Path | None = None,
        *,
        announce: bool = True,
        scope: Literal["auto", "case", "question"] = "auto",
    ) -> None:
        """Write the forensic report: the whole case, one question, or a file.

        A bare /export covers every question this case's history retains, in
        order — question, answer, calls, findings and oversight decisions per
        run — under a name that carries the case id and a timestamp, so no
        export overwrites another. A bare number selects one question by its
        position in the history. An explicit path writes the most recent
        question's report to that file.

        ``scope`` separates *what the report covers* from *where it is
        written*, which the interactive grammar alone cannot express. Typing a
        path at /export means "this one answer, here", so ``"auto"`` keeps that
        reading and no operator sees a change. But /complete also passes a
        path, and it means the opposite: the closing document of a case is the
        case, and under ``"auto"`` it silently got the last exchange under a
        filename claiming to be the case report. ``"case"`` asks for the
        whole-case document at whatever destination is named, ``"question"``
        for the single-question one, and neither is reachable by writing the
        argument differently — which is why this is a keyword and not another
        spelling of ``path``.

        A ``"case"`` scope over a history that retains no turn still writes the
        single-question report: it is the only material there is, and a
        whole-case document listing zero questions would be a worse answer than
        the narrower one.

        ``announce`` exists for callers that already summarise where everything
        went: /complete writes the same report and then names all its artifacts
        in one place, and two overlapping reports of the same file read as two
        different files to anyone skimming the transcript.
        """

        argument = path.strip() if isinstance(path, str) else path
        ordinal: int | None = None
        if isinstance(argument, str) and argument.removeprefix("#").isdecimal():
            ordinal = int(argument.removeprefix("#"))
            argument = None
        active = self._history.active
        turns = tuple(active.history()) if active is not None else ()
        if not turns and not self.last_report:
            self._console.print(f"[{DIM}]nothing to export yet. Ask a question first[/]")
            return

        single_question = ordinal is None and (
            scope == "question"
            or (scope == "auto" and argument is not None)
            or not turns
        )
        if single_question:
            # A caller that asked for one question, an explicit destination
            # under the interactive reading, or a case whose history retains no
            # turn but whose last answer is still on screen: the
            # single-question report, exactly as before — under the
            # overwrite-proof default name when no destination was named.
            if not self.last_report:
                self._console.print(
                    f"[{DIM}]nothing to export yet. Ask a question first[/]"
                )
                return
            destination = self._export_destination(
                argument, default_name=self._case_export_name()
            )
            if argument is None:
                destination = _session_exports.unique_destination(destination)
            _session_exports.write_forensic_report(
                self._console,
                destination,
                question=self.last_q,
                report=self.last_report,
                tool_calls=self.last_evidence,
                model=self.model,
                engine=self.engine,
                operation_mode=self.operation_mode,
                disk_label=self.disk_label,
                oversight_path=self.oversight_path,
                findings=self.last_findings,
                announce=announce,
            )
            return

        if ordinal is not None:
            if not 1 <= ordinal <= len(turns):
                self._console.print(
                    build_usage_renderable(
                        "export",
                        detail=(
                            "The number is the question's position in this "
                            "case's history."
                            if turns
                            else "This case's history retains no questions."
                        ),
                    )
                )
                return
            selected = [(ordinal, turns[ordinal - 1])]
        else:
            selected = list(enumerate(turns, start=1))

        from forensic_agent.core.environ import backend_kind
        from forensic_agent.reporting import markdown as _report

        records = [self._case_turn_record(number, turn) for number, turn in selected]
        identity = active.inference_identity if active is not None else None
        provider = getattr(identity, "provider", None) or backend_kind(self.base_url)
        markdown = _report.build_case_markdown(
            records,
            case_id=self.case_id,
            model=self.model,
            provider=provider,
            reasoning_effort=_reasoning.current_effort(),
            engine=self.engine,
            operation_mode=self.operation_mode,
            sources=self._case_export_sources(),
        )
        companion = "\n".join(
            _report.build_oversight_markdown(record["oversight"], model=self.model)
            for record in records
            if record["oversight"]
        )
        destination = self._export_destination(
            argument, default_name=self._case_export_name()
        )
        if argument is None:
            # A named destination is honoured as named: /complete resolves one
            # stem for every artifact it files and picks a free one there, and
            # a second uniquing here would move the report off that stem and
            # leave the diagram and the declaration behind on it.
            destination = _session_exports.unique_destination(destination)
        _session_exports.write_case_report(
            self._console,
            destination,
            markdown=markdown,
            oversight_markdown=companion,
            questions=len(records),
            announce=announce,
        )

    def export_trace(self, path: str | Path | None = None) -> None:
        if self.last_run is None or not self.last_q:
            self._console.print(
                f"[{DIM}]No completed investigation to visualize. "
                "Ask a question first.[/]"
            )
            return
        destination = self._export_destination(
            path,
            default_name=f"forensic_agent_trace_{self.last_run.run_id[:12]}.svg",
        )
        _session_exports.write_execution_trace(
            self._console,
            destination,
            run=self.last_run,
            question=self.last_q,
            model=self.model,
            provider=self.last_provider,
        )

    def complete_case(self, path: str | Path | None = None) -> bool:
        """Declare the active case finished and write its closing artifacts.

        The document is the forensic report the project already knows how to
        build, covering every exchange in the case, with the oversight
        reconstruction beside it and a self-contained HTML rendering of it for
        a reader with no markdown viewer. The diagram draws what actually ran.
        The last file records the declaration itself — because "complete" is
        something the operator says, and a case that closes without saying who
        closed it leaves the reader to assume the system decided.

        Everything one completion writes is written here, on one stem, once.
        The closing sequence used to write the whole-case report a second time
        from the caller, under a different auto-generated stem, while the
        report on the completion stem covered only the last exchange — so the
        operator was handed two documents with the same title, and the one
        named for the closed case was the narrower of the two. Splitting the
        work across two callers is what made that possible, so this method now
        does all of it and callers sequence nothing after it.
        """

        if self.last_run is None or not self.last_report or not self.last_q:
            self._console.print(
                f"[{DIM}]"
                f"{_t('Nothing to complete yet. No investigation has been run in this case.')}"
                f"[/]"
            )
            # False, not an exception: nothing was attempted, but a caller
            # sequencing follow-up steps (exports, detach) must know to stop.
            return False

        from forensic_agent.reporting.html_report import write_html_report
        from forensic_agent.reporting.trace_svg import (
            controlled_run_trace_record,
            export_investigation_diagram,
        )

        report_path = _case_completion.completion_destination(
            path, self.last_run.run_id, run_root=self.run_root
        )
        diagram_path = report_path.with_suffix(".svg")
        declaration_path = report_path.with_suffix(".json")
        html_path = report_path.with_suffix(".html")

        self.export_report(report_path, announce=False, scope="case")
        # Rendered from the file that was just written rather than from the
        # markdown in memory, so the page cannot state anything the record on
        # disk does not. A report that failed to write leaves no page behind
        # to be mistaken for one.
        if report_path.is_file():
            write_html_report(
                html_path,
                report_path.read_text(encoding="utf-8"),
                title=report_path.name,
            )
        record = controlled_run_trace_record(
            self.last_run,
            question=self.last_q,
            model=self.model,
            provider=self.last_provider,
        )
        export_investigation_diagram(record, diagram_path)
        declaration = _case_completion.completion_declaration(
            record,
            report=report_path,
            diagram=diagram_path,
            case_label=self.case_label,
            model=self.model,
            provider=self.last_provider,
            engine=self.engine,
            operation_mode=self.operation_mode,
        )
        _case_completion.write_completion_declaration(declaration_path, declaration)
        self.completion_declaration_path = declaration_path
        self._console.print()
        self._console.print(
            _case_completion.completion_panel(
                report_path,
                diagram_path,
                declaration_path,
                html=html_path,
                width=self._panel_width(),
            )
        )
        return True

    def show_oversight(self) -> None:
        _oversight_view.show_oversight(
            self._console, oversight_path=self.oversight_path
        )

    def show_oversight_call(
        self, identifier: str, *, console: Console | None = None
    ) -> None:
        """One recorded call in full; ``console`` as in :meth:`show_findings`."""

        _oversight_view.show_oversight_call(
            console or self._console,
            identifier=identifier,
            oversight_path=self.oversight_path,
            width=self._panel_width(),
        )

    def show_oversight_prompt(self, *, console: Console | None = None) -> None:
        """The message the run sent the model; ``console`` as in
        :meth:`show_findings`."""

        _oversight_view.show_oversight_prompt(
            console or self._console,
            oversight_path=self.oversight_path,
            width=self._panel_width(),
        )

    def show_executed_commands(self, *, console: Console | None = None) -> None:
        """Every executed call with its arguments; ``console`` as in
        :meth:`show_findings`."""

        _oversight_view.show_executed_commands(
            console or self._console, oversight_path=self.oversight_path
        )
