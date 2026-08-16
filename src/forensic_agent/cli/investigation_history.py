"""The saved investigation a console is writing to, and the store it lives in.

The active conversation and the store it is persisted to are never independently
valid. A conversation is only meaningful under the case identity it was opened
with, and every operation that replaces one — starting, resuming, continuing,
changing the model — has to reach the store under that same identity to find or
record it. Two owners for those two fields would be two places that can each
decide what "the current investigation" is, and the console would have no single
answer to give.

So both live here, behind operations that move them together. The case a
conversation is written against is *not* one of those fields: it belongs to the
evidence that is open, changes underneath this collaborator, and therefore
arrives as a value from the supplier this object is constructed with. That is
what keeps the lifecycle checkable on its own — every transition can be driven
with a store in a temporary directory and a supplier returning a fixed identity,
with no session anywhere — and what keeps this module unable to see the disk, or
to decide whether a case is open at all. Callers that need those decisions make
them before they call.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.markup import escape

import forensic_agent.cli.investigation_history_view as _history_view
from forensic_agent.agent.case_context import MAX_CASE_CONTEXT_BYTES
from forensic_agent.cli.console_layout import PANEL_WIDTH
from forensic_agent.cli.console_layout import short as _short
from forensic_agent.cli.conversation import (
    ConversationEvidenceBinding,
    ConversationNotFoundError,
    ConversationSession,
    ConversationStore,
)
from forensic_agent.cli.terminal import ACCENT, DIM, ORANGE, RED, SUCCESS
from forensic_agent.core.environ import backend_kind


@dataclass(frozen=True, slots=True)
class ActiveCase:
    """What a saved investigation is an investigation of, and under what model.

    Every one of these values reaches the store, which refuses to resume a
    conversation whose case, evidence or inference identity differs from the one
    recorded. They are therefore read together, from the console's state at the
    moment of the transition, rather than remembered from an earlier one.
    """

    case_id: str
    source_identity: str
    provider_endpoint: str
    model: str


def session_id_prefix(title: str | None) -> str:
    """A readable, identifier-safe stem so a saved file names its own subject.

    The result is concatenated with a UUID to form a session id, and the store
    rejects an id outside a narrow character set, so anything the title
    contributes has to survive that set unchanged: non-ASCII, punctuation and
    whitespace all collapse to a hyphen rather than being carried through.
    """

    if not title:
        return ""
    safe = "".join(
        (
            character
            if character.isascii() and (character.isalnum() or character in "._-")
            else "-"
        )
        for character in title.strip()
    ).strip("-")
    return f"{safe[:40]}-" if safe else ""


def matched_session_id(
    rows: Sequence[Mapping[str, object]],
    identifier: str,
) -> str:
    """Resolve one saved investigation from a full id or an unambiguous prefix.

    A prefix that matches several investigations is refused rather than resolved
    to the first: the operator named something they believed was unique, and
    quietly picking one of the candidates would resume a different investigation
    than the one they meant.
    """

    requested = identifier.strip()
    matches = [
        str(row["session_id"])
        for row in rows
        if str(row["session_id"]).startswith(requested)
    ]
    if requested in matches:
        return requested
    if len(matches) != 1:
        raise ValueError(
            "The investigation identifier was not found or is not unique."
        )
    return matches[0]


def first_continuable(
    rows: Sequence[Mapping[str, object]],
    *,
    active_session_id: str,
    require_evidence_binding: bool,
) -> Mapping[str, object] | None:
    """The most recent saved investigation this console could take up.

    Rows arrive newest first. The one already open is never a candidate — it is
    not continued, it is simply still there — and when no evidence is open the
    candidate must carry an evidence binding, because taking it up means
    reopening the sources it was produced over.
    """

    for row in rows:
        if str(row["session_id"]) == active_session_id:
            continue
        if require_evidence_binding and not isinstance(
            row.get("evidence_binding"), Mapping
        ):
            continue
        return row
    return None


def recorded_binding(row: Mapping[str, object]) -> ConversationEvidenceBinding:
    """Rebuild the evidence binding a saved investigation recorded for itself."""

    raw_binding = row["evidence_binding"]
    assert isinstance(raw_binding, Mapping)
    return ConversationEvidenceBinding.create(
        case_label=raw_binding["case_label"],
        sources=raw_binding["sources"],
        network_default=raw_binding["network_default"],
        network_inputs=raw_binding["network_inputs"],
    )


def read_case_context_file(candidate: Path) -> str:
    """Read a file the operator offered as case context, or refuse to.

    Case context is carried into every subsequent prompt, so what may become one
    is bounded before it is read: a symlink or a device is not a document the
    operator can vouch for, the size limit is the store's own, and text that is
    not UTF-8 would reach the model as replacement characters standing where the
    operator believes their brief is.
    """

    if candidate.is_symlink() or not candidate.is_file():
        raise ValueError("The case-context path must be a regular file.")
    if candidate.stat().st_size > MAX_CASE_CONTEXT_BYTES:
        raise ValueError(
            f"The case-context file exceeds {MAX_CASE_CONTEXT_BYTES} UTF-8 bytes."
        )
    try:
        return candidate.read_text(encoding="utf-8")
    except UnicodeError as exc:
        raise ValueError("The case-context file must contain valid UTF-8 text.") from exc


class InvestigationHistory:
    """The one conversation a console is writing to, and the store behind it."""

    def __init__(
        self,
        store: ConversationStore,
        *,
        console: Console,
        case: Callable[[], ActiveCase],
        evidence_binding: Callable[[], ConversationEvidenceBinding | None],
    ) -> None:
        self._store = store
        self._console = console
        self._case = case
        self._evidence_binding = evidence_binding
        self._active: ConversationSession | None = None

    @property
    def store(self) -> ConversationStore:
        """Where investigations are persisted, for callers that must find the files."""

        return self._store

    @property
    def active(self) -> ConversationSession | None:
        """The conversation being written to, or ``None`` before one is started."""

        return self._active

    @property
    def active_session_id(self) -> str:
        """The active investigation's identifier, empty when none is active."""

        return self._active.session_id if self._active is not None else ""

    @property
    def case_context(self) -> str:
        """The operator's brief for the active investigation, empty when unset."""

        return self._active.case_context if self._active is not None else ""

    def build(
        self,
        title: str | None = None,
        *,
        model: str | None = None,
        base_url: str | None = None,
        case_context: str | None = None,
    ) -> ConversationSession:
        """Create a persisted, empty investigation without making it the active one.

        Configuration changes prepare an investigation before they commit the
        change, so that a store that refuses to write one leaves the console on
        the provider it already had.
        """

        case = self._case()
        provider_endpoint = base_url or case.provider_endpoint
        conversation = self._store.new_session(
            case_id=case.case_id,
            source_identity=case.source_identity,
            provider=backend_kind(provider_endpoint),
            provider_endpoint=provider_endpoint,
            model=model or case.model,
            session_id=f"{session_id_prefix(title)}{uuid.uuid4().hex}",
        )
        inherited_context = self.case_context if case_context is None else case_context
        if inherited_context:
            conversation.set_case_context(inherited_context)
        # Recorded when the investigation begins rather than when it ends: any
        # change to the evidence set starts a new conversation anyway, so the
        # binding written here always describes the sources this history was
        # produced over, and closing the terminal stays free of bookkeeping.
        #
        # A convenience record may never be the reason a case cannot be opened,
        # so a binding that will not validate or will not persist is left off
        # entirely. Continuing then says it has nothing to reopen, which is true.
        try:
            binding = self._evidence_binding()
            if binding is not None:
                conversation.bind_evidence(binding)
        except Exception:
            pass
        return conversation

    def start(
        self,
        title: str | None = None,
        *,
        model: str | None = None,
        base_url: str | None = None,
        case_context: str | None = None,
    ) -> None:
        """Begin a fresh investigation and write to it from here on."""

        self._active = self.build(
            title,
            model=model,
            base_url=base_url,
            case_context=case_context,
        )

    def ensure_started(self) -> ConversationSession:
        """Leave the console with somewhere to write, and never take one away.

        A refused continuation is not a reason to discard what the operator
        already has open, so an existing investigation is left exactly as it is.
        """

        active = self._active
        if active is None:
            active = self.build()
            self._active = active
        return active

    def activate(self, conversation: ConversationSession) -> None:
        """Write to an already prepared investigation from here on."""

        self._active = conversation

    def discard(self) -> None:
        """Stop writing to the active investigation without deleting it.

        The evidence set has changed under it, so nothing further belongs in it;
        what it already holds stays saved and can be continued later.
        """

        self._active = None

    def resume(
        self,
        identifier: str,
        *,
        quiet: bool = False,
        strict: bool = False,
    ) -> None:
        """Take up a saved investigation named by id or unambiguous prefix.

        Failure is reported here only when this call is the whole command.
        ``strict`` belongs to the launch flag, which must fail rather than open
        the console on a different footing than it was asked for, and ``quiet``
        to a caller that has its own account to give and needs the exception in
        order to give it — so both raise, and only a bare ``/resume`` prints.
        """

        try:
            case = self._case()
            requested = matched_session_id(
                self._store.list_sessions(
                    case_id=case.case_id,
                    source_identity=case.source_identity,
                ),
                identifier,
            )
            self._active = self._store.resume(
                requested,
                case_id=case.case_id,
                source_identity=case.source_identity,
                provider=backend_kind(case.provider_endpoint),
                provider_endpoint=case.provider_endpoint,
                model=case.model,
            )
        except Exception as exc:
            if strict or quiet:
                raise
            self._console.print(
                f"[{RED}]Investigation could not be resumed:[/] {str(exc)[:240]}"
            )
            return
        if not quiet:
            self._console.print(
                f"[{SUCCESS}]Investigation resumed:[/] "
                f"[{DIM}]{self._active.session_id}[/]"
            )

    def continuable(self, *, evidence_open: bool) -> Mapping[str, object] | None:
        """The saved investigation to take up, or ``None`` if there is none.

        With evidence already open the console stays on it and looks only among
        the investigations of that same case; with nothing open the whole store
        is in scope, because the candidate is what will decide which evidence is
        reopened.
        """

        case = self._case()
        rows = (
            self._store.list_sessions(
                case_id=case.case_id,
                source_identity=case.source_identity,
            )
            if evidence_open
            else self._store.list_sessions()
        )
        return first_continuable(
            rows,
            active_session_id=self.active_session_id,
            require_evidence_binding=not evidence_open,
        )

    def record_answer(
        self,
        question: str,
        report: str,
        *,
        audit_ref: str,
        verification_ref: str,
        turn_id: str,
    ) -> None:
        """Append one completed exchange, and never fail the answer over it.

        The answer is already on screen and its audit material is already
        written; a history that could not be appended to is worth saying so
        about, and worth nothing more than that.
        """

        conversation = self.ensure_started()
        try:
            conversation.append(
                question,
                report,
                audit_ref=audit_ref,
                verification_ref=verification_ref,
                turn_id=turn_id,
            )
        except Exception as exc:
            self._console.print(
                f"[{ORANGE}]The answer completed, but investigation history "
                "could not be saved:[/] "
                f"{escape(str(exc)[:220])}"
            )

    def show_saved_investigations(self) -> None:
        case = self._case()
        rows = self._store.list_sessions(
            case_id=case.case_id,
            source_identity=case.source_identity,
        )
        self._console.print(
            _history_view.saved_investigations_table(
                rows,
                active_session_id=(
                    self._active.session_id if self._active is not None else None
                ),
            )
        )

    def show_completed_questions(
        self, limit: int | None = None, *, console: Console | None = None
    ) -> None:
        """The completed questions, on this history's console or a given one.

        A caller that passes its own console leaves ``self._console`` alone,
        which is what lets the interactive console read this view while an
        investigation is printing into the session's console from another
        thread.
        """

        out = console or self._console
        if self._active is None:
            out.print(f"[{DIM}]No active investigation history.[/]")
            return
        rows = self._active.history(limit)
        if not rows:
            out.print(f"[{DIM}]No completed questions yet.[/]")
            return
        _history_view.show_history(out, rows, width=min(out.width, PANEL_WIDTH))

    def show_case_context(self) -> None:
        conversation = self.ensure_started()
        value = conversation.case_context
        if not value:
            self._console.print(
                f"[{DIM}]No case context is set. Use[/] "
                f"[{ACCENT}]/context set <text>[/]."
            )
            return
        digest = conversation.case_context_sha256 or ""
        self._console.print(
            _history_view.case_context_panel(
                value,
                digest,
                width=min(self._console.width, PANEL_WIDTH),
            )
        )

    def set_case_context(self, value: str) -> None:
        conversation = self.ensure_started()
        conversation.set_case_context(value)
        digest = conversation.case_context_sha256 or ""
        self._console.print(
            f"[{SUCCESS}]Case context updated.[/] "
            f"[{DIM}]sha256:{digest}[/]"
        )

    def clear_case_context(self) -> None:
        conversation = self.ensure_started()
        if conversation.clear_case_context():
            self._console.print(f"[{SUCCESS}]Case context cleared.[/]")
        else:
            self._console.print(f"[{DIM}]No case context was set.[/]")

    def question_to_retry(self) -> str | None:
        """The last question, with its answer taken out of future model context.

        Returns ``None`` when there is nothing to retry; the reason is already
        on screen by then.
        """

        if self._active is None:
            self._console.print(f"[{ORANGE}]No question is available to retry.[/]")
            return None
        try:
            rows = self._active.history(1)
            if not rows:
                raise ConversationNotFoundError(
                    "The session has no retained questions."
                )
            last = rows[-1]
            question = last.question
            # Regenerate from the preceding context rather than anchoring the
            # model on the very answer being retried — and exclude THE turn
            # being retried, by id. The bare form excluded whichever turn was
            # newest still-included, so a retry after /undo silently stripped
            # an EARLIER exchange from context instead.
            if last.included_in_context:
                self._active.undo_from_context(last.turn_id)
        except Exception as exc:
            self._console.print(f"[{ORANGE}]{escape(str(exc))}[/]")
            return None
        return question

    def undo_context(self) -> None:
        if self._active is None:
            self._console.print(f"[{ORANGE}]No answer is available to remove.[/]")
            return
        try:
            turn = self._active.undo_from_context()
        except Exception as exc:
            self._console.print(f"[{ORANGE}]{escape(str(exc))}[/]")
            return
        self._console.print(
            f"[{SUCCESS}]Removed from future model context:[/] "
            f"[{DIM}]{_short(turn.turn_id)}[/]"
        )

