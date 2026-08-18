"""What the session currently is, said to the operator in three places.

Three views answer the same question at three levels of detail: the status line
under a command, the panel that stands above the prompt, and the evidence table
``/sources`` prints. They have to agree — a source counted in one and not the
other is a bug the operator has no way to diagnose — so they are written next to
each other and share the one function that counts sources.

Everything here is a pure function of the facts it is handed. The session owns
those facts; this module only decides how they read.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Group
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from forensic_agent import __version__
from forensic_agent.cli.console_layout import kv_row, short
from forensic_agent.cli.i18n import t as _t
from forensic_agent.cli.terminal import (
    ACCENT,
    BORDER,
    DIM,
    GLYPH_ABSENT,
    GLYPH_OK,
    GLYPH_POINT,
    PANEL_BOX,
    SUCCESS,
    TABLE_BOX,
)

if TYPE_CHECKING:
    from forensic_agent.tools.pcap_sources import PcapSourceCatalog


def source_count(
    *,
    disk: object | None,
    memory: str | None,
    pcap: str | None,
    pcap_sources: PcapSourceCatalog | None,
) -> int:
    """How many evidence sources are attached, counting each capture separately."""

    return (
        int(disk is not None)
        + int(bool(memory))
        + (
            len(pcap_sources.bindings)
            if pcap_sources is not None
            else int(bool(pcap))
        )
    )


def status_line(
    *,
    case_label: str,
    sources: int,
    tools: int,
) -> str:
    return (
        f"[{DIM}]{_t('active case')}[/] "
        f"[{ACCENT}]{escape(case_label)}[/]  "
        f"[{DIM}]{_t('sources')}[/] [{SUCCESS}]{sources}[/]  "
        f"[{DIM}]{_t('tools')}[/] "
        f"[{SUCCESS}]{tools} {_t('available')}[/]"
    )


def session_panel(
    *,
    model: str,
    provider: str,
    reasoning_effort: str,
    max_steps: int,
    max_tool_calls: int,
    case_label: str,
    has_evidence: bool,
    disk: object | None,
    disk_label: str,
    memory: str | None,
    pcap: str | None,
    pcap_sources: PcapSourceCatalog | None,
    tools: int,
    case_context_set: bool,
) -> Panel:
    t = Table.grid(padding=(0, 2))
    t.add_column(justify="right", no_wrap=True)
    t.add_column(overflow="fold")
    t.add_column(justify="right", no_wrap=True)
    kv_row(t, _t("model"), model, ACCENT, "/model")
    kv_row(t, _t("provider"), provider, ACCENT)
    # Beside the model because it is a standing fact about every request
    # this session sends, and the one that most governs how long the
    # operator waits for an answer. The value is the token that travels to
    # the provider, so it stays English on either terminal language.
    kv_row(
        t,
        _t("reasoning"),
        reasoning_effort,
        ACCENT,
        "/reasoning",
    )
    kv_row(
        t,
        _t("active case"),
        case_label if has_evidence else _t("not loaded"),
        ACCENT if has_evidence else DIM,
        "/case",
    )
    if disk is not None:
        kv_row(t, _t("disk image"), disk_label, SUCCESS)
    if memory:
        kv_row(t, _t("memory dump"), Path(memory).name, SUCCESS)
    if pcap_sources is not None:
        capture_count = len(pcap_sources.bindings)
        capture_value = (
            pcap_sources.default.basename
            if capture_count == 1
            else (
                f"{capture_count} attached (default "
                f"{pcap_sources.default.basename})"
            )
        )
        kv_row(t, _t("network captures"), capture_value, SUCCESS)
    elif pcap:
        kv_row(t, _t("network capture"), Path(pcap).name, SUCCESS)
    attached = source_count(
        disk=disk,
        memory=memory,
        pcap=pcap,
        pcap_sources=pcap_sources,
    )
    present = GLYPH_OK if attached else GLYPH_ABSENT
    # With nothing loaded the count read "0 attached", which puts a number where
    # the operator is looking for a state and reads as a malfunction rather than
    # an empty session.
    attached_text = (
        f"{attached} {_t('attached')}" if attached else _t("none attached")
    )
    kv_row(
        t,
        _t("sources"),
        f"{present} {attached_text}",
        SUCCESS if attached else DIM,
        "/sources",
    )
    kv_row(
        t,
        _t("tools"),
        f"{tools} {_t('available')}",
        ACCENT,
        "/tools",
    )
    context_mark = GLYPH_OK if case_context_set else GLYPH_ABSENT
    kv_row(
        t,
        _t("case context"),
        f"{context_mark} {_t('set')}"
        if case_context_set
        else f"{context_mark} {_t('not set')}",
        SUCCESS if case_context_set else DIM,
        "/context",
    )
    facts: Table | Group = t
    if not has_evidence:
        # The one move that matters when nothing is loaded, said once and
        # in the accent, because from here everything else is unreachable.
        facts = Group(
            t,
            "",
            f"[{DIM}]{_t('Open evidence')}[/]  [{ACCENT}]/case <folder-or-file>[/]",
        )
    body = facts
    # An ambient panel: quiet border, no fill, so the session facts frame the
    # prompt without drawing the eye away from the work in the transcript.
    # The build and the way in are carried here rather than under the wordmark:
    # they are standing facts about this session, and the wordmark reads better
    # as a wordmark than as a place to file provenance.
    return Panel(
        body,
        title=f"[bold]{GLYPH_POINT} {_t('Session')}[/]",
        title_align="left",
        subtitle=f"[{DIM}]v{__version__}, /help[/]",
        subtitle_align="right",
        border_style=BORDER,
        box=PANEL_BOX,
        padding=(0, 2),
        width=72,
    )


def evidence_sources_table(
    *,
    case_label: str,
    has_evidence: bool,
    disk: object | None,
    disk_label: str,
    memory: str | None,
    pcap: str | None,
    pcap_sources: PcapSourceCatalog | None,
    digests: Mapping[str, str] | None = None,
) -> Table:
    # The evidence header answers one question first — what is the mediator
    # allowed to touch — so every row states its type, its source, and the
    # single access guarantee that never varies: the tools only ever read.
    read_only = Text(_t("read only"), style=DIM)
    recorded = dict(digests or {})

    def digest_line(path: object) -> str:
        """One source's digest, or a statement that it could not be computed.

        Every source is hashed when the case binds it, so a blank line here
        would read as "no digest was needed" rather than "this one has none".
        """

        digest = recorded.get(str(path))
        if not digest:
            return f"\n[{DIM}]sha256: {_t('none recorded')}[/]"
        return f"\n[{DIM}]sha256:{short(digest, 16)}[/]"
    table = Table(
        title=Text(
            f"{GLYPH_POINT} {_t('Evidence sources')}: {case_label}",
            style=f"bold {ACCENT}",
        ),
        title_justify="left",
        box=TABLE_BOX,
        header_style=f"bold {ACCENT}",
        show_lines=False,
        pad_edge=False,
    )
    table.add_column(_t("Type"), min_width=16, style=SUCCESS, no_wrap=True)
    table.add_column(_t("Source"), overflow="fold")
    # Sized by a minimum rather than a fixed width so the right-aligned
    # access column keeps its English proportions while still fitting a
    # longer translated guarantee instead of wrapping it onto a second line.
    table.add_column(_t("Access"), min_width=12, justify="right")

    if disk is not None:
        path = getattr(disk, "image_path", disk_label)
        digest = getattr(disk, "image_sha", None)
        suffix = f"\n[{DIM}]sha256:{short(str(digest), 16)}[/]" if digest else ""
        # A split acquisition is more physical files than the one path the case
        # points at, and the attestation already knows them: pyewf's own segment
        # discovery recorded every .E01/.E02 path when the source was attested.
        # A custody listing that names one file of two is wrong in a way the
        # operator cannot see, so every segment is listed whenever there is more
        # than one. One segment stays a single line — the path already names the
        # only physical file — and a disk opened from verified physical
        # components carries no attestation here, so it renders as before.
        # Operator-facing only: the model-facing portable_record deliberately
        # carries a segment count and no paths, and this reads nothing into it.
        segments = (
            getattr(
                getattr(disk, "evidence_source_attestation", None), "segments", ()
            )
            or ()
        )
        segment_lines = ""
        if len(segments) > 1:
            segment_lines = f"\n[{DIM}]{len(segments)} {_t('segments')}[/]" + "".join(
                f"\n[{DIM}]{escape(str(getattr(segment, 'path', segment)))}[/]"
                for segment in segments
            )
        table.add_row(
            _t("disk image"),
            Text.from_markup(f"{escape(str(path))}{suffix}{segment_lines}"),
            read_only,
        )
    if memory:
        table.add_row(
            _t("memory dump"),
            Text.from_markup(f"{escape(str(memory))}{digest_line(memory)}"),
            read_only,
        )
    if pcap_sources is not None:
        merged_inputs = set(pcap_sources.default_input_component_ids)
        for binding in pcap_sources.bindings:
            annotations = [binding.role]
            if binding.component_id == pcap_sources.default_component_id:
                annotations.append("default")
            if binding.component_id in merged_inputs:
                annotations.append("merged input")
            table.add_row(
                _t("network capture"),
                Text.from_markup(
                    f"{escape(str(binding.path))}{digest_line(binding.path)}\n"
                    f"[{DIM}]{escape(str(binding.component_id))}: "
                    + escape(", ".join(annotations))
                    + "[/]"
                ),
                read_only,
            )
    elif pcap:
        table.add_row(
            _t("network capture"),
            Text.from_markup(f"{escape(pcap)}{digest_line(pcap)}"),
            read_only,
        )
    if not has_evidence:
        table.add_row(
            Text("—", style=DIM),
            _t("No evidence source is loaded."),
            Text("—", style=DIM),
        )
    return table
