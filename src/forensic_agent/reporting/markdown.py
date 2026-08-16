"""Markdown forensic reports with a chain-of-custody appendix.

Turns an investigation (question + agent report + audited tool accesses) into a
self-contained Markdown report: the finding, followed by an evidence table where
every audited tool access carries its SHA-256 output hash from `audit.jsonl`.
This makes each report a reproducible, court-traceable artifact.

Two duties shape everything below the section headings.

The first is ACPO v5 §6.5.4: a report must "always identify where an opinion is
being given, to distinguish this from fact". The run decides that per result and
records it as ``provenance.evidence_class``; section 5 separates observations
from interpretations on that recorded decision alone (see
:mod:`forensic_agent.reporting.findings`) and never on the wording of a
statement.

The second is SWGDE 18-Q-002 §5, whose list of report elements includes three
facts about the engagement rather than about the examination — the requester, the
disposition of the evidence, and an authorization naming its authorizer and
carrying a signature (§5.7). A run cannot observe any of them, so they arrive
only from an operator-supplied record (:mod:`forensic_agent.reporting.engagement`)
and are printed as not supplied when nobody supplied them. No field in this
module is ever filled with a value the caller did not provide: a generated report
carrying an unsigned authorization block or an invented requester would be worse
than the omission it replaced.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
from collections.abc import Mapping, Sequence

from forensic_agent.core.durations import format_duration
from forensic_agent.reporting.engagement import (
    NOT_SUPPLIED,
    EngagementRecord,
    engagement_record_from_environment,
    is_supplied,
    stated,
)
from forensic_agent.reporting.findings import (
    ClassifiedFindings,
    ReportedFinding,
    classify_findings,
    standing_of,
)

#: Printed where the run recorded no case identifier at all. It is a different
#: statement from "not supplied": nobody is being asked for this one, so the
#: report says the record does not carry it.
_CASE_ID_UNRECORDED = "Not recorded in the run record"

_UNSEPARATED_FINDINGS = (
    "The run's standardized findings were not supplied to this report, so no "
    "statement below is separated into observation and interpretation. Each "
    "finding's evidence class is recorded in the run's own result trace; this "
    "document does not restate it, and nothing here establishes which of its "
    "statements are readings of the evidence and which are inferences about it."
)

_NARRATIVE_STANDING = (
    "The text below was drafted by the model named in the header, over the "
    "findings above. It is an account composed from readings, not a reading: no "
    "statement acquires the standing of an observation by appearing in it. The "
    "report authorization below records whether a named examiner has authorized "
    "it."
)


def _heading(title: str, *, number: str | None) -> str:
    """A section heading, numbered where the document that holds it numbers them."""

    return f"## {number}. {title}\n" if number else f"## {title}\n"


def _subheading(title: str, *, number: str | None) -> str:
    return f"### {number} {title}\n" if number else f"### {title}\n"


def _cell(value: object, *, fallback: str = "—") -> str:
    """One table cell: whitespace collapsed, column separator neutralised."""

    text = " ".join(str("" if value is None else value).split()).replace("|", r"\|")
    return text or fallback


def _digest_cell(value: str | None) -> str:
    """A digest printed whole, because half a SHA-256 matches nothing."""

    return f"`{value}`" if value else "—"


def _resolved_engagement(engagement: EngagementRecord | None) -> EngagementRecord | None:
    """The record the caller passed, or the one the environment names."""

    return engagement if engagement is not None else engagement_record_from_environment()


def _recorded_case_identifiers(
    audit_entries: Sequence[Mapping[str, object]],
) -> tuple[str, ...]:
    """Every case identifier the recorded accesses carry, in the order recorded.

    All of them, never the first: a report that silently picked one of two
    recorded identifiers would be choosing which case it is about.
    """

    recorded: list[str] = []
    for entry in audit_entries:
        value = entry.get("case_id")
        if isinstance(value, str) and value.strip() and value.strip() not in recorded:
            recorded.append(value.strip())
    return tuple(recorded)


def _case_identifier_line(audit_entries: Sequence[Mapping[str, object]]) -> str:
    identifiers = _recorded_case_identifiers(audit_entries)
    return ", ".join(identifiers) if identifiers else _CASE_ID_UNRECORDED


def _observation_rows(observations: Sequence[ReportedFinding]) -> list[str]:
    lines = [
        "| # | Chain entry | Function | Result type | Produced by | Receipt SHA-256 |",
        "|---|---|---|---|---|---|",
    ]
    for finding in observations:
        lines.append(
            f"| {finding.sequence} | {_cell(finding.chain_entry)} | "
            f"{_cell(finding.tool)} | {_cell(finding.data_type)} | "
            f"{_cell(', '.join(finding.producers))} | "
            f"{_digest_cell(finding.receipt_sha256)} |"
        )
    return lines


def _interpretation_rows(interpretations: Sequence[ReportedFinding]) -> list[str]:
    lines = [
        "| # | Chain entry | Function | Result type | Method | Computed over | Receipt SHA-256 |",
        "|---|---|---|---|---|---|---|",
    ]
    for finding in interpretations:
        lines.append(
            f"| {finding.sequence} | {_cell(finding.chain_entry)} | "
            f"{_cell(finding.tool)} | {_cell(finding.data_type)} | "
            f"{_cell(finding.derivation_method)} | "
            f"{_cell('; '.join(finding.derivation_inputs))} | "
            f"{_digest_cell(finding.receipt_sha256)} |"
        )
    return lines


def _unadmitted_rows(unadmitted: Sequence[ReportedFinding]) -> list[str]:
    lines = [
        "| # | Chain entry | Function | Result type | Standing |",
        "|---|---|---|---|---|",
    ]
    for finding in unadmitted:
        lines.append(
            f"| {finding.sequence} | {_cell(finding.chain_entry)} | "
            f"{_cell(finding.tool)} | {_cell(finding.data_type)} | "
            f"{_cell(standing_of(finding))} |"
        )
    return lines


def _findings_body(
    classified: ClassifiedFindings | None,
    report_text: str | None,
    *,
    section: str | None,
) -> list[str]:
    """What was read, what was inferred from it, what was neither, and the narrative.

    The whole of the findings section is built here, narrative included, so the
    subsection numbering follows the subsections that were actually emitted
    instead of being predicted by a caller that would drift from it.
    """

    out: list[str] = []
    subsection = 1

    def heading(title: str) -> str:
        nonlocal subsection
        number = f"{section}.{subsection}" if section else None
        subsection += 1
        return _subheading(title, number=number)

    if classified is None:
        out.append(heading("Observations and interpretations"))
        out.append(_UNSEPARATED_FINDINGS + "\n")
    else:
        out.append(heading("Observations"))
        out.append(
            "Each row is a reading reported by the named component from the bound "
            "evidence, recorded by the run as an observation.\n"
        )
        if classified.observations:
            out.extend(_observation_rows(classified.observations))
            out.append("")
        else:
            out.append("_(the run recorded no observation)_\n")

        out.append(heading("Interpretations"))
        out.append(
            "Each row is a computation this system performed over the inputs it "
            "names, recorded by the run as derived rather than observed. The "
            "method and the inputs are the basis of the interpretation, stated "
            "in full under the explanation of conclusions and opinions below.\n"
        )
        if classified.interpretations:
            out.extend(_interpretation_rows(classified.interpretations))
            out.append("")
        else:
            out.append("_(the run recorded no interpretation)_\n")

        if classified.unadmitted:
            out.append(heading("Readings admitted as neither"))
            out.append(
                "The run recorded these readings but did not admit them as an "
                "observation or as an interpretation. Each states its own "
                "standing, and none of them is an evidential basis for a "
                "conclusion.\n"
            )
            out.extend(_unadmitted_rows(classified.unadmitted))
            out.append("")

    out.append(heading("Narrative drafted from the findings"))
    out.append(_NARRATIVE_STANDING + "\n")
    out.append((report_text or "_(no finding)_").strip() + "\n")
    return out


def _explanation_section(
    classified: ClassifiedFindings | None, *, number: str | None
) -> list[str]:
    """SWGDE 18-Q-002 §5's explanation of the conclusions and opinions drawn."""

    out = [_heading("Explanation of conclusions and opinions", number=number)]
    out.append(
        "The separation in section 5 is taken from the evidence class each "
        "standardized result carries in the run record. It is not inferred from "
        "the wording of any statement in this document, and no statement here is "
        "reclassified by this report.\n"
    )
    if classified is None:
        out.append(
            "No standardized findings were supplied to this report, so it states "
            "no basis for any interpretation it contains.\n"
        )
    elif classified.interpretations:
        out.append("Basis of each interpretation listed above:\n")
        for finding in classified.interpretations:
            basis = ", ".join(finding.derivation_inputs) or "no input the record names"
            line = (
                f"- **Finding {finding.sequence}** ({_cell(finding.tool)}) — "
                f"method {_cell(finding.derivation_method)}, computed over {_cell(basis)}."
            )
            if finding.assumptions:
                line += f" Stated assumptions: {_cell('; '.join(finding.assumptions))}."
            out.append(line)
        out.append("")
    else:
        out.append(
            "The run recorded no interpretation, so no finding it admitted "
            "carries a derivation to explain.\n"
        )
    out.append(
        "This report is an aid to an examination and not an expert opinion. The "
        "professional conclusion drawn from the material above remains the "
        "responsibility of the qualified examiner who authorizes it.\n"
    )
    return out


def _disposition_section(
    engagement: EngagementRecord | None, *, number: str | None
) -> list[str]:
    """SWGDE 18-Q-002 §5's disposition of the evidence."""

    disposition = stated(engagement.evidence_disposition if engagement else None)
    return [
        _heading("Disposition of evidence", number=number),
        f"**Disposition:** {disposition}\n",
        "What became of the evidence after the examination is a fact of the "
        "engagement, not of this run: the system received the evidence already "
        "acquired, opened it read-only, and records no transfer, release or "
        f'destruction of it. Where the line above reads "{NOT_SUPPLIED}", '
        "nobody stated a disposition to this report.\n",
    ]


def _authorization_section(
    engagement: EngagementRecord | None, *, number: str | None
) -> list[str]:
    """SWGDE 18-Q-002 §5.7's report authorizer name and signature."""

    authorizer = stated(engagement.authorizing_examiner if engagement else None)
    signature = stated(engagement.authorization_signature if engagement else None)
    out = [
        _heading("Report authorization", number=number),
        "| Element | Value |",
        "|---|---|",
        f"| Name of report authorizer | {_cell(authorizer)} |",
        f"| Signature | {_cell(signature)} |",
        "",
    ]
    if engagement is not None and engagement.is_authorized:
        out.append(
            "The name and the signature are reproduced exactly as they were "
            "supplied. This report does not verify the signature and attests "
            "nothing about the identity of the person named.\n"
        )
    else:
        out.append(
            "**This report is not authorized.** SWGDE 18-Q-002 §5.7 requires "
            "both the name of the report authorizer and a signature, and the "
            "table above shows at least one of the two not supplied. Until both "
            "are supplied this is an unauthorized, unsigned examination record "
            "and nobody has taken responsibility for its contents.\n"
        )
    out.append(_engagement_provenance(engagement) + "\n")
    return out


def _engagement_provenance(engagement: EngagementRecord | None) -> str:
    """Where the requester, disposition and authorization in this report came from."""

    if engagement is None:
        return (
            "No engagement record was supplied to this report, so the requester, "
            "the disposition of the evidence and the report authorization are "
            "stated as not supplied."
        )
    if is_supplied(engagement.source_path):
        origin = f"the engagement record at `{_cell(engagement.source_path)}`"
        if is_supplied(engagement.source_sha256):
            origin += f" (SHA-256 `{engagement.source_sha256}`)"
    else:
        origin = "an engagement record supplied by the caller"
    return (
        "Every value this report states for the requester, the disposition of "
        f"the evidence and the report authorization was read from {origin}; a "
        f'field marked "{NOT_SUPPLIED}" carried no value there. None of them '
        "was supplied by this system."
    )


# Mapping of tool name -> forensic artifact category (for the coverage section).
_TOOL_CATEGORY = {
    "list_directory": "File system", "file_metadata": "File system",
    "read_file": "File system", "extract_file": "File system",
    "search_keyword": "File system",
    "registry_query": "Windows Registry",
    "evtx_query": "Windows event logs",
    "timeline_query": "Timeline",
    "memory_query": "Memory", "memory_strings": "Memory",
    "pcap_query": "Network traffic", "reconstruct_http_exfil": "Network traffic",
    "reconstruct_dns_exfil": "Network traffic",
    "archive_query": "Archives", "ocr_image": "Images and media",
    "vision_read": "Images and media", "read_text_file": "Host files",
    "hash_file": "Integrity and hashes", "decode": "Decoding",
}


def build_standard_markdown(
    question: str | None,
    report_text: str | None,
    audit_entries: Sequence[Mapping[str, object]],
    *,
    model: str,
    engine: str,
    disk_label: str,
    operation_mode: str | None = None,
    when: str | None = None,
    evidence_sha256: str | None = None,
    findings: Sequence[Mapping[str, object]] | None = None,
    engagement: EngagementRecord | None = None,
) -> str:
    """Professional forensic report following the NIST SP 800-86 phase model and a
    SANS/NISTIR-8428 section structure: case summary, scope, evidence inventory,
    methodology with examined-category coverage, findings separated into
    observations and interpretations, the basis of those interpretations, the
    disposition of the evidence, the report authorization, and a
    chain-of-custody appendix where every tool access carries its SHA-256 output
    hash.

    ``findings`` are the run's standardized findings — the rows
    ``ControlledRun.standardized_findings()`` returns — and they are the only
    thing that separates an observation from an interpretation here. Omitting
    them yields a report that says so, rather than one that presents readings
    and inferences as a single undifferentiated block.

    ``engagement`` carries the three elements no run can observe. Passing none
    lets the environment name a record; supplying neither prints each of those
    elements as not supplied.
    """
    when = when or _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    resolved = _resolved_engagement(engagement)
    classified = classify_findings(findings) if findings is not None else None
    tools_used = sorted({str(e.get("tool", "")) for e in audit_entries if e.get("tool")})
    # tool names may carry a namespace prefix in the audit log (e.g. "tsk.list_directory")
    categories = sorted({_TOOL_CATEGORY.get(t.split(".")[-1], "Other") for t in tools_used})
    out = []
    out.append("# Forensic report\n")
    out.append(f"- **Case identifier:** {_case_identifier_line(audit_entries)}")
    out.append(f"- **Case / evidence:** {disk_label}")
    out.append(f"- **Requester:** {stated(resolved.requester if resolved else None)}")
    out.append(f"- **Model:** {model}")
    out.append(f"- **Runtime engine:** {engine}")
    if operation_mode:
        out.append(
            f"- **Operation mode:** {str(operation_mode).replace('_', ' ').title()}"
        )
    out.append(f"- **Generated:** {when}")
    out.append(f"- **Recorded evidence accesses:** {len(audit_entries)}\n")

    out.append("## 1. Case summary\n")
    out.append(f"The investigation concerns the evidence source {disk_label}. "
               f"The investigative question is: {question} Findings and conclusions "
               "are presented in section 5 and supported by the evidence trail in Appendix A.\n")

    out.append("## 2. Scope and objectives\n")
    out.append(f"The objective is to answer: {question} The scope is limited to the "
               "loaded evidence, which was accessed in read-only mode without executing "
               "its contents.\n")

    out.append("## 3. Evidence inventory\n")
    out.append("| Evidence | Access mode | SHA-256 |")
    out.append("|---|---|---|")
    ev_hash = (evidence_sha256 or "—")
    if evidence_sha256:
        ev_hash = f"`{evidence_sha256[:32]}…`"
    out.append(f"| {disk_label} | read only | {ev_hash} |")
    out.append("")

    out.append("## 4. Methodology and examined categories\n")
    out.append("The investigation followed the NIST SP 800-86 collection, examination, "
               "analysis, and reporting phases while preserving chain of custody in "
               "accordance with ISO/IEC 27037. Evidence was processed only by approved "
               "read-only tools, and each access was recorded with a SHA-256 digest of "
               "the output (Appendix A).\n")
    out.append("Tools used: " + (", ".join(f"`{t}`" for t in tools_used) or "—") + ".\n")
    out.append("Examined artifact categories: " + (", ".join(categories) or "—")
               + ". Categories outside the loaded evidence are not applicable to this case.\n")

    out.append("## 5. Findings and conclusions\n")
    out.extend(_findings_body(classified, report_text, section="5"))

    out.extend(_explanation_section(classified, number="6"))
    out.extend(_disposition_section(resolved, number="7"))
    out.extend(_authorization_section(resolved, number="8"))

    out.append("## Appendix A — Evidence trail (chain of custody)\n")
    if audit_entries:
        out.append("| # | Chain entry | Tool | Arguments | Output SHA-256 | Duration (s) |")
        out.append("|---|---|---|---|---|---|")
        for i, e in enumerate(audit_entries, 1):
            args = json.dumps(e.get("args", {}), ensure_ascii=False)
            if len(args) > 60:
                args = args[:57] + "…"
            sha = str(e.get("output_sha256") or "")[:16]
            dur = e.get("duration_s")
            dur = f"{dur:.2f}" if isinstance(dur, (int, float)) else ""
            out.append(
                f"| {i} | {_cell(e.get('seq'))} | {e.get('tool', '')} | "
                f"`{args}` | `{sha}…` | {dur} |"
            )
        out.append("")
    else:
        out.append("_(no audited evidence access was recorded for this case)_\n")

    out.append("---")
    out.append("This report follows NIST SP 800-86 and the SANS/NISTIR 8428 structure. "
               "Every evidence access is recorded with a SHA-256 digest of the output "
               "to preserve evidence integrity in accordance with ISO/IEC 27037.")
    return "\n".join(out) + "\n"


def _refused_action_rows(refused: Sequence[Mapping[str, object]]) -> list[str]:
    """Every refusal as one table row, with the layer that made it and its ground."""

    lines = ["| Tool | Arguments | Refused by | Ground |", "|---|---|---|---|"]
    for b in refused:
        args = json.dumps(b.get("args", {}), ensure_ascii=False)
        if len(args) > 60:
            args = args[:57] + "…"
        layer = (
            "the tool"
            if b.get("outcome") == "refused_by_tool"
            else "the oversight policy"
        )
        reasons = b.get("reasons")
        ground = (
            "; ".join(reasons) if isinstance(reasons, (list, tuple)) else ""
        ) or str(b.get("detail") or "")
        lines.append(f"| {b.get('tool', '')} | `{args}` | {layer} | {ground} |")
    return lines


def _timeline_rows(timeline: Sequence[Mapping[str, object]]) -> list[str]:
    """The decision timeline as table rows, one per recorded call."""

    lines = [
        "| # | Tool | Decision | Outcome | Risk | Note |",
        "|---|------|--------|--------|-------|----------|",
    ]
    for t in timeline:
        reasons = t.get("reasons")
        note = (
            "; ".join(reasons) if isinstance(reasons, (list, tuple)) else ""
        ) or str(t.get("detail") or "")
        if len(note) > 70:
            note = note[:67] + "…"
        lines.append(
            f"| {t.get('seq')} | {t.get('tool', '')} | {t.get('decision')} | "
            f"{t.get('outcome', '')} | {t.get('risk')} | {note} |"
        )
    return lines


def _call_accounting_line(recon: Mapping[str, object]) -> str:
    """One line accounting for every recorded call of one run, exactly once.

    "Refused" counts both refusing layers; the figure beside it counts the one
    the gate itself stopped, leaving the difference as the calls the tools
    reached and declined.  It is no longer labelled "by policy": the gate has
    two refusal points and this figure has counted both since the record began
    stamping ``forensic.oversight-record.v2``, so naming the capability policy
    alone would attribute an argument refusal to a rule that permitted it.
    """

    return (
        f"- **Tool calls:** {recon.get('tool_calls')}  ·  "
        f"**Ran:** {recon.get('executed_calls')}  ·  "
        f"**Refused:** {recon.get('refused_calls')} "
        f"(by oversight: {recon.get('blocked_calls')})  ·  "
        f"**Failed:** {recon.get('failed_calls')}  ·  "
        f"**Highest risk:** {recon.get('max_risk')}"
    )


def build_oversight_markdown(recon, *, model=None, when=None) -> str:
    """Render an oversight layer oversight log reconstruction (from
    `oversight.reconstruct`) into a Markdown post-incident report of the agent's
    OWN behaviour: what it was asked, the policy in effect, every tool decision,
    which actions were blocked and why, and the highest risk reached."""
    when = when or _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pol = recon.get("policy") or {}
    out = []
    out.append("# Oversight layer — agent activity reconstruction\n")
    out.append(f"- **Question:** {recon.get('question')}")
    out.append(f"- **Model:** {model or recon.get('model')}")
    out.append(f"- **Runtime engine:** {recon.get('engine')}")
    out.append(f"- **Policy:** {pol.get('name')}"
               + (f"  ·  granted capabilities: {', '.join(pol.get('granted_caps') or [])}" if pol else ""))
    out.append(f"- **Generated:** {when}")
    if recon.get("transcript_sha256"):
        out.append(f"- **Transcript SHA-256:** `{recon.get('transcript_sha256')}`")
    out.append(_call_accounting_line(recon) + "\n")

    out.append("## Refused actions\n")
    refused = recon.get("refusal_summary") or recon.get("blocked_summary") or []
    if refused:
        out.extend(_refused_action_rows(refused))
        out.append("")
    else:
        out.append("_(no action was refused; every call the agent made ran)_\n")

    out.append("## Agent decision timeline\n")
    tl = recon.get("timeline") or []
    if tl:
        out.extend(_timeline_rows(tl))
        out.append("")
    else:
        out.append("_(no tool calls were recorded)_\n")

    out.append("---")
    out.append("Every agent action (request, decision, tool call, block, and risk) "
               "is recorded append-only in `oversight.jsonl` with a SHA-256 digest "
               "of the output. This supports forensic reconstruction of agent activity, "
               "chain of custody under ISO/IEC 27037, audit replay, and reproducibility "
               "checks when the same case is run again.")
    return "\n".join(out) + "\n"


def _evidence_access_rows(calls: Sequence[Mapping[str, object]]) -> list[str]:
    """One chain-of-custody row per executed access, as the appendix prints them."""

    lines = [
        "| # | Chain entry | Tool | Arguments | Output SHA-256 | Duration (s) |",
        "|---|---|---|---|---|---|",
    ]
    for i, e in enumerate(calls, 1):
        args = json.dumps(e.get("args", {}), ensure_ascii=False)
        if len(args) > 60:
            args = args[:57] + "…"
        sha = str(e.get("output_sha256") or "")[:16]
        dur = e.get("duration_s")
        dur = f"{dur:.2f}" if isinstance(dur, (int, float)) else ""
        lines.append(
            f"| {i} | {_cell(e.get('seq'))} | {e.get('tool', '')} | "
            f"`{args}` | `{sha}…` | {dur} |"
        )
    return lines


def _record(value: object) -> Mapping[str, object]:
    """One nested record read back from a run's JSON, empty when it is absent."""

    return value if isinstance(value, Mapping) else {}


def _records(value: object) -> list[Mapping[str, object]]:
    """A nested list of records read back from a run's JSON.

    The report only ever formats what a run wrote, so a value that is not a
    list of records is reported as nothing recorded rather than crashing the
    whole case report over one malformed entry.
    """

    if not isinstance(value, (list, tuple)):
        return []
    return [row for row in value if isinstance(row, Mapping)]


def build_case_markdown(
    turns: Sequence[Mapping[str, object]],
    *,
    case_id: str,
    model: str,
    provider: str,
    reasoning_effort: str,
    engine: str,
    operation_mode: str | None = None,
    sources: Sequence[str] = (),
    when: str | None = None,
) -> str:
    """The whole-case report: every recorded question of the case, in order.

    Each entry of ``turns`` is one run's record, already read from that run's
    own directory by the caller: ``ordinal``, ``question``, ``answer``,
    ``published``, ``calls`` (the executed accesses), ``findings`` (the
    standardized rows), ``oversight`` (the ``reconstruct`` dictionary) and
    ``duration_s`` (``case_close.ts - case_open.ts``). Nothing here re-derives
    a value from the evidence; every number is read from what the run recorded.

    The header carries what a reader needs to place the whole document — the
    model, the provider, the reasoning effort the console reports, the
    evidence sources and the case totals — and the summary table answers per
    question what the sections below state in full: whether an answer was
    published, how many calls ran, how long the run took, and how many calls
    a guardrail stopped (every refusal by either layer, counted once).
    """

    when = when or _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    reconstructions = [_record(turn.get("oversight")) for turn in turns]
    total_calls = sum(
        calls
        for recon in reconstructions
        if isinstance(calls := recon.get("tool_calls"), int)
    )
    total_duration = sum(
        duration
        for turn in turns
        if isinstance(duration := turn.get("duration_s"), (int, float))
    )
    out: list[str] = []
    out.append("# Forensic case report\n")
    out.append(f"- **Case identifier:** {case_id}")
    out.append(f"- **Model:** {model}")
    out.append(f"- **Provider:** {provider}")
    out.append(f"- **Reasoning effort:** {reasoning_effort}")
    out.append(f"- **Runtime engine:** {engine}")
    if operation_mode:
        out.append(
            f"- **Operation mode:** {str(operation_mode).replace('_', ' ').title()}"
        )
    out.append(f"- **Generated:** {when}")
    out.append("- **Evidence sources:**")
    if sources:
        out.extend(f"  - {line}" for line in sources)
    else:
        out.append("  - _(no evidence source is attached)_")
    out.append(
        f"- **Questions:** {len(turns)}  ·  "
        f"**Recorded tool calls:** {total_calls}  ·  "
        f"**Total duration:** {format_duration(total_duration)}\n"
    )

    out.append("## Question summary\n")
    out.append(
        "| # | Question | Published | Calls | Duration (s) | Guardrails triggered |"
    )
    out.append("|---|---|---|---|---|---|")
    for turn, recon in zip(turns, reconstructions, strict=True):
        duration = turn.get("duration_s")
        duration_cell = (
            f"{duration:.1f}" if isinstance(duration, (int, float)) else "—"
        )
        out.append(
            f"| {turn.get('ordinal')} | {_cell(turn.get('question'))} | "
            f"{'yes' if turn.get('published') else 'no'} | "
            f"{recon.get('tool_calls') or 0} | {duration_cell} | "
            f"{recon.get('refused_calls') or 0} |"
        )
    out.append("")

    for turn, recon in zip(turns, reconstructions, strict=True):
        out.append(f"## Question {turn.get('ordinal')}\n")
        out.append(f"**Question:** {turn.get('question')}\n")

        findings = turn.get("findings")
        classified = classify_findings(_records(findings)) if findings is not None else None
        answer = turn.get("answer")
        out.extend(
            _findings_body(classified, answer if isinstance(answer, str) else None, section=None)
        )

        out.append("### Evidence accesses\n")
        calls = _records(turn.get("calls"))
        if calls:
            out.extend(_evidence_access_rows(calls))
            out.append("")
        else:
            out.append(
                "_(no audited evidence access was recorded for this question)_\n"
            )

        out.append("### Oversight decisions\n")
        out.append(_call_accounting_line(recon) + "\n")
        refused = _records(recon.get("refusal_summary")) or _records(
            recon.get("blocked_summary")
        )
        if refused:
            out.extend(_refused_action_rows(refused))
            out.append("")
        timeline = _records(recon.get("timeline"))
        if timeline:
            out.extend(_timeline_rows(timeline))
            out.append("")
        else:
            out.append("_(no tool calls were recorded)_\n")

    out.append("---")
    out.append(
        "Each question's record is read from its own run directory: the "
        "answer from the case history, the accesses and decisions from "
        "`oversight.jsonl`, and the standardized findings from "
        "`tool-results.jsonl`, each access carrying a SHA-256 digest of its "
        "output in accordance with ISO/IEC 27037."
    )
    return "\n".join(out) + "\n"


def write_report(path, content) -> str:
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return os.path.abspath(path)
