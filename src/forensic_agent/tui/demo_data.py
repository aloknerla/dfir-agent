"""A recorded, stubbed investigation for ``dfir-agent tui --demo``.

A live run needs Docker, a mounted evidence image, and a configured model. So
the whole console can be reviewed without any of that, this module hands the
demo controller one complete case: a status frame, a script of tool calls (one
of them refused by the deterministic oversight layer, one refused by the tool
itself), a set of standardized findings with real-shaped SHA-256 receipts, the
matching capability decisions, and a grounded answer with its provenance.

Nothing here touches the forensic core; it is illustrative data only.
"""

from __future__ import annotations

from forensic_agent.tui.model import (
    ANSWER_VERIFIED_WITH_BOUND,
    OUTCOME_EXECUTED,
    OUTCOME_FAILED,
    OUTCOME_REFUSED_BY_OVERSIGHT,
    ControlCard,
    DemoInvestigation,
    FindingCard,
    InvestigationResult,
    OversightCard,
    ScriptedToolStep,
    StatusState,
)

# Real-shaped digests (64 lowercase hex). Illustrative — not of any real object.
_SHA_USBSTOR = "3f9a1c77e0b4d2a6c8e13f5079b2a4d6c1e8f0a3b5d7c9e2f4a6b8d0c2e4f6a81"
_SHA_MOUNTED = "a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00"
_SHA_SETUPAPI = "77c0ffee1234567890abcdef0011223344556677889900aabbccddeeff1029384"
_SHA_SECURITY = "b5d41402abc4b2a76b9719d911017c592f0e1a2b3c4d5e6f70819a2b3c4d5e6f7"
_SHA_TIMELINE = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


DEMO_STATUS = StatusState(
    mode="DEMO",
    model="deepseek-chat",
    provider="OpenRouter",
    case_label="laptop-0731",
    case_id="case-2026-0731-laptop",
    evidence_sources=(
        "disk: DESKTOP-audit.E01",
        "memory: DESKTOP-audit.mem",
    ),
    max_steps=20,
    max_tool_calls=20,
    max_model_requests=24,
    reasoning_effort="high",
    max_wall_time_s=900,
)


DEMO_QUESTION = (
    "Which USB mass-storage device was connected to this machine, and which "
    "user account was logged in at the time of first insertion?"
)


# --- the live flight-recorder script -------------------------------------
# Six calls: four execute, one is refused by the oversight layer (an attempt to
# reach an external vendor-ID lookup — outside the granted authority), and one
# is refused by the tool (a plugin that had nothing to parse).
DEMO_TOOL_SCRIPT: tuple[ScriptedToolStep, ...] = (
    ScriptedToolStep(
        function="registry_query",
        operation="enumerate_usbstor",
        args_summary="hive=SYSTEM key=ControlSet001\\Enum\\USBSTOR",
        final_status=OUTCOME_EXECUTED,
        duration_s=1.84,
        evidence_id="EV-DISK-01",
        run_delay_s=0.5,
    ),
    ScriptedToolStep(
        function="registry_query",
        operation="read_mounted_devices",
        args_summary="hive=SYSTEM key=MountedDevices",
        final_status=OUTCOME_EXECUTED,
        duration_s=0.72,
        evidence_id="EV-DISK-01",
        run_delay_s=0.35,
    ),
    ScriptedToolStep(
        function="filesystem_read",
        operation="read_setupapi_log",
        args_summary="path=/Windows/INF/setupapi.dev.log offset=0 limit=4000",
        final_status=OUTCOME_EXECUTED,
        duration_s=2.31,
        evidence_id="EV-DISK-01",
        run_delay_s=0.55,
    ),
    ScriptedToolStep(
        function="http_fetch",
        operation="resolve_vendor_id",
        args_summary="url=https://usb.ids/lookup?vid=0781&pid=5583",
        final_status=OUTCOME_REFUSED_BY_OVERSIGHT,
        duration_s=0.02,
        evidence_id="",
        run_delay_s=0.25,
    ),
    ScriptedToolStep(
        function="registry_query",
        operation="resolve_logged_on_user",
        args_summary="hive=SAM key=SAM\\Domains\\Account\\Users",
        final_status=OUTCOME_EXECUTED,
        duration_s=1.06,
        evidence_id="EV-DISK-01",
        run_delay_s=0.4,
    ),
    ScriptedToolStep(
        function="evtx_scan",
        operation="carve_removable_events",
        args_summary="channel=Microsoft-Windows-Partition/Diagnostic",
        final_status=OUTCOME_FAILED,
        duration_s=0.44,
        evidence_id="EV-DISK-01",
        run_delay_s=0.3,
    ),
)


# --- the standardized findings -------------------------------------------
DEMO_FINDINGS: tuple[FindingCard, ...] = (
    FindingCard(
        sequence=1,
        status="ok",
        label="USB device",
        function="registry_query",
        operation="enumerate_usbstor",
        data_type="registry.usbstor_devices",
        records="1/1 devices",
        coverage_label="complete",
        coverage_complete=True,
        coverage_scope="all USBSTOR subkeys in ControlSet001",
        coverage_reason="",
        receipt_full=_SHA_USBSTOR,
        arguments=(
            ("hive", "SYSTEM"),
            ("key", "ControlSet001\\Enum\\USBSTOR"),
        ),
        result_summary=(
            "Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00 — serial 4C531001820731107205, "
            "FriendlyName 'SanDisk Ultra USB Device'."
        ),
        source_id="EV-DISK-01",
        source_uri="ewf://DESKTOP-audit.E01/vol_2/Windows/System32/config/SYSTEM",
        evidence_class="observed",
        warnings=(),
        oversight_sequence=1,
    ),
    FindingCard(
        sequence=2,
        status="ok",
        label="drive mapping",
        function="registry_query",
        operation="read_mounted_devices",
        data_type="registry.mounted_devices",
        records="2/2 mappings",
        coverage_label="complete",
        coverage_complete=True,
        coverage_scope="MountedDevices value set",
        coverage_reason="",
        receipt_full=_SHA_MOUNTED,
        arguments=(("hive", "SYSTEM"), ("key", "MountedDevices")),
        result_summary=(
            "Volume GUID {f4a1...9c} maps to the SanDisk serial above; drive letter "
            "E: bound to the same device signature."
        ),
        source_id="EV-DISK-01",
        source_uri="ewf://DESKTOP-audit.E01/vol_2/Windows/System32/config/SYSTEM",
        evidence_class="observed",
        warnings=(),
        oversight_sequence=2,
    ),
    FindingCard(
        sequence=3,
        status="partial",
        label="setup log",
        function="filesystem_read",
        operation="read_setupapi_log",
        data_type="filesystem.text_region",
        records="4000/18213 bytes",
        coverage_label="truncated",
        coverage_complete=False,
        coverage_scope="first 4000 bytes of setupapi.dev.log",
        coverage_reason="page limit reached; continuation offset 4000 available",
        receipt_full=_SHA_SETUPAPI,
        arguments=(
            ("path", "/Windows/INF/setupapi.dev.log"),
            ("offset", "0"),
            ("limit", "4000"),
        ),
        result_summary=(
            "First-install record for the SanDisk device timestamped "
            "2026-07-29 21:14:07 (local) during an interactive session."
        ),
        source_id="EV-DISK-01",
        source_uri="ewf://DESKTOP-audit.E01/vol_2/Windows/INF/setupapi.dev.log",
        evidence_class="observed",
        warnings=("coverage.truncated",),
        oversight_sequence=3,
    ),
    FindingCard(
        sequence=4,
        status="ok",
        label="user account",
        function="registry_query",
        operation="resolve_logged_on_user",
        data_type="registry.account_index",
        records="3/3 accounts",
        coverage_label="complete",
        coverage_complete=True,
        coverage_scope="SAM local account RIDs",
        coverage_reason="",
        receipt_full=_SHA_SECURITY,
        arguments=(
            ("hive", "SAM"),
            ("key", "SAM\\Domains\\Account\\Users"),
        ),
        result_summary=(
            "RID 0x3E9 → 'm.kovac' last-logon 2026-07-29 21:09:52, the only "
            "interactive account active in the insertion window."
        ),
        source_id="EV-DISK-01",
        source_uri="ewf://DESKTOP-audit.E01/vol_2/Windows/System32/config/SAM",
        evidence_class="derived",
        warnings=(),
        oversight_sequence=5,
    ),
)


# --- the capability decisions (oversight pane) ---------------------------
_GRANTED_CAPS = ("read_evidence", "controlled_scratch", "decode")
_ALLOWED_TOOLS = ("registry_query", "filesystem_read", "evtx_scan", "http_fetch")
_WRITE_SCOPE = ("/runs/case-2026-0731-laptop/scratch",)

DEMO_OVERSIGHT: tuple[OversightCard, ...] = (
    OversightCard(
        sequence=1,
        function="registry_query",
        operation="enumerate_usbstor",
        outcome=OUTCOME_EXECUTED,
        requested_caps=("read_evidence",),
        granted_caps=_GRANTED_CAPS,
        allowed_tools=_ALLOWED_TOOLS,
        write_scope=_WRITE_SCOPE,
        risk_name="low",
        reasons=("read-only evidence access within granted authority",),
        duration_s=1.84,
        arguments=(("hive", "SYSTEM"), ("key", "ControlSet001\\Enum\\USBSTOR")),
        output_digests=(("recorded_output_sha256", _SHA_USBSTOR),),
    ),
    OversightCard(
        sequence=2,
        function="registry_query",
        operation="read_mounted_devices",
        outcome=OUTCOME_EXECUTED,
        requested_caps=("read_evidence",),
        granted_caps=_GRANTED_CAPS,
        allowed_tools=_ALLOWED_TOOLS,
        write_scope=_WRITE_SCOPE,
        risk_name="low",
        reasons=("read-only evidence access within granted authority",),
        duration_s=0.72,
        arguments=(("hive", "SYSTEM"), ("key", "MountedDevices")),
        output_digests=(("recorded_output_sha256", _SHA_MOUNTED),),
    ),
    OversightCard(
        sequence=3,
        function="filesystem_read",
        operation="read_setupapi_log",
        outcome=OUTCOME_EXECUTED,
        requested_caps=("read_evidence",),
        granted_caps=_GRANTED_CAPS,
        allowed_tools=_ALLOWED_TOOLS,
        write_scope=_WRITE_SCOPE,
        risk_name="low",
        reasons=("path argument inside the allowed case scope",),
        duration_s=2.31,
        arguments=(
            ("path", "/Windows/INF/setupapi.dev.log"),
            ("offset", "0"),
            ("limit", "4000"),
        ),
        output_digests=(("recorded_output_sha256", _SHA_SETUPAPI),),
    ),
    OversightCard(
        sequence=4,
        function="http_fetch",
        operation="resolve_vendor_id",
        outcome=OUTCOME_REFUSED_BY_OVERSIGHT,
        requested_caps=("network",),
        granted_caps=_GRANTED_CAPS,
        allowed_tools=_ALLOWED_TOOLS,
        write_scope=_WRITE_SCOPE,
        risk_name="high",
        reasons=(
            "requires ungranted capability [network]",
            "network egress is disabled for this case (allow_network=False)",
        ),
        duration_s=0.02,
        arguments=(("url", "https://usb.ids/lookup?vid=0781&pid=5583"),),
        output_digests=(),
    ),
    OversightCard(
        sequence=5,
        function="registry_query",
        operation="resolve_logged_on_user",
        outcome=OUTCOME_EXECUTED,
        requested_caps=("read_evidence",),
        granted_caps=_GRANTED_CAPS,
        allowed_tools=_ALLOWED_TOOLS,
        write_scope=_WRITE_SCOPE,
        risk_name="low",
        reasons=("read-only evidence access within granted authority",),
        duration_s=1.06,
        arguments=(("hive", "SAM"), ("key", "SAM\\Domains\\Account\\Users")),
        output_digests=(("recorded_output_sha256", _SHA_SECURITY),),
    ),
    OversightCard(
        sequence=6,
        function="evtx_scan",
        operation="carve_removable_events",
        outcome=OUTCOME_FAILED,
        requested_caps=("read_evidence",),
        granted_caps=_GRANTED_CAPS,
        allowed_tools=_ALLOWED_TOOLS,
        write_scope=_WRITE_SCOPE,
        risk_name="low",
        reasons=("read-only evidence access within granted authority",),
        duration_s=0.44,
        arguments=(("channel", "Microsoft-Windows-Partition/Diagnostic"),),
        output_digests=(),
    ),
)


DEMO_ANSWER_MARKDOWN = """\
A single USB mass-storage device was connected: a **SanDisk Ultra USB** flash
drive (VID 0781 / PID 5583, serial **4C531001820731107205**), first inserted on
**2026-07-29 at 21:14:07 local time** and mounted as drive **E:**.

The only interactive account active in that insertion window was **`m.kovac`**
(RID 0x3E9, last interactive logon 21:09:52, ~4 minutes before first insertion),
so that account was logged in when the device was attached.

*Coverage bound:* the setupapi.dev.log was read to its 4000-byte page limit; a
continuation offset (4000) remains unread, and the Partition/Diagnostic EVTX
channel could not be parsed, so later re-insertions are not ruled out.
"""


DEMO_RESULT = InvestigationResult(
    question=DEMO_QUESTION,
    answer_markdown=DEMO_ANSWER_MARKDOWN,
    answer_source=ANSWER_VERIFIED_WITH_BOUND,
    evidence_ids=("EV-DISK-01",),
    findings=DEMO_FINDINGS,
    oversight=DEMO_OVERSIGHT,
    controls=ControlCard(
        verification="grounded; coverage bound stated",
        answer_source=ANSWER_VERIFIED_WITH_BOUND,
        tool_calls=5,
        findings=4,
        model_requests=7,
        trace_id="run-7b3e9c1a4f28",
        elapsed_s=11.7,
    ),
    incomplete=False,
)


DEMO_FOLLOWUPS = (
    "Was the SanDisk drive ever re-inserted after the first session?",
    "What files were copied to drive E: while it was mounted?",
)


def demo_investigation() -> DemoInvestigation:
    """Return the canned investigation the demo controller replays."""

    return DemoInvestigation(
        status=DEMO_STATUS,
        question=DEMO_QUESTION,
        tool_script=DEMO_TOOL_SCRIPT,
        result=DEMO_RESULT,
        followups=DEMO_FOLLOWUPS,
    )
