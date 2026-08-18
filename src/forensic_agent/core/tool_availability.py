"""The single source of truth for external forensic tool availability.

Three surfaces need to agree about whether an external binary can be used: the
``doctor`` preflight report, the interactive ``/tools`` catalog, and the registry
of functions handed to the model.  When each of them probed the filesystem on its
own, they drifted: ``doctor`` could report a tool as present while the model was
never offered the function that needs it, and vice versa.

This module therefore owns the whole declaration — the executable candidates, the
environment-variable override, the fallback install locations, and which
model-visible functions each binary backs — and every surface reads its answers
from here.  Probing is deliberately cheap and side-effect free: it resolves paths
only and never executes a forensic tool, so asking "is this available?" can never
touch evidence.

A function can also be missing from the model surface for a reason that has
nothing to do with this host: we withdrew it.  That decision is declared here too
(:data:`QUARANTINED_MODEL_TOOLS`), beside the dependency table, because the
question a caller asks is the same one — "why can the model not call this?" — and
because a withdrawal that is not declared anywhere is indistinguishable from a
function that was quietly deleted.
"""

from __future__ import annotations

import os
import shutil
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

IS_WIN = os.name == "nt"


def _candidates(name):
    return (name, name + ".exe") if IS_WIN else (name,)


def _is_executable_file(path):
    return os.path.isfile(path) and (IS_WIN or os.access(path, os.X_OK))


def resolve_tool(names, env_var=None):
    """Return an absolute path to the first available external tool, or None.

    Order: explicit env var -> dir of the active interpreter -> system PATH.
    Preferring the active virtual environment prevents a direct invocation of its
    Python executable from silently mixing in a globally installed console tool.
    """
    if env_var:
        v = os.environ.get(env_var)
        if v and _is_executable_file(v):
            return v
    bindir = os.path.dirname(os.path.abspath(sys.executable))
    for sub in ("", "Scripts", "bin"):
        d = os.path.join(bindir, sub) if sub else bindir
        for n in names:
            for cand in _candidates(n):
                full = os.path.join(d, cand)
                if _is_executable_file(full):
                    return full
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


@dataclass(frozen=True, slots=True)
class ExternalToolSpec:
    """One external command-line tool, declared exactly once."""

    #: Stable identifier used by every surface and by the legacy ``*_path``
    #: helpers (``<id>_path``).
    id: str
    #: Name an investigator recognises, used in reasons and hints.
    display_name: str
    #: Executable names tried on PATH and in the interpreter's script directory.
    candidates: tuple[str, ...]
    #: Environment variable that overrides discovery with an explicit path.
    env_var: str
    #: Row label used by the ``doctor`` preflight report.
    doctor_label: str
    #: What to do when it is missing. Always mentions ``env_var``.
    install_hint: str
    #: Absolute locations checked when the tool is installed outside PATH.
    fallback_paths: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ToolAvailability:
    """The resolved state of one external tool at a single point in time."""

    id: str
    display_name: str
    available: bool
    path: str | None
    env_var: str
    #: Empty when available; otherwise a short, machine-stable explanation.
    reason: str
    hint: str
    doctor_label: str
    #: Model-visible function names this tool backs.
    backs: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ModelToolDependency:
    """What one model-visible function needs from the outside world.

    ``requires`` is a tuple of any-of groups: every group must be satisfied by at
    least one available tool.  ``memory_malware_scan`` needs Volatility *and*
    ClamAV, while ``registry_ripper`` needs RegRipper alone.
    """

    tool_name: str
    requires: tuple[tuple[str, ...], ...]
    #: Which evidence binding makes this function part of the registry at all.
    scope: str
    #: Environment variables that select a different execution route entirely.
    #: When one of them is configured the local binary is not required, so the
    #: function is not failed closed on its absence.
    alternate_route_env: tuple[str, ...] = ()


class ExternalToolUnavailable(RuntimeError):
    """A registry segment declines to build a function: a dependency is missing.

    This is the ONLY exception the tool registry treats as unavailability.  A
    ``TypeError``, an ``ImportError`` of our own modules, or any other defect is
    a programming error and must surface, never be recorded as "not installed".
    """

    def __init__(self, tool_name: str, missing: tuple[str, ...] = ()) -> None:
        self.tool_name = tool_name
        self.missing = tuple(missing)
        super().__init__(
            f"{tool_name} is unavailable: "
            + (", ".join(self.missing) if self.missing else "external dependency missing")
        )


_SPECS: tuple[ExternalToolSpec, ...] = (
    ExternalToolSpec(
        id="vol",
        display_name="Volatility 3",
        candidates=("vol", "volatility3", "vol.py"),
        env_var="DFA_VOL",
        doctor_label="Volatility 3 — vol (memory)",
        install_hint="pip install volatility3 (or add it to PATH / set DFA_VOL)",
    ),
    ExternalToolSpec(
        id="clamscan",
        display_name="ClamAV clamscan",
        candidates=("clamscan",),
        env_var="DFA_CLAMSCAN",
        doctor_label="ClamAV — clamscan (offline malware signature scan)",
        install_hint=(
            "install ClamAV and set DFA_CLAMSCAN, or set "
            "DFA_MEMORY_SCAN_DOCKER_IMAGE for containerized scanning"
        ),
    ),
    ExternalToolSpec(
        id="tshark",
        display_name="Wireshark tshark",
        candidates=("tshark",),
        env_var="DFA_TSHARK",
        doctor_label="Wireshark — tshark (network/PCAP)",
        install_hint=(
            "install Wireshark (includes tshark), add it to PATH, or set DFA_TSHARK"
        ),
        fallback_paths=(
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
            "/usr/bin/tshark",
            "/usr/local/bin/tshark",
            "/opt/homebrew/bin/tshark",
        ),
    ),
    ExternalToolSpec(
        id="mergecap",
        display_name="Wireshark mergecap",
        candidates=("mergecap",),
        env_var="DFA_MERGECAP",
        doctor_label="mergecap (optional PCAP merging)",
        install_hint="install Wireshark, add mergecap to PATH, or set DFA_MERGECAP",
    ),
    ExternalToolSpec(
        id="seven_zip",
        display_name="7-Zip",
        candidates=("7z", "7za", "7zr"),
        env_var="DFA_7Z",
        doctor_label="7-Zip — 7z (archives)",
        install_hint="install 7-Zip, add it to PATH, or set DFA_7Z",
        fallback_paths=(
            r"C:\Program Files\7-Zip\7z.exe",
            r"C:\Program Files (x86)\7-Zip\7z.exe",
            "/usr/bin/7z",
            "/usr/local/bin/7z",
            "/opt/homebrew/bin/7z",
        ),
    ),
    ExternalToolSpec(
        id="tesseract",
        display_name="Tesseract OCR",
        candidates=("tesseract",),
        env_var="DFA_TESSERACT",
        doctor_label="Tesseract — OCR (image text)",
        install_hint="install Tesseract OCR, add it to PATH, or set DFA_TESSERACT",
        fallback_paths=(
            r"C:\Program Files\Tesseract-OCR\tesseract.exe",
            r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
            "/usr/bin/tesseract",
            "/usr/local/bin/tesseract",
            "/opt/homebrew/bin/tesseract",
        ),
    ),
    ExternalToolSpec(
        id="regripper",
        display_name="RegRipper",
        candidates=("rip.pl", "rip", "regripper", "rip.exe"),
        env_var="DFA_REGRIPPER",
        doctor_label="RegRipper (optional Registry/USB names)",
        install_hint="install RegRipper (rip.pl), add it to PATH, or set DFA_REGRIPPER",
    ),
    ExternalToolSpec(
        id="bulk_extractor",
        display_name="bulk_extractor",
        candidates=("bulk_extractor", "bulk_extractor64.exe", "bulk_extractor.exe"),
        env_var="DFA_BULK_EXTRACTOR",
        doctor_label="bulk_extractor (unallocated feature extraction)",
        install_hint=(
            "install bulk_extractor, add it to PATH, or set DFA_BULK_EXTRACTOR"
        ),
        fallback_paths=(
            "/usr/bin/bulk_extractor",
            "/usr/local/bin/bulk_extractor",
            "/opt/homebrew/bin/bulk_extractor",
        ),
    ),
    ExternalToolSpec(
        id="john",
        display_name="John the Ripper",
        candidates=("john", "john.exe"),
        env_var="DFA_JOHN",
        doctor_label="John the Ripper (optional password recovery)",
        install_hint=(
            "install John the Ripper (jumbo), add john to PATH, or set DFA_JOHN"
        ),
        fallback_paths=(
            "/usr/bin/john",
            "/usr/local/bin/john",
            "/opt/john/run/john",
            "/opt/homebrew/bin/john",
        ),
    ),
)

EXTERNAL_TOOLS: Mapping[str, ExternalToolSpec] = MappingProxyType(
    {spec.id: spec for spec in _SPECS}
)

#: Evidence bindings, mirroring the gating in
#: :func:`forensic_agent.agent.tool_registry.build_tools`.
SCOPE_ALWAYS = "always"
SCOPE_DISK = "disk"
SCOPE_DISK_EXTRACT = "disk_extract"
SCOPE_MEMORY = "memory"
SCOPE_PCAP = "pcap"
#: A raw evidence image of ANY kind is loaded — a disk image or a memory image.
#: What a scanner reads off raw bytes it reads the same way in both.
SCOPE_RAW_IMAGE = "raw_image"

_DEPENDENCIES: tuple[ModelToolDependency, ...] = (
    ModelToolDependency("memory_query", (("vol",),), SCOPE_MEMORY),
    ModelToolDependency(
        "memory_malware_scan",
        (("vol",), ("clamscan",)),
        SCOPE_MEMORY,
        alternate_route_env=("DFA_MEMORY_SCAN_DOCKER_IMAGE",),
    ),
    ModelToolDependency("pcap_query", (("tshark",),), SCOPE_PCAP),
    ModelToolDependency("reconstruct_http_exfil", (("tshark",),), SCOPE_PCAP),
    ModelToolDependency("bulk_extract", (("bulk_extractor",),), SCOPE_RAW_IMAGE),
    ModelToolDependency("registry_ripper", (("regripper",),), SCOPE_DISK_EXTRACT),
    ModelToolDependency(
        "windows_local_accounts", (("regripper",),), SCOPE_DISK_EXTRACT
    ),
    ModelToolDependency("archive_query", (("seven_zip",),), SCOPE_ALWAYS),
    ModelToolDependency("ocr_image", (("tesseract",),), SCOPE_ALWAYS),
)

MODEL_TOOL_DEPENDENCIES: Mapping[str, ModelToolDependency] = MappingProxyType(
    {dependency.tool_name: dependency for dependency in _DEPENDENCIES}
)


@dataclass(frozen=True, slots=True)
class QuarantinedModelTool:
    """One function withdrawn from the DEFAULT model surface, and why.

    The implementation stays in the repository and its binding stays buildable
    through the explicit opt-in, so historical and experimental callers keep
    working.  What this record removes is the function's place in the palette a
    model is handed by default.
    """

    tool_name: str
    #: The evidence binding that would otherwise put it in the registry. It is
    #: what limits the withheld report to builds where the function is genuinely
    #: expected, exactly as ``ModelToolDependency.scope`` does.
    scope: str
    #: Why it was withdrawn, in one sentence, stated to the investigator.
    reason: str


#: Withdrawn because each one is artifact-specific or rests on our own forensic
#: interpretation rather than on what an upstream backend reported.
_QUARANTINED: tuple[QuarantinedModelTool, ...] = (
    QuarantinedModelTool(
        "configuration_query",
        SCOPE_DISK,
        "hand-rolled INI parsing with a known splitting defect on values that "
        "contain a colon, where a standard parser covers the format",
    ),
    QuarantinedModelTool(
        "find_email_addresses",
        SCOPE_DISK,
        "our own address extraction plus a context classification that asserts "
        "account ownership the extraction never observed",
    ),
    QuarantinedModelTool(
        "google_drive_sync_events",
        SCOPE_DISK,
        "artifact-specific hand-written parsing of one application's sync log, "
        "with an account list inferred by sweeping the whole text",
    ),
    QuarantinedModelTool(
        "printing_activity_events",
        SCOPE_DISK,
        "artifact-specific parsing of one print server's files that also "
        "synthesizes events from state transitions and ranks them by our rules",
    ),
    QuarantinedModelTool(
        "gcode_metadata",
        SCOPE_DISK,
        "artifact-specific G-code scanning with our own unit inference on the "
        "filament value",
    ),
    QuarantinedModelTool(
        "printing_job_sessions",
        SCOPE_DISK,
        "correlates print events into sessions by an analyst-chosen inactivity "
        "window and links jobs to files by our own basename rule",
    ),
    QuarantinedModelTool(
        "windows_network_config",
        SCOPE_DISK_EXTRACT,
        "joins three registry keys into an adapter inventory and decides by a "
        "hand-written predicate which interfaces exist at all",
    ),
    QuarantinedModelTool(
        "windows_domain_identity",
        SCOPE_DISK_EXTRACT,
        "returns a decoded string our own binary sniffing produced, not the "
        "value the registry parser reported",
    ),
    QuarantinedModelTool(
        "usb_storage_history",
        SCOPE_DISK_EXTRACT,
        "stitches seven registry artifacts into device conclusions and "
        "hand-rolls binary structure parsing; it may return only as an optional "
        "derived analysis with explicit lineage",
    ),
    QuarantinedModelTool(
        "installed_applications",
        SCOPE_DISK_EXTRACT,
        "correlates Uninstall records with Prefetch filenames and applies a "
        "hard-coded anti-forensic executable watchlist",
    ),
    QuarantinedModelTool(
        "windows_local_accounts",
        SCOPE_DISK_EXTRACT,
        "re-parses RegRipper's human-readable report with regexes and derives a "
        "machine SID that samparse never stated",
    ),
    QuarantinedModelTool(
        "reconstruct_http_exfil",
        SCOPE_PCAP,
        "trial-decrypts RC4 keys until the plaintext looks right, which is an "
        "invented conclusion, and writes to an ambient temporary directory",
    ),
    QuarantinedModelTool(
        "read_text_file",
        SCOPE_ALWAYS,
        "takes an arbitrary HOST path with no containment root and duplicates "
        "the in-image read",
    ),
    # Not a withdrawal but a name that was never a tool.  It is carried by the
    # taxonomy, the result-contract data types, the capability map and the
    # classifier, and no binding was ever written for it: no module in this
    # repository has ever defined it, so no surface could offer it and no run
    # could call it.  Recorded here because the alternative is deleting four
    # entries and leaving nothing that says the capability was ever intended;
    # an absence nothing states is exactly how this one survived unnoticed.
    QuarantinedModelTool(
        "vision_read",
        SCOPE_ALWAYS,
        "declared across the tool tables but never implemented: no binding "
        "for it exists, so it has never been callable. Text recognition over "
        "an image is served by ocr_image, which is implemented and offered",
    ),
)

QUARANTINED_MODEL_TOOLS: Mapping[str, QuarantinedModelTool] = MappingProxyType(
    {quarantined.tool_name: quarantined for quarantined in _QUARANTINED}
)

#: The withdrawn names alone, for callers that only need membership.
QUARANTINED_MODEL_TOOL_NAMES: frozenset[str] = frozenset(QUARANTINED_MODEL_TOOLS)


def _backed_by(tool_id: str) -> tuple[str, ...]:
    """Derive the backed function names so the two tables cannot drift."""

    return tuple(
        dependency.tool_name
        for dependency in _DEPENDENCIES
        if any(tool_id in group for group in dependency.requires)
    )


_BACKS: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {spec.id: _backed_by(spec.id) for spec in _SPECS}
)


def _resolve_spec(spec: ExternalToolSpec) -> str | None:
    """Resolve one declared tool to an absolute path, or ``None``.

    This is the ONLY probe in the codebase.  Every surface calls it through
    :func:`tool_availability`, so monkeypatching it in a test changes ``doctor``,
    ``/tools`` and the model-visible registry together, exactly as a real missing
    binary would.
    """

    found = resolve_tool(list(spec.candidates), spec.env_var)
    if found:
        return found
    for candidate in spec.fallback_paths:
        if _is_executable_file(candidate):
            return candidate
    return None


def _hint_for(spec: ExternalToolSpec) -> str:
    if spec.env_var in spec.install_hint:
        return spec.install_hint
    return f"{spec.install_hint}, or set {spec.env_var}"


def tool_availability(tool_id: str) -> ToolAvailability:
    """Resolve one declared external tool by its stable id."""

    spec = EXTERNAL_TOOLS.get(tool_id)
    if spec is None:
        raise KeyError(f"unknown external tool id: {tool_id!r}")
    path = _resolve_spec(spec)
    return ToolAvailability(
        id=spec.id,
        display_name=spec.display_name,
        available=bool(path),
        path=path,
        env_var=spec.env_var,
        reason=(
            ""
            if path
            else (
                f"{spec.display_name} was not found through {spec.env_var}, the "
                "active interpreter's script directory, or PATH"
            )
        ),
        hint=_hint_for(spec),
        doctor_label=spec.doctor_label,
        backs=_BACKS[spec.id],
    )


def available_tools() -> Mapping[str, ToolAvailability]:
    """Resolve every declared external tool, in declaration order.

    Deliberately uncached: an environment-variable override must take effect the
    moment it is set, and resolution is only path arithmetic.
    """

    return MappingProxyType(
        {spec.id: tool_availability(spec.id) for spec in _SPECS}
    )


def tool_path(tool_id: str) -> str | None:
    """Resolved path for one declared tool, or ``None`` when unavailable."""

    return tool_availability(tool_id).path


def _route_is_configured(dependency: ModelToolDependency) -> bool:
    return any(
        (os.environ.get(name) or "").strip()
        for name in dependency.alternate_route_env
    )


def missing_dependencies_for(
    tool_name: str,
    statuses: Mapping[str, ToolAvailability] | None = None,
) -> tuple[ToolAvailability, ...]:
    """Return the unsatisfied external dependencies of a model-visible function.

    An empty result means the function can run: either it declares no external
    dependency, every any-of group is satisfied, or an alternative execution
    route is configured for it.
    """

    dependency = MODEL_TOOL_DEPENDENCIES.get(tool_name)
    if dependency is None or _route_is_configured(dependency):
        return ()
    resolved = statuses if statuses is not None else available_tools()
    missing: list[ToolAvailability] = []
    for group in dependency.requires:
        group_statuses = [resolved[tool_id] for tool_id in group]
        if not any(status.available for status in group_statuses):
            missing.extend(group_statuses)
    return tuple(missing)


def unavailability_result(
    tool_name: str,
    missing: tuple[ToolAvailability, ...],
) -> dict[str, object]:
    """The deterministic structured result a fail-closed function returns.

    It contains no host paths and no timing, so two runs on the same
    configuration produce byte-identical output.
    """

    names = ", ".join(status.display_name for status in missing)
    return {
        "items": [],
        "rows": [],
        "coverage_complete": False,
        "error": {
            "code": "external_tool_unavailable",
            "tool": tool_name,
            "message": (
                f"{tool_name} cannot run: no required external tool is installed "
                f"on this host ({names or 'unknown dependency'}). "
                "No evidence was read."
            ),
            "missing_dependencies": [
                {
                    "id": status.id,
                    "name": status.display_name,
                    "env_var": status.env_var,
                    "reason": status.reason,
                    "hint": status.hint,
                }
                for status in missing
            ],
        },
    }


def dependency_summary(
    tool_name: str,
    statuses: Mapping[str, ToolAvailability] | None = None,
) -> str:
    """One short line describing a function's external backing, for ``/tools``."""

    dependency = MODEL_TOOL_DEPENDENCIES.get(tool_name)
    if dependency is None:
        return ""
    if _route_is_configured(dependency):
        return "container route configured"
    resolved = statuses if statuses is not None else available_tools()
    missing = missing_dependencies_for(tool_name, resolved)
    if missing:
        return "unavailable: " + ", ".join(
            f"{status.display_name} ({status.env_var})" for status in missing
        )
    satisfied = [
        resolved[tool_id].display_name
        for group in dependency.requires
        for tool_id in group
        if resolved[tool_id].available
    ]
    return "ready: " + ", ".join(satisfied)
