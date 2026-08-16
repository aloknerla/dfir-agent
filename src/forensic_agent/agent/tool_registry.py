"""Registry of forensic functions exposed to the language model.

The DEFAULT surface consists of the consolidated domain functions alone — the
typed facades over :mod:`forensic_agent.agent.tool_operations`; no old function
name is reachable on it by any route.  ``include_quarantined_tools=True`` rebuilds
the previous, pre-consolidation surface for a caller reproducing a recorded run.
The quarantine bindings and the tool modules only they imported were removed, so
the full pre-consolidation palette can no longer be rebuilt; the opt-in returns
the legacy surface WITHOUT those withdrawn own-forensic-logic functions.
"""

from __future__ import annotations

import inspect
import os
import time
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from langchain_core.tools import StructuredTool

from forensic_agent.agent.tool_bindings.artifacts import (
    _build_artifact_processors,
    _build_artifact_readers,
)
from forensic_agent.agent.tool_bindings.carving import _build_feature_scan_tools
from forensic_agent.agent.tool_bindings.context import (
    ToolBuildContext,
    _validate_pcap_binding,
)
from forensic_agent.agent.tool_bindings.disk import (
    _build_disk_analysis_tools,
    _build_disk_core_tools,
)
from forensic_agent.agent.tool_bindings.memory import _build_memory_tools
from forensic_agent.agent.tool_bindings.output_guard import _guard_tool_outputs
from forensic_agent.agent.tool_bindings.pcap import _build_pcap_tools
from forensic_agent.agent.tool_bindings.tool_interface import (
    build_domain_facade,
    build_legacy_index,
)
from forensic_agent.agent.tool_bindings.windows import _build_windows_tools
from forensic_agent.agent.tool_operations import (
    DOMAIN_FUNCTIONS,
    LEGACY_FUNCTION_DISPOSITIONS,
    WITHDRAWN_OPERATIONS,
    functions_for_scope,
)
from forensic_agent.core.controlled_scratch import ControlledScratchSession
from forensic_agent.core.storage_containment import (
    EvidenceWriteScope,
    StorageContainmentError,
    acquire_evidence_write_dir,
)
from forensic_agent.core.tool_availability import (
    MODEL_TOOL_DEPENDENCIES,
    QUARANTINED_MODEL_TOOLS,
    SCOPE_ALWAYS,
    SCOPE_DISK,
    SCOPE_DISK_EXTRACT,
    SCOPE_MEMORY,
    SCOPE_PCAP,
    SCOPE_RAW_IMAGE,
    ExternalToolUnavailable,
    ToolAvailability,
    available_tools,
    missing_dependencies_for,
    unavailability_result,
)
from forensic_agent.tools.pcap_sources import PcapSourceCatalog

#: Keep every declared function on the model surface, with its name, description
#: and argument schema preserved byte for byte, and replace only what invoking it
#: does (see :func:`_fail_closed`).  The palette therefore has the same shape on
#: every host, which is what keeps ``tool_registry_sha256`` — and the system
#: prompt digest that the tool names feed — reproducible across the machines a
#: locked evaluation runs on.  This is the default for exactly that reason.
TOOL_EXPOSURE_FAIL_CLOSED = "fail_closed"

#: Withhold a function whose external dependency is missing from the model
#: surface entirely, while still recording it in
#: :attr:`ToolRegistrySnapshot.unavailable`.  This is for the interactive
#: terminal, where an investigator is better served by a model that cannot call
#: what this host cannot run.  It MOVES both the tool-registry digest and the
#: system-prompt digest, so it must never reach a locked evaluation, whose
#: telemetry pins those digests across hosts.
TOOL_EXPOSURE_HIDE_UNAVAILABLE = "hide_unavailable"

_TOOL_EXPOSURES = frozenset({TOOL_EXPOSURE_FAIL_CLOSED, TOOL_EXPOSURE_HIDE_UNAVAILABLE})

#: Parameter through which a registry segment receives the accumulator owned by
#: :func:`_collect`.  See :func:`_appends_into_accumulator`.
_SEGMENT_ACCUMULATOR = "built"

#: Assembly order of the default (domain-facade) surface: evidence-scoped
#: families first, the always-available ones last, mirroring the segment order
#: the previous surface used.
_FACADE_SCOPE_ORDER: tuple[str, ...] = (
    SCOPE_DISK,
    SCOPE_DISK_EXTRACT,
    SCOPE_MEMORY,
    SCOPE_RAW_IMAGE,
    SCOPE_PCAP,
    SCOPE_ALWAYS,
)


def _dependency_named_on_surface(name: str, historical: bool) -> bool:
    """Whether one dependency declaration names a function of the built surface.

    The default surface carries domain-function names only; the historical
    opt-in carries the previous names only (shared names, such as
    ``memory_query``, exist on both).
    """

    if historical:
        return name not in DOMAIN_FUNCTIONS or name in LEGACY_FUNCTION_DISPOSITIONS
    return name in DOMAIN_FUNCTIONS


@dataclass(frozen=True, slots=True)
class UnavailableTool:
    """An explicit record that one function is not usable on the model surface.

    ``exposed`` is ``True`` for the fail-closed case: the function is still
    offered to the model with its real schema, and invoking it returns the
    deterministic :func:`unavailability_result` without touching evidence. It is
    ``False`` when the function is not on the model surface at all — because the
    registry segment never built it, or because the caller asked for
    :data:`TOOL_EXPOSURE_HIDE_UNAVAILABLE`. Recording it here either way is what
    turns that omission from a silent disappearance into an observable decision.

    ``quarantined`` separates the two kinds of absence. A missing binary is a
    property of this host and may be fixed by installing it, which is what
    ``missing`` and ``env_vars`` describe. A quarantined function is absent
    because WE withdrew it from the default surface, so those two are empty and
    ``reason`` states the withdrawal instead.
    """

    name: str
    exposed: bool
    missing: tuple[str, ...]
    env_vars: tuple[str, ...]
    reason: str
    quarantined: bool = False


@dataclass(frozen=True, slots=True)
class ToolRegistrySnapshot:
    """The built registry together with every unavailability it decided on."""

    tools: tuple[StructuredTool, ...]
    unavailable: Mapping[str, UnavailableTool]

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(str(tool.name) for tool in self.tools)


def _record(name: str, exposed: bool, missing: tuple[ToolAvailability, ...]) -> UnavailableTool:
    return UnavailableTool(
        name=name,
        exposed=exposed,
        missing=tuple(status.id for status in missing),
        env_vars=tuple(status.env_var for status in missing),
        reason="; ".join(status.reason for status in missing)
        or f"{name} declared an external dependency that could not be resolved",
    )


def _record_quarantined(name: str) -> UnavailableTool:
    """State that a function was withheld from the default surface, and why."""

    quarantined = QUARANTINED_MODEL_TOOLS[name]
    return UnavailableTool(
        name=name,
        exposed=False,
        missing=(),
        env_vars=(),
        reason=(
            f"{name} is withheld from the default model surface: "
            f"{quarantined.reason}. The historical quarantined bindings that once "
            "rebuilt it were retired when the quarantine surface was removed; no route restores it."
        ),
        quarantined=True,
    )


def _record_withdrawn_operation(key: str) -> UnavailableTool:
    """State that one operation left a facade's enum, and why.

    Recorded under ``function.operation`` because that is what is gone: the
    function is on the surface and every other operation of it still runs. A
    caller reading this learns which call it can no longer make, and which one
    now answers the same question.
    """

    withdrawn = WITHDRAWN_OPERATIONS[key]
    return UnavailableTool(
        name=key,
        exposed=False,
        missing=(),
        env_vars=(),
        reason=(
            f"{key} is withheld from the default model surface: {withdrawn.reason}. "
            f"{withdrawn.function} answers a content search with "
            f"{withdrawn.superseded_by} instead."
        ),
        quarantined=True,
    )


def _fail_closed(
    tool: StructuredTool,
    missing: tuple[ToolAvailability, ...],
    context: ToolBuildContext,
) -> StructuredTool:
    """Return the same tool, with invocation replaced by a structured refusal.

    The name, description and argument schema are preserved byte for byte, so the
    model surface (and anything pinned to its digest) does not change shape when a
    binary happens to be absent. What changes is that calling it can no longer
    reach a subprocess that is not there: it returns one deterministic
    ``external_tool_unavailable`` result and reads no evidence.
    """

    name = str(tool.name)

    def unavailable(**arguments: object) -> dict[str, object]:
        # The call still reaches the activity feed: a refused call that left no
        # trace would be indistinguishable from a call that was never made.
        context.emit(name, arguments, time.time(), refused=True)
        # Rebuilt per call so a caller mutating the result cannot poison the next
        # one, while the value itself stays identical between calls.
        return unavailability_result(name, missing)

    return tool.model_copy(update={"func": unavailable, "coroutine": None})


def _appends_into_accumulator(builder: Callable[..., object]) -> bool:
    """Whether this segment writes into the accumulator instead of returning one.

    A segment declares the accumulator by naming it as a parameter. That is the
    contract by which a segment that builds several functions keeps the ones it
    already produced when a later function in the same segment turns out to have
    no binary behind it.
    """

    try:
        parameters = inspect.signature(builder).parameters
    except (TypeError, ValueError):  # C callables expose no signature
        return False
    return _SEGMENT_ACCUMULATOR in parameters


def _collect(
    builder: Callable[..., list[StructuredTool] | None],
    context: ToolBuildContext,
    unavailable: dict[str, UnavailableTool],
) -> list[StructuredTool]:
    """Run one registry segment, separating unavailability from real defects.

    Only :class:`ExternalToolUnavailable` means "the binary is not installed"; it
    is recorded and the remaining segments still build. Anything else — an
    ``ImportError`` of our own modules, a ``TypeError``, a malformed allowlist —
    is a programming error and propagates, because absorbing it here would hide a
    bug behind an "unavailable tool" message.

    The accumulator belongs to THIS function, not to the segment. A segment that
    builds several functions and only then discovers that one of them has no
    binary behind it keeps the siblings it already produced: discarding the whole
    segment while recording a single name would remove functions whose own
    dependencies are installed, and nothing would say so. A segment keeps its
    partial output by taking the accumulator (:func:`_appends_into_accumulator`)
    or by yielding, since ``extend`` appends as it consumes.
    """

    built: list[StructuredTool] = []
    try:
        if _appends_into_accumulator(builder):
            builder(context, built)
        else:
            produced = builder(context)
            if produced is not None:
                built.extend(produced)
    except ExternalToolUnavailable as declared:
        statuses = available_tools()
        missing = tuple(
            statuses[tool_id] for tool_id in declared.missing if tool_id in statuses
        )
        unavailable[declared.tool_name] = _record(declared.tool_name, False, missing)
    return built


def _scopes_in_play(disk, memory_path, pcap_path) -> frozenset[str]:
    """Which registry segments this build actually assembles.

    It mirrors the gating in :func:`build_tools` below, so a declared function is
    only reported as withheld when its evidence source is present and the
    function is therefore genuinely expected.
    """

    scopes = {SCOPE_ALWAYS}
    if disk is not None:
        scopes.add(SCOPE_DISK)
    if hasattr(disk, "extract_file"):
        scopes.add(SCOPE_DISK_EXTRACT)
    if memory_path:
        scopes.add(SCOPE_MEMORY)
    if disk is not None or memory_path:
        scopes.add(SCOPE_RAW_IMAGE)
    if pcap_path:
        scopes.add(SCOPE_PCAP)
    return frozenset(scopes)


def build_tools(
    disk,
    memory_path: str | None = None,
    pcap_path: str | None = None,
    only: set | None = None,
    on_tool=None,
    controlled_scratch: ControlledScratchSession | None = None,
    tool_argument_allowlists: Mapping[str, Mapping[str, Collection[object]]] | None = None,
    pcap_sources: PcapSourceCatalog | None = None,
    oversight_log=None,
    capture: bool = True,
    project: bool = True,
    tool_exposure: str = TOOL_EXPOSURE_FAIL_CLOSED,
    include_quarantined_tools: bool = False,
    cited_value_resolver=None,
    operator_progress=None,
    memory_sha256: str | None = None,
) -> list:
    """Wrap the forensic tools as LangChain tools bound to this image.

    `only` filters to a subset of tool names. `on_tool(name, args, dt)` (if given)
    fires after each tool call (for live UI activity feeds). `oversight_log` is
    the run's recorder, whose object store retains the complete captured outputs.
    `project=False` defers the model-facing byte boundary to the caller, so a
    standardizer downstream still receives the COMPLETE result.
    `tool_exposure` selects what happens to a function whose external dependency
    is missing; it defaults to the digest-stable :data:`TOOL_EXPOSURE_FAIL_CLOSED`.
    `include_quarantined_tools` rebuilds the historical (pre-consolidation)
    surface a recorded run pins; it defaults to False, so the palette a caller
    gets without asking is the domain-function surface. The quarantine functions
    were removed, so True now returns the legacy surface WITHOUT them (the full
    pre-consolidation palette can no longer be rebuilt).
    `cited_value_resolver` is the run's lineage store: it turns a citation handle
    (invocation id, payload digest, field path) back into the exact earlier
    value, so an operation that consumes a previous result never has to accept
    text the model retyped. Without one, every citing operation refuses.
    `operator_progress` is the console's own progress reporter, bound so an
    operation that takes minutes is visible to the operator while it runs;
    nothing it reports reaches the model or a receipt, and without one those
    operations run silently.
    `memory_sha256` is the content digest of `memory_path`, which the caller
    that opened the case already computed: a whole-image scan of a memory dump
    is reused across runs only when it can be keyed by content, and the dump
    carries no attestation digest to key it by.

    Callers that need to know WHICH functions were failed closed or withheld, and
    why, should use :func:`build_tool_registry` instead; this wrapper returns only
    the tools."""

    return list(
        build_tool_registry(
            disk,
            memory_path=memory_path,
            pcap_path=pcap_path,
            only=only,
            on_tool=on_tool,
            controlled_scratch=controlled_scratch,
            tool_argument_allowlists=tool_argument_allowlists,
            pcap_sources=pcap_sources,
            oversight_log=oversight_log,
            capture=capture,
            project=project,
            tool_exposure=tool_exposure,
            include_quarantined_tools=include_quarantined_tools,
            cited_value_resolver=cited_value_resolver,
            operator_progress=operator_progress,
            memory_sha256=memory_sha256,
        ).tools
    )


def build_tool_registry(
    disk,
    memory_path: str | None = None,
    pcap_path: str | None = None,
    only: set | None = None,
    on_tool=None,
    controlled_scratch: ControlledScratchSession | None = None,
    tool_argument_allowlists: Mapping[str, Mapping[str, Collection[object]]] | None = None,
    pcap_sources: PcapSourceCatalog | None = None,
    oversight_log=None,
    capture: bool = True,
    project: bool = True,
    tool_exposure: str = TOOL_EXPOSURE_FAIL_CLOSED,
    include_quarantined_tools: bool = False,
    cited_value_resolver=None,
    operator_progress=None,
    memory_sha256: str | None = None,
) -> ToolRegistrySnapshot:
    """Build the model-visible registry and report every unavailability it found.

    The DEFAULT build returns the consolidated domain facades only: one function
    per entry in :data:`~forensic_agent.agent.tool_operations.DOMAIN_FUNCTIONS`
    whose evidence scope this binding puts in play.  No function of the previous
    surface is reachable on it under any name.

    External-tool availability is read from the single registry in
    ``core.tool_availability`` — the same one ``doctor`` and ``/tools`` read — so
    the three surfaces cannot disagree about whether a binary is present.

    Under the default :data:`TOOL_EXPOSURE_FAIL_CLOSED`, a function whose declared
    dependency is missing is still exposed with its real schema, but it FAILS
    CLOSED: invoking it returns a deterministic ``external_tool_unavailable``
    result instead of reaching a subprocess that does not exist. Under
    :data:`TOOL_EXPOSURE_HIDE_UNAVAILABLE` it is withheld from the model surface
    instead. A function a segment declined to build at all is recorded in
    ``unavailable`` with ``exposed=False``, so its absence is stated rather than
    silent — and so is a withheld one.

    ``include_quarantined_tools`` is the historical opt-in: it rebuilds the
    previous, pre-consolidation model surface a recorded run pins.  Every function
    declared in :data:`QUARANTINED_MODEL_TOOLS` was removed (its binding and the
    tool modules only it imported), so the full pre-consolidation palette can no
    longer be rebuilt; passing ``True`` returns the legacy surface WITHOUT those
    withdrawn functions.  It defaults to ``False``, and on the default surface
    each withdrawn name is reported in ``unavailable`` with ``quarantined=True``
    and the reason it was withdrawn, so its absence is stated rather than silent."""

    if tool_exposure not in _TOOL_EXPOSURES:
        # Refused before anything is built: a mistyped policy that fell through to
        # the default would silently give a locked evaluation's palette to a
        # caller that asked for the interactive one, or the reverse.
        raise ValueError(f"unknown tool exposure policy: {tool_exposure!r}")
    _validate_pcap_binding(pcap_path, pcap_sources)
    context = ToolBuildContext(
        disk=disk,
        memory_path=memory_path,
        pcap_path=pcap_path,
        controlled_scratch=controlled_scratch,
        tool_argument_allowlists=tool_argument_allowlists,
        pcap_sources=pcap_sources,
        on_tool=on_tool,
        cited_value_resolver=cited_value_resolver,
        operator_progress=operator_progress,
        memory_sha256=memory_sha256,
    )
    tools: list[StructuredTool] = []
    unavailable: dict[str, UnavailableTool] = {}
    scopes = _scopes_in_play(disk, memory_path, pcap_path)

    if not include_quarantined_tools:
        # The default surface: domain facades over one shared legacy index.  The
        # previous surface's implementations stay callable through dispatch but
        # none of their names is exposed, here or anywhere downstream.
        legacy_index = build_legacy_index(context)
        tools.extend(
            build_domain_facade(function.name, context, legacy_index)
            for scope in _FACADE_SCOPE_ORDER
            if scope in scopes
            for function in functions_for_scope(scope)
        )
        # A segment that declined to build keeps its facade on the surface (the
        # facade refuses deterministically at call time), but the absence of a
        # working implementation must be observable in the snapshot too.
        for legacy_name, reason in legacy_index.withheld.items():
            disposition = LEGACY_FUNCTION_DISPOSITIONS.get(legacy_name)
            if disposition is None or disposition.domain_function is None:
                continue
            unavailable[disposition.domain_function] = UnavailableTool(
                name=disposition.domain_function,
                exposed=True,
                missing=(),
                env_vars=(),
                reason=reason,
            )
    else:
        # The historical (pre-consolidation) surface, rebuilt for a caller
        # reproducing a recorded run: the previous standalone functions, byte for
        # byte.  The quarantine bindings and the tool modules only they imported
        # were removed, so the full pre-consolidation palette can no longer be
        # rebuilt; what this returns is the legacy surface WITHOUT the withdrawn
        # own-forensic-logic functions.
        if disk is not None:
            tools.extend(_collect(_build_disk_core_tools, context, unavailable))
            tools.extend(_collect(_build_disk_analysis_tools, context, unavailable))
        if hasattr(disk, "extract_file"):
            tools.extend(_collect(_build_windows_tools, context, unavailable))
        if memory_path:
            tools.extend(_collect(_build_memory_tools, context, unavailable))
        if disk is not None or memory_path:
            # Feature extraction reads raw bytes, so it belongs to whichever raw
            # image the run holds rather than to the disk alone.
            tools.extend(_collect(_build_feature_scan_tools, context, unavailable))

        if pcap_path:
            tools.extend(_collect(_build_pcap_tools, context, unavailable))
        tools.extend(_collect(_build_artifact_readers, context, unavailable))
        tools.extend(_collect(_build_artifact_processors, context, unavailable))

    if only is not None:
        tools = [tool for tool in tools if tool.name in only]

    statuses = available_tools()
    built = {str(tool.name) for tool in tools}
    hide_unavailable = tool_exposure == TOOL_EXPOSURE_HIDE_UNAVAILABLE
    guarded: list[StructuredTool] = []
    for tool in tools:
        name = str(tool.name)
        missing = missing_dependencies_for(name, statuses)
        if not missing:
            guarded.append(tool)
            continue
        unavailable[name] = _record(name, not hide_unavailable, missing)
        if not hide_unavailable:
            guarded.append(_fail_closed(tool, missing, context))
    tools = guarded

    # A segment may decline to construct a function whose binary is absent. That
    # is legitimate, but it must not be invisible: record it against the same
    # dependency table, limited to the evidence bindings this build assembled, to
    # the `only` filter the caller asked for, and to the names the built surface
    # can actually carry — the carving requirement is declared under both its
    # consolidated and its historical name, and reporting the other surface's
    # name would describe a function the model was never offered.
    for name, dependency in MODEL_TOOL_DEPENDENCIES.items():
        if name in built or dependency.scope not in scopes:
            continue
        if not _dependency_named_on_surface(name, include_quarantined_tools):
            continue
        if only is not None and name not in only:
            continue
        missing = missing_dependencies_for(name, statuses)
        if missing:
            unavailable[name] = _record(name, False, missing)

    # A withdrawn function must not simply vanish either. It is recorded last so
    # that the withdrawal, not an incidentally missing binary, is the reason the
    # investigator reads: on the default surface the function would be absent
    # even on a host where every dependency resolves.
    if not include_quarantined_tools:
        for name, quarantined in QUARANTINED_MODEL_TOOLS.items():
            if quarantined.scope not in scopes:
                continue
            if only is not None and name not in only:
                continue
            unavailable[name] = _record_quarantined(name)
        # An operation withdrawn from a facade that IS on the surface would
        # otherwise be the one absence nothing reports: the function is present,
        # every dependency resolves, and only the call itself is gone.
        for key, withdrawn in WITHDRAWN_OPERATIONS.items():
            host = DOMAIN_FUNCTIONS[withdrawn.function]
            if host.scope not in scopes:
                continue
            if only is not None and withdrawn.function not in only:
                continue
            unavailable[key] = _record_withdrawn_operation(key)

    if not capture:
        # The caller owns the whole boundary chain (capture -> oversight ->
        # standardization -> projection) and will apply it to EVERY tool it
        # exposes, including externally supplied ones.  Returning raw tools here
        # keeps that chain in one place instead of capturing twice, projecting
        # early, and leaving external tools uncaptured.
        return ToolRegistrySnapshot(tuple(tools), MappingProxyType(dict(unavailable)))
    return ToolRegistrySnapshot(
        tuple(
            _guard_tool_outputs(
                tools,
                capture_store=full_output_store(oversight_log),
                project=project,
            )
        ),
        MappingProxyType(dict(unavailable)),
    )


def full_output_store(oversight_log):
    """Content-addressed store for complete pre-shaping outputs, or ``None``.

    Takes the run's actual :class:`OversightLog`, so captured outputs land in the
    same object store as the audit chain that binds them.  Deriving it from a
    disk's incidental ``audit`` attribute instead would silently miss the real
    run recorder whenever the two differ.
    """

    root = getattr(oversight_log, "object_store_dir", None)
    if not getattr(oversight_log, "store_full_outputs", False) or not root:
        return None
    from forensic_agent.core.output_capture import FullOutputStore

    # The store retains complete tool outputs, which are evidence content, so its
    # root is classified through the write-scope facade before a store is built
    # over it. A root shared with the host filesystem yields no store rather than
    # a store that would write evidence where the host can reach it; the capture
    # layer then records the digest with storage disabled, exactly as it does
    # when full-output storage is off.
    # Where the audit path itself is host-shared the classification is right and
    # refusing the store outright is wrong: the console keeps its audit records
    # on a bind mount precisely so they survive the container, so on that
    # deployment this refused every store — and a standardized result whose
    # complete output was never retained is refused in turn, which took the whole
    # console down before its first tool call. The bytes move to container-
    # private storage instead, the declared payload root.
    for candidate, subject in (
        (root, "complete tool outputs captured before shaping"),
        (
            _contained_object_store_root(),
            "complete tool outputs captured before shaping, kept off host-shared storage",
        ),
    ):
        if not candidate:
            continue
        try:
            acquire_evidence_write_dir(
                str(candidate),
                subject=subject,
                scope=EvidenceWriteScope.NOT_HOST_SHARED,
            )
        except StorageContainmentError:
            continue
        return FullOutputStore(str(candidate))
    return None


def _contained_object_store_root() -> str | None:
    """Container-private fallback root for retained complete outputs."""

    from forensic_agent.core.storage_containment import payload_scratch_root

    payload_root = payload_scratch_root()
    if payload_root is None:
        return None
    root = os.path.join(str(payload_root), "audit-objects")
    os.makedirs(root, exist_ok=True)
    return root
