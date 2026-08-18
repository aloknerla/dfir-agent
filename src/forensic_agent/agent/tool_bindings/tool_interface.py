"""The model-facing tool interface over the shared operation registry.

Each entry is ONE model-visible function that carries a closed set of typed
operations.  Everything a function states about itself is derived from
:mod:`forensic_agent.agent.tool_operations` — the enum, the argument validation,
the epistemic classification and the description all read the same definitions,
so an operation cannot exist in the code and be missing from the text the model
reads.

The call path is fixed and ordered:

1. **Validate.**  Every call goes through the registry's discriminated argument
   union first.  An unknown operation, a missing required argument, an extra
   argument and an argument belonging to a different operation are all refused
   here, before any evidence is opened and before any external tool could be
   launched — and the refusal is a deterministic structured error, never an
   exception into the agent loop.  The same union is published to the oversight
   gate as :class:`DomainArgumentContract`, so on a supervised surface the
   DECISION is taken there, one call earlier, and a refused call never reaches
   this module at all.  What remains here is the parse a dispatch needs, and the
   belt for a surface no gate is bound to.
2. **Check availability.**  Dependency state is read from the single registry in
   :mod:`forensic_agent.core.tool_availability`, so this surface cannot disagree
   with ``doctor`` or ``/tools`` about whether a binary is present.  A facade
   whose backing is absent keeps its schema and fails closed with the same
   deterministic ``external_tool_unavailable`` result the central guard emits.
3. **Dispatch.**  The validated operation is forwarded to the SAME
   implementation the previous 25-function surface used.  This module is a
   boundary, not a rewrite: read-only access, containment, resource caps and the
   result envelopes all come from those implementations unchanged.

The legacy functions therefore stop being model-visible — a facade build returns
only domain-function names — while remaining callable from the facade.

Backends are declared in the registry and RECORDED from the executed path:
:func:`executed_backend` is the seam a result emitter reads.  For an operation
with one declared producer the answer is that producer; for a fallback set it is
taken from the marker the executed implementation left in its result, and it is
``None`` when the result does not state one — an emitter must treat ``None`` as
"unattested", never fall back to the static table.
"""

from __future__ import annotations

import inspect
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Any

from langchain_core.tools import StructuredTool

from forensic_agent.agent.tool_bindings.artifacts import (
    _build_artifact_processors,
    _build_artifact_readers,
)
from forensic_agent.agent.tool_bindings.carving import (
    _build_feature_scan_tools,
    _build_image_literal_search_tools,
)
from forensic_agent.agent.tool_bindings.context import ToolBuildContext
from forensic_agent.agent.tool_bindings.disk import (
    _build_disk_analysis_tools,
    _build_disk_content_search_tools,
    _build_disk_core_tools,
)
from forensic_agent.agent.tool_bindings.memory import (
    _build_memory_string_search_tools,
    _build_memory_tools,
)
from forensic_agent.agent.tool_bindings.pcap import _build_pcap_tools
from forensic_agent.agent.tool_bindings.reference import (
    _build_hardware_vendor_tools,
)
from forensic_agent.agent.tool_bindings.windows import _build_windows_tools
from forensic_agent.agent.tool_operations import (
    DOMAIN_FUNCTIONS,
    DomainFunction,
    OperationArguments,
    OperationValidationError,
    ToolOperationError,
    argument_guidance,
    function_description,
    functions_for_scope,
    operation_argument_schemas,
    operation_definition,
    validate_operation_arguments,
)
from forensic_agent.core.controlled_scratch import ControlledScratchError
from forensic_agent.core.tool_availability import (
    MODEL_TOOL_DEPENDENCIES,
    SCOPE_ALWAYS,
    SCOPE_DISK,
    SCOPE_DISK_EXTRACT,
    SCOPE_MEMORY,
    SCOPE_PCAP,
    SCOPE_RAW_IMAGE,
    ExternalToolUnavailable,
    missing_dependencies_for,
    unavailability_result,
)
from forensic_agent.oversight.enforcement import ArgumentContract, ArgumentRefusal
from forensic_agent.tools.pcap_sources import PcapSourceSelectionError


class FacadeConfigurationError(ToolOperationError):
    """The dispatch tables disagree with the registry — a programming error."""


# ---------------------------------------------------------------------------
# Deterministic structured refusals.  A facade never raises into the agent
# loop: every refused call returns one of these shapes.
# ---------------------------------------------------------------------------

#: Refusal code for a call the registry's validation rejected.
INVALID_OPERATION_ARGUMENTS = "invalid_operation_arguments"
#: Refusal code shared with the central fail-closed guard.
EXTERNAL_TOOL_UNAVAILABLE = "external_tool_unavailable"
#: Refusal code for a transform whose cited input could not be fetched.
TRANSFORM_CITATION_UNRESOLVED = "transform_citation_unresolved"
#: Refusal code for a capture selector the bound catalog does not know.
UNKNOWN_SOURCE_SELECTOR = "unknown_source_selector"
#: Refusal code for a validated argument the session policy does not permit.
ARGUMENT_OUTSIDE_POLICY = "argument_outside_policy"

#: Argument names that never reach the UI activity feed.  A secret is never sent
#: to a UI: ``password`` for the archive reader, ``passphrase`` for the decode
#: transform.
_FEED_DENYLIST = frozenset({"password", "passphrase"})


def _refusal(tool_name: str, code: str, message: str, **details: Any) -> dict[str, Any]:
    return {
        "error": {"code": code, "tool": tool_name, "message": message[:2000], **details},
        "deterministic_error": True,
    }


def _validation_refusal(
    function: DomainFunction, error: OperationValidationError
) -> dict[str, Any]:
    # The defined operations are repeated in the refusal so the model can
    # self-correct from the error alone instead of re-reading the description.
    # ``guidance`` repeats what the message already leads with, as a list, so a
    # reader acts on the offending field without parsing prose out of a
    # transcript that the message cap may have clipped.
    return _refusal(
        function.name,
        INVALID_OPERATION_ARGUMENTS,
        str(error),
        operations=list(function.operation_names()),
        guidance=argument_guidance(function, error),
    )


def _refusal_guidance(payload: Mapping[str, Any]) -> tuple[str, ...]:
    """The per-field sentences of one refusal payload, for the run's record.

    ``guidance`` is the readable half of a refusal: one line per offending
    field, each read from that field's own schema, with neither the generic
    opening line nor the validator transcript that follow it in ``message``.
    That makes it exactly what an entry's ``reasons`` should lead with, and
    lifting it here means the record quotes the tool rather than paraphrasing
    it.

    Defensive about the shape even though this module writes it: a refusal that
    could not produce guidance still has to reach the gate as a refusal, and
    losing the whole denial to a missing key would be the aid replacing the
    thing it aids.
    """

    error = payload.get("error")
    if not isinstance(error, Mapping):
        return ()
    guidance = error.get("guidance")
    if not isinstance(guidance, Sequence) or isinstance(guidance, (str, bytes)):
        return ()
    return tuple(line for line in guidance if isinstance(line, str) and line.strip())


#: Names the registry function a model-visible tool stands for.  It travels WITH
#: the tool because a surface may be built in one place and supervised in
#: another, and because several of these names are also historical function names
#: with entirely different signatures: matching on the bare name would let the
#: opt-in historical surface be judged against a schema that was never its own.
FACADE_FUNCTION_METADATA_KEY = "domain_function"


@dataclass(frozen=True, slots=True)
class DomainArgumentContract:
    """The registry's argument union, offered to the oversight layer as a gate.

    Validation used to happen one step PAST the decision: the policy approved a
    call, this module then refused its arguments, and the gate had already
    recorded ``allowed`` for a call that never opened anything.  The same union
    answers here before the tool is reached, so one layer decides whether a call
    may proceed and one entry says what became of it.

    The facades keep validating.  They need the validated model to dispatch, and
    a surface supervised by no gate — or by a gate this contract was not bound to
    — must still refuse a malformed call rather than forward it.  What moved is
    the DECISION, not the check: both sides call
    :func:`validate_operation_arguments` over the same union, so they cannot come
    to disagree about one call, and the refusal a caller receives is built by the
    same :func:`_validation_refusal` either way.
    """

    #: Model-visible tool name -> the registry function it stands for.
    functions: Mapping[str, DomainFunction]

    def refusal(
        self, tool: str, args: Mapping[str, Any]
    ) -> ArgumentRefusal | None:
        function = self.functions.get(tool)
        if function is None:
            return None
        try:
            validate_operation_arguments(function, args)
        except OperationValidationError as error:
            payload = _validation_refusal(function, error)
            return ArgumentRefusal(
                code=INVALID_OPERATION_ARGUMENTS,
                output=payload,
                # Read back out of the payload this module has just written,
                # rather than derived a second time: one call to
                # ``argument_guidance`` means the sentence in the run's record
                # and the sentence the model was handed are the same sentence,
                # and neither can be revised without the other.  The read stays
                # inside the module that owns the shape; the gate is given a
                # plain tuple of lines and knows nothing of the payload.
                reasons=_refusal_guidance(payload),
            )
        return None


def domain_argument_contract(
    tools: Iterable[Any],
) -> ArgumentContract | None:
    """The argument contract of exactly the registry facades on one surface.

    Read off the tools themselves rather than off the registry, so the contract
    covers what this surface actually exposes and nothing else.  ``None`` for a
    surface that declares no facade at all: a gate binds a contract only where
    there is one to bind, instead of holding an empty object that answers for
    every tool by saying nothing.
    """

    functions: dict[str, DomainFunction] = {}
    for tool in tools:
        metadata = getattr(tool, "metadata", None)
        declared = (
            metadata.get(FACADE_FUNCTION_METADATA_KEY)
            if isinstance(metadata, Mapping)
            else None
        )
        function = DOMAIN_FUNCTIONS.get(declared) if isinstance(declared, str) else None
        if function is not None:
            functions[str(tool.name)] = function
    return (
        DomainArgumentContract(MappingProxyType(functions)) if functions else None
    )


# ---------------------------------------------------------------------------
# The legacy implementations, indexed once per build.  The previous surface's
# closures are reused verbatim — they are where read-only access, containment,
# clamping and the result envelopes already live — but they are built with a
# muted context so only the facade reports to the activity feed, under the
# domain-function name.
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class LegacyToolIndex:
    """Callable index of the previous surface, plus its declared absences."""

    callables: dict[str, Callable[..., Any]] = field(default_factory=dict)
    #: Legacy name -> the segment's own statement of why it did not build.
    withheld: dict[str, str] = field(default_factory=dict)

    def call(self, name: str, /, **arguments: Any) -> Any:
        return self.callables[name](**arguments)


def _appends_into_accumulator(builder: Callable[..., object]) -> bool:
    """Mirror of the central registry's segment contract.

    A segment that names ``built`` as a parameter writes into the caller's
    accumulator so siblings built before a declared unavailability survive it.
    The convention is defined by ``tool_registry._collect``; reading it the same
    way here keeps one contract instead of two.
    """

    try:
        parameters = inspect.signature(builder).parameters
    except (TypeError, ValueError):
        return False
    return "built" in parameters


def build_legacy_index(context: ToolBuildContext) -> LegacyToolIndex:
    """Build every legacy implementation this evidence binding supports."""

    # Muted feed: the inner closures emit under their legacy names, and a
    # dispatched call must appear in the feed exactly once, as the domain call.
    muted = replace(context, on_tool=None)
    index = LegacyToolIndex()

    def collect(builder: Callable[..., Any]) -> None:
        produced: list[StructuredTool] = []
        try:
            if _appends_into_accumulator(builder):
                builder(muted, produced)
            else:
                returned = builder(muted)
                if returned is not None:
                    produced.extend(returned)
        except ExternalToolUnavailable as declared:
            # Only unavailability is absorbed; any other exception is a defect
            # and must surface, exactly as in the central registry.
            index.withheld[declared.tool_name] = str(declared)
        for tool in produced:
            function = tool.func
            if function is not None:
                index.callables[str(tool.name)] = function

    disk = context.disk
    if disk is not None:
        collect(_build_disk_core_tools)
        collect(_build_disk_analysis_tools)
        # Collected here and nowhere else: the whole-image search has no place
        # in the historical palette, which the registry rebuilds from the two
        # segments above alone.
        collect(_build_disk_content_search_tools)
    if hasattr(disk, "extract_file"):
        collect(_build_windows_tools)
    if context.memory_path:
        collect(_build_memory_tools)
        # Collected here and nowhere else, like the two whole-image searches:
        # the recorded palette is rebuilt from the segment above alone.
        collect(_build_memory_string_search_tools)
    if disk is not None or context.memory_path:
        # The implementation behind the raw-image feature scan, collected on the
        # same condition the facade offers it.
        collect(_build_feature_scan_tools)
        # Collected here and nowhere else, like the disk's whole-image search:
        # the recorded palette is rebuilt from other segments.
        collect(_build_image_literal_search_tools)
    if context.pcap_path:
        collect(_build_pcap_tools)
    collect(_build_artifact_readers)
    collect(_build_hardware_vendor_tools)
    collect(_build_artifact_processors)
    return index


# ---------------------------------------------------------------------------
# Dispatch: one entry per operation, derived from the validated model itself.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class OperationDispatch:
    """Forward one validated operation to one legacy implementation.

    The forwarded keyword set is the validated model's own field set (minus the
    discriminator), so the dispatch cannot smuggle an argument validation never
    saw; ``rename`` and ``fixed`` only translate between the operation's
    vocabulary and the legacy signature.
    """

    target: str
    fixed: Mapping[str, Any] = field(default_factory=dict)
    rename: Mapping[str, str] = field(default_factory=dict)


OperationExecutor = Callable[
    [ToolBuildContext, LegacyToolIndex, OperationArguments], dict[str, Any]
]


@dataclass(frozen=True, slots=True)
class OperationExecution:
    """Run one operation here, carrying the availability declaration a dispatch
    carries in its ``target``.

    An executor exists where no single legacy signature fits, but it reaches an
    implementation all the same, and that implementation is built — or not — by
    the same evidence binding.  ``requires`` names the legacy targets whose build
    state gates it, so ONE belt answers for both kinds of entry: without this the
    two halves of one evidence scope behaved differently, and an executor-served
    operation reached its implementation on a binding that had none.  An empty
    tuple is a positive statement — this executor reaches no evidence binding and
    no external tool — rather than a check that was skipped.
    """

    run: OperationExecutor
    requires: tuple[str, ...] = ()

    def __call__(
        self,
        context: ToolBuildContext,
        legacy: LegacyToolIndex,
        validated: OperationArguments,
    ) -> dict[str, Any]:
        return self.run(context, legacy, validated)


def _forward_arguments(
    validated: OperationArguments, dispatch: OperationDispatch
) -> dict[str, Any]:
    arguments = validated.model_dump(mode="python")
    arguments.pop("operation", None)
    for source_name, target_name in dispatch.rename.items():
        arguments[target_name] = arguments.pop(source_name)
    arguments.update(dispatch.fixed)
    return arguments


def _run_recover_deleted(
    context: ToolBuildContext,
    legacy: LegacyToolIndex,
    validated: OperationArguments,
) -> dict[str, Any]:
    """Both operations of ``recover_deleted``, confined to the TSK view.

    Called directly (not through the legacy closure) because the closure has no
    way to switch the residual FAT scan off, and ruling B1 requires this
    function to expose The Sleuth Kit's view only.  Imported at call time so a
    test can prove that a refused call never reached it.
    """

    del legacy
    from forensic_agent.tools import recover_tool

    arguments = validated.model_dump(mode="python")
    operation = arguments.pop("operation")
    if operation == "recover_content":
        arguments = {"recover": arguments.pop("meta_addr")}
    try:
        return recover_tool.recover_deleted_files(
            context.disk, include_fat_residual=False, **arguments
        )
    except Exception as error:  # mirror the legacy closure's bounded failure
        return {"error": str(error)[:120]}


def _run_hashset_lookup(
    context: ToolBuildContext,
    legacy: LegacyToolIndex,
    validated: OperationArguments,
) -> dict[str, Any]:
    """``host_file_hash.hashset_lookup`` with the reputation verdict withheld.

    The loader admits 32-, 40- and 64-hex digests into the sets while the
    lookup compares SHA-256 only, so ``known_good``/``unknown`` from this path
    is an artefact of a digest-length mismatch, not evidence.  Until that is
    repaired the mapping table withholds the verdict: the digest and the set
    sizes remain, and the withholding says why instead of vanishing silently.
    """

    del context
    result = legacy.call("hash_lookup", path=validated.path)  # type: ignore[attr-defined]
    if not isinstance(result, Mapping) or "status" not in result:
        return dict(result) if isinstance(result, Mapping) else {"error": "hash lookup failed"}
    withheld = {key: value for key, value in result.items() if key != "status"}
    withheld["status_withheld"] = {
        "reason": (
            "the known_good/known_bad/unknown verdict is withheld: the configured "
            "hash sets admit 32-, 40- and 64-hex digests while this lookup compares "
            "SHA-256 only, so the verdict would not be evidence of anything"
        ),
    }
    return withheld


#: Transforms served by the existing decoder exactly as named.  ``filetime``
#: and ``epoch`` are absent deliberately: their previous implementation guessed
#: the input form from length and magnitude, which the consolidation withdrew.
_DECODER_TRANSFORMS = frozenset(
    {"base64", "base32", "hex", "rot13", "url", "utf16le", "gzip"}
)


def _filetime_from_stated_form(value: str, input_form: str) -> dict[str, Any]:
    """Windows FILETIME conversion driven by the STATED form alone.

    The conversion itself is dfdatetime's, the timestamp library the plaso stack
    in this image already runs on, so a converted moment is attributable to a
    component with a release rather than to arithmetic written here.  Reading
    the ticks out of the caller's STATED form is all that happens on this side,
    and the form is required precisely because the previous decoder sniffed it
    from the string length: the same 16 characters convert differently under
    ``hex_le`` and ``decimal_ticks``, and only the caller's statement decides.
    """

    from dfdatetime import filetime as dfdatetime_filetime

    compact = "".join(value.split())
    try:
        if input_form == "hex_le":
            ticks = int.from_bytes(bytes.fromhex(compact), "little")
        else:
            ticks = int(compact, 10)
        moment = dfdatetime_filetime.Filetime(timestamp=ticks).CopyToDateTimeString()
        if not moment:
            raise ValueError("dfdatetime returned no date for this timestamp")
    except Exception:
        return {
            "error": (
                f"the cited value is not readable as a FILETIME in the stated "
                f"form {input_form!r}"
            )
        }
    return {
        "op": "filetime",
        "input_form": input_form,
        "ticks": ticks,
        "backend": "dfdatetime",
        "utc": f"{moment} UTC",
    }


def _epoch_from_stated_unit(value: str, unit: str) -> dict[str, Any]:
    """Unix epoch conversion driven by the STATED unit alone, through dfdatetime.

    The unit selects dfdatetime's own class for that resolution, so neither the
    scale nor the calendar is applied here.
    """

    from dfdatetime import posix_time as dfdatetime_posix

    compact = "".join(value.split())
    try:
        count = int(compact, 10)
        stated = (
            dfdatetime_posix.PosixTimeInMilliseconds(timestamp=count)
            if unit == "milliseconds"
            else dfdatetime_posix.PosixTime(timestamp=count)
        )
        moment = stated.CopyToDateTimeString()
        if not moment:
            raise ValueError("dfdatetime returned no date for this timestamp")
    except Exception:
        return {
            "error": (
                f"the cited value is not readable as a Unix epoch in the stated "
                f"unit {unit!r}"
            )
        }
    return {
        "op": "epoch",
        "unit": unit,
        "epoch": count,
        "backend": "dfdatetime",
        "utc": f"{moment} UTC",
    }


def _run_transform(
    context: ToolBuildContext,
    legacy: LegacyToolIndex,
    validated: OperationArguments,
) -> dict[str, Any]:
    """Every ``transform_query`` operation: resolve the citation, then apply.

    The input is a reference to an earlier result, never retyped text, so the
    value comes from the runtime-owned resolver.  Without one the transform
    refuses before doing anything; the refusal is what keeps a surface with no
    lineage store from quietly accepting model-asserted input.
    """

    del legacy
    arguments = validated.model_dump(mode="python")
    operation = str(arguments["operation"])
    citation = {
        "source_invocation_id": arguments["source_invocation_id"],
        "source_payload_sha256": arguments["source_payload_sha256"],
        "source_field": arguments["source_field"],
    }
    resolver = context.cited_value_resolver
    if resolver is None:
        return _refusal(
            "transform_query",
            TRANSFORM_CITATION_UNRESOLVED,
            "no lineage resolver is bound to this surface, so the cited result "
            "cannot be fetched and nothing was transformed",
            **citation,
        )
    try:
        value = resolver(
            citation["source_invocation_id"],
            citation["source_payload_sha256"],
            citation["source_field"],
        )
    except Exception as error:
        return _refusal(
            "transform_query",
            TRANSFORM_CITATION_UNRESOLVED,
            f"the cited result could not be resolved: {str(error)[:300]}",
            **citation,
        )
    if not isinstance(value, str):
        return _refusal(
            "transform_query",
            TRANSFORM_CITATION_UNRESOLVED,
            "the lineage resolver must return the exact cited text",
            **citation,
        )
    if operation in _DECODER_TRANSFORMS:
        from forensic_agent.tools import decode_tool

        result = dict(decode_tool.decode(value, operation))  # type: ignore[arg-type]
    elif operation == "filetime":
        result = _filetime_from_stated_form(value, str(arguments["input_form"]))
    else:
        result = _epoch_from_stated_unit(value, str(arguments["unit"]))
    # The lineage link travels with the derived value either way, so the result
    # names what it was computed over even when the codec itself failed.
    result["cited_input"] = citation
    return result


def _dispatch(target: str, **fixed: Any) -> OperationDispatch:
    return OperationDispatch(target=target, fixed=MappingProxyType(dict(fixed)))


def _dispatch_renamed(
    target: str, rename: Mapping[str, str], **fixed: Any
) -> OperationDispatch:
    return OperationDispatch(
        target=target,
        fixed=MappingProxyType(dict(fixed)),
        rename=MappingProxyType(dict(rename)),
    )


def _pcap_dispatch(operation: str) -> OperationDispatch:
    # The legacy binding's ``query`` argument IS the operation selector, so the
    # closed enum of pcap operations maps one-to-one onto it.
    return _dispatch("pcap_query", query=operation)


_PCAP_OPERATIONS: tuple[str, ...] = (
    "dns",
    "http",
    "http_auth",
    "ftp",
    "telnet",
    "protocols",
    "conversations",
    "endpoints",
    "stat",
    "fields",
    "dns_exfil",
    "ftp_objects",
    "http_objects",
    "export",
    "follow",
    "cross_capture_linkage",
)

#: One entry per operation of every domain function.  Verified at import
#: against the registry, so an operation cannot exist there and be missing
#: here, and cannot exist here without being defined there.
_DISPATCH_TABLE: Mapping[str, Mapping[str, OperationDispatch | OperationExecution]] = (
    MappingProxyType(
        {
            "filesystem_query": MappingProxyType(
                {
                    "list_directory": _dispatch("list_directory"),
                    "read_file": _dispatch("read_file"),
                    "file_metadata": _dispatch("file_metadata"),
                    "find_files": _dispatch("find_files"),
                    "search_image_content": _dispatch("search_image_content"),
                    "search_in_file": _dispatch("search_in_file"),
                }
            ),
            "recover_deleted": MappingProxyType(
                {
                    # The TSK reader is built by the disk segment under its
                    # historical name; that build state is exactly this
                    # executor's availability, since it reads the same bound
                    # image through the same segment's binding.
                    "list_deleted": OperationExecution(
                        _run_recover_deleted, ("recover_deleted_files",)
                    ),
                    "recover_content": OperationExecution(
                        _run_recover_deleted, ("recover_deleted_files",)
                    ),
                }
            ),
            "bulk_extract": MappingProxyType(
                {
                    "list_features": _dispatch("bulk_extract"),
                    "read_feature": _dispatch("bulk_extract"),
                    "find_literal": _dispatch("find_in_image"),
                }
            ),
            "registry_query": MappingProxyType(
                {
                    # The legacy binding re-validates the operation itself, so it
                    # is forwarded explicitly rather than relied on as a default.
                    "registry_values": _dispatch(
                        "registry_query", operation="registry_values"
                    ),
                    "value_readings": _dispatch(
                        "registry_query", operation="value_readings"
                    ),
                }
            ),
            "registry_ripper": MappingProxyType(
                {
                    "plugin": _dispatch("registry_ripper"),
                    "profile": _dispatch("registry_ripper", plugin=None),
                }
            ),
            "evtx_query": MappingProxyType({"query": _dispatch("evtx_query")}),
            "sqlite_query": MappingProxyType(
                {
                    "schema": _dispatch("sqlite_query"),
                    "table_info": _dispatch("sqlite_query"),
                    "select": _dispatch("sqlite_query"),
                    "pragma": _dispatch_renamed("sqlite_query", {"pragma": "query"}),
                }
            ),
            "archive_query": MappingProxyType(
                {
                    "list": _dispatch("archive_query", action="list"),
                    "extract_inspect": _dispatch("archive_query", action="extract"),
                }
            ),
            # A transform reads no evidence binding and launches nothing: it
            # computes over a value the lineage resolver returns, with the
            # standard library.  Its own gate is that resolver, refused inside
            # the executor, so it requires no built target and says so.
            "transform_query": MappingProxyType(
                {
                    "base64": OperationExecution(_run_transform),
                    "base32": OperationExecution(_run_transform),
                    "hex": OperationExecution(_run_transform),
                    "rot13": OperationExecution(_run_transform),
                    "url": OperationExecution(_run_transform),
                    "utf16le": OperationExecution(_run_transform),
                    "gzip": OperationExecution(_run_transform),
                    "filetime": OperationExecution(_run_transform),
                    "epoch": OperationExecution(_run_transform),
                }
            ),
            "verify_image_integrity": MappingProxyType(
                {"verify_image": _dispatch("verify_image_integrity")}
            ),
            "evidence_file_hash": MappingProxyType(
                {"sha256": _dispatch("evidence_file_hash")}
            ),
            "host_file_hash": MappingProxyType(
                {
                    "sha256": _dispatch("hash_file"),
                    "hashset_lookup": OperationExecution(
                        _run_hashset_lookup, ("hash_lookup",)
                    ),
                }
            ),
            "ocr_image": MappingProxyType({"read_text": _dispatch("ocr_image")}),
            "memory_query": MappingProxyType(
                {
                    operation: _dispatch("memory_query", operation=operation)
                    for operation in (
                        "plugin_rows",
                        "process_parentage",
                        "external_connections",
                        "injection_candidates",
                        "field_distribution",
                    )
                }
            ),
            "memory_malware_scan": MappingProxyType(
                {
                    "scan_pid": _dispatch("memory_malware_scan", scope="pid"),
                    "scan_all_candidates": _dispatch(
                        "memory_malware_scan", scope="all_candidates", pid=None
                    ),
                }
            ),
            "memory_strings": MappingProxyType(
                {"pattern_hits": _dispatch("memory_strings")}
            ),
            "pcap_query": MappingProxyType(
                {operation: _pcap_dispatch(operation) for operation in _PCAP_OPERATIONS}
            ),
            "artifact_reference_query": MappingProxyType(
                {
                    "hardware_vendor": _dispatch("hardware_vendor"),
                }
            ),
        }
    )
)

# ---------------------------------------------------------------------------
# The executed-backend seam.
# ---------------------------------------------------------------------------

#: Marker readers for operations with more than one declared producer.  Each
#: reads the statement the EXECUTED implementation left in its own result.
_EVTX_PARSERS: Mapping[str, str] = MappingProxyType(
    {
        "libyal-pyevtx": "pyevtx",
        "libyal-pyevt": "pyevt",
        "python-evtx": "python_evtx",
    }
)


def _evtx_backend(result: Mapping[str, Any]) -> str | None:
    parser = result.get("parser_backend")
    return _EVTX_PARSERS.get(parser) if isinstance(parser, str) else None


def _archive_backend(result: Mapping[str, Any]) -> str | None:
    # The archive reader states which of py7zr, the stdlib ZIP reader or the
    # 7-Zip subprocess opened the archive, under its own ``engine`` key.  The
    # neighbouring ``format`` key is deliberately NOT consulted: it says what the
    # archive IS, not what read it, and the two diverge in exactly the fallback
    # case this seam exists for (a 7z archive read by the 7-Zip program because
    # py7zr is absent).
    engine = result.get("engine")
    return engine if isinstance(engine, str) else None


_EXECUTED_BACKEND_READERS: Mapping[str, Callable[[Mapping[str, Any]], str | None]] = (
    MappingProxyType(
        {
            "evtx_query": _evtx_backend,
            "archive_query": _archive_backend,
        }
    )
)


def executed_backend(
    function_name: str, operation: str, result: Mapping[str, Any]
) -> str | None:
    """The producer backend the executed path reports for one result.

    This is the recording seam ruling B7 requires: a fallback may reach a
    different tool than the declaration predicts, so a result emitter asks the
    RESULT, not the table.  ``None`` means the executed path did not state its
    backend; an emitter must record that as unattested rather than substitute
    the declaration.  A single-producer operation has no fallback to
    disambiguate, so its sole declared producer is the executed one.
    """

    definition = operation_definition(function_name, operation)
    producers = tuple(
        backend.name for backend in definition.backends if backend.role == "producer"
    )
    if len(producers) == 1:
        return producers[0]
    if not producers:
        return None
    reader = _EXECUTED_BACKEND_READERS.get(function_name)
    if reader is None:
        return None
    reported = reader(result)
    return reported if reported in producers else None


# ---------------------------------------------------------------------------
# Facade construction.
# ---------------------------------------------------------------------------

#: A short, fixed transport note appended to every generated description.  The
#: per-operation argument rosters come from the registry; this only tells the
#: model HOW to pass them.
_TRANSPORT_NOTE = (
    "Pass `operation` plus that operation's own arguments as top-level fields. "
    "An unknown operation, a missing required argument, an extra argument or an "
    "argument belonging to a different operation is refused before any evidence "
    "is read."
)


def _transport_schema(function: DomainFunction) -> dict[str, Any]:
    """The model-facing wire schema, derived from the registry's own union.

    Two things have to hold at once here, and they used to be traded against
    each other.

    **The transport must not judge.**  Declaring the union as a pydantic
    ``args_schema`` would make LangChain validate the call before the facade
    ever saw it, and an invalid call would come back as an exception into the
    agent loop instead of the deterministic structured refusal a facade owes
    its caller.  A JSON-Schema ``args_schema`` is passed to the model and to
    the wrapped function UNVALIDATED (``BaseTool._parse_input`` returns a
    mapping input unchanged when the schema is a dict), so the wire still
    judges nothing and the registry's strict union in
    :func:`validate_operation_arguments` remains the only check.  The schema
    narrows what a model can easily emit; it never becomes the check, and every
    call a provider lets through is still refused here, deterministically.

    **The model must see what it is sending.**  The previous form published one
    nullable ``operation`` string with ``extra='allow'``, so every argument
    name and every value format had to be guessed out of the prose — and a
    guess the strict union then refused cost a whole tool call.  The variants
    below come from :func:`operation_argument_schemas`, i.e. from the SAME
    union the facade validates against, so the published shape and the enforced
    shape cannot drift apart.

    The form is chosen rather than inherited, and it must clear the same wall on
    every provider.  A discriminated union is naturally a top-level ``oneOf``,
    and the previous form kept it as a top-level ``anyOf`` beside the object —
    which OpenAI and DeepSeek tolerate but Anthropic, Google, Bedrock and Azure
    all reject outright (``input_schema does not support oneOf, allOf, or anyOf
    at the top level``).  A schema that only one provider accepts is not a wire;
    it is a lock-in.  The union is therefore FOLDED into one flat object: every
    operation's arguments are merged into a single ``properties`` map, the
    discriminator stays a closed ``enum``, and a field an operation constrains
    differently than its neighbour becomes a NESTED ``anyOf`` (nested unions are
    accepted everywhere — only the top level is refused).

    Folding costs the exact mirror the union gave: a flat object cannot say
    "``key`` is required only for ``value_readings``", so per-operation
    requirements relax to optional on the wire and the required roster is spelled
    into the ``operation`` description instead.  This does not loosen the check.
    The transport never judged; :func:`validate_operation_arguments` did and
    still does, so the schema is a SUPERSET HINT and the strict union remains the
    only judge.  What the fold gives up is the schema's ability to pre-reject
    every ill-formed call before it is sent; what it buys is that the call
    reaches every model at all.
    """

    variants = operation_argument_schemas(function)
    operation_names = list(function.operation_names())

    # Merge each operation's declared arguments into one flat property set.
    required_by_operation: list[str] = []
    property_shapes: dict[str, list[dict[str, Any]]] = {}
    for variant in variants:
        variant_properties = variant.get("properties", {})
        discriminator = variant_properties.get("operation", {})
        operation_const = discriminator.get("const")
        required_here = [
            name for name in variant.get("required", ()) if name != "operation"
        ]
        if operation_const is not None and required_here:
            required_by_operation.append(
                f"{operation_const} needs {', '.join(required_here)}"
            )
        for name, declared in variant_properties.items():
            if name == "operation":
                continue
            shapes = property_shapes.setdefault(name, [])
            declared = dict(declared)
            if declared not in shapes:
                shapes.append(declared)

    merged_properties: dict[str, Any] = {}
    for name, shapes in property_shapes.items():
        # One shape across every operation stays itself; divergent shapes stand
        # beside each other as a nested union, which the top-level rule allows.
        merged_properties[name] = shapes[0] if len(shapes) == 1 else {"anyOf": shapes}

    names = ", ".join(operation_names)
    if function.default_operation is not None:
        operation_text = f"One of: {names}. Omitted, {function.default_operation} runs."
    else:
        operation_text = f"Required. One of: {names}."
    if required_by_operation:
        # The per-operation required roster the flat shape cannot encode is said
        # in words, so the model still reads what each operation needs.
        operation_text += " Required arguments per operation: " + "; ".join(
            required_by_operation
        )

    properties: dict[str, Any] = {
        "operation": {
            "type": "string",
            "enum": operation_names,
            "description": operation_text,
        }
    }
    properties.update(merged_properties)
    schema: dict[str, Any] = {
        "type": "object",
        "properties": properties,
        "additionalProperties": False,
    }
    if function.default_operation is None:
        # Nothing supplies it for the caller, so the schema says so rather than
        # letting an omitted operation look like a legal call.
        schema["required"] = ["operation"]
    return schema


def _argument_policy_rules(
    function: DomainFunction,
    allowlists: Mapping[str, Mapping[str, Any]] | None,
) -> Mapping[str, tuple[str, ...]] | None:
    """Normalize one function's per-argument policy allowlist, or raise.

    The historical bindings narrowed their model-visible schema from the same
    policy input, so a facade must keep both halves of that contract: the
    narrowing is DISCLOSED in the model-visible description and ENFORCED as a
    deterministic refusal after validation.  A malformed rule stays what it was
    before — a configuration error raised at build time — because silently
    dropping a policy restriction would fail open.
    """

    if allowlists is None:
        return None
    rules = allowlists.get(function.name)
    if not rules:
        return None
    known_arguments = {"operation"} | {
        field_name
        for operation in function.operations
        for field_name in operation.arguments.model_fields
    }
    normalized: dict[str, tuple[str, ...]] = {}
    for argument, raw_values in rules.items():
        if argument not in known_arguments:
            raise ValueError(
                f"{function.name} allowlist names unknown argument {argument!r}"
            )
        if raw_values is None or isinstance(raw_values, (str, bytes)):
            raise ValueError(f"{function.name} {argument} allowlist must be a collection")
        values = tuple(
            sorted(
                {
                    value.strip()
                    for value in raw_values
                    if isinstance(value, str) and value.strip()
                }
            )
        )
        if len(values) != len(tuple(raw_values)):
            raise ValueError(f"{function.name} {argument} allowlist is malformed")
        if argument == "operation" and not set(values) <= set(function.operation_names()):
            raise ValueError(
                f"{function.name} operation allowlist names undefined operations"
            )
        normalized[argument] = values
    return MappingProxyType(normalized)


def _policy_refusal(
    function: DomainFunction, argument: str, permitted: tuple[str, ...]
) -> dict[str, Any]:
    # The permitted values are repeated so the model can self-correct from the
    # refusal alone, exactly as the validation refusal repeats the operations.
    return _refusal(
        function.name,
        ARGUMENT_OUTSIDE_POLICY,
        f"the active read-only policy restricts {argument!r}; it permits "
        f"exactly: {', '.join(permitted)}. Nothing was read.",
        argument=argument,
    )


def facade_description(
    function: DomainFunction,
    context: ToolBuildContext,
    policy_rules: Mapping[str, tuple[str, ...]] | None = None,
) -> str:
    """The model-visible text, generated from the registry definitions.

    Only palette-derived material may be appended: the bound capture inventory
    and the active policy restrictions depend on loaded evidence sources and on
    the session policy, never on any question.
    """

    description = f"{function_description(function)}\n\n{_TRANSPORT_NOTE}"
    if policy_rules:
        # The restriction is part of the model-visible surface, so it travels
        # inside the locked registry digest instead of being discovered by
        # refusal at call time.
        restrictions = " ".join(
            f"{argument} permits exactly: {', '.join(values)}."
            for argument, values in sorted(policy_rules.items())
        )
        description += f"\n\nACTIVE POLICY RESTRICTIONS: {restrictions}"
    if function.name == "pcap_query" and context.pcap_sources is not None:
        description += "\n\n" + context.pcap_sources.model_hint()
    return description


def _feed_arguments(validated: OperationArguments) -> dict[str, Any]:
    arguments = validated.model_dump(mode="python")
    return {key: value for key, value in arguments.items() if key not in _FEED_DENYLIST}


def _availability_refusal(
    function: DomainFunction,
    dispatch: OperationDispatch | OperationExecution,
    legacy: LegacyToolIndex,
) -> dict[str, Any] | None:
    """Fail closed, deterministically, before any dispatch.

    The first check reads the SAME dependency table the central registry guard
    and ``doctor`` read.  The second honours a segment's own declaration — an
    absence the dependency table cannot express, such as a missing event-log
    parser binding.  The third is a belt: a dispatch target that simply was not
    built must refuse rather than raise.

    Both kinds of entry state which targets they need — a declarative dispatch in
    its ``target``, an executor in its ``requires`` — so the last two checks run
    for every operation.  They used to be skipped for every executor, which left
    ``recover_deleted`` reaching The Sleuth Kit on a binding that never built it
    while its dfVFS sibling in the same evidence scope refused.
    """

    missing = missing_dependencies_for(function.name)
    if missing:
        return unavailability_result(function.name, missing)
    targets = (
        (dispatch.target,)
        if isinstance(dispatch, OperationDispatch)
        else dispatch.requires
    )
    for target in targets:
        reason = legacy.withheld.get(target)
        if reason is not None:
            return _refusal(
                function.name,
                EXTERNAL_TOOL_UNAVAILABLE,
                f"{function.name} cannot run: {reason}. No evidence was read.",
            )
        if target not in legacy.callables:
            return _refusal(
                function.name,
                EXTERNAL_TOOL_UNAVAILABLE,
                f"{function.name} cannot run: its implementation was not built for "
                "this evidence binding. No evidence was read.",
            )
    return None


def build_domain_facade(
    function_name: str,
    context: ToolBuildContext,
    legacy: LegacyToolIndex | None = None,
) -> StructuredTool:
    """One domain facade, bound to this evidence context."""

    function = DOMAIN_FUNCTIONS[function_name]
    operations = _DISPATCH_TABLE[function.name]
    index = legacy if legacy is not None else build_legacy_index(context)
    policy_rules = _argument_policy_rules(function, context.tool_argument_allowlists)

    def facade(**arguments: Any) -> dict[str, Any]:
        started = time.time()
        try:
            validated = validate_operation_arguments(function, arguments)
        except OperationValidationError as error:
            raw_operation = arguments.get("operation")
            # Only the operation is shown: the rest of the call did not survive
            # validation, so there is no validated form of it to report.  That
            # the call was refused is stated as a refusal, not smuggled in as an
            # argument the model never passed.
            context.emit(
                function.name,
                {"operation": raw_operation if isinstance(raw_operation, str) else None},
                started,
                refused=True,
            )
            return _validation_refusal(function, error)
        operation = str(validated.operation)  # type: ignore[attr-defined]
        if policy_rules is not None:
            # Enforced immediately after validation, before even the
            # availability probe: a policy-refused call must be deterministic
            # in every environment, exactly like the schema narrowing the
            # historical bindings applied.
            dumped = validated.model_dump(mode="python")
            for argument, permitted in policy_rules.items():
                supplied = dumped.get(argument)
                if not isinstance(supplied, str) or supplied not in permitted:
                    context.emit(
                        function.name,
                        _feed_arguments(validated),
                        started,
                        refused=True,
                    )
                    return _policy_refusal(function, argument, permitted)
        dispatch = operations[operation]
        refusal = _availability_refusal(function, dispatch, index)
        if refusal is not None:
            # A refused call still reaches the activity feed: silence here would
            # be indistinguishable from a call that was never made.
            context.emit(
                function.name, _feed_arguments(validated), started, refused=True
            )
            return refusal
        try:
            if isinstance(dispatch, OperationDispatch):
                result = index.call(
                    dispatch.target, **_forward_arguments(validated, dispatch)
                )
            else:
                result = dispatch(context, index, validated)
        except PcapSourceSelectionError as error:
            # Selector resolution is a catalog lookup, refused before any
            # capture file is opened; the legacy schema enum used to catch this.
            result = _refusal(function.name, UNKNOWN_SOURCE_SELECTOR, str(error)[:300])
        except ControlledScratchError:
            # A scratch whose cleanup could not be verified is a containment
            # failure of the RUN, not a routine tool error the model may shrug
            # at.  The legacy closures let it propagate and the facade must
            # not soften that into a structured refusal.
            context.emit(function.name, _feed_arguments(validated), started)
            raise
        except Exception as error:
            result = _refusal(
                function.name,
                f"{function.name}_failed",
                f"{type(error).__name__}: {str(error)[:300]}",
            )
        # Whether the dispatch refused is read off the result, using the marker
        # every refusal in this module already sets, so the feed and the run's
        # own accounting of refusals cannot disagree about one call.
        context.emit(
            function.name,
            _feed_arguments(validated),
            started,
            refused=isinstance(result, Mapping)
            and result.get("deterministic_error") is True,
        )
        return result if isinstance(result, dict) else {"result": result}

    return StructuredTool.from_function(
        facade,
        name=function.name,
        description=facade_description(function, context, policy_rules),
        args_schema=_transport_schema(function),
        # Not model-visible: the OpenAI conversion the registry digest is taken
        # over reads the name, the description and the parameters only.  It says,
        # to the layers this tool passes through, which registry function's
        # argument contract belongs to it.
        metadata={FACADE_FUNCTION_METADATA_KEY: function.name},
    )


#: Build order: evidence-scoped families first, the always-available ones last,
#: mirroring the segment order of the previous surface.
_SCOPE_ORDER: tuple[str, ...] = (
    SCOPE_DISK,
    SCOPE_DISK_EXTRACT,
    SCOPE_MEMORY,
    SCOPE_RAW_IMAGE,
    SCOPE_PCAP,
    SCOPE_ALWAYS,
)


def active_scopes(context: ToolBuildContext) -> frozenset[str]:
    """The evidence scopes this binding puts in play — never question-derived."""

    scopes = {SCOPE_ALWAYS}
    if context.disk is not None:
        scopes.add(SCOPE_DISK)
    if hasattr(context.disk, "extract_file"):
        scopes.add(SCOPE_DISK_EXTRACT)
    if context.memory_path:
        scopes.add(SCOPE_MEMORY)
    if context.pcap_path:
        scopes.add(SCOPE_PCAP)
    if context.disk is not None or context.memory_path:
        # A raw evidence image of either kind: what reads bytes off one reads
        # them off the other.
        scopes.add(SCOPE_RAW_IMAGE)
    return frozenset(scopes)


def build_tool_interface(context: ToolBuildContext) -> list[StructuredTool]:
    """Every domain facade the bound evidence sources support, in stable order.

    The returned surface carries ONLY domain-function names: the previous
    surface's functions are internal here — callable through dispatch, no
    longer model-visible.
    """

    legacy = build_legacy_index(context)
    scopes = active_scopes(context)
    return [
        build_domain_facade(function.name, context, legacy)
        for scope in _SCOPE_ORDER
        if scope in scopes
        for function in functions_for_scope(scope)
    ]


# ---------------------------------------------------------------------------
# Import-time verification: a dispatch table that disagrees with the registry
# is worse than an import error.
# ---------------------------------------------------------------------------


def _verify_facade_tables(
    table: Mapping[str, Mapping[str, OperationDispatch | OperationExecution]] | None = None,
) -> None:
    checked = _DISPATCH_TABLE if table is None else table
    if set(checked) != set(DOMAIN_FUNCTIONS):
        raise FacadeConfigurationError(
            "the dispatch table must cover exactly the registry's domain functions; "
            f"missing: {sorted(set(DOMAIN_FUNCTIONS) - set(checked))}, "
            f"undefined: {sorted(set(checked) - set(DOMAIN_FUNCTIONS))}"
        )
    for name, function in DOMAIN_FUNCTIONS.items():
        entries = checked[name]
        defined = set(function.operation_names())
        if set(entries) != defined:
            raise FacadeConfigurationError(
                f"{name}: dispatch operations must equal the registry's; "
                f"missing: {sorted(defined - set(entries))}, "
                f"undefined: {sorted(set(entries) - defined)}"
            )
        for operation_name, dispatch in entries.items():
            if isinstance(dispatch, OperationDispatch):
                model_fields = set(
                    operation_definition(function, operation_name).arguments.model_fields
                ) - {"operation"}
                unknown = set(dispatch.rename) - model_fields
                if unknown:
                    raise FacadeConfigurationError(
                        f"{name}.{operation_name}: rename source(s) {sorted(unknown)} "
                        "are not fields of the operation's argument model"
                    )
            elif not isinstance(dispatch, OperationExecution):
                # A bare callable would reach the same implementation while
                # stating nothing about what has to be built for it, which is
                # how the availability belt came to have a hole.
                raise FacadeConfigurationError(
                    f"{name}.{operation_name}: dispatch entry is neither a "
                    "declarative dispatch nor a declared executor"
                )
    # Every facade checks the central dependency table under its OWN name, so a
    # facade with an external requirement must be declared there under that name.
    for name in (
        "bulk_extract",
        "registry_ripper",
        "archive_query",
    ):
        if name not in MODEL_TOOL_DEPENDENCIES:
            raise FacadeConfigurationError(
                f"{name}: expected a central dependency declaration under this name"
            )


_verify_facade_tables()


__all__ = [
    "ARGUMENT_OUTSIDE_POLICY",
    "EXTERNAL_TOOL_UNAVAILABLE",
    "FACADE_FUNCTION_METADATA_KEY",
    "INVALID_OPERATION_ARGUMENTS",
    "TRANSFORM_CITATION_UNRESOLVED",
    "UNKNOWN_SOURCE_SELECTOR",
    "DomainArgumentContract",
    "FacadeConfigurationError",
    "LegacyToolIndex",
    "OperationDispatch",
    "OperationExecution",
    "active_scopes",
    "build_domain_facade",
    "build_tool_interface",
    "build_legacy_index",
    "domain_argument_contract",
    "executed_backend",
    "facade_description",
]
