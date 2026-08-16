"""The single shared source of definitions for the consolidated tool surface.

Every consumer of the consolidation — the operation registry, the argument
validation schema, the model-visible description and the epistemic classifier —
reads ONE definition per operation from this module.  Three hand-maintained
copies of "which operations exist and what they take" are exactly what drifted
before; here a domain function declares, once per operation:

* the operation name (a member of that function's closed enum);
* its own argument model, so the permitted and the required arguments follow
  from the operation alone;
* the evidence scope that makes the function available at all;
* the upstream backend(s) the operation reaches, each with its role;
* the epistemic class of the operation's result, and for a DERIVED operation
  the derivation method identifier;
* a short human description usable in the docstring and in ``/tools``.

The discriminated argument union is the heart of the module: each operation owns
a strict (``extra='forbid'``) immutable pydantic model whose ``operation`` field
is the discriminator, so validation itself — not a hand-written check after it —
rejects an unknown operation, a missing required argument, an extra argument,
and an argument that belongs to a different operation.  Validation never touches
evidence or launches a tool, which is what lets a facade refuse a malformed call
before opening anything.

Backends are DECLARED here and RECORDED elsewhere: a definition names the
component(s) an operation can reach, but a fallback may reach a different one
than the table predicts, so the result's ``upstream_backends`` record is built
from the path that actually executed, through
:mod:`forensic_agent.core.backend_versions`.  A declaration with several
producers is a runtime fallback set; an OBSERVED result still names exactly one.

Nothing in this module may depend on a question, a task id or an expected
answer.  Availability derives from ``scope`` plus backend availability alone.

The mapping from the previous 25 model-visible functions is recorded in
:data:`LEGACY_FUNCTION_DISPOSITIONS` so the old-to-new correspondence is a
checkable table rather than folklore.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from functools import cache
from types import MappingProxyType
from typing import Annotated, Any, Literal, get_args

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StringConstraints,
    TypeAdapter,
    ValidationError,
)

from forensic_agent.core.backend_versions import CLI_BACKENDS, PYTHON_BACKENDS
from forensic_agent.core.result_contract import EvidenceClass, PageUnit
from forensic_agent.core.result_navigation import PageContinuation
from forensic_agent.core.tool_availability import (
    SCOPE_ALWAYS,
    SCOPE_DISK,
    SCOPE_DISK_EXTRACT,
    SCOPE_MEMORY,
    SCOPE_PCAP,
    SCOPE_RAW_IMAGE,
)

#: Names the FORM of the model-facing argument schema this registry publishes,
#: and therefore what ``tool_registry_sha256`` is a digest OF.  The first form,
#: ``operation-only-v1``, put a single nullable ``operation`` string on the wire
#: and left every other argument name, pattern and enum inside these models,
#: where the model never saw them; this one publishes the discriminated union
#: itself.  The identifier travels in the model-surface identity record for the
#: same reason ``canonical_json`` does: two digests taken over different surface
#: forms must never be mistaken for one digest that moved.
MODEL_ARGUMENT_SCHEMA_ID = "registry-derived-flat-operation-v3"


class ToolOperationError(ValueError):
    """The operation registry itself is inconsistent — a programming error."""


class UnknownDomainFunctionError(ToolOperationError):
    """A caller named a domain function this registry does not define."""


class OperationValidationError(ToolOperationError):
    """One call's arguments were refused before any evidence was touched."""


# ---------------------------------------------------------------------------
# Backends an operation may declare.
# ---------------------------------------------------------------------------

#: Every backend name a definition may declare.  Anchored to the ids the runtime
#: version registry resolves — and to nothing else, so a declaration the
#: preflight could never attest fails at import instead of at the first emitted
#: result.  The set used to carry a second, "supplementary" half for components
#: the preflight did not inventory (the SQLite engine, the stdlib codecs, the
#: libyal bindings); they are inventoried now, which is what lets this be a
#: single source rather than a declaration and an excuse.
KNOWN_BACKEND_NAMES: frozenset[str] = frozenset(
    {spec.backend for spec in PYTHON_BACKENDS} | {spec.backend for spec in CLI_BACKENDS}
)


@dataclass(frozen=True, slots=True)
class OperationBackend:
    """One component an operation is declared to reach, and its role.

    ``producer`` produced the bytes or records the claim is about; ``support``
    only made the read possible (pyewf presenting a container, dfVFS staging a
    database copy).  Several declared producers mean a runtime fallback set —
    the executed path decides which one a result records, never this table.
    """

    name: str
    role: Literal["producer", "support"]


def _producer(name: str) -> OperationBackend:
    return OperationBackend(name=name, role="producer")


def _support(name: str) -> OperationBackend:
    return OperationBackend(name=name, role="support")


# ---------------------------------------------------------------------------
# Argument models.  One strict model per operation; the operation field is the
# union discriminator, so cross-operation arguments die in validation.
# ---------------------------------------------------------------------------


class OperationArguments(BaseModel):
    """Strict, immutable base for every operation's argument model.

    ``extra='forbid'`` is what makes an argument belonging to another operation
    a validation error rather than silently ignored input; ``frozen=True``
    keeps a validated call immutable on its way to the executor, matching the
    result contract's convention.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)


_NonEmptyText = Annotated[str, StringConstraints(min_length=1)]
#: Digest lengths accepted where an independently published hash is compared.
_HexDigest = Annotated[
    str,
    StringConstraints(pattern=r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$"),
]
_Sha256Hex = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
#: Bounded ISO-8601 date or date-time.  Constraining the shape here is what
#: keeps a crafted bound from editing an engine's own filter expression.
_IsoTimestamp = Annotated[
    str, StringConstraints(pattern=r"^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?Z?)?$")
]
#: Both ends of every time-range filter accept the SAME value — an ISO-8601 date
#: or date-time — so the sentence a refusal reads back is written once here and
#: shared by every time-range filter; only the bound word differs.  The
#: pattern alone showed the model a regex, which it answered by retyping the same
#: rejected shape; a described bound with a concrete example is the correction the
#: regex could not be.
_ISO_LOWER_BOUND_DESCRIPTION = (
    "Lower bound of the event-time window, as an ISO-8601 date (YYYY-MM-DD) or "
    "date-time; a trailing Z marks UTC."
)
_ISO_UPPER_BOUND_DESCRIPTION = (
    "Upper bound of the event-time window, as an ISO-8601 date (YYYY-MM-DD) or "
    "date-time; a trailing Z marks UTC."
)
_ISO_LOWER_BOUND_EXAMPLES = ["2021-04-01", "2021-04-01T14:30:00Z"]
_ISO_UPPER_BOUND_EXAMPLES = ["2021-04-30", "2021-04-30T23:59:59Z"]
#: A registry hive selector, published as a CHOICE rather than as a description
#: of one.  A single regex over a free string is a description: the provider's
#: function-calling layer emits whatever string the model composed and only the
#: validator ever objects, so the prior "a hive is a file" outlives every
#: sentence saying otherwise: a filesystem path arrives here and each such call
#: is refused before touching evidence.  The four machine hives are therefore an
#: enum the layer can only pick a member of.  The user hive cannot be enumerated, because the account
#: names live in the evidence and not in this file, so it stays a string — but
#: one whose ``NTUSER:`` prefix no path satisfies.  What matters is that NO
#: branch admits a path, instead of a sentence asking for none.
#:
#: The NTUSER branch forbids path separators, which is all a pattern can do
#: here: ``..`` is a traversal component that needs none, and the resolver
#: strips the user name, so no pattern could reject ``" .."`` either.
#: Containing the name is therefore the resolver's job, and
#: ``tools.registry_tool._select_profile_directory`` does it by building no path
#: at all: the name only selects among directories the evidence itself declared.
#:
#: The description stays because a choice still has to say what it names: the
#: field beside it describes a "path of one KEY inside the hive", so a caller
#: reading only field names reasonably took this one for the path of the hive
#: FILE.  The enum is what makes that call unsendable; the sentence is what
#: makes the refusal of one act on.
_MachineHive = Literal["SYSTEM", "SOFTWARE", "SAM", "SECURITY"]
_MACHINE_HIVE_NAMES: frozenset[str] = frozenset(get_args(_MachineHive))
_USER_HIVE_PREFIX = "NTUSER:"
_USER_HIVE_PREFIXES = ("NTUSER:", "USRCLASS:")
_UserHive = Annotated[str, StringConstraints(pattern=r"^(?:NTUSER|USRCLASS):[^/\\]+$")]


def _canonical_hive(value: Any) -> Any:
    """Fold the case the superseded pattern folded, before the enum judges.

    That pattern matched case-insensitively, so ``system`` was a legal call; an
    enum is exact, and letting those spellings start failing would be a
    regression bought with nothing.  Only the SYMBOLIC part is folded — whatever
    follows ``NTUSER:`` is an account name taken from the evidence and is passed
    through byte for byte.  Mirrors how ``operation`` is normalized before its
    own discriminator, for the same reason: what validates should be what the
    caller meant, not how they capitalized it.
    """

    if not isinstance(value, str):
        return value
    upper = value.upper()
    if upper in _MACHINE_HIVE_NAMES:
        return upper
    for prefix in _USER_HIVE_PREFIXES:
        if upper.startswith(prefix):
            return prefix + value[len(prefix) :]
    return value


_HiveSelector = Annotated[
    _MachineHive | _UserHive,
    BeforeValidator(_canonical_hive),
    Field(
        description=(
            "Which hive to read, named symbolically. One of: SYSTEM, SOFTWARE, "
            "SAM, SECURITY. For a user hive, write NTUSER: or USRCLASS: followed by "
            "that ACCOUNT NAME — NTUSER:Administrator is that user's HKCU, while "
            "USRCLASS:Administrator is HKCU\\Software\\Classes, which holds the "
            "per-user Explorer ShellBags that record the folders a user browsed. "
            "Never a file name and never a path: the runtime locates and stages the "
            "hive itself."
        ),
        examples=[
            "SYSTEM", "SOFTWARE", "SAM", "SECURITY",
            "NTUSER:Administrator", "USRCLASS:Administrator",
        ],
    ),
]
#: The RegRipper adapter stages a hive by a fixed machine-hive path and has no
#: resolver for a per-user NTUSER hive, so registry_ripper must not advertise
#: one: a selector it can never satisfy would send the model to a refusal.  This
#: is the machine-hive-only counterpart of :data:`_HiveSelector`; the regipy-
#: backed ``registry_query`` keeps the user branch because it stages NTUSER by
#: account name.
_MachineHiveSelector = Annotated[
    _MachineHive,
    BeforeValidator(_canonical_hive),
    Field(
        description=(
            "Which hive to read, named symbolically. One of: SYSTEM, SOFTWARE, "
            "SAM, SECURITY. Never a file name and never a path: the runtime "
            "locates and stages the hive itself."
        ),
        examples=["SYSTEM", "SOFTWARE", "SAM", "SECURITY"],
    ),
]
_TsharkFieldName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._-]{1,128}$")]


# --- filesystem_query (dfVFS, the allocated namespace of the selected filesystem)


class ListDirectoryArguments(OperationArguments):
    operation: Literal["list_directory"] = "list_directory"
    path: str = Field(default="/", min_length=1, description="In-image directory path.")
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=100, ge=1, le=500)
    filter: str | None = Field(
        default=None, description="Literal substring over rows, not a query expression."
    )


class ReadFileArguments(OperationArguments):
    operation: Literal["read_file"] = "read_file"
    path: _NonEmptyText = Field(description="In-image file path.")
    max_bytes: int = Field(default=8192, ge=1, le=10000)
    offset: int = Field(default=0, ge=0)


class FileMetadataArguments(OperationArguments):
    operation: Literal["file_metadata"] = "file_metadata"
    path: _NonEmptyText = Field(description="In-image file path.")


class FindFilesArguments(OperationArguments):
    operation: Literal["find_files"] = "find_files"
    pattern: _NonEmptyText = Field(description="Pattern interpreted per match_mode.")
    start: str = Field(default="/", min_length=1)
    match_mode: Literal["glob", "name", "path"] = "glob"
    case_sensitive: bool = False
    recursive: bool = True
    max_dirs: int = Field(default=1000, ge=1, le=10000)
    max_entries: int = Field(default=10000, ge=1, le=100000)
    max_results: int = Field(default=100, ge=1, le=500)


class SearchKeywordArguments(OperationArguments):
    operation: Literal["search_keyword"] = "search_keyword"
    keyword: _NonEmptyText = Field(description="One literal term, not an expression.")
    max_hits: int = Field(default=20, ge=1)
    start: str = Field(default="/", min_length=1)


#: Hits attributed in one page.  ``offset_attribution`` resolves at most 256
#: distinct offsets per call, so a wider page would return rows the attribution
#: never looked at and could not label.
_IMAGE_SEARCH_PAGE_CAP = 200


class SearchImageContentArguments(OperationArguments):
    operation: Literal["search_image_content"] = "search_image_content"
    keyword: _NonEmptyText = Field(
        description=(
            "One literal term, matched byte for byte across the whole image. Not "
            "a query expression and not a regular expression: a term carrying . "
            "or + matches those characters and nothing wider."
        ),
    )
    max_hits: int = Field(default=20, ge=1, le=_IMAGE_SEARCH_PAGE_CAP)
    start: str = Field(
        default="/",
        min_length=1,
        description=(
            "Absolute directory inside the image. It narrows the RESULT to hits "
            "in files below it and never the coverage, which is always the whole "
            "image; hits it sets aside are counted rather than dropped."
        ),
    )
    offset: int = Field(default=0, ge=0)


class SearchInFileArguments(OperationArguments):
    operation: Literal["search_in_file"] = "search_in_file"
    path: _NonEmptyText = Field(description="In-image file path.")
    term: _NonEmptyText = Field(description="One literal term, not a regular expression.")
    max_hits: int = Field(default=50, ge=1)
    offset: int = Field(default=0, ge=0)


# --- recover_deleted (The Sleuth Kit view only)


class DeletedListingArguments(OperationArguments):
    operation: Literal["list_deleted"] = "list_deleted"
    path: str = Field(default="/", min_length=1)
    recursive: bool = True
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=100, ge=1, le=500)
    filter: str | None = None
    # The traversal bounds are model-visible because the walk opens directories in
    # the filesystem's own order and stops when either is reached.  A result that
    # reports an incomplete enumeration is answerable only by a caller that can
    # raise the bound which stopped it; there is no cursor to resume the walk from.
    max_dirs: int = Field(
        default=800,
        ge=1,
        le=10000,
        description=(
            "Directories the deleted-entry walk may open before it stops. When a "
            "result says it stopped at max_dirs, raise this or scope path to a "
            "subtree — offset pages the rows already collected, not the walk."
        ),
    )
    max_entries: int = Field(
        default=500,
        ge=1,
        le=100000,
        description=(
            "Deleted entries the walk may collect before it stops, counted over the "
            "whole source rather than over one returned page. When a result says it "
            "stopped at max_entries, raise this rather than paging with offset."
        ),
    )


class RecoverContentArguments(OperationArguments):
    operation: Literal["recover_content"] = "recover_content"
    meta_addr: int = Field(
        ge=0, description="TSK metadata address copied from a listed row, never invented."
    )


# --- bulk_extract (bulk_extractor feature files)


class ListFeaturesArguments(OperationArguments):
    operation: Literal["list_features"] = "list_features"


class FindLiteralArguments(OperationArguments):
    operation: Literal["find_literal"] = "find_literal"
    keyword: _NonEmptyText = Field(
        description=(
            "One literal term to find in the image's bytes. Not a regular "
            "expression and not a query expression."
        )
    )
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=100, ge=1)


class ReadFeatureArguments(OperationArguments):
    operation: Literal["read_feature"] = "read_feature"
    feature: _NonEmptyText = Field(
        description="A feature name this scan reported, never a path."
    )
    filter: str | None = None
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=100, ge=1)


# --- registry_query (regipy only; RegRipper stays its own function)


class RegistryValuesArguments(OperationArguments):
    operation: Literal["registry_values"] = "registry_values"
    hive: _HiveSelector
    key: str | None = Field(
        default=None, description="Path of one KEY inside the hive; None runs the plugin sweep."
    )
    depth: int = Field(default=0, ge=0, le=1)
    filter: str | None = None
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=50, ge=1)


class RegistryValueReadingsArguments(OperationArguments):
    operation: Literal["value_readings"] = "value_readings"
    hive: _HiveSelector
    key: _NonEmptyText = Field(
        description="The readings are computed over one named key, so it is required here."
    )
    depth: int = Field(default=0, ge=0, le=1)
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=50, ge=1)


# --- registry_ripper (RegRipper only)

_RegRipperPluginName = Literal[
    "samparse",
    "compname",
    "computername",
    "mountdev",
    "mounteddevices",
    "usbstor",
    "usbdevices",
    "usb",
    "uninstall",
]


class RegRipperPluginArguments(OperationArguments):
    operation: Literal["plugin"] = "plugin"
    hive: _MachineHiveSelector
    plugin: _RegRipperPluginName
    filter: str | None = None
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=200, ge=1)


class RegRipperProfileArguments(OperationArguments):
    operation: Literal["profile"] = "profile"
    hive: _MachineHiveSelector
    filter: str | None = None
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=200, ge=1)


# --- evtx_query (one operation; the parser fallback is disclosed per result)


class EventLogQueryArguments(OperationArguments):
    operation: Literal["query"] = "query"
    log: str = Field(default="Security", min_length=1)
    event_ids: list[int] | None = None
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=30, ge=1, le=1000)
    user: str | None = None
    logon_types: list[int] | None = None
    time_from: _IsoTimestamp | None = Field(
        default=None,
        description=_ISO_LOWER_BOUND_DESCRIPTION,
        examples=_ISO_LOWER_BOUND_EXAMPLES,
    )
    time_to: _IsoTimestamp | None = Field(
        default=None,
        description=_ISO_UPPER_BOUND_DESCRIPTION,
        examples=_ISO_UPPER_BOUND_EXAMPLES,
    )
    order: Literal["asc", "desc"] = "asc"


# --- sqlite_query (stdlib sqlite3 over a sealed in-image copy)


class SqliteSchemaArguments(OperationArguments):
    operation: Literal["schema"] = "schema"
    path: _NonEmptyText = Field(description="In-image database path.")


class SqliteTableInfoArguments(OperationArguments):
    operation: Literal["table_info"] = "table_info"
    path: _NonEmptyText
    table: _NonEmptyText = Field(description="Exact table name from the schema listing.")


class SqliteSelectArguments(OperationArguments):
    operation: Literal["select"] = "select"
    path: _NonEmptyText
    query: _NonEmptyText = Field(
        description="Read-only SQL: SELECT, CTE or EXPLAIN SELECT."
    )
    max_rows: int = Field(default=50, ge=1)


class SqlitePragmaArguments(OperationArguments):
    operation: Literal["pragma"] = "pragma"
    path: _NonEmptyText
    pragma: _NonEmptyText = Field(description="One allowlisted read-only PRAGMA statement.")


# --- archive_query


class ArchiveListArguments(OperationArguments):
    operation: Literal["list"] = "list"
    archive_path: _NonEmptyText
    password: str | None = None
    limit: int = Field(default=60, ge=1)


class ArchiveExtractInspectArguments(OperationArguments):
    operation: Literal["extract_inspect"] = "extract_inspect"
    archive_path: _NonEmptyText
    password: str | None = None
    limit: int = Field(default=60, ge=1)


# --- transform_query (named stdlib transforms over a cited input, never
# retyped text; the hand-written crypto is withdrawn, not re-homed)


#: One citation path: dotted keys with bracketed array indices, rooted at the
#: cited result's own envelope.  Constrained here so a malformed handle is
#: refused in validation, before anything is fetched — and so the model reads
#: the grammar from the schema instead of inferring it.
_CitationFieldPath = Annotated[
    str, StringConstraints(pattern=r"^[A-Za-z_]\w*(?:\[\d+\]|\.[A-Za-z_]\w*)*$")
]


class _TransformArguments(OperationArguments):
    """Common input citation of every transform.

    A transform takes a REFERENCE to a previous result, because retyped text is
    a model assertion rather than evidence: the invocation id names the parent
    call and the digest commits to the exact value taken from it, which is what
    the lineage resolver later verifies.
    """

    source_invocation_id: _NonEmptyText = Field(
        description=(
            "provenance.invocation_id of the earlier result the input value comes "
            "from. Copy it from that result; never compose one."
        )
    )
    source_payload_sha256: _Sha256Hex = Field(
        description=(
            "receipt.payload_sha256 of that result, binding the citation to its "
            "exact content."
        )
    )
    source_field: _CitationFieldPath | None = Field(
        default=None,
        description=(
            "Path to the field holding the value, rooted at the cited result: "
            "dotted keys with bracketed array indices, for example "
            "data.items[3].command_line or data.attributes.content_text. Omit it "
            "only when the result carries exactly one citable value; otherwise "
            "the refusal lists the candidate paths."
        ),
    )


class TransformBase64Arguments(_TransformArguments):
    operation: Literal["base64"] = "base64"


class TransformBase32Arguments(_TransformArguments):
    operation: Literal["base32"] = "base32"


class TransformHexArguments(_TransformArguments):
    operation: Literal["hex"] = "hex"


class TransformRot13Arguments(_TransformArguments):
    operation: Literal["rot13"] = "rot13"


class TransformUrlArguments(_TransformArguments):
    operation: Literal["url"] = "url"


class TransformUtf16leArguments(_TransformArguments):
    operation: Literal["utf16le"] = "utf16le"


class TransformGzipArguments(_TransformArguments):
    operation: Literal["gzip"] = "gzip"


class TransformFiletimeArguments(_TransformArguments):
    operation: Literal["filetime"] = "filetime"
    # Required with no default: the previous implementation sniffed the input
    # form from its length, which is automatic detection under another name.
    input_form: Literal["hex_le", "decimal_ticks"] = Field(
        description="How the FILETIME value is written; stated, never guessed."
    )


class TransformEpochArguments(_TransformArguments):
    operation: Literal["epoch"] = "epoch"
    # Required for the same reason: magnitude sniffing is withdrawn.
    unit: Literal["seconds", "milliseconds"] = Field(
        description="Unit of the epoch value; stated, never guessed from magnitude."
    )


# --- integrity and hashing family (three functions: the container operation
# keeps its no-path design, the in-image hash keeps its validated path, and the
# host-side pair never shares a function with either)


class VerifyImageArguments(OperationArguments):
    operation: Literal["verify_image"] = "verify_image"
    # Deliberately no path argument: the image comes from the open evidence
    # handle, so this operation cannot be aimed at an arbitrary object.
    expected: list[_HexDigest] | None = Field(
        default=None,
        description="Independently published digests to compare against; never inferred.",
    )


class EvidenceFileHashArguments(OperationArguments):
    operation: Literal["sha256"] = "sha256"
    path: _NonEmptyText = Field(description="In-image file path.")


class HostFileHashArguments(OperationArguments):
    operation: Literal["sha256"] = "sha256"
    path: _NonEmptyText = Field(description="Host-side path, outside the evidence chain.")


class HashsetLookupArguments(OperationArguments):
    operation: Literal["hashset_lookup"] = "hashset_lookup"
    path: _NonEmptyText = Field(description="Host-side path, outside the evidence chain.")


# --- ocr_image


class OcrReadTextArguments(OperationArguments):
    operation: Literal["read_text"] = "read_text"
    image_path: _NonEmptyText
    lang: Annotated[str, StringConstraints(pattern=r"^[A-Za-z]{3}(\+[A-Za-z]{3})*$")] = Field(
        default="eng", description="Tesseract language code, for example eng or deu."
    )


# --- memory_query (closed Volatility 3 plugin set; derived computations are
# separate operations asked for by name, never attached to observed rows)

#: The curated plugin set.  Closing the previously open dotted pass-through is
#: part of the consolidation: an operation over an unlisted plugin is refused in
#: validation instead of being forwarded verbatim to the backend.
_MemoryPlugin = Literal[
    "cmdline",
    "dlllist",
    "dumpfiles",
    "filescan",
    "hashdump",
    "hivelist",
    "malfind",
    "netscan",
    "netstat",
    "pslist",
    "psscan",
    "pstree",
]

#: The same curated set as an ordered tuple, DERIVED from the Literal above so the
#: two can no longer be hand-maintained apart — the idiom this module already
#: applies to ``_MACHINE_HIVE_NAMES``.  ``get_args`` preserves declaration order,
#: so any consumer or receipt that pinned the sequence is unaffected.
MEMORY_PLUGINS: tuple[str, ...] = get_args(_MemoryPlugin)


class PluginRowsArguments(OperationArguments):
    operation: Literal["plugin_rows"] = "plugin_rows"
    plugin: _MemoryPlugin
    limit: int = Field(default=50, ge=1)
    offset: int = Field(default=0, ge=0)
    filter: str | None = None


class ProcessParentageArguments(OperationArguments):
    operation: Literal["process_parentage"] = "process_parentage"
    # Only the process listings carry the PPID column the join runs over; the
    # substring filter is absent because a filtered join would make the filter
    # part of the derivation without ever being disclosed.
    plugin: Literal["pslist", "psscan"]
    limit: int = Field(default=50, ge=1)
    offset: int = Field(default=0, ge=0)


class ExternalConnectionsArguments(OperationArguments):
    operation: Literal["external_connections"] = "external_connections"
    plugin: Literal["netscan", "netstat"]
    limit: int = Field(default=50, ge=1)
    offset: int = Field(default=0, ge=0)


class InjectionCandidatesArguments(OperationArguments):
    operation: Literal["injection_candidates"] = "injection_candidates"
    plugin: Literal["malfind"] = "malfind"
    limit: int = Field(default=50, ge=1)
    offset: int = Field(default=0, ge=0)


class FieldDistributionArguments(OperationArguments):
    operation: Literal["field_distribution"] = "field_distribution"
    plugin: _MemoryPlugin
    limit: int = Field(default=50, ge=1)
    offset: int = Field(default=0, ge=0)


# --- memory_malware_scan (its own function)


class MalwareScanPidArguments(OperationArguments):
    operation: Literal["scan_pid"] = "scan_pid"
    pid: int = Field(ge=1, le=0xFFFFFFFF)


class MalwareScanAllCandidatesArguments(OperationArguments):
    operation: Literal["scan_all_candidates"] = "scan_all_candidates"


# --- pcap_query


class _PcapArguments(OperationArguments):
    """Common capture selector.

    ``source`` stays an opaque component id: the facade narrows it to the bound
    catalog's ids at build time (the runtime enum pattern the pcap binding
    already uses), so this static model never names a capture.
    """

    source: str | None = Field(
        default=None, description="Bound capture component id; None selects the default."
    )


class PcapDnsArguments(_PcapArguments):
    operation: Literal["dns"] = "dns"
    limit: int = Field(default=100, ge=1)
    offset: int = Field(default=0, ge=0)
    filter: str | None = None


class PcapHttpArguments(_PcapArguments):
    operation: Literal["http"] = "http"
    limit: int = Field(default=100, ge=1)
    offset: int = Field(default=0, ge=0)
    filter: str | None = None


class PcapHttpAuthArguments(_PcapArguments):
    operation: Literal["http_auth"] = "http_auth"
    limit: int = Field(default=100, ge=1)
    offset: int = Field(default=0, ge=0)
    filter: str | None = None


class PcapFtpArguments(_PcapArguments):
    operation: Literal["ftp"] = "ftp"
    transport: Literal["tcp", "udp"] = "tcp"
    limit: int = Field(default=100, ge=1)
    offset: int = Field(default=0, ge=0)
    filter: str | None = None


class PcapTelnetArguments(_PcapArguments):
    operation: Literal["telnet"] = "telnet"
    transport: Literal["tcp", "udp"] = "tcp"
    limit: int = Field(default=100, ge=1)
    offset: int = Field(default=0, ge=0)
    filter: str | None = None


class PcapProtocolsArguments(_PcapArguments):
    operation: Literal["protocols"] = "protocols"


class PcapConversationsArguments(_PcapArguments):
    operation: Literal["conversations"] = "conversations"


class PcapEndpointsArguments(_PcapArguments):
    operation: Literal["endpoints"] = "endpoints"


class PcapStatArguments(_PcapArguments):
    operation: Literal["stat"] = "stat"
    stat: _NonEmptyText = Field(description='The -z statistic, for example "io,phs".')


class PcapFieldsArguments(_PcapArguments):
    operation: Literal["fields"] = "fields"
    fields: list[_TsharkFieldName] = Field(
        min_length=1,
        description=(
            "One or more tshark field names to extract; each is a protocol.field "
            "token of letters, digits, dots, hyphens or underscores."
        ),
        examples=["dns.qry.name", "ip.src", "http.host"],
    )
    display_filter: str | None = Field(
        default=None, description="Real tshark display-filter syntax."
    )
    limit: int = Field(default=100, ge=1)
    offset: int = Field(default=0, ge=0)
    filter: str | None = None


class PcapDnsExfilArguments(_PcapArguments):
    # No save_path: reconstructed payloads never travel to a model-chosen host
    # location; the previous argument was the one hole in the metadata-only
    # policy and is withdrawn with the consolidation.
    operation: Literal["dns_exfil"] = "dns_exfil"
    transport: Literal["tcp", "udp"] = "tcp"


class PcapFtpObjectsArguments(_PcapArguments):
    operation: Literal["ftp_objects"] = "ftp_objects"
    limit: int = Field(default=100, ge=1)
    offset: int = Field(default=0, ge=0)


class PcapHttpObjectsArguments(_PcapArguments):
    operation: Literal["http_objects"] = "http_objects"
    limit: int = Field(default=100, ge=1)
    offset: int = Field(default=0, ge=0)


class PcapExportArguments(_PcapArguments):
    operation: Literal["export"] = "export"
    # "ftp" is deliberately absent: tshark has no FTP object export, so the FTP
    # route is a different method and lives under its own operation name
    # (ftp_objects) instead of hiding behind this one.
    proto: Literal["dicom", "http", "imf", "smb", "tftp"]
    limit: int = Field(default=100, ge=1)
    offset: int = Field(default=0, ge=0)


class PcapFollowArguments(_PcapArguments):
    operation: Literal["follow"] = "follow"
    stream: int = Field(ge=0)
    transport: Literal["tcp", "udp"] = "tcp"


class CrossCaptureLinkageArguments(OperationArguments):
    # Deliberately no ``source``: this operation reads EVERY bound original
    # capture, and the strict model turns a supplied selector into a validation
    # error instead of a silently ignored argument.
    operation: Literal["cross_capture_linkage"] = "cross_capture_linkage"


# --- artifact_reference_query (generic tables only, never the bound evidence)


#: A hardware address as it is actually written down: hexadecimal digit pairs
#: with any of the four separators in use, or none at all.  The pattern admits
#: every spelling and nothing else — a value carrying a path separator, a shell
#: metacharacter or a word is refused here, before the table is opened.  How MANY
#: digits a lookup needs is not a shape question and stays with the tool, which
#: answers a too-short address with a structured error rather than a refusal.
_HardwareAddress = Annotated[
    str, StringConstraints(pattern=r"^[0-9A-Fa-f][0-9A-Fa-f.:\- ]{4,62}[0-9A-Fa-f]$")
]


class HardwareVendorArguments(OperationArguments):
    operation: Literal["hardware_vendor"] = "hardware_vendor"
    address: _HardwareAddress = Field(
        description=(
            "A hardware address, or just the assignment prefix, written with or "
            "without separators. Take it from a reading of the evidence; this "
            "operation reads no evidence and only maps the prefix to its "
            "registrant."
        ),
        examples=["00:1B:21:3A:4B:5C", "001b21", "00-1B-21-3A-4B-5C"],
    )


# ---------------------------------------------------------------------------
# Definitions.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class OperationNavigation:
    """How one operation is navigated: continued, narrowed, or neither.

    The model works with a result whose whole content never enters its context,
    so the affordances for reaching the rest of that result have to be stated
    rather than guessed from an argument's name.  This declaration is what the
    model-visible description, the agent loop's continuation planner and the
    import-time verification all read, so a continuation the arguments support
    cannot be invisible and one they do not support cannot be advertised.

    ``cursor_argument`` names the argument that resumes a page, and
    ``cursor_unit`` says what it counts.  The unit matters: a byte window and an
    item page both continue "by offset", but feeding one page's item count into
    a byte cursor would skip real content, so a planner compares the unit before
    advancing anything.  ``no_continuation_reason`` is mandatory in its absence,
    because "this operation returns one page" and "someone forgot the offset"
    must not look the same to a reader.

    ``cursor_source`` states WHERE in the previous result the next cursor value
    is written.  Almost every operation continues from the page envelope, and
    :data:`PAGE_CURSOR_SOURCE` is that answer; an operation whose producer
    states its cursor somewhere else says so here rather than letting the
    description promise a field the result does not carry.
    """

    cursor_argument: str | None
    cursor_unit: PageUnit | None
    cursor_source: str | None
    page_size_argument: str | None
    #: Arguments that narrow the result set without changing what is being read.
    #: A caller refines a query by re-issuing it with one of these; an argument
    #: that selects a DIFFERENT object (a path, a hive, a plugin) is not listed,
    #: because changing it asks a different question rather than the same one
    #: more precisely.
    filter_arguments: tuple[str, ...]
    no_continuation_reason: str | None


@dataclass(frozen=True, slots=True)
class OperationDefinition:
    """Everything the consolidation knows about one operation, defined once."""

    name: str
    arguments: type[OperationArguments]
    evidence_class: EvidenceClass
    #: Derivation method identifier; set exactly when the class is DERIVED.
    method: str | None
    method_version: str | None
    #: Declared reachable backends.  The executed path decides what a result
    #: actually records; see :class:`OperationBackend`.
    backends: tuple[OperationBackend, ...]
    description: str
    navigation: OperationNavigation


@dataclass(frozen=True, slots=True)
class OperationClassification:
    """The classifier-consumable projection of one operation's definition."""

    evidence_class: EvidenceClass
    method: str | None
    method_version: str | None


@dataclass(frozen=True, slots=True)
class DomainFunction:
    """One model-visible domain function: a closed set of typed operations."""

    name: str
    #: Evidence scope that makes the function available; never question-derived.
    scope: str
    summary: str
    operations: tuple[OperationDefinition, ...]
    #: Operation assumed when the caller omits ``operation``; None means the
    #: caller must always name one.
    default_operation: str | None = None

    def operation_names(self) -> tuple[str, ...]:
        return tuple(operation.name for operation in self.operations)

    def operation(self, name: str) -> OperationDefinition:
        for operation in self.operations:
            if operation.name == name:
                return operation
        withdrawn = WITHDRAWN_OPERATIONS.get(f"{self.name}.{name}")
        if withdrawn is not None:
            # Withdrawn from the enum, not from the registry.  A run recorded
            # before the withdrawal still has to be classified and attested
            # against the operation it ran; dropping the definition would leave
            # that call with no declared producer and publish it as DIAGNOSTIC,
            # which says something about the run when the only thing that
            # changed is what the model is now handed.
            return withdrawn.definition
        raise OperationValidationError(
            f"{self.name} has no operation {name!r}; defined: {', '.join(self.operation_names())}"
        )


#: Argument names that bound how much ONE call returns, most specific first.
#: The page size is read off the model rather than declared a second time, so an
#: operation cannot advertise a bound it does not accept.
_PAGE_SIZE_ARGUMENTS: tuple[str, ...] = (
    "limit",
    "max_hits",
    "max_rows",
    "max_results",
    "max_files",
    "max_bytes",
)

#: Argument names that narrow the SAME query rather than asking a different one.
_FILTER_ARGUMENTS: tuple[str, ...] = ("filter",)

_SINGLE_CALL_REASON = (
    "no continuation argument is declared: one call returns the whole result "
    "this operation can produce for these arguments"
)

_ARCHIVE_SINGLE_CALL_REASON = (
    "the reader reports the member inventory up to limit in one call; raise "
    "limit rather than asking for a next page"
)


#: The page envelope's own continuation field — where nearly every operation
#: states its next cursor, and the only source the uniform planner reads.
PAGE_CURSOR_SOURCE = "page.next_offset"


def _navigation(
    arguments: type[OperationArguments],
    *,
    cursor: str | None = "offset",
    unit: PageUnit = PageUnit.ITEM,
    source: str = PAGE_CURSOR_SOURCE,
    reason: str | None = None,
) -> OperationNavigation:
    """Derive one operation's navigation from its own argument model.

    Deriving rather than declaring a second time is what keeps the affordance
    and the arguments from drifting: an operation that gains an ``offset`` gains
    a continuation in the same edit, and one that never had a cursor cannot be
    described as continuable.  ``cursor``, ``unit`` and ``reason`` exist for the
    cases the argument names alone cannot settle — a byte window rather than an
    item page, a cursor spelled ``match_offset``, or a bound whose real reason
    for returning one page is worth stating in full.
    """

    fields = arguments.model_fields
    cursor_argument = cursor if cursor is not None and cursor in fields else None
    page_size = next(
        (
            name
            for name in _PAGE_SIZE_ARGUMENTS
            if name in fields and name != cursor_argument
        ),
        None,
    )
    filters = tuple(name for name in _FILTER_ARGUMENTS if name in fields)
    if cursor_argument is None:
        return OperationNavigation(
            cursor_argument=None,
            cursor_unit=None,
            cursor_source=None,
            page_size_argument=page_size,
            filter_arguments=filters,
            no_continuation_reason=reason or _SINGLE_CALL_REASON,
        )
    return OperationNavigation(
        cursor_argument=cursor_argument,
        cursor_unit=unit,
        cursor_source=source,
        page_size_argument=page_size,
        filter_arguments=filters,
        no_continuation_reason=None,
    )


def _observed(
    name: str,
    arguments: type[OperationArguments],
    backends: tuple[OperationBackend, ...],
    description: str,
    *,
    cursor: str | None = "offset",
    unit: PageUnit = PageUnit.ITEM,
    source: str = PAGE_CURSOR_SOURCE,
    reason: str | None = None,
) -> OperationDefinition:
    return OperationDefinition(
        name=name,
        arguments=arguments,
        evidence_class=EvidenceClass.OBSERVED,
        method=None,
        method_version=None,
        backends=backends,
        description=description,
        navigation=_navigation(
            arguments, cursor=cursor, unit=unit, source=source, reason=reason
        ),
    )


def _derived(
    name: str,
    arguments: type[OperationArguments],
    method: str,
    backends: tuple[OperationBackend, ...],
    description: str,
    method_version: str = "1",
    *,
    cursor: str | None = "offset",
    unit: PageUnit = PageUnit.ITEM,
    source: str = PAGE_CURSOR_SOURCE,
    reason: str | None = None,
) -> OperationDefinition:
    return OperationDefinition(
        name=name,
        arguments=arguments,
        evidence_class=EvidenceClass.DERIVED,
        method=method,
        method_version=method_version,
        backends=backends,
        description=description,
        navigation=_navigation(
            arguments, cursor=cursor, unit=unit, source=source, reason=reason
        ),
    )


_DOMAIN_FUNCTIONS: tuple[DomainFunction, ...] = (
    DomainFunction(
        name="filesystem_query",
        scope=SCOPE_DISK,
        summary=(
            "Read the allocated namespace of the selected filesystem through dfVFS: "
            "list, read, describe and find. Content search is the exception and "
            "says so: search_image_content reads the raw image whole, through the "
            "scanner and The Sleuth Kit, and reaches bytes no directory entry "
            "points at. Deleted-entry recovery is a separate function. This is the "
            "general browser of live files; when an answer lives in a structured "
            "store, the specialized reader is faster and more complete than walking "
            "directories by hand: a browser/app SQLite database -> sqlite_query; "
            "the Windows Registry hives -> registry_query; a deleted file or emptied "
            "folder -> recover_deleted. Reach for those before concluding an artifact "
            "is absent."
        ),
        operations=(
            _observed(
                "list_directory",
                ListDirectoryArguments,
                (_producer("dfvfs"),),
                "One page of directory entries exactly as the parser reported them.",
            ),
            _observed(
                "read_file",
                ReadFileArguments,
                (_producer("dfvfs"),),
                "One byte window of one allocated file, paged by offset.",
                # The cursor counts BYTES here.  A planner that advanced it by a
                # returned item count would skip content that was never read.
                unit=PageUnit.BYTE,
            ),
            _observed(
                "file_metadata",
                FileMetadataArguments,
                (_producer("dfvfs"),),
                "Size, timestamps and inode of one file, with per-field timestamp bases.",
            ),
            _derived(
                "find_files",
                FindFilesArguments,
                "filesystem.name_filter",
                (_producer("dfvfs"),),
                "Bounded traversal selecting entries by name or path pattern. Start "
                "from a specific subtree, not the filesystem root: a root-wide walk "
                "is slow and can hit max_dirs before reaching a deep target. When the "
                "artifact type is known, a targeted reader (registry_query, "
                "sqlite_query, recover_deleted) is faster than a broad "
                "name search.",
                reason=(
                    "the traversal is bounded by max_dirs, max_entries and "
                    "max_results and states its own coverage; there is no "
                    "resumable cursor, so raise a bound or narrow pattern/start "
                    "rather than asking for a next page"
                ),
            ),
            _derived(
                "search_image_content",
                SearchImageContentArguments,
                "image.literal_content_scan",
                # The scanner is the producer and The Sleuth Kit is declared as
                # support, although both run and neither is optional.  A second
                # declared PRODUCER means a runtime fallback set here, and two
                # candidates with no marker to choose between them leave the
                # producer unestablished, which would publish every hit as
                # DIAGNOSTIC.  Support records the component all the same, so
                # both names reach the result, and neither is dfVFS: this
                # operation does not walk the file system at all.
                (_producer("bulk_extractor"), _support("sleuthkit")),
                "Whole-image literal scan; each hit names the file holding those "
                "bytes, or states that none does.",
            ),
            _derived(
                "search_in_file",
                SearchInFileArguments,
                "filesystem.in_file_search",
                (_producer("dfvfs"),),
                "Literal-term match over the first window of one file.",
            ),
        ),
    ),
    DomainFunction(
        name="recover_deleted",
        scope=SCOPE_DISK,
        summary=(
            "The Sleuth Kit's view of deleted entries: unallocated directory names, "
            "the $OrphanFiles listing where TSK exposes it, and content read-back "
            "for an entry TSK still holds metadata for. Nothing here is carved and "
            "nothing rests on this project's own filesystem parsing."
        ),
        operations=(
            _derived(
                "list_deleted",
                DeletedListingArguments,
                "filesystem.tsk_deleted_listing",
                (_producer("sleuthkit"), _support("pytsk3"), _support("libewf")),
                "Deleted-name rows from TSK's breadth-first walk; membership is bounded "
                "by max_dirs and max_entries, and the result says which bound stopped it.",
            ),
            _derived(
                "recover_content",
                RecoverContentArguments,
                "filesystem.tsk_recovery",
                (_producer("sleuthkit"), _support("pytsk3"), _support("libewf")),
                "Content, digests and preview of one TSK-recoverable entry.",
            ),
        ),
    ),
    DomainFunction(
        name="bulk_extract",
        scope=SCOPE_RAW_IMAGE,
        summary=(
            "bulk_extractor feature files over the raw image, allocated and "
            "unallocated alike: list what one scan produced, then read one "
            "feature file verbatim. The scan reads the whole image and takes "
            "minutes; use it for an image-wide sweep of scattered indicators "
            "(e-mail addresses, URLs, PII across unallocated space), not to re-find "
            "data a structured reader (registry_query, sqlite_query, "
            "recover_deleted) has already returned."
        ),
        operations=(
            _observed(
                "list_features",
                ListFeaturesArguments,
                (_producer("bulk_extractor"),),
                "The feature names this scan produced.",
            ),
            _observed(
                "read_feature",
                ReadFeatureArguments,
                (_producer("bulk_extractor"),),
                "Rows of one feature file in the scanner's documented layout.",
            ),
            _observed(
                "find_literal",
                FindLiteralArguments,
                (_producer("bulk_extractor"),),
                "Literal-term matches from the image's bytes, each with its offset "
                "and surrounding context. The result is a bounded page: on a common "
                "term the remainder is withheld, so page it to exhaustion or narrow "
                "the term before treating an absence or a count as complete. For a "
                "known kind of value such as an email address, URL, or domain, the "
                "deduplicated feature files (list_features, read_feature) are the "
                "encoding-robust source.",
            ),
        ),
    ),
    DomainFunction(
        name="registry_query",
        scope=SCOPE_DISK_EXTRACT,
        summary=(
            "regipy over one staged hive: plugin rows and raw key values as the "
            "parser reported them, and — only when asked by name — this project's "
            "readings of what those bytes may encode. RegRipper is a different "
            "backend and stays a different function."
        ),
        operations=(
            _observed(
                "registry_values",
                RegistryValuesArguments,
                (_producer("regipy"),),
                "Plugin rows or one key's values, exactly as regipy reported them.",
            ),
            _derived(
                "value_readings",
                RegistryValueReadingsArguments,
                "registry.value_readings",
                (_producer("regipy"),),
                "Readings (epoch, FILETIME, UTF-16LE text) computed over one key's bytes.",
            ),
        ),
        default_operation="registry_values",
    ),
    DomainFunction(
        name="registry_ripper",
        scope=SCOPE_DISK_EXTRACT,
        summary=(
            "RegRipper over one staged hive, verbatim: one named plugin or the "
            "hive's full profile. Kept apart from regipy so no envelope ever "
            "stands for two registry parsers."
        ),
        operations=(
            _observed(
                "plugin",
                RegRipperPluginArguments,
                (_producer("regripper"),),
                "One RegRipper plugin's report lines, unparsed.",
            ),
            _observed(
                "profile",
                RegRipperProfileArguments,
                (_producer("regripper"),),
                "The hive profile's report lines across its plugins, unparsed.",
            ),
        ),
    ),
    DomainFunction(
        name="evtx_query",
        scope=SCOPE_DISK_EXTRACT,
        summary=(
            "Windows event logs, modern EVTX or legacy EVT, through the first "
            "available parser binding; the caller cannot pick the backend and "
            "every result names the one that ran."
        ),
        operations=(
            _observed(
                "query",
                EventLogQueryArguments,
                (_producer("pyevtx"), _producer("pyevt"), _producer("python_evtx")),
                "Filtered, paged event records from one log file.",
            ),
        ),
        default_operation="query",
    ),
    DomainFunction(
        name="sqlite_query",
        scope=SCOPE_DISK,
        summary=(
            "Read-only stdlib SQLite over a sealed byte-for-byte copy of one "
            "in-image database: schema listing, one object's description, "
            "restricted SELECT, or an allowlisted PRAGMA. The executed operation "
            "is echoed into the result."
        ),
        operations=(
            _observed(
                "schema",
                SqliteSchemaArguments,
                (_producer("cpython_sqlite3"), _support("dfvfs")),
                "The database schema listing from sqlite_schema.",
            ),
            _observed(
                "table_info",
                SqliteTableInfoArguments,
                (_producer("cpython_sqlite3"), _support("dfvfs")),
                "Columns and indexes of one named object.",
            ),
            _observed(
                "select",
                SqliteSelectArguments,
                (_producer("cpython_sqlite3"), _support("dfvfs")),
                "Rows of one restricted read-only SELECT, executed by SQLite itself.",
                reason=(
                    "paging belongs inside the statement here: SQLite orders and "
                    "windows rows itself through LIMIT/OFFSET, and max_rows bounds "
                    "what one call returns"
                ),
            ),
            _observed(
                "pragma",
                SqlitePragmaArguments,
                (_producer("cpython_sqlite3"), _support("dfvfs")),
                "Output of one allowlisted read-only PRAGMA over the sealed copy.",
            ),
        ),
    ),
    DomainFunction(
        name="archive_query",
        scope=SCOPE_ALWAYS,
        summary=(
            "Archives: the member inventory an upstream reader reports, and — as "
            "a separate DERIVED operation — bounded characterization of extracted "
            "members. The two never share a result: declared size and "
            "post-extraction size are different claims."
        ),
        operations=(
            _observed(
                "list",
                ArchiveListArguments,
                (_producer("py7zr"), _producer("cpython_zipfile"), _producer("seven_zip")),
                "The archive's declared member inventory; the executed reader is recorded.",
                reason=_ARCHIVE_SINGLE_CALL_REASON,
            ),
            _derived(
                "extract_inspect",
                ArchiveExtractInspectArguments,
                "archive.extract_inspection",
                (_producer("py7zr"), _producer("cpython_zipfile")),
                "Types, sizes and string samples computed over ephemerally extracted members.",
                reason=_ARCHIVE_SINGLE_CALL_REASON,
            ),
        ),
        default_operation="list",
    ),
    DomainFunction(
        name="transform_query",
        scope=SCOPE_ALWAYS,
        summary=(
            "Explicit deterministic transformations, performed by the chepy "
            "decoder and by dfDateTime, over a cited earlier result. The input is a HANDLE, never "
            "retyped text: source_invocation_id plus source_payload_sha256 name "
            "the earlier call and commit to its content, and source_field is the "
            "path to the value inside it. No detection of any kind; the caller "
            "states the scheme, the form and the unit. The hand-written RC4, XOR "
            "and key-derivation code is withdrawn, not relocated."
        ),
        operations=(
            _derived(
                "base64",
                TransformBase64Arguments,
                "transform.base64",
                (_producer("chepy"),),
                "Base64 decoding of the cited value.",
            ),
            _derived(
                "base32",
                TransformBase32Arguments,
                "transform.base32",
                (_producer("chepy"),),
                "Base32 decoding of the cited value.",
            ),
            _derived(
                "hex",
                TransformHexArguments,
                "transform.hex",
                (_producer("chepy"),),
                "Hexadecimal decoding of the cited value.",
            ),
            _derived(
                "rot13",
                TransformRot13Arguments,
                "transform.rot13",
                (_producer("chepy"),),
                "ROT13 rotation of the cited value.",
            ),
            _derived(
                "url",
                TransformUrlArguments,
                "transform.url",
                (_producer("chepy"),),
                "URL percent-decoding of the cited value.",
            ),
            _derived(
                "utf16le",
                TransformUtf16leArguments,
                "transform.utf16le",
                (_producer("chepy"),),
                "UTF-16LE decoding of the cited value.",
            ),
            _derived(
                "gzip",
                TransformGzipArguments,
                "transform.gzip",
                (_producer("chepy"),),
                "gzip decompression of the cited value.",
            ),
            _derived(
                "filetime",
                TransformFiletimeArguments,
                "transform.filetime",
                (_producer("dfdatetime"),),
                "Windows FILETIME conversion; the input form is stated, never sniffed.",
            ),
            _derived(
                "epoch",
                TransformEpochArguments,
                "transform.epoch",
                (_producer("dfdatetime"),),
                "Unix epoch conversion; the unit is stated, never sniffed.",
            ),
        ),
    ),
    DomainFunction(
        name="verify_image_integrity",
        scope=SCOPE_DISK,
        summary=(
            "Whole-container integrity: digests of the decoded media, the stored "
            "acquisition hash where the container carries one, and the comparison "
            "verdict. Takes no path by design, so it cannot be aimed at an "
            "arbitrary object."
        ),
        operations=(
            _derived(
                "verify_image",
                VerifyImageArguments,
                "evidence.integrity_compare",
                (_producer("libewf"), _support("cpython_hashlib")),
                "Computed media digests compared against stored or published ones.",
            ),
        ),
        default_operation="verify_image",
    ),
    DomainFunction(
        name="evidence_file_hash",
        scope=SCOPE_DISK,
        summary=(
            "SHA-256 and exact size over every byte of one file inside the "
            "evidence image, path-validated and capped; never shares a result "
            "shape with any host-side hash."
        ),
        operations=(
            _derived(
                "sha256",
                EvidenceFileHashArguments,
                "hash.sha256",
                (_producer("dfvfs"), _support("cpython_hashlib")),
                "Full-content digest of one in-image file, fail-closed on any gap.",
            ),
        ),
        default_operation="sha256",
    ),
    DomainFunction(
        name="host_file_hash",
        scope=SCOPE_ALWAYS,
        summary=(
            "Digests and hash-set classification of HOST-side files, outside the "
            "evidence chain, and each result says so. Kept away from every "
            "evidence-reading function so a digest's origin is never ambiguous."
        ),
        operations=(
            _derived(
                "sha256",
                HostFileHashArguments,
                "hash.host_file_sha256",
                (_producer("cpython_stdlib"), _support("cpython_hashlib")),
                "Digest and size of one host-side file.",
            ),
            _derived(
                "hashset_lookup",
                HashsetLookupArguments,
                "hashset.classification",
                (_producer("cpython_stdlib"), _support("cpython_hashlib")),
                "Digest membership in the configured hash sets, naming each set.",
            ),
        ),
    ),
    DomainFunction(
        name="ocr_image",
        scope=SCOPE_ALWAYS,
        summary=(
            "Tesseract text recognition over one image file; the reading is a "
            "derived selection among candidate passes and is labelled as such."
        ),
        operations=(
            _derived(
                "read_text",
                OcrReadTextArguments,
                "image.ocr",
                (_producer("tesseract"),),
                "Recognized text from one image, with the pass selection disclosed.",
            ),
        ),
        default_operation="read_text",
    ),
    DomainFunction(
        name="memory_query",
        scope=SCOPE_MEMORY,
        summary=(
            "Volatility 3 over the bound memory image: the rows one curated "
            "plugin emitted, and — as separate operations asked for by name — "
            "computations this project performs over those rows. No computed "
            "value ever travels inside an observed row."
        ),
        operations=(
            _observed(
                "plugin_rows",
                PluginRowsArguments,
                (_producer("volatility3"),),
                "The rows one plugin emitted, and nothing else.",
            ),
            _derived(
                "process_parentage",
                ProcessParentageArguments,
                "memory.process_parentage_join",
                (_producer("volatility3"),),
                "PPID-to-PID join over one process listing's rows.",
            ),
            _derived(
                "external_connections",
                ExternalConnectionsArguments,
                "memory.external_connection_filter",
                (_producer("volatility3"),),
                "Rows whose foreign address is outside this tool's local-address set.",
            ),
            _derived(
                "injection_candidates",
                InjectionCandidatesArguments,
                "memory.injection_candidate_summary",
                (_producer("volatility3"),),
                "Per-process grouping and count of malfind's regions.",
            ),
            _derived(
                "field_distribution",
                FieldDistributionArguments,
                "memory.row_field_distribution",
                (_producer("volatility3"),),
                "Value distribution of each low-cardinality field over the full row set.",
            ),
        ),
        default_operation="plugin_rows",
    ),
    DomainFunction(
        name="memory_malware_scan",
        scope=SCOPE_MEMORY,
        summary=(
            "Signature scan of dumped executable memory regions: Volatility "
            "malfind supplies the candidates, ClamAV supplies the verdicts, and "
            "the correlation is DERIVED by construction. Never an operation of "
            "memory_query: two backends, a different provenance, an opposite "
            "failure policy."
        ),
        # Two components run, and the roles say which one the CLAIM is about.
        # Several producers mean a runtime fallback set here (see
        # :class:`OperationBackend`), and these two are a pipeline rather than
        # alternatives: Volatility stages the regions the scan reads, exactly as
        # dfVFS stages a database copy, and ClamAV produces the detections the
        # result reports.  Declaring both as producers made this the one
        # operation whose executed producer could never be named at all, because
        # the recording seam had a fallback marker to read and no fallback.
        operations=(
            _derived(
                "scan_pid",
                MalwareScanPidArguments,
                "memory.signature_scan",
                (_producer("clamav"), _support("volatility3")),
                "Scan the dumped regions of one named process.",
            ),
            _derived(
                "scan_all_candidates",
                MalwareScanAllCandidatesArguments,
                "memory.signature_scan",
                (_producer("clamav"), _support("volatility3")),
                "Scan and rank the complete bounded candidate population.",
            ),
        ),
    ),
    DomainFunction(
        name="pcap_query",
        scope=SCOPE_PCAP,
        summary=(
            "tshark over one bound capture, with every operation classified "
            "DERIVED because this project's code runs over the tshark output. "
            "cross_capture_linkage alone reads all bound captures and refuses a "
            "source selector."
        ),
        operations=(
            _derived(
                "dns",
                PcapDnsArguments,
                "network.dns_summary",
                (_producer("tshark"),),
                "DNS field rows with name-frequency summaries.",
            ),
            _derived(
                "http",
                PcapHttpArguments,
                "network.http_summary",
                (_producer("tshark"),),
                "HTTP request field rows.",
            ),
            _derived(
                "http_auth",
                PcapHttpAuthArguments,
                "network.http_auth_extraction",
                (_producer("tshark"),),
                "HTTP Authorization header values from request records.",
            ),
            _derived(
                "ftp",
                PcapFtpArguments,
                "network.ftp_session_summary",
                (_producer("tshark"),),
                "FTP field rows with a deterministic session summary.",
            ),
            _derived(
                "telnet",
                PcapTelnetArguments,
                "network.telnet_session_reconstruction",
                (_producer("tshark"),),
                "Telnet field rows with session reconstruction.",
            ),
            _derived(
                "protocols",
                PcapProtocolsArguments,
                "network.protocol_hierarchy",
                (_producer("tshark"),),
                "The protocol hierarchy statistic.",
            ),
            _derived(
                "conversations",
                PcapConversationsArguments,
                "network.conversations",
                (_producer("tshark"),),
                "The IP conversations statistic.",
            ),
            _derived(
                "endpoints",
                PcapEndpointsArguments,
                "network.endpoints",
                (_producer("tshark"),),
                "The IP endpoints statistic.",
            ),
            _derived(
                "stat",
                PcapStatArguments,
                "network.tshark_statistic",
                (_producer("tshark"),),
                "One caller-named -z statistic.",
            ),
            _derived(
                "fields",
                PcapFieldsArguments,
                "network.field_extraction_with_roles",
                (_producer("tshark"),),
                "Named field extraction with endpoint roles where both ends are selected.",
            ),
            _derived(
                "dns_exfil",
                PcapDnsExfilArguments,
                "network.dns_exfil_reconstruction",
                (_producer("tshark"),),
                "Reassembly of chunked DNS query payloads. The reconstructed bytes "
                "ARE written to run-controlled storage and the result names that "
                "file in saved_to, so they can be opened with the archive, carving "
                "or text tools rather than existing only in this result.",
            ),
            _derived(
                "ftp_objects",
                PcapFtpObjectsArguments,
                "network.ftp_object_reconstruction",
                (
                    _producer("tshark"),
                    _support("py7zr"),
                    _support("cpython_zipfile"),
                    _support("seven_zip"),
                ),
                "FTP data-stream reassembly — a different method from export, named apart.",
            ),
            _derived(
                "http_objects",
                PcapHttpObjectsArguments,
                "network.http_object_reconstruction",
                (_producer("tshark"), _support("pefile")),
                "HTTP object export metadata with bounded static summaries.",
            ),
            _derived(
                "export",
                PcapExportArguments,
                "network.object_export",
                (_producer("tshark"), _support("pefile")),
                "tshark --export-objects metadata for the protocols tshark implements.",
            ),
            _derived(
                "follow",
                PcapFollowArguments,
                "network.stream_follow_reconstruction",
                (_producer("tshark"),),
                "Reassembly of one selected TCP or UDP stream.",
            ),
            _derived(
                "cross_capture_linkage",
                CrossCaptureLinkageArguments,
                "network.cross_capture_correlation",
                (_producer("tshark"),),
                "Link-layer and same-side associations across ALL bound captures.",
            ),
        ),
        default_operation="dns",
    ),
    DomainFunction(
        name="artifact_reference_query",
        scope=SCOPE_ALWAYS,
        summary=(
            "Lookup in a generic table, never case evidence: which organisation "
            "registered a hardware-address prefix. It does not open the bound "
            "evidence and cannot back a case claim on its own — it names the "
            "table that answered."
        ),
        operations=(
            # OBSERVED rather than DERIVED: nothing here is computed over a
            # reading.  The organisation's name is a row the table already
            # holds, selected by the longest prefix the registry assigns, and
            # returned as the table wrote it.  And OBSERVED rather than
            # REFERENCE, which its sibling carries: a REFERENCE operation names
            # no component because our own shipped corpus has none to name,
            # while this answer comes from a package the version registry
            # inventories — declaring that component is what lets a reading be
            # tied to the table version that produced it, and a class that
            # attests nothing would throw that away.  What keeps the answer out
            # of the case record is not the class but the function it belongs
            # to: nothing here opens the bound evidence.
            _observed(
                "hardware_vendor",
                HardwareVendorArguments,
                (_producer("tshark"),),
                "The organisation registered for one hardware-address prefix, from "
                "the packet analyser's shipped table, with that table's digest. A "
                "prefix the table does not assign comes back unassigned, which is a "
                "fact about the registry and not about the adapter.",
                reason=(
                    "one prefix has one registrant; the whole answer is the row "
                    "the table holds for it"
                ),
            ),
        ),
        default_operation="hardware_vendor",
    ),
)

DOMAIN_FUNCTIONS: Mapping[str, DomainFunction] = MappingProxyType(
    {function.name: function for function in _DOMAIN_FUNCTIONS}
)


# ---------------------------------------------------------------------------
# Operations withdrawn from the model-visible enum, and why.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class WithdrawnOperation:
    """One operation removed from a domain function's enum, and why.

    The counterpart of
    :data:`~forensic_agent.core.tool_availability.QUARANTINED_MODEL_TOOLS` one
    level down: that table withdraws a whole function from the default surface,
    this one withdraws a single operation from a function that stays.  What the
    record removes is the operation's place in the enum a model is handed — its
    DEFINITION stays here, because a recorded call still has to be classified
    and attested against the operation it ran, and because a withdrawal nothing
    declares is indistinguishable from a capability quietly deleted.
    """

    #: Domain function the operation was withdrawn from.
    function: str
    definition: OperationDefinition
    #: The operation that now answers the question this one answered. Required:
    #: a withdrawal with no successor is a capability removal and belongs in the
    #: legacy disposition's ``withdrawn`` list instead.
    superseded_by: str
    #: Why it was withdrawn, in one sentence, stated to the investigator.
    reason: str

    @property
    def key(self) -> str:
        return f"{self.function}.{self.definition.name}"


_WITHDRAWN_OPERATIONS: tuple[WithdrawnOperation, ...] = (
    WithdrawnOperation(
        function="filesystem_query",
        # Byte for byte the definition this operation carried while it was
        # offered, so a call recorded under it attests dfVFS and classifies as
        # the keyword scan it was, exactly as before.
        definition=_derived(
            "search_keyword",
            SearchKeywordArguments,
            "filesystem.keyword_scan",
            (_producer("dfvfs"),),
            "Bounded scan matching one literal term in names and contents.",
            reason=(
                "a bounded, non-resumable source scan: when it stops early it "
                "reports incomplete coverage instead of offering a next page, "
                "so narrow start or raise max_hits"
            ),
        ),
        superseded_by="search_image_content",
        reason=(
            "its tree walk read the first 32 KiB of at most 1200 files under at "
            "most 800 directories — on the graded evidence under one percent of "
            "the image — and neither bound was reachable from the model, so a "
            "run told its coverage was incomplete could only re-scan subtrees by "
            "hand until its step budget was gone. It was withdrawn rather than "
            "offered alongside its successor because a measured run given both, "
            "and told which was which, still reached for this one"
        ),
    ),
)

WITHDRAWN_OPERATIONS: Mapping[str, WithdrawnOperation] = MappingProxyType(
    {withdrawn.key: withdrawn for withdrawn in _WITHDRAWN_OPERATIONS}
)


# ---------------------------------------------------------------------------
# The mapping from the previous model surface, as a checkable table.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LegacyDisposition:
    """Where one previous model-visible function went, and what was withdrawn."""

    legacy_name: str
    status: Literal["operation", "internal", "quarantined"]
    domain_function: str | None
    operations: tuple[str, ...]
    #: Capabilities of the legacy function that do NOT survive, each with the
    #: ruling that removed it.  Empty when everything carried over.
    withdrawn: tuple[str, ...] = ()


_LEGACY_DISPOSITIONS: tuple[LegacyDisposition, ...] = (
    LegacyDisposition("list_directory", "operation", "filesystem_query", ("list_directory",)),
    LegacyDisposition("read_file", "operation", "filesystem_query", ("read_file",)),
    LegacyDisposition("file_metadata", "operation", "filesystem_query", ("file_metadata",)),
    LegacyDisposition("find_files", "operation", "filesystem_query", ("find_files",)),
    LegacyDisposition(
        "search_keyword",
        "operation",
        "filesystem_query",
        ("search_keyword",),
        withdrawn=(
            "its place in the model-visible enum: the operation is declared in "
            "WITHDRAWN_OPERATIONS and the default surface answers a content "
            "search with search_image_content, which scans the whole image "
            "instead of walking part of the allocated namespace",
        ),
    ),
    LegacyDisposition("search_in_file", "operation", "filesystem_query", ("search_in_file",)),
    LegacyDisposition(
        "recover_deleted_files",
        "operation",
        "recover_deleted",
        ("list_deleted", "recover_content"),
        withdrawn=(
            "the residual FAT listing and recover_ids read-back: our own FAT parser, "
            "quarantined as an experimental derived scan per ruling B1, exposed "
            "neither to the model nor to evaluation",
        ),
    ),
    LegacyDisposition(
        "bulk_extract", "operation", "bulk_extract", ("list_features", "read_feature")
    ),
    LegacyDisposition(
        "registry_query",
        "operation",
        "registry_query",
        ("registry_values", "value_readings"),
    ),
    LegacyDisposition("registry_ripper", "operation", "registry_ripper", ("plugin", "profile")),
    LegacyDisposition("evtx_query", "operation", "evtx_query", ("query",)),
    LegacyDisposition(
        "sqlite_query",
        "operation",
        "sqlite_query",
        ("schema", "table_info", "select", "pragma"),
    ),
    LegacyDisposition(
        "archive_query", "operation", "archive_query", ("list", "extract_inspect")
    ),
    LegacyDisposition(
        "decode",
        "operation",
        "transform_query",
        (
            "base64",
            "base32",
            "hex",
            "rot13",
            "url",
            "utf16le",
            "gzip",
            "filetime",
            "epoch",
        ),
        withdrawn=(
            "rc4 and xor operations and the kdf argument: hand-written cryptography, "
            "withdrawn per ruling B3 until a vetted library or external tool provides them",
            "retyped-text input: a transform now cites a previous result instead",
        ),
    ),
    LegacyDisposition(
        "verify_image_integrity", "operation", "verify_image_integrity", ("verify_image",)
    ),
    LegacyDisposition("evidence_file_hash", "operation", "evidence_file_hash", ("sha256",)),
    LegacyDisposition("hash_file", "operation", "host_file_hash", ("sha256",)),
    LegacyDisposition(
        "hash_lookup",
        "operation",
        "host_file_hash",
        ("hashset_lookup",),
        withdrawn=(
            "the three-way verdict is withheld until the digest-length lookup defect "
            "is repaired; until then a lookup names its sets and their digests only",
        ),
    ),
    LegacyDisposition("ocr_image", "operation", "ocr_image", ("read_text",)),
    LegacyDisposition(
        "memory_query",
        "operation",
        "memory_query",
        (
            "plugin_rows",
            "process_parentage",
            "external_connections",
            "injection_candidates",
            "field_distribution",
        ),
        withdrawn=(
            "the dotted plugin pass-through: the plugin set is closed to the curated "
            "names so validation can refuse an unlisted plugin before the backend runs",
        ),
    ),
    LegacyDisposition(
        "memory_malware_scan",
        "operation",
        "memory_malware_scan",
        ("scan_pid", "scan_all_candidates"),
    ),
    LegacyDisposition(
        "pcap_query",
        "operation",
        "pcap_query",
        (
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
        ),
        withdrawn=(
            "save_path and metadata_only arguments: reconstructed payloads never reach "
            "a model-chosen host location, closing the dns_exfil policy hole",
            "export proto='ftp': the FTP route is a different method and is served "
            "solely by its own operation, ftp_objects",
        ),
    ),
)

LEGACY_FUNCTION_DISPOSITIONS: Mapping[str, LegacyDisposition] = MappingProxyType(
    {disposition.legacy_name: disposition for disposition in _LEGACY_DISPOSITIONS}
)


# ---------------------------------------------------------------------------
# Derived artefacts: the enum, the validator, the classification table and the
# description all read the same definitions, so they cannot drift.
# ---------------------------------------------------------------------------

_EVIDENCE_SCOPES: frozenset[str] = frozenset(
    {
        SCOPE_ALWAYS,
        SCOPE_DISK,
        SCOPE_DISK_EXTRACT,
        SCOPE_MEMORY,
        SCOPE_PCAP,
        SCOPE_RAW_IMAGE,
    }
)


def _resolve(function: str | DomainFunction) -> DomainFunction:
    if isinstance(function, DomainFunction):
        return function
    resolved = DOMAIN_FUNCTIONS.get(function)
    if resolved is None:
        raise UnknownDomainFunctionError(
            f"no domain function named {function!r} is defined"
        )
    return resolved


@cache
def _adapter_for(function: DomainFunction) -> TypeAdapter[Any]:
    """Build the discriminated argument union for one function, once.

    The union is derived from the operation definitions themselves — never a
    second hand-written list — so adding an operation to a definition is the
    single edit that extends the enum, the validator, the classification table
    and the description together.
    """

    members = tuple(operation.arguments for operation in function.operations)
    if len(members) == 1:
        return TypeAdapter(members[0])
    union: Any = members[0]
    for member in members[1:]:
        union = union | member
    return TypeAdapter(Annotated[union, Field(discriminator="operation")])


def _inline_refs(node: Any, definitions: Mapping[str, Any]) -> Any:
    """Resolve every ``$ref`` against ``definitions``, leaving nothing dangling.

    A variant is lifted out of the union's ``$defs`` and has to stand on its
    own afterwards, because the model-facing schema carries no ``$defs`` to
    resolve against — and a reference nothing resolves is worse than a missing
    constraint: a reader cannot tell that anything is missing at all.
    """

    if isinstance(node, Mapping):
        reference = node.get("$ref")
        if isinstance(reference, str):
            name = reference.rsplit("/", 1)[-1]
            if name not in definitions:
                raise ToolOperationError(f"argument schema reference {reference!r} is unresolved")
            return _inline_refs(definitions[name], definitions)
        return {key: _inline_refs(value, definitions) for key, value in node.items()}
    if isinstance(node, list):
        return [_inline_refs(item, definitions) for item in node]
    return node


def _without_generated_titles(variant: Any) -> dict[str, Any]:
    """One operation's schema without the titles pydantic generated for it.

    The ``title`` of the variant itself and of each declared property is dropped;
    nothing nested inside a property is touched, so a constraint that happens to
    live under ``anyOf`` keeps everything it states.
    """

    schema = {key: value for key, value in variant.items() if key != "title"}
    properties = schema.get("properties")
    if isinstance(properties, Mapping):
        schema["properties"] = {
            name: (
                {key: value for key, value in declared.items() if key != "title"}
                if isinstance(declared, Mapping)
                else declared
            )
            for name, declared in properties.items()
        }
    return schema


def operation_argument_schemas(
    function: str | DomainFunction,
) -> tuple[dict[str, Any], ...]:
    """One standalone JSON Schema per operation, in the registry's own order.

    Taken from the SAME :func:`_adapter_for` union the facade validates against,
    so the shape a model reads and the shape a call is judged by cannot come to
    disagree: there is one source, and both sides read it.  Each member arrives
    exactly as its strict model declares it — ``additionalProperties: false``
    from ``extra='forbid'``, the ``Literal`` discriminator as a ``const``, the
    ``StringConstraints`` patterns, the field descriptions and their examples,
    and the required set that follows from the fields themselves.

    The generated ``title`` is dropped, and only that.  It is pydantic's
    rendering of a Python identifier — the argument model's class name, the
    field's attribute name — and this surface names an operation and its
    arguments, never our classes: a model shown ``RegistryValuesArguments``
    learns a name it cannot use anywhere.  Every declared key survives, and no
    field is named ``title``, so nothing an operation states is lost with it.
    """

    resolved = _resolve(function)
    schema = dict(_adapter_for(resolved).json_schema())
    definitions = schema.pop("$defs", {})
    members = schema.get("oneOf") or schema.get("anyOf") or [schema]
    variants = tuple(
        _without_generated_titles(_inline_refs(member, definitions)) for member in members
    )
    if len(variants) != len(resolved.operations):
        raise ToolOperationError(
            f"{resolved.name}: the argument union published "
            f"{len(variants)} variants for {len(resolved.operations)} operations"
        )
    return variants


def domain_function(name: str) -> DomainFunction:
    """The definition of one domain function, or raise."""

    return _resolve(name)


def domain_function_names() -> tuple[str, ...]:
    return tuple(DOMAIN_FUNCTIONS)


def functions_for_scope(scope: str) -> tuple[DomainFunction, ...]:
    """Every domain function one evidence scope makes available.

    This is the palette seam: availability derives from bound evidence sources
    and backend availability only, never from a question.
    """

    return tuple(
        function for function in DOMAIN_FUNCTIONS.values() if function.scope == scope
    )


def operation_names(function: str | DomainFunction) -> tuple[str, ...]:
    """The closed operation enum of one domain function."""

    return _resolve(function).operation_names()


def operation_definition(
    function: str | DomainFunction, operation: str
) -> OperationDefinition:
    """One operation's full definition — the seam emitters read backends from."""

    return _resolve(function).operation(operation)


def classification_table(
    function: str | DomainFunction,
) -> Mapping[str, OperationClassification]:
    """The per-operation classification table, derived from the definitions.

    Shaped for :mod:`forensic_agent.agent.evidence_classification`: the
    classifier maps these entries onto its own ``Classification`` objects, so an
    operation added here is classified without a second registration anywhere.
    """

    resolved = _resolve(function)
    return MappingProxyType(
        {
            operation.name: OperationClassification(
                evidence_class=operation.evidence_class,
                method=operation.method,
                method_version=operation.method_version,
            )
            for operation in resolved.operations
        }
    )


def validate_operation_arguments(
    function: str | DomainFunction,
    arguments: Mapping[str, Any] | None,
) -> OperationArguments:
    """Validate one call against the function's discriminated union, or raise.

    Pure validation: no evidence is opened and no external tool is launched, so
    a facade can call this first and refuse a malformed call before touching
    anything.  The function's declared default operation is applied when the
    caller omits ``operation``; every other failure — an unknown operation, a
    missing required argument, an extra argument, an argument belonging to a
    different operation — surfaces as :class:`OperationValidationError` with
    the pydantic error chained for detail.  That refusal is the only thing a
    caller learns from a rejected call, so it LEADS with
    :func:`argument_guidance` and keeps the validator transcript underneath.
    """

    resolved = _resolve(function)
    if arguments is None:
        data: dict[str, Any] = {}
    elif isinstance(arguments, Mapping):
        data = dict(arguments)
    else:
        raise OperationValidationError(
            f"{resolved.name} arguments must be a mapping, not {type(arguments).__name__}"
        )
    raw_operation = data.get("operation")
    if raw_operation in (None, ""):
        if resolved.default_operation is None:
            raise OperationValidationError(
                f"{resolved.name} requires an explicit operation; "
                f"defined: {', '.join(resolved.operation_names())}"
            )
        data["operation"] = resolved.default_operation
    elif isinstance(raw_operation, str):
        # Mirrors the classifier's normalization so the operation that validates
        # is byte-identical to the operation that classifies.
        data["operation"] = raw_operation.strip().casefold()
    try:
        validated = _adapter_for(resolved).validate_python(data)
    except ValidationError as error:
        # Guidance first, validator transcript last: the model reads the top of
        # the message and acts on it, and a regex is not an instruction.
        raise OperationValidationError(
            "\n".join(
                (
                    f"{resolved.name} arguments were refused before any evidence access.",
                    *argument_guidance(resolved, error),
                    f"Validator detail: {error}",
                )
            )
        ) from error
    return validated


def argument_guidance(
    function: str | DomainFunction,
    refused: Mapping[str, Any] | BaseException | None,
) -> list[str]:
    """What the fields of one refused call actually accept, one line per field.

    Every sentence here is READ from ``model_fields`` at refusal time — the
    offending field's own ``description`` and ``examples``, reached through the
    discriminated union's tag — and none of it is written down a second time
    beside the schema.  A transcribed copy of the rules would keep answering
    after the schema had moved on, and the model would then be corrected towards
    a form the tool no longer takes; the only sentence that cannot say that is
    the one the validator itself is enforcing.

    ``refused`` is the call in whichever form the caller holds it: the arguments
    that were rejected, or the refusal raised for them (a facade has only the
    error).  Anything this function cannot resolve — an unknown function, a
    refusal with no validator behind it, an error location naming no field —
    yields no line for that error rather than an exception, because guidance is
    an aid to a refusal and must never be able to replace it with a crash.
    """

    try:
        resolved = _resolve(function)
    except UnknownDomainFunctionError:
        return []
    detail = _validator_error(resolved, refused)
    if detail is None:
        return []
    lines: list[str] = []
    try:
        by_tag = _models_by_tag(resolved)
        for entry in detail.errors():
            location = tuple(entry.get("loc", ()))
            # A pydantic location mixes field names with sequence indices; only a
            # name can be a discriminator tag, so an index is not offered to the
            # tag map as if it might match one.
            head = location[0] if location else None
            if isinstance(head, str) and head in by_tag:
                model, rest = by_tag[head], location[1:]
            elif len(by_tag) == 1:
                model, rest = next(iter(by_tag.values())), location
            else:
                # A failed discriminator has no member model to read from; the
                # tags themselves are the only thing left to say.
                model, rest = None, ()
            field_name = str(rest[0]) if rest else "operation"
            line = _field_guidance(resolved, model, field_name)
            if line is not None and line not in lines:
                lines.append(line)
    except Exception:  # pragma: no cover - defensive: a refusal outranks its aid
        return lines
    return lines


def _validator_error(
    function: DomainFunction, refused: Mapping[str, Any] | BaseException | None
) -> ValidationError | None:
    """The pydantic error behind a refused call, however the caller holds it."""

    if isinstance(refused, ValidationError):
        return refused
    if isinstance(refused, BaseException):
        # ``validate_operation_arguments`` chains it; its other refusals — a
        # non-mapping payload, a missing default operation — have none.
        cause = refused.__cause__
        return cause if isinstance(cause, ValidationError) else None
    if refused is not None and not isinstance(refused, Mapping):
        return None
    try:
        validate_operation_arguments(function, refused)
    except OperationValidationError as error:
        cause = error.__cause__
        return cause if isinstance(cause, ValidationError) else None
    return None


@cache
def _models_by_tag(function: DomainFunction) -> Mapping[str, type[OperationArguments]]:
    """Discriminator tag -> argument model, read off the models themselves.

    The tag is taken from each model's own ``operation`` literal rather than
    from the definition's name, so this map is keyed by exactly what the
    validator matched on when it refused.
    """

    tagged: dict[str, type[OperationArguments]] = {}
    for operation in function.operations:
        field = operation.arguments.model_fields.get("operation")
        tags = get_args(field.annotation) if field is not None else ()
        for tag in tags or (operation.name,):
            tagged[str(tag)] = operation.arguments
    return MappingProxyType(tagged)


def _field_guidance(
    function: DomainFunction,
    model: type[OperationArguments] | None,
    field_name: str,
) -> str | None:
    """One field's own statement of what it takes, or ``None`` if it has none."""

    if field_name == "operation" or model is None:
        return f"operation: name one of {', '.join(_models_by_tag(function))}."
    field = model.model_fields.get(field_name)
    if field is None:
        # An argument of a neighbouring operation, or an invention: the roster
        # this operation does take is the shortest route back.
        return (
            f"{field_name}: not an argument of this operation, "
            f"which takes {_argument_summary(model)}."
        )
    parts = [field.description] if field.description else []
    if field.examples:
        parts.append(
            f"Accepted values: {', '.join(str(example) for example in field.examples)}."
        )
    return f"{field_name}: {' '.join(parts)}" if parts else None


def resolved_operation(
    function: object, arguments: Mapping[str, Any] | None
) -> str | None:
    """Which registered operation a recorded call executed, or ``None``.

    The name a caller wrote is not the answer: an omitted ``operation`` means the
    function's declared default, and the registry is the only place that knows
    which one that is.  Anything the registry would refuse resolves to ``None``,
    because a call that could not have run cannot be described as having run one
    operation rather than another.

    Shared so that every reader keying a recorded call by its operation — the
    frontier reader, the page navigator — asks the same question of the same
    registry.  Two private copies of this would eventually disagree about what a
    defaulted call did, and then about whether two calls were the same call.
    """

    if not isinstance(function, str) or function not in DOMAIN_FUNCTIONS:
        return None
    try:
        validated = validate_operation_arguments(function, arguments)
    except (OperationValidationError, UnknownDomainFunctionError):
        return None
    return str(validated.operation)  # type: ignore[attr-defined]


def _argument_summary(model: type[OperationArguments]) -> str:
    """Required-first argument roster, read from the model itself."""

    parts: list[str] = []
    for field_name, field in model.model_fields.items():
        if field_name == "operation":
            continue
        parts.append(field_name if field.is_required() else f"{field_name}?")
    return ", ".join(parts) if parts else "no arguments"


def operation_navigation(
    function: str | DomainFunction, operation: str
) -> OperationNavigation:
    """How one operation is continued and narrowed — the single declaration."""

    return _resolve(function).operation(operation).navigation


def continuation_arguments(
    function: str | DomainFunction,
    operation: str,
    arguments: Mapping[str, Any],
    continuation: PageContinuation,
) -> dict[str, Any] | None:
    """The exact next-page call for one operation, or ``None`` if there is none.

    Registry-driven and refusal-first.  The next call is the SAME call with the
    declared cursor moved to the offset the result itself stated, so nothing
    about the query is re-decided here — a planner that rebuilt the arguments
    could quietly change a filter between two pages and produce a "complete"
    enumeration of two different sets.

    ``None`` is returned, rather than a best effort, whenever the continuation
    would be a guess: the operation declares no cursor, its cursor is stated
    somewhere other than the page envelope this planner reads, the result offers
    no safely resumable offset, or the page counts a unit the cursor does not
    advance (an item count fed into a byte window skips content that was never
    read).
    """

    navigation = operation_navigation(function, operation)
    if navigation.cursor_argument is None or continuation.resumable_offset is None:
        return None
    if navigation.cursor_source != PAGE_CURSOR_SOURCE:
        # Reading a producer's own cursor key would make this planner a table of
        # per-tool special cases again, which is exactly what one declaration per
        # operation exists to replace.  The model still learns that cursor from
        # the operation's description.
        return None
    if navigation.cursor_unit is not continuation.unit:
        return None
    next_arguments = dict(arguments)
    next_arguments[navigation.cursor_argument] = continuation.resumable_offset
    return next_arguments


def _navigation_summary(navigation: OperationNavigation) -> str:
    """The model-visible sentence about continuing and narrowing one operation."""

    if navigation.cursor_argument is not None:
        unit = navigation.cursor_unit.value if navigation.cursor_unit is not None else "item"
        line = (
            f" Continue: re-issue the same call with "
            f"{navigation.cursor_argument}={navigation.cursor_source} taken from the "
            f"previous result, for as long as that field is present (unit: {unit}"
        )
        if navigation.page_size_argument is not None:
            line += f"; page size: {navigation.page_size_argument}"
        line += ")."
    else:
        line = f" Single page: {navigation.no_continuation_reason}."
    if navigation.filter_arguments:
        line += f" Narrow the same query with: {', '.join(navigation.filter_arguments)}."
    return line


def operation_description(function: str | DomainFunction, operation: str) -> str:
    """One operation's description line, derived from its definition."""

    resolved = _resolve(function).operation(operation)
    backends = ", ".join(dict.fromkeys(backend.name for backend in resolved.backends))
    line = (
        f"{resolved.name} [{resolved.evidence_class.value}]"
        f" ({_argument_summary(resolved.arguments)}): {resolved.description}"
    )
    if resolved.method is not None:
        line += f" Method: {resolved.method}."
    if backends:
        line += f" Reaches: {backends}."
    return line + _navigation_summary(resolved.navigation)


def function_description(function: str | DomainFunction) -> str:
    """The model-visible description of one domain function and its operations.

    Assembled from the definitions alone so the text handed to the model and to
    ``/tools`` cannot disagree with what validation accepts.
    """

    resolved = _resolve(function)
    header = (
        f"Operations (default: {resolved.default_operation}):"
        if resolved.default_operation is not None
        else "Operations (operation is required):"
    )
    lines = [resolved.summary.strip(), "", header]
    lines.extend(
        f"- {operation_description(resolved, operation.name)}"
        for operation in resolved.operations
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Import-time verification.  A registry that lies about itself is worse than an
# import error, so every structural invariant is checked before first use.
# ---------------------------------------------------------------------------


def _verify_operation(function: DomainFunction, operation: OperationDefinition) -> None:
    where = f"{function.name}.{operation.name}"
    discriminator = operation.arguments.model_fields.get("operation")
    if discriminator is None or get_args(discriminator.annotation) != (operation.name,):
        raise ToolOperationError(
            f"{where}: the argument model's operation literal must be exactly the "
            "operation name — it is the union discriminator"
        )
    if discriminator.default != operation.name:
        raise ToolOperationError(
            f"{where}: the operation field's default must equal the operation name"
        )
    derived = operation.evidence_class is EvidenceClass.DERIVED
    if derived != (operation.method is not None) or derived != (
        operation.method_version is not None
    ):
        raise ToolOperationError(
            f"{where}: a derivation method identifier is carried exactly by DERIVED"
        )
    if operation.evidence_class is not EvidenceClass.REFERENCE and not operation.backends:
        raise ToolOperationError(f"{where}: an evidence operation must declare its backends")
    if operation.evidence_class is EvidenceClass.OBSERVED and not any(
        backend.role == "producer" for backend in operation.backends
    ):
        raise ToolOperationError(f"{where}: an OBSERVED operation must declare a producer")
    seen: set[tuple[str, str]] = set()
    for backend in operation.backends:
        if backend.name not in KNOWN_BACKEND_NAMES:
            raise ToolOperationError(
                f"{where}: backend {backend.name!r} is not inventoried by the version "
                "registry, so no result could ever attest its version"
            )
        key = (backend.name, backend.role)
        if key in seen:
            raise ToolOperationError(f"{where}: backend {backend.name!r} declared twice")
        seen.add(key)
    if not operation.description.strip():
        raise ToolOperationError(f"{where}: an operation must carry a description")
    _verify_navigation(where, operation)


#: Argument names that can only mean "resume the previous page here".  Any one
#: of them present on a model must BE the declared cursor: a continuation the
#: arguments support but the registry does not name is invisible to the model
#: and to the loop, which is the same as not having it.
_CURSOR_ARGUMENT_NAMES: tuple[str, ...] = ("offset", "match_offset")


def _verify_navigation(where: str, operation: OperationDefinition) -> None:
    """Check one navigation declaration against the operation's own arguments."""

    navigation = operation.navigation
    fields = operation.arguments.model_fields
    declared = (
        navigation.cursor_argument,
        navigation.page_size_argument,
        *navigation.filter_arguments,
    )
    for argument in declared:
        if argument is not None and argument not in fields:
            raise ToolOperationError(
                f"{where}: navigation names {argument!r}, which is not an argument "
                "of this operation"
            )
    if (navigation.cursor_argument is None) != (navigation.cursor_unit is None) or (
        navigation.cursor_argument is None
    ) != (navigation.cursor_source is None):
        raise ToolOperationError(
            f"{where}: a continuation cursor, the unit it counts and the field its "
            "next value comes from are declared together"
        )
    if (navigation.cursor_argument is None) != (
        navigation.no_continuation_reason is not None
    ):
        raise ToolOperationError(
            f"{where}: an operation without a cursor must state why it returns one "
            "page, and one with a cursor must not"
        )
    if navigation.cursor_argument is not None:
        cursor_field = fields[navigation.cursor_argument]
        if cursor_field.annotation is not int:
            raise ToolOperationError(
                f"{where}: the continuation cursor {navigation.cursor_argument!r} "
                "must be an integer argument"
            )
    for candidate in _CURSOR_ARGUMENT_NAMES:
        if candidate in fields and navigation.cursor_argument != candidate:
            raise ToolOperationError(
                f"{where}: {candidate!r} is an argument of this operation but is not "
                "declared as its continuation cursor"
            )
    for candidate in _FILTER_ARGUMENTS:
        if candidate in fields and candidate not in navigation.filter_arguments:
            raise ToolOperationError(
                f"{where}: {candidate!r} narrows this operation but is not declared "
                "as one of its filters"
            )


def _verify_definitions() -> None:
    for function in DOMAIN_FUNCTIONS.values():
        if function.scope not in _EVIDENCE_SCOPES:
            raise ToolOperationError(
                f"{function.name}: unknown evidence scope {function.scope!r}"
            )
        names = function.operation_names()
        if not names or len(set(names)) != len(names):
            raise ToolOperationError(
                f"{function.name}: operations must be nonempty and uniquely named"
            )
        if function.default_operation is not None and function.default_operation not in names:
            raise ToolOperationError(
                f"{function.name}: default operation {function.default_operation!r} "
                "is not one of its operations"
            )
        for operation in function.operations:
            _verify_operation(function, operation)
    withdrawn_by_function: dict[str, set[str]] = {}
    for withdrawn in WITHDRAWN_OPERATIONS.values():
        host = DOMAIN_FUNCTIONS.get(withdrawn.function)
        if host is None:
            raise ToolOperationError(
                f"{withdrawn.key}: withdrawn from a function that is not defined"
            )
        offered = host.operation_names()
        if withdrawn.definition.name in offered:
            raise ToolOperationError(
                f"{withdrawn.key}: declared withdrawn while still in the function's enum"
            )
        if withdrawn.superseded_by not in offered:
            raise ToolOperationError(
                f"{withdrawn.key}: successor {withdrawn.superseded_by!r} is not an "
                f"operation of {host.name}"
            )
        if not withdrawn.reason.strip():
            raise ToolOperationError(f"{withdrawn.key}: a withdrawal must state its reason")
        # Held to the same structural rules as an offered one: it is still the
        # definition a recorded call is attested against.
        _verify_operation(host, withdrawn.definition)
        withdrawn_by_function.setdefault(host.name, set()).add(withdrawn.definition.name)
    for disposition in LEGACY_FUNCTION_DISPOSITIONS.values():
        if disposition.status != "operation":
            continue
        if disposition.domain_function is None:
            raise ToolOperationError(
                f"{disposition.legacy_name}: an operation disposition must name its function"
            )
        target = DOMAIN_FUNCTIONS.get(disposition.domain_function)
        if target is None:
            raise ToolOperationError(
                f"{disposition.legacy_name}: target function "
                f"{disposition.domain_function!r} is not defined"
            )
        # A withdrawn operation still counts as defined here: the disposition
        # records where a previous function WENT, and that history does not stop
        # being true when the operation leaves the enum.
        defined = set(target.operation_names()) | withdrawn_by_function.get(target.name, set())
        for operation_name in disposition.operations:
            if operation_name not in defined:
                raise ToolOperationError(
                    f"{disposition.legacy_name}: target operation {operation_name!r} "
                    f"is not defined on {target.name}"
                )


_verify_definitions()


__all__ = [
    "DOMAIN_FUNCTIONS",
    "KNOWN_BACKEND_NAMES",
    "LEGACY_FUNCTION_DISPOSITIONS",
    "MEMORY_PLUGINS",
    "MODEL_ARGUMENT_SCHEMA_ID",
    "DomainFunction",
    "LegacyDisposition",
    "OperationArguments",
    "OperationBackend",
    "OperationClassification",
    "OperationDefinition",
    "OperationNavigation",
    "OperationValidationError",
    "PAGE_CURSOR_SOURCE",
    "ToolOperationError",
    "UnknownDomainFunctionError",
    "WITHDRAWN_OPERATIONS",
    "WithdrawnOperation",
    "classification_table",
    "continuation_arguments",
    "domain_function",
    "domain_function_names",
    "function_description",
    "functions_for_scope",
    "operation_argument_schemas",
    "operation_definition",
    "operation_description",
    "operation_names",
    "operation_navigation",
    "resolved_operation",
    "validate_operation_arguments",
]
