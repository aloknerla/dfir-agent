"""Memory forensics tool (Volatility 3).

Runs a curated Volatility 3 plugin on a memory dump and returns structured
results: running processes, process tree, command lines, network connections,
injected/hidden code (malfind), loaded DLLs. The agent calls this read-only.

Network symbol retrieval is disabled unconditionally.  Supply local symbol packs
through ``DFA_VOL_SYMBOL_DIRS`` when the built-in symbols are insufficient.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import threading
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from forensic_agent.core.derivation_inputs import (
    DerivationInputError,
    confirmed_result_inputs,
    observed_operation_input,
)
from forensic_agent.core.environ import clamscan_path, vol_path
from forensic_agent.core.tool_failure import tool_failure_result
from forensic_agent.core.toolkit import ExternalToolError, run_external

_CACHE_DIRNAME = ".volatility3-cache"
_MALWARE_SCAN_SCHEMA_ID = "forensic.memory-malware-scan.v1"
_MALFIND_PLUGIN = "windows.malware.malfind.Malfind"
_MALWARE_SCAN_SCOPES = frozenset({"pid", "all_candidates"})
_MAX_MALFIND_CANDIDATES = 16
_MAX_MALFIND_DUMPS = 64
_MAX_MALFIND_DUMP_BYTES = 64 * 1024 * 1024
_MAX_MALFIND_TOTAL_BYTES = 512 * 1024 * 1024
_MAX_CLAMAV_DATABASE_BYTES = 1024 * 1024 * 1024
_CLAMAV_VERSION_MAX_CHARS = 500
_CLAMAV_DETECTION_MAX_CHARS = 240
_MAX_CLAMAV_DETECTIONS_PER_ARTIFACT = 32
_SAFE_CLAMAV_DETECTION = re.compile(r"^[^\x00-\x1f\x7f]{1,240}$")
_MALFIND_DUMP_PID = re.compile(r"(?:^|\.)pid\.(?P<pid>[1-9][0-9]*)(?:\.|$)", re.IGNORECASE)
_MAX_MEMORY_SCAN_ATTEMPTS = 2
#: Wire version of the closed-shape scan envelope exchanged with a scan that
#: executes outside this process.
_SCAN_ENVELOPE_VERSION = 1
_TRANSIENT_SPAWN_ERRNOS = frozenset({errno.EAGAIN, errno.EINTR, errno.ETIMEDOUT})
_MEMORY_SCAN_FAILURE_STAGES = frozenset(
    {
        "runtime_configuration",
        "signature_database_validation",
        "scanner_identity",
        "memory_extraction",
        "memory_extraction_output",
        "artifact_validation",
        "signature_scan",
        "signature_scan_output",
        "signature_database_revalidation",
        "internal",
    }
)
_MEMORY_SCAN_FAILURE_CODES = frozenset(
    {
        "dependency_unavailable",
        "configuration_failure",
        "validation_failure",
        "resource_limit",
        "external_timeout",
        "external_signal",
        "external_spawn_failure",
        "external_failure",
        "invalid_output",
        "integrity_failure",
        "internal_failure",
    }
)


class _MemoryScanFailure(RuntimeError):
    """One sanitized, closed-class failure from an offline scan attempt."""

    def __init__(self, stage: str, code: str, *, retryable: bool = False) -> None:
        if stage not in _MEMORY_SCAN_FAILURE_STAGES:
            raise ValueError("unknown memory-scan failure stage")
        if code not in _MEMORY_SCAN_FAILURE_CODES:
            raise ValueError("unknown memory-scan failure code")
        self.stage = stage
        self.code = code
        self.retryable = retryable
        super().__init__(f"{stage}:{code}")


def _absolute_directory(value: str, *, setting: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise ValueError(f"{setting} must be an absolute directory")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"{setting} directory is not available") from exc
    if not resolved.is_dir():
        raise ValueError(f"{setting} must name a directory")
    return resolved


def _cache_directory(base: Path) -> Path:
    """Return the mutable Volatility cache directory for this execution cell.

    Volatility 3 2.28 treats ``--cache-path`` as a directory and creates its
    internal ``identifier.cache`` below it.  With no explicit override, place
    that directory below ``base`` — the configured per-cell workdir, so one arm
    cannot reuse another arm's mutable symbol-index state.
    """

    configured = os.environ.get("DFA_VOL_CACHE", "").strip()
    cache = Path(configured).expanduser() if configured else base / _CACHE_DIRNAME
    if not cache.is_absolute():
        raise ValueError("DFA_VOL_CACHE must be an absolute directory")
    try:
        cache.mkdir(parents=True, exist_ok=True)
        resolved = cache.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError("DFA_VOL_CACHE directory is not writable") from exc
    if not resolved.is_dir():
        raise ValueError("DFA_VOL_CACHE must name a directory")
    return resolved


def _symbol_directories() -> str | None:
    """Validate Volatility's semicolon-delimited local symbol directory list."""

    configured = os.environ.get("DFA_VOL_SYMBOL_DIRS", "").strip()
    if not configured:
        return None
    values = [value.strip() for value in configured.split(";")]
    if not values or any(not value for value in values):
        raise ValueError("DFA_VOL_SYMBOL_DIRS contains an empty directory")
    directories = [_absolute_directory(value, setting="DFA_VOL_SYMBOL_DIRS") for value in values]
    return ";".join(str(directory) for directory in directories)


#: Where an unconfigured run keeps its symbol index.  Nothing configured the
#: runtime, so there is no cell to isolate — and a cache below the per-call
#: temporary output directory is deleted with it, which made every call re-index
#: the packaged symbols from nothing.  Created once and reused for the life of
#: the process; a configured runtime keeps its own directory and never comes here.
_unconfigured_cache_root_path: Path | None = None
_unconfigured_cache_root_lock = threading.Lock()


def _unconfigured_cache_root() -> Path:
    """Return the process-lifetime directory an unconfigured run caches below."""

    global _unconfigured_cache_root_path
    with _unconfigured_cache_root_lock:
        if _unconfigured_cache_root_path is None or not _unconfigured_cache_root_path.is_dir():
            _unconfigured_cache_root_path = Path(
                tempfile.mkdtemp(prefix="forensic_agent_vol_cache_")
            ).resolve(strict=True)
        return _unconfigured_cache_root_path


@contextmanager
def _runtime_directories() -> Iterator[tuple[Path, Path]]:
    """Yield per-call output/cache directories without process-global state."""

    configured = os.environ.get("DFA_VOL_WORKDIR", "").strip()
    if configured:
        workdir = _absolute_directory(configured, setting="DFA_VOL_WORKDIR")
        yield workdir, _cache_directory(workdir)
        return

    with tempfile.TemporaryDirectory(prefix="forensic_agent_vol_") as temporary:
        workdir = Path(temporary).resolve(strict=True)
        # The plugin output directory is per call and is deleted here; the symbol
        # index is not, so it caches below a directory that outlives the call.
        yield workdir, _cache_directory(_unconfigured_cache_root())


#: The Windows Volatility 3 plugins the agent may run against a memory image.
#: Deliberately broad — a case should not stall because a standard read-only
#: plugin was never exposed.  Every entry runs with no mandatory user arguments; plugins
#: that require a target (``--pid``/``--key``/``--yara-rules``: pedump, printkey,
#: yarascan, strings) are omitted because the wrapper passes none.  The short
#: name is what the model selects; the value is the fully qualified plugin.
PLUGINS = {
    # OS and image metadata
    "info": "windows.info.Info",  # OS build, kernel base, capture time
    "statistics": "windows.statistics.Statistics",  # page availability stats
    "verinfo": "windows.verinfo.VerInfo",  # PE version resources
    # Processes
    "pslist": "windows.pslist.PsList",  # active processes (walk)
    "pstree": "windows.pstree.PsTree",  # process parent/child tree
    "psscan": "windows.psscan.PsScan",  # processes incl. hidden/terminated (scan)
    "psxview": "windows.malware.psxview.PsXView",  # cross-view hidden processes
    "cmdline": "windows.cmdline.CmdLine",  # process command lines
    "envars": "windows.envars.Envars",  # process environment variables
    "getsids": "windows.getsids.GetSIDs",  # process owner SIDs
    "privileges": "windows.privileges.Privs",  # process privileges
    "sessions": "windows.sessions.Sessions",  # logon sessions
    "handles": "windows.handles.Handles",  # open handles (files, keys, mutexes)
    "thrdscan": "windows.thrdscan.ThrdScan",  # threads (scan)
    "hollowprocesses": "windows.malware.hollowprocesses.HollowProcesses",  # hollowing
    # Loaded code / injection
    "dlllist": "windows.dlllist.DllList",  # loaded user modules
    "ldrmodules": "windows.ldrmodules.LdrModules",  # unlinked / hidden DLLs
    "iat": "windows.iat.IAT",  # import address table (hook detection)
    "malfind": "windows.malware.malfind.Malfind",  # injected / hidden code
    "vadinfo": "windows.vadinfo.VadInfo",  # virtual address descriptors
    # Network
    "netscan": "windows.netscan.NetScan",  # connections/sockets (scan)
    "netstat": "windows.netstat.NetStat",  # connections (walk)
    # Kernel / drivers / hooks
    "modules": "windows.modules.Modules",  # kernel modules (walk)
    "modscan": "windows.modscan.ModScan",  # kernel modules (scan)
    "driverscan": "windows.driverscan.DriverScan",  # driver objects
    "callbacks": "windows.callbacks.Callbacks",  # kernel notification callbacks
    "ssdt": "windows.ssdt.SSDT",  # system service descriptor table
    "mutantscan": "windows.mutantscan.MutantScan",  # mutexes (malware markers)
    # Services
    "svcscan": "windows.svcscan.SvcScan",  # services + on-disk binary paths (scan)
    "svclist": "windows.svclist.SvcList",  # services (list)
    "getservicesids": "windows.getservicesids.GetServiceSIDs",  # service SIDs
    # Credentials
    "hashdump": "windows.hashdump.Hashdump",  # local SAM NTLM hashes
    "cachedump": "windows.registry.cachedump.Cachedump",  # cached domain creds
    "lsadump": "windows.registry.lsadump.Lsadump",  # LSA secrets
    # Registry: persistence and execution artifacts
    "hivelist": "windows.registry.hivelist.HiveList",  # loaded registry hives
    "userassist": "windows.registry.userassist.UserAssist",  # program execution
    "amcache": "windows.registry.amcache.Amcache",  # program execution
    "scheduled_tasks": "windows.registry.scheduled_tasks.ScheduledTasks",  # tasks
    "certificates": "windows.registry.certificates.Certificates",  # cert stores
    # Filesystem artifacts
    "filescan": "windows.filescan.FileScan",  # file objects
    "dumpfiles": "windows.dumpfiles.DumpFiles",  # carve a file out of memory
    "mftscan": "windows.mftscan.MFTScan",  # MFT records (timestamps, timestomping)
    # Cross-plugin timeline
    "timeliner": "timeliner.Timeliner",  # unified timeline of memory artifacts
}


def canonical_plugin_name(requested: str, resolved: str) -> str:
    """Return the short plugin identity behind any accepted alias.

    A caller may pass the short name, the fully qualified name, or a partial
    dotted name that Volatility itself resolves.  The per-plugin summaries must
    not depend on which of those was typed: a result without its complete typed
    projection is a different capability, not a different spelling.  This mirrors
    the normalization the agent layer already applies when reading results.
    """

    for candidate in (str(resolved), str(requested)):
        normalized = candidate.strip().casefold()
        if not normalized:
            continue
        for short in PLUGINS:
            if (
                normalized == short
                or normalized.endswith(f".{short}")
                or f".{short}." in normalized
            ):
                return short
    return str(requested).strip().casefold()


# Deep enough to hold every plugin a single memory investigation runs, so a
# follow-up question re-uses the earlier scans instead of paying their minutes
# again. Four evicted an early plugin (netscan) before a later question asked
# for it, and a multi-gigabyte re-scan followed. Each entry is one bounded row
# set (capped below), so the deeper cache costs a few megabytes at most.
_PLUGIN_OUTPUT_CACHE_ENTRIES = 32
_PLUGIN_OUTPUT_CACHE_MAX_ROWS = 500_000
_plugin_output_cache: dict[tuple[object, ...], list] = {}
_plugin_output_cache_lock = threading.Lock()


def _memory_source_identity(dump_path: str) -> tuple[str, int, int]:
    """Identify the evidence file without rehashing gigabytes on every call."""

    info = os.stat(dump_path)
    return os.path.realpath(dump_path), info.st_size, info.st_mtime_ns


def _plugin_output_cache_key(
    dump_path: str,
    plugin: str,
    requested_name: str,
    symbol_directories: str | None,
) -> tuple[object, ...]:
    """Key one retained row set.

    ``requested_name`` is part of the key because the derived operations select
    what they may compute from the canonical plugin identity.  Keeping the short
    name and the fully-qualified alias in separate entries means a cached page is
    always identical to the page a fresh run would have produced.  The retained
    rows themselves are never rewritten, so a cached row set stays exactly the
    output Volatility produced for however many pages are served from it.

    The runtime directories are deliberately NOT part of the key.  The console
    rebinds them to a fresh scratch directory for every question, so including
    them made the key differ on every message and the cache could never hit — the
    follow-up questions it exists for paid a full re-scan each time.  What the
    rows are is fixed by the evidence file, the plugin and the symbols, all of
    which are here.  A plugin whose rows instead POINT INTO the scratch directory
    is not keyed at all: see :data:`_WORKSPACE_OUTPUT_PLUGINS`.
    """

    return (
        _memory_source_identity(dump_path),
        plugin,
        requested_name.strip().casefold(),
        symbol_directories,
    )


#: Plugins whose rows name files the plugin wrote into this run's output
#: directory.  That directory is per run, so a retained row set would hand a
#: later run paths that do not exist — these always run again.  Matched on any
#: dotted segment, so the short name, the curated name and any fully-qualified
#: pass-through spelling of the same plugin are all recognised.
_WORKSPACE_OUTPUT_PLUGINS = frozenset({"dumpfiles", "pedump", "memmap"})


def _writes_workspace_files(plugin: str, requested_name: str) -> bool:
    """Whether this plugin's rows reference files it wrote into the run workspace."""

    for candidate in (plugin, requested_name):
        segments = str(candidate).strip().casefold().split(".")
        if any(segment in _WORKSPACE_OUTPUT_PLUGINS for segment in segments):
            return True
    return False


def _cached_plugin_rows(key: tuple[object, ...]) -> list | None:
    """Serve one previously produced plugin row set, refreshing its LRU position."""

    with _plugin_output_cache_lock:
        rows = _plugin_output_cache.pop(key, None)
        if rows is None:
            return None
        _plugin_output_cache[key] = rows
        return rows


def _store_plugin_rows(key: tuple[object, ...], rows: list) -> None:
    """Retain one bounded plugin row set for the remaining pages of the same result."""

    if len(rows) > _PLUGIN_OUTPUT_CACHE_MAX_ROWS:
        return
    with _plugin_output_cache_lock:
        _plugin_output_cache.pop(key, None)
        _plugin_output_cache[key] = rows
        while len(_plugin_output_cache) > _PLUGIN_OUTPUT_CACHE_ENTRIES:
            _plugin_output_cache.pop(next(iter(_plugin_output_cache)))


#: Applied when the caller omits ``operation``, and mirrored by the classifier so
#: an omitted argument classifies as the operation that actually runs.  The full
#: operation set lives with the computations themselves, in
#: ``_DERIVED_MEMORY_OPERATIONS`` below.
_DEFAULT_MEMORY_OPERATION = "plugin_rows"


def memory_query(
    dump_path: str,
    plugin: str,
    limit: int = 50,
    offset: int = 0,
    filter: str | None = None,
    operation: str = _DEFAULT_MEMORY_OPERATION,
    *,
    derived_from: object = None,
) -> dict:
    """Run one curated Volatility 3 plugin on a memory dump (read-only) and
    return structured results. Use for process/network/injection facts in RAM;
    for loose strings (URLs, commands) that no plugin surfaces use memory_strings.

    Example: memory_query(dump_path, "netscan", filter="443", limit=50)

    Input: `dump_path` is the memory image; `plugin` is one of the curated short
    names (pslist, pstree, psscan, cmdline, netscan, netstat, malfind, dlllist,
    hashdump, filescan, dumpfiles, hivelist) OR — pass-through — ANY fully-qualified
    Volatility 3 plugin name (contains a dot), e.g. "windows.getsids.GetSIDs",
    "windows.svcscan.SvcScan", "windows.registry.userassist.UserAssist",
    "linux.pslist.PsList". The short list is convenience only, not a limit: any
    plugin Volatility ships is reachable. `offset`/`limit` paginate.

    `filter` is a PLAIN SUBSTRING match applied to each serialized row, NOT a query
    expression. Pass one literal value: filter="4321", filter="sampleproc",
    filter="ESTABLISHED", filter="198.51.100.42". Comparison syntax such as
    filter="ForeignAddr != '*'" or filter="Proto == 'TCPv4' and State == 'ESTABLISHED'"
    is compared literally and always returns zero rows. To see everything, omit
    `filter`; a plugin whose raw rows do not fit a page can also be read through a
    summary `operation` (below) computed over its complete output. Read-only;
    Volatility is always run with ``--offline``. Configure local symbols with the
    semicolon-delimited ``DFA_VOL_SYMBOL_DIRS`` environment variable.

    `operation` selects which question this call answers, because these are not
    the same kind of claim. "plugin_rows" (default) returns what the plugin
    emitted, and nothing else. Every other operation is a computation THIS module
    performs over those rows and returns as a separate derived result:
    "process_parentage" matches each row's PPID against the PID column
    (pslist/psscan); "external_connections" keeps the rows whose ForeignAddr is
    outside this module's own local-address set (netscan/netstat);
    "injection_candidates" counts malfind's regions per process (malfind);
    "field_distribution" describes how each low-cardinality field's values are
    distributed (any plugin). None of them travels inside the observed read,
    because a parent name, a verdict of "external" or a candidate ranking is an
    inference and not something Volatility reported. pstree reports parentage
    itself, so ask pstree for it there.

    Returns, for "plugin_rows": {"plugin", "count" (total rows emitted), plus the
    filtered/paginated envelope (total_matching, returned, offset, truncated,
    note, rows)}; a row carries only the columns Volatility emitted. A summary
    operation instead returns {"plugin", "operation", "schema_id",
    "evidence_class": "derived", "derivation" (method and the inputs it was
    computed over), "summary_scope", "source_row_count", "count", ...} with the
    computed entries as its rows. On failure returns {"error"}.
    """
    if not dump_path or not os.path.exists(dump_path):
        return {"error": "memory dump not available (set one with --memory / /memory)."}
    requested_operation = (operation or "").strip().casefold() or _DEFAULT_MEMORY_OPERATION
    if requested_operation not in MEMORY_QUERY_OPERATIONS:
        return {
            "error": f"unknown operation '{operation}'. Use one of: "
            f"{', '.join(MEMORY_QUERY_OPERATIONS)}."
        }
    p = (plugin or "").strip()
    # Pass-through: a dotted name is a fully-qualified Volatility plugin — run it
    # verbatim so the agent is never boxed into the curated short list.
    full = PLUGINS.get(p.lower()) or (p if "." in p else None)
    if not full:
        return {
            "error": f"unknown plugin '{plugin}'. Use a short name ({', '.join(PLUGINS)}) "
            f"or any fully-qualified Volatility plugin (e.g. windows.getsids.GetSIDs)."
        }
    VOL = vol_path()
    if not VOL:
        return {
            "error": "Volatility 3 'vol' not found. Install with `pip install volatility3`, "
            "add it to PATH, or set DFA_VOL. Run `dfir-agent --doctor`."
        }
    # Pagination must not re-parse the image. Volatility output for one
    # (evidence file, plugin) pair is deterministic, so the full pre-pagination
    # row set is produced once and every later page, filter and summary is
    # derived from that same retained result.  The returned envelope is
    # byte-identical whether it was served from the cache or from a fresh run.
    canonical = canonical_plugin_name(p, full)
    cited_inputs: list[dict] = []
    derived = _DERIVED_MEMORY_OPERATIONS.get(requested_operation)
    if derived is not None:
        # Refused before the image is parsed: each of these computations reads
        # named columns, and a plugin that does not report them has nothing to
        # compute over.  Parsing the image first would spend minutes to produce an
        # empty answer that reads like a finding of "none".
        if derived.plugins is not None and canonical not in derived.plugins:
            return {
                "plugin": plugin,
                "operation": requested_operation,
                "error": (
                    f"{requested_operation} "
                    + derived.refusal.format(
                        plugin=plugin, plugins=" or ".join(derived.plugins)
                    )
                ),
            }
        try:
            cited_inputs = confirmed_result_inputs(derived_from)
        except DerivationInputError as e:
            return {
                "plugin": plugin,
                "operation": requested_operation,
                "error": f"cited derivation inputs are unusable: {str(e)[:150]}",
            }
    try:
        symbol_directories = _symbol_directories()
        cache_key = _plugin_output_cache_key(dump_path, full, canonical, symbol_directories)
    except Exception as e:
        return tool_failure_result(e, subject=str(dump_path), backend="volatility3")

    cacheable = not _writes_workspace_files(full, canonical)
    rows = _cached_plugin_rows(cache_key) if cacheable else None
    if rows is None:
        try:
            with _runtime_directories() as (workdir, cache_directory):
                command = [
                    VOL,
                    "-q",
                    "-r",
                    "json",
                    "--offline",
                    "--cache-path",
                    str(cache_directory),
                ]
                if symbol_directories is not None:
                    command.extend(["--symbol-dirs", symbol_directories])
                command.extend(["-o", str(workdir), "-f", dump_path, full])
                proc = run_external(
                    command,
                    timeout=900,
                    check=False,
                    cwd=str(workdir),
                )
        except Exception as e:
            return tool_failure_result(e, subject=str(dump_path), backend="volatility3")

        if proc.returncode != 0:
            return {
                "plugin": plugin,
                "error": "Volatility returned a non-zero exit status",
                "returncode": proc.returncode,
                "stderr": (proc.stderr or "")[-800:],
            }
        out = (proc.stdout or "").strip()
        try:
            data = json.loads(out)
        except Exception:
            return {
                "plugin": plugin,
                "error": "could not parse Volatility output",
                "raw": out[:1200],
                "stderr": (proc.stderr or "")[-400:],
            }
        rows = data if isinstance(data, list) else [data]
        if cacheable:
            _store_plugin_rows(cache_key, rows)
    if derived is not None:
        # Every summary is computed from the canonical plugin identity, never from
        # the spelling the caller used, so an alias cannot change the answer.
        return _derived_operation_result(
            requested_operation,
            derived,
            plugin,
            canonical,
            rows,
            offset=offset,
            limit=limit,
            filter=filter,
            cited_inputs=cited_inputs,
        )
    from forensic_agent.core.toolio import shape

    # The observed read states what Volatility emitted and nothing else: how many
    # rows there were, and the requested page of them.  Each summary is an
    # operation of its own, because a computation over the rows is this module's
    # claim about them and not the plugin's report.
    env = shape(rows, offset=offset, limit=limit, filter=filter)  # filter + paginate
    return {"plugin": plugin, "count": len(rows), **env}


_MAX_PROJECTION_FIELDS = 8
_MAX_PROJECTION_DISTINCT = 40
_MAX_PROJECTION_VALUES = 6
_MAX_PROJECTION_VALUE_CHARS = 80


def _compute_field_distribution(rows: list) -> tuple[list[dict], dict]:
    """Describe the whole plugin result compactly, without returning its rows.

    A byte-bounded page cannot carry a plugin that emits hundreds or thousands of
    rows, and paging through them one call at a time is not a realistic plan
    under a call budget.  This states, over the complete result, which fields
    exist and how their values are distributed, so a caller with a limited
    context can decide what to filter on instead of enumerating.

    Counting the values is this module's arithmetic over the plugin's output, not
    a distribution Volatility reported, which is why it is asked for by name
    instead of riding along with every observed read.

    Only low-cardinality fields are described: a field whose values are nearly
    all distinct (a path, an offset) carries no useful distribution and would
    only spend bytes.
    """

    import collections

    fields: list[dict] = []
    names: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        for key in row:
            name = str(key)
            if name not in names and not name.startswith("__"):
                names.append(name)
        if len(names) >= _MAX_PROJECTION_FIELDS * 3:
            break
    for name in names:
        counter: collections.Counter = collections.Counter()
        for row in rows:
            if not isinstance(row, dict) or name not in row:
                continue
            value = row[name]
            if value is None or isinstance(value, (dict, list)):
                continue
            text = str(value)
            if len(text) > _MAX_PROJECTION_VALUE_CHARS:
                continue
            counter[text] += 1
            if len(counter) > _MAX_PROJECTION_DISTINCT:
                break
        if not counter or len(counter) > _MAX_PROJECTION_DISTINCT:
            continue
        fields.append(
            {
                "name": name,
                "distinct": len(counter),
                "values": [
                    {"value": value, "count": count}
                    for value, count in counter.most_common(_MAX_PROJECTION_VALUES)
                ],
            }
        )
        if len(fields) >= _MAX_PROJECTION_FIELDS:
            break
    return fields, {}


def _clamav_database_directory() -> Path:
    configured = os.environ.get("DFA_CLAMAV_DB", "/opt/clamav-1.5.3/db").strip()
    return _absolute_directory(configured, setting="DFA_CLAMAV_DB")


def _clamav_database_identity(
    directory: Path,
) -> tuple[dict[str, object], dict[Path, tuple[int, int, int, int]]]:
    """Hash the exact official databases and detached signatures."""

    candidates = sorted(
        (
            path
            for path in directory.iterdir()
            if path.suffix.casefold() in {".cvd", ".cld", ".sign"}
        ),
        key=lambda path: path.name,
    )
    if not candidates:
        raise ValueError("ClamAV signature database contains no official database files")
    entries: list[dict[str, object]] = []
    identities: dict[Path, tuple[int, int, int, int]] = {}
    total_bytes = 0
    for path in candidates:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
            raise ValueError("ClamAV signature database contains a non-regular file")
        size = int(before.st_size)
        if size <= 0:
            raise ValueError("ClamAV signature database contains an empty file")
        total_bytes += size
        if total_bytes > _MAX_CLAMAV_DATABASE_BYTES:
            raise ValueError("ClamAV signature database exceeds the bounded size cap")
        identity = (
            int(before.st_dev),
            int(before.st_ino),
            size,
            int(before.st_mtime_ns),
        )
        digest = hashlib.sha256()
        with path.open("rb", buffering=0) as handle:
            while chunk := handle.read(4 * 1024 * 1024):
                digest.update(chunk)
        after = path.lstat()
        if identity != (
            int(after.st_dev),
            int(after.st_ino),
            int(after.st_size),
            int(after.st_mtime_ns),
        ):
            raise ValueError("ClamAV signature database changed while it was hashed")
        identities[path] = identity
        entries.append(
            {
                "filename": path.name,
                "sha256": digest.hexdigest(),
                "size_bytes": size,
            }
        )
    database_files = {
        path.name.casefold(): path
        for path in candidates
        if path.suffix.casefold() in {".cvd", ".cld"}
    }
    selected_databases: dict[str, Path] = {}
    for stem in ("bytecode", "daily", "main"):
        matches = [
            path for name, path in database_files.items() if name in {f"{stem}.cvd", f"{stem}.cld"}
        ]
        if len(matches) != 1:
            raise ValueError("ClamAV signature database is incomplete")
        selected_databases[stem] = matches[0]
    observed_names = {path.name.casefold() for path in candidates}
    detached_signatures_valid = all(
        sum(
            re.fullmatch(
                rf"{re.escape(stem)}-[1-9][0-9]*\.{re.escape(path.suffix.casefold().lstrip('.'))}\.sign",
                name,
            )
            is not None
            for name in observed_names
        )
        == 1
        for stem, path in selected_databases.items()
    )
    if not detached_signatures_valid:
        raise ValueError("ClamAV signature database is incomplete")
    manifest_bytes = json.dumps(
        entries,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return (
        {
            "format": "official-clamav-cvd-cld-sign-files-v1",
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "file_count": len(entries),
            "total_bytes": total_bytes,
            "files": entries,
        },
        identities,
    )


def _assert_clamav_database_unchanged(
    identities: dict[Path, tuple[int, int, int, int]],
) -> None:
    for path, expected in identities.items():
        observed = path.lstat()
        if (
            not stat.S_ISREG(observed.st_mode)
            or stat.S_ISLNK(observed.st_mode)
            or expected
            != (
                int(observed.st_dev),
                int(observed.st_ino),
                int(observed.st_size),
                int(observed.st_mtime_ns),
            )
        ):
            raise ValueError("ClamAV signature database changed during the scan")


def _stable_regular_file_identity(path: Path) -> tuple[str, int, tuple[int, int, int, int]]:
    """Hash one private dump without following links and return its stable identity."""

    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise ValueError("Volatility produced a non-regular malfind artifact")
    size = int(before.st_size)
    if size <= 0 or size > _MAX_MALFIND_DUMP_BYTES:
        raise ValueError("Volatility malfind artifact is empty or exceeds the scan cap")
    identity = (
        int(before.st_dev),
        int(before.st_ino),
        size,
        int(before.st_mtime_ns),
    )
    digest = hashlib.sha256()
    with path.open("rb", buffering=0) as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    after = path.lstat()
    if (
        not stat.S_ISREG(after.st_mode)
        or stat.S_ISLNK(after.st_mode)
        or identity
        != (
            int(after.st_dev),
            int(after.st_ino),
            int(after.st_size),
            int(after.st_mtime_ns),
        )
    ):
        raise ValueError("Volatility malfind artifact changed while it was hashed")
    return digest.hexdigest(), size, identity


def _clamav_detection_map(
    stdout: str,
    artifacts: list[Path],
) -> dict[str, tuple[str, ...]]:
    """Bind one batched ClamAV result to the exact bounded artifact set.

    ClamAV loads a signature database before every process invocation.  Passing
    the already hashed malfind artifacts in one fixed-argv call avoids reloading
    that database once per VAD while preserving an exact per-file result.  Only
    the basenames supplied to the scanner are accepted back; unknown or malformed
    output fails closed instead of being attributed to a candidate.
    """

    expected = {artifact.name for artifact in artifacts}
    if len(expected) != len(artifacts):
        raise ValueError("malfind artifact names are not unique")
    detections: dict[str, set[str]] = {name: set() for name in expected}
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    if len(lines) > len(artifacts) * _MAX_CLAMAV_DETECTIONS_PER_ARTIFACT:
        raise ValueError("ClamAV returned too many detection lines")
    for line in lines:
        if not line.endswith(" FOUND") or ": " not in line:
            raise ValueError("ClamAV returned an unrecognized output line")
        rendered_artifact, rendered_detection = line.rsplit(": ", 1)
        if rendered_artifact not in expected:
            raise ValueError("ClamAV returned a detection for an unknown artifact")
        detection = rendered_detection.removesuffix(" FOUND").strip()
        if (
            not detection
            or len(detection) > _CLAMAV_DETECTION_MAX_CHARS
            or _SAFE_CLAMAV_DETECTION.fullmatch(detection) is None
        ):
            raise ValueError("ClamAV returned an invalid detection name")
        artifact_detections = detections[rendered_artifact]
        artifact_detections.add(detection)
        if len(artifact_detections) > _MAX_CLAMAV_DETECTIONS_PER_ARTIFACT:
            raise ValueError("ClamAV returned too many detections for one malfind artifact")
    return {name: tuple(sorted(names)) for name, names in detections.items()}


def _external_scan_failure(stage: str, exc: ExternalToolError | OSError) -> _MemoryScanFailure:
    if isinstance(exc, ExternalToolError):
        returncode = exc.returncode
        if returncode is None:
            return _MemoryScanFailure(stage, "external_timeout", retryable=True)
        if isinstance(returncode, int) and not isinstance(returncode, bool) and returncode < 0:
            return _MemoryScanFailure(stage, "external_signal", retryable=True)
        return _MemoryScanFailure(stage, "external_failure")
    return _MemoryScanFailure(
        stage,
        "external_spawn_failure",
        retryable=exc.errno in _TRANSIENT_SPAWN_ERRNOS,
    )


def _returncode_scan_failure(stage: str, returncode: object) -> _MemoryScanFailure:
    if isinstance(returncode, int) and not isinstance(returncode, bool) and returncode < 0:
        return _MemoryScanFailure(stage, "external_signal", retryable=True)
    return _MemoryScanFailure(stage, "external_failure")


def _run_scan_external(
    command: list[str],
    *,
    timeout: int,
    check: bool,
    stage: str,
    cwd: str | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        return run_external(
            command,
            timeout=timeout,
            check=check,
            cwd=cwd,
        )
    except (ExternalToolError, OSError) as exc:
        raise _external_scan_failure(stage, exc) from exc


def _positive_pid(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 0xFFFFFFFF:
        return None
    return value


def _bounded_process_name(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    name = value.strip()
    if not name or len(name) > 260 or any(ord(character) < 32 for character in name):
        return None
    return name


def _required_counter(record: Mapping[str, object], key: str) -> int:
    """Read one non-negative internal counter without truthy coercion."""

    value = record.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise _MemoryScanFailure("internal", "internal_failure")
    return value


def _malfind_candidate_rows(
    rows: list[dict[str, object]],
    *,
    require_process_name: bool,
) -> dict[int, dict[str, object]]:
    """Summarize the complete bounded malfind population without selecting a target."""

    if len(rows) > _MAX_MALFIND_DUMPS:
        raise _MemoryScanFailure("memory_extraction_output", "resource_limit")
    candidates: dict[int, dict[str, object]] = {}
    for row in rows:
        pid = _positive_pid(row.get("PID"))
        process = _bounded_process_name(row.get("Process"))
        if pid is None or (require_process_name and process is None):
            raise _MemoryScanFailure("memory_extraction_output", "invalid_output")
        candidate = candidates.setdefault(
            pid,
            {
                "pid": pid,
                "process": process,
                "regions": 0,
                "portable_executable_header_regions": 0,
            },
        )
        if candidate["process"] != process:
            raise _MemoryScanFailure("memory_extraction_output", "integrity_failure")
        candidate["regions"] = _required_counter(candidate, "regions") + 1
        note = str(row.get("Notes") or "").strip().casefold()
        if note in {"mz header", "pe header"}:
            candidate["portable_executable_header_regions"] = (
                _required_counter(candidate, "portable_executable_header_regions") + 1
            )
    if len(candidates) > _MAX_MALFIND_CANDIDATES:
        raise _MemoryScanFailure("memory_extraction_output", "resource_limit")
    return candidates


def _malfind_artifact_pid(
    artifact: Path,
    *,
    rows: list[dict[str, object]],
    candidate_pids: set[int],
    selected_pid: int | None,
) -> int:
    """Bind a private dump filename back to the PID reported by Volatility."""

    by_filename: dict[str, int] = {}
    for row in rows:
        pid = _positive_pid(row.get("PID"))
        file_output = row.get("File output")
        if pid is None or not isinstance(file_output, str):
            continue
        basename = Path(file_output).name
        if (
            not basename
            or basename in {"Disabled", "Error outputting to file"}
            or basename != file_output
        ):
            continue
        previous = by_filename.get(basename)
        if previous is not None and previous != pid:
            raise _MemoryScanFailure("memory_extraction_output", "integrity_failure")
        by_filename[basename] = pid

    pid = by_filename.get(artifact.name)
    if pid is None:
        match = _MALFIND_DUMP_PID.search(artifact.name)
        pid = int(match.group("pid")) if match is not None else None
    # Retain compatibility with older/synthetic Volatility renderers that omit
    # the PID from a filename when the command selected exactly one process.
    if pid is None and selected_pid is not None and candidate_pids == {selected_pid}:
        pid = selected_pid
    if pid is None or pid not in candidate_pids:
        raise _MemoryScanFailure("artifact_validation", "integrity_failure")
    return pid


def _rank_malfind_candidates(
    candidates: dict[int, dict[str, object]],
    items: list[dict[str, object]],
) -> tuple[list[dict[str, object]], dict[str, object]]:
    """Return evidence-only ranking and a fail-closed unique-selection state."""

    for item in items:
        pid = _positive_pid(item.get("pid"))
        candidate = candidates.get(pid or -1)
        if candidate is None:
            raise _MemoryScanFailure("artifact_validation", "integrity_failure")
        candidate.setdefault("artifacts_scanned", 0)
        candidate.setdefault("artifacts_detected", 0)
        candidate.setdefault("detection_names", set())
        candidate["artifacts_scanned"] = _required_counter(candidate, "artifacts_scanned") + 1
        if item.get("scan_status") == "detected":
            candidate["artifacts_detected"] = _required_counter(candidate, "artifacts_detected") + 1
        detection_names = item.get("detection_names", [])
        if not isinstance(detection_names, list):
            raise _MemoryScanFailure("signature_scan_output", "invalid_output")
        cast_names = candidate["detection_names"]
        if not isinstance(cast_names, set):  # pragma: no cover - initialized above
            raise _MemoryScanFailure("internal", "internal_failure")
        cast_names.update(str(name) for name in detection_names)

    ranked: list[dict[str, object]] = []
    for candidate in candidates.values():
        artifacts_scanned = _required_counter(candidate, "artifacts_scanned")
        regions = _required_counter(candidate, "regions")
        if artifacts_scanned != regions:
            raise _MemoryScanFailure("artifact_validation", "integrity_failure")
        raw_names = candidate.get("detection_names")
        if not isinstance(raw_names, set) or any(not isinstance(name, str) for name in raw_names):
            raise _MemoryScanFailure("internal", "internal_failure")
        names = sorted(raw_names)
        artifacts_detected = _required_counter(candidate, "artifacts_detected")
        pe_header_regions = _required_counter(candidate, "portable_executable_header_regions")
        signals: list[str] = []
        if artifacts_detected:
            signals.append("offline_signature_detection")
        if pe_header_regions:
            signals.append("portable_executable_header")
        ranked.append(
            {
                "pid": candidate["pid"],
                "process": candidate["process"],
                "regions": regions,
                "portable_executable_header_regions": pe_header_regions,
                "artifacts_scanned": artifacts_scanned,
                "artifacts_detected": artifacts_detected,
                "detection_names": names,
                "corroboration_signals": signals,
            }
        )

    def rank_key(candidate: Mapping[str, object]) -> tuple[int, int, int, int, int]:
        candidate_names = candidate.get("detection_names")
        if not isinstance(candidate_names, list):
            raise _MemoryScanFailure("internal", "internal_failure")
        return (
            -_required_counter(candidate, "artifacts_detected"),
            -len(candidate_names),
            -_required_counter(candidate, "portable_executable_header_regions"),
            -_required_counter(candidate, "regions"),
            _required_counter(candidate, "pid"),
        )

    ranked.sort(key=rank_key)
    for rank, candidate in enumerate(ranked, start=1):
        candidate["rank"] = rank

    detected = [
        candidate for candidate in ranked if _required_counter(candidate, "artifacts_detected")
    ]
    selection: dict[str, object]
    if len(detected) == 1:
        selection = {
            "status": "unique_signature_supported_candidate",
            "candidate": {
                "pid": detected[0]["pid"],
                "process": detected[0]["process"],
            },
            "basis": "exactly one candidate had an offline signature detection",
        }
    elif detected:
        selection = {
            "status": "ambiguous_multiple_signature_supported_candidates",
            "candidate": None,
            "basis": "more than one candidate had an offline signature detection",
        }
    else:
        selection = {
            "status": "inconclusive_no_signature_supported_candidate",
            "candidate": None,
            "basis": "malfind candidates alone do not uniquely identify an injection target",
        }
    return ranked, selection


def _memory_scan_failure_result(
    pid: int | None,
    failure: _MemoryScanFailure,
    *,
    attempts: int,
    scope: str = "pid",
) -> dict:
    target = f"PID {pid}" if scope == "pid" else "all bounded malfind candidates"
    return {
        "schema_id": _MALWARE_SCAN_SCHEMA_ID,
        "pid": pid,
        "scope": scope,
        "scan_complete": False,
        "failure_stage": failure.stage,
        "failure_code": failure.code,
        "attempts": attempts,
        "coverage": {
            "complete": False,
            "scope": f"malfind executable private-memory regions for {target}",
            "reason": "offline memory malware scan failed closed",
        },
        "error": "offline Volatility/ClamAV memory malware scan failed closed",
    }


def _validate_clamav_database_unchanged(
    database_state: dict[Path, tuple[int, int, int, int]],
) -> None:
    try:
        _assert_clamav_database_unchanged(database_state)
    except Exception as exc:
        raise _MemoryScanFailure(
            "signature_database_revalidation",
            "integrity_failure",
        ) from exc


def _memory_malware_scan_attempt(
    dump_path: str,
    pid: int | None,
    *,
    volatility: str,
    scanner: str,
    database: Path,
    workdir: Path,
    cache_directory: Path,
    symbol_directories: str | None,
) -> dict[str, object]:
    try:
        temporary_context = tempfile.TemporaryDirectory(prefix="malfind-scan-", dir=workdir)
        with temporary_context as temporary:
            dump_directory = Path(temporary).resolve(strict=True)

            version_proc = _run_scan_external(
                [scanner, "--version"],
                timeout=30,
                check=True,
                stage="scanner_identity",
            )
            engine_version = (version_proc.stdout or "").strip()
            if (
                not engine_version
                or len(engine_version) > _CLAMAV_VERSION_MAX_CHARS
                or any(
                    ord(character) < 32 and character not in "\r\n\t"
                    for character in engine_version
                )
            ):
                raise _MemoryScanFailure("scanner_identity", "invalid_output")

            command = [
                volatility,
                "-q",
                "-r",
                "json",
                "--offline",
                "--cache-path",
                str(cache_directory),
            ]
            if symbol_directories is not None:
                command.extend(["--symbol-dirs", symbol_directories])
            command.extend(["-o", str(dump_directory), "-f", dump_path, _MALFIND_PLUGIN])
            if pid is not None:
                command.extend(["--pid", str(pid)])
            command.append("--dump")
            volatility_proc = _run_scan_external(
                command,
                timeout=900,
                check=True,
                cwd=str(dump_directory),
                stage="memory_extraction",
            )
            try:
                decoded = json.loads((volatility_proc.stdout or "").strip())
            except (json.JSONDecodeError, TypeError) as exc:
                raise _MemoryScanFailure(
                    "memory_extraction_output",
                    "invalid_output",
                ) from exc
            rows = decoded if isinstance(decoded, list) else [decoded]
            if any(not isinstance(row, dict) for row in rows):
                raise _MemoryScanFailure("memory_extraction_output", "invalid_output")
            typed_rows = rows
            for row in rows:
                observed_pid = _positive_pid(row.get("PID"))
                if observed_pid is None or (pid is not None and observed_pid != pid):
                    raise _MemoryScanFailure("memory_extraction_output", "integrity_failure")
            candidates = _malfind_candidate_rows(
                typed_rows,
                require_process_name=pid is None,
            )
            if pid is not None and candidates and set(candidates) != {pid}:
                raise _MemoryScanFailure("memory_extraction_output", "integrity_failure")

            try:
                entries = sorted(dump_directory.iterdir(), key=lambda path: path.name)
            except OSError as exc:
                raise _MemoryScanFailure("artifact_validation", "integrity_failure") from exc
            if len(entries) > _MAX_MALFIND_DUMPS:
                raise _MemoryScanFailure("artifact_validation", "resource_limit")
            if rows and not entries:
                raise _MemoryScanFailure("memory_extraction_output", "invalid_output")
            if len(entries) != len(rows):
                raise _MemoryScanFailure("artifact_validation", "integrity_failure")

            artifact_records: list[tuple[Path, int, str, int, tuple[int, int, int, int]]] = []
            total_bytes = 0
            for artifact in entries:
                artifact_pid = _malfind_artifact_pid(
                    artifact,
                    rows=typed_rows,
                    candidate_pids=set(candidates),
                    selected_pid=pid,
                )
                try:
                    artifact_sha256, artifact_bytes, identity = _stable_regular_file_identity(
                        artifact
                    )
                except (OSError, ValueError) as exc:
                    raise _MemoryScanFailure(
                        "artifact_validation",
                        "integrity_failure",
                    ) from exc
                total_bytes += artifact_bytes
                if total_bytes > _MAX_MALFIND_TOTAL_BYTES:
                    raise _MemoryScanFailure("artifact_validation", "resource_limit")
                artifact_records.append(
                    (artifact, artifact_pid, artifact_sha256, artifact_bytes, identity)
                )

            detections_by_artifact: dict[str, tuple[str, ...]] = {}
            if entries:
                scan_proc = _run_scan_external(
                    [
                        scanner,
                        "--no-summary",
                        "--infected",
                        "--stdout",
                        f"--database={database}",
                        "--official-db-only=yes",
                        "--allmatch=yes",
                        "--bytecode=yes",
                        "--bytecode-unsigned=no",
                        "--detect-pua=no",
                        "--scan-archive=no",
                        f"--max-files={_MAX_MALFIND_DUMPS}",
                        "--max-filesize=64M",
                        "--max-scansize=64M",
                        *(artifact.name for artifact in entries),
                    ],
                    timeout=300,
                    check=False,
                    cwd=str(dump_directory),
                    stage="signature_scan",
                )
                if scan_proc.returncode not in {0, 1}:
                    raise _returncode_scan_failure("signature_scan", scan_proc.returncode)
                try:
                    detections_by_artifact = _clamav_detection_map(
                        scan_proc.stdout or "",
                        entries,
                    )
                except ValueError as exc:
                    raise _MemoryScanFailure(
                        "signature_scan_output",
                        "invalid_output",
                    ) from exc
                if (scan_proc.returncode == 1) is not any(detections_by_artifact.values()):
                    raise _MemoryScanFailure("signature_scan_output", "invalid_output")

            items: list[dict[str, object]] = []
            for (
                artifact,
                artifact_pid,
                artifact_sha256,
                artifact_bytes,
                identity,
            ) in artifact_records:
                detections = detections_by_artifact.get(artifact.name, ())
                try:
                    after = artifact.lstat()
                except OSError as exc:
                    raise _MemoryScanFailure(
                        "artifact_validation",
                        "integrity_failure",
                    ) from exc
                if identity != (
                    int(after.st_dev),
                    int(after.st_ino),
                    int(after.st_size),
                    int(after.st_mtime_ns),
                ):
                    raise _MemoryScanFailure("artifact_validation", "integrity_failure")
                item: dict[str, object] = {
                    "pid": artifact_pid,
                    "process": candidates[artifact_pid]["process"],
                    "artifact_sha256": artifact_sha256,
                    "artifact_bytes": artifact_bytes,
                    "scan_status": "detected" if detections else "no_match",
                }
                if detections:
                    item["detection_names"] = list(detections)
                items.append(item)
    except _MemoryScanFailure:
        raise
    except (OSError, RuntimeError) as exc:
        raise _MemoryScanFailure(
            "runtime_configuration",
            "configuration_failure",
        ) from exc
    except Exception as exc:
        raise _MemoryScanFailure("internal", "internal_failure") from exc

    return {
        "scanner_version": engine_version,
        "malfind_rows": len(rows),
        "candidates": candidates,
        "items": items,
        "bytes_scanned": total_bytes,
    }


_CONTAINER_EVIDENCE_DIR = "/evidence"
_CONTAINER_SOURCE_DIR = "/dfa-src"
_CONTAINER_SCRATCH_DIR = "/scan"
_CONTAINER_SYMBOL_DIR = "/symbols"
#: The image ships no symbols; it expects them mounted, and Volatility also
#: unpacks its packaged archive below this path.
_CONTAINER_PACKAGED_SYMBOLS = (
    "/opt/venv/lib/python3.12/site-packages/volatility3/symbols/windows"
)
#: Mirrors the launcher's scratch policy for this exact surface: the dumped
#: regions are executable images, so the mount that holds them denies execution.
_CONTAINER_SCRATCH_OPTIONS = "rw,noexec,nosuid,nodev,size=1g,mode=0700,uid=10001,gid=10001"
_CONTAINER_FALLBACK_BUDGET_SECONDS = 600.0
_ENVELOPE_BEGIN = "<<<DFA-MEMORY-SCAN-ENVELOPE-V1>>>"
_ENVELOPE_END = "<<<DFA-MEMORY-SCAN-ENVELOPE-END>>>"


def _memory_scan_container_image() -> str:
    """Return the configured scan image, or empty to keep the native path."""

    return os.environ.get("DFA_MEMORY_SCAN_DOCKER_IMAGE", "").strip()


def _decoded_scan_envelope(stdout: str) -> dict | None:
    """Extract one delimited envelope and check its closed shape."""

    begin = stdout.find(_ENVELOPE_BEGIN)
    end = stdout.find(_ENVELOPE_END, begin + 1)
    if begin < 0 or end < 0:
        return None
    try:
        payload = json.loads(stdout[begin + len(_ENVELOPE_BEGIN) : end].strip())
    except (json.JSONDecodeError, TypeError):
        return None
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != _SCAN_ENVELOPE_VERSION
        or not isinstance(payload.get("attempts"), int)
        or isinstance(payload.get("attempts"), bool)
        or payload["attempts"] < 0
    ):
        return None
    status = payload.get("status")
    if status == "failed":
        if (
            payload.get("failure_stage") not in _MEMORY_SCAN_FAILURE_STAGES
            or payload.get("failure_code") not in _MEMORY_SCAN_FAILURE_CODES
        ):
            return None
        return payload
    if status != "complete":
        return None
    outcome = payload.get("outcome")
    if (
        not isinstance(payload.get("signature_database"), dict)
        or not isinstance(outcome, dict)
        or not isinstance(outcome.get("items"), list)
        or not isinstance(outcome.get("candidates"), dict)
    ):
        return None
    # JSON object keys are always text, while the candidate map is keyed by PID
    # and is looked up with an integer downstream. Restore the native key type
    # here rather than weakening the lookup.
    restored: dict[int, object] = {}
    for key, value in outcome["candidates"].items():
        if not isinstance(key, str) or re.fullmatch(r"[0-9]{1,10}", key) is None:
            return None
        pid = _positive_pid(int(key))
        if pid is None or pid in restored or not isinstance(value, dict):
            return None
        restored[pid] = value
    outcome["candidates"] = restored
    return payload


def _transport_failure(reason: str) -> dict:
    return {
        "schema_version": _SCAN_ENVELOPE_VERSION,
        "status": "failed",
        "attempts": 0,
        "failure_stage": "runtime_configuration",
        "failure_code": reason,
    }


def _host_symbol_directory() -> Path | None:
    """Return the single local symbol directory to expose to the container.

    Only one directory is passed: the container path is fixed, so a
    semicolon-separated list could not be reproduced without inventing a
    mapping. A configuration with several directories therefore falls back to
    whatever the image itself provides rather than silently using only the first.
    """

    configured = os.environ.get("DFA_VOL_SYMBOL_DIRS", "").strip()
    if not configured or ";" in configured:
        return None
    candidate = Path(configured).expanduser()
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    return resolved if resolved.is_dir() else None


def _containerized_scan_envelope(
    dump_path: str,
    selected_pid: int | None,
    *,
    image: str,
) -> tuple[dict, dict]:
    """Run the scan inside one throwaway container and decode its envelope."""

    from forensic_agent.core.environ import resolve_tool
    from forensic_agent.core.toolkit import effective_external_timeout

    route: dict[str, object] = {"execution": "container", "image": image}
    docker = resolve_tool(["docker"], "DFA_DOCKER")
    if not docker:
        return _transport_failure("dependency_unavailable"), route

    evidence = Path(dump_path).resolve()
    source_root = Path(__file__).resolve().parents[2]
    seed = os.environ.get("DFA_VOL_CACHE_SEED", "").strip()
    budget = effective_external_timeout(_CONTAINER_FALLBACK_BUDGET_SECONDS)
    if budget is None:
        return _transport_failure("external_timeout"), route

    command = [
        docker,
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--tmpfs",
        f"{_CONTAINER_SCRATCH_DIR}:{_CONTAINER_SCRATCH_OPTIONS}",
        # The image points HOME, XDG_CACHE_HOME and MPLCONFIGDIR below /tmp and
        # normally creates them in its entrypoint, which this route bypasses.
        # With a read-only root they must come from a writable mount instead.
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=256m,mode=1777",
        # Volatility unpacks its packaged symbol archive next to itself, which a
        # read-only root forbids. Giving it exactly that directory keeps the
        # rest of the filesystem immutable.
        "--tmpfs",
        f"{_CONTAINER_PACKAGED_SYMBOLS}:rw,noexec,nosuid,nodev,size=1g,mode=0755,uid=10001,gid=10001",
        "-v",
        f"{evidence.parent}:{_CONTAINER_EVIDENCE_DIR}:ro",
        "-v",
        f"{source_root}:{_CONTAINER_SOURCE_DIR}:ro",
        "-e",
        f"PYTHONPATH={_CONTAINER_SOURCE_DIR}",
        "-e",
        f"DFA_VOL_WORKDIR={_CONTAINER_SCRATCH_DIR}",
        "-e",
        f"DFA_VOL_CACHE={_CONTAINER_SCRATCH_DIR}/vol-cache",
        "-e",
        f"DFA_MEMORY_SCAN_BUDGET_SECONDS={max(1.0, budget - 15.0):.0f}",
    ]
    if seed:
        seed_path = Path(seed).resolve()
        command.extend(
            [
                "-v",
                f"{seed_path}:{_CONTAINER_SCRATCH_DIR}-seed:ro",
                "-e",
                f"DFA_VOL_CACHE_SEED={_CONTAINER_SCRATCH_DIR}-seed",
            ]
        )
    host_symbols = _host_symbol_directory()
    if host_symbols is not None:
        command.extend(
            [
                "-v",
                f"{host_symbols}:{_CONTAINER_SYMBOL_DIR}:ro",
                "-e",
                f"DFA_VOL_SYMBOL_DIRS={_CONTAINER_SYMBOL_DIR}",
            ]
        )
    command.extend(
        [
            "--entrypoint",
            "python",
            image,
            "-m",
            "forensic_agent.tools.memory_scan_container",
            "--dump-path",
            f"{_CONTAINER_EVIDENCE_DIR}/{evidence.name}",
        ]
    )
    if selected_pid is not None:
        command.extend(["--pid", str(selected_pid)])

    try:
        proc = run_external(command, timeout=budget, check=False)
    except ExternalToolError:
        return _transport_failure("external_timeout"), route
    except Exception:
        return _transport_failure("external_failure"), route
    if proc.returncode != 0:
        return _transport_failure("external_failure"), route
    envelope = _decoded_scan_envelope(proc.stdout or "")
    if envelope is None:
        return _transport_failure("invalid_output"), route
    return envelope, route


def offline_scan_pipeline(
    dump_path: str,
    selected_pid: int | None,
    *,
    volatility: str,
    scanner: str,
) -> dict:
    """Run the whole offline scan and return a closed-shape envelope.

    This is the unit of work that can execute somewhere other than the calling
    process.  It therefore never raises outward and never returns objects that
    do not survive serialization: every outcome, including every closed-class
    failure, is expressed in the returned mapping.

    ``attempts`` is zero when the run failed before the retry loop began, which
    is the case for every configuration and signature-database failure.
    """

    attempts = 0
    try:
        try:
            database = _clamav_database_directory()
        except Exception as exc:
            raise _MemoryScanFailure(
                "runtime_configuration",
                "configuration_failure",
            ) from exc
        try:
            database_identity, database_state = _clamav_database_identity(database)
        except Exception as exc:
            raise _MemoryScanFailure(
                "signature_database_validation",
                "validation_failure",
            ) from exc
        try:
            runtime_context = _runtime_directories()
            with runtime_context as (workdir, cache_directory):
                symbol_directories = _symbol_directories()
                outcome: dict[str, object] | None = None
                for attempt in range(1, _MAX_MEMORY_SCAN_ATTEMPTS + 1):
                    attempts = attempt
                    try:
                        outcome = _memory_malware_scan_attempt(
                            dump_path,
                            selected_pid,
                            volatility=volatility,
                            scanner=scanner,
                            database=database,
                            workdir=workdir,
                            cache_directory=cache_directory,
                            symbol_directories=symbol_directories,
                        )
                    except _MemoryScanFailure as failure:
                        _validate_clamav_database_unchanged(database_state)
                        if failure.retryable and attempt < _MAX_MEMORY_SCAN_ATTEMPTS:
                            continue
                        raise
                    _validate_clamav_database_unchanged(database_state)
                    break
        except _MemoryScanFailure:
            raise
        except Exception as exc:
            raise _MemoryScanFailure(
                "runtime_configuration",
                "configuration_failure",
            ) from exc
        if outcome is None:
            raise _MemoryScanFailure("internal", "internal_failure")
    except _MemoryScanFailure as failure:
        return {
            "schema_version": _SCAN_ENVELOPE_VERSION,
            "status": "failed",
            "attempts": attempts,
            "failure_stage": failure.stage,
            "failure_code": failure.code,
        }
    except Exception:
        return {
            "schema_version": _SCAN_ENVELOPE_VERSION,
            "status": "failed",
            "attempts": attempts,
            "failure_stage": "internal",
            "failure_code": "internal_failure",
        }
    return {
        "schema_version": _SCAN_ENVELOPE_VERSION,
        "status": "complete",
        "attempts": attempts,
        "signature_database": database_identity,
        "outcome": outcome,
    }


def memory_malware_scan(
    dump_path: str,
    pid: int | None = None,
    scope: str = "pid",
) -> dict:
    """Classify suspicious private executable memory, offline and read-only.

    ``scope="pid"`` dumps only one selected PID. ``scope="all_candidates"``
    enumerates the complete bounded ``windows.malfind`` candidate population and
    scans every dumped region before returning an evidence-only ranking.  The
    latter identifies a unique *signature-supported candidate* only when exactly
    one process has detections; raw RWX/malfind frequency alone never selects a
    target. Dumped bytes stay in private scratch, are never executed or returned,
    and are deleted after the call.
    """

    if not dump_path or not os.path.exists(dump_path):
        return {"error": "memory dump not available (set one with --memory / /memory)."}
    if scope not in _MALWARE_SCAN_SCOPES:
        return {"error": "scope must be 'pid' or 'all_candidates'"}
    if scope == "pid" and _positive_pid(pid) is None:
        return {"error": "pid must be an integer between 1 and 4294967295"}
    if scope == "all_candidates" and pid is not None:
        return {"error": "pid must be omitted when scope is 'all_candidates'"}
    selected_pid = pid if scope == "pid" else None
    image = _memory_scan_container_image()
    if image:
        # The extracted regions are live payloads. Running the scan in a
        # container keeps them on a tmpfs that disappears with the process, so
        # they never reach the host filesystem.
        envelope, route = _containerized_scan_envelope(dump_path, selected_pid, image=image)
    else:
        volatility = vol_path()
        scanner = clamscan_path()
        if not volatility or not scanner:
            return _memory_scan_failure_result(
                selected_pid,
                _MemoryScanFailure("runtime_configuration", "dependency_unavailable"),
                attempts=0,
                scope=scope,
            )
        envelope = offline_scan_pipeline(
            dump_path,
            selected_pid,
            volatility=volatility,
            scanner=scanner,
        )
        route = {"execution": "native"}
    attempts = envelope["attempts"]
    if envelope["status"] != "complete":
        return _memory_scan_failure_result(
            selected_pid,
            _MemoryScanFailure(envelope["failure_stage"], envelope["failure_code"]),
            attempts=attempts,
            scope=scope,
        )
    database_identity = envelope["signature_database"]
    outcome = envelope["outcome"]

    raw_items = outcome["items"]
    if not isinstance(raw_items, list):
        return _memory_scan_failure_result(
            selected_pid,
            _MemoryScanFailure("internal", "internal_failure"),
            attempts=attempts,
            scope=scope,
        )
    items = raw_items
    raw_candidates = outcome.get("candidates")
    if not isinstance(raw_candidates, dict):
        return _memory_scan_failure_result(
            selected_pid,
            _MemoryScanFailure("internal", "internal_failure"),
            attempts=attempts,
            scope=scope,
        )
    try:
        candidates, selection = _rank_malfind_candidates(raw_candidates, items)
    except _MemoryScanFailure as failure:
        return _memory_scan_failure_result(
            selected_pid,
            failure,
            attempts=attempts,
            scope=scope,
        )

    return {
        "schema_id": _MALWARE_SCAN_SCHEMA_ID,
        "scope": scope,
        "pid": selected_pid,
        "volatility_plugin": _MALFIND_PLUGIN,
        "scanner": "ClamAV clamscan",
        "scanner_version": outcome["scanner_version"],
        "signature_database": database_identity,
        "malfind_rows": outcome["malfind_rows"],
        "artifacts_scanned": len(items),
        "bytes_scanned": outcome["bytes_scanned"],
        "artifacts_detected": sum(item["scan_status"] == "detected" for item in items),
        "detections": sum(len(item.get("detection_names", [])) for item in items),
        "candidate_count": len(candidates),
        "candidate_set_complete": True,
        "candidate_ranking": candidates,
        "selection": selection,
        "items": items,
        "total": len(items),
        "offset": 0,
        "truncated": False,
        "scan_complete": True,
        "attempts": attempts,
        # Where the scan executed is part of its provenance: a containerized run
        # and a native run must never be indistinguishable in the recorded provenance.
        "execution_route": route,
        "coverage": {
            "complete": True,
            "scope": (
                f"all dumped malfind executable private-memory regions for PID {selected_pid}"
                if scope == "pid"
                else "all dumped regions for every bounded malfind process candidate"
            ),
        },
    }


#: Addresses and prefixes THIS module treats as "not off the host".  Volatility
#: reports an address; it never reports a verdict that a connection left the
#: machine, so this set is the whole reason the filter below is ours.
_LOCAL_ADDR = {"", "*", "0.0.0.0", "::", "127.0.0.1", "::1"}
_LOCAL_ADDR_PREFIXES = ("127.", "fe80", "::1")
_PROCESS_PARENTAGE_LIMIT = 200
#: Plugins whose rows state a PPID but no parent name, so the link is ours to
#: compute.  ``pstree`` is deliberately absent: Volatility reports parentage
#: itself there, and a caller who wants the parent name should read the tool's
#: own answer rather than a second one this module invented.
_PARENTAGE_JOIN_PLUGINS = ("pslist", "psscan")


def _compute_process_parentage(rows: list) -> tuple[list[dict], dict]:
    """Match each row's PPID against the PID column of that same plugin output.

    A PPID with no matching PID stays unresolved rather than receiving a
    placeholder name.  The parent may have exited, may be hidden, or may simply
    lie outside this plugin's scope, and this module cannot tell those apart.
    """

    names_by_pid: dict[int, str] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        pid, name = row.get("PID"), row.get("ImageFileName")
        if isinstance(pid, int) and not isinstance(pid, bool) and isinstance(name, str) and name:
            names_by_pid.setdefault(pid, name)

    links: list[dict] = []
    unresolved: list[int] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        ppid = row.get("PPID")
        link = {"pid": row.get("PID"), "process": row.get("ImageFileName"), "ppid": ppid}
        if isinstance(ppid, int) and not isinstance(ppid, bool):
            if ppid in names_by_pid:
                link["parent_process"] = names_by_pid[ppid]
            elif ppid not in unresolved:
                unresolved.append(ppid)
        links.append(link)
    return links, {
        "unresolved_parent_pids": unresolved[:_PROCESS_PARENTAGE_LIMIT],
        "unresolved_parent_pid_count": len(unresolved),
    }


def _compute_external_connections(rows: list) -> tuple[list[dict], dict]:
    """Keep the rows whose ForeignAddr lies outside THIS module's local set.

    Volatility reports the address; the judgement that an address is off-host is
    made here, by :data:`_LOCAL_ADDR` and :data:`_LOCAL_ADDR_PREFIXES`.  Which
    rows survive is therefore our claim about the plugin's output rather than a
    column it emitted, which is why this is a result of its own and not a count
    attached to the read.
    """

    external: list[dict] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        foreign = str(row.get("ForeignAddr", ""))
        if foreign in _LOCAL_ADDR or foreign.startswith(_LOCAL_ADDR_PREFIXES):
            continue
        external.append(
            {
                "proto": row.get("Proto"),
                "local": row.get("LocalAddr"),
                "foreign": foreign,
                "fport": row.get("ForeignPort"),
                "state": row.get("State"),
                "pid": row.get("PID"),
                "owner": row.get("Owner"),
            }
        )
    return external, {}


def _compute_injection_candidates(rows: list) -> tuple[list[dict], dict]:
    """Count malfind's regions per (PID, Process) and calibrate what that means.

    malfind reports one row per suspicious region.  Collapsing those rows into a
    per-process region count, and the reading that a lone candidate is not proof
    of a target, are both this module's, so they travel together in one derived
    result instead of beside rows the plugin produced.
    """

    import collections

    counts: collections.Counter = collections.Counter()
    for row in rows:
        if not isinstance(row, dict):
            continue
        counts[(row.get("PID"), row.get("Process"))] += 1
    candidates = [
        {"pid": pid, "process": process, "regions": regions}
        for (pid, process), regions in counts.items()
    ]
    return candidates, {
        "target_selection_status": (
            "single_malfind_candidate_requires_corroboration"
            if len(candidates) == 1
            else (
                "ambiguous_multiple_malfind_candidates"
                if len(candidates) > 1
                else "no_malfind_candidate"
            )
        ),
        "target_selection_note": (
            "malfind entries are candidates, not unique proof of an injection target; "
            "corroborate the complete candidate set before attribution"
        ),
    }


@dataclass(frozen=True, slots=True)
class _DerivedMemoryOperation:
    """One computation ``memory_query`` performs OVER a Volatility plugin's rows.

    Everything described here is this module's, not Volatility's, so each entry
    is returned as a result of its own epistemic class instead of a block riding
    inside the observed read — where a reader had no way to tell an inference
    from the tool's own observation, whatever the block was labelled.

    ``plugins`` names the outputs whose columns the computation reads; ``None``
    means the computation reads no particular column and applies to any plugin.
    """

    schema_id: str
    method: str
    method_version: str
    basis: str
    plugins: tuple[str, ...] | None
    #: Why a plugin outside ``plugins`` is refused, rendered with ``plugin`` and
    #: ``plugins`` and read after the operation name.
    refusal: str
    #: Returns the computed entries plus the fields that describe them.
    compute: Callable[[list], tuple[list[dict], dict]]


#: Every ``memory_query`` operation other than the observed plugin read.  The
#: classifier registers exactly these names as DERIVED, and the test that
#: cross-checks the two registries fails until it does, so an operation cannot
#: reach a caller unclassified.
_DERIVED_MEMORY_OPERATIONS: dict[str, _DerivedMemoryOperation] = {
    "process_parentage": _DerivedMemoryOperation(
        schema_id="forensic.memory-process-parentage.v1",
        method="memory.process_parentage_join",
        method_version="1",
        basis=(
            "each row's PPID matched against the PID column of this same plugin "
            "output; the parent name is the product of that join, not a field "
            "Volatility reported"
        ),
        plugins=_PARENTAGE_JOIN_PLUGINS,
        refusal=(
            "joins the PID and PPID columns of {plugins}; '{plugin}' does not report "
            "both, and pstree reports parentage itself"
        ),
        compute=_compute_process_parentage,
    ),
    "external_connections": _DerivedMemoryOperation(
        schema_id="forensic.memory-network-summary.v1",
        method="memory.external_connection_filter",
        method_version="1",
        basis=(
            "every row whose ForeignAddr is outside this module's own set of local "
            "addresses and prefixes; the plugin reports the address, never a verdict "
            "that the connection left the host"
        ),
        plugins=("netscan", "netstat"),
        refusal=(
            "tests the ForeignAddr column of {plugins} against this module's own "
            "local-address set; '{plugin}' reports no ForeignAddr column"
        ),
        compute=_compute_external_connections,
    ),
    "injection_candidates": _DerivedMemoryOperation(
        schema_id="forensic.memory-injection-candidates.v1",
        method="memory.injection_candidate_summary",
        method_version="1",
        basis=(
            "malfind's region rows grouped by the process they were found in; the "
            "per-process region count and the candidate set are this grouping, not a "
            "finding malfind reported"
        ),
        plugins=("malfind",),
        refusal=(
            "groups the region rows {plugins} emits per process; '{plugin}' reports "
            "no such rows"
        ),
        compute=_compute_injection_candidates,
    ),
    "field_distribution": _DerivedMemoryOperation(
        schema_id="forensic.row-field-summary.v1",
        method="memory.row_field_distribution",
        method_version="1",
        basis=(
            "the values of each low-cardinality field counted over the complete "
            "plugin output; the distribution is this arithmetic, not something the "
            "plugin stated"
        ),
        # The counting reads no named column, so it describes any plugin's rows.
        plugins=None,
        refusal="",
        compute=_compute_field_distribution,
    ),
}

#: Operations ``memory_query`` services, each with its own epistemic class in the
#: authoritative classifier.  ``plugin_rows`` returns what Volatility emitted;
#: every other entry is OUR computation over that output and is asked for by name.
MEMORY_QUERY_OPERATIONS: tuple[str, ...] = (
    _DEFAULT_MEMORY_OPERATION,
    *_DERIVED_MEMORY_OPERATIONS,
)


def _derived_operation_result(
    operation: str,
    derived: _DerivedMemoryOperation,
    plugin: str,
    canonical: str,
    rows: list,
    *,
    offset: int,
    limit: int,
    filter: str | None,
    cited_inputs: list[dict],
) -> dict:
    """Return one computation over a plugin's output as its own DERIVED result.

    The result names what it was computed from: the caller's confirmed prior
    results when it has them, otherwise the observed read this call performed,
    which below the runtime standardizer is the only citation that exists.

    ``summary_scope`` and ``source_row_count`` state that the computation ran over
    the plugin's COMPLETE output rather than over the page a caller asked for, so
    a truncated page of raw rows can be judged against it.  The entries themselves
    go through the shared envelope, so a summary the page limit or the byte guard
    shortened says so instead of silently describing only part of the output.
    """

    from forensic_agent.core.toolio import shape

    items, described = derived.compute(rows)
    inputs = list(cited_inputs) or [
        observed_operation_input(
            tool="memory_query",
            operation=_DEFAULT_MEMORY_OPERATION,
            parameters={"plugin": PLUGINS.get(canonical, canonical)},
            source_row_count=len(rows),
        )
    ]
    return {
        "plugin": plugin,
        "operation": operation,
        "schema_id": derived.schema_id,
        "evidence_class": "derived",
        "derivation": {
            "method": derived.method,
            "method_version": derived.method_version,
            "derivation_inputs": inputs,
            "basis": derived.basis,
        },
        "summary_scope": "full_plugin_output",
        "source_row_count": len(rows),
        "count": len(items),
        **described,
        **shape(items, offset=offset, limit=limit, filter=filter),
    }
