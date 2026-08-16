"""Functions for memory analysis and corroboration of suspicious regions."""

from __future__ import annotations

import time
from typing import Literal

from langchain_core.tools import StructuredTool
from pydantic import Field, create_model

from forensic_agent.agent.tool_bindings.context import ToolBuildContext
from forensic_agent.agent.tool_operations import MEMORY_PLUGINS
from forensic_agent.core.repro import canonical_json, sha256_hex
from forensic_agent.tools.memory_tool import PLUGINS as _BACKEND_MEMORY_PLUGINS

# Import-time proof that every plugin the model-visible curated enum offers can be
# resolved by the backend map (short name -> dotted Volatility class).  The
# relation is subset, not equality: the backend deliberately knows more plugins
# than the surface exposes.  A curated plugin the backend cannot resolve fails
# here rather than at the run that selects it.
_MISSING_BACKEND_PLUGINS = frozenset(MEMORY_PLUGINS) - frozenset(_BACKEND_MEMORY_PLUGINS)
if _MISSING_BACKEND_PLUGINS:
    raise RuntimeError(
        "the curated memory plugin enum names plugins the backend cannot resolve: "
        f"{sorted(_MISSING_BACKEND_PLUGINS)}"
    )


def _build_memory_tools(context: ToolBuildContext) -> list[StructuredTool]:
    """Build the corresponding registry segment without changing model schemas."""

    memory_path = context.memory_path
    tool_argument_allowlists = context.tool_argument_allowlists
    _emit = context.emit
    _begin = context.begin
    tools: list[StructuredTool] = []

    from forensic_agent.tools.memory_tool import MEMORY_QUERY_OPERATIONS
    from forensic_agent.tools.memory_tool import memory_query as _mq

    memory_plugin_values: tuple[str, ...] | None = None
    if tool_argument_allowlists is not None:
        memory_rules = tool_argument_allowlists.get("memory_query", {})
        raw_plugins = memory_rules.get("plugin")
        if raw_plugins is not None:
            if isinstance(raw_plugins, (str, bytes)):
                raise ValueError("memory plugin allowlist must be a collection")
            normalized_plugins = tuple(
                sorted(
                    {
                        value.strip()
                        for value in raw_plugins
                        if isinstance(value, str) and value.strip()
                    }
                )
            )
            if len(normalized_plugins) != len(raw_plugins):
                raise ValueError("memory plugin allowlist is malformed")
            memory_plugin_values = normalized_plugins

    def memory_query(
        plugin: str,
        limit: int = 50,
        offset: int = 0,
        filter: str | None = None,
        operation: str = "plugin_rows",
    ) -> dict:
        """Run one Volatility 3 plugin on the memory dump. Choose the plugin by the
                category the question falls in, then read its rows:

                - OS / image identity: info (OS edition, build, capture time), statistics, verinfo
                - Processes: pslist, pstree, psscan (hidden/terminated), psxview, cmdline
                  (command line and image path), envars, getsids (owner SID), privileges,
                  sessions (logon sessions), handles, thrdscan, hollowprocesses
                - Injected / loaded code: malfind (injected RWX regions), ldrmodules (hidden
                  DLLs), dlllist (loaded modules), iat, vadinfo
                - Network connections: netscan, netstat
                - Kernel / drivers / hooks: modules, modscan, driverscan, callbacks, ssdt,
                  mutantscan
                - Services (a malware installed as a service, and its on-disk binary path,
                  lives here): svcscan, svclist, getservicesids
                - Credentials: hashdump (local SAM NTLM hashes), cachedump (cached domain
                  credentials), lsadump (LSA secrets)
                - Registry persistence / execution: hivelist, userassist, amcache,
                  scheduled_tasks, certificates
                - Files / timestamps: filescan (file objects), dumpfiles, mftscan (MFT
                  records, useful for timestomping)
                - Timeline across artifacts: timeliner

                NOT a closed list — any fully-qualified dotted Volatility plugin also works
                (e.g. linux.pslist.PsList). Supports offset/limit pagination and a substring
                `filter` (PID, process name, IP, filename).

                Args:
                    plugin: A short name from the categories above, or any fully qualified
                        Volatility 3 plugin name containing dots.
                    limit: Rows per page, default 50. A byte cap may return fewer.
                    offset: Index of the first row; continue from the previous page's
                        next_offset.
                    filter: Plain substring matched against each serialized row, such as
                        a PID, process name, IP address or file name. Not a query
                        expression: comparison syntax matches nothing.
                    operation: 'plugin_rows' (default) returns the rows the plugin
                        emitted, and nothing else. Every other value returns a
                        separate derived result computed over those rows:
                        'process_parentage' matches each row's PPID against the PID
                        column (pslist/psscan); 'external_connections' keeps the rows
                        whose ForeignAddr is outside this tool's own local-address set
                        (netscan/netstat); 'injection_candidates' counts malfind's
                        regions per process (malfind); 'field_distribution' describes
                        how each low-cardinality field's values are distributed (any
                        plugin, and the way to read a plugin whose rows do not fit a
                        page). None of these is something Volatility reported. Ask
                        pstree for parentage the plugin itself states.
                """
        call_arguments = {"plugin": plugin, "filter": filter, "operation": operation}
        # A Volatility scan over a multi-gigabyte image runs for minutes; announce
        # the call before it starts so the feed shows it working, not a frozen pane.
        _begin("memory_query", call_arguments)
        t0 = time.time()
        r = _mq(memory_path, plugin, limit, offset, filter, operation)  # type: ignore[arg-type]
        _emit("memory_query", call_arguments, t0)
        return r

    if memory_plugin_values is None:
        tools.append(StructuredTool.from_function(memory_query))
    else:
        plugin_names = ", ".join(memory_plugin_values)
        description = (
            "Run one permitted Volatility 3 plugin on this memory dump. "
            f"The active read-only policy permits exactly: {plugin_names}. "
            "Use offset/limit pagination and an optional substring filter."
        )
        plugin_literal = Literal.__getitem__(memory_plugin_values)
        schema_name = (
            "MemoryQueryArguments_" + sha256_hex(canonical_json(memory_plugin_values))[:12]
        )
        args_schema = create_model(
            schema_name,
            plugin=(
                plugin_literal,
                Field(description=f"Permitted values: {plugin_names}"),
            ),
            limit=(int, Field(default=50, ge=1)),
            offset=(int, Field(default=0, ge=0)),
            filter=(str | None, Field(default=None)),
            # A policy-restricted plugin set restricts the plugin, not which
            # question may be asked of it: dropping the operation here would make
            # every derived computation unreachable and silently return the
            # observed rows.  The values come from the tool itself so a new
            # operation cannot be reachable in one surface and absent in the other.
            operation=(
                Literal.__getitem__(MEMORY_QUERY_OPERATIONS),
                Field(
                    default="plugin_rows",
                    description=(
                        "plugin_rows returns what the plugin emitted; every other "
                        "value returns a separate derived result this tool computed "
                        "over those rows"
                    ),
                ),
            ),
        )
        tools.append(
            StructuredTool.from_function(
                memory_query,
                description=description,
                args_schema=args_schema,
            )
        )

    from forensic_agent.tools.memory_tool import (
        memory_malware_scan as _memory_malware_scan,
    )

    def memory_malware_scan(
        pid: int | None = None,
        scope: Literal["pid", "all_candidates"] = "pid",
    ) -> dict:
        """Offline signature-scan executable private-memory regions dumped by
                Volatility 3 windows.malfind. scope='pid' scans one positive PID.
                scope='all_candidates' scans the complete bounded malfind population and
                returns a structured candidate ranking. A unique signature-supported
                candidate is reported only when exactly one process has detections;
                RWX/malfind frequency alone is not unique proof. Dumped bytes remain in
                private controlled scratch, are never executed or returned, and are
                deleted after the call. A no-match is not proof that memory is benign.
                Partial coverage or an empty scanned-artifact set cannot establish a
                negative result.

                Args:
                    pid: Positive process ID. Required with scope='pid'; omit it
                        with scope='all_candidates'.
                    scope: 'pid' scans one named process. 'all_candidates' scans
                        and ranks the complete bounded malfind population."""
        t0 = time.time()
        r = _memory_malware_scan(
            memory_path,  # type: ignore[arg-type]
            pid=pid,
            scope=scope,
        )
        _emit("memory_malware_scan", {"pid": pid, "scope": scope}, t0)
        return r

    scan_scope_values: tuple[str, ...] | None = None
    if tool_argument_allowlists is not None:
        scan_rules = tool_argument_allowlists.get("memory_malware_scan", {})
        raw_scopes = scan_rules.get("scope")
        if raw_scopes is not None:
            if isinstance(raw_scopes, (str, bytes)):
                raise ValueError("memory malware scan scope allowlist must be a collection")
            scan_scope_values = tuple(
                sorted(
                    {
                        value.strip()
                        for value in raw_scopes
                        if isinstance(value, str)
                        and value.strip() in {"pid", "all_candidates"}
                    }
                )
            )
            if len(scan_scope_values) != len(raw_scopes):
                raise ValueError("memory malware scan scope allowlist is malformed")
    if scan_scope_values is None:
        tools.append(StructuredTool.from_function(memory_malware_scan))
    else:
        scope_literal = Literal.__getitem__(scan_scope_values)
        schema_name = (
            "MemoryMalwareScanArguments_"
            + sha256_hex(canonical_json(scan_scope_values))[:12]
        )
        scan_args_schema = create_model(
            schema_name,
            scope=(
                scope_literal,
                Field(description="Select one PID or the complete bounded candidate set"),
            ),
            pid=(
                int | None,
                Field(
                    default=None,
                    ge=1,
                    le=0xFFFFFFFF,
                    description=(
                        "Required only for scope='pid'; omit for scope='all_candidates'"
                    ),
                ),
            ),
        )
        tools.append(
            StructuredTool.from_function(
                memory_malware_scan,
                args_schema=scan_args_schema,
            )
        )

    return tools
