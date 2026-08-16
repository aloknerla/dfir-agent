"""Funkcije za Windows registre, zapisnike i sistemske artefakte."""

from __future__ import annotations

import time

from langchain_core.tools import StructuredTool

from forensic_agent.agent.tool_bindings.context import ToolBuildContext
from forensic_agent.agent.tool_operations import _RegRipperPluginName as _RegRipperPlugin
from forensic_agent.core.tool_availability import (
    ExternalToolUnavailable,
    missing_dependencies_for,
)

# The RegRipper plugin enum is single-sourced in the shared operation registry
# (``tool_operations._RegRipperPluginName``), not restated here: two hand-kept
# copies of the same nine-name allowlist would drift.  Binding the owner's
# ``Literal`` keeps this binding's ``plugin`` annotation identical to the
# registered schema by construction rather than by a copied list.


def _build_windows_tools(context: ToolBuildContext, built: list[StructuredTool]) -> None:
    """Izgradi pripadajući dio registra bez promjene modelskih shema.

    Piše u akumulator pozivatelja jer ovaj dio registra na kraju može prijaviti
    nedostupnost: funkcije izgrađene prije te prijave ostaju modelu dostupne.
    """

    disk = context.disk
    controlled_scratch = context.controlled_scratch
    _emit = context.emit

    from forensic_agent.tools.registry_tool import registry_query as _rq

    def registry_query(
        hive: str,
        filter: str | None = None,
        offset: int = 0,
        limit: int = 50,
        key: str | None = None,
        depth: int = 0,
        operation: str = "registry_values",
    ) -> dict:
        """Query a Windows registry hive (SYSTEM/SOFTWARE/SAM/SECURITY or
                NTUSER:<user>) and return raw plugin rows: computer name, timezone,
                services, per-user activity and any other key or value in the hive.

                This returns rows from single keys and does not join several
                hives or log files into one record. Nothing on this surface does
                that join for you: read each key you need and say which key every
                value came from. RegRipper's own plugins are the upstream reading
                of the artifacts that most often need one, and they are available
                through `registry_ripper` — `usbstor` and `usbdevices` for
                attached removable storage, `samparse` for SAM accounts,
                `mountdev` for mounted devices, `uninstall` for installed
                software. Output is paginated; use
                `filter` to narrow plugin/value rows. For RAW lookup, `key` is a KEY
                path within that hive, not a value path: to read ProductName, query its
                parent and use filter='ProductName'. `CurrentControlSet` is accepted and
                resolved from SYSTEM\\Select\\Current. Add depth=1 to read each direct
                subkey's values. A missing/mis-rooted key returns bounded full-path
                candidates or the deepest existing ancestor as explicitly partial
                recovery rather than requiring blind retries.

                Args:
                    hive: Which hive to open: SYSTEM, SOFTWARE, SAM, SECURITY, or
                        NTUSER:<user> for one user's NTUSER.DAT, for example
                        NTUSER:suspect.
                    filter: Plain substring matched against each returned row, such
                        as a value name or service name. Not a query expression:
                        comparison syntax matches nothing.
                    offset: Index of the first row; continue from the previous
                        page's next_offset.
                    limit: Rows per page, default 50.
                    key: Path of one KEY inside this hive, not a value path, for
                        example ControlSet001\\Services\\Tcpip. To read a single
                        value, query its parent key and pass the value name as
                        `filter`. CurrentControlSet is accepted and resolved
                        through SYSTEM\\Select\\Current.
                    depth: 0 reads only the named key's values; 1 also reads the
                        values of each direct subkey.
                    operation: 'registry_values' (default) returns the values the
                        parser reported. 'value_readings' needs `key` and returns a
                        separate derived result: what this tool read in those bytes
                        (a Unix epoch, a Windows FILETIME, UTF-16LE text behind a
                        struct header). Each reading is an interpretation the
                        registry itself never states, so it never travels inside the
                        reported value."""
        t0 = time.time()
        r = _rq(
            disk,
            hive,
            offset=offset,
            limit=limit,
            filter=filter,
            key=key,
            depth=depth,
            operation=operation,
            scratch=controlled_scratch,
        )
        _emit(
            "registry_query",
            {
                "hive": hive,
                "filter": filter,
                "key": key,
                "depth": depth,
                "operation": operation,
            },
            t0,
        )
        return r

    built.append(StructuredTool.from_function(registry_query))

    # Asked of the availability registry rather than of the binary directly, so
    # this segment withholds the function on exactly the condition the central
    # registry path uses — including a configured alternate execution route,
    # which a bare path probe would not see.  Declining here is recorded against
    # the same dependency table, so the omission is stated, not silent.
    if not missing_dependencies_for("registry_ripper"):
        from forensic_agent.tools.regripper_tool import registry_ripper as _rr

        def registry_ripper(
            hive: str,
            plugin: _RegRipperPlugin | None = None,
            offset: int = 0,
            limit: int = 200,
            filter: str | None = None,
        ) -> dict:
            """Run RegRipper over a hive — AUTHORITATIVE for SAM account NAMES,
                    USB device history, and shellbags (regipy returns only RIDs).
                    hive: SYSTEM/SOFTWARE/SAM/SECURITY (the adapter stages a
                    machine hive by a fixed path and cannot locate a per-user
                    NTUSER hive; use registry_query for a user hive);
                    plugin=None runs the hive's full profile, or pass a specific plugin
                    such as samparse, compname/computername, mountdev/mounteddevices,
                    usbstor, usbdevices, or usb. Common descriptive aliases are
                    normalized to installed plugin names. Paginated
                    (offset/limit/filter)."""
            t0 = time.time()
            r = _rr(disk, hive, plugin=plugin, offset=offset, limit=limit, filter=filter)
            _emit("registry_ripper", {"hive": hive, "plugin": plugin}, t0)
            return r

        built.append(StructuredTool.from_function(registry_ripper))

    from forensic_agent.tools import evtx_tool as _evtx_module

    if (
        _evtx_module.pyevtx is None
        and _evtx_module.PythonEvtx is None
        and _evtx_module.pyevt is None
    ):
        # Every event-log backend is an optional binding installed alongside the
        # forensic extras, so having none of them is a deployment state, not a
        # defect: declare it, and let the caller record the function as
        # unavailable instead of dropping it without a word.
        raise ExternalToolUnavailable("evtx_query")
    _evtx = _evtx_module.evtx_query

    def evtx_query(
        log: str = "Security",
        event_ids: list[int] | None = None,
        offset: int = 0,
        limit: int = 30,
        user: str | None = None,
        logon_types: list[int] | None = None,
        time_from: str | None = None,
        time_to: str | None = None,
        order: str = "asc",
    ) -> dict:
        """Query a modern EVTX or legacy EVT Windows event log.

            Args:
                log: Name of the event log to parse. Security, System and
                    Application are the common aliases. Bare aliases try the
                    modern log and then the XP SecEvent/SysEvent/AppEvent name.
                    An explicit .evt or .evtx suffix is preserved.
                event_ids: Event IDs to keep, as integers, for example
                    [528, 540] for Windows XP or [4624, 4625] for modern
                    Windows. The histogram covers every scanned record.
                offset: Zero-based matching-record page offset.
                limit: Number of matching records to return, from 1 to 1000.
                user: Optional case-insensitive exact user name or SID filter.
                logon_types: Optional Windows logon-type numbers, for example
                    [2, 10]. Applied where the parser exposes that field.
                time_from: Optional inclusive ISO-8601 lower UTC time bound.
                time_to: Optional inclusive ISO-8601 upper UTC time bound.
                order: Chronological result order, either asc or desc."""
        t0 = time.time()
        r = _evtx(
            disk,
            log,
            event_ids=event_ids,
            offset=offset,
            limit=limit,
            user=user,
            logon_types=logon_types,
            time_from=time_from,
            time_to=time_to,
            order=order,
            scratch=controlled_scratch,
        )
        _emit(
            "evtx_query",
            {
                "log": log,
                "event_ids": event_ids,
                "offset": offset,
                "limit": limit,
                "user": user,
                "logon_types": logon_types,
                "time_from": time_from,
                "time_to": time_to,
                "order": order,
            },
            t0,
        )
        return r

    built.append(StructuredTool.from_function(evtx_query))
