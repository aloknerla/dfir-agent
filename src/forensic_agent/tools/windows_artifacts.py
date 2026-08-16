"""Bounded, read-only Windows forensic artifact joins.

The functions in this module turn low-level registry/file observations into
small, named records.  They never contain case-specific answers: every value is
derived from the supplied image at call time.  Registry hives are opened only
through :func:`registry_query`, which confines ephemeral copies to the caller's
controlled scratch session.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

from forensic_agent.core.controlled_scratch import ControlledScratchSession
from forensic_agent.core.evidence_locator import normalize_evidence_path
from forensic_agent.tools.registry_tool import registry_query, registry_query_many

NETWORK_INTERFACES_KEY = r"CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
NETWORK_CLASS_KEY = r"CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
NETWORK_CARDS_KEY = r"Microsoft\Windows NT\CurrentVersion\NetworkCards"
PRIMARY_DOMAIN_KEY = r"Policy\PolPrDmN"
USBSTOR_KEY = r"CurrentControlSet\Enum\USBSTOR"
MOUNTED_DEVICES_KEY = r"MountedDevices"
STORAGE_VOLUMES_KEY = r"CurrentControlSet\Enum\STORAGE\Volume"
DISK_DEVICE_CLASSES_KEY = (
    r"CurrentControlSet\Control\DeviceClasses\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"
)
VOLUME_DEVICE_CLASSES_KEY = (
    r"CurrentControlSet\Control\DeviceClasses\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}"
)
VOLUME_INFO_CACHE_KEY = r"Microsoft\Windows Search\VolumeInfoCache"
UNINSTALL_NATIVE_KEY = r"Microsoft\Windows\CurrentVersion\Uninstall"
UNINSTALL_WOW64_KEY = r"Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
DEFAULT_SETUPAPI_PATH = "/Windows/inf/setupapi.dev.log"
DEFAULT_PREFETCH_PATH = "/Windows/Prefetch"
_MAX_REGISTRY_ROWS = 10_000
_MAX_REGISTRY_PAGES = 512
_MAX_NETWORK_INTERFACES = 256
_MAX_USB_MODEL_KEYS = 128
_MAX_USB_DEVICES = 512
_MAX_APPLICATIONS = 512
_MAX_PREFETCH_ENTRIES = 20_000
_MAX_SETUPAPI_BYTES = 16_000_000
_MAX_GDRIVE_BYTES = 8_000_000
_MAX_GDRIVE_EVENTS = 2_000

# Observed Prefetch executable names are returned as-is
# (``related_execution_artifacts``). Naming a software family and ranking it as
# "notable" is the analyst's judgement, not this tool's, so no watchlist mapping
# is applied here.


def _rows(result: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    value = result.get("rows")
    return [item for item in value if isinstance(item, Mapping)] if isinstance(value, list) else []


def _registry_page_source_complete(result: Mapping[str, Any]) -> bool:
    """Return source completeness while ignoring recoverable row pagination."""

    coverage = result.get("coverage")
    return not (
        result.get("error") not in (None, "", False)
        or result.get("status") in {"partial", "error"}
        or result.get("coverage_complete") is False
        or result.get("scan_complete") is False
        or (isinstance(coverage, Mapping) and coverage.get("complete") is False)
    )


def _registry_rows_all(
    disk: Any,
    hive: str,
    *,
    key: str,
    depth: int,
    scratch: ControlledScratchSession,
    operation: str = "registry_values",
) -> dict[str, Any]:
    """Read every bounded registry row of ONE operation by following the page contract.

    ``registry_query`` intentionally limits each result envelope by UTF-8 bytes.
    Passing a large row limit therefore does not make a single call exhaustive.
    This internal deterministic join follows ``next_offset`` until the reported
    row set is complete, while retaining hard row/page caps and explicit partial
    coverage if the transport cannot supply a lossless next page.

    ``operation`` is passed through unchanged, so the same paging contract serves
    the parser's values and the separate derived readings of them without either
    one being mixed into the other's pages.
    """

    rows: list[Mapping[str, Any]] = []
    subkeys: list[str] = []
    warnings: list[Any] = []
    expected_total: int | None = None
    offset = 0
    pages_read = 0
    complete = True
    terminal_error: Any = None
    exact_key_absent = False

    while pages_read < _MAX_REGISTRY_PAGES and len(rows) < _MAX_REGISTRY_ROWS:
        page = registry_query(
            disk,
            hive,
            key=key,
            depth=depth,
            offset=offset,
            limit=_MAX_REGISTRY_ROWS - len(rows),
            operation=operation,
            scratch=scratch,
        )
        pages_read += 1
        if not isinstance(page, Mapping):
            complete = False
            terminal_error = "registry reader returned a non-object page"
            break

        if page.get("resolution") == "deepest_existing_ancestor":
            # The generic registry tool returns an ancestor as a grounded recovery
            # hint.  Specialized joins must not mistake those ancestor values for
            # values of the requested key; retain an explicit absence signal.
            exact_key_absent = True
            complete = False
            break

        page_warnings = page.get("warnings")
        if isinstance(page_warnings, list):
            warnings.extend(page_warnings)
        if not _registry_page_source_complete(page):
            complete = False
        error = page.get("error")
        if error not in (None, "", False):
            terminal_error = error
            break

        for value in page.get("subkeys", []):
            text = str(value)
            if text and text not in subkeys:
                subkeys.append(text)

        page_rows = _rows(page)
        remaining = _MAX_REGISTRY_ROWS - len(rows)
        rows.extend(page_rows[:remaining])
        if len(page_rows) > remaining:
            complete = False
            warnings.append("registry row safety cap reached")
            break

        total = page.get("total_matching")
        if isinstance(total, int) and not isinstance(total, bool) and total >= 0:
            if expected_total is None:
                expected_total = total
            elif total != expected_total:
                complete = False
                warnings.append(
                    "registry page total changed while reading an immutable evidence source"
                )
                expected_total = max(expected_total, total)

        end = offset + len(page_rows)
        truncated = page.get("truncated") is True
        next_offset = page.get("next_offset")
        if not truncated:
            if expected_total is not None and end < expected_total:
                complete = False
                warnings.append("registry result ended before its reported row total")
            break

        if (
            isinstance(next_offset, int)
            and not isinstance(next_offset, bool)
            and next_offset > offset
        ):
            offset = next_offset
            continue
        if expected_total is not None and end < expected_total and end > offset:
            # Compatibility fallback for a conforming count without next_offset.
            offset = end
            continue

        # A page can be marked truncated solely because a returned field itself
        # exceeded the per-row byte cap. Repeating the same offset cannot recover
        # that content, so report partial coverage rather than looping or claiming
        # exhaustive evidence.
        complete = False
        warnings.append("registry page was truncated without a recoverable next offset")
        break
    else:
        complete = False
        if pages_read >= _MAX_REGISTRY_PAGES:
            warnings.append("registry page safety cap reached")
        if len(rows) >= _MAX_REGISTRY_ROWS:
            warnings.append("registry row safety cap reached")

    total_matching = expected_total if expected_total is not None else len(rows)
    if total_matching > len(rows):
        complete = False

    # Avoid repeating an identical warning once per page.
    unique_warnings: list[Any] = []
    warning_keys: set[str] = set()
    for warning in warnings:
        warning_key = json.dumps(warning, ensure_ascii=False, default=str, sort_keys=True)
        if warning_key not in warning_keys:
            warning_keys.add(warning_key)
            unique_warnings.append(warning)

    result: dict[str, Any] = {
        "hive": hive,
        "key": key,
        "rows": rows,
        "subkeys": subkeys,
        "returned": len(rows),
        "total_matching": total_matching,
        "offset": 0,
        "pages_read": pages_read,
        "truncated": not complete,
        "coverage_complete": complete,
        "warnings": unique_warnings,
        "exact_key_absent": exact_key_absent,
    }
    if terminal_error not in (None, "", False):
        result["error"] = terminal_error
    if not complete:
        result.update(
            _partial_metadata(
                "registry pagination or source coverage was incomplete",
                f"{hive}\\{key}",
            )
        )
    else:
        result["coverage"] = {"complete": True, "scope": f"{hive}\\{key}"}
    return result


def _source_complete(result: Mapping[str, Any]) -> bool:
    coverage = result.get("coverage")
    return not (
        result.get("error") not in (None, "", False)
        or result.get("status") in {"partial", "error"}
        or result.get("coverage_complete") is False
        or result.get("scan_complete") is False
        or result.get("truncated") is True
        or (isinstance(coverage, Mapping) and coverage.get("complete") is False)
    )


def _warning_text(result: Mapping[str, Any], *, source: str) -> list[str]:
    warnings: list[str] = []
    error = result.get("error")
    if error not in (None, "", False):
        warnings.append(f"{source}: {str(error)[:240]}")
    value = result.get("warnings")
    if isinstance(value, list):
        for item in value:
            if isinstance(item, Mapping):
                message = item.get("message")
            else:
                message = item
            if message:
                warnings.append(f"{source}: {str(message)[:240]}")
    return warnings


def _group_rows(result: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = defaultdict(dict)
    for row in _rows(result):
        subkey = str(row.get("subkey") or "")
        name = row.get("name")
        if not subkey or not isinstance(name, str) or not name:
            continue
        groups[subkey][name.casefold()] = row.get("value")
    return dict(groups)


def _text_values(value: Any) -> list[str]:
    values: list[str] = []
    if isinstance(value, str):
        text = value.strip().strip("\x00")
        if text:
            values.append(text)
    elif isinstance(value, Mapping):
        for preferred in ("utf16le_text", "utf8_text", "text", "raw"):
            if preferred in value:
                values.extend(_text_values(value[preferred]))
        if not values:
            for nested in value.values():
                values.extend(_text_values(nested))
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        for nested in value:
            values.extend(_text_values(nested))
    elif value is not None and not isinstance(value, bytes | bytearray):
        values.append(str(value))
    return list(dict.fromkeys(values))


#: One registry value's identity within a key read: (subkey, value name).  Both
#: operations report it, which is what lets a reading be tied back to the value
#: it was read from without either result carrying the other.
_ValueIdentity = tuple[str, str]


def _value_identity(row: Mapping[str, Any]) -> _ValueIdentity:
    return str(row.get("subkey") or ""), str(row.get("name") or "")


def _registry_value_readings(
    disk: Any,
    hive: str,
    *,
    key: str,
    depth: int,
    scratch: ControlledScratchSession,
) -> tuple[dict[_ValueIdentity, list[Mapping[str, Any]]], dict[str, Any]]:
    """Ask ``registry_query`` for the separate derived readings of one key.

    The readings are no longer attached to the observed values — they are their
    own DERIVED operation — so a join that needs the decoded text asks for that
    operation and indexes it by the value it belongs to.  The result envelope is
    returned as well, because a readings read that was cut short makes the join
    that consumes it incomplete just as an observed one does.
    """

    readings_result = _registry_rows_all(
        disk,
        hive,
        key=key,
        depth=depth,
        scratch=scratch,
        operation="value_readings",
    )
    index: dict[_ValueIdentity, list[Mapping[str, Any]]] = defaultdict(list)
    for row in _rows(readings_result):
        for reading in row.get("derived_interpretations") or ():
            if isinstance(reading, Mapping):
                index[_value_identity(row)].append(reading)
    return dict(index), readings_result


def _row_text_values(
    row: Mapping[str, Any],
    readings: Mapping[_ValueIdentity, Sequence[Mapping[str, Any]]],
) -> list[str]:
    """Readable text for one registry value: our readings of it, else the value.

    ``registry_query`` reports the value exactly as regipy produced it, and any
    decoding this project performed is a separate derived operation rather than
    a block inside that value.  These correlating analyses legitimately need the
    decoded text, so they take it from that operation's result rather than
    reaching into the observed value and finding raw hex where a decoded string
    used to sit.

    A reading exists only where the parser reported something that is not text on
    its own: a raw buffer, or a number that may encode a time.  Its rendering is
    therefore the only text this value has, and returning the observed value
    beside it would offer a hex buffer as a candidate name.  Where no reading
    exists the observed value IS the text, and is returned unchanged.
    """

    rendered: list[str] = []
    for reading in readings.get(_value_identity(row), ()):
        rendered.extend(_text_values(reading.get("value")))
    if rendered:
        return list(dict.fromkeys(rendered))
    return _text_values(row.get("value"))


def _first_text(value: Any) -> str | None:
    values = _text_values(value)
    return values[0] if values else None


def _first_integer(value: Any) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    text = _first_text(value)
    if text is None:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def _guid(value: str | None) -> str | None:
    if not value:
        return None
    match = re.search(r"\{[0-9a-fA-F-]{36}\}", value)
    return match.group(0).upper() if match else value.strip()


def _ip_list(value: Any) -> list[str]:
    output: list[str] = []
    for text in _text_values(value):
        output.extend(part for part in re.split(r"[,;\s]+", text) if part)
    return list(dict.fromkeys(output))


#: Windows writes the all-zero address to mean "no static value is configured".
_UNCONFIGURED_ADDRESSES = frozenset({"0.0.0.0", "255.255.255.255", "::"})


def _configured(addresses: list[str]) -> list[str]:
    """Drop the placeholders Windows writes when nothing was configured."""

    return [address for address in addresses if address not in _UNCONFIGURED_ADDRESSES]


def _partial_metadata(reason: str, scope: str) -> dict[str, Any]:
    return {
        "status": "partial",
        "coverage_complete": False,
        "coverage": {"complete": False, "scope": scope, "reason": reason},
    }


def windows_network_config(
    disk: Any,
    *,
    scratch: ControlledScratchSession,
) -> dict[str, Any]:
    """Join interface DHCP values to a human-readable Windows adapter record."""

    interfaces = _registry_rows_all(
        disk,
        "SYSTEM",
        key=NETWORK_INTERFACES_KEY,
        depth=1,
        scratch=scratch,
    )
    network_class = _registry_rows_all(
        disk,
        "SYSTEM",
        key=NETWORK_CLASS_KEY,
        depth=1,
        scratch=scratch,
    )
    network_cards = _registry_rows_all(
        disk,
        "SOFTWARE",
        key=NETWORK_CARDS_KEY,
        depth=1,
        scratch=scratch,
    )

    adapter_names: dict[str, str] = {}
    for values in _group_rows(network_class).values():
        identifier = _guid(_first_text(values.get("netcfginstanceid")))
        description = _first_text(values.get("driverdesc"))
        if identifier and description:
            adapter_names[identifier.casefold()] = description
    for values in _group_rows(network_cards).values():
        identifier = _guid(_first_text(values.get("servicename")))
        description = _first_text(values.get("description"))
        if identifier and description:
            adapter_names.setdefault(identifier.casefold(), description)

    # ``NetworkCards`` is a compact installed-NIC inventory.  Keep it separate
    # from TCP/IP interface records: a physical adapter can have no surviving
    # DHCP/static-address values and must not disappear merely because it was
    # disconnected when the image was acquired.  This also avoids asking a
    # caller to page through the much noisier network class (which contains RAS
    # and protocol miniports alongside physical cards).
    registered_network_cards: list[dict[str, Any]] = []
    for subkey, values in sorted(_group_rows(network_cards).items()):
        description = _first_text(values.get("description"))
        service_name = _guid(_first_text(values.get("servicename")))
        if not description:
            continue
        registered_network_cards.append(
            {
                "description": description,
                "service_name": service_name,
                "registry_subkey": subkey,
            }
        )

    items: list[dict[str, Any]] = []
    for subkey, values in sorted(_group_rows(interfaces).items()):
        identifier = _guid(subkey)
        assigned = _ip_list(values.get("dhcpipaddress"))
        masks = _ip_list(values.get("dhcpsubnetmask"))
        gateways = _ip_list(values.get("dhcpdefaultgateway"))
        name_servers = _ip_list(values.get("dhcpnameserver"))
        dhcp_servers = _ip_list(values.get("dhcpserver"))
        # A statically configured interface writes the plain value names and
        # leaves every ``Dhcp*`` value absent, so reading only the DHCP side made
        # a statically addressed host report no addresses at all.
        static_addresses = _ip_list(values.get("ipaddress"))
        static_masks = _ip_list(values.get("subnetmask"))
        static_gateways = _ip_list(values.get("defaultgateway"))
        static_name_servers = _ip_list(values.get("nameserver"))
        if not any(
            (
                assigned,
                masks,
                gateways,
                name_servers,
                dhcp_servers,
                # Windows stores the all-zero placeholder for "not configured",
                # which is not by itself a reason to list an interface.
                _configured(static_addresses),
                _configured(static_gateways),
                _configured(static_name_servers),
            )
        ):
            continue
        enabled = _first_integer(values.get("enabledhcp"))
        items.append(
            {
                "interface_guid": identifier,
                "adapter_name": adapter_names.get((identifier or "").casefold()),
                "dhcp_enabled": None if enabled is None else bool(enabled),
                "assigned_ip_addresses": assigned,
                "subnet_masks": masks,
                "default_gateways": gateways,
                "name_servers": name_servers,
                "dhcp_servers": dhcp_servers,
                "static_ip_addresses": static_addresses,
                "static_subnet_masks": static_masks,
                "static_default_gateways": static_gateways,
                "static_name_servers": static_name_servers,
            }
        )

    warnings = [
        *_warning_text(interfaces, source="SYSTEM Interfaces"),
        *_warning_text(network_class, source="SYSTEM network class"),
        *_warning_text(network_cards, source="SOFTWARE NetworkCards"),
    ]
    if not any(
        _configured(item["assigned_ip_addresses"]) or _configured(item["static_ip_addresses"])
        for item in items
    ):
        # An empty inventory reads like an authoritative "this host had no
        # address", which is wrong: a machine addressed by a third-party tool,
        # or one whose lease had expired, records nothing here. Saying where
        # else an address is recorded keeps a negative result from ending the
        # investigation.
        warnings.append(
            "no interface records a configured address; the registry is not the only place "
            "one appears, so search the filesystem for network-tool configuration files and "
            "read them with configuration_query"
        )
    complete = all(_source_complete(item) for item in (interfaces, network_class, network_cards))
    total = len(items)
    if total > _MAX_NETWORK_INTERFACES:
        items = items[:_MAX_NETWORK_INTERFACES]
        complete = False
        warnings.append("network interface safety cap reached")
    result: dict[str, Any] = {
        "items": items,
        "registered_network_cards": registered_network_cards,
        "registered_network_card_count": len(registered_network_cards),
        "registered_network_cards_coverage_complete": _source_complete(network_cards),
        "ip_configuration_coverage_complete": all(
            _source_complete(item) for item in (interfaces, network_class)
        ),
        "total_matching": total,
        "truncated": total > len(items),
        "coverage_complete": complete,
        "sources": [NETWORK_INTERFACES_KEY, NETWORK_CLASS_KEY, NETWORK_CARDS_KEY],
        "warnings": warnings,
    }
    if not complete:
        result.update(
            _partial_metadata(
                "one or more registry joins were incomplete",
                "Windows network interface registry records",
            )
        )
    return result


def windows_domain_identity(
    disk: Any,
    *,
    scratch: ControlledScratchSession,
) -> dict[str, Any]:
    """Read Windows' LSA primary-domain/workgroup identity from SECURITY.

    Older standalone Windows systems persist the primary workgroup/domain name
    as the LSA ``PolPrDmN`` value rather than beside ``ComputerName``.  The raw
    value is an LSA Unicode structure, so :func:`registry_query` retains its hex
    bytes and exposes the deterministic UTF-16LE reading as a separate derived
    operation, which this wrapper asks for.  It returns that decoded value with
    its exact hive/key provenance and never guesses a default workgroup when the
    value is absent.
    """

    source = _registry_rows_all(
        disk,
        "SECURITY",
        key=PRIMARY_DOMAIN_KEY,
        depth=0,
        scratch=scratch,
    )
    readings, readings_source = _registry_value_readings(
        disk,
        "SECURITY",
        key=PRIMARY_DOMAIN_KEY,
        depth=0,
        scratch=scratch,
    )
    values: list[str] = []
    for row in _rows(source):
        name = str(row.get("name") or "").casefold()
        if name not in {"", "(default)", "default"}:
            continue
        values.extend(_row_text_values(row, readings))
    candidates = list(dict.fromkeys(value for value in values if value))

    warnings = _warning_text(source, source=f"SECURITY {PRIMARY_DOMAIN_KEY}")
    warnings.extend(
        _warning_text(readings_source, source=f"SECURITY {PRIMARY_DOMAIN_KEY} value readings")
    )
    complete = _source_complete(source) and _source_complete(readings_source)
    items = [
        {
            "identity_type": "primary_domain_or_workgroup",
            "value": value,
            "source_hive": "SECURITY",
            "source_key": PRIMARY_DOMAIN_KEY,
            "source_value": "(default)",
        }
        for value in candidates
    ]
    result: dict[str, Any] = {
        "items": items,
        "candidate_count": len(items),
        "source": f"SECURITY\\{PRIMARY_DOMAIN_KEY}",
        "truncated": False,
        "coverage_complete": complete and len(items) == 1,
        "warnings": warnings,
    }
    if not complete or len(items) != 1:
        reason = (
            "LSA primary-domain evidence was incomplete"
            if not complete
            else "LSA primary-domain evidence was absent or ambiguous"
        )
        result.update(_partial_metadata(reason, f"SECURITY\\{PRIMARY_DOMAIN_KEY}"))
    else:
        result["coverage"] = {
            "complete": True,
            "scope": f"SECURITY\\{PRIMARY_DOMAIN_KEY}",
        }
    return result


def installed_applications(
    disk: Any,
    *,
    scratch: ControlledScratchSession,
) -> dict[str, Any]:
    """Enumerate Uninstall records and separately report execution traces.

    ``items`` contains only records proven by the two Windows Uninstall views.
    Prefetch filenames are returned under ``related_execution_artifacts`` and
    explicitly do *not* establish that an application was installed.  Keeping
    the evidence classes separate prevents an execution trace from being
    silently promoted to an installation record.
    """

    sources = (
        ("native", UNINSTALL_NATIVE_KEY),
        ("wow6432", UNINSTALL_WOW64_KEY),
    )
    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    absent_registry_views: list[str] = []
    registry_view_results: list[dict[str, Any]] = []
    complete = True
    for view, key in sources:
        raw = _registry_rows_all(
            disk,
            "SOFTWARE",
            key=key,
            depth=1,
            scratch=scratch,
        )
        if raw.get("exact_key_absent") is True:
            warnings.append(f"{view} Uninstall: registry view is absent")
            absent_registry_views.append(view)
            registry_view_results.append(
                {
                    "registry_view": view,
                    "registry_path": key,
                    "view_present": False,
                    "records_observed": False,
                    "record_count": 0,
                    "query_complete": True,
                }
            )
            continue
        source_complete = _source_complete(raw)
        complete = complete and source_complete
        warnings.extend(_warning_text(raw, source=f"SOFTWARE {view} Uninstall"))
        records_before = len(items)
        for subkey, values in _group_rows(raw).items():
            name = _first_text(values.get("displayname"))
            if not name:
                continue
            items.append(
                {
                    "name": name,
                    "version": _first_text(values.get("displayversion")),
                    "publisher": _first_text(values.get("publisher")),
                    "registry_view": view,
                    "registry_subkey": subkey,
                }
            )
        record_count = len(items) - records_before
        registry_view_results.append(
            {
                "registry_view": view,
                "registry_path": key,
                "view_present": True,
                "records_observed": record_count > 0,
                "record_count": record_count,
                "query_complete": source_complete,
            }
        )

    deduplicated: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in items:
        identity = (
            str(item["name"]).casefold(),
            str(item.get("version") or "").casefold(),
            str(item["registry_view"]),
        )
        deduplicated.setdefault(identity, item)
    all_items = sorted(
        deduplicated.values(),
        key=lambda item: (
            str(item["name"]).casefold(),
            str(item.get("version") or "").casefold(),
            str(item["registry_view"]),
        ),
    )
    observed_registry_views = sorted(
        {str(item["registry_view"]) for item in all_items}
    )
    source_by_view = {view: key for view, key in sources}
    observed_sources = [source_by_view[view] for view in observed_registry_views]
    absent_sources = [source_by_view[view] for view in sorted(set(absent_registry_views))]
    total = len(all_items)
    if total > _MAX_APPLICATIONS:
        all_items = all_items[:_MAX_APPLICATIONS]
        complete = False
        warnings.append("installed-application safety cap reached")

    execution_artifacts: list[dict[str, Any]] = []
    execution_complete = False
    try:
        bounded_lister = getattr(disk, "list_directory_bounded", None)
        if callable(bounded_lister):
            listing = bounded_lister(
                DEFAULT_PREFETCH_PATH,
                max_entries=_MAX_PREFETCH_ENTRIES,
            )
        else:
            listing = disk.list_directory(DEFAULT_PREFETCH_PATH)
        if not isinstance(listing, Mapping):
            raise TypeError("directory reader returned a non-object result")
        entries = listing.get("entries")
        if not isinstance(entries, list):
            raise TypeError("directory reader returned no entry list")
        execution_complete = not (
            listing.get("incomplete") is True
            or listing.get("enumeration_complete") is False
            or listing.get("error") not in (None, "", False)
            or len(entries) > _MAX_PREFETCH_ENTRIES
        )
        for entry in entries[:_MAX_PREFETCH_ENTRIES]:
            if not isinstance(entry, Mapping):
                continue
            artifact_name = str(entry.get("name") or "")
            match = re.fullmatch(
                r"(?P<executable>.+)-[0-9A-Fa-f]{8}\.pf",
                artifact_name,
                flags=re.IGNORECASE,
            )
            if match is None:
                continue
            execution_artifacts.append(
                {
                    "executable": match.group("executable"),
                    "source_path": f"{DEFAULT_PREFETCH_PATH}/{artifact_name}",
                    "evidence_class": "execution_trace_not_uninstall_record",
                    "installation_status": "not_established",
                }
            )
    except Exception as exc:
        warnings.append(f"Prefetch execution artifacts unavailable: {str(exc)[:240]}")

    execution_artifacts = sorted(
        {
            (str(item["source_path"]).casefold(), str(item["executable"]).casefold()): item
            for item in execution_artifacts
        }.values(),
        key=lambda item: (
            str(item["executable"]).casefold(),
            str(item["source_path"]).casefold(),
        ),
    )
    result: dict[str, Any] = {
        "items": all_items,
        "total_matching": total,
        "truncated": total > len(all_items),
        "coverage_complete": complete,
        # ``sources`` means locations that actually yielded the returned records.
        # Attempted locations remain available separately so a model cannot mistake
        # query scope for observation scope.
        "sources": observed_sources,
        "sources_semantics": "observed_record_registry_paths",
        "observed_sources": observed_sources,
        "absent_sources": absent_sources,
        "queried_sources": [key for _view, key in sources],
        "queried_registry_views": [view for view, _key in sources],
        "observed_registry_views": observed_registry_views,
        "absent_registry_views": sorted(set(absent_registry_views)),
        "registry_view_results": registry_view_results,
        "related_execution_artifacts": execution_artifacts,
        "related_execution_artifact_count": len(execution_artifacts),
        "execution_artifact_source": DEFAULT_PREFETCH_PATH,
        "execution_artifact_coverage_complete": execution_complete,
        "warnings": warnings,
    }
    if not complete:
        result.update(
            _partial_metadata(
                "one or more Uninstall views were incomplete",
                "SOFTWARE native and Wow6432Node Uninstall records",
            )
        )
    return result


_SETUPAPI_SECTION = re.compile(
    r"^>>>\s*\[(?P<header>.*?USBSTOR\\.*?\\(?P<serial>[^\\\]\s]+).*?)\]\s*$",
    re.IGNORECASE,
)
_SETUPAPI_START = re.compile(
    r"^>>>\s*Section start\s+(?P<time>\d{4}[/-]\d{2}[/-]\d{2}\s+\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?)",
    re.IGNORECASE,
)


def _setupapi_first_connections(text: str) -> dict[str, str]:
    current_serial: str | None = None
    observed: dict[str, list[str]] = defaultdict(list)
    for line in text.splitlines():
        section = _SETUPAPI_SECTION.match(line.strip())
        if section:
            current_serial = section.group("serial").split("&", 1)[0].casefold()
            continue
        started = _SETUPAPI_START.match(line.strip())
        if started and current_serial:
            stamp = started.group("time").replace("/", "-")
            observed[current_serial].append(stamp)
    return {serial: min(stamps) for serial, stamps in observed.items() if stamps}


def _device_model(model_key: str, friendly_name: str | None) -> tuple[str, str | None, str | None]:
    vendor = re.search(r"(?:^|&)Ven_([^&]+)", model_key, re.IGNORECASE)
    product = re.search(r"(?:^|&)Prod_([^&]+)", model_key, re.IGNORECASE)
    revision = re.search(r"(?:^|&)Rev_([^&]+)", model_key, re.IGNORECASE)
    if friendly_name:
        model = re.sub(r"\s+USB\s+Device\s*$", "", friendly_name, flags=re.IGNORECASE)
    else:
        parts = [match.group(1).replace("_", " ") for match in (vendor, product) if match]
        model = " ".join(parts) or model_key
    return model, vendor.group(1).replace("_", " ") if vendor else None, revision.group(1) if revision else None


def _drive_designator(value: str) -> str | None:
    """Return a canonical drive designator such as ``E:`` from a registry name."""

    match = re.search(r"([A-Za-z]):\\?$", value.strip())
    return f"{match.group(1).upper()}:" if match else None


_STORAGE_VOLUME_INSTANCE = re.compile(
    r"^(?P<disk_id>\{[0-9a-fA-F-]{36}\})#(?P<offset>[0-9a-fA-F]{16})$"
)


def _storage_volume_identity(value: str) -> tuple[str, int] | None:
    """Parse ``Enum\\STORAGE\\Volume`` disk GUID and partition offset."""

    matched = _STORAGE_VOLUME_INSTANCE.fullmatch(value.strip())
    if matched is None:
        return None
    return matched.group("disk_id").upper(), int(matched.group("offset"), 16)


def _mounted_mbr_identity(row: Mapping[str, Any]) -> tuple[str, int] | None:
    """Return a legacy MountedDevices binary identity and partition offset.

    An MBR-backed mounted-volume value is exactly 12 bytes: the four-byte disk
    signature followed by the little-endian 64-bit partition byte offset.  The
    full 12-byte identity remains the join key; the offset is used only after a
    uniqueness proof across the complete STORAGE volume inventory.
    """

    value_type = str(row.get("value_type") or "").upper()
    if value_type not in {"REG_BINARY", "REG_NONE"}:
        return None
    value = row.get("value")
    if isinstance(value, Mapping):
        encoded = value.get("hex")
    else:
        encoded = value
    if not isinstance(encoded, str):
        return None
    text = encoded.strip()
    if len(text) != 24 or any(character not in "0123456789abcdefABCDEF" for character in text):
        return None
    raw = bytes.fromhex(text)
    return raw.hex(), int.from_bytes(raw[4:12], byteorder="little", signed=False)


def _device_class_instances(result: Mapping[str, Any]) -> set[str]:
    instances: set[str] = set()
    for values in _group_rows(result).values():
        instance = _first_text(values.get("deviceinstance"))
        if instance:
            instances.add(instance.casefold())
    return instances


def _read_bounded_text(disk: Any, path: str, max_bytes: int) -> tuple[str, bool, int | None, str | None]:
    try:
        raw = disk.read_file(path, max_bytes=max_bytes, offset=0)
    except Exception as exc:
        return "", False, None, str(exc)[:240]
    if not isinstance(raw, Mapping):
        return "", False, None, "file reader returned a non-object result"
    error = raw.get("error")
    if error not in (None, "", False):
        return "", False, None, str(error)[:240]
    text = str(raw.get("content_text") or "")
    size = raw.get("size") if isinstance(raw.get("size"), int) else None
    complete = raw.get("eof") is not False and (size is None or size <= max_bytes)
    return text, complete, size, None


def usb_storage_history(
    disk: Any,
    *,
    scratch: ControlledScratchSession,
    setupapi_path: str = DEFAULT_SETUPAPI_PATH,
) -> dict[str, Any]:
    """Join USBSTOR, DeviceClasses, volume mappings and first-seen times.

    A USB instance's Partmgr ``DiskId`` must match an enumerated STORAGE volume
    and its DeviceClasses interface.  Its partition offset is accepted only
    when it is unique in both the complete STORAGE inventory and the set of
    12-byte MBR ``MountedDevices`` identities.  Ambiguous evidence remains
    visible, but is never promoted to a device/drive/label association.
    """

    setupapi_path = normalize_evidence_path(setupapi_path, allow_root=False)
    system = registry_query_many(
        disk,
        "SYSTEM",
        {
            "usbstor": (USBSTOR_KEY, 0),
            "mounted_devices": (MOUNTED_DEVICES_KEY, 0),
            "storage_volumes": (STORAGE_VOLUMES_KEY, 1),
            "disk_device_classes": (DISK_DEVICE_CLASSES_KEY, 1),
            "volume_device_classes": (VOLUME_DEVICE_CLASSES_KEY, 1),
        },
        scratch=scratch,
    )
    root = system["usbstor"]
    mounted = system["mounted_devices"]
    storage_volumes = system["storage_volumes"]
    disk_device_classes = system["disk_device_classes"]
    volume_device_classes = system["volume_device_classes"]
    volume_info = _registry_rows_all(
        disk,
        "SOFTWARE",
        key=VOLUME_INFO_CACHE_KEY,
        depth=1,
        scratch=scratch,
    )
    # A serial often appears only once the MountedDevices buffer is decoded, and
    # that decoding is a derived operation of its own, so it is asked for
    # separately rather than found inside the observed value.
    mounted_readings, mounted_readings_source = _registry_value_readings(
        disk,
        "SYSTEM",
        key=MOUNTED_DEVICES_KEY,
        depth=0,
        scratch=scratch,
    )
    model_keys = [str(item) for item in root.get("subkeys", []) if str(item)]
    complete = all(
        _source_complete(item)
        for item in (
            root,
            mounted,
            mounted_readings_source,
            storage_volumes,
            disk_device_classes,
            volume_device_classes,
            volume_info,
        )
    )
    warnings = [
        *_warning_text(root, source="SYSTEM USBSTOR"),
        *_warning_text(mounted, source="SYSTEM MountedDevices"),
        *_warning_text(
            mounted_readings_source, source="SYSTEM MountedDevices value readings"
        ),
        *_warning_text(storage_volumes, source="SYSTEM STORAGE volumes"),
        *_warning_text(disk_device_classes, source="SYSTEM disk DeviceClasses"),
        *_warning_text(volume_device_classes, source="SYSTEM volume DeviceClasses"),
        *_warning_text(volume_info, source="SOFTWARE VolumeInfoCache"),
    ]
    if len(model_keys) > _MAX_USB_MODEL_KEYS:
        model_keys = model_keys[:_MAX_USB_MODEL_KEYS]
        complete = False
        warnings.append("USBSTOR model-key safety cap reached")

    model_results = (
        registry_query_many(
            disk,
            "SYSTEM",
            {
                model_key: (f"{USBSTOR_KEY}\\{model_key}", 1)
                for model_key in model_keys
            },
            scratch=scratch,
        )
        if model_keys
        else {}
    )
    for model_key, raw in model_results.items():
        complete = complete and _source_complete(raw)
        warnings.extend(_warning_text(raw, source=f"SYSTEM USBSTOR {model_key}"))

    mounted_rows = _rows(mounted)
    volume_labels: dict[str, str] = {}
    for subkey, values in _group_rows(volume_info).items():
        drive = _drive_designator(subkey)
        label = _first_text(values.get("volumelabel"))
        if drive and label:
            volume_labels[drive.casefold()] = label

    disk_class_instances = _device_class_instances(disk_device_classes)
    volume_class_instances = _device_class_instances(volume_device_classes)
    volumes_by_disk_id: dict[str, list[dict[str, Any]]] = defaultdict(list)
    volumes_by_offset: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for subkey in storage_volumes.get("subkeys", []):
        identity = _storage_volume_identity(str(subkey))
        if identity is None:
            continue
        parsed_disk_id, partition_offset = identity
        device_instance = f"STORAGE\\Volume\\{str(subkey)}"
        record = {
            "disk_id": parsed_disk_id,
            "partition_offset": partition_offset,
            "storage_volume_instance": str(subkey),
            "device_instance": device_instance,
            "device_class_verified": (
                device_instance.casefold() in volume_class_instances
            ),
        }
        volumes_by_disk_id[parsed_disk_id].append(record)
        volumes_by_offset[partition_offset].append(record)

    mounted_names_by_identity: dict[str, set[str]] = defaultdict(set)
    mounted_identities_by_offset: dict[int, set[str]] = defaultdict(set)
    for row in mounted_rows:
        identity = _mounted_mbr_identity(row)
        name = row.get("name")
        if identity is None or not isinstance(name, str) or not name:
            continue
        identity_hex, partition_offset = identity
        mounted_names_by_identity[identity_hex].add(name)
        mounted_identities_by_offset[partition_offset].add(identity_hex)

    device_drafts: list[dict[str, Any]] = []
    for model_key in model_keys:
        raw = model_results[model_key]
        for instance, values in _group_rows(raw).items():
            serial = instance.split("&", 1)[0]
            friendly = _first_text(values.get("friendlyname"))
            model, vendor, revision = _device_model(model_key, friendly)
            device_instance = f"USBSTOR\\{model_key}\\{instance}"
            device_drafts.append(
                {
                    "model_key": model_key,
                    "model": model,
                    "vendor": vendor,
                    "revision": revision,
                    "serial_number": serial,
                    "instance_id": instance,
                    "device_instance": device_instance,
                    "disk_interface_verified": (
                        device_instance.casefold() in disk_class_instances
                    ),
                }
            )

    if len(device_drafts) > _MAX_USB_DEVICES:
        device_drafts = device_drafts[:_MAX_USB_DEVICES]
        complete = False
        warnings.append("USB device safety cap reached")

    parameter_results = (
        registry_query_many(
            disk,
            "SYSTEM",
            {
                str(index): (
                    f"{USBSTOR_KEY}\\{draft['model_key']}\\{draft['instance_id']}"
                    "\\Device Parameters",
                    1,
                )
                for index, draft in enumerate(device_drafts)
            },
            scratch=scratch,
        )
        if device_drafts
        else {}
    )

    devices: list[dict[str, Any]] = []
    for index, draft in enumerate(device_drafts):
        parameters = parameter_results[str(index)]
        complete = complete and _source_complete(parameters)
        warnings.extend(
            _warning_text(
                parameters,
                source=f"SYSTEM USBSTOR {draft['instance_id']} Device Parameters",
            )
        )
        partmgr = next(
            (
                values
                for subkey, values in _group_rows(parameters).items()
                if subkey.casefold() == "partmgr"
            ),
            {},
        )
        raw_disk_id = _guid(_first_text(partmgr.get("diskid")))
        disk_id = (
            raw_disk_id.upper()
            if raw_disk_id
            and _STORAGE_VOLUME_INSTANCE.fullmatch(
                f"{raw_disk_id}#0000000000000000"
            )
            else None
        )

        serial = str(draft["serial_number"])
        direct_names: set[str] = set()
        for row in mounted_rows:
            # The serial is matched against the observed value AND our labelled
            # readings of it: the observed value is regipy's own bytes, so a
            # serial that only appears once the buffer is decoded lives in the
            # separate derived readings rather than inside the value itself.
            rendered = json.dumps(
                [row.get("value"), *_row_text_values(row, mounted_readings)],
                ensure_ascii=False,
                default=str,
            )
            if serial.casefold() in rendered.casefold():
                name = row.get("name")
                if isinstance(name, str) and name:
                    direct_names.add(name)

        linked_names: set[str] = set()
        linked_volumes: list[dict[str, Any]] = []
        association_ambiguous = False
        uniqueness_sources_complete = all(
            _source_complete(source) for source in (storage_volumes, mounted)
        )
        if disk_id and draft["disk_interface_verified"] and uniqueness_sources_complete:
            for volume in volumes_by_disk_id.get(disk_id, []):
                if not volume["device_class_verified"]:
                    continue
                partition_offset = int(volume["partition_offset"])
                if len(volumes_by_offset.get(partition_offset, [])) != 1:
                    association_ambiguous = True
                    continue
                identities = mounted_identities_by_offset.get(partition_offset, set())
                if len(identities) != 1:
                    if len(identities) > 1:
                        association_ambiguous = True
                    continue
                identity_hex = next(iter(identities))
                names = mounted_names_by_identity.get(identity_hex, set())
                if names:
                    linked_names.update(names)
                    linked_volumes.append(
                        {**volume, "mounted_identity_hex": identity_hex}
                    )

        if direct_names and linked_names and direct_names.isdisjoint(linked_names):
            association_ambiguous = True
            mounted_names: list[str] = []
            association_basis: list[str] = []
        else:
            mounted_names = sorted(direct_names | linked_names)
            association_basis = []
            if direct_names:
                association_basis.append("mounted_devices_serial_literal")
            if linked_names:
                association_basis.append(
                    "partmgr_diskid_deviceclasses_unique_partition_offset"
                )

        drive_letters = sorted(
            {
                drive
                for mounted_name in mounted_names
                if (drive := _drive_designator(mounted_name)) is not None
            }
        )
        label_sources = [
            {
                "drive": drive,
                "label": volume_labels[drive.casefold()],
                "registry_key": f"{VOLUME_INFO_CACHE_KEY}\\{drive}",
            }
            for drive in drive_letters
            if drive.casefold() in volume_labels
        ]
        unique_labels = list(
            dict.fromkeys(str(source["label"]) for source in label_sources)
        )
        if len(unique_labels) > 1:
            warnings.append(
                "multiple VolumeInfoCache labels matched USB instance "
                f"{draft['instance_id']}; scalar volume_label omitted"
            )
        if association_ambiguous:
            association_status = "ambiguous"
        elif mounted_names:
            association_status = "proven"
        else:
            association_status = "unresolved"

        devices.append(
            {
                **{key: value for key, value in draft.items() if key != "model_key"},
                "disk_id": disk_id,
                "mounted_device_names": mounted_names,
                "drive_letters": drive_letters,
                "volume_label": (
                    unique_labels[0] if len(unique_labels) == 1 else None
                ),
                "volume_label_sources": label_sources,
                "volume_association_status": association_status,
                "volume_association_basis": association_basis,
                "linked_storage_volumes": linked_volumes,
                "first_connected_time": None,
            }
        )

    setup_text, setup_complete, setup_size, setup_error = _read_bounded_text(
        disk, setupapi_path, _MAX_SETUPAPI_BYTES
    )
    if setup_error:
        warnings.append(f"SetupAPI unavailable: {setup_error}")
    elif not setup_complete:
        complete = False
        warnings.append("SetupAPI log exceeded the bounded full-file scan")
    first_connections = _setupapi_first_connections(setup_text)
    for device in devices:
        device["first_connected_time"] = first_connections.get(
            str(device["serial_number"]).casefold()
        )

    observed_volume_labels: list[dict[str, Any]] = []
    for drive_key, label in sorted(volume_labels.items()):
        drive = drive_key.upper()
        associated_instances = sorted(
            str(device["instance_id"])
            for device in devices
            if drive in {str(value).upper() for value in device.get("drive_letters", [])}
        )
        observed_volume_labels.append(
            {
                "drive": drive,
                "label": label,
                "registry_key": f"{VOLUME_INFO_CACHE_KEY}\\{drive}",
                "association_status": "proven" if associated_instances else "unresolved",
                "associated_instance_ids": associated_instances,
            }
        )

    deduplicated: dict[str, dict[str, Any]] = {}
    for device in devices:
        deduplicated.setdefault(str(device["instance_id"]).casefold(), device)
    all_items = sorted(deduplicated.values(), key=lambda item: str(item["instance_id"]).casefold())
    total = len(all_items)
    if total > _MAX_USB_DEVICES:
        all_items = all_items[:_MAX_USB_DEVICES]
        complete = False
        warnings.append("USB device safety cap reached")
    if all_items and all(item.get("volume_label") is None for item in all_items):
        warnings.append(
            "no MountedDevices drive mapping could be joined to a VolumeInfoCache label"
        )
    result: dict[str, Any] = {
        "items": all_items,
        "total_matching": total,
        "truncated": total > len(all_items),
        "coverage_complete": complete,
        "setupapi_path": setupapi_path,
        "setupapi_size": setup_size,
        "observed_volume_labels": observed_volume_labels,
        "volume_association_coverage_complete": all(
            _source_complete(item)
            for item in (
                root,
                mounted,
                storage_volumes,
                disk_device_classes,
                volume_device_classes,
                *model_results.values(),
                *parameter_results.values(),
            )
        ),
        "sources": [
            USBSTOR_KEY,
            STORAGE_VOLUMES_KEY,
            DISK_DEVICE_CLASSES_KEY,
            VOLUME_DEVICE_CLASSES_KEY,
            MOUNTED_DEVICES_KEY,
            VOLUME_INFO_CACHE_KEY,
            setupapi_path,
        ],
        "warnings": list(dict.fromkeys(warnings)),
    }
    if not complete:
        result.update(
            _partial_metadata(
                "one or more USB history sources were incomplete",
                "USBSTOR, DeviceClasses, MountedDevices and SetupAPI device history",
            )
        )
    return result


_EMAIL = re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_RAW_DELETE = re.compile(
    r"RawEvent\(\s*DELETE\s*,\s*path=(?:u)?(?P<quote>['\"])(?P<path>.*?)(?P=quote)",
    re.IGNORECASE,
)
_LOG_TIME = re.compile(
    r"^(?P<time>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d{3}\s+[+-]\d{4})"
)
_ACCOUNT_CREDENTIALS_INITIALIZED = re.compile(
    r"Initializing\s+User\s+instance\s+with\s+new\s+credentials\.\s*"
    r"(?P<account>[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})",
    re.IGNORECASE,
)


def _google_log_time_iso(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S,%f %z").isoformat()
    except ValueError:
        return None


def _windows_log_path(value: str) -> str:
    path = value
    while "\\\\" in path:
        path = path.replace("\\\\", "\\")
    path = re.sub(r"^\\\\\?\\", "", path)
    return path


def google_drive_sync_events(
    disk: Any,
    path: str,
) -> dict[str, Any]:
    """Parse a complete bounded Google Drive sync log for accounts and DELETE events."""

    path = normalize_evidence_path(path, allow_root=False)
    text, complete, size, error = _read_bounded_text(disk, path, _MAX_GDRIVE_BYTES)
    if error:
        return {
            "path": path,
            "items": [],
            "error": {"code": "gdrive_sync_log_unreadable", "message": error},
            "coverage_complete": False,
            "coverage": {"complete": False, "scope": path, "reason": error},
        }

    accounts = list(dict.fromkeys(match.group(0).casefold() for match in _EMAIL.finditer(text)))
    events: dict[str, dict[str, Any]] = {}
    account_events: dict[tuple[str, str], dict[str, Any]] = {}
    for line in text.splitlines():
        timestamp = _LOG_TIME.match(line)
        observed_time = timestamp.group("time") if timestamp else None
        credentials = _ACCOUNT_CREDENTIALS_INITIALIZED.search(line)
        if credentials is not None:
            account = credentials.group("account").casefold()
            account_key = (account, observed_time or "")
            account_events.setdefault(
                account_key,
                {
                    "event": "ACCOUNT_CREDENTIALS_INITIALIZED",
                    "account": account,
                    "observed_time": observed_time,
                    "observed_time_iso": _google_log_time_iso(observed_time),
                },
            )
        deletion = _RAW_DELETE.search(line)
        if deletion is None:
            continue
        deleted_path = _windows_log_path(deletion.group("path"))
        name = re.split(r"[\\/]", deleted_path.rstrip("\\/"))[-1]
        if not name:
            continue
        event_key = deleted_path.casefold()
        events.setdefault(
            event_key,
            {
                "name": name,
                "path": deleted_path,
                "observed_time": observed_time,
                "event": "DELETE",
            },
        )

    all_items = list(events.values())
    total = len(all_items)
    truncated = total > _MAX_GDRIVE_EVENTS
    if truncated:
        all_items = all_items[:_MAX_GDRIVE_EVENTS]
        complete = False
    warnings = ["Google Drive DELETE-event safety cap reached"] if truncated else []
    result: dict[str, Any] = {
        "path": path,
        "file_size": size,
        "accounts": accounts,
        "account_events": list(account_events.values()),
        "items": all_items,
        "total_matching": total,
        "truncated": truncated,
        "coverage_complete": complete,
        "warnings": warnings,
    }
    if not complete:
        result.update(
            _partial_metadata(
                "the sync log exceeded the bounded full-file scan",
                path,
            )
        )
    return result


__all__ = [
    "DEFAULT_PREFETCH_PATH",
    "DEFAULT_SETUPAPI_PATH",
    "google_drive_sync_events",
    "installed_applications",
    "usb_storage_history",
    "windows_domain_identity",
    "windows_network_config",
]
