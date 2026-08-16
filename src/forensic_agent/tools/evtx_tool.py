"""Read-only Windows event-log queries for modern EVTX and legacy EVT files.

Modern logs are parsed with libyal ``pyevtx`` when available, otherwise with
``python-evtx``.  Windows 2000/XP/2003 ``.evt`` logs are parsed with libyal
``pyevt``.  Both formats return the same record envelope, paging contract and
scan-coverage metadata.  Result-page truncation is deliberately independent of
scan coverage: returning 30 of 10,000 fully scanned matches is a complete scan
with a truncated page, not an incomplete forensic examination.
"""
from __future__ import annotations

import heapq
import re
import xml.etree.ElementTree as ET
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime, time
from typing import Any, cast

from forensic_agent.core.controlled_scratch import (
    ControlledScratchError,
    ControlledScratchSession,
    ScratchArtifact,
    ScratchKind,
)

try:
    import pyevtx
except ImportError:  # optional system/manual libyal binding
    pyevtx = None

try:
    import pyevt
except ImportError:  # installed transitively with Plaso in the forensic image
    pyevt = None

try:
    from Evtx.Evtx import Evtx as PythonEvtx
except ImportError:  # installed by the ``forensics`` extra
    PythonEvtx = None


_EVTX_LOG_DIRS = (
    "/Windows/System32/winevt/Logs",
    "/Windows/System32/winevtx/Logs",
    "/WINDOWS/System32/winevt/Logs",
    "/WINDOWS/System32/winevtx/Logs",
)
_EVT_LOG_DIRS = (
    "/Windows/System32/config",
    "/WINDOWS/System32/config",
)
_XP_EVT_ALIASES = {
    "application": "AppEvent.evt",
    "security": "SecEvent.evt",
    "system": "SysEvent.evt",
}

# Labels are descriptive only.  The numeric identifier remains authoritative.
SECURITY_EVENT_IDS = {
    528: "uspjesna prijava (legacy)",
    529: "neuspjela prijava (legacy)",
    538: "odjava (legacy)",
    540: "uspjesna mrezna prijava (legacy)",
    551: "pokrenuta odjava (legacy)",
    552: "prijava s eksplicitnim vjerodajnicama (legacy)",
    680: "provjera vjerodajnica (legacy)",
    4624: "uspjesna prijava",
    4625: "neuspjela prijava",
    4634: "odjava",
    4648: "prijava s eksplicitnim vjerodajnicama",
    4672: "posebne ovlasti pri prijavi",
    4720: "stvoren korisnicki racun",
    4722: "omogucen racun",
    4726: "obrisan korisnicki racun",
    4732: "clan dodan u grupu",
    4688: "stvoren novi proces",
    4697: "instalirana usluga",
    7045: "instalirana usluga (System)",
    1102: "obrisan sigurnosni zapisnik",
    104: "obrisan zapisnik",
    6005: "pokrenut Event Log",
    6006: "zaustavljen Event Log",
}

_MAX_SCAN = 200_000
_MAX_PAGE = 1_000
_MAX_UNREADABLE_DETAILS = 50
_DATA = re.compile(r"<Data(?:\s+Name=['\"]([^'\"]*)['\"])?[^>]*>([^<]*)</Data>")

# Known insertion-string layouts for classic Security events.  libevt exposes
# the strings but cannot attach the localized message-template field names.
_LEGACY_USER_INDEX = {
    528: 0,
    529: 0,
    530: 0,
    531: 0,
    532: 0,
    533: 0,
    534: 0,
    535: 0,
    536: 0,
    537: 0,
    538: 0,
    539: 0,
    540: 0,
    551: 0,
    552: 3,
    680: 1,
}
_LEGACY_LOGON_TYPE_INDEX = {
    528: 3,
    529: 2,
    530: 2,
    531: 2,
    532: 2,
    533: 2,
    534: 2,
    535: 2,
    536: 2,
    537: 2,
    538: 3,
    539: 2,
    540: 3,
}


def _brief(xml: str, limit: int = 320, field_cap: int = 140) -> str:
    """Return a bounded, field-labelled summary of one EVTX XML record."""

    out = []
    for name, val in _DATA.findall(xml or ""):
        val = val.strip()
        if not val:
            continue
        out.append((f"{name}={val}" if name else val)[:field_cap])
    if out:
        return " | ".join(out)[:limit]
    return (xml or "").replace("\n", " ")[:limit]


def _bare_log_name(log: str) -> str:
    name = (log or "Security").strip().replace("\\", "/").split("/")[-1]
    return name or "Security"


def _sanitize_name(log: str) -> str:
    """Defeat traversal while preserving an explicit ``.evt``/``.evtx`` suffix."""

    name = _bare_log_name(log)
    if name.casefold().endswith((".evt", ".evtx")):
        return name
    return f"{name}.evtx"


def _log_candidates(log: str) -> list[tuple[str, str]]:
    """Return deterministic extraction candidates as ``(path, format)`` pairs.

    Bare Security/System/Application names try their modern EVTX name first and
    then the Windows XP aliases SecEvent/SysEvent/AppEvent.  An explicit suffix
    is never rewritten, which matters for nonstandard and renamed evidence.
    """

    bare = _bare_log_name(log)
    folded = bare.casefold()
    if folded.endswith(".evtx"):
        return [(f"{directory}/{bare}", "evtx") for directory in _EVTX_LOG_DIRS]
    if folded.endswith(".evt"):
        return [(f"{directory}/{bare}", "evt") for directory in _EVT_LOG_DIRS]

    candidates = [
        (f"{directory}/{bare}.evtx", "evtx") for directory in _EVTX_LOG_DIRS
    ]
    legacy_name = _XP_EVT_ALIASES.get(folded, f"{bare}.evt")
    candidates.extend((f"{directory}/{legacy_name}", "evt") for directory in _EVT_LOG_DIRS)
    return candidates


def _parse_integer_filter(value: Any, *, name: str) -> tuple[set[int] | None, str | None]:
    if value is None or value == "" or value == []:
        return None, None
    sequence = value if isinstance(value, (list, tuple, set)) else [value]
    if not sequence:
        return None, None
    parsed: set[int] = set()
    for item in sequence:
        if isinstance(item, bool):
            return None, f"{name} must contain integers; bool is not allowed: {value!r}"
        try:
            parsed.add(int(item))
        except (TypeError, ValueError):
            return None, f"{name} must contain integers, received: {value!r}"
    return parsed, None


def _parse_event_ids(event_ids: Any) -> tuple[set[int] | None, str | None]:
    ids, error = _parse_integer_filter(event_ids, name="event_ids")
    if error:
        # Retain the Croatian phrase used by the existing public error contract.
        return None, error.replace("must contain integers", "mora biti popis cijelih brojeva")
    return ids, None


def _positive_int(value: Any, *, name: str, maximum: int | None = None) -> tuple[int | None, str | None]:
    if isinstance(value, bool):
        return None, f"{name} must be a positive integer"
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None, f"{name} must be a positive integer"
    if parsed <= 0 or (maximum is not None and parsed > maximum):
        suffix = f" no greater than {maximum}" if maximum is not None else ""
        return None, f"{name} must be a positive integer{suffix}"
    return parsed, None


def _nonnegative_int(value: Any, *, name: str) -> tuple[int | None, str | None]:
    if isinstance(value, bool):
        return None, f"{name} must be a non-negative integer"
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None, f"{name} must be a non-negative integer"
    if parsed < 0:
        return None, f"{name} must be a non-negative integer"
    return parsed, None


def _as_utc_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, date):
        parsed = datetime.combine(value, time.min)
    else:
        text = str(value).strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = f"{text[:-1]}+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _parse_time_bound(value: Any, *, name: str) -> tuple[datetime | None, str | None]:
    if value is None or value == "":
        return None, None
    parsed = _as_utc_datetime(value)
    if parsed is None:
        return None, f"{name} must be an ISO-8601 timestamp"
    return parsed, None


def _utc_text(value: Any) -> str | None:
    """Render a timestamp as UTC without falsely retaining local ambiguity."""

    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.endswith("Z") or re.search(r"[+-]\d\d:\d\d$", text):
            return text
        return f"{text}Z"
    parsed = _as_utc_datetime(value)
    if parsed is None:
        return None if value is None else str(value)
    return parsed.isoformat().replace("+00:00", "Z")


def _xml_fields(xml: str) -> dict[str, Any]:
    root = ET.fromstring(xml)
    system = root.find("./{*}System")
    if system is None:
        raise ValueError("EVTX record has no System element")
    event_id_element = system.find("./{*}EventID")
    if event_id_element is None or event_id_element.text is None:
        raise ValueError("EVTX record has no EventID")
    provider = system.find("./{*}Provider")
    created = system.find("./{*}TimeCreated")
    record_id = system.find("./{*}EventRecordID")
    computer = system.find("./{*}Computer")
    security = system.find("./{*}Security")

    values: dict[str, list[str]] = {}
    for index, element in enumerate(root.findall("./{*}EventData/{*}Data")):
        value = (element.text or "").strip()
        if not value:
            continue
        key = element.get("Name") or f"data_{index}"
        values.setdefault(key, []).append(value)

    def first(*names: str) -> str | None:
        for candidate in names:
            for key, entries in values.items():
                if key.casefold() == candidate.casefold() and entries:
                    return entries[0]
        return None

    user = first("TargetUserName", "SubjectUserName", "AccountName", "UserName")
    user_sid = first("TargetUserSid", "SubjectUserSid", "UserSid")
    if user_sid is None and security is not None:
        user_sid = security.get("UserID")
    logon_type_text = first("LogonType")
    try:
        logon_type = int(logon_type_text) if logon_type_text is not None else None
    except ValueError:
        logon_type = None

    return {
        "event_id": int(event_id_element.text.strip()),
        "timestamp": created.get("SystemTime") if created is not None else None,
        "source": provider.get("Name") if provider is not None else None,
        "record_id": int(record_id.text) if record_id is not None and record_id.text else None,
        "computer": computer.text if computer is not None else None,
        "user": user,
        "user_sid": user_sid,
        "logon_type": logon_type,
        "user_values": [
            item
            for item in (
                user,
                user_sid,
                first("SubjectDomainName"),
                first("TargetDomainName"),
            )
            if item
        ],
    }


def _record_value(record: Any, method: str, attribute: str | None = None) -> Any:
    callback = getattr(record, method, None)
    if callable(callback):
        return callback()
    if attribute is not None:
        return getattr(record, attribute, None)
    return None


def _record_strings(record: Any) -> list[str]:
    try:
        count = int(_record_value(record, "get_number_of_strings", "number_of_strings") or 0)
    except (TypeError, ValueError):
        count = 0
    values: list[str] = []
    for index in range(max(0, count)):
        try:
            value = record.get_string(index)
        except Exception:
            continue
        if value is not None:
            values.append(str(value))
    if values:
        return values
    fallback = getattr(record, "strings", None)
    if fallback is None:
        return []
    try:
        return [str(item) for item in fallback if item is not None]
    except TypeError:
        return []


def _legacy_record(record: Any, *, recovered: bool) -> dict[str, Any]:
    raw_event_id = _record_value(record, "get_event_identifier", "event_identifier")
    if raw_event_id is None:
        raise ValueError("legacy EVT record has no event identifier")
    event_id = int(raw_event_id) & 0xFFFF
    timestamp = _record_value(record, "get_written_time", "written_time")
    source = _record_value(record, "get_source_name", "source_name")
    strings = _record_strings(record)
    user_index = _LEGACY_USER_INDEX.get(event_id)
    user = strings[user_index] if user_index is not None and user_index < len(strings) else None
    type_index = _LEGACY_LOGON_TYPE_INDEX.get(event_id)
    logon_type = None
    if type_index is not None and type_index < len(strings):
        try:
            logon_type = int(strings[type_index])
        except (TypeError, ValueError):
            pass
    sid = _record_value(record, "get_user_security_identifier", "user_security_identifier")
    sid_text = str(sid) if sid not in (None, "") else None
    message = " | ".join(
        f"string_{index}={value}" for index, value in enumerate(strings) if value
    )[:320]
    item: dict[str, Any] = {
        "event_id": event_id,
        "time": _utc_text(timestamp),
        "source": str(source) if source is not None else None,
        "label": SECURITY_EVENT_IDS.get(event_id, ""),
        "message": message,
    }
    optional = {
        "user": user,
        "user_sid": sid_text,
        "logon_type": logon_type,
        "event_type": _record_value(record, "get_event_type", "event_type"),
        "event_category": _record_value(record, "get_event_category", "event_category"),
        "computer": _record_value(record, "get_computer_name", "computer_name"),
        "record_id": _record_value(record, "get_identifier", "identifier"),
    }
    item.update({key: value for key, value in optional.items() if value is not None})
    if recovered:
        item["recovered"] = True
    item["_timestamp"] = timestamp
    item["_user_values"] = [value for value in (user, sid_text, *strings) if value]
    return item


def _modern_record(
    *,
    xml: str,
    fallback_event_id: Any = None,
    fallback_timestamp: Any = None,
    fallback_source: Any = None,
    fallback_user_sid: Any = None,
    recovered: bool,
) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    if xml:
        try:
            fields = _xml_fields(xml)
        except (ET.ParseError, TypeError, ValueError):
            fields = {}
    event_id = fields.get("event_id", fallback_event_id)
    if event_id is None:
        raise ValueError("EVTX record has no event identifier")
    timestamp = fields.get("timestamp", fallback_timestamp)
    source = fields.get("source", fallback_source)
    user_sid = fields.get("user_sid", fallback_user_sid)
    item: dict[str, Any] = {
        "event_id": int(event_id),
        "time": _utc_text(timestamp),
        "source": str(source) if source is not None else None,
        "label": SECURITY_EVENT_IDS.get(int(event_id), ""),
        "message": _brief(xml),
    }
    for key in ("record_id", "computer", "user", "logon_type"):
        value = fields.get(key)
        if value is not None:
            item[key] = value
    if user_sid not in (None, ""):
        item["user_sid"] = str(user_sid)
    if recovered:
        item["recovered"] = True
    item["_timestamp"] = timestamp
    item["_user_values"] = [
        str(value)
        for value in (
            *fields.get("user_values", []),
            user_sid,
        )
        if value not in (None, "")
    ]
    return item


def _matches(
    item: Mapping[str, Any],
    *,
    event_ids: set[int] | None,
    user: str | None,
    logon_types: set[int] | None,
    time_from: datetime | None,
    time_to: datetime | None,
) -> bool:
    if event_ids is not None and item.get("event_id") not in event_ids:
        return False
    if user:
        target = user.casefold()
        candidates = item.get("_user_values", [])
        if not isinstance(candidates, list) or not any(
            str(candidate).casefold() == target for candidate in candidates
        ):
            return False
    if logon_types is not None and item.get("logon_type") not in logon_types:
        return False
    if time_from is not None or time_to is not None:
        timestamp = _as_utc_datetime(item.get("_timestamp"))
        if timestamp is None:
            return False
        if time_from is not None and timestamp < time_from:
            return False
        if time_to is not None and timestamp > time_to:
            return False
    return True


@dataclass
class _PageItem:
    """A reverse-comparison heap item, so the worst retained key is at index 0."""

    key: tuple[int, float, int]
    value: dict[str, Any]

    def __lt__(self, other: _PageItem) -> bool:
        return self.key > other.key


class _PageCollector:
    def __init__(self, *, offset: int, limit: int, order: str) -> None:
        self.offset = offset
        self.limit = limit
        self.order = order
        self.total_matching = 0
        self._capacity = offset + limit
        self._heap: list[_PageItem] = []

    def add(self, item: dict[str, Any], sequence: int) -> None:
        self.total_matching += 1
        timestamp = _as_utc_datetime(item.get("_timestamp"))
        if timestamp is None:
            key = (1, 0.0, sequence if self.order == "asc" else -sequence)
        else:
            epoch = timestamp.timestamp()
            key = (
                0,
                epoch if self.order == "asc" else -epoch,
                sequence if self.order == "asc" else -sequence,
            )
        visible = {key: value for key, value in item.items() if not key.startswith("_")}
        candidate = _PageItem(key=key, value=visible)
        if len(self._heap) < self._capacity:
            heapq.heappush(self._heap, candidate)
        elif self._capacity and key < self._heap[0].key:
            heapq.heapreplace(self._heap, candidate)

    def page(self) -> list[dict[str, Any]]:
        retained = sorted(self._heap, key=lambda item: item.key)
        return [item.value for item in retained[self.offset : self.offset + self.limit]]


def evtx_query(
    disk: Any,
    log: str = "Security",
    event_ids: Any = None,
    count: int | None = None,
    max_scan: int = _MAX_SCAN,
    *,
    offset: int = 0,
    limit: int | None = None,
    user: str | None = None,
    logon_types: Any = None,
    time_from: str | datetime | None = None,
    time_to: str | datetime | None = None,
    order: str = "asc",
    scratch: ControlledScratchSession | None = None,
) -> dict[str, Any]:
    """Query one Windows ``.evtx`` or legacy ``.evt`` log from an image.

    ``event_ids``, ``user``, ``logon_types`` and the inclusive ISO-8601 time
    bounds filter records before paging.  ``offset``/``limit`` select one page;
    ``order`` is ``asc`` or ``desc`` by UTC event time.  ``count`` remains a
    backward-compatible alias for ``limit`` and is not used by the model-facing
    wrapper.  The histogram covers every record scanned, regardless of filters.
    """

    ids, error = _parse_event_ids(event_ids)
    if error:
        return {"log": log, "error": error}
    parsed_logon_types, error = _parse_integer_filter(logon_types, name="logon_types")
    if error:
        return {"log": log, "error": error}
    parsed_offset, error = _nonnegative_int(offset, name="offset")
    if error:
        return {"log": log, "error": error}
    page_size_input = limit if limit is not None else count if count is not None else 30
    parsed_limit, error = _positive_int(page_size_input, name="limit", maximum=_MAX_PAGE)
    if error:
        return {"log": log, "error": error}
    parsed_max_scan, error = _positive_int(max_scan, name="max_scan")
    if error:
        return {"log": log, "error": error}
    order = str(order).casefold()
    if order not in {"asc", "desc"}:
        return {"log": log, "error": "order must be 'asc' or 'desc'"}
    parsed_from, error = _parse_time_bound(time_from, name="time_from")
    if error:
        return {"log": log, "error": error}
    parsed_to, error = _parse_time_bound(time_to, name="time_to")
    if error:
        return {"log": log, "error": error}
    if parsed_from is not None and parsed_to is not None and parsed_from > parsed_to:
        return {"log": log, "error": "time_from must not be later than time_to"}
    normalized_user = str(user).strip() if user is not None else None
    if normalized_user == "":
        normalized_user = None

    if type(scratch) is not ControlledScratchSession:
        return {"log": log, "error": "controlled scratch authority is required for event-log parsing"}
    scratch = cast(ControlledScratchSession, scratch)
    artifact: ScratchArtifact | None = None
    used: str | None = None
    log_format: str | None = None
    last_error: str | None = None
    short_extract = False
    for path, candidate_format in _log_candidates(log):
        candidate = scratch.artifact(ScratchKind.EVTX_LOG)
        candidate.__enter__()
        try:
            extract_to = getattr(disk, "extract_file_to", None)
            if callable(extract_to):
                metadata = extract_to(path, candidate.writer)
            else:
                candidate.writer.close()
                metadata = disk.extract_file(path, str(candidate.path))
        except Exception as exc:
            candidate.__exit__(type(exc), exc, exc.__traceback__)
            if isinstance(exc, ControlledScratchError):
                raise
            last_error = f"{path}: {type(exc).__name__}: {str(exc)[:80]}"
            continue
        artifact = candidate
        used = path
        log_format = candidate_format
        if isinstance(metadata, Mapping):
            size, written = metadata.get("size"), metadata.get("written")
            if isinstance(size, int) and isinstance(written, int) and written < size:
                short_extract = True
        break
    if artifact is None or used is None or log_format is None:
        requested = _sanitize_name(log)
        return {
            "log": log,
            "error": (
                f"zapisnik '{requested}' nije uspjesno izvaden; zadnji razlog: "
                f"{last_error or 'nije pronaden ni u jednoj putanji'}"
            ),
        }

    try:
        local = artifact.seal()
        histogram: Counter[int] = Counter()
        collector = _PageCollector(
            offset=cast(int, parsed_offset),
            limit=cast(int, parsed_limit),
            order=order,
        )
        unreadable_details: list[dict[str, Any]] = []
        unreadable_count = 0
        sequence = 0

        def mark_unreadable(record_set: str, index: int, exc: Exception) -> None:
            nonlocal unreadable_count
            unreadable_count += 1
            if len(unreadable_details) < _MAX_UNREADABLE_DETAILS:
                unreadable_details.append(
                    {
                        "record_set": record_set,
                        "index": index,
                        "error": f"{type(exc).__name__}: {str(exc)[:120]}",
                    }
                )

        def handle(item: dict[str, Any]) -> None:
            nonlocal sequence
            sequence += 1
            histogram[int(item["event_id"])] += 1
            if _matches(
                item,
                event_ids=ids,
                user=normalized_user,
                logon_types=parsed_logon_types,
                time_from=parsed_from,
                time_to=parsed_to,
            ):
                collector.add(item, sequence)

        parser_warning: str | None = None
        scan_limited = False
        format_corrupt = False
        scanned_active = 0
        scanned_recovered = 0
        total: int | None
        recovered_total: int | None

        if log_format == "evt":
            if pyevt is None:
                return {
                    "log": log,
                    "path": used,
                    "format": "evt",
                    "error": "legacy EVT parser is not installed; install libevt-python/pyevt",
                }
            parser_backend = "libyal-pyevt"
            recovered_supported = True
            evt_file = pyevt.file()
            evt_file.open(str(local))
            try:
                total = int(evt_file.get_number_of_records())
                try:
                    recovered_total = int(evt_file.get_number_of_recovered_records())
                except Exception:
                    recovered_total = 0
                try:
                    format_corrupt = bool(evt_file.is_corrupted())
                except Exception:
                    format_corrupt = False
                for index in range(min(total, cast(int, parsed_max_scan))):
                    try:
                        record = evt_file.get_record(index)
                        handle(_legacy_record(record, recovered=False))
                    except Exception as exc:
                        mark_unreadable("active", index, exc)
                    scanned_active += 1
                for index in range(min(recovered_total, cast(int, parsed_max_scan))):
                    try:
                        record = evt_file.get_recovered_record(index)
                        handle(_legacy_record(record, recovered=True))
                    except Exception as exc:
                        mark_unreadable("recovered", index, exc)
                    scanned_recovered += 1
                scan_limited = (
                    total > cast(int, parsed_max_scan)
                    or recovered_total > cast(int, parsed_max_scan)
                )
            finally:
                try:
                    evt_file.close()
                except Exception:
                    pass
        elif pyevtx is not None:
            parser_backend = "libyal-pyevtx"
            recovered_supported = True
            evtx_file = pyevtx.file()
            evtx_file.open(str(local))
            try:
                total = int(evtx_file.get_number_of_records())
                try:
                    recovered_total = int(evtx_file.get_number_of_recovered_records())
                except Exception:
                    recovered_total = 0
                for index in range(min(total, cast(int, parsed_max_scan))):
                    try:
                        record = evtx_file.get_record(index)
                        xml = _record_value(record, "get_xml_string", "xml_string") or ""
                        handle(
                            _modern_record(
                                xml=str(xml),
                                fallback_event_id=_record_value(
                                    record, "get_event_identifier", "event_identifier"
                                ),
                                fallback_timestamp=_record_value(
                                    record, "get_written_time", "written_time"
                                ),
                                fallback_source=_record_value(
                                    record, "get_source_name", "source_name"
                                ),
                                fallback_user_sid=_record_value(
                                    record,
                                    "get_user_security_identifier",
                                    "user_security_identifier",
                                ),
                                recovered=False,
                            )
                        )
                    except Exception as exc:
                        mark_unreadable("active", index, exc)
                    scanned_active += 1
                for index in range(min(recovered_total, cast(int, parsed_max_scan))):
                    try:
                        record = evtx_file.get_recovered_record(index)
                        xml = _record_value(record, "get_xml_string", "xml_string") or ""
                        handle(
                            _modern_record(
                                xml=str(xml),
                                fallback_event_id=_record_value(
                                    record, "get_event_identifier", "event_identifier"
                                ),
                                fallback_timestamp=_record_value(
                                    record, "get_written_time", "written_time"
                                ),
                                fallback_source=_record_value(
                                    record, "get_source_name", "source_name"
                                ),
                                fallback_user_sid=_record_value(
                                    record,
                                    "get_user_security_identifier",
                                    "user_security_identifier",
                                ),
                                recovered=True,
                            )
                        )
                    except Exception as exc:
                        mark_unreadable("recovered", index, exc)
                    scanned_recovered += 1
                scan_limited = (
                    total > cast(int, parsed_max_scan)
                    or recovered_total > cast(int, parsed_max_scan)
                )
            finally:
                try:
                    evtx_file.close()
                except Exception:
                    pass
        elif PythonEvtx is not None:
            parser_backend = "python-evtx"
            recovered_supported = False
            recovered_total = None
            exhausted = False
            with PythonEvtx(str(local)) as evtx_file:
                records = iter(evtx_file.records())
                while scanned_active < cast(int, parsed_max_scan):
                    try:
                        record = next(records)
                    except StopIteration:
                        exhausted = True
                        break
                    except Exception as exc:
                        mark_unreadable("active", scanned_active, exc)
                        parser_warning = (
                            "parser stopped before end of log: "
                            f"{type(exc).__name__}: {str(exc)[:100]}"
                        )
                        break
                    try:
                        xml = record.xml()
                        handle(_modern_record(xml=xml, recovered=False))
                    except Exception as exc:
                        mark_unreadable("active", scanned_active, exc)
                    scanned_active += 1
                if not exhausted and parser_warning is None and scanned_active >= cast(
                    int, parsed_max_scan
                ):
                    try:
                        next(records)
                    except StopIteration:
                        exhausted = True
                    except Exception as exc:
                        mark_unreadable("active", scanned_active, exc)
                        parser_warning = (
                            "parser could not confirm end of log: "
                            f"{type(exc).__name__}: {str(exc)[:100]}"
                        )
                    else:
                        scan_limited = True
            total = scanned_active if exhausted else None
        else:
            return {
                "log": log,
                "path": used,
                "format": "evtx",
                "error": "EVTX parser is not installed; install dfir-agent[forensics]",
            }

        events = collector.page()
        page_truncated = collector.total_matching > cast(int, parsed_offset) + len(events)
        next_offset = (
            cast(int, parsed_offset) + len(events) if page_truncated and events else None
        )
        scan_reasons: list[str] = []
        if short_extract:
            scan_reasons.append("short_extract")
        if scan_limited:
            scan_reasons.append("max_scan_reached")
        if parser_warning:
            scan_reasons.append("parser_stopped_early")
        if unreadable_count:
            scan_reasons.append("unreadable_records")
        if format_corrupt:
            scan_reasons.append("source_marked_corrupt")
        scan_complete = not scan_reasons

        counts = sorted(histogram.items(), key=lambda item: item[1], reverse=True)
        top = counts[:40]
        shown = {event_id for event_id, _ in top}
        for event_id, frequency in counts:
            if event_id in SECURITY_EVENT_IDS and event_id not in shown:
                top.append((event_id, frequency))

        result: dict[str, Any] = {
            "log": log,
            "resolved_log": used.rsplit("/", 1)[-1],
            "path": used,
            "format": log_format,
            "total_records": total,
            "recovered_records": recovered_total,
            "scanned": scanned_active + scanned_recovered,
            "scanned_active": scanned_active,
            "scanned_recovered": scanned_recovered,
            "unreadable_records": unreadable_count,
            "unreadable_record_details": unreadable_details,
            "parser_backend": parser_backend,
            "recovered_supported": recovered_supported,
            "event_id_counts": [
                {
                    "event_id": event_id,
                    "label": SECURITY_EVENT_IDS.get(event_id, ""),
                    "count": frequency,
                }
                for event_id, frequency in top
            ],
            "events": events,
            "filters": {
                "event_ids": sorted(ids) if ids is not None else None,
                "user": normalized_user,
                "logon_types": (
                    sorted(parsed_logon_types) if parsed_logon_types is not None else None
                ),
                "time_from": _utc_text(parsed_from),
                "time_to": _utc_text(parsed_to),
            },
            "order": order,
            "total_matching": collector.total_matching,
            "offset": cast(int, parsed_offset),
            "limit": cast(int, parsed_limit),
            "returned": len(events),
            "next_offset": next_offset,
            "truncated": page_truncated,
            "page_truncated": page_truncated,
            "scan_complete": scan_complete,
            "coverage_complete": scan_complete,
            "scan_coverage": {
                "complete": scan_complete,
                "stop_reasons": scan_reasons,
                "short_extract": short_extract,
                "max_scan": cast(int, parsed_max_scan),
                "format_corrupt": format_corrupt,
            },
        }
        if short_extract:
            result["warning"] = (
                "extraction was shorter than the source file; record counts may be low"
            )
        if scan_limited:
            result["warning_scan"] = (
                f"scan stopped at the configured per-record-set cap of {parsed_max_scan}"
            )
        if not recovered_supported:
            result["warning_recovery"] = (
                "python-evtx does not recover slack records; recovered_records is unknown"
            )
        if parser_warning:
            result["warning_parser"] = parser_warning
        if unreadable_count:
            result["warning_unreadable"] = (
                f"{unreadable_count} record(s) could not be decoded; inspect "
                "unreadable_record_details"
            )
        return result
    except ControlledScratchError:
        raise
    except Exception as exc:
        return {
            "log": log,
            "path": used,
            "format": log_format,
            "error": f"{type(exc).__name__}: {str(exc)[:200]}",
        }
    finally:
        artifact.__exit__(None, None, None)
