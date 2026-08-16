"""RegRipper (rip.pl) verified-subprocess registry tool.

regipy's samparse decodes SAM accounts by RID only, not string usernames. RegRipper — the
canonical registry forensic tool — resolves usernames, USB history and shellbags. This is a
thin subprocess adapter (like the vol/tshark wrappers): it stages the hive read-only
and returns RegRipper's OWN output verbatim, wrapping lines as rows only for pagination via the
shared toolio envelope. No forensic parsing is done here.
"""
from __future__ import annotations

import os
import re
import shutil
import tempfile
from datetime import UTC, datetime
from typing import Any

from forensic_agent.core.environ import regripper_path
from forensic_agent.core.storage_containment import (
    EvidenceWriteScope,
    acquire_evidence_write_dir,
)
from forensic_agent.core.toolio import shape
from forensic_agent.core.toolkit import ExternalToolError, run_external
from forensic_agent.tools.registry_tool import _resolve

_PROFILE = {"SYSTEM": "system", "SOFTWARE": "software", "SAM": "sam", "SECURITY": "security"}

# Common descriptive names used by analysts and other RegRipper distributions
# do not match the Debian package's actual plugin basenames.  Normalize only
# verified synonyms; arbitrary plugin names still pass through and fail closed
# in RegRipper itself.
_PLUGIN_ALIASES = {
    "computername": "compname",
    "mounteddevices": "mountdev",
}

_SAM_USERNAME = re.compile(r"^Username\s*:\s*(.*?)\s*\[(\d+)\]\s*$", re.IGNORECASE)
_SAM_SID = re.compile(r"^SID\s*:\s*(S-\d-\d+(?:-\d+)+)\s*$", re.IGNORECASE)
_SAM_LAST_LOGIN = re.compile(r"^Last Login Date\s*:\s*(.*?)\s*$", re.IGNORECASE)
_SAM_LOGIN_COUNT = re.compile(r"^Login Count\s*:\s*(\d+)\s*$", re.IGNORECASE)
_SAM_ACCOUNT_TYPE = re.compile(r"^Account Type\s*:\s*(.*?)\s*$", re.IGNORECASE)
_WELL_KNOWN_LOCAL_RIDS = frozenset({500, 501, 502, 503, 504})


def _samparse_utc(value: str) -> str | None:
    """Normalize RegRipper's documented UTC timestamp without guessing a local zone."""

    if value.strip().casefold() == "never":
        return None
    try:
        parsed = datetime.strptime(value.strip(), "%a %b %d %H:%M:%S %Y Z").replace(
            tzinfo=UTC
        )
    except ValueError:
        return None
    return parsed.isoformat().replace("+00:00", "Z")


def _profile_for(hive: str) -> str:
    h = hive.strip().upper()
    return "ntuser" if h.startswith("NTUSER") else _PROFILE.get(h, h.lower())


def _plugin_target(plugin: str) -> str:
    normalized = plugin.strip()
    return _PLUGIN_ALIASES.get(normalized.casefold(), normalized)


def registry_ripper(disk, hive: str, plugin: str | None = None,
                    offset: int = 0, limit: int = 200, filter: str | None = None) -> dict:
    """Run RegRipper over a registry hive and return its output verbatim — AUTHORITATIVE
    for SAM account NAMES, USB device history, and shellbags where regipy returns only RIDs.
    hive: SYSTEM/SOFTWARE/SAM/SECURITY. This adapter stages a machine hive by a fixed
    path and has no resolver for a per-user NTUSER hive; use registry_query for one.
    plugin=None runs the hive's full plugin profile (rip.pl -f <profile>); pass plugin=
    for a specific one (rip.pl -p <plugin>, e.g. "samparse"). Common aliases
    computername->compname and mounteddevices->mountdev are normalized to the
    installed plugin names. offset/limit paginate, filter narrows lines (substring).
    Read-only."""
    rip = regripper_path()
    if not rip:
        return {"error": "RegRipper not available. Install RegRipper, add rip.pl to PATH, or set DFA_REGRIPPER."}
    path = _resolve(hive)
    if not path:
        return {"error": f"unknown hive '{hive}'. Use SYSTEM/SOFTWARE/SAM/SECURITY (NTUSER is not resolvable here; use registry_query)."}
    scratch_base = tempfile.gettempdir()
    acquire_evidence_write_dir(
        scratch_base,
        subject="a registry hive staged out of the evidence",
        scope=EvidenceWriteScope.NOT_HOST_SHARED,
    )
    tmpdir = tempfile.mkdtemp(prefix="forensic_agent_rr_", dir=scratch_base)
    local = os.path.join(tmpdir, "hive")
    try:
        disk.extract_file(path, local)
    except Exception as e:
        shutil.rmtree(tmpdir, ignore_errors=True)
        return {"hive": hive, "path": path, "error": f"could not extract hive: {str(e)[:160]}"}
    try:
        flag, target = ("-p", _plugin_target(plugin)) if plugin else ("-f", _profile_for(hive))
        try:
            proc = run_external([rip, "-r", local, flag, target], timeout=300, check=False)
        except ExternalToolError as e:
            return {"hive": hive, "path": path, "error": f"RegRipper failed: {e}"}
        if proc.returncode != 0:
            diagnostic = (proc.stderr or proc.stdout or "no diagnostic output").strip()
            return {
                "hive": hive,
                "path": path,
                "tool": "regripper",
                ("plugin" if plugin else "profile"): target,
                "returncode": proc.returncode,
                "error": f"RegRipper failed (rc={proc.returncode}): {diagnostic[:500]}",
            }
        rows = [{"line": ln} for ln in (proc.stdout or "").splitlines() if ln.strip()]
        env = shape(rows, offset=offset, limit=limit, filter=filter)
        out = {"hive": hive, "path": path, "tool": "regripper",
               ("plugin" if plugin else "profile"): target,
               "returncode": proc.returncode, **env}
        if plugin and target != plugin.strip():
            out["requested_plugin"] = plugin
        return out
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def windows_local_accounts(disk) -> dict:
    """Return compact, validated local-account records from ``samparse``.

    RegRipper remains the forensic parser; this function only converts its
    verbose account section into a stable structure. Account SIDs are accepted
    only when their last component matches the RID printed beside the username.
    Well-known local accounts are classified by RID rather than localized name.
    """

    raw = registry_ripper(
        disk,
        "SAM",
        plugin="samparse",
        offset=0,
        limit=10_000,
    )
    if raw.get("error") not in (None, "", False):
        return {
            "items": [],
            "excluded_well_known_accounts": [],
            "machine_sid": None,
            "coverage_complete": False,
            "error": raw.get("error"),
            "source": {"hive": "SAM", "tool": "RegRipper", "plugin": "samparse"},
        }

    lines = [
        str(row.get("line") or "")
        for row in raw.get("rows", [])
        if isinstance(row, dict) and str(row.get("line") or "")
    ]
    version = next(
        (line.strip() for line in lines if line.casefold().startswith("samparse v.")),
        None,
    )
    user_marker = next(
        (index for index, line in enumerate(lines) if line.strip() == "User Information"),
        None,
    )
    group_marker = next(
        (
            index
            for index, line in enumerate(lines)
            if line.strip() == "Group Membership Information"
        ),
        None,
    )
    warnings: list[str] = []
    if user_marker is None or group_marker is None or group_marker <= user_marker:
        warnings.append("samparse account-section boundaries were absent or ambiguous")
        account_lines = lines
        section_complete = False
    else:
        account_lines = lines[user_marker + 1 : group_marker]
        section_complete = True

    accounts: list[dict] = []
    pending: dict[str, Any] | None = None
    invalid_pairs = 0

    def finish_pending() -> None:
        nonlocal invalid_pairs, pending
        if pending is None:
            return
        username = str(pending["username"])
        rid = int(pending["rid"])
        account_sid = str(pending.get("account_sid") or "").upper()
        sid_prefix, separator, sid_rid = account_sid.rpartition("-")
        if not separator:
            invalid_pairs += 1
            warnings.append(f"no account SID followed username RID {rid}")
            pending = None
            return
        if not sid_rid.isdecimal() or int(sid_rid) != rid:
            invalid_pairs += 1
            warnings.append(f"SID/RID mismatch for local account RID {rid}")
            pending = None
            return
        last_login_raw = pending.get("last_login_raw")
        last_login_utc = (
            _samparse_utc(str(last_login_raw)) if last_login_raw is not None else None
        )
        record = {
            "username": username,
            "rid": rid,
            "account_sid": account_sid,
            "machine_sid": sid_prefix,
            "well_known_builtin": rid in _WELL_KNOWN_LOCAL_RIDS,
            "login_count": pending.get("login_count"),
            "last_login_utc": last_login_utc,
            "last_login_status": (
                "never"
                if str(last_login_raw or "").strip().casefold() == "never"
                else "observed" if last_login_utc is not None else "not_reported"
            ),
            "account_type": pending.get("account_type"),
            "source_lines": list(pending["source_lines"]),
        }
        if last_login_raw is not None:
            record["last_login_raw"] = last_login_raw
        accounts.append(record)
        pending = None

    for line in account_lines:
        stripped = line.strip()
        username_match = _SAM_USERNAME.match(stripped)
        if username_match is not None:
            finish_pending()
            pending = {
                "username": username_match.group(1).strip(),
                "rid": int(username_match.group(2)),
                "source_lines": [stripped],
            }
            continue
        if pending is None:
            continue
        sid_match = _SAM_SID.match(stripped)
        if sid_match is not None:
            pending["account_sid"] = sid_match.group(1).upper()
            pending["source_lines"].append(stripped)
            continue
        last_login_match = _SAM_LAST_LOGIN.match(stripped)
        if last_login_match is not None:
            pending["last_login_raw"] = last_login_match.group(1).strip()
            pending["source_lines"].append(stripped)
            continue
        login_count_match = _SAM_LOGIN_COUNT.match(stripped)
        if login_count_match is not None:
            pending["login_count"] = int(login_count_match.group(1))
            pending["source_lines"].append(stripped)
            continue
        account_type_match = _SAM_ACCOUNT_TYPE.match(stripped)
        if account_type_match is not None:
            pending["account_type"] = account_type_match.group(1).strip()
            pending["source_lines"].append(stripped)
    finish_pending()

    unique: dict[int, dict] = {}
    for account in accounts:
        rid = int(account["rid"])
        if rid in unique and unique[rid] != account:
            invalid_pairs += 1
            warnings.append(f"conflicting samparse records for local RID {rid}")
            continue
        unique.setdefault(rid, account)
    accounts = [unique[rid] for rid in sorted(unique)]
    prefixes = {str(account["machine_sid"]) for account in accounts}
    machine_sid = next(iter(prefixes)) if len(prefixes) == 1 else None
    if len(prefixes) != 1:
        warnings.append("local account SIDs did not yield one unambiguous machine SID")

    excluded = [account for account in accounts if account["well_known_builtin"]]
    items = [account for account in accounts if not account["well_known_builtin"]]
    complete = bool(
        section_complete
        and raw.get("truncated") is not True
        and raw.get("coverage_complete") is not False
        and invalid_pairs == 0
        and accounts
        and machine_sid
    )
    result: dict[str, object] = {
        "items": items,
        "excluded_well_known_accounts": excluded,
        "machine_sid": machine_sid,
        "total_account_count": len(accounts),
        "non_builtin_account_count": len(items),
        "excluded_well_known_count": len(excluded),
        "coverage_complete": complete,
        "truncated": not complete,
        "source": {
            "hive": "SAM",
            "tool": "RegRipper",
            "plugin": "samparse",
            "version": version,
        },
        "warnings": warnings,
    }
    if not complete:
        result.update(
            {
                "status": "partial",
                "coverage": {
                    "complete": False,
                    "scope": "SAM local-account records",
                    "reason": "samparse account records were incomplete or internally inconsistent",
                },
            }
        )
    else:
        result["coverage"] = {"complete": True, "scope": "SAM local-account records"}
    return result
