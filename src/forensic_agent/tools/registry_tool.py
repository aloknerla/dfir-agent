"""Windows registry forensics tool (regipy — pure-Python RegRipper equivalent).

The agent does NOT parse the registry itself: regipy (a validated tool) runs its own
plugins; this module is a thin adapter that extracts a hive read-only and returns the
plugins' findings. Two design points keep it honest:

* **Correct invocation, not custom logic.** regipy's ``run_relevant_plugins`` catches
  only ``ModuleNotFoundError``, so one plugin raising anything else (e.g.
  ``AppCompatCache`` on an old SYSTEM hive) aborts the WHOLE run and the summary
  collapses to ``{"error": ...}``. We run regipy's OWN validated plugins with
  per-plugin isolation so a single failure never zeroes out the survivors. The
  forensics is still entirely regipy's; we only call it robustly.
* **Centralised output contract.** Findings are returned through the shared
  ``core.toolio.shape`` envelope (filter + pagination + truncation metadata) — the
  same contract every row-returning tool uses — instead of a per-tool character cap
  that silently buried evidence (e.g. SAM users cut off mid-list).
* **regipy's value, and ours only when asked for.** A returned value is exactly
  what regipy reported.  Anything this module reads out of it (a timestamp, a
  string behind a struct header) is a guess about a meaning the registry never
  states, so it is a separate DERIVED operation — ``operation="value_readings"``
  — and not a block travelling inside the observed result, where one result would
  carry an observation and an inference at once.
* **The installed library is the authority on its own plugins.** The curated
  selection below is checked against the plugin table of the regipy that is
  actually imported, so a renamed plugin fails loudly instead of quietly
  matching nothing.
* **regipy's complaints travel with the read that provoked them.** The library
  reports its trouble on ``stderr``, where it used to interleave with the
  operator's activity feed and then scroll away unrecorded.  It is captured at
  the regipy boundary and published in that read's own result instead — never
  dropped, because a diagnostic nobody retained is a diagnostic that was thrown
  away.
* **A value regipy cannot report is read by a second vetted parser, not by us.**
  A hive stores a value of four bytes or fewer inside the ``vk`` record, with bit
  31 of ``data_size`` set to say so.  regipy 6.2.1 hands back ``vk.data_offset``
  — the little-endian integer of those four bytes — and drops ``data_size``, so
  a ``REG_SZ`` holding ``"8"`` arrives here as ``56``, an empty one as ``0``, and
  the true length is gone with it.  Neither the content nor its length can be
  recovered from that integer, so those values are re-read through **libregf**,
  which keeps both.  The row names the reader that supplied it, and the result
  says how many rows were substituted.  Nothing here decodes a value type by
  hand: the substitution asks libregf's own typed accessors, so the value stays
  an upstream observation of a validated tool rather than becoming this
  project's composition.
* **Where BOTH parsers are known to be wrong, nothing is published.**  libregf
  has a defect of its own in the same class: an inline value shorter than four
  bytes comes back as zeros, so a one-byte ``REG_BINARY`` holding ``\\x02`` reads
  as ``\\x00`` — the right type, the right length and the wrong content, which
  unlike the integer it would replace looks correct.  That sub-class is withheld
  with the reason on the row, because separating the values libregf gets wrong
  from the ones it happens to get right would mean decoding the ``vk`` record
  here, and a registry value decoder written in this project is the thing the
  substitution above exists to avoid.  A withheld value is one an examiner can
  go and read; a wrong one that looks right is not.
"""

from __future__ import annotations

import hashlib
import os
import threading
from collections import deque
from collections.abc import Iterable, Iterator, Mapping
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from regipy.plugins.utils import run_relevant_plugins
from regipy.registry import RegistryHive
from regipy.utils import convert_wintime

from forensic_agent.core.backend_stream import BackendStderr, capture_backend_stderr
from forensic_agent.core.backend_versions import (
    PYTHON_BACKENDS,
    BackendVersion,
    BackendVersionError,
    resolve_python_backend,
    session_backend_versions,
)
from forensic_agent.core.controlled_scratch import (
    ControlledScratchError,
    ControlledScratchSession,
    ScratchKind,
    ScratchWorkspaceKind,
)
from forensic_agent.core.derivation_inputs import (
    DerivationInputError,
    confirmed_result_inputs,
    observed_operation_input,
)
from forensic_agent.core.tool_failure import tool_failure_result
from forensic_agent.core.toolio import shape

# System hive paths (NTUSER is per-user: pass hive="NTUSER:<username>")
HIVE_PATHS = {
    "SYSTEM": "/Windows/System32/config/SYSTEM",
    "SOFTWARE": "/Windows/System32/config/SOFTWARE",
    "SAM": "/Windows/System32/config/SAM",
    "SECURITY": "/Windows/System32/config/SECURITY",
}


class RegistryPluginSetError(RuntimeError):
    """The curated plugin selection disagrees with the installed regipy."""


#: The regipy entry of the project's backend inventory.  Taken from the module
#: that already resolves backend versions from the running interpreter, so this
#: tool cannot report a different regipy than the one a run record publishes,
#: and no pin file is consulted: a pin states an intent, not what is installed.
_REGIPY_BACKEND = next(spec for spec in PYTHON_BACKENDS if spec.backend == "regipy")

#: The second reader of the same hive bytes, taken from the same inventory so a
#: substituted value names a version this host established rather than a pin.
_LIBREGF_BACKEND = next(spec for spec in PYTHON_BACKENDS if spec.backend == "libregf")

# Plugins most useful to surface first (others still available via a wider filter).
# Every name here is validated against the installed regipy before it is used:
# a curated list is a claim about another library, and an unchecked claim decays
# into a filter that silently matches nothing after an upstream rename.
_CURATED_PLUGINS = frozenset(
    {
        # SYSTEM
        "computer_name",
        "timezone_data",
        "shutdown",
        "usb_devices",
        "usbstor_plugin",
        "mounted_devices",
        "network_data",
        "services",
        "shimcache",
        # SOFTWARE
        "installed_programs_software",
        "profilelist_plugin",
        "winver_plugin",
        "previous_winver_plugin",
        "networklist",
        # NTUSER
        "ntuser_persistence",
        # regipy reads the per-user Uninstall entries under this name; it has no
        # plugin called "uninstall".  RegRipper's own `uninstall` stays reachable
        # through registry_ripper.
        "installed_programs_ntuser",
        "user_assist",
        "typed_urls",
        "typed_paths",
        "recentdocs",
        "ntuser_shellbag_plugin",
        "word_wheel_query",
        "runmru",
    }
)


def _backend_version(backend: str) -> BackendVersion:
    """What this interpreter established about one registry parser it imported.

    Prefers the session inventory so the version named here is the same one the
    run record attests.  Outside a session (a unit-level caller, a tool exercised
    on its own) the same spec is resolved directly: it asks the same library the
    same question and executes nothing.
    """

    try:
        return session_backend_versions().entry(backend)
    except BackendVersionError:
        spec = next(candidate for candidate in PYTHON_BACKENDS if candidate.backend == backend)
        return resolve_python_backend(spec)


def _backend_identity(backend: str) -> dict:
    """Name one parser, as this host resolved it."""

    entry = _backend_version(backend)
    return {
        "name": entry.backend,
        "version": entry.version,
        "version_status": entry.status.value,
        "version_source": entry.source,
    }


def _regipy_backend_version() -> BackendVersion:
    """What this interpreter established about the regipy it just imported."""

    return _backend_version(_REGIPY_BACKEND.backend)


def _regipy_identity() -> dict:
    """Name the parser that produced the findings, as this host resolved it."""

    return _backend_identity(_REGIPY_BACKEND.backend)


#: Where a captured complaint lands: in the failure of a read that raised, and on
#: the warning channel of one that did not.
_BACKEND_STDERR_FIELD = "backend_stderr"
_BACKEND_STDERR_WARNING_CODE = "registry_backend_stderr"


def _hive_staging_failure(error: Exception, *, hive: str, path: str) -> dict[str, object]:
    """Report a hive that never reached the parser, saying which failure it was.

    Staging the hive is a read of the evidence, and its two failures are not the
    same finding: a hive the filesystem does not have and one the container could
    not deliver were both worded "could not open hive", so a reader could not tell
    an absent SAM from an unreadable one.  The classification decides that from
    the exception exactly as the filesystem functions do, and it travels in the
    result so what a run may conclude from a failed read stays decided in the one
    module that decides it.
    """

    return {
        "hive": hive,
        "path": path,
        **tool_failure_result(error, subject=path, backend="dfvfs"),
    }


#: Guards the two registries below, and nothing else: a thread that holds a
#: staging lock still needs this one to publish its extraction, so it is never
#: held while a staging lock is acquired.
_HIVE_REGISTRY_LOCK = threading.Lock()

#: (retained workspace identity, evidence identity, in-image path) -> staged
#: hive path.  The hive is immutable evidence, so one extraction answers every
#: identical later one for the life of the scratch session that owns the copy.
#: The workspace identity is part of the key so one run can never be served a
#: hive staged below another run's controlled root, and the evidence identity
#: (the image's own digest) is part of it so a second evidence source can never
#: be served another's hive.
_HIVE_CACHE: dict[tuple[str, str, str], str] = {}

#: One lock per cache key.  At most one extraction runs for a given key, and no
#: staged copy is parsed while another thread is still writing it — a partial
#: read would otherwise hand a caller a zero-byte copy.  Entries are never
#: dropped: the lock a thread already holds must stay the one every other
#: thread for that key acquires, so the registry is bounded by the distinct
#: keys seen, not by the number of calls.
_HIVE_LOCKS: dict[tuple[str, str, str], threading.Lock] = {}


def _hive_stage_lock(key: tuple[str, str, str]) -> threading.Lock:
    """Return the one lock that serialises everything done for one staged hive."""

    with _HIVE_REGISTRY_LOCK:
        lock = _HIVE_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _HIVE_LOCKS[key] = lock
        return lock


def _extract_hive_into(disk, path: str, writer, destination: Path) -> None:
    """Run the disk's own extraction into one exclusively created destination."""

    extract_to = getattr(disk, "extract_file_to", None)
    if callable(extract_to):
        extract_to(path, writer)
    else:
        # Development test doubles may only expose the legacy path API.  The
        # caller still chose and exclusively created this path; production
        # DiskImage always uses the open-stream method above.
        writer.close()
        disk.extract_file(path, str(destination))


def _staged_hive(
    disk, path: str, scratch: ControlledScratchSession, stack: ExitStack
) -> tuple[Path, bool]:
    """Stage one in-image hive for parsing, extracting it at most once per session.

    Returns the staged copy's path and whether it was reused from an identical
    earlier extraction.  Re-extracting the same immutable hive for every call is
    the defect ``registry_query_many`` already names within one batch —
    needlessly expensive, and it widens the opportunity for inconsistent
    partial reads — generalised here across calls: the copy goes into a
    workspace the session RETAINS and purges at close, so the extraction's
    lifetime matches the immutability claim that justifies sharing it.

    The shared copy is keyed by the image's own digest.  A disk that does not
    declare one (development doubles) keeps the per-call artifact path: without
    a durable evidence identity there is nothing safe to share by, and the
    old behaviour is the correct fallback rather than a guessed key.

    Whatever staged the copy, the caller-held ``stack`` owns the locks and the
    per-call artifact, so the copy is readable for exactly as long as the
    caller parses it and the staging lock is held for the same span — no
    thread ever parses a hive another thread is still writing.
    """

    identity = getattr(disk, "image_sha", None)
    if not isinstance(identity, str) or not identity:
        artifact = stack.enter_context(scratch.artifact(ScratchKind.REGISTRY_HIVE))
        _extract_hive_into(disk, path, artifact.writer, artifact.path)
        return artifact.seal(), False
    workspace = scratch.retained_workspace(ScratchWorkspaceKind.REGISTRY_HIVE_CACHE).path
    key = (os.path.normcase(str(workspace)), identity, path)
    stack.enter_context(_hive_stage_lock(key))
    with _HIVE_REGISTRY_LOCK:
        cached = _HIVE_CACHE.get(key)
    if cached is not None:
        staged = Path(cached)
        try:
            # An emptied or vanished copy is the same defect as a missing one:
            # a purged session's entry must re-extract, never half-answer.
            intact = staged.is_file() and staged.stat().st_size > 0
        except OSError:
            intact = False
        if intact:
            return staged, True
        with _HIVE_REGISTRY_LOCK:
            _HIVE_CACHE.pop(key, None)
    digest = hashlib.sha256("\n".join(key).encode("utf-8")).hexdigest()[:32]
    target = workspace / f"hive-{digest}"
    if target.exists():
        # Leftovers of an interrupted extraction; this thread holds the key's
        # staging lock, so nothing else is writing or parsing here.
        target.unlink()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    writer = os.fdopen(os.open(target, flags, 0o600), "wb")
    try:
        _extract_hive_into(disk, path, writer, target)
        if not writer.closed:
            writer.flush()
            os.fsync(writer.fileno())
            writer.close()
    except BaseException:
        # A partial copy must never be findable, cached or not: the next
        # attempt re-creates the file exclusively and starts from nothing.
        if not writer.closed:
            writer.close()
        try:
            os.unlink(target)
        except OSError:
            pass
        raise
    if target.stat().st_size > 0:
        with _HIVE_REGISTRY_LOCK:
            # A closed session's entries can never be reached again through
            # their own key, so drop them here instead of letting the map grow
            # for the life of the process.  Dropping an entry only forgets a
            # path; it removes nothing from disk.
            for stale in [item for item, kept in _HIVE_CACHE.items() if not Path(kept).is_file()]:
                _HIVE_CACHE.pop(stale, None)
            _HIVE_CACHE[key] = str(target)
    return target, False


def _with_backend_stderr(result: dict, stream: BackendStderr) -> dict:
    """Publish what regipy wrote to stderr in the result of the read that caused it.

    Which field it lands in follows from what the read did, because the two are
    not the same claim.  A failed read's diagnosis IS the library's complaint: the
    exception carries a type and a message, while the reason it happened was
    already printed and would otherwise be gone.  A read that succeeded is still a
    successful read of the same evidence, so the complaint rides on the warning
    channel and leaves the rows, the counters, the coverage and the status exactly
    as they were — a talkative library must not move a finding.

    Neither path drops it.  Silencing the stream and keeping nothing would leave a
    tidy console as the only thing this achieved, and would lose the one account of
    the failure that named its cause.
    """

    report = stream.report()
    if report is None:
        return result
    if result.get("error"):
        return {
            **result,
            "error": f"{result['error']} [{report['backend']} stderr: {report['stderr']}]",
            _BACKEND_STDERR_FIELD: report,
        }
    return {
        **result,
        "warnings": [
            *result.get("warnings", []),
            {
                "code": _BACKEND_STDERR_WARNING_CODE,
                "message": (
                    f"{report['backend']} wrote to stderr while reading this hive; "
                    "the read itself completed"
                ),
                "details": report,
            },
        ],
    }


def installed_plugin_names() -> frozenset[str]:
    """Every plugin name the installed regipy actually exposes.

    Read from regipy's own plugin table rather than from anything this project
    maintains, so the answer moves with the library on whatever host it runs.
    """

    try:
        from regipy.plugins.utils import PLUGINS
    except Exception as error:  # pragma: no cover - regipy internals moved
        raise RegistryPluginSetError(
            "the installed regipy does not expose its plugin table, so no plugin "
            "selection can be validated against it"
        ) from error
    return frozenset(
        name for name in (str(getattr(plugin, "NAME", "")) for plugin in PLUGINS) if name
    )


def curated_plugin_names() -> frozenset[str]:
    """The curated selection, proven to exist in the regipy that is installed.

    Raises rather than dropping an unknown name.  A plugin this project asks for
    and the library does not have is a defect in this file, and the failure mode
    it used to produce — a filter that quietly matched nothing, so the findings
    simply were not there — is indistinguishable from a hive that had nothing to
    report.
    """

    installed = installed_plugin_names()
    missing = sorted(_CURATED_PLUGINS - installed)
    if missing:
        entry = _regipy_backend_version()
        stated = entry.version or f"version {entry.status.value}"
        raise RegistryPluginSetError(
            f"regipy {stated} exposes no plugin named {', '.join(missing)}; the curated "
            "registry selection names plugins this installed library does not have"
        )
    return _CURATED_PLUGINS


#: Where the system records each account's profile directory.  The artifact
#: corpus this project ships names it ``WindowsRegistryProfiles``, and it is the
#: version-independent answer: ``Documents and Settings`` on XP and 2003,
#: ``Users`` from Vista onward, and whatever an administrator relocated it to.
#: Reading it means the layout is never assumed from an OS version.
_PROFILE_LIST_KEY = r"\Microsoft\Windows NT\CurrentVersion\ProfileList"
_PROFILE_PATH_VALUE = "ProfileImagePath"

#: Where a profile keeps its UsrClass.dat, relative to the profile directory the
#: ProfileList declared: the Vista-and-later location first, then the XP and
#: 2003 one.  NTUSER.DAT needs no such table — every version keeps it at the
#: profile root — but this hive moved between versions, and the profile list
#: does not record which layout a given image has, so the image itself is asked.
_USRCLASS_IN_PROFILE = (
    "AppData/Local/Microsoft/Windows/UsrClass.dat",
    "Local Settings/Application Data/Microsoft/Windows/UsrClass.dat",
)


def _in_image_profile_path(value: object) -> str | None:
    """Turn one declared profile directory into a path inside this image.

    The stored values name a volume the image does not have: a drive letter, a
    ``%SystemDrive%`` variable, or an NT object prefix.  Each describes the
    volume this image IS, so the leading segment is dropped and the remainder is
    the in-image path.
    """

    if not isinstance(value, str):
        return None
    text = value.strip().replace("\\", "/")
    if not text:
        return None
    for prefix in ("//?/", "/??/"):
        if text.startswith(prefix):
            text = text[len(prefix) :]
    if text.startswith("%") and "%" in text[1:]:
        text = text[text.index("%", 1) + 1 :]
    elif len(text) > 1 and text[1] == ":":
        text = text[2:]
    text = "/" + text.strip("/")
    # A bare file name names no directory an account could live in.
    return text if text.count("/") > 1 else None


def _select_profile_directory(user: str, declared: Iterable[object]) -> str | None:
    """Pick the declared profile directory belonging to one account name.

    The caller's text is never interpolated into a path.  It only selects among
    directories the evidence itself reported, so traversal text, a file name or
    any other input matches nothing instead of steering a read.  Containment
    stops being something this module has to enforce, because there is no longer
    a place for caller text to act as a path operator.
    """

    wanted = user.strip().casefold()
    if not wanted:
        return None
    for value in declared:
        path = _in_image_profile_path(value)
        if path is None:
            continue
        if path.rsplit("/", 1)[-1].casefold() == wanted:
            return path
    return None


def _declared_profile_paths(disk, scratch) -> list[object]:
    """Every profile directory the SOFTWARE hive reports, as it reports them."""

    result = registry_query(
        disk,
        hive="SOFTWARE",
        key=_PROFILE_LIST_KEY,
        depth=1,
        limit=500,
        scratch=scratch,
    )
    if not isinstance(result, Mapping):
        return []
    declared: list[object] = []
    for row in result.get("rows") or result.get("values") or []:
        if not isinstance(row, Mapping):
            continue
        if str(row.get("name") or "") == _PROFILE_PATH_VALUE:
            declared.append(row.get("value"))
    return declared


def _user_hive_path(hive: str, *, disk, scratch) -> tuple[str | None, str]:
    """Locate one account's NTUSER.DAT or UsrClass.dat through the profile list.

    No Windows layout is assumed.  The account name selects among directories the
    evidence declared, so the same call works on XP, on Vista and later, and on a
    system whose profiles were relocated.
    """

    user = hive.split(":", 1)[1].strip() if ":" in hive else ""
    if not user:
        return None, (
            "A per-user hive requires an account name, as in NTUSER:Administrator "
            "or USRCLASS:Administrator."
        )
    declared = _declared_profile_paths(disk, scratch)
    if not declared:
        return None, (
            "the profile list in the SOFTWARE hive could not be read, so no user "
            "hive location is established by this evidence"
        )
    directory = _select_profile_directory(user, declared)
    if directory is None:
        known = sorted(
            {
                str(path).rsplit("/", 1)[-1]
                for path in (_in_image_profile_path(value) for value in declared)
                if path
            }
        )
        return None, (
            f"no profile for account '{user}' is recorded in this evidence; the "
            f"profile list declares: {', '.join(known) if known else 'none'}"
        )
    if hive.upper().startswith("USRCLASS"):
        # UsrClass.dat holds the per-user HKCU\Software\Classes branch, incl. the
        # Explorer ShellBags (BagMRU) that record the folders a user browsed.
        # Unlike NTUSER.DAT it does not sit at the profile root, and the profile
        # list does not say where inside the profile it went, so each standard
        # location is asked for on the image rather than chosen by an assumed
        # Windows version.  A disk without a metadata probe (development
        # doubles) keeps the modern location, as before.
        candidates = [f"{directory}/{relative}" for relative in _USRCLASS_IN_PROFILE]
        probe = getattr(disk, "file_metadata", None)
        if not callable(probe):
            return candidates[0], ""
        for candidate in candidates:
            try:
                probe(candidate)
            except Exception:
                continue
            return candidate, ""
        return None, (
            f"no readable UsrClass.dat for account '{user}' at either of its "
            f"standard locations under {directory}"
        )
    return f"{directory}/NTUSER.DAT", ""


def _is_user_hive(hive: str) -> bool:
    """Whether this selector names a per-user hive, stated once for both askers.

    :func:`_resolve` declines these so the caller routes them through the
    ProfileList lookup, and the caller must recognise the same set to do the
    routing.  Two hand-kept copies of this test is how ``USRCLASS:`` came to be
    declined in one place and not routed in the other, so the set lives here.
    """

    h = hive.strip().upper()
    return h.startswith("NTUSER") or h.startswith("USRCLASS")


def _resolve(hive: str) -> str | None:
    """Resolve a system hive.  User hives are located from the evidence instead.

    A user hive has no fixed location: only the system knows where it put each
    profile.  Returning ``None`` here routes ``NTUSER:`` through the ProfileList
    lookup rather than through a guess about the Windows version, which is what
    made this selector unusable on every XP-era image.
    """

    if _is_user_hive(hive):
        return None
    return HIVE_PATHS.get(hive.strip().upper())


def _run_plugins(h) -> tuple[dict, list]:
    """Run regipy's validated plugins with PER-PLUGIN isolation: one plugin raising
    (anything, not only ModuleNotFoundError) must not abort the rest. Returns
    (results, failed_names). Falls back to the stock runner if regipy internals move."""
    try:
        from regipy.plugins.utils import PLUGINS, is_plugin_validated
    except Exception:
        try:
            return (run_relevant_plugins(h, as_json=True) or {}), []
        except Exception as e:
            return {}, [f"run_relevant_plugins:{type(e).__name__}"]
    results: dict = {}
    failed: list = []
    for plugin_class in PLUGINS:
        try:
            plugin = plugin_class(h, as_json=True)
            if not is_plugin_validated(plugin.NAME):
                continue
            if plugin.can_run():
                plugin.run()
                results[plugin.NAME] = plugin.entries
        except Exception:
            failed.append(getattr(plugin_class, "NAME", getattr(plugin_class, "__name__", "?")))
    return results, failed


#: One sweep runs every plugin the installed regipy validates over the whole
#: hive, which is minutes of work whose product is then paginated: without this
#: every PAGE of the same query repeated the sweep.  Deep enough to hold the
#: hives one investigation reads, and each entry is one bounded sweep product.
_PLUGIN_SWEEP_CACHE_ENTRIES = 8
_PLUGIN_SWEEP_CACHE_MAX_ROWS = 200_000

#: The whole product of one sweep: its rows, the plugins that reported, and the
#: plugins that raised.  Retaining only the rows would leave a later page
#: reporting an empty plugin inventory beside rows those plugins produced.
_PluginSweep = tuple[list, list[str], list[str]]
_plugin_sweep_cache: dict[tuple[object, ...], _PluginSweep] = {}
_plugin_sweep_cache_lock = threading.Lock()


def _plugin_sweep_cache_key(
    disk, path: str, scratch: ControlledScratchSession, curated: frozenset[str]
) -> tuple[object, ...] | None:
    """Key one whole sweep, or ``None`` when nothing durable identifies it.

    The evidence components are the ones the staged copy is already keyed by —
    the retained workspace, the image's own digest and the in-image path — plus
    the parser and the curated selection, which decide what the sweep produces.
    A disk that declares no digest (development doubles) has no durable evidence
    identity, so its sweep is not retained rather than shared under a guessed key.
    """

    identity = getattr(disk, "image_sha", None)
    if not isinstance(identity, str) or not identity:
        return None
    workspace = scratch.retained_workspace(ScratchWorkspaceKind.REGISTRY_HIVE_CACHE).path
    entry = _regipy_backend_version()
    return (
        os.path.normcase(str(workspace)),
        identity,
        path,
        entry.backend,
        entry.version,
        entry.status.value,
        tuple(sorted(curated)),
    )


def _cached_plugin_sweep(key: tuple[object, ...]) -> _PluginSweep | None:
    """Serve one previously produced sweep, refreshing its LRU position."""

    with _plugin_sweep_cache_lock:
        sweep = _plugin_sweep_cache.pop(key, None)
        if sweep is None:
            return None
        _plugin_sweep_cache[key] = sweep
        return sweep


def _store_plugin_sweep(key: tuple[object, ...], sweep: _PluginSweep) -> None:
    """Retain one bounded sweep for the remaining pages of the same result."""

    if len(sweep[0]) > _PLUGIN_SWEEP_CACHE_MAX_ROWS:
        return
    with _plugin_sweep_cache_lock:
        _plugin_sweep_cache.pop(key, None)
        _plugin_sweep_cache[key] = sweep
        while len(_plugin_sweep_cache) > _PLUGIN_SWEEP_CACHE_ENTRIES:
            _plugin_sweep_cache.pop(next(iter(_plugin_sweep_cache)))


def _entries_to_rows(name: str, entries) -> list:
    if isinstance(entries, list):
        return [
            {"plugin": name, **item} if isinstance(item, dict) else {"plugin": name, "value": item}
            for item in entries
        ]
    if isinstance(entries, dict):
        return [{"plugin": name, **entries}]
    if entries not in (None, "", [], {}):
        return [{"plugin": name, "value": entries}]
    return []


def _rows(res: dict) -> list:
    """Flatten regipy's {plugin: entries} into uniform rows, ROUND-ROBIN across plugins
    (one row per plugin per cycle) so a single verbose plugin (e.g. shimcache/services
    with hundreds of rows) cannot crowd a compact high-value plugin (computer_name's
    single row) off the first page once the shared envelope applies its byte budget."""
    buckets = [rows for rows in (_entries_to_rows(n, e) for n, e in res.items()) if rows]
    out, i = [], 0
    while any(i < len(b) for b in buckets):
        for b in buckets:
            if i < len(b):
                out.append(b[i])
        i += 1
    return out


_BINARY_TYPES = {"REG_BINARY", "REG_NONE"}
_SINGLE_STRING_TYPES = {"REG_SZ", "REG_EXPAND_SZ", "REG_LINK"}
#: Value types whose stored form IS a number, so an integer from the parser is
#: the value rather than the substitution :func:`_regipy_lost_the_value` detects.
#: Both spellings of the big-endian word appear across registry tooling.
_INTEGER_VALUE_TYPES = frozenset(
    {"REG_DWORD", "REG_DWORD_BE", "REG_DWORD_BIG_ENDIAN", "REG_QWORD"}
)
#: The name regipy gives a value that has none.
_DEFAULT_VALUE_NAME = "(default)"
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
#: Bound on the hex rendering of one binary value.  A value cut by it says so on
#: its row: a silently shortened value reads exactly like a complete short one.
_MAX_BINARY_HEX_CHARS = 400
_VALUE_INTERPRETATION_SCHEMA_ID = "forensic.registry-value-interpretation.v1"
#: Unix-epoch seconds between 2000-01-01 and 2036-01-01.
_EPOCH_WINDOW = (946684800, 2082758400)

#: Operations ``registry_query`` services, each with its own epistemic class in
#: the authoritative classifier.  ``registry_values`` returns what regipy
#: reported; ``value_readings`` returns the readings this module computed and is
#: asked for by name.
REGISTRY_QUERY_OPERATIONS: tuple[str, ...] = ("registry_values", "value_readings")
#: Applied when the caller omits ``operation``, and mirrored by the classifier so
#: an omitted argument classifies as the operation that actually runs.
_DEFAULT_REGISTRY_OPERATION = "registry_values"
_VALUE_READINGS_OPERATION = "value_readings"
_VALUE_READINGS_METHOD = "registry.value_readings"
_VALUE_READINGS_METHOD_VERSION = "1"
#: Where a value's readings ride between ``_key_values`` and the row projection.
#: The leading underscore keeps it out of both operations' rows: the observed
#: projection drops it, and the derived projection republishes it under the name
#: a reader knows it by.
_ROW_READINGS_FIELD = "_readings"
#: Fields of an observed value row that the derived result must not restate: a
#: derivation reports what it read, never a second copy of the observation.
_OBSERVED_ONLY_ROW_FIELDS = frozenset({"value", "value_bytes", "value_truncated"})


def _filetime_utc(v: bytes):
    """If `v` is exactly 8 bytes and a plausible little-endian Windows FILETIME (a
    modern date), return its UTC string; else None.

    The year window is what makes this a GUESS: the registry does not state that
    these eight bytes are a timestamp, so the answer is offered as a derived
    reading beside the value and never as the value itself."""
    if len(v) != 8:
        return None
    ticks = int.from_bytes(v, "little")
    if not ticks:
        return None
    try:
        dt = datetime(1601, 1, 1, tzinfo=UTC) + timedelta(microseconds=ticks / 10)
    except (OverflowError, OSError, ValueError):
        return None
    if 1990 <= dt.year <= 2035:  # plausible modern timestamp, not random bytes
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    return None


def _utf16le_text(v: bytes) -> str | None:
    """The printable UTF-16LE text inside `v`, or None when there is too little.

    A struct header in front of the characters (an LSA UNICODE_STRING such as
    SECURITY ``Policy\\PolPrDmN``) decodes to unprintable noise, which is why the
    non-printable characters are dropped rather than the decode refused.  The
    three-character floor is a sniff, not a fact about the value."""
    try:
        decoded = v.decode("utf-16-le", "replace")
    except Exception:
        return None
    text = " ".join("".join(ch if ch.isprintable() else " " for ch in decoded).split())[:200]
    return text if len(text) >= 3 else None


def _observed_registry_value(raw, value_type) -> tuple[object, bytes | None]:
    """Render one regipy value for JSON, and hand back the bytes behind it.

    The first element is what regipy reported, unchanged except where JSON cannot
    carry it: bytes become hex, which re-encodes the value rather than reading
    it.  The one exception is a byte buffer whose own declared type says it is a
    string — some readers expose ``REG_SZ`` data as the whole backing buffer, and
    decoding it per the type the hive itself states is a format normalization
    (without it, stale storage after the first UTF-16 NUL contaminates host
    names, time-zone keys and paths).  Nothing else about the content is decided
    here.

    The second element is the bytes a derived reading may work on, or None when
    there are none to read.  It is TYPE-GATED for the string form regipy uses for
    raw-key binary values: a ``REG_SZ`` whose text happens to be all hex digits
    is text, and reading a date out of it would fabricate a finding.
    """

    normalized_type = str(value_type or "").upper()
    if isinstance(raw, bytes):
        if normalized_type in _SINGLE_STRING_TYPES and not len(raw) % 2:
            try:
                return raw.decode("utf-16-le", "strict").split("\x00", 1)[0], None
            except UnicodeDecodeError:
                pass
        elif normalized_type == "REG_MULTI_SZ" and not len(raw) % 2:
            try:
                decoded = raw.decode("utf-16-le", "strict")
            except UnicodeDecodeError:
                pass
            else:
                return [part for part in decoded.split("\x00") if part], None
        return raw.hex()[:_MAX_BINARY_HEX_CHARS], raw
    if isinstance(raw, str) and normalized_type in _BINARY_TYPES:
        # regipy hands a raw-key REG_BINARY/REG_NONE value back as a hex STRING,
        # so the same readings have to reach it through this form too.
        text = raw.strip()
        if text and not len(text) % 2 and all(c in _HEX_DIGITS for c in text):
            try:
                return raw, bytes.fromhex(text)
            except ValueError:
                return raw, None
    return raw, None


def _interpretation(rule_id: str, rendering: str, value, *, basis: str) -> dict:
    return {
        "schema_id": _VALUE_INTERPRETATION_SCHEMA_ID,
        "evidence_class": "derived",
        "rule_id": rule_id,
        "rendering": rendering,
        "value": value,
        "basis": basis,
    }


def _derived_value_interpretations(raw, blob: bytes | None) -> list[dict]:
    """Readings of one value that THIS module computed, never ones regipy made.

    They are reachable only through the separate ``value_readings`` operation, so
    the reported value stays exactly what regipy reported and no observed result
    ever carries an inference beside it.  Each entry names the rule that produced
    it and the condition that rule accepted, because all three readings are
    guesses about a meaning the registry does not state anywhere.
    """

    if isinstance(raw, bool):
        return []
    if isinstance(raw, int):
        low, high = _EPOCH_WINDOW
        if not low <= raw <= high:
            return []
        try:
            decoded = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(seconds=raw)
        except (OverflowError, OSError, ValueError):
            return []
        return [
            _interpretation(
                "registry.value.unix_epoch_seconds.v1",
                "epoch_utc",
                decoded.strftime("%Y-%m-%d %H:%M:%S UTC"),
                basis=(
                    "integer inside the 2000-2036 Unix-epoch window read as seconds "
                    "since 1970-01-01; the registry does not state that it is a time"
                ),
            )
        ]
    if blob is None:
        return []
    entries: list[dict] = []
    text = _utf16le_text(blob)
    if text:
        entries.append(
            _interpretation(
                "registry.value.utf16le_text.v1",
                "utf16le_text",
                text,
                basis=(
                    "bytes decoded as UTF-16LE with unprintable characters dropped; "
                    "kept because at least three printable characters survived"
                ),
            )
        )
    filetime = _filetime_utc(blob)
    if filetime:
        entries.append(
            _interpretation(
                "registry.value.windows_filetime.v1",
                "filetime_utc",
                filetime,
                basis=(
                    "eight little-endian bytes read as a Windows FILETIME; kept "
                    "because the resulting year falls between 1990 and 2035"
                ),
            )
        )
    return entries


def _regipy_lost_the_value(raw: object, value_type: str | None) -> bool:
    """Whether the parser replaced this value's content with the integer of its bytes.

    A hive holds a value of four bytes or fewer inside the ``vk`` record itself
    and sets bit 31 of ``data_size`` to say so.  regipy 6.2.1 returns
    ``vk.data_offset`` — the little-endian integer of those four bytes — for
    ``REG_SZ``, ``REG_EXPAND_SZ``, ``REG_BINARY`` and ``REG_NONE`` stored that
    way, and discards ``data_size`` with it.  An integer under a type that is not
    stored as a number is therefore the symptom, and it is the only signal left:
    the length the integer would have to be sliced back to no longer exists here.
    """

    return (
        isinstance(raw, int)
        and not isinstance(raw, bool)
        and value_type is not None
        and value_type.upper() not in _INTEGER_VALUE_TYPES
    )


#: libregf's numeric value types.  They select which of the library's own typed
#: accessors answers for a value; the decoding stays libregf's.
_LIBREGF_STRING_TYPES = frozenset({1, 2, 6})
_LIBREGF_MULTI_STRING_TYPE = 7

#: The declared length below which libregf's reading of an inline value is not
#: its content.
#:
#: The second reader has a defect of its own in the same class as the first
#: reader's.  For a value the hive stores inside the ``vk`` record, libregf
#: returns the LAST ``data_size`` bytes of the four-byte field rather than the
#: first, so every inline value shorter than four bytes comes back zero-padded
#: at the wrong end: a one-byte ``\x02`` reads as ``\x00``, a two-byte
#: ``20 04`` as ``00 00``.  Four-byte inline values are read correctly.
#:
#: Nothing available here can tell an inline value that holds real content from
#: one that happens to hold zeros anyway, because doing so would mean reading the
#: ``vk`` record's own encoding — a registry value decoder written in this
#: project, which is exactly
#: what routing the class to a second vetted parser existed to avoid.  The
#: alternatives were weighed and none survives: falling back to regipy publishes
#: the integer this substitution was introduced to stop, and no third reader is
#: reachable — dfwinreg is a wrapper over the same libregf and reproduces the
#: defect byte for byte, and no other REGF parser is installed.  So the class is
#: withheld with a reason.  A value withheld is a value an examiner can go and
#: read; a one-byte binary published as ``\x00`` is right in type and length,
#: wrong in content, and looks correct.
_LIBREGF_TRUSTWORTHY_INLINE_SIZE = 4
_LIBREGF_SHORT_INLINE_DEFECT = (
    "{reader} returns zeros for a registry value the hive stores inside its vk "
    "record in fewer than {bound} bytes, and regipy returns the integer of those "
    "bytes rather than the bytes; no parser installed here reports this value's "
    "content, so none is published (docs/TOOL_VALIDATION.md)"
)
#: Bound on libregf's retained stderr in one result, and on how many separate
#: complaints are kept: a reader that fails per value would otherwise fill a
#: result with the same sentence.
_MAX_SECOND_READER_STDERR_CHARS = 400
_MAX_SECOND_READER_COMPLAINTS = 5


@dataclass(frozen=True, slots=True)
class _SecondReading:
    """What the second parser could say about one value the first one lost."""

    backend: str
    value: object = None
    unread_reason: str | None = None

    @property
    def read(self) -> bool:
        return self.unread_reason is None


class _SecondValueReader:
    """libregf over the same staged hive, for the values regipy returns as integers.

    This is a second reader of the same bytes, not a parser written here.  The
    content and its declared length both come from libregf's own typed
    accessors, so a value it supplies remains an upstream observation of a
    validated tool; the alternative — slicing the integer back into bytes and
    decoding them — could not recover the length regipy dropped and would make
    every such value this project's own composition.

    It never raises.  A host without libregf, a hive it declines to open, a
    value it does not hold and a value of the one class libregf is known to read
    wrongly all resolve to a reading that states why it is absent, because the
    caller's remaining option is regipy's integer and that is known to be wrong
    too.
    """

    backend = _LIBREGF_BACKEND.backend

    def __init__(self, hive_path: Path) -> None:
        self._file: Any = None
        self._unavailable: str | None = None
        self._complaints: list[str] = []
        self._version: str | None = None
        try:
            import pyregf
        except ImportError as error:
            self._unavailable = f"{self.backend} is not installed on this host ({error})"
            return
        with self._attributed():
            try:
                handle = pyregf.file()
                handle.open(str(hive_path))
            except Exception as error:
                self._unavailable = (
                    f"{self.backend} could not open the staged hive: {str(error)[:160]}"
                )
            else:
                self._file = handle

    @contextmanager
    def _attributed(self) -> Iterator[None]:
        """Keep what libregf writes out of the capture that answers for regipy.

        The capture stack attributes a write to the innermost open capture, so
        without this the second reader's complaints would be published as the
        first reader's.
        """

        with capture_backend_stderr(self.backend) as stream:
            try:
                yield
            finally:
                report = stream.report()
                if report is not None and len(self._complaints) < _MAX_SECOND_READER_COMPLAINTS:
                    self._complaints.append(report["stderr"][:_MAX_SECOND_READER_STDERR_CHARS])

    def value(self, key_path: str | None, name: object) -> _SecondReading:
        """The named value of one key, as libregf reads it."""

        if self._unavailable is not None:
            return _SecondReading(backend=self.backend, unread_reason=self._unavailable)
        if not key_path or not isinstance(name, str):
            return _SecondReading(
                backend=self.backend,
                unread_reason="the value was read outside a resolved key path",
            )
        with self._attributed():
            try:
                key = self._file.get_key_by_path(key_path)
                value = None if key is None else key.get_value_by_name(name)
                if value is None and key is not None and name == _DEFAULT_VALUE_NAME:
                    # libregf leaves an unnamed value's name empty where regipy
                    # spells it "(default)".
                    value = key.get_value_by_name("")
                if value is None:
                    return _SecondReading(
                        backend=self.backend,
                        unread_reason=f"{self.backend} does not report this value under {key_path}",
                    )
                defect = self._known_defect(value)
                if defect is not None:
                    return _SecondReading(backend=self.backend, unread_reason=defect)
                return _SecondReading(backend=self.backend, value=self._reading(value))
            except Exception as error:
                return _SecondReading(
                    backend=self.backend,
                    unread_reason=f"{self.backend} could not read this value: {str(error)[:120]}",
                )

    def _known_defect(self, value: Any) -> str | None:
        """Why this value's second reading must not be published, or ``None``.

        The declared length comes from libregf's own accessor.  Only values the
        first parser already lost reach here, and the first parser loses exactly
        the values the hive stores inside the ``vk`` record, so a declared length
        between one and three bytes here is an inline value of the class
        :data:`_LIBREGF_TRUSTWORTHY_INLINE_SIZE` documents.  Zero bytes is empty
        under either reading and is published.
        """

        size = value.get_data_size()
        if not isinstance(size, int) or not 0 < size < _LIBREGF_TRUSTWORTHY_INLINE_SIZE:
            return None
        return _LIBREGF_SHORT_INLINE_DEFECT.format(
            reader=self._named_reader(), bound=_LIBREGF_TRUSTWORTHY_INLINE_SIZE
        )

    def _named_reader(self) -> str:
        """The second reader with the version this host established, resolved once.

        A host that could not establish one is named without it rather than with
        a placeholder: the reason is about libregf either way, and a version this
        host did not determine must not appear in a result as though it had.
        """

        if self._version is None:
            version = _backend_version(self.backend).version
            self._version = f"{self.backend} {version}" if version else self.backend
        return self._version

    @staticmethod
    def _reading(value: Any) -> object:
        """One libregf value in the shape the row projection already renders.

        Zero bytes under a string type is the empty string and zero bytes under
        any other type is an empty buffer; libregf reports both as no data,
        which is what regipy's ``0`` was standing in for.
        """

        value_type = int(value.get_type())
        if value_type in _LIBREGF_STRING_TYPES:
            return value.get_data_as_string() or ""
        if value_type == _LIBREGF_MULTI_STRING_TYPE:
            return list(value.get_data_as_multi_string() or [])
        return bytes(value.get_data() or b"")

    def complaints(self) -> tuple[str, ...]:
        return tuple(self._complaints)

    def close(self) -> None:
        handle, self._file = self._file, None
        if handle is None:
            return
        with self._attributed():
            try:
                handle.close()
            except Exception:  # noqa: BLE001 - a closed handle must not fail a read
                pass


def _child_key_path(parent: str | None, name: str) -> str | None:
    """The path of one subkey, spelled as the parsers spell an absolute path."""

    if parent is None:
        return None
    return f"{parent.rstrip(chr(92))}\\{name}"


def _value_row(v, *, key_path: str | None = None, reader: _SecondValueReader | None = None) -> dict:
    """One registry value as a row, with its readings held for the projection.

    Both operations read the same value once, so they can never disagree about
    what was there.  Which of the two halves reaches the caller is decided by
    :func:`_projected_rows`, and only one of them ever does.

    A value the first parser lost is taken from the second and the row names
    which one supplied it.  Where no second reading is available the row carries
    no value at all: the integer that remains is not a shortened or approximate
    reading of the value, it is a different number, and reporting it would let a
    consumer read an empty string as a zero.
    """

    value_type = str(getattr(v, "value_type", "") or "") or None
    name = getattr(v, "name", None)
    raw = getattr(v, "value", None)
    second: _SecondReading | None = None
    if _regipy_lost_the_value(raw, value_type):
        second = (
            reader.value(key_path, name)
            if reader is not None
            else _SecondReading(
                backend=_LIBREGF_BACKEND.backend,
                unread_reason="no second registry parser was opened for this read",
            )
        )
        if not second.read:
            return {
                "name": name,
                "value_type": value_type,
                "value": None,
                "value_unreadable": second.unread_reason,
            }
        raw = second.value
    observed, blob = _observed_registry_value(raw, value_type)
    row = {"name": name, "value_type": value_type, "value": observed}
    if second is not None:
        row["value_reader"] = second.backend
    # Only the hex rendering is bounded (``blob`` is the buffer behind it); a
    # value the declared type turned into text is returned whole.
    if blob is raw and isinstance(raw, bytes) and len(raw) * 2 > _MAX_BINARY_HEX_CHARS:
        row["value_bytes"] = len(raw)
        row["value_truncated"] = True
    derived = _derived_value_interpretations(raw, blob)
    if derived:
        row[_ROW_READINGS_FIELD] = derived
    return row


def _projected_rows(rows: list, operation: str) -> list:
    """Return the rows of ONE operation: regipy's values, or our readings.

    Projecting before the shared envelope is what keeps the two apart: pagination,
    the substring filter and the byte budget all run over the rows of the
    operation that was actually asked for, so an observed page can never spend
    its budget on, or leak, a reading.
    """

    if operation != _VALUE_READINGS_OPERATION:
        return [
            {key: value for key, value in row.items() if key != _ROW_READINGS_FIELD}
            for row in rows
        ]
    projected: list = []
    for row in rows:
        readings = row.get(_ROW_READINGS_FIELD)
        if not readings:
            continue
        identity = {
            key: value
            for key, value in row.items()
            if key != _ROW_READINGS_FIELD and key not in _OBSERVED_ONLY_ROW_FIELDS
        }
        projected.append({**identity, "derived_interpretations": readings})
    return projected


def _key_values(
    k,
    *,
    key_path: str | None = None,
    reader: _SecondValueReader | None = None,
) -> list:
    rows = []
    try:
        for v in k.iter_values() or []:
            rows.append(_value_row(v, key_path=key_path, reader=reader))
    except Exception as e:
        rows.append({"note": f"partial value read: {str(e)[:100]}"})
    return rows


#: Bound on how many affected value NAMES one warning carries.  The names are
#: what scopes the warning, but a key with hundreds of affected values must not
#: spend the projection byte budget on a roster; past this bound the list is
#: cut and says so in ``value_names_truncated``.
_MAX_WARNING_VALUE_NAMES = 20


def _named_scope(affected: list) -> tuple[list[str], dict[str, object]]:
    """The affected rows' value names, bounded, as message text and details.

    Returns the names to interpolate into the warning message and the details
    entries that carry them.  Sorted so the same rows always produce the same
    warning bytes, and bounded for the reason ``_MAX_WARNING_VALUE_NAMES``
    states.
    """

    names = sorted(str(row.get("name")) for row in affected)
    shown = names[:_MAX_WARNING_VALUE_NAMES]
    details: dict[str, object] = {"value_names": shown}
    if len(names) > len(shown):
        details["value_names_truncated"] = True
    return shown, details


def _second_reader_warnings(rows: list, reader: _SecondValueReader | None) -> list[dict]:
    """Declare, once per result, every value the first parser did not supply.

    The rows say which reader answered for them; this says why a reader other
    than the one that opened the hive answered at all, so the substitution is a
    stated property of the result rather than something a reader has to notice
    from a field that is usually absent.

    A withheld value is declared here as one count with its reasons rather than
    as one warning per cause, because the two causes — no second parser was
    reachable, and the second parser's reading of this value's class is known to
    be wrong — differ in why nothing can be published and not in what the result
    may be read as saying.  Each row carries the sentence for its own cause.

    Both warnings NAME the affected values and state the read/withheld split.
    A count without names leaves the scope to be inferred — a consumer can read
    an unscoped "3 value(s) unreadable" as denying a readable value elsewhere —
    while the names and the split leave nothing to infer.  Neither cause
    ever touches the whole result: ``coverage_complete``/``status`` are set
    only by the subkey cap in ``_read_open_key``, and the named-and-counted
    warning here is deliberately the narrower indicator instead.
    """

    substituted = [row for row in rows if row.get("value_reader")]
    unreadable = [row for row in rows if row.get("value_unreadable")]
    warnings: list[dict] = []
    if substituted:
        reader_name = str(substituted[0]["value_reader"])
        shown, named = _named_scope(substituted)
        details: dict[str, object] = {
            "substituted_values": len(substituted),
            **named,
            "value_reader": reader_name,
            "value_reader_version": _backend_identity(_LIBREGF_BACKEND.backend).get("version"),
            "first_reader": _REGIPY_BACKEND.backend,
        }
        complaints = reader.complaints() if reader is not None else ()
        if complaints:
            details["value_reader_stderr"] = list(complaints)
        warnings.append(
            {
                "code": "registry_value_reader_substituted",
                "message": (
                    f"{len(substituted)} of {len(rows)} value(s) of this key "
                    f"({', '.join(shown)}) are stored inside their vk record, where "
                    f"{_REGIPY_BACKEND.backend} returns the integer of those bytes "
                    f"instead of their content; those rows carry {reader_name}'s "
                    "reading of the same bytes and name it in value_reader"
                ),
                "details": details,
            }
        )
    if unreadable:
        shown, named = _named_scope(unreadable)
        readable = len(rows) - len(unreadable)
        warnings.append(
            {
                "code": "registry_value_unreadable",
                "message": (
                    f"{len(unreadable)} of {len(rows)} value(s) of this key "
                    f"({', '.join(shown)}) are stored inside their vk record, where "
                    f"{_REGIPY_BACKEND.backend} returns the integer of those bytes "
                    "instead of their content, and no parser reachable here reports "
                    "the content either; no value is reported for them, and each row "
                    "says in value_unreadable which reader failed and how; the "
                    f"remaining {readable} value(s) were read and are reported "
                    "normally"
                ),
                "details": {
                    "unreadable_values": len(unreadable),
                    **named,
                    "readable_values": readable,
                    "total_values": len(rows),
                    "reasons": sorted({str(row["value_unreadable"]) for row in unreadable}),
                },
            }
        )
    return warnings


def _read_open_key(
    key,
    key_path: str,
    *,
    offset: int,
    limit: int,
    filter: str | None,
    depth: int,
    operation: str = _DEFAULT_REGISTRY_OPERATION,
    reader: _SecondValueReader | None = None,
) -> dict:
    """Shape one already-resolved registry key without another lookup."""

    rows = _key_values(key, key_path=key_path, reader=reader)
    subs = []
    try:
        for subkey in key.iter_subkeys() or []:
            name = getattr(subkey, "name", None)
            if not name:
                continue
            subs.append(name)
            if depth >= 1 and len(subs) <= 200:  # one level deep, bounded
                for row in _key_values(
                    subkey, key_path=_child_key_path(key_path, name), reader=reader
                ):
                    rows.append({"subkey": name, **row})
    except Exception:
        pass
    reader_warnings = _second_reader_warnings(rows, reader)
    subkeys_truncated = len(subs) > 100
    key_last_write_utc = None
    try:
        raw_last_write = getattr(getattr(key, "header", None), "last_modified", None)
        if isinstance(raw_last_write, int) and not isinstance(raw_last_write, bool):
            key_last_write_utc = convert_wintime(raw_last_write, as_json=True)
    except (OverflowError, TypeError, ValueError):
        key_last_write_utc = None
    result = {
        "key": key_path,
        "key_last_write_utc": key_last_write_utc,
        "subkeys": subs[:100],
        "subkeys_total": len(subs),
        "subkeys_truncated": subkeys_truncated,
        **shape(_projected_rows(rows, operation), offset=offset, limit=limit, filter=filter),
    }
    if reader_warnings:
        result["warnings"] = [*result.get("warnings", []), *reader_warnings]
    if subkeys_truncated:
        result["coverage_complete"] = False
        result["status"] = "partial"
        result["warnings"] = [
            *result.get("warnings", []),
            {
                "code": "registry_subkey_cap_reached",
                "message": "registry subkey enumeration exceeded the 100-key safety cap",
            },
        ]
    return result


_SYSTEM_CONTROL_SET_BRANCHES = frozenset(
    {
        "control",
        "enum",
        "hardware profiles",
        "services",
    }
)
_SYSTEM_SELECT_CURRENT_BASIS = r"SYSTEM\Select\Current"
_HKLM_ALIASES = frozenset({"hkey_local_machine", "hklm"})


def _normalize_key_within_hive(hive: str, key: str) -> tuple[str, str | None]:
    r"""Remove only an explicit, redundant HKLM/current-hive prefix.

    ``registry_query`` already receives the hive as a separate argument.  Models
    and reference catalogues nevertheless commonly supply a canonical full path
    such as ``HKLM\SOFTWARE\Microsoft\...``.  Accept that unambiguous spelling,
    while refusing to reinterpret a path rooted in a different hive.
    """

    normalized = str(key or "").strip().replace("/", "\\")
    parts = [part for part in normalized.strip("\\").split("\\") if part]
    hive_name = hive.strip().split(":", 1)[0].casefold()
    if not parts or hive_name not in {"system", "software", "sam", "security", "default"}:
        return normalized, None

    original_parts = list(parts)
    if parts[0].casefold() in _HKLM_ALIASES:
        if len(parts) < 2 or parts[1].casefold() != hive_name:
            return normalized, None
        parts = parts[2:]
    elif parts[0].casefold() == hive_name:
        parts = parts[1:]
    else:
        return normalized, None

    if parts == original_parts:
        return normalized, None
    return "\\".join(parts), "redundant_hklm_hive_prefix_removed"


def _system_select_current_number(h) -> tuple[int | None, str | None]:
    """Return a strict SYSTEM Select\\Current number or a fail-closed reason."""

    try:
        select = h.get_key("\\Select")
        matches = [
            value
            for value in (select.iter_values() or [])
            if str(getattr(value, "name", "")).casefold() == "current"
        ]
    except Exception:
        return None, "SYSTEM Select key is unavailable"
    if len(matches) != 1:
        return None, "SYSTEM Select must contain exactly one Current value"
    value = matches[0]
    current = getattr(value, "value", None)
    value_type = str(getattr(value, "value_type", "") or "").upper()
    if type(current) is not int:
        return None, "SYSTEM Select Current is not an integer"
    if value_type and "DWORD" not in value_type:
        return None, "SYSTEM Select Current is not a REG_DWORD"
    if not 1 <= current <= 999:
        return None, "SYSTEM Select Current is outside the supported control-set range"
    return current, None


def _system_control_set_request(key_path: str) -> tuple[str, list[str]] | None:
    """Classify an explicit CurrentControlSet alias or a root control-set shorthand."""

    parts = [part for part in key_path.strip("\\").split("\\") if part]
    if not parts:
        return None
    first = parts[0].casefold()
    if first == "currentcontrolset":
        return "system_select_current_alias", parts[1:]
    if first in _SYSTEM_CONTROL_SET_BRANCHES:
        return "system_select_current_root_shorthand", parts
    return None


def _control_set_resolution_warning(
    *,
    requested_key: str,
    resolved_key: str | None,
    current_control_set_number: int | None,
    resolution: str,
    error: str | None = None,
) -> dict:
    """Describe a successful or rejected SYSTEM control-set semantic resolution."""

    details = {
        "requested_key": requested_key,
        "resolved_key": resolved_key,
        "current_control_set_number": current_control_set_number,
        "resolution": resolution,
        "resolution_basis": _SYSTEM_SELECT_CURRENT_BASIS,
    }
    if error is not None:
        details["error"] = error
        return {
            "code": "registry_current_control_set_resolution_failed",
            "message": (
                f"Could not resolve {requested_key} to one active SYSTEM control set: "
                f"{error}. No inactive control-set candidate was returned."
            ),
            "details": details,
        }
    return {
        "code": "registry_current_control_set_resolved",
        "message": (
            f"Resolved {requested_key} to the active key {resolved_key} from "
            f"{_SYSTEM_SELECT_CURRENT_BASIS}={current_control_set_number}."
        ),
        "details": details,
    }


def _failed_control_set_resolution(
    *,
    requested_key: str,
    resolved_key: str | None,
    current_control_set_number: int | None,
    resolution: str,
    reason: str,
    offset: int,
    limit: int,
    filter: str | None,
) -> dict:
    """Return no evidence values when active-control-set resolution is uncertain."""

    return {
        "key": requested_key,
        "requested_key": requested_key,
        "resolved_key": resolved_key,
        "current_control_set_number": current_control_set_number,
        "resolution": resolution,
        "resolution_basis": _SYSTEM_SELECT_CURRENT_BASIS,
        "status": "partial",
        "coverage_complete": False,
        "coverage": {
            "complete": False,
            "scope": requested_key,
            "reason": reason,
        },
        "warnings": [
            _control_set_resolution_warning(
                requested_key=requested_key,
                resolved_key=resolved_key,
                current_control_set_number=current_control_set_number,
                resolution=resolution,
                error=reason,
            )
        ],
        **shape([], offset=offset, limit=limit, filter=filter),
    }


def _suffix_key_candidates(
    h,
    key_path: str,
    *,
    max_keys: int = 10_000,
    max_candidates: int = 20,
) -> tuple[list[tuple[str, object]], bool]:
    """Find bounded exact suffix matches for a shorthand/mis-rooted key path."""

    target = tuple(part.casefold() for part in key_path.strip("\\").split("\\") if part)
    if not target:
        return [], True
    try:
        root = h.get_key("\\")
    except Exception:
        return [], True
    queue = deque([(root, "")])
    candidates: list[tuple[str, object]] = []
    examined = 0
    while queue and examined < max_keys and len(candidates) < max_candidates:
        parent, parent_path = queue.popleft()
        try:
            children = parent.iter_subkeys() or []
            for child in children:
                name = str(getattr(child, "name", "") or "")
                if not name:
                    continue
                child_path = f"{parent_path}\\{name}" if parent_path else f"\\{name}"
                examined += 1
                parts = tuple(part.casefold() for part in child_path.strip("\\").split("\\"))
                if len(parts) >= len(target) and parts[-len(target) :] == target:
                    candidates.append((child_path, child))
                    if len(candidates) >= max_candidates:
                        break
                queue.append((child, child_path))
                if examined >= max_keys:
                    break
        except Exception:
            continue
    return candidates, not queue and len(candidates) < max_candidates


def _recovery_warning(requested: str, resolved: str, resolution: str) -> dict:
    return {
        "code": "registry_key_recovered",
        "message": (
            f"The exact requested registry key {requested} was absent; returned "
            f"bounded evidence from {resolved} via {resolution}."
        ),
        "details": {
            "requested_key": requested,
            "resolved_key": resolved,
            "resolution": resolution,
        },
    }


def _read_key(
    h,
    key_path,
    offset: int = 0,
    limit: int = 50,
    filter: str | None = None,
    depth: int = 0,
    *,
    resolve_current_control_set: bool = False,
    operation: str = _DEFAULT_REGISTRY_OPERATION,
    reader: _SecondValueReader | None = None,
) -> dict:
    """Raw key/value lookup by path via regipy's native get_key — reads one key's values +
    subkeys, for a value no extraction plugin covers (workgroup, arbitrary key). With depth=1
    also returns EACH subkey's values in one call (enumerate children — e.g. every Uninstall
    subkey's DisplayName/DisplayVersion, every NetworkCards/USBSTOR device), tagged by subkey.
    Read-only."""
    # regipy's get_key resolves absolute from the hive root and REQUIRES a leading
    # backslash; models naturally write paths without it — accept both forms.
    kp = "\\" + (key_path or "").strip().lstrip("\\")
    parts = [part for part in kp.strip("\\").split("\\") if part]

    # Offline SYSTEM hives do not persist the runtime CurrentControlSet alias.
    # Queries may also omit that alias and start at a control-set branch such as
    # Control or Services. Resolve either semantic form before generic suffix
    # recovery so inactive control sets can never become answer evidence.
    semantic_request = _system_control_set_request(kp) if resolve_current_control_set else None
    if semantic_request is not None:
        resolution, tail = semantic_request
        current_number, selection_error = _system_select_current_number(h)
        if selection_error is not None or current_number is None:
            return _failed_control_set_resolution(
                requested_key=kp,
                resolved_key=None,
                current_control_set_number=None,
                resolution=resolution,
                reason=selection_error or "SYSTEM Select Current is unavailable",
                offset=offset,
                limit=limit,
                filter=filter,
            )
        resolved_key = "\\" + "\\".join([f"ControlSet{current_number:03d}", *tail])
        try:
            resolved = h.get_key(resolved_key)
        except Exception:
            resolved = None
        if resolved is None:
            return _failed_control_set_resolution(
                requested_key=kp,
                resolved_key=resolved_key,
                current_control_set_number=current_number,
                resolution=resolution,
                reason="the selected active control-set key does not exist",
                offset=offset,
                limit=limit,
                filter=filter,
            )
        result = _read_open_key(
            resolved,
            resolved_key,
            offset=offset,
            limit=limit,
            filter=filter,
            depth=depth,
            operation=operation,
            reader=reader,
        )
        result.update(
            {
                "requested_key": kp,
                "resolved_key": resolved_key,
                "current_control_set_number": current_number,
                "resolution": resolution,
                "resolution_basis": _SYSTEM_SELECT_CURRENT_BASIS,
                "warnings": [
                    *result.get("warnings", []),
                    _control_set_resolution_warning(
                        requested_key=kp,
                        resolved_key=resolved_key,
                        current_control_set_number=current_number,
                        resolution=resolution,
                    ),
                ],
            }
        )
        if result.get("coverage_complete") is not False:
            result["coverage_complete"] = True
            result["coverage"] = {
                "complete": True,
                "scope": resolved_key,
            }
        return result

    exact_error: Exception | None = None
    try:
        k = h.get_key(kp)
    except Exception as error:
        exact_error = error
        k = None
    if k is not None:
        return _read_open_key(
            k,
            kp,
            offset=offset,
            limit=limit,
            filter=filter,
            depth=depth,
            operation=operation,
            reader=reader,
        )

    # A frequent API-shape error is supplying a value name as the final key
    # component.  If the parent exists and owns that value, satisfy the intended
    # read deterministically instead of reporting a missing child key.
    if len(parts) >= 2:
        parent_path = "\\" + "\\".join(parts[:-1])
        value_name = parts[-1]
        try:
            parent = h.get_key(parent_path)
        except Exception:
            parent = None
        if parent is not None:
            # Whether the requested name resolves to a value is decided by what
            # the parser reported, never by whether this module happened to read
            # something in it: a value with no readings still exists, and letting
            # the readings operation fall through to key recovery here would
            # answer a different question than the one that was asked.
            matched = [
                row
                for row in _key_values(parent, key_path=parent_path, reader=reader)
                if str(row.get("name") or "").casefold() == value_name.casefold()
            ]
            matching_rows = _projected_rows(matched, operation)
            if matched:
                return {
                    "key": parent_path,
                    "requested_key": kp,
                    "resolved_key": parent_path,
                    "resolved_value": value_name,
                    "resolution": "final_component_is_value_name",
                    "subkeys": [],
                    "warnings": [
                        _recovery_warning(kp, parent_path, "parent-key value-name lookup"),
                        *_second_reader_warnings(matched, reader),
                    ],
                    **shape(matching_rows, offset=offset, limit=limit, filter=filter),
                }

    # A short key such as "USBSTOR" can be unambiguous in intent but rooted at
    # the wrong level.  Return every exact suffix match, tagged by its full path;
    # never silently select one candidate when multiple ControlSets exist.
    candidates, search_complete = _suffix_key_candidates(h, kp)
    if candidates:
        candidate_rows: list[dict] = []
        candidate_meta: list[dict] = []
        for candidate_path, candidate_key in candidates:
            opened = _read_open_key(
                candidate_key,
                candidate_path,
                offset=0,
                limit=10_000,
                filter=None,
                depth=depth,
                operation=operation,
                reader=reader,
            )
            candidate_meta.append(
                {
                    "key": candidate_path,
                    "subkeys": opened.get("subkeys", []),
                    "returned": opened.get("returned", 0),
                    "total_matching": opened.get("total_matching"),
                    "truncated": opened.get("truncated", False),
                }
            )
            for row in opened.get("rows", []):
                candidate_rows.append({"candidate_key": candidate_path, **row})
        reason = "exact key absent; returned bounded full-path suffix candidates"
        return {
            "requested_key": kp,
            "candidate_keys": candidate_meta,
            "resolution": "bounded_full_path_suffix_search",
            "status": "partial",
            "coverage_complete": False,
            "coverage": {
                "complete": False,
                "scope": kp,
                "reason": reason if search_complete else reason + "; search cap reached",
            },
            "warnings": [
                {
                    "code": "registry_key_candidates",
                    "message": reason,
                    "details": {
                        "requested_key": kp,
                        "candidate_count": len(candidates),
                        "search_complete": search_complete,
                    },
                }
            ],
            **shape(candidate_rows, offset=offset, limit=limit, filter=filter),
        }

    # Finally return the deepest existing ancestor as explicitly partial
    # recovery.  Its values and child names give the model a grounded correction
    # path (e.g. a duplicated/misspelled component) without pretending the exact
    # requested key existed.
    for count in range(len(parts) - 1, -1, -1):
        ancestor_path = "\\" + "\\".join(parts[:count]) if count else "\\"
        try:
            ancestor = h.get_key(ancestor_path)
        except Exception:
            continue
        recovered = _read_open_key(
            ancestor,
            ancestor_path,
            offset=offset,
            limit=limit,
            filter=filter,
            depth=0,
            operation=operation,
            reader=reader,
        )
        reason = "exact key absent; returned deepest existing ancestor"
        recovered.update(
            {
                "requested_key": kp,
                "resolved_key": ancestor_path,
                "missing_components": parts[count:],
                "resolution": "deepest_existing_ancestor",
                "status": "partial",
                "coverage_complete": False,
                "coverage": {"complete": False, "scope": kp, "reason": reason},
                "warnings": [
                    _recovery_warning(kp, ancestor_path, "deepest-existing-ancestor lookup")
                ],
            }
        )
        return recovered

    return {
        "key": kp,
        "error": f"key not found: {str(exact_error or 'unresolved key')[:140]}",
    }


def _value_readings_result(
    hive: str,
    path: str,
    key_result: dict,
    *,
    normalized_key: str,
    depth: int,
    cited_inputs: list[dict],
) -> dict:
    """Wrap the readings of one key as their own DERIVED result.

    The result names what it was computed from: the caller's confirmed prior
    results when it has them, otherwise the observed read this call performed —
    below the runtime standardizer a direct parser caller has no invocation id or
    receipt to cite, and an immutable hive plus the key path is what identifies
    that read.  It never restates the observed value, because a derivation that
    republished its input would be exactly the mixed result this split removes.
    """

    inputs = list(cited_inputs) or [
        observed_operation_input(
            tool="registry_query",
            operation=_DEFAULT_REGISTRY_OPERATION,
            parameters={"hive": hive, "key": normalized_key, "depth": depth},
        )
    ]
    return {
        "hive": hive,
        "path": path,
        "operation": _VALUE_READINGS_OPERATION,
        "schema_id": _VALUE_INTERPRETATION_SCHEMA_ID,
        "evidence_class": "derived",
        "derivation": {
            "method": _VALUE_READINGS_METHOD,
            "method_version": _VALUE_READINGS_METHOD_VERSION,
            "derivation_inputs": inputs,
            "basis": (
                "each reading is this module's interpretation of the bytes or integer "
                "regipy reported; the registry does not state that a value is a time "
                "or a string, so the rule and the condition it accepted are named per "
                "reading"
            ),
        },
        **key_result,
    }


def registry_query(
    disk,
    hive: str,
    offset: int = 0,
    limit: int = 50,
    filter: str | None = None,
    key: str | None = None,
    depth: int = 0,
    operation: str = _DEFAULT_REGISTRY_OPERATION,
    *,
    scratch: ControlledScratchSession | None = None,
    derived_from: object = None,
) -> dict:
    """Extract a Windows registry hive from the image (read-only) and return regipy's
    plugin findings (computer name, USB history, timezone, services, installed
    software, per-user activity) as paginated rows. Use for registry facts.

    Example: registry_query(disk, "SYSTEM")            # all relevant plugins
             registry_query(disk, "SAM", filter="user")  # narrow to user accounts
             registry_query(disk, "SYSTEM", key="ControlSet001\\Services\\Tcpip\\Parameters")
                                                        # RAW value lookup by key path
             registry_query(disk, "NTUSER:Alice")

    Input: `disk` is the open image handle; `hive` is one of SYSTEM, SOFTWARE, SAM,
    SECURITY, "NTUSER:<username>" or "USRCLASS:<username>" (the hive NAME, never a
    path). For a specific value that NO plugin
    exposes, pass `key=<path within the hive>` (e.g. key="ControlSet001\\Control\\ComputerName\\
    ComputerName") for a RAW key/value lookup — returns that key's values + subkeys.
    `offset`/`limit` paginate and `filter` narrows rows (substring). Read-only.

    `operation` selects which question this call answers, because the two are not
    the same kind of claim. "registry_values" (default) returns what regipy
    reported. "value_readings" returns only what THIS module read in those bytes
    — a Unix epoch, a Windows FILETIME, UTF-16LE text behind a struct header —
    for one `key`; each reading is a guess about a meaning the registry never
    states, so it is a separate derived result and never sits inside the value.

    A raw key read opens a SECOND parser over the same staged hive, because
    regipy 6.2.1 returns the little-endian integer of a value stored inside its
    own vk record rather than that value's content — a REG_SZ holding "8" comes
    back as 56 and an empty one as 0. Such a row carries libregf's reading of the
    same bytes and names it in "value_reader"; the result declares the
    substitution in a "registry_value_reader_substituted" warning. Where no
    reader can supply the value the row reports no value at all and says why in
    "value_unreadable", because the integer is a different number and not a
    shortened reading of the value. That covers two cases: no second parser was
    reachable, and the value is one of the class libregf itself returns as zeros
    — an inline value shorter than four bytes — which is withheld rather than
    published as the right type and length with the wrong content. The plugin
    sweep is NOT covered: regipy's
    plugins report entries carrying neither the declared type nor the key path,
    so a substitution there could not be decided.

    Returns the shared tool envelope: {"hive", "path", "parser" (the regipy this
    host actually imported), "plugins_available", "rows", "total_matching",
    "returned", "offset", "truncated", "note", and "plugins_failed" if any plugin
    raised without aborting the rest}. A row carries regipy's own value. The
    readings operation instead returns {"evidence_class": "derived", "derivation",
    ...} whose rows name the value and carry its "derived_interpretations".
    Returns an "error" key only if the hive cannot be opened. If regipy wrote
    anything to stderr while reading, that text comes back with this result — in
    "backend_stderr" and the "error" text when the read failed, otherwise as a
    "registry_backend_stderr" warning beside unchanged rows — and never on the
    console.
    """
    requested_operation = (operation or "").strip().casefold() or _DEFAULT_REGISTRY_OPERATION
    if requested_operation not in REGISTRY_QUERY_OPERATIONS:
        return {
            "hive": hive,
            "error": f"unknown operation '{operation}'. Use one of: "
            f"{', '.join(REGISTRY_QUERY_OPERATIONS)}.",
        }
    cited_inputs: list[dict] = []
    if requested_operation == _VALUE_READINGS_OPERATION:
        if not key:
            # The plugin-findings path never produces readings: regipy's own
            # plugins report already-interpreted entries, and this module reads
            # nothing further in them. Asking for readings without a key would
            # otherwise return an empty result that reads like "there are none".
            return {
                "hive": hive,
                "error": (
                    "value_readings reads the values of one key; pass key=<path within "
                    "the hive>. regipy's plugin findings carry no readings of ours."
                ),
            }
        try:
            cited_inputs = confirmed_result_inputs(derived_from)
        except DerivationInputError as e:
            return {
                "hive": hive,
                "error": f"cited derivation inputs are unusable: {str(e)[:150]}",
            }
    path = _resolve(hive)
    if path is None and _is_user_hive(hive):
        path, profile_error = _user_hive_path(hive, disk=disk, scratch=scratch)
        if path is None:
            return {"hive": hive, "error": profile_error}
    if not path:
        return {
            "error": f"unknown hive '{hive}'. Use SYSTEM/SOFTWARE/SAM/SECURITY, "
            "NTUSER:<user> or USRCLASS:<user>."
        }
    if type(scratch) is not ControlledScratchSession:
        return {
            "hive": hive,
            "path": path,
            "error": "controlled scratch authority is required for registry parsing",
        }
    scratch = cast(ControlledScratchSession, scratch)
    with ExitStack() as stack:
        try:
            local, extraction_reused = _staged_hive(disk, path, scratch, stack)
        except ControlledScratchError:
            raise
        except Exception as e:
            return _hive_staging_failure(e, hive=hive, path=path)
        # Stated on the result so a reader can tell a shared staged copy from a
        # fresh extraction; absent (not false) on a fresh one, whose results
        # keep exactly the bytes they had before the cache existed.
        reuse_marker: dict[str, object] = (
            {"hive_extraction_reused": True} if extraction_reused else {}
        )
        # Only a raw key read can reach a value's declared type and path, which is
        # what the second reader needs to answer for one; regipy's plugins report
        # already-shaped entries that carry neither, so the sweep opens no second
        # reader and its rows stay subject to the defect this one corrects.
        reader = _SecondValueReader(local) if key else None
        # regipy starts on the next line and nothing above it is regipy, so the
        # capture starts here too: a wider scope would take output the backend
        # never wrote and could not be asked to explain.
        with capture_backend_stderr(_REGIPY_BACKEND.backend) as backend_stream:
            try:
                h = RegistryHive(str(local))
            except Exception as e:
                if reader is not None:
                    reader.close()
                return _with_backend_stderr(
                    {
                        "hive": hive,
                        "path": path,
                        "error": f"could not open hive: {str(e)[:160]}",
                    },
                    backend_stream,
                )
            try:
                if key:
                    normalized_key, key_normalization = _normalize_key_within_hive(hive, key)
                    key_result = _read_key(
                        h,
                        normalized_key,
                        offset=offset,
                        limit=limit,
                        filter=filter,
                        depth=depth,
                        resolve_current_control_set=hive.strip().upper() == "SYSTEM",
                        operation=requested_operation,
                        reader=reader,
                    )
                    if key_normalization is not None:
                        key_result = {
                            **key_result,
                            "input_key": key,
                            "normalized_key": normalized_key,
                            "key_normalization": key_normalization,
                        }
                    if requested_operation == _VALUE_READINGS_OPERATION:
                        return _with_backend_stderr(
                            {
                                **_value_readings_result(
                                    hive,
                                    path,
                                    key_result,
                                    normalized_key=normalized_key,
                                    depth=depth,
                                    cited_inputs=cited_inputs,
                                ),
                                **reuse_marker,
                            },
                            backend_stream,
                        )
                    return _with_backend_stderr(
                        {
                            "hive": hive,
                            "path": path,
                            **key_result,
                            **reuse_marker,
                        },
                        backend_stream,
                    )
                curated = curated_plugin_names()
                sweep_key = _plugin_sweep_cache_key(disk, path, scratch, curated)
                sweep = None if sweep_key is None else _cached_plugin_sweep(sweep_key)
                if sweep is None:
                    res, failed = _run_plugins(h)
                    relevant = {k: v for k, v in res.items() if k in curated and v} or {
                        k: v for k, v in res.items() if v
                    }
                    sweep = (_rows(relevant), sorted(res.keys()), sorted(set(failed)))
                    if sweep_key is not None:
                        _store_plugin_sweep(sweep_key, sweep)
                rows, available, failed_names = sweep
                env = shape(rows, offset=offset, limit=limit, filter=filter)
                out = {
                    "hive": hive,
                    "path": path,
                    "parser": _regipy_identity(),
                    "plugins_available": available,
                    **env,
                    **reuse_marker,
                }
                if failed_names:
                    out["plugins_failed"] = failed_names
                return _with_backend_stderr(out, backend_stream)
            finally:
                if reader is not None:
                    reader.close()
                close = getattr(h, "close", None)
                if callable(close):
                    close()
    raise AssertionError("controlled scratch context returned without a registry result")


def registry_query_many(
    disk,
    hive: str,
    queries: Mapping[str, tuple[str, int]],
    *,
    scratch: ControlledScratchSession | None = None,
) -> dict[str, dict]:
    """Read several trusted raw keys while extracting the hive only once.

    Specialized deterministic joins often need several related registry keys.
    Re-extracting the same immutable hive for every internal lookup is needlessly
    expensive and widens the opportunity for inconsistent partial reads.  This
    helper retains the exact :func:`_read_key` result contract per named query,
    but shares one controlled, read-only hive extraction.  It is an internal
    parser primitive; model-facing tools continue to expose their narrow schemas.
    """

    path = _resolve(hive)
    if not path:
        return {
            name: {
                "error": (
                    f"unknown hive '{hive}'. Use SYSTEM/SOFTWARE/SAM/SECURITY or NTUSER:<user>."
                )
            }
            for name in queries
        }
    if type(scratch) is not ControlledScratchSession:
        return {
            name: {
                "hive": hive,
                "path": path,
                "error": "controlled scratch authority is required for registry parsing",
            }
            for name in queries
        }
    normalized: dict[str, tuple[str, int]] = {}
    for name, query in queries.items():
        if not isinstance(name, str) or not name:
            raise ValueError("registry batch query names must be non-empty strings")
        if (
            not isinstance(query, tuple)
            or len(query) != 2
            or not isinstance(query[0], str)
            or not query[0]
            or isinstance(query[1], bool)
            or not isinstance(query[1], int)
            or query[1] < 0
        ):
            raise ValueError("registry batch queries must be (non-empty key, depth) tuples")
        normalized[name] = query

    scratch = cast(ControlledScratchSession, scratch)
    with scratch.artifact(ScratchKind.REGISTRY_HIVE) as artifact:
        try:
            extract_to = getattr(disk, "extract_file_to", None)
            if callable(extract_to):
                extract_to(path, artifact.writer)
            else:
                artifact.writer.close()
                disk.extract_file(path, str(artifact.path))
            local = artifact.seal()
        except ControlledScratchError:
            raise
        except Exception as exc:
            failure = _hive_staging_failure(exc, hive=hive, path=path)
            return {name: dict(failure) for name in normalized}
        # Every named query here is a raw key read, so all of them are entitled to
        # the second reader, and one handle answers for the whole batch.
        reader = _SecondValueReader(local)
        # One extraction, one hive, one backend scope.  Every named query below is
        # answered from the same regipy read, so its complaint belongs to each of
        # the results that read produced.
        with capture_backend_stderr(_REGIPY_BACKEND.backend) as backend_stream:
            try:
                registry_hive = RegistryHive(str(local))
            except Exception as exc:
                reader.close()
                return {
                    name: _with_backend_stderr(
                        {
                            "hive": hive,
                            "path": path,
                            "error": f"could not open hive: {str(exc)[:160]}",
                        },
                        backend_stream,
                    )
                    for name in normalized
                }
            try:
                resolve_current = hive.strip().upper() == "SYSTEM"
                results = {
                    name: {
                        "hive": hive,
                        "path": path,
                        **_read_key(
                            registry_hive,
                            key,
                            offset=0,
                            limit=10_000,
                            filter=None,
                            depth=depth,
                            resolve_current_control_set=resolve_current,
                            reader=reader,
                        ),
                    }
                    for name, (key, depth) in normalized.items()
                }
                return {
                    name: _with_backend_stderr(result, backend_stream)
                    for name, result in results.items()
                }
            finally:
                reader.close()
                close = getattr(registry_hive, "close", None)
                if callable(close):
                    close()
