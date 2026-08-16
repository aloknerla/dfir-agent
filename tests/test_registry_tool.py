"""Per-user hive selectors resolve through the profile list, for BOTH spellings.

``USRCLASS:<user>`` is advertised beside ``NTUSER:<user>`` in the tool schema,
and ``_resolve`` declines both so the caller can route them through the
ProfileList lookup — but the routing gate used to recognise only ``NTUSER``,
so every ``USRCLASS`` reference died as "unknown hive" without the evidence
ever being asked.  These tests pin the shared selector set, the routing, and
the UsrClass.dat location choice: unlike NTUSER.DAT it moved between Windows
versions, so the standard candidates are probed on the image rather than
chosen from an assumed version.  No real hive parsing is required: resolution
is what is under test, and the profile list is faked at the seam that reads it.

The second half pins what a keyless read costs.  It runs every plugin the
installed regipy validates over the whole hive and then paginates the product,
so every PAGE of one result used to repeat the entire sweep; the retained
product is the whole sweep — rows, the plugins that reported and the plugins
that raised — because a later page reporting an empty plugin inventory beside
those plugins' own rows would be a defect and not a saving.
"""

from __future__ import annotations

from pathlib import Path

from forensic_agent.core.controlled_scratch import (
    ControlledScratchSession,
    attest_controlled_scratch_root,
)
from forensic_agent.tools import registry_tool
from forensic_agent.tools.registry_tool import registry_query

_MODERN_USRCLASS = "/Users/Administrator/AppData/Local/Microsoft/Windows/UsrClass.dat"
_XP_USRCLASS = (
    "/Documents and Settings/Administrator"
    "/Local Settings/Application Data/Microsoft/Windows/UsrClass.dat"
)


def _session(tmp_path: Path) -> ControlledScratchSession:
    root = tmp_path / "scratch"
    root.mkdir()
    return ControlledScratchSession(
        attest_controlled_scratch_root(root), namespace="registry-test"
    )


class _ProbeDisk:
    """A minimal image adapter: metadata answers only for the paths it has."""

    def __init__(self, present=()) -> None:
        self._present = {path for path in present}

    def file_metadata(self, path: str) -> dict:
        if path not in self._present:
            raise FileNotFoundError(path)
        return {"path": path, "size": 1}

    def extract_file_to(self, path: str, writer) -> None:
        writer.write(b"not a registry hive")


class _LegacyDisk:
    """No metadata probe at all, like the development doubles ``_extract_hive_into``
    already tolerates."""


class _ImageDisk:
    """An image that declares its own digest, as a real ``DiskImage`` does."""

    image_sha = "9f" * 32

    def extract_file_to(self, path: str, writer) -> None:
        writer.write(b"staged hive bytes")


class _FakeHive:
    """Stands in for ``RegistryHive``: the sweep is faked, so nothing is parsed."""

    def __init__(self, path: str) -> None:
        self.path = path

    def close(self) -> None:
        return None


class _CountingSweep:
    """Counts how many times the whole regipy plugin sweep actually ran."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, hive) -> tuple[dict, list]:
        self.calls += 1
        return (
            {
                "computer_name": [{"name": "WORKSTATION"}],
                "services": [{"name": f"service-{index}"} for index in range(6)],
            },
            ["shimcache", "shimcache"],
        )


def _declares(*profiles: str):
    """A profile list that declares exactly these directories."""

    return lambda disk, scratch: list(profiles)


# ---------------------------------------------------------------------------
# The selector set, stated once and honoured by both askers.


def test_both_user_hive_spellings_are_one_selector_class():
    assert registry_tool._is_user_hive("NTUSER:Administrator")
    assert registry_tool._is_user_hive("USRCLASS:Administrator")
    assert registry_tool._is_user_hive("  usrclass:administrator  ")
    assert not registry_tool._is_user_hive("SYSTEM")
    assert registry_tool._resolve("USRCLASS:Administrator") is None
    assert registry_tool._resolve("NTUSER:Administrator") is None


def test_the_unknown_hive_refusal_names_both_user_hive_forms():
    result = registry_query(None, hive="BOGUS")
    assert "USRCLASS:<user>" in result["error"]
    assert "NTUSER:<user>" in result["error"]


# ---------------------------------------------------------------------------
# UsrClass.dat location resolution against the profile list the system wrote.


def test_usrclass_resolves_the_modern_location_the_image_has(monkeypatch):
    monkeypatch.setattr(
        registry_tool, "_declared_profile_paths", _declares("C:\\Users\\Administrator")
    )
    path, error = registry_tool._user_hive_path(
        "USRCLASS:Administrator", disk=_ProbeDisk({_MODERN_USRCLASS}), scratch=None
    )
    assert path == _MODERN_USRCLASS
    assert error == ""


def test_usrclass_resolves_the_xp_location_the_image_has(monkeypatch):
    monkeypatch.setattr(
        registry_tool,
        "_declared_profile_paths",
        _declares("C:\\Documents and Settings\\Administrator"),
    )
    path, error = registry_tool._user_hive_path(
        "USRCLASS:Administrator", disk=_ProbeDisk({_XP_USRCLASS}), scratch=None
    )
    assert path == _XP_USRCLASS
    assert error == ""


def test_usrclass_selector_matches_the_profile_without_case(monkeypatch):
    monkeypatch.setattr(
        registry_tool, "_declared_profile_paths", _declares("C:\\Users\\Administrator")
    )
    path, error = registry_tool._user_hive_path(
        "usrclass:ADMINISTRATOR", disk=_ProbeDisk({_MODERN_USRCLASS}), scratch=None
    )
    assert path == _MODERN_USRCLASS
    assert error == ""


def test_usrclass_absent_from_both_standard_locations_fails_with_the_reason(monkeypatch):
    monkeypatch.setattr(
        registry_tool, "_declared_profile_paths", _declares("C:\\Users\\Administrator")
    )
    path, error = registry_tool._user_hive_path(
        "USRCLASS:Administrator", disk=_ProbeDisk(), scratch=None
    )
    assert path is None
    assert "UsrClass.dat" in error
    assert "Administrator" in error


def test_usrclass_without_a_probe_keeps_the_modern_location(monkeypatch):
    monkeypatch.setattr(
        registry_tool, "_declared_profile_paths", _declares("C:\\Users\\Administrator")
    )
    path, error = registry_tool._user_hive_path(
        "USRCLASS:Administrator", disk=_LegacyDisk(), scratch=None
    )
    assert path == _MODERN_USRCLASS
    assert error == ""


def test_ntuser_resolution_is_unchanged_and_never_probes(monkeypatch):
    monkeypatch.setattr(
        registry_tool, "_declared_profile_paths", _declares("C:\\Users\\Administrator")
    )
    path, error = registry_tool._user_hive_path(
        "NTUSER:Administrator", disk=_LegacyDisk(), scratch=None
    )
    assert path == "/Users/Administrator/NTUSER.DAT"
    assert error == ""


def test_usrclass_for_an_account_the_profile_list_does_not_declare(monkeypatch):
    monkeypatch.setattr(
        registry_tool, "_declared_profile_paths", _declares("C:\\Users\\Administrator")
    )
    path, error = registry_tool._user_hive_path(
        "USRCLASS:Alice", disk=_ProbeDisk({_MODERN_USRCLASS}), scratch=None
    )
    assert path is None
    assert "Alice" in error
    assert "Administrator" in error


# ---------------------------------------------------------------------------
# The routing gate itself: a USRCLASS reference reaches resolution end to end.


def test_registry_query_routes_usrclass_to_the_resolved_hive(tmp_path, monkeypatch):
    monkeypatch.setattr(
        registry_tool, "_declared_profile_paths", _declares("C:\\Users\\Administrator")
    )
    result = registry_query(
        _ProbeDisk({_MODERN_USRCLASS}),
        hive="USRCLASS:Administrator",
        scratch=_session(tmp_path),
    )
    # Resolution succeeded and the staged bytes reached the parser; the junk
    # content cannot open, which is the proof the reference was never refused
    # as an unknown hive.
    assert result["path"] == _MODERN_USRCLASS
    assert "unknown hive" not in result.get("error", "")
    assert "could not open hive" in result["error"]


def test_registry_query_reports_a_usrclass_the_image_does_not_have(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        registry_tool, "_declared_profile_paths", _declares("C:\\Users\\Administrator")
    )
    result = registry_query(
        _ProbeDisk(), hive="USRCLASS:Administrator", scratch=_session(tmp_path)
    )
    assert result.get("path") is None
    assert "UsrClass.dat" in result["error"]
    assert "unknown hive" not in result["error"]


# ---------------------------------------------------------------------------
# The plugin sweep is paid once per hive, not once per page.
#
# With no ``key`` the read runs every plugin the installed regipy validates over
# the whole hive and then paginates the product, so every page of the same
# result used to repeat minutes of sweeping.  The retained product is the WHOLE
# product: rows alone would leave a later page reporting an empty plugin
# inventory beside rows those very plugins produced.


def _sweeping(monkeypatch) -> _CountingSweep:
    sweep = _CountingSweep()
    registry_tool._plugin_sweep_cache.clear()
    monkeypatch.setattr(registry_tool, "_run_plugins", sweep)
    monkeypatch.setattr(registry_tool, "RegistryHive", _FakeHive)
    return sweep


def test_a_second_page_of_the_same_query_does_not_repeat_the_sweep(tmp_path, monkeypatch):
    sweep = _sweeping(monkeypatch)
    disk, scratch = _ImageDisk(), _session(tmp_path)
    first = registry_query(disk, "SYSTEM", offset=0, limit=2, scratch=scratch)
    second = registry_query(disk, "SYSTEM", offset=2, limit=2, scratch=scratch)
    assert sweep.calls == 1
    assert first["rows"] and second["rows"] and second["rows"] != first["rows"]
    assert second["offset"] == 2
    assert second["total_matching"] == first["total_matching"]


def test_the_later_page_still_reports_the_whole_plugin_inventory(tmp_path, monkeypatch):
    sweep = _sweeping(monkeypatch)
    disk, scratch = _ImageDisk(), _session(tmp_path)
    first = registry_query(disk, "SYSTEM", offset=0, limit=2, scratch=scratch)
    second = registry_query(disk, "SYSTEM", offset=2, limit=2, scratch=scratch)
    assert sweep.calls == 1
    assert first["plugins_available"] == ["computer_name", "services"]
    assert second["plugins_available"] == first["plugins_available"]
    assert first["plugins_failed"] == ["shimcache"]
    assert second["plugins_failed"] == first["plugins_failed"]


def test_a_second_hive_of_the_same_image_is_swept_on_its_own(tmp_path, monkeypatch):
    sweep = _sweeping(monkeypatch)
    disk, scratch = _ImageDisk(), _session(tmp_path)
    registry_query(disk, "SYSTEM", scratch=scratch)
    registry_query(disk, "SOFTWARE", scratch=scratch)
    assert sweep.calls == 2


def test_an_image_without_a_digest_retains_nothing(tmp_path, monkeypatch):
    sweep = _sweeping(monkeypatch)
    scratch = _session(tmp_path)
    registry_query(_ProbeDisk(), "SYSTEM", scratch=scratch)
    registry_query(_ProbeDisk(), "SYSTEM", scratch=scratch)
    assert sweep.calls == 2
    assert not registry_tool._plugin_sweep_cache
