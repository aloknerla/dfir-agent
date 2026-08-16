"""The retained Volatility results, and the symbol index they are produced with.

Two costs used to be paid on every message of the same investigation.  The row
cache was keyed on ``DFA_VOL_WORKDIR`` and ``DFA_VOL_CACHE``, which the console
rebinds to a fresh per-question scratch directory for every ``ask()``, so the
key differed each time and the cache never hit — a follow-up question re-ran a
multi-gigabyte scan it already had.  And an unconfigured run put Volatility's
mutable symbol index below the per-call temporary output directory, which is
deleted when the call ends, so every call re-indexed the packaged symbols from
nothing.

Dropping the directories from the key means a plugin whose rows POINT AT files
it wrote into that scratch directory must not be retained at all: those paths
belong to the run that produced them.  That is pinned here too, because a cached
row set naming files a later run cannot open is worse than the re-scan it saved.

Volatility itself is never executed: the subprocess boundary is faked, and what
is under test is which calls reach it.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from forensic_agent.tools import memory_tool
from forensic_agent.tools.memory_tool import memory_query

_ROWS = [{"PID": 4, "ImageFileName": "System"}, {"PID": 512, "ImageFileName": "smss.exe"}]


class _FakeVolatility:
    """One recorded invocation boundary in place of the Volatility subprocess."""

    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    def __call__(self, command, **kwargs) -> subprocess.CompletedProcess:
        self.commands.append(list(command))
        return subprocess.CompletedProcess(
            args=list(command), returncode=0, stdout=json.dumps(_ROWS), stderr=""
        )

    @property
    def runs(self) -> int:
        return len(self.commands)


@pytest.fixture
def volatility(monkeypatch) -> _FakeVolatility:
    fake = _FakeVolatility()
    memory_tool._plugin_output_cache.clear()
    monkeypatch.setattr(memory_tool, "vol_path", lambda: "vol")
    monkeypatch.setattr(memory_tool, "run_external", fake)
    monkeypatch.delenv("DFA_VOL_WORKDIR", raising=False)
    monkeypatch.delenv("DFA_VOL_CACHE", raising=False)
    monkeypatch.delenv("DFA_VOL_SYMBOL_DIRS", raising=False)
    return fake


@pytest.fixture
def dump(tmp_path: Path) -> Path:
    path = tmp_path / "memory.raw"
    path.write_bytes(b"memory image bytes")
    return path


def _rebind_scratch(monkeypatch, tmp_path: Path, name: str) -> None:
    """Do what the console does between two questions of the same investigation."""

    scratch = tmp_path / name
    scratch.mkdir()
    monkeypatch.setenv("DFA_VOL_WORKDIR", str(scratch))
    monkeypatch.setenv("DFA_VOL_CACHE", str(scratch))


# ---------------------------------------------------------------------------
# The row cache survives the per-question scratch directory.


def test_the_same_plugin_on_the_same_dump_runs_volatility_once(volatility, dump):
    first = memory_query(str(dump), "pslist")
    second = memory_query(str(dump), "pslist")
    assert volatility.runs == 1
    assert second == first


def test_a_rebound_scratch_directory_still_serves_the_retained_rows(
    volatility, dump, tmp_path, monkeypatch
):
    _rebind_scratch(monkeypatch, tmp_path, "question-1")
    first = memory_query(str(dump), "netscan")
    _rebind_scratch(monkeypatch, tmp_path, "question-2")
    second = memory_query(str(dump), "netscan")
    assert volatility.runs == 1
    assert second == first


def test_a_different_plugin_is_a_different_entry(volatility, dump):
    memory_query(str(dump), "pslist")
    memory_query(str(dump), "netscan")
    assert volatility.runs == 2


def test_a_modified_dump_is_never_served_from_the_earlier_scan(volatility, dump):
    memory_query(str(dump), "pslist")
    dump.write_bytes(b"a different memory image entirely")
    memory_query(str(dump), "pslist")
    assert volatility.runs == 2


# ---------------------------------------------------------------------------
# Plugins whose rows name files written into the run workspace.


@pytest.mark.parametrize(
    "plugin",
    ["dumpfiles", "windows.dumpfiles.DumpFiles", "windows.pedump.PeDump", "windows.memmap.Memmap"],
)
def test_a_plugin_that_writes_into_the_workspace_is_never_retained(volatility, dump, plugin):
    memory_query(str(dump), plugin)
    memory_query(str(dump), plugin)
    assert volatility.runs == 2
    assert not memory_tool._plugin_output_cache


# ---------------------------------------------------------------------------
# The symbol index outlives the call that built it.


def test_an_unconfigured_run_keeps_one_symbol_cache_directory(volatility):
    with memory_tool._runtime_directories() as (first_workdir, first_cache):
        first_cache.mkdir(parents=True, exist_ok=True)
    with memory_tool._runtime_directories() as (second_workdir, second_cache):
        pass
    assert first_workdir != second_workdir
    assert not first_workdir.exists()
    assert first_cache == second_cache
    assert second_cache.is_dir()


def test_a_configured_cache_directory_is_used_as_it_stands(volatility, tmp_path, monkeypatch):
    configured = tmp_path / "vol-cache"
    configured.mkdir()
    monkeypatch.setenv("DFA_VOL_CACHE", str(configured))
    with memory_tool._runtime_directories() as (_, cache):
        assert cache == configured.resolve()
