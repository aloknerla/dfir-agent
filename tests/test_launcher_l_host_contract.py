"""What the host launchers have to say, read as text because they cannot run.

Two modules inside the container read four environment variables that only a
host launcher can fill in: ``build_identity`` names the image, ``host_display``
turns a container path into one the operator can open. Neither raises when a
variable is missing, so an export dropped from a launcher costs nothing at
import time and shows up as a blank field on someone's screen a week later.

The launchers are PowerShell and bash. Nothing in this suite can execute them,
and a test that mocked them would be testing the mock, so these read the files
and assert on what they say. That is weaker than running them and it is the
strongest thing available; the alternative on offer is no coverage at all.

The evidence kinds are the same story from the other side. ``timeline`` was
removed from the console, and a launcher that still advertises ``--timeline``
is offering an operator a flag the product cannot honour.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
_LAUNCHERS = {
    "launch.ps1": _REPO_ROOT / "deploy" / "console" / "launch.ps1",
    "launch.sh": _REPO_ROOT / "deploy" / "console" / "launch.sh",
}
_COMPOSE_FILE = _REPO_ROOT / "docker-compose.yml"

#: The four the container reads. Kept as literals rather than imported from the
#: two modules on purpose: importing them would let a rename pass this test
#: while breaking the contract between a launcher and the image it starts.
_HOST_VARIABLES = (
    "DFA_BUILD_ID",
    "DFA_BUILD_TIME",
    "DFA_HOST_RUNS",
    "DFA_HOST_EVIDENCE",
)


@pytest.fixture(scope="module")
def launcher_text() -> dict[str, str]:
    return {name: path.read_text(encoding="utf-8") for name, path in _LAUNCHERS.items()}


@pytest.fixture(scope="module")
def compose_text() -> str:
    return _COMPOSE_FILE.read_text(encoding="utf-8")


@pytest.mark.parametrize("launcher", sorted(_LAUNCHERS))
def test_neither_launcher_offers_a_timeline_flag(
    launcher: str, launcher_text: dict[str, str]
) -> None:
    text = launcher_text[launcher]
    assert "--timeline" not in text
    assert "attach-timeline" not in text


@pytest.mark.parametrize("launcher", sorted(_LAUNCHERS))
def test_the_word_survives_only_where_a_timeline_is_turned_away(
    launcher: str, launcher_text: dict[str, str]
) -> None:
    """Naming the kind in the refusal is the point; naming it anywhere else is not."""

    remaining = [
        line.strip()
        for line in launcher_text[launcher].splitlines()
        if "timeline" in line.lower()
    ]
    assert remaining, "the refusal has to name the kind it is refusing"
    for line in remaining:
        assert "no longer supported" in line.lower(), line


@pytest.mark.parametrize("launcher", sorted(_LAUNCHERS))
def test_a_plaso_store_is_refused_rather_than_mounted_and_ignored(
    launcher: str, launcher_text: dict[str, str]
) -> None:
    """A .plaso case would open with its only source silently unread."""

    text = launcher_text[launcher].lower()
    assert "plaso" in text
    assert "no longer supported" in text


@pytest.mark.parametrize("launcher", sorted(_LAUNCHERS))
def test_every_evidence_action_the_console_can_request_is_still_accepted(
    launcher: str, launcher_text: dict[str, str]
) -> None:
    """Removing a kind must not have taken a live one with it."""

    text = launcher_text[launcher]
    for action in (
        "case",
        "disk",
        "memory",
        "network",
        "attach-disk",
        "attach-memory",
        "attach-network",
    ):
        assert action in text


@pytest.mark.parametrize("launcher", sorted(_LAUNCHERS))
@pytest.mark.parametrize("variable", _HOST_VARIABLES)
def test_both_launchers_state_what_the_container_cannot_see(
    launcher: str, variable: str, launcher_text: dict[str, str]
) -> None:
    text = launcher_text[launcher]
    if launcher.endswith(".ps1"):
        assert re.search(rf"\$env:{variable}\s*=", text), variable
    else:
        assert re.search(rf"^\s*{variable}=", text, re.MULTILINE), variable
        assert re.search(rf"export .*\b{variable}\b", text), variable


@pytest.mark.parametrize("variable", _HOST_VARIABLES)
def test_compose_passes_each_variable_through_and_defaults_it_to_empty(
    variable: str, compose_text: str
) -> None:
    """The empty default is what keeps an invocation that sets none of them working."""

    assert f'{variable}: "${{{variable}:-}}"' in compose_text


@pytest.mark.parametrize("launcher", sorted(_LAUNCHERS))
def test_the_host_roots_are_restated_for_every_run_not_once(
    launcher: str, launcher_text: dict[str, str]
) -> None:
    """The handoff loop remounts a different host path and relaunches.

    A value exported once, before the loop, names the case the operator opened
    first and keeps naming it after they open another.
    """

    text = launcher_text[launcher]
    setter = "Set-HostMountVariables" if launcher.endswith(".ps1") else (
        "set_host_mount_variables"
    )
    loop_start = text.index("while ")
    assert setter in text[loop_start:], setter


@pytest.mark.parametrize("launcher", sorted(_LAUNCHERS))
def test_the_build_identity_is_read_off_the_image_compose_will_run(
    launcher: str, launcher_text: dict[str, str]
) -> None:
    """Nothing inside an image can name the image it is in."""

    text = launcher_text[launcher]
    inspect = '"image", "inspect"' if launcher.endswith(".ps1") else "image inspect"
    assert inspect in text
    assert "{{.Id}} {{.Created}}" in text
    # Asked of Compose rather than assembled from the project name by hand.
    assert "config" in text and "--images" in text


@pytest.mark.parametrize("launcher", sorted(_LAUNCHERS))
def test_a_launcher_older_than_its_checkout_is_not_allowed_to_pass_quietly(
    launcher: str, launcher_text: dict[str, str]
) -> None:
    text = launcher_text[launcher]
    assert "install" in text
    assert "DFA_ALLOW_STALE" in text
    # Both staleness axes are reported, not just whichever was noticed first.
    assert "installed dfir-agent command" in text
    assert "built before" in text
