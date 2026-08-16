"""The container entrypoint's symbol-store seed, which no other test can reach.

The entrypoint is a POSIX shell script written into the image by a heredoc in
``deploy/Dockerfile``. Nothing imports it, the suite never executes it, and it
only runs inside a container, so every defect in it has to be found by reading
or by an operator hitting it. It copies 807 MB on a first run, which is long
enough that going silent there is indistinguishable from hanging.

These tests read the script out of the Dockerfile and assert the properties that
made it honest, plus a syntax check through the same ``sh -n`` the image build
runs. They are text-level assertions by necessity, and they are still worth
having: the one defect found while writing this script was a ``printf`` that
emitted a literal backslash-n instead of a newline, which is exactly the kind of
thing that survives a careful reading.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

DOCKERFILE = Path(__file__).resolve().parents[1] / "deploy" / "Dockerfile"
_HEREDOC_OPENING = "RUN cat >/usr/local/bin/dfir-agent-console"


def entrypoint_script() -> str:
    """The entrypoint exactly as the image will hold it."""

    lines = DOCKERFILE.read_text(encoding="utf-8").splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith(_HEREDOC_OPENING))
    end = next(i for i in range(start + 1, len(lines)) if lines[i].strip() == "SH")
    return "\n".join(lines[start + 1 : end]) + "\n"


def test_the_script_is_valid_posix_shell(tmp_path: Path) -> None:
    """The same check the image build runs, so a break is caught before a build."""

    shell = shutil.which("sh")
    if shell is None:
        pytest.skip("no POSIX shell available to syntax-check with")
    script = tmp_path / "dfir-agent-console"
    script.write_text(entrypoint_script(), encoding="utf-8", newline="\n")
    finished = subprocess.run(
        [shell, "-n", str(script)], capture_output=True, text=True, timeout=60
    )
    assert finished.returncode == 0, finished.stderr


def test_the_seed_says_how_much_it_is_about_to_copy() -> None:
    """A first run that prints one sentence and goes quiet reads as a hang."""

    script = entrypoint_script()
    assert "preparing the local symbol store" in script
    # The size comes from du rather than from a number written into the script,
    # which would go stale the moment the symbol pack changed.
    assert "du -sk" in script
    assert "$((total_kb / 1024)) MB" in script


def test_progress_is_measured_against_the_total_and_never_invented() -> None:
    script = entrypoint_script()
    assert "report_copy_progress" in script
    # The fraction is two directory measurements taken the same way, so the
    # ratio compares like with like.
    assert "copied_kb=$(tree_kb \"$staging\")" in script
    assert "MB of %s MB" in script
    # Where no total could be measured the line states what has landed and does
    # not turn into a percentage nobody computed.
    assert "MB copied" in script


def test_the_progress_line_emits_real_control_characters() -> None:
    """``printf`` expands escapes in the FORMAT, never in a ``%s`` argument.

    Written with ``%s`` the terminator reached the operator as a literal
    backslash-n, running every update into the next. ``%b`` is the conversion
    that interprets escapes in the argument, so the distinction is load-bearing
    rather than stylistic.
    """

    script = entrypoint_script()
    for line in script.splitlines():
        if "symbol store %s MB" in line:
            assert line.rstrip().endswith("%b' \\"), line
    assert "progress_end='\\r'" in script
    assert "progress_end='\\n'" in script


def test_a_redirected_stream_gets_one_line_per_update() -> None:
    """A captured log records that the copy advanced, without thousands of redraws."""

    script = entrypoint_script()
    assert "if [ -t 2 ]; then" in script


def test_a_missing_volume_is_named_rather_than_paid_for_silently() -> None:
    """Without the named volume the copy repeats on every single run."""

    script = entrypoint_script()
    assert "symbols_volume_mounted" in script
    assert "not mounted" in script
    assert "/proc/mounts" in script


def test_an_unanswerable_mount_question_stays_quiet() -> None:
    """A false report of a missing volume sends an operator after a fault that is not there."""

    script = entrypoint_script()
    body = script[script.index("symbols_volume_mounted() {") :]
    body = body[: body.index("\n}")]
    # The last word of the function is "mounted", which is the quiet answer.
    assert body.rstrip().endswith("return 0")


def test_a_failed_copy_cleans_up_and_falls_back_instead_of_failing_the_run() -> None:
    script = entrypoint_script()
    assert 'rm -rf -- "$staging"' in script
    assert "the host copy is used instead" in script
    # The store is renamed into place, so an interrupted seed cannot leave a
    # half-store that later runs would read as finished.
    assert 'mv -- "$staging" "$local_store"' in script


def test_the_console_still_starts_however_the_seed_went() -> None:
    script = entrypoint_script()
    assert script.rstrip().endswith('exec dfir-agent "$@"')
    assert "seed_symbol_store || true" in script
