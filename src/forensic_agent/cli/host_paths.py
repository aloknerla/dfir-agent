"""Where a path an operator typed is allowed to point, and where exports land.

Every path the interactive console accepts arrives as free text from a person,
and the console may be running inside a container that can see only the evidence
directory mounted into it. Two rules therefore have to be applied to each of
them, in the same way every time: a source must resolve inside the mounted
evidence root, and an export must resolve inside the run directory. Both are
boundary decisions rather than presentation, so they are kept away from the
session's own state and stated once here, as functions over the roots the
session happens to hold.

The third function is the other half of that boundary. A path that is genuinely
not reachable from inside the container is not a mistake the operator made; it
is a path only the host launcher can mount. Rather than refusing it, the console
hands the same text back to the launcher and lets the host resolve it against
the terminal's own working directory — which keeps ``/case case-001`` convenient
without weakening the mounted-root rule for everything that *is* reachable.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

_WINDOWS_ABSOLUTE_PATH = re.compile(r"^[A-Za-z]:[\\/]")


def resolve_evidence_path(path: str, *, evidence_root: Path | None) -> Path:
    """Resolve an investigator-supplied path within the mounted evidence root."""

    raw = path.strip()
    if not raw:
        raise ValueError("Evidence path must not be empty.")
    windows_host_style = (
        evidence_root is not None
        and len(raw) >= 3
        and raw[0].isalpha()
        and raw[1] == ":"
        and raw[2] in {"\\", "/"}
    )

    candidate = Path(raw).expanduser()
    if evidence_root is not None:
        if windows_host_style:
            resolved_windows_path = candidate.resolve()
            try:
                resolved_windows_path.relative_to(evidence_root)
            except ValueError as exc:
                raise ValueError(
                    "This host path is not mounted in the current Docker "
                    "session. Open it as a new case with /case <path>, or "
                    "place related sources in one case directory and open "
                    "that directory."
                ) from exc
            return resolved_windows_path
        if not candidate.is_absolute():
            candidate = evidence_root / candidate
        candidate = candidate.resolve()
        try:
            candidate.relative_to(evidence_root)
        except ValueError as exc:
            raise ValueError(
                f"Evidence paths must remain within {evidence_root}."
            ) from exc
        return candidate
    return candidate.resolve()


def existing_file(path: str, *, label: str, evidence_root: Path | None) -> str:
    candidate = resolve_evidence_path(path, evidence_root=evidence_root)
    if not candidate.is_file():
        raise FileNotFoundError(f"{label} not found: {candidate}")
    return str(candidate)


def export_destination(
    path: str | Path | None,
    *,
    default_name: str,
    run_root: Path,
) -> Path:
    """Resolve exports under the persistent run directory by default.

    A destination already resolved to a :class:`~pathlib.Path` is accepted as
    readily as one the operator typed.
    """

    export_root = (run_root / "exports").resolve()
    candidate = Path(path).expanduser() if path else Path(default_name)
    if not candidate.is_absolute():
        candidate = export_root / candidate
    destination = candidate.resolve()
    if os.environ.get("DFA_CONTAINERIZED") == "1":
        try:
            destination.relative_to(run_root.resolve())
        except ValueError as exc:
            raise ValueError(
                "Container exports must remain within /runtime. "
                "Use a relative path or an absolute /runtime path."
            ) from exc
    destination.parent.mkdir(parents=True, exist_ok=True)
    return destination


def handoff_host_path_if_needed(
    path: str,
    *,
    action: str,
    evidence_root: Path | None,
    run_root: Path,
    model: str,
    conversation_id: str,
) -> None:
    """Let the host launcher mount a path unavailable in this container.

    Relative paths are first resolved inside the active evidence mount. If
    no such entry exists, the same text is handed to the launcher, which
    resolves it against the host terminal's working directory. This keeps
    `/case case-001` convenient without weakening the mounted-root boundary.
    """

    raw_path = path.strip()
    if (
        not raw_path
        or os.environ.get("DFA_CONTAINERIZED") != "1"
        or evidence_root is None
    ):
        return

    root = evidence_root.resolve()
    is_windows_host_path = bool(
        _WINDOWS_ABSOLUTE_PATH.match(raw_path) or raw_path.startswith("\\\\")
    )
    is_home_relative = raw_path == "~" or raw_path.startswith(("~/", "~\\"))
    is_external_posix_path = False
    is_missing_relative_path = False

    if raw_path.startswith("/"):
        candidate = Path(raw_path).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            is_external_posix_path = True
    elif not is_windows_host_path and not is_home_relative:
        candidate = (root / raw_path).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            # Keep traversal attempts on the regular resolver path, where
            # they are rejected instead of being reinterpreted by the host.
            return
        is_missing_relative_path = not candidate.exists()

    if not (
        is_windows_host_path
        or is_home_relative
        or is_external_posix_path
        or is_missing_relative_path
    ):
        return

    from forensic_agent.cli.host_case_handoff import request_host_case_mount

    request_host_case_mount(
        raw_path,
        run_root=run_root,
        action=action,
        model=model,
        conversation_id=conversation_id,
    )
