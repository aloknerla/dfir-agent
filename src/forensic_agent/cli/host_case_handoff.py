"""Narrow host-launcher handoff for evidence paths outside a Docker mount.

Docker bind mounts cannot be added to a running container.  When an interactive
user enters an absolute host path, the console records that path in the
persistent runtime directory and exits with a dedicated status.  The trusted
host launcher validates the request, mounts only the selected source read-only,
and starts the console again with the corresponding container path.
"""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import NoReturn

HOST_CASE_HANDOFF_SCHEMA = "dfir-agent-host-case-v3"
HOST_CASE_HANDOFF_EXIT_CODE = 75
_TOKEN_PATTERN = re.compile(r"^[a-f0-9]{32}$")
_CASE_ACTIONS = frozenset({"case", "disk", "memory", "network"})
_ATTACH_ACTIONS = frozenset(
    {
        "attach-disk",
        "attach-memory",
        "attach-network",
    }
)
_ACTIONS = _CASE_ACTIONS | _ATTACH_ACTIONS
_BIDI_CONTROLS = frozenset(
    {
        "\u061c",
        "\u200e",
        "\u200f",
        "\u202a",
        "\u202b",
        "\u202c",
        "\u202d",
        "\u202e",
        "\u2066",
        "\u2067",
        "\u2068",
        "\u2069",
    }
)


def _contains_unsafe_terminal_character(value: str) -> bool:
    return any(
        ord(character) < 32
        or 127 <= ord(character) <= 159
        or character in _BIDI_CONTROLS
        for character in value
    )


def request_host_case_mount(
    host_path: str,
    *,
    run_root: Path,
    action: str = "case",
    model: str,
    conversation_id: str = "",
) -> NoReturn:
    """Write one authenticated host-path request and end the container process."""

    value = host_path.strip()
    if not value or _contains_unsafe_terminal_character(value):
        raise ValueError("The case path is empty or contains a control character.")
    selected_model = model.strip()
    if (
        not selected_model
        or selected_model.startswith("-")
        or any(character.isspace() for character in selected_model)
        or _contains_unsafe_terminal_character(selected_model)
    ):
        raise ValueError("The active model identifier is invalid.")
    normalized_action = action.strip().casefold()
    if normalized_action not in _ACTIONS:
        raise ValueError("The host-path handoff action is invalid.")
    selected_conversation = (conversation_id or "").strip()
    if selected_conversation and (
        selected_conversation.startswith("-")
        or any(character.isspace() for character in selected_conversation)
        or _contains_unsafe_terminal_character(selected_conversation)
    ):
        raise ValueError("The active investigation identifier is invalid.")

    request_value = os.environ.get("DFA_HOST_CASE_REQUEST_FILE", "").strip()
    token = os.environ.get("DFA_HOST_CASE_REQUEST_TOKEN", "").strip()
    if not request_value or not _TOKEN_PATTERN.fullmatch(token):
        raise ValueError(
            "This Docker session cannot mount a new host path. Start it with the "
            "installed dfir-agent launcher, or open the path when starting the agent."
        )

    request_path = Path(request_value).resolve()
    permitted_root = Path(run_root).resolve()
    try:
        request_path.relative_to(permitted_root)
    except ValueError as exc:
        raise ValueError("The host-path handoff file is outside the runtime directory.") from exc

    request_path.parent.mkdir(parents=True, exist_ok=True)
    payload = (
        f"{HOST_CASE_HANDOFF_SCHEMA}\n{token}\n{normalized_action}\n"
        f"{selected_model}\n{selected_conversation}\n{value}\n"
    )
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{request_path.name}.",
        suffix=".tmp",
        dir=request_path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, request_path)
        try:
            os.chmod(request_path, 0o600)
        except OSError:
            pass
    finally:
        temporary.unlink(missing_ok=True)

    raise SystemExit(HOST_CASE_HANDOFF_EXIT_CODE)
