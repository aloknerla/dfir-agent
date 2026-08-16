"""Saying where a file went in a path the operator can actually open.

Inside the container the exports land in ``/runtime/exports`` and the evidence
is read from ``/evidence``. Both are bind mounts, so both correspond to a real
directory on the operator's machine — but the correspondence exists only in the
launcher's arguments. Nothing inside the container can see a mount's source, so
a console that prints its own paths back is telling an operator to open a
directory that does not exist on their computer.

The launcher therefore states the two host roots as environment variables, and
this module is the one place that reads them. Two properties are deliberate:

* **Translation is presentation only.** Every path the console *uses* stays the
  container path; only the string shown to a person is rewritten. A host path
  that reached a tool, a receipt or the model would be a path that machine
  cannot open.
* **An untranslatable path says so.** With no host root the fallback is not to
  print ``/runtime/exports`` bare and let the operator hunt for it, but to name
  it as being inside the container, which is a true statement and a different
  instruction.
"""

from __future__ import annotations

import os
from pathlib import PurePosixPath

#: Host directory bind-mounted at ``/runtime``; the launcher's ``RUNS``.
ENV_HOST_RUNS = "DFA_HOST_RUNS"
#: Host directory (or file's directory) bind-mounted at ``/evidence``.
ENV_HOST_EVIDENCE = "DFA_HOST_EVIDENCE"

#: The container-side mount points those two variables correspond to.
CONTAINER_RUNS = "/runtime"
CONTAINER_EVIDENCE = "/evidence"


def containerized() -> bool:
    return os.environ.get("DFA_CONTAINERIZED") == "1"


def _root(name: str) -> str:
    return (os.environ.get(name) or "").strip().rstrip("/\\")


def host_runs_root() -> str:
    """The host directory mounted at ``/runtime``, or "" when unstated."""

    return _root(ENV_HOST_RUNS)


def host_evidence_root() -> str:
    """The host directory mounted at ``/evidence``, or "" when unstated."""

    return _root(ENV_HOST_EVIDENCE)


def _join_host(root: str, relative: str) -> str:
    """Append a container-relative tail to a host root in the host's own style."""

    if not relative:
        return root
    separator = "\\" if ("\\" in root or (len(root) > 1 and root[1] == ":")) else "/"
    tail = relative.replace("/", separator)
    return f"{root}{separator}{tail}"


def host_path(path: object) -> str:
    """The host path for a container path, or "" when it cannot be worked out.

    Only the two known mounts are translated. A path under neither of them —
    ``/tmp``, ``/app``, anything the image owns — has no host counterpart at all,
    and guessing one would be worse than admitting it.
    """

    text = str(path).strip()
    if not text or not containerized():
        return ""
    if not text.startswith("/"):
        return ""
    for mount, root in (
        (CONTAINER_RUNS, host_runs_root()),
        (CONTAINER_EVIDENCE, host_evidence_root()),
    ):
        if not root:
            continue
        pure = PurePosixPath(text)
        try:
            relative = pure.relative_to(mount)
        except ValueError:
            continue
        return _join_host(root, str(relative) if str(relative) != "." else "")
    return ""


def display_path(path: object) -> str:
    """One path, written the way the operator should read it.

    Outside a container this is the path itself. Inside one it is the host path
    when the mount is known, and otherwise the container path marked as such, so
    the operator is never handed a string that looks openable and is not.
    """

    text = str(path)
    if not containerized():
        return text
    translated = host_path(text)
    if translated:
        return translated
    return f"{text} (not reachable from your computer)"


def path_is_container_only(path: object) -> bool:
    """True when :func:`display_path` had to fall back to the container path."""

    return containerized() and not host_path(path)
