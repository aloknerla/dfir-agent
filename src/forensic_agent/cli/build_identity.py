"""Which build of this console is actually running, in words an operator can act on.

The package version answers a different question. ``v0.1.0`` is chosen by hand
and changes when someone decides to change it, so two images built a week apart
from two different trees carry the same string. That gap has a cost measured in
whole days: defects already fixed in the checkout were reported again because the
image on the operator's machine predated the fix and nothing on screen said so.

What a build can honestly know about itself, in the order this module tries it:

* **What the launcher was told.** The host launcher can ask Docker for the image
  it is about to run and pass the answer in. This is the only source that names
  the *image*, and it needs nothing baked in at build time — ``docker image
  inspect`` already records an id and a creation timestamp for every image, so a
  running container can be told which one it came out of.
* **When the installed code was written.** Failing that, the modification time of
  the installed package is the moment the image layer holding it was built. It
  cannot name a commit, but it dates the code, which is the question a stale
  image actually raises.
* **Which commit the checkout is on.** Running from source there is no image at
  all, and the short commit is both available and exact.

Each answer is labelled with which of the three it is. A timestamp presented as
if it were a commit would be worse than printing nothing: the operator would
compare it against a commit and conclude the build was current.

Nothing here may raise. A console that cannot work out what it is still has to
start, and every lookup below is best-effort by construction.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime

#: Set by the host launcher from ``docker image inspect``. Short image id.
ENV_BUILD_ID = "DFA_BUILD_ID"
#: Set by the host launcher from ``docker image inspect``. RFC 3339 creation time.
ENV_BUILD_TIME = "DFA_BUILD_TIME"


@dataclass(frozen=True)
class BuildIdentity:
    """What is known about the running build, and how it came to be known.

    ``label`` is the short string a status line shows. ``source`` names which of
    the three lookups produced it, so a caller that has room can say whether it
    is looking at an image, a file date or a commit.
    """

    label: str
    source: str
    detail: str = ""
    #: Epoch seconds the build was produced, when that is knowable. Only the
    #: image and mtime lookups can date a build; a commit id cannot be turned
    #: into a date without the repository, so ``None`` is the honest answer
    #: there and :func:`staleness_note` stays quiet rather than guessing.
    moment: float | None = None

    def __str__(self) -> str:
        return self.label


def _clean(value: str | None) -> str:
    return (value or "").strip()


def _short_digest(value: str) -> str:
    """A docker image id, reduced to the twelve characters docker itself shows."""

    digest = value.removeprefix("sha256:")
    return digest[:12] if digest else ""


def _readable_moment(value: str) -> str:
    """An RFC 3339 timestamp as a date and a time, or "" if it is neither.

    Docker returns nanosecond precision, which :func:`datetime.fromisoformat`
    rejects on every Python this project supports, so the fractional part is
    dropped before parsing rather than after failing.
    """

    text = _clean(value)
    if not text:
        return ""
    normalised = text.replace("Z", "+00:00")
    if "." in normalised:
        head, _, tail = normalised.partition(".")
        # Keep whatever offset followed the fraction; drop the fraction itself.
        for index, character in enumerate(tail):
            if not character.isdigit():
                normalised = head + tail[index:]
                break
        else:
            normalised = head
    try:
        moment = datetime.fromisoformat(normalised)
    except ValueError:
        return ""
    if moment.tzinfo is not None:
        moment = moment.astimezone()
    return moment.strftime("%Y-%m-%d %H:%M")


def _epoch(value: str) -> float | None:
    """An RFC 3339 timestamp as epoch seconds, or ``None`` if it is not one."""

    text = _clean(value)
    if not text:
        return None
    normalised = text.replace("Z", "+00:00")
    if "." in normalised:
        head, _, tail = normalised.partition(".")
        for index, character in enumerate(tail):
            if not character.isdigit():
                normalised = head + tail[index:]
                break
        else:
            normalised = head
    try:
        moment = datetime.fromisoformat(normalised)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.timestamp()


def _from_launcher() -> BuildIdentity | None:
    """The image the launcher started, as the launcher read it from Docker."""

    identifier = _short_digest(_clean(os.environ.get(ENV_BUILD_ID)))
    when = _readable_moment(_clean(os.environ.get(ENV_BUILD_TIME)))
    if not identifier and not when:
        return None
    stamp = _epoch(_clean(os.environ.get(ENV_BUILD_TIME)))
    if identifier and when:
        return BuildIdentity(f"build {identifier}, {when}", "image", when, stamp)
    if identifier:
        return BuildIdentity(f"build {identifier}", "image")
    return BuildIdentity(f"build {when}", "image", when, stamp)


def _from_source_tree() -> BuildIdentity | None:
    """The checkout's own commit, for a console run straight from the tree.

    Only attempted outside a container: a container holds a copy of the source
    without the repository, so the lookup would be a subprocess that always
    fails, on the startup path, for nothing.
    """

    if os.environ.get("DFA_CONTAINERIZED") == "1":
        return None
    import subprocess
    from pathlib import Path

    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / ".git").exists():
            break
    else:
        return None
    try:
        finished = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(parent),
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except Exception:
        return None
    commit = _clean(finished.stdout)
    if finished.returncode != 0 or not commit:
        return None
    return BuildIdentity(f"build {commit}", "commit", commit)


def _from_package_mtime() -> BuildIdentity | None:
    """When the installed code was last written, which dates the image layer."""

    from pathlib import Path

    try:
        marker = Path(__file__).resolve().parent.parent / "__init__.py"
        stamp = marker.stat().st_mtime
    except Exception:
        return None
    moment = datetime.fromtimestamp(stamp, tz=UTC).astimezone()
    when = moment.strftime("%Y-%m-%d %H:%M")
    return BuildIdentity(f"build {when}", "mtime", when, stamp)


def build_identity() -> BuildIdentity | None:
    """The best honest answer to "which build is this?", or ``None``.

    ``None`` means every lookup came back empty, which is a real outcome and not
    an error: a caller shows the package version alone rather than inventing a
    build. To make ``None`` impossible the launcher has to supply
    :data:`ENV_BUILD_ID`; nothing inside the image can name the image it is in.
    """

    for lookup in (_from_launcher, _from_source_tree, _from_package_mtime):
        try:
            found = lookup()
        except Exception:
            found = None
        if found is not None:
            return found
    return None


def build_label() -> str:
    """:func:`build_identity` as a bare string, empty when nothing is known."""

    found = build_identity()
    return found.label if found is not None else ""


#: How old a build has to be before the console says so. A fortnight, because
#: the defect this exists for is an operator reporting a bug that was fixed
#: days ago from an image they have not rebuilt — and because a threshold short
#: enough to fire on a build from this morning would train them to ignore it.
STALE_AFTER_DAYS: int = 14


def staleness_note(now: float | None = None) -> str:
    """A sentence for an operator running an old build, or "" for a current one.

    Empty is the normal answer and the whole point of the function: an operator
    on a fresh build is told nothing, so the one time this does speak, it means
    something. It also stays empty when the build cannot be dated at all —
    a console that does not know how old it is has nothing to warn about.
    """

    import time

    found = build_identity()
    if found is None or found.moment is None:
        return ""
    days = ((now if now is not None else time.time()) - found.moment) / 86400
    if days < STALE_AFTER_DAYS:
        return ""
    weeks = int(days // 7)
    age = f"{weeks} weeks old" if weeks > 1 else f"{int(days)} days old"
    return (
        f"This console is {age}. Fixes made since then are not in it. "
        "Rebuild before reporting a problem, in case it is already solved."
    )
