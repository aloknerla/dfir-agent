"""Prepay the whole-image entity scan as the case opens, always.

Case open prepares THE artifact the agent's entity search actually reuses: the
published default bulk_extractor scan, content-addressed by the evidence's
verified digest and the scanner's sealed version. The first entity question of
a case therefore costs nothing, and the scan itself is paid at most once per
evidence, ever. This is the ingest the established tools perform at case load —
Autopsy, AXIOM and Cyber Triage all derive their entity and text indexes when a
case is added — minus their deferred carving.

The index outlives the run deliberately. It is keyed by the evidence's own
content identity, the scanner and the scanners enabled, so a rebuild is only ever
skipped for an index taken from the same bytes by the same tool — and a second
session on the same evidence pays nothing.

The scanner set is the store's own — :data:`~forensic_agent.tools.entity_index.
ENTITY_INDEX_SCANNERS`, the recorders an entity question would be answered from
once a reader is bound — and is deliberately not restated here. The set is part
of the index's identity, so a second definition of it on the calling side would
be a second identity: this module would build an index under a key the reading
side never looks under.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rich.console import Console

#: Where indexes live when the operator has not said otherwise. It sits BESIDE the
#: per-run directories rather than inside one: an index destroyed with the run
#: that built it is the problem this module exists to fix.
INDEX_ROOT_ENVIRONMENT_VARIABLE = "DFA_INDEX_ROOT"
_INDEX_DIRECTORY_NAME = "entity-index"

#: Reported to the operator, never to the model. What it says depends on how fast
#: this host is, which has no place in a record a run claims is reproducible.
ProgressReport = Callable[[float | None, str | None], None]

#: What the operator is told this step IS, for the whole length of it. The
#: scanner announces its own phase once and then blocks inside a subprocess
#: whose output is captured rather than streamed, so that phase name would
#: appear, never be replaced, and leave a row nobody could match to a step. One
#: name held for the duration is what lets an operator tell this step from the
#: evidence digest and the memory hash that run beside it.
INDEX_STEP = "Indexing evidence"


def _named_index_step(progress: ProgressReport) -> ProgressReport:
    """Report every event of the index build under the one name the step has.

    The fraction passes through untouched: where the scan can state how far it
    got, that number is the scan's own and this wrapper has no business
    changing it, and where it cannot, ``None`` stays ``None`` rather than
    becoming a percentage nobody measured.
    """

    from forensic_agent.cli.i18n import t as _t

    label = _t(INDEX_STEP)

    def report(fraction: float | None = None, detail: str | None = None) -> None:
        del detail  # one name for the step, whatever the scanner calls its phase
        progress(fraction, label)

    return report


def index_root_for(runs_root: Path) -> Path | None:
    """Resolve the persistent index root; the logic lives with the store.

    Moved to :func:`forensic_agent.tools.entity_index.index_root_for` so the
    tools that publish persistent scan artifacts resolve the SAME root without
    importing the console; this name stays as the console-facing entry.
    """

    from forensic_agent.tools.entity_index import index_root_for as _resolve

    return _resolve(runs_root)


def index_case_evidence(
    image_path: str,
    *,
    runs_root: Path,
    evidence_sha256: str | None = None,
    progress: ProgressReport | None = None,
) -> dict[str, object]:
    """Build or reuse the entity index for one image, reporting what happened.

    Never raises and never fails the case: a case that opened without an index is
    a case with one fewer instrument, while a case that refused to open over an
    index is no case at all. The outcome is returned so the caller can say which
    of the two happened rather than leaving the operator to guess.
    """

    from forensic_agent.tools.bulk_extractor_tool import prewarm_default_scan

    del runs_root  # the store resolves its own root; kept for call parity
    return prewarm_default_scan(
        image_path,
        evidence_sha256=evidence_sha256,
        progress=progress,
    )


#: Said whenever the index is absent, and said in full every time. A case that
#: opened without it is a case whose entity questions are answered from the file
#: system alone, and an operator who is not told that reads the same confident
#: answer either way. The bare fact that a scan did not run does not carry that
#: consequence, so the consequence is spelled out rather than left to be inferred
#: from the name of a missing instrument.
INDEX_ABSENT_CONSEQUENCE = (
    "Nothing is lost; the first search will just take longer."
)


def describe_index(outcome: dict[str, object]) -> str:
    """One line an operator can read, naming what is now available and what is not."""

    state = str(outcome.get("state", ""))
    if state in {"unavailable", "failed"}:
        default = (
            "no scan directory" if state == "unavailable" else "the scan did not finish"
        )
        return (
            f"Image index NOT built: {outcome.get('detail', default)}. "
            f"{INDEX_ABSENT_CONSEQUENCE}"
        )

    # One plain sentence: what the artifact is (the image index) and the
    # fact it buys (no rescanning) — stated as what happens, not as a speed
    # promise. The category names it holds are scanner internals the agent
    # reads for itself when it searches.
    if state == "reused":
        return "Image index reused; searches skip the full scan."
    return (
        "Image index built; searches reuse it instead of rescanning the image."
    )


def index_opened_case(
    console: Console,
    *,
    image_path: str,
    runs_root: Path,
    evidence_sha256: str | None,
    progress: ProgressReport | None = None,
) -> None:
    """Index the image a case has just opened, in front of the operator.

    The scan and the line that says what became of it belong together: an index
    built silently is one the operator cannot tell from one that failed.

    Nothing here can fail the case. The index is derived from the evidence and
    never the other way round, so a scan that could not run is reported as a
    missing instrument and the case stays open — which is why the exception is
    caught at the same place the outcome is announced, rather than left to a
    caller who would have to decide again what to do about it.
    """

    try:
        if progress is not None:
            # The caller renders its own progress (a full-screen front end);
            # the console display below could not animate there anyway. The
            # step is named BEFORE the scan is asked for, because the lookup
            # that decides whether a published scan can be reused already
            # stats a directory tree, and a row that appears only once the
            # scanner starts leaves that part of the wait unaccounted for.
            named = _named_index_step(progress)
            named(None, None)
            outcome = index_case_evidence(
                image_path,
                runs_root=runs_root,
                evidence_sha256=evidence_sha256,
                progress=named,
            )
        else:
            from forensic_agent.cli.progress import reporting

            with reporting(console, "Indexing evidence") as report:
                outcome = index_case_evidence(
                    image_path,
                    runs_root=runs_root,
                    evidence_sha256=evidence_sha256,
                    progress=report,
                )
    except Exception as error:
        # Reported in the words describe_index uses for the same state: the
        # scan not finishing and the scan raising leave the case in one
        # condition, and two spellings of it read as two different things.
        _announce_index(
            console,
            f"Image index NOT built: {str(error)[:160]}. {INDEX_ABSENT_CONSEQUENCE}",
            degraded=True,
        )
        return
    _announce_index(
        console,
        describe_index(outcome),
        degraded=str(outcome.get("state", "")) in {"unavailable", "failed"},
    )


def _announce_index(console: Console, line: str, *, degraded: bool) -> None:
    """Say what became of the index in the colour that state carries elsewhere.

    A case opening without its entity index is a degraded capability, and the
    console spends one colour on exactly that, so the single sentence naming
    what this case can no longer be asked does not read like the two words of
    ordinary output above it.

    The sentence is long enough to wrap on an ordinary terminal, which is why
    it goes through ``glyphed_line``. Written as one string it wrapped back to
    column zero, where the continuation carried neither the glyph nor, in the
    full-screen console, the colour that made the warning a warning. It is
    passed as ``Text`` rather than as markup because the reason is host text,
    and a bracket in it would otherwise be read as a style tag and disappear.
    """

    from rich.text import Text

    from forensic_agent.cli.terminal import (
        DIM,
        GLYPH_OK,
        GLYPH_WARN,
        ORANGE,
        SUCCESS,
        glyphed_line,
    )

    glyph, colour, body = (
        (GLYPH_WARN, ORANGE, ORANGE) if degraded else (GLYPH_OK, SUCCESS, DIM)
    )
    console.print(glyphed_line(glyph, colour, Text(line, style=body)))
