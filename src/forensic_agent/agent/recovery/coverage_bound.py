"""Compose the coverage-scope limit a run failed to state, from records it holds.

One reading of "which regions of this evidence went unread, and how to say so",
shared by every gate that has to decide what a run may publish when its coverage
was incomplete.  The absence gate in
:mod:`forensic_agent.agent.orchestration.finalization` and the two recovery gates
in :mod:`forensic_agent.agent.orchestration.recovery` all reach for it, so a
report one gate qualifies with a stated bound and a report another gate withholds
cannot end up described by two subtly different sentences about the same fact.

The bound is composed by the runtime rather than asked of the model, for the same
reason every other value in a published answer is: a bound the model composes is a
bound the model could get wrong, and this one exists precisely because the model
did not notice it.  It names a REGION and a bundle, never a tool and never a next
step, so it states what was not examined without telling the model how the
examination should have been carried out.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from forensic_agent.agent.evidence_regions import unread_regions


def _tool_names(tools: Iterable[object]) -> tuple[str, ...]:
    """The model-visible names of the functions this run was given."""

    return tuple(
        name
        for name in (getattr(tool, "name", None) for tool in tools)
        if isinstance(name, str) and name
    )


def unread_region_labels(
    records: Sequence[Mapping[str, Any]], *, tools: Iterable[object]
) -> tuple[str, ...]:
    """Name the regions this run's own tools could have opened and did not.

    The region's human ``label`` is used rather than its ``name``: the label is
    the phrase the runtime already states to the model elsewhere, and reusing it
    keeps one wording for one fact.  Recomputed from the records the run finished
    with, so a region a late recovery stage opened is no longer reported as a gap.
    """

    return tuple(
        region.label for region in unread_regions(records, tools=_tool_names(tools))
    )


def bound_stated_for(
    regions: tuple[str, ...],
    *,
    bundle_truncated: bool = False,
    bundle_included: int | None = None,
    bundle_source: int | None = None,
    bundle_shortened: int | None = None,
) -> str:
    """Compose the coverage limit the report failed to state, or ``""`` for none.

    Two clauses, either or both: the regions of the medium this run never opened,
    and — where a final check reasoned over a bundle that omitted or shortened
    results — that its negative conclusions are bounded by what the bundle
    actually carried.  An empty string means there is no limit to state, not
    that one was withheld.
    """

    parts: list[str] = []
    if regions:
        listed = ", ".join(sorted(regions))
        parts.append(
            "Coverage for this run is incomplete: "
            f"{listed} {'was' if len(regions) == 1 else 'were'} not read, so "
            "anything reported above as not present is bounded by that limit."
        )
    if bundle_truncated:
        # A truncated set is stated WITH its numbers where the caller holds
        # them: how many findings the check saw, of how many, and how many it
        # shortened.  A bare adjective would leave the reader to guess how much
        # of the run the negative conclusions actually rest on.
        counts = ""
        if isinstance(bundle_included, int) and isinstance(bundle_source, int):
            shortened = bundle_shortened if isinstance(bundle_shortened, int) else 0
            counts = (
                f" (it carried {bundle_included} of {bundle_source} usable "
                f"results; {shortened} shortened)"
            )
        parts.append(
            "The final check also reasoned from a truncated evidence bundle "
            f"that omitted or shortened results{counts}, so its negative "
            "conclusions are bounded as well."
        )
    return " ".join(parts)


__all__ = ["bound_stated_for", "unread_region_labels"]
