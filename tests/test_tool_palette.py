"""Every implemented tool must be offered to the model by some palette.

``memory_strings`` was classified, contracted and capability-granted while no
function defined it and no palette named it.  Nothing failed.  The only symptom
was a tool that was never called across an entire evaluation, which reads
exactly like a model choosing not to use it — so the measurement was short a
capability and said nothing about being short.

The rules below close that class rather than that instance, and each is checked
at import by the module it belongs to; these tests pin the rules themselves and,
just as importantly, show them failing.  A guard only ever run on input already
known to pass is a guard nobody has watched work.

There was no test file for the palette before this one.
"""

from __future__ import annotations

from itertools import product
from typing import get_args

from forensic_agent.agent.tool_contract import (
    accounted_tool_names,
    orphaned_tool_names,
)
from forensic_agent.agent.tool_operations import DOMAIN_FUNCTIONS
from forensic_agent.agent.tool_palette import (
    HISTORICAL_MEMORY_TOOLS,
    HISTORICAL_PCAP_TOOLS,
    NAVIGATION_FUNCTIONS,
    WITHHELD_FROM_EVERY_PALETTE,
    DiskFamily,
    reachable_functions,
    tools_for_evidence_sources,
    unimplemented_palette_names,
    unreachable_functions,
)
from forensic_agent.core.tool_availability import QUARANTINED_MODEL_TOOL_NAMES

# ---------------------------------------------------------------------------
# The rule: implemented implies reachable.
# ---------------------------------------------------------------------------


def test_every_implemented_tool_is_offered_by_some_palette() -> None:
    """The failure names the tool, so the next person reads what went wrong."""

    unreachable = unreachable_functions()
    assert not unreachable, (
        "implemented and offered by no palette, so no run can call "
        f"{sorted(unreachable)}: add each to the live palette of the evidence it "
        "reads, or declare it in WITHHELD_FROM_EVERY_PALETTE with a reason"
    )


def test_the_reachability_rule_actually_catches_an_unreachable_tool() -> None:
    """The same check, on a tool that is implemented and offered nowhere."""

    assert unreachable_functions(
        {"ghost_tool"}, reachable=set(), withheld=set()
    ) == frozenset({"ghost_tool"})
    # ...and a declared withhold is the one thing that excuses it.
    assert not unreachable_functions(
        {"ghost_tool"}, reachable=set(), withheld={"ghost_tool"}
    )


def test_reach_is_taken_from_the_palette_itself_not_from_its_declarations() -> None:
    """A declared set the function body never consults offers nothing.

    Unioning the declarations would call such a tool reachable; asking the
    palette, once per evidence combination, is what makes the answer true.
    """

    asked: set[str] = set()
    for disk_available, disk_family, memory_available, pcap_available in product(
        (True, False), get_args(DiskFamily), (True, False), (True, False)
    ):
        asked |= tools_for_evidence_sources(
            disk_available=disk_available,
            disk_family=disk_family,
            memory_available=memory_available,
            pcap_available=pcap_available,
        )
    assert reachable_functions() == frozenset(asked)


# ---------------------------------------------------------------------------
# The reverse rule: a palette may not name what nothing implements.
# ---------------------------------------------------------------------------


def test_every_name_a_palette_offers_is_implemented() -> None:
    dangling = unimplemented_palette_names()
    assert not dangling, (
        f"the palette offers {sorted(dangling)} and no function implements them; "
        "a run intersects the palette with what the registry built, so the model "
        "is silently handed fewer functions than the palette promises"
    )


def test_the_reverse_rule_actually_catches_a_renamed_away_tool() -> None:
    assert unimplemented_palette_names(
        {"renamed_away"}, implemented=set()
    ) == frozenset({"renamed_away"})


def test_the_navigation_function_is_offered_and_is_not_a_domain_function() -> None:
    """It is the one legitimate palette name the registry does not build.

    The model surface assembles it, so the reverse rule has to admit it — and
    admitting it is only safe because it is proven not to be a domain function.
    """

    assert NAVIGATION_FUNCTIONS <= reachable_functions()
    assert NAVIGATION_FUNCTIONS.isdisjoint(DOMAIN_FUNCTIONS)


# ---------------------------------------------------------------------------
# The exception set is explicit, reasoned, and about implemented tools only.
# ---------------------------------------------------------------------------


def test_every_withheld_tool_carries_a_written_reason() -> None:
    for name, reason in WITHHELD_FROM_EVERY_PALETTE.items():
        assert reason.strip(), name
        # A reason, not a label: one word restates the decision instead of
        # justifying it, and the point of the table is that the exception costs
        # a sentence.
        assert len(reason.split()) >= 8, name


def test_a_withheld_tool_is_one_that_exists() -> None:
    """Withholding names an implemented function; a name nothing implements is
    a withdrawal and belongs in the quarantine table instead."""

    assert frozenset(WITHHELD_FROM_EVERY_PALETTE) <= frozenset(DOMAIN_FUNCTIONS)


def test_withheld_and_withdrawn_are_different_registers_and_stay_apart() -> None:
    assert frozenset(WITHHELD_FROM_EVERY_PALETTE).isdisjoint(QUARANTINED_MODEL_TOOL_NAMES)
    # A function the registry defines is built and offered, so a quarantine
    # entry for it is stale by construction. memory_strings was exactly that.
    assert QUARANTINED_MODEL_TOOL_NAMES.isdisjoint(DOMAIN_FUNCTIONS)


# ---------------------------------------------------------------------------
# The frozen historical palettes are history, never a way to satisfy the rule.
# ---------------------------------------------------------------------------


def test_the_historical_palettes_do_not_count_towards_reach() -> None:
    """A tool only history ever offered is unreachable, and must read as such.

    Counting the historical surface would let ``memory_strings`` have "passed"
    on the strength of a palette no run can select. The fix for an unreachable
    tool is a live palette entry; the frozen record is never widened.
    """

    historical: set[str] = set()
    for disk_available, disk_family, memory_available, pcap_available in product(
        (True, False), get_args(DiskFamily), (True, False), (True, False)
    ):
        historical |= tools_for_evidence_sources(
            disk_available=disk_available,
            disk_family=disk_family,
            memory_available=memory_available,
            pcap_available=pcap_available,
            include_quarantined_tools=True,
        )
    # The historical surface really does carry names the live one does not, so
    # this exclusion is load-bearing rather than theoretical.
    assert frozenset(historical) - reachable_functions()
    assert reachable_functions().isdisjoint(frozenset(historical) - reachable_functions())


def test_the_frozen_historical_memory_palette_is_not_widened() -> None:
    """It records what those runs were offered, and they were not offered this."""

    assert HISTORICAL_MEMORY_TOOLS == frozenset({"memory_query", "memory_malware_scan"})
    assert HISTORICAL_PCAP_TOOLS == frozenset({"pcap_query"})
    assert "memory_strings" not in HISTORICAL_MEMORY_TOOLS
    # ...while the live palette does offer it.
    assert "memory_strings" in reachable_functions()


# ---------------------------------------------------------------------------
# One level up: a name the tables call a tool that nothing implements at all.
# ---------------------------------------------------------------------------


def test_no_table_calls_something_a_tool_that_nothing_defines_or_withdraws() -> None:
    orphans = orphaned_tool_names()
    assert not orphans, "; ".join(
        f"{name} is treated as a model tool by {', '.join(where)} and nothing "
        "defines, supersedes or withdraws it"
        for name, where in sorted(orphans.items())
    )


def test_the_orphan_rule_catches_the_state_memory_strings_was_actually_in() -> None:
    """Classified, contracted and capability-granted; defined and offered by nothing.

    This is the check that would have failed on the day the name was added, and
    the one the palette rule above cannot make: a name with no implementation is
    not among the functions that rule examines.
    """

    orphans = orphaned_tool_names(
        tables={
            "the tool taxonomy": frozenset({"memory_strings"}),
            "the result-contract data types": frozenset({"memory_strings"}),
            "the capability map": frozenset({"memory_strings"}),
        },
        accounted=frozenset({"memory_query", "memory_malware_scan"}),
    )
    assert set(orphans) == {"memory_strings"}
    # The failure names where the claim is written, not only that one exists.
    assert orphans["memory_strings"] == (
        "the capability map",
        "the result-contract data types",
        "the tool taxonomy",
    )
    # Defining it is what clears it.
    assert not orphaned_tool_names(
        tables={"the tool taxonomy": frozenset({"memory_strings"})},
        accounted=frozenset({"memory_strings"}),
    )


def test_every_accounted_name_has_exactly_one_kind_of_disposition() -> None:
    """Defined, superseded and withdrawn are answers to different questions.

    A name in two of them is a contradiction the run resolves by accident: the
    registry builds it while a table says it was withheld, or the classifier
    reads it as a legacy name while the facade dispatches it as a live one.
    """

    from forensic_agent.agent.tool_operations import LEGACY_FUNCTION_DISPOSITIONS

    superseded = frozenset(LEGACY_FUNCTION_DISPOSITIONS)
    assert QUARANTINED_MODEL_TOOL_NAMES.isdisjoint(DOMAIN_FUNCTIONS)
    assert QUARANTINED_MODEL_TOOL_NAMES.isdisjoint(superseded)
    assert accounted_tool_names() >= frozenset(DOMAIN_FUNCTIONS)
