"""Final-answer constraints exposed to the investigation model."""

import re

from forensic_agent.agent.orchestration.recovery import _PROSE_TERMINAL_REQUEST
from forensic_agent.agent.system_prompt import SYSTEM_PROMPT


def test_answer_contract_requires_the_finding_and_its_evidentiary_support() -> None:
    prompt = " ".join(SYSTEM_PROMPT.split())

    assert "Begin the final answer directly with the requested answer" in prompt
    assert (
        "without conversational acknowledgements or sentences announcing "
        "that the question is answered"
    ) in prompt
    assert "one factual proposition directly entailed by exact values" in prompt
    assert "Name a tool or source only when that identity is itself visible" in prompt
    assert "EVERY answer carries its evidence" in prompt
    assert "That finding is the FIRST LINE and stands alone on it" in prompt
    assert "never the mechanics of your reading" in prompt
    assert "Do not add that scope narrative to a direct factual answer" in prompt
    assert "Record which artifact answered it" not in prompt


def test_the_prompt_names_the_answer_part_with_exactly_one_word() -> None:
    """The heading varied because the prompt handed the model two words for it.

    ``Evidence:`` on one answer and ``Support:`` on the next was the model
    choosing between two synonyms this prompt used interchangeably in a single
    paragraph. The word is settled as EVIDENCE, the domain's own term and the
    one the prompt already defined the other by. ``support`` survives only as a
    verb, never as the name of the part of an answer that carries the artifact
    and its value, and this test is what keeps the drift from coming back.
    """

    prompt = " ".join(SYSTEM_PROMPT.split())

    # Every noun phrase the drift used, in the forms a rewrite would reach for.
    forbidden = (
        r"\bits support\b",
        r"\bthe support\b",
        r"\bsupporting evidence\b",
        r"\bcarries its support\b",
        r"\bis not support\b",
        r"\bwith its support\b",
        r"\bthen its support\b",
    )
    for pattern in forbidden:
        assert re.search(pattern, prompt, re.IGNORECASE) is None, pattern

    # And the word that replaced it is actually there, doing that job.
    assert "state the EVIDENCE that establishes it" in prompt
    assert "The evidence is what the tools returned" in prompt


def test_the_prompt_bounds_the_evidence_and_leaves_the_heading_to_the_console() -> None:
    """The two shape rules the renderer relies on the model already following.

    A render-time cap cannot be disobeyed, but everything the model writes is
    verified claim by claim first, so a bound stated to the model is what keeps
    an inventory of empty searches from being written and checked at all. The
    heading rule is the other half of moving the label to the console: a label
    the model still writes would be printed twice.
    """

    prompt = " ".join(SYSTEM_PROMPT.split())

    assert "AT MOST THREE lines" in prompt
    assert "never an inventory of the checks that returned nothing" in prompt
    assert "Write NO heading, title, or label over either part" in prompt
    assert "the console labels them" in prompt


def test_the_prompt_keeps_call_addresses_out_of_the_answer() -> None:
    """An invocation id names a call of the run, not an artifact of the case.

    The ids are real and load-bearing: the model passes one as
    ``source_invocation_id`` to cite a value it read earlier. That is an
    argument. In a final-answer sentence it is the mechanics of the reading,
    which this prompt already forbids in general and now names outright.
    """

    prompt = " ".join(SYSTEM_PROMPT.split())

    assert "An invocation id, a result_ref, and a payload digest are ADDRESSES" in prompt
    assert "no final-answer sentence contains one" in prompt


def test_forced_final_request_defers_to_the_system_answer_contract() -> None:
    request = _PROSE_TERMINAL_REQUEST.casefold()

    assert "answer the original question" in request
    assert "final answer format in the system prompt" in request
    assert "cite" not in request
    assert "citing" not in request
    assert "tool outputs you used" not in request
