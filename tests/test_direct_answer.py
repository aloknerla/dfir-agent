"""A single direct factual question is answered in one plain sentence.

The classifier drives a STEER-ONLY rewrite: when a recovery arm re-drove the
model and its acknowledgement of that nudge ("I have now read everything", "the
list is complete") prefixed or replaced the found value, the run reissues a
reserved terminal turn asking for the fact alone. Nothing here gates publication
— a draft that stays verbose is still published — so the contract is read only
to decide whether one clean restatement is worth asking for.
"""

from __future__ import annotations

import pytest

from forensic_agent.agent.direct_answer import (
    is_atomic_direct_answer,
    is_single_direct_factual_question,
)


@pytest.mark.parametrize(
    "question",
    [
        "What is the computer name?",
        "Koje je ime računala?",
        "Tko se posljednji prijavio na računalo?",
        "Koja je SMTP adresa e-pošte postavljena za osumnjičenika?",
        "Koja je Yahoo adresa e-pošte glavnog korisnika?",
    ],
)
def test_a_single_direct_factual_question_is_recognized(question: str) -> None:
    assert is_single_direct_factual_question(question) is True


@pytest.mark.parametrize(
    "question",
    [
        "Navedite mrežne kartice koje računalo koristi.",  # list, no interrogative
        "Koliko je ukupno korisničkih računa na sustavu?",  # "how many" list cue
        "Koje su NNTP postavke (poslužitelj vijesti) osumnjičenika?",  # plural "su"
        "Kada je zabilježeno posljednje gašenje (datum i vrijeme)?",  # "i" multipart
        "Jesu li datoteke stvarno izbrisane ili se mogu oporaviti?",  # "ili" multipart
        "Zašto je datoteka izbrisana?",  # why
        "Kako je preneseno?",  # how
        "What is the account and its SID?",  # requests additional context
    ],
)
def test_a_list_multipart_or_why_how_question_is_not_a_single_direct_one(
    question: str,
) -> None:
    assert is_single_direct_factual_question(question) is False


@pytest.mark.parametrize(
    "answer",
    [
        "The computer name is WS-EXAMPLE-07.",
        "Ime računala je WS-EXAMPLE-07.",
        "Posljednje gašenje bilo je 2004-08-27 15:46:33 UTC.",
    ],
)
def test_one_plain_sentence_with_only_the_fact_is_atomic(answer: str) -> None:
    assert is_atomic_direct_answer(answer, claim_count=1) is True


@pytest.mark.parametrize(
    "answer",
    [
        # reading / process narration that a re-driven model produced
        "Provjerio sam sve pozive. Svi zapisi su u potpunosti pročitani.",
        "Sada je pokrivenost potpuna. Ime računala je WS-EXAMPLE-07.",
        # source narration
        "The computer name WS-EXAMPLE-07 was obtained from the SYSTEM hive.",
        "Ime računala je WS-EXAMPLE-07, prema vrijednosti u SYSTEM hivu.",
        # a bullet list
        "- Xircom\n- Compaq WL110",
    ],
)
def test_narration_source_or_multi_sentence_answers_are_not_atomic(answer: str) -> None:
    claim_count = 1 if len(answer.splitlines()) == 1 and answer.count(".") <= 1 else 2
    assert is_atomic_direct_answer(answer, claim_count=claim_count) is False


def test_an_honest_unestablished_answer_is_atomic_not_a_rewrite_target() -> None:
    """This project's deliberate divergence from the codex origin: the reformat
    only steers, and the terminal request itself tells the model to state that
    the evidence does not establish the answer in one sentence — so that exact
    honest sentence must count as atomic, never trigger a pointless rewrite."""

    for answer in (
        "The time zone cannot be determined from the available evidence.",
        "Vremenska zona se ne može utvrditi iz dostupnih dokaza.",
    ):
        assert is_atomic_direct_answer(answer, claim_count=1) is True
