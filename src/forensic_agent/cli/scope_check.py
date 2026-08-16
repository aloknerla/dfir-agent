"""The model's own scope triage, asked before an investigation is minted.

The console refuses input that is not about the loaded case, and the
decision is the model's: one small request to the SAME configured model
asks whether the input concerns the case or the investigation of it. A
word list used to sit here and was removed for the reason word lists
always fail — exact matches were refused while near-misses sailed past,
and the two outcomes side by side read as arbitrary.

This rail complements, not replaces, the prompt's SCOPE OF SERVICE
section: input the triage lets through is still answered under that rule
and under the publication gates, which withhold any answer that cites no
case evidence. The triage exists so an off-case question is refused in
one cheap request — before a run directory, a trace id and a budget are
spent — and so the refusal reads as one clean sentence instead of a
blocked-gate diagnostic.

FAIL-OPEN by construction: a triage that cannot be made (provider down,
timeout, unexpected reply) never blocks a question. The cost of a false
pass is one wasted run; the cost of a false refusal is an operator's
real question going unanswered, and the guardrail literature is blunt
about which is worse.

The rail can also be taken out entirely with ``DFA_SCOPE_TRIAGE=0``. It
asks the SAME model the investigation will use, so a comparison between
models measures the triage alongside the investigation: a weaker model
that refuses a legitimate follow-up never reaches the work it was being
compared on. Off, no request is made at all and every question is in
scope; the run records the setting so the two configurations cannot be
mistaken for one another.
"""

from __future__ import annotations

from forensic_agent.core.environ import scope_triage_enabled

#: Shown to the operator when the triage refuses. The SAME sentence the
#: prompt's SCOPE OF SERVICE section instructs the model to use, so the
#: refusal reads identically whichever rail caught it.
SCOPE_REFUSAL_NOTICE = (
    "This console answers only questions about the loaded case; "
    "ask about its files, users, activity or other artifacts."
)

#: The triage instruction. Follow-up turns and console questions are
#: named in scope, and the tie-break is ONTOPIC — over-blocking is the
#: documented failure mode of topical rails, not under-blocking.
SCOPE_CLASSIFIER_PROMPT = (
    "You triage operator input for a digital-forensics investigation console "
    "that has a forensic case loaded. Decide whether the input is IN SCOPE. "
    "In scope: any question or instruction about the loaded evidence — its "
    "files, users, accounts, programs, devices, network activity, timestamps "
    "or other artifacts — and any question about the investigation itself, "
    "its tools, its findings, or a follow-up to an earlier investigation "
    "turn, in any language. "
    "Out of scope: requests unrelated to the case — general knowledge, "
    "current events, arithmetic for its own sake, coding help, opinions, "
    "small talk, creative writing. "
    "Reply with exactly one word: ONTOPIC or OFFTOPIC. If unsure, reply "
    "ONTOPIC."
)


def question_in_scope(
    question: str,
    *,
    model: str,
    base_url: str,
    api_key: str,
) -> bool:
    """Whether the model reads this input as being about the loaded case.

    True unless the model plainly says OFFTOPIC. Every failure — import,
    connection, timeout, an answer in neither word — is True: the rail
    refuses questions, never availability.

    With the rail switched off no client is constructed and no request is
    made: the answer is True before anything that could reach a provider,
    so a comparison run under ``DFA_SCOPE_TRIAGE=0`` spends nothing here
    and cannot be perturbed by a triage verdict it never asked for.
    """

    if not scope_triage_enabled():
        return True

    try:
        from langchain_openai import ChatOpenAI
        from pydantic import SecretStr

        client = ChatOpenAI(
            model=model,
            base_url=base_url,
            # The field is a SecretStr; a bare string only reaches it through
            # the validator that wraps it in exactly this.
            api_key=SecretStr(api_key),
            timeout=25,
            max_retries=0,
            # A triage verdict must not vary between identical inputs;
            # sampling variance is exactly how one recipe question passed
            # while the next was refused.
            temperature=0,
        )
        reply = client.invoke(
            [
                ("system", SCOPE_CLASSIFIER_PROMPT),
                ("user", question),
            ]
        )
        content = reply.content
        if isinstance(content, list):  # some providers return content blocks
            content = " ".join(
                str(block.get("text", block) if isinstance(block, dict) else block)
                for block in content
            )
        verdict = str(content or "").upper()
        return "OFFTOPIC" not in verdict
    except Exception:
        return True


__all__ = [
    "SCOPE_CLASSIFIER_PROMPT",
    "SCOPE_REFUSAL_NOTICE",
    "question_in_scope",
]
