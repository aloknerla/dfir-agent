"""What one question becomes on its way to the model: its controls and its framing.

Two decisions stand between a question the operator typed and the request that
carries it, and both of them have to be made again for every question rather than
once at startup.

The first is the set of controls the run is built under — which model, at which
endpoint, how many steps it may take, how much reasoning it is asked for, and
which Volatility material the host has. The reasoning effort in particular is
read at the moment a runner is built, because ``/effort`` takes effect by
discarding the cached runner: a value pinned when the console started would mean
the operator's choice applied only after a restart.

The second is the framing wrapped around the question when earlier turns are
carried into it. That framing is not phrasing but policy: it tells the model to
resolve references against the session context while revalidating every
case-specific claim through a tool, and never to treat one of its own prior
answers as evidence. It is the one instruction that keeps a conversation from
laundering an unverified answer into a premise. This module no longer authors it:
the wrapper is owned by ``agent.model_surface.frame_question_with_context`` — the
single home for the context-carrying question text the model reads — and this
module only chooses the session-context variant of the guidance and hands the
history to it.

Both are pure functions of what they are given. Neither reads the session, and
neither touches the evidence, the history or anything a run mutates — which is
what makes it possible to check what a question was sent with, without sending
one.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, Final

import forensic_agent.cli.reasoning as _reasoning
from forensic_agent.core.environ import scope_triage_enabled

if TYPE_CHECKING:
    from forensic_agent.cli.controlled import ControlledInvestigationSession

#: The interactive console's topical guardrail, stated to the model as one
#: prompt section. Scope plus an exact refusal sentence is the documented
#: shape for a domain-limited assistant (Azure OpenAI system-message
#: guidance; topical-rail practice), and the carve-out for questions about
#: the investigation itself is the standard defence against over-blocking.
#: The refusal is instructed to use no tools, so a declined question comes
#: back as a zero-tool-call run — which the console shows as an unnumbered
#: note and does not count as an exchange. Interactive-only by placement:
#: evaluation runs build the base session and never read this.
#: Environment variable naming interactive-only disabled tools, comma
#: separated. Read through :func:`disabled_tool_names` everywhere — the
#: prompt palette and every console display must subtract the same set.
DISABLED_TOOLS_ENVIRONMENT_VARIABLE = "DFA_DISABLED_TOOLS"

#: Functions the console keeps out of the palette unless the operator asks for
#: them. Empty: the palette carries no function the project itself withholds, so
#: narrowing it is entirely the operator's decision. Every tool description
#: travels in every request, so an operator working one kind of question can
#: still trim the ones that cannot answer it.
DEFAULT_DISABLED_TOOLS: Final[frozenset[str]] = frozenset()


def disabled_tool_names() -> frozenset[str]:
    """The function names switched off for this console.

    Left unset, nothing is disabled. Set, the operator's list applies outright,
    so an empty value restores the whole palette.
    """

    raw = os.environ.get(DISABLED_TOOLS_ENVIRONMENT_VARIABLE)
    if raw is None:
        return DEFAULT_DISABLED_TOOLS
    return frozenset(name.strip() for name in raw.split(",") if name.strip())


INTERACTIVE_SCOPE_GUIDANCE = (
    "SCOPE OF SERVICE:\n"
    "You answer ONLY questions about the loaded forensic case: its evidence "
    "sources, artifacts, files, users, activity, timeline, and the "
    "investigation of them. If a request is unrelated to this case — general "
    "knowledge, current events, coding help, opinions, small talk, creative "
    "writing, or any task other than examining the loaded evidence — do not "
    "investigate it, call no tools, and reply with exactly this one "
    'sentence: "This console answers only questions about the loaded case; '
    'ask about its files, users, activity or other artifacts." A question '
    "about the investigation itself (what a tool reported, what an artifact "
    "found in this case means) is in scope."
    "\n\n"
    "ANSWER STYLE:\n"
    "Write every answer in complete sentences. State the finding as a "
    "sentence that names the artifact it came from — never reply with a "
    "bare value, a fragment, or a label-colon list."
)


def build_controlled_runner(
    *,
    model: str,
    base_url: str,
    api_key: str,
    output_root: Path,
    max_steps: int,
    max_tool_calls: int = 20,
) -> ControlledInvestigationSession:
    """Build the runner one interactive question executes under."""

    from forensic_agent.cli.controlled import ControlledInvestigationSession

    class InteractiveInvestigationSession(ControlledInvestigationSession):
        """The controlled session plus the console's own scope rule.

        A subclass rather than an edit to the controlled session: the
        evaluation harness instantiates the base class directly, so its
        prompts stay byte-identical while every interactive question
        carries the guardrail.
        """

        @classmethod
        def _evidence_guidance(cls, disk) -> str | None:
            base = ControlledInvestigationSession._evidence_guidance(disk)
            return "\n\n".join(
                part for part in (base, INTERACTIVE_SCOPE_GUIDANCE) if part
            )

        @classmethod
        def _scope_triage_state(cls) -> bool | None:
            """The interactive console DOES triage, unless the switch says not to.

            Read per question rather than pinned when the runner is built, so a
            session that changes the setting between questions records each run
            under the rail it actually ran with.
            """

            return scope_triage_enabled()

        def _narrow_tool_palette(self, tools):
            """Drop the functions the operator has switched off.

            Every tool description rides in every request's prompt, so an
            unused function is paid for on every question. The operator
            names the unwanted ones in ``DFA_DISABLED_TOOLS`` (comma
            separated); an empty or fully-consuming setting narrows
            nothing, so a typo cannot strand the console without tools.
            """

            disabled = disabled_tool_names()
            if not disabled:
                return tools
            kept = [
                tool
                for tool in tools
                if str(getattr(tool, "name", "")) not in disabled
            ]
            return kept if kept else tools

    return InteractiveInvestigationSession(
        model=model,
        base_url=base_url,
        api_key=api_key,
        output_root=output_root,
        # Interactive use follows the selected provider's normal model
        # routing. Provider and precision pins are reserved for frozen
        # evaluation runs, whose callers pass them explicitly.
        provider=None,
        provider_quantizations=None,
        max_steps=max_steps,
        max_tool_calls=max_tool_calls,
        # Read here rather than pinned at startup: /effort drops the
        # cached runner, so the next question is built under whatever
        # the operator has chosen by then.
        reasoning_effort=_reasoning.current_effort(),
        volatility_symbol_dir=(
            Path(os.environ["DFA_VOL_SYMBOL_DIRS"])
            if os.environ.get("DFA_VOL_SYMBOL_DIRS")
            else None
        ),
        volatility_cache_seed=(
            Path(os.environ["DFA_VOL_CACHE_SEED"])
            if os.environ.get("DFA_VOL_CACHE_SEED")
            else None
        ),
    )


def question_with_history_context(question: str, context: str) -> str:
    """Carry earlier turns into this question without letting them count as evidence.

    An empty context yields the question untouched: a request that says it has
    session context and then supplies none invites the model to invent what was
    supposedly established earlier.

    The framing itself is not authored here: it is the single-owner wrapper
    :func:`forensic_agent.agent.model_surface.frame_question_with_context`, so the
    interactive session-history path and the publication case-context path present
    prior context to the model through the same bytes and cannot drift.
    """

    if not context:
        return question
    from forensic_agent.agent.model_surface import (
        SESSION_CONTEXT_FRAMING_GUIDANCE,
        frame_question_with_context,
    )

    return frame_question_with_context(
        question, context, SESSION_CONTEXT_FRAMING_GUIDANCE
    )
