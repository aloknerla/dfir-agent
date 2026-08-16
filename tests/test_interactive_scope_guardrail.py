"""The console's topical guardrail: the model refuses off-case questions.

The rule rides the prompt's guidance section, injected by the interactive
runner subclass only. The evaluation harness instantiates the base
controlled session, so its prompts stay byte-identical — the one property
that makes an interactive-only prompt change safe at all.
"""

from __future__ import annotations

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from forensic_agent.cli.model_request import (
    INTERACTIVE_SCOPE_GUIDANCE,
    build_controlled_runner,
)
from forensic_agent.oversight import OversightLog

REFUSAL_SENTENCE = (
    "This console answers only questions about the loaded case; "
    "ask about its files, users, activity or other artifacts."
)


def _interactive_class(tmp_path):
    runner = build_controlled_runner(
        model="test-model",
        base_url="http://localhost:11434/v1",
        api_key="k",
        output_root=tmp_path,
        max_steps=20,
        max_tool_calls=20,
    )
    return type(runner)


def test_every_interactive_question_carries_the_scope_rule(tmp_path):
    cls = _interactive_class(tmp_path)
    guidance = cls._evidence_guidance(None)
    assert guidance is not None
    assert "SCOPE OF SERVICE" in guidance
    assert REFUSAL_SENTENCE in guidance
    # The refusal is instructed to run no tools, which is what lets the
    # console hand a declined question's number back.
    assert "call no tools" in guidance
    # Answers come back as prose, not bare values.
    assert "ANSWER STYLE" in guidance
    assert "complete sentences" in guidance


def test_the_scope_rule_composes_with_evidence_guidance(tmp_path, monkeypatch):
    from forensic_agent.cli.controlled import ControlledInvestigationSession

    cls = _interactive_class(tmp_path)
    monkeypatch.setattr(
        ControlledInvestigationSession,
        "_disk_family",
        classmethod(lambda _cls, _disk: "posix"),
    )
    guidance = cls._evidence_guidance(object())
    assert "EVIDENCE-SURFACE GUIDANCE" in guidance
    assert "SCOPE OF SERVICE" in guidance
    # The surface note precedes the scope rule as its own section.
    assert guidance.index("EVIDENCE-SURFACE") < guidance.index("SCOPE OF SERVICE")


def test_evaluation_runs_never_carry_the_interactive_rule(tmp_path):
    from forensic_agent.cli.controlled import ControlledInvestigationSession

    assert ControlledInvestigationSession._evidence_guidance(None) is None


def test_the_rule_lands_in_the_built_system_prompt():
    from forensic_agent.agent.system_prompt import build_system_prompt

    prompt = build_system_prompt(
        ["filesystem_read"],
        guidance=INTERACTIVE_SCOPE_GUIDANCE,
    )
    assert REFUSAL_SENTENCE in prompt


def test_scope_triage_reads_the_models_verdict(monkeypatch):
    """The triage refuses ONLY on a plain OFFTOPIC; anything else — the
    other word, an unexpected reply, or a transport failure — lets the
    question through. The rail refuses questions, never availability."""

    import forensic_agent.cli.scope_check as scope_check

    class _Reply:
        def __init__(self, content):
            self.content = content

    def fake_client(verdict):
        class _Client:
            def __init__(self, **_kwargs):
                pass

            def invoke(self, _messages):
                if isinstance(verdict, Exception):
                    raise verdict
                return _Reply(verdict)

        return _Client

    def ask(verdict):
        import langchain_openai

        monkeypatch.setattr(langchain_openai, "ChatOpenAI", fake_client(verdict))
        return scope_check.question_in_scope(
            "anything", model="m", base_url="http://x", api_key="k"
        )

    assert ask("OFFTOPIC") is False
    assert ask("offtopic") is False
    assert ask("ONTOPIC") is True
    assert ask("The input concerns the case.") is True  # no plain verdict
    assert ask(ConnectionError("down")) is True  # fail-open
    assert ask([{"type": "text", "text": "OFFTOPIC"}]) is False  # block content


def test_the_scope_triage_switch_parses_the_usual_spellings(monkeypatch):
    """Default ON, and the usual off spellings take the rail out."""

    from forensic_agent.core import environ

    for value, expected in [
        (None, True),
        ("", True),
        ("1", True),
        ("0", False),
        ("false", False),
        ("OFF", False),
        ("no", False),
    ]:
        if value is None:
            monkeypatch.delenv(environ.SCOPE_TRIAGE_ENVIRONMENT_VARIABLE, raising=False)
        else:
            monkeypatch.setenv(environ.SCOPE_TRIAGE_ENVIRONMENT_VARIABLE, value)
        assert environ.scope_triage_enabled() is expected


def test_the_triage_refuses_an_offtopic_verdict_while_it_is_on(monkeypatch):
    """The switch unset is the shipped behaviour: the model's verdict decides."""

    import langchain_openai

    import forensic_agent.cli.scope_check as scope_check
    from forensic_agent.core import environ

    class _Reply:
        content = "OFFTOPIC"

    class _Client:
        def __init__(self, **_kwargs):
            pass

        def invoke(self, _messages):
            return _Reply()

    monkeypatch.delenv(environ.SCOPE_TRIAGE_ENVIRONMENT_VARIABLE, raising=False)
    monkeypatch.setattr(langchain_openai, "ChatOpenAI", _Client)
    assert (
        scope_check.question_in_scope(
            "how do I bake bread", model="m", base_url="http://x", api_key="k"
        )
        is False
    )


def test_the_triage_switched_off_never_builds_a_client(monkeypatch):
    """Off means no network call at all, not a call whose verdict is ignored.

    The switch exists so a model comparison is not charged a request of the
    model under test, so a client that is constructed and then disregarded
    would defeat the whole point of it.
    """

    import langchain_openai

    import forensic_agent.cli.scope_check as scope_check
    from forensic_agent.core import environ

    constructed: list[object] = []

    class _Client:
        def __init__(self, **_kwargs):
            constructed.append(self)

        def invoke(self, _messages):  # pragma: no cover - must never be reached
            raise AssertionError("the triage asked the model with the rail switched off")

    monkeypatch.setenv(environ.SCOPE_TRIAGE_ENVIRONMENT_VARIABLE, "0")
    monkeypatch.setattr(langchain_openai, "ChatOpenAI", _Client)
    assert (
        scope_check.question_in_scope(
            "how do I bake bread", model="m", base_url="http://x", api_key="k"
        )
        is True
    )
    assert constructed == []


def test_the_run_record_states_which_rail_the_run_used(tmp_path, monkeypatch):
    """A measurement taken with the triage off must not read like one with it on."""

    from forensic_agent.cli.controlled import ControlledInvestigationSession
    from forensic_agent.core import environ

    # The evaluation harness runs no such rail, and says so rather than
    # reporting a switch it never consulted.
    assert ControlledInvestigationSession._scope_triage_state() is None

    interactive = _interactive_class(tmp_path)
    monkeypatch.delenv(environ.SCOPE_TRIAGE_ENVIRONMENT_VARIABLE, raising=False)
    assert interactive._scope_triage_state() is True
    monkeypatch.setenv(environ.SCOPE_TRIAGE_ENVIRONMENT_VARIABLE, "0")
    assert interactive._scope_triage_state() is False

    recorder = OversightLog(str(tmp_path / "oversight.jsonl"))
    recorder.open_case(question="q", scope_triage=False)
    recorder.open_case(question="q", scope_triage=True)
    recorder.open_case(question="q")
    opened = [
        entry
        for entry in OversightLog.load(recorder.path)
        if entry.get("event") == "case_open"
    ]
    assert [entry["scope_triage"] for entry in opened] == [False, True, None]


def test_the_console_hands_its_triage_state_to_the_run_record():
    """Regression: the switch is worthless if the run never records it."""

    import inspect

    from forensic_agent.cli import controlled

    source = inspect.getsource(controlled.ControlledInvestigationSession.ask)
    assert "scope_triage=self._scope_triage_state()," in source


ANSWERED_OFFLINE = "The capture contains 12 DNS queries."


class _OfflineChatModel(BaseChatModel):
    """A chat model that answers once, in prose, and never leaves the process.

    A real ``BaseChatModel`` rather than a stand-in object, so the investigation
    runs through the same LangChain agent the console builds: the callbacks fire,
    the request ledger records a genuine model row, and the published answer is
    accepted by the same finalization path a live run goes through. Extra
    constructor keywords are accepted because the runtime hands its transport the
    full decoding profile.
    """

    model_config = {"extra": "allow"}

    @property
    def _llm_type(self) -> str:
        return "offline-suite-model"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        del messages, stop, run_manager, kwargs
        return ChatResult(
            generations=[ChatGeneration(message=AIMessage(content=ANSWERED_OFFLINE))]
        )

    def bind_tools(self, tools, **kwargs):
        del tools, kwargs
        return self


def _investigate_offline(tmp_path, monkeypatch, scope_triage):
    """Drive one whole investigation through the public runtime entry point.

    No network, no evidence image and no tools: the point is the WIRING between
    the console's call and the run record, which every unit test of an individual
    function in that chain passes straight over.
    """

    from forensic_agent.agent import runtime as agent_runtime
    from forensic_agent.oversight import Policy

    monkeypatch.setattr(agent_runtime, "ChatOpenAI", _OfflineChatModel)
    oversight_path = tmp_path / "oversight.jsonl"
    report = agent_runtime.run_investigation(
        None,
        "How many DNS queries does this capture hold?",
        prepared_tools=[],
        model="offline-model",
        api_key="unused",
        policy=Policy.secure(path_roots=[str(tmp_path)]),
        oversight_path=str(oversight_path),
        verbose=False,
        verify=False,
        recover_incomplete_run=False,
        scope_triage=scope_triage,
    )
    return report, list(OversightLog.load(str(oversight_path)))


@pytest.mark.parametrize("state", [True, False, None])
def test_a_whole_run_carries_the_triage_state_into_its_record(tmp_path, monkeypatch, state):
    """End to end: the value the console states reaches ``case_open`` unchanged.

    This is the test whose absence let a run die on its first question while the
    suite stayed green. Every link in the chain — ``run_investigation``, the
    orchestration runner, the frozen configuration, preparation, the model-surface
    façade — is the real one here, so a keyword one of them accepts and the next
    does not fails HERE rather than in the console.
    """

    report, entries = _investigate_offline(tmp_path, monkeypatch, state)

    # The run completed and published what the model answered.
    assert report == ANSWERED_OFFLINE
    (closed,) = [entry for entry in entries if entry.get("event") == "case_close"]
    assert closed["status"] == "ok"

    (opened,) = [entry for entry in entries if entry.get("event") == "case_open"]
    assert opened["scope_triage"] is state


def test_the_console_runs_investigations_through_that_same_entry_point(tmp_path):
    """The seam above is the console's seam, not a private one for the suite."""

    from forensic_agent.agent.runtime import run_investigation
    from forensic_agent.cli.controlled import ControlledInvestigationSession

    session = ControlledInvestigationSession(
        model="local-model",
        base_url="http://127.0.0.1:11434/v1",
        api_key=None,
        output_root=tmp_path,
    )
    assert session._graph_runner is run_investigation


def test_doctor_reports_whether_the_triage_is_on(monkeypatch):
    """An operator taking a measurement can read the setting off the preflight."""

    from forensic_agent.core import environ

    def rows(**_kwargs):
        return [
            row
            for row in environ.doctor(base_url="http://127.0.0.1:1/v1")
            if row["name"] == "Question scope triage"
        ]

    monkeypatch.delenv(environ.SCOPE_TRIAGE_ENVIRONMENT_VARIABLE, raising=False)
    (on_row,) = rows()
    assert on_row["ok"] is True and on_row["required"] is False
    assert "on" in on_row["detail"]

    monkeypatch.setenv(environ.SCOPE_TRIAGE_ENVIRONMENT_VARIABLE, "0")
    (off_row,) = rows()
    assert off_row["ok"] is False
    assert environ.SCOPE_TRIAGE_ENVIRONMENT_VARIABLE in off_row["detail"]


def test_both_rails_speak_the_same_refusal_sentence():
    """One wording whichever rail catches it: the triage notice and the
    prompt's instructed sentence must never drift apart."""

    import forensic_agent.cli.scope_check as scope_check

    assert scope_check.SCOPE_REFUSAL_NOTICE == REFUSAL_SENTENCE
    assert scope_check.SCOPE_REFUSAL_NOTICE in INTERACTIVE_SCOPE_GUIDANCE


class _Tool:
    def __init__(self, name):
        self.name = name


def test_disabled_tools_leave_the_interactive_palette(tmp_path, monkeypatch):
    """DFA_DISABLED_TOOLS drops named functions from interactive prompts;
    a setting that would empty the palette narrows nothing."""

    cls = _interactive_class(tmp_path)
    session = cls.__new__(cls)
    tools = [_Tool("registry_query"), _Tool("ocr_image"), _Tool("evtx_query")]

    monkeypatch.delenv("DFA_DISABLED_TOOLS", raising=False)
    assert session._narrow_tool_palette(tools) == tools

    monkeypatch.setenv("DFA_DISABLED_TOOLS", "ocr_image, sqlite_query")
    assert [t.name for t in session._narrow_tool_palette(tools)] == [
        "registry_query",
        "evtx_query",
    ]

    monkeypatch.setenv(
        "DFA_DISABLED_TOOLS", "registry_query,ocr_image,evtx_query"
    )
    assert session._narrow_tool_palette(tools) == tools


def test_evaluation_palette_is_never_narrowed(tmp_path, monkeypatch):
    from forensic_agent.cli.controlled import ControlledInvestigationSession

    session = ControlledInvestigationSession.__new__(ControlledInvestigationSession)
    tools = [_Tool("registry_query"), _Tool("ocr_image")]
    monkeypatch.setenv("DFA_DISABLED_TOOLS", "ocr_image")
    assert session._narrow_tool_palette(tools) == tools
