"""Tests for the centralized deterministic model configuration."""

from forensic_agent.core import config as cfg


def test_default_profile_is_greedy_and_neutral():
    p = cfg.DETERMINISTIC
    assert p.temperature == 0.0
    assert p.top_p == 1.0
    assert p.top_k == 1
    assert p.seed == 42
    assert p.frequency_penalty == 0.0
    assert p.presence_penalty == 0.0
    assert p.repeat_penalty == 1.0
    assert p.stream is False


def test_backend_detection():
    assert cfg.is_local("http://localhost:11434/v1")
    assert cfg.is_local("http://127.0.0.1:11434/v1")
    assert not cfg.is_local("https://openrouter.ai/api/v1")
    assert cfg.is_openrouter("https://openrouter.ai/api/v1")
    assert not cfg.is_openrouter("http://localhost:11434/v1")


def test_extra_body_local_sets_native_options():
    eb = cfg.extra_body(cfg.DETERMINISTIC, "http://localhost:11434/v1")
    assert eb["options"]["num_ctx"] == cfg.DETERMINISTIC.num_ctx
    assert eb["options"]["top_k"] == 1
    assert eb["options"]["seed"] == 42
    assert eb["options"]["repeat_penalty"] == 1.0
    assert "provider" not in eb


def test_extra_body_openrouter_pins_provider():
    eb = cfg.extra_body(cfg.DETERMINISTIC, "https://openrouter.ai/api/v1", provider="some/provider")
    assert eb["provider"]["require_parameters"] is True
    assert eb["provider"]["allow_fallbacks"] is False
    assert eb["provider"]["order"] == ["some/provider"]
    assert "options" not in eb


def test_openrouter_pin_can_omit_quantization_filter_for_unknown_endpoint_metadata():
    eb = cfg.extra_body(
        cfg.DETERMINISTIC,
        "https://openrouter.ai/api/v1",
        provider="openai",
        provider_quantizations=None,
    )
    assert eb["provider"]["order"] == ["openai"]
    assert eb["provider"]["allow_fallbacks"] is False
    assert "quantizations" not in eb["provider"]


def test_completion_kwargs_local():
    kw = cfg.completion_kwargs(base_url="http://localhost:11434/v1", max_tokens=123)
    assert kw["temperature"] == 0.0
    assert kw["top_p"] == 1.0
    assert kw["seed"] == 42
    assert kw["max_tokens"] == 123
    assert kw["stream"] is False
    assert "options" in kw["extra_body"]


def test_chat_openai_kwargs_remote_pins_provider_only_when_given(monkeypatch):
    monkeypatch.delenv("DFA_OPENROUTER_DATA_COLLECTION", raising=False)
    monkeypatch.delenv("DFA_OPENROUTER_ZDR", raising=False)
    # No provider pinned => best-effort ROUTING, but never best-effort
    # PRIVACY: an unpinned interactive request carries evidence excerpts, so
    # providers that retain prompts are declined by default.
    kw = cfg.chat_openai_kwargs(base_url="https://openrouter.ai/api/v1")
    assert kw["temperature"] == 0.0
    assert kw["extra_body"]["max_tokens"] == cfg.DETERMINISTIC.max_tokens
    assert kw["extra_body"]["provider"] == {"data_collection": "deny"}
    # The escape hatch restores the historical best-effort routing.
    monkeypatch.setenv("DFA_OPENROUTER_DATA_COLLECTION", "allow")
    kw_allow = cfg.chat_openai_kwargs(base_url="https://openrouter.ai/api/v1")
    assert "provider" not in kw_allow["extra_body"]
    monkeypatch.delenv("DFA_OPENROUTER_DATA_COLLECTION", raising=False)
    # Provider pinned => strict, no silent fallback (and the pin wins over
    # the privacy default; a pinned evaluation stays byte-identical).
    kw2 = cfg.chat_openai_kwargs(base_url="https://openrouter.ai/api/v1", provider="vendor/x")
    assert kw2["extra_body"]["provider"]["allow_fallbacks"] is False
    assert kw2["extra_body"]["provider"]["order"] == ["vendor/x"]
    assert "data_collection" not in kw2["extra_body"]["provider"]


def test_pin_provider_false_opts_adjudication_out_of_env_pin(monkeypatch):
    # The env-wide pin targets the AGENT loop; a judge/verdict call with a different
    # model family must be able to opt out or the pinned provider (which may not
    # serve the judge model) breaks every adjudication step.
    monkeypatch.setenv("DFA_OPENROUTER_PROVIDER", "vendor/x")
    pinned = cfg.chat_openai_kwargs(base_url="https://openrouter.ai/api/v1")
    assert pinned["extra_body"]["provider"]["order"] == ["vendor/x"]
    judge = cfg.chat_openai_kwargs(base_url="https://openrouter.ai/api/v1", pin_provider=False)
    assert "provider" not in judge.get("extra_body", {})
    judge2 = cfg.completion_kwargs(base_url="https://openrouter.ai/api/v1", pin_provider=False)
    assert "provider" not in judge2.get("extra_body", {})



def test_structured_kwargs_constrains_decoding():
    kw = cfg.structured_kwargs({"type": "object"}, base_url="http://localhost:11434/v1")
    assert kw["response_format"]["type"] == "json_schema"
    assert kw["response_format"]["json_schema"]["strict"] is True
    assert "extra_body" not in kw  # local: no provider pin needed


def test_structured_kwargs_openrouter_requires_params():
    kw = cfg.structured_kwargs({"type": "object"}, base_url="https://openrouter.ai/api/v1")
    assert kw["extra_body"]["provider"]["require_parameters"] is True


def test_local_backend_carries_output_budget_and_reasoning(monkeypatch):
    """Ollama parity: the completion bound and the reasoning control both
    reach the local wire, and the omitted effort travels as an explicit
    'none' (Ollama's omission means default-ON thinking)."""

    kw = cfg.chat_openai_kwargs(base_url="http://localhost:11434/v1")
    # langchain-openai renames a first-class max_tokens to
    # max_completion_tokens, a field Ollama does not have; extra_body merges
    # after the rename and Ollama maps max_tokens to num_predict.
    assert "max_tokens" not in kw
    assert kw["extra_body"]["max_tokens"] == cfg.DETERMINISTIC.max_tokens
    assert kw["extra_body"]["reasoning"] == {"effort": "none"}
    kw_high = cfg.chat_openai_kwargs(
        base_url="http://localhost:11434/v1", reasoning_effort="high"
    )
    assert kw_high["extra_body"]["reasoning"] == {"effort": "high"}
    # No privacy-routing block leaks to the local backend.
    assert "provider" not in kw_high["extra_body"]


def test_local_transport_never_attests_a_dead_tool_choice():
    """Ollama drops tool_choice without a 400, so the degradation detector
    can never fire there; the transport must declare the incapability up
    front instead of attesting a compulsion the provider never saw."""

    from forensic_agent.agent.model_transport import ChatOpenAI

    transport = ChatOpenAI(
        model="qwen3", api_key="ollama", base_url="http://localhost:11434/v1"
    )
    assert transport._accepts_constrained_tool_choice is True
    transport._declare_local_tool_choice_incapability()
    assert transport._accepts_constrained_tool_choice is False

    remote = ChatOpenAI(
        model="m", api_key="k", base_url="https://openrouter.ai/api/v1"
    )
    remote._declare_local_tool_choice_incapability()
    assert remote._accepts_constrained_tool_choice is True
