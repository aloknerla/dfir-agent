"""Centralized, reproducible model configuration.

This module is the single source of truth for *how* the agent talks to a language
model. Forensic conclusions must be as reproducible as the probabilistic nature of
language models allows, so decoding is locked to a deterministic profile. The
supported execution path uses OpenRouter; local OpenAI-compatible endpoints remain
available only when a caller configures one explicitly.

Key facts that shape this design (see docs/REPRODUCIBILITY.md):

* On ``temperature=0`` the sampler collapses to greedy/argmax; determinism comes
  from the greedy path and a fixed numeric environment, **not** from the seed. The
  seed is kept for documentation and for hosted backends where it is honoured.
* The dominant remaining source of non-determinism even at ``temperature=0`` is the
  lack of *batch invariance*. Serving a single request at a time (batch size 1)
  against a dense local model on fixed hardware therefore maximizes reproducibility.
* Remote routing (OpenRouter) is best-effort: a request may hit different providers
  or GPUs. We pin a single provider and refuse silent fallbacks, but we never claim
  bitwise determinism for the remote path.

Reproducibility is therefore something we *measure* (see :mod:`forensic_agent.core.repro`),
not something we assert.
"""

from __future__ import annotations

import os
from collections.abc import Collection
from dataclasses import dataclass
from typing import Any

# Load the local .env file (credentials and endpoints). The file is ignored by
# Git, so secrets never enter the repository. Loading is explicit and
# idempotent so behavior does not depend on module import order.
from forensic_agent.core.environment_file import load_environment_file

load_environment_file()


# --------------------------------------------------------------------------- #
#  Deterministic decoding profile
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class DecodingProfile:
    """An immutable, locked set of decoding parameters.

    The defaults define the *evidence-grade* profile used for all forensic runs.
    Fields map either to standard OpenAI chat parameters or, for ``top_k`` /
    ``num_ctx`` / ``repeat_penalty``, to backend-native options applied through
    :func:`extra_body`.
    """

    temperature: float = 0.0  # greedy / argmax decoding
    top_p: float = 1.0  # no nucleus truncation (neutral)
    top_k: int = 1  # local backends: force argmax explicitly
    seed: int = 42  # documented; no-op at temp=0 on local greedy
    frequency_penalty: float = 0.0  # neutral: no path-dependent token shaping
    presence_penalty: float = 0.0  # neutral
    repeat_penalty: float = 1.0  # neutral (Ollama-native)
    num_ctx: int = 8192  # fixed context window (Ollama: unset => drift)
    # Bounded as a reproducibility control rather than a cost one: a shorter
    # completion has fewer places to diverge. The value sits far under every
    # configured model's ceiling (32,768 on the smallest, 393,216 on the
    # default), leaving headroom to quote a long passage of evidence.
    max_tokens: int = 16384
    stream: bool = False  # disabled: simpler, auditable logging
    reasoning_effort: str | None = None  # gpt-oss/o-series: low|medium|high (OpenRouter); None=omit


#: The locked profile used for evidence-grade forensic analysis.
DETERMINISTIC = DecodingProfile()


def _request_timeout() -> float:
    """Per-request HTTP timeout (seconds) for every model call, bounding a stalled
    provider connection so it cannot hang indefinitely. Generous by default (high
    reasoning-effort calls can take minutes); env-overridable."""
    try:
        return float(os.environ.get("DFA_REQUEST_TIMEOUT", "900"))
    except Exception:
        return 900.0


# --------------------------------------------------------------------------- #
#  Backend detection
# --------------------------------------------------------------------------- #
def is_openrouter(base_url: str | None) -> bool:
    return "openrouter" in (base_url or "").lower()


def is_local(base_url: str | None) -> bool:
    b = (base_url or "").lower()
    return any(tok in b for tok in ("localhost", "127.0.0.1", ":11434"))


#: The remote model a run uses when nothing selects one.  Declared once and
#: imported wherever a default is needed: the banner, ``doctor``, the setup
#: prompt and the agent API each report "the default", and a second literal in
#: any of them would let the terminal name a model the run would not use.
DEFAULT_MODEL = "deepseek/deepseek-v4-flash-0731"

OPENROUTER_DEFAULT_QUANTIZATIONS = ("fp8", "bf16", "fp16")

#: Request parameter names that a frozen model endpoint may declare.  ``tools``
#: and ``tool_choice`` are bound by LangChain/the caller rather than emitted by
#: the factories below, but remain part of the endpoint contract so one frozen
#: allowlist can attest the complete agent request surface.
RECOGNIZED_REQUEST_PARAMETER_NAMES: tuple[str, ...] = (
    "temperature",
    "top_p",
    "seed",
    "frequency_penalty",
    "presence_penalty",
    "max_tokens",
    "stream",
    "reasoning",
    "tools",
    "tool_choice",
)
RECOGNIZED_REQUEST_PARAMETERS: frozenset[str] = frozenset(RECOGNIZED_REQUEST_PARAMETER_NAMES)


def _normalize_allowed_parameters(
    allowed_parameters: Collection[str] | None,
) -> frozenset[str] | None:
    """Validate and freeze a model endpoint's request-parameter allowlist.

    ``None`` means the unfiltered request profile.  An explicit collection is
    fail-closed: empty, duplicate, non-string, and unknown names are rejected
    instead of silently changing the request surface.
    """
    if allowed_parameters is None:
        return None
    if isinstance(allowed_parameters, str):
        raise ValueError("allowed_parameters must be a collection of parameter names")
    names = tuple(allowed_parameters)
    if not names:
        raise ValueError("allowed_parameters must not be empty")
    if any(not isinstance(name, str) for name in names):
        raise ValueError("allowed_parameters must contain only strings")
    if len(set(names)) != len(names):
        raise ValueError("allowed_parameters must not contain duplicate names")
    unknown = set(names).difference(RECOGNIZED_REQUEST_PARAMETERS)
    if unknown:
        raise ValueError(f"unknown allowed_parameters: {', '.join(sorted(unknown))}")
    return frozenset(names)


def _filter_standard_request_parameters(
    kwargs: dict[str, Any],
    allowed_parameters: frozenset[str] | None,
) -> None:
    """Remove unsupported standard API fields, retaining client-side controls."""
    if allowed_parameters is None:
        return
    for name in (
        "temperature",
        "top_p",
        "seed",
        "frequency_penalty",
        "presence_penalty",
        "max_tokens",
        "stream",
    ):
        if name not in allowed_parameters:
            kwargs.pop(name, None)


def _openrouter_provider(
    provider: str | None = None,
    *,
    quantizations: tuple[str, ...] | None = OPENROUTER_DEFAULT_QUANTIZATIONS,
) -> dict[str, Any] | None:
    """OpenRouter provider preference. Pin a SINGLE provider (from the arg or
    DFA_OPENROUTER_PROVIDER) so cross-provider routing cannot change tool-call parsing
    or precision run-to-run — a dominant source of remote non-determinism even at temp 0.
    Also bounds precision (excludes fp4). Returns None when no provider is pinned, leaving
    the remote path best-effort (unchanged behaviour)."""
    prov = provider or os.environ.get("DFA_OPENROUTER_PROVIDER")
    if not prov:
        return None
    route: dict[str, Any] = {
        "order": [prov],
        "allow_fallbacks": False,
        "require_parameters": True,
    }
    if quantizations is not None:
        if not quantizations or any(not item.strip() for item in quantizations):
            raise ValueError("provider quantizations must be non-empty names or None")
        route["quantizations"] = list(quantizations)
    return route


def extra_body(
    profile: DecodingProfile,
    base_url: str | None,
    *,
    provider: str | None = None,
    provider_quantizations: tuple[str, ...] | None = OPENROUTER_DEFAULT_QUANTIZATIONS,
    pin_provider: bool = True,
) -> dict[str, Any]:
    """Build the backend-specific request extras that are not standard OpenAI fields.

    * Local (Ollama): native options (``num_ctx``, ``top_k``, ``seed``,
      ``repeat_penalty``) so the context window is fixed and decoding is argmax.
    * OpenRouter: pin a single provider and require it to honour our parameters,
      refusing silent fallback to a different provider/GPU.
    """
    eb: dict[str, Any] = {}
    if is_local(base_url):
        eb["options"] = {
            "num_ctx": profile.num_ctx,
            "top_k": profile.top_k,
            "seed": profile.seed,
            "repeat_penalty": profile.repeat_penalty,
        }
    if is_openrouter(base_url) and pin_provider:
        # Pin to a single provider (from arg or DFA_OPENROUTER_PROVIDER) to refuse silent
        # fallback to a different provider/GPU, the dominant remote variance source at
        # temp 0. Without a pinned provider the path stays best-effort.
        # The pin is an AGENT-determinism control: adjudication callers (verdict/classify
        # judges, possibly a different model family the pinned provider does not serve)
        # pass pin_provider=False to opt out of the env-wide pin.
        pref = _openrouter_provider(provider, quantizations=provider_quantizations)
        if pref:
            eb["provider"] = pref
        else:
            # An UNPINNED request is routed best-effort to any provider — and
            # an interactive request carries spotlighted evidence excerpts.
            # Routing preferences are the control OpenRouter offers for
            # exactly that: providers that retain prompts are declined by
            # default (DFA_OPENROUTER_DATA_COLLECTION=allow restores the old
            # best-effort routing; DFA_OPENROUTER_ZDR=1 additionally requires
            # zero-data-retention endpoints). Judges opt out of pinning with
            # pin_provider=False and are deliberately not touched here.
            privacy = _openrouter_privacy_routing()
            if privacy:
                eb["provider"] = privacy
    return eb


def _openrouter_privacy_routing() -> dict[str, Any] | None:
    """Routing preferences for evidence-bearing, unpinned OpenRouter requests."""

    if os.environ.get("DFA_OPENROUTER_DATA_COLLECTION", "").strip().lower() == "allow":
        return None
    privacy: dict[str, Any] = {"data_collection": "deny"}
    if os.environ.get("DFA_OPENROUTER_ZDR", "").strip().lower() in {"1", "true"}:
        privacy["zdr"] = True
    return privacy


# --------------------------------------------------------------------------- #
#  Client argument factories
# --------------------------------------------------------------------------- #
# Sentinel: use the profile's max_tokens. Passing ``max_tokens=None`` instead omits
# the field entirely (the model's own default applies, i.e. unbounded output).
_USE_PROFILE_MAX = -1


def _resolve_max_tokens(
    kw: dict[str, Any], profile: DecodingProfile, max_tokens: int | None
) -> None:
    """Apply the max_tokens policy in place.

    ``-1`` (default) uses the profile budget; ``None`` omits the field (model
    default); any positive int sets that explicit budget. The output-token budget
    does not affect greedy determinism on the local path; it is tuned per task to
    avoid truncation.
    """
    if max_tokens == _USE_PROFILE_MAX:
        kw["max_tokens"] = profile.max_tokens
    elif max_tokens is not None:
        kw["max_tokens"] = max_tokens


def completion_kwargs(
    profile: DecodingProfile = DETERMINISTIC,
    *,
    base_url: str | None = None,
    provider: str | None = None,
    provider_quantizations: tuple[str, ...] | None = OPENROUTER_DEFAULT_QUANTIZATIONS,
    max_tokens: int | None = _USE_PROFILE_MAX,
    reasoning_effort: str | None = None,
    pin_provider: bool = True,
    allowed_parameters: Collection[str] | None = None,
) -> dict[str, Any]:
    """Keyword arguments for ``openai.OpenAI().chat.completions.create``.

    Excludes ``model``/``messages``/``tools`` which the caller supplies. The
    returned dict already includes backend-appropriate ``extra_body``.  Passing a
    frozen endpoint ``allowed_parameters`` collection omits unsupported request
    fields; ``None`` preserves the historical request exactly.
    """
    allowed = _normalize_allowed_parameters(allowed_parameters)
    kw: dict[str, Any] = {
        "temperature": profile.temperature,
        "top_p": profile.top_p,
        "seed": profile.seed,
        "frequency_penalty": profile.frequency_penalty,
        "presence_penalty": profile.presence_penalty,
        "stream": profile.stream,
        "timeout": _request_timeout(),
    }
    _resolve_max_tokens(kw, profile, max_tokens)
    _filter_standard_request_parameters(kw, allowed)
    eb = extra_body(
        profile,
        base_url,
        provider=provider,
        provider_quantizations=provider_quantizations,
        pin_provider=pin_provider,
    )
    eff = reasoning_effort if reasoning_effort is not None else profile.reasoning_effort
    if allowed is None or "reasoning" in allowed:
        if eff and is_openrouter(base_url):
            # OpenRouter unified reasoning control; gpt-oss honours low|medium|high.
            eb["reasoning"] = {"effort": eff}
        elif is_local(base_url):
            # Ollama parses the same shape with the same vocabulary — but its
            # omission semantics are the OPPOSITE of OpenRouter's: an omitted
            # field means the model's default-ON thinking. The console's
            # omitted choice therefore travels as an explicit 'none', so
            # /effort none actually turns local thinking off.
            eb["reasoning"] = {"effort": eff or "none"}
    if eb:
        kw["extra_body"] = eb
    return kw


def chat_openai_kwargs(
    profile: DecodingProfile = DETERMINISTIC,
    *,
    base_url: str | None = None,
    provider: str | None = None,
    provider_quantizations: tuple[str, ...] | None = OPENROUTER_DEFAULT_QUANTIZATIONS,
    max_tokens: int | None = _USE_PROFILE_MAX,
    reasoning_effort: str | None = None,
    pin_provider: bool = True,
    allowed_parameters: Collection[str] | None = None,
) -> dict[str, Any]:
    """Keyword arguments for ``langchain_openai.ChatOpenAI`` (used by graph engines).

    Standard parameters are passed as first-class fields; backend-native extras go
    through ``extra_body`` (supported by langchain-openai).  On OpenRouter the
    output budget also goes through ``extra_body`` because current
    ``langchain-openai`` rewrites its public ``max_tokens`` argument to
    ``max_completion_tokens`` on the wire.  OpenRouter endpoint metadata and
    ``require_parameters`` use ``max_tokens`` for these controlled routes, so the
    rewrite would otherwise filter out every eligible endpoint. ``pin_provider=False``
    opts an adjudication call (verdict/classify judge) out of the env-wide
    DFA_OPENROUTER_PROVIDER pin, which targets the agent model only.  Passing a
    frozen endpoint ``allowed_parameters`` collection omits unsupported request
    fields; ``None`` preserves the historical request exactly.
    """
    allowed = _normalize_allowed_parameters(allowed_parameters)
    kw: dict[str, Any] = {
        "temperature": profile.temperature,
        "top_p": profile.top_p,
        "seed": profile.seed,
        "frequency_penalty": profile.frequency_penalty,
        "presence_penalty": profile.presence_penalty,
        "timeout": _request_timeout(),
    }
    _resolve_max_tokens(kw, profile, max_tokens)
    _filter_standard_request_parameters(kw, allowed)
    # Both non-OpenAI backends need the output budget spelled ``max_tokens``
    # on the wire, and current langchain-openai rewrites its public argument
    # to ``max_completion_tokens``: OpenRouter's endpoint filtering keys on
    # the unrenamed field, and Ollama has no ``max_completion_tokens`` at all
    # (its ``max_tokens`` maps to ``num_predict``), so the rewrite silently
    # dropped the local completion bound. ``extra_body`` merges after the
    # rename and carries the honest spelling to both.
    routed_max_tokens = (
        kw.pop("max_tokens", None)
        if (is_openrouter(base_url) or is_local(base_url))
        else None
    )
    if is_openrouter(base_url):
        # Ask OpenRouter to return the provider-selection receipt in the response.
        # The graph preserves this body metadata before langchain-openai normalizes
        # away provider-specific extension fields. The attribution pair is
        # optional and identifies this tool in the provider dashboard.
        kw["default_headers"] = {
            "X-OpenRouter-Metadata": "enabled",
            "HTTP-Referer": "https://github.com/aloknerla/dfir-agent",
            "X-Title": "DFIR-AGENT",
        }
    eb = extra_body(
        profile,
        base_url,
        provider=provider,
        provider_quantizations=provider_quantizations,
        pin_provider=pin_provider,
    )
    if routed_max_tokens is not None:
        eb["max_tokens"] = routed_max_tokens
    eff = reasoning_effort if reasoning_effort is not None else profile.reasoning_effort
    if allowed is None or "reasoning" in allowed:
        if eff and is_openrouter(base_url):
            # OpenRouter unified reasoning control; gpt-oss honours low|medium|high.
            eb["reasoning"] = {"effort": eff}
        elif is_local(base_url):
            # Ollama parses the same shape with the same vocabulary — but its
            # omission semantics are the OPPOSITE of OpenRouter's: an omitted
            # field means the model's default-ON thinking. The console's
            # omitted choice therefore travels as an explicit 'none', so
            # /effort none actually turns local thinking off.
            eb["reasoning"] = {"effort": eff or "none"}
    if eb:
        kw["extra_body"] = eb
    return kw


def agent_reasoning_effort() -> str | None:
    """Reasoning effort for the AGENT engines (the multi-step investigation), read from
    DFA_REASONING_EFFORT (default 'high'). 'none'/'off'/'' -> None (omit). Adjudication
    steps (triage/verdict/judge) keep the default (None) and are unaffected."""
    v = os.environ.get("DFA_REASONING_EFFORT", "high")
    return v if v and v.lower() not in ("none", "off") else None


def _bounded_max_tokens(max_tokens: int | None) -> int:
    """Reject accidental opt-out from a role that promises bounded output.

    The lower-level factories intentionally retain ``None`` as an escape hatch for
    callers that need a provider-defined limit.  Agent and verification calls must
    never use that escape hatch: an omitted provider limit makes latency/cost and
    cross-engine comparisons unbounded.
    """
    if max_tokens is None:
        raise ValueError("agent/verification max_tokens must be bounded, not None")
    if max_tokens != _USE_PROFILE_MAX and max_tokens <= 0:
        raise ValueError("max_tokens must be a positive integer")
    return max_tokens


def agent_chat_openai_kwargs(
    profile: DecodingProfile = DETERMINISTIC,
    *,
    base_url: str | None = None,
    provider: str | None = None,
    provider_quantizations: tuple[str, ...] | None = OPENROUTER_DEFAULT_QUANTIZATIONS,
    max_tokens: int = _USE_PROFILE_MAX,
    allowed_parameters: Collection[str] | None = None,
) -> dict[str, Any]:
    """Bounded kwargs shared by graph, supervisor, and scoped engines.

    Specialists, supervisors, synthesis, and forced-final calls all use the same
    ``ChatOpenAI`` instance, so this per-call limit applies uniformly to every model
    role in those engines.  The default is ``profile.max_tokens``.
    """
    return chat_openai_kwargs(
        profile,
        base_url=base_url,
        provider=provider,
        provider_quantizations=provider_quantizations,
        max_tokens=_bounded_max_tokens(max_tokens),
        reasoning_effort=(
            profile.reasoning_effort
            if profile.reasoning_effort is not None
            else agent_reasoning_effort()
        ),
        allowed_parameters=allowed_parameters,
    )


def verification_completion_kwargs(
    profile: DecodingProfile = DETERMINISTIC,
    *,
    base_url: str | None = None,
    provider: str | None = None,
    provider_quantizations: tuple[str, ...] | None = OPENROUTER_DEFAULT_QUANTIZATIONS,
    max_tokens: int = _USE_PROFILE_MAX,
    allowed_parameters: Collection[str] | None = None,
) -> dict[str, Any]:
    """Bounded kwargs for the evidence-grounding verification pass.

    Verification defaults to the same output budget as the primary engines so a
    complete claim report cannot receive an unfairly larger allowance. It is
    unpinned by default because the verifier may be a different model family. A
    caller can pass an explicit provider to pin the verification call to the same
    realized route as the investigation model.
    """
    return completion_kwargs(
        profile,
        base_url=base_url,
        provider=provider,
        provider_quantizations=provider_quantizations,
        max_tokens=_bounded_max_tokens(max_tokens),
        pin_provider=provider is not None,
        allowed_parameters=allowed_parameters,
    )


def structured_kwargs(
    schema: dict[str, Any],
    *,
    base_url: str | None = None,
    provider: str | None = None,
) -> dict[str, Any]:
    """Request kwargs that *constrain decoding* to a JSON Schema.

    Constrained decoding masks tokens that would violate the schema, so an invalid
    response becomes impossible at generation time (far stronger than parse-and-retry).
    Both Ollama's OpenAI-compatible endpoint and OpenRouter honour
    ``response_format`` with a ``json_schema``. On OpenRouter ``require_parameters``
    is set so a provider that cannot enforce the schema is not silently used (which
    would degrade to plain ``json_object``).
    """
    kw: dict[str, Any] = {
        "response_format": {
            "type": "json_schema",
            "json_schema": {"name": "output", "schema": schema, "strict": True},
        }
    }
    if is_openrouter(base_url):
        prov: dict[str, Any] = {"require_parameters": True}
        if provider:
            prov["order"] = [provider]
            prov["allow_fallbacks"] = False
        kw["extra_body"] = {"provider": prov}
    return kw
