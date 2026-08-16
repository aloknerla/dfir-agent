"""What this console refuses to run on, and where an accepted choice is kept.

A model is named at three different moments — on the launch command, by
``/model``, and by ``/setup`` — and at every one of them the same two questions
decide whether the console may adopt it: does the configured provider actually
have it, and will it accept a tool call. Nothing else about a model matters
here, because an agent that reaches evidence only through tool calls cannot make
one step of an investigation with a model that will not make one.

The refusals are gathered here so that their wording cannot drift apart. The
questions are identical at each moment but the remedy is not: a launch flag is
corrected with a shell command and a slash command with another slash command,
so the same refusal has to be said twice, in two vocabularies. Written out at
the call sites those two sets of messages diverge silently, and the console ends
up telling an operator to run something that does not exist where they are
standing.

Nothing in this module can see the session. That is deliberate: the case that is
open, the history being written and the evidence attached have no bearing on
whether a model is usable, and a check with nothing in reach cannot disturb what
the operator already has open while it decides. Each function either returns
silently or raises :class:`ValueError` naming what the operator has to do.

Writing the choice down belongs with the refusals rather than with the file
format, because the rule that a local endpoint never has a credential stored
beside it is a property of the selection itself. A caller that saved a
configuration without applying that rule would leave a key on disk for an
endpoint that never asked for one.
"""

from __future__ import annotations


def ensure_launch_model_is_usable(
    base_url: str,
    requested_model: str,
    *,
    default_model: str,
) -> None:
    """Refuse a launch that named no local model, or one this service cannot run.

    ``default_model`` is what the console falls back to when the operator named
    nothing. Against a local service its presence can only mean that nobody
    chose, because the fallback names a hosted model no local service installs.
    """

    from forensic_agent.core.environ import local_models

    installed = local_models(base_url)
    names = {entry["name"] for entry in installed}
    capable = {entry["name"] for entry in installed if entry["supports_tools"]}
    if requested_model == default_model:
        raise ValueError(
            "Select a local model with --model. List installed models "
            "with: dfir-agent models"
        )
    if installed and requested_model not in names:
        raise ValueError(
            f"Model {requested_model} is not installed in local Ollama. "
            "List models with: dfir-agent models"
        )
    if requested_model in names and requested_model not in capable:
        raise ValueError(
            f"Model {requested_model} does not support tool calls and cannot "
            "run an investigation. Choose a tool-capable model with: "
            "dfir-agent models"
        )


def ensure_selected_model_is_usable(
    *,
    backend: str,
    base_url: str,
    api_key: str,
    model: str,
) -> None:
    """Refuse a selection the configured provider does not advertise for tool calls.

    The credential is reduced out of anything quoted back to the operator: a
    provider that is merely unreachable still answers with a message, and that
    message can carry the key that was sent to it.
    """

    from forensic_agent.core.environ import backend_status, local_models

    if backend == "ollama":
        discovered = local_models(base_url)
        if not discovered:
            raise ValueError(
                "Ollama is unavailable or has no installed models."
            )
        selected = next(
            (
                entry
                for entry in discovered
                if entry.get("name") == model
            ),
            None,
        )
        if selected is None:
            raise ValueError(
                f"Model {model} is not installed in local Ollama. "
                "List what is installed with: /model list"
            )
        if selected.get("supports_tools") is not True:
            raise ValueError(
                f"Model {model} does not advertise tool-call support and "
                "cannot run an investigation. List usable models with: "
                "/model list"
            )
        return

    status = backend_status(
        base_url,
        model=model,
        api_key=api_key,
    )
    if status.get("authenticated") is False:
        raise ValueError(
            "OpenRouter rejected the configured API key. Run /setup."
        )
    if not status.get("reachable"):
        detail = str(
            status.get("error") or "the provider did not respond"
        )
        if api_key:
            detail = detail.replace(api_key, "[REDACTED]")
        raise ValueError(
            f"OpenRouter is unavailable: {detail[:180]}"
        )
    if status.get("has_model") is not True:
        raise ValueError(
            f"OpenRouter does not advertise model {model}. "
            "List what the account can use with: /model list"
        )
    if status.get("model_supports_tools") is not True:
        # Refused rather than warned: this agent reaches evidence only
        # through tool calls, so such a model cannot make one step of an
        # investigation, and accepting it would defer a certain failure.
        raise ValueError(
            f"Model {model} does not advertise tool-call support and "
            "cannot run an investigation. List usable models with: "
            "/model list"
        )


def persist_provider_choice(
    *,
    backend: str,
    base_url: str,
    model: str,
    api_key: str,
) -> None:
    """Record the accepted selection as the default, and apply it to this process.

    Saved and applied together, so the console the operator is looking at and
    the console they start tomorrow cannot be configured differently by one
    command.
    """

    from forensic_agent.cli.setup import (
        ProviderConfiguration,
        apply_configuration,
        configuration_path,
        save_configuration,
    )

    configuration = ProviderConfiguration(
        backend=backend,
        base_url=base_url,
        model=model,
        # A local service validates no credential, so none is written down
        # beside one: a key stored for an endpoint that never asked for it is a
        # secret kept for no reason.
        api_key=api_key if backend == "openrouter" else "",
    )
    save_configuration(configuration, configuration_path())
    apply_configuration(configuration)
