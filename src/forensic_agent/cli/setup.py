"""Interactive and persistent model-provider configuration for the CLI."""

from __future__ import annotations

import os
import re
import sys
import tempfile
from collections.abc import Callable, Mapping, MutableMapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.markup import escape
from rich.prompt import Prompt

from forensic_agent.core.config import DEFAULT_MODEL
from forensic_agent.core.environ import (
    OPENROUTER_BASE_URL,
    ProviderEndpointError,
    backend_kind,
    backend_status,
    local_models,
    validate_local_endpoint_value,
    validate_openrouter_endpoint_value,
)

#: The model setup offers when the investigator simply presses Enter.  Aliased
#: rather than re-declared, so what setup saves is what an unconfigured run uses.
OPENROUTER_MODEL = DEFAULT_MODEL
LOCAL_OLLAMA_URL = "http://localhost:11434/v1"
CONTAINER_OLLAMA_URL = "http://host.docker.internal:11434/v1"

_MANAGED_KEYS = frozenset(
    {
        "DFA_BACKEND",
        "DFA_MODEL",
        "DFA_BASE_URL",
        "DFA_API_KEY",
        "OPENROUTER_API_KEY",
        "OPENROUTER_BASE_URL",
        "OLLAMA_BASE_URL",
    }
)
_ASSIGNMENT_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")


class SetupError(RuntimeError):
    """The requested provider configuration cannot be completed safely."""


class SetupCancelled(SetupError):
    """The user cancelled setup before any provider setting was changed."""


@dataclass(frozen=True, slots=True)
class ProviderConfiguration:
    """Provider settings selected by the user."""

    backend: str
    base_url: str
    model: str
    api_key: str = ""

    def environment(self) -> dict[str, str]:
        if self.backend == "ollama":
            return {
                "DFA_BACKEND": "ollama",
                "OLLAMA_BASE_URL": self.base_url,
                "DFA_MODEL": self.model,
            }
        return {
            "DFA_BACKEND": "openrouter",
            "OPENROUTER_API_KEY": self.api_key,
            "DFA_MODEL": self.model,
        }


def configuration_path(
    environment: Mapping[str, str] | None = None,
    *,
    home: Path | None = None,
) -> Path:
    """Return the explicit installation config or the per-user native default."""

    env = os.environ if environment is None else environment
    explicit = (env.get("DFA_ENV_FILE") or "").strip()
    if explicit:
        return Path(explicit).expanduser()
    return (Path.home() if home is None else home) / ".dfir-agent" / ".env"


def _usable_secret(value: str | None) -> bool:
    normalized = (value or "").strip()
    if not normalized:
        return False
    folded = normalized.casefold()
    return not any(
        marker in folded
        for marker in (
            "replace-with",
            "replace_with",
            "your-api-key",
            "your_api_key",
            "changeme",
            "<api",
        )
    )


def configuration_ready(base_url: str, api_key: str | None, model: str | None) -> bool:
    """Return whether provider settings are syntactically complete.

    This check performs no network requests. Interactive startup must additionally
    call :func:`validate_saved_configuration` before constructing a session.
    """

    if backend_kind(base_url) == "ollama":
        return bool((model or "").strip())
    if backend_kind(base_url) == "openrouter":
        return _usable_secret(api_key)
    return bool((model or "").strip() and _usable_secret(api_key))


def validate_saved_configuration(
    *,
    base_url: str,
    api_key: str | None,
    model: str | None,
    backend_probe: Callable[..., Mapping[str, Any]] = backend_status,
    model_discovery: Callable[..., list[dict[str, Any]]] = local_models,
) -> ProviderConfiguration:
    """Validate one saved provider selection before interactive startup."""

    selected_model = (model or "").strip()
    if not configuration_ready(base_url, api_key, selected_model):
        raise SetupError("The saved provider configuration is incomplete.")

    kind = backend_kind(base_url)
    try:
        if kind == "ollama":
            validated_url = validate_local_endpoint_value(base_url)
        elif kind == "openrouter":
            validated_url = validate_openrouter_endpoint_value(
                base_url,
                api_key,
            )
        else:
            raise SetupError(
                "The saved provider endpoint is unsupported by the interactive CLI."
            )
    except ProviderEndpointError as exc:
        raise SetupError(str(exc)) from exc

    if kind == "ollama":
        discovered = model_discovery(validated_url)
        selected = next(
            (
                entry
                for entry in discovered
                if entry.get("name") == selected_model
            ),
            None,
        )
        if selected is None:
            if discovered:
                raise SetupError(
                    f"Saved Ollama model {selected_model} is not installed."
                )
            raise SetupError(
                "Ollama is unavailable or returned no installed models."
            )
        if selected.get("supports_tools") is not True:
            raise SetupError(
                f"Saved Ollama model {selected_model} does not advertise "
                "tool-call support."
            )
        return ProviderConfiguration(
            backend="ollama",
            base_url=validated_url,
            model=selected_model,
        )

    assert isinstance(api_key, str)
    status = backend_probe(
        validated_url,
        model=selected_model,
        api_key=api_key,
    )
    if status.get("authenticated") is False:
        raise SetupError("OpenRouter rejected the saved API key.")
    if not status.get("reachable"):
        detail = str(status.get("error") or "the provider did not respond")
        detail = detail.replace(api_key, "[REDACTED]")
        raise SetupError(f"OpenRouter is unavailable: {detail[:180]}")
    if status.get("has_model") is not True:
        raise SetupError(
            f"Saved model {selected_model} is not available on OpenRouter."
        )
    if status.get("model_supports_tools") is not True:
        raise SetupError(
            f"Saved model {selected_model} does not advertise tool-call support."
        )
    return ProviderConfiguration(
        backend="openrouter",
        base_url=validated_url,
        model=selected_model,
        api_key=api_key,
    )


def _dotenv_value(value: str) -> str:
    if "\n" in value or "\r" in value or "\x00" in value:
        raise SetupError("A configuration value contains a forbidden control character.")
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def save_configuration(configuration: ProviderConfiguration, path: Path) -> None:
    """Atomically update provider settings while preserving unrelated options."""

    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    retained: list[str] = []
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            match = _ASSIGNMENT_RE.match(line)
            if match and match.group(1) in _MANAGED_KEYS:
                continue
            retained.append(line)

    while retained and not retained[-1].strip():
        retained.pop()
    if retained:
        retained.append("")
    retained.append("# Model provider selected by dfir-agent")
    retained.extend(
        f"{key}={_dotenv_value(value)}"
        for key, value in configuration.environment().items()
    )
    payload = "\n".join(retained) + "\n"

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
        text=True,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            temporary.chmod(0o600)
        except OSError:
            pass
        os.replace(temporary, path)
        try:
            path.chmod(0o600)
        except OSError:
            pass
    finally:
        temporary.unlink(missing_ok=True)


def apply_configuration(
    configuration: ProviderConfiguration,
    environment: MutableMapping[str, str] | None = None,
) -> None:
    """Apply a saved selection to the current process without exposing secrets."""

    env = os.environ if environment is None else environment
    for key in _MANAGED_KEYS:
        env.pop(key, None)
    env.update(configuration.environment())


def _default_ollama_url(environment: Mapping[str, str]) -> str:
    if environment.get("DFA_CONTAINERIZED") == "1":
        return CONTAINER_OLLAMA_URL
    return LOCAL_OLLAMA_URL


def _ask_openrouter_key(
    *,
    console: Console,
    fallback: Callable[..., str],
) -> str:
    """Read a pasted secret with visible masking on an interactive terminal."""

    console.print(
        "[grey50]Paste with Ctrl+V or right-click, then press Enter. "
        "Only masking characters are shown; the key is not saved to terminal history.[/]"
    )
    if sys.stdin.isatty() and sys.stdout.isatty():
        try:
            from prompt_toolkit.shortcuts import prompt

            return str(prompt("OpenRouter API key: ", is_password=True))
        except (ImportError, OSError):
            pass
    return str(
        fallback(
            "OpenRouter API key",
            password=True,
            console=console,
        )
    )


def _configure_openrouter(
    *,
    console: Console,
    ask: Callable[..., str],
    backend_probe: Callable[..., Mapping[str, Any]],
) -> ProviderConfiguration:
    console.print(
        # This value is what an unconfigured run uses; a caller that pins its own
        # model id passes it explicitly rather than relying on this default.
        f"\n[grey50]Press Enter to use the default model "
        f"({OPENROUTER_MODEL}), or enter another OpenRouter model ID.[/]"
    )
    model = ask(
        "DFIR-AGENT model",
        default=OPENROUTER_MODEL,
        console=console,
    ).strip()
    if not model or any(character.isspace() for character in model):
        raise SetupError("The OpenRouter model ID is invalid.")
    api_key = _ask_openrouter_key(console=console, fallback=ask).strip()
    if not _usable_secret(api_key):
        raise SetupError("The OpenRouter API key is invalid.")
    with console.status("[grey50]Checking model availability…[/]"):
        status = backend_probe(
            OPENROUTER_BASE_URL,
            model=model,
            api_key=api_key,
        )
    if status.get("authenticated") is False:
        detail = str(status.get("error") or "the API key was rejected").replace(
            api_key,
            "[REDACTED]",
        )
        raise SetupError(f"OpenRouter rejected the API key: {detail[:180]}")
    if not status.get("reachable"):
        detail = str(status.get("error") or "the provider did not respond").replace(
            api_key,
            "[REDACTED]",
        )
        raise SetupError(
            "OpenRouter could not validate the API key and model: "
            f"{detail[:180]}"
        )
    if status.get("has_model") is not True:
        raise SetupError(
            f"OpenRouter does not advertise model {model}. "
            "Enter a current OpenRouter model ID."
        )
    if status.get("model_supports_tools") is not True:
        raise SetupError(
            f"OpenRouter model {model} does not advertise tool-call support. "
            "Choose a model whose supported parameters include tools."
        )
    return ProviderConfiguration(
        backend="openrouter",
        base_url=OPENROUTER_BASE_URL,
        model=model,
        api_key=api_key,
    )


def _configure_ollama(
    *,
    console: Console,
    ask: Callable[..., str],
    environment: Mapping[str, str],
    model_discovery: Callable[..., list[dict[str, Any]]],
) -> ProviderConfiguration:
    base_url = _default_ollama_url(environment)
    discovered = model_discovery(base_url)
    usable = [entry for entry in discovered if entry.get("supports_tools")]
    if not usable:
        if (
            environment.get("DFA_CONTAINERIZED") == "1"
            and environment.get("DFA_HOST_PLATFORM") == "linux"
        ):
            host_hint = (
                "Start Ollama on the Linux host and configure it to listen "
                "on an address reachable from Docker; the default loopback-only "
                "listener is not reachable from a bridge container. Set "
                "OLLAMA_HOST=0.0.0.0 (e.g. a systemd override) and allow the "
                "docker bridge subnet through the firewall; rootless Docker "
                "may additionally block host loopback via slirp4netns."
            )
        elif environment.get("DFA_CONTAINERIZED") == "1":
            host_hint = "Start Ollama on the host and allow access from Docker."
        else:
            host_hint = "Start Ollama and install a model that supports tool calls."
        raise SetupError(
            "No local Ollama model with tool-call support was found. " + host_hint
        )
    console.print("\nAvailable models with tool support:")
    for index, entry in enumerate(usable, start=1):
        details = ", ".join(
            value
            for value in (
                str(entry.get("parameter_size") or ""),
                str(entry.get("quantization") or ""),
            )
            if value
        )
        suffix = f" [grey50]{escape(details)}[/]" if details else ""
        console.print(
            f"  [bold]{index}[/]  "
            f"{escape(str(entry['name']))}{suffix}"
        )
    selected = ask(
        "Model",
        choices=tuple(str(index) for index in range(1, len(usable) + 1)),
        default="1",
        console=console,
    )
    return ProviderConfiguration(
        backend="ollama",
        base_url=base_url,
        model=str(usable[int(selected) - 1]["name"]),
    )


def run_setup(
    *,
    console: Console,
    ask: Callable[..., str] = Prompt.ask,
    environment: MutableMapping[str, str] | None = None,
    model_discovery: Callable[..., list[dict[str, Any]]] = local_models,
    backend_probe: Callable[..., Mapping[str, Any]] = backend_status,
    destination: Path | None = None,
    persist: bool = True,
) -> ProviderConfiguration:
    """Guide the user through OpenRouter or Ollama setup."""

    env = os.environ if environment is None else environment
    console.print()
    console.print("[bold #7aa2f7]DFIR-AGENT setup[/]")
    console.print(
        "[grey50]Choose remote OpenRouter or local Ollama. "
        "You can change this later with /setup.[/]"
    )
    provider: str | None = None
    while True:
        if provider is None:
            provider = ask(
                "Provider [1: OpenRouter, 2: Ollama, c: Cancel]",
                choices=("1", "2", "c"),
                default="1",
                console=console,
            )
            if provider == "c":
                raise SetupCancelled("Setup cancelled.")
        try:
            if provider == "1":
                configuration = _configure_openrouter(
                    console=console,
                    ask=ask,
                    backend_probe=backend_probe,
                )
            else:
                configuration = _configure_ollama(
                    console=console,
                    ask=ask,
                    environment=env,
                    model_discovery=model_discovery,
                )
            break
        except SetupError as exc:
            console.print(f"\n[bold red]Setup failed:[/] {escape(str(exc))}")
            action = ask(
                "Next [r: Retry, b: Back, c: Cancel]",
                choices=("r", "b", "c"),
                default="r",
                console=console,
            )
            if action == "c":
                raise SetupCancelled("Setup cancelled.") from exc
            if action == "b":
                provider = None

    if persist:
        target = destination or configuration_path(env)
        save_configuration(configuration, target)
        apply_configuration(configuration, env)
        console.print(
            f"\n[#73daca]✓ Configuration saved.[/] "
            f"[grey50]{escape(str(target))}[/]"
        )
        console.print(
            f"[grey50]Active provider: {escape(configuration.backend)}; "
            f"model: {escape(configuration.model)}. "
            "The API key is never displayed or logged.[/]\n"
        )
    return configuration
