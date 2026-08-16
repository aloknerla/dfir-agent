"""Environment resolution and a preflight 'doctor' check.

Cross-platform: external forensic tools (Plaso's psort, Volatility's vol) are
resolved at call time via an explicit env var, then the system PATH, then the
active Python's script directory — never a hardcoded absolute path. This is what
makes forensic agent portable across machines and operating systems.
"""
from __future__ import annotations

import importlib
import json
import os
import sys
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from forensic_agent.core.environment_file import (
    environment_file_state,
    load_environment_file,
)
from forensic_agent.core.tool_availability import (
    IS_WIN,
    available_tools,
    resolve_tool,
    tool_path,
)

__all__ = [
    "IS_WIN",
    "OLLAMA_BASE_URL",
    "OPENROUTER_BASE_URL",
    "ModelCatalogError",
    "ProviderEndpointError",
    "SCOPE_TRIAGE_ENVIRONMENT_VARIABLE",
    "available_tools",
    "backend_kind",
    "backend_status",
    "bulk_extractor_path",
    "catalog_models",
    "clamscan_path",
    "configured_backend",
    "curated_wordlist_path",
    "doctor",
    "john_path",
    "local_models",
    "mergecap_path",
    "regripper_path",
    "resolve_tool",
    "scope_triage_enabled",
    "seven_zip_path",
    "tesseract_path",
    "tshark_path",
    "validate_local_endpoint_value",
    "validate_openrouter_endpoint_value",
    "vol_path",
]
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
#: Default local Ollama endpoint. Used only when DFA_BACKEND=ollama.
OLLAMA_BASE_URL = "http://localhost:11434/v1"


class ProviderEndpointError(ValueError):
    """A provider endpoint would violate the interactive trust boundary."""


class ModelCatalogError(RuntimeError):
    """The provider catalogue could not be read, so no listing exists.

    Raised rather than returning an empty list. A console that prints nothing
    after a failed fetch states that the account has no models available, and
    that is a different — and false — claim from "the catalogue could not be
    fetched". The operator has to be able to tell the two apart before they
    conclude anything about the run.
    """


def validate_openrouter_endpoint_value(
    base_url: str,
    api_key: str | None,
) -> str:
    """Accept only the canonical OpenRouter API before sending a credential."""

    candidate = (base_url or "").strip().rstrip("/")
    parsed = urlsplit(candidate)
    if (
        parsed.scheme.casefold() != "https"
        or parsed.hostname is None
        or parsed.hostname.casefold() != "openrouter.ai"
        or parsed.port not in (None, 443)
        or parsed.path.rstrip("/") != "/api/v1"
        or parsed.username is not None
        or parsed.password is not None
        or bool(parsed.query)
        or bool(parsed.fragment)
    ):
        raise ProviderEndpointError(
            "The interactive terminal only permits https://openrouter.ai/api/v1."
        )
    if (
        not isinstance(api_key, str)
        or not api_key.strip()
        or api_key.casefold() == "ollama"
    ):
        raise ProviderEndpointError("The OpenRouter API key is not configured.")
    return OPENROUTER_BASE_URL


def validate_local_endpoint_value(
    base_url: str,
    *,
    containerized: bool | None = None,
) -> str:
    """Accept only a loopback or Docker-host endpoint for local inference."""

    candidate = (base_url or "").strip().rstrip("/")
    parsed = urlsplit(candidate)
    host = (parsed.hostname or "").casefold()
    permitted_hosts = {"localhost", "127.0.0.1", "::1"}
    if containerized is None:
        containerized = os.environ.get("DFA_CONTAINERIZED") == "1"
    if containerized:
        permitted_hosts.add("host.docker.internal")
    if (
        parsed.scheme.casefold() != "http"
        or host not in permitted_hosts
        or parsed.username is not None
        or parsed.password is not None
        or bool(parsed.query)
        or bool(parsed.fragment)
    ):
        raise ProviderEndpointError(
            "The local provider must use a loopback host address."
        )
    return candidate


# The per-tool helpers below own no discovery logic: each asks the single
# availability registry in ``core.tool_availability`` for the same id that
# ``doctor`` and ``/tools`` ask about, so the three surfaces cannot drift apart.


def vol_path():
    return tool_path("vol")


def clamscan_path():
    return tool_path("clamscan")


def tshark_path():
    return tool_path("tshark")


def mergecap_path():
    return tool_path("mergecap")


def seven_zip_path():
    return tool_path("seven_zip")


def tesseract_path():
    return tool_path("tesseract")


def regripper_path():
    return tool_path("regripper")


def bulk_extractor_path():
    return tool_path("bulk_extractor")


def john_path():
    return tool_path("john")


#: Pinned in-image wordlist consulted by the offline dictionary attack (John's
#: ``--wordlist``). It is a DEPLOYMENT asset, not a call argument:
#: no operation accepts a wordlist path, so a passphrase can never be recovered
#: against a model- or case-chosen list. ``DFA_WORDLIST`` relocates the asset for
#: a different image layout; the default is the path the Dockerfile is expected
#: to populate.
_CURATED_WORDLIST_DEFAULT = "/opt/wordlists/curated.txt"


def curated_wordlist_path():
    """Absolute path of the pinned dictionary asset, honouring the image layout.

    Existence is the caller's concern: the resolver only names the location so
    that a build without the asset fails with a stated reason instead of a
    silently empty attack.
    """

    override = (os.environ.get("DFA_WORDLIST") or "").strip()
    return override or _CURATED_WORDLIST_DEFAULT


#: Environment override that takes the console's scope triage OUT of a session.
#:
#: The triage asks the SAME configured model, before an investigation is opened,
#: whether the input concerns the loaded case, and refuses it when the answer is
#: OFFTOPIC (``cli/scope_check.py::question_in_scope()``). That costs one request
#: of the model under test, and a weaker model spends it badly: measured against
#: ``openai/gpt-oss-120b`` and ``openai/gpt-oss-20b`` it refused legitimate
#: Croatian follow-up questions, so the comparison scored the triage rather than
#: the investigation.
#:
#: Default ON, so an ordinary session keeps the rail it has always had. Set the
#: variable to 0 to take the triage out and let every question through to the
#: investigation, which is the configuration a model comparison wants.
SCOPE_TRIAGE_ENVIRONMENT_VARIABLE = "DFA_SCOPE_TRIAGE"


def scope_triage_enabled() -> bool:
    """Whether the console asks the model to triage a question before running it."""

    raw = os.environ.get(SCOPE_TRIAGE_ENVIRONMENT_VARIABLE)
    if raw is None:
        return True
    return raw.strip().lower() not in ("0", "false", "off", "no")


def backend_kind(base_url):
    """Classify a configured endpoint without probing or changing it."""
    url = (base_url or "").lower()
    if "openrouter" in url:
        return "openrouter"
    if any(token in url for token in ("localhost", "127.0.0.1", ":11434")):
        return "ollama"
    return "openai-compatible"


def configured_backend():
    """Resolve the configured endpoint without an implicit local fallback.

    The supported CLI path defaults to OpenRouter. ``DFA_BASE_URL`` may still
    select another OpenAI-compatible endpoint explicitly, but a missing or broken
    OpenRouter configuration is reported as such and is never replaced with a
    localhost service.
    """
    # Resolution must not depend on another module having been imported first.
    # Without this call, a valid .env file remains unread when this module is
    # imported directly, and the key is incorrectly reported as unconfigured.
    load_environment_file()
    # DFA_BACKEND selects the service without requiring a full URL. Never infer
    # a local service: silently switching to localhost changes where evidence
    # data is sent.
    backend = (os.environ.get("DFA_BACKEND") or "").strip().casefold()
    if backend == "ollama":
        # Honor DFA_BASE_URL only when it points to a local service. Otherwise,
        # a stale .env value could override the explicit backend selection and
        # silently send execution back to a remote service.
        requested = os.environ.get("DFA_BASE_URL")
        if requested and backend_kind(requested) != "ollama":
            requested = None
        base_url = requested or os.environ.get("OLLAMA_BASE_URL") or OLLAMA_BASE_URL
    else:
        base_url = (
            os.environ.get("DFA_BASE_URL")
            or os.environ.get("OPENROUTER_BASE_URL")
            or OPENROUTER_BASE_URL
        )
    kind = backend_kind(base_url)
    explicit_key = os.environ.get("DFA_API_KEY")
    if kind == "ollama":
        # Never forward a remote credential to a local service, even if it
        # remains configured after the provider changes.
        api_key = ""
    elif explicit_key is not None:
        api_key = explicit_key
    elif kind == "openrouter":
        api_key = os.environ.get("OPENROUTER_API_KEY", "")
    else:
        # A local service needs no credential, and a real one is never sent.
        # The session supplies a placeholder if the client requires a value.
        api_key = ""
    return base_url, api_key


def local_models(base_url=None, timeout=4):
    """List locally installed Ollama models and their tool support.

    The agent operates exclusively through function calls, so a model without
    tool support cannot conduct an investigation regardless of its size.
    ``/api/tags`` reports installed models and ``/api/show`` reports their
    capabilities. Both endpoints are checked instead of inferring support from
    a model name.

    Returns dictionaries with ``name``, ``parameter_size``, ``quantization``,
    ``context_length``, ``size_bytes``, and ``supports_tools`` fields. Returns
    an empty list when the service is unavailable.
    """

    host = (base_url or OLLAMA_BASE_URL).removesuffix("/v1").rstrip("/")
    try:
        with urllib.request.urlopen(host + "/api/tags", timeout=timeout) as response:
            payload = json.load(response)
    except Exception:
        return []
    entries = payload.get("models")
    if not isinstance(entries, list):
        return []
    models = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name") or entry.get("model") or ""
        if not name:
            continue
        raw_details = entry.get("details")
        details: dict[str, object] = (
            dict(raw_details) if isinstance(raw_details, dict) else {}
        )
        capabilities = entry.get("capabilities")
        show_payload: dict[str, object] = {}
        if not isinstance(capabilities, list):
            try:
                show_request = urllib.request.Request(
                    host + "/api/show",
                    data=json.dumps({"model": name}).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(show_request, timeout=timeout) as response:
                    candidate = json.load(response)
                if isinstance(candidate, dict):
                    show_payload = candidate
                    capabilities = candidate.get("capabilities")
            except Exception:
                capabilities = []
        show_details = show_payload.get("details")
        if isinstance(show_details, dict):
            details = {**details, **show_details}
        raw_model_info = show_payload.get("model_info")
        model_info: dict[str, object] = (
            dict(raw_model_info) if isinstance(raw_model_info, dict) else {}
        )
        context_length = details.get("context_length")
        if context_length is None:
            context_lengths = [
                value
                for key, value in model_info.items()
                if str(key).endswith(".context_length") and isinstance(value, int)
            ]
            context_length = max(context_lengths, default=None)
        models.append(
            {
                "name": name,
                "parameter_size": details.get("parameter_size") or "",
                "quantization": details.get("quantization_level") or "",
                "context_length": context_length,
                "size_bytes": entry.get("size"),
                "supports_tools": bool(
                    isinstance(capabilities, list) and "tools" in capabilities
                ),
            }
        )
    models.sort(key=lambda item: (not item["supports_tools"], item["name"]))
    return models


def _usd_per_token(value):
    """Parse one price field into USD per token, or None when it is not stated.

    OpenRouter writes prices as decimal strings ("0.00000009"). A field that is
    absent or unparseable yields None rather than zero, because a free model and
    a model whose price could not be read are different facts and only one of
    them is safe to show as costing nothing.
    """

    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    if not isinstance(value, str):
        return None
    try:
        return float(value.strip())
    except ValueError:
        return None


def catalog_models(base_url, api_key=None, timeout=6):
    """Read the configured provider's model catalogue with price and capability.

    ``GET /models`` is the provider's own answer about what the configured key
    can address. Five fields are carried through and no others, because these
    are the ones whose meaning the OpenRouter reference states outright:

    * ``id`` — the identifier a request must carry, kept byte-identical.
    * ``context_length`` — the maximum context window, in TOKENS.
    * ``supported_parameters`` — the request parameters the model accepts.
      ``tools`` is the entry that means function calling, and a model without it
      can never conduct an investigation here; the flag is derived the same way
      ``local_models`` derives it for Ollama, so one meaning serves both.
    * ``pricing.prompt`` and ``pricing.completion`` — the cost of one input and
      one output token, in USD PER TOKEN. They are carried in that unit, with the
      unit named in the key, and converted only where they are displayed: a price
      that silently changes scale between here and the screen is exactly how a
      wrong number ends up printed under a confident label. The top-level keys
      are the prices that apply under default conditions; the conditional
      ``overrides`` are deliberately not reported, since no view here states the
      condition they would depend on.

    The request is bounded by ``timeout`` and is issued only when a listing is
    asked for — never to open the console. Nothing is cached, so what is shown is
    always the provider's current answer rather than a stale one wearing a fresh
    label.

    Raises :class:`ModelCatalogError` when the catalogue cannot be read.
    """

    headers = {"Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    request = urllib.request.Request(base_url.rstrip("/") + "/models", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as exc:
        raise ModelCatalogError(f"the provider answered HTTP {exc.code}") from exc
    except Exception as exc:
        raise ModelCatalogError(str(exc)[:140] or exc.__class__.__name__) from exc

    entries = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(entries, list):
        raise ModelCatalogError("the provider returned no model catalogue")

    catalog: list[dict[str, object]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        model_id = entry.get("id")
        if not isinstance(model_id, str) or not model_id:
            continue
        supported = entry.get("supported_parameters")
        supported_parameters = (
            tuple(str(parameter) for parameter in supported)
            if isinstance(supported, list)
            else ()
        )
        raw_pricing = entry.get("pricing")
        pricing = raw_pricing if isinstance(raw_pricing, dict) else {}
        context_length = entry.get("context_length")
        catalog.append(
            {
                "id": model_id,
                "context_length": (
                    context_length
                    if isinstance(context_length, int)
                    and not isinstance(context_length, bool)
                    else None
                ),
                "prompt_usd_per_token": _usd_per_token(pricing.get("prompt")),
                "completion_usd_per_token": _usd_per_token(pricing.get("completion")),
                "supports_tools": "tools" in supported_parameters,
            }
        )
    return catalog


def _openrouter_key_status(base_url, api_key, timeout):
    """Validate an OpenRouter key against an endpoint that requires auth."""

    request = urllib.request.Request(
        base_url.rstrip("/") + "/key",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.load(response)
        if not isinstance(payload.get("data"), dict):
            return {
                "reachable": True,
                "authenticated": False,
                "error": "OpenRouter returned an invalid key-status response",
            }
        return {"reachable": True, "authenticated": True}
    except urllib.error.HTTPError as exc:
        if exc.code in {401, 403}:
            return {
                "reachable": True,
                "authenticated": False,
                "error": f"OpenRouter rejected the configured API key (HTTP {exc.code})",
            }
        return {
            "reachable": False,
            "authenticated": None,
            "error": f"OpenRouter key validation failed (HTTP {exc.code})",
        }
    except Exception as exc:
        return {
            "reachable": False,
            "authenticated": None,
            "error": str(exc)[:140],
        }


def backend_status(base_url, model=None, api_key=None, timeout=4):
    """Probe exactly the configured backend and return its advertised models.

    Ollama exposes ``/api/tags`` with ``name`` fields. OpenRouter and other
    OpenAI-compatible services expose ``/v1/models`` with ``id`` fields. No
    fallback endpoint is attempted when the configured service is unavailable.
    """
    kind = backend_kind(base_url)
    if kind == "openrouter" and not api_key:
        return {
            "reachable": False,
            "authenticated": False,
            "models": [],
            "has_model": False if model else None,
            "kind": kind,
            "error": "OpenRouter API key is not configured",
        }

    authentication = None
    if kind == "openrouter":
        key_status = _openrouter_key_status(base_url, api_key, timeout)
        authentication = key_status["authenticated"]
        if authentication is not True:
            return {
                "reachable": key_status["reachable"],
                "authenticated": authentication,
                "models": [],
                "has_model": False if model else None,
                "kind": kind,
                "error": key_status["error"],
            }

    if kind == "ollama":
        host = base_url.removesuffix("/v1").rstrip("/")
        url = host + "/api/tags"
        request = urllib.request.Request(url)
    else:
        url = base_url.rstrip("/") + "/models"
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as r:
            data = json.load(r)
        entries = data.get("models", []) if kind == "ollama" else data.get("data", [])
        model_details: list[dict[str, object]] = []
        if kind == "ollama":
            models = [m.get("name") or m.get("model") for m in entries]
        else:
            # OpenAI-compatible /models objects often include both a display
            # ``name`` and a canonical ``id``. Requests use the ID, so checking
            # the display name produces a false negative for a valid model.
            models = []
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                model_id = entry.get("id") or entry.get("name")
                if not isinstance(model_id, str) or not model_id:
                    continue
                supported = entry.get("supported_parameters")
                supported_parameters = (
                    tuple(
                        str(parameter)
                        for parameter in supported
                        if isinstance(parameter, str)
                    )
                    if isinstance(supported, list)
                    else ()
                )
                models.append(model_id)
                model_details.append(
                    {
                        "id": model_id,
                        "name": str(entry.get("name") or model_id),
                        "supported_parameters": supported_parameters,
                        "supports_tools": (
                            "tools" in supported_parameters
                            if isinstance(supported, list)
                            else None
                        ),
                    }
                )
        models = [m for m in models if m]
        result = {
            "reachable": True,
            "models": models,
            "has_model": (model in models) if model else None,
            "kind": kind,
        }
        if model_details:
            result["model_details"] = model_details
        if model and model_details:
            selected = next(
                (
                    entry
                    for entry in model_details
                    if entry.get("id") == model
                ),
                None,
            )
            result["model_supports_tools"] = (
                selected.get("supports_tools") if selected is not None else None
            )
        if kind == "openrouter":
            result["authenticated"] = authentication
        return result
    except Exception as e:
        result = {
            "reachable": False,
            "models": [],
            "has_model": False if model else None,
            "kind": kind,
            "error": str(e)[:140],
        }
        if kind == "openrouter":
            result["authenticated"] = authentication
        return result


def _has(mod):
    try:
        importlib.import_module(mod)
        return True
    except Exception:
        return False


def doctor(base_url=OPENROUTER_BASE_URL, model=None, api_key=None):
    """Return a list of (component, ok, detail, fix_hint) preflight rows."""
    rows = []

    def add(name, ok, detail="", hint="", *, required=True, tool_id="", env_var=""):
        rows.append(
            {
                "name": name,
                "ok": bool(ok),
                "detail": detail,
                "hint": hint,
                "required": bool(required),
                # Present only on rows derived from the external-tool registry.
                # The renderer uses them to name the override variable, so the
                # investigator is told exactly which value to set.
                "tool_id": tool_id,
                "env_var": env_var,
            }
        )

    # runtime
    add("Python >= 3.11", sys.version_info >= (3, 11), sys.version.split()[0],
        "Install Python 3.11 or newer from python.org")

    # Report the configuration source. Docker Compose passes .env values as
    # environment variables, so the file itself is absent from the container;
    # that absence must not be reported as a failure.
    load_environment_file()
    env_state = environment_file_state()
    environment_configured = bool(
        api_key
        or os.environ.get("OPENROUTER_API_KEY")
        or os.environ.get("DFA_API_KEY")
    )
    config_available = bool(env_state.get("loaded")) or environment_configured
    config_source = str(env_state.get("path") or "")
    if environment_configured and not config_source:
        config_source = "environment variables"
    add(
        "Configuration",
        config_available,
        config_source,
        (
            f"{env_state.get('reason') or 'not loaded'}; copy .env.example to "
            ".env or set DFA_ENV_FILE to the configuration file path"
        ),
        required=False,
    )

    # The console's own pre-run rail, reported because a session that runs
    # without it answers questions an ordinary session refuses. A measurement
    # taken with the triage off must be readable as such from the preflight, not
    # inferred later from an absent refusal.
    triage_on = scope_triage_enabled()
    add(
        "Question scope triage",
        triage_on,
        (
            "on — off-case questions are refused before a run starts"
            if triage_on
            else f"off — {SCOPE_TRIAGE_ENVIRONMENT_VARIABLE}=0, every question reaches the model"
        ),
        f"Unset {SCOPE_TRIAGE_ENVIRONMENT_VARIABLE} (or set it to 1) to restore the triage",
        required=False,
    )

    # Core dependencies (the agent cannot run without them).
    for mod, label, hint in [
        ("openai", "openai", "pip install openai"),
        ("langchain", "langchain", "pip install langchain"),
        ("langgraph", "langgraph", "pip install langgraph"),
        ("langchain_openai", "langchain-openai", "pip install langchain-openai"),
        ("rich", "rich (color terminal UI)", "pip install rich"),
        (
            "prompt_toolkit",
            "prompt-toolkit (history and command completion)",
            "pip install prompt-toolkit",
        ),
    ]:
        add(label, _has(mod), "", hint)

    # File-system support (the foundational forensic capability).
    add("pytsk3 (file system)", _has("pytsk3"), "", "pip install pytsk3")
    add("pyewf (E01/EWF images)", _has("pyewf"), "", "pip install libewf-python")

    # Optional Python dependencies used by the interactive forensic console.
    # Statistical analysis packages are not part of the product environment and
    # are therefore not checked here.
    for mod, label, hint in [
        ("regipy", "regipy (Registry)", "pip install regipy"),
    ]:
        add(label, _has(mod), "", hint, required=False)

    # External command-line tools. Every row is derived from the one availability
    # registry, so this report can never claim a tool the model-visible registry
    # treats as missing (or the reverse).
    scan_image = os.environ.get("DFA_MEMORY_SCAN_DOCKER_IMAGE", "").strip()
    for status in available_tools().values():
        if status.id == "clamscan" and scan_image:
            # With the container route configured, a missing local clamscan is
            # not a gap: report the route that will actually run, and whether it
            # can run. Availability of the tool itself is still the registry's
            # answer; only the reported route changes.
            add("ClamAV — containerized scanning",
                bool(resolve_tool(["docker"], "DFA_DOCKER")),
                scan_image,
                "install Docker or unset DFA_MEMORY_SCAN_DOCKER_IMAGE",
                required=False)
            continue
        add(
            status.doctor_label,
            status.available,
            status.path or "",
            status.hint,
            required=False,
            tool_id=status.id,
            env_var=status.env_var,
        )

    # backend / model
    b = backend_status(base_url, model, api_key=api_key)
    kind = b["kind"]
    label = {"ollama": "Ollama", "openrouter": "OpenRouter",
             "openai-compatible": "OpenAI-compatible"}[kind]
    if kind == "ollama":
        backend_hint = "Install and start Ollama, then run `ollama serve`"
    elif kind == "openrouter":
        backend_hint = "Check the OpenRouter URL and configure the API key"
    else:
        backend_hint = "Check the configured backend URL, network connection, and credentials"
    add(f"{label} backend available", b["reachable"],
        base_url if b["reachable"] else b.get("error", ""), backend_hint)
    if kind == "ollama":
        # Two server-side settings the OpenAI-compatible endpoint cannot carry
        # per request. Without them the agent's ~16k-token turns are silently
        # truncated to the 4096-token default window, and the model unloads
        # after five idle minutes — mid-run, during a long tool phase.
        context_setting = os.environ.get("OLLAMA_CONTEXT_LENGTH", "").strip()
        add(
            "Ollama context window",
            bool(context_setting),
            (
                f"OLLAMA_CONTEXT_LENGTH={context_setting}"
                if context_setting
                else "server default (4096 tokens) — agent turns will be truncated"
            ),
            "Set OLLAMA_CONTEXT_LENGTH=16384 (or higher) where the Ollama "
            "server runs; the per-request API cannot raise it",
            required=False,
        )
        keep_alive = os.environ.get("OLLAMA_KEEP_ALIVE", "").strip()
        add(
            "Ollama keep-alive",
            bool(keep_alive),
            (
                f"OLLAMA_KEEP_ALIVE={keep_alive}"
                if keep_alive
                else "server default (5m) — the model can unload mid-run"
            ),
            "Set OLLAMA_KEEP_ALIVE=30m where the Ollama server runs so long "
            "tool phases do not pay a full model reload",
            required=False,
        )
    if kind == "openrouter":
        authenticated = b.get("authenticated") is True
        add(
            "OpenRouter API key valid",
            authenticated,
            "authenticated" if authenticated else b.get("error", ""),
            "Run `dfir-agent setup` and enter a current OpenRouter API key",
        )
    if model and not (
        kind == "openrouter" and b.get("authenticated") is not True
    ):
        if kind == "ollama":
            model_label = f"Model '{model}' installed"
            model_detail = f"{len(b.get('models', []))} local models" if b["reachable"] else ""
            model_hint = f"ollama pull {model}"
        else:
            model_label = f"Model '{model}' available on {label}"
            model_detail = f"{len(b.get('models', []))} available models" if b["reachable"] else ""
            model_hint = f"Check model identifier '{model}' with the configured provider"
        has_model = bool(b.get("has_model"))
        supports_tools: object = b.get("model_supports_tools")
        if has_model and kind == "ollama":
            local_entry = next(
                (
                    entry
                    for entry in local_models(base_url)
                    if entry.get("name") == model
                ),
                None,
            )
            supports_tools = (
                local_entry.get("supports_tools")
                if local_entry is not None
                else False
            )
        checks_tools = has_model and kind in {"ollama", "openrouter"}
        tool_hint = (
            "Select a model that advertises function or tool calling "
            "with `dfir-agent setup`"
        )
        if checks_tools and supports_tools is True:
            # Both facts on one line. They were two, and each named the model
            # again: "Model 'x' available on OpenRouter" directly above
            # "Model 'x' supports tool calls" told the reader the model's name
            # twice and its state once. One line, one name, both facts — and
            # only while they agree, because a model that is present but has no
            # tool calling is a pass and a failure, which cannot share a mark.
            add(
                f"{model_label}, with tool calls",
                True,
                ", ".join(part for part in (model_detail, "tool calling advertised") if part),
                model_hint,
            )
        else:
            add(model_label, has_model, model_detail, model_hint)
            if checks_tools:
                add(
                    f"Model '{model}' supports tool calls",
                    False,
                    "tool calling not advertised",
                    tool_hint,
                )

    return rows
