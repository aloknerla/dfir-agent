"""Backend selection, local-model discovery, and .env loading."""

from __future__ import annotations

import json

import pytest

from forensic_agent.core import environ, environment_file


def test_explicit_ollama_backend_ignores_a_stale_remote_url(monkeypatch):
    """An explicit backend selection must override a stale .env URL.

    Otherwise, a stale DFA_BASE_URL silently restores remote execution even
    though the user explicitly selected a local backend.
    """

    monkeypatch.setattr(environment_file, "load_environment_file", lambda: {})
    monkeypatch.setenv("DFA_BACKEND", "ollama")
    monkeypatch.setenv("DFA_BASE_URL", "https://openrouter.ai/api/v1")
    monkeypatch.delenv("DFA_API_KEY", raising=False)
    monkeypatch.delenv("OLLAMA_BASE_URL", raising=False)

    base_url, api_key = environ.configured_backend()

    assert base_url == environ.OLLAMA_BASE_URL
    assert api_key == ""


def test_local_backend_keeps_an_explicit_loopback_url(monkeypatch):
    monkeypatch.setattr(environment_file, "load_environment_file", lambda: {})
    monkeypatch.setenv("DFA_BACKEND", "ollama")
    monkeypatch.setenv("DFA_BASE_URL", "http://127.0.0.1:11434/v1")
    monkeypatch.delenv("DFA_API_KEY", raising=False)

    assert environ.configured_backend()[0] == "http://127.0.0.1:11434/v1"


def test_local_models_reports_tool_capability(monkeypatch):
    """A model without tool support cannot conduct an agent investigation."""

    tags_payload = {
        "models": [
            {
                "name": "qwen3:30b-a3b",
                "size": 18_600_000_000,
                "details": {"parameter_size": "30.5B", "quantization_level": "Q4_K_M"},
            },
            {
                "name": "nomic-embed-text:latest",
                "size": 300_000_000,
                "details": {"parameter_size": "137M", "quantization_level": "F16"},
            },
        ]
    }

    class _Response:
        def __init__(self, payload):
            self.payload = payload

        def read(self):
            return json.dumps(self.payload).encode()

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def urlopen(request, **_kwargs):
        url = request if isinstance(request, str) else request.full_url
        if url.endswith("/api/tags"):
            return _Response(tags_payload)
        assert url.endswith("/api/show")
        requested = json.loads(request.data)
        capabilities = (
            ["completion", "tools"]
            if requested["model"] == "qwen3:30b-a3b"
            else ["embedding"]
        )
        return _Response({"capabilities": capabilities})

    monkeypatch.setattr(environ.urllib.request, "urlopen", urlopen)

    models = environ.local_models("http://localhost:11434/v1")

    assert [m["name"] for m in models] == ["qwen3:30b-a3b", "nomic-embed-text:latest"]
    assert models[0]["supports_tools"] is True
    assert models[1]["supports_tools"] is False
    assert models[0]["parameter_size"] == "30.5B"


def test_local_models_returns_empty_when_service_is_down(monkeypatch):
    def _fail(*args, **kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr(environ.urllib.request, "urlopen", _fail)

    assert environ.local_models("http://localhost:11434/v1") == []


@pytest.mark.parametrize(
    "url",
    [
        "https://openrouter.ai/api/v1",
        "http://192.168.1.10:11434/v1",
        "http://example.com:11434/v1",
        "https://localhost:11434/v1",
    ],
)
def test_local_endpoint_rejects_anything_that_is_not_loopback(url):
    """Local execution is valid only when data stays on the workstation."""

    from forensic_agent.cli.controlled import (
        ControlledConsoleError,
        validate_local_endpoint,
    )

    with pytest.raises(ControlledConsoleError):
        validate_local_endpoint(url)


@pytest.mark.parametrize(
    "url",
    ["http://localhost:11434/v1", "http://127.0.0.1:11434/v1"],
)
def test_local_endpoint_accepts_loopback(url):
    from forensic_agent.cli.controlled import validate_local_endpoint

    assert validate_local_endpoint(url) == url


def test_local_endpoint_accepts_docker_host_alias_only_in_container(monkeypatch):
    from forensic_agent.cli.controlled import (
        ControlledConsoleError,
        validate_local_endpoint,
    )

    url = "http://host.docker.internal:11434/v1"
    monkeypatch.delenv("DFA_CONTAINERIZED", raising=False)
    with pytest.raises(ControlledConsoleError):
        validate_local_endpoint(url)

    monkeypatch.setenv("DFA_CONTAINERIZED", "1")
    assert validate_local_endpoint(url) == url


def test_env_file_prefers_the_tool_over_the_working_directory(tmp_path, monkeypatch):
    """An arbitrary launch directory must not supply an unrelated .env file.

    For a forensic tool this is more than an inconvenience because credentials
    and tool paths would come from outside the intended setup.
    """

    package_root = tmp_path / "paket" / "forensic_agent"
    package_root.mkdir(parents=True)
    (tmp_path / "paket" / ".env").write_text("IZVOR=alat\n", encoding="utf-8")
    work = tmp_path / "predmet"
    work.mkdir()
    (work / ".env").write_text("IZVOR=radni-direktorij\n", encoding="utf-8")

    monkeypatch.setattr(
        environment_file, "__file__", str(package_root / "core" / "environment_file.py")
    )
    monkeypatch.chdir(work)

    candidates = environment_file._candidate_paths()
    tool_env = tmp_path / "paket" / ".env"
    work_env = work / ".env"
    assert candidates.index(tool_env) < candidates.index(work_env)
