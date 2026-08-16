import os
from io import BytesIO

# Discovery itself now lives in the single availability registry that doctor,
# /tools and the model-visible registry all read; environ re-exports it.
from forensic_agent.core import environ, tool_availability


class _Response(BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def test_resolve_missing():
    assert environ.resolve_tool(["definitely_not_a_real_tool_xyz123"]) is None


def test_resolve_env_override(tmp_path):
    f = tmp_path / "fake_tool"
    f.write_text("x")
    f.chmod(0o700)
    os.environ["DFA_TESTTOOL"] = str(f)
    try:
        assert environ.resolve_tool(["nope"], "DFA_TESTTOOL") == str(f)
    finally:
        del os.environ["DFA_TESTTOOL"]


def test_resolve_rejects_directory_and_non_executable_posix_file(tmp_path, monkeypatch):
    monkeypatch.setattr(tool_availability, "IS_WIN", False)
    monkeypatch.setattr(tool_availability.os, "access", lambda _path, _mode: False)
    directory = tmp_path / "not-a-tool"
    directory.mkdir()
    monkeypatch.setenv("DFA_TESTTOOL", str(directory))
    assert environ.resolve_tool(["nope"], "DFA_TESTTOOL") is None

    file = tmp_path / "not-executable"
    file.write_text("x")
    file.chmod(0o600)
    monkeypatch.setenv("DFA_TESTTOOL", str(file))
    assert environ.resolve_tool(["nope"], "DFA_TESTTOOL") is None


def test_resolve_prefers_active_virtualenv_over_global_path(tmp_path, monkeypatch):
    scripts = tmp_path / "venv" / "Scripts"
    scripts.mkdir(parents=True)
    active_tool = scripts / "psort.exe"
    active_tool.write_text("active")
    monkeypatch.setattr(tool_availability.sys, "executable", str(scripts / "python.exe"))
    monkeypatch.setattr(tool_availability, "IS_WIN", True)
    monkeypatch.setattr(
        tool_availability.shutil, "which", lambda _name: r"C:\Python312\psort.exe"
    )

    assert environ.resolve_tool(["psort"]) == str(active_tool)


def test_backend_unreachable():
    st = environ.backend_status("http://127.0.0.1:59999/v1", timeout=1)
    assert st["reachable"] is False
    assert st["models"] == []
    assert st["kind"] == "ollama"


def test_backend_status_probes_local_ollama_only(monkeypatch):
    requested = []

    def fake_urlopen(request, timeout):
        requested.append((request.full_url, request.get_header("Authorization"), timeout))
        return _Response(b'{"models":[{"name":"local-model"}]}')

    monkeypatch.setattr(environ.urllib.request, "urlopen", fake_urlopen)
    st = environ.backend_status(
        "http://localhost:11434/v1", model="local-model", timeout=2
    )
    assert st == {
        "reachable": True,
        "models": ["local-model"],
        "has_model": True,
        "kind": "ollama",
    }
    assert requested == [("http://localhost:11434/api/tags", None, 2)]


def test_backend_status_probes_openrouter_only_with_auth(monkeypatch):
    requested = []

    def fake_urlopen(request, timeout):
        requested.append((request.full_url, request.get_header("Authorization"), timeout))
        if request.full_url.endswith("/key"):
            return _Response(b'{"data":{"label":"test-key"}}')
        # OpenRouter's real shape includes a human-readable name as well as the
        # canonical request ID. The ID must win even when name appears first.
        return _Response(
            b'{"data":[{"id":"openai/gpt-oss-120b",'
            b'"name":"OpenAI: gpt-oss-120b",'
            b'"supported_parameters":["tools","tool_choice"],'
            b'"created":1754430000}]}'
        )

    monkeypatch.setattr(environ.urllib.request, "urlopen", fake_urlopen)
    st = environ.backend_status(
        "https://openrouter.ai/api/v1",
        model="openai/gpt-oss-120b",
        api_key="test-key",
        timeout=3,
    )
    assert st == {
        "reachable": True,
        "models": ["openai/gpt-oss-120b"],
        "has_model": True,
        "kind": "openrouter",
        "authenticated": True,
        "model_details": [
            {
                "id": "openai/gpt-oss-120b",
                "name": "OpenAI: gpt-oss-120b",
                "supported_parameters": ("tools", "tool_choice"),
                "supports_tools": True,
            }
        ],
        "model_supports_tools": True,
    }
    assert requested == [
        ("https://openrouter.ai/api/v1/key", "Bearer test-key", 3),
        ("https://openrouter.ai/api/v1/models", "Bearer test-key", 3)
    ]


def test_backend_status_rejects_invalid_openrouter_key_before_model_probe(
    monkeypatch,
):
    requested = []

    def fake_urlopen(request, timeout):
        requested.append((request.full_url, timeout))
        raise environ.urllib.error.HTTPError(
            request.full_url,
            401,
            "Unauthorized",
            {},
            None,
        )

    monkeypatch.setattr(environ.urllib.request, "urlopen", fake_urlopen)
    status = environ.backend_status(
        "https://openrouter.ai/api/v1",
        model="openai/gpt-oss-120b",
        api_key="revoked-key",
        timeout=3,
    )

    assert status["reachable"] is True
    assert status["authenticated"] is False
    assert status["has_model"] is False
    assert "HTTP 401" in status["error"]
    assert requested == [("https://openrouter.ai/api/v1/key", 3)]


def test_openrouter_without_key_never_falls_back_or_probes(monkeypatch):
    def unexpected_probe(*_args, **_kwargs):
        raise AssertionError("no endpoint should be probed without the configured key")

    monkeypatch.setattr(environ.urllib.request, "urlopen", unexpected_probe)
    st = environ.backend_status(
        "https://openrouter.ai/api/v1", model="openai/gpt-oss-120b", api_key=""
    )
    assert st["reachable"] is False
    assert st["kind"] == "openrouter"
    assert "key" in st["error"].lower()


def test_configured_backend_uses_openrouter_without_local_fallback(monkeypatch):
    for name in (
        "DFA_BASE_URL", "DFA_API_KEY", "OPENROUTER_BASE_URL", "OPENROUTER_API_KEY"
    ):
        monkeypatch.delenv(name, raising=False)

    assert environ.configured_backend() == (environ.OPENROUTER_BASE_URL, "")

    monkeypatch.setenv("OPENROUTER_API_KEY", "remote-key")
    assert environ.configured_backend() == (environ.OPENROUTER_BASE_URL, "remote-key")

    monkeypatch.delenv("OPENROUTER_API_KEY")
    monkeypatch.setenv("OPENROUTER_BASE_URL", "https://openrouter.example/v1")
    # An incomplete remote setup remains remote so doctor can expose the missing key.
    assert environ.configured_backend() == ("https://openrouter.example/v1", "")


def test_explicit_dfa_backend_has_priority(monkeypatch):
    monkeypatch.setenv("DFA_BASE_URL", "http://localhost:11434/v1")
    monkeypatch.delenv("DFA_API_KEY", raising=False)
    monkeypatch.setenv("OPENROUTER_API_KEY", "remote-key")
    assert environ.configured_backend() == ("http://localhost:11434/v1", "")

    monkeypatch.setenv("DFA_API_KEY", "explicit-local-key")
    assert environ.configured_backend() == (
        "http://localhost:11434/v1",
        "",
    )


def test_doctor_rows_shape():
    rows = environ.doctor(base_url="http://127.0.0.1:59999/v1", model="some-model")
    assert isinstance(rows, list) and rows
    assert all({"name", "ok", "detail", "hint", "required"} <= set(r) for r in rows)
    assert next(row for row in rows if row["name"].startswith("Python"))["name"] == (
        "Python >= 3.11"
    )


def test_doctor_accepts_configuration_passed_through_environment(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")

    rows = environ.doctor(base_url="http://127.0.0.1:59999/v1", model="some-model")

    configuration = next(row for row in rows if row["name"] == "Configuration")
    assert configuration["ok"] is True
    assert configuration["detail"] in {
        "environment variables",
        str(environ.environment_file_state().get("path") or ""),
    }


def test_doctor_labels_openrouter_not_ollama(monkeypatch):
    monkeypatch.setattr(
        environ,
        "backend_status",
        lambda *_args, **_kwargs: {
            "reachable": True,
            "authenticated": True,
            "models": ["openai/gpt-oss-120b"],
            "has_model": True,
            "model_supports_tools": True,
            "kind": "openrouter",
        },
    )
    rows = environ.doctor(
        base_url="https://openrouter.ai/api/v1",
        model="openai/gpt-oss-120b",
        api_key="test-key",
    )
    backend_rows = rows[-3:]
    text = " ".join(
        f"{row['name']} {row['detail']} {row['hint']}" for row in backend_rows
    )
    assert "OpenRouter backend available" in backend_rows[0]["name"]
    assert "OpenRouter API key valid" in backend_rows[1]["name"]
    # One row, not two. A working model used to be reported twice — once for
    # being there and once for taking tool calls — with its full identifier
    # repeated in both. Both facts still appear; the name does not.
    model_row = backend_rows[2]
    assert model_row["name"] == (
        "Model 'openai/gpt-oss-120b' available on OpenRouter, with tool calls"
    )
    assert model_row["ok"] is True
    assert "tool calling advertised" in model_row["detail"]
    assert model_row["name"].count("openai/gpt-oss-120b") == 1
    assert not any(row["name"].endswith("supports tool calls") for row in rows)
    assert "Ollama" not in text
    assert "ollama" not in text


def test_doctor_reports_rejected_openrouter_key_separately(monkeypatch):
    monkeypatch.setattr(
        environ,
        "backend_status",
        lambda *_args, **_kwargs: {
            "reachable": True,
            "authenticated": False,
            "models": [],
            "has_model": False,
            "kind": "openrouter",
            "error": "OpenRouter rejected the configured API key (HTTP 401)",
        },
    )

    rows = environ.doctor(
        base_url="https://openrouter.ai/api/v1",
        model="openai/gpt-oss-120b",
        api_key="revoked-key",
    )

    key_row = next(row for row in rows if row["name"] == "OpenRouter API key valid")
    assert key_row["ok"] is False
    assert "HTTP 401" in key_row["detail"]
    assert "dfir-agent setup" in key_row["hint"]
    assert not any(
        row["name"].startswith("Model '") for row in rows
    )


def test_doctor_rejects_openrouter_model_without_tool_calls(monkeypatch):
    monkeypatch.setattr(
        environ,
        "backend_status",
        lambda *_args, **_kwargs: {
            "reachable": True,
            "authenticated": True,
            "models": ["provider/text-only"],
            "has_model": True,
            "model_supports_tools": False,
            "kind": "openrouter",
        },
    )

    rows = environ.doctor(
        base_url="https://openrouter.ai/api/v1",
        model="provider/text-only",
        api_key="test-key",
    )

    capability = next(
        row for row in rows if row["name"].endswith("supports tool calls")
    )
    assert capability["ok"] is False
    assert capability["required"] is True


def test_doctor_does_not_include_research_statistics_dependencies(monkeypatch):
    monkeypatch.setattr(
        environ,
        "backend_status",
        lambda *_args, **_kwargs: {
            "reachable": False,
            "models": [],
            "has_model": False,
            "kind": "ollama",
            "error": "offline",
        },
    )

    names = {row["name"] for row in environ.doctor(model="local-model")}

    assert "scipy / statsmodels / sklearn (research statistics)" not in names
