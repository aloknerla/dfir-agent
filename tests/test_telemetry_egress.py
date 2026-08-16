"""No-network tests for the third-party telemetry egress seal.

The decisive test here is the subprocess one.  The in-process tests check that
the policy *names* the right variables, but naming them proves nothing on its
own: the failure this guards against is a library reading a value before the
policy runs, which can only be observed in a process whose import order is real.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from forensic_agent.core.telemetry_egress import (
    TELEMETRY_EGRESS_VARIABLES,
    live_telemetry_variables,
    seal_telemetry_egress,
    telemetry_egress_record,
)

_SRC = str(Path(__file__).resolve().parents[1] / "src")


# The four spellings were measured against the installed library: each one alone
# makes ``langsmith.utils.tracing_is_enabled()`` true.  None of them appears as a
# literal in the package — they are composed from a namespace and a suffix at
# read time — so a policy built by searching for strings would miss all four.
@pytest.mark.parametrize(
    "name",
    [
        "LANGSMITH_TRACING",
        "LANGCHAIN_TRACING",
        "LANGSMITH_TRACING_V2",
        "LANGCHAIN_TRACING_V2",
    ],
)
def test_every_measured_tracing_toggle_is_watched(name):
    assert name in TELEMETRY_EGRESS_VARIABLES


@pytest.mark.parametrize(
    "name",
    [
        # Reroutes the model call itself, with no tracing toggle involved.
        "LANGSMITH_GATEWAY",
        "LANGCHAIN_GATEWAY",
        # Choose where an upload lands.
        "LANGSMITH_ENDPOINT",
        "LANGSMITH_RUNS_ENDPOINTS",
        # Read bare, without a namespace prefix, by the OTLP exporter.
        "OTEL_EXPORTER_OTLP_ENDPOINT",
        "OTEL_EXPORTER_OTLP_HEADERS",
        # Would otherwise re-enable the rest by indirection.
        "LANGSMITH_CONFIG_FILE",
        "LANGSMITH_PROFILE",
    ],
)
def test_every_destination_credential_and_indirection_is_watched(name):
    assert name in TELEMETRY_EGRESS_VARIABLES


def test_empty_values_are_not_reported_as_live():
    # ``get_env_var`` treats empty and whitespace-only as unset, so reporting
    # these would claim a finding the library would never have acted on.
    environ = {"LANGSMITH_TRACING": "", "LANGCHAIN_ENDPOINT": "   "}
    assert live_telemetry_variables(environ) == ()


def test_seal_removes_live_variables_and_names_them():
    environ = {
        "LANGSMITH_TRACING": "true",
        "LANGSMITH_GATEWAY": "https://gateway.smith.langchain.com",
        "OTEL_EXPORTER_OTLP_ENDPOINT": "https://collector.example",
        "PATH": "/usr/bin",
    }
    removed = seal_telemetry_egress(environ)
    assert set(removed) == {
        "LANGSMITH_TRACING",
        "LANGSMITH_GATEWAY",
        "OTEL_EXPORTER_OTLP_ENDPOINT",
    }
    assert live_telemetry_variables(environ) == ()
    assert environ == {"PATH": "/usr/bin"}, "the seal must touch nothing else"


def test_seal_is_idempotent():
    environ = {"LANGSMITH_TRACING": "true"}
    assert seal_telemetry_egress(environ) == ("LANGSMITH_TRACING",)
    assert seal_telemetry_egress(environ) == ()


def test_receipt_reports_a_live_variable_as_unsealed():
    record = telemetry_egress_record({"LANGSMITH_TRACING": "true"})
    assert record["sealed"] is False
    assert record["live_now"] == ["LANGSMITH_TRACING"]


def test_receipt_reports_a_clean_environment_as_sealed():
    record = telemetry_egress_record({"PATH": "/usr/bin"})
    assert record["sealed"] is True
    assert record["live_now"] == []
    assert record["variables_watched"] == len(TELEMETRY_EGRESS_VARIABLES)


def _run_child(source: str, extra_env: dict[str, str]) -> dict[str, object]:
    env = {**os.environ, "PYTHONPATH": _SRC, **extra_env}
    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", source],
        capture_output=True,
        text=True,
        timeout=300,
        env=env,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout.strip().splitlines()[-1])


def test_importing_the_package_disables_tracing_in_a_real_process():
    """The regression test proper: import order, in a process, with the library.

    Fails on code without the seal, because ``LANGSMITH_TRACING=true`` is all
    the library needs to begin uploading tool results.
    """
    pytest.importorskip("langsmith")
    result = _run_child(
        "import json\n"
        "import forensic_agent\n"
        "from langsmith.utils import tracing_is_enabled\n"
        "from forensic_agent.core.telemetry_egress import telemetry_egress_record\n"
        "print(json.dumps({\n"
        "    'tracing': bool(tracing_is_enabled()),\n"
        "    'record': telemetry_egress_record(),\n"
        "}))\n",
        {
            "LANGSMITH_TRACING": "true",
            "LANGSMITH_API_KEY": "not-a-real-key",
            "LANGSMITH_GATEWAY": "https://gateway.smith.langchain.com",
        },
    )
    assert result["tracing"] is False, "tracing survived the package import"
    record = result["record"]
    assert isinstance(record, dict)
    assert record["sealed"] is True
    # The receipt has to name what it switched off; "sealed" with an empty list
    # would be indistinguishable from a run where nothing was ever set.
    assert set(record["neutralised_at_import"]) == {
        "LANGSMITH_TRACING",
        "LANGSMITH_API_KEY",
        "LANGSMITH_GATEWAY",
    }


def test_the_run_manifest_states_its_egress_posture():
    """The offline claim has to be readable from the record, not inferred."""
    from forensic_agent.core.repro import RunManifest, environment_info

    environment = environment_info()
    assert environment["telemetry_egress"]["policy"] == "third-party-telemetry-egress-v1"
    # langsmith is the package that performs upload; a manifest that named every
    # other client library and not this one could not describe the egress surface.
    assert "langsmith" in environment["libraries"]

    manifest = RunManifest(
        case_id="c", model="m", engine="e", backend="b", profile={}
    )
    assert "telemetry_egress" in manifest.to_dict()["environment"]


def test_egress_posture_is_not_part_of_the_reproducibility_fingerprint():
    """A stray variable that was removed must not re-key an otherwise identical run."""
    from forensic_agent.core.repro import RunManifest

    def _manifest(**overrides):
        return RunManifest(case_id="c", model="m", engine="e", backend="b", profile={}, **overrides)

    clean = _manifest()
    noisy = _manifest(
        environment={**clean.environment, "telemetry_egress": {"sealed": False}}
    )
    assert clean.fingerprint() == noisy.fingerprint()


def test_a_clean_process_reports_sealed_with_nothing_neutralised():
    result = _run_child(
        "import json\n"
        "import forensic_agent\n"
        "from forensic_agent.core.telemetry_egress import telemetry_egress_record\n"
        "print(json.dumps(telemetry_egress_record()))\n",
        {name: "" for name in sorted(TELEMETRY_EGRESS_VARIABLES)},
    )
    assert result["sealed"] is True
    assert result["neutralised_at_import"] == []
