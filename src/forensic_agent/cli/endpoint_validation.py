"""Whether a configured provider address may be used, decided on its own.

Checking an address is reading a string.  It settles nothing about evidence, runs
no investigation and needs no orchestration, so it does not belong behind the
module that carries all three.  It lived there because the console had one caller
and the module was already open; the cost of that convenience was that starting
the console loaded the agent runtime, LangChain and every tool-argument model
before the first prompt was drawn, for two functions that inspect a URL.

The refusals stay what they were: a rejected address raises
:class:`ControlledConsoleError`, the same class and the same message, so nothing
that already catches it can tell the difference.  ``cli.controlled`` re-exports
all three names, because where they are defined is an implementation detail and
every existing importer is entitled to keep working.
"""

from __future__ import annotations

from forensic_agent.core.environ import (
    ProviderEndpointError,
    validate_local_endpoint_value,
    validate_openrouter_endpoint_value,
)


class ControlledConsoleError(RuntimeError):
    """The interactive run cannot preserve its reliability boundary."""


def validate_openrouter_endpoint(base_url: str, api_key: str | None) -> str:
    """Fail closed unless the configured endpoint is the canonical OpenRouter API."""

    try:
        return validate_openrouter_endpoint_value(base_url, api_key)
    except ProviderEndpointError as exc:
        raise ControlledConsoleError(str(exc)) from exc


def validate_local_endpoint(base_url: str) -> str:
    """Fail closed unless the endpoint is a loopback service on this machine.

    Local execution protects evidence only if data stays on the workstation,
    so this path accepts loopback endpoints exclusively. A remote server that
    exposes the same interface is not local execution and is rejected here.
    """

    try:
        return validate_local_endpoint_value(base_url)
    except ProviderEndpointError as exc:
        raise ControlledConsoleError(str(exc)) from exc
