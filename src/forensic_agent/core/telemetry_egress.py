"""Seal the ambient third-party telemetry channels before anything can use them.

The LangChain client libraries carry two upload paths that are switched on by
environment alone.  Neither needs a code change, an argument, or a call site in
this project, and neither announces itself:

* **Run tracing.**  With a tracing toggle set, a bare ``StructuredTool.invoke()``
  — no agent, no graph — posts the tool's return value to
  ``api.smith.langchain.com``.  On this project a tool's return value is
  evidence.  The upload fails *open and silent*: when the socket is blocked the
  library retries and then continues as though nothing was attempted, so a run
  that leaked and a run that did not are indistinguishable from their output.
* **Gateway proxying.**  ``LANGSMITH_GATEWAY`` rewrites the chat model's
  ``base_url`` to ``gateway.smith.langchain.com``, sending the whole prompt —
  the evidence bundle — through a third party, while this project's own
  transport still reports the pinned endpoint it believes it is using.

Two properties of the libraries drive the shape of this module, and both were
measured against the installed versions rather than assumed:

1. **Names are composed at read time, not written down.**  ``langsmith`` resolves
   a setting through ``get_env_var(name, namespaces=("LANGSMITH", "LANGCHAIN"))``,
   which tries ``LANGSMITH_<name>`` and then ``LANGCHAIN_<name>``.  The string
   ``"LANGSMITH_TRACING"`` therefore appears nowhere in the package, and a block
   list built by searching for literals silently omits the single most important
   variable.  The policy below is a **cross product of namespaces and suffixes**
   for that reason.  A measured check of the installed library confirms all four
   of ``LANGSMITH_TRACING``, ``LANGCHAIN_TRACING``, ``LANGSMITH_TRACING_V2`` and
   ``LANGCHAIN_TRACING_V2`` enable tracing on their own.
2. **A setting is read once.**  ``get_env_var`` is ``functools.lru_cache``-wrapped,
   so a value observed at first read is retained even if the variable is removed
   afterwards.  Clearing these at ``main()`` is therefore *too late* whenever an
   import chain reached the library first.  The seal is applied from
   ``forensic_agent/__init__.py`` — before any module of this package, and so
   before any transitive ``langchain`` import, can run.

The behaviour is to **remove and record**, not to abort.  A refusal to run would
convert an operator's stray ambient variable into a failed investigation, while
the project's actual requirement is only that evidence does not leave the
machine.  Removal satisfies that requirement; the record is what lets a run
*state* it was satisfied, which the sealed-receipt claim depends on.  As the
sibling rule in :mod:`forensic_agent.core.toolkit` puts it: evidence must never
leave this machine because an ambient variable said so.

Empty values are left alone deliberately: ``get_env_var`` treats an empty or
whitespace-only value as absent, so an empty variable cannot switch anything on,
and reporting it as neutralised would overstate what was found.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping, MutableMapping

#: Namespaces ``langsmith.utils.get_env_var`` searches, in its own order.  Both
#: are live: ``LANGCHAIN_*`` is the legacy spelling and is still honoured.
TELEMETRY_NAMESPACES: tuple[str, ...] = ("LANGSMITH", "LANGCHAIN")

#: Suffixes that switch an upload on.  Measured against the installed library:
#: each of these alone makes ``langsmith.utils.tracing_is_enabled()`` true, or
#: enables the OTLP span exporter.
_UPLOAD_TOGGLES: tuple[str, ...] = ("TRACING", "TRACING_V2", "OTEL_ENABLED", "OTEL_ONLY")

#: Suffixes that choose *where* an upload goes.  Harmless while every toggle is
#: off, but they are what turns a leak into a leak to a chosen host, and
#: ``GATEWAY`` additionally reroutes the model call itself with no toggle at all.
_DESTINATIONS: tuple[str, ...] = ("ENDPOINT", "RUNS_ENDPOINTS", "GATEWAY")

#: Suffixes carrying a credential.  Removed so that a key belonging to some other
#: project cannot authorise an upload from this one.
_CREDENTIALS: tuple[str, ...] = ("API_KEY", "GATEWAY_API_KEY")

#: Suffixes that name a *file or profile* which can set any of the above.  Left
#: in place these would defeat the rest of the policy by indirection.
_INDIRECTION: tuple[str, ...] = ("CONFIG_FILE", "PROFILE", "HANDLER")

#: Standard OpenTelemetry names.  These are read straight from ``os.environ`` by
#: ``langsmith._internal.otel``, without a namespace prefix, so they are listed
#: whole rather than composed.
_BARE_VARIABLES: tuple[str, ...] = (
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "OTEL_EXPORTER_OTLP_HEADERS",
)


def _composed() -> frozenset[str]:
    suffixes = _UPLOAD_TOGGLES + _DESTINATIONS + _CREDENTIALS + _INDIRECTION
    return frozenset(
        f"{namespace}_{suffix}" for namespace in TELEMETRY_NAMESPACES for suffix in suffixes
    )


#: Every variable this module refuses to leave standing, as a flat set.
TELEMETRY_EGRESS_VARIABLES: frozenset[str] = _composed() | frozenset(_BARE_VARIABLES)

#: Names removed from this process, in the order the policy lists them.  Written
#: once, at package import, and read by the receipt.
_neutralised: list[str] = []


def _is_live(value: str | None) -> bool:
    """Mirror ``get_env_var``: absent, empty and whitespace-only all mean unset."""
    return value is not None and value.strip() != ""


def live_telemetry_variables(environ: Mapping[str, str] | None = None) -> tuple[str, ...]:
    """Return the egress variables that are set to a value able to act.

    Passing ``environ`` explicitly is what makes the policy testable without
    mutating the interpreter running the test.
    """
    source: Mapping[str, str] = os.environ if environ is None else environ
    return tuple(
        sorted(name for name in TELEMETRY_EGRESS_VARIABLES if _is_live(source.get(name)))
    )


def seal_telemetry_egress(
    environ: MutableMapping[str, str] | None = None,
) -> tuple[str, ...]:
    """Remove every live egress variable and return the names removed.

    Idempotent, and safe to call before or after the libraries are imported —
    though only a call made *before* the first read is guaranteed to bite, which
    is why the package seals itself at import.
    """
    target: MutableMapping[str, str] = os.environ if environ is None else environ
    removed = live_telemetry_variables(target)
    for name in removed:
        del target[name]
    if environ is None:
        _neutralised.extend(name for name in removed if name not in _neutralised)
    return removed


def neutralised_telemetry_variables() -> tuple[str, ...]:
    """Names this process removed from its own environment, for the receipt."""
    return tuple(_neutralised)


def telemetry_egress_record(environ: Mapping[str, str] | None = None) -> dict[str, object]:
    """Describe the process's egress posture for a run receipt.

    A receipt that does not state whether egress was possible cannot support the
    claim that the run was offline, so this reports both halves: what was found
    and removed, and whether anything is live *now*.  ``sealed`` being true is a
    statement about this process only — it says the known ambient channels are
    shut, not that the host has no network.
    """
    still_live = live_telemetry_variables(environ)
    return {
        "policy": "third-party-telemetry-egress-v1",
        "namespaces": list(TELEMETRY_NAMESPACES),
        "variables_watched": len(TELEMETRY_EGRESS_VARIABLES),
        "neutralised_at_import": list(neutralised_telemetry_variables()),
        "live_now": list(still_live),
        "sealed": not still_live,
    }


def describe_neutralised(names: Iterable[str]) -> str:
    """One operator-facing line naming what was switched off, and why it matters."""
    listed = ", ".join(sorted(names))
    return (
        f"Third-party telemetry disabled for this run: {listed}. "
        "These would have uploaded tool results and prompts off this machine."
    )
