"""Investigation-time path grounding.

At action-selection time, a path or registry argument proposed by the model must
be grounded: it must either be a known forensic artifact location from the curated
knowledge base or have appeared in evidence already returned during the
investigation. An ungrounded path is a likely invented location and a direct
mechanism behind artifact-location hallucination.

Two design rules:

* **Two matchers.** The knowledge-base arm uses ``known_location`` (curated, prefix
  matching is correct there). The provenance arm uses EXACT normalized full-path
  matching — never prefix — so a directory listing grounds its *actual* children
  (which appear verbatim in the output) but not invented siblings.
* **Default advisory, deny opt-in.** Grounding only ever ANNOTATES by default (a
  recorded reason), so legitimate navigation never breaks. Hard blocking is enabled
  only by ``Policy.ground_paths``; when it is on, the cost of the control is that a
  correct path can be wrongly blocked.

The ledger is fed from the FULL tool output before any truncation, so a path that
appears late in a listing still grounds the next legitimate step.
"""
from __future__ import annotations

import json
import re

from forensic_agent.oversight.policy import PATH_ARG_NAMES as _POLICY_PATH_ARG_NAMES

# The host-filesystem path argument names are owned by :mod:`oversight.policy`;
# grounding derives from that single declaration instead of keeping a second
# copy.  Grounding additionally treats the registry ``key`` argument as a
# groundable location — policy's host-path scope check deliberately omits it,
# because a registry key names a location inside the evidence, not a host
# filesystem path a wrapper opens.  The security-relevant invariant is that
# grounding must cover everything policy scope-checks and more, so this set is a
# strict superset of policy's; the assertion makes a name added to policy that is
# not reflected here fail at import rather than silently leave grounding blind to
# it.  (Neither caller was under-protected by the previous divergence — the two
# differed only by ``key`` — but the duplication is exactly what could have left
# grounding behind on a future policy addition.)
_REGISTRY_KEY_ARG_NAMES = frozenset({"key"})
PATH_ARG_NAMES = set(_POLICY_PATH_ARG_NAMES) | set(_REGISTRY_KEY_ARG_NAMES)
assert PATH_ARG_NAMES >= _POLICY_PATH_ARG_NAMES

# Distinctive full tokens to harvest from a tool output (low false-positive).
_REG_RE = re.compile(r"HK(?:LM|CU|CR|U|CC)[\\/][^\s\"',;]+", re.I)
_WIN_RE = re.compile(r"[A-Za-z]:\\[^\s\"',;]+")


def _norm(s) -> str:
    """Normalise a path / registry key for EXACT comparison: lowercase, forward
    slashes, collapse slash runs (JSON doubles backslashes), drop trailing slash."""
    s = str(s or "").strip().lower().replace("\\", "/")
    s = re.sub(r"/+", "/", s)
    return s.rstrip("/") or "/"


def _join(parent, name) -> str:
    return _norm(_norm(parent) + "/" + str(name))


def _declares_failure(output) -> bool:
    """Whether a tool result declares that the call failed or was refused.

    Recognizes the standardized envelope (``status == "error"`` or a
    ``deterministic_error`` marker in ``data.attributes``) and the legacy dict
    with a truthy top-level ``error``. A ``partial`` status is a SUCCESS that
    read the source incompletely, so it does not count as a failure here.
    """
    if not isinstance(output, dict):
        return False
    status = output.get("status")
    if isinstance(status, str) and status.strip().lower() == "error":
        return True
    if output.get("error"):
        return True
    data = output.get("data")
    if isinstance(data, dict):
        attributes = data.get("attributes")
        if isinstance(attributes, dict) and attributes.get("deterministic_error"):
            return True
    return False


def path_args(args):
    """Yield (name, value) for string args that denote a host/image/registry path."""
    for k, v in (args or {}).items():
        # Tool schemas, not a value's spelling, determine whether the wrapper can
        # dereference it. A PCAP display filter such as ``/api/v1/`` is query text,
        # while ``save_path`` is a path even when its value happens to be relative.
        if isinstance(v, str) and v and k in PATH_ARG_NAMES:
            yield k, v


class GroundingLedger:
    """Tracks which paths the agent has actually OBSERVED during a session, so an
    invented path can be told apart from a discovered one (exact full-path match)."""

    def __init__(self, roots=None) -> None:
        self._seen: set[str] = set()
        self._roots: set[str] = {_norm(r) for r in (roots or [])}
        self._roots.add("/")            # the image root is a valid listing start point

    def observe(self, args, output) -> None:
        """Record paths that genuinely appeared in a SUCCESSFUL call. Pass the FULL
        tool output (before truncation) so late entries still ground later steps.

        A call that FAILED or was REFUSED confirmed no path: recording the model's
        own supplied argument (or a location echoed back inside an error message)
        would ground a location the run never actually reached, laundering an
        invented path so the ungrounded-path signal is suppressed on reuse. The
        enforce pipeline calls this after every non-exception completion and has no
        success flag to pass, so the success test is made here, on the raw result.
        """
        if _declares_failure(output):
            return
        for _k, v in path_args(args):
            self._seen.add(_norm(v))
        if isinstance(output, dict):
            base = output.get("path")
            ents = output.get("entries")
            if isinstance(base, str) and isinstance(ents, list):
                for e in ents:                          # listing children: join(dir, name)
                    nm = e.get("name") if isinstance(e, dict) else None
                    if nm:
                        self._seen.add(_join(base, nm))
        text = output if isinstance(output, str) else json.dumps(output, ensure_ascii=False, default=str)
        for rx in (_REG_RE, _WIN_RE):                   # distinctive full tokens in output
            for m in rx.findall(text):
                self._seen.add(_norm(m))

    def is_grounded(self, value) -> dict:
        """Return {grounded, basis}. basis ∈ {prior_output, nav_root, ungrounded}.
        Provenance is EXACT match against paths observed during the session."""
        v = _norm(value)
        if v in self._seen:
            return {"grounded": True, "basis": "prior_output"}
        if v in self._roots:
            return {"grounded": True, "basis": "nav_root"}
        return {"grounded": False, "basis": "ungrounded"}

    def check(self, args) -> list:
        """Return [(name, value, basis)] for the ungrounded path args of one call."""
        out = []
        for k, v in path_args(args):
            g = self.is_grounded(v)
            if not g["grounded"]:
                out.append((k, v, g["basis"]))
        return out
