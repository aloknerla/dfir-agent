"""Capability policy definitions and tool-call evaluation."""

from __future__ import annotations

import os
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from forensic_agent.core.controlled_scratch import (
    ControlledScratchError,
    attest_controlled_scratch_root,
)

RISK_NAMES = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}

CAP_READ_EVIDENCE = (
    "read_evidence"  # read inside the forensic image/case (sandboxed, volume-relative)
)
CAP_READ_HOST_PATH = "read_host_path"  # read an arbitrary host filesystem path (scope-checked)
CAP_WRITE = "write"  # writes files to the host disk (extraction, carving, temp)
CAP_CONTROLLED_SCRATCH = "controlled_scratch"  # bounded ephemeral copies under an attested root
CAP_NETWORK = "network"  # makes a network call (e.g. a local model endpoint)
CAP_SPAWN = "spawn_process"  # spawns a verified external tool (tshark, vol, tesseract, 7z)
CAP_DECODE = "decode"  # pure in-memory data transform, no I/O

ALL_CAPS = {
    CAP_READ_EVIDENCE,
    CAP_READ_HOST_PATH,
    CAP_WRITE,
    CAP_CONTROLLED_SCRATCH,
    CAP_NETWORK,
    CAP_SPAWN,
    CAP_DECODE,
}

# Default capability map for the forensic agent tool set (override per deployment).
DEFAULT_TOOL_CAPS: dict[str, set] = {
    "list_directory": {CAP_READ_EVIDENCE},
    "file_metadata": {CAP_READ_EVIDENCE},
    "read_file": {CAP_READ_EVIDENCE},
    "search_keyword": {CAP_READ_EVIDENCE},
    "search_in_file": {CAP_READ_EVIDENCE},
    "configuration_query": {CAP_READ_EVIDENCE},
    "find_email_addresses": {CAP_READ_EVIDENCE},
    "find_files": {CAP_READ_EVIDENCE},
    "evidence_file_hash": {CAP_READ_EVIDENCE},
    "sqlite_query": {CAP_READ_EVIDENCE, CAP_CONTROLLED_SCRATCH},
    "verify_image_integrity": {CAP_READ_EVIDENCE},
    "recover_deleted_files": {CAP_READ_EVIDENCE},
    "bulk_extract": {CAP_READ_EVIDENCE, CAP_SPAWN, CAP_WRITE},
    # These parsers execute in-process and physically write an ephemeral host
    # copy. CAP_CONTROLLED_SCRATCH names that bounded allocator-only write;
    # it remains distinct from arbitrary/model-selected CAP_WRITE authority.
    "registry_query": {CAP_READ_EVIDENCE, CAP_CONTROLLED_SCRATCH},
    "windows_network_config": {CAP_READ_EVIDENCE, CAP_CONTROLLED_SCRATCH},
    "windows_domain_identity": {CAP_READ_EVIDENCE, CAP_CONTROLLED_SCRATCH},
    "usb_storage_history": {CAP_READ_EVIDENCE, CAP_CONTROLLED_SCRATCH},
    "installed_applications": {CAP_READ_EVIDENCE, CAP_CONTROLLED_SCRATCH},
    "google_drive_sync_events": {CAP_READ_EVIDENCE},
    "printing_activity_events": {CAP_READ_EVIDENCE},
    "gcode_metadata": {CAP_READ_EVIDENCE},
    "printing_job_sessions": {CAP_READ_EVIDENCE},
    "registry_ripper": {CAP_READ_EVIDENCE, CAP_SPAWN, CAP_WRITE},
    "windows_local_accounts": {CAP_READ_EVIDENCE, CAP_SPAWN, CAP_WRITE},
    "evtx_query": {CAP_READ_EVIDENCE, CAP_CONTROLLED_SCRATCH},
    "memory_query": {CAP_READ_EVIDENCE, CAP_SPAWN, CAP_WRITE},
    "memory_malware_scan": {CAP_READ_EVIDENCE, CAP_SPAWN, CAP_WRITE},
    "memory_strings": {CAP_READ_EVIDENCE},
    "pcap_query": {CAP_READ_EVIDENCE, CAP_SPAWN, CAP_WRITE},
    "reconstruct_http_exfil": {CAP_READ_EVIDENCE, CAP_SPAWN, CAP_WRITE},
    "hash_file": {CAP_READ_HOST_PATH},
    "hash_lookup": {CAP_READ_HOST_PATH},
    "archive_query": {CAP_READ_HOST_PATH, CAP_SPAWN, CAP_WRITE},
    "ocr_image": {CAP_READ_HOST_PATH, CAP_SPAWN},
    "vision_read": {CAP_READ_HOST_PATH, CAP_NETWORK},
    "read_text_file": {CAP_READ_HOST_PATH},
    "decode": {CAP_DECODE},
    # Consolidated domain functions.  Each carries the union of the capabilities
    # its dispatched implementations exercise, so no operation of a facade can
    # reach a capability the facade never declared.
    "filesystem_query": {CAP_READ_EVIDENCE},
    "recover_deleted": {CAP_READ_EVIDENCE},
    "transform_query": {CAP_DECODE},
    "host_file_hash": {CAP_READ_HOST_PATH},
    "artifact_reference_query": {CAP_DECODE},
}

# Argument names that name a host location a wrapper OPENS FOR READING. The
# memory image arrives as ``dump_path``: it is a source, never a destination.
READ_PATH_ARG_NAMES = frozenset(
    {
        "path",
        "archive_path",
        "image_path",
        "file_path",
        "dump_path",
    }
)

# Argument names that name a host location a wrapper OPENS FOR WRITING. Only
# these are answered from the write scope, so an argument listed here that the
# wrapper in fact reads would be scope-checked against the wrong collection.
WRITE_PATH_ARG_NAMES = frozenset(
    {
        "save_path",
        "out_path",
        "output_path",
    }
)

# Argument names that carry a host filesystem path (read or write destinations).
PATH_ARG_NAMES = set(READ_PATH_ARG_NAMES | WRITE_PATH_ARG_NAMES)

# Match a leading drive-letter (with OR without a following separator -> catches
# Windows drive-relative "C:foo"), or a leading (back)slash / UNC.
_ABS_PATH_RE = re.compile(r"^(?:[A-Za-z]:|[\\/]{1,2})")

# Arguments whose values can legitimately begin with ``/`` while remaining
# pure query text. Scope-checking them as host paths creates false denials, but
# exempting them is safe because the corresponding wrapper never opens them as
# files. Real host-path destinations such as ``save_path`` remain checked.
_NON_PATH_ARGUMENTS_BY_TOOL: dict[str, frozenset[str]] = {
    "pcap_query": frozenset({"filter", "display_filter"}),
}

# Argument names that carry a secret the model supplies as content, never a
# filesystem location. A passphrase or an archive password is an arbitrary
# string, so it can legitimately begin with a drive letter or contain ``..``;
# the path heuristic below then read it as an out-of-scope host location and
# refused a correct call (a 7-Zip archive password). These arguments are
# never opened as files, so they are never a host read or a write destination,
# and exempting them by name leaves every real path argument still checked.
NON_PATH_ARG_NAMES = frozenset({"password", "passphrase"})


def _looks_like_path(tool: str, name: str, value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    if name in NON_PATH_ARG_NAMES:
        return False
    if name in _NON_PATH_ARGUMENTS_BY_TOOL.get(tool, frozenset()):
        return False
    return name in PATH_ARG_NAMES or bool(_ABS_PATH_RE.match(value)) or ".." in value


def _within_roots(value: str, roots: list[str]) -> bool:
    """Return whether ``value`` resolves inside one of the allowed roots."""
    try:
        rp = os.path.realpath(value)
    except Exception:
        return False
    for root in roots:
        try:
            rr = os.path.realpath(root)
            if os.path.commonpath([rp, rr]) == rr:
                return True
        except Exception:
            continue
    return False


def _assert_write_scope_is_attested_scratch(
    write_roots: Sequence[str],
    *,
    scratch_root: str | None,
    attestation_sha256: str | None,
) -> None:
    """Refuse a write scope that does not lie inside the run's attested scratch.

    The named directory is re-attested here rather than taken on trust, so a
    caller cannot hand the evidence directory in as a work directory: the
    identity this run already pinned would not match it. Without this the
    separation of the two scopes would hold only because the current callers
    happen to pass the right thing.
    """

    if scratch_root is None or attestation_sha256 is None:
        raise ValueError(
            "a write scope requires the attested controlled scratch root that contains it"
        )
    try:
        observed = attest_controlled_scratch_root(Path(scratch_root))
    except ControlledScratchError as exc:
        raise ValueError(
            "the declared controlled scratch root is not an attestable directory"
        ) from exc
    if observed.sha256 != attestation_sha256.casefold():
        raise ValueError(
            "the declared controlled scratch root is not the one this run attested"
        )
    for directory in write_roots:
        if not _within_roots(directory, [scratch_root]):
            raise ValueError("write scope is outside the attested controlled scratch root")


@dataclass
class Policy:
    """A security policy for an agent session.

    The read scope and the write scope are two collections rather than one
    because the read scope contains the directory holding the evidence: a run
    must read the image and everything acquired beside it. A policy that
    answered a write destination from ``path_roots`` would therefore grant
    write authority over the evidence under examination, and outside a
    read-only mount nothing downstream refuses that write.

    ``write_roots`` is empty by default, so a policy that declares a scope
    without declaring where it may write permits no host write destination at
    all. A non-empty one is refused at construction unless it lies inside
    ``controlled_scratch_root``, and unless re-attesting that directory
    reproduces the digest this run pinned.
    """

    name: str = "default"
    allowed_tools: set | None = None  # None => any tool name allowed
    granted_caps: set = field(default_factory=lambda: set(ALL_CAPS))
    path_roots: list = field(default_factory=list)  # read scope
    write_roots: list[str] = field(default_factory=list)  # write scope
    tool_caps: dict = field(default_factory=lambda: dict(DEFAULT_TOOL_CAPS))
    deny_unknown_tools: bool = False
    quarantine_poisoned_tools: bool = False
    #: NOT ARMED IN PRODUCTION. Nothing in ``src/`` ever sets this True —
    #: ``secure()`` and ``sandbox()`` below leave it at the default, and no
    #: caller assigns it afterwards — so the grounding gate in
    #: ``enforcement.py`` never refuses anything outside the tests that set it
    #: by hand. Ungrounded paths are still DETECTED and written to the record as
    #: ``ungrounded-path:`` reasons on a permitted call; 6,207 of them appear in
    #: the written corpus, every one advisory. Arming it is a policy decision,
    #: not an oversight.
    ground_paths: bool = False
    controlled_scratch_attestation_sha256: str | None = None
    # Runtime-only: the exact directory the digest above attests. It is a host
    # path of this machine and this run, so it stays out of ``summary()``.
    controlled_scratch_root: str | None = None
    #: NOT ARMED IN PRODUCTION. Nothing in ``src/`` ever populates this — it is
    #: declared here, read by ``evaluate()`` below and by the tool builders that
    #: describe the restriction to the model, and assigned only in tests. The
    #: argument gate in ``evaluate()`` therefore cannot fire in a real run, and
    #: has not once in the written corpus. An argument refusal in a recorded run
    #: came from the tool's own schema through the argument CONTRACT in
    #: ``enforcement.py``, which is a different mechanism with a different
    #: reason string. Populating this is a policy decision, not an oversight.
    argument_allowlists: dict[str, dict[str, set]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.write_roots:
            _assert_write_scope_is_attested_scratch(
                self.write_roots,
                scratch_root=self.controlled_scratch_root,
                attestation_sha256=self.controlled_scratch_attestation_sha256,
            )

    @classmethod
    def permissive(cls) -> Policy:
        """Observe-only: everything allowed (oversight = oversight log only)."""
        return cls(name="permissive")

    @classmethod
    def secure(
        cls,
        path_roots: list[str],
        *,
        work_dirs: list | None = None,
        allowed_tools: set | None = None,
        allow_network: bool = False,
        allow_write: bool = True,
        allow_spawn: bool = True,
        controlled_scratch_attestation_sha256: str | None = None,
        controlled_scratch_root: str | None = None,
    ) -> Policy:
        """Build a least-privilege forensic policy.

        Host reads are confined to ``path_roots`` plus ``work_dirs``; host
        writes are confined to ``work_dirs`` alone, because ``path_roots``
        names the evidence. Each work directory must lie inside the attested
        ``controlled_scratch_root``, so declaring one is what makes it a work
        directory. Unknown and poisoned tools are denied, and network access is
        off by default.
        """
        caps = {CAP_READ_EVIDENCE, CAP_READ_HOST_PATH, CAP_DECODE}
        if allow_write:
            caps.add(CAP_WRITE)
        if allow_spawn:
            caps.add(CAP_SPAWN)
        if allow_network:
            caps.add(CAP_NETWORK)
        if controlled_scratch_attestation_sha256 is not None:
            digest = controlled_scratch_attestation_sha256.casefold()
            if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
                raise ValueError("controlled scratch authority must be a SHA-256 attestation")
            caps.add(CAP_CONTROLLED_SCRATCH)
            controlled_scratch_attestation_sha256 = digest
        write_scope = [str(directory) for directory in (work_dirs or [])]
        # The declared payload root joins the READ scope and never the write
        # scope. It holds what this run reconstructed out of the evidence, and a
        # run that may not read that back cannot open the archive it has just
        # lifted out of a capture. Reading is not writing: what puts payloads
        # there goes through the write-scope facade, untouched here.
        from forensic_agent.core.storage_containment import payload_scratch_root

        payload_root = payload_scratch_root()
        reconstructions = [str(payload_root)] if payload_root is not None else []
        roots = list(path_roots) + list(write_scope) + reconstructions
        return cls(
            name="secure",
            allowed_tools=allowed_tools,
            granted_caps=caps,
            path_roots=roots,
            write_roots=write_scope,
            deny_unknown_tools=True,
            quarantine_poisoned_tools=True,
            controlled_scratch_attestation_sha256=controlled_scratch_attestation_sha256,
            controlled_scratch_root=controlled_scratch_root,
        )

    @classmethod
    def sandbox(
        cls,
        path_roots: list[str],
        *,
        work_dirs: list | None = None,
        allowed_tools: set | None = None,
        allow_spawn: bool = True,
        controlled_scratch_attestation_sha256: str | None = None,
        controlled_scratch_root: str | None = None,
    ) -> Policy:
        """Build an airgapped analysis policy for malware-bearing evidence."""
        policy = cls.secure(
            path_roots,
            work_dirs=work_dirs,
            allowed_tools=allowed_tools,
            allow_network=False,
            allow_write=True,
            allow_spawn=allow_spawn,
            controlled_scratch_attestation_sha256=controlled_scratch_attestation_sha256,
            controlled_scratch_root=controlled_scratch_root,
        )
        policy.name = "sandbox"
        return policy

    def summary(self) -> dict:
        """Return the portable design identity of this policy.

        The key set is a stable identity, so ``write_roots`` and
        ``controlled_scratch_root`` are deliberately absent: they are host- and
        run-specific, and this record therefore understates the authority a run
        held. The run's own accountability record carries the effective write
        scope instead: ``OversightLog`` writes it into the ``case_open`` entry
        beside this summary.
        """

        record: dict[str, object] = {
            "name": self.name,
            "allowed_tools": sorted(self.allowed_tools) if self.allowed_tools else None,
            "granted_caps": sorted(self.granted_caps),
            "path_roots": list(self.path_roots),
            "controlled_scratch_attestation_sha256": self.controlled_scratch_attestation_sha256,
            "deny_unknown_tools": self.deny_unknown_tools,
            "ground_paths": self.ground_paths,
        }
        if self.argument_allowlists:
            record["argument_allowlists"] = {
                tool: {
                    argument: sorted(values, key=lambda value: str(value))
                    for argument, values in sorted(rules.items())
                }
                for tool, rules in sorted(self.argument_allowlists.items())
            }
        return record


#: The reasons :func:`evaluate` appends to DESCRIBE a call rather than to refuse
#: it: what the tool would have done with the authority it holds. They are
#: written only in the ``if not blocked`` branch below, so their presence on an
#: entry is itself the statement that the POLICY permitted the call — and a
#: reader who meets them at the top of something marked refused is told the
#: opposite of what happened. Named here, beside the only code that writes them,
#: so a view can put the ground of a refusal first without carrying a second
#: transcript of these strings.
CAPABILITY_DESCRIPTION_REASONS = (
    "network-capable",
    "writes to host disk",
    "uses bounded attested ephemeral scratch",
    "spawns external process",
    "read-only evidence access",
)


def partition_reasons(reasons: Sequence[str]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Split recorded reasons into the deciding ones and the describing ones.

    Order is preserved within each half, and nothing is dropped: this reads a
    recorded list, it does not rewrite one. Matching is by prefix rather than by
    equality because a description may carry a qualifying tail (``read-only
    evidence access within granted authority``), and an unrecognised string is
    treated as DECIDING — an unknown reason on a refused call is far more likely
    to be its ground than a decoration, and burying it is the failure this
    function exists to end.
    """

    deciding: list[str] = []
    describing: list[str] = []
    for reason in reasons:
        text = str(reason)
        if text.startswith(CAPABILITY_DESCRIPTION_REASONS):
            describing.append(text)
        else:
            deciding.append(text)
    return tuple(deciding), tuple(describing)


@dataclass
class Decision:
    allowed: bool
    risk: int
    reasons: list
    capabilities: list

    @property
    def risk_name(self) -> str:
        return RISK_NAMES.get(self.risk, str(self.risk))


def evaluate(policy: Policy, tool: str, args: dict) -> Decision:
    """Evaluate one tool call against the supplied policy."""
    args = args or {}
    is_unknown = tool not in policy.tool_caps
    caps = set(policy.tool_caps.get(tool, set()))
    reasons: list[str] = []
    risk = 0
    blocked = False

    if policy.allowed_tools is not None and tool not in policy.allowed_tools:
        blocked, risk = True, 4
        reasons.append(f"tool '{tool}' is not in the session allowlist")

    if is_unknown:
        if policy.deny_unknown_tools:
            blocked, risk = True, max(risk, 4)
            reasons.append(f"unknown tool '{tool}' denied (deny-by-default)")
        else:
            risk = max(risk, 2)
            reasons.append(f"unknown tool '{tool}' (not in capability map)")

    ungranted = caps - policy.granted_caps
    if ungranted:
        blocked, risk = True, max(risk, 4)
        reasons.append(f"requires ungranted capability {sorted(ungranted)}")

    argument_rules = policy.argument_allowlists.get(tool, {})
    for argument, allowed_values in argument_rules.items():
        supplied = args.get(argument)
        if argument not in args or not any(supplied == allowed for allowed in allowed_values):
            blocked, risk = True, max(risk, 4)
            reasons.append(f"argument {argument!r} is outside the session allowlist")

    if policy.path_roots or policy.write_roots:
        for name, value in args.items():
            if not _looks_like_path(tool, name, value):
                continue
            if name in WRITE_PATH_ARG_NAMES and CAP_WRITE in caps:
                # Answered from the write scope ALONE. The read scope holds the
                # directory the evidence sits in, and a destination resolved
                # against it is a permit to overwrite the evidence.
                if not _within_roots(value, policy.write_roots):
                    blocked, risk = True, max(risk, 3)
                    reasons.append(
                        f"write destination {name}={value!r} is outside the "
                        "allowed case write scope"
                    )
            elif CAP_READ_HOST_PATH in caps:
                # A host read is scope-checked against the host read roots, and
                # this is gated on CAP_READ_HOST_PATH rather than on CAP_WRITE. A
                # tool that writes but reads the evidence takes IMAGE-INTERNAL
                # path arguments — volume-relative locations governed by
                # CAP_READ_EVIDENCE and resolved inside the image, not on the
                # host — and judging one of those against host roots refused
                # legitimate mainline calls whose in-image path simply is not a
                # host location. The one host destination such a tool does name,
                # a write path, is answered from the write scope above.
                if not _within_roots(value, policy.path_roots):
                    blocked, risk = True, max(risk, 3)
                    reasons.append(
                        f"path argument {name}={value!r} is outside the allowed case scope"
                    )

    if not blocked:
        if CAP_NETWORK in caps:
            risk = max(risk, 2)
            reasons.append("network-capable")
        if CAP_WRITE in caps:
            risk = max(risk, 1)
            reasons.append("writes to host disk")
        if CAP_CONTROLLED_SCRATCH in caps:
            risk = max(risk, 1)
            reasons.append("uses bounded attested ephemeral scratch")
        if CAP_SPAWN in caps:
            risk = max(risk, 1)
            reasons.append("spawns external process")
        if not reasons:
            reasons.append("read-only evidence access")

    return Decision(
        allowed=not blocked,
        risk=risk,
        reasons=reasons,
        capabilities=sorted(caps) if caps else (["unknown"] if is_unknown else []),
    )


__all__ = [
    "ALL_CAPS",
    "CAPABILITY_DESCRIPTION_REASONS",
    "CAP_CONTROLLED_SCRATCH",
    "CAP_DECODE",
    "CAP_NETWORK",
    "CAP_READ_EVIDENCE",
    "CAP_READ_HOST_PATH",
    "CAP_SPAWN",
    "CAP_WRITE",
    "DEFAULT_TOOL_CAPS",
    "Decision",
    "PATH_ARG_NAMES",
    "Policy",
    "READ_PATH_ARG_NAMES",
    "RISK_NAMES",
    "WRITE_PATH_ARG_NAMES",
    "evaluate",
    "partition_reasons",
]
