"""One open evidence set said three ways: its identity, its record, and what remains.

An investigation's saved history is only meaningful next to the evidence it was
produced over, so the console has to be able to say three different things about
a set of sources.

The first is an *identity*: one digest that changes whenever the evidence set
changes, used to decide whether a saved conversation still belongs to what is
open now. It is derived from what the console already knows — sizes, mtimes,
inode identity, and the bounded identity digests the evidence layer computed
when each source was attached — so that answering "is this still the same
evidence?" never rereads a multi-gigabyte medium.

The second is a *binding record*: the sources named as paths, so a later console
can find them again. The two are deliberately not the same value. A record that
could be reopened would be a poor identity, because two different files can sit
at one path; a digest that cannot be reopened would be a poor record.

The third is what is left of such a record on a later host: which of the paths it
names can still be read, which cannot, and what the readable ones amount to as a
capture set. That question belongs beside the record it is asked about, because
the answer is only ever as good as the record's own vocabulary — a source
reported missing has to be named the way the evidence table named it while it was
still there, or the operator is told that something they never heard of is gone.

All three are pure functions of the evidence set rather than methods on the
session, because that is what makes them checkable: nothing about the console's
state can influence what identity a given set of sources produces, and nothing
about deciding what is still reachable can disturb the case that is open while it
decides.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from forensic_agent.cli.i18n import t as _t

if TYPE_CHECKING:
    from forensic_agent.cli.conversation import (
        ConversationEvidenceBinding,
        ConversationEvidenceSource,
    )
    from forensic_agent.tools.pcap_sources import PcapSourceCatalog


def source_identity(
    *,
    disk: object | None,
    disk_label: str,
    memory: str | None,
    pcap: str | None,
    pcap_sources: PcapSourceCatalog | None,
) -> str:
    """Bind conversation context to the active evidence set without rereading it."""

    from forensic_agent.cli.evidence_identity import bounded_file_identity

    # A relocation is not a change of evidence: this digest is a function of what
    # the sources ARE, never of where they sit.  Folding path, inode or mtime in
    # made an unchanged case that was copied or moved read as different evidence,
    # so the ordinary DFIR act of copying a case to another host or mount defeated
    # the restore path this identity exists to gate.  Every row therefore carries
    # only content identity (a full or bounded content digest and the size) plus
    # the source's structural role in the set.
    rows: list[dict[str, object]] = []
    if disk is not None:
        image_path = getattr(disk, "image_path", None)
        image_sha = getattr(disk, "image_sha", None)
        if image_sha:
            rows.append(
                {
                    "kind": "disk",
                    "sha256": image_sha,
                    "size": getattr(disk, "image_size", None),
                }
            )
        elif image_path:
            identity = bounded_file_identity(Path(image_path).resolve())
            rows.append(
                {
                    "kind": "disk",
                    "size": identity.size_bytes,
                    "bounded_identity_sha256": identity.identity_sha256,
                    "identity_semantics": identity.identity_semantics,
                }
            )
        else:
            rows.append({"kind": "disk", "label": disk_label})
    for kind, value in (("memory", memory),):
        if not value:
            continue
        identity = bounded_file_identity(Path(value).resolve())
        rows.append(
            {
                "kind": kind,
                "size": identity.size_bytes,
                "bounded_identity_sha256": identity.identity_sha256,
                "identity_semantics": identity.identity_semantics,
            }
        )
    if pcap_sources is not None:
        for binding in pcap_sources.bindings:
            identity = bounded_file_identity(Path(binding.path).resolve())
            rows.append(
                {
                    "kind": "pcap",
                    "component_id": binding.component_id,
                    "role": binding.role,
                    "default": (
                        binding.component_id
                        == pcap_sources.default_component_id
                    ),
                    "source_input_component_ids": (
                        list(pcap_sources.default_input_component_ids)
                        if binding.component_id
                        == pcap_sources.default_component_id
                        else []
                    ),
                    "size": identity.size_bytes,
                    "bounded_identity_sha256": identity.identity_sha256,
                    "identity_semantics": identity.identity_semantics,
                }
            )
    elif pcap:
        identity = bounded_file_identity(Path(pcap).resolve())
        rows.append(
            {
                "kind": "pcap",
                "size": identity.size_bytes,
                "bounded_identity_sha256": identity.identity_sha256,
                "identity_semantics": identity.identity_semantics,
            }
        )
    if not rows:
        rows.append({"kind": "none"})
    encoded = json.dumps(
        rows,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def evidence_binding_record(
    *,
    disk: object | None,
    case_label: str,
    memory: str | None,
    pcap: str | None,
    pcap_sources: PcapSourceCatalog | None,
) -> ConversationEvidenceBinding | None:
    """Describe the open evidence set as sources a later console can reopen."""

    from forensic_agent.cli.conversation import (
        ConversationEvidenceBinding,
        ConversationEvidenceSource,
    )

    sources: list[ConversationEvidenceSource] = []
    image_path = getattr(disk, "image_path", None)
    if image_path:
        sources.append(
            ConversationEvidenceSource.create(kind="disk", path=str(image_path))
        )
    for kind, value in (("memory", memory),):
        if value:
            sources.append(
                ConversationEvidenceSource.create(kind=kind, path=str(value))
            )
    network_default = ""
    network_inputs: tuple[str, ...] = ()
    if pcap_sources is not None:
        for binding in pcap_sources.bindings:
            sources.append(
                ConversationEvidenceSource.create(
                    kind="network",
                    path=binding.path,
                    component_id=binding.component_id,
                    role=binding.role,
                )
            )
        network_default = pcap_sources.default_component_id
        network_inputs = pcap_sources.default_input_component_ids
    elif pcap:
        sources.append(
            ConversationEvidenceSource.create(kind="network", path=str(pcap))
        )
    if not sources:
        return None
    return ConversationEvidenceBinding.create(
        case_label=case_label,
        sources=tuple(sources),
        network_default=network_default,
        network_inputs=network_inputs,
    )


class EvidenceFileResolver(Protocol):
    """Turns one recorded path into a file this console may read, or raises."""

    def __call__(self, path: str, *, label: str) -> str: ...


@dataclass(frozen=True, slots=True)
class RestorableSources:
    """What a recorded binding still amounts to, and what it no longer does.

    Carries paths rather than opened sources: opening a disk image is minutes of
    work that can fail, and it has to happen where the failure can be allowed to
    leave the active case untouched.
    """

    any_reachable: bool
    disk_path: str | None
    memory_path: str | None
    pcap_sources: PcapSourceCatalog | None
    unreachable: tuple[str, ...]


def restorable_sources(
    binding: ConversationEvidenceBinding,
    *,
    resolve: EvidenceFileResolver,
) -> RestorableSources:
    """Sort a recorded binding into what can be reopened and what cannot.

    ``resolve`` is supplied by the caller and is the whole of this function's
    reach into the filesystem, which is what keeps the container boundary out of
    a restore: a path that no longer lies inside the mounted evidence root simply
    fails to resolve and is reported missing. Reopening what is still mounted is
    a restore; asking the host launcher for a new mount on the operator's behalf
    is a different act, and it is not this one.
    """

    from forensic_agent.tools.pcap_sources import PcapSourceCatalog

    labels = {
        "disk": "Disk image",
        "memory": "Memory dump",
        "network": "Network capture",
    }
    # Named the way the evidence table names them, so a missing source reads
    # as the same thing the operator saw when it was still there.
    named = {
        "disk": _t("disk image"),
        "memory": _t("memory dump"),
        "network": _t("network capture"),
    }
    reachable: list[tuple[ConversationEvidenceSource, str]] = []
    unreachable: list[str] = []
    for source in binding.sources:
        try:
            resolved = resolve(source.path, label=labels[source.kind])
        except Exception:
            unreachable.append(f"{named[source.kind]}: {source.path}")
            continue
        reachable.append((source, resolved))
    if not reachable:
        return RestorableSources(
            any_reachable=False,
            disk_path=None,
            memory_path=None,
            pcap_sources=None,
            unreachable=tuple(unreachable),
        )

    memory_path: str | None = None
    network_sources: dict[str, tuple[str, str]] = {}
    for source, resolved in reachable:
        if source.kind == "memory":
            memory_path = resolved
        elif source.kind == "network":
            component = (
                source.component_id or f"pcap-{len(network_sources) + 1:03d}"
            )
            network_sources[component] = (resolved, source.role or "pcap")
    catalog: PcapSourceCatalog | None = None
    if network_sources:
        default = binding.network_default
        if default not in network_sources:
            default = next(iter(network_sources))
        inputs = tuple(
            value for value in binding.network_inputs if value in network_sources
        )
        try:
            catalog = PcapSourceCatalog.create(
                sources=network_sources,
                default_component_id=default,
                default_input_component_ids=inputs,
            )
        except ValueError:
            # A derived capture without the originals it was merged from is
            # no longer the set that was recorded, so it is reported missing
            # rather than rebuilt into something that only resembles it.
            unreachable.extend(
                f"{named['network']}: {path}"
                for path, _role in network_sources.values()
            )
            catalog = None

    disk_path: str | None = None
    for source, resolved in reachable:
        if source.kind == "disk":
            disk_path = resolved
            break
    return RestorableSources(
        any_reachable=True,
        disk_path=disk_path,
        memory_path=memory_path,
        pcap_sources=catalog,
        unreachable=tuple(unreachable),
    )
