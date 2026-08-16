"""Path-free case evidence identities used by the interactive console."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from forensic_agent.agent.case_evidence import (
    CANONICAL_CASE_BUNDLE_DIGEST_SEMANTICS,
    SAMPLED_FILE_IDENTITY_SEMANTICS,
    CaseEvidenceComponentBinding,
    CaseEvidenceSource,
)
from forensic_agent.core.evidence_source import (
    EvidenceSourceAttestation,
    stable_file_identity,
)
from forensic_agent.core.repro import canonical_json, sha256_hex
from forensic_agent.tools.pcap_sources import PcapSourceCatalog

_SAMPLE_BYTES = 1024 * 1024


@dataclass(frozen=True, slots=True)
class BoundedFileIdentity:
    """Correlation identity over a file's size and three bounded byte samples."""

    size_bytes: int
    identity_sha256: str
    identity_semantics: str = SAMPLED_FILE_IDENTITY_SEMANTICS


def _path_handle_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    """Fields Windows reports consistently through path and open-handle stat."""

    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
    )


def bounded_file_identity(path: str | Path) -> BoundedFileIdentity:
    """Return a stable bounded identity without claiming a complete content hash."""

    source = Path(path).expanduser().resolve()
    before = source.stat()
    offsets = {
        0,
        max(0, before.st_size // 2 - _SAMPLE_BYTES // 2),
        max(0, before.st_size - _SAMPLE_BYTES),
    }
    digest = hashlib.sha256()
    digest.update(str(before.st_size).encode("ascii"))
    with source.open("rb") as handle:
        opened_before = os.fstat(handle.fileno())
        for offset in sorted(offsets):
            handle.seek(offset)
            chunk = handle.read(_SAMPLE_BYTES)
            digest.update(offset.to_bytes(8, "big", signed=False))
            digest.update(len(chunk).to_bytes(8, "big", signed=False))
            digest.update(chunk)
        opened_after = os.fstat(handle.fileno())
    after = source.stat()
    path_handle_identities = {
        _path_handle_identity(before),
        _path_handle_identity(opened_before),
        _path_handle_identity(opened_after),
        _path_handle_identity(after),
    }
    if (
        stable_file_identity(before) != stable_file_identity(after)
        or stable_file_identity(opened_before) != stable_file_identity(opened_after)
        or len(path_handle_identities) != 1
    ):
        raise RuntimeError("evidence file changed while its bounded identity was sampled")
    return BoundedFileIdentity(
        size_bytes=before.st_size,
        identity_sha256=digest.hexdigest(),
    )


def build_interactive_pcap_catalog(
    pcap_path: str | None,
) -> PcapSourceCatalog | None:
    """Bind the console's single capture to a stable model-visible component ID."""

    if not pcap_path:
        return None
    return PcapSourceCatalog.create(
        sources={"pcap-primary": (str(Path(pcap_path).resolve()), "pcap")},
        default_component_id="pcap-primary",
    )


def _sampled_component(
    *,
    component_id: str,
    role: str,
    path: str,
) -> CaseEvidenceComponentBinding:
    identity = bounded_file_identity(path)
    return CaseEvidenceComponentBinding(
        component_id=component_id,
        role=role,
        size_bytes=identity.size_bytes,
        identity_sha256=identity.identity_sha256,
        identity_semantics=identity.identity_semantics,
        content_sha256=None,
    )


def _disk_component(disk: Any) -> CaseEvidenceComponentBinding | None:
    attestation = getattr(disk, "evidence_source_attestation", None)
    if type(attestation) is EvidenceSourceAttestation:
        attestation = cast(EvidenceSourceAttestation, attestation)
        image_path = getattr(disk, "image_path", None)
        if image_path and Path(image_path).resolve() != Path(attestation.primary_path).resolve():
            raise ValueError("disk attestation belongs to a different evidence path")
        return CaseEvidenceComponentBinding(
            component_id="disk-primary",
            role="disk",
            size_bytes=attestation.size_bytes,
            identity_sha256=attestation.sha256,
            identity_semantics=attestation.digest_semantics,
            content_sha256=attestation.sha256,
        )
    image_path = getattr(disk, "image_path", None)
    if image_path and Path(image_path).is_file():
        return _sampled_component(
            component_id="disk-primary",
            role="disk",
            path=str(image_path),
        )
    return None


def build_interactive_case_evidence_source(
    *,
    case_id: str,
    disk: Any | None,
    memory_path: str | None,
    pcap_path: str | None,
    pcap_sources: PcapSourceCatalog | None = None,
) -> CaseEvidenceSource | None:
    """Build a path-free descriptor for the local evidence currently in use."""

    components: list[CaseEvidenceComponentBinding] = []
    active: dict[str, tuple[str, ...]] = {}

    if disk is not None:
        disk_component = _disk_component(disk)
        if disk_component is not None:
            components.append(disk_component)
            active["disk"] = (disk_component.component_id,)

    if memory_path:
        component = _sampled_component(
            component_id="memory-primary",
            role="memory",
            path=memory_path,
        )
        components.append(component)
        active["memory"] = (component.component_id,)

    if pcap_path:
        catalog = pcap_sources or build_interactive_pcap_catalog(pcap_path)
        assert catalog is not None
        default_binding = catalog.resolve(None)
        if Path(default_binding.path).resolve() != Path(pcap_path).resolve():
            raise ValueError("PCAP catalog default differs from the selected capture")
        for binding in catalog.bindings:
            components.append(
                _sampled_component(
                    component_id=binding.component_id,
                    role=binding.role,
                    path=binding.path,
                )
            )
        active["pcap"] = (catalog.default_component_id,)

    if not components:
        return None

    canonical_components = tuple(
        sorted(components, key=lambda item: (item.role, item.component_id))
    )
    canonical_active = {
        modality: tuple(sorted(component_ids))
        for modality, component_ids in sorted(active.items())
    }
    manifest = {
        "schema_id": "forensic.interactive-case-evidence-manifest.v1",
        "case_id": case_id,
        "components": [component.record() for component in canonical_components],
        "active_component_ids_by_modality": {
            modality: list(component_ids)
            for modality, component_ids in canonical_active.items()
        },
    }
    return CaseEvidenceSource.create(
        case_id=case_id,
        case_bundle_sha256=sha256_hex(canonical_json(manifest)),
        bundle_digest_semantics=CANONICAL_CASE_BUNDLE_DIGEST_SEMANTICS,
        components=canonical_components,
        active_component_ids_by_modality=canonical_active,
    )


__all__ = [
    "BoundedFileIdentity",
    "bounded_file_identity",
    "build_interactive_case_evidence_source",
    "build_interactive_pcap_catalog",
]
