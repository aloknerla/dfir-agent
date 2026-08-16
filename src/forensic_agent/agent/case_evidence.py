"""Typed, path-free identities for the evidence sources in one forensic case.

The contract is independent of the agent runtime and can therefore be shared by
the interactive console and evaluation adapters.  Component records distinguish
an exact content digest from a bounded correlation identity: a sampled identity
must never be presented as proof that the complete evidence source was hashed.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from typing import Final

from forensic_agent.agent.tool_taxonomy import (
    CITED_RESULT_INPUT_TOOLS,
    HOST_PATH_TOOLS,
    MEMORY_TOOLS,
    PCAP_COMPONENT_ROLES,
    PCAP_TOOLS,
    RAW_IMAGE_TOOLS,
    REFERENCE_TOOLS,
)
from forensic_agent.core.repro import canonical_json, sha256_hex
from forensic_agent.tools.pcap_sources import PcapSourceCatalog

CASE_EVIDENCE_SOURCE_SCHEMA_ID: Final = "forensic.case-evidence-source.v1"
CASE_EVIDENCE_SOURCE_MEDIA_TYPE: Final = (
    "application/vnd.forensic-agent.case-evidence-bundle+json"
)
DERIVED_ARTIFACT_SOURCE_MEDIA_TYPE: Final = (
    "application/vnd.forensic-agent.derived-artifact+json"
)
EXACT_FILE_IDENTITY_SEMANTICS: Final = "sha256-exact-file-bytes-v1"
SAMPLED_FILE_IDENTITY_SEMANTICS: Final = (
    "sha256-size-and-up-to-three-bounded-samples-v1"
)
CANONICAL_CASE_BUNDLE_DIGEST_SEMANTICS: Final = (
    "sha256-canonical-case-component-manifest-v1"
)
_DIRECT_SOURCE_MODALITIES: Final[frozenset[str]] = frozenset({"disk", "memory", "pcap"})
_SAFE_SOURCE_ID: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$")


def _valid_sha256(value: object) -> str | None:
    text = str(value or "").casefold()
    return text if re.fullmatch(r"[0-9a-f]{64}", text) else None


@dataclass(frozen=True, slots=True)
class CaseEvidenceComponentBinding:
    """Path-free identity of one evidence component selected for a case."""

    component_id: str
    role: str
    size_bytes: int
    identity_sha256: str
    identity_semantics: str
    content_sha256: str | None = None

    def __post_init__(self) -> None:
        if _SAFE_SOURCE_ID.fullmatch(self.component_id) is None:
            raise ValueError("case evidence component_id is invalid")
        if _SAFE_SOURCE_ID.fullmatch(self.role) is None:
            raise ValueError("case evidence component role is invalid")
        if isinstance(self.size_bytes, bool) or not isinstance(self.size_bytes, int):
            raise ValueError("case evidence component size must be an integer")
        if self.size_bytes < 0:
            raise ValueError("case evidence component size cannot be negative")
        identity_digest = _valid_sha256(self.identity_sha256)
        if identity_digest is None or identity_digest != self.identity_sha256:
            raise ValueError("case evidence component identity SHA-256 must be lowercase")
        if _SAFE_SOURCE_ID.fullmatch(self.identity_semantics) is None:
            raise ValueError("case evidence component identity semantics are invalid")
        if self.content_sha256 is not None:
            content_digest = _valid_sha256(self.content_sha256)
            if content_digest is None or content_digest != self.content_sha256:
                raise ValueError("case evidence component content SHA-256 must be lowercase")
        if (
            self.identity_semantics == SAMPLED_FILE_IDENTITY_SEMANTICS
            and self.content_sha256 is not None
        ):
            raise ValueError("a sampled component identity cannot claim a full content SHA-256")
        if (
            self.identity_semantics == EXACT_FILE_IDENTITY_SEMANTICS
            and self.content_sha256 != self.identity_sha256
        ):
            raise ValueError("an exact-file identity must equal its content SHA-256")

    def record(self) -> dict[str, object]:
        return {
            "component_id": self.component_id,
            "role": self.role,
            "size_bytes": self.size_bytes,
            "identity_sha256": self.identity_sha256,
            "identity_semantics": self.identity_semantics,
            "content_sha256": self.content_sha256,
        }


@dataclass(frozen=True, slots=True)
class CaseEvidenceSource:
    """Receipt-ready logical case source plus its selected evidence inputs.

    ``case_bundle_sha256`` identifies a path-free case manifest, not concatenated
    evidence bytes.  ``bundle_digest_semantics`` states how that digest was
    produced.  Every component separately records whether its identity represents
    complete content or only a bounded correlation sample.
    """

    case_id: str
    case_bundle_sha256: str
    bundle_digest_semantics: str
    components: tuple[CaseEvidenceComponentBinding, ...]
    active_component_ids_by_modality: tuple[tuple[str, tuple[str, ...]], ...]
    schema_id: str = CASE_EVIDENCE_SOURCE_SCHEMA_ID

    def __post_init__(self) -> None:
        if self.schema_id != CASE_EVIDENCE_SOURCE_SCHEMA_ID:
            raise ValueError("unknown case-evidence source schema")
        if _SAFE_SOURCE_ID.fullmatch(self.case_id) is None:
            raise ValueError("case-evidence case_id is invalid")
        digest = _valid_sha256(self.case_bundle_sha256)
        if digest is None or digest != self.case_bundle_sha256:
            raise ValueError("case-evidence bundle SHA-256 must be lowercase")
        if _SAFE_SOURCE_ID.fullmatch(self.bundle_digest_semantics) is None:
            raise ValueError("case-evidence bundle digest semantics are invalid")
        if not self.components or any(
            type(component) is not CaseEvidenceComponentBinding
            for component in self.components
        ):
            raise ValueError("case-evidence components are invalid")
        canonical_components = tuple(
            sorted(self.components, key=lambda item: (item.role, item.component_id))
        )
        if self.components != canonical_components:
            raise ValueError("case-evidence components are not canonical")
        component_ids = tuple(item.component_id for item in self.components)
        if len(component_ids) != len(set(component_ids)):
            raise ValueError("case-evidence component IDs are not unique")

        modalities = self.active_component_ids_by_modality
        if not modalities or tuple(sorted(modalities)) != modalities:
            raise ValueError("case-evidence parser-source modalities are not canonical")
        seen_modalities: set[str] = set()
        known_ids = set(component_ids)
        for modality, active_ids in modalities:
            if modality not in _DIRECT_SOURCE_MODALITIES or modality in seen_modalities:
                raise ValueError("case-evidence parser-source modality is invalid")
            seen_modalities.add(modality)
            if not active_ids or tuple(sorted(set(active_ids))) != active_ids:
                raise ValueError("case-evidence parser-source component IDs are not canonical")
            if not set(active_ids).issubset(known_ids):
                raise ValueError("case-evidence parser source references a foreign component")

    @classmethod
    def create(
        cls,
        *,
        case_id: str,
        case_bundle_sha256: str,
        bundle_digest_semantics: str,
        components: Collection[CaseEvidenceComponentBinding],
        active_component_ids_by_modality: Mapping[str, Collection[str]],
    ) -> CaseEvidenceSource:
        canonical_components = tuple(
            sorted(tuple(components), key=lambda item: (item.role, item.component_id))
        )
        canonical_modalities = tuple(
            sorted(
                (
                    modality,
                    tuple(sorted(set(component_ids))),
                )
                for modality, component_ids in active_component_ids_by_modality.items()
            )
        )
        return cls(
            case_id=case_id,
            case_bundle_sha256=case_bundle_sha256,
            bundle_digest_semantics=bundle_digest_semantics,
            components=canonical_components,
            active_component_ids_by_modality=canonical_modalities,
        )

    @property
    def source_id(self) -> str:
        return f"case-evidence-bundle-sha256:{self.case_bundle_sha256}"

    @property
    def source_uri(self) -> str:
        return f"evidence-bundle://sha256/{self.case_bundle_sha256}"

    @property
    def source_media_type(self) -> str:
        return CASE_EVIDENCE_SOURCE_MEDIA_TYPE

    @property
    def selected_component_set_sha256(self) -> str:
        return sha256_hex(canonical_json([item.record() for item in self.components]))

    def descriptor_record(self) -> dict[str, object]:
        return {
            "schema_id": self.schema_id,
            "case_id": self.case_id,
            "case_bundle_sha256": self.case_bundle_sha256,
            "bundle_digest_semantics": self.bundle_digest_semantics,
            "selected_component_set_sha256": self.selected_component_set_sha256,
            "selected_components": [item.record() for item in self.components],
            "active_component_ids_by_modality": {
                modality: list(component_ids)
                for modality, component_ids in self.active_component_ids_by_modality
            },
        }

    @property
    def descriptor_sha256(self) -> str:
        return sha256_hex(canonical_json(self.descriptor_record()))

    def _modality_for_tool(self, tool_name: str) -> str:
        if tool_name in REFERENCE_TOOLS:
            raise ValueError("reference tools cannot use a case-evidence bundle source")
        if tool_name in HOST_PATH_TOOLS or tool_name in ("decode", "transform_query"):
            raise ValueError("derived or inline tools require explicit parent-artifact provenance")
        if tool_name in MEMORY_TOOLS:
            return "memory"
        if tool_name in PCAP_TOOLS:
            return "pcap"
        if tool_name in RAW_IMAGE_TOOLS:
            # Which raw image is a property of the case, not of the function.
            active = dict(self.active_component_ids_by_modality)
            return "disk" if active.get("disk") else "memory"
        return "disk"

    def source_attributes_for_tool(self, tool_name: str) -> dict[str, object]:
        modality = self._modality_for_tool(tool_name)
        active = dict(self.active_component_ids_by_modality).get(modality)
        if active is None:
            raise ValueError(f"case-evidence source lacks {modality!r} parser inputs")
        by_id = {item.component_id: item for item in self.components}
        active_components = [by_id[component_id] for component_id in active]
        return {
            **self.descriptor_record(),
            "descriptor_sha256": self.descriptor_sha256,
            "active_modality": modality,
            "active_component_ids": list(active),
            "active_component_roles": sorted({item.role for item in active_components}),
        }

    def for_derived_artifact(
        self,
        tool_name: str,
        artifact: object,
    ) -> DerivedArtifactEvidenceSource:
        """Serve a function reading an artifact this run produced from evidence."""

        if tool_name not in HOST_PATH_TOOLS | CITED_RESULT_INPUT_TOOLS:
            raise ValueError("only derived-input functions read a reconstructed artifact")
        case_id = str(getattr(artifact, "case_id", "") or "")
        if case_id != self.case_id:
            raise ValueError("a reconstructed artifact of another case is not this case's evidence")
        invocation = str(getattr(artifact, "producing_invocation_id", "") or "")
        payload_digest = _valid_sha256(getattr(artifact, "producing_payload_sha256", None))
        if not invocation or payload_digest is None:
            raise ValueError("a reconstructed artifact must name the call that produced it")
        return DerivedArtifactEvidenceSource(
            case_source=self,
            producing_invocation_id=invocation,
            producing_payload_sha256=payload_digest,
            producing_tool=str(getattr(artifact, "producing_tool", "") or "unknown"),
        )

    def for_tool_component(
        self,
        tool_name: str,
        component_id: str,
        *,
        related_component_ids: Collection[str] = (),
    ) -> CaseEvidenceSource:
        """Narrow one call's descriptor to the exact parser-active component."""

        modality = self._modality_for_tool(tool_name)
        by_id = {item.component_id: item for item in self.components}
        component = by_id.get(component_id)
        if component is None:
            raise ValueError("case-evidence call source references a foreign component")
        if modality == "pcap" and component.role not in PCAP_COMPONENT_ROLES:
            raise ValueError("case-evidence PCAP call source has a non-PCAP role")
        related_ids = tuple(sorted(set(related_component_ids)))
        if component_id in set(related_ids):
            raise ValueError("case-evidence call source cannot be its own related input")
        try:
            selected_components = (component, *(by_id[item] for item in related_ids))
        except KeyError as exc:
            raise ValueError("case-evidence call source input references a foreign component") from exc
        if modality == "pcap" and any(
            item.role not in PCAP_COMPONENT_ROLES for item in selected_components
        ):
            raise ValueError("case-evidence PCAP call input has a non-PCAP role")
        return CaseEvidenceSource.create(
            case_id=self.case_id,
            case_bundle_sha256=self.case_bundle_sha256,
            bundle_digest_semantics=self.bundle_digest_semantics,
            components=selected_components,
            active_component_ids_by_modality={modality: (component.component_id,)},
        )


@dataclass(frozen=True, slots=True)
class DerivedArtifactEvidenceSource:
    """Receipt-ready source for a function reading what this run reconstructed.

    It carries the case identity unchanged and names, as its own source, the call
    that produced the artifact, so the result over it is a DERIVED result whose
    parent the final check resolves through the trusted audit chain.
    """

    case_source: CaseEvidenceSource
    producing_invocation_id: str
    producing_payload_sha256: str
    producing_tool: str

    @property
    def case_id(self) -> str:
        return self.case_source.case_id

    @property
    def case_bundle_sha256(self) -> str:
        return self.case_source.case_bundle_sha256

    @property
    def components(self) -> tuple[CaseEvidenceComponentBinding, ...]:
        return self.case_source.components

    @property
    def source_id(self) -> str:
        return f"derived-artifact-invocation:{self.producing_invocation_id}"

    @property
    def source_uri(self) -> str:
        return f"derived-artifact://invocation/{self.producing_invocation_id}"

    @property
    def source_media_type(self) -> str:
        return DERIVED_ARTIFACT_SOURCE_MEDIA_TYPE

    def source_attributes_for_tool(self, tool_name: str) -> dict[str, object]:
        if tool_name not in HOST_PATH_TOOLS | CITED_RESULT_INPUT_TOOLS:
            raise ValueError("a derived-artifact source serves only derived-input functions")
        return {
            **self.case_source.descriptor_record(),
            "descriptor_sha256": self.case_source.descriptor_sha256,
            "active_modality": "derived",
            "active_component_ids": [],
            "active_component_roles": [],
            "derived_from_invocation_id": self.producing_invocation_id,
            "derived_from_payload_sha256": self.producing_payload_sha256,
            "derived_from_tool": self.producing_tool,
        }


def validate_case_pcap_catalog(
    source: CaseEvidenceSource,
    catalog: PcapSourceCatalog,
) -> None:
    """Bind every runtime capture path to its path-free selected component."""

    by_id = {item.component_id: item for item in source.components}
    expected_ids = {
        item.component_id for item in source.components if item.role in PCAP_COMPONENT_ROLES
    }
    if set(catalog.component_ids) != expected_ids:
        raise ValueError("PCAP source catalog differs from selected case components")
    for binding in catalog.bindings:
        if by_id[binding.component_id].role != binding.role:
            raise ValueError("PCAP source catalog role differs from case component")
    active_default = dict(source.active_component_ids_by_modality).get("pcap")
    if active_default != (catalog.default_component_id,):
        raise ValueError("PCAP source catalog default differs from parser-active component")
    default_role = by_id[catalog.default_component_id].role
    raw_ids = tuple(sorted(item.component_id for item in source.components if item.role == "pcap"))
    if default_role in {"derived_pcap", "merged_pcap", "pcap_merged"}:
        if catalog.default_input_component_ids != raw_ids:
            raise ValueError("derived PCAP catalog does not bind every raw input")
    elif catalog.default_input_component_ids:
        raise ValueError("a raw default PCAP cannot declare derived source inputs")


__all__ = [
    "CANONICAL_CASE_BUNDLE_DIGEST_SEMANTICS",
    "CASE_EVIDENCE_SOURCE_MEDIA_TYPE",
    "CASE_EVIDENCE_SOURCE_SCHEMA_ID",
    "EXACT_FILE_IDENTITY_SEMANTICS",
    "SAMPLED_FILE_IDENTITY_SEMANTICS",
    "CaseEvidenceComponentBinding",
    "CaseEvidenceSource",
    "validate_case_pcap_catalog",
]
