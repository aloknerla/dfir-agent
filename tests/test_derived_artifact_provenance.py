"""A reconstruction is served by the call that produced it, not by the bundle.

The case bundle digest is the case identity. A run that added the archive it
lifted out of a capture as a bundle component would be changing what the case is
while examining it; a run that refused the archive outright stops one step short
of the answer. These tests pin the third way: the artifact keeps the case
identity and names its producing call as its source, which is what makes the
result over it a DERIVED result the final check can resolve.
"""

from __future__ import annotations

import pytest

from forensic_agent.agent.case_evidence import (
    CANONICAL_CASE_BUNDLE_DIGEST_SEMANTICS,
    DERIVED_ARTIFACT_SOURCE_MEDIA_TYPE,
    CaseEvidenceComponentBinding,
    CaseEvidenceSource,
)
from forensic_agent.agent.derived_artifacts import (
    DerivedArtifactCatalog,
    named_artifact_path,
)

CASE = "case-derived-01"


def _source() -> CaseEvidenceSource:
    component = CaseEvidenceComponentBinding(
        component_id="pcap-primary",
        role="pcap",
        size_bytes=19_550,
        identity_sha256="a" * 64,
        identity_semantics="sha256-exact-file-bytes-v1",
        content_sha256="a" * 64,
    )
    return CaseEvidenceSource.create(
        case_id=CASE,
        case_bundle_sha256="c" * 64,
        bundle_digest_semantics=CANONICAL_CASE_BUNDLE_DIGEST_SEMANTICS,
        components=[component],
        active_component_ids_by_modality={"pcap": ("pcap-primary",)},
    )


def _catalog() -> DerivedArtifactCatalog:
    catalog = DerivedArtifactCatalog()
    catalog.register(
        "/payload/dns_exfil_reconstruction.bin",
        case_id=CASE,
        producing_invocation_id="inv-0001",
        producing_payload_sha256="b" * 64,
        producing_tool="pcap_query",
    )
    return catalog


def test_the_artifact_keeps_the_case_identity_and_names_its_producer() -> None:
    artifact = _catalog().resolve("/payload/dns_exfil_reconstruction.bin")

    derived = _source().for_derived_artifact("archive_query", artifact)

    # The case is unchanged: same id, same bundle digest, same components.
    assert derived.case_id == CASE
    assert derived.case_bundle_sha256 == "c" * 64
    assert [item.component_id for item in derived.components] == ["pcap-primary"]
    # The SOURCE is the producing call, not a component.
    assert derived.source_id == "derived-artifact-invocation:inv-0001"
    assert derived.source_uri == "derived-artifact://invocation/inv-0001"
    assert derived.source_media_type == DERIVED_ARTIFACT_SOURCE_MEDIA_TYPE


def test_the_attributes_carry_the_parent_a_derived_result_must_cite() -> None:
    artifact = _catalog().resolve("/payload/dns_exfil_reconstruction.bin")

    attributes = _source().for_derived_artifact(
        "archive_query", artifact
    ).source_attributes_for_tool("archive_query")

    assert attributes["active_modality"] == "derived"
    assert attributes["derived_from_invocation_id"] == "inv-0001"
    assert attributes["derived_from_payload_sha256"] == "b" * 64
    assert attributes["derived_from_tool"] == "pcap_query"
    # No component is claimed active: the artifact is not one.
    assert attributes["active_component_ids"] == []
    assert attributes["case_id"] == CASE


def test_a_path_this_run_did_not_produce_resolves_to_nothing() -> None:
    catalog = _catalog()

    assert catalog.resolve("/payload/somebody-elses.7z") is None
    assert catalog.resolve("") is None
    assert catalog.resolve(None) is None


def test_an_artifact_of_another_case_is_refused() -> None:
    catalog = DerivedArtifactCatalog()
    foreign = catalog.register(
        "/payload/foreign.7z",
        case_id="another-case",
        producing_invocation_id="inv-0002",
        producing_payload_sha256="d" * 64,
        producing_tool="pcap_query",
    )

    with pytest.raises(ValueError, match="another case"):
        _source().for_derived_artifact("archive_query", foreign)


def test_the_first_producer_of_an_artifact_stays_its_parent() -> None:
    catalog = _catalog()

    again = catalog.register(
        "/payload/dns_exfil_reconstruction.bin",
        case_id=CASE,
        producing_invocation_id="inv-9999",
        producing_payload_sha256="e" * 64,
        producing_tool="pcap_query",
    )

    assert again.producing_invocation_id == "inv-0001"
    assert len(catalog) == 1


def test_an_incomplete_registration_records_nothing() -> None:
    catalog = DerivedArtifactCatalog()

    assert (
        catalog.register(
            "/payload/x.7z",
            case_id=CASE,
            producing_invocation_id="",
            producing_payload_sha256="b" * 64,
            producing_tool="pcap_query",
        )
        is None
    )
    assert (
        catalog.register(
            "/payload/x.7z",
            case_id=CASE,
            producing_invocation_id="inv-3",
            producing_payload_sha256="not-a-digest",
            producing_tool="pcap_query",
        )
        is None
    )
    assert len(catalog) == 0


def test_only_a_derived_input_function_may_be_served_this_way() -> None:
    artifact = _catalog().resolve("/payload/dns_exfil_reconstruction.bin")

    with pytest.raises(ValueError, match="derived-input functions"):
        _source().for_derived_artifact("pcap_query", artifact)


def test_the_named_path_is_read_from_the_argument_that_carries_one() -> None:
    assert named_artifact_path({"archive_path": "/payload/a.7z"}) == "/payload/a.7z"
    assert named_artifact_path({"image_path": "/payload/b.png"}) == "/payload/b.png"
    assert named_artifact_path({"operation": "list"}) == ""
    assert named_artifact_path(None) == ""
