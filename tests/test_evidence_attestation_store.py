"""Verify once, reuse with the identity re-check, re-verify on demand.

The store keeps the first verified pass's digests keyed by source path;
a later open reuses them only while every physical segment still matches
the recorded device, inode, size and timestamps — the same comparison
the streaming pass anchors to.
"""

from __future__ import annotations

import pytest

from forensic_agent.core import evidence_attestation_store as store
from forensic_agent.core.evidence_source import attest_evidence_source


@pytest.fixture()
def store_root(tmp_path, monkeypatch):
    root = tmp_path / "index-root"
    root.mkdir()
    monkeypatch.setenv("DFA_INDEX_ROOT", str(root))
    monkeypatch.delenv(store.VERIFY_EVERY_OPEN_ENVIRONMENT_VARIABLE, raising=False)
    return root


def test_round_trip_and_identity_gate(tmp_path, store_root):
    image = tmp_path / "evidence.dd"
    image.write_bytes(b"raw evidence bytes" * 1024)

    attestation = attest_evidence_source(image)
    store.store_open_attestation(attestation, md5="a" * 32, sha1="b" * 40)

    reused = store.load_reusable_attestation(str(image))
    assert reused is not None
    reloaded, verified_at = reused
    assert reloaded.sha256 == attestation.sha256
    assert reloaded.size_bytes == attestation.size_bytes
    assert verified_at

    # The identity gate: any change to the file's stable metadata voids
    # the stored attestation and forces a fresh full pass.
    image.write_bytes(b"different bytes entirely" * 1024)
    assert store.load_reusable_attestation(str(image)) is None


def test_absent_record_means_full_verification(tmp_path, store_root):
    image = tmp_path / "never-seen.dd"
    image.write_bytes(b"x" * 4096)
    assert store.load_reusable_attestation(str(image)) is None


def test_the_environment_can_force_the_old_behaviour(monkeypatch):
    monkeypatch.setenv(store.VERIFY_EVERY_OPEN_ENVIRONMENT_VARIABLE, "1")
    assert store.verification_reuse_enabled() is False
    monkeypatch.delenv(store.VERIFY_EVERY_OPEN_ENVIRONMENT_VARIABLE)
    assert store.verification_reuse_enabled() is True


def test_a_corrupt_record_fails_open(tmp_path, store_root):
    image = tmp_path / "evidence.dd"
    image.write_bytes(b"raw evidence bytes" * 512)
    attestation = attest_evidence_source(image)
    store.store_open_attestation(attestation)
    record = next((store_root / "integrity-attestations").glob("*.json"))
    record.write_text("{not json", encoding="utf-8")
    assert store.load_reusable_attestation(str(image)) is None
