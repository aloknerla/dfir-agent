"""Where a domain ends is read from a published list, never inferred here.

The rule this replaced returned the last two labels of a query name, so
``evil.co.uk`` was reported as ``co.uk`` — the registry operator's name in place
of the registrant's. Today's validation recorded that as a defect. What is pinned
below is that the answer now comes from a Public Suffix List reader, that the
reading names the list version that gave it, and that a host with no reader
installed reports no domain at all rather than reviving the old rule under
another name.

The reassembly itself is pinned as independent of all of that: chunks are grouped
by the stem their indexed label was prepended to, which is a property of the query
names, so the recovered bytes are identical on a host with a reader and on one
without. A capability that changed what evidence a call could reach depending on
what happened to be installed would be worse than the defect it replaced.
"""

from __future__ import annotations

from typing import Any

import pytest

from forensic_agent.tools import public_suffix
from forensic_agent.tools.pcap_tool import reconstruct_dns_exfil

#: A reader available on this host answers for real; one that is not is stubbed,
#: so the wiring is pinned everywhere and the list itself is pinned where it is.
_LIVE_READER = public_suffix.reader_identity().get("available") is True
_requires_reader = pytest.mark.skipif(
    not _LIVE_READER, reason="no Public Suffix List reader is installed on this host"
)


class _StubReader:
    """The two calls :func:`registrable_domain` makes on a loaded library."""

    #: Only the suffixes these tests exercise; a stub that answered more would be
    #: this project carrying a suffix list of its own, which is the thing removed.
    _SUFFIXES = ("co.uk", "com", "org", "hr")

    def split(self, name: str) -> tuple[str | None, str | None]:
        for suffix in sorted(self._SUFFIXES, key=len, reverse=True):
            if name == suffix:
                return None, suffix
            if name.endswith("." + suffix):
                registrable = name[: -(len(suffix) + 1)].rsplit(".", 1)[-1]
                return f"{registrable}.{suffix}", suffix
        return None, name

    def identity(self) -> dict[str, Any]:
        return {
            "reader": "stub",
            "library": "stub",
            "library_version": "0",
            "list": {"source": "stub", "sha1": "0" * 40},
            "suffix_entries": len(self._SUFFIXES),
            "suffix_exceptions": 0,
        }


@pytest.fixture
def stub_reader(monkeypatch: pytest.MonkeyPatch) -> _StubReader:
    reader = _StubReader()
    monkeypatch.setattr(public_suffix, "_reader", lambda: reader)
    return reader


@pytest.fixture
def no_reader(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(public_suffix, "_reader", lambda: None)


def _chunks(stem: str, payload: bytes) -> list[str]:
    hexed = payload.hex()
    half = len(hexed) // 2
    return [f"0-{hexed[:half]}.{stem}", f"1-{hexed[half:]}.{stem}"]


# --- the reading itself ------------------------------------------------------ #


def test_a_multi_label_public_suffix_does_not_swallow_the_registrant(stub_reader):
    """The case the retired rule got wrong, at the reader's own boundary."""

    out = public_suffix.registrable_domain("evil.co.uk")

    assert out["registrable_domain"] == "evil.co.uk"
    assert out["public_suffix"] == "co.uk"


def test_a_deeper_name_still_resolves_to_the_registrable_domain(stub_reader):
    out = public_suffix.registrable_domain("a.b.evil.co.uk")

    assert out["registrable_domain"] == "evil.co.uk"
    assert out["public_suffix"] == "co.uk"


def test_every_reading_carries_the_identity_of_the_list_that_answered(stub_reader):
    """A split with no list version behind it is not attributable to anything."""

    out = public_suffix.registrable_domain("t.evil.com")

    assert out["public_suffix_list"]["reader"] == "stub"
    assert out["public_suffix_list"]["list"]["sha1"] == "0" * 40
    assert out["public_suffix_list"]["suffix_entries"] == 4


def test_a_name_is_normalised_before_it_is_looked_up(stub_reader):
    assert public_suffix.registrable_domain("  T.EVIL.CO.UK.  ")["name"] == "t.evil.co.uk"


def test_an_empty_name_is_refused_before_any_reader_is_consulted(no_reader):
    assert "error" in public_suffix.registrable_domain("")


def test_a_missing_reader_is_reported_rather_than_worked_around(no_reader):
    out = public_suffix.registrable_domain("evil.co.uk")

    assert "registrable_domain" not in out
    assert "no Public Suffix List reader is installed" in out["error"]
    assert public_suffix.reader_identity()["available"] is False


def test_a_named_library_that_is_not_one_leaves_no_reader(
    tmp_path, monkeypatch: pytest.MonkeyPatch
):
    """An operator's pointer is honoured or reported, never quietly bypassed."""

    decoy = tmp_path / "libpsl.so.5"
    decoy.write_bytes(b"not an object file")
    monkeypatch.setenv("DFA_PSL_LIBRARY", str(decoy))
    public_suffix.reset_cache()
    try:
        assert public_suffix.reader_identity()["available"] is False
    finally:
        public_suffix.reset_cache()


@_requires_reader
def test_the_installed_list_resolves_the_defect_case_and_names_its_version():
    """The live list, on a host that has one: no stub stands in for the answer."""

    out = public_suffix.registrable_domain("a.b.evil.co.uk")

    assert out["registrable_domain"] == "evil.co.uk"
    assert out["public_suffix"] == "co.uk"
    identity = out["public_suffix_list"]
    assert identity["reader"] == "libpsl"
    assert identity["suffix_entries"] > 1000
    assert identity["list"].get("sha1") or identity["list"].get("sha256")


# --- what the reconstruction does with it ------------------------------------ #


def test_the_exfiltration_domain_is_the_registrant_not_the_registry(stub_reader):
    """The whole point: ``evil.co.uk`` is reported, not ``co.uk``."""

    out = reconstruct_dns_exfil([f"{i}-4142.t.evil.co.uk" for i in range(1, 6)])

    assert out["base_domain"] == "evil.co.uk"
    assert out["exfiltration_query_stem"] == "t.evil.co.uk"
    assert out["base_domain_reading"]["public_suffix"] == "co.uk"


def test_the_reported_domain_is_the_readers_word_and_says_whose(stub_reader):
    out = reconstruct_dns_exfil([f"{i}-4142.tunnel.evil.com" for i in range(1, 6)])

    assert out["base_domain"] == "evil.com"
    assert out["base_domain_reading"]["public_suffix_list"]["reader"] == "stub"


def test_unrelated_queries_do_not_join_the_reassembly(stub_reader):
    names = [f"{i}-4142.t.evil.com" for i in range(1, 8)] + [
        "www.example.org",
        "cdn.example.org",
    ]

    out = reconstruct_dns_exfil(names)

    assert out["base_domain"] == "evil.com"
    assert out["chunk_count"] == 7


def test_the_recovered_bytes_do_not_depend_on_the_list_being_installed(
    monkeypatch: pytest.MonkeyPatch,
):
    """Grouping is syntactic, so an absent reader costs a name and no evidence."""

    names = _chunks("t.evil.co.uk", b"hello exfil")

    monkeypatch.setattr(public_suffix, "_reader", lambda: _StubReader())
    with_reader = reconstruct_dns_exfil(names)
    monkeypatch.setattr(public_suffix, "_reader", lambda: None)
    without_reader = reconstruct_dns_exfil(names)

    assert with_reader["chunk_count"] == without_reader["chunk_count"] == 2
    assert with_reader["utf8"] == without_reader["utf8"] == "hello exfil"
    assert with_reader["base_domain"] == "evil.co.uk"
    assert without_reader["base_domain"] is None
    assert "no Public Suffix List reader" in without_reader["base_domain_reading"]["error"]


def test_names_with_nothing_indexed_still_report_the_stem_they_share(stub_reader):
    out = reconstruct_dns_exfil(["www.example.org", "cdn.example.org"])

    assert out["chunk_count"] == 0
    assert out["base_domain"] == "example.org"
    assert out["exfiltration_query_stem"] == "example.org"
    labels = {entry["label"] for entry in out["non_indexed_labels_base64"]}
    assert labels == {"cdn", "www"}


def test_nothing_to_analyse_is_still_nothing_to_analyse(stub_reader):
    assert reconstruct_dns_exfil([]) == {"note": "no DNS query names to analyze"}
    assert reconstruct_dns_exfil(["localhost"]) == {
        "note": "no DNS query names to analyze"
    }


@_requires_reader
def test_the_installed_list_answers_the_reconstruction_too():
    out = reconstruct_dns_exfil([f"{i}-4142.t.evil.co.uk" for i in range(1, 6)])

    assert out["base_domain"] == "evil.co.uk"
    assert out["base_domain_reading"]["public_suffix_list"]["reader"] == "libpsl"
