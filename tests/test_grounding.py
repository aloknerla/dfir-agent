"""Tests for investigation-time path grounding (provenance arm of P1)."""
import pytest

from forensic_agent.oversight.grounding import GroundingLedger


# --------------------------- pure ledger logic --------------------------- #
def test_listing_grounds_real_children_not_invented_siblings():
    led = GroundingLedger()
    led.observe({"path": "/Windows"},
                {"path": "/Windows", "entries": [{"name": "System32"}, {"name": "notepad.exe"}]})
    assert led.is_grounded("/Windows/System32")["basis"] == "prior_output"
    assert led.is_grounded("/Windows/notepad.exe")["grounded"] is True
    assert led.is_grounded("/Windows/InventedDir")["grounded"] is False   # sibling not in listing


def test_nav_root_and_accessed_arg_are_grounded():
    led = GroundingLedger(roots=["/case/evidence"])
    assert led.is_grounded("/")["basis"] == "nav_root"
    assert led.is_grounded("/case/evidence")["basis"] == "nav_root"
    led.observe({"path": "/Users/Alice/note.txt"},
                {"path": "/Users/Alice/note.txt", "content_text": "hello"})
    assert led.is_grounded("/Users/Alice/note.txt")["basis"] == "prior_output"


def test_registry_token_harvested_from_output_with_backslash_norm():
    led = GroundingLedger()
    led.observe({}, {"text": r"found key HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR in hive"})
    # proposed value uses single backslashes; ledger stored from JSON (double) -> still matches
    assert led.is_grounded(r"HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR")["grounded"] is True


def test_check_lists_ungrounded_path_args():
    led = GroundingLedger()
    out = led.check({"path": "/invented/x", "max_bytes": 10})
    assert out == [("path", "/invented/x", "ungrounded")]
    assert led.check({"path": "/"}) == []                      # nav root is fine


def test_query_text_that_looks_like_a_path_is_not_grounded_as_a_path():
    led = GroundingLedger()

    assert led.check({"filter": "/~gnome/", "display_filter": "/http/"}) == []
    assert led.check({"save_path": "/outside"}) == [
        ("save_path", "/outside", "ungrounded")
    ]


# --------------------------- integration via the gate -------------------- #
def test_grounding_annotates_by_default_without_blocking(tmp_path):
    st = pytest.importorskip("langchain_core.tools")
    from forensic_agent.oversight import wrap_with_oversight
    from forensic_agent.oversight.core import OversightGate, OversightLog, Policy

    ran = {"n": 0}

    def read_file(path: str) -> dict:
        """Read a file on the image."""
        ran["n"] += 1
        return {"path": path, "content_text": "x"}

    bb = str(tmp_path / "bb.jsonl")
    gate = OversightGate(Policy.permissive(), OversightLog(bb))   # ground_paths = False
    gate.recorder.open_case(question="q", policy=gate.policy)
    rf = wrap_with_oversight([st.StructuredTool.from_function(read_file)], gate)[0]

    out = rf.invoke({"path": "/Windows/System32/never/seen"})
    assert ran["n"] == 1 and out.get("content_text") == "x"         # ran: annotate, not block
    acts = [e for e in OversightLog.load(bb) if e.get("event") == "action"]
    assert any("ungrounded-path" in r for r in acts[-1]["reasons"])  # but it was flagged


def test_grounding_blocks_when_enabled_and_bootstraps_via_listing(tmp_path):
    st = pytest.importorskip("langchain_core.tools")
    from forensic_agent.oversight import wrap_with_oversight
    from forensic_agent.oversight.core import OversightGate, OversightLog, Policy

    def list_directory(path: str) -> dict:
        """List a directory on the image."""
        return {"path": path, "entries": [{"name": "Windows"}]}

    def read_file(path: str) -> dict:
        """Read a file on the image."""
        return {"path": path, "content_text": "x"}

    pol = Policy.permissive()
    pol.ground_paths = True                                          # deny arm (ablation)
    gate = OversightGate(pol, OversightLog(str(tmp_path / "bb.jsonl")))
    gate.recorder.open_case(question="q", policy=pol)
    ld, rf = wrap_with_oversight(
        [st.StructuredTool.from_function(list_directory),
         st.StructuredTool.from_function(read_file)], gate)

    # invented path -> blocked, real function never runs
    blocked = rf.invoke({"path": "/Invented/secret"})
    assert "BLOCKED" in str(blocked.get("error", "")) and "ungrounded" in str(blocked.get("error", ""))

    # list the root (nav_root) -> allowed, grounds its children
    listing = ld.invoke({"path": "/"})
    assert listing.get("entries")

    # now a discovered child is grounded -> allowed
    ok = rf.invoke({"path": "/Windows"})
    assert ok.get("content_text") == "x"
