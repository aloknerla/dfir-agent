"""Which file a raw-image byte offset came from.

A disk-wide search reports where bytes sit, not what holds them. Turning an
offset into a path is what makes a hit a finding, and the same step is where a
false attribution would be most damaging: bytes in unallocated space belong to no
file, and offering the nearest path instead would put a name on content the file
system does not claim. Both halves are pinned here.

Mocked — the binaries live on the evaluation host. What is pinned is the contract:
which sentences from the tools mean what, that repeated data units cost one
lookup, and that every refusal stays a refusal.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from forensic_agent.tools import offset_attribution as oa

#: A file system whose data units are 4096 bytes, in the shape fsstat reports it.
_FSSTAT = "File System Type: NTFS\nCluster Size: 4096\nSector Size: 512\n"


class _Tsk:
    """Stand in for the binaries, answering by which one was invoked."""

    def __init__(self, *, ifind: dict[str, str] | None = None,
                 ffind: dict[str, str] | None = None,
                 fsstat: str = _FSSTAT) -> None:
        self.ifind = ifind or {}
        self.ffind = ffind or {}
        self.fsstat = fsstat
        self.calls: list[list[str]] = []

    def __call__(self, argv, **kwargs):  # noqa: ANN001, ANN003
        self.calls.append(list(argv))
        binary = argv[0]
        if binary.endswith("fsstat"):
            return SimpleNamespace(stdout=self.fsstat, stderr="", returncode=0)
        if binary.endswith("ifind"):
            unit = argv[argv.index("-d") + 1]
            return SimpleNamespace(stdout=self.ifind.get(unit, "inode not found"),
                                   stderr="", returncode=0)
        return SimpleNamespace(stdout=self.ffind.get(argv[-1], "File name not found"),
                               stderr="", returncode=0)

    def count(self, binary: str) -> int:
        return sum(1 for argv in self.calls if argv[0].endswith(binary))


@pytest.fixture
def image(tmp_path):
    path = tmp_path / "img.dd"
    path.write_bytes(b"\x00")
    return str(path)


@pytest.fixture
def wired(monkeypatch):
    """Resolve every binary, and let each test install its own answers."""

    monkeypatch.setattr(oa, "resolve_tool", lambda names, env: f"/usr/bin/{names[0]}")

    def install(tsk: _Tsk) -> _Tsk:
        monkeypatch.setattr(oa, "run_external", tsk)
        return tsk

    return install


def _row(result: dict, offset: str) -> dict:
    return next(row for row in result["rows"] if row["offset"] == offset)


# --- an offset becomes a path ------------------------------------------------ #


def test_an_offset_resolves_to_the_file_holding_those_bytes(image, wired):
    wired(_Tsk(ifind={"176": "8724"}, ffind={"8724": "/Documents/notes.txt"}))
    out = oa.attribute_offsets(image, [721_408], block_size=4096)
    row = _row(out, "721408")
    assert row["attribution"] == "path"
    assert row["path"] == "/Documents/notes.txt"
    assert row["inode"] == "8724"
    assert row["deleted"] is False
    assert out["data_unit_bytes"] == 4096


def test_the_data_unit_is_measured_from_the_file_system_start(image, wired):
    """TSK addresses inside the file system while a search reports inside the image."""

    tsk = wired(_Tsk(ifind={"1": "5"}, ffind={"5": "/a"}))
    oa.attribute_offsets(image, [63 * 512 + 4096], partition_offset_sectors=63,
                         block_size=4096)
    ifind = next(argv for argv in tsk.calls if argv[0].endswith("ifind"))
    assert ifind[ifind.index("-d") + 1] == "1"
    assert ifind[ifind.index("-o") + 1] == "63"


def test_a_deleted_name_is_reported_as_deleted_rather_than_stripped(image, wired):
    """A name that pointed at the inode is not the same claim as a file holding it."""

    wired(_Tsk(ifind={"2": "99"}, ffind={"99": "* /Recycled/old.doc"}))
    row = _row(oa.attribute_offsets(image, [8192], block_size=4096), "8192")
    assert row["deleted"] is True
    assert row["path"] == "/Recycled/old.doc"


def test_the_block_size_is_read_from_the_file_system_when_not_supplied(image, wired):
    tsk = wired(_Tsk(ifind={"176": "8724"}, ffind={"8724": "/x"}))
    out = oa.attribute_offsets(image, [721_408])
    assert out["data_unit_bytes"] == 4096
    assert tsk.count("fsstat") == 1


# --- a hit recovered from a compressed stream -------------------------------- #


def test_a_composite_offset_resolves_on_the_stream_and_says_so(image, wired):
    """The path names the file carrying the stream, not one holding the hit as stored."""

    wired(_Tsk(ifind={"146": "4110"}, ffind={"4110": "/cache/page[1].htm"}))
    out = oa.attribute_offsets(image, ["598016-GZIP-1450"], block_size=4096)
    row = _row(out, "598016-GZIP-1450")
    assert row["path"] == "/cache/page[1].htm"
    assert row["in_compressed_stream"] is True
    assert row["stream_position"] == "GZIP-1450"
    assert "decompressed" in row["stream_note"]


def test_a_plain_offset_is_not_marked_as_compressed(image, wired):
    wired(_Tsk(ifind={"0": "7"}, ffind={"7": "/a"}))
    row = _row(oa.attribute_offsets(image, [0], block_size=4096), "0")
    assert row["in_compressed_stream"] is False
    assert "stream_position" not in row


# --- refusing to attribute --------------------------------------------------- #


def test_unallocated_bytes_are_reported_as_unallocated_never_as_a_nearby_path(
    image, wired
):
    wired(_Tsk(ifind={}, ffind={}))
    row = _row(oa.attribute_offsets(image, [4096], block_size=4096), "4096")
    assert row["attribution"] == "unallocated"
    assert "path" not in row
    assert "unallocated" in row["note"]


def test_file_system_structures_are_distinguished_from_file_content(image, wired):
    wired(_Tsk(ifind={"1": "Meta data"}))
    row = _row(oa.attribute_offsets(image, [4096], block_size=4096), "4096")
    assert row["attribution"] == "filesystem_metadata"
    assert "path" not in row


def test_an_inode_no_directory_entry_names_is_reported_as_orphaned(image, wired):
    wired(_Tsk(ifind={"1": "77"}, ffind={"77": "File name not found for inode"}))
    row = _row(oa.attribute_offsets(image, [4096], block_size=4096), "4096")
    assert row["attribution"] == "unnamed"
    assert row["inode"] == "77"
    assert "path" not in row


def test_an_unrecognised_answer_is_quoted_rather_than_interpreted(image, wired):
    wired(_Tsk(ifind={"1": "something the tool has not said before"}))
    row = _row(oa.attribute_offsets(image, [4096], block_size=4096), "4096")
    assert row["attribution"] == "unattributed"
    assert "something the tool has not said before" in row["note"]


def test_an_offset_before_the_file_system_is_not_attributed_to_it(image, wired):
    wired(_Tsk())
    out = oa.attribute_offsets(image, [1024], partition_offset_sectors=63, block_size=4096)
    row = _row(out, "1024")
    assert row["attribution"] == "outside_filesystem"
    assert "path" not in row


def test_an_unparsable_offset_fails_only_its_own_row(image, wired):
    wired(_Tsk(ifind={"0": "7"}, ffind={"7": "/a"}))
    out = oa.attribute_offsets(image, ["not-an-offset", 0], block_size=4096)
    assert _row(out, "not-an-offset")["attribution"] == "invalid_offset"
    assert _row(out, "0")["attribution"] == "path"


# --- the cost of a batch ----------------------------------------------------- #


def test_offsets_sharing_a_data_unit_are_looked_up_once(image, wired):
    """Hundreds of hits land in a handful of files; one lookup pair each is waste."""

    tsk = wired(_Tsk(ifind={"0": "7"}, ffind={"7": "/a"}))
    out = oa.attribute_offsets(image, [0, 100, 4095, 1, 2], block_size=4096)
    assert out["data_unit_lookups"] == 1
    assert tsk.count("ifind") == 1
    assert all(row["path"] == "/a" for row in out["rows"])


def test_a_repeated_offset_is_counted_once(image, wired):
    wired(_Tsk(ifind={"0": "7"}, ffind={"7": "/a"}))
    out = oa.attribute_offsets(image, [0, 0, 0], block_size=4096)
    assert out["requested"] == 3
    assert out["distinct_offsets"] == 1


def test_a_batch_beyond_the_cap_truncates_and_says_how_many_it_left(image, wired):
    wired(_Tsk())
    offsets = [index * 4096 for index in range(oa._OFFSET_CAP + 20)]
    out = oa.attribute_offsets(image, offsets, block_size=4096)
    assert out["truncated"] is True
    assert len(out["rows"]) == oa._OFFSET_CAP
    assert str(len(offsets)) in out["note"]


def test_a_batch_within_the_cap_is_not_marked_truncated(image, wired):
    wired(_Tsk())
    out = oa.attribute_offsets(image, [0, 4096], block_size=4096)
    assert out["truncated"] is False
    assert "note" not in out


# --- structured refusals, never exceptions ----------------------------------- #


def test_missing_binaries_are_reported_rather_than_raised(image, monkeypatch):
    monkeypatch.setattr(oa, "resolve_tool", lambda names, env: None)
    out = oa.attribute_offsets(image, [0], block_size=4096)
    assert "error" in out and "ifind" in out["error"]


def test_a_missing_image_is_reported_rather_than_raised(tmp_path, wired):
    wired(_Tsk())
    assert "error" in oa.attribute_offsets(str(tmp_path / "absent.dd"), [0], block_size=4096)


@pytest.mark.parametrize("offsets", [[], "0", None])
def test_an_offset_list_that_is_not_one_is_refused(image, wired, offsets):
    wired(_Tsk())
    assert "error" in oa.attribute_offsets(image, offsets, block_size=4096)


@pytest.mark.parametrize("sectors", [-1, 1.5, True])
def test_a_partition_offset_that_is_not_a_sector_count_is_refused(image, wired, sectors):
    wired(_Tsk())
    assert "error" in oa.attribute_offsets(image, [0], partition_offset_sectors=sectors,
                                           block_size=4096)


@pytest.mark.parametrize("size", [0, -4096, 1.5, True])
def test_a_block_size_that_is_not_a_byte_count_is_refused(image, wired, size):
    wired(_Tsk())
    assert "error" in oa.attribute_offsets(image, [0], block_size=size)


def test_a_binary_that_fails_becomes_a_record_not_an_exception(image, monkeypatch):
    monkeypatch.setattr(oa, "resolve_tool", lambda names, env: f"/usr/bin/{names[0]}")

    def explode(argv, **kwargs):  # noqa: ANN001, ANN003
        raise OSError("the medium stopped responding")

    monkeypatch.setattr(oa, "run_external", explode)
    out = oa.attribute_offsets(image, [0], block_size=4096)
    assert _row(out, "0")["attribution"] == "error"


def test_the_result_states_what_an_attribution_does_and_does_not_claim(image, wired):
    wired(_Tsk(ifind={"0": "7"}, ffind={"7": "/a"}))
    out = oa.attribute_offsets(image, [0], block_size=4096)
    assert "unallocated" in out["scope"]
