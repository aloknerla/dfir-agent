"""Tests for signature-based evidence probing."""
from forensic_agent.core import evidence_probe


def _write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def test_detect_ntfs_raw(tmp_path):
    hdr = b"\xeb\x52\x90" + b"NTFS    " + b"\x00" * (512 - 11)
    info = evidence_probe.detect_evidence(_write(tmp_path, "d.raw", hdr))
    assert info["container"] == "raw/dd"
    assert info["filesystem"] == "NTFS"
    assert "NTFS" in evidence_probe.summarize(info)


def test_detect_fat32_raw(tmp_path):
    b = bytearray(512)
    b[82:87] = b"FAT32"
    info = evidence_probe.detect_evidence(_write(tmp_path, "d.img", bytes(b)))
    assert info["filesystem"] == "FAT"


def test_detect_ext(tmp_path):
    b = bytearray(1082)
    b[1080:1082] = b"\x53\xef"
    info = evidence_probe.detect_evidence(_write(tmp_path, "linux.dd", bytes(b)))
    assert info["filesystem"] == "ext2/3/4"


def test_detect_ewf_container(tmp_path):
    hdr = b"EVF\x09\x0d\x0a\xff\x00" + b"\x00" * 100
    info = evidence_probe.detect_evidence(_write(tmp_path, "case.E01", hdr))
    assert info["container"] == "EWF/E01"
    assert evidence_probe.summarize(info) == (
        "Evidence source case.E01: container EWF/E01, "
        "file system determined after opening, size 0 MB."
    )


def test_detect_unknown_and_missing(tmp_path):
    info = evidence_probe.detect_evidence(_write(tmp_path, "x.bin", b"\x00" * 512))
    assert info["container"] == "raw/dd" and info["filesystem"] == "unknown"
    miss = evidence_probe.detect_evidence(str(tmp_path / "nope.raw"))
    assert any("not found" in n for n in miss["notes"])


def test_detect_filesystem_inside_mbr_partition(tmp_path):
    image = bytearray(8192)
    image[510:512] = b"\x55\xaa"
    entry = 446
    image[entry + 4] = 0x07
    image[entry + 8:entry + 12] = (8).to_bytes(4, "little")
    image[entry + 12:entry + 16] = (4).to_bytes(4, "little")
    image[4096 + 3:4096 + 11] = b"NTFS    "

    info = evidence_probe.detect_evidence(_write(tmp_path, "partitioned.raw", bytes(image)))

    assert info["partition_scheme"] == "MBR"
    assert info["filesystem"] == "NTFS"
    assert info["partitions"] == [{
        "index": 1,
        "offset_bytes": 4096,
        "length_bytes": 2048,
        "filesystem": "NTFS",
        "scheme": "MBR",
        "type": "0x07",
    }]
    assert "NTFS@4096" in evidence_probe.summarize(info)


def test_detect_filesystem_inside_gpt_partition(tmp_path):
    image = bytearray(8192)
    image[510:512] = b"\x55\xaa"
    image[450] = 0xEE
    image[454:458] = (1).to_bytes(4, "little")
    image[458:462] = (15).to_bytes(4, "little")

    image[512:520] = b"EFI PART"
    image[512 + 72:512 + 80] = (2).to_bytes(8, "little")
    image[512 + 80:512 + 84] = (1).to_bytes(4, "little")
    image[512 + 84:512 + 88] = (128).to_bytes(4, "little")
    image[1024:1040] = b"\x01" * 16
    image[1024 + 32:1024 + 40] = (8).to_bytes(8, "little")
    image[1024 + 40:1024 + 48] = (11).to_bytes(8, "little")
    image[4096 + 3:4096 + 11] = b"NTFS    "

    info = evidence_probe.detect_evidence(_write(tmp_path, "gpt.raw", bytes(image)))

    assert info["partition_scheme"] == "GPT"
    assert info["filesystem"] == "NTFS"
    assert info["partitions"][0]["offset_bytes"] == 4096
    assert info["partitions"][0]["filesystem"] == "NTFS"


def test_boot_signature_with_out_of_bounds_entry_is_not_a_partition_table(tmp_path):
    image = bytearray(1024)
    image[510:512] = b"\x55\xaa"
    image[450] = 0x07
    image[454:458] = (9999).to_bytes(4, "little")
    image[458:462] = (10).to_bytes(4, "little")

    info = evidence_probe.detect_evidence(_write(tmp_path, "boot-sector.raw", bytes(image)))

    assert info["partition_scheme"] is None
    assert info["partitions"] == []
