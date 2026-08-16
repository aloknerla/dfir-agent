"""Greska citanja nije odsutnost, i alat to mora reci.

Kada listanje direktorija prijavi „path not found or unreadable“ a stvarni
uzrok je greska citanja (npr. ``pyfsntfs_file_object_read_buffer: unable to
read``), direktorij moze postojati i sadrzavati podatke. Razvrstavanje neuspjeha
zivi na jednom mjestu i odlucuje se iz iznimke, ne iz recenice napisane na
mjestu hvatanja.
"""

from __future__ import annotations

import pytest

from forensic_agent.core.tool_failure import (
    FailureKind,
    classify_failure,
    establishes_absence,
    tool_failure,
)


def test_the_measured_read_failure_is_not_reported_as_an_absence() -> None:
    """Točan slučaj koji je odnio odgovor."""

    error = OSError(
        "pyfsntfs_volume_get_file_entry_by_path: unable to retrieve file entry. "
        "pyfsntfs_file_object_read_buffer: unable to read from file object"
    )

    kind = classify_failure(error)

    assert kind is FailureKind.UNREADABLE
    assert establishes_absence(kind) is False


def test_only_a_genuine_absence_establishes_absence() -> None:
    """Jedina vrsta koja smije značiti odsutnost je ona koja to i kaže."""

    assert establishes_absence(FailureKind.NOT_FOUND) is True
    for kind in (
        FailureKind.UNREADABLE,
        FailureKind.UNSUPPORTED,
        FailureKind.REFUSED,
        FailureKind.INVALID_ARGUMENTS,
        FailureKind.FAILED,
    ):
        assert establishes_absence(kind) is False, kind


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (FileNotFoundError("/x/y"), FailureKind.NOT_FOUND),
        (OSError("No such file or directory: /x"), FailureKind.NOT_FOUND),
        (OSError("unable to read from file object"), FailureKind.UNREADABLE),
        (OSError("CRC mismatch in segment 2"), FailureKind.UNREADABLE),
        (TimeoutError("read timed out"), FailureKind.UNREADABLE),
        (RuntimeError("unsupported container format"), FailureKind.UNSUPPORTED),
        (NotImplementedError("no handler"), FailureKind.UNSUPPORTED),
        (PermissionError("permission denied"), FailureKind.REFUSED),
        (ValueError("validation error for arguments"), FailureKind.INVALID_ARGUMENTS),
        (RuntimeError("something else entirely"), FailureKind.FAILED),
    ],
)
def test_each_kind_is_recognised_from_the_exception(error, expected) -> None:
    assert classify_failure(error) is expected


def test_an_unclassified_failure_never_defaults_to_absence() -> None:
    """Nerazvrstano ne smije značiti „nema ga"."""

    kind = classify_failure(RuntimeError("backend exploded"))

    assert kind is FailureKind.FAILED
    assert establishes_absence(kind) is False


def test_a_backend_diagnostic_is_carried_rather_than_replaced() -> None:
    """Ono što je backend rekao jedino i objašnjava; ne smije se izgubiti."""

    error = OSError("pyfsntfs_file_object_read_buffer: unable to read from file object")

    record = tool_failure(error, subject="/Users/analyst", backend="dfvfs")

    assert record["kind"] == "unreadable"
    assert record["establishes_absence"] is False
    assert record["subject"] == "/Users/analyst"
    assert record["backend"] == "dfvfs"
    assert record["exception_type"] == "OSError"
    assert "pyfsntfs_file_object_read_buffer" in str(record["detail"])


def test_the_message_states_a_read_failure_without_claiming_absence() -> None:
    """Rečenica mora reći što se dogodilo i što time NIJE utvrđeno."""

    record = tool_failure(
        OSError("unable to read from file object"), subject="/x", backend="dfvfs"
    )
    message = str(record["message"]).lower()

    assert "read" in message
    assert "not an absence" in message or "establishes nothing" in message
    assert "not found" not in message


def test_a_real_absence_says_so_plainly() -> None:
    """Stvarna odsutnost se smije izreći kao odsutnost."""

    record = tool_failure(FileNotFoundError("/x/y"), subject="/x/y")

    assert record["kind"] == "not_found"
    assert record["establishes_absence"] is True
    assert "not present" in str(record["message"])


def test_a_type_that_means_absence_wins_over_a_generic_not_found_phrase() -> None:
    """Klasa koja jednoznačno znači odsutnost nadjačava dvosmislen tekst."""

    assert classify_failure(FileNotFoundError("file not found")) is FailureKind.NOT_FOUND
    # ...while a read failure carrying the same phrase stays a read failure.
    assert (
        classify_failure(OSError("unable to read; entry not found in cache"))
        is FailureKind.UNREADABLE
    )


def test_the_result_message_adds_the_classification_without_replacing_the_detail() -> None:
    """Backendov tekst je katkad jedina uputa i ne smije se izgubiti.

    Konfiguracijski neuspjeh imenuje varijablu ili direktorij koji treba
    popraviti. Zamijeniti to kategorijom znači oduzeti jedini djelotvoran dio
    poruke, pa se klasifikacija dodaje onome što je backend rekao.
    """

    from forensic_agent.core.tool_failure import tool_failure_result

    result = tool_failure_result(
        RuntimeError("DFA_VOL_SYMBOL_DIRS directory is not available"),
        subject="/evidence/memory.raw",
        backend="volatility3",
    )

    assert "DFA_VOL_SYMBOL_DIRS" in str(result["error"])
    assert "volatility3" in str(result["error"])
    assert result["failure"]["kind"] == "failed"


def test_a_read_failure_result_still_says_it_is_not_an_absence() -> None:
    """Dodavanje detalja ne smije razvodniti glavnu tvrdnju."""

    from forensic_agent.core.tool_failure import tool_failure_result

    result = tool_failure_result(
        OSError("pyfsntfs_file_object_read_buffer: unable to read"),
        subject="/x",
        backend="dfvfs",
    )

    error = str(result["error"]).lower()
    assert "not an absence" in error or "establishes nothing" in error
    assert "pyfsntfs_file_object_read_buffer" in error


def test_the_detail_is_bounded_so_a_backend_cannot_flood_the_record() -> None:
    """Dijagnostika se prenosi, ali omeđena."""

    record = tool_failure(OSError("x" * 5000), subject="/x", detail_limit=120)

    assert len(str(record["detail"])) == 120
