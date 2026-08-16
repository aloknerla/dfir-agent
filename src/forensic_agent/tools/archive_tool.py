"""Read-only archive forensics with ephemeral, path-free extraction results.

ZIP files are handled with the standard library and 7-Zip archives with
``py7zr`` when it is installed. Other formats fall back to the 7-Zip command
line program. Extraction never returns a host path: callers receive member
metadata, detected payload types and bounded printable strings.

Because the reader is chosen at run time and falls back, every result states
which of the three actually ran, under ``engine``. That is the fact a result
emitter records: the declaration alone would name a component that may never
have been reached, and the archive ``format`` is a different question from the
reader that opened it.

The model-facing wrapper supplies a tracked controlled-scratch workspace.
Direct callers that do not supply one use ``TemporaryDirectory`` and receive a
result only after that directory has been removed successfully.
"""

from __future__ import annotations

import os
import re
import stat
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from forensic_agent.core.environ import seven_zip_path
from forensic_agent.core.storage_containment import (
    EvidenceWriteScope,
    StorageContainmentError,
    acquire_evidence_write_dir,
)
from forensic_agent.core.toolkit import run_external
from forensic_agent.tools.ocr_tool import ocr_image
from forensic_agent.tools.payload_identification import (
    extract_embedded_strings,
    identify_payload,
)

try:
    import py7zr

    _HAVE_PY7ZR = True
except Exception:
    _HAVE_PY7ZR = False

_7Z_MAGIC = b"7z\xbc\xaf\x27\x1c"
_ZIP_MAGIC = b"PK\x03\x04"
_WINDOWS_REPARSE_POINT = 0x0400

#: What py7zr's own exception classes mean, in the terms a reader acts on. The
#: distinction cannot be recovered from the message: a WRONG password surfaces as
#: the decompressor's "Corrupt input data", so matching that text calls a locked
#: archive a damaged one and a damaged one locked. Keys are class names so an
#: absent py7zr costs nothing and a future subclass is not silently reclassified.
_PY7ZR_FAILURES: dict[str, str] = {
    "PasswordRequired": "the archive is encrypted and no password was supplied",
    "UnsupportedCompressionMethodError": (
        "this reader does not implement the codec the archive was written with"
    ),
    "DecompressionBombError": "the archive expands past the limits this reader enforces",
    "CrcError": (
        "a member failed its recorded CRC, so the archive's stored bytes are damaged"
    ),
    "Bad7zFile": "the archive header is not readable, so the archive itself is damaged",
}
#: Raised by the codec rather than by py7zr, and reachable only with a password
#: set: 7z verifies no key before decrypting, so a wrong one decodes to noise and
#: the decompressor reports that noise as corrupt input. A wrong password is by
#: far the common cause, so the message leads with it: the reader should re-check
#: and re-derive the password before concluding the stored bytes are damaged,
#: because "corrupt input" here is exactly what a wrong key looks like.
_PY7ZR_DECODE_FAILURE = (
    "the password most likely did not decrypt the archive — a wrong password "
    "decrypts to noise that the decompressor reports as corrupt input; re-check "
    "and re-derive the password and retry before concluding the compressed data "
    "is damaged"
)

# Extraction is an inspection aid, not a general unpacking service. These
# fixed limits bound both declared archive expansion and the actual tree that
# is observed before any content is read back into Python/model context.
_MAX_ARCHIVE_MEMBERS = 4096
_MAX_ARCHIVE_MEMBER_BYTES = 128 * 1024 * 1024
_MAX_ARCHIVE_TOTAL_BYTES = 512 * 1024 * 1024
_MAX_CONTENT_SAMPLE_BYTES = 1024 * 1024


class ArchiveSafetyError(RuntimeError):
    """An archive member or extracted filesystem object was unsafe."""


def _magic(path: str, n: int = 8) -> bytes:
    try:
        with open(path, "rb") as source:
            return source.read(n)
    except OSError:
        return b""


def _safe_member_name(name: object) -> bool:
    """Reject absolute and traversal member names on both POSIX and Windows."""

    if not isinstance(name, str) or not name or "\x00" in name:
        return False
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        return False
    parts = PurePosixPath(normalized).parts
    return bool(parts) and all(part not in {"", ".", ".."} for part in parts)


def _assert_declared_limits(
    members: list[tuple[object, object, bool]],
) -> None:
    """Reject archives whose declared expansion cannot fit fixed limits."""

    if len(members) > _MAX_ARCHIVE_MEMBERS:
        raise ArchiveSafetyError("archive exceeds the member-count limit")
    total = 0
    for name, raw_size, is_directory in members:
        if not _safe_member_name(name):
            raise ArchiveSafetyError("archive contains an unsafe member name")
        if is_directory and raw_size is None:
            size = 0
        elif (
            not isinstance(raw_size, int)
            or isinstance(raw_size, bool)
            or raw_size < 0
        ):
            raise ArchiveSafetyError("archive member has no trustworthy declared size")
        else:
            size = raw_size
        if size > _MAX_ARCHIVE_MEMBER_BYTES:
            raise ArchiveSafetyError("archive member exceeds the extraction-size limit")
        total += size
        if total > _MAX_ARCHIVE_TOTAL_BYTES:
            raise ArchiveSafetyError("archive exceeds the total extraction-size limit")


def _is_link_or_reparse(observed: os.stat_result) -> bool:
    attributes = int(getattr(observed, "st_file_attributes", 0) or 0)
    return stat.S_ISLNK(observed.st_mode) or bool(attributes & _WINDOWS_REPARSE_POINT)


def _regular_files(root: Path) -> list[tuple[Path, int]]:
    """Walk and size an extracted tree without following special objects."""

    files: list[tuple[Path, int]] = []
    pending = [root]
    observed_entries = 0
    observed_bytes = 0
    while pending:
        directory = pending.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as exc:
            raise ArchiveSafetyError("extracted archive tree cannot be inspected") from exc
        for entry in entries:
            observed_entries += 1
            if observed_entries > _MAX_ARCHIVE_MEMBERS:
                raise ArchiveSafetyError("extracted archive exceeds the member-count limit")
            path = Path(entry.path)
            try:
                observed = os.lstat(path)
            except OSError as exc:
                raise ArchiveSafetyError("extracted archive entry cannot be inspected") from exc
            if _is_link_or_reparse(observed):
                raise ArchiveSafetyError("archive extraction produced a link or reparse point")
            if stat.S_ISDIR(observed.st_mode):
                pending.append(path)
            elif stat.S_ISREG(observed.st_mode):
                size = int(observed.st_size)
                if size < 0 or size > _MAX_ARCHIVE_MEMBER_BYTES:
                    raise ArchiveSafetyError(
                        "extracted archive member exceeds the extraction-size limit"
                    )
                observed_bytes += size
                if observed_bytes > _MAX_ARCHIVE_TOTAL_BYTES:
                    raise ArchiveSafetyError(
                        "extracted archive exceeds the total extraction-size limit"
                    )
                files.append((path, size))
            else:
                raise ArchiveSafetyError(
                    "archive extraction produced a non-regular filesystem object"
                )
    return sorted(files, key=lambda item: item[0].relative_to(root).as_posix())


#: How many image members one extraction reads with OCR. OCR runs several
#: preprocessing passes per image, so an archive full of images could otherwise
#: spend the whole run in Tesseract; members past this cap are still listed and
#: typed, only their rendered text is left unread.
_MAX_OCR_MEMBERS = 8


def _member_ocr_text(path: Path) -> str | None:
    """Read text rendered inside an image member, inside the extraction boundary.

    The member is already on disk here, so OCR reads it in place and only the
    recognised text travels back — never the host path. A flag rasterised into an
    archived image is therefore reachable without the extracted file ever
    becoming an addressable path, which is the property the rest of this module
    exists to keep. A host without Tesseract, or an image with no text, yields
    ``None``, and a failed reading never fails the surrounding extraction.
    """

    try:
        result = ocr_image(str(path))
    except Exception:
        return None
    text = result.get("text") if isinstance(result, dict) else None
    if isinstance(text, str) and text.strip():
        return text[:4000]
    return None


def _describe(outdir: Path, limit: int) -> tuple[list[dict[str, Any]], int]:
    """Return useful member evidence without disclosing extraction paths."""

    paths = _regular_files(outdir)
    files: list[dict[str, Any]] = []
    ocr_budget = _MAX_OCR_MEMBERS
    for path, size in paths[:limit]:
        try:
            with path.open("rb") as source:
                raw = source.read(_MAX_CONTENT_SAMPLE_BYTES)
        except OSError:
            continue
        identification = identify_payload(raw)
        row: dict[str, Any] = {
            "name": path.relative_to(outdir).as_posix(),
            "size": size,
            "sampled_bytes": len(raw),
            "content_sample_truncated": size > len(raw),
            **identification.fields(),
            "strings": extract_embedded_strings(raw)[:15],
        }
        mime = identification.mime_type
        if isinstance(mime, str) and mime.startswith("image/") and ocr_budget > 0:
            ocr_budget -= 1
            text = _member_ocr_text(path)
            if text is not None:
                row["ocr_text"] = text
        files.append(row)
    return files, len(paths)


#: Names of the three readers this tool can reach, as the result states them.
#: They are the ids the backend version registry inventories, so a result can be
#: attested against the component that produced it without a translation table
#: in between.
ENGINE_PY7ZR = "py7zr"
ENGINE_ZIPFILE = "cpython_zipfile"
ENGINE_SEVEN_ZIP = "seven_zip"


def _extract_result(
    *,
    engine: str,
    archive_format: str,
    output_directory: Path,
    limit: int,
) -> dict[str, Any]:
    files, count = _describe(output_directory, limit)
    return {
        "action": "extract",
        "ok": True,
        # ``format`` is what the archive IS; ``engine`` is what READ it.  They
        # are not the same fact — a 7z archive is read by py7zr when it is
        # installed and by the 7-Zip program when it is not — so a consumer that
        # inferred the reader from the format would attest a component that
        # never ran.
        "engine": engine,
        "format": archive_format,
        "extracted_file_count": count,
        "returned_file_count": len(files),
        "truncated": count > len(files),
        "files": files,
    }


def _validate_output_directory(path: Path) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ArchiveSafetyError("archive output directory must be an absolute Path")
    try:
        observed = os.lstat(path)
        entries = list(os.scandir(path))
    except OSError as exc:
        raise ArchiveSafetyError("archive output directory cannot be inspected") from exc
    if (
        not stat.S_ISDIR(observed.st_mode)
        or _is_link_or_reparse(observed)
        or entries
    ):
        raise ArchiveSafetyError("archive output directory must be an empty regular directory")
    return path


def _redact_directory(value: object, directory: Path) -> object:
    """Remove a private extraction path from nested error/result text."""

    private_forms = {
        str(directory),
        os.path.normpath(str(directory)),
        str(directory).replace("\\", "/"),
    }
    if isinstance(value, str):
        redacted = value
        for private in private_forms:
            if private:
                redacted = redacted.replace(private, "<ephemeral-output>")
        return redacted
    if isinstance(value, list):
        return [_redact_directory(item, directory) for item in value]
    if isinstance(value, dict):
        return {
            key: _redact_directory(item, directory)
            for key, item in value.items()
            if key not in {"path", "extracted_to"}
        }
    return value


def _py7zr_failure(error: Exception, *, password: str | None) -> dict[str, Any]:
    """Say which of "locked", "damaged" and "unsupported" one py7zr failure was."""

    name = type(error).__name__
    reason = _PY7ZR_FAILURES.get(name)
    if reason is None and password:
        reason = _PY7ZR_DECODE_FAILURE
    detail = str(error)[:160]
    return {
        "error": f"{reason} ({name}: {detail})" if reason else detail,
        "failure_class": name,
        **({"password_supplied": True} if password else {}),
    }


def _query_with_output(
    archive_path: str,
    action: str,
    password: str | None,
    limit: int,
    output_directory: Path | None,
) -> dict[str, Any]:
    """Perform one query; extraction requires an already managed directory."""

    magic = _magic(archive_path)
    is7z = magic.startswith(_7Z_MAGIC) or archive_path.lower().endswith(".7z")
    iszip = magic.startswith(_ZIP_MAGIC) or archive_path.lower().endswith(".zip")

    if is7z and _HAVE_PY7ZR:
        try:
            with py7zr.SevenZipFile(archive_path, mode="r", password=password) as archive:
                info = archive.list()
                if action == "list":
                    members = []
                    for member in info[:limit]:
                        row = {
                            "name": getattr(member, "filename", None),
                            "size": getattr(member, "uncompressed", None),
                        }
                        crc = getattr(member, "crc32", None)
                        # An empty member's recorded CRC is 0, so testing the value
                        # for truth drops a real checksum and leaves it looking like
                        # a member the archive recorded no checksum for at all.
                        if isinstance(crc, int) and not isinstance(crc, bool):
                            row["crc32"] = format(crc, "08x")
                        members.append(row)
                    return {
                        "action": "list",
                        "engine": ENGINE_PY7ZR,
                        "format": "7z",
                        "count": len(info),
                        "members": members,
                    }
                assert output_directory is not None
                declared_members = []
                for member in info:
                    directory_marker = getattr(member, "is_directory", False)
                    is_directory = (
                        bool(directory_marker())
                        if callable(directory_marker)
                        else bool(directory_marker)
                    )
                    declared_members.append(
                        (
                            getattr(member, "filename", None),
                            getattr(member, "uncompressed", None),
                            is_directory,
                        )
                    )
                _assert_declared_limits(declared_members)
                archive.extractall(path=output_directory)
            return _extract_result(
                engine=ENGINE_PY7ZR,
                archive_format="7z",
                output_directory=output_directory,
                limit=limit,
            )
        except Exception as exc:
            # The reader that failed is still the reader that ran, and a failed
            # call has to be attributable to it.
            return {
                "action": action,
                "engine": ENGINE_PY7ZR,
                "ok": False,
                **_py7zr_failure(exc, password=password),
            }

    if iszip:
        try:
            with zipfile.ZipFile(archive_path) as archive:
                info = archive.infolist()
                if action == "list":
                    members = [
                        {
                            "name": member.filename,
                            "crc32": format(member.CRC, "08x"),
                            "size": member.file_size,
                            "compressed": member.compress_size,
                            "modified": "%04d-%02d-%02d %02d:%02d:%02d"
                            % member.date_time,
                        }
                        for member in info[:limit]
                    ]
                    return {
                        "action": "list",
                        "engine": ENGINE_ZIPFILE,
                        "format": "zip",
                        "count": len(info),
                        "members": members,
                    }
                assert output_directory is not None
                _assert_declared_limits(
                    [
                        (member.filename, member.file_size, member.is_dir())
                        for member in info
                    ]
                )
                if any(stat.S_ISLNK(member.external_attr >> 16) for member in info):
                    raise ArchiveSafetyError("archive contains a symbolic-link member")
                archive.extractall(
                    path=output_directory,
                    pwd=password.encode() if password else None,
                )
            return _extract_result(
                engine=ENGINE_ZIPFILE,
                archive_format="zip",
                output_directory=output_directory,
                limit=limit,
            )
        except Exception as exc:
            return {
                "action": action,
                "engine": ENGINE_ZIPFILE,
                "ok": False,
                "error": str(exc)[:160],
            }

    executable = seven_zip_path()
    if not executable:
        return {
            "error": "Unsupported archive and 7-Zip '7z' not found. Install 7-Zip "
            "(or py7zr for .7z). Run `dfir-agent --doctor`."
        }
    password_flag = "-p" + (password or "")
    try:
        listed = run_external(
            [executable, "l", "-slt", password_flag, archive_path],
            timeout=120,
            check=False,
        )
        if listed.returncode != 0:
            return {
                "action": action,
                "engine": ENGINE_SEVEN_ZIP,
                "ok": False,
                "error": (listed.stderr or listed.stdout or "")[-200:],
            }
        names = [
            name
            for name in re.findall(r"^Path = (.+)$", listed.stdout or "", re.MULTILINE)
            if name != archive_path
        ]
        if action == "list":
            return {
                "action": "list",
                "engine": ENGINE_SEVEN_ZIP,
                "format": "cli",
                "members": names[:limit],
            }
        return {
            "action": "extract",
            "engine": ENGINE_SEVEN_ZIP,
            "ok": False,
            "error": (
                "fallback 7-Zip extraction is disabled because trustworthy "
                "declared expansion limits are unavailable"
            ),
        }
    except Exception as exc:
        return {
            "action": action,
            "engine": ENGINE_SEVEN_ZIP,
            "ok": False,
            "error": f"7z failed: {str(exc)[:150]}",
        }


def archive_query(
    archive_path: str,
    action: str = "list",
    password: str | None = None,
    limit: int = 60,
    *,
    output_directory: Path | None = None,
) -> dict[str, Any]:
    """List or inspect extracted archive members without returning host paths.

    ``action="list"`` preserves the member inventory behavior. For
    ``action="extract"``, the returned ``files`` rows contain relative member
    names, sizes, detected types and bounded strings. The source is never
    modified and extracted files are not retained by the direct API.

    A trusted wrapper may supply an exact, empty ``output_directory`` managed
    by :class:`ControlledScratchSession`. If it is omitted, a
    :class:`TemporaryDirectory` is created and removed before this function
    returns. Cleanup failures propagate rather than being reported as success.
    """

    if not archive_path or not os.path.exists(archive_path):
        return {"error": "archive not found at the given path."}
    if type(action) is not str or action not in {"list", "extract"}:
        return {
            "action": action,
            "ok": False,
            "error": "action must be exactly 'list' or 'extract'",
        }
    if type(limit) is not int or isinstance(limit, bool) or limit < 1:
        return {"action": action, "ok": False, "error": "limit must be a positive integer"}

    absolute_archive_path = os.path.abspath(archive_path)
    if action == "list":
        return _query_with_output(
            absolute_archive_path,
            action,
            password,
            limit,
            None,
        )

    if output_directory is not None:
        managed_output = _validate_output_directory(output_directory)
        result = _query_with_output(
            absolute_archive_path,
            action,
            password,
            limit,
            managed_output,
        )
        return _redact_directory(result, managed_output)  # type: ignore[return-value]

    # No managed workspace was supplied, so the members are unpacked into an
    # ephemeral TemporaryDirectory that is removed before this returns. Unpacked
    # archive members are content reconstructed out of the evidence — on a real
    # case, executables — so the temporary base is resolved through the
    # write-scope facade before anything is written, and a host-shared base (a
    # bind-mounted TEMP inside a container) is refused rather than written into.
    # The recorded weak scope is the correct one here: this base is not retained
    # bulk payload but a self-cleaning working tree the runner's rebind already
    # lands inside contained storage, and the model-facing wrapper never reaches
    # this branch because it supplies an ``output_directory``.
    temporary_base = tempfile.gettempdir()
    try:
        acquire_evidence_write_dir(
            temporary_base,
            subject="archive members unpacked out of the evidence",
            scope=EvidenceWriteScope.NOT_HOST_SHARED,
        )
    except StorageContainmentError as exc:
        return {"action": action, "ok": False, "error": str(exc)[:300]}

    with tempfile.TemporaryDirectory(
        prefix="forensic_agent_archive_", dir=temporary_base
    ) as temporary:
        ephemeral_output = Path(temporary)
        result = _query_with_output(
            absolute_archive_path,
            action,
            password,
            limit,
            ephemeral_output,
        )
        path_free_result = _redact_directory(result, ephemeral_output)
    assert isinstance(path_free_result, dict)
    path_free_result["cleanup_verified"] = True
    path_free_result["output_retained"] = False
    return path_free_result
