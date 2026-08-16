"""Functions for reading and deterministically processing derived artifacts."""

from __future__ import annotations

import hashlib
import time
from pathlib import Path

from langchain_core.tools import StructuredTool

from forensic_agent.agent.tool_bindings.context import ToolBuildContext

# Imported at module scope so the model-visible schema carries the closed sets
# themselves (enumerated literals), not a bare string the model has to guess at.
from forensic_agent.tools.decode_tool import DecodeOp


def _fresh_member_directory(archive_path: str) -> Path | None:
    """An empty, per-call directory under the payload root for extracted members.

    Per call, because the extractor refuses a destination that is not an empty
    directory and a second extraction of the same archive would otherwise land in
    the first one's output.
    """

    from forensic_agent.core.storage_containment import payload_scratch_root

    root = payload_scratch_root()
    if root is None:
        return None
    stem = hashlib.sha256(str(archive_path).encode("utf-8", errors="replace")).hexdigest()[:16]
    base = Path(str(root)) / "archive-members"
    for attempt in range(1, 1000):
        candidate = base / f"{stem}-{attempt:03d}"
        if not candidate.exists():
            candidate.mkdir(parents=True)
            return candidate
    return None


def _build_artifact_readers(context: ToolBuildContext) -> list[StructuredTool]:
    """Build the corresponding registry segment without changing model schemas."""

    _emit = context.emit
    tools: list[StructuredTool] = []

    from forensic_agent.tools.archive_tool import archive_query as _aq

    def archive_query(
        archive_path: str, action: str = "list", password: str | None = None, limit: int = 60
    ) -> dict:
        """Inspect an archive with 7-Zip or a native parser. action = list | extract;
            optional password for encrypted archives. Extraction returns member metadata,
            detected types, bounded readable-string samples, and extracted_paths: the
            extracted members, which stay readable so another function can be pointed
            at one. Check content_sample_truncated before inferring that text is absent.

            Args:
                archive_path: Path of the archive to inspect, for example a
                    .zip, .7z or .rar recovered from the evidence.
                action: "list" returns member metadata only; "extract" also
                    returns detected types and bounded readable-string samples
                    from the members.
                password: Password for an encrypted archive. Pass it only when it
                    was recovered from evidence, never a guess.
                limit: Members to return, default 60."""
        t0 = time.time()
        if action == "extract":
            if context.controlled_scratch is None:
                r = {
                    "action": "extract",
                    "ok": False,
                    "error": "controlled scratch is required for model-visible extraction",
                    "cleanup_verified": False,
                }
            else:
                # Members are extracted into the declared payload root and
                # survive the call: the text-extraction function takes a path, so
                # a member that exists only during the call is one no later step
                # can look at. The payload root also keeps it nameable, since a
                # path under the run's private scratch is redacted out of the
                # model's copy.
                destination = _fresh_member_directory(archive_path)
                if destination is None:
                    with context.controlled_scratch.tool_runtime_workspace() as workspace:
                        r = dict(
                            _aq(
                                archive_path,
                                action,
                                password,
                                limit,
                                output_directory=workspace.path,
                            )
                        )
                    r["cleanup_verified"] = True
                    r["output_retained"] = False
                else:
                    r = dict(
                        _aq(
                            archive_path,
                            action,
                            password,
                            limit,
                            output_directory=destination,
                        )
                    )
                    members = sorted(
                        str(item) for item in destination.rglob("*") if item.is_file()
                    )
                    r["cleanup_verified"] = False
                    r["output_retained"] = bool(members)
                    if members:
                        r["extracted_paths"] = members[:limit]
        else:
            r = _aq(archive_path, action, password, limit)
        _emit("archive_query", {"action": action, "path": archive_path}, t0)
        return r

    tools.append(StructuredTool.from_function(archive_query))

    from forensic_agent.tools.ocr_tool import ocr_image as _ocr

    def ocr_image(image_path: str, lang: str = "eng") -> dict:
        """Read text rendered inside an image (Tesseract OCR). Use to recover a flag
            or note rasterized into a recovered image (e.g. a PNG).

            Args:
                image_path: Path of the image file to read text from, for example
                    a PNG or JPEG recovered from the evidence.
                lang: Tesseract language code for the text in the image, for
                    example eng, deu or hrv. Default eng."""
        t0 = time.time()
        r = _ocr(image_path, lang)
        _emit("ocr_image", {"path": image_path}, t0)
        return r

    tools.append(StructuredTool.from_function(ocr_image))

    return tools


def _build_artifact_processors(context: ToolBuildContext) -> list[StructuredTool]:
    """Build functions for decoding, summarization, and image reading."""

    _emit = context.emit
    tools: list[StructuredTool] = []

    from forensic_agent.tools.decode_tool import decode as _dec

    def decode(data: str, op: DecodeOp) -> dict:
        """Decode/transform data with a structured op (no scripting). op = base64 |
            base32 | hex | gzip | rot13 | url | utf16le. The transformation is
            performed by the chepy decoder, exactly as named and never detected for
            you, so state which scheme you are applying. Chain results.

            Args:
                data: The payload to transform.
                op: The transformation to apply, named explicitly: base64,
                    base32, hex, gzip, rot13, url or utf16le. There is no
                    automatic detection; if the scheme is unknown, try one and
                    read the result. The keyed operations rc4 and xor were
                    withdrawn: they were this project's own implementations.
            """
        t0 = time.time()
        r = _dec(data, op)
        _emit("decode", {"op": op}, t0)
        return r

    tools.append(StructuredTool.from_function(decode))

    from forensic_agent.tools.hash_tool import hash_file as _hf

    def hash_file(path: str) -> dict:
        """Compute the SHA-256 digest and size of a file on disk (chain-of-custody hashing).

            Args:
                path: Host-side path of the file to hash. For a file inside the
                    evidence image use evidence_file_hash instead."""
        t0 = time.time()
        r = _hf(path)
        _emit("hash_file", {"path": path}, t0)
        return r

    tools.append(StructuredTool.from_function(hash_file))

    from forensic_agent.tools.hashset_tool import hash_lookup as _hl

    def hash_lookup(path: str) -> dict:
        """Classify a file against known-good/known-bad hash sets (NSRL): known_good / known_bad / unknown.

            Args:
                path: Path of the file to classify. The tool hashes it and looks
                    the digest up in the hash sets."""
        t0 = time.time()
        r = _hl(path)
        _emit("hash_lookup", {"path": path}, t0)
        return r

    tools.append(StructuredTool.from_function(hash_lookup))

    return tools
