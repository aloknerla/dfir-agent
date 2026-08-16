"""Functions that process the WHOLE raw image: feature extraction and literal search.

Neither function is restricted to unallocated space: ``bulk_extract`` scans
allocated and unallocated bytes alike, and the literal search reads the same pass.
The docstrings the model reads say so, because a scope stated narrower than the
real one invites a recovered string to be read as proof of deletion.
"""

from __future__ import annotations

import time

from langchain_core.tools import StructuredTool

from forensic_agent.agent.tool_bindings.context import ToolBuildContext
from forensic_agent.core.controlled_scratch import (
    ControlledScratchError,
    ScratchWorkspaceKind,
)
from forensic_agent.core.tool_availability import missing_dependencies_for


def _evidence_digest(context: ToolBuildContext, image_path: str) -> str | None:
    """The content digest that keys a cross-run scan of THIS raw image, if known.

    The disk's digest was attested when the case opened. A memory dump carries
    none of its own, so the digest the case-open scan was published under is
    handed down on the build context; without it a memory image scans per run,
    as before.
    """

    if image_path == getattr(context.disk, "image_path", None):
        return getattr(context.disk, "image_sha", None)
    if image_path == context.memory_path:
        return context.memory_sha256
    return None


def _build_feature_scan_tools(context: ToolBuildContext) -> list[StructuredTool]:
    """Feature extraction over whatever raw evidence image this run holds.

    Split out of the carving segment because it is not a disk capability: the
    scanner reads raw bytes, and what it recovers from unallocated disk space it
    recovers from a process's working memory in the same way. Building it only
    beside a disk stated the opposite, and left a memory-only examination with no
    way to reach a loose string no structured plugin reports.
    """

    disk = context.disk
    _emit = context.emit
    _begin = context.begin
    tools: list[StructuredTool] = []

    if not missing_dependencies_for("bulk_extract"):

        def bulk_extract(
            feature: str | None = None,
            filter: str | None = None,
            offset: int = 0,
            limit: int = 100,
        ) -> dict:
            """Scan the RAW image (incl. UNALLOCATED + slack) with bulk_extractor for
                    features the metadata tools cannot reach. Call with no feature to list what
                    was found, then feature='windirs' for DELETED FILENAMES surviving in
                    unallocated FAT/NTFS directory entries (when recover_deleted finds
                    nothing because the metadata was wiped/quick-formatted), or 'email'/'url'/
                    'domain' for addresses in BOTH UTF-8 and UTF-16 (encoding-robust where an
                    ASCII grep misses). Read-only; the scan is slow, so ask for the feature you
                    need. `feature` is one of the names the scan reports, never a path."""
            from forensic_agent.tools.bulk_extractor_tool import (
                bulk_extract as _be,
            )

            img = getattr(disk, "image_path", None) or context.memory_path
            if not img:
                return {"error": "no raw image path available for bulk_extractor."}
            scratch = context.controlled_scratch
            if scratch is None:
                return {
                    "error": "bulk_extract requires this run's controlled scratch "
                             "directory; no controlled root is bound."
                }
            # The scan output is confined to a workspace the run's controlled
            # scratch session retains: the same workspace is handed to every
            # call, so paging one feature or reading a second one reuses the one
            # scan instead of paying its 1800 s timeout again, and the session
            # removes the whole tree when the run closes.
            try:
                output_root = scratch.retained_workspace(
                    ScratchWorkspaceKind.SCAN_OUTPUTS
                ).path
            except ControlledScratchError as e:
                return {
                    "error": "bulk_extract could not open its controlled scan "
                             f"area: {str(e)[:160]}"
                }
            # A full-image scan runs for a minute or more; announce it first so
            # the feed shows it working rather than an empty pane.
            _begin("bulk_extract", {"feature": feature})
            t0 = time.time()
            # The verified content digest lets a finished scan of the SAME
            # bytes be reused across runs and sessions, including the one the
            # case open prewarmed.
            verified_sha = _evidence_digest(context, img)
            r = _be(
                img,
                feature=feature,
                filter=filter,
                offset=offset,
                limit=limit,
                output_root=output_root,
                evidence_sha256=verified_sha,
            )
            _emit("bulk_extract", {"feature": feature}, t0)
            return r

        tools.append(StructuredTool.from_function(bulk_extract))

    return tools


def _build_image_literal_search_tools(context: ToolBuildContext) -> list[StructuredTool]:
    """The whole-image literal search as its own segment, like the disk one.

    Its own segment for the same reason: the recorded palette is rebuilt from the
    segments above, and a function appended to one of them would join a palette
    it was never part of. Only the facade's index collects this, so the model
    reaches it exclusively as an operation of the raw-image function.
    """

    disk = context.disk
    _emit = context.emit
    tools: list[StructuredTool] = []

    if not missing_dependencies_for("bulk_extract"):

        def find_in_image(keyword: str, offset: int = 0, limit: int = 100) -> dict:
            """Find every occurrence of ONE LITERAL term in the raw evidence image's
                    bytes and report each with its offset and surrounding context. Coverage is
                    the whole medium, allocated and unallocated alike, including the content of
                    compressed streams, because the scan reads bytes instead of walking a
                    filesystem or a process list. Use it for a term no structured view reports
                    and that no feature list recognises as a value of its own kind — a string
                    interrupted by other bytes is still found this way. Read-only and PAGED.

                    Args:
                        keyword: One literal term to find. Not a regular expression.
                        offset: Zero-based position in the hit list; continue from the
                            previous result's next_offset.
                        limit: Hits to return in this page."""
            from forensic_agent.tools.bulk_extractor_tool import find_literal as _find

            img = getattr(disk, "image_path", None) or context.memory_path
            if not img:
                return {"error": "no raw image path available for bulk_extractor."}
            scratch = context.controlled_scratch
            if scratch is None:
                return {
                    "error": "find_in_image requires this run's controlled scratch "
                             "directory; no controlled root is bound."
                }
            try:
                output_root = scratch.retained_workspace(
                    ScratchWorkspaceKind.SCAN_OUTPUTS
                ).path
            except ControlledScratchError as e:
                return {
                    "error": "find_in_image could not open its controlled scan "
                             f"area: {str(e)[:160]}"
                }
            t0 = time.time()
            r = _find(
                img,
                keyword,
                offset=offset,
                limit=limit,
                output_root=output_root,
                evidence_sha256=_evidence_digest(context, img),
            )
            _emit("find_in_image", {"keyword": keyword, "offset": offset}, t0)
            return r

        tools.append(StructuredTool.from_function(find_in_image))

    return tools
