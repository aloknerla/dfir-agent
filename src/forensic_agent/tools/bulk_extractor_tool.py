"""bulk_extractor pass-through — feature extraction over the RAW image, INCLUDING unallocated
and slack that the TSK-metadata tools cannot reach.

bulk_extractor scans the whole image (allocated AND unallocated) for features its scanners
recognise: Windows directory entries -> deleted FILENAMES (``windirs``, FAT + NTFS $INDX, the
name bytes that survive a wipe/quick-format), emails and URLs in BOTH UTF-8 and UTF-16
(``email``/``url``/``domain`` — the encoding-robust answer a plain ASCII grep misses), NTFS
$MFT/$USN, SQLite records, EXIF, etc. It reads E01 directly. Read-only; the agent picks which
feature to read. This is the tool that decides whether a "lost" filename is truly gone or just
sitting in unallocated space.

Containment: the scan writes below ONE controlled root supplied by the caller
(:mod:`forensic_agent.core.controlled_scratch`), never below the ambient system
temporary directory.  Without such a root the scan is refused rather than run.
The model names a feature, never a path: the requested name is matched against
the feature files the scan actually produced, and the resolved path is asserted
to be inside the scan directory before a single byte is read.

Lifetime: a scan of a real image is bounded by a 1800 s timeout, so paging one
feature or reading a second one must never rescan.  The scan output therefore
stays below the controlled root it was written to, and is removed when the owner
of that root releases it — for an agent run, when the controlled scratch session
closes.
"""
from __future__ import annotations

import hashlib
import os
import re
import stat
import threading
import xml.etree.ElementTree as ET
from collections.abc import Mapping, Sequence
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from forensic_agent.core.controlled_scratch import (
    ControlledScratchError,
    ControlledScratchSession,
    attest_controlled_scratch_root,
    provision_controlled_scratch_root,
    purge_controlled_directory,
)
from forensic_agent.core.environ import bulk_extractor_path
from forensic_agent.core.storage_containment import (
    StorageContainmentError,
    assert_payload_root_contained,
)
from forensic_agent.core.tool_failure import tool_failure_result
from forensic_agent.core.toolio import shape
from forensic_agent.core.toolkit import run_external

#: Every scan directory this module creates carries this prefix below the
#: controlled root, so cleanup can never remove a directory it did not create.
_SCAN_PREFIX = "bulk-extractor-"

#: Guards the two registries below, and nothing else: a thread that holds a scan
#: lock still needs this one to publish its result, so it is never held while a
#: scan lock is acquired.
_REGISTRY_LOCK = threading.Lock()

#: (controlled root identity, evidence identity, and for a pattern scan the
#: pattern itself) -> scan output directory.  The controlled root is part of the
#: key so one case/run can never be served the scan directory provisioned below
#: another controlled root, and the pattern is part of it because two searches
#: for different terms are two different scans that must never share output.
_CACHE: dict[tuple[str, ...], str] = {}

#: One lock per cache key.  At most one bulk_extractor process runs for a given
#: (controlled root, image), and no directory is removed while another thread
#: scans into it or reads a feature file out of it.  Entries are never dropped:
#: the lock a thread already holds must stay the one every other thread for that
#: key acquires, so the registry is bounded by the distinct pairs seen, not by
#: the number of calls.
_SCAN_LOCKS: dict[tuple[str, ...], threading.Lock] = {}

#: Cache key -> {top-level file name: size in bytes} as the scan left it.  A walk
#: of the directory reports what is there now; only a record of what was there
#: when the scan finished can report what is no longer there.  Sizes are kept
#: beside the names because a file emptied in place is the same defect as one
#: deleted, and a walk cannot see either.
_INVENTORY: dict[tuple[str, ...], dict[str, int]] = {}

_NO_CONTROLLED_ROOT = (
    "bulk_extractor needs a controlled output root and none was supplied; the scan was "
    "not run and nothing was written. Bind this run's controlled scratch directory."
)

#: Every scan this module runs reconstructs file content.  The default scanner
#: set unpacks archives found inside the evidence and carves the members back
#: out onto disk; the pattern scan enables ``gzip``, which does the same for
#: compressed streams.  On real evidence those members are the executables the
#: evidence is an investigation of, so the directory they land in decides
#: whether this analysis is sandboxed for writes or only for execution.
_PAYLOAD_SUBJECT = "bulk_extractor"


class _FeatureRefused(ValueError):
    """The requested feature is not a feature file this scan produced."""


def _identity(path: str | os.PathLike[str]) -> str:
    """Comparable identity of a path (resolved, normalised, case-folded on Windows)."""

    return os.path.normcase(os.path.normpath(os.path.realpath(os.fspath(path))))


def _inside(root: str | os.PathLike[str], candidate: str | os.PathLike[str]) -> bool:
    """True when ``candidate`` resolves strictly below ``root``."""

    root_identity = _identity(root)
    candidate_identity = _identity(candidate)
    if candidate_identity == root_identity:
        return False
    try:
        common = os.path.commonpath((root_identity, candidate_identity))
    except ValueError:  # different drives/volumes
        return False
    return common == root_identity


def _controlled_root(
    output_root: str | os.PathLike[str] | ControlledScratchSession | None,
) -> Path:
    """Resolve the one controlled directory the scan may write below, or fail closed."""

    candidate: Path | None = None
    if type(output_root) is ControlledScratchSession:
        candidate = output_root.session_path
    elif isinstance(output_root, str | os.PathLike):
        text = os.fspath(output_root)
        candidate = Path(text) if str(text).strip() else None
    if candidate is None:
        raise ControlledScratchError(_NO_CONTROLLED_ROOT)
    # Rejects a relative root, a traversal component, and any symlink/reparse
    # point along the way, and proves the root is an existing directory.
    return attest_controlled_scratch_root(candidate).root_path


def _scan_lock(key: tuple[str, ...]) -> threading.Lock:
    """Return the one lock that serialises everything done for one cache key."""

    with _REGISTRY_LOCK:
        lock = _SCAN_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _SCAN_LOCKS[key] = lock
        return lock


def _scan_directory(root: Path, image_path: str) -> Path:
    """Provision this evidence item's empty scan directory below the controlled root."""

    digest = hashlib.sha256(_identity(image_path).encode("utf-8")).hexdigest()[:32]
    target = root / f"{_SCAN_PREFIX}{digest}"
    if target.exists():
        # A partial directory from an interrupted scan must never be presented
        # as this scan's output, and scanning into the leftovers would mix two
        # scans' features, so a removal that fails is raised rather than
        # ignored.  The caller holds this key's scan lock, so no other thread is
        # writing here.
        purge_controlled_directory(target)
    provision_controlled_scratch_root(target, anchor=root)
    return target


def _cached_scan(key: tuple[str, ...], root: Path) -> Path | None:
    """Return a cached scan directory only while it exists inside this controlled root."""

    with _REGISTRY_LOCK:
        cached = _CACHE.get(key)
    if cached is None:
        return None
    path = Path(cached)
    if not path.is_dir() or not _inside(root, path):
        with _REGISTRY_LOCK:
            _CACHE.pop(key, None)
            _INVENTORY.pop(key, None)
        return None
    return path


def _written_files(outdir: Path) -> dict[str, int]:
    """Name and size of every top-level file the scan left, taken once it finished."""

    written: dict[str, int] = {}
    try:
        with os.scandir(outdir) as entries:
            for entry in entries:
                if not entry.is_file(follow_symlinks=False):
                    continue
                try:
                    written[entry.name] = int(entry.stat(follow_symlinks=False).st_size)
                except OSError:
                    continue
    except OSError:
        return {}
    return written


def _remember_scan(key: tuple[str, ...], outdir: Path) -> None:
    """Publish a completed scan, forgetting the ones their owners already released."""

    written = _written_files(outdir)
    with _REGISTRY_LOCK:
        # A released root's entries can never be reached again through their own
        # key, so drop them here instead of letting the map grow for the life of
        # the process.  Dropping an entry only forgets a directory; it removes
        # nothing from disk.
        for stale in [item for item, path in _CACHE.items() if not Path(path).is_dir()]:
            _CACHE.pop(stale, None)
            _INVENTORY.pop(stale, None)
        _CACHE[key] = str(outdir)
        _INVENTORY[key] = written


def _remembered_inventory(key: tuple[str, ...]) -> dict[str, int]:
    with _REGISTRY_LOCK:
        return dict(_INVENTORY.get(key, {}))


#: bulk_extractor's find scanner takes a REGULAR EXPRESSION, while this
#: project's keyword contract is one LITERAL term.  Every metacharacter is
#: escaped before the pattern reaches the scanner: a search for "payroll.doc" whose
#: dot had silently widened into "any character" would also report "payroll_doc"
#: and "payroll2doc" — matches the examiner never asked for, reported without
#: saying so.
#:
#: The engine is the C++ standard library's ECMAScript grammar, not RE2, so the
#: inline "(?i)" flag other tools accept is a hard error here. Case-insensitivity
#: is therefore spelled out per letter as a two-member character class, which
#: that grammar does accept and which keeps the pattern a literal match.
_REGEX_METACHARACTERS = frozenset(r"\.[]{}()*+?|^$/")

#: The find scanner alone reads the image as it is stored.  gzip is enabled
#: beside it because the values a disk-wide search is asked for routinely sit
#: inside compressed browser cache: bytes that no scan of the stored image and
#: no walk of the file system can reach, however complete either one is.
_FIND_SCANNERS = ("-E", "find", "-e", "gzip")

#: The one recorder the find scanner writes.
_FIND_FEATURE = "find"


def _literal_regex(keyword: str) -> str:
    """One literal term as the case-insensitive pattern that matches it, and nothing wider."""

    parts = []
    for ch in keyword:
        if ch in _REGEX_METACHARACTERS:
            parts.append("\\" + ch)
        elif ch.isalpha() and ch.lower() != ch.upper():
            parts.append(f"[{ch.lower()}{ch.upper()}]")
        else:
            parts.append(ch)
    return "".join(parts)


def _find_directory(root: Path, image_path: str, pattern: str) -> Path:
    """Provision the empty scan directory belonging to ONE (evidence, pattern) pair."""

    digest = hashlib.sha256(
        "\x00".join((_identity(image_path), pattern)).encode("utf-8")
    ).hexdigest()[:32]
    target = root / f"{_SCAN_PREFIX}find-{digest}"
    if target.exists():
        # Same reasoning as the feature scan: leftovers from an interrupted run
        # must never be presented as this scan's output.
        purge_controlled_directory(target)
    provision_controlled_scratch_root(target, anchor=root)
    return target


def _run_find(image: str, be: str, pattern: str, outdir: str) -> str:
    """Scan ``image`` for one pattern into the already provisioned ``outdir``."""

    run_external(
        [be, *_FIND_SCANNERS, "-f", pattern, "-o", outdir, image], timeout=1800
    )
    return outdir


def _read_find(outdir: Path, *, offset: int, limit: int,
               inventory: Mapping[str, int]) -> dict:
    """Read the find recorder of a completed pattern scan; the caller holds its lock.

    A missing recorder file used to read as zero hits.  For this tool that is the
    worst possible reading: a disk-wide search reporting no occurrences is the
    single result an examiner is most likely to act on, and it must never be what
    a deleted output file looks like.
    """

    path = outdir / f"{_FIND_FEATURE}{_FEATURE_SUFFIX}"
    removed = _removed_outputs(outdir, inventory)
    if removed:
        return {
            "error": f"this search wrote output that is no longer on disk ({', '.join(removed)}), "
                     "so the hits it found cannot be read back and reporting none would "
                     "understate them. " + _OUTPUT_REMOVED_NOTE,
            _OUTPUT_REMOVED_KEY: removed,
        }
    rows = []
    if path.is_file():
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.rstrip("\n").split("\t")
                if len(parts) >= 2:
                    rows.append({"offset": parts[0], "match": parts[1],
                                 "context": parts[2] if len(parts) > 2 else ""})
    return shape(rows, offset=offset, limit=limit)


def _run(image: str, be: str, outdir: str) -> str:
    """Scan ``image`` into the already provisioned controlled directory ``outdir``."""

    # run_external raises ExternalToolError on failure, so the caller does NOT cache a failed scan
    run_external([be, "-o", outdir, image], timeout=1800)
    return outdir


#: The scan writes three kinds of output beside the raw feature files, and all
#: three used to be discarded before the model could see them.  Each is named
#: here because each has to be presented as what it is: a ranked summary read as
#: an occurrence list misstates how often a value occurred, and the provenance
#: record is not a feature at all.
_FEATURE_SUFFIX = ".txt"
_HISTOGRAM_SUFFIX = "_histogram.txt"
_REPORT_FILE = "report.xml"

#: The name the scan's own provenance record is read under.  What is served is a
#: summary: the record itself is thousands of lines of build environment, and
#: pushing that into the context would spend the budget the features need.
_REPORT_FEATURE = "report"

#: The name the files the scan reconstructed into its own subdirectories (carved
#: ``jpeg/``, ``ntfsindx_carved/`` and the like) are inventoried under.  Their
#: bytes are already recovered onto disk; what the model cannot otherwise learn
#: is that they exist, how many there are and how large each one is.
_RECONSTRUCTED_FEATURE = "reconstructed"

#: Nested content is named with this separator rather than with the path
#: separator it actually sits behind.  ``/`` and ``\`` are refused by the rule
#: that stops the model naming a path, and that rule is not being relaxed for
#: subdirectories; this character is illegal in a Windows filename and unused by
#: bulk_extractor, so an alias can never collide with a name on disk either.
_ALIAS_SEPARATOR = "|"

#: Bounds on the walk.  A scan that carved tens of thousands of files must not
#: turn every later call into a full stat of the tree, and when a bound is
#: reached the listing says so rather than presenting a partial inventory as the
#: whole one.
_MAX_WALK_DEPTH = 8
_MAX_WALK_FILES = 20000

#: report.xml is the scanner's own output inside a directory only the scanner
#: wrote to, but it is still parsed under a size bound: anything larger is not a
#: provenance record, and the stdlib parser expands entities.
_MAX_REPORT_BYTES = 8 * 1024 * 1024

#: What each readable name is, stated on the result that carries its rows.  A
#: model that mistook the second for the first would read 4,669 ranked values as
#: 4,669 occurrences of 30,882.
_KIND_RAW = "raw occurrence list: one row per occurrence, in the order the scanner wrote them"
_KIND_RANKED = (
    "ranked summary: one row per DISTINCT value with the number of times it occurred, "
    "so a row here is not one occurrence"
)
_KIND_PROVENANCE = "the scan's own provenance record, summarised from report.xml"
_KIND_RECONSTRUCTED = (
    "inventory of the files this scan reconstructed into its own subdirectories; their "
    "bytes stay on disk and are not returned here"
)

#: Histogram lines are ``n=<count><TAB><value>``, and the scanner appends
#: ``(utf16=<count>)`` to the values it also saw UTF-16 encoded.  The row parser
#: for feature files cannot read this: it would take ``n=530`` for an offset.
_HISTOGRAM_COUNT_RE = re.compile(r"^n=(\d+)$")
_UTF16_FIELD_RE = re.compile(r"^\(utf16=(\d+)\)$")
_UTF16_TAIL_RE = re.compile(r"\s*\(utf16=(\d+)\)$")

#: Provenance fields worth a row, in the order they are emitted: what ran, over
#: what, and when.  Anything not listed here stays in the record on disk.
_REPORT_FIELDS: tuple[tuple[str, str], ...] = (
    ("image_filename", "image"),
    ("image_size", "image_bytes"),
    ("start_time", "started"),
    ("elapsed_seconds", "elapsed_seconds"),
    ("command_line", "command_line"),
)

_REPORT_FIELD_TAGS = frozenset(tag for tag, _ in _REPORT_FIELDS)

_ENABLED_VALUES = frozenset({"1", "true", "yes", "on"})


@dataclass(frozen=True)
class _ScanCatalog:
    """What one finished scan left on disk, split by what each part actually means."""

    #: Raw occurrence lists, one row per occurrence.
    features: list[str]
    #: Ranked, deduplicated summaries, one row per distinct value.
    histograms: list[str]
    #: Files reconstructed into subdirectories: {directory, file, bytes}.
    reconstructed: list[dict[str, object]]
    #: Readable name -> location RELATIVE to the scan directory.  Built from the
    #: scan's own entries, so no location here ever came from the model.
    paths: dict[str, str]
    #: Whether the scan wrote a provenance record.
    report: bool
    #: False when a bound stopped the walk, so a caller is told the inventory it
    #: is reading is not everything the scan produced.
    complete: bool


def _alias(relative: tuple[str, ...]) -> str:
    """Name one discovered file so the name can never be read back as a path.

    Only the file extension is dropped, so a ranked summary keeps the
    ``_histogram`` its own name carries: the name has to say which of the two
    lists it belongs to wherever it is quoted afterwards, not only in the listing
    that offered it.
    """

    tail = relative[-1]
    if tail.endswith(_FEATURE_SUFFIX):
        tail = tail[: -len(_FEATURE_SUFFIX)]
    return _ALIAS_SEPARATOR.join((*relative[:-1], tail))


def _catalog(outdir: str | os.PathLike[str]) -> _ScanCatalog:
    """Inventory one scan directory, subdirectories included.

    Symlinks are skipped here rather than filtered later, so a link planted in
    the output never enters the readable namespace at all; :func:`_feature_path`
    refuses one that reaches it by some other route.
    """

    root = Path(os.fspath(outdir))
    features: list[str] = []
    histograms: list[str] = []
    reconstructed: list[dict[str, object]] = []
    paths: dict[str, str] = {}
    report = False
    complete = True
    seen = 0
    pending: list[tuple[Path, tuple[str, ...]]] = [(root, ())]
    while pending:
        directory, prefix = pending.pop(0)
        try:
            with os.scandir(directory) as scan:
                entries = sorted(scan, key=lambda entry: entry.name)
        except OSError:
            complete = False
            continue
        for entry in entries:
            relative = (*prefix, entry.name)
            if entry.is_dir(follow_symlinks=False):
                if len(relative) < _MAX_WALK_DEPTH:
                    pending.append((Path(entry.path), relative))
                else:
                    complete = False
                continue
            if not entry.is_file(follow_symlinks=False):
                continue
            seen += 1
            if seen > _MAX_WALK_FILES:
                complete = False
                pending.clear()
                break
            if not prefix and entry.name == _REPORT_FILE:
                report = True
                continue
            target: list[str] | None = None
            if entry.name.endswith(_HISTOGRAM_SUFFIX):
                target = histograms
            elif entry.name.endswith(_FEATURE_SUFFIX):
                target = features
            if target is None:
                if not prefix:
                    continue
                try:
                    size = entry.stat(follow_symlinks=False).st_size
                except OSError:
                    complete = False
                    continue
                reconstructed.append({
                    "directory": _ALIAS_SEPARATOR.join(prefix),
                    "file": entry.name,
                    "bytes": int(size),
                })
                continue
            name = _alias(relative)
            if name in paths:
                # One name can only serve one file, so the later one stays
                # unlisted and the listing declares itself incomplete rather
                # than quietly serving whichever file was walked first.
                complete = False
                continue
            paths[name] = os.path.join(*relative)
            target.append(name)
    return _ScanCatalog(
        features=sorted(features),
        histograms=sorted(histograms),
        reconstructed=reconstructed,
        paths=paths,
        report=report,
        complete=complete,
    )


def _feature_path(
    outdir: Path,
    feature: str,
    available: Sequence[str] | Mapping[str, str],
) -> Path:
    """Resolve one DISCOVERED feature file, refusing anything that looks like a path."""

    name = str(feature)
    if (
        not name
        or name in {".", ".."}
        or ".." in name
        or "/" in name
        or "\\" in name
        or "\x00" in name
        or os.path.isabs(name)
        or bool(os.path.splitdrive(name)[0])
        or name != os.path.basename(name)
    ):
        raise _FeatureRefused(
            f"refused feature name {name[:60]!r}: a feature is one of the names in "
            "available_features, never a path"
        )
    if name not in available:
        raise _FeatureRefused(
            f"unknown feature {name[:60]!r}: this scan produced "
            f"{', '.join(str(item) for item in available) or 'no feature files'}"
        )
    # The location comes from the scan's own inventory, never from the name the
    # model typed: reconstructed content sits one or more directories down, and
    # the only way to reach it is a location this module discovered itself.
    relative = available[name] if isinstance(available, Mapping) else f"{name}{_FEATURE_SUFFIX}"
    parts = Path(relative).parts
    if not parts or any(part in {"", ".", ".."} or os.path.isabs(part) for part in parts):
        raise _FeatureRefused(
            f"refused feature {name[:60]!r}: its recorded location leaves the scan directory"
        )
    resolved = Path(os.path.realpath(outdir.joinpath(*parts)))
    # Defence in depth: the membership test above already excludes traversal, so
    # a resolved path outside the scan directory means a link was planted.
    if not _inside(outdir, resolved):
        raise _FeatureRefused(
            f"refused feature {name[:60]!r}: it resolves outside the scan directory"
        )
    if not resolved.is_file():
        raise _FeatureRefused(
            f"feature {name[:60]!r} is no longer a readable feature file of this scan"
        )
    return resolved


def _feature_rows(path: Path) -> list[dict[str, str]]:
    """One row per occurrence, in bulk_extractor's documented feature-file layout."""

    rows: list[dict[str, str]] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 2:
                rows.append({"offset": parts[0], "feature": parts[1],
                             "context": parts[2] if len(parts) > 2 else ""})
    return rows


def _histogram_rows(path: Path) -> list[dict[str, object]]:
    """One row per DISTINCT value, carrying its count, in the scanner's own ranking.

    The order is the file's order and is never re-sorted here: the ranking is the
    scanner's finding, and a value's position in it is part of what it reports.
    """

    rows: list[dict[str, object]] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.rstrip("\n").split("\t")
            counted = _HISTOGRAM_COUNT_RE.match(parts[0])
            if counted is None or len(parts) < 2:
                continue
            value = parts[1]
            utf16: int | None = None
            for extra in parts[2:]:
                annotated = _UTF16_FIELD_RE.match(extra.strip())
                if annotated is not None:
                    utf16 = int(annotated.group(1))
            if utf16 is None:
                # Some builds append the annotation to the value instead of
                # writing it as a field of its own; dropping it there would
                # understate how much of the count came from UTF-16 text, and
                # leaving it on the value would corrupt the value itself.
                tail = _UTF16_TAIL_RE.search(value)
                if tail is not None:
                    utf16 = int(tail.group(1))
                    value = value[: tail.start()]
            row: dict[str, object] = {"count": int(counted.group(1)), "value": value}
            if utf16 is not None:
                row["utf16"] = utf16
            rows.append(row)
    return rows


def _local_tag(element: ET.Element) -> str:
    """The element name without its namespace, which is what the record is keyed by."""

    return str(element.tag).rpartition("}")[2]


def _element_text(element: ET.Element) -> str:
    return (element.text or "").strip()


def _report_parser() -> ET.XMLParser:
    """A parser that refuses every entity declaration, which is the XML risk here.

    ``defusedxml`` is not a dependency of this project, and the record is the
    scanner's own output inside a directory only the scanner wrote to — but a
    parser that cannot be made to expand an entity removes the question instead
    of arguing it.  Expat resolves no external entity on its own, so refusing the
    declarations closes both the external reference and the expansion bomb.
    """

    parser = ET.XMLParser()
    expat = getattr(parser, "parser", None)
    if expat is not None:
        def refuse(*_: object) -> None:
            raise ET.ParseError("the provenance record declares an XML entity")

        expat.EntityDeclHandler = refuse
    return parser


@dataclass(frozen=True)
class _ScanReport:
    """What the scan's own provenance record states about the scan it records.

    Kept apart from the rows it is rendered into because the same record answers
    a second question: which recorders the scan wrote.  A recorder named here
    whose file is not on disk is a file that was removed after the scanner wrote
    it, which no walk of the directory can distinguish from a recorder that never
    ran.
    """

    #: Empty when the record could not be read, which is the one state in which
    #: nothing may be concluded from its silence.
    readable: bool
    build: str = ""
    fields: Mapping[str, str] = MappingProxyType({})
    image_hash: str = ""
    scanners: tuple[str, ...] = ()
    #: Recorder name -> rows the scanner says it wrote, in the record's order.
    counts: tuple[tuple[str, int], ...] = ()
    unreadable_reason: str = ""


def _read_report(path: Path) -> _ScanReport:
    """Read the scan's provenance record; the XML itself never leaves this function."""

    try:
        if path.stat().st_size > _MAX_REPORT_BYTES:
            return _ScanReport(
                readable=False,
                unreadable_reason=(
                    "the provenance record is too large to be one, and was not parsed"
                ),
            )
        root = ET.parse(path, parser=_report_parser()).getroot()
    except (OSError, ET.ParseError):
        return _ScanReport(
            readable=False,
            unreadable_reason="the provenance record could not be parsed",
        )

    fields: dict[str, str] = {}
    scanners: set[str] = set()
    counts: list[tuple[str, int]] = []
    program = ""
    version = ""
    image_hash = ""
    for element in root.iter():
        tag = _local_tag(element)
        if tag == "program":
            program = program or _element_text(element)
        elif tag == "version":
            version = version or _element_text(element)
        elif tag == "hashdigest":
            digest = _element_text(element)
            if digest and not image_hash:
                image_hash = f"{element.get('type', 'hash')} {digest}"
        elif tag == "scanner":
            # The record names an enabled scanner as the element's own TEXT under
            # <configuration><scanners>, and repeats the enabled ones as a <name>
            # child under <scanner_stats>. Neither form carries a "name"
            # attribute, so reading one is how the list stays empty for every scan.
            scanner = str(element.get("name") or "").strip() or _element_text(element)
            flag = str(element.get("enabled") or "").strip()
            for child in element:
                child_tag = _local_tag(child)
                if child_tag == "name":
                    scanner = _element_text(child)
                elif child_tag == "enabled":
                    flag = _element_text(child)
            # A scanner element carrying no flag at all is one the record is
            # listing as having run; only an explicit falsey flag excludes it.
            if scanner and (not flag or flag.lower() in _ENABLED_VALUES):
                scanners.add(scanner)
        elif tag in {"feature_file", "feature_recorder"}:
            recorder = str(element.get("name") or "")
            written = str(element.get("count") or "")
            for child in element:
                child_tag = _local_tag(child)
                if child_tag == "name":
                    recorder = _element_text(child)
                elif child_tag == "count":
                    written = _element_text(child)
            if recorder and written.isdigit():
                counts.append((recorder, int(written)))
        elif tag in _REPORT_FIELD_TAGS:
            fields.setdefault(tag, _element_text(element))

    return _ScanReport(
        readable=True,
        build=" ".join(part for part in (program, version) if part),
        fields=MappingProxyType(dict(fields)),
        image_hash=image_hash,
        scanners=tuple(sorted(scanners)),
        counts=tuple(counts),
    )


def _report_rows(report: _ScanReport) -> list[dict[str, str]]:
    """Render the provenance record as the rows a caller reads it through.

    What survives is what changes how a result should be read: which build of the
    scanner ran, which scanners it enabled (a feature nothing enabled cannot have
    hits, and that is not the same finding as a feature with none), what image it
    read, and how many rows each recorder wrote.
    """

    if not report.readable:
        return [{"field": "report", "value": report.unreadable_reason}]
    rows: list[dict[str, str]] = []
    if report.build:
        rows.append({"field": "scanner", "value": report.build})
    for tag, label in _REPORT_FIELDS:
        if report.fields.get(tag):
            rows.append({"field": label, "value": report.fields[tag]})
    if report.image_hash:
        rows.append({"field": "image_hash", "value": report.image_hash})
    # The count leads each joined value, so a row the byte cap shortens still
    # states how many entries it was built from.
    if report.scanners:
        rows.append({
            "field": "scanners_enabled",
            "value": f"{len(report.scanners)}: " + ", ".join(report.scanners),
        })
    if report.counts:
        ranked = sorted(report.counts, key=lambda item: (-item[1], item[0]))
        wrote = [f"{name}={count}" for name, count in ranked if count]
        rows.append({
            "field": "feature_counts",
            "value": f"{len(wrote)} of {len(report.counts)} recorders wrote rows: "
                     + ", ".join(wrote),
        })
    return rows


def _names(catalog: _ScanCatalog) -> dict[str, list[str]]:
    """The name lists every result echoes, kept apart so neither is read as the other."""

    names: dict[str, list[str]] = {"available_features": catalog.features}
    if catalog.histograms:
        names["available_histograms"] = catalog.histograms
    return names


def _reconstructed_directories(catalog: _ScanCatalog) -> list[dict[str, object]]:
    """One entry per subdirectory the scan reconstructed files into, with its size."""

    totals: dict[str, tuple[int, int]] = {}
    for entry in catalog.reconstructed:
        directory = str(entry["directory"])
        files, size = totals.get(directory, (0, 0))
        totals[directory] = (files + 1, size + int(str(entry["bytes"])))
    return [
        {"directory": directory, "files": files, "bytes": size}
        for directory, (files, size) in sorted(totals.items())
    ]


def _listing(catalog: _ScanCatalog) -> dict:
    """What one scan produced, with each kind of output named for what it is."""

    result: dict = dict(_names(catalog))
    if catalog.reconstructed:
        result["reconstructed_directories"] = _reconstructed_directories(catalog)
    if catalog.report:
        result["provenance"] = _REPORT_FEATURE
    note = [
        "pass feature=<name> to read one. available_features are RAW occurrence lists "
        "({offset, feature, context}, one row per occurrence): 'windirs' = deleted "
        "filenames in unallocated (FAT/NTFS dir entries), 'email'/'url'/'domain' = "
        "encoding-robust (UTF-8+UTF-16), plus whatever else was found."
    ]
    if catalog.histograms:
        note.append(
            "available_histograms are the scanner's RANKED, DEDUPLICATED summaries "
            "({count, value}, one row per distinct value): read one to rank a feature "
            "whose raw list is too long to page, and never read its count as a row count "
            "of the raw list."
        )
    if catalog.report:
        note.append(
            f"feature='{_REPORT_FEATURE}' summarises the scan's own provenance record: "
            "scanner version, scanners enabled, image scanned, rows per recorder."
        )
    if catalog.reconstructed:
        note.append(
            f"feature='{_RECONSTRUCTED_FEATURE}' inventories the files this scan carved "
            "back out into its own subdirectories."
        )
    if not catalog.complete:
        note.append(
            "this scan wrote more than one listing can enumerate, so the names and the "
            "inventory above are partial."
        )
    result["note"] = " ".join(note)
    return result


#: Stated on every result read out of a scan directory that lost output after the
#: scanner wrote it.  The wording says what was taken away and what that does to
#: the result, because the failure mode being guarded against is a result that
#: looks complete: fewer rows and fewer names, with nothing saying why.
_OUTPUT_REMOVED_KEY = "output_removed"
_OUTPUT_REMOVED_NOTE = (
    "output this scan wrote was removed or truncated after the scanner wrote it "
    "(an on-access antivirus scanner quarantining carved content does exactly this). "
    "What is reported here is therefore NOT the complete result of this scan, and an "
    "absence in it is not evidence of absence in the image. Re-run the scan with its "
    "output on storage no other process writes to."
)


def _removed_outputs(outdir: Path, inventory: Mapping[str, int]) -> list[str]:
    """Files the scan produced that are now gone, or shorter than they were.

    A walk of the directory reports what is there, and a file that was deleted
    underneath the scanner is indistinguishable by that walk from a recorder that
    never wrote anything.  The two independent witnesses to what the scan
    produced are compared instead: the scanner's own provenance record, which
    names every recorder that wrote rows — the only witness to a file removed
    while the scan was still running — and the inventory taken the moment the
    scan finished, which is the witness to a file removed between two reads.
    """

    removed: set[str] = set()
    for name, size in inventory.items():
        try:
            observed = os.lstat(outdir / name)
        except OSError:
            removed.add(name)
            continue
        if not stat.S_ISREG(observed.st_mode) or int(observed.st_size) < size:
            removed.add(name)
    report = _read_report(outdir / _REPORT_FILE)
    if report.readable:
        for recorder, count in report.counts:
            if count > 0 and not (outdir / f"{recorder}{_FEATURE_SUFFIX}").is_file():
                removed.add(f"{recorder}{_FEATURE_SUFFIX}")
    return sorted(removed)


def _declare_removed_outputs(result: dict, removed: Sequence[str]) -> dict:
    """Attach the removal statement to a result, ahead of the rows it qualifies."""

    if not removed:
        return result
    note = str(result.get("note") or "")
    return {
        **result,
        _OUTPUT_REMOVED_KEY: list(removed),
        "note": f"{_OUTPUT_REMOVED_NOTE} {note}".strip(),
    }


def _read_scan(outdir: Path, feature: str | None, *,
               filter: str | None, offset: int, limit: int,
               inventory: Mapping[str, int]) -> dict:
    """List or read one feature of an existing scan; the caller holds its lock."""

    catalog = _catalog(outdir)
    removed = _removed_outputs(outdir, inventory)
    if not feature:
        return _declare_removed_outputs(_listing(catalog), removed)
    name = str(feature)
    # The two names below stand for output that is not one feature file, so they
    # are answered before resolution.  A real feature file of that name keeps the
    # name: what the scan wrote wins over what this module offers on top of it.
    if name not in catalog.paths:
        if name == _REPORT_FEATURE and catalog.report:
            return _declare_removed_outputs(
                {"feature": name, **_names(catalog), "kind": _KIND_PROVENANCE,
                 **shape(_report_rows(_read_report(outdir / _REPORT_FILE)),
                         offset=offset, limit=limit, filter=filter)},
                removed,
            )
        if name == _RECONSTRUCTED_FEATURE and catalog.reconstructed:
            return _declare_removed_outputs(
                {"feature": name, **_names(catalog), "kind": _KIND_RECONSTRUCTED,
                 **shape(catalog.reconstructed, offset=offset, limit=limit, filter=filter)},
                removed,
            )
    try:
        fp = _feature_path(outdir, name, catalog.paths)
    except _FeatureRefused as e:
        return _declare_removed_outputs(
            {"feature": name[:120], **_names(catalog), "error": str(e)}, removed
        )
    ranked = name in catalog.histograms
    rows: list = _histogram_rows(fp) if ranked else _feature_rows(fp)
    return _declare_removed_outputs(
        {"feature": name, **_names(catalog),
         "kind": _KIND_RANKED if ranked else _KIND_RAW,
         **shape(rows, offset=offset, limit=limit, filter=filter)},
        removed,
    )


def release_scan_outputs(
    output_root: str | os.PathLike[str] | ControlledScratchSession | None,
) -> int:
    """Remove every scan directory this module created below one controlled root.

    This is the teardown path for a caller that owns a plain controlled root; an
    agent run instead lets its controlled scratch session purge the workspace the
    scans were written to.  It is a teardown operation: it serialises against
    every scan in flight for that root, but it is not meant to run while new
    scans are being started for it.

    Returns the number of scan directories removed, and raises
    :class:`ControlledScratchError` when one of them could not be removed —
    counting an unremoved tree as released would let the owning root be declared
    clean while the scan output is still on disk.
    """

    root = _controlled_root(output_root)
    root_identity = _identity(root)
    # Take every scan lock for this root, so no directory is removed while
    # another thread scans into it or reads a feature file out of it.  A scanner
    # only ever holds one lock and never asks for a second, so acquiring these in
    # a fixed order cannot deadlock against it.
    with _REGISTRY_LOCK:
        keys = sorted(key for key in _SCAN_LOCKS if key[0] == root_identity)
        locks = [_SCAN_LOCKS[key] for key in keys]
    with ExitStack() as held:
        for lock in locks:
            held.enter_context(lock)
        with _REGISTRY_LOCK:
            for key in [item for item in _CACHE if item[0] == root_identity]:
                _CACHE.pop(key, None)
                _INVENTORY.pop(key, None)
        try:
            entries = list(os.scandir(root))
        except OSError as exc:
            raise ControlledScratchError("controlled root could not be enumerated") from exc
        released = 0
        for entry in entries:
            # Only the directories this module named and created, and never a link.
            if not entry.name.startswith(_SCAN_PREFIX) or not entry.is_dir(follow_symlinks=False):
                continue
            purge_controlled_directory(Path(entry.path))
            released += 1
    return released


# --------------------------------------------------------------------------- #
# Cross-run scan cache.
#
# Within one run the scan is cached in the run's retained workspace; that
# workspace dies with the run, so every LATER question on the same evidence
# used to pay the whole 1800 s scan again.  A finished default scan is
# therefore PUBLISHED into the persistent index root, content-addressed by the
# evidence's verified SHA-256 and the scanner's sealed version, and any later
# call — this run, the next question, next week's session — reuses it.  With
# no verified evidence digest (a memory image the open did not hash) nothing
# is published and the behavior is exactly what it was.
# --------------------------------------------------------------------------- #
_SCAN_CACHE_SCHEMA = "forensic.bulk-extractor-default-scan.v1"
_FIND_CACHE_SCHEMA = "forensic.bulk-extractor-find-scan.v1"
_SCAN_CACHE_MANIFEST = "scan-manifest.json"


def _scan_cache_identity(evidence_sha256: str, be: str) -> dict[str, str] | None:
    """The identity a published default scan is stored and re-served under."""

    try:
        from forensic_agent.tools.entity_index import _scanner_version

        version = _scanner_version(None)
    except Exception:
        # The sealed inventory cannot name the scanner's version; an artifact
        # that cannot name what built it must not be reused, so no identity.
        del be
        return None
    return {
        "schema": _SCAN_CACHE_SCHEMA,
        "evidence_sha256": str(evidence_sha256),
        "scanner": "bulk_extractor",
        "scanner_version": version,
        "scanners": "default",
    }


def _find_cache_identity(
    evidence_sha256: str, be: str, pattern: str
) -> dict[str, str] | None:
    """The identity a published literal search is stored and re-served under.

    A SEPARATE identity rather than a pattern field added to the default scan's:
    a publication is re-served only when its stored manifest equals the identity
    exactly, so widening that dict would orphan every default scan already on
    disk — including the one the case open builds.
    """

    identity = _scan_cache_identity(evidence_sha256, be)
    if identity is None:
        return None
    return {
        **identity,
        "schema": _FIND_CACHE_SCHEMA,
        "scanners": "find+gzip",
        "pattern": pattern,
    }


def _scan_cache_key(identity: Mapping[str, str]) -> str:
    import json as _json

    canonical = _json.dumps(dict(identity), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


def _scan_cache_root() -> Path | None:
    """The persistent, containment-attested root published scans live below."""

    from forensic_agent.tools.entity_index import index_root_for

    runs = (
        os.environ.get("DFA_RUNS_DIR", "").strip()
        or os.environ.get("_DFA_RUNS_ROOT_HINT", "").strip()
    )
    return index_root_for(Path(runs) if runs else None)


def _published_under(identity: Mapping[str, str] | None) -> Path | None:
    """A finished scan stored under this exact identity, if one exists."""

    import json as _json

    if identity is None:
        return None
    root = _scan_cache_root()
    if root is None:
        return None
    final = root / f"scan-{_scan_cache_key(identity)}"
    manifest = final / _SCAN_CACHE_MANIFEST
    try:
        recorded = _json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if recorded != dict(identity):
        return None
    return final


def _publish_under(outdir: Path, identity: Mapping[str, str] | None) -> Path | None:
    """Copy a finished scan into the persistent store, atomically, best-effort.

    Publication must never fail the call that produced the scan: any problem
    here leaves the run serving its own scratch copy exactly as before.
    """

    import json as _json
    import shutil as _shutil

    if identity is None:
        return None
    root = _scan_cache_root()
    if root is None:
        return None
    final = root / f"scan-{_scan_cache_key(identity)}"
    if (final / _SCAN_CACHE_MANIFEST).exists():
        return final
    staging = root / f".scan-{_scan_cache_key(identity)}.tmp-{os.getpid()}"
    try:
        _shutil.copytree(outdir, staging)
        # The manifest is written LAST inside the staging tree, so a directory
        # that carries one is complete by construction.
        (staging / _SCAN_CACHE_MANIFEST).write_text(
            _json.dumps(dict(identity), sort_keys=True, indent=1), encoding="utf-8"
        )
        os.rename(staging, final)
        return final
    except OSError:
        _shutil.rmtree(staging, ignore_errors=True)
        # A concurrent publisher may have won the rename; their copy is ours.
        return _published_under(identity)
    except Exception:
        _shutil.rmtree(staging, ignore_errors=True)
        return None


def _published_scan(evidence_sha256: str | None, be: str) -> Path | None:
    """A finished DEFAULT scan of these bytes by this scanner version, if one exists."""

    if not evidence_sha256:
        return None
    return _published_under(_scan_cache_identity(evidence_sha256, be))


def _publish_scan(outdir: Path, evidence_sha256: str | None, be: str) -> Path | None:
    """Publish a finished default scan under the identity it is re-served by."""

    if not evidence_sha256:
        return None
    return _publish_under(outdir, _scan_cache_identity(evidence_sha256, be))


def _published_find(evidence_sha256: str | None, be: str, pattern: str) -> Path | None:
    """A finished search of these bytes for this pattern, if one exists."""

    if not evidence_sha256:
        return None
    return _published_under(_find_cache_identity(evidence_sha256, be, pattern))


def _publish_find(
    outdir: Path, evidence_sha256: str | None, be: str, pattern: str
) -> Path | None:
    """Publish a finished literal search under the identity it is re-served by."""

    if not evidence_sha256:
        return None
    return _publish_under(outdir, _find_cache_identity(evidence_sha256, be, pattern))


def _published_features(scan_dir: Path) -> list[str]:
    """The non-empty feature files a published scan produced, by name."""

    names: list[str] = []
    try:
        for entry in sorted(scan_dir.glob("*.txt")):
            if entry.name.startswith("."):
                continue
            try:
                if entry.stat().st_size > 0:
                    names.append(entry.stem)
            except OSError:
                continue
    except OSError:
        return names
    return names[:24]


def prewarm_default_scan(
    image_path: str,
    *,
    evidence_sha256: str | None,
    progress=None,
) -> dict:
    """Build (or find) the published default scan BEFORE a question needs it.

    This is the case-open ingest the established tools perform: the whole
    medium is read once, the extracted entity features are published under
    the evidence's content identity, and the agent's entity search
    (:func:`bulk_extract`) then reuses them at no cost — this run, the next
    question, or next week's session. Never raises; the outcome dict says
    which of built / reused / unavailable / failed happened.
    """

    be = bulk_extractor_path()
    if not be:
        return {
            "state": "unavailable",
            "detail": "bulk_extractor is not available on this host",
        }
    if not image_path or not os.path.exists(image_path):
        return {"state": "unavailable", "detail": "image not available"}
    if not evidence_sha256:
        return {
            "state": "unavailable",
            "detail": "the source carries no verified digest to key the scan by",
        }
    identity = _scan_cache_identity(evidence_sha256, be)
    if identity is None:
        return {
            "state": "unavailable",
            "detail": "the scanner's sealed version is unknown",
        }
    root = _scan_cache_root()
    if root is None:
        return {
            "state": "unavailable",
            "detail": "no writable scan-cache root could be established",
        }
    published = _published_scan(evidence_sha256, be)
    if published is not None:
        return {"state": "reused", "features": _published_features(published)}

    import json as _json
    import shutil as _shutil

    if progress is not None:
        try:
            progress(None, "scanning the whole image with bulk_extractor")
        except Exception:
            pass
    key = _scan_cache_key(identity)
    with _scan_lock(("prewarm", str(root), key)):
        published = _published_scan(evidence_sha256, be)
        if published is not None:
            return {"state": "reused", "features": _published_features(published)}
        staging = root / f".scan-{key}.prewarm-{os.getpid()}"
        try:
            staging.mkdir(parents=True, exist_ok=False)
            _run(image_path, be, str(staging))
            # The manifest is written LAST, so a directory carrying one is
            # complete by construction; the rename decides publication.
            (staging / _SCAN_CACHE_MANIFEST).write_text(
                _json.dumps(identity, sort_keys=True, indent=1), encoding="utf-8"
            )
            final = root / f"scan-{key}"
            os.rename(staging, final)
            return {"state": "built", "features": _published_features(final)}
        except Exception as error:
            _shutil.rmtree(staging, ignore_errors=True)
            later = _published_scan(evidence_sha256, be)
            if later is not None:
                return {"state": "reused", "features": _published_features(later)}
            return {"state": "failed", "detail": str(error)[:200]}


def bulk_extract(image_path: str, feature: str | None = None, filter: str | None = None,
                 offset: int = 0, limit: int = 100, *,
                 output_root: str | os.PathLike[str] | ControlledScratchSession | None = None,
                 evidence_sha256: str | None = None,
                 ) -> dict:
    """Run bulk_extractor over the raw image (cached) and read one feature file. Call with no
    `feature` to list what was found; then feature='windirs' for deleted filenames in
    unallocated, 'email'/'url'/'domain' for encoding-robust addresses, etc. Read-only.

    `output_root` is the ONE controlled directory the scan may write below (a
    ControlledScratchSession or the exact path of a controlled root). Without it the scan is
    refused: nothing is written to the ambient system temporary directory.

    The listing separates what the scan wrote by what it means: `available_features` are
    raw occurrence lists, `available_histograms` are the scanner's ranked, deduplicated
    summaries of the same features, `provenance` is the scan's own report, and
    `reconstructed_directories` are the files it carved back out onto disk.

    Returns {"feature", "available_features", "kind", rows + envelope}; a raw list rows
    {offset, feature, context}, a histogram rows {count, value[, utf16]}."""
    be = bulk_extractor_path()
    if not be:
        return {"error": "bulk_extractor not found. Install it (github.com/simsong/bulk_extractor) "
                         "or set DFA_BULK_EXTRACTOR. Run `dfir-agent --doctor`."}
    if not image_path or not os.path.exists(image_path):
        return {"error": "image not available."}
    try:
        root = _controlled_root(output_root)
        assert_payload_root_contained(root, subject=_PAYLOAD_SUBJECT)
    except ControlledScratchError as e:
        return {"error": f"bulk_extractor refused to run: {str(e)[:200]}"}
    except StorageContainmentError as e:
        return {"error": f"bulk_extractor refused to run: {e}"}
    key = (_identity(root), _identity(image_path))
    # Everything done for one (controlled root, image) happens under one lock:
    # the cache check, the scan, and the read.  Two concurrent calls therefore
    # cannot start two bulk_extractor processes into the same directory, and no
    # directory is removed while another thread is still reading it.
    with _scan_lock(key):
        outdir = _cached_scan(key, root)
        if outdir is None:
            # A scan of these bytes by this scanner version may already be
            # published from an earlier run or session; the feature files are
            # identical by identity, so re-reading them IS the scan.
            published = _published_scan(evidence_sha256, be)
            if published is not None:
                _remember_scan(key, published)
                outdir = published
        if outdir is None:
            try:
                outdir = Path(_run(image_path, be, str(_scan_directory(root, image_path))))
            except ControlledScratchError as e:
                return {"error": f"controlled scratch for bulk_extractor failed: {str(e)[:160]}"}
            except Exception as e:
                return tool_failure_result(e, subject=str(image_path), backend="bulk_extractor")
            if not outdir.is_dir() or not _inside(root, outdir):
                return {
                    "error": "bulk_extractor output was not written inside the controlled root."
                }
            promoted = _publish_scan(outdir, evidence_sha256, be)
            if promoted is not None:
                outdir = promoted
            _remember_scan(key, outdir)
        return _read_scan(
            outdir,
            feature,
            filter=filter,
            offset=offset,
            limit=limit,
            inventory=_remembered_inventory(key),
        )


def find_literal(image_path: str, keyword: str, *,
                 output_root: str | os.PathLike[str] | ControlledScratchSession | None = None,
                 evidence_sha256: str | None = None,
                 offset: int = 0, limit: int = 50) -> dict:
    """Scan the raw image ONCE for one literal term and return every hit it carries.

    This is the disk-wide content search. It reads the image as bytes rather than
    walking the file system, so it neither enumerates files nor stops at a file
    budget: a term that survives only inside a compressed stream, in slack, or in
    unallocated space is reported here and cannot be reported by any traversal of
    the allocated namespace, however far that traversal is allowed to run.

    `keyword` is a literal term. It is escaped before it reaches the scanner's
    regular-expression engine, so a term carrying `.` or `+` matches those
    characters and nothing wider.

    `output_root` is the ONE controlled directory the scan may write below.
    Without it the scan is refused: nothing is written to the ambient system
    temporary directory.

    Returns rows of {offset, match, context}. The offset locates the hit in the
    image; a hit recovered from a compressed stream carries the stream's offset
    and its position within the decompressed bytes, so it stays traceable to the
    evidence it came from.
    """
    be = bulk_extractor_path()
    if not be:
        return {"error": "bulk_extractor not found. Install it (github.com/simsong/bulk_extractor) "
                         "or set DFA_BULK_EXTRACTOR. Run `dfir-agent --doctor`."}
    if not image_path or not os.path.exists(image_path):
        return {"error": "image not available."}
    if not str(keyword).strip():
        return {"error": "keyword must not be empty."}
    try:
        root = _controlled_root(output_root)
        assert_payload_root_contained(root, subject=_PAYLOAD_SUBJECT)
    except ControlledScratchError as e:
        return {"error": f"bulk_extractor refused to run: {str(e)[:200]}"}
    except StorageContainmentError as e:
        return {"error": f"bulk_extractor refused to run: {e}"}
    pattern = _literal_regex(str(keyword))
    # One scan per (controlled root, image, pattern): a second search for the
    # same term reads the finished output instead of paying the pass again, and
    # a search for a different term can never be served this one's hits.
    key = (_identity(root), _identity(image_path), pattern)
    with _scan_lock(key):
        outdir = _cached_scan(key, root)
        if outdir is None:
            # The run's scratch dies with the question. A search of these bytes
            # for this pattern may already be published from an earlier question
            # or session, and its output IS this search's answer.
            published = _published_find(evidence_sha256, be, pattern)
            if published is not None:
                _remember_scan(key, published)
                outdir = published
        if outdir is None:
            try:
                outdir = Path(
                    _run_find(image_path, be, pattern, str(_find_directory(root, image_path, pattern)))
                )
            except ControlledScratchError as e:
                return {"error": f"controlled scratch for bulk_extractor failed: {str(e)[:160]}"}
            except Exception as e:
                return tool_failure_result(e, subject=str(image_path), backend="bulk_extractor")
            if not outdir.is_dir() or not _inside(root, outdir):
                return {
                    "error": "bulk_extractor output was not written inside the controlled root."
                }
            promoted = _publish_find(outdir, evidence_sha256, be, pattern)
            if promoted is not None:
                outdir = promoted
            _remember_scan(key, outdir)
        return {"keyword": str(keyword)[:120], "scanned": "whole image, allocated and unallocated",
                **_read_find(outdir, offset=offset, limit=limit,
                             inventory=_remembered_inventory(key))}
