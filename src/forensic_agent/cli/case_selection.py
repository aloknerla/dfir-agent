"""Turning what was found, declared or chosen into one unambiguous case.

Between "the operator named something" and "the console opens it" there is a
body of validation that has nothing to do with the session's state: a directory
may hold two disk images and no way to tell which is the case; a ``case.json``
may declare a merged capture without saying what it was merged from; a RAW file
is either a disk image or a memory dump and the file itself will not say which.
Every one of those has to be resolved into a single :class:`DiscoveredCase`, and
refused with a specific reason when it cannot be.

That work lives here, apart from the session, for one reason: none of it may
touch the evidence that is already open. The console has to be able to inspect,
validate and reject a candidate case while the operator's current case stays
exactly as it was, and the surest way to guarantee that is for the validation to
have nothing to mutate. Everything below is a function from a description of
sources to a better description of the same sources, or to a ``ValueError``
naming what the operator has to decide.

:mod:`forensic_agent.cli.case_discovery` answers the neighbouring question of
what is *on* a directory; this module answers what to do about what it found.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

from forensic_agent.cli.host_paths import existing_file

if TYPE_CHECKING:
    from forensic_agent.cli.case_discovery import DiscoveredCase
    from forensic_agent.tools.pcap_sources import PcapSourceCatalog


def requires_source_resolution(discovered: DiscoveredCase) -> bool:
    """Return whether discovery left any choice requiring user intent."""

    return bool(
        discovered.ambiguous
        or len(discovered.disks) > 1
        or len(discovered.memories) > 1
        or len(discovered.pcaps) > 1
    )


def stage_overlays(
    discovered: DiscoveredCase,
    *,
    disk: Path | None,
    memory: Path | None,
    pcap: Path | None,
) -> DiscoveredCase:
    """Let an explicitly typed source settle the slot discovery left open.

    A source named together with its type has already answered the question
    discovery could not, so it *replaces* the candidates found for its slot
    rather than joining them, and it leaves the ambiguous list: a file the
    operator has classified themselves must not come back as one the console asks
    them to classify. Every slot they did not name keeps whatever was discovered
    for it.

    Returns a new case rather than editing the one it was given, so a staged
    choice can be assembled and inspected without the case already open being
    able to notice.
    """

    overlay_paths = {
        path
        for path in (
            disk,
            memory,
            pcap,
        )
        if path is not None
    }
    return replace(
        discovered,
        disk=disk or discovered.disk,
        disks=((disk,) if disk else discovered.disks),
        memory=memory or discovered.memory,
        memories=((memory,) if memory else discovered.memories),
        pcap=pcap or discovered.pcap,
        pcaps=((pcap,) if pcap else discovered.pcaps),
        ambiguous=tuple(
            source for source in discovered.ambiguous if source not in overlay_paths
        ),
    )


def resolve_staged_selector(
    candidates: Sequence[Path], selector: str, *, label: str
) -> Path:
    requested = str(selector).strip()
    if not requested:
        raise ValueError(f"{label} selector must not be empty.")
    requested_path = Path(requested).expanduser()
    normalized_requested = requested.replace("\\", "/").casefold()
    matches: list[Path] = []
    for candidate in candidates:
        if requested_path.is_absolute() and candidate == requested_path.resolve():
            matches.append(candidate)
        elif candidate.name.casefold() == requested.casefold():
            matches.append(candidate)
        elif candidate.as_posix().casefold().endswith("/" + normalized_requested):
            matches.append(candidate)
    unique = tuple(dict.fromkeys(matches))
    if len(unique) == 1:
        return unique[0]
    if not unique:
        raise ValueError(f"Unknown {label} selector: {requested}")
    raise ValueError(f"Ambiguous {label} selector: {requested}")


def resolve_staged_selection(
    discovered: DiscoveredCase,
    default_pcap: str | None = None,
    *,
    selected_disk: str | None = None,
    selected_memory: str | None = None,
    pcap_roles: Mapping[str, str] | None = None,
    merged_inputs: Mapping[str, Sequence[str]] | None = None,
    ambiguous_roles: Mapping[str, str] | None = None,
) -> tuple[DiscoveredCase, PcapSourceCatalog | None]:
    """Validate one staged multi-source case down to a single set of sources.

    This function never creates or merges captures. ``merged_pcap`` records
    only user-declared lineage for an existing derived capture.
    """

    from forensic_agent.tools.pcap_sources import PcapSourceCatalog

    role_by_path = {path: "pcap" for path in discovered.pcaps}
    for selector, role in dict(pcap_roles or {}).items():
        selected = resolve_staged_selector(
            discovered.pcaps, str(selector), label="PCAP"
        )
        normalized_role = str(role).strip().casefold()
        if normalized_role not in {"pcap", "merged_pcap", "ignore"}:
            raise ValueError("PCAP role must be pcap, merged_pcap, or ignore.")
        role_by_path[selected] = normalized_role

    active_pcaps = tuple(
        path for path in discovered.pcaps if role_by_path[path] != "ignore"
    )
    catalog: PcapSourceCatalog | None = None
    if active_pcaps:
        if default_pcap is None:
            if len(active_pcaps) != 1:
                raise ValueError(
                    "Select an explicit default PCAP for a multi-capture case."
                )
            default_path = active_pcaps[0]
        else:
            default_path = resolve_staged_selector(
                active_pcaps, default_pcap, label="default PCAP"
            )
        base_catalog = PcapSourceCatalog.from_paths(
            active_pcaps,
            default_path=default_path,
        )
        id_by_path = {
            Path(binding.path): binding.component_id
            for binding in base_catalog.bindings
        }
        declared_inputs: tuple[str, ...] = ()
        merged_declarations = dict(merged_inputs or {})
        if merged_declarations:
            if len(merged_declarations) != 1:
                raise ValueError(
                    "Only the default merged PCAP may declare source inputs."
                )
            merged_selector, input_selectors = next(
                iter(merged_declarations.items())
            )
            merged_path = resolve_staged_selector(
                active_pcaps,
                str(merged_selector),
                label="merged PCAP",
            )
            if merged_path != default_path:
                raise ValueError("The declared merged PCAP must be the default.")
            input_paths = tuple(
                resolve_staged_selector(
                    active_pcaps,
                    str(selector),
                    label="merged PCAP input",
                )
                for selector in input_selectors
            )
            if not input_paths or merged_path in set(input_paths):
                raise ValueError(
                    "A merged PCAP must name one or more distinct original inputs."
                )
            if len(set(input_paths)) != len(input_paths):
                raise ValueError("Merged PCAP inputs must not contain duplicates.")
            if any(role_by_path[path] != "pcap" for path in input_paths):
                raise ValueError("Merged PCAP inputs must have the pcap role.")
            declared_inputs = tuple(
                sorted(id_by_path[path] for path in input_paths)
            )

        if role_by_path[default_path] == "merged_pcap" and not declared_inputs:
            raise ValueError(
                "A merged_pcap default must declare its original inputs."
            )
        if role_by_path[default_path] == "pcap" and declared_inputs:
            raise ValueError("A pcap default cannot declare merged inputs.")
        if any(
            role == "merged_pcap" and path != default_path
            for path, role in role_by_path.items()
            if path in set(active_pcaps)
        ):
            raise ValueError("Only the default PCAP may have the merged_pcap role.")
        catalog = PcapSourceCatalog.create(
            sources={
                binding.component_id: (
                    binding.path,
                    role_by_path[Path(binding.path)],
                )
                for binding in base_catalog.bindings
            },
            default_component_id=base_catalog.default_component_id,
            default_input_component_ids=declared_inputs,
        )

    classified: dict[Path, str] = {}
    for selector, role in dict(ambiguous_roles or {}).items():
        selected = resolve_staged_selector(
            discovered.ambiguous,
            str(selector),
            label="RAW/BIN",
        )
        normalized_role = str(role).strip().casefold()
        if normalized_role not in {"disk", "memory", "ignore"}:
            raise ValueError("RAW/BIN role must be disk, memory, or ignore.")
        classified[selected] = normalized_role
    missing = [path for path in discovered.ambiguous if path not in classified]
    if missing:
        raise ValueError(
            "Classify or explicitly ignore every ambiguous RAW/BIN source: "
            + ", ".join(path.name for path in missing)
        )
    classified_disks = [
        path for path, role in classified.items() if role == "disk"
    ]
    classified_memories = [
        path for path, role in classified.items() if role == "memory"
    ]

    def selected_source(
        candidates: Sequence[Path],
        selector: str | None,
        *,
        label: str,
    ) -> Path | None:
        unique = tuple(dict.fromkeys(candidates))
        if not unique:
            if selector is not None:
                raise ValueError(f"The staged case contains no {label} source.")
            return None
        if selector is None:
            if len(unique) != 1:
                raise ValueError(
                    f"Select an explicit {label} for this multi-source case."
                )
            return unique[0]
        return resolve_staged_selector(unique, selector, label=label)

    disk_path = selected_source(
        (*discovered.disks, *classified_disks),
        selected_disk,
        label="disk image",
    )
    memory_path = selected_source(
        (*discovered.memories, *classified_memories),
        selected_memory,
        label="memory dump",
    )
    resolved = replace(
        discovered,
        disk=disk_path,
        disks=((disk_path,) if disk_path else ()),
        memory=memory_path,
        memories=((memory_path,) if memory_path else ()),
    )
    return resolved, catalog


def pcap_catalog_from_manifest(
    declaration: object,
    base: Path,
    *,
    evidence_root: Path | None,
) -> PcapSourceCatalog:
    """Validate a path-private multi-capture declaration from ``case.json``."""

    from forensic_agent.tools.pcap_sources import PcapSourceCatalog

    if not isinstance(declaration, Mapping):
        raise ValueError("case.json field pcaps must be an object.")
    unknown = set(declaration) - {"default", "sources"}
    if unknown:
        raise ValueError(
            "Unknown case.json pcaps fields: " + ", ".join(sorted(unknown))
        )
    default_id = declaration.get("default")
    sources_raw = declaration.get("sources")
    if not isinstance(default_id, str) or not default_id.strip():
        raise ValueError("case.json pcaps.default must be a component ID.")
    if not isinstance(sources_raw, list) or not sources_raw:
        raise ValueError("case.json pcaps.sources must be a non-empty list.")

    sources: dict[str, tuple[str, str]] = {}
    inputs_by_id: dict[str, tuple[str, ...]] = {}
    for item in sources_raw:
        if not isinstance(item, Mapping):
            raise ValueError("Each case.json PCAP source must be an object.")
        item_unknown = set(item) - {"id", "path", "role", "inputs"}
        if item_unknown:
            raise ValueError(
                "Unknown case.json PCAP source fields: "
                + ", ".join(sorted(item_unknown))
            )
        component_id = item.get("id")
        source_path = item.get("path")
        role = item.get("role", "pcap")
        if not isinstance(component_id, str) or not component_id.strip():
            raise ValueError("A case.json PCAP source id must be non-empty text.")
        component_id = component_id.strip()
        if component_id in sources:
            raise ValueError("case.json PCAP source IDs must be unique.")
        if not isinstance(source_path, str) or not source_path.strip():
            raise ValueError("A case.json PCAP source path must be non-empty text.")
        if role not in {"pcap", "merged_pcap"}:
            raise ValueError("A case.json PCAP role must be pcap or merged_pcap.")
        requested_path = Path(source_path)
        resolved = (
            (base / requested_path).resolve()
            if not requested_path.is_absolute()
            else requested_path.resolve()
        )
        checked = existing_file(
            str(resolved), label="PCAP source", evidence_root=evidence_root
        )
        sources[component_id] = (checked, role)
        inputs = item.get("inputs", [])
        if not isinstance(inputs, list) or any(
            not isinstance(value, str) or not value.strip() for value in inputs
        ):
            raise ValueError("case.json PCAP inputs must be component IDs.")
        inputs_by_id[component_id] = tuple(
            sorted({str(value).strip() for value in inputs})
        )

    selected_default = default_id.strip()
    if selected_default not in sources:
        raise ValueError("case.json pcaps.default is not a declared source.")
    default_role = sources[selected_default][1]
    default_inputs = inputs_by_id[selected_default]
    if default_role == "merged_pcap":
        if not default_inputs:
            raise ValueError("A merged_pcap source must declare original inputs.")
        if selected_default in set(default_inputs):
            raise ValueError("A merged_pcap cannot include itself as an input.")
        if not set(default_inputs).issubset(set(sources)):
            raise ValueError("A merged_pcap input is not a declared source.")
        if any(sources[item][1] != "pcap" for item in default_inputs):
            raise ValueError("Merged PCAP inputs must have the pcap role.")
    elif default_inputs:
        raise ValueError("A pcap default cannot declare merged inputs.")
    if any(
        role == "merged_pcap" and component_id != selected_default
        for component_id, (_path, role) in sources.items()
    ):
        raise ValueError("Only the default PCAP may have the merged_pcap role.")
    if any(inputs_by_id[item] for item in inputs_by_id if item != selected_default):
        raise ValueError("Only the default merged PCAP may declare inputs.")
    return PcapSourceCatalog.create(
        sources=sources,
        default_component_id=selected_default,
        default_input_component_ids=default_inputs,
    )


def case_from_manifest(
    candidate: Path,
    *,
    evidence_root: Path | None,
) -> tuple[DiscoveredCase, PcapSourceCatalog | None, str | None, str]:
    """Read one ``case.json`` into the case it declares.

    Returns the discovered sources, their capture catalogue, the case identity
    the manifest declared (``None`` when it declared none, in which case the
    identity is derived from the sources like any other case), and the label the
    case is shown under.
    """

    raw = json.loads(candidate.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("case.json must contain a JSON object.")
    allowed = {"case_id", "disk", "memory", "pcap", "pcaps"}
    unknown = set(raw) - allowed
    if unknown:
        raise ValueError("Unknown case.json fields: " + ", ".join(sorted(unknown)))
    base = candidate.parent

    def source(name: str) -> Path | None:
        value = raw.get(name)
        if value is None:
            return None
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"case.json field {name} must be a path.")
        resolved = (
            (base / value).resolve()
            if not Path(value).is_absolute()
            else Path(value).resolve()
        )
        return Path(
            existing_file(str(resolved), label=name, evidence_root=evidence_root)
        )

    if raw.get("pcap") is not None and raw.get("pcaps") is not None:
        raise ValueError("case.json cannot declare both pcap and pcaps.")
    legacy_pcap = source("pcap")
    pcap_catalog = None
    if legacy_pcap is not None:
        from forensic_agent.tools.pcap_sources import PcapSourceCatalog

        pcap_catalog = PcapSourceCatalog.from_paths(
            (legacy_pcap,),
            default_path=legacy_pcap,
        )
    elif raw.get("pcaps") is not None:
        pcap_catalog = pcap_catalog_from_manifest(
            raw["pcaps"], base, evidence_root=evidence_root
        )

    from forensic_agent.cli.case_discovery import DiscoveredCase

    manifest_id = raw.get("case_id")
    if manifest_id is not None and (
        not isinstance(manifest_id, str) or not manifest_id.strip()
    ):
        raise ValueError("case.json field case_id must be non-empty text.")
    discovered = DiscoveredCase(
        root=base,
        disk=source("disk"),
        memory=source("memory"),
        pcap=(Path(pcap_catalog.default.path) if pcap_catalog else None),
        pcaps=(
            tuple(Path(item.path) for item in pcap_catalog.bindings)
            if pcap_catalog
            else ()
        ),
    )
    return (
        discovered,
        pcap_catalog,
        (manifest_id.strip() if manifest_id else None),
        base.name,
    )


def case_from_evidence_file(
    candidate: Path,
) -> tuple[DiscoveredCase, PcapSourceCatalog | None, str]:
    """Read one evidence file as the whole case it stands for.

    A RAW or BIN file is the one shape this cannot settle: the same bytes are a
    disk image or a memory dump depending on how they were taken, and nothing in
    the file says which. It therefore comes back as an *ambiguous* source, which
    the caller stages for the operator to classify rather than opening.
    """

    suffix = candidate.suffix.casefold()
    from forensic_agent.cli.case_discovery import (
        DiscoveredCase,
        is_compound_archive_volume,
    )
    from forensic_agent.core.evidence_source import (
        ewf_segment_paths,
        is_ewf_source,
    )

    if is_compound_archive_volume(candidate):
        raise ValueError(
            "Multipart archive volumes cannot be opened as disk images. "
            "Open the archive through a supported artifact workflow."
        )
    if suffix in {".e01", ".ex01"}:
        return (
            DiscoveredCase(root=candidate.parent, disk=candidate),
            None,
            candidate.name,
        )
    if is_ewf_source(candidate):
        segments = ewf_segment_paths(candidate)
        primary = segments[0]
        return (
            DiscoveredCase(root=primary.parent, disk=primary),
            None,
            primary.name,
        )
    if suffix in {
        ".dd",
        ".img",
        ".001",
        ".iso",
        ".vhd",
        ".vhdx",
    }:
        return (
            DiscoveredCase(root=candidate.parent, disk=candidate),
            None,
            candidate.name,
        )
    if suffix in {".mem", ".vmem", ".dmp"}:
        return (
            DiscoveredCase(root=candidate.parent, memory=candidate),
            None,
            candidate.name,
        )
    if suffix in {".pcap", ".pcapng"}:
        from forensic_agent.cli.evidence_identity import (
            build_interactive_pcap_catalog,
        )

        catalog = build_interactive_pcap_catalog(str(candidate))
        assert catalog is not None
        return (
            DiscoveredCase(
                root=candidate.parent,
                pcap=candidate,
                pcaps=(candidate,),
            ),
            catalog,
            candidate.name,
        )
    if suffix in {".raw", ".bin"}:
        return (
            DiscoveredCase(
                root=candidate.parent,
                ambiguous=(candidate,),
            ),
            None,
            candidate.name,
        )
    raise ValueError("Unsupported forensic evidence type.")
