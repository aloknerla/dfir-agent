"""Typed, path-private selection of one capture from a bound PCAP set."""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

_SAFE_COMPONENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$")
_UNSAFE_COMPONENT_CHARACTER = re.compile(r"[^A-Za-z0-9._:@/-]+")
_DERIVED_PCAP_ROLES = {"derived_pcap", "merged_pcap", "pcap_merged"}


class PcapSourceSelectionError(ValueError):
    """A caller requested a PCAP source that cannot be resolved uniquely."""


@dataclass(frozen=True, slots=True)
class PcapSourceBinding:
    """One model-addressable capture whose host path remains runtime-private."""

    component_id: str
    role: str
    path: str = field(repr=False)

    def __post_init__(self) -> None:
        if _SAFE_COMPONENT_ID.fullmatch(self.component_id) is None:
            raise ValueError("PCAP source component_id is invalid")
        if _SAFE_COMPONENT_ID.fullmatch(self.role) is None:
            raise ValueError("PCAP source role is invalid")
        if not isinstance(self.path, str) or not self.path:
            raise ValueError("PCAP source path must be non-empty text")
        if not Path(self.path).is_absolute():
            raise ValueError("PCAP source path must be absolute")

    @property
    def basename(self) -> str:
        return Path(self.path).name


@dataclass(frozen=True, slots=True)
class PcapSourceCatalog:
    """Canonical source catalog with an explicit parser-default input.

    Exact component IDs take precedence.  Otherwise a case-insensitive component
    ID or basename may be used only when it identifies exactly one binding.  No
    failed or ambiguous selection ever falls back to the default capture.  The
    default may be one explicitly selected original or a declared derived view.
    """

    bindings: tuple[PcapSourceBinding, ...]
    default_component_id: str
    default_input_component_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.bindings or any(type(item) is not PcapSourceBinding for item in self.bindings):
            raise ValueError("PCAP source catalog bindings are invalid")
        canonical = tuple(sorted(self.bindings, key=lambda item: item.component_id))
        if self.bindings != canonical:
            raise ValueError("PCAP source catalog bindings are not canonical")
        component_ids = tuple(item.component_id for item in self.bindings)
        if len(component_ids) != len(set(component_ids)):
            raise ValueError("PCAP source catalog component IDs are not unique")
        path_keys = tuple(os.path.normcase(os.path.normpath(item.path)) for item in self.bindings)
        if len(path_keys) != len(set(path_keys)):
            raise ValueError("PCAP source catalog paths are not unique")
        if self.default_component_id not in set(component_ids):
            raise ValueError("PCAP source catalog default is not bound")
        if tuple(sorted(set(self.default_input_component_ids))) != self.default_input_component_ids:
            raise ValueError("PCAP default input component IDs are not canonical")
        if not set(self.default_input_component_ids).issubset(set(component_ids)):
            raise ValueError("PCAP default inputs reference an unbound component")
        if self.default_component_id in set(self.default_input_component_ids):
            raise ValueError("PCAP default capture cannot be its own source input")
        default_role = self.default.role
        if default_role in _DERIVED_PCAP_ROLES and not self.default_input_component_ids:
            raise ValueError("A derived default PCAP must declare its original inputs")
        if default_role not in _DERIVED_PCAP_ROLES and self.default_input_component_ids:
            raise ValueError("An original default PCAP cannot declare source inputs")
        if any(
            item.role in _DERIVED_PCAP_ROLES
            and item.component_id != self.default_component_id
            for item in self.bindings
        ):
            raise ValueError("Only the default PCAP may be a derived capture")

    @classmethod
    def create(
        cls,
        *,
        sources: Mapping[str, tuple[str, str]],
        default_component_id: str,
        default_input_component_ids: tuple[str, ...] = (),
    ) -> PcapSourceCatalog:
        return cls(
            bindings=tuple(
                sorted(
                    (
                        PcapSourceBinding(component_id=component_id, path=path, role=role)
                        for component_id, (path, role) in sources.items()
                    ),
                    key=lambda item: item.component_id,
                )
            ),
            default_component_id=default_component_id,
            default_input_component_ids=tuple(sorted(set(default_input_component_ids))),
        )

    @classmethod
    def from_paths(
        cls,
        paths: Iterable[str | Path],
        *,
        default_path: str | Path | None = None,
    ) -> PcapSourceCatalog:
        """Bind several original captures without merging or discarding any.

        Component IDs are derived from filenames and made unique. Filename
        discovery cannot establish that a file is merged or otherwise derived,
        so every source receives the ``pcap`` role until explicitly declared.
        """

        resolved = tuple(
            sorted(
                {str(Path(path).expanduser().resolve()) for path in paths},
                key=str.casefold,
            )
        )
        if not resolved:
            raise ValueError("At least one PCAP source path is required")
        if default_path is None and len(resolved) > 1:
            raise ValueError("A default PCAP must be selected for a multi-capture set")
        requested_default = str(
            Path(default_path or resolved[0]).expanduser().resolve()
        )
        if requested_default not in set(resolved):
            raise ValueError("The default PCAP path is not part of the source set")

        used: set[str] = set()
        sources: dict[str, tuple[str, str]] = {}
        default_component_id = ""
        for index, path in enumerate(resolved, start=1):
            stem = _UNSAFE_COMPONENT_CHARACTER.sub("-", Path(path).stem).strip("-.")
            base_id = stem or f"capture-{index:03d}"
            component_id = base_id
            suffix = 2
            while component_id.casefold() in used:
                component_id = f"{base_id}-{suffix}"
                suffix += 1
            used.add(component_id.casefold())
            sources[component_id] = (path, "pcap")
            if path == requested_default:
                default_component_id = component_id
        return cls.create(
            sources=sources,
            default_component_id=default_component_id,
        )

    def add_original(self, path: str | Path) -> PcapSourceCatalog:
        """Return a new catalog with one explicitly attached original capture."""

        resolved = str(Path(path).expanduser().resolve())
        normalized = os.path.normcase(os.path.normpath(resolved))
        if any(
            os.path.normcase(os.path.normpath(item.path)) == normalized
            for item in self.bindings
        ):
            return self
        stem = _UNSAFE_COMPONENT_CHARACTER.sub("-", Path(resolved).stem).strip("-.")
        base_id = stem or "capture"
        used = {item.component_id.casefold() for item in self.bindings}
        component_id = base_id
        suffix = 2
        while component_id.casefold() in used:
            component_id = f"{base_id}-{suffix}"
            suffix += 1
        sources = {
            item.component_id: (item.path, item.role) for item in self.bindings
        }
        sources[component_id] = (resolved, "pcap")
        return type(self).create(
            sources=sources,
            default_component_id=self.default_component_id,
            default_input_component_ids=self.default_input_component_ids,
        )

    @property
    def component_ids(self) -> tuple[str, ...]:
        return tuple(item.component_id for item in self.bindings)

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(item.path for item in self.bindings)

    @property
    def default(self) -> PcapSourceBinding:
        return next(
            item for item in self.bindings if item.component_id == self.default_component_id
        )

    @property
    def cross_capture_component_ids(self) -> tuple[str, ...]:
        """Return every original exactly once for cross-capture correlation."""

        return tuple(
            item.component_id
            for item in self.bindings
            if item.role not in _DERIVED_PCAP_ROLES
        )

    def resolve(self, selector: str | None = None) -> PcapSourceBinding:
        if selector is None:
            return self.default
        if not isinstance(selector, str) or not selector.strip():
            raise PcapSourceSelectionError("PCAP source selector must be non-empty text")
        requested = selector.strip()
        exact = [item for item in self.bindings if item.component_id == requested]
        if exact:
            return exact[0]
        folded = requested.casefold()
        matches = [
            item
            for item in self.bindings
            if item.component_id.casefold() == folded or item.basename.casefold() == folded
        ]
        # One binding can match by both ID and basename; count distinct components.
        unique = {item.component_id: item for item in matches}
        if len(unique) == 1:
            return next(iter(unique.values()))
        if not unique:
            raise PcapSourceSelectionError(f"unknown PCAP source selector: {requested}")
        raise PcapSourceSelectionError(f"ambiguous PCAP source selector: {requested}")

    def model_hint(self) -> str:
        labels = [
            (
                f"{item.component_id} (role {item.role})"
                if item.basename == item.component_id
                else f"{item.component_id} (basename {item.basename}; role {item.role})"
            )
            for item in self.bindings
        ]
        hint = (
            "Available source selectors: "
            + ", ".join(labels)
            + f". Omitting source uses {self.default_component_id}."
        )
        if self.default_input_component_ids:
            hint += (
                f" {self.default_component_id} is a derived view of "
                + ", ".join(self.default_input_component_ids)
                + "; never aggregate it with those inputs because that would "
                "double-count the same packets."
            )
        return hint

    def available_sources(self) -> list[dict[str, object]]:
        """Return a canonical, path-free selector inventory for model discovery."""

        inventory: list[dict[str, object]] = []
        input_ids = set(self.default_input_component_ids)
        for item in self.bindings:
            row: dict[str, object] = {
                "component_id": item.component_id,
                "basename": item.basename,
                "role": item.role,
                "default": item.component_id == self.default_component_id,
            }
            if item.component_id == self.default_component_id and input_ids:
                row["derived_from_component_ids"] = list(
                    self.default_input_component_ids
                )
                row["aggregation_warning"] = (
                    "Do not add this derived capture's aggregate counts to its inputs."
                )
            elif item.component_id in input_ids:
                row["included_in_default_merged"] = self.default_component_id
                row["aggregation_warning"] = (
                    "This capture is already included in the default merged capture; "
                    "do not add their aggregate counts."
                )
            inventory.append(row)
        return inventory


__all__ = [
    "PcapSourceBinding",
    "PcapSourceCatalog",
    "PcapSourceSelectionError",
]
