"""What this run reconstructed out of evidence, and which call produced it.

A reconstruction is not case evidence and must never be treated as though the
case bundle had carried it: the bundle digest is the case identity, and a run
that quietly added a component to it would be changing what the case *is* while
examining it.  Nor is a reconstruction an ordinary host file — it exists only
because an attested call over attested evidence produced it.

So it is neither, and this module names the third thing.  Each entry ties one
container-private path to the call that wrote it: that call's invocation id and
payload digest, which is exactly what :class:`ResultInput` needs to make a later
result a DERIVED result whose parent the final check can resolve.  A function
reading a path with no entry here reads something this run did not produce, and
is refused.

Registration is by content: two calls that reconstruct the same bytes to the
same path are the same artifact, and re-registering keeps the FIRST producer,
because the parent of an artifact is the call that created it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DerivedArtifact:
    """One artifact this run reconstructed, and the call that produced it."""

    path: str
    case_id: str
    producing_invocation_id: str
    producing_payload_sha256: str
    producing_tool: str

    def result_input_fields(self) -> dict[str, str]:
        """The parent identity, in the shape the result contract cites it."""

        return {
            "case_id": self.case_id,
            "invocation_id": self.producing_invocation_id,
            "payload_sha256": self.producing_payload_sha256,
        }


class DerivedArtifactCatalog:
    """Run-scoped record of reconstructions, keyed by their absolute path."""

    def __init__(self) -> None:
        self._by_path: dict[str, DerivedArtifact] = {}

    @staticmethod
    def _key(path: object) -> str:
        text = str(path or "").strip()
        return os.path.abspath(text) if text else ""

    def register(
        self,
        path: object,
        *,
        case_id: str,
        producing_invocation_id: str,
        producing_payload_sha256: str,
        producing_tool: str,
    ) -> DerivedArtifact | None:
        """Record the call that produced ``path``; the first producer wins."""

        key = self._key(path)
        if not key or not case_id or not producing_invocation_id:
            return None
        if len(producing_payload_sha256 or "") != 64:
            return None
        existing = self._by_path.get(key)
        if existing is not None:
            return existing
        entry = DerivedArtifact(
            path=key,
            case_id=case_id,
            producing_invocation_id=producing_invocation_id,
            producing_payload_sha256=producing_payload_sha256,
            producing_tool=producing_tool,
        )
        self._by_path[key] = entry
        return entry

    def resolve(self, path: object) -> DerivedArtifact | None:
        """The artifact this run produced at ``path``, or ``None``."""

        key = self._key(path)
        return self._by_path.get(key) if key else None

    def __len__(self) -> int:
        return len(self._by_path)


#: Argument names through which a function names the artifact it is to read.
DERIVED_PATH_ARGUMENTS: tuple[str, ...] = ("archive_path", "image_path", "path")


def named_artifact_path(arguments: object) -> str:
    """The path a call names, read from the first argument that carries one."""

    if not hasattr(arguments, "get"):
        return ""
    for name in DERIVED_PATH_ARGUMENTS:
        value = arguments.get(name)  # type: ignore[union-attr]
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


__all__ = [
    "DERIVED_PATH_ARGUMENTS",
    "DerivedArtifact",
    "DerivedArtifactCatalog",
    "named_artifact_path",
]
