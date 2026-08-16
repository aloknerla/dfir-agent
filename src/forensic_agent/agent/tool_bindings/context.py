"""Shared immutable context for constructing forensic functions."""

from __future__ import annotations

import os
import time
from collections.abc import Callable, Collection, Iterator, Mapping
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from typing import Any

from forensic_agent.core.controlled_scratch import ControlledScratchSession
from forensic_agent.tools.pcap_sources import (
    PcapSourceBinding,
    PcapSourceCatalog,
    PcapSourceSelectionError,
)


def _validate_pcap_binding(
    pcap_path: str | None,
    pcap_sources: PcapSourceCatalog | None,
) -> None:
    """Verify that the supplied path matches the typed source catalog."""

    if pcap_sources is None:
        return
    if type(pcap_sources) is not PcapSourceCatalog:
        raise TypeError("pcap_sources must use the exact typed source catalog")
    if not pcap_path:
        raise ValueError("a PCAP source catalog requires a default pcap_path")
    if os.path.normcase(os.path.normpath(pcap_sources.default.path)) != os.path.normcase(
        os.path.normpath(pcap_path)
    ):
        raise ValueError("the default pcap_path differs from the PCAP source catalog")


#: What a long operation reports through: a fraction where one can be estimated
#: and ``None`` where it cannot, plus a short detail.  Structurally the sink
#: :func:`forensic_agent.cli.progress.reporting` yields, spelled here as a plain
#: callable so this layer never imports the console.
ProgressSink = Callable[[float | None, str | None], None]

#: How a binding asks for one, named: a factory taking the label the operator
#: reads and yielding a sink for the length of the operation.
ProgressReporter = Callable[[str], AbstractContextManager[ProgressSink]]


def _unreported(fraction: float | None = None, detail: str | None = None) -> None:
    """The sink used when nobody is watching, so an operation needs no branch."""


@contextmanager
def _unwatched(label: str) -> Iterator[ProgressSink]:
    """The reporter used when no operator sink is bound: silent, and still valid."""

    del label
    yield _unreported


@dataclass(frozen=True, slots=True)
class ToolBuildContext:
    """Dependencies shared by domain-specific function builders."""

    disk: Any
    memory_path: str | None
    pcap_path: str | None
    controlled_scratch: ControlledScratchSession | None
    tool_argument_allowlists: Mapping[str, Mapping[str, Collection[object]]] | None
    pcap_sources: PcapSourceCatalog | None
    #: ``(name, arguments, elapsed_s, refused)``. The last says whether the
    #: surface refused the call instead of performing it; a UI that shows only
    #: the first three would render a refusal as an ordinary completed call.
    # The third argument is the elapsed time, and it is None for the "still
    # running" event ``begin`` emits before a call can report a result.
    on_tool: Callable[[str, object, float | None, bool], None] | None
    #: Runtime-owned resolver of a record citation:
    #: ``(source_invocation_id, source_payload_sha256, source_field) -> value``.
    #: A citing operation takes a REFERENCE to an earlier result instead of
    #: retyped text, so the value has to be fetched by the runtime that holds
    #: those results.  ``source_field`` is a path in the grammar of
    #: :mod:`forensic_agent.core.result_navigation`.  The resolver must verify
    #: that the digest binds the cited result before returning, and raise
    #: otherwise.  ``None`` means no lineage store is bound to this surface, and
    #: every citing operation refuses deterministically — which is a real
    #: capability gap, not a safe default, so a run that offers those operations
    #: is expected to bind one.
    cited_value_resolver: Callable[[str, str, str | None], str] | None = None
    #: Runtime-owned factory for an OPERATOR-facing progress sink: given the
    #: label a human reads, it yields a sink for the length of one operation.
    #: An extraction that runs for a quarter of an hour is indistinguishable
    #: from a hung console without one, so an operation that can take minutes
    #: asks for it here.  Nothing it is told may enter a result or a receipt:
    #: how far a local process has got depends on the host, and the record must
    #: not.  ``None`` means nobody is watching, which is a legitimate state —
    #: a batch run has no console — and the operation runs silently rather than
    #: refusing.
    operator_progress: ProgressReporter | None = None
    #: Content digest of :attr:`memory_path`, when the caller that opened the
    #: case computed one.  A memory dump carries no attestation digest of its
    #: own, so an operation whose cross-run cache is keyed by evidence content
    #: has nothing to key a memory image by unless the digest is handed down
    #: here; without it those operations rescan, exactly as before.
    memory_sha256: str | None = None

    def watch(self, label: str) -> AbstractContextManager[ProgressSink]:
        """The reporter for one long operation, or a silent one if none is bound."""

        if self.operator_progress is None:
            return _unwatched(label)
        return self.operator_progress(label)

    def begin(self, name: str, args: object) -> None:
        """Announce that a long call has STARTED, before it can report a result.

        A slow subprocess (a Volatility scan over a multi-gigabyte image)
        otherwise leaves the feed empty until it returns, indistinguishable
        from a frozen console. The event travels on the same ``on_tool``
        channel with ``elapsed_s=None`` as the sole "still running" marker;
        a feed that shows only settled calls simply ignores it, and the
        matching :meth:`emit` later settles the same call.
        """

        if self.on_tool:
            try:
                self.on_tool(name, args, None, False)
            except Exception:
                pass

    def emit(
        self, name: str, args: object, started_at: float, *, refused: bool = False
    ) -> None:
        """Send an event to the user interface without affecting the investigation.

        ``refused`` travels as its own fact rather than as a synthetic argument.
        A marker smuggled in beside the real arguments read as something the
        model had passed, and the feed rendered it as one.
        """

        if self.on_tool:
            try:
                self.on_tool(name, args, time.time() - started_at, refused)
            except Exception:
                pass

    @staticmethod
    def items_as_rows(value: Any) -> Any:
        """Expose repeatable records to the central byte guard as a row envelope."""

        if not isinstance(value, Mapping) or not isinstance(value.get("items"), list):
            return value
        normalized = dict(value)
        normalized["rows"] = normalized.pop("items")
        return normalized

    def selected_pcap(self, source: str | None) -> tuple[str, PcapSourceBinding | None]:
        """Resolve an allowed network source without guessing its path."""

        if self.pcap_sources is None:
            if source is not None:
                raise PcapSourceSelectionError(
                    "PCAP source selection is unavailable for this evidence input"
                )
            if self.pcap_path is None:
                raise PcapSourceSelectionError("no PCAP evidence input is bound")
            return self.pcap_path, None
        binding = self.pcap_sources.resolve(source)
        return binding.path, binding

    def with_pcap_component(
        self,
        result: Any,
        binding: PcapSourceBinding | None,
    ) -> Any:
        """Attach component identity to a typed network-analysis finding."""

        if (
            binding is None
            or self.pcap_sources is None
            or not isinstance(result, Mapping)
        ):
            return result
        annotated = dict(result)
        available_sources = self.pcap_sources.available_sources()
        annotated["source_component"] = next(
            item
            for item in available_sources
            if item["component_id"] == binding.component_id
        )
        annotated["available_sources"] = available_sources
        if binding.component_id == self.pcap_sources.default_component_id:
            annotated["source_input_component_ids"] = list(
                self.pcap_sources.default_input_component_ids
            )
        return annotated
