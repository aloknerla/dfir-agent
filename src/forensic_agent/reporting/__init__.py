"""Public reporting API with lazy imports for optional visualization support."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from forensic_agent.reporting.trace_record import (
        controlled_run_trace_record,
        load_trace_record,
    )
    from forensic_agent.reporting.trace_svg import (
        export_investigation_diagram,
        export_trace_svg,
    )

__all__ = [
    "controlled_run_trace_record",
    "export_investigation_diagram",
    "export_trace_svg",
    "load_trace_record",
]


def __getattr__(name: str) -> Any:
    """Load trace helpers only when callers request the compatibility API."""
    if name in {"controlled_run_trace_record", "load_trace_record"}:
        from forensic_agent.reporting import trace_record

        value = getattr(trace_record, name)
    elif name in {"export_investigation_diagram", "export_trace_svg"}:
        from forensic_agent.reporting import trace_svg

        value = getattr(trace_svg, name)
    else:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    globals()[name] = value
    return value
