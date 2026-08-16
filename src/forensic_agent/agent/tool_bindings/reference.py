"""Reference-knowledge functions kept separate from case-specific evidence."""

from __future__ import annotations

import time

from langchain_core.tools import StructuredTool

from forensic_agent.agent.tool_bindings.context import ToolBuildContext


def _build_hardware_vendor_tools(context: ToolBuildContext) -> list[StructuredTool]:
    """Build the hardware-address registry lookup as its own registry segment.

    Its own segment on purpose. The segment above is one of those the historical
    opt-in rebuilds byte for byte, and a function appended to it would join the
    historically reproduced palette. Only the facade's legacy index collects this
    one, so the lookup reaches a model exclusively as an operation of
    ``artifact_reference_query``.

    Nothing is withheld when the table is absent: the lookup reports that in
    band, naming the package to install and the variable that overrides it.
    Withholding it instead would make the surface depend on which packages a
    host happens to carry, and the digest with it.
    """

    _emit = context.emit

    from forensic_agent.tools.hardware_vendor import hardware_vendor as _hv

    def hardware_vendor(address: str) -> dict:
        """Name the organisation that registered a hardware address's prefix, from the
        table the installed packet analyser ships. It is a REGISTRY LOOKUP, not an
        inference: the same address and the same table always give the same answer, and
        the answer carries that table's sha256 so the reading stays attributable. Reads
        NO evidence — pass an address something else already read. A prefix the registry
        does not assign comes back with vendor=null and says so, which is a fact about
        the registry and not about the adapter.

        Args:
            address: A hardware address, or just its assignment prefix, in any
                written form: 00:1B:21:3A:4B:5C, 00-1B-21-3A-4B-5C, 001b21.
        """
        t0 = time.time()
        try:
            r = _hv(address)
        except Exception as e:
            r = {"error": str(e)[:120]}
        _emit("hardware_vendor", {"address": address}, t0)
        return r

    return [StructuredTool.from_function(hardware_vendor)]
