"""Autonomous DFIR investigation assistant with deterministic oversight.

Importing this package seals the ambient third-party telemetry channels before
anything else in it runs.  The placement is deliberate rather than tidy: the
LangChain libraries cache each setting on first read, so removing these
variables inside ``main()`` is too late whenever an import chain reached the
library first, and the only point that reliably precedes every such chain is the
package's own import.  See :mod:`forensic_agent.core.telemetry_egress` for what
is removed and why.
"""

from forensic_agent.core.telemetry_egress import seal_telemetry_egress

__version__ = "0.1.0"

seal_telemetry_egress()
