"""Functions for network-traffic analysis and reconstruction."""

from __future__ import annotations

import time
from collections.abc import Mapping
from typing import Literal, cast

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field, create_model

from forensic_agent.agent.tool_bindings.context import ToolBuildContext
from forensic_agent.core.repro import canonical_json, sha256_hex
from forensic_agent.tools.pcap_sources import (
    PcapSourceBinding,
)


def _build_pcap_tools(context: ToolBuildContext) -> list[StructuredTool]:
    """Build the corresponding registry segment without changing model schemas."""

    pcap_sources = context.pcap_sources
    _selected_pcap = context.selected_pcap
    _with_pcap_component = context.with_pcap_component
    _emit = context.emit
    tools: list[StructuredTool] = []

    from forensic_agent.tools.pcap_tool import (
        cross_capture_host_linkage as _cross_capture_host_linkage,
    )
    from forensic_agent.tools.pcap_tool import pcap_query as _pq

    def pcap_query(
        query: str = "dns",
        limit: int = 100,
        fields: list | None = None,
        display_filter: str | None = None,
        stat: str | None = None,
        proto: Literal["dicom", "ftp", "http", "imf", "smb", "tftp"] | None = None,
        stream: int | None = None,
        transport: str = "tcp",
        save_path: str | None = None,
        offset: int = 0,
        filter: str | None = None,
        source: str | None = None,
        metadata_only: bool = True,
    ) -> dict:
        """Analyze a bound network capture with tshark.

                Supported curated views are dns, dns_exfil, http, ftp, telnet,
                ftp_objects, http_objects, protocols, conversations, endpoints,
                and cross_capture_linkage. The general
                views are fields, stat, export, and follow:

                * fields extracts the supplied tshark field names after an optional
                  display_filter. It returns positional rows and self-describing
                  named_rows. When both endpoints are selected, application records
                  include endpoint_roles. FTP request fields such as ip.src, ip.dst,
                  ftp.request.command, and ftp.request.arg also produce a deterministic
                  ftp_session_summary; named_rows remains its packet-level audit trail.
                  The summary retains both endpoint roles, so never omit the server
                  address when it is present in the returned data.
                * stat runs the supplied tshark -z statistic.
                * export supports only dicom, ftp, http, imf, smb, and tftp. FTP export
                  contains transferred objects only, not control-channel records. It
                  reassembles FTP data streams and may return archive-member metadata,
                  archive_member_summary, and a deterministic match_with descriptor.
                  Exported MZ/PE objects may include bounded static metadata and an
                  executable_summary. Recovered code is never executed. For Telnet or
                  any other protocol, NEVER use query="export"; query="fields" can
                  extract protocol fields such as telnet.data.
                * follow reassembles one selected TCP or UDP stream.
                * cross_capture_linkage compares all bound original captures and
                  returns common link-layer and same-side IPv4 associations together
                  with an explicit ambiguity flag.

                Export results are paginated. metadata_only defaults to true, which
                removes reconstructed payload bytes before return and exposes no object
                path. A false value writes only to controlled scratch storage.

                Args:
                    query: The view to run. Curated: dns, dns_exfil, http, ftp,
                        telnet, ftp_objects, http_objects, protocols, conversations,
                        endpoints, cross_capture_linkage. Pass-through:
                        fields (with fields=), stat (with stat=), export (with proto=).
                    limit: Rows per page, default 100.
                    fields: tshark field names to extract when query="fields", for
                        example ["ip.src","ip.dst","ftp.request.command"].
                    display_filter: A tshark display filter applied before extraction,
                        for example "ftp" or "tcp.port==21". This is real tshark filter
                        syntax, unlike the substring `filter` argument.
                    stat: The -z statistic to run when query="stat", for example
                        "endpoints,eth", "conv,eth" or "io,phs".
                    proto: Protocol whose transferred objects to export when
                        query="export". Only dicom, ftp, http, imf, smb and tftp.
                    stream: Index of a single TCP or UDP stream to confine the view to.
                    transport: Transport for stream selection, tcp or udp, default tcp.
                    save_path: Directory for exported objects. Omit to use the run's
                        controlled scratch, which is the normal choice.
                    offset: Index of the first row to return; continue from the
                        previous page's next_offset.
                    filter: Plain substring matched against returned rows. Not a
                        tshark expression; use display_filter for that.
                    source: Component id of the capture to read when several are
                        bound. Omit to use the default capture. Use
                        query="cross_capture_linkage" to correlate across all of them
                        rather than reading them one at a time.
                    metadata_only: Return object metadata rather than writing payload
                        bytes. Default true.
                """
        t0 = time.time()
        selected_binding: PcapSourceBinding | None = None
        r: dict[str, object]
        if query.casefold() == "cross_capture_linkage":
            if source is not None:
                r = {
                    "error": (
                        "cross_capture_linkage uses every bound original capture; "
                        "omit source"
                    )
                }
            elif pcap_sources is None:
                r = {
                    "error": (
                        "cross_capture_linkage requires a typed multi-capture source set"
                    )
                }
            else:
                component_ids = pcap_sources.cross_capture_component_ids
                bindings = tuple(pcap_sources.resolve(item) for item in component_ids)
                r = _cross_capture_host_linkage(
                    [(item.component_id, item.path) for item in bindings]
                )
                if isinstance(r, Mapping):
                    r = {
                        **dict(r),
                        "available_sources": pcap_sources.available_sources(),
                        "source_input_component_ids": list(component_ids),
                    }
        else:
            selected_path, selected_binding = _selected_pcap(source)
            if metadata_only is not True:
                r = {
                    "error": (
                        "Materializing reconstructed network payloads is not "
                        "available to the model; use metadata_only=true."
                    ),
                    "deterministic_error": True,
                }
            else:
                r = _pq(
                    selected_path,
                    query,
                    limit,
                    save_path=save_path,
                    fields=fields,
                    display_filter=display_filter,
                    stat=stat,
                    proto=proto,
                    stream=stream,
                    transport=transport,
                    offset=offset,
                    filter=filter,
                    metadata_only=True,
                )
            r = _with_pcap_component(r, selected_binding)
        _emit(
            "pcap_query",
            {
                "query": query,
                "fields": fields,
                "stat": stat,
                "proto": proto,
                "stream": stream,
                "metadata_only": metadata_only,
                "source": (
                    selected_binding.component_id if selected_binding is not None else None
                ),
            },
            t0,
        )
        return r

    pcap_description = pcap_query.__doc__ or "Analyze one bound PCAP source."
    pcap_args_schema = None
    if pcap_sources is not None:
        pcap_description += "\n\n" + pcap_sources.model_hint()
        # The source catalog is already fixed before the model-visible
        # surface is built.  Expose those exact path-private component
        # IDs as an enum instead of asking the model to transcribe an
        # unconstrained string.  This rejects invented or mistyped
        # selectors before any evidence file can be opened and still
        # preserves the safe ``None`` default selected for this case.
        inferred_schema = StructuredTool.from_function(pcap_query).args_schema
        if not isinstance(inferred_schema, type) or not issubclass(
            inferred_schema, BaseModel
        ):
            raise TypeError("pcap_query did not produce a Pydantic argument schema")
        basename_counts: dict[str, int] = {}
        for binding in pcap_sources.bindings:
            folded_basename = binding.basename.casefold()
            basename_counts[folded_basename] = basename_counts.get(folded_basename, 0) + 1
        source_selectors = tuple(
            sorted(
                {
                    *pcap_sources.component_ids,
                    *(
                        binding.basename
                        for binding in pcap_sources.bindings
                        if basename_counts[binding.basename.casefold()] == 1
                    ),
                }
            )
        )
        source_selector = cast(type[object], Literal.__getitem__(source_selectors))
        schema_suffix = sha256_hex(canonical_json(source_selectors))[:12]
        pcap_args_schema = create_model(
            f"PcapQueryArguments_{schema_suffix}",
            __base__=inferred_schema,
            source=(
                source_selector | None,
                Field(
                    default=None,
                    description=(
                        "Exact bound PCAP component ID. Omit this field to use the "
                        f"default {pcap_sources.default_component_id}. Never invent a "
                        "selector."
                    ),
                ),
            ),
        )
    tools.append(
        StructuredTool.from_function(
            pcap_query,
            description=pcap_description,
            args_schema=pcap_args_schema,
        )
    )

    return tools
