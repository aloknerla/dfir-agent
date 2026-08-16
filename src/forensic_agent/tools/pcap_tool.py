"""Network forensics tool — wraps Wireshark's `tshark`.

tshark is Wireshark's command-line packet analyzer. The agent never parses
packets itself; tshark reads the capture and returns structured output for the
model to interpret. The source capture is opened read-only.

The `dns_exfil` view additionally reconstructs data smuggled over DNS: tshark
extracts the query names, then a deterministic decoder reassembles indexed
sub-domain chunks (hex / UTF-16 / base64) into the exfiltrated payload.
"""
from __future__ import annotations

import base64
import collections
import hashlib
import ipaddress
import json
import mimetypes
import os
import re
import shutil
import tempfile

from forensic_agent.core.environ import tshark_path
from forensic_agent.core.storage_containment import (
    EvidenceWriteScope,
    StorageContainmentError,
    acquire_evidence_write_dir,
    payload_scratch_root,
)
from forensic_agent.core.tool_failure import tool_failure_result
from forensic_agent.core.toolkit import run_external
from forensic_agent.tools import public_suffix
from forensic_agent.tools.payload_identification import (
    extract_embedded_strings,
    identification_field_names,
    identify_payload,
)


def _contained_scratch(prefix: str, *, subject: str) -> str:
    """A fresh scratch directory whose base has passed the write-scope facade.

    tshark writes derived working files here — a merged capture, exported HTTP
    objects, a followed stream — all reconstructed out of the evidence. The
    production runner rebinds ``tempfile`` into controlled scratch for the whole
    tool-executing region, so this base is already contained on every model
    path; routing it through the facade under the recorded weak scope makes that
    containment mandatory and explicit rather than an implicit consequence a
    future caller could drop.
    """

    base = tempfile.gettempdir()
    acquire_evidence_write_dir(base, subject=subject, scope=EvidenceWriteScope.NOT_HOST_SHARED)
    return tempfile.mkdtemp(prefix=prefix, dir=base)


# Backwards-compatible private export.  New callers should import the public
# name directly from ``payload_identification``.
_embedded_strings = extract_embedded_strings

#: libmagic's own media types for the two things this module routes on, in every
#: spelling the installed versions use: file 5.44 answers ``application/x-dosexec``
#: for a DOS header alone and ``application/vnd.microsoft.portable-executable``
#: once the PE header is present.  Routing on a media type rather than on the
#: shape of a description keeps the decision in libmagic's vocabulary.
_PE_MEDIA_TYPES = frozenset(
    {"application/x-dosexec", "application/vnd.microsoft.portable-executable"}
)
_ARCHIVE_MEDIA_TYPES = frozenset(
    {
        "application/zip",
        "application/x-7z-compressed",
        "application/x-rar",
        "application/vnd.rar",
        "application/gzip",
        "application/x-gzip",
    }
)

FIELD_QUERIES = {
    "dns": ["-Y", "dns", "-T", "fields", "-e", "frame.number", "-e", "ip.src",
            "-e", "ip.dst", "-e", "dns.qry.name", "-e", "dns.qry.type"],
    "http": ["-Y", "http.request", "-T", "fields", "-e", "ip.dst",
             "-e", "http.host", "-e", "http.request.uri"],
    "http_auth": ["-Y", "http.request and http.authorization", "-T", "fields",
                  "-e", "ip.dst", "-e", "http.authorization"],
}
CURATED_PROTOCOL_FIELDS = {
    "ftp": [
        "frame.number",
        "frame.time_epoch",
        "eth.src",
        "eth.dst",
        "ip.src",
        "ip.dst",
        "tcp.stream",
        "ftp.request.command",
        "ftp.request.arg",
        "ftp.response.code",
        "ftp.response.arg",
    ],
    "telnet": [
        "frame.number",
        "frame.time_epoch",
        "eth.src",
        "eth.dst",
        "ip.src",
        "ip.dst",
        "tcp.stream",
        "telnet.data",
    ],
}
STAT_QUERIES = {
    "protocols": ["-q", "-z", "io,phs"],
    "conversations": ["-q", "-z", "conv,ip"],
    "endpoints": ["-q", "-z", "endpoints,ip"],
}

#: Every ``query`` value ``pcap_query`` accepts at this (tool) layer.  Single
#: source of truth: the unknown-query guard rejects anything not in this set, so
#: the accepted operations cannot silently drift from what is advertised.  The
#: data-driven views come straight from the registries above; the remaining names
#: are the operations dispatched by explicit branches (the pass-through ``fields``
#: / ``stat`` / ``export`` / ``follow`` routes, the ``*_objects`` export aliases,
#: and ``dns_exfil``).  The model-visible binding layer services one further
#: operation, ``cross_capture_linkage``, before delegating the rest here; it is
#: therefore not part of this tool-layer set.
PCAP_QUERY_OPERATIONS: frozenset[str] = frozenset(
    set(FIELD_QUERIES)
    | set(STAT_QUERIES)
    | set(CURATED_PROTOCOL_FIELDS)
    | {"dns_exfil", "ftp_objects", "http_objects", "fields", "stat", "export", "follow"}
)
_CHUNK_RE = re.compile(r"^(\d+)[-_.]([0-9a-fA-F]+)$")

def _printable(b: bytes) -> str:
    return "".join(chr(c) if 32 <= c < 127 else "." for c in b)


#: Fixed name of the reconstructed payload when no caller named a destination.
_DNS_RECONSTRUCTION_NAME = "dns_exfil_reconstruction"


def _contained_dns_save_path(identification) -> str | None:
    """Where a DNS reconstruction is written when no caller named a destination.

    Reporting it only as metadata left the examination unable to continue: the
    bytes carry an archive, and the archive, carving and text tools all read a
    path. The destination is chosen here or not at all, which is what closed the
    earlier hole and stays closed — fixed, container-private, never model-chosen
    and never the ambient temporary directory.
    """

    payload_root = payload_scratch_root()
    if payload_root is None:
        return None
    suffix = (
        mimetypes.guess_extension(identification.mime_type)
        if identification.mime_type
        else None
    )
    return os.path.join(str(payload_root), _DNS_RECONSTRUCTION_NAME + (suffix or ".bin"))


def reconstruct_dns_exfil(query_names, save_path: str | None = None) -> dict:
    """Reassemble data smuggled over DNS from a list of query names: group the
    indexed sub-domain chunks by the query-name stem they were prepended to,
    order them, decode hex, and identify the payload type. The registrable
    domain of that stem is read from the Public Suffix List. Normally reached
    via pcap_query(query="dns_exfil"); call directly only when you already hold
    a list of query names.

    Example: reconstruct_dns_exfil(["1-89504e47.t.evil.com", "2-0d0a1a0a.t.evil.com"])

    Input: `query_names` is a list of DNS query-name strings; `save_path` names
    where the recovered bytes are written. Reconstructed bytes are ALWAYS written
    once they decode: omitting `save_path` selects a run-controlled location
    rather than suppressing the write. The evidence itself is only read.

    Returns: {"base_domain", "exfiltration_query_stem", "base_domain_reading",
    "chunk_count", "distinct_query_names"} plus, when chunks decode,
    {"reconstructed_bytes", "magic_hex", and either
    "detected_type"/"embedded_strings"/"note" for a binary or "utf8"/"ascii"
    for text, plus "saved_to" naming the written file, or "save_refused"/"save_error"
    when the write could not be contained}; non-indexed labels
    surface under "non_indexed_labels"(_base64). `base_domain` is None when no
    Public Suffix List reader is installed, and `base_domain_reading` says so.
    Returns {"note": ...} when there is nothing to reassemble.
    """
    # Which names belong to one reassembly is a property of the names: an
    # indexed leading label prepended to a common stem. Grouping therefore never
    # consults a rule about how many labels a domain has, and the reassembled
    # bytes are the same on a host with no Public Suffix List reader as on one
    # with it.
    stems: collections.Counter[str] = collections.Counter()
    for n in query_names:
        labels = str(n).split(".")
        if len(labels) >= 2 and _CHUNK_RE.match(labels[0]) is not None:
            stems[".".join(labels[1:])] += 1
    if not stems:
        for n in query_names:
            labels = str(n).split(".")
            if len(labels) >= 2:
                stems[".".join(labels[1:])] += 1
    if not stems:
        return {"note": "no DNS query names to analyze"}
    stem = stems.most_common(1)[0][0]

    chunks: dict[int, str] = {}
    extras: list[str] = []
    for n in query_names:
        name = str(n)
        if not name.endswith("." + stem):
            continue
        token = name[: -(len(stem) + 1)].split(".")[0]
        if not token:
            continue
        m = _CHUNK_RE.match(token)
        if m:
            chunks[int(m.group(1))] = m.group(2)
        else:
            extras.append(token)

    # Where the registrant's name ends and the public suffix begins is published,
    # not inferred: the reader and the list version that answered are carried
    # beside the answer, and an absent reader yields no domain rather than one
    # this tool made up.
    reading = public_suffix.registrable_domain(stem)
    out = {"base_domain": reading.get("registrable_domain"),
           "exfiltration_query_stem": stem,
           "base_domain_reading": reading,
           "chunk_count": len(chunks),
           "distinct_query_names": len(set(query_names))}
    if chunks:
        try:
            raw = bytes.fromhex("".join(chunks[i] for i in sorted(chunks)))
        except ValueError:
            raw = b""
        out["reconstructed_bytes"] = len(raw)
        out["magic_hex"] = raw[:8].hex()
        identification = identify_payload(raw)
        out.update(identification.fields())
        media_type = identification.mime_type or ""
        textual = media_type.startswith("text/")
        if not textual:
            out["embedded_strings"] = _embedded_strings(raw)
        # The reconstructed payload is exfiltrated content, so it leaves this
        # process only to a container-private location this run controls — the
        # destination is chosen here or not at all, never model-chosen and never
        # an ambient temporary directory. save_path, when given, is resolved
        # through the write-scope facade and refused if it escapes the payload
        # root. The write happens BEFORE the note below so the note can name the
        # path the archive, carving and text tools then open, instead of
        # claiming the bytes went nowhere while they sit ready on disk.
        destination_path = save_path or _contained_dns_save_path(identification)
        if raw and destination_path:
            destination = os.path.dirname(os.path.abspath(destination_path))
            try:
                acquire_evidence_write_dir(
                    destination,
                    subject="a payload reconstructed from DNS-tunnelled exfiltration",
                )
            except StorageContainmentError as exc:
                out["save_refused"] = str(exc)[:500]
            else:
                try:
                    with open(destination_path, "wb") as f:
                        f.write(raw)
                    out["saved_to"] = destination_path
                except Exception as exc:
                    out["save_error"] = str(exc)[:120]
        saved = out.get("saved_to")
        if identification.identified and not textual:
            out["note"] = (
                f"Binary payload exfiltrated over DNS — {identification.description}. "
                + (
                    f"The reconstructed bytes are written to {saved}, ready to open "
                    "with the archive, carving or text tools."
                    if saved
                    else "The bytes could not be written to a container-private "
                    "path, so they remain metadata only."
                )
            )
        else:
            out["utf8"] = raw.decode("utf-8", "replace")[:600]
            out["ascii"] = _printable(raw)[:600]
            if identification.leading_byte_signature:
                # A reassembly that is missing chunks is exactly what libmagic
                # refuses to classify, so the refusal and the leading bytes are
                # reported as the two separate facts they are.
                out["note"] = (
                    "libmagic identified no format in these bytes; their leading "
                    f"bytes are those of {identification.leading_byte_signature}, "
                    "which is also what a partial reassembly of one looks like. "
                    + (
                        f"The bytes are written to {saved}."
                        if saved
                        else "The bytes were not written anywhere."
                    )
                )
    dec = []
    for extra in extras[:20]:
        try:
            d = base64.b64decode(extra + "=" * (-len(extra) % 4))
            dec.append({"label": extra, "base64_decoded": _printable(d)[:120]})
        except Exception:
            pass
    if dec:
        out["non_indexed_labels_base64"] = dec
    elif extras:
        out["non_indexed_labels"] = extras[:10]
    return out


def _run(ts, pcap_path, args):
    return run_external([ts, "-r", pcap_path] + args, timeout=180, check=False)


_REQUEST_DIRECTION_FIELDS = (
    "ftp.request.command",
    "http.request.method",
    "http.request.uri",
    "smtp.req.command",
)
_RESPONSE_DIRECTION_FIELDS = (
    "ftp.response.code",
    "http.response.code",
    "smtp.response.code",
)


def _first_named_value(record: dict[str, str], names: tuple[str, ...]) -> str | None:
    for name in names:
        value = record.get(name)
        if value:
            return value
    return None


def _endpoint_roles(record: dict[str, str]) -> dict[str, str] | None:
    """Annotate application request/response direction without guessing endpoints.

    Raw tshark columns remain available for compatibility.  This additional map
    makes the direction explicit only when a role-bearing request or response
    field and both network endpoints are present in the same extracted packet.
    """

    source = _first_named_value(record, ("ip.src", "ipv6.src", "eth.src"))
    destination = _first_named_value(record, ("ip.dst", "ipv6.dst", "eth.dst"))
    if not source or not destination:
        return None
    request_basis = _first_named_value(record, _REQUEST_DIRECTION_FIELDS)
    if request_basis:
        return {
            "client": source,
            "server": destination,
            "direction": "client_to_server",
            "basis": next(
                name for name in _REQUEST_DIRECTION_FIELDS if record.get(name)
            ),
        }
    response_basis = _first_named_value(record, _RESPONSE_DIRECTION_FIELDS)
    if response_basis:
        return {
            "client": destination,
            "server": source,
            "direction": "server_to_client",
            "basis": next(
                name for name in _RESPONSE_DIRECTION_FIELDS if record.get(name)
            ),
        }
    return None


#: ``-z follow,<transport>,raw`` prints each contiguous run of payload as one hex
#: line and marks the second node's runs with a leading tab.  That tab is the only
#: record of who sent the bytes, so it is read before the line is trimmed.
_FOLLOW_REVERSE_MARK = "\t"
_FOLLOW_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
#: Names for the two halves of a followed stream, and for taking both.
_FOLLOW_FORWARD = "node0_to_node1"
_FOLLOW_REVERSE = "node1_to_node0"
_FOLLOW_BOTH = "both"
#: Take whichever half carries the payload.  A transfer connection carries bytes
#: in one direction and control chatter in the other, so the larger half is the
#: transferred object; concatenating the two produces a stream that was never sent.
_FOLLOW_DOMINANT = "dominant"
_FOLLOW_MERGED_NOTE = (
    "both directions of this stream carry payload and they are concatenated here, so "
    "the size and hashes describe the two peers' bytes joined in transmission order "
    "rather than anything either peer sent; read the per-direction entries instead"
)
_FOLLOW_SELECTED_NOTE = (
    "both directions of this stream carry payload; the size and hashes describe only "
    "the selected direction"
)


def _unhex(text: str) -> bytes:
    """Decode one follow direction, treating an unusable run as no bytes at all."""

    try:
        return bytes.fromhex(text)
    except ValueError:
        return b""


def _follow_directions(stdout: str | None) -> tuple[bytes, bytes, bytes]:
    """Split a raw follow into (whole conversation, what node0 sent, what node1 sent).

    The whole conversation keeps the order the runs were printed in, which is the
    order they were transmitted; the two halves keep only their own sender's runs.
    """

    combined: list[str] = []
    forward: list[str] = []
    reverse: list[str] = []
    for line in (stdout or "").splitlines():
        body = line.strip()
        if not body or not _FOLLOW_HEX_DIGITS.issuperset(body):
            continue
        combined.append(body)
        (reverse if line.startswith(_FOLLOW_REVERSE_MARK) else forward).append(body)
    return (
        _unhex("".join(combined)),
        _unhex("".join(forward)),
        _unhex("".join(reverse)),
    )


def _selected_follow_payload(
    combined: bytes, forward: bytes, reverse: bytes, select: str
) -> bytes:
    """The bytes one selection names, out of the two directions of a stream."""

    if select == _FOLLOW_FORWARD:
        return forward
    if select == _FOLLOW_REVERSE:
        return reverse
    if select == _FOLLOW_DOMINANT:
        return forward if len(forward) >= len(reverse) else reverse
    return combined


def _follow_direction_note(select: str, both_carry_payload: bool) -> dict[str, str]:
    """State what a bidirectional stream did to the reported size and hashes."""

    if not both_carry_payload:
        return {}
    if select == _FOLLOW_BOTH:
        return {"direction_note": _FOLLOW_MERGED_NOTE}
    return {"direction_note": _FOLLOW_SELECTED_NOTE}


def _field_rows(stdout: str | None) -> list[list[str]]:
    """Split ``-T fields`` output into one column list per emitted packet.

    tshark writes one line per matching packet and separates the requested fields
    with a tab, so a packet whose leading field is empty begins its line with the
    separator, and a packet that matched but carries none of the requested fields
    is a line of nothing but separators.  Stripping the output as a whole would
    delete that leading separator on the first packet, putting every value in that
    row under the wrong field name; treating a separator-only line as blank would
    drop those packets out of the count altogether.
    """

    return [line.split("\t") for line in (stdout or "").splitlines() if line]


def _named_field_rows(fields: list[str], rows: list[list[str]]) -> list[dict[str, object]]:
    """Return field-name-bound records while preserving the legacy row arrays."""

    named: list[dict[str, object]] = []
    for values in rows:
        record: dict[str, str] = {
            field: values[index] if index < len(values) else ""
            for index, field in enumerate(fields)
        }
        item: dict[str, object] = dict(record)
        roles = _endpoint_roles(record)
        if roles is not None:
            item["endpoint_roles"] = roles
        named.append(item)
    return named


def _parse_ftp_port_argument(value: str) -> tuple[str, int] | None:
    """Parse one RFC 959 ``PORT h1,h2,h3,h4,p1,p2`` argument."""

    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if candidate[:5].casefold() == "port ":
        candidate = candidate[5:].strip()
    parts = [part.strip() for part in candidate.split(",")]
    if len(parts) != 6 or any(not part.isdecimal() for part in parts):
        return None
    numbers = [int(part, 10) for part in parts]
    if any(number > 255 for number in numbers):
        return None
    ipv4 = ".".join(str(number) for number in numbers[:4])
    return ipv4, numbers[4] * 256 + numbers[5]


def _ftp_session_summary(
    named_rows: list[dict[str, object]],
) -> dict[str, object] | None:
    """Derive a bounded deterministic FTP control-session summary."""

    ftp_rows = [
        row
        for row in named_rows
        if isinstance(row.get("ftp.request.command"), str)
        and str(row["ftp.request.command"]).strip()
    ]
    if not ftp_rows:
        return None

    username: str | None = None
    password: str | None = None
    active_data_endpoint: dict[str, object] | None = None
    uploaded_files: list[str] = []
    client_ipv4: str | None = None
    server_ipv4: str | None = None
    role_client_ipv4: str | None = None
    role_server_ipv4: str | None = None

    for row in ftp_rows:
        command = str(row["ftp.request.command"]).strip().upper()
        argument_value = row.get("ftp.request.arg")
        argument = argument_value.strip() if isinstance(argument_value, str) else ""
        roles = row.get("endpoint_roles")
        if isinstance(roles, dict):
            role_client = roles.get("client")
            role_server = roles.get("server")
            if role_client_ipv4 is None and isinstance(role_client, str):
                role_client_ipv4 = _single_tshark_value(role_client, kind="ipv4")
                client_ipv4 = client_ipv4 or role_client_ipv4
            if role_server_ipv4 is None and isinstance(role_server, str):
                role_server_ipv4 = _single_tshark_value(role_server, kind="ipv4")
                server_ipv4 = server_ipv4 or role_server_ipv4

        if command == "USER" and username is None and argument:
            username = argument
        elif command == "PASS" and password is None and argument:
            password = argument
        elif command == "PORT" and active_data_endpoint is None:
            parsed = _parse_ftp_port_argument(argument)
            if parsed is not None:
                port_ipv4, port = parsed
                client_ipv4 = port_ipv4
                active_data_endpoint = {"ipv4": port_ipv4, "port": port}
        elif command == "STOR" and argument and argument not in uploaded_files:
            uploaded_files.append(argument)

    endpoint_roles = {
        "client": role_client_ipv4,
        "server": role_server_ipv4,
    }
    return {
        "username": username,
        "password": password,
        "client_ipv4": client_ipv4,
        "server_ipv4": server_ipv4,
        "active_data_endpoint": active_data_endpoint,
        "uploaded_files": uploaded_files,
        "endpoint_roles": endpoint_roles,
    }


def _selected_field_names(args: list[str]) -> list[str]:
    """Read the ordered ``-e`` field names from one fixed tshark argument list."""

    return [args[index + 1] for index, value in enumerate(args[:-1]) if value == "-e"]


#: Fields that carry transferred bytes rather than metadata. One of them turns a
#: 26-row answer into a megabyte, and the central output guard then truncates the
#: rows that held the answer. ``metadata_only`` exists to say "not those".
_PAYLOAD_FIELDS = frozenset(
    {
        "http.file_data",
        "data",
        "data.data",
        "data.text",
        "tcp.payload",
        "udp.payload",
        "ftp-data.data",
        "media.type",
        "image-gif.data",
        "image-jfif.data",
    }
)


#: One row of ``tshark -z io,phs``: leading indentation is the nesting depth, and
#: the protocol name is captured only to be discarded — the depth is what tells a
#: root row from a nested one, and the name varies by build and link type.
_HIERARCHY_ROW_RE = re.compile(r"^(\s*)\S+\s+frames:(\d+)\b")


def _capture_packet_total(TS, pcap_path) -> int | None:
    """Return the whole capture's frame count, or None when it cannot be read.

    A filtered view reports how many packets matched. Without the total, "50
    packets" reads like the capture, and a protocol the filter excluded looks
    absent. The count comes from tshark's own protocol hierarchy so no extra
    dependency is introduced, and it is advisory: failure to obtain it must not
    fail the query the caller actually asked for.
    """

    try:
        proc = _run(TS, pcap_path, ["-q", "-z", "io,phs"])
    except Exception:
        return None
    return _hierarchy_frame_total(proc.stdout or "")


def _hierarchy_frame_total(output: str) -> int | None:
    """Sum the frame counts of the outermost rows of a protocol hierarchy.

    The hierarchy is an indented tree whose nesting depth is the only structural
    marker, so the outermost rows are the ones at the smallest indentation and
    every deeper row is a subset of one of them.  Which protocol sits at that
    outermost level is a property of the build and of the capture's link type:
    some emit ``frame`` as a single root, others start at ``eth``, and a capture
    holding more than one link type has several roots whose counts add up.
    Reading the depth rather than the name keeps this correct across all three
    instead of silently returning nothing whenever the outermost name is not the
    expected one.
    """

    rows: list[tuple[int, int]] = []
    for line in output.splitlines():
        match = _HIERARCHY_ROW_RE.match(line)
        if match is not None:
            rows.append((len(match.group(1)), int(match.group(2))))
    if not rows:
        return None
    outermost = min(depth for depth, _frames in rows)
    return sum(frames for depth, frames in rows if depth == outermost)


def _matching_rows(rows, filter_text):
    """Apply the documented plain-substring filter over extracted rows."""

    if not filter_text:
        return rows
    needle = str(filter_text).casefold()
    return [
        row
        for row in rows
        if needle in json.dumps(row, ensure_ascii=False, default=str).casefold()
    ]


def _q_fields(
    TS,
    pcap_path,
    fields,
    display_filter,
    limit,
    *,
    offset=0,
    filter=None,
    metadata_only=False,
):
    fields = [f for f in (fields or []) if isinstance(f, str) and f.strip()][:16]
    if not fields:
        return {
            "error": "query='fields' needs a non-empty 'fields' list of tshark field names "
            "(e.g. ['eth.src','eth.dst'] for MAC, ['ftp.request.command','ftp.request.arg'] for FTP).",
            "deterministic_error": True,
        }
    withheld: list[str] = []
    if metadata_only:
        withheld = sorted({f for f in fields if f.casefold() in _PAYLOAD_FIELDS})
        fields = [f for f in fields if f.casefold() not in _PAYLOAD_FIELDS]
        if not fields:
            return {
                "error": "metadata_only=True withholds every requested field, because they all "
                f"carry transferred bytes: {', '.join(withheld)}. Ask for metadata "
                "fields such as http.request.full_uri or http.content_type, or set "
                "metadata_only=False to receive the payload.",
                "deterministic_error": True,
            }
    args = (["-Y", display_filter] if display_filter else []) + ["-T", "fields"]
    for f in fields:
        args += ["-e", f]
    try:
        proc = _run(TS, pcap_path, args)
    except Exception as e:
        return tool_failure_result(e, subject=str(pcap_path), backend="tshark")
    rows = _field_rows(proc.stdout)
    from forensic_agent.core.toolio import MAX_TOTAL_BYTES, row_bytes, shape

    envelope = shape(rows, offset=offset, limit=limit, filter=filter)
    page = envelope["rows"]
    named_rows = _named_field_rows(fields, page)
    # ``named_rows`` re-describes the very page shape() just bounded, in a larger
    # self-describing form, and is carried alongside the positional ``rows``.
    # Left outside the byte budget it can double or triple the result, and
    # downstream projection can truncate the positional rows item by item but can
    # only drop ``named_rows`` as a whole. Co-bind both views to one budget so a
    # fields page is carried once, within the output guard, in both forms and
    # shrinks together rather than escaping.
    if page and row_bytes(page) + row_bytes(named_rows) > MAX_TOTAL_BYTES:
        lo, hi = 1, len(page)
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if row_bytes(page[:mid]) + row_bytes(named_rows[:mid]) <= MAX_TOTAL_BYTES:
                lo = mid
            else:
                hi = mid - 1
        if lo < len(page):
            envelope = shape(rows, offset=offset, limit=lo, filter=filter)
            page = envelope["rows"]
            named_rows = _named_field_rows(fields, page)
    out = {
        "query": "fields",
        "fields": fields,
        "display_filter": display_filter,
        **(
            {
                "withheld_payload_fields": withheld,
                "withheld_reason": "metadata_only=True; these fields carry transferred bytes",
            }
            if withheld
            else {}
        ),
        "packet_count": len(rows),
        **envelope,
        # Keep the positional representation for callers that bind ``fields``
        # themselves, and also return self-describing records so endpoint and
        # credential roles are not lost when columns are summarized downstream.
        "named_rows": named_rows,
    }
    if display_filter:
        # A filtered view is a slice of the capture, and reading it as the whole
        # capture makes every unselected protocol look absent. The packets a
        # filter drops can still carry the answer, so say the coverage is partial
        # and name the view that lists what else is present.
        out["coverage_complete"] = False
        capture_total = _capture_packet_total(TS, pcap_path)
        if capture_total is not None:
            out["capture_packet_total"] = capture_total
            out["unexamined_packet_count"] = max(0, capture_total - len(rows))
        scope = (
            f"these rows are only the {len(rows)} of {capture_total} packets in this capture "
            f"that match display_filter={display_filter!r}, leaving "
            f"{max(0, capture_total - len(rows))} packets unexamined"
            if capture_total is not None
            else f"these rows are only the packets matching display_filter={display_filter!r}"
        )
        out["coverage_note"] = (
            f"{scope}; this view cannot show that a protocol is absent from the capture. "
            "query='protocols' lists every protocol the capture actually contains"
        )
        # State the same thing through the structured coverage contract, not only
        # as a free-text attribute, because gates read the structured field rather
        # than the note. Partial coverage of the capture does not weaken what these
        # rows directly show; it bounds only claims about what is absent, and the
        # counts are what let a reader tell those two apart.
        coverage: dict[str, object] = {
            "complete": False,
            "scope": scope,
            "reason": (
                "a display_filter selects a subset of the capture, so this view can "
                "establish what it shows but cannot establish that anything it "
                "excluded is absent"
            ),
        }
        if capture_total is not None and len(rows) <= capture_total:
            coverage["examined"] = len(rows)
            coverage["expected"] = capture_total
        out["coverage"] = coverage
    # The compact session summary is computed over the complete extracted view,
    # not merely the current page. This makes it useful under pagination without
    # pretending that a tshark display_filter examined the rest of the capture.
    summary_rows = _matching_rows(rows, filter)
    ftp_summary = _ftp_session_summary(_named_field_rows(fields, summary_rows))
    if ftp_summary is not None:
        out["ftp_session_summary"] = ftp_summary
    returncode = int(getattr(proc, "returncode", 0) or 0)
    if returncode != 0:
        diagnostic = (proc.stderr or "tshark returned no diagnostic output")[:300]
        out["returncode"] = returncode
        out["stderr"] = diagnostic
        out["coverage_complete"] = False
        out["scan_complete"] = False
        out["error"] = {
            "code": "tshark_partial_output" if rows else "tshark_query_failed",
            "message": (
                "tshark returned a non-zero exit status; any emitted rows are partial "
                "and an empty result cannot establish absence"
            ),
        }
    return out


def _q_stat(TS, pcap_path, stat):
    if not stat or not isinstance(stat, str):
        return {
            "error": "query='stat' needs a tshark -z spec (e.g. 'conv,eth', 'endpoints,eth', 'io,phs').",
            "deterministic_error": True,
        }
    try:
        proc = _run(TS, pcap_path, ["-q", "-z", stat])
    except Exception as e:
        return tool_failure_result(e, subject=str(pcap_path), backend="tshark")
    out = {"query": "stat", "stat": stat, "output": (proc.stdout or "")[:4000]}
    returncode = int(getattr(proc, "returncode", 0) or 0)
    if returncode != 0:
        out.update(
            {
                "returncode": returncode,
                "stderr": (proc.stderr or "tshark returned no diagnostic output")[:300],
                "coverage_complete": False,
                "scan_complete": False,
                "error": {
                    "code": "tshark_partial_output" if proc.stdout else "tshark_query_failed",
                    "message": (
                        "tshark returned a non-zero exit status; the statistic is not "
                        "a complete result"
                    ),
                },
            }
        )
    return out


_MAC_ADDRESS_RE = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$", re.IGNORECASE)


def _single_tshark_value(value: str, *, kind: str) -> str | None:
    """Return one normalized endpoint value from a tshark field cell.

    A packet can contain repeated encapsulated fields.  Host linkage only uses
    the first syntactically valid Ethernet/IPv4 value and never guesses from a
    malformed or truncated token.

    An Ethernet address is eligible only when it addresses ONE interface.  The
    test is the I/G bit — bit 0 of the first octet — not the U/L bit beside it: a
    locally administered unicast address such as ``02:...`` belongs to a real
    interface and stays, while every group and broadcast address goes, because no
    single machine can be linked across captures by an address many machines
    answer to.
    """

    for token in re.split(r"[,;]", value or ""):
        candidate = token.strip().casefold()
        if kind == "mac":
            if _MAC_ADDRESS_RE.fullmatch(candidate) is not None:
                first_octet = int(candidate[:2], 16)
                if candidate != "ff:ff:ff:ff:ff:ff" and first_octet & 1 == 0:
                    return candidate
        elif kind == "ipv4":
            try:
                address = ipaddress.IPv4Address(candidate)
            except ipaddress.AddressValueError:
                continue
            if not (address.is_multicast or address.is_unspecified):
                return str(address)
        else:  # pragma: no cover - private caller contract
            raise ValueError("unsupported tshark endpoint kind")
    return None


def cross_capture_host_linkage(captures: list[tuple[str, str]]) -> dict:
    """Correlate Ethernet interfaces and their IPv4 addresses across captures.

    ``captures`` contains model-safe component labels paired with private PCAP
    paths.  tshark extracts same-side ``eth.src/ip.src`` and ``eth.dst/ip.dst``
    observations.  The result reports every MAC present in all captures and, when
    unambiguous, the interface with the smallest stable set of associated IPv4
    addresses.  This avoids asking a model to copy and join thousands of packet
    rows and prevents gateway MACs from being mistaken for the investigated host.
    """

    if not isinstance(captures, list) or len(captures) < 2:
        return {"error": "cross-capture linkage needs at least two labeled captures."}
    labels = [item[0] for item in captures if isinstance(item, tuple) and len(item) == 2]
    if len(labels) != len(captures) or len(set(labels)) != len(labels):
        return {"error": "cross-capture labels must be unique non-empty strings."}
    if any(not isinstance(label, str) or not label.strip() for label in labels):
        return {"error": "cross-capture labels must be unique non-empty strings."}
    if any(not isinstance(path, str) or not os.path.exists(path) for _label, path in captures):
        return {"error": "one or more bound packet captures are unavailable."}
    TS = tshark_path()
    if not TS:
        return {"error": "Wireshark 'tshark' not found."}

    by_capture: dict[str, dict[str, collections.Counter[str]]] = {}
    packet_counts: dict[str, int] = {}
    warnings_out: list[dict[str, str]] = []
    for label, path in captures:
        try:
            proc = _run(
                TS,
                path,
                [
                    "-T",
                    "fields",
                    "-E",
                    "occurrence=f",
                    "-e",
                    "eth.src",
                    "-e",
                    "eth.dst",
                    "-e",
                    "ip.src",
                    "-e",
                    "ip.dst",
                ],
            )
        except Exception as exc:
            return {"error": f"tshark linkage extraction failed for {label}: {str(exc)[:150]}"}
        associations: dict[str, collections.Counter[str]] = collections.defaultdict(
            collections.Counter
        )
        observed_packets = 0
        for line in (proc.stdout or "").splitlines():
            columns = line.rstrip("\r\n").split("\t")
            if len(columns) < 4:
                columns.extend([""] * (4 - len(columns)))
            src_mac = _single_tshark_value(columns[0], kind="mac")
            dst_mac = _single_tshark_value(columns[1], kind="mac")
            src_ip = _single_tshark_value(columns[2], kind="ipv4")
            dst_ip = _single_tshark_value(columns[3], kind="ipv4")
            if src_mac and src_ip:
                associations[src_mac][src_ip] += 1
            if dst_mac and dst_ip:
                associations[dst_mac][dst_ip] += 1
            if (src_mac and src_ip) or (dst_mac and dst_ip):
                observed_packets += 1
        by_capture[label] = dict(associations)
        packet_counts[label] = observed_packets
        if proc.returncode != 0 and proc.stderr:
            warnings_out.append(
                {"source": label, "message": (proc.stderr or "")[:300]}
            )

    common_macs = sorted(
        set.intersection(*(set(by_capture[label]) for label in labels))
        if labels
        else set()
    )
    candidates: list[tuple[tuple[object, ...], dict[str, object]]] = []
    for mac in common_macs:
        per_capture: list[dict[str, object]] = []
        all_ips: set[str] = set()
        minimum_dominance = 1.0
        total_associations = 0
        for label in labels:
            counts = by_capture[label][mac]
            ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
            dominant_ip, dominant_count = ordered[0]
            observed = sum(counts.values())
            dominance = dominant_count / observed if observed else 0.0
            all_ips.update(counts)
            minimum_dominance = min(minimum_dominance, dominance)
            total_associations += observed
            per_capture.append(
                {
                    "source": label,
                    "dominant_ipv4": dominant_ip,
                    "dominant_observations": dominant_count,
                    "total_same_side_observations": observed,
                    "dominance_ratio": round(dominance, 6),
                    "associated_ipv4_count": len(counts),
                }
            )
        record: dict[str, object] = {
            "mac": mac,
            "ipv4_addresses": sorted(all_ips),
            "distinct_ipv4_count": len(all_ips),
            "observed_in_all_captures": True,
            "minimum_dominance_ratio": round(minimum_dominance, 6),
            "total_same_side_observations": total_associations,
            "per_capture": per_capture,
        }
        # Prefer a consistently attributable endpoint over a gateway that is
        # paired with many remote IP addresses.  A changed address is useful
        # corroboration, but stable-address captures remain valid candidates.
        rank = (
            0 if 1 < len(all_ips) <= len(captures) else 1,
            len(all_ips),
            -minimum_dominance,
            -total_associations,
            mac,
        )
        candidates.append((rank, record))
    candidates.sort(key=lambda item: item[0])

    compact_candidates: list[dict[str, object]] = []
    for _rank, record in candidates:
        raw_addresses = record.get("ipv4_addresses")
        if not isinstance(raw_addresses, list):  # internal record invariant
            raise RuntimeError("cross-capture candidate is missing its IPv4 address list")
        addresses = [address for address in raw_addresses if isinstance(address, str)]
        compact = dict(record)
        compact["ipv4_addresses"] = addresses[:12]
        if len(addresses) > 12:
            compact["ipv4_addresses_truncated"] = True
            compact["omitted_ipv4_count"] = len(addresses) - 12
        compact_candidates.append(compact)

    result: dict[str, object] = {
        "query": "cross_capture_linkage",
        "method": "tshark same-side Ethernet/IPv4 association",
        "capture_count": len(captures),
    }
    if candidates:
        best_rank, best = candidates[0]
        ambiguity_key = best_rank[:-1]
        ambiguous = len(candidates) > 1 and candidates[1][0][:-1] == ambiguity_key
        result["selection_ambiguous"] = ambiguous
        if not ambiguous:
            result["linked_machine"] = best
    result.update(
        {
            "common_mac_addresses": common_macs,
            "capture_packet_counts": [
                {"source": label, "ip_ethernet_packets": packet_counts[label]}
                for label in labels
            ],
            "candidates": compact_candidates,
            "selection_rule": (
                "present in every capture; prefer a renumbered interface with the smallest "
                "associated IPv4 set, then highest minimum per-capture dominance"
            ),
        }
    )
    if warnings_out:
        result["warnings"] = warnings_out
    return result


_TSHARK_EXPORT_OBJECT_PROTOS = {"http", "smb", "tftp", "imf", "dicom"}
_EXPORT_PROTOS = _TSHARK_EXPORT_OBJECT_PROTOS | {"ftp"}
_PE_PARSE_MAX_BYTES = 32 * 1024 * 1024
_PE_STRING_SCAN_MAX_BYTES = 8 * 1024 * 1024
_PE_STRING_LIMIT = 6
_EXPORT_SUMMARY_CANDIDATE_LIMIT = 100
_FOLLOW_PREVIEW_BYTES = 8 * 1024


def _hashes(data):
    return {"size": len(data), **identify_payload(data).fields(key="type"),
            "md5": hashlib.md5(data).hexdigest(), "sha256": hashlib.sha256(data).hexdigest()}


def _pe_text(value, *, limit: int = 256) -> str:
    if isinstance(value, bytes):
        text = value.decode("utf-8", "replace")
    else:
        text = str(value)
    return " ".join(text.replace("\x00", " ").split())[:limit]


def _pe_identifying_strings(data: bytes) -> list[dict[str, str]]:
    """Return a deterministic, bounded set of likely identifying PE strings."""

    sample = data[:_PE_STRING_SCAN_MAX_BYTES]
    candidates: list[tuple[tuple[int, int, int, int], dict[str, str]]] = []
    seen: set[str] = set()
    patterns = (
        ("utf-16le", re.compile(rb"(?:[\x20-\x7e]\x00){4,160}")),
        ("ascii", re.compile(rb"[\x20-\x7e]{4,160}")),
    )
    priority = re.compile(
        r"(?i)(company|copyright|description|product|internal|original|version|"
        r"\.exe\b|\.dll\b|application|utility|driver)"
    )
    for encoding, pattern in patterns:
        observed = 0
        for match in pattern.finditer(sample):
            observed += 1
            if observed > 4_000:
                break
            raw = match.group(0)
            text = _pe_text(
                raw.decode("utf-16-le" if encoding == "utf-16le" else "ascii", "replace"),
                limit=120,
            )
            folded = text.casefold()
            if (
                len(text) < 4
                or folded in seen
                or sum(character.isalnum() for character in text) < 3
                or len(set(folded)) < 3
            ):
                continue
            seen.add(folded)
            rank = (
                0 if priority.search(text) else 1,
                0 if " " in text else 1,
                abs(len(text) - 40),
                match.start(),
            )
            candidates.append((rank, {"encoding": encoding, "value": text}))
    candidates.sort(key=lambda item: item[0])
    return [item for _rank, item in candidates[:_PE_STRING_LIMIT]]


def _pe_static_metadata(data: bytes) -> dict[str, object] | None:
    """Parse bounded static PE metadata without loading or executing the image."""

    if not data.startswith(b"MZ"):
        return None
    strings = _pe_identifying_strings(data)
    result: dict[str, object] = {
        "parser": "pefile",
        "execution": "never",
        "input_size": len(data),
        "bounds": {
            "parse_bytes": _PE_PARSE_MAX_BYTES,
            "string_scan_bytes": _PE_STRING_SCAN_MAX_BYTES,
            "string_count": _PE_STRING_LIMIT,
        },
    }
    if len(data) > _PE_PARSE_MAX_BYTES:
        result["parse_status"] = "skipped_size_cap"
        result["identifying_strings"] = strings
        return result
    try:
        import pefile
    except Exception as exc:
        result.update(
            {
                "parse_status": "parser_unavailable",
                "parse_error": type(exc).__name__,
                "identifying_strings": strings,
            }
        )
        return result

    pe = None
    try:
        pe = pefile.PE(data=data, fast_load=False)
        file_header = pe.FILE_HEADER
        optional = pe.OPTIONAL_HEADER
        machine = int(getattr(file_header, "Machine", 0))
        subsystem = int(getattr(optional, "Subsystem", 0))
        machine_name = pefile.MACHINE_TYPE.get(machine)
        subsystem_name = pefile.SUBSYSTEM_TYPE.get(subsystem)
        result.update(
            {
                "parse_status": "ok",
                "machine": machine_name or f"0x{machine:04x}",
                "timestamp": int(getattr(file_header, "TimeDateStamp", 0)),
                "entry_point": int(getattr(optional, "AddressOfEntryPoint", 0)),
                "image_base": int(getattr(optional, "ImageBase", 0)),
                "subsystem": subsystem_name or subsystem,
                "section_names": [
                    _pe_text(getattr(section, "Name", b""), limit=16)
                    for section in list(getattr(pe, "sections", []))[:8]
                ],
            }
        )

        version_info: dict[str, str] = {}

        def collect_file_info(node) -> None:
            if isinstance(node, (list, tuple)):
                for item in node:
                    collect_file_info(item)
                return
            key = _pe_text(getattr(node, "Key", b""), limit=64)
            if key != "StringFileInfo":
                return
            for table in list(getattr(node, "StringTable", []) or [])[:8]:
                entries = getattr(table, "entries", {}) or {}
                for raw_key, raw_value in list(entries.items())[:16]:
                    name = _pe_text(raw_key, limit=64)
                    value = _pe_text(raw_value, limit=160)
                    if name and value and name not in version_info:
                        version_info[name] = value

        collect_file_info(getattr(pe, "FileInfo", []))
        if version_info:
            result["version_info"] = version_info

        fixed = list(getattr(pe, "VS_FIXEDFILEINFO", []) or [])
        if fixed:
            info = fixed[0]

            def dotted(ms: int, ls: int) -> str:
                return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"

            result["fixed_version_info"] = {
                "file_version": dotted(
                    int(getattr(info, "FileVersionMS", 0)),
                    int(getattr(info, "FileVersionLS", 0)),
                ),
                "product_version": dotted(
                    int(getattr(info, "ProductVersionMS", 0)),
                    int(getattr(info, "ProductVersionLS", 0)),
                ),
            }
        result["identifying_strings"] = strings
    except Exception as exc:
        result.update(
            {
                "parse_status": "parse_error",
                "parse_error": type(exc).__name__,
            }
        )
        result["identifying_strings"] = strings
    finally:
        close = getattr(pe, "close", None)
        if callable(close):
            close()
    return result


def _pe_executable_summary(files: list[dict[str, object]]) -> dict[str, object]:
    """Return a compact content-validated PE view over an export result.

    Exported object names can contain URL/query text that merely mentions an
    executable.  Candidate selection therefore depends only on successful PE
    content recognition (the presence of ``pe_metadata``), never on a filename
    substring.  The full rows remain the auditable source of every copied value.
    """

    identity_keys = (
        "FileDescription",
        "ProductName",
        "InternalName",
        "OriginalFilename",
        "CompanyName",
    )
    candidates: list[dict[str, object]] = []
    for item_index, row in enumerate(files):
        pe_metadata = row.get("pe_metadata")
        if not isinstance(pe_metadata, dict):
            continue
        version_info = pe_metadata.get("version_info")
        identity = (
            {
                key: version_info[key]
                for key in identity_keys
                if key in version_info and version_info[key] not in (None, "")
            }
            if isinstance(version_info, dict)
            else {}
        )
        candidate: dict[str, object] = {
            "role": "mz_signature_pe_candidate",
            "item_index": item_index,
            "name": row.get("name"),
            "size": row.get("size"),
            "md5": row.get("md5"),
            "sha256": row.get("sha256"),
            "pe_parse_status": pe_metadata.get("parse_status"),
        }
        if identity:
            candidate["program_identity"] = identity
        candidates.append(candidate)
    return {
        "scope": "all exported protocol objects before row filtering/pagination",
        "selection_rule": (
            "MZ-signature candidate with bounded PE metadata; URL/name substrings are not "
            "executable evidence"
        ),
        "candidate_count": len(candidates),
        "selection_ambiguous": len(candidates) != 1,
        "returned_candidate_count": min(len(candidates), _EXPORT_SUMMARY_CANDIDATE_LIMIT),
        "truncated": len(candidates) > _EXPORT_SUMMARY_CANDIDATE_LIMIT,
        "candidates": candidates[:_EXPORT_SUMMARY_CANDIDATE_LIMIT],
    }


def _archive_member_metadata(member: object) -> dict[str, object]:
    """Normalize one listed archive member and expose a safe disk-join affordance."""

    if isinstance(member, dict):
        normalized: dict[str, object] = dict(member)
    else:
        normalized = {"name": str(member)}

    raw_filename = next(
        (
            normalized.get(key)
            for key in ("member_filename", "name", "filename", "path")
            if normalized.get(key) is not None
        ),
        None,
    )
    member_filename = str(raw_filename).strip() if raw_filename is not None else None
    normalized["member_filename"] = member_filename or None
    normalized["role"] = "archive_member"

    member_size: int | None = None
    for key in ("uncompressed_size", "size"):
        value = normalized.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, int) and value >= 0:
            member_size = value
            break
        if isinstance(value, str) and value.strip().isdecimal():
            member_size = int(value.strip())
            break

    raw_crc32 = normalized.get("crc32")
    normalized_crc32: str | None = None
    if isinstance(raw_crc32, int) and not isinstance(raw_crc32, bool):
        if 0 <= raw_crc32 <= 0xFFFFFFFF:
            normalized_crc32 = f"{raw_crc32:08x}"
    elif raw_crc32 is not None:
        candidate = str(raw_crc32).strip().lower()
        if candidate.startswith("0x"):
            candidate = candidate[2:]
        if re.fullmatch(r"[0-9a-f]{1,8}", candidate):
            normalized_crc32 = candidate.zfill(8)

    if member_size is not None:
        normalized["uncompressed_size"] = member_size
    if normalized_crc32 is not None:
        normalized["crc32"] = normalized_crc32
    return normalized


def _archive_member_summary(files: list[dict[str, object]]) -> dict[str, object]:
    """Flatten transferred-archive members into a compact deterministic join view."""

    candidates: list[dict[str, object]] = []
    for item_index, row in enumerate(files):
        archive = row.get("archive")
        if not isinstance(archive, dict) or not isinstance(archive.get("members"), list):
            continue
        for member_index, member in enumerate(archive["members"]):
            if not isinstance(member, dict):
                continue
            candidate: dict[str, object] = {
                "role": "transferred_archive_member",
                "export_item_index": item_index,
                "archive_name": row.get("name"),
                "archive_size": row.get("size"),
                "archive_md5": row.get("md5"),
                "archive_format": archive.get("format"),
                "member_index": member_index,
                "member_filename": member.get("member_filename"),
                "uncompressed_size": member.get(
                    "uncompressed_size", member.get("size")
                ),
                "crc32": member.get("crc32"),
            }
            candidates.append(candidate)
    candidates.sort(
        key=lambda item: (
            str(item.get("archive_name") or ""),
            str(item.get("member_filename") or ""),
            str(item.get("uncompressed_size") or ""),
            str(item.get("crc32") or ""),
        )
    )
    return {
        "scope": "members of every archive reconstructed by this protocol export",
        "candidate_count": len(candidates),
        "selection_ambiguous": len(candidates) != 1,
        "returned_candidate_count": min(len(candidates), _EXPORT_SUMMARY_CANDIDATE_LIMIT),
        "truncated": len(candidates) > _EXPORT_SUMMARY_CANDIDATE_LIMIT,
        "candidates": candidates[:_EXPORT_SUMMARY_CANDIDATE_LIMIT],
    }


def _archive_metadata(path: str, media_type: object, *, limit: int) -> dict | None:
    """List reconstructed archive members without exposing another model tool.

    FTP has no tshark ``--export-objects`` implementation.  Its data streams are
    therefore reconstructed below, and archive metadata must stay attached to
    that same evidence-producing call: a restricted task may expose only
    ``pcap_query`` and cannot safely be expected to invoke a host-path tool.
    ``archive_query`` is the existing verified parser adapter (stdlib ZIP,
    py7zr, or 7-Zip); list mode never extracts or executes a member.
    """

    if media_type not in _ARCHIVE_MEDIA_TYPES:
        return None
    from forensic_agent.tools.archive_tool import archive_query

    listed = archive_query(path, action="list", limit=max(1, min(int(limit or 60), 200)))
    members = [
        _archive_member_metadata(member)
        for member in (listed.get("members") or [])
    ]
    result = {
        "parser": "archive_query",
        "action": "list",
        "format": listed.get("format"),
        "count": listed.get("count"),
        "members": members,
    }
    if listed.get("error") or listed.get("ok") is False:
        result["error"] = str(listed.get("error") or "archive listing failed")[:200]
    return result


def _q_export_ftp(
    TS,
    pcap_path,
    *,
    offset: int = 0,
    limit: int = 50,
    filter: str | None = None,
    metadata_only: bool = False,
):
    """Reconstruct every tshark-identified FTP data stream as an exported object."""

    try:
        proc = _run(
            TS,
            pcap_path,
            [
                "-Y",
                "ftp-data",
                "-T",
                "fields",
                "-e",
                "tcp.stream",
                "-e",
                "ftp-data.command",
            ],
        )
    except Exception as exc:
        return {"error": f"tshark FTP stream discovery failed: {str(exc)[:150]}"}

    streams: dict[int, str | None] = {}
    for line in (proc.stdout or "").splitlines():
        columns = line.rstrip("\r\n").split("\t")
        if not columns or not columns[0].strip():
            continue
        try:
            stream = int(columns[0].split(",", 1)[0].strip())
        except (TypeError, ValueError):
            continue
        command = columns[1].strip() if len(columns) > 1 and columns[1].strip() else None
        streams.setdefault(stream, command)
        if command and not streams[stream]:
            streams[stream] = command

    files: list[dict[str, object]] = []
    warnings_out: list[dict[str, object]] = []
    cleanup_paths: list[str] = []
    for stream, command in sorted(streams.items()):
        # An FTP data connection carries the transferred file in ONE direction; the
        # other carries at most the peer's chatter. Joining the two would hash bytes
        # that were never a file, under the transferred file's name.
        followed = _q_follow(TS, pcap_path, stream, "tcp", select=_FOLLOW_DOMINANT)
        if followed.get("error"):
            warnings_out.append(
                {
                    "code": "ftp_stream_reassembly_failed",
                    "message": str(followed["error"])[:200],
                    "details": {"stream": stream},
                }
            )
            continue
        saved_path = str(followed["saved_path"])
        transfer_name = None
        if command:
            # Wireshark commonly supplies "RETR name" or "STOR name".  Keep
            # only a display basename; it is never used as an output path.
            parts = command.split(maxsplit=1)
            candidate = parts[1] if len(parts) == 2 else parts[0]
            transfer_name = os.path.basename(candidate.replace("\\", "/")) or None
        row: dict[str, object] = {
            "name": transfer_name or f"ftp_stream_{stream}.bin",
            "stream": stream,
            "command": command,
            "saved_path": saved_path,
            "size": followed.get("size"),
            **{
                name: followed[name]
                for name in identification_field_names("type")
                if name in followed
            },
            "md5": followed.get("md5"),
            "sha256": followed.get("sha256"),
        }
        if followed.get("type_mime") in _PE_MEDIA_TYPES:
            try:
                with open(saved_path, "rb") as file_object:
                    pe_metadata = _pe_static_metadata(file_object.read(_PE_PARSE_MAX_BYTES + 1))
            except Exception:
                pe_metadata = None
            if pe_metadata is not None:
                row["pe_metadata"] = pe_metadata
        archive = _archive_metadata(
            saved_path,
            followed.get("type_mime"),
            limit=limit,
        )
        if archive is not None:
            row["archive"] = archive
        if metadata_only:
            row.pop("saved_path", None)
            stream_dir = os.path.dirname(saved_path)
            shutil.rmtree(stream_dir, ignore_errors=True)
            cleanup_paths.append(stream_dir)
        files.append(row)

    from forensic_agent.core.toolio import shape

    result = {
        "query": "export",
        "proto": "ftp",
        "export_method": "tshark-ftp-data-stream-reassembly",
        "exported": len(files),
        "archive_member_summary": _archive_member_summary(files),
        "protocol_scope_note": (
            "FTP data export is the authoritative view for members and CRC values of "
            "archives transferred over FTP."
        ),
        **shape(files, offset=offset, limit=limit, filter=filter),
    }
    if metadata_only:
        result["object_handling"] = {
            "mode": "metadata_only",
            "objects_retained": False,
            "execution_performed": False,
            "cleanup_confirmed": all(not os.path.exists(path) for path in cleanup_paths),
        }
    if proc.returncode != 0 and proc.stderr:
        warnings_out.append(
            {
                "code": "tshark_ftp_discovery_stderr",
                "message": proc.stderr[:300],
            }
        )
    if warnings_out:
        result["warnings"] = warnings_out
    return result


def _q_export(
    TS,
    pcap_path,
    proto,
    offset: int = 0,
    limit: int = 50,
    filter: str | None = None,
    metadata_only: bool = False,
):
    proto = (proto or "").lower()
    if proto not in _EXPORT_PROTOS:
        return {"error": f"query='export' needs proto in {sorted(_EXPORT_PROTOS)}."}
    if proto == "ftp":
        return _q_export_ftp(
            TS,
            pcap_path,
            offset=offset,
            limit=limit,
            filter=filter,
            metadata_only=metadata_only,
        )
    outdir = _contained_scratch(
        "forensic_agent_obj_", subject="objects exported from a capture"
    )
    try:
        proc = _run(TS, pcap_path, ["--export-objects", f"{proto},{outdir}"])
    except Exception as e:
        return tool_failure_result(e, subject=str(pcap_path), backend="tshark")
    returncode = int(getattr(proc, "returncode", 0) or 0)
    files = []
    for name in sorted(os.listdir(outdir)):
        fp = os.path.join(outdir, name)
        if not os.path.isfile(fp):
            continue
        with open(fp, "rb") as fh:
            data = fh.read()
        row = {"name": name, "saved_path": fp, **_hashes(data)}
        pe_metadata = _pe_static_metadata(data)
        if pe_metadata is not None:
            row["pe_metadata"] = pe_metadata
        files.append(row)
    # Shared envelope instead of a hard files[:50] cap: a large export set (100+ objects)
    # stays fully reachable via offset/limit paging and a name/hash substring filter,
    # so the one file that matters cannot be silently truncated out of view.
    from forensic_agent.core.toolio import shape
    if metadata_only:
        for row in files:
            row.pop("saved_path", None)
        shutil.rmtree(outdir, ignore_errors=True)
    result = {
        "query": "export",
        "proto": proto,
        "exported": len(files),
        "executable_summary": _pe_executable_summary(files),
        "protocol_scope_note": (
            f"This result contains {proto.upper()} objects only. It cannot establish "
            "member names or CRC values for an archive transferred over FTP; for such "
            "a question call pcap_query(operation='ftp_objects'), which is the only "
            "call the schema accepts for the FTP route — export refuses proto='ftp'."
        ),
        **shape(files, offset=offset, limit=limit, filter=filter),
    }
    if returncode != 0:
        # An export that could not run and a capture that carried no objects both
        # leave the directory empty, so the exit status is the only thing that
        # tells them apart and it has to reach the caller.
        result["returncode"] = returncode
        result["stderr"] = (proc.stderr or "tshark returned no diagnostic output")[:300]
        result["coverage_complete"] = False
        result["scan_complete"] = False
        result["error"] = {
            "code": "tshark_partial_output" if files else "tshark_query_failed",
            "message": (
                "tshark returned a non-zero exit status; any exported objects are "
                "partial and an empty result cannot establish that the capture "
                "carried none"
            ),
        }
    if metadata_only:
        result["object_handling"] = {
            "mode": "metadata_only",
            "objects_retained": False,
            "execution_performed": False,
            "cleanup_confirmed": not os.path.exists(outdir),
        }
    else:
        result["dir"] = outdir
    return result


def _q_follow(
    TS,
    pcap_path,
    stream,
    transport,
    *,
    metadata_only: bool = False,
    select: str = _FOLLOW_BOTH,
):
    if stream is None:
        return {"error": "query='follow' needs 'stream' (int index; find it via query='stat', stat='conv,tcp')."}
    try:
        si = int(stream)
    except Exception:
        return {"error": "stream must be an integer index."}
    tr = (transport or "tcp").lower()
    if tr not in ("tcp", "udp"):
        return {"error": "transport must be tcp or udp."}
    try:
        proc = _run(TS, pcap_path, ["-q", "-z", f"follow,{tr},raw,{si}"])
    except Exception as e:
        return tool_failure_result(e, subject=str(pcap_path), backend="tshark")
    combined, forward, reverse = _follow_directions(proc.stdout)
    data = _selected_follow_payload(combined, forward, reverse, select)
    directions = {
        _FOLLOW_FORWARD: _hashes(forward),
        _FOLLOW_REVERSE: _hashes(reverse),
    }
    both_carry_payload = bool(forward) and bool(reverse)
    if metadata_only:
        preview = data[:_FOLLOW_PREVIEW_BYTES]
        return {
            "query": "follow",
            "stream": si,
            "transport": tr,
            **_hashes(data),
            "total_bytes": len(data),
            "returned_bytes": len(preview),
            "text_preview": preview.decode("utf-8", errors="replace"),
            "hex_preview": preview.hex(),
            "truncated": len(preview) < len(data),
            "content_sample_truncated": len(preview) < len(data),
            "selected_direction": select,
            "directions": directions,
            **_follow_direction_note(select, both_carry_payload),
            "object_handling": {
                "mode": "metadata_only",
                "objects_retained": False,
                "execution_performed": False,
                "cleanup_confirmed": True,
            },
        }
    outdir = _contained_scratch(
        "forensic_agent_follow_", subject="a reassembled stream followed from a capture"
    )
    fp = os.path.join(outdir, f"stream_{si}.bin")
    with open(fp, "wb") as fh:
        fh.write(data)
    return {
        "query": "follow",
        "stream": si,
        "transport": tr,
        "saved_path": fp,
        **_hashes(data),
        "selected_direction": select,
        "directions": directions,
        **_follow_direction_note(select, both_carry_payload),
    }


def pcap_query(pcap_path: str, query: str = "dns", limit: int = 100,
               save_path: str | None = None, fields=None, display_filter=None,
               stat=None, proto=None, stream=None, transport: str = "tcp",
               offset: int = 0, filter: str | None = None,
               metadata_only: bool = False) -> dict:
    """Run a read-only tshark (Wireshark) analysis on a packet capture. Use for
    DNS/HTTP/protocol views over a .pcap; to reconstruct a file exfiltrated over
    HTTP headers use reconstruct_http_exfil instead (here query='dns_exfil'
    reconstructs DNS-tunnelled payloads).

    Example: pcap_query(pcap_path, query="dns", limit=100)

    Input: `pcap_path` is the capture file; `query` is one of dns, dns_exfil,
    http, ftp, telnet, protocols, conversations, endpoints, fields, stat,
    export, ftp_objects, http_objects, follow;
    `limit` caps returned rows;
    `save_path` sets where a reconstructed dns_exfil payload is written.
    Read-only over the evidence.

    For the set of hosts — the network layout, the subnet, which addresses talked
    to which — use query="endpoints" or query="conversations": each enumerates every
    IP (or IP pair) in the capture as one complete-coverage result, so the whole host
    list is read at once. The per-packet routes (query="fields"/"dns"/"http") page
    over the fully filtered set, so an answer about which hosts EXIST must not rest on
    a single page of them; the statistics above already carry every host.

    General pass-through (you pick the tshark query — no fixed list): query="fields"
    with fields=[tshark field names] (+ optional display_filter) extracts ANY fields
    (e.g. ['eth.src','eth.dst'] for MAC, ['ftp.request.command','ftp.request.arg'] for
    FTP creds/filenames). It preserves positional `rows` and also returns self-describing
    `named_rows`; when request/response fields and both endpoints are selected, each named
    row carries explicit `endpoint_roles`. query="stat" with
    stat="conv,eth"/"endpoints,eth"/"io,phs" runs any -z statistic.

    Export results include a protocol_scope_note. FTP export also includes a compact
    archive_member_summary; other export protocols include an executable_summary whose
    candidates require an MZ signature and bounded PE metadata rather than filename substrings.

    Returns: {"query", "packet_count", ...}. 'dns' adds distinct_query_names,
    top_query_names and rows; field queries (http, ...) add rows; stat queries
    (protocols/conversations/endpoints) return {"query", "output"} (raw tshark
    text); 'dns_exfil' merges the reconstruct_dns_exfil result. On failure
    returns {"error"}.
    """
    if not pcap_path or not os.path.exists(pcap_path):
        return {"error": "pcap not available (attach one with --pcap / /pcap)."}
    TS = tshark_path()
    if not TS:
        return {"error": "Wireshark 'tshark' not found. Install Wireshark (it includes "
                         "tshark), add it to PATH, or set DFA_TSHARK. "
                         "Run `dfir-agent --doctor`."}
    q = (query or "dns").lower()
    if q not in PCAP_QUERY_OPERATIONS:
        # The registry gates execution: this membership check runs before every
        # dispatch branch, so an operation removed from PCAP_QUERY_OPERATIONS can
        # no longer be executed by any early-returning branch.  Naming only the
        # curated views made every other protocol look absent from the capture,
        # when the general routes reach all of them.
        curated = sorted(
            set(FIELD_QUERIES)
            | set(STAT_QUERIES)
            | set(CURATED_PROTOCOL_FIELDS)
            | {"dns_exfil", "ftp_objects", "http_objects"}
        )
        return {
            "error": f"unknown query '{query}'. Curated views: "
            f"{', '.join(curated)}. Any other protocol is still reachable: "
            "query='fields' with fields=[tshark field names] and an optional display_filter "
            "(e.g. fields=['frame.number','telnet.data'], display_filter='telnet'), "
            "query='follow' with stream=<n> to read one whole TCP stream, or "
            "query='protocols' to see which protocols the capture actually contains.",
            "deterministic_error": True,
        }
    if display_filter and q != "fields":
        # Only the field-extraction route passes a filter to tshark. Running a
        # curated view instead answered a different question and never said the
        # filter had been dropped, which reads as "this protocol is not here".
        return {
            "error": f"display_filter is only applied by query='fields', not by query='{q}'. "
            "Call query='fields' with fields=[tshark field names] and the same display_filter, "
            "for example fields=['frame.number','telnet.data'] with display_filter='telnet'.",
            "deterministic_error": True,
        }
    if q == "fields":
        return _q_fields(
            TS,
            pcap_path,
            fields,
            display_filter,
            limit,
            offset=offset,
            filter=filter,
            metadata_only=metadata_only,
        )
    if q in CURATED_PROTOCOL_FIELDS:
        return _q_fields(
            TS,
            pcap_path,
            CURATED_PROTOCOL_FIELDS[q],
            q,
            limit,
            offset=offset,
            filter=filter,
            metadata_only=metadata_only,
        )
    if q == "stat":
        return _q_stat(TS, pcap_path, stat)
    if q == "export":
        return _q_export(
            TS,
            pcap_path,
            proto,
            offset=offset,
            limit=limit,
            filter=filter,
            metadata_only=metadata_only,
        )
    if q in {"ftp_objects", "http_objects"}:
        return _q_export(
            TS,
            pcap_path,
            q.removesuffix("_objects"),
            offset=offset,
            limit=limit,
            filter=filter,
            metadata_only=metadata_only,
        )
    if q == "follow":
        return _q_follow(
            TS,
            pcap_path,
            stream,
            transport,
            metadata_only=metadata_only,
        )

    try:
        if q in STAT_QUERIES:
            proc = _run(TS, pcap_path, STAT_QUERIES[q])
            out = {"query": q, "output": (proc.stdout or "")[:3000]}
            returncode = int(getattr(proc, "returncode", 0) or 0)
            if returncode != 0:
                out.update(
                    {
                        "returncode": returncode,
                        "stderr": (
                            proc.stderr or "tshark returned no diagnostic output"
                        )[:300],
                        "coverage_complete": False,
                        "scan_complete": False,
                        "error": {
                            "code": (
                                "tshark_partial_output"
                                if proc.stdout
                                else "tshark_query_failed"
                            ),
                            "message": (
                                "tshark returned a non-zero exit status; the statistic "
                                "is not a complete result"
                            ),
                        },
                    }
                )
            return out
        args = FIELD_QUERIES["dns" if q == "dns_exfil" else q]
        proc = _run(TS, pcap_path, args)
    except Exception as e:
        return tool_failure_result(e, subject=str(pcap_path), backend="tshark")

    rows = _field_rows(proc.stdout)

    returncode = int(getattr(proc, "returncode", 0) or 0)
    if returncode != 0 and not rows:
        return {
            "query": q,
            "returncode": returncode,
            "stderr": (proc.stderr or "tshark returned no diagnostic output")[:300],
            "coverage_complete": False,
            "scan_complete": False,
            "error": {
                "code": "tshark_query_failed",
                "message": (
                    "tshark returned a non-zero exit status; an empty result cannot "
                    "establish absence"
                ),
            },
        }

    if q == "dns_exfil":
        names = [r[3] for r in rows if len(r) >= 4 and r[3]]
        result = {
            "query": q,
            "packet_count": len(names),
            **reconstruct_dns_exfil(names, save_path),
        }
        if returncode != 0:
            result.update(
                {
                    "returncode": returncode,
                    "stderr": (
                        proc.stderr or "tshark returned no diagnostic output"
                    )[:300],
                    "coverage_complete": False,
                    "scan_complete": False,
                    "error": {
                        "code": "tshark_partial_output",
                        "message": (
                            "tshark returned a non-zero exit status; the reconstructed "
                            "payload is based on partial output"
                        ),
                    },
                }
            )
        return result

    from forensic_agent.core.toolio import shape

    envelope = shape(rows, offset=offset, limit=limit, filter=filter)
    page = envelope["rows"]
    result = {"query": q, "packet_count": len(rows), **envelope}
    selected_fields = _selected_field_names(args)
    if selected_fields:
        result["fields"] = selected_fields
        result["named_rows"] = _named_field_rows(selected_fields, page)
    if q == "dns":
        matching_rows = _matching_rows(rows, filter)
        name_counts = collections.Counter(
            r[3] for r in matching_rows if len(r) >= 4 and r[3]
        )
        result["distinct_query_names"] = len(name_counts)
        result["top_query_names"] = name_counts.most_common(40)
    if returncode != 0:
        result.update(
            {
                "returncode": returncode,
                "stderr": (proc.stderr or "tshark returned no diagnostic output")[:300],
                "coverage_complete": False,
                "scan_complete": False,
                "error": {
                    "code": "tshark_partial_output",
                    "message": (
                        "tshark returned a non-zero exit status; emitted rows are partial"
                    ),
                },
            }
        )
    return result
