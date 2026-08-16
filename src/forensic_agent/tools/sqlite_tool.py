"""Read-only, bounded SQLite inspection for databases inside disk images.

The evidence file is copied into an attested controlled-scratch allocation and
opened by Python's in-process SQLite library.  No subprocess or network API is
used.  WAL, shared-memory, rollback-journal, super-journal, and basename-derived
statement-journal companions are never replayed: only the main database file is
copied and it is opened immutable. When a companion IS present the tool reads the
committed main database anyway and discloses the companion in
``journal_coverage.read_despite_companion`` (a rollback journal at rest leaves the
main file at its last committed state; a WAL may hold committed-but-uncheckpointed
pages this read does not reflect) rather than refusing real evidence outright. It
still fails closed only when it cannot even prove what companions exist (an
incomplete or unsafe parent-directory listing). SQLite can give statement journals
randomized OS-temporary names that cannot be associated with a captured database by
filename; this limitation is explicit in every
``journal_coverage.association_scope`` record.
"""

from __future__ import annotations

import base64
import hashlib
import math
import sqlite3
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Literal, cast

from forensic_agent.core.controlled_scratch import ControlledScratchSession, ScratchKind
from forensic_agent.core.evidence_locator import (
    EvidencePathError,
    evidence_locator_commitment,
    evidence_parent,
    normalize_evidence_path,
    validate_evidence_name,
)

MAX_DATABASE_BYTES = 1 << 30
MAX_PARENT_DIRECTORY_ENTRIES = 100_000
MAX_QUERY_CHARS = 4096
MAX_QUERY_UTF8_BYTES = 16_384
MAX_ROWS = 100
MAX_COLUMNS = 64
MAX_CELLS = 1_000
MAX_CELL_BYTES = 4096
MAX_COLUMN_NAME_BYTES = 256
QUERY_TIMEOUT_SECONDS = 2.0
SQLITE_VALUE_LENGTH_LIMIT = 262_144

_SCALAR_PRAGMAS = {
    "application_id",
    "data_version",
    "encoding",
    "freelist_count",
    "journal_mode",
    "page_count",
    "page_size",
    "schema_version",
    "user_version",
}
_ARGUMENT_PRAGMAS = {
    "foreign_key_list",
    "index_info",
    "index_list",
    "index_xinfo",
    "integrity_check",
    "quick_check",
    "table_info",
    "table_xinfo",
}
_READ_ONLY_PRAGMAS = _SCALAR_PRAGMAS | _ARGUMENT_PRAGMAS
_FORBIDDEN_FUNCTIONS = {
    "edit",
    "fts3_tokenizer",
    "load_extension",
    "readfile",
    "shell_add_schema",
    "writefile",
}


class _DatabaseTooLarge(RuntimeError):
    pass


class _InvalidSql(ValueError):
    pass


class _LimitedHashingWriter:
    """Bound an extraction while committing the exact parser copy."""

    def __init__(self, writer: BinaryIO, limit: int) -> None:
        self._writer = writer
        self._limit = limit
        self.size = 0
        self._sha256 = hashlib.sha256()

    def write(self, data: bytes) -> int:
        if not isinstance(data, bytes):
            raise TypeError("SQLite extraction received non-byte content")
        if self.size + len(data) > self._limit:
            raise _DatabaseTooLarge
        written = self._writer.write(data)
        if written != len(data):
            raise OSError("short controlled-scratch write")
        self._sha256.update(data)
        self.size += len(data)
        return written

    @property
    def sha256(self) -> str:
        return self._sha256.hexdigest()


@dataclass(slots=True)
class _ExecutedQuery:
    columns: list[object]
    rows: list[list[object]]
    truncated: bool
    complete: bool
    effective_row_limit: int = 0
    error_code: str | None = None
    error_message: str | None = None


def _failure(
    path: str,
    *,
    code: str,
    message: str,
    reason: str | None = None,
    journal_coverage: Mapping[str, object] | None = None,
) -> dict[str, object]:
    result: dict[str, object] = {
        "path": path,
        "error": {"code": code, "message": message},
        "scan_complete": False,
        "coverage": {
            "complete": False,
            "scope": path,
            "reason": reason or message,
        },
    }
    if journal_coverage is not None:
        result["journal_coverage"] = dict(journal_coverage)
    return result


def _journal_coverage(disk, path: str) -> tuple[dict[str, object], str | None]:
    parent, basename = evidence_parent(path)
    record: dict[str, object] = {
        "policy": "fail-closed-if-companion-present-or-parent-listing-incomplete.v1",
        "parent": parent,
        "parent_listing_complete": False,
        "parent_entry_limit": MAX_PARENT_DIRECTORY_ENTRIES,
        "parent_enumeration_bound_mode": "adapter-enforced-required",
        "association_scope": (
            "same-directory database-derived rollback/WAL/SHM/super-journal/"
            "statement-journal names, including conservative 8.3 recovery alternates; "
            "randomized OS-temp statement files cannot be attributed by filename"
        ),
        "randomized_statement_journal_attribution_complete": False,
        "checked_companion_classes": [
            "wal",
            "shared_memory",
            "rollback_journal",
            "master_journal",
            "statement_journal",
        ],
        "companion_classes_present": [],
        "companion_count": 0,
        "complete_for_declared_same_directory_scope": False,
        "complete": False,
    }
    bounded_lister = getattr(disk, "list_directory_bounded", None)
    if not callable(bounded_lister):
        return record, "sqlite_parent_listing_unbounded"
    try:
        listing = bounded_lister(parent, max_entries=MAX_PARENT_DIRECTORY_ENTRIES)
    except Exception:
        return record, "sqlite_parent_unreadable"
    if not isinstance(listing, Mapping) or not isinstance(listing.get("entries"), list):
        return record, "sqlite_parent_listing_malformed"
    if (
        listing.get("incomplete") is True
        or listing.get("scan_complete") is False
        or listing.get("enumeration_complete") is False
    ):
        return record, "sqlite_parent_listing_incomplete"

    companion_classes: set[str] = set()
    companion_count = 0
    unsafe_name = False
    base_folded = basename.casefold()
    short_stem = base_folded.rsplit(".", 1)[0]
    for entry in listing["entries"]:
        if not isinstance(entry, Mapping):
            unsafe_name = True
            continue
        try:
            name = validate_evidence_name(entry.get("name"))
        except EvidencePathError:
            unsafe_name = True
            continue
        folded = name.casefold()
        companion_class = None
        if (
            folded == base_folded + "-wal"
            or folded.startswith(base_folded + "-wal2")
            or folded == short_stem + ".wal"
        ):
            companion_class = "wal"
        elif folded == base_folded + "-shm" or folded == short_stem + ".shm":
            companion_class = "shared_memory"
        elif folded == base_folded + "-journal" or folded == short_stem + ".nal":
            companion_class = "rollback_journal"
        elif folded.startswith(base_folded + "-mj"):
            companion_class = "master_journal"
        elif folded.startswith(base_folded + "-stmtjrnl"):
            companion_class = "statement_journal"
        if companion_class is not None:
            companion_count += 1
            companion_classes.add(companion_class)
    record["companion_classes_present"] = sorted(companion_classes)
    record["companion_count"] = companion_count
    if unsafe_name:
        return record, "sqlite_parent_listing_unsafe_entry"
    record["parent_listing_complete"] = True
    if companion_count:
        return record, "sqlite_companion_present"
    record["complete_for_declared_same_directory_scope"] = True
    record["complete"] = True
    return record, None


def _lex_sql(sql: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    index = 0
    length = len(sql)
    while index < length:
        character = sql[index]
        if character.isspace():
            index += 1
            continue
        if sql.startswith("--", index):
            newline = sql.find("\n", index + 2)
            index = length if newline < 0 else newline + 1
            continue
        if sql.startswith("/*", index):
            end = sql.find("*/", index + 2)
            if end < 0:
                raise _InvalidSql("SQL contains an unterminated comment")
            index = end + 2
            continue
        if character in {"'", '"', "`"}:
            quote = character
            start = index
            index += 1
            while index < length:
                if sql[index] == quote:
                    if index + 1 < length and sql[index + 1] == quote:
                        index += 2
                        continue
                    index += 1
                    break
                index += 1
            else:
                raise _InvalidSql("SQL contains an unterminated quoted value")
            tokens.append(("quoted", sql[start:index]))
            continue
        if character == "[":
            end = sql.find("]", index + 1)
            if end < 0:
                raise _InvalidSql("SQL contains an unterminated quoted identifier")
            tokens.append(("quoted", sql[index : end + 1]))
            index = end + 1
            continue
        if character.isalpha() or character == "_":
            start = index
            index += 1
            while index < length and (sql[index].isalnum() or sql[index] in {"_", "$"}):
                index += 1
            tokens.append(("word", sql[start:index]))
            continue
        tokens.append(("symbol", character))
        index += 1
    return tokens


def _validate_sql(sql: str) -> tuple[Literal["select", "pragma"], list[tuple[str, str]]]:
    if not isinstance(sql, str) or not sql.strip():
        raise _InvalidSql("query must be non-empty SQL text")
    if "\x00" in sql or len(sql) > MAX_QUERY_CHARS:
        raise _InvalidSql("query is malformed or exceeds the hard character limit")
    if len(sql.encode("utf-8")) > MAX_QUERY_UTF8_BYTES:
        raise _InvalidSql("query exceeds the hard UTF-8 byte limit")
    tokens = _lex_sql(sql)
    if not tokens:
        raise _InvalidSql("query contains no SQL statement")
    semicolons = [index for index, token in enumerate(tokens) if token == ("symbol", ";")]
    if len(semicolons) > 1 or (semicolons and semicolons[0] != len(tokens) - 1):
        raise _InvalidSql("stacked or multiple SQL statements are not allowed")
    if semicolons:
        tokens = tokens[:-1]
    if not tokens or tokens[0][0] != "word":
        raise _InvalidSql("query must begin with SELECT, WITH, EXPLAIN, or PRAGMA")
    first = tokens[0][1].casefold()
    if first in {"select", "with"}:
        return "select", tokens
    if first == "explain":
        words = [value.casefold() for kind, value in tokens[1:] if kind == "word"]
        if words[:2] == ["query", "plan"]:
            words = words[2:]
        if not words or words[0] not in {"select", "with"}:
            raise _InvalidSql("EXPLAIN is limited to SELECT or WITH ... SELECT")
        return "select", tokens
    if first == "pragma":
        if len(tokens) < 2 or tokens[1][0] not in {"word", "quoted"}:
            raise _InvalidSql("PRAGMA must name one allowed read-only pragma")
        pragma_name = tokens[1][1].strip('"`[]').casefold()
        if pragma_name not in _READ_ONLY_PRAGMAS:
            raise _InvalidSql("PRAGMA is not in the read-only inspection allowlist")
        if any(token == ("symbol", "=") for token in tokens):
            raise _InvalidSql("PRAGMA assignment is not allowed")
        return "pragma", tokens
    raise _InvalidSql(
        "only SELECT, WITH ... SELECT, EXPLAIN SELECT, and read-only PRAGMA are allowed"
    )


def _authorizer(
    action: int, arg1: str | None, arg2: str | None, _db: str | None, _source: str | None
) -> int:
    allowed_actions = {
        value
        for value in (
            getattr(sqlite3, "SQLITE_SELECT", None),
            getattr(sqlite3, "SQLITE_READ", None),
            getattr(sqlite3, "SQLITE_FUNCTION", None),
            getattr(sqlite3, "SQLITE_RECURSIVE", None),
        )
        if value is not None
    }
    if action in allowed_actions:
        if action == getattr(sqlite3, "SQLITE_FUNCTION", -1):
            function_name = str(arg2 or arg1 or "").casefold()
            if function_name in _FORBIDDEN_FUNCTIONS:
                return sqlite3.SQLITE_DENY
        if action == getattr(sqlite3, "SQLITE_READ", -1):
            table_name = str(arg1 or "").casefold()
            if table_name.startswith("pragma_"):
                pragma_name = table_name.removeprefix("pragma_")
                if pragma_name not in _READ_ONLY_PRAGMAS:
                    return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK
    if action == getattr(sqlite3, "SQLITE_PRAGMA", -1):
        pragma_name = str(arg1 or "").casefold()
        if pragma_name not in _READ_ONLY_PRAGMAS:
            return sqlite3.SQLITE_DENY
        if arg2 not in (None, "") and pragma_name not in _ARGUMENT_PRAGMAS:
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def _set_sqlite_limits(connection: sqlite3.Connection) -> None:
    limits = {
        "SQLITE_LIMIT_LENGTH": SQLITE_VALUE_LENGTH_LIMIT,
        "SQLITE_LIMIT_SQL_LENGTH": MAX_QUERY_UTF8_BYTES,
        "SQLITE_LIMIT_COLUMN": MAX_COLUMNS,
        "SQLITE_LIMIT_EXPR_DEPTH": 100,
        "SQLITE_LIMIT_COMPOUND_SELECT": 20,
        "SQLITE_LIMIT_VARIABLE_NUMBER": 100,
        "SQLITE_LIMIT_ATTACHED": 0,
        "SQLITE_LIMIT_LIKE_PATTERN_LENGTH": 1_000,
    }
    for constant_name, value in limits.items():
        constant = getattr(sqlite3, constant_name, None)
        if constant is not None:
            connection.setlimit(constant, value)


def _open_read_only(path: Path) -> sqlite3.Connection:
    uri = path.as_uri() + "?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True, timeout=0.1, isolation_level=None)
    connection.enable_load_extension(False)
    connection.execute("PRAGMA query_only=ON")
    connection.execute("PRAGMA temp_store=MEMORY")
    try:
        connection.execute("PRAGMA trusted_schema=OFF")
    except sqlite3.DatabaseError:
        pass
    _set_sqlite_limits(connection)
    connection.set_authorizer(_authorizer)
    return connection


def _bounded_text(value: str, limit: int) -> str | dict[str, object]:
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= limit:
        return value
    prefix = encoded[:limit].decode("utf-8", errors="ignore")
    return {
        "type": "text",
        "value_prefix": prefix,
        "original_bytes": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "truncated": True,
    }


def _bounded_cell(value: object) -> object:
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, bytes):
        prefix_bytes = (MAX_CELL_BYTES // 4) * 3
        prefix = value[:prefix_bytes]
        return {
            "type": "blob",
            "size_bytes": len(value),
            "sha256": hashlib.sha256(value).hexdigest(),
            "base64_prefix": base64.b64encode(prefix).decode("ascii"),
            "truncated": len(prefix) < len(value),
        }
    return _bounded_text(str(value), MAX_CELL_BYTES)


def _sqlite_error(exc: sqlite3.Error) -> tuple[str, str]:
    message = str(exc).casefold()
    if "interrupted" in message:
        return "sqlite_query_timeout", "SQLite query exceeded the fixed execution limit."
    if "not authorized" in message or "authorization denied" in message:
        return "sqlite_operation_denied", "SQLite authorizer denied a non-read-only operation."
    if "not a database" in message or "malformed" in message or "corrupt" in message:
        return "sqlite_malformed", "SQLite database is malformed or unreadable."
    if "too many columns" in message or "too big" in message or "string or blob too big" in message:
        return "sqlite_limit_exceeded", "SQLite query exceeded a fixed structural limit."
    return "sqlite_query_failed", "SQLite could not execute the read-only query."


def _execute(
    connection: sqlite3.Connection,
    sql: str,
    *,
    parameters: tuple[object, ...] = (),
    max_rows: int,
    deadline: float,
) -> _ExecutedQuery:
    connection.set_progress_handler(lambda: 1 if time.monotonic() >= deadline else 0, 1_000)
    cursor = connection.cursor()
    rows: list[list[object]] = []
    columns: list[object] = []
    row_cap = 0
    try:
        cursor.execute(sql, parameters)
        description = cursor.description or ()
        if len(description) > MAX_COLUMNS:
            return _ExecutedQuery(
                [],
                [],
                False,
                False,
                error_code="sqlite_limit_exceeded",
                error_message="SQLite query returned too many columns.",
            )
        for column in description:
            columns.append(_bounded_text(str(column[0]), MAX_COLUMN_NAME_BYTES))
        row_cap = min(max_rows, max(1, MAX_CELLS // max(1, len(columns))))
        for _index in range(row_cap):
            row = cursor.fetchone()
            if row is None:
                return _ExecutedQuery(columns, rows, False, True, row_cap)
            rows.append([_bounded_cell(value) for value in row])
        has_more = cursor.fetchone() is not None
        return _ExecutedQuery(columns, rows, has_more, True, row_cap)
    except sqlite3.Error as exc:
        code, message = _sqlite_error(exc)
        return _ExecutedQuery(
            columns,
            rows,
            False,
            False,
            row_cap,
            code,
            message,
        )
    finally:
        connection.set_progress_handler(None, 0)
        cursor.close()


def _schema_query(
    connection: sqlite3.Connection,
    table: str | None,
    *,
    max_rows: int,
    deadline: float,
) -> _ExecutedQuery:
    if table is None:
        return _execute(
            connection,
            """SELECT type, name, tbl_name, rootpage, sql
               FROM sqlite_schema
               WHERE type IN ('table','view','index','trigger')
               ORDER BY type, name COLLATE BINARY""",
            max_rows=max_rows,
            deadline=deadline,
        )
    if (
        not isinstance(table, str)
        or not table
        or len(table.encode("utf-8")) > MAX_COLUMN_NAME_BYTES
    ):
        return _ExecutedQuery(
            [],
            [],
            False,
            False,
            error_code="invalid_table_name",
            error_message="table must be a bounded non-empty name",
        )
    if "\x00" in table:
        return _ExecutedQuery(
            [],
            [],
            False,
            False,
            error_code="invalid_table_name",
            error_message="table name contains a NUL character",
        )
    # The table name is a bound value, never interpolated into SQL.
    return _execute(
        connection,
        """SELECT 'object' AS record_kind, type, name, tbl_name, sql, NULL, NULL, NULL
             FROM sqlite_schema WHERE name = ? COLLATE BINARY
           UNION ALL
           SELECT 'column', NULL, name, NULL, type, cid, "notnull", pk
             FROM pragma_table_xinfo(?)
           UNION ALL
           SELECT 'index', NULL, name, NULL, NULL, seq, "unique", partial
             FROM pragma_index_list(?)
           ORDER BY record_kind, name COLLATE BINARY""",
        parameters=(table, table, table),
        max_rows=max_rows,
        deadline=deadline,
    )


def sqlite_query(
    disk,
    path: str,
    *,
    query: str | None = None,
    table: str | None = None,
    max_rows: int = 50,
    scratch: ControlledScratchSession | None = None,
) -> dict[str, object]:
    """Inspect or query one in-image SQLite database without host-path exposure.

    Omit ``query`` to list schema objects; add ``table`` to inspect one table's
    columns and indexes.  User SQL is limited to one SELECT/CTE, EXPLAIN SELECT,
    or an allowlisted read-only PRAGMA.  Results are bounded by rows, columns,
    cells, cell bytes, SQL length, database size, and a fixed VM time limit.
    """

    try:
        normalized = normalize_evidence_path(path, allow_root=False)
    except EvidencePathError as exc:
        return _failure(
            evidence_locator_commitment(path),
            code="invalid_evidence_path",
            message=str(exc),
        )
    if isinstance(max_rows, bool) or not isinstance(max_rows, int) or not 1 <= max_rows <= MAX_ROWS:
        return _failure(
            normalized,
            code="invalid_row_limit",
            message=f"max_rows must be an integer from 1 through {MAX_ROWS}.",
        )
    if query is not None and table is not None:
        return _failure(
            normalized,
            code="ambiguous_sqlite_request",
            message="table inspection and a custom query cannot be requested together.",
        )
    if table is not None and (
        not isinstance(table, str)
        or not table
        or "\x00" in table
        or len(table.encode("utf-8")) > MAX_COLUMN_NAME_BYTES
    ):
        return _failure(
            normalized,
            code="invalid_table_name",
            message="table must be a bounded non-empty SQLite object name.",
        )
    query_kind: Literal["select", "pragma", "schema"]
    if query is not None:
        try:
            query_kind, query_tokens = _validate_sql(query)
        except _InvalidSql as exc:
            return _failure(normalized, code="invalid_read_only_sql", message=str(exc))
    else:
        query_kind, query_tokens = "schema", []
    if type(scratch) is not ControlledScratchSession:
        return _failure(
            normalized,
            code="controlled_scratch_required",
            message="SQLite inspection requires an attested controlled-scratch session.",
        )
    scratch_session = cast(ControlledScratchSession, scratch)

    journal_coverage, journal_error = _journal_coverage(disk, normalized)
    if journal_error is not None:
        messages = {
            "sqlite_companion_present": (
                "A SQLite WAL, shared-memory, or journal companion is present; "
                "this tool does not replay companions and therefore refuses the database."
            ),
            "sqlite_parent_listing_incomplete": "The parent directory listing was incomplete, so journal absence cannot be proved.",
            "sqlite_parent_listing_unsafe_entry": "The parent directory contained an unsafe entry name, so journal absence cannot be proved.",
            "sqlite_parent_listing_unbounded": "The disk adapter cannot enforce the fixed parent-directory entry cap, so journal absence cannot be proved safely.",
        }
        if journal_error == "sqlite_companion_present":
            # Forensic SQLite stores (browser history, app databases) almost always
            # carry a rollback-journal/WAL/SHM companion at rest, so refusing them
            # outright makes the tool unusable on real evidence. The extraction below
            # copies ONLY the main database file and opens it immutable, so no
            # companion is ever replayed; reading the committed main database is
            # therefore well defined. Read it and DISCLOSE the companion instead of
            # withholding the data: a rollback journal at rest leaves the main file
            # at its last committed state; a -wal may hold committed-but-
            # uncheckpointed pages this read does not reflect. Interpreting that is
            # the caller's work, so the fact rides along in journal_coverage.
            journal_coverage = dict(journal_coverage or {})
            journal_coverage["read_despite_companion"] = {
                "companion_present": True,
                "main_database_state": "last committed state; companions are not replayed",
                "caveat": (
                    "Rows reflect the committed main database only. A rollback journal "
                    "at rest means the main file is at its last committed state; a WAL "
                    "may hold committed-but-uncheckpointed transactions this read does "
                    "not include."
                ),
            }
        else:
            return _failure(
                normalized,
                code=journal_error,
                message=messages.get(
                    journal_error, "The parent directory could not prove SQLite companion-file absence."
                ),
                journal_coverage=journal_coverage,
            )

    try:
        metadata = disk.file_metadata(normalized)
    except Exception:
        return _failure(
            normalized,
            code="sqlite_file_unreadable",
            message="The requested in-image database could not be read.",
            journal_coverage=journal_coverage,
        )
    metadata_size = metadata.get("size") if isinstance(metadata, Mapping) else None
    if isinstance(metadata_size, bool) or not isinstance(metadata_size, int) or metadata_size < 0:
        metadata_size = None
    if metadata_size is not None and metadata_size > MAX_DATABASE_BYTES:
        return _failure(
            normalized,
            code="sqlite_database_too_large",
            message="The database exceeds the fixed controlled-scratch byte limit.",
            journal_coverage=journal_coverage,
        )

    result: dict[str, object]
    with scratch_session.artifact(ScratchKind.SQLITE_DB) as artifact:
        writer = _LimitedHashingWriter(artifact.writer, MAX_DATABASE_BYTES)
        try:
            extractor = getattr(disk, "extract_file_to", None)
            if callable(extractor):
                extractor(normalized, writer)
            else:
                iterator = getattr(disk, "iter_file_chunks", None)
                if not callable(iterator):
                    return _failure(
                        normalized,
                        code="sqlite_byte_stream_unavailable",
                        message="The disk adapter cannot make a byte-accurate parser copy.",
                        journal_coverage=journal_coverage,
                    )
                for chunk in iterator(normalized, chunk_size=1 << 20):
                    writer.write(chunk)
        except _DatabaseTooLarge:
            return _failure(
                normalized,
                code="sqlite_database_too_large",
                message="The database exceeded the fixed controlled-scratch byte limit during extraction.",
                journal_coverage=journal_coverage,
            )
        except Exception:
            return _failure(
                normalized,
                code="sqlite_extraction_failed",
                message="The in-image database could not be copied completely for parsing.",
                journal_coverage=journal_coverage,
            )
        sealed_path = artifact.seal()
        if metadata_size is not None and metadata_size != writer.size:
            return _failure(
                normalized,
                code="sqlite_size_mismatch",
                message="The parser copy size differs from filesystem metadata.",
                journal_coverage=journal_coverage,
            )
        try:
            with sealed_path.open("rb") as stream:
                header = stream.read(100)
        except OSError:
            return _failure(
                normalized,
                code="sqlite_parser_copy_unreadable",
                message="The controlled parser copy could not be verified.",
                journal_coverage=journal_coverage,
            )
        if len(header) < 100 or not header.startswith(b"SQLite format 3\x00"):
            return _failure(
                normalized,
                code="sqlite_header_invalid",
                message="The requested file does not have a complete SQLite 3 database header.",
                journal_coverage=journal_coverage,
            )

        connection: sqlite3.Connection | None = None
        try:
            connection = _open_read_only(sealed_path)
            deadline = time.monotonic() + QUERY_TIMEOUT_SECONDS
            executed = (
                _execute(connection, query, max_rows=max_rows, deadline=deadline)
                if query is not None
                else _schema_query(
                    connection,
                    table,
                    max_rows=max_rows,
                    deadline=deadline,
                )
            )
        except sqlite3.Error as exc:
            code, message = _sqlite_error(exc)
            executed = _ExecutedQuery(
                [],
                [],
                False,
                False,
                error_code=code,
                error_message=message,
            )
        finally:
            if connection is not None:
                connection.close()

        read_versions = {1: "rollback", 2: "wal"}
        warnings: list[dict[str, object]] = []
        if query is not None and query_kind == "select":
            word_tokens = [value.casefold() for kind, value in query_tokens if kind == "word"]
            explicit_order = any(
                left == "order" and right == "by"
                for left, right in zip(word_tokens, word_tokens[1:], strict=False)
            )
            if not explicit_order:
                warnings.append(
                    {
                        "code": "row_order_not_bound",
                        "message": "Custom SELECT order is not reproducible unless the query includes an explicit ORDER BY.",
                    }
                )
        result = {
            "path": normalized,
            "action": query_kind,
            "table": table,
            "database_sha256": writer.sha256,
            "database_size_bytes": writer.size,
            "header_read_version": read_versions.get(header[19], f"unknown:{header[19]}"),
            "header_write_version": read_versions.get(header[18], f"unknown:{header[18]}"),
            "journal_coverage": journal_coverage,
            "columns": executed.columns,
            "rows": executed.rows,
            "returned": len(executed.rows),
            "truncated": executed.truncated,
            "query_result_complete": executed.complete and not executed.truncated,
            "scan_complete": executed.complete,
            "coverage": {
                "complete": executed.complete,
                "scope": normalized,
                "reason": executed.error_message,
            },
            "limits": {
                "database_bytes": MAX_DATABASE_BYTES,
                "query_characters": MAX_QUERY_CHARS,
                "query_utf8_bytes": MAX_QUERY_UTF8_BYTES,
                "rows": max_rows,
                "effective_rows": executed.effective_row_limit,
                "columns": MAX_COLUMNS,
                "cells": MAX_CELLS,
                "cell_bytes": MAX_CELL_BYTES,
                "query_time_seconds": QUERY_TIMEOUT_SECONDS,
            },
            "warnings": warnings,
        }
        if executed.error_code is not None:
            result["error"] = {
                "code": executed.error_code,
                "message": executed.error_message or "SQLite read-only query failed.",
            }

    audit = getattr(disk, "audit", None)
    if audit is not None and callable(getattr(audit, "record", None)):
        audit.record(
            tool="filesystem.sqlite_query",
            args={
                "path": normalized,
                "action": query_kind,
                "query_sha256": hashlib.sha256((query or "").encode("utf-8")).hexdigest()
                if query is not None
                else None,
                "table": table,
                "max_rows": max_rows,
            },
            output=result,
            input_sha=getattr(disk, "image_sha", None),
        )
    return result
