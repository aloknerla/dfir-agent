"""Offline tests for carrying documented argument meaning into the schema."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from pydantic import BaseModel, Field

from forensic_agent.agent.tool_bindings.argument_docs import (
    carry_argument_docs,
    description_without_argument_docs,
    parse_argument_docs,
)

_SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src" / "forensic_agent"


def test_documented_arguments_are_read_in_document_order() -> None:
    parsed = parse_argument_docs(
        "Summary line.\n"
        "\n"
        "Args:\n"
        "    plugin: Curated short name.\n"
        "    limit: Rows per page.\n"
    )

    assert list(parsed) == ["plugin", "limit"]
    assert parsed["limit"] == "Rows per page."


def test_a_colon_inside_wrapped_prose_does_not_start_a_new_argument() -> None:
    """The reason the entry column is anchored, kept as an executable rule."""

    parsed = parse_argument_docs(
        "Run a plugin.\n"
        "\n"
        "                Args:\n"
        "                    filter: Plain substring matched against each row.\n"
        "                        Not a query expression: comparison syntax\n"
        "                        matches nothing.\n"
    )

    assert list(parsed) == ["filter"]
    assert parsed["filter"] == (
        "Plain substring matched against each row. Not a query expression: "
        "comparison syntax matches nothing."
    )


def test_an_example_value_containing_a_colon_stays_inside_its_argument() -> None:
    parsed = parse_argument_docs(
        "Query the event log.\n"
        "\n"
        "Args:\n"
        "    data_type: Exact record type, for example\n"
        "        fs:stat or windows:evtx:record.\n"
        "    parser: Exact parser name.\n"
    )

    assert list(parsed) == ["data_type", "parser"]
    assert "fs:stat" in parsed["data_type"]
    assert "windows:evtx:record" in parsed["data_type"]


def test_a_docstring_without_an_args_section_documents_nothing() -> None:
    assert parse_argument_docs("Summary only.") == {}
    assert parse_argument_docs(None) == {}


def test_the_args_section_ends_at_the_next_heading() -> None:
    parsed = parse_argument_docs(
        "Summary.\n"
        "\n"
        "Args:\n"
        "    limit: Rows per page.\n"
        "\n"
        "Returns:\n"
        "    A page of rows.\n"
    )

    assert list(parsed) == ["limit"]


def test_documentation_reaches_the_schema_the_model_receives() -> None:
    class Schema(BaseModel):
        plugin: str = "pslist"
        limit: int = 50

    applied, _ = carry_argument_docs(
        Schema, "Summary.\n\nArgs:\n    plugin: Curated short name.\n    limit: Rows per page.\n"
    )

    assert applied.model_json_schema()["properties"]["plugin"]["description"] == (
        "Curated short name."
    )
    assert applied.model_json_schema()["properties"]["limit"]["description"] == "Rows per page."


def test_an_argument_that_no_longer_exists_cannot_invent_a_field() -> None:
    """Unlike the upstream parser, a stale entry is dropped instead of raising."""

    class Schema(BaseModel):
        limit: int = 50

    applied, _ = carry_argument_docs(
        Schema, "Summary.\n\nArgs:\n    limit: Rows per page.\n    removed: Gone.\n"
    )

    assert set(applied.model_json_schema()["properties"]) == {"limit"}


def test_an_existing_description_is_never_overwritten() -> None:
    class Schema(BaseModel):
        limit: int = Field(50, description="Authoritative text.")

    applied, _ = carry_argument_docs(Schema, "Summary.\n\nArgs:\n    limit: Replacement text.\n")

    assert applied.model_json_schema()["properties"]["limit"]["description"] == (
        "Authoritative text."
    )


def test_prose_appended_after_the_docstring_is_not_an_argument() -> None:
    """pcap_query appends its bound capture inventory after the docstring."""

    description = (
        "Analyze the network capture.\n"
        "\n"
        "                Args:\n"
        "                    query: Curated view to run.\n"
        "                    source: Exact bound component id.\n"
        "\n"
        "Available source selectors: capture-a (role source_pcap), capture-b "
        "(role source_pcap). Omitting source uses capture-merged."
    )

    parsed = parse_argument_docs(description)

    assert list(parsed) == ["query", "source"]
    assert "capture-a" not in parsed["source"]


def test_appended_prose_survives_the_strip() -> None:
    """Losing it would hide which captures exist from the model."""

    description = (
        "Analyze the network capture.\n"
        "\n"
        "                Args:\n"
        "                    source: Exact bound component id.\n"
        "\n"
        "Available source selectors: capture-a, capture-b."
    )

    stripped = description_without_argument_docs(description)

    assert "Args:" not in stripped
    assert "Exact bound component id." not in stripped
    assert stripped.endswith("Available source selectors: capture-a, capture-b.")


def test_a_section_after_the_arguments_is_kept() -> None:
    stripped = description_without_argument_docs(
        "Summary.\n\nArgs:\n    limit: Rows per page.\n\nReturns:\n    A page of rows.\n"
    )

    assert "Args:" not in stripped
    assert stripped.startswith("Summary.")
    assert stripped.endswith("A page of rows.")


def test_a_docstring_this_module_cannot_apply_keeps_everything_it_had() -> None:
    """Dropping the prose is safe only because it is conditional on landing."""

    class Schema(BaseModel):
        limit: int = 50

    description = "Summary.\n\nArgs:\n    removed: Names no parameter.\n"
    _schema, carried = carry_argument_docs(Schema, description)

    assert carried == description


def test_the_arguments_are_not_spent_on_the_context_twice() -> None:
    class Schema(BaseModel):
        limit: int = 50

    schema, carried = carry_argument_docs(
        Schema, "Summary.\n\nArgs:\n    limit: Rows per page.\n"
    )

    assert "Rows per page." not in carried
    assert schema.model_json_schema()["properties"]["limit"]["description"] == "Rows per page."


def test_documentation_survives_into_the_payload_the_model_is_sent() -> None:
    """The parser is only worth anything if the serialized schema carries it.

    This builds the tool the way every call site does, with no ``args_schema``,
    so it exercises the schema LangChain infers rather than a hand-written one.
    """

    from langchain_core.tools import StructuredTool
    from langchain_core.utils.function_calling import convert_to_openai_tool

    from forensic_agent.agent.tool_bindings.output_guard import _guard_tool_outputs

    def memory_query(plugin: str = "pslist", limit: int = 50) -> dict:
        """Run a Volatility 3 plugin on the memory dump.

        Args:
            plugin: Curated short name, or any fully qualified plugin name.
            limit: Rows per page, default 50. A byte cap may return fewer.
        """
        return {}

    raw = StructuredTool.from_function(memory_query)
    assert [field.get("description") for field in raw.args.values()] == [None, None]

    guarded = _guard_tool_outputs([raw])[0]
    properties = convert_to_openai_tool(guarded)["function"]["parameters"]["properties"]

    assert properties["plugin"]["description"].startswith("Curated short name")
    assert properties["limit"]["description"].endswith("A byte cap may return fewer.")
    assert "Args:" not in guarded.description
    assert len(guarded.description) < len(raw.description)


def _documented_tool_functions() -> list[tuple[str, str, set[str], str]]:
    found: list[tuple[str, str, set[str], str]] = []
    for path in sorted(_SOURCE_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            docstring = ast.get_docstring(node)
            if not docstring or "Args:" not in docstring:
                continue
            names = {argument.arg for argument in node.args.args + node.args.kwonlyargs}
            found.append((path.name, node.name, names, docstring))
    return found


def test_every_documented_argument_names_a_real_parameter() -> None:
    """A stray name means a description was silently cut in two."""

    documented = _documented_tool_functions()
    assert documented, "no tool documents its arguments"

    stray = {
        f"{module}::{function}": sorted(set(parse_argument_docs(docstring)) - names)
        for module, function, names, docstring in documented
        if set(parse_argument_docs(docstring)) - names
    }

    assert stray == {}


@pytest.mark.parametrize(
    ("function_name", "argument", "expected"),
    [
        ("memory_query", "filter", "comparison syntax matches nothing"),
    ],
)
def test_a_wrapped_description_reaches_the_model_whole(
    function_name: str, argument: str, expected: str
) -> None:
    """This one carried the defect that anchoring the entry column fixed."""

    for _module, name, _names, docstring in _documented_tool_functions():
        if name != function_name:
            continue
        assert expected in parse_argument_docs(docstring)[argument]
        return
    pytest.fail(f"{function_name} no longer documents its arguments")
