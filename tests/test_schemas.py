import pytest

from canmcp.checks.network import ScanError, bounded_json
from canmcp.checks.schemas import validate_schema


def test_data_examples_are_not_schema_keywords():
    assert not validate_schema(
        {
            "type": "object",
            "examples": [
                {"x-mcp-header": "not a schema annotation", "$ref": "https://private.example/x"}
            ],
            "default": {"$schema": "anything"},
        },
        modern=True,
    )


def test_nested_header_properties():
    assert not validate_schema(
        {
            "type": "object",
            "properties": {
                "config": {
                    "type": "object",
                    "properties": {"region": {"type": "string", "x-mcp-header": "Region"}},
                }
            },
        },
        modern=True,
    )


@pytest.mark.parametrize(
    "schema",
    [
        {"type": "object", "x-mcp-header": "Root"},
        {"type": "object", "properties": {"a": {"type": "number", "x-mcp-header": "A"}}},
        {"type": "object", "properties": {"a": {"type": "string", "x-mcp-header": "bad\r\n"}}},
        {
            "type": "object",
            "allOf": [{"properties": {"a": {"type": "string", "x-mcp-header": "A"}}}],
        },
        {
            "type": "object",
            "properties": {
                "a": {"type": "string", "x-mcp-header": "A"},
                "b": {"type": "string", "x-mcp-header": "a"},
            },
        },
    ],
)
def test_invalid_modern_header_annotations(schema):
    with pytest.raises(ScanError, match="x-mcp-header"):
        validate_schema(schema, modern=True)


def test_cyclic_local_reference_does_not_execute_or_recurse():
    assert not validate_schema({"type": "object", "properties": {"next": {"$ref": "#"}}})


def test_float_overflow_is_not_valid_json():
    with pytest.raises(ScanError):
        bounded_json(b'{"value":1e9999}')
