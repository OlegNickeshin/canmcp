"""Validate schemas as data. Never instantiate tools or fetch schema references."""

import json
import re

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from jsonschema.validators import validator_for

from canmcp.checks.network import ScanError
from canmcp.models import Evidence, Status

SOURCE = "https://modelcontextprotocol.io/specification/2026-07-28/server/tools"
TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


def validate_schema(schema, *, modern=False):
    if not isinstance(schema, dict) or schema.get("type") != "object":
        raise ScanError("tool_schemas", "Tool input/output schema must have type: object.")
    if len(json.dumps(schema)) > 65_536:
        raise ScanError("limits", "Individual schema exceeds 64 KiB; inspection is incomplete.")
    dialect = schema.get("$schema")
    if dialect is not None and not isinstance(dialect, str):
        raise ScanError("tool_schemas", "Schema dialect must be a string URI.")
    validator = validator_for(schema, default=None) if dialect else Draft202012Validator
    warnings = []
    if validator is None:
        warnings.append("Unrecognized JSON Schema dialect; validation is incomplete.")
    else:
        try:
            validator.check_schema(schema)
        except (SchemaError, ValueError, TypeError, RecursionError) as exc:
            raise ScanError(
                "tool_schemas", "Tool schema is invalid for its JSON Schema dialect."
            ) from exc
    stack = [(schema, (), False)]
    headers = set()
    nodes = 0
    while stack:
        node, path, reachable = stack.pop()
        nodes += 1
        if nodes > 4000:
            raise ScanError("limits", "Schema complexity limit exceeded; inspection is incomplete.")
        if isinstance(node, dict):
            for key in ("$ref", "$dynamicRef", "$recursiveRef"):
                ref = node.get(key)
                if isinstance(ref, str) and not ref.startswith("#"):
                    warnings.append("External schema references are not fetched or resolved.")
                elif isinstance(ref, str) and ref.startswith("#/"):
                    target = schema
                    try:
                        for part in ref[2:].split("/"):
                            part = part.replace("~1", "/").replace("~0", "~")
                            target = target[int(part)] if isinstance(target, list) else target[part]
                    except (KeyError, IndexError, TypeError, ValueError):
                        # Nested $id changes reference resolution; do not invent invalidity.
                        warnings.append("A local reference could not be resolved statically.")
            if modern and "x-mcp-header" in node:
                header = node["x-mcp-header"]
                if (
                    not reachable
                    or not isinstance(header, str)
                    or not TOKEN.fullmatch(header)
                    or header.lower() in headers
                    or node.get("type") not in ("string", "boolean", "integer")
                ):
                    raise ScanError(
                        "tool_schemas", "Invalid x-mcp-header type, location, name, or duplicate."
                    )
                headers.add(header.lower())
            # Traverse schema locations only. Examples/defaults are arbitrary instance data.
            for key, value in node.items():
                if key in {
                    "properties",
                    "patternProperties",
                    "$defs",
                    "definitions",
                    "dependentSchemas",
                } and isinstance(value, dict):
                    for name, child in value.items():
                        can_reach = key == "properties" and (reachable or not path)
                        stack.append((child, (*path, key, name), can_reach))
                elif key in {
                    "items",
                    "additionalItems",
                    "contains",
                    "additionalProperties",
                    "unevaluatedProperties",
                    "unevaluatedItems",
                    "propertyNames",
                    "not",
                    "if",
                    "then",
                    "else",
                    "allOf",
                    "anyOf",
                    "oneOf",
                    "prefixItems",
                }:
                    stack.append((value, (*path, key), False))
        elif isinstance(node, list):
            stack.extend((child, (*path, index), False) for index, child in enumerate(node))
    return set(warnings)


def check_tools(tools: list, evidence: Evidence):
    names = set()
    warnings = set()
    for index, tool in enumerate(tools, start=1):
        if not isinstance(tool, dict) or not isinstance(tool.get("name"), str):
            raise ScanError("tool_schemas", "Tool descriptor or tool name is malformed.")
        name = tool["name"]
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name):
            warnings.add("Some tool names do not follow MCP's recommended naming convention.")
        if name in names:
            warnings.add("Duplicate tool names can make tool selection ambiguous.")
        names.add(name)
        for field in ("description", "title"):
            if field in tool and not isinstance(tool[field], str):
                raise ScanError("tool_schemas", "Tool description/title must be a string.")
        if not tool.get("description", "").strip():
            evidence.missing_descriptions += 1
        annotations = tool.get("annotations")
        if "annotations" not in tool:
            evidence.missing_annotations += 1
        elif not isinstance(annotations, dict):
            raise ScanError("tool_schemas", "Tool annotations must be an object.")
        else:
            for key in ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"):
                if key in annotations and not isinstance(annotations[key], bool):
                    raise ScanError("tool_schemas", "Tool behavior hints must be booleans.")
        if not annotations or not {"readOnlyHint", "destructiveHint"} <= annotations.keys():
            evidence.missing_claude_hints += 1
        modern = evidence.protocol_version == "2026-07-28"
        for field in ("inputSchema", "outputSchema"):
            if field == "outputSchema" and field not in tool:
                continue
            try:
                warnings.update(
                    validate_schema(tool.get(field), modern=modern and field == "inputSchema")
                )
            except ScanError as exc:
                raise ScanError(exc.check_id, f"Tool #{index} {field}: {exc}") from exc
    evidence.tool_count = len(tools)
    evidence.add(
        "tool_schemas",
        Status.PASS,
        f"Validated descriptors and schemas for {len(tools)} tools.",
        SOURCE,
    )
    for warning in sorted(warnings):
        evidence.add("tool_schemas.advisory", Status.WARN, warning, SOURCE)
