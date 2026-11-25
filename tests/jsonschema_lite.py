"""Tiny JSON-Schema validator for the subset used by invisi-guard's schemas.

The project core is stdlib-only, so tests cannot depend on the third-party
``jsonschema`` package. This module supports exactly the keywords used in
``docs/finding.schema.json`` and ``docs/scan-result.schema.json``:
type, required, properties, additionalProperties, enum, const, pattern,
minimum, minLength, items and local ``$ref`` by schema filename.
"""

from __future__ import annotations

import re
from typing import Any

SUPPORTED_TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "null": type(None),
}


def _type_matches(value: Any, expected: str) -> bool:
    python_type = SUPPORTED_TYPES[expected]
    if expected in ("integer", "number") and isinstance(value, bool):
        return False
    return isinstance(value, python_type)


def validate(instance: Any, schema: dict[str, Any], schemas: dict[str, dict[str, Any]]) -> list[str]:
    """Return a list of human-readable validation errors (empty means valid)."""
    errors: list[str] = []
    _validate(instance, schema, schemas, "$", errors)
    return errors


def _resolve(ref: str, schemas: dict[str, dict[str, Any]]) -> dict[str, Any]:
    if ref not in schemas:
        raise KeyError("unknown $ref %r (known: %s)" % (ref, sorted(schemas)))
    return schemas[ref]


def _validate(
    value: Any,
    schema: dict[str, Any],
    schemas: dict[str, dict[str, Any]],
    path: str,
    errors: list[str],
) -> None:
    if "$ref" in schema:
        _validate(value, _resolve(schema["$ref"], schemas), schemas, path, errors)
        return
    if "const" in schema:
        if value != schema["const"]:
            errors.append("%s: expected const %r, got %r" % (path, schema["const"], value))
    if "enum" in schema:
        if value not in schema["enum"]:
            errors.append("%s: %r not in enum %r" % (path, value, schema["enum"]))
    expected_type = schema.get("type")
    if expected_type is not None:
        if isinstance(expected_type, list):
            matched = any(_type_matches(value, item) for item in expected_type)
        else:
            matched = _type_matches(value, expected_type)
        if not matched:
            errors.append("%s: expected type %r, got %r" % (path, expected_type, type(value).__name__))
            return
    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append("%s: string shorter than minLength %d" % (path, schema["minLength"]))
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errors.append("%s: string does not match pattern %r" % (path, schema["pattern"]))
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append("%s: %r < minimum %r" % (path, value, schema["minimum"]))
    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                errors.append("%s: missing required property %r" % (path, key))
        properties = schema.get("properties", {})
        for key, item in value.items():
            if key in properties:
                _validate(item, properties[key], schemas, "%s.%s" % (path, key), errors)
            else:
                additional = schema.get("additionalProperties", True)
                if additional is False:
                    errors.append("%s: unexpected property %r" % (path, key))
                elif isinstance(additional, dict):
                    _validate(item, additional, schemas, "%s.%s" % (path, key), errors)
    if isinstance(value, list) and "items" in schema:
        for index, item in enumerate(value):
            _validate(item, schema["items"], schemas, "%s[%d]" % (path, index), errors)
