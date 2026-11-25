"""Schema conformance tests for the JSON output of invisi_guard.

These tests deliberately avoid third-party packages: ``tests/jsonschema_lite.py``
implements only the JSON-Schema subset used by the two published schemas.
"""

from __future__ import annotations

import json
import unittest

from invisi_guard import scan

from tests.helpers import FIXTURES, json_out, load_schemas, read_fixture, run_cli
from tests.jsonschema_lite import validate


class SchemaFilesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.schemas = load_schemas()

    def test_schema_files_are_valid_json(self) -> None:
        self.assertIn("finding.schema.json", self.schemas)
        self.assertIn("scan-result.schema.json", self.schemas)
        self.assertEqual(self.schemas["finding.schema.json"]["type"], "object")

    def test_finding_schema_required_fields(self) -> None:
        required = set(self.schemas["finding.schema.json"]["required"])
        self.assertEqual(
            required,
            {
                "code",
                "kind",
                "severity",
                "start",
                "end",
                "length",
                "line",
                "column",
                "message",
                "data",
            },
        )

    def test_severity_enum_is_stable(self) -> None:
        schema = self.schemas["finding.schema.json"]
        self.assertEqual(schema["properties"]["severity"]["enum"], ["low", "medium", "high"])

    def test_kind_enum_has_all_documented_kinds(self) -> None:
        kinds = set(self.schemas["finding.schema.json"]["properties"]["kind"]["enum"])
        self.assertEqual(
            kinds,
            {
                "bidi_control",
                "zero_width",
                "unicode_tag",
                "variation_selector",
                "confusable",
                "encoded_payload",
            },
        )


class ScanJsonSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schemas = load_schemas()
        proc = run_cli(["scan", str(FIXTURES / "hidden_instructions.txt"), "--json"])
        assert proc.returncode == 0, proc.stderr
        cls.payload = json_out(proc)

    def test_scan_json_matches_schema(self) -> None:
        errors = validate(self.payload, self.schemas["scan-result.schema.json"], self.schemas)
        self.assertEqual(errors, [])

    def test_each_finding_matches_finding_schema(self) -> None:
        schema = self.schemas["finding.schema.json"]
        self.assertGreater(len(self.payload["findings"]), 0)
        for finding in self.payload["findings"]:
            errors = validate(finding, schema, self.schemas)
            self.assertEqual(errors, [], msg=json.dumps(finding))

    def test_end_never_precedes_start(self) -> None:
        for finding in self.payload["findings"]:
            self.assertLessEqual(finding["start"], finding["end"])
            self.assertEqual(finding["length"], finding["end"] - finding["start"])

    def test_empty_findings_schema_valid(self) -> None:
        proc = run_cli(["scan", str(FIXTURES / "clean_english.txt"), "--json"])
        payload = json_out(proc)
        errors = validate(payload, self.schemas["scan-result.schema.json"], self.schemas)
        self.assertEqual(errors, [])
        self.assertEqual(payload["findings"], [])
        self.assertIsNone(payload["max_severity"])

    def test_invalid_finding_is_rejected(self) -> None:
        schema = self.schemas["finding.schema.json"]
        bad = {
            "code": "IG-TEST",
            "kind": "zero_width",
            "severity": "critical",
            "start": -1,
            "end": 0,
            "length": 0,
            "line": 1,
            "column": 1,
            "message": "",
            "data": {},
        }
        errors = validate(bad, schema, self.schemas)
        self.assertGreaterEqual(len(errors), 2)

    def test_api_findings_serialize_to_schema_valid_dicts(self) -> None:
        schema = self.schemas["finding.schema.json"]
        findings = scan(read_fixture("hidden_instructions.txt"))
        serialized = json.loads(json.dumps([finding.to_dict() for finding in findings]))
        for finding in serialized:
            errors = validate(finding, schema, self.schemas)
            self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
