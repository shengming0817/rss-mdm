"""Regressions for the immutable Agent V1 contract gate."""
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("wire_compat", ROOT / "hack/agent_wire_compat.py")
compat = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(compat)


class WireCompatibilityTests(unittest.TestCase):
    def test_current_contract_matches_fixed_baseline(self):
        compat.check(ROOT / "crates/agent-wire/schema")

    def test_breaking_mutations_fail_even_without_fingerprint_check(self):
        mutations = [
            ("report-ack", lambda s: s["properties"]["wireVersion"].update(const=True)),
            ("report-request", lambda s: s["properties"]["sequence"].update(minimum=1)),
            ("report-request", lambda s: s["required"].append("newField")),
            ("report-request", lambda s: s["$defs"]["valuesBody"]["properties"]["values"].update(maxItems=1)),
            ("report-status", lambda s: s["properties"]["projection"]["enum"].append("newState")),
            ("report-status", lambda s: s["required"].remove("projection")),
            ("error-body", lambda s: s["properties"]["code"]["enum"].pop()),
            ("report-ack", lambda s: s.update(additionalProperties=True)),
            ("report-ack", lambda s: s["properties"].update(newField={"type": "string"})),
        ]
        for name, mutate in mutations:
            with self.subTest(schema=name, mutation=mutate), tempfile.TemporaryDirectory() as tmp:
                schema = Path(tmp) / "schema"
                shutil.copytree(ROOT / "crates/agent-wire/schema", schema)
                path = schema / f"{name}-v1.schema.json"
                value = json.loads(path.read_text())
                mutate(value)
                path.write_text(json.dumps(value))
                with self.assertRaisesRegex(ValueError, "wire major"):
                    compat.check(schema)

    def test_formatting_and_object_key_order_are_allowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            schema = Path(tmp) / "schema"
            shutil.copytree(ROOT / "crates/agent-wire/schema", schema)
            for path in schema.glob("*.json"):
                path.write_text(json.dumps(json.loads(path.read_text()), sort_keys=True))
            compat.check(schema)

    def test_missing_history_fails_closed(self):
        with patch.object(compat.subprocess, "run", return_value=SimpleNamespace(returncode=1)):
            with self.assertRaisesRegex(ValueError, "baseline unavailable"):
                compat.check(ROOT / "crates/agent-wire/schema")

    def test_manifest_cannot_drop_a_public_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            schema = Path(tmp) / "schema"
            shutil.copytree(ROOT / "crates/agent-wire/schema", schema)
            path = schema / "agent-v1.schema-manifest.json"
            value = json.loads(path.read_text())
            value["schemas"].pop()
            path.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, "wire major"):
                compat.check(schema)
