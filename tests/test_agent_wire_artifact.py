"""Regressions for the complete current Agent V6 schema artifact."""
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("wire_artifact", ROOT / "hack/agent_wire_artifact.py")
artifact = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(artifact)


class WireArtifactTests(unittest.TestCase):
    def test_current_manifest_and_fingerprint(self):
        artifact.check()

    def fixture(self):
        directory = tempfile.TemporaryDirectory()
        schema = Path(directory.name) / "schema"
        shutil.copytree(ROOT / "crates/agent-wire/schema", schema)
        return directory, schema

    def check_copy(self, schema):
        with patch.object(artifact, "SCHEMAS", schema), patch.object(artifact, "MANIFEST", schema / "agent-v6.schema-manifest.json"):
            artifact.check()

    def test_task_mutation_fails_embedded_contract(self):
        directory, schema = self.fixture()
        with directory:
            path = schema / "task-payload-v6.schema.json"
            value = json.loads(path.read_text())
            value["oneOf"][1]["properties"]["intent"]["enum"].append("arbitrary")
            path.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, "embedded task contract"):
                self.check_copy(schema)

    def test_other_schema_mutation_fails_fingerprint(self):
        directory, schema = self.fixture()
        with directory:
            path = schema / "report-ack-v6.schema.json"
            value = json.loads(path.read_text())
            value["$id"] += "#changed"
            path.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, "fingerprint"):
                self.check_copy(schema)

    def test_referenced_behavior_mutation_fails_embedded_contract(self):
        directory, schema = self.fixture()
        with directory:
            path = schema / "task-payload-v6.schema.json"
            value = json.loads(path.read_text())
            value["$defs"]["SoftwareTaskInvocation"]["properties"]["timeoutSeconds"]["maximum"] += 1
            path.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, "embedded task contract"):
                self.check_copy(schema)

    def test_missing_or_extra_shape_fails(self):
        directory, schema = self.fixture()
        with directory:
            (schema / "report-ack-v6.schema.json").unlink()
            with self.assertRaisesRegex(ValueError, "schema directory"):
                self.check_copy(schema)
        directory, schema = self.fixture()
        with directory:
            (schema / "report-ack-v2.schema.json").write_text("{}")
            with self.assertRaisesRegex(ValueError, "schema directory"):
                self.check_copy(schema)

    def test_manifest_cannot_drop_a_public_shape(self):
        directory, schema = self.fixture()
        with directory:
            path = schema / "agent-v6.schema-manifest.json"
            value = json.loads(path.read_text())
            value["schemas"].pop()
            path.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, "schema directory"):
                self.check_copy(schema)

    def test_major_and_schema_identity_are_exact(self):
        directory, schema = self.fixture()
        with directory:
            path = schema / "agent-v6.schema-manifest.json"
            value = json.loads(path.read_text())
            value["wireVersion"] = 2
            path.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, "Agent V6"):
                self.check_copy(schema)
