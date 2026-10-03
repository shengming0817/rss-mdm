"""Regressions for the complete current Agent V1 schema artifact."""
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
        shutil.copytree(ROOT / "crates/agent-wire/schema/runtime", schema)
        return directory, schema

    def check_copy(self, schema):
        with patch.object(artifact, "SCHEMAS", schema), patch.object(artifact, "MANIFEST", schema / "agent-v1.schema-manifest.json"):
            artifact.check()

    def test_task_mutation_fails_embedded_contract(self):
        directory, schema = self.fixture()
        with directory:
            path = schema / "task-payload-v1.schema.json"
            value = json.loads(path.read_text())
            value["oneOf"][1]["properties"]["intent"]["enum"].append("arbitrary")
            path.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, "embedded task contract"):
                self.check_copy(schema)

    def test_other_schema_mutation_fails_fingerprint(self):
        directory, schema = self.fixture()
        with directory:
            path = schema / "report-ack-v1.schema.json"
            value = json.loads(path.read_text())
            value["properties"]["receivedAt"]["minimum"] += 1
            path.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, "fingerprint"):
                self.check_copy(schema)

    def test_referenced_behavior_mutation_fails_embedded_contract(self):
        directory, schema = self.fixture()
        with directory:
            path = schema / "task-payload-v1.schema.json"
            value = json.loads(path.read_text())
            value["$defs"]["SoftwareTaskInvocation"]["properties"]["timeoutSeconds"]["maximum"] += 1
            path.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, "embedded task contract"):
                self.check_copy(schema)

    def test_missing_or_extra_shape_fails(self):
        directory, schema = self.fixture()
        with directory:
            (schema / "report-ack-v1.schema.json").unlink()
            with self.assertRaisesRegex(ValueError, "schema directory"):
                self.check_copy(schema)
        directory, schema = self.fixture()
        with directory:
            (schema / "report-ack-v6.schema.json").write_text("{}")
            with self.assertRaisesRegex(ValueError, "schema directory"):
                self.check_copy(schema)

    def test_manifest_cannot_drop_a_public_shape(self):
        directory, schema = self.fixture()
        with directory:
            path = schema / "agent-v1.schema-manifest.json"
            value = json.loads(path.read_text())
            value["schemas"].pop()
            path.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, "schema directory"):
                self.check_copy(schema)

    def test_major_and_schema_identity_are_exact(self):
        directory, schema = self.fixture()
        with directory:
            path = schema / "agent-v1.schema-manifest.json"
            value = json.loads(path.read_text())
            value["wireVersion"] = 6
            path.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, "Agent V1"):
                self.check_copy(schema)

    def test_retired_schema_identity_and_version_cannot_be_rehashed(self):
        for mutation, error in [("identity", "schema identifier"), ("version", "wireVersion")]:
            with self.subTest(mutation=mutation):
                directory, schema = self.fixture()
                with directory:
                    path = schema / "report-status-v1.schema.json"
                    value = json.loads(path.read_text())
                    if mutation == "identity":
                        value["$id"] = value["$id"].replace("/payload/v1/", "/payload/v6/")
                    else:
                        value["properties"]["ack"]["properties"]["wireVersion"]["const"] = 6
                    path.write_text(json.dumps(value))
                    manifest = json.loads((schema / "agent-v1.schema-manifest.json").read_text())
                    import hashlib
                    import re
                    digest = hashlib.sha256(b"".join((schema / item["file"]).read_bytes() for item in manifest["schemas"])).hexdigest()
                    source = re.sub(r'(pub const SCHEMA_FINGERPRINT: &str =\s*")[0-9a-f]{64}', lambda m: m[1] + digest, artifact.LIB.read_text())
                    library = schema / "runtime.rs"
                    library.write_text(source)
                    with patch.object(artifact, "LIB", library):
                        with self.assertRaisesRegex(ValueError, error):
                            self.check_copy(schema)
