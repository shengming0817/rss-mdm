"""Generated schemas cannot drift, even when their digest is recomputed."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('wire_artifact', ROOT / 'hack/agent_wire_artifact.py')
artifact = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(artifact)


class WireArtifactTests(unittest.TestCase):
    def test_current_manifest_and_fingerprint(self):
        artifact.check()
        artifact.enrollment()

    def copy(self, area, mutate, message, rehash=False):
        with tempfile.TemporaryDirectory() as temporary:
            schemas = Path(temporary) / 'schemas'
            shutil.copytree(ROOT / 'crates/agent-wire/schema' / area, schemas)
            manifest = schemas / ('agent-v1.schema-manifest.json' if area == 'runtime' else 'manifest.json')
            library = Path(temporary) / 'lib.rs'
            library.write_text((ROOT / 'crates/agent-wire/src' / (area + '.rs')).read_text())
            mutate(schemas, manifest, library)
            if rehash:
                digest = hashlib.sha256(b''.join((schemas / e['file']).read_bytes() for e in json.loads(manifest.read_text())['schemas'])).hexdigest()
                library.write_text(re.sub(r'(pub const SCHEMA_FINGERPRINT:\s*&str\s*=\s*")[0-9a-f]{64}', lambda m: m[1] + digest, library.read_text()))
            with self.assertRaisesRegex(ValueError, message):
                artifact.artifact(schemas, manifest, library, area)

    def test_mutations_cannot_be_approved_by_rehashing(self):
        for area, file in [('runtime', 'task-payload-v1.schema.json'), ('enroll', 'grant-request-v1.schema.json')]:
            for change in ('constraint', 'identity', 'embedded'):
                def mutate(schemas, manifest, library):
                    path = schemas / file
                    value = json.loads(path.read_text())
                    if change == 'constraint':
                        value['additionalProperties'] = True
                    elif change == 'identity':
                        value['$id'] += '/drift'
                    else:
                        value.setdefault('$defs', {})['Injected'] = {'type':'string'}
                    path.write_text(json.dumps(value))
                with self.subTest(area=area, change=change):
                    self.copy(area, mutate, 'schema differs from Rust', rehash=True)

    def test_missing_or_extra_shape_fails(self):
        self.copy('runtime', lambda s, m, l: (s / 'report-ack-v1.schema.json').unlink(), 'schema directory')
        self.copy('runtime', lambda s, m, l: (s / 'extra-v1.schema.json').write_text('{}'), 'schema directory')

    def test_manifest_cannot_drop_a_public_shape(self):
        def mutate(schemas, manifest, library):
            value = json.loads(manifest.read_text())
            removed = value['schemas'].pop()
            (schemas / removed['file']).unlink()
            manifest.write_text(json.dumps(value))
        self.copy('runtime', mutate, 'Rust protocol declarations')

    def test_fingerprint_is_checked(self):
        self.copy('runtime', lambda s, m, l: l.write_text(l.read_text().replace('pub const SCHEMA_FINGERPRINT:', 'pub const OTHER:')), 'fingerprint declaration')
        self.copy('runtime', lambda s, m, l: l.write_text(re.sub(r'(pub const SCHEMA_FINGERPRINT:\s*&str\s*=\s*")[0-9a-f]{64}', lambda match: match[1] + '0' * 64, l.read_text())), 'schema fingerprint differs')

    def test_major_is_exact(self):
        def mutate(schemas, manifest, library):
            value = json.loads(manifest.read_text())
            value['wireVersion'] = 2
            manifest.write_text(json.dumps(value))
        self.copy('runtime', mutate, 'Agent V1')
