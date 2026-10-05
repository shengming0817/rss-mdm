"""Generated schemas cannot drift, even when their digest is recomputed."""
from contextlib import contextmanager
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'hack'))
SPEC = importlib.util.spec_from_file_location('wire_artifact', ROOT / 'hack/agent_wire_artifact.py')
artifact = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(artifact)


class WireArtifactTests(unittest.TestCase):
    def test_current_manifest_and_fingerprint(self):
        artifact.verify()

    @contextmanager
    def cloned(self, area):
        with tempfile.TemporaryDirectory() as temporary:
            schemas = Path(temporary) / 'schemas'
            shutil.copytree(ROOT / 'crates/agent-wire/schema' / area, schemas)
            manifest = schemas / artifact.FAMILIES[area][0]
            library = Path(temporary) / 'lib.rs'
            library.write_text((ROOT / 'crates/agent-wire/src' / (area + '.rs')).read_text())
            yield schemas, manifest, library

    def copy(self, area, mutate, message, rehash=False, write=False):
        with self.cloned(area) as (schemas, manifest, library):
            mutate(schemas, manifest, library)
            if rehash:
                digest = hashlib.sha256(b''.join((schemas / e['file']).read_bytes() for e in json.loads(manifest.read_text())['schemas'])).hexdigest()
                library.write_text(re.sub(r'(pub const SCHEMA_FINGERPRINT:\s*&str\s*=\s*")[0-9a-f]{64}', lambda m: m[1] + digest, library.read_text()))
            with self.assertRaisesRegex(ValueError, message):
                artifact.artifact(schemas, manifest, library, area, write)

    def test_mutations_cannot_be_approved_by_rehashing(self):
        for area in artifact.FAMILIES:
            for change in ('constraint', 'identity', 'embedded'):
                def mutate(schemas, manifest, library):
                    path = schemas / json.loads(manifest.read_text())['schemas'][0]['file']
                    value = json.loads(path.read_text())
                    if change == 'constraint':
                        value['additionalProperties'] = True
                    elif change == 'identity':
                        value['$id'] += '/drift'
                    else:
                        value.setdefault('$defs', {})['Injected'] = {'type': 'string'}
                    path.write_text(json.dumps(value))
                with self.subTest(area=area, change=change):
                    self.copy(area, mutate, 'schema differs from Rust', rehash=True)

    def test_missing_or_extra_shape_fails(self):
        def remove(s, m, l):
            (s / json.loads(m.read_text())['schemas'][0]['file']).unlink()
        for area in artifact.FAMILIES:
            with self.subTest(area=area):
                self.copy(area, remove, 'schema directory')
                for write in (False, True):
                    self.copy(area, lambda s, m, l: (s / 'extra-v1.schema.json').write_text('{}'), 'schema directory', write=write)

    def test_write_materializes_missing_declared_shapes(self):
        for area in artifact.FAMILIES:
            with self.subTest(area=area), self.cloned(area) as (schemas, manifest, library):
                files = [schemas / e['file'] for e in json.loads(manifest.read_text())['schemas']]
                original = [p.read_bytes() for p in files]
                for path in files:
                    path.unlink()
                artifact.artifact(schemas, manifest, library, area, True)
                artifact.artifact(schemas, manifest, library, area)
                self.assertEqual([p.read_bytes() for p in files], original)

    def test_manifest_cannot_drop_duplicate_or_escape_shapes(self):
        for area in artifact.FAMILIES:
            for change in ('drop', 'duplicate', 'escape'):
                def mutate(schemas, manifest, library):
                    value = json.loads(manifest.read_text())
                    if change == 'drop':
                        removed = value['schemas'].pop()
                        (schemas / removed['file']).unlink()
                    elif change == 'duplicate':
                        value['schemas'].append(value['schemas'][0])
                    else:
                        value['schemas'][0]['file'] = '../escaped-v1.schema.json'
                    manifest.write_text(json.dumps(value))
                with self.subTest(area=area, change=change):
                    self.copy(area, mutate, 'Rust protocol declarations' if change == 'drop' else 'schema entries')

    def test_fingerprint_is_checked(self):
        for area in artifact.FAMILIES:
            with self.subTest(area=area):
                self.copy(area, lambda s, m, l: l.write_text(l.read_text().replace('pub const SCHEMA_FINGERPRINT:', 'pub const OTHER:')), 'fingerprint declaration')
                self.copy(area, lambda s, m, l: l.write_text(re.sub(r'(pub const SCHEMA_FINGERPRINT:\s*&str\s*=\s*")[0-9a-f]{64}', lambda match: match[1] + '0' * 64, l.read_text())), 'schema fingerprint differs')

    def test_major_is_exact(self):
        for area, (_, _, versions) in artifact.FAMILIES.items():
            for key in versions:
                def mutate(schemas, manifest, library):
                    value = json.loads(manifest.read_text())
                    value[key] = 2
                    manifest.write_text(json.dumps(value))
                with self.subTest(area=area, key=key):
                    self.copy(area, mutate, 'Agent V1')

    def test_unregistered_protocol_family_is_rejected(self):
        generated = dict(artifact.generated())
        generated['unexpected'] = {}
        with patch.object(artifact, 'generated', return_value=generated):
            with self.assertRaisesRegex(ValueError, 'protocol families'):
                artifact.verify()
        with self.assertRaisesRegex(ValueError, 'unknown protocol family'):
            artifact.artifact(None, None, None, 'unexpected')
