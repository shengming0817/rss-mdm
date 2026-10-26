"""Fixed-revision extraction uses actual Git objects, never a source file's self-assertion."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hack'))
import http_contract_artifact as artifact


class HttpArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repository = self.root / 'producer'
        self.repository.mkdir()
        self.run_git('init', '-q')
        self.document = {'formatVersion': 1, 'schemaDialect': 'https://json-schema.org/draft/2020-12/schema',
                         'schemas': {'sha256-' + 'a' * 64: {'type': 'null'}}, 'endpoints': [
            {'operationId': 'agent.receipt', 'listener': 'agent', 'method': 'GET',
             'path': '/operations/{id}', 'request': {'body': None, 'headers': {}},
             'responses': [{'status': 200, 'body': {'content_type': 'application/json',
                 'schema': {'direction': 'response', 'schemaId': 'sha256-' + 'a' * 64}}, 'headers': {}}]}]}
        self.artifact = self.repository / artifact.ARTIFACT
        self.artifact.parent.mkdir()
        self.artifact.write_text(json.dumps(self.document) + '\n')
        self.revision = self.commit()
        self.output = self.root / 'consumer' / 'http-v1.json'

    def run_git(self, *arguments):
        return subprocess.run(['/usr/bin/git', '-C', str(self.repository), *arguments],
                              check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout

    def commit(self):
        self.run_git('add', artifact.ARTIFACT)
        self.run_git('-c', 'user.name=Contract test', '-c', 'user.email=contract-test@example.invalid',
                     'commit', '-qm', 'fixture')
        return self.run_git('rev-parse', 'HEAD').decode().strip()

    def test_old_commit_survives_new_head_and_dirty_worktree_without_cargo(self):
        expected = self.artifact.read_bytes()
        self.document['endpoints'][0]['path'] = '/new-path/{id}'
        self.artifact.write_text(json.dumps(self.document))
        self.commit()
        self.artifact.write_text('dirty and invalid')
        with patch.object(artifact, 'generated', side_effect=AssertionError('must not build')):
            artifact.extract(self.repository, self.revision, self.output)
            artifact.verify_source(self.repository, self.revision, self.output)
        self.assertEqual(self.output.read_bytes(), expected)
        source = json.loads(artifact.source_file(self.output).read_bytes())
        self.assertEqual(source['sourceRevision'], self.revision)
        self.assertEqual(source['blob'], self.run_git('rev-parse', self.revision + ':' + artifact.ARTIFACT).decode().strip())

    def test_copied_extractor_needs_only_python_and_absolute_git(self):
        import os
        import shutil
        script = self.root / 'http_contract_artifact.py'
        shutil.copyfile(artifact.__file__, script)
        result = subprocess.run([sys.executable, str(script), '--repository', str(self.repository),
                                 '--extract', self.revision, '--output', str(self.output)],
                                cwd=self.root, env={**os.environ, 'PATH': '/nonexistent'},
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.output.read_bytes(), self.artifact.read_bytes())

    def test_rehashing_tampered_artifact_does_not_change_selected_git_object(self):
        artifact.extract(self.repository, self.revision, self.output)
        self.output.write_text(json.dumps({'formatVersion': 1, 'endpoints': []}))
        source_path = artifact.source_file(self.output)
        source = json.loads(source_path.read_bytes())
        source['sha256'] = hashlib.sha256(self.output.read_bytes()).hexdigest()
        source['blob'] = self.run_git('hash-object', str(self.output)).decode().strip()
        source_path.write_text(json.dumps(source))
        with self.assertRaisesRegex(ValueError, 'selected Git object'):
            artifact.verify_source(self.repository, self.revision, self.output)

    def test_receipt_cannot_substitute_a_different_revision(self):
        artifact.extract(self.repository, self.revision, self.output)
        source_path = artifact.source_file(self.output)
        source = json.loads(source_path.read_bytes())
        source['sourceRevision'] = 'a' * 40
        source_path.write_text(json.dumps(source))
        with self.assertRaisesRegex(ValueError, 'receipt'):
            artifact.verify_source(self.repository, self.revision, self.output)

    def test_only_full_existing_commit_objects_are_accepted(self):
        for revision in ('HEAD', self.revision[:12], '../other', 'a' * 40):
            with self.subTest(revision=revision), self.assertRaises((ValueError, subprocess.CalledProcessError)):
                artifact.committed(self.repository, revision)
        self.run_git('rm', artifact.ARTIFACT)
        self.run_git('-c', 'user.name=Contract test', '-c', 'user.email=contract-test@example.invalid', 'commit', '-qm', 'remove fixture')
        missing = self.run_git('rev-parse', 'HEAD').decode().strip()
        with self.assertRaises(subprocess.CalledProcessError):
            artifact.committed(self.repository, missing)

    def test_unknown_format_duplicate_keys_and_duplicate_routes_fail(self):
        for value in (True, 2, '1'):
            self.document['formatVersion'] = value
            with self.assertRaises(ValueError):
                artifact.validate_document(json.dumps(self.document))
        with self.assertRaises(ValueError):
            artifact.strict_json('{"formatVersion":1,"formatVersion":1}')
        self.document['formatVersion'] = 1
        self.document['endpoints'].append(dict(self.document['endpoints'][0], operationId='different'))
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            artifact.validate_document(json.dumps(self.document))

    def test_missing_binding_unresolved_reference_and_unknown_dialect_fail(self):
        import copy
        broken = copy.deepcopy(self.document)
        broken['endpoints'][0]['responses'][0]['body']['schema']['schemaId'] = 'missing'
        with self.assertRaisesRegex(ValueError, 'unbound'):
            artifact.validate_document(json.dumps(broken))
        broken = copy.deepcopy(self.document)
        broken['schemas']['sha256-' + 'a' * 64] = {'$ref': '#/$defs/missing'}
        with self.assertRaisesRegex(ValueError, 'unresolved'):
            artifact.validate_document(json.dumps(broken))
        broken = copy.deepcopy(self.document)
        broken['schemaDialect'] = 'future'
        with self.assertRaisesRegex(ValueError, 'dialect'):
            artifact.validate_document(json.dumps(broken))

    def test_collection_projection_uses_mounted_schema_and_reference_closure(self):
        import copy
        document = copy.deepcopy(self.document)
        identity = 'sha256-' + 'a' * 64
        root = {'type': 'object', '$defs': {
            'FieldView': {'type': 'object', 'properties': {'nested': {'$ref': '#/$defs/Shared'}}},
            'Shared': {'type': 'string'}, 'Unrelated': {'type': 'boolean'},
            'FieldImpact': {'type': 'integer'}, 'FieldMappingReference': {'type': 'string'}}}
        document['schemas'][identity] = root
        document['endpoints'] = []
        for method, path in [('POST', '/api/v1/resources/{id}'),
                             ('PUT', '/api/v1/asset-fields/{field}'),
                             ('GET', '/api/v1/asset-fields/{field}'),
                             ('GET', '/api/v1/asset-fields/{field}/references')]:
            endpoint = copy.deepcopy(self.document['endpoints'][0])
            endpoint.update(listener='browser', method=method, path=path)
            endpoint['request'].update(body={'schema': {'schemaId': identity}},
                                       query={'schemaId': identity})
            document['endpoints'].append(endpoint)
        projection = artifact.collection_projection(document)
        self.assertEqual(projection['ResourceWrite'], root)
        self.assertEqual(set(projection['FieldView']['$defs']), {'Shared'})
        self.assertEqual(projection['FieldView']['properties']['nested']['$ref'], '#/$defs/Shared')
        document['endpoints'].pop()
        with self.assertRaisesRegex(ValueError, 'mounted owner'):
            artifact.collection_projection(document)

    def test_worktree_check_compares_generated_bytes_not_digest(self):
        expected = self.artifact.read_bytes()
        projection = self.repository / 'crates/management-http/schema/Collection.json'
        projection.parent.mkdir(parents=True)
        projection.write_bytes(b'{}\n')
        with patch.object(artifact, 'ROOT', self.repository), patch.object(artifact, 'generated', return_value=expected), patch.object(artifact, 'collection_projection', return_value={}):
            artifact.check()
            self.artifact.write_bytes(expected + b' ')
            with self.assertRaisesRegex(ValueError, 'actual registered handlers'):
                artifact.check()
            artifact.check(write=True)
            self.assertEqual(self.artifact.read_bytes(), expected)


if __name__ == '__main__':
    unittest.main()
