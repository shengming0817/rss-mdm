"""Current-source export and the independently tracked Collection projection."""
import json
from pathlib import Path
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
        self.document = {'formatVersion': 1, 'schemaDialect': 'https://json-schema.org/draft/2020-12/schema',
                         'schemas': {'sha256-' + 'a' * 64: {'type': 'null'}}, 'endpoints': [
            {'operationId': 'agent.receipt', 'listener': 'agent', 'method': 'GET',
             'path': '/operations/{id}', 'request': {'body': None, 'headers': {}},
             'responses': [{'status': 200, 'body': {'content_type': 'application/json',
                 'schema': {'direction': 'response', 'schemaId': 'sha256-' + 'a' * 64}}, 'headers': {}}]}]}
        self.output = self.root / 'consumer' / 'http-v1.json'

    def test_authentication_schema_references_are_validated(self):
        self.document['endpoints'][0]['authentication'] = {
            'owner': 'middleware', 'alternatives': [{
                'kind': 'cookie', 'owner': 'identity', 'headers': {
                    'cookie': {'direction': 'request', 'schemaId': 'sha256-' + 'a' * 64}},
                'required_headers': ['cookie']}], 'conditional_response_headers': []}
        artifact.validate_document(json.dumps(self.document))
        credential = self.document['endpoints'][0]['authentication']['alternatives'][0]
        credential['headers']['cookie']['schemaId'] = 'sha256-' + 'b' * 64
        with self.assertRaisesRegex(ValueError, 'unbound'):
            artifact.validate_document(json.dumps(self.document))

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
            'Shared': {'type': 'string'}, 'Unrelated': {'type': 'boolean'}}}
        document['schemas'][identity] = root
        document['endpoints'] = []
        for method, path in [('POST', '/api/v1/resources/{id}'),
                             ('PUT', '/api/v1/asset-fields/{field}'),
                             ('GET', '/api/v1/asset-fields/{field}'),
                             ('GET', '/api/v1/asset-fields/{field}/references'),
                             ('GET', '/api/v1/resources/{id}/versions/{version}/references'),
                             ('GET', '/api/v1/groups/{id}/references'),
                             ('GET', '/api/v1/scopes/{id}/references'),
                             ('GET', '/api/v1/groups/{id}/impacts')]:
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

    def test_collection_check_detects_drift_and_write_repairs_it(self):
        expected = json.dumps(self.document).encode()
        projection = self.repository / artifact.COLLECTION
        projection.parent.mkdir(parents=True)
        projection.write_bytes(b'{}\n')
        with patch.object(artifact, 'ROOT', self.repository), patch.object(artifact, 'generated', return_value=expected), patch.object(artifact, 'collection_projection', return_value={}):
            artifact.check()
            projection.write_bytes(b'{"stale": true}\n')
            with self.assertRaisesRegex(ValueError, 'actual registered handlers'):
                artifact.check()
            artifact.check(write=True)
            self.assertEqual(projection.read_bytes(), b'{}\n')

    def test_export_writes_full_contract_without_updating_collection(self):
        expected = json.dumps(self.document).encode()
        with patch.object(artifact, 'ROOT', self.repository), patch.object(artifact, 'generated', return_value=expected):
            self.assertEqual(artifact.main(['--output', str(self.output)]), 0)
        self.assertEqual(self.output.read_bytes(), expected)
        self.assertFalse((self.repository / artifact.COLLECTION).exists())


if __name__ == '__main__':
    unittest.main()
