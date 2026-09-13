"""Fail-closed proof selection and independent source/feature identity guards."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hack'))
import group_postgres_consumer as consumer


class GroupPostgresGuards(unittest.TestCase):
    def test_active_tree_rejects_non_pg_drivers(self):
        tree = '\n'.join(f'{name} v1.0.0' for name in consumer.PRODUCTS | consumer.RSS | {'sqlx-postgres'})
        consumer.verify_active_tree(tree)
        for name in ['sqlx-mysql', 'sqlx-sqlite', 'axum', 'hyper-util']:
            with self.assertRaises(RuntimeError): consumer.verify_active_tree(tree + f'\n{name} v1.0.0')
        with self.assertRaises(RuntimeError): consumer.verify_active_tree('')

    def test_empty_partial_and_ignored_success_fail(self):
        valid = '\n'.join(f'test {name} ... ok' for name in consumer.pg.EXPECTED)
        valid += f'\ntest result: ok. {len(consumer.pg.EXPECTED)} passed; 0 failed; 0 ignored;'
        consumer.pg.verify_tests(valid)
        for invalid in ['', 'test result: ok. 0 passed; 0 failed; 0 ignored;',
                        valid.replace('0 ignored;', '1 ignored;'), valid.replace(' ... ok', ' ... ignored', 1)]:
            with self.subTest(invalid=invalid), self.assertRaises(RuntimeError):
                consumer.pg.verify_tests(invalid)

    def fixture(self):
        pin = ('https://example.test/rss', 'a' * 40)
        product = 'git+file:///test?rev=' + 'b' * 40 + '#' + 'b' * 40
        rss = f'git+{pin[0]}?rev={pin[1]}#{pin[1]}'
        registry = 'registry+https://github.com/rust-lang/crates.io-index'
        names = consumer.PRODUCTS | consumer.RSS | consumer.DIRECT
        packages = [{'id': n, 'name': n, 'version': '1.0.0', 'source': product if n in consumer.PRODUCTS else rss if n in consumer.RSS else registry} for n in sorted(names)]
        packages.append({'id': 'root', 'name': 'consumer', 'source': None})
        def edge(name):
            return {'pkg': name, 'dep_kinds': [{'kind': None, 'target': None}]}
        nodes = [{'id': n, 'features': ['consumer', 'default', 'producer'] if n == 'rss-transactional-messaging' else [],
                  'deps': [edge(x) for x in names - {n}] if n == 'rss-mdm-group-postgres' else []} for n in sorted(names)]
        nodes.append({'id': 'root', 'features': [], 'deps': [edge(n) for n in consumer.DIRECT]})
        return {'packages': packages, 'workspace_members': ['root'], 'resolve': {'root': 'root', 'nodes': nodes}}, product, pin, {(p['name'], p['version'], p['source']) for p in packages if p['source'] == registry}

    def test_unrelated_product_source_and_features_are_rejected(self):
        data, source, pin, locked = self.fixture()
        consumer.verify_closure(data, source, pin, locked)
        consumer.verify_no_feature_supplement(data, data)
        extra_feature = copy.deepcopy(data)
        extra_feature['resolve']['nodes'][0]['features'].append('unprovided')
        with self.assertRaises(RuntimeError): consumer.verify_no_feature_supplement(extra_feature, data)
        for name in ['rss-mdm-group-postgres', 'rss-mdm-group', 'rss-contract']:
            altered = copy.deepcopy(data)
            next(p for p in altered['packages'] if p['name'] == name)['source'] = 'path+file:///parent'
            with self.assertRaises(RuntimeError): consumer.verify_closure(altered, source, pin, locked)
        altered = copy.deepcopy(data)
        next(n for n in altered['resolve']['nodes'] if n['id'] == 'rss-transactional-messaging')['features'].append('relay')
        with self.assertRaises(RuntimeError): consumer.verify_closure(altered, source, pin, locked)
        altered = copy.deepcopy(data)
        next(n for n in altered['resolve']['nodes'] if n['id'] == 'rss-mdm-group-postgres')['features'].append('integration')
        with self.assertRaises(RuntimeError): consumer.verify_closure(altered, source, pin, locked)
        altered = copy.deepcopy(data)
        altered['packages'].append({'id': 'other', 'name': 'rss-mdm-inventory', 'version': '1.0.0', 'source': source})
        altered['resolve']['nodes'].append({'id': 'other', 'features': [], 'deps': []})
        with self.assertRaises(RuntimeError): consumer.verify_closure(altered, source, pin, locked)

    def test_backend_capabilities_enforce_their_own_core_and_source(self):
        import json
        for capability in ('policy', 'resource', 'software-release'):
            with self.subTest(capability=capability):
                data, source, pin, locked = self.fixture()
                data = json.loads(json.dumps(data).replace('rss-mdm-group', 'rss-mdm-' + capability))
                consumer.verify_closure(data, source, pin, locked, capability)
                products = {f'rss-mdm-{capability}', f'rss-mdm-{capability}-postgres'}
                tree = '\n'.join(f'{name} v1.0.0' for name in products | consumer.RSS | {'sqlx-postgres'})
                consumer.verify_active_tree(tree, capability)
                altered = copy.deepcopy(data)
                next(p for p in altered['packages'] if p['name'] == f'rss-mdm-{capability}')['source'] = 'path+file:///parent'
                with self.assertRaises(RuntimeError): consumer.verify_closure(altered, source, pin, locked, capability)
                altered = json.loads(json.dumps(data).replace(f'rss-mdm-{capability}\"', 'rss-mdm-inventory\"'))
                with self.assertRaises(RuntimeError): consumer.verify_closure(altered, source, pin, locked, capability)

    def test_backend_proofs_require_every_named_behavior(self):
        import backend_postgres_consumer as backend
        for names in backend.pg.CONSUMERS.values():
            valid = '\n'.join(f'test {name} ... ok' for name in names)
            valid += f'\ntest result: ok. {len(names)} passed; 0 failed; 0 ignored;'
            backend.pg.verify_tests(valid, names)
            for invalid in ('', valid.replace(' ... ok', ' ... ignored', 1), valid.replace('0 ignored;', '1 ignored;')):
                with self.assertRaises(RuntimeError): backend.pg.verify_tests(invalid, names)
