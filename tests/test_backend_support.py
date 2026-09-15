"""Product-only support edges must not widen core/adapter boundaries."""
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hack'))
import ci

SUPPORT = 'rss-mdm-backend-postgres-support'
ADAPTERS = {f'rss-mdm-{kind}-postgres' for kind in ('policy', 'resource', 'software-release')}

def graph():
    names = ADAPTERS | {SUPPORT, 'rss-mdm-policy', 'rss-mdm-app', 'sqlx'}
    def edge(n):
        return {'pkg': n, 'dep_kinds': [{'kind': None, 'target': None}]}
    nodes = [{'id': n, 'features': [], 'deps': [edge(SUPPORT)] if n in ADAPTERS else [edge('sqlx')] if n == SUPPORT else []} for n in names]
    return {'packages': [{'id': n, 'name': n} for n in names], 'resolve': {'nodes': nodes}}

class BackendSupportBoundary(unittest.TestCase):
    def test_exact_consumers_and_no_product_dependencies(self):
        ci.verify_backend_support(graph())
        for owner, target in [('rss-mdm-app', SUPPORT), ('rss-mdm-policy', SUPPORT), (SUPPORT, 'rss-mdm-policy')]:
            data = graph()
            next(n for n in data['resolve']['nodes'] if n['id'] == owner)['deps'].append({'pkg': target, 'dep_kinds': [{'kind': None, 'target': None}]})
            with self.subTest(owner=owner), self.assertRaises(RuntimeError):
                ci.verify_backend_support(data)
        data = graph()
        next(n for n in data['resolve']['nodes'] if n['id'] == SUPPORT)['features'] = ['compat']
        with self.assertRaises(RuntimeError): ci.verify_backend_support(data)

    def test_forbidden_transitive_product(self):
        data = graph()
        next(n for n in data['resolve']['nodes'] if n['id'] == 'sqlx')['deps'].append({'pkg': 'rss-mdm-policy', 'dep_kinds': [{'kind': None, 'target': None}]})
        with self.assertRaises(RuntimeError): ci.verify_backend_support(data)
