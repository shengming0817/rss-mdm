"""Cases own observations; invocations own mutable objects, not databases."""
from dataclasses import replace
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hack'))
from t2_execution import Case, Invocation
from t2_registry import MODULES
from t2_context import contexts, installation


def job(name, scope='objects', invocation=0):
    module = replace(MODULES['agent.registration'], scope=scope)
    case = Case(module.build, 'binary', '/binary', name)
    return Invocation(module, case, invocation)


class ContextTests(unittest.TestCase):
    def test_objects_share_tenant_and_repeated_invocations_change_namespace(self):
        jobs = [job('a'), job('b'), job('a', invocation=1)]
        values = list(contexts('run', jobs).values())
        self.assertEqual(len({x['tenant'] for x in values}), 1)
        self.assertEqual(len({x['namespace'] for x in values}), 3)
        self.assertEqual(values[0]['caseId'], values[2]['caseId'])

    def test_full_tenant_observations_are_owned_by_each_invocation(self):
        jobs = [job('a', 'tenant'), job('b', 'pair'), job('a', 'tenant', 1)]
        values = list(contexts('run', jobs).values())
        self.assertNotEqual(values[0]['tenant'], values[2]['tenant'])
        self.assertNotEqual(values[0]['tenant'], values[1]['tenant'])
        self.assertNotEqual(values[1]['tenant'], values[1]['peer'])
        self.assertEqual(values[0]['identityTenants'], [values[0]['tenant']])
        self.assertEqual(values[1]['identityTenants'], [values[1]['tenant'], values[1]['peer']])
        self.assertTrue({v[k] for v in values for k in ('tenant', 'peer')} <= set(installation(values)['tenants']))

    def test_installation_limit_fails_before_services(self):
        jobs = [job(str(i), 'pair') for i in range(65)]
        with self.assertRaisesRegex(ValueError, '128'):
            installation(contexts('run', jobs).values())
