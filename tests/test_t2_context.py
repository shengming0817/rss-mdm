"""Cases own observations; invocations own mutable objects, not databases."""
from dataclasses import replace
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hack'))
from t2_execution import Case, Invocation
from t2_registry import MODULES
from t2_context import contexts, registration_tenants
import t2_context


def job(name, scope='objects', invocation=0):
    module = replace(MODULES['agent.registration'], scope=scope, actors=(('tenant', 'admin'),) + ((('peer', 'admin'),) if scope == 'pair' else ()))
    case = Case(module.build, 'binary', '/binary', name)
    return Invocation(module, case, invocation)


class ContextTests(unittest.TestCase):
    def test_contract_rejects_missing_wrong_typed_and_unprepared_fields(self):
        from copy import deepcopy
        value = next(iter(contexts('run', [job('a')]).values()))
        for field in ('caseId', 'invocationId', 'namespace', 'tenant', 'peer',
                      'fixtures', 'actors'):
            for replacement in (None, 42, ''):
                broken = deepcopy(value)
                if replacement is None:
                    del broken[field]
                else:
                    broken[field] = replacement
                with self.subTest(field=field, value=replacement), self.assertRaises(ValueError):
                    t2_context.validate(broken)
        with self.assertRaisesRegex(ValueError, 'actor'):
            t2_context.validate(value, ready=True)
        value['actors'][0]['principal'] = '44444444-4444-4444-8444-444444444444'
        self.assertEqual(t2_context.validate(value, ready=True), value)

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
        self.assertEqual([a['tenant'] for a in values[0]['actors']], [values[0]['tenant']])
        self.assertEqual([a['tenant'] for a in values[1]['actors']], [values[1]['tenant'], values[1]['peer']])
        self.assertTrue({v[k] for v in values for k in ('tenant', 'peer')} <= set(registration_tenants(values)))

    def test_registration_plan_accepts_1024_tenants_and_rejects_1025_before_services(self):
        jobs = [job(str(i), 'tenant') for i in range(1023)]
        self.assertEqual(len(registration_tenants(contexts('run', jobs).values())), 1024)
        jobs.append(job('one-over', 'tenant'))
        with self.assertRaisesRegex(ValueError, '1024'):
            registration_tenants(contexts('run', jobs).values())

    def test_admission_pause_owns_tenant_across_completion_failure_and_cancellation(self):
        from t2_model import resolve_cases
        registration = 'agent::t2::registration::'
        names = [registration + name for name in (
            'admission_pause_preserves_candidate_and_existing_identity',
            'registration_binding_and_replay',
            'browser_approval_quota_expiry_and_restart_are_durable',
            'registration_recovery_preserves_credential_rotation')]
        policies = resolve_cases(MODULES['agent.registration'], names)
        delivery = 'execution::t2::agent::delivery::registration_capability_and_wire_gate'
        delivery_module = MODULES['execution.agent.delivery']
        # Resolve its exact override without constructing an incomplete discovery roster.
        delivery_module = replace(delivery_module, policies=tuple(
            p for p in delivery_module.policies if delivery.startswith(p.selector)))
        policies += resolve_cases(delivery_module, [delivery])
        jobs = [Invocation(module, Case(module.build, 'binary', '/binary', name))
                for name, module in zip(names + [delivery], policies)]
        pause = jobs[0]
        self.assertEqual((pause.module.db_mode, pause.module.scope), ('reuse', 'tenant'))
        victims = [jobs[1], jobs[2], jobs[4]]
        self.assertTrue(all(j.module.scope == 'objects' for j in victims))
        # Every new invocation gets an observation domain even if its predecessor
        # never restores admission (success, early error, or process cancellation).
        repeated = [replace(pause, invocation=i) for i in range(3)]
        values = contexts('admission-regression', repeated + victims)
        ordinary = {values[j.key]['tenant'] for j in victims}
        isolated = {values[j.key]['tenant'] for j in repeated}
        self.assertEqual(len(ordinary), 1)
        self.assertEqual(len(isolated), 3)
        self.assertTrue(ordinary.isdisjoint(isolated))
