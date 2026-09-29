"""Reuse qualifications reject changed databases and non-overlapping executions."""
from dataclasses import replace
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hack'))
from t2_execution import Invocation, Case
from t2_registry import MODULES
import t2

class ReuseTests(unittest.TestCase):
    def test_reuse_plan_preserves_order_and_requires_compatible_real_cases(self):
        jobs = [Invocation(replace(MODULES['agent.registration'], scope=scope),
                           Case(MODULES['agent.registration'].build, 'binary', '/binary', name))
                for name, scope in [('a', 'objects'), ('b', 'objects'), ('c', 'tenant'), ('d', 'pair')]]
        plan = {'objects': [j.id for j in jobs[:2]], 'tenants': [j.id for j in jobs[2:]]}
        phases = t2.reuse_phases(jobs, plan)
        self.assertEqual([[j.case.name for j in phase] for phase in phases],
                         [['a'], ['b'], ['a'], ['b'], ['a'], ['b'], ['a', 'b'], ['c', 'd']])
        flat = [j for phase in phases for j in phase]
        self.assertEqual(len({j.key for j in flat}), 10)
        jobs[0] = replace(jobs[0], module=replace(jobs[0].module, db_mode='fresh'))
        with self.assertRaisesRegex(RuntimeError, 'reuse'):
            t2.reuse_phases(jobs, plan)

    def test_evidence_requires_same_database_and_actual_execution_overlap(self):
        def result(tenant, begin, end, database='same'):
            return dict(status='passed', environment=dict(database=database, pg='normal', pgGeneration=1, tenant=tenant),
                        executionStartedMonotonic=begin, executionEndedMonotonic=end)
        pair = [result('tenant', 1, 4), result('tenant', 2, 3)]
        anchor = ('normal', 1, 'same')
        t2.verify_reuse_phase(pair, anchor, 'objects')
        for bad in [result('tenant', 5, 6), result('tenant', 2, 3, 'replacement'), result('foreign', 2, 3)]:
            with self.assertRaises(RuntimeError):
                t2.verify_reuse_phase([pair[0], bad], anchor, 'objects')
        with self.assertRaises(RuntimeError):
            t2.verify_reuse_phase(pair, anchor, 'tenants')
