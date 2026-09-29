"""Discovered cases resolve one isolation policy without a duplicate case roster."""
from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hack'))
from t2_registry import MODULES, CasePolicy, resolve_cases


class Policies(unittest.TestCase):
    def test_module_default_and_exact_override(self):
        module = replace(MODULES['agent.registration'], db_mode='reuse', scope='objects',
                         policies=(CasePolicy('fault', 'fresh', 'objects'),))
        resolved = resolve_cases(module, ['ordinary', 'fault'])
        self.assertEqual([item.db_mode for item in resolved], ['reuse', 'fresh'])

    def test_overlapping_missing_and_stale_policies_fail(self):
        module = replace(MODULES['agent.registration'], policies=())
        variants = [
            replace(module, db_mode=None),
            replace(module, policies=(CasePolicy('gone', 'fresh', 'objects'),)),
            replace(module, policies=(CasePolicy('fault::', 'fresh', 'objects'),
                                      CasePolicy('fault::one', 'instance', 'objects'))),
        ]
        for value in variants:
            with self.subTest(value=value), self.assertRaises(ValueError):
                resolve_cases(value, ['fault::one'])

    def test_no_pg_has_no_database_mode_or_scope(self):
        module = MODULES['sources.winget']
        resolved, = resolve_cases(module, ['new_test'])
        self.assertIsNone(resolved.db_mode)
        self.assertIsNone(resolved.scope)
        with self.assertRaises(ValueError):
            resolve_cases(replace(module, db_mode='fresh'), ['new_test'])

    def test_local_worker_cannot_share_the_public_tenant(self):
        module = replace(MODULES['agent.registration'], db_mode='reuse', scope='objects',
                         fixtures=('local_worker',), policies=())
        with self.assertRaises(ValueError):
            resolve_cases(module, ['new_test'])


if __name__ == '__main__':
    unittest.main()
