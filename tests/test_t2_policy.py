"""Discovered cases resolve one isolation policy without a duplicate case roster."""
from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hack'))
from t2_registry import MODULES
from t2_model import CasePolicy, resolve_cases


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

    def test_asset_storage_has_no_identity_or_signing_preparation(self):
        module = MODULES['assets.http']
        storage = tuple(p for p in module.policies if '::storage::' in p.selector)
        self.assertTrue(storage)
        source = (Path(__file__).resolve().parents[1] / 'crates/app/tests/assets/storage.rs').read_text()
        names = [p.selector for p in storage]
        values = resolve_cases(replace(module, policies=storage), names)
        for name, value in zip(names, values):
            with self.subTest(case=name):
                self.assertIn('async fn ' + name.rsplit('::', 1)[1] + '(', source)
                self.assertEqual(value.fixtures, ('runtime_config',))
                self.assertEqual(value.actors, ())
        self.assertNotIn('agent_pki', module.fixtures)
        planning = MODULES['planning.http']
        self.assertNotIn('agent_pki', planning.fixtures)
        signer = next(p for p in planning.policies if p.selector.endswith('console_script_support_requires_signer_and_content'))
        self.assertIn('agent_pki', signer.fixtures)
        self.assertIn('task_signing', signer.fixtures)

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

    def test_empty_installers_cannot_reuse_a_migrated_database(self):
        registry = MODULES['installation.registry']
        self.assertEqual((registry.profile, registry.db_mode, registry.fixtures), ('product', 'fresh', ()))
        module = replace(MODULES['installation.migration'], policies=())
        for mode in ('fresh', 'instance'):
            resolved, = resolve_cases(replace(module, db_mode=mode), ['installer'])
            self.assertEqual((resolved.profile, resolved.db_mode), ('empty', mode))
        with self.assertRaises(ValueError):
            resolve_cases(replace(module, db_mode='reuse'), ['installer'])


if __name__ == '__main__':
    unittest.main()
