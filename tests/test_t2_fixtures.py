"""Database and observation lifetimes are independent from case scheduling."""
from collections import Counter
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hack'))
from t2_database import DatabasePool, measure
from t2_execution import Case, Invocation
from t2_fixtures import RunFixtures
from t2_registry import MODULES


class PoolTests(unittest.TestCase):
    def pool(self):
        pool = DatabasePool(Mock(), 't2', Counter())
        pool.postgres = Mock()
        pool.owner = Mock()
        pool.clone = Mock(side_effect=lambda profile, prefix: prefix + profile)
        return pool

    def test_compatible_cases_share_database_without_cloning_per_worker(self):
        pool = self.pool()
        with pool.database('product', 'reuse') as first:
            with pool.database('product', 'reuse') as second:
                self.assertEqual(first, second)
            with pool.database('backend', 'reuse') as third:
                self.assertNotEqual(first, third)
        self.assertEqual(pool.clone.call_count, 2)
        self.assertEqual(pool.counts['sharedDatabases'], 2)
        pool.owner.sql.assert_not_called()

    def test_fresh_drops_its_database_even_on_failure(self):
        pool = self.pool()
        with self.assertRaisesRegex(RuntimeError, 'case failed'):
            with pool.database('product', 'fresh'):
                raise RuntimeError('case failed')
        pool.owner.sql.assert_called_once_with('DROP DATABASE "t2_case_product" WITH (FORCE)')
        self.assertFalse(pool.dirty)

    def test_successful_fault_requires_restoration_before_reuse(self):
        pool = self.pool()
        pool.role_state = Mock(side_effect=['before', 'before'])
        with pool.database('product', 'instance'):
            pass
        self.assertFalse(pool.dirty)
        self.assertEqual(pool.counts['faultRestorations'], 1)
        pool.owner.reset.assert_not_called()

    def test_failed_fault_or_role_drift_is_quarantined(self):
        for failed in (True, False):
            pool = self.pool()
            pool.role_state = Mock(side_effect=['before', 'after'])
            with self.assertRaises((RuntimeError, AssertionError)):
                with pool.database('product', 'instance'):
                    if failed:
                        raise RuntimeError('original failure')
            self.assertTrue(pool.dirty)
            pool.owner.reset.assert_not_called()

    def test_quarantined_fault_is_replaced_for_next_case_only(self):
        pool = DatabasePool(Mock(), 't2-fault', Counter())
        pool.owner = Mock()
        pool.dirty = True
        pool.templates = {'product': 'stale'}
        pool.postgres()
        self.assertEqual(pool.templates, {})
        pool.owner.reset.assert_called_once()
        pool.owner.up.assert_called_once()
        self.assertEqual(pool.counts['faultReplacements'], 1)
        self.assertEqual(pool.generation, 1)


class PreparationTests(unittest.TestCase):
    def fixture(self, output):
        fixture = RunFixtures(Mock(), output)
        fixture.normal = Mock()
        fixture.fault = Mock()
        fixture.gateway_owner = Mock()
        return fixture

    def test_cleanup_attempts_every_owner_after_a_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.fixture(Path(tmp))
            try:
                fixture.normal.owner.reset.side_effect = RuntimeError('normal cleanup')
                with self.assertRaisesRegex(RuntimeError, 'clean owned'):
                    fixture.cleanup_environments()
                fixture.fault.owner.reset.assert_called_once()
                fixture.gateway_owner.reset.assert_called_once()
            finally:
                fixture.cert_directory.cleanup()

    def test_instance_only_does_not_start_normal_pg(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.fixture(Path(tmp))
            module = MODULES['identity.local']
            job = Invocation(module, Case(module.build, 'test', '/test', 'identity'))
            try:
                fixture.prepare([job])
                fixture.normal.database.assert_not_called()
                fixture.fault.database.assert_not_called()
            finally:
                fixture.cert_directory.cleanup()

    def test_no_pg_starts_no_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.fixture(Path(tmp))
            try:
                module = MODULES['publication.artifact']
                fixture.certificates = Mock()
                fixture.prepare([Invocation(module, Case(module.build, 'test', '/test', 'artifact'))])
                fixture.normal.database.assert_not_called()
                fixture.fault.database.assert_not_called()
            finally:
                fixture.cert_directory.cleanup()


class CostTests(unittest.TestCase):
    def test_failed_preparation_keeps_its_cost_and_coordinates(self):
        events = []
        with self.assertRaisesRegex(RuntimeError, 'original'):
            with measure(events, 'clone', database='owned'):
                raise RuntimeError('original')
        event, = events
        self.assertEqual((event['phase'], event['status'], event['database']), ('clone', 'failed', 'owned'))
        self.assertGreaterEqual(event['endedMonotonic'], event['startedMonotonic'])
