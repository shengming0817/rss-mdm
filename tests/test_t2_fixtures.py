"""Database and observation lifetimes are independent from case scheduling."""
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hack'))
from t2_database import Costs, DatabasePool, measure
from t2_execution import Case, Invocation
from t2_fixtures import RunFixtures
from t2_registry import MODULES


class PoolTests(unittest.TestCase):
    def pool(self):
        pool = DatabasePool(Mock(), 't2', Costs(), 384)
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
        self.assertEqual(pool.costs.snapshot()['counts']['sharedDatabases'], 2)
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
        self.assertEqual(pool.costs.snapshot()['counts']['faultRestorations'], 1)
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
        pool = DatabasePool(Mock(), 't2-fault', Costs(), 128)
        pool.owner = Mock()
        pool.owner.sql.return_value = '128'
        pool.dirty = True
        pool.templates = {'product': 'stale'}
        pool.postgres()
        self.assertEqual(pool.templates, {})
        pool.owner.reset.assert_called_once()
        pool.owner.up.assert_called_once()
        self.assertEqual(pool.costs.snapshot()['counts']['faultReplacements'], 1)
        self.assertEqual(pool.generation, 1)


class PreparationTests(unittest.TestCase):
    def fixture(self, output):
        fixture = RunFixtures(Mock(), output, 2)
        fixture.normal = Mock()
        fixture.normal.owner.project = 'normal'
        fixture.fault = Mock()
        fixture.fault.owner.project = 'fault'
        fixture.gateway_owner = Mock()
        fixture.gateway_owner.project = 'gateway'
        return fixture

    def test_jobs_budget_sets_connection_capacity_without_allocating_more_databases(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = RunFixtures(Mock(), Path(tmp), 4)
            try:
                self.assertEqual(fixture.normal.owner.extra['MDM_PG_MAX_CONNECTIONS'], '640')
                self.assertEqual(fixture.fault.owner.extra['MDM_PG_MAX_CONNECTIONS'], '128')
                self.assertEqual(fixture.normal.shared, {})
            finally:
                fixture.cert_directory.cleanup()

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

    def test_cleanup_recovers_compose_resources_when_local_directories_are_missing(self):
        from t2_environment import Environment
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.fixture(Path(tmp))
            try:
                for owner in (fixture.normal.owner, fixture.fault.owner, fixture.gateway_owner):
                    owner.root = Path(tmp) / owner.project
                fixture.cleanup_environments()
                for owner in (fixture.normal.owner, fixture.fault.owner, fixture.gateway_owner):
                    owner.reset.assert_called_once()
                # The existing reset still verifies Docker ownership without owner.json.
                environment = Environment(Path(tmp))
                with patch.object(environment, 'verify_ownership') as verify, \
                     patch.object(environment, 'compose') as compose, \
                     patch.object(environment, 'host_ports'):
                    environment.reset()
                    verify.assert_called_once()
                    compose.assert_called_once_with('--profile', '*', 'down', '--volumes', '--remove-orphans')
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
    def test_cost_updates_have_one_owner_across_pools(self):
        from concurrent.futures import ThreadPoolExecutor
        from t2_database import Costs
        costs = Costs()
        def record(_):
            for _ in range(1000):
                costs.increment('clones')
                costs.append({'phase': 'clone'})
        with ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(record, range(8)))
        value = costs.snapshot()
        self.assertEqual(value['counts']['clones'], 8000)
        self.assertEqual(len(value['operations']), 8000)

    def test_failed_preparation_keeps_its_cost_and_coordinates(self):
        events = []
        with self.assertRaisesRegex(RuntimeError, 'original'):
            with measure(events, 'clone', database='owned'):
                raise RuntimeError('original')
        event, = events
        self.assertEqual((event['phase'], event['status'], event['database']), ('clone', 'failed', 'owned'))
        self.assertGreaterEqual(event['endedMonotonic'], event['startedMonotonic'])
