"""Database and observation lifetimes are independent from case scheduling."""
from contextlib import contextmanager, nullcontext
from dataclasses import replace
from pathlib import Path
import sys
import json
from types import SimpleNamespace
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
        pool = DatabasePool(Mock(), 't2', Costs(), 384, Path(tempfile.gettempdir()) / 't2-fixture-unit')
        pool.postgres = Mock()
        pool.owner = Mock(project='pg-test')
        pool.clone = Mock(side_effect=lambda profile, prefix: prefix + profile)
        return pool

    def test_first_postgres_failure_is_recorded_and_later_consumers_are_blocked(self):
        from verification_result import DependencyBlocked
        with tempfile.TemporaryDirectory() as temporary:
            pool = DatabasePool(Mock(), 't2', Costs(), 384, Path(temporary))
            pool.owner = Mock(project='pg-test')
            failure = RuntimeError('startup rejected')
            pool.owner.up.side_effect = failure
            with self.assertRaises(RuntimeError) as first:
                pool.postgres()
            self.assertIs(first.exception, failure)
            self.assertEqual(json.loads(Path(failure.root_cause).read_text())['phase'], 'postgres-start')
            with self.assertRaises(DependencyBlocked) as later:
                pool.postgres()
            self.assertEqual(later.exception.root_cause, failure.root_cause)
            pool.owner.up.assert_called_once()

    def test_profile_failure_blocks_only_that_profile(self):
        from verification_result import DependencyBlocked
        with tempfile.TemporaryDirectory() as temporary:
            pool = DatabasePool(Mock(), 't2', Costs(), 384, Path(temporary))
            pool.owner = Mock(project='pg-test')
            pool.ready = True
            failure = RuntimeError('baseline rejected')
            pool.owner.sql.side_effect = failure
            with self.assertRaises(RuntimeError) as first:
                pool.template('product')
            self.assertIs(first.exception, failure)
            with self.assertRaises(DependencyBlocked) as later:
                pool.template('product')
            self.assertEqual(later.exception.root_cause, failure.root_cause)
            independent = ('backend-template', {}, 'coordinates')
            pool.templates['backend'] = independent
            self.assertEqual(pool.template('backend'), independent)
            pool.owner.sql.assert_called_once()

    def test_cleanup_failure_preserves_case_failure_and_quarantines_owner(self):
        pool = self.pool()
        pool.sample_connections = Mock()
        pool.owner.sql.side_effect = RuntimeError('drop failed')
        failure = RuntimeError('business failed')
        with self.assertRaises(RuntimeError) as original:
            with pool.disposable('product'):
                raise failure
        self.assertIs(original.exception, failure)
        self.assertIsNotNone(pool.cleanup_error)
        self.assertTrue(any('drop failed' in note for note in failure.__notes__))

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
        pool.owner.sql.assert_any_call('DROP DATABASE "t2_case_product" WITH (FORCE)')
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
        pool = DatabasePool(Mock(), 't2-fault', Costs(), 128, Path(tempfile.gettempdir()) / 't2-fixture-unit')
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

    def test_tenant_seed_batches_only_missing_coordinates_and_records_after_commit(self):
        pool = self.pool()
        pool.seed_tenants('shared', 'product', ['b', 'a', 'a'])
        sql, database = pool.owner.sql.call_args.args
        self.assertEqual(database, 'shared')
        self.assertEqual(sql.count('public.create_new_tenant'), 2)
        self.assertIn('BEGIN;', sql)
        self.assertIn('COMMIT;', sql)
        pool.seed_tenants('shared', 'product', ['a'])
        self.assertEqual(pool.owner.sql.call_count, 1)
        pool.owner.sql.side_effect = RuntimeError('seed rejected')
        with self.assertRaisesRegex(RuntimeError, 'seed rejected'):
            pool.seed_tenants('shared', 'product', ['c'])
        self.assertNotIn('c', pool.seeded_tenants['shared'])
        self.assertEqual(pool.costs.snapshot()['counts']['preparedTenants'], 2)


class PreparationTests(unittest.TestCase):
    def test_each_gateway_invocation_mounts_its_own_immutable_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture=object.__new__(RunFixtures)
            environment=SimpleNamespace(root=Path(temporary),extra={},prepare_inputs=Mock(),verify_ownership=Mock(),reset=Mock())
            environment.compose=Mock(side_effect=lambda *args, **kwargs: '127.0.0.1:12345' if args[0]=='port' else 'owned-container' if args[0]=='ps' else '')
            fixture.gateway_owner=environment
            with fixture.gateway('first configuration',{'server.crt':'first certificate'}):
                first=Path(environment.extra['MDM_GATEWAY_PROBE_DIRECTORY'])
            with fixture.gateway('second configuration',{'server.crt':'second certificate'}):
                second=Path(environment.extra['MDM_GATEWAY_PROBE_DIRECTORY'])
                self.assertNotEqual(first,second)
                self.assertEqual((first/'nginx.conf').read_text(),'first configuration')
                self.assertEqual((first/'server.crt').read_text(),'first certificate')
                self.assertEqual((second/'nginx.conf').read_text(),'second configuration')
                self.assertEqual((second/'server.crt').read_text(),'second certificate')
            environment.reset.assert_not_called()
            self.assertEqual(sum(call.args == ('--profile', '*', 'down', '--volumes', '--remove-orphans') for call in environment.compose.call_args_list), 2)

    def fixture(self, output):
        recovery_patch = patch('apple_ca.recover')
        recovery = recovery_patch.start()
        self.addCleanup(recovery_patch.stop)
        fixture = RunFixtures(Mock(), output, 2)
        fixture.apple_recovery_test = recovery
        fixture.normal = Mock()
        fixture.normal.owner.project = 'normal'
        fixture.normal.ready = False
        fixture.fault = Mock()
        fixture.fault.owner.project = 'fault'
        fixture.fault.ready = False
        fixture.gateway_owner = Mock()
        fixture.gateway_owner.project = 'gateway'
        for owner in (fixture.normal.owner, fixture.fault.owner, fixture.gateway_owner):
            owner.postgres_queries = dict(container=0, port=0)
        fixture.builds.processes.cleanup.return_value = nullcontext()
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
        for failing in ('normal', 's3'):
            with self.subTest(failing=failing), tempfile.TemporaryDirectory() as tmp:
                fixture = self.fixture(Path(tmp))
                fixture.s3 = Mock()
                try:
                    owners = {'normal': fixture.normal.owner, 'fault': fixture.fault.owner,
                              'gateway': fixture.gateway_owner, 's3': fixture.s3}
                    owners[failing].reset.side_effect = RuntimeError('cleanup failed')
                    with self.assertRaisesRegex(RuntimeError, 'clean owned'):
                        fixture.cleanup_environments()
                    for owner in owners.values():
                        owner.reset.assert_called_once()
                finally:
                    fixture.cert_directory.cleanup()

    def test_non_s3_run_recovers_prior_owned_provider_without_starting_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.fixture(Path(tmp))
            fixture.certificates = Mock()
            self.assertFalse(fixture.s3.ready)
            info = {'Name': '/' + fixture.s3.name, 'Config': {'Labels': {
                'rss.mdm.worktree': fixture.s3.owner.identity, 'rss.mdm.fixture': 'content-s3'}}}
            module = MODULES['publication.artifact']
            job = Invocation(module, Case(module.build, 'test', '/test', 'artifact'))
            with patch('s3_fixtures.run') as run, \
                 patch('t2_fixtures.owned_by', return_value=nullcontext()), \
                 patch.object(fixture.s3, 'prepare') as prepare:
                run.side_effect = [SimpleNamespace(stdout='prior'), SimpleNamespace(stdout=json.dumps([info])),
                                   None, SimpleNamespace(stdout='')]
                with fixture:
                    fixture.prepare([job])
                run.assert_any_call(['docker', 'rm', '-f', '-v', 'prior'], capture_output=True, timeout=30)
                self.assertEqual(run.call_count, 4)
                prepare.assert_not_called()
                fixture.normal.database.assert_not_called()
                fixture.normal.owner.reset.assert_called_with()
                self.assertEqual(fixture.normal.owner.reset.call_count, 2)

    def test_startup_recovery_refuses_foreign_s3_and_still_cleans_other_owners(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.fixture(Path(tmp))
            info = {'Name': '/' + fixture.s3.name, 'Config': {'Labels': {
                'rss.mdm.worktree': 'foreign', 'rss.mdm.fixture': 'content-s3'}}}
            with patch('s3_fixtures.run') as run, \
                 patch('t2_fixtures.owned_by', return_value=nullcontext()):
                run.side_effect = [SimpleNamespace(stdout='foreign'), SimpleNamespace(stdout=json.dumps([info]))]
                with self.assertRaisesRegex(RuntimeError, 'clean owned'):
                    with fixture:
                        self.fail('foreign ownership must reject startup')
                self.assertEqual(run.call_count, 2)
                for owner in (fixture.normal.owner, fixture.fault.owner, fixture.gateway_owner):
                    owner.reset.assert_called_once()

    def test_cleanup_recovers_compose_resources_when_local_directories_are_missing(self):
        from t2_environment import Environment
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.fixture(Path(tmp))
            fixture.s3 = Mock()
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
                    compose.assert_called_once_with('--profile', '*', 'down', '--volumes', '--remove-orphans', timeout=30)
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

    def test_identity_environment_initialization_and_refresh_are_single_flight(self):
        from concurrent.futures import ThreadPoolExecutor
        import threading
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.fixture(Path(tmp))
            self.addCleanup(fixture.cert_directory.cleanup)
            pool = fixture.normal
            pool.owner.root = Path(tmp)
            (pool.owner.root / 'ca.crt').write_text('fixture CA')
            pool.owner.sql.return_value = 'management'
            pool.generation = 1
            pool.installation = 'installation'
            pool.database_config.return_value = {}
            fixture.runtime_config = Mock(return_value={})
            fixture.recovery_config = Mock(return_value={})
            fixture.builds.executables = {'rss-mdm': '/fixture/mdm'}
            # Publication-only cases may populate content before identity is first requested.
            content = fixture.root / 'shared' / 'content'
            content.mkdir(parents=True)
            (content / 'artifact').write_text('retained')
            stages = []
            def helper(root, manifest, output, database):
                stages.append(manifest['stage'])
                (root / 'source-session').write_text(str(len(stages)))
            fixture.preparation_helper = helper
            def parallel():
                barrier = threading.Barrier(4)
                def call(_):
                    barrier.wait(timeout=5)
                    return fixture.identity_environment(pool, 'shared', Path(tmp))
                with ThreadPoolExecutor(max_workers=4) as executor:
                    return list(executor.map(call, range(4)))
            with patch('t2_fixtures.run') as run:
                initial = parallel()
                self.assertEqual(stages, ['environment'])
                self.assertEqual({value[2] for value in initial}, {'1'})
                run.assert_called_once()
                fixture.identities[('normal', 1, 'shared')]['refreshed'] = -1000
                refreshed = parallel()
                self.assertEqual(stages, ['environment', 'refresh'])
                self.assertEqual({value[2] for value in refreshed}, {'2'})
                # Previously returned snapshots remain valid strings, not mutable file handles.
                self.assertEqual(initial[0][2], '1')
                self.assertEqual((content / 'artifact').read_text(), 'retained')

    def test_shared_materials_copy_private_bytes_and_relocate_configuration(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.fixture(Path(tmp))
            self.addCleanup(fixture.cert_directory.cleanup)
            roots = [Path(tmp) / name for name in ('first', 'second')]
            for root in roots:
                root.mkdir()
                for name in ('ca.crt', 'server.crt', 'server.key'):
                    (root / name).write_text(name)
            def generate(root, certificate, key, materials):
                (root / 'device.key').write_text('original')
                (root / 'windows.json').write_text(json.dumps({'path': str(root / 'device.key')}))
            with patch('windows_fixtures.generate', side_effect=generate) as generator:
                for root in roots:
                    fixture.prepare_materials('windows', root)
                generator.assert_called_once()
            (roots[0] / 'device.key').write_text('corrupted')
            self.assertEqual((roots[1] / 'device.key').read_text(), 'original')
            self.assertEqual(json.loads((roots[1] / 'windows.json').read_text())['path'], str(roots[1] / 'device.key'))

    def test_failed_materials_reference_the_original_failure(self):
        from verification_result import DependencyBlocked
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.fixture(Path(tmp))
            self.addCleanup(fixture.cert_directory.cleanup)
            root = Path(tmp) / 'input'
            root.mkdir()
            for name in ('ca.crt', 'server.crt', 'server.key'):
                (root / name).write_text(name)
            failure = RuntimeError('material generation failed')
            with patch('windows_fixtures.generate', side_effect=failure) as generate:
                with self.assertRaises(RuntimeError) as first:
                    fixture.prepare_materials('windows', root)
                self.assertIs(first.exception, failure)
                self.assertTrue(Path(failure.root_cause).is_file())
                with self.assertRaises(DependencyBlocked) as later:
                    fixture.prepare_materials('windows', root)
                self.assertEqual(later.exception.root_cause, failure.root_cause)
                generate.assert_called_once()

    def test_failed_identity_environment_is_not_retried_by_later_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.fixture(Path(tmp))
            self.addCleanup(fixture.cert_directory.cleanup)
            pool = fixture.normal
            pool.generation = 1
            pool.owner.root = Path(tmp)
            (pool.owner.root / 'ca.crt').write_text('fixture CA')
            pool.owner.sql.side_effect = RuntimeError('original database failure')
            with self.assertRaisesRegex(RuntimeError, 'original database failure'):
                fixture.identity_environment(pool, 'shared', Path(tmp))
            with self.assertRaisesRegex(RuntimeError, 'previously failed') as caught:
                fixture.identity_environment(pool, 'shared', Path(tmp))
            self.assertEqual(str(caught.exception.__cause__), 'original database failure')
            pool.owner.sql.assert_called_once()

    def test_helper_failure_keeps_its_log_for_later_blocked_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.fixture(Path(tmp))
            self.addCleanup(fixture.cert_directory.cleanup)
            pool = fixture.normal
            pool.generation = 1
            root = fixture.root / 'shared'
            root.mkdir()
            fixture.identities[('normal', 1, 'shared')] = dict(management='management', refreshed=-1000)
            fixture.builds.discover.return_value = [object()]
            failure = RuntimeError('helper SQL failed')
            def execute(case, env, output):
                output.mkdir(parents=True)
                (output / 'test.log').write_text('original SQL failure')
                raise failure
            fixture.builds.execute.side_effect = execute
            output = Path(tmp) / 'first' / 'identity-setup'
            with self.assertRaisesRegex(RuntimeError, 'helper SQL failed') as first:
                fixture.identity_environment(pool, 'shared', output)
            with self.assertRaisesRegex(RuntimeError, 'previously failed') as blocked:
                fixture.identity_environment(pool, 'shared', Path(tmp) / 'second' / 'identity-setup')
            expected = output / 'refresh' / 'test.log'
            self.assertEqual(first.exception.root_cause, str(expected))
            self.assertEqual(blocked.exception.root_cause, str(expected))
            self.assertEqual(expected.read_text(), 'original SQL failure')
            fixture.builds.execute.assert_called_once()


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


class CryptographicNeedsTests(unittest.TestCase):
    def test_normal_agent_material_is_minimal_and_configuration_keys_are_exact(self):
        from agent_pki_fixtures import prepare
        for count, materials in ((0, ()), (2, ('other',))):
            with self.subTest(count=count), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                config = root / 'ca.json'
                config.write_text(json.dumps({'root': [str(root / 'root.crt')],
                                             'crt': str(root / 'issuer.crt'), 'key': str(root / 'issuer.key')}))
                commands = []
                def openssl(*args):
                    commands.append(tuple(map(str, args)))
                    for flag in ('-out', '-keyout'):
                        if flag in args:
                            Path(args[args.index(flag) + 1]).write_text('fixture')
                with patch('agent_pki_fixtures.openssl', side_effect=openssl):
                    prepare(root, config, root / 'password', configuration_devices=count, materials=materials)
                self.assertEqual(sorted(path.name for path in root.glob('configuration-*.der')),
                                 [f'configuration-{i}.der' for i in range(count)])
                self.assertTrue((root / 'agent.der').exists())
                self.assertEqual((root / 'other.der').exists(), 'other' in materials)
                self.assertFalse((root / 'weak.der').exists())
                self.assertFalse((root / 'agent-subordinate.key').exists())
                self.assertFalse(any('x509' in command for command in commands))

class PreparationBatchTests(unittest.TestCase):
    def test_admitted_actors_are_batched_and_stable_admin_reuses_credentials(self):
        import threading
        import time
        import uuid
        from concurrent.futures import ThreadPoolExecutor
        from t2_environment import private
        with tempfile.TemporaryDirectory() as tmp:
            fixture = RunFixtures(Mock(), Path(tmp), 2)
            self.addCleanup(fixture.cert_directory.cleanup)
            module = replace(MODULES['execution.agent.content'], actors=(('tenant', 'admin'),))
            jobs = [Invocation(module, Case(module.build, 'test', '/test', str(i))) for i in range(3)]
            fixture.prepare(jobs)
            shared = fixture.root / 'shared'
            shared.mkdir()
            fixture.identity_environment = Mock(return_value=(shared, 'management', 'source'))
            pool = SimpleNamespace(owner=SimpleNamespace(project='pg'), generation=1,
                                   database_config=lambda *args: {})
            calls = []
            def helper(root, manifest, output, database):
                calls.append(manifest)
                for name in manifest['cases']:
                    path = Path(name)
                    context = json.loads(path.read_text())
                    for actor in context['actors']:
                        actor['principal'] = str(uuid.uuid5(uuid.NAMESPACE_URL, actor['login']))
                        private(path.parent / f"credential-{actor['tenant']}-{actor['role']}", 'real-issued-test-double')
                        private(path.parent / f"credential-meta-{actor['tenant']}-{actor['role']}", time.time() + 300)
                    private(path, context)
            fixture.preparation_helper = helper
            gate = threading.Barrier(2)
            def prepare(job):
                gate.wait(timeout=3)
                fixture.prepare_identity(pool, 'db', job, Path(tmp) / job.key)
            with ThreadPoolExecutor(max_workers=2) as executor:
                list(executor.map(prepare, jobs[:2]))
            self.assertEqual(len(calls), 1)
            self.assertEqual(len(calls[0]['cases']), 2)
            fixture.prepare_identity(pool, 'db', jobs[2], Path(tmp) / jobs[2].key)
            self.assertEqual(len(calls), 1)
            self.assertEqual(len({fixture.case_contexts[j.key]['actors'][0]['principal'] for j in jobs}), 1)

    def test_gateway_product_worker_has_a_distinct_tenant_from_shared_workers(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = RunFixtures(Mock(), Path(tmp), 2)
            self.addCleanup(fixture.cert_directory.cleanup)
            shared = MODULES['execution.agent.content']
            gateway = MODULES['gateway.admission']
            jobs = [Invocation(shared, Case(shared.build, 'test', '/test', 'shared')), Invocation(gateway, None)]
            fixture.prepare(jobs)
            contexts = [fixture.case_contexts[job.key] for job in jobs]
            self.assertNotEqual(contexts[0]['tenant'], contexts[1]['tenant'])
            self.assertEqual(jobs[0].module.profile, jobs[1].module.profile)
            self.assertIn('local_worker', gateway.fixtures)

    def test_host_start_does_not_hold_global_resource_lock_and_failure_is_shared(self):
        import threading
        from concurrent.futures import ThreadPoolExecutor
        with tempfile.TemporaryDirectory() as tmp:
            fixture = RunFixtures(Mock(), Path(tmp), 2)
            self.addCleanup(fixture.cert_directory.cleanup)
            module = MODULES['execution.agent.content']
            jobs = [Invocation(module, Case(module.build, 'test', '/test', str(i))) for i in range(2)]
            fixture.prepare(jobs)
            entered = threading.Event()
            release = threading.Event()
            def start(*args):
                entered.set()
                if not release.wait(3):
                    raise TimeoutError('test stalled')
                raise RuntimeError('original host failure')
            def run(job):
                with fixture.workers(job, 'db', 'config'):
                    self.fail('failed host was published')
            with patch('t2_fixtures.compatibility', return_value='same'), patch('t2_fixtures.Host', side_effect=start) as host:
                with ThreadPoolExecutor(max_workers=2) as executor:
                    first = executor.submit(run, jobs[0])
                    self.assertTrue(entered.wait(3))
                    self.assertTrue(fixture.lock.acquire(timeout=1))
                    fixture.lock.release()
                    second = executor.submit(run, jobs[1])
                    release.set()
                    for result in (first, second):
                        with self.assertRaises(RuntimeError):
                            result.result(timeout=3)
                self.assertEqual(host.call_count, 1)


class HostOwnershipTests(unittest.TestCase):
    def test_different_tenants_and_configs_never_overlap_full_hosts(self):
        import threading
        from concurrent.futures import ThreadPoolExecutor
        from types import SimpleNamespace
        from t2_execution import Processes
        with tempfile.TemporaryDirectory() as tmp:
            processes = Processes()
            fixture = RunFixtures(SimpleNamespace(processes=processes), Path(tmp), 2)
            self.addCleanup(fixture.cert_directory.cleanup)
            module = MODULES['execution.agent.content']
            jobs = [Invocation(module, Case(module.build, 'test', '/test', str(i))) for i in range(2)]
            fixture.prepare(jobs)
            fixture.case_contexts[jobs[1].key]['tenant'] = 'other-tenant'
            held, release, second = threading.Event(), threading.Event(), threading.Event()
            live = []
            class Worker:
                def __init__(self, builds, config, output):
                    if live:
                        raise AssertionError('overlapping physical database owner')
                    live.append(self)
                    self.failed = threading.Event()
                    self.address, self.log_path = config, output / 'host.log'
                def check(self):
                    pass
                def close(self):
                    live.remove(self)
            def run(index):
                with fixture.workers(jobs[index], 'db', str(index)):
                    if index == 0:
                        held.set()
                        if not release.wait(3):
                            raise TimeoutError('first borrow not released')
                    else:
                        second.set()
            with patch('t2_fixtures.compatibility', side_effect=lambda value: value), patch('t2_fixtures.Host', Worker):
                with ThreadPoolExecutor(max_workers=2) as executor:
                    first = executor.submit(run, 0)
                    self.assertTrue(held.wait(3))
                    next_case = executor.submit(run, 1)
                    self.assertFalse(second.wait(.1))
                    release.set()
                    first.result(timeout=3)
                    next_case.result(timeout=3)
                self.assertTrue(second.is_set())
                for host in fixture.hosts.values():
                    host.close()


    def test_dead_retained_host_blocks_different_configuration_without_restart(self):
        import threading
        from t2_execution import Processes
        with tempfile.TemporaryDirectory() as tmp:
            fixture = RunFixtures(SimpleNamespace(processes=Processes()), Path(tmp), 2)
            self.addCleanup(fixture.cert_directory.cleanup)
            module = replace(MODULES['execution.agent.content'], scope='objects')
            jobs = [Invocation(module, Case(module.build, 'test', '/test', str(i))) for i in range(3)]
            fixture.prepare(jobs)
            host = Mock(failed=threading.Event(), log_path=Path(tmp) / 'host.log')
            def check():
                if host.failed.is_set():
                    raise RuntimeError('unexpected exit')
            host.check.side_effect = check
            with patch('t2_fixtures.compatibility', side_effect=lambda value: value), patch('t2_fixtures.Host', return_value=host) as start:
                with fixture.workers(jobs[0], 'db', 'first'):
                    pass
                host.close.assert_not_called()
                host.failed.set()
                with self.assertRaisesRegex(RuntimeError, 'unexpected exit'):
                    with fixture.workers(jobs[1], 'db', 'changed'):
                        self.fail('dead host was replaced')
                with self.assertRaisesRegex(RuntimeError, 'previously failed') as blocked:
                    with fixture.workers(jobs[2], 'db', 'third'):
                        self.fail('failed generation was reused')
                start.assert_called_once()
                host.close.assert_called_once()
                self.assertEqual(blocked.exception.root_cause, str(Path(tmp) / 'failure.json'))
