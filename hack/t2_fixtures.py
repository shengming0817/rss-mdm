"""Run-owned services and immutable migration baselines; scenarios own writable state.

ref: PostgreSQL src/backend/commands/dbcommands.c@7885b94dd81b98bbab9ed878680d156df7bf857f
"""
from __future__ import annotations
from contextlib import contextmanager, ExitStack
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
from types import SimpleNamespace

from candidate_fixture import INSTANCE, ADMIN
from t2_context import contexts, installation, validate
from t2_database import Costs, DatabasePool, measure
from t2_hosts import Host
from t2_environment import Environment, private, run
from t2_registry import ROOT, IDENTITY_SETUP
from t2_processes import diagnostic_phase, owned_by
from verification_result import require


class RunFixtures:
    def __init__(self, builds, output, jobs):
        self.builds = builds
        self.output = output
        self.costs = Costs()
        self.normal = DatabasePool(builds, 't2', self.costs, 128 * (jobs + 1))
        self.fault = DatabasePool(builds, 't2-fault', self.costs, 128)
        self.gateway_owner = Environment(group='t2-gateway')
        self.cert_directory = tempfile.TemporaryDirectory(prefix='mdm-t2-run-')
        self.root = Path(self.cert_directory.name)
        self.native_key = private(self.root / 'native-data.key', '')
        self.native_key.write_bytes(os.urandom(32))
        self.certificates = Environment(group='t2-certificates')
        self.certificates.root = self.root / 'certificates'
        self.lock = threading.RLock()
        self.case_contexts = {}
        self.shared = {}
        self.hosts = {}

    def __enter__(self):
        self.process_ownership = owned_by(self.builds.processes)
        self.process_ownership.__enter__()
        try:
            # The worktree lease makes these known projects exclusively ours.
            # Recover all registered owners even when this run selects no PG/gateway.
            self.cleanup_environments('prepare-recovery')
        except BaseException:
            self.cert_directory.cleanup()
            self.process_ownership.__exit__(*sys.exc_info())
            raise
        return self

    def cleanup_environments(self, phase='run-cleanup'):
        errors = []
        for host in self.hosts.values():
            try:
                with measure(self.costs, phase, host=host.address, hostLog=str(host.log_path)):
                    host.close()
            except Exception as error:
                errors.append(error)
        self.hosts.clear()
        for environment in (self.normal.owner, self.fault.owner, self.gateway_owner):
            try:
                with measure(self.costs, phase, pg=environment.project):
                    environment.reset()
            except Exception as error:
                errors.append(error)
        if errors:
            raise RuntimeError('failed to clean owned T2 environments') from errors[0]

    def __exit__(self, *unused):
        try:
            with diagnostic_phase('cleanup'), self.builds.processes.cleanup():
                self.cleanup_environments()
        finally:
            try:
                self.cert_directory.cleanup()
            finally:
                self.process_ownership.__exit__(*unused)

    def prepare(self, jobs):
        self.case_contexts = contexts(self.output.name, jobs)
        normal = [self.case_contexts[job.key] for job in jobs
                  if job.module.postgres and job.module.db_mode != 'instance']
        fault = [self.case_contexts[job.key] for job in jobs if job.module.db_mode == 'instance']
        if normal:
            self.normal.installation = installation(normal)
        if fault:
            self.fault.installation = installation(fault)
        for job in jobs:
            root = self.root / job.key
            root.mkdir()
            private(root / 'case.json', self.case_contexts[job.key])
        if any(set(job.module.fixtures) & {'tls', 'windows', 'apple', 'apns'} for job in jobs):
            self.certificates.prepare_inputs()
        # A compatible profile owns one writable database for the complete run.
        for profile in sorted({job.module.profile for job in jobs if job.module.db_mode == 'reuse'}):
            selected = [job for job in jobs if job.module.profile == profile and job.module.db_mode == 'reuse']
            with self.normal.database(profile, 'reuse') as database:
                self.shared[profile] = database
                identity_jobs = [job for job in selected if 'identity' in job.module.fixtures]
                if identity_jobs:
                    self.prepare_identity(self.normal, database, identity_jobs, self.output / 'identity' / profile)

    def runtime_config(self, pool, root, database, tenant):
        config = json.loads((ROOT / 'fixtures/mdm-config.example.json').read_text())
        db = pool.database_config
        for key, role in [('access_database', 'mdm_access'), ('runtime_database', 'mdm_runtime')]:
            config[key] = db(root, database, role, 'access-fixture' if role == 'mdm_access' else 'runtime-fixture')
        for owner, key, role, password in [
            ('identity', 'database', 'mdm_identity_runtime', 'identity-runtime-fixture'),
            ('identity', 'audit_worker', 'mdm_identity_audit', 'identity-audit-fixture'),
            ('execution', 'database', 'mdm_command_runtime', 'runtime-fixture')]:
            config[owner][key] = db(root, database, role, password)
        config['flow']['storage']['database'] = db(root, database, 'mdm_flow_runtime', 'runtime-fixture')
        config['flow']['publication']['database'] = db(root, database, 'mdm_software_driver', 'runtime-fixture')
        config['identity']['tenant_id'] = tenant
        config['native_protocols'] = {}
        config['native_protection_key_file'] = str(self.native_key)
        config['identity_management'] = [dict(tenant_id=tenant, instance_id=INSTANCE, principal_id=ADMIN,
                                               permissions=['accounts', 'providers'])]
        return config

    def prepare_identity(self, pool, database, jobs, output):
        root = self.root / database
        root.mkdir(exist_ok=True)
        private(root / 'ca.crt', (pool.owner.root / 'ca.crt').read_text())
        tenants = sorted({tenant for j in jobs for tenant in self.case_contexts[j.key]['identityTenants']})
        config = self.runtime_config(pool, root, database, tenants[0])
        env = dict(os.environ, RUST_MIN_STACK=str(8 * 1024 * 1024),
                   MDM_TEST_CONFIG=str(private(root / 'runtime.json', config)))
        maintenance = pool.database_config(root, database, 'mdm_identity_maintenance', 'identity-maintenance-fixture')
        password = private(root / 'account-password', 'Fixture-only-correct-horse-battery-2026!')
        for tenant in tenants:
            path = private(root / 'initialize.json', dict(database=maintenance, installation=pool.installation,
                           tenant_id=tenant, principal_id=ADMIN, login='bootstrap', password_file=str(password)))
            with measure(self.costs, 'identity-initialize', database=database, tenant=tenant):
                run([self.builds.executables['rss-mdm'], 'initialize', '--config', path],
                    cwd=ROOT, env=env, capture_output=True, timeout=30)
            self.costs.increment('identityInitializations', 1)
        manifest = dict(stage='accounts', tenants=tenants, cases=[str(self.root / j.key / 'case.json') for j in jobs])
        env['MDM_IDENTITY_SETUP'] = str(private(root / 'identity-setup.json', manifest))
        cases = self.builds.discover(IDENTITY_SETUP)
        require(len(cases) == 1, 'identity setup target is ambiguous')
        with measure(self.costs, 'identity-setup', database=database):
            self.builds.execute(cases[0], env, output)
        for event in json.loads((root / 'identity-costs.json').read_text()):
            self.costs.append(dict(event, database=database))
            self.costs.increment(event['phase'], event['count'])
        self.costs.increment('identitySetups', 1)
        # The helper creates real case accounts and writes their public coordinates.
        for job in jobs:
            case_root = self.root / job.key
            context = validate(json.loads((case_root / 'case.json').read_text()), ready=True)
            self.case_contexts[job.key] = context
            value = self.runtime_config(pool, case_root, database, context['tenant'])
            value['identity_management'][0]['principal_id'] = context['admins'][context['tenant']]
            value['content'] = json.loads((root / 'content.json').read_text())
            value['task_signing'] = json.loads((root / 'task-signing.json').read_text())
            private(case_root / 'runtime.json', value)
            private(case_root / 'account-password', password.read_text())
            pool.database_config(case_root, database, 'mdm_identity_maintenance', 'identity-maintenance-fixture')

    def prepare_sessions(self, job, env, database, output):
        # Credentials age from case admission, not from the start of a long run.
        root = self.root / job.key
        manifest = dict(stage='sessions', tenants=[], cases=[str(root / 'case.json')])
        session_env = dict(env, MDM_IDENTITY_SETUP=str(private(root / 'identity-sessions.json', manifest)))
        cases = self.builds.discover(IDENTITY_SETUP)
        require(len(cases) == 1, 'identity setup target is ambiguous')
        with measure(self.costs, 'identity-session-setup', database=database, invocationId=job.key):
            self.builds.execute(cases[0], session_env, output)
        for event in json.loads((root / 'identity-costs.json').read_text()):
            self.costs.append(dict(event, database=database))
            self.costs.increment(event['phase'], event['count'])

    @contextmanager
    def workers(self, job, database, config):
        key = (database, self.case_contexts[job.key]['tenant'])
        with self.lock:
            if key not in self.hosts:
                with measure(self.costs, 'host-start', database=database, tenant=key[1]):
                    self.hosts[key] = Host(self.builds, config, self.output / 'hosts' / database / key[1])
                self.costs.increment('hostStarts', 1)
            host = self.hosts[key]
        host.check()
        try:
            yield host
            host.check()
        finally:
            # The shared object tenant lives for the run. A private consumer tenant
            # has no remaining clients after this case; retire it within JOBS.
            if job.module.db_mode != 'reuse' or job.module.scope != 'objects':
                with self.lock:
                    with measure(self.costs, 'host-stop', database=database, tenant=key[1], host=host.address):
                        self.hosts.pop(key).close()

    def source_tls(self, root):
        with self.lock:
            self.certificates.prepare_inputs()
            directory = self.certificates.root / 'source-cert'
            self.certificates.issue_leaf(directory, ['source.invalid', 'raw.githubusercontent.com'])
            for source, target in ((self.certificates.root / 'ca.crt', 'ca.pem'),
                                   (directory / 'server.crt', 'server.pem'),
                                   (directory / 'server.key', 'server.key')):
                private(root / target, source.read_text())

    @contextmanager
    def gateway(self, config):
        environment = self.gateway_owner
        try:
            environment.prepare_inputs(certificates=False)
            private(environment.root / 'probe/nginx.conf', config)
            environment.verify_ownership()
            environment.compose('--profile', 'probe', 'up', '-d', 'gateway-probe')
            name = environment.compose('ps', '-q', 'gateway-probe')
            port = int(environment.compose('port', 'gateway-probe', '8080').rsplit(':', 1)[1])
            yield name, port
        finally:
            environment.reset()

    def evidence(self, job):
        context = self.case_contexts[job.key]
        pool = self.fault if job.module.db_mode == 'instance' else self.normal
        return dict(database=None, tenant=context['tenant'], peer=context['peer'],
                    pg=pool.owner.project if job.module.postgres else None,
                    pgGeneration=None, host=None, hostLog=None)

    @contextmanager
    def scenario(self, job, output, receipt):
        module = job.module
        pool = self.fault if module.db_mode == 'instance' else self.normal
        owner = pool.owner
        stack = ExitStack()
        try:
            root = self.root / job.key
            env = dict(os.environ, RUST_MIN_STACK=str(8 * 1024 * 1024),
                       MDM_CASE_CONTEXT=str(root / 'case.json'))
            env.pop('MDM_CASE_RENDEZVOUS', None)
            database = None
            if module.postgres:
                database = stack.enter_context(pool.database(module.profile, module.db_mode))
                receipt['environment'].update(database=database, pgGeneration=pool.generation)
            if module.postgres or set(module.fixtures) & {'tls', 'windows', 'apple', 'apns'}:
                certificates = owner if module.postgres else self.certificates
                with self.lock:
                    certificates.prepare_inputs()
                for name in ('ca.crt', 'server.crt', 'server.key'):
                    private(root / name, (certificates.root / name).read_text())
            if 'windows' in module.fixtures:
                from windows_fixtures import generate
                generate(root, root / 'server.crt', root / 'server.key')
                env['MDM_WINDOWS_FIXTURES'] = str(root)
            if 'apple' in module.fixtures:
                from apple_fixtures import generate
                generate(root, root / 'server.crt', root / 'server.key')
                env['MDM_APPLE_FIXTURES'] = str(root)
            if 'tls' in module.fixtures:
                from source_fixtures import tls_environment
                source_root = root / 'source'
                source_root.mkdir()
                env.update(tls_environment(source_root, self))
            migration_config = None
            if database:
                port = owner.port()
                env.update(PG_CA_FILE=str(root / 'ca.crt'),
                           DATABASE_URL=f'postgres://mdm_runtime:runtime-fixture@localhost:{port}/{database}',
                           MDM_COLLECTION_URL=f'postgres://mdm_access:access-fixture@localhost:{port}/{database}',
                           MDM_OWNER_URL=f'postgres://mdm_owner:owner-fixture@localhost:{port}/{database}',
                           MDM_ADMIN_URL=f'postgres://postgres:local-fixture@localhost:{port}/{database}',
                           MDM_TEST_PG_CONTAINER=owner.container())
                config = private(root / 'database.json', dict(port=port, ca=str(root / 'ca.crt'),
                                 container=owner.container(), database=database))
                env.update(BACKEND_PG_CONFIG=str(config), GROUP_PG_CONFIG=str(config))
                migration_config = pool.installation_config(root, database)
                if 'identity' in module.fixtures:
                    if module.db_mode != 'reuse':
                        self.prepare_identity(pool, database, [job], output / 'identity-setup')
                    value = json.loads((root / 'runtime.json').read_text())
                    if (root / 'windows.json').exists():
                        value['native_protocols']['windows'] = json.loads((root / 'windows.json').read_text())
                    env['MDM_TEST_CONFIG'] = str(private(root / 'runtime.json', value))
            host = None
            if 'shared_worker' in module.fixtures:
                receipt['environment']['hostLog'] = str((self.output / 'hosts' / database /
                    self.case_contexts[job.key]['tenant'] / 'host.log').relative_to(self.output))
                host = stack.enter_context(self.workers(job, database, env['MDM_TEST_CONFIG']))
                receipt['environment']['host'] = host.address
            if 'examples' in module.fixtures:
                env['MDM_FIXTURE_BIN'] = self.builds.executables['rss-mdm-fixture']
            if 'agent_pki' in module.fixtures:
                env['MDM_AGENT_PKI_FIXTURE'] = '1'
            if 'scep' in module.fixtures:
                from apple_ca import running
                stack.enter_context(running(root, env))
                if 'agent_pki' in module.fixtures:
                    value = json.loads(Path(env['MDM_TEST_CONFIG']).read_text())
                    value['agent_pki'] = json.loads((root / 'agent-pki.json').read_text())
                    private(Path(env['MDM_TEST_CONFIG']), value)
            if 'oracle' in module.fixtures:
                from apple_oracle import running as oracle
                stack.enter_context(oracle(root, env))
            if 'idp' in module.fixtures:
                from enterprise_idp import fixture
                env.update(stack.enter_context(fixture(root, owner)))
            if 'identity' in module.fixtures:
                self.prepare_sessions(job, env, database, output / 'identity-sessions')
            with self.lock:
                for dependency in module.fixtures:
                    self.costs.increment('fixture:' + dependency, 1)
            receipt['prepared'] = time.monotonic()
            yield SimpleNamespace(root=root, env=env, database=database,
                                  migration_config=migration_config, owner=owner,
                                  binary=self.builds.executables.get('rss-mdm'), context=self)
        finally:
            receipt['cleanupStarted'] = time.monotonic()
            try:
                with diagnostic_phase('cleanup'), self.builds.processes.cleanup():
                    try:
                        stack.close()
                    finally:
                        if module.python == 'gateway' and self.gateway_owner.root.exists():
                            self.gateway_owner.reset()
            finally:
                receipt['cleaned'] = time.monotonic()
