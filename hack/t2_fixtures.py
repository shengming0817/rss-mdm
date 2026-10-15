"""Run-owned services and immutable migration baselines; scenarios own writable state.

ref: PostgreSQL src/backend/commands/dbcommands.c@7885b94dd81b98bbab9ed878680d156df7bf857f
"""
from __future__ import annotations
from contextlib import contextmanager, ExitStack
import json
import hashlib
import shutil
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
from types import SimpleNamespace

from candidate_fixture import INSTANCE, ADMIN
from t2_context import contexts, installation, registration_tenants, validate
from t2_database import Costs, DatabasePool, measure
from t2_hosts import Host
from t2_environment import Environment, private, run
from t2_registry import IDENTITY_SETUP
from s3_fixtures import S3Environment
from t2_model import ROOT
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
        self.identities = {}
        self.identity_locks = {}
        self.hosts = {}
        self.authorities = {}
        self.authority_locks = {}
        self.authority_stack = ExitStack()
        self.materials = {}
        self.material_locks = {}
        self.s3 = S3Environment()

    def __enter__(self):
        self.process_ownership = owned_by(self.builds.processes)
        self.process_ownership.__enter__()
        try:
            # The worktree lease makes these known projects exclusively ours.
            # Recover all registered owners, independently of this run's selected fixtures.
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
        try:
            self.authority_stack.close()
        except BaseException as error:
            errors.append(error)
        self.authorities.clear()
        for pool in (self.normal, self.fault):
            if pool.ready:
                pool.sample_connections(list(pool.shared.values()))
        for environment in (self.normal.owner, self.fault.owner, self.gateway_owner):
            try:
                with measure(self.costs, phase, pg=environment.project):
                    environment.reset()
            except Exception as error:
                errors.append(error)
        try:
            self.s3.reset()
        except Exception as error:
            errors.append(error)
        try:
            from apple_ca import recover
            recover()
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
            self.normal.installation = installation()
            self.costs.increment('plannedNormalTenants', len(registration_tenants(normal)))
        if fault:
            self.fault.installation = installation()
            self.costs.increment('plannedFaultTenants', len(registration_tenants(fault)))
        for job in jobs:
            root = self.root / job.key
            root.mkdir()
            private(root / 'case.json', self.case_contexts[job.key])
        self.costs.increment('plannedActors', sum(len(value['actors']) for value in self.case_contexts.values()))

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
        config['device_pki'] = []
        config['native_protection_key_file'] = str(self.native_key)
        return config

    def identity_helper(self, root, manifest, output, database):
        env = dict(os.environ, RUST_MIN_STACK=str(8 * 1024 * 1024),
                   MDM_TEST_CONFIG=str(root / 'runtime.json'),
                   MDM_IDENTITY_SETUP=str(private(root / 'identity-setup.json', manifest)))
        cases = self.builds.discover(IDENTITY_SETUP)
        require(len(cases) == 1, 'identity setup target is ambiguous')
        with measure(self.costs, 'identity-' + manifest['stage'], database=database):
            self.builds.execute(cases[0], env, output)
        self.costs.increment('identityHelpers', 1)
        for event in json.loads((root / 'identity-costs.json').read_text()):
            self.costs.append(dict(event, database=database))
            self.costs.increment(event['phase'], event['count'])

    def identity_environment(self, pool, database, output):
        key = (pool.owner.project, pool.generation, database)
        with self.lock:
            lock = self.identity_locks.setdefault(key, threading.Lock())
        started = time.monotonic()
        with lock:
            self.costs.append(dict(phase='identity-lock-wait', seconds=time.monotonic()-started, database=database))
            self.builds.processes.check()
            state = self.identities.get(key)
            if isinstance(state, BaseException):
                raise RuntimeError('identity environment preparation previously failed') from state
            root = self.root / database
            try:
                if state is None:
                    root.mkdir()
                    private(root / 'ca.crt', (pool.owner.root / 'ca.crt').read_text())
                    management = pool.owner.sql('SELECT management_tenant_id::text FROM public.mdm_installation', database)
                    config = self.runtime_config(pool, root, database, management)
                    private(root / 'runtime.json', config)
                    password = private(root / 'account-password', 'Fixture-only-correct-horse-battery-2026!')
                    maintenance = pool.database_config(root, database, 'mdm_identity_maintenance', 'identity-maintenance-fixture')
                    path = private(root / 'initialize.json', dict(database=maintenance, installation=pool.installation,
                        tenant_id=management, expected_epoch=1, principal_id=ADMIN, login='bootstrap', password_file=str(password)))
                    with measure(self.costs, 'identity-initialize', database=database):
                        run([self.builds.executables['rss-mdm'], 'initialize', '--config', path],
                            cwd=ROOT, capture_output=True, timeout=30)
                    self.costs.increment('identityInitializations', 1)
                    self.identity_helper(root, dict(stage='environment'), output / 'environment', database)
                    state = dict(management=management, refreshed=time.monotonic())
                elif time.monotonic() - state['refreshed'] >= 180:
                    self.identity_helper(root, dict(stage='refresh'), output / 'refresh', database)
                    state['refreshed'] = time.monotonic()
                self.identities[key] = state
                # The caller owns a credential snapshot; a later refresh cannot overwrite it.
                return root, state['management'], (root / 'source-session').read_text()
            except BaseException as error:
                self.identities[key] = error
                raise

    def prepare_identity(self, pool, database, job, output):
        shared, management, source = self.identity_environment(pool, database, output)
        root = self.root / job.key
        context = self.case_contexts[job.key]
        config = self.runtime_config(pool, root, database, context['tenant'])
        config['content'] = json.loads((shared / 'content.json').read_text())
        config['task_signing'] = json.loads((shared / 'task-signing.json').read_text())
        private(root / 'runtime.json', config)
        private(root / 'account-password', (shared / 'account-password').read_text())
        pool.database_config(root, database, 'mdm_identity_maintenance', 'identity-maintenance-fixture')
        manifest = dict(stage='accounts', cases=[str(root / 'case.json')], management=management,
                        source_secret=str(private(root / 'source-session', source)),
                        provisioning_database=pool.database_config(root, database, 'mdm_identity_provisioning', 'identity-provisioning-fixture'))
        self.identity_helper(root, manifest, output / 'accounts', database)
        self.case_contexts[job.key] = validate(json.loads((root / 'case.json').read_text()), ready=True)

    def prepare_sessions(self, job, env, database, output):
        root = self.root / job.key
        self.identity_helper(root, dict(stage='sessions', cases=[str(root / 'case.json')]), output, database)

    def prepare_materials(self, kind, root, materials=()):
        inputs = {name: (root / name).read_bytes() for name in ('ca.crt', 'server.crt', 'server.key')}
        digest = hashlib.sha256(b''.join(inputs.values()) + json.dumps([kind, materials]).encode()).hexdigest()
        with self.lock:
            lock = self.material_locks.setdefault(digest, threading.Lock())
        with lock:
            self.builds.processes.check()
            source = self.materials.get(digest)
            if isinstance(source, BaseException):
                raise RuntimeError('cryptographic material preparation previously failed') from source
            if source is None:
                source = self.root / ('materials-' + digest)
                try:
                    source.mkdir(mode=0o700)
                    for name, value in inputs.items():
                        path = source / name
                        path.write_bytes(value)
                        path.chmod(0o600)
                    with measure(self.costs, 'cryptographic-materials', kind=kind, materials=list(materials)):
                        if kind == 'windows':
                            from windows_fixtures import generate
                            generate(source, source / 'server.crt', source / 'server.key', materials=materials)
                        elif kind == 'apple':
                            from apple_fixtures import generate
                            generate(source, source / 'server.crt', source / 'server.key')
                        else:
                            raise ValueError('unknown cryptographic fixture')
                    self.materials[digest] = source
                    self.costs.increment('cryptographicMaterialSets', 1)
                except BaseException as error:
                    self.materials[digest] = error
                    raise
        def relocate(value):
            if isinstance(value, str) and value.startswith(str(source) + '/'):
                return str(root) + value[len(str(source)):]
            if isinstance(value, dict):
                return {key: relocate(item) for key, item in value.items()}
            if isinstance(value, list):
                return [relocate(item) for item in value]
            return value
        for path in source.iterdir():
            require(path.is_file() and not path.is_symlink(), 'invalid cached cryptographic material')
            if path.suffix == '.json':
                private(root / path.name, relocate(json.loads(path.read_text())))
            else:
                # Independent bytes, never links: permission/corruption probes own their files.
                shutil.copy2(path, root / path.name)

    def authority(self, stack, job, root, env, pool, database, purpose):
        from pki_fixtures import running
        options = dict(case=job.key, agent=purpose == 'agent', windows=purpose == 'windows',
                       configuration_devices=job.module.configuration_devices, materials=job.module.materials)
        if job.module.db_mode != 'reuse' or job.module.scope != 'objects':
            stack.enter_context(running(root, env, **options))
            self.costs.increment('caStarts', 1)
            return
        require(purpose == 'agent' and not job.module.materials and job.module.configuration_devices == 0,
                'shared CA requires stable agent material')
        key = (pool.owner.project, pool.generation, database, self.case_contexts[job.key]['tenant'], purpose)
        with self.lock:
            lock = self.authority_locks.setdefault(key, threading.Lock())
        with lock:
            self.builds.processes.check()
            state = self.authorities.get(key)
            if isinstance(state, BaseException):
                raise RuntimeError('CA environment preparation previously failed') from state
            if state is None:
                owned = ExitStack()
                shared_env = dict(env)
                try:
                    provider = owned.enter_context(running(root, shared_env, **options))
                    config = json.loads((root / (purpose + '-pki.json' if purpose == 'agent' else 'windows.json')).read_text())
                    entries = [entry for entry in json.loads((root / 'device-pki.json').read_text()) if entry['purpose'] == purpose]
                    runtime = json.loads((root / 'runtime.json').read_text())
                    runtime['agent_pki'] = config
                    runtime['device_pki'] = entries
                    private(root / 'runtime.json', runtime)
                    self.identity_helper(root, {'stage': 'agent_trust'},
                                         self.output / 'ca-admission' / job.key, database)
                    state = dict(provider=provider, config=config, entries=entries,
                                 env={name: value for name, value in shared_env.items() if env.get(name) != value})
                    with self.lock:
                        self.authority_stack.enter_context(owned.pop_all())
                    self.authorities[key] = state
                    self.costs.increment('caStarts', 1)
                except BaseException as error:
                    owned.close()
                    self.authorities[key] = error
                    raise
            state['provider'].check()
            env.update(state['env'])
            private(root / (purpose + '-pki.json' if purpose == 'agent' else 'windows.json'), state['config'])
            path = root / 'device-pki.json'
            entries = json.loads(path.read_text()) if path.exists() else []
            private(path, [entry for entry in entries if entry['purpose'] != purpose] + state['entries'])

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
                pool.seed_tenants(database, module.profile, registration_tenants([self.case_contexts[job.key]]))
            if module.postgres or set(module.fixtures) & {'tls', 'windows', 'apple', 'apns','agent_pki'}:
                certificates = owner if module.postgres else self.certificates
                if not module.postgres:
                    with self.lock:
                        certificates.prepare_inputs()
                for name in ('ca.crt', 'server.crt', 'server.key'):
                    private(root / name, (certificates.root / name).read_text())
            if 'windows' in module.fixtures:
                self.prepare_materials('windows', root, tuple(item for item in module.materials if item.startswith('windows-')))
                env['MDM_WINDOWS_FIXTURES'] = str(root)
            if 'apple' in module.fixtures:
                self.prepare_materials('apple', root)
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
                           MDM_TEST_PG_CONTAINER=owner.container(),
                           MDM_CONTENT_DIRECTORY=str(self.root / database / 'content'),
                           MDM_NATIVE_PROTECTION_KEY_FILE=str(self.native_key))
                config = private(root / 'database.json', dict(port=port, ca=str(root / 'ca.crt'),
                                 container=owner.container(), database=database))
                env.update(BACKEND_PG_CONFIG=str(config), GROUP_PG_CONFIG=str(config))
                migration_config = pool.installation_config(root, database)
                if 'identity' in module.fixtures:
                    self.prepare_identity(pool, database, job, output / 'identity-setup')
                    value = json.loads((root / 'runtime.json').read_text())
                    if (root / 'windows.json').exists():
                        value['native_protocols']['windows'] = json.loads((root / 'windows.json').read_text())
                    env['MDM_TEST_CONFIG'] = str(private(root / 'runtime.json', value))
            host = None
            if 'examples' in module.fixtures:
                env['MDM_FIXTURE_BIN'] = self.builds.executables['rss-mdm-fixture']
            if 'windows' in module.fixtures:
                from pki_fixtures import running as pki
                self.authority(stack, job, root, env, pool, database, 'windows')
            if 'agent_pki' in module.fixtures:
                from pki_fixtures import running as pki
                self.authority(stack, job, root, env, pool, database, 'agent')
            if 'pki_rotation' in module.fixtures:
                stack.enter_context(pki(root,env,case=job.key,agent=True,generation='next'))
            if 'scep' in module.fixtures:
                from apple_ca import running
                stack.enter_context(running(root, env, case=job.key))
            if 'MDM_TEST_CONFIG' in env:
                value=json.loads(Path(env['MDM_TEST_CONFIG']).read_text())
                if (root/'device-pki.json').exists():value['device_pki']=json.loads((root/'device-pki.json').read_text())
                if (root/'agent-pki.json').exists():value['agent_pki']=json.loads((root/'agent-pki.json').read_text())
                for channel in ('windows','apple'):
                    if (root/(channel+'.json')).exists():value['native_protocols'][channel]=json.loads((root/(channel+'.json')).read_text())
                private(Path(env['MDM_TEST_CONFIG']),value)
            if 'shared_worker' in module.fixtures:
                receipt['environment']['hostLog'] = str((self.output / 'hosts' / database /
                    self.case_contexts[job.key]['tenant'] / 'host.log').relative_to(self.output))
                host = stack.enter_context(self.workers(job, database, env['MDM_TEST_CONFIG']))
                receipt['environment']['host'] = host.address
            if 'oracle' in module.fixtures:
                from apple_oracle import running as oracle
                stack.enter_context(oracle(root, env))
            if 's3' in module.fixtures:
                with self.lock:
                    env.update(self.s3.environment())
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
