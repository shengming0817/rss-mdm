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
from t2_hosts import Host, compatibility
from t2_environment import Environment, private, run
from t2_registry import IDENTITY_SETUP
from s3_fixtures import S3Environment
from t2_model import ROOT
from t2_processes import diagnostic_phase, owned_by, subprocess
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
        self.actor_batches = {}
        self.actors = {}
        self.hosts = {}
        self.host_locks = {}
        self.recovery_material = None
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
            if isinstance(host, BaseException):
                continue
            try:
                with measure(self.costs, phase, host=host.address, hostLog=str(host.log_path)):
                    host.close()
            except Exception as error:
                errors.append(error)
        self.hosts.clear()
        for pool in (self.normal, self.fault):
            if pool.ready:
                pool.sample_connections(list(pool.shared.values()))
        for environment in (self.normal.owner, self.fault.owner, self.gateway_owner):
            try:
                with measure(self.costs, phase, pg=environment.project):
                    environment.reset()
            except Exception as error:
                errors.append(error)
            finally:
                self.costs.append(dict(phase='postgres-endpoint-queries', pg=environment.project,
                                       queries=dict(environment.postgres_queries)))
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

    @staticmethod
    def runtime_config(pool, root, database, tenant, *, native_key, recovery_credentials):
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
        config['webhooks']['recovery_database'] = db(root, database, 'mdm_webhook_operator', 'runtime-fixture')
        config['identity']['tenant_id'] = tenant
        config['native_protocols'] = {}
        config['device_pki'] = []
        config['native_protection'] = dict(active_file=str(native_key),historical_files=[],fingerprint_file=str(native_key))
        config['recovery_credentials'] = recovery_credentials
        return config

    def recovery_config(self):
        # Independent ephemeral crypto material; never reuse identity/APNs/native keys.
        with self.lock:
            if self.recovery_material is None:
                key = private(self.root / 'recovery-material.key', '')
                key.write_bytes(os.urandom(32))
                recipient_key = private(self.root / 'recovery-recipient.key', '')
                certificate = self.root / 'recovery-recipient.crt'
                der = self.root / 'recovery-recipient.der'
                run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                     '-subj', '/CN=MDM recovery fixture', '-days', '2',
                     '-keyout', recipient_key, '-out', certificate], capture_output=True)
                run(['openssl', 'x509', '-in', certificate, '-outform', 'DER', '-out', der], capture_output=True)
                self.recovery_material = dict(active_key='fixture', key_files={'fixture': str(key)},
                    active_recipient=hashlib.sha256(der.read_bytes()).hexdigest(),
                    recipients=[dict(certificate_file=str(certificate), private_key_file=str(recipient_key))])
            return self.recovery_material

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
                    root.mkdir(exist_ok=True)
                    private(root / 'ca.crt', (pool.owner.root / 'ca.crt').read_text())
                    management = pool.owner.sql('SELECT management_tenant_id::text FROM public.mdm_installation', database)
                    config = self.runtime_config(pool, root, database, management,
                        native_key=self.native_key, recovery_credentials=self.recovery_config())
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

    def configure_identity(self, pool, database, job, output):
        shared, management, source = self.identity_environment(pool, database, output)
        root = self.root / job.key
        context = self.case_contexts[job.key]
        config = self.runtime_config(pool, root, database, context['tenant'],
            native_key=self.native_key, recovery_credentials=self.recovery_config())
        config['content'] = json.loads((shared / 'content.json').read_text())
        config['task_signing'] = {'revision':1}
        private(root / 'task-signing-fixture.json', json.loads((shared / 'task-signing.json').read_text()))
        private(root / 'runtime.json', config)
        private(root / 'account-password', (shared / 'account-password').read_text())
        pool.database_config(root, database, 'mdm_identity_maintenance', 'identity-maintenance-fixture')
    def prepare_identity(self, pool, database, job, output):
        shared, management, source = self.identity_environment(pool, database, output)
        key = (pool.owner.project, pool.generation, database)
        item = dict(job=job, done=threading.Event(), error=None)
        with self.lock:
            state = self.actor_batches.setdefault(key, dict(pending=[], busy=False, error=None))
            if state['error'] is not None:
                raise RuntimeError('actor preparation previously failed') from state['error']
            state['pending'].append(item)
        while not item['done'].is_set():
            self.builds.processes.check()
            with self.lock:
                lead = not state['busy'] and bool(state['pending'])
                if lead:
                    state['busy'] = True
            if not lead:
                item['done'].wait(.05)
                continue
            # A bounded coalescing window only for already-admitted peers, never a run barrier.
            item['done'].wait(.01)
            with self.lock:
                batch, state['pending'] = state['pending'], []
            try:
                paths = []
                for member in batch:
                    context = self.case_contexts[member['job'].key]
                    root = self.root / member['job'].key
                    for actor in context['actors']:
                        cached = self.actors.get((*key, actor['tenant'], actor['login']))
                        if cached is not None:
                            actor['principal'] = cached['principal']
                            if cached['until'] - time.time() > 120:
                                private(root / f"credential-{actor['tenant']}-{actor['role']}", cached['secret'])
                                private(root / f"credential-meta-{actor['tenant']}-{actor['role']}", cached['until'])
                                self.costs.increment('sessionReuses', 1)
                            self.costs.increment('actorReuses', 1)
                    paths.append(str(private(root / 'case.json', context)))
                root = self.root / batch[0]['job'].key
                manifest = dict(stage='actors', cases=paths, management=management,
                    source_secret=str(private(root / 'source-session', source)),
                    provisioning_database=pool.database_config(root, database, 'mdm_identity_provisioning', 'identity-provisioning-fixture'))
                if any(actor['principal'] is None or not (Path(path).parent / f"credential-{actor['tenant']}-{actor['role']}").exists()
                       for path in paths for actor in json.loads(Path(path).read_text())['actors']):
                    self.identity_helper(root, manifest, output / 'actors', database)
                for member, path in zip(batch, paths):
                    root = Path(path).parent
                    context = validate(json.loads(Path(path).read_text()), ready=True)
                    self.case_contexts[member['job'].key] = context
                    for actor in context['actors']:
                        self.actors[(*key, actor['tenant'], actor['login'])] = dict(principal=actor['principal'],
                            secret=(root / f"credential-{actor['tenant']}-{actor['role']}").read_text(),
                            until=json.loads((root / f"credential-meta-{actor['tenant']}-{actor['role']}").read_text()))
            except BaseException as error:
                with self.lock:
                    state['error'] = error
                    batch += state['pending']
                    state['pending'] = []
                for member in batch:
                    member['error'] = error
            finally:
                with self.lock:
                    state['busy'] = False
                    for member in batch:
                        member['done'].set()
        if item['error'] is not None:
            raise RuntimeError('actor batch preparation failed') from item['error']

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
                        elif kind.startswith('pki-'):
                            from pki_fixtures import offline_materials
                            offline_materials(source, kind.removeprefix('pki-'))
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

    def offline_authority(self, job, root, env, purpose):
        from pki_fixtures import offline
        directory = root / ('pki-' + purpose)
        directory.mkdir(mode=0o700)
        for name in ('ca.crt', 'server.crt', 'server.key'):
            shutil.copy2(root / name, directory / name)
        self.prepare_materials('pki-' + purpose, directory)
        offline(directory, root, env, purpose)

    @contextmanager
    def workers(self, job, database, config):
        pool = self.fault if job.module.db_mode == 'instance' else self.normal
        tenant = self.case_contexts[job.key]['tenant']
        key = (pool.owner.project, pool.generation, database, tenant, compatibility(config))
        with self.lock:
            lock = self.host_locks.setdefault(key, threading.Lock())
        with measure(self.costs, 'host-wait', database=database, tenant=tenant):
            while not lock.acquire(timeout=.05):
                self.builds.processes.check()
        try:
            self.builds.processes.check()
            host = self.hosts.get(key)
            if isinstance(host, BaseException):
                raise RuntimeError('host preparation previously failed') from host
            if host is None:
                try:
                    with measure(self.costs, 'host-start', database=database, tenant=tenant):
                        host = Host(self.builds, config, self.output / 'hosts' / database / tenant / key[-1])
                    with self.lock:
                        self.hosts[key] = host
                    self.costs.increment('hostStarts', 1)
                except BaseException as error:
                    with self.lock:
                        self.hosts[key] = error
                    raise
        finally:
            lock.release()
        host.check()
        try:
            yield host
            host.check()
        finally:
            if job.module.db_mode != 'reuse' or job.module.scope != 'objects':
                with self.lock:
                    owned = self.hosts.pop(key, None)
                if owned is not None:
                    with measure(self.costs, 'host-stop', database=database, tenant=tenant, host=host.address):
                        owned.close()

    def source_tls(self, root):
        with self.lock:
            self.certificates.prepare_inputs()
            directory = self.certificates.root / 'source-cert'
            self.certificates.issue_leaf(directory, ['source.invalid'])
            for source, target in ((self.certificates.root / 'ca.crt', 'ca.pem'),
                                   (directory / 'server.crt', 'server.pem'),
                                   (directory / 'server.key', 'server.key')):
                private(root / target, source.read_text())

    @contextmanager
    def gateway(self, config, files=None):
        environment = self.gateway_owner
        try:
            environment.prepare_inputs(certificates=False)
            private(environment.root / 'probe/nginx.conf', config)
            for name,value in (files or {}).items():
                if Path(name).name!=name:raise ValueError('gateway fixture filename required')
                private(environment.root / 'probe' / name,value)
            environment.verify_ownership()
            environment.compose('--profile', 'probe', 'up', '-d', 'gateway-probe')
            name = environment.compose('ps', '-q', 'gateway-probe')
            try:
                port = int(environment.compose('port', 'gateway-probe', '8080').rsplit(':', 1)[1])
            except subprocess.CalledProcessError as error:
                diagnostic = environment.compose('logs', '--no-color', '--tail', '80', 'gateway-probe')
                raise RuntimeError('gateway startup failed before port discovery:\n' + diagnostic) from error
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
                if 'runtime_config' in module.fixtures:
                    value = self.runtime_config(pool, root, database, self.case_contexts[job.key]['tenant'],
                        native_key=self.native_key, recovery_credentials=self.recovery_config())
                    env['MDM_TEST_CONFIG'] = str(private(root / 'runtime.json', value))
                if 'identity' in module.fixtures:
                    self.configure_identity(pool, database, job, output / 'identity-setup')
                    value = json.loads((root / 'runtime.json').read_text())
                    if (root / 'windows.json').exists():
                        value['native_protocols']['windows'] = json.loads((root / 'windows.json').read_text())
                    env['MDM_TEST_CONFIG'] = str(private(root / 'runtime.json', value))
            host = None
            if 'examples' in module.fixtures:
                env['MDM_FIXTURE_BIN'] = self.builds.executables['rss-mdm-fixture']
            from pki_fixtures import running as pki
            for purpose, fixture in (('windows', 'windows'), ('agent', 'agent_pki')):
                if fixture in module.fixtures:
                    if 'ca_' + purpose in module.fixtures:
                        stack.enter_context(pki(root, env, case=job.key, agent=purpose == 'agent',
                            windows=purpose == 'windows', configuration_devices=module.configuration_devices,
                            materials=module.materials))
                        self.costs.increment('caStarts', 1)
                    else:
                        self.offline_authority(job, root, env, purpose)
            if 'pki_rotation' in module.fixtures:
                stack.enter_context(pki(root,env,case=job.key,agent=True,generation='next'))
                self.costs.increment('caStarts', 1)
            if 'scep' in module.fixtures:
                from apple_ca import running
                stack.enter_context(running(root, env, case=job.key))
                self.costs.increment('caStarts', 1)
            elif 'apple' in module.fixtures and module.postgres:
                self.offline_authority(job, root, env, 'apple')
            if 'MDM_TEST_CONFIG' in env:
                value=json.loads(Path(env['MDM_TEST_CONFIG']).read_text())
                if (root/'device-pki.json').exists():value['device_pki']=json.loads((root/'device-pki.json').read_text())
                if (root/'agent-pki.json').exists():value['agent_pki']=json.loads((root/'agent-pki.json').read_text())
                for channel in ('windows','apple'):
                    if (root/(channel+'.json')).exists():value['native_protocols'][channel]=json.loads((root/(channel+'.json')).read_text())
                if 'agent-bootstrap' in module.materials:
                    from bootstrap_fixtures import configure
                    configure(root, value, env)
                private(Path(env['MDM_TEST_CONFIG']),value)
            # Runtime authority revisions must exist before a real host consumes them.
            if 'identity' in module.fixtures:
                self.prepare_identity(pool, database, job, output / 'identity-setup')
            if 'shared_worker' in module.fixtures:
                host = stack.enter_context(self.workers(job, database, env['MDM_TEST_CONFIG']))
                receipt['environment']['hostLog'] = str(host.log_path.relative_to(self.output))
                receipt['environment']['host'] = host.address
            if 'oracle' in module.fixtures:
                from apple_oracle import running as oracle
                stack.enter_context(oracle(root, env))
            if 'telemetry' in module.fixtures:
                from telemetry_fixtures import telemetry_profiles
                selected=module.id.rsplit('.',1)[-1] if module.id.startswith('telemetry.ingress.') else None
                env.update(stack.enter_context(telemetry_profiles(root, self.case_contexts[job.key]['tenant'], selected, owner if database else None)))
            if 's3' in module.fixtures:
                with self.lock:
                    env.update(self.s3.environment())
            if 'idp' in module.fixtures:
                from enterprise_idp import fixture
                env.update(stack.enter_context(fixture(root, owner)))
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
