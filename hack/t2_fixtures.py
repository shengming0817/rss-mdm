"""Run-owned services and immutable migration baselines; scenarios own writable state.

ref: PostgreSQL src/backend/commands/dbcommands.c@7885b94dd81b98bbab9ed878680d156df7bf857f
"""
from __future__ import annotations
from collections import Counter
from contextlib import contextmanager, ExitStack
from dataclasses import replace
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import uuid

from candidate_fixture import installation as product_installation, INSTANCE, ADMIN, TENANTS
from t2_environment import Environment, private, run
from t2_registry import ROOT, APP, Module
from t2_processes import owned_by
from verification_result import require


def installation():
    config = product_installation()
    config['tenants'] = [*config['tenants'], '11111111-1111-1111-1111-111111111111',
                         '22222222-2222-2222-2222-222222222222']
    return config


def identifier(value):
    return '"' + value.replace('"', '""') + '"'


def literal(value):
    return "'" + value.replace("'", "''") + "'"


class RunFixtures:
    def __init__(self, builds, output):
        self.builds = builds
        self.output = output
        self.owner = Environment(group='t2')
        self.gateway_owner = Environment(group='t2-gateway')
        self.started = False
        self.cert_directory = tempfile.TemporaryDirectory(prefix='mdm-t2-certificates-')
        self.certificates = Environment(group='t2-certificates')
        self.certificates.root = Path(self.cert_directory.name)
        self.lock = threading.RLock()
        self.templates = {}
        self.ready = False
        self.counts = Counter()

    def __enter__(self):
        self.process_ownership = owned_by(self.builds.processes)
        self.process_ownership.__enter__()
        try:
            # The worktree lease makes these known projects exclusively ours.
            # Recover all registered owners even when this run selects no PG/gateway.
            self.cleanup_environments()
        except BaseException:
            self.cert_directory.cleanup()
            self.process_ownership.__exit__(*sys.exc_info())
            raise
        return self

    def cleanup_environments(self):
        errors = []
        for environment in (self.owner, self.gateway_owner):
            try:
                if environment.root.exists():
                    environment.reset()
            except Exception as error:
                errors.append(error)
        if errors:
            raise RuntimeError('failed to clean owned T2 environments') from errors[0]

    def __exit__(self, *unused):
        try:
            with self.builds.processes.cleanup():
                self.cleanup_environments()
        finally:
            try:
                self.cert_directory.cleanup()
            finally:
                self.process_ownership.__exit__(*unused)

    def prepare(self, modules):
        if any(module.postgres and not module.exclusive for module in modules):
            self.postgres()
        if any(set(module.fixtures) & {'tls', 'windows', 'apple', 'apns'} for module in modules):
            with self.lock:
                self.certificates.prepare_inputs()
        for profile in sorted({m.profile for m in modules if m.postgres and not m.exclusive and m.profile != 'empty'}):
            self.template(profile)

    def postgres(self):
        with self.lock:
            if not self.ready:
                self.started = True
                if self.owner.root.exists():
                    # build_run owns the worktree lease; verify and retire only
                    # residue from this same T2 service before preparing it.
                    self.owner.reset()
                self.owner.up()
                self.owner.roles()
                self.ready = True
                self.counts['postgresStarts'] += 1
            return self.owner

    def reset(self):
        """Only called after the normal phase is drained, never from parallel jobs."""
        if self.owner.root.exists():
            self.owner.reset()
        self.ready = False
        self.started = False
        self.templates.clear()
        self.counts['exclusiveResets'] += 1

    def database_config(self, root, database, role='mdm_owner', password='owner-fixture'):
        private(root / (role + '-password'), password)
        return dict(host='localhost', port=self.owner.port(), name=database, user=role,
                    password_file=str(root / (role + '-password')), ca_file=str(root / 'ca.crt'))

    def installation_config(self, root, database):
        return private(root / 'migrate.json', {
            'installation': installation(), 'database': self.database_config(root, database)})

    def database_grants(self, name):
        self.owner.sql(f'GRANT CREATE ON DATABASE {identifier(name)} TO mdm_audit_owner,mdm_ledger_owner,mdm_group_owner; '
                       'GRANT CREATE ON SCHEMA public TO mdm_owner,mdm_group_owner;', name)

    def coordinates(self, name, profile):
        if profile == 'product':
            return json.loads(self.owner.sql('SELECT configuration FROM public.mdm_installation', name))
        return self.owner.sql("SELECT encode(target,'hex')||':'||encode(lineage,'hex') FROM rss_transactional_messaging.storage_lineage ORDER BY target", name)

    def properties(self, name):
        query = f'''SELECT jsonb_build_object(
          'owner',pg_get_userbyid(d.datdba),
          'acl',(SELECT jsonb_agg(jsonb_build_object('role',CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,
                       'privilege',a.privilege_type,'grantable',a.is_grantable) ORDER BY a.grantee,a.privilege_type)
                 FROM aclexplode(coalesce(d.datacl,acldefault('d',d.datdba))) a),
          'settings',(SELECT coalesce(jsonb_agg(jsonb_build_object('role',s.setrole,'values',s.setconfig) ORDER BY s.setrole),'[]'::jsonb)
                      FROM pg_db_role_setting s WHERE s.setdatabase=d.oid))
          FROM pg_database d WHERE d.datname={literal(name)}'''
        return json.loads(self.owner.sql(query))

    def restore_properties(self, name, properties):
        database = identifier(name)
        self.owner.sql(f'ALTER DATABASE {database} OWNER TO {identifier(properties["owner"])}; '
                       f'REVOKE ALL ON DATABASE {database} FROM PUBLIC;')
        for entry in properties['acl']:
            privilege = entry['privilege']
            require(privilege in {'CONNECT', 'CREATE', 'TEMPORARY'}, 'unsupported database privilege')
            role = 'PUBLIC' if entry['role'] == 'PUBLIC' else identifier(entry['role'])
            grantable = ' WITH GRANT OPTION' if entry['grantable'] else ''
            self.owner.sql(f'GRANT {privilege} ON DATABASE {database} TO {role}{grantable};')
        for entry in properties['settings']:
            if entry['role']:
                role = self.owner.sql(f'SELECT rolname FROM pg_roles WHERE oid={int(entry["role"])}')
                prefix = f'ALTER ROLE {identifier(role)} IN DATABASE {database}'
            else:
                prefix = f'ALTER DATABASE {database}'
            for setting in entry['values']:
                key, value = setting.split('=', 1)
                self.owner.sql(f'{prefix} SET {identifier(key)} TO {literal(value)};')
        require(self.properties(name) == properties, 'cloned database permissions/settings differ from baseline')

    def template(self, profile):
        with self.lock:
            if profile in self.templates:
                return self.templates[profile]
            owner = self.postgres()
            name = 't2_template_' + uuid.uuid4().hex
            owner.sql(f'CREATE DATABASE {identifier(name)} OWNER mdm_owner')
            self.database_grants(name)
            with tempfile.TemporaryDirectory(prefix='mdm-template-') as directory:
                root = Path(directory)
                private(root / 'ca.crt', (owner.root / 'ca.crt').read_text())
                if profile == 'product':
                    config = self.installation_config(root, name)
                    run([self.builds.executables['rss-mdm'], 'migrate', '--config', config],
                        cwd=ROOT, capture_output=True, timeout=90)
                else:
                    executable = 'migrations' if profile == 'group' else 'policy_migrations'
                    sql = run([self.builds.executables[executable]], cwd=ROOT, capture_output=True).stdout
                    if profile == 'backend':
                        sql += '\n' + '\n'.join((ROOT / f'crates/{kind}-postgres/migrations/{unit}').read_text()
                                                 for kind in ('resource', 'software-release')
                                                 for unit in ('0001.sql', '0002_outbox_writer.sql'))
                    role = 'mdm_group_owner' if profile == 'group' else 'mdm_owner'
                    owner.sql(f'BEGIN; SET ROLE {role}; {sql} COMMIT;', name)
                    owner.sql("INSERT INTO rss_transactional_messaging.storage_lineage(target,lineage) VALUES(decode(repeat('01',16),'hex'),decode(repeat('02',16),'hex')); "
                              "INSERT INTO rss_transactional_messaging.tenant_epoch VALUES('11111111-1111-1111-1111-111111111111',1),('22222222-2222-2222-2222-222222222222',1);", name)
            properties = self.properties(name)
            coordinates = self.coordinates(name, profile)
            owner.sql(f'ALTER DATABASE {identifier(name)} ALLOW_CONNECTIONS false;')
            require(owner.sql(f'SELECT count(*) FROM pg_stat_activity WHERE datname={literal(name)}') == '0',
                    'migration baseline still has live connections')
            require(owner.sql(f'SELECT count(*) FROM pg_prepared_xacts WHERE database={literal(name)}') == '0',
                    'migration baseline has prepared transactions')
            self.templates[profile] = (name, properties, coordinates)
            self.counts['baseline:' + profile] += 1
            return self.templates[profile]

    @contextmanager
    def database(self, profile):
        self.postgres()
        if profile == 'empty':
            with self.owner.database() as name:
                self.counts['emptyDatabases'] += 1
                yield name
            return
        template, properties, coordinates = self.template(profile)
        name = 't2_case_' + uuid.uuid4().hex
        self.owner.sql(f'CREATE DATABASE {identifier(name)} OWNER mdm_owner TEMPLATE {identifier(template)}')
        try:
            self.restore_properties(name, properties)
            require(self.coordinates(name, profile) == coordinates, 'cloned installation coordinates differ')
            with self.lock:
                self.counts['clonedDatabases'] += 1
            yield name
        finally:
            self.owner.sql(f'DROP DATABASE {identifier(name)} WITH (FORCE)')

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

    def identity(self, root, database, env, output):
        config = json.loads((ROOT / 'fixtures/mdm-config.example.json').read_text())
        for key, role in [('access_database', 'mdm_access'), ('runtime_database', 'mdm_runtime')]:
            config[key] = self.database_config(root, database, role, 'access-fixture' if role == 'mdm_access' else 'runtime-fixture')
        config['identity']['database'] = self.database_config(root, database, 'mdm_identity_runtime', 'identity-runtime-fixture')
        config['identity']['audit_worker'] = self.database_config(root, database, 'mdm_identity_audit', 'identity-audit-fixture')
        config['flow']['storage']['database'] = self.database_config(root, database, 'mdm_flow_runtime', 'runtime-fixture')
        config['execution']['database'] = self.database_config(root, database, 'mdm_command_runtime', 'runtime-fixture')
        config['flow']['publication']['database'] = self.database_config(root, database, 'mdm_software_driver', 'runtime-fixture')
        config['native_protocols'] = {}
        if (root / 'windows.json').exists():
            config['native_protocols']['windows'] = json.loads((root / 'windows.json').read_text())
        config['identity_management'] = [dict(tenant_id=TENANTS[0], instance_id=INSTANCE, principal_id=ADMIN, permissions=['accounts', 'providers'])]
        env['MDM_TEST_CONFIG'] = str(private(root / 'runtime.json', config))
        maintenance = self.database_config(root, database, 'mdm_identity_maintenance', 'identity-maintenance-fixture')
        password = private(root / 'account-password', 'Fixture-only-correct-horse-battery-2026!')
        for tenant in TENANTS:
            path = private(root / 'initialize.json', dict(database=maintenance, installation=installation(),
                           tenant_id=tenant, principal_id=ADMIN, login='admin', password_file=str(password)))
            run([self.builds.executables['rss-mdm'], 'initialize', '--config', path],
                cwd=ROOT, env=env, capture_output=True, timeout=30)
        module = Module('identity-setup', APP, ('test_support::identity::',))
        cases = self.builds.discover(module, include_support=True)
        require(len(cases) == 1, 'identity setup target is ambiguous')
        self.builds.execute(cases[0], env, output / 'identity-setup')
        with self.lock:
            self.counts['identitySetups'] += 1

    @contextmanager
    def scenario(self, module, output):
        stack = ExitStack()
        try:
            root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='mdm-module-')))
            env = dict(os.environ, RUST_MIN_STACK=str(8 * 1024 * 1024))
            database = None
            if module.postgres:
                database = stack.enter_context(self.database(module.profile))
            if module.postgres or set(module.fixtures) & {'tls', 'windows', 'apple', 'apns'}:
                certificates = self.owner if module.postgres else self.certificates
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
                port = self.owner.port()
                env.update(PG_CA_FILE=str(root / 'ca.crt'),
                           DATABASE_URL=f'postgres://mdm_runtime:runtime-fixture@localhost:{port}/{database}',
                           MDM_OWNER_URL=f'postgres://mdm_owner:owner-fixture@localhost:{port}/{database}',
                           MDM_ADMIN_URL=f'postgres://postgres:local-fixture@localhost:{port}/{database}',
                           MDM_TEST_PG_CONTAINER=self.owner.container())
                config = private(root / 'database.json', dict(port=port, ca=str(root / 'ca.crt'),
                                 container=self.owner.container(), database=database))
                env.update(BACKEND_PG_CONFIG=str(config), GROUP_PG_CONFIG=str(config))
                migration_config = self.installation_config(root, database)
                if 'identity' in module.fixtures:
                    self.identity(root, database, env, output)
            if 'examples' in module.fixtures:
                env['MDM_FIXTURE_BIN'] = self.builds.executables['rss-mdm-fixture']
            if 'scep' in module.fixtures:
                from apple_ca import running
                stack.enter_context(running(root, env))
            if 'oracle' in module.fixtures:
                from apple_oracle import running as oracle
                stack.enter_context(oracle(root, env))
            if 'idp' in module.fixtures:
                from enterprise_idp import fixture
                env.update(stack.enter_context(fixture(root, self.owner)))
            with self.lock:
                for dependency in module.fixtures:
                    self.counts['fixture:' + dependency] += 1
            yield SimpleNamespace(root=root, env=env, database=database,
                                  migration_config=migration_config, owner=self.owner,
                                  binary=self.builds.executables.get('rss-mdm'), context=self)
        finally:
            with self.builds.processes.cleanup():
                try:
                    stack.close()
                finally:
                    if module.python == 'gateway' and self.gateway_owner.root.exists():
                        self.gateway_owner.reset()
