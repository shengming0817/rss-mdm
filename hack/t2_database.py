"""Run-owned PG pools and immutable migration baselines.

ref: PostgreSQL src/backend/commands/dbcommands.c@7885b94dd81b98bbab9ed878680d156df7bf857f
"""
from contextlib import contextmanager
import json
from pathlib import Path
import tempfile
import threading
import time
import uuid
from t2_environment import Environment, private, run
from t2_registry import ROOT
from verification_result import require


def identifier(value):
    return '"' + value.replace('"', '""') + '"'


def literal(value):
    return "'" + value.replace("'", "''") + "'"


@contextmanager
def measure(events, phase, **coordinates):
    begin = time.monotonic()
    status = 'failed'
    try:
        yield
        status = 'passed'
    finally:
        end = time.monotonic()
        events.append(dict(phase=phase, status=status, startedMonotonic=begin,
                           endedMonotonic=end, seconds=round(end-begin, 3), **coordinates))


class DatabasePool:
    def __init__(self, builds, group, counts, events=None):
        self.builds = builds
        self.owner = Environment(group=group)
        self.counts = counts
        self.events = events if events is not None else []
        self.lock = threading.RLock()
        self.ready = False
        self.generation = 0
        self.dirty = False
        self.templates = {}
        self.shared = {}
        self.installation = None

    def postgres(self):
        with self.lock:
            if self.dirty:
                with measure(self.events, 'fault-reset', pg=self.owner.project):
                    self.owner.reset()
                self.ready = False
                self.templates.clear()
                self.shared.clear()
                self.dirty = False
                self.counts['faultReplacements'] += 1
            if not self.ready:
                with measure(self.events, 'postgres-start', pg=self.owner.project):
                    self.owner.up()
                    self.owner.roles()
                self.ready = True
                self.generation += 1
                self.counts['postgresStarts'] += 1
            return self.owner

    def role_state(self):
        # Compare names rather than OIDs: temporary roles may be created and retired.
        return self.owner.sql("""SELECT jsonb_build_object(
          'roles',(SELECT jsonb_agg(to_jsonb(r)-'oid' ORDER BY rolname) FROM pg_roles r),
          'members',(SELECT coalesce(jsonb_agg(jsonb_build_array(
            pg_get_userbyid(roleid),pg_get_userbyid(member),pg_get_userbyid(grantor),
            admin_option,inherit_option,set_option) ORDER BY roleid,member),'[]') FROM pg_auth_members),
          'settings',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY setdatabase,setrole),'[]')
            FROM pg_db_role_setting s WHERE setdatabase=0))""")

    @contextmanager
    def database(self, profile, mode):
        self.postgres()
        if mode == 'reuse':
            with self.lock:
                if profile not in self.shared:
                    self.shared[profile] = self.clone(profile, 't2_shared_')
                    self.counts['sharedDatabases'] += 1
                name = self.shared[profile]
            yield name
            return
        before = self.role_state() if mode == 'instance' else None
        try:
            with self.disposable(profile) as name:
                yield name
            if before is not None:
                require(self.role_state() == before, 'fault case did not restore shared PG roles/settings')
                self.counts['faultRestorations'] += 1
        except BaseException:
            if mode == 'instance':
                self.dirty = True
            raise

    def clone(self, profile, prefix):
        template, properties, coordinates = self.template(profile)
        name = prefix + uuid.uuid4().hex
        with measure(self.events, 'clone', database=name, profile=profile, pg=self.owner.project):
            self.owner.sql(f'CREATE DATABASE {identifier(name)} OWNER mdm_owner TEMPLATE {identifier(template)}')
            self.restore_properties(name, properties)
            require(self.coordinates(name, profile) == coordinates, 'cloned installation coordinates differ')
        self.counts['clonedDatabases'] += 1
        return name

    def database_config(self, root, database, role='mdm_owner', password='owner-fixture'):
        private(root / (role + '-password'), password)
        return dict(host='localhost', port=self.owner.port(), name=database, user=role,
                    password_file=str(root / (role + '-password')), ca_file=str(root / 'ca.crt'))

    def installation_config(self, root, database):
        return private(root / 'migrate.json', {
            'installation': self.installation, 'database': self.database_config(root, database)})

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
            with measure(self.events, 'baseline', profile=profile, pg=self.owner.project):
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
                                  + 'INSERT INTO rss_transactional_messaging.tenant_epoch VALUES'
                                  + ','.join(f'({literal(tenant)},1)' for tenant in self.installation['tenants']) + ';', name)
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
    def disposable(self, profile):
        self.postgres()
        if profile == 'empty':
            with self.owner.database() as name:
                self.counts['emptyDatabases'] += 1
                yield name
            return
        name = self.clone(profile, 't2_case_')
        try:
            yield name
        finally:
            with measure(self.events, 'database-drop', database=name, pg=self.owner.project):
                self.owner.sql(f'DROP DATABASE {identifier(name)} WITH (FORCE)')

