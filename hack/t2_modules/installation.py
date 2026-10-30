"""Product CLI seams, kept independent of Rust business matrices."""
import json, os, sys, time, uuid
from t2_processes import subprocess
from pathlib import Path
from build_run import lease_fds
from t2_environment import run
from verification_result import require
ROOT=Path(__file__).resolve().parents[2]

def verify_migrations(container, binary, config, root, env):
    database=json.loads(config.read_text())["database"]["name"]
    def sql(statement):
        return run(["docker", "exec", "-i", container, "psql", "-At", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", database], input=statement, capture_output=True, timeout=10).stdout.strip()
    def migrate(path=config, accepted=True, reason=None):
        result = subprocess.run([binary,"migrate","--config",str(path)],pass_fds=lease_fds(), cwd=ROOT,env=env,capture_output=True,text=True,timeout=70)
        if (result.returncode == 0) != accepted:
            raise RuntimeError("migration admission/ledger expectation failed: " + result.stderr)
        if reason is not None:
            require(reason in result.stderr, "wrong migration failure stage: " + result.stderr)
    admin = json.loads(config.read_text())
    (root/"admin-password").write_text("local-fixture"); os.chmod(root/"admin-password",0o600)
    admin["database"].update(user="postgres",password_file=str(root/"admin-password"))
    admin_config=root/"admin-migrate.json";admin_config.write_text(json.dumps(admin));os.chmod(admin_config,0o600)
    migrate(admin_config,accepted=False,reason="migration installation: mdm_owner admission rejected")
    require(sql("SELECT to_regclass('public.mdm_migrations') IS NULL") == "t", "rejected migrator performed DDL")
    migrate(); migrate()
    original = sql("SELECT digest FROM public.mdm_migrations WHERE name='inventory-v1'")
    import hashlib
    require(original == hashlib.sha256(b''.join((ROOT/'crates/inventory-postgres/migrations'/name).read_bytes() for name in ('install.sql','arrays.sql','asset-cuts.sql'))).hexdigest(), "migration invariant rejected")
    sql("UPDATE public.mdm_migrations SET complete=false WHERE name='inventory-v1'")
    migrate(accepted=False,reason="migration installation: existing ledger differs or is incomplete")
    sql("UPDATE public.mdm_migrations SET complete=true WHERE name='inventory-v1'")
    migrate()
    # An owned holder makes both independent installers visibly wait before release.
    holder_name = 't2-holder-' + uuid.uuid4().hex
    holder = subprocess.Popen(["docker","exec","-e","PGAPPNAME="+holder_name,container,"psql","-U","postgres","-d",database,"-c","SELECT pg_advisory_lock(2346); SELECT pg_sleep(30)"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    holder_pid = 0
    children=[]
    try:
        deadline=time.monotonic()+5
        while sql("SELECT count(*) FROM pg_locks WHERE database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND locktype='advisory' AND objid=2346 AND granted") != "1":
            if time.monotonic()>deadline: raise RuntimeError("migration lock holder deadline")
            time.sleep(.1)
        holder_pid = int(sql(f"SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND application_name='{holder_name}'"))
        children=[subprocess.Popen([binary,"migrate","--config",str(config)],pass_fds=lease_fds(), cwd=ROOT,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True) for _ in range(2)]
        deadline=time.monotonic()+5
        while sql("SELECT count(*) FROM pg_locks WHERE database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND locktype='advisory' AND objid=2346 AND NOT granted") != "2":
            if time.monotonic()>deadline: raise RuntimeError("concurrent migrators did not serialize")
            time.sleep(.1)
        sql(f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=current_database() AND ({holder_pid}=0 OR pid={holder_pid}) AND application_name='{holder_name}'")
        for child in children:
            _,error=child.communicate(timeout=15)
            if child.returncode: raise RuntimeError("serialized migration failed: "+error)
        require(sql("SELECT count(*) FROM public.mdm_migrations WHERE complete") == str(len(json.loads(run([binary,"--describe"],capture_output=True).stdout)["units"])), "migration invariant rejected")
    finally:
        sql(f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=current_database() AND ({holder_pid}=0 OR pid={holder_pid}) AND application_name='{holder_name}'")
        holder.wait(timeout=5)
        for child in children:
            if child.poll() is None: child.terminate();child.wait(timeout=5)
    print("migration CLI admission, interrupted ledger and concurrent installers passed",flush=True)

def execute(fixture):
    verify_migrations(fixture.owner.container(), fixture.binary, fixture.migration_config, fixture.root, fixture.env)


def ready(fixture):
    """One empty installation reaches product readiness with independent business roles."""
    from types import SimpleNamespace
    from candidate_fixture import ADMIN, INSTANCE
    from t2_database import DatabasePool
    from t2_environment import private
    from t2_fixtures import RunFixtures
    from t2_hosts import Host
    from t2_modules.tenants import HostProcesses

    root = fixture.root
    pool = SimpleNamespace(owner=fixture.owner)
    pool.database_config = lambda *args: DatabasePool.database_config(pool, *args)
    installation = json.loads(fixture.migration_config.read_text())['installation']

    def command(verb, value):
        path = private(root / (verb + '.json'), value)
        result = subprocess.run([fixture.binary, verb, '--config', str(path)],
                                pass_fds=lease_fds(), cwd=ROOT, env=fixture.env,
                                capture_output=True, text=True, timeout=90)
        require(result.returncode == 0, verb + ' failed: ' + result.stderr)
        return json.loads(result.stdout) if result.stdout.strip() else None

    require(fixture.owner.sql("SELECT to_regclass('public.mdm_installation') IS NULL", fixture.database).strip() == 't',
            'startup proof requires an empty database')
    command('migrate', json.loads(fixture.migration_config.read_text()))
    business = str(uuid.uuid4())
    fixture.owner.sql(f"SELECT public.create_new_tenant('{uuid.UUID(business)}',1,NULL,NULL)", fixture.database)
    password = private(root / 'account-password', 'Fixture-only-startup-password-2026!')
    command('initialize', dict(audit={'mode':'plain'}, installation=installation,
        database=pool.database_config(root, fixture.database, 'mdm_identity_maintenance', 'identity-maintenance-fixture'),
        tenant_id=business, expected_epoch=1, principal_id=ADMIN, login='admin', password_file=str(password)))
    command('initialize-authorization', dict(installation=installation, audit={'mode':'plain'},
        database=pool.database_config(root, fixture.database, 'mdm_access', 'access-fixture'),
        identityDatabase=pool.database_config(root, fixture.database, 'mdm_identity_runtime', 'identity-runtime-fixture'),
        expectedEpoch=1, login='admin', passwordFile=str(password), operationId=str(uuid.uuid4()),
        user=dict(instanceId=INSTANCE, tenantId=business, principalId=ADMIN)))
    config = RunFixtures.runtime_config(pool, root, fixture.database, business,
        native_key=fixture.env['MDM_NATIVE_PROTECTION_KEY_FILE'], recovery_credentials=fixture.recovery_credentials)
    directory = root / 'content'
    directory.mkdir()
    config['content'] = dict(storage=dict(kind='volume', directory=str(directory)), imports={},
        max_artifact_bytes=33554432, max_temporary_bytes=67108864, max_uploads=4,
        transfer_seconds=60, retention_seconds=3600, max_bundle_entries=4096, max_expansion_ratio=100)
    from telemetry_fixtures import telemetry_profiles
    with telemetry_profiles(root / 'telemetry', business, selected='postgres',
                            group_prefix='t2r-' + root.name[:16]) as environment:
        requests = json.loads(Path(environment['MDM_TELEMETRY_PROVIDERS']).read_text())
        require(len(requests) == 1, 'startup uses one Postgres telemetry backend')
        request = requests[0]
        command('prepare-telemetry', request)
        config['telemetry'] = request['configuration']
        path = private(root / 'runtime.json', config)
        builds = SimpleNamespace(processes=HostProcesses(), executables={'rss-mdm':fixture.binary})
        # A fresh baseline may retry once after concurrent owner initialization.
        host = Host(builds, path, root / 'ready-host', ready_timeout=180)
        try:
            require(fixture.owner.sql("SELECT count(DISTINCT usename) FROM pg_stat_activity WHERE datname=current_database() AND usename IN ('mdm_command_runtime','mdm_policy_runtime')", fixture.database).strip() == '2',
                    'ready host omitted business connections')
            print('fresh installation reached /readyz=200 after Command and PolicyEvents binding', flush=True)
        finally:
            host.close()
