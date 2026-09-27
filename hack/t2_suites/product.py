#!/usr/bin/env python3
"""Own one disposable TLS PostgreSQL server. Missing Docker/PG is a failure."""
import sys
if sys.version_info < (3, 11):
    raise SystemExit("Python >= 3.11 is required for local CI")

import json
import os
import re
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

from build_run import lease_fds, require_lease

ROOT = Path(__file__).resolve().parents[2]
IMAGE = json.loads((ROOT / "deployment/providers.lock.json").read_text())["postgres"]

def require(condition,message):
    if not condition:raise RuntimeError(message)

def run(args, **kw):
    if args[:2]==['cargo','test']:
        result=subprocess.run(args,pass_fds=lease_fds(),check=True,text=True,capture_output=True,**kw)
        print(result.stdout,flush=True);print(result.stderr,file=sys.stderr,flush=True)
        expected=None
        for key,names in CARGO_EXPECTED.items():
            if key in args:expected=names;break
        require(expected is not None,'Cargo T2 has no execution oracle')
        verify_set(result.stdout,expected)
        return result
    return subprocess.run(args, pass_fds=lease_fds(), check=True, text=True, **kw)

CARGO_EXPECTED={
 'identity_fixture::seed_accounts':{'identity_fixture::seed_accounts'},
 'inventory-postgres-integration':{'real_pg_inventory_and_recovery'},
 'postgres':{'reader_is_exact_tenant_scoped_and_read_only'},
 'identity_t2::authorization::':{'identity_t2::authorization::capability_routes_without_application_preserve_revocation_and_atomicity','identity_t2::authorization::persistent_rules_membership_cas_replay_and_restart'},
 'identity_t2::local_identity_mdm_authorization_and_revocation':{'identity_t2::local_identity_mdm_authorization_and_revocation'},
 'identity_t2::sso::':{'identity_t2::sso::product_callback_link_step_up_and_provider_isolation'},
}

def verify_set(output,expected):
    passed=re.findall(r'^test (\S+) \.\.\. ok$',output,re.MULTILINE)
    require(set(passed)==expected and len(passed)==len(expected) and
            f'test result: ok. {len(expected)} passed; 0 failed; 0 ignored;' in output,
            'T2 did not execute the complete expected behavior')

def verify_exact_result(output, selected):
    passed = re.findall(r'^test (\S+) \.\.\. ok$', output, re.MULTILINE)
    require(passed == [selected] and re.search(r'^test result: ok\. 1 passed; 0 failed; 0 ignored;', output, re.MULTILINE),
            'T2 did not execute exactly the selected test: ' + selected)

def run_exact_test(env, selected, integration=True):
    args = ["cargo", "test", "--locked", "-p", "rss-mdm-app"]
    if integration: args += ["--features", "integration"]
    args += ["--lib", selected, "--", "--ignored", "--exact", "--test-threads=1"]
    if env.get('MDM_AUDIT_DIAGNOSTIC'): args += ['--nocapture']
    result = subprocess.run(args, pass_fds=lease_fds(), cwd=ROOT, env=env, text=True, capture_output=True)
    print(result.stdout, flush=True)
    print(result.stderr, file=sys.stderr, flush=True)
    require(result.returncode == 0, 'T2 failed: ' + selected)
    verify_exact_result(result.stdout, selected)
    return result.stdout

def run_foundation_tests(env):
    for selected in ["identity_t2::authorization::capability_routes_without_application_preserve_revocation_and_atomicity", "device::tests::postgres_boundary", "inventory_runtime::tests::durable_report_recovery_and_projection"]:
        output=run_exact_test({**env, "MDM_AUDIT_DIAGNOSTIC":"1"}, selected, integration=True)
        if selected=="inventory_runtime::tests::durable_report_recovery_and_projection":
            require('"event":"mdm_inventory_failure"' in output and '"phase":"projection_run"' in output, "worker failure lost safe phase diagnostic")

def verify_windows_result(output):
    expected={
        'windows::tests::issuance_recovery_and_enrollment_boundaries',
        'windows::tests::native_tls_enrollment_management_replay_and_revoke',
    }
    passed=set(re.findall(r'^test (\S+) \.\.\. ok$',output,re.MULTILINE))
    require(passed==expected and 'test result: ok. 2 passed; 0 failed; 0 ignored;' in output,
            'Windows T2 did not execute both required protocol/recovery tests')

def verify_migrations(container, binary, config, root, env):
    database=json.loads(config.read_text())["database"]["name"]
    def sql(statement):
        return run(["docker", "exec", "-i", container, "psql", "-At", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", database], input=statement, capture_output=True, timeout=10).stdout.strip()
    def migrate(path=config, accepted=True):
        result = subprocess.run([binary,"migrate","--config",str(path)],pass_fds=lease_fds(), cwd=ROOT,env=env,capture_output=True,text=True,timeout=70)
        if (result.returncode == 0) != accepted:
            raise RuntimeError("migration admission/ledger expectation failed: " + result.stderr)
    admin = json.loads(config.read_text())
    (root/"admin-password").write_text("local-fixture"); os.chmod(root/"admin-password",0o600)
    admin["database"].update(user="postgres",password_file=str(root/"admin-password"))
    admin_config=root/"admin-migrate.json";admin_config.write_text(json.dumps(admin));os.chmod(admin_config,0o600)
    migrate(admin_config,accepted=False)
    require(sql("SELECT to_regclass('public.mdm_migrations') IS NULL") == "t", "rejected migrator performed DDL")
    migrate(); migrate()
    require(sql("SELECT to_regclass('mdm_access.audit') IS NULL") == "t", "retired product audit table was installed")
    original = sql("SELECT digest FROM public.mdm_migrations WHERE name='inventory-v1'")
    import hashlib
    require(original == hashlib.sha256((ROOT/'crates/inventory-postgres/migrations/0001_inventory.sql').read_bytes()).hexdigest(), "migration invariant rejected")
    for change in ["complete=false", "digest=repeat('0',64)"]:
        sql("UPDATE public.mdm_migrations SET " + change + " WHERE name='inventory-v1'")
        migrate(accepted=False)
        sql("UPDATE public.mdm_migrations SET complete=true,digest='" + original + "' WHERE name='inventory-v1'")
    # An owned holder makes both independent installers visibly wait before release.
    holder = subprocess.Popen(["docker","exec","-e","PGAPPNAME=mdm-t2-migration-lock",container,"psql","-U","postgres","-d",database,"-c","SELECT pg_advisory_lock(2346); SELECT pg_sleep(30)"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    children=[]
    try:
        deadline=time.monotonic()+5
        while sql("SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND objid=2346 AND granted") != "1":
            if time.monotonic()>deadline: raise RuntimeError("migration lock holder deadline")
            time.sleep(.1)
        children=[subprocess.Popen([binary,"migrate","--config",str(config)],pass_fds=lease_fds(), cwd=ROOT,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True) for _ in range(2)]
        deadline=time.monotonic()+5
        while sql("SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND objid=2346 AND NOT granted") != "2":
            if time.monotonic()>deadline: raise RuntimeError("concurrent migrators did not serialize")
            time.sleep(.1)
        sql("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='mdm-t2-migration-lock'")
        for child in children:
            _,error=child.communicate(timeout=15)
            if child.returncode: raise RuntimeError("serialized migration failed: "+error)
        require(sql("SELECT count(*) FROM public.mdm_migrations WHERE complete") == str(len(json.loads(run([binary,"--describe"],capture_output=True).stdout)["units"])), "migration invariant rejected")
    finally:
        sql("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='mdm-t2-migration-lock'")
        holder.wait(timeout=5)
        for child in children:
            if child.poll() is None: child.terminate();child.wait(timeout=5)
    print("migration admission, immutable digest, interrupted ledger and concurrent installers passed",flush=True)

def verify_startup_deadlines(binary, root, env):
    import socket
    config=json.loads((root/'runtime.json').read_text())
    runtime_password = config['runtime_database']['password_file']
    config['runtime_database']['password_file'] = str(root/'missing-runtime-password')
    invalid_runtime = root/'invalid-runtime.json'
    invalid_runtime.write_text(json.dumps(config)); invalid_runtime.chmod(0o600)
    result = subprocess.run([binary, 'serve', '--config', str(invalid_runtime)], pass_fds=lease_fds(), cwd=ROOT, env=env, capture_output=True, text=True, timeout=22)
    require(result.returncode != 0 and 'startup.runtime_database_configuration' in result.stderr,
            'runtime database input lost its startup stage: ' + result.stderr)
    config['runtime_database']['password_file'] = runtime_password
    secrets=['api-fixture','access-fixture','runtime-fixture','identity-runtime-fixture','identity-maintenance-fixture','o'*40]
    def verify(result, start, stage):
        require(result.returncode != 0 and time.monotonic()-start < 21, 'startup dependency stall escaped total budget')
        require(stage in result.stderr, 'startup failure lost safe stage classification: ' + result.stderr)
        require(all(secret not in result.stderr for secret in secrets), 'startup diagnostics exposed credentials')
    with socket.socket() as stalled:
        stalled.bind(('127.0.0.1',0));stalled.listen(8)
        stalled_port=stalled.getsockname()[1]
        for key in ['access_database','runtime_database']:
            config[key]['port']=stalled_port
        for key in ['database','publication_database']:
            config['flow']['storage' if key=='database' else 'publication']['database']['port']=stalled_port
        config['execution']['database']['port']=stalled_port
        config['identity']['database']['port']=stalled_port
        config['identity']['audit_worker']['port']=stalled_port
        path=root/'stalled.json';path.write_text(json.dumps(config));path.chmod(0o600)
        start=time.monotonic()
        result=subprocess.run([binary,'serve','--config',str(path)],pass_fds=lease_fds(), cwd=ROOT,env=env,capture_output=True,text=True,timeout=22)
        verify(result,start,'startup.access_store')
    # Keep the same physical PG identity required by production configuration.
    # This table is probed only by Identity; the earlier product stores remain healthy.
    container=env['MDM_TEST_PG_CONTAINER']
    def sql(statement):
        return run(['docker','exec',container,'psql','-X','-At','-v','ON_ERROR_STOP=1','-U','postgres','-d',config['access_database']['name'],'-c',statement],capture_output=True,timeout=5).stdout.strip()
    holder=subprocess.Popen(['docker','exec','-e','PGAPPNAME=mdm-t2-identity-startup-holder',container,'psql','-X','-v','ON_ERROR_STOP=1','-U','postgres','-d',config['access_database']['name'],'-c',
        'BEGIN; LOCK TABLE identity_authority.deployment IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(60); ROLLBACK;'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    child=None
    try:
        end=time.monotonic()+5
        while sql("SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a USING(pid) WHERE a.application_name='mdm-t2-identity-startup-holder' AND l.relation='identity_authority.deployment'::regclass AND l.mode='AccessExclusiveLock' AND l.granted") != '1':
            require(holder.poll() is None and time.monotonic()<end,'identity startup lock holder deadline')
            time.sleep(.1)
        start=time.monotonic()
        child=subprocess.Popen([binary,'serve','--config',str(root/'runtime.json')],pass_fds=lease_fds(), cwd=ROOT,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        end=time.monotonic()+8
        while sql("SELECT count(*) FROM pg_stat_activity WHERE usename='mdm_identity_runtime' AND wait_event_type='Lock'") != '1':
            require(child.poll() is None and time.monotonic()<end,'startup did not reach the blocked Identity probe')
            time.sleep(.1)
        output,error=child.communicate(timeout=22)
        verify(subprocess.CompletedProcess(child.args,child.returncode,output,error),start,'startup.identity')
    finally:
        sql("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='mdm-t2-identity-startup-holder'")
        holder.wait(timeout=5)
        if child is not None and child.poll() is None:
            child.terminate();child.communicate(timeout=10)
    print('database and Identity startup stalls rejected within budget with safe stage diagnostics',flush=True)

from candidate_fixture import INSTANCE, ADMIN, TENANTS, installation

def configure_identity(root, port, binary, env, database_name):
    def write(name, value):
        path=root/name;path.write_text(value if isinstance(value,str) else json.dumps(value));path.chmod(0o600);return str(path)
    config=json.loads((ROOT/'fixtures/mdm-config.example.json').read_text())
    def database(role, password):
        return dict(host='localhost',port=int(port),name=database_name,user=role,password_file=write(role+'-password',password),ca_file=str(root/'ca.crt'))
    for key,role,password in [('access_database','mdm_access','access-fixture'),('runtime_database','mdm_runtime','runtime-fixture')]:config[key]=database(role,password)
    config['identity']['database']=database('mdm_identity_runtime','identity-runtime-fixture')
    config['identity']['audit_worker']=database('mdm_identity_audit','identity-audit-fixture')
    config['flow']['storage']['database']=database('mdm_flow_runtime','runtime-fixture')
    config['execution']['database']=database('mdm_command_runtime','runtime-fixture')
    config['flow']['publication']['database']=database('mdm_software_driver','runtime-fixture')
    config['native_protocols']={}
    if (root/'windows.json').exists(): config['native_protocols']['windows']=json.loads((root/'windows.json').read_text())
    config['identity_management']=[dict(tenant_id=TENANTS[0],instance_id=INSTANCE,principal_id=ADMIN,permissions=['accounts','providers'])]
    env['MDM_TEST_CONFIG']=write('runtime.json',config)
    maintenance=database('mdm_identity_maintenance','identity-maintenance-fixture')
    password=write('account-password','Fixture-only-correct-horse-battery-2026!')
    for tenant in TENANTS:
        path=write('initialize.json',dict(database=maintenance,installation=installation(),tenant_id=tenant,principal_id=ADMIN,login='admin',password_file=password))
        result=subprocess.run([binary,'initialize','--config',path],pass_fds=lease_fds(), env=env,cwd=ROOT,text=True,capture_output=True,timeout=30)
        require(result.returncode==0,'component initialization failed: '+result.stderr)
    run(['cargo','test','--locked','-p','rss-mdm-app','--features','integration','--lib','identity_fixture::seed_accounts','--','--ignored'],env=env,cwd=ROOT)

def run_scenario(context, scenario):
    require_lease(ROOT)
    executables=[]
    if 'examples' in context.spec.fixtures:
        build = run(["cargo", "build", "--locked", "-p", "rss-mdm-examples", "--bin", "rss-mdm-fixture", "--message-format=json"], cwd=ROOT, capture_output=True)
        executables = [item["executable"] for line in build.stdout.splitlines() if (item := json.loads(line)).get("reason") == "compiler-artifact" and item.get("executable") and item["target"]["name"] == "rss-mdm-fixture"]
        if len(executables) != 1: raise RuntimeError("cannot locate the tested fixture executable")
    product = run(["cargo", "build", "--locked", "-p", "rss-mdm-app", "--bin", "rss-mdm", "--message-format=json"], cwd=ROOT, capture_output=True)
    migrators = [item["executable"] for line in product.stdout.splitlines() if (item := json.loads(line)).get("reason") == "compiler-artifact" and item.get("executable") and item["target"]["name"] == "rss-mdm"]
    if len(migrators) != 1: raise RuntimeError("cannot locate product migrator")
    with context.cluster() as owner, owner.database() as database, tempfile.TemporaryDirectory(prefix='mdm-product-inputs-') as directory:
        root=Path(directory)
        for file in ('ca.crt','server.crt','server.key'):
            (root/file).write_bytes((owner.root/file).read_bytes())
        (root/'server.key').chmod(0o600)
        name=owner.container();port=owner.port()
        env = os.environ.copy()
        # Composed debug async tests include Audit ownership around existing business
        # frames. This is the Rust test thread stack, not a production runtime setting.
        env.setdefault('RUST_MIN_STACK', str(8 * 1024 * 1024))
        env.update(PG_CA_FILE=str(root / "ca.crt"), DATABASE_URL=f"postgres://mdm_runtime:runtime-fixture@localhost:{port}/{database}", MDM_OWNER_URL=f"postgres://mdm_owner:owner-fixture@localhost:{port}/{database}", MDM_ADMIN_URL=f"postgres://postgres:local-fixture@localhost:{port}/{database}")
        (root / "owner-password").write_text("owner-fixture")
        os.chmod(root / "owner-password", 0o600)
        migration_config = root / "migrate.json"
        migration_config.write_text(json.dumps({"installation":installation(),"database":{"host":"localhost","port":int(port),"name":database,"user":"mdm_owner","password_file":str(root/"owner-password"),"ca_file":str(root/"ca.crt")}}))
        os.chmod(migration_config, 0o600)
        if 'windows' in context.spec.fixtures:
            from windows_fixtures import generate
            generate(root, root/'server.crt', root/'server.key')
            env['MDM_WINDOWS_FIXTURES']=str(root)
        if 'apple' in context.spec.fixtures:
            from apple_fixtures import generate
            generate(root, root/'server.crt', root/'server.key')
            env['MDM_APPLE_FIXTURES']=str(root)
        if executables:env['MDM_FIXTURE_BIN']=executables[0]
        if 'unmigrated' not in context.spec.fixtures:
            with owner.phase('migrate'):
                run([migrators[0],'migrate','--config',str(migration_config)],env=env,cwd=ROOT,timeout=70)
        if 'identity' in context.spec.fixtures:
            with owner.phase('initialize'):
                configure_identity(root,port,migrators[0],env,database)
        env['MDM_TEST_PG_CONTAINER']=name
        from types import SimpleNamespace
        return scenario(SimpleNamespace(root=root,env=env,binary=migrators[0],migration_config=migration_config,
                        owner=owner,name=name,database=database,context=context))

def installation_tests(f):
    root,env,name,owner=f.root,f.env,f.name,f.owner
    run(["docker", "exec", name, "createdb", "-U", "postgres", "-O", "mdm_owner", "mdm_installation"], stdout=subprocess.DEVNULL, timeout=10)
    run(["docker", "exec", name, "createdb", "-U", "postgres", "-O", "mdm_owner", "mdm_installation_tasks"], stdout=subprocess.DEVNULL, timeout=10)
    run(["docker", "exec", "-i", name, "psql", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", f.database], input="GRANT CREATE ON DATABASE mdm_installation,mdm_installation_tasks TO mdm_audit_owner,mdm_ledger_owner;", stdout=subprocess.DEVNULL, timeout=10)
    upgrade = subprocess.run(["cargo", "test", "--locked", "-p", "rss-mdm-app", "--lib", "migration::tests::fresh_installation_replay_and_mismatch_rejection", "--", "--ignored"], pass_fds=lease_fds(), cwd=ROOT, env=env, capture_output=True, text=True)
    print(upgrade.stdout, end='', flush=True)
    require(upgrade.returncode == 0 and 'test migration::tests::fresh_installation_replay_and_mismatch_rejection ... ok' in upgrade.stdout and 'test result: ok. 1 passed; 0 failed; 0 ignored;' in upgrade.stdout, 'fresh installation test failed: ' + upgrade.stderr)
    verify_migrations(name, f.binary, f.migration_config, root, env)
    run_exact_test(env, "audit_integration_tests::installed_audit_receipts_replay_and_atomicity")
    run_exact_test(env, "audit_integration_tests::operation_cutoff_leaves_owner_time_to_rollback")
    return

def catalog(f):
    root,env,name,owner=f.root,f.env,f.name,f.owner
    from command_catalog import capture
    capture(name, 'check', f.database)
    return

def apple(f):
    root,env,name,owner=f.root,f.env,f.name,f.owner
    from apple_ca import running
    from apple_oracle import running as oracle
    with running(root, env), oracle(root, env):
        result=subprocess.run(['cargo','test','--locked','-p','rss-mdm-app','--features','integration','--lib','apple::','--','--ignored','--test-threads=1'],pass_fds=lease_fds(), cwd=ROOT,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        print(result.stdout,flush=True)
        print(result.stderr,file=sys.stderr,flush=True)
        expected={'apple::certificate::tests::cms_is_attached_and_independently_verified','apple::push::tests::production_transport_receipts_are_not_command_evidence','apple::tests::native_enrollment_collection_and_profile_lifecycle'}
        passed=set(re.findall(r'^test (\S+) \.\.\. ok$',result.stdout,re.MULTILINE))
        require(result.returncode==0 and passed==expected and 'test result: ok. 3 passed; 0 failed; 0 ignored;' in result.stdout,'Apple T2 failed or omitted required real protocol tests')
    return

def software(f):
    root,env,name,owner=f.root,f.env,f.name,f.owner
    result=subprocess.run(["cargo","test","--locked","-p","rss-mdm-app","--features","integration","--lib","identity_t2::software::","--","--ignored","--test-threads=1","--nocapture"],pass_fds=lease_fds(), cwd=ROOT,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    print(result.stdout,flush=True)
    require(result.returncode==0 and 'test result: ok. 1 passed; 0 failed; 0 ignored;' in result.stdout,'enterprise software T2 failed or did not execute')
    return

def tasks(f):
    root,env,name,owner=f.root,f.env,f.name,f.owner
    result=subprocess.run(["cargo","test","--locked","-p","rss-mdm-app","--features","integration","--lib","identity_t2::tasks::","--","--ignored","--test-threads=1","--nocapture"],pass_fds=lease_fds(), cwd=ROOT,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    print(result.stdout,flush=True)
    require(result.returncode==0 and 'test result: ok. 1 passed; 0 failed; 0 ignored;' in result.stdout,'enterprise task T2 failed or did not execute')
    return

def compliance(f):
    root,env,name,owner=f.root,f.env,f.name,f.owner
    command=["cargo","test","--locked","-p","rss-mdm-app","--features","integration","--lib","identity_t2::compliance::","--","--ignored","--test-threads=1","--nocapture"]
    with subprocess.Popen(command,pass_fds=lease_fds(),cwd=ROOT,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT) as process:
        lines=[]
        for line in process.stdout:
            print(line,end='',flush=True)
            lines.append(line)
        code=process.wait()
    require(code==0 and 'test result: ok. 1 passed; 0 failed; 0 ignored;' in ''.join(lines),'compliance Router/PG T2 failed or omitted')
    return

def assets(f):
    root,env,name,owner=f.root,f.env,f.name,f.owner
    result=subprocess.run(["cargo","test","--locked","-p","rss-mdm-app","--features","integration","--lib","identity_t2::assets::","--","--ignored","--test-threads=1"],pass_fds=lease_fds(), cwd=ROOT,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    print(result.stdout,flush=True)
    require(result.returncode==0 and 'test identity_t2::assets::asset_write_query_group_and_isolation ... ok' in result.stdout and 'test result: ok. 1 passed; 0 failed; 0 ignored;' in result.stdout,'asset Router/PG T2 failed')
    return

def commands(f):
    root,env,name,owner=f.root,f.env,f.name,f.owner
    result=subprocess.run(["cargo","test","--locked","-p","rss-mdm-app","--features","integration","--lib","windows::tests::native_command_operations_and_observation","--","--ignored","--nocapture","--test-threads=1"],pass_fds=lease_fds(), cwd=ROOT,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    print(result.stdout,flush=True)
    require(result.returncode==0 and 'test result: ok. 1 passed; 0 failed; 0 ignored;' in result.stdout,'command T2 failed or did not run')
    diagnostics=[json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
    require(any(item.get('event')=='mdm_command_recovery_failure' and item.get('phase')=='runner' and item.get('reason')=='StorageContract' for item in diagnostics),'fatal recovery diagnostic was not emitted')
    return

def identity(f):
    root,env,name,owner=f.root,f.env,f.name,f.owner
    run_exact_test(env, "identity_audit::tests::http_events_deliver_replay_and_fail_closed")
    from t2_suites import sources as source
    source_root=root/'source';source_root.mkdir()
    env.update(source.tls_environment(source_root))
    run(["cargo","test","--locked","-p","rss-mdm-app","--features","integration","--lib","identity_t2::authorization::","--","--ignored","--test-threads=1","--nocapture"],cwd=ROOT,env=env)
    run(["cargo","test","--locked","-p","rss-mdm-app","--features","integration","--lib","identity_t2::local_identity_mdm_authorization_and_revocation","--","--ignored","--test-threads=1","--nocapture"],cwd=ROOT,env=env)
    from enterprise_idp import fixture as enterprise
    with enterprise(root, owner) as provider:
        run(["cargo","test","--locked","-p","rss-mdm-app","--features","integration","--lib","identity_t2::sso::","--","--ignored","--test-threads=1","--nocapture"],cwd=ROOT,env={**env,**provider})
    return

def foundation(f):
    root,env,name,owner=f.root,f.env,f.name,f.owner
    verify_startup_deadlines(f.binary,root,env)
    run_foundation_tests(env)
    for selected in ["api::tests::audit_failure_logs_preserve_action_and_origin", "api::tests::request_diagnostics_keep_causes_internal_and_issue_request_ids"]:
        run_exact_test(env, selected)
    run(["cargo", "test", "--locked", "-p", "inventory-postgres-integration", "--features", "integration", "--test", "t2"], cwd=ROOT, env=env)
    run(["cargo","test","--locked","-p","rss-mdm-app","--test","postgres","--","--ignored"],cwd=ROOT,env=env)
    return

def windows(f):
    root,env,name,owner=f.root,f.env,f.name,f.owner
    windows=subprocess.run(["cargo","test","--locked","-p","rss-mdm-app","--features","integration","--lib","windows::tests","--","--ignored","--test-threads=1","--skip","windows::tests::native_command_operations_and_observation"],pass_fds=lease_fds(),cwd=ROOT,env=env,text=True,capture_output=True)
    print(windows.stdout,flush=True)
    require(windows.returncode == 0, windows.stderr)
    verify_windows_result(windows.stdout)
    return
