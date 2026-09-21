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

ROOT = Path(__file__).resolve().parents[1]
IMAGE = json.loads((ROOT / "deployment/providers.lock.json").read_text())["postgres"]

def require(condition,message):
    if not condition:raise RuntimeError(message)

def run(args, **kw):
    return subprocess.run(args, check=True, text=True, **kw)

def verify_windows_result(output):
    expected={
        'windows::tests::issuance_recovery_and_enrollment_boundaries',
        'windows::tests::native_tls_enrollment_management_replay_and_revoke',
    }
    passed=set(re.findall(r'^test (\S+) \.\.\. ok$',output,re.MULTILINE))
    require(passed==expected and 'test result: ok. 2 passed; 0 failed; 0 ignored;' in output,
            'Windows T2 did not execute both required protocol/recovery tests')

def verify_migrations(container, binary, config, root, env):
    def sql(statement):
        return run(["docker", "exec", "-i", container, "psql", "-At", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "mdm_test"], input=statement, capture_output=True, timeout=10).stdout.strip()
    def migrate(path=config, accepted=True):
        result = subprocess.run([binary,"migrate","--config",str(path)],cwd=ROOT,env=env,capture_output=True,text=True,timeout=70)
        if (result.returncode == 0) != accepted:
            raise RuntimeError("migration admission/ledger expectation failed: " + result.stderr)
    admin = json.loads(config.read_text())
    (root/"admin-password").write_text("local-fixture"); os.chmod(root/"admin-password",0o600)
    admin["database"].update(user="postgres",password_file=str(root/"admin-password"))
    admin_config=root/"admin-migrate.json";admin_config.write_text(json.dumps(admin));os.chmod(admin_config,0o600)
    migrate(admin_config,accepted=False)
    require(sql("SELECT to_regclass('public.mdm_migrations') IS NULL") == "t", "rejected migrator performed DDL")
    migrate(); migrate()
    # Force index eligibility on the tiny fixture; this is not a throughput claim.
    plan = json.loads(sql("SET enable_seqscan=off; EXPLAIN (FORMAT JSON) SELECT id FROM mdm_access.audit WHERE tenant_id='11111111-1111-4111-8111-111111111111' AND request_id='22222222-2222-4222-8222-222222222222'").removeprefix("SET\n"))
    require('request_id' in json.dumps(plan[0]['Plan'].get('Index Cond', '')), 'request-id lookup lacks an index condition')
    original = sql("SELECT digest FROM public.mdm_migrations WHERE name='inventory-v1'")
    import hashlib
    require(original == hashlib.sha256((ROOT/'crates/inventory-postgres/migrations/0001_inventory.sql').read_bytes()).hexdigest(), "migration invariant rejected")
    for change in ["complete=false", "digest=repeat('0',64)"]:
        sql("UPDATE public.mdm_migrations SET " + change + " WHERE name='inventory-v1'")
        migrate(accepted=False)
        sql("UPDATE public.mdm_migrations SET complete=true,digest='" + original + "' WHERE name='inventory-v1'")
    # An owned holder makes both independent installers visibly wait before release.
    holder = subprocess.Popen(["docker","exec","-e","PGAPPNAME=mdm-t2-migration-lock",container,"psql","-U","postgres","-d","mdm_test","-c","SELECT pg_advisory_lock(2346); SELECT pg_sleep(30)"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    children=[]
    try:
        deadline=time.monotonic()+5
        while sql("SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND objid=2346 AND granted") != "1":
            if time.monotonic()>deadline: raise RuntimeError("migration lock holder deadline")
            time.sleep(.1)
        children=[subprocess.Popen([binary,"migrate","--config",str(config)],cwd=ROOT,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True) for _ in range(2)]
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
    result = subprocess.run([binary, 'serve', '--config', str(invalid_runtime)], cwd=ROOT, env=env, capture_output=True, text=True, timeout=22)
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
        for key in ['database','access_database','runtime_database','command_database']:
            config[key]['port']=stalled_port
        for key in ['database','publication_database']:
            config['management'][key]['port']=stalled_port
        config['identity']['database']['port']=stalled_port
        path=root/'stalled.json';path.write_text(json.dumps(config));path.chmod(0o600)
        start=time.monotonic()
        result=subprocess.run([binary,'serve','--config',str(path)],cwd=ROOT,env=env,capture_output=True,text=True,timeout=22)
        verify(result,start,'startup.reader_connection_or_admission')
    # Keep the same physical PG identity required by production configuration.
    # This table is probed only by Identity; the earlier product stores remain healthy.
    container=env['MDM_TEST_PG_CONTAINER']
    def sql(statement):
        return run(['docker','exec',container,'psql','-X','-At','-v','ON_ERROR_STOP=1','-U','postgres','-d','mdm_test','-c',statement],capture_output=True,timeout=5).stdout.strip()
    holder=subprocess.Popen(['docker','exec','-e','PGAPPNAME=mdm-t2-identity-startup-holder',container,'psql','-X','-v','ON_ERROR_STOP=1','-U','postgres','-d','mdm_test','-c',
        'BEGIN; LOCK TABLE identity_authority.deployment IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(60); ROLLBACK;'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    child=None
    try:
        end=time.monotonic()+5
        while sql("SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a USING(pid) WHERE a.application_name='mdm-t2-identity-startup-holder' AND l.relation='identity_authority.deployment'::regclass AND l.mode='AccessExclusiveLock' AND l.granted") != '1':
            require(holder.poll() is None and time.monotonic()<end,'identity startup lock holder deadline')
            time.sleep(.1)
        start=time.monotonic()
        child=subprocess.Popen([binary,'serve','--config',str(root/'runtime.json')],cwd=ROOT,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
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

INSTANCE = '33333333-3333-4333-8333-333333333333'
ADMIN = '44444444-4444-4444-8444-444444444444'
TENANTS = ['11111111-1111-4111-8111-111111111111','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb']

def installation():
    return dict(instance_id=INSTANCE,target=[1]*16,lineage=[2]*16,epoch=1,tenants=TENANTS)

def configure_identity(root, port, binary, env):
    def write(name, value):
        path=root/name;path.write_text(value if isinstance(value,str) else json.dumps(value));path.chmod(0o600);return str(path)
    config=json.loads((ROOT/'fixtures/mdm-config.example.json').read_text())
    def database(role, password):
        return dict(host='localhost',port=int(port),name='mdm_test',user=role,password_file=write(role+'-password',password),ca_file=str(root/'ca.crt'))
    for key,role,password in [('database','mdm_api','api-fixture'),('access_database','mdm_access','access-fixture'),('runtime_database','mdm_runtime','runtime-fixture')]:config[key]=database(role,password)
    config['identity']['database']=database('mdm_identity_runtime','identity-runtime-fixture')
    config['management']['database']=database('mdm_management_runtime','runtime-fixture')
    config['command_database']=database('mdm_command_runtime','runtime-fixture')
    config['management']['publication_database']=database('mdm_software_driver','runtime-fixture')
    config['windows']=json.loads((root/'windows.json').read_text())
    config['identity_management']=[dict(tenant_id=TENANTS[0],instance_id=INSTANCE,principal_id=ADMIN,permissions=['accounts','providers'])]
    env['MDM_TEST_CONFIG']=write('runtime.json',config)
    maintenance=database('mdm_identity_maintenance','identity-maintenance-fixture')
    password=write('account-password','Fixture-only-correct-horse-battery-2026!')
    for tenant in TENANTS:
        path=write('initialize.json',dict(database=maintenance,installation=installation(),tenant_id=tenant,principal_id=ADMIN,login='admin',password_file=password))
        result=subprocess.run([binary,'initialize','--config',path],env=env,cwd=ROOT,text=True,capture_output=True,timeout=30)
        require(result.returncode==0,'component initialization failed: '+result.stderr)
    run(['cargo','test','--locked','-p','rss-mdm-app','--lib','identity_fixture::seed_accounts','--','--ignored'],env=env,cwd=ROOT)

def main(identity_only=False,command_only=False,catalog_mode=None):
    device_only = sys.argv[1:] == ["--device"]
    windows_only = sys.argv[1:] == ["--windows"]
    build = run(["cargo", "build", "--locked", "-p", "rss-mdm-examples", "--bin", "rss-mdm-fixture", "--message-format=json"], cwd=ROOT, capture_output=True)
    executables = [item["executable"] for line in build.stdout.splitlines() if (item := json.loads(line)).get("reason") == "compiler-artifact" and item.get("executable") and item["target"]["name"] == "rss-mdm-fixture"]
    if len(executables) != 1: raise RuntimeError("cannot locate the tested fixture executable")
    product = run(["cargo", "build", "--locked", "-p", "rss-mdm-app", "--bin", "rss-mdm", "--message-format=json"], cwd=ROOT, capture_output=True)
    migrators = [item["executable"] for line in product.stdout.splitlines() if (item := json.loads(line)).get("reason") == "compiler-artifact" and item.get("executable") and item["target"]["name"] == "rss-mdm"]
    if len(migrators) != 1: raise RuntimeError("cannot locate product migrator")
    name = "mdm-t2-" + uuid.uuid4().hex[:12]
    with tempfile.TemporaryDirectory(prefix="mdm-pg-") as directory:
        root = Path(directory)
        quiet = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL, "timeout": 20}
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=MDM T2 CA", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", str(root / "ca.key"), "-out", str(root / "ca.crt")], **quiet)
        run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost", "-keyout", str(root / "server.key"), "-out", str(root / "server.csr")], **quiet)
        (root / "extensions").write_text("basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n")
        run(["openssl", "x509", "-req", "-in", str(root / "server.csr"), "-CA", str(root / "ca.crt"), "-CAkey", str(root / "ca.key"), "-CAcreateserial", "-days", "1", "-extfile", str(root / "extensions"), "-out", str(root / "server.crt")], **quiet)
        os.chmod(root / "server.key", 0o644)  # disposable fixture key; copied/chmod 0600 in container
        try:
            run(["docker", "run", "-d", "--rm", "--name", name, "-p", "127.0.0.1::5432", "-v", f"{root}:/certs:ro", "-e", "POSTGRES_PASSWORD=local-fixture", "-e", "POSTGRES_DB=mdm_test", IMAGE, "sh", "-c", "cp /certs/server.key /tmp/server.key; cp /certs/server.crt /tmp/server.crt; chown postgres:postgres /tmp/server.*; chmod 600 /tmp/server.key; exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key"], stdout=subprocess.DEVNULL, timeout=120)
            end = time.monotonic() + 45
            while True:
                ready = subprocess.run(["docker", "exec", name, "pg_isready", "-U", "postgres", "-d", "mdm_test"], capture_output=True, timeout=5)
                if ready.returncode == 0:
                    # pg_isready can see initdb's temporary socket server. Require host TCP below.
                    port = run(["docker", "port", name, "5432"], capture_output=True, timeout=5).stdout.strip().rsplit(":", 1)[1]
                    probe = subprocess.run(["docker", "exec", name, "pg_isready", "-h", "127.0.0.1", "-U", "postgres", "-d", "mdm_test"], capture_output=True, timeout=5)
                    if probe.returncode == 0: break
                if time.monotonic() > end: raise RuntimeError("PostgreSQL startup deadline")
                time.sleep(0.2)
            sql = "CREATE ROLE mdm_owner LOGIN PASSWORD 'owner-fixture' NOSUPERUSER NOBYPASSRLS; CREATE ROLE mdm_runtime LOGIN PASSWORD 'runtime-fixture' NOSUPERUSER NOBYPASSRLS; CREATE ROLE mdm_api LOGIN PASSWORD 'api-fixture' NOSUPERUSER NOBYPASSRLS; CREATE ROLE mdm_access LOGIN PASSWORD 'access-fixture' NOSUPERUSER NOBYPASSRLS; GRANT CREATE ON DATABASE mdm_test TO mdm_owner; GRANT CREATE ON SCHEMA public TO mdm_owner;"
            sql += ((ROOT/'crates/app/schema/software-publication-roles.sql').read_text()+(ROOT/'crates/app/schema/management-roles.sql').read_text()+(ROOT/'crates/app/schema/commands-roles.sql').read_text()+(ROOT/'crates/app/schema/identity-roles.sql').read_text())
            sql += "ALTER ROLE mdm_management_runtime LOGIN PASSWORD 'runtime-fixture'; ALTER ROLE mdm_command_runtime LOGIN PASSWORD 'runtime-fixture'; ALTER ROLE mdm_software_driver LOGIN PASSWORD 'runtime-fixture'; ALTER ROLE mdm_identity_runtime LOGIN PASSWORD 'identity-runtime-fixture'; ALTER ROLE mdm_identity_maintenance LOGIN PASSWORD 'identity-maintenance-fixture';"
            run(["docker", "exec", "-i", name, "psql", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "mdm_test"], input=sql, stdout=subprocess.DEVNULL, timeout=15)
            env = os.environ.copy()
            env.update(MDM_FIXTURE_BIN=executables[0], PG_CA_FILE=str(root / "ca.crt"), DATABASE_URL=f"postgres://mdm_runtime:runtime-fixture@localhost:{port}/mdm_test", MDM_OWNER_URL=f"postgres://mdm_owner:owner-fixture@localhost:{port}/mdm_test", MDM_ADMIN_URL=f"postgres://postgres:local-fixture@localhost:{port}/mdm_test")
            (root / "owner-password").write_text("owner-fixture")
            os.chmod(root / "owner-password", 0o600)
            migration_config = root / "migrate.json"
            migration_config.write_text(json.dumps({"installation":installation(),"database":{"host":"localhost","port":int(port),"name":"mdm_test","user":"mdm_owner","password_file":str(root/"owner-password"),"ca_file":str(root/"ca.crt")}}))
            os.chmod(migration_config, 0o600)
            from windows_fixtures import generate
            generate(root, root/'server.crt', root/'server.key')
            env['MDM_WINDOWS_FIXTURES']=str(root)
            run(["docker", "exec", name, "createdb", "-U", "postgres", "-O", "mdm_owner", "mdm_installation"], stdout=subprocess.DEVNULL, timeout=10)
            upgrade = subprocess.run(["cargo", "test", "--locked", "-p", "rss-mdm-app", "--lib", "migration::tests::fresh_installation_replay_and_mismatch_rejection", "--", "--ignored"], cwd=ROOT, env=env, capture_output=True, text=True)
            print(upgrade.stdout, end='', flush=True)
            require(upgrade.returncode == 0 and 'test migration::tests::fresh_installation_replay_and_mismatch_rejection ... ok' in upgrade.stdout and 'test result: ok. 1 passed; 0 failed; 0 ignored;' in upgrade.stdout, 'fresh installation test failed: ' + upgrade.stderr)
            verify_migrations(name, migrators[0], migration_config, root, env)
            if catalog_mode:
                from command_catalog import capture
                capture(name, catalog_mode)
                return
            configure_identity(root, port, migrators[0], env)
            env['MDM_TEST_PG_CONTAINER'] = name
            if command_only:
                result=subprocess.run(["cargo","test","--locked","-p","rss-mdm-app","--features","integration","--lib","windows::tests::native_command_operations_and_observation","--","--ignored","--nocapture","--test-threads=1"],cwd=ROOT,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                print(result.stdout,flush=True)
                require(result.returncode==0 and 'test result: ok. 1 passed; 0 failed; 0 ignored;' in result.stdout,'command T2 failed or did not run')
                diagnostics=[json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
                require(any(item.get('event')=='mdm_command_recovery_failure' and item.get('phase')=='runner' and item.get('reason')=='StorageContract' for item in diagnostics),'fatal recovery diagnostic was not emitted')
                return
            if identity_only:
                import importlib.util
                spec=importlib.util.spec_from_file_location('mdm_source_t2', ROOT/'hack/source-t2.py');source=importlib.util.module_from_spec(spec);spec.loader.exec_module(source)
                source_root=root/'source';source_root.mkdir()
                env.update(source.tls_environment(source_root))
                run(["cargo","test","--locked","-p","rss-mdm-app","--features","integration","--lib","identity_t2::authorization::","--","--ignored","--test-threads=1","--nocapture"],cwd=ROOT,env=env)
                run(["cargo","test","--locked","-p","rss-mdm-app","--features","integration","--lib","identity_t2::local_identity_mdm_authorization_and_revocation","--","--ignored","--test-threads=1","--nocapture"],cwd=ROOT,env=env)
                from enterprise_idp import fixture as enterprise
                with enterprise(root) as provider:
                    run(["cargo","test","--locked","-p","rss-mdm-app","--features","integration","--lib","identity_t2::sso::","--","--ignored","--test-threads=1","--nocapture"],cwd=ROOT,env={**env,**provider})
                return
            if not device_only and not windows_only and not identity_only:
                verify_startup_deadlines(migrators[0],root,env)
            print(json.dumps({"provider": IMAGE, "tls": "verify-full", "runtime": "NOSUPERUSER NOBYPASSRLS"}), flush=True)
            if not device_only and not windows_only and not identity_only:
                run(["cargo", "test", "--locked", "-p", "inventory-postgres-integration", "--features", "integration", "--test", "t2", *sys.argv[1:]], cwd=ROOT, env=env)
                run(["cargo","test","--locked","-p","rss-mdm-app","--test","postgres","--","--ignored"],cwd=ROOT,env=env)
            windows=subprocess.run(["cargo","test","--locked","-p","rss-mdm-app","--features","integration","--lib","windows::tests","--","--ignored","--test-threads=1","--skip","windows::tests::native_command_operations_and_observation"],cwd=ROOT,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            print(windows.stdout,end='',flush=True)
            require(windows.returncode == 0, 'Windows T2 failed')
            verify_windows_result(windows.stdout)
            collection=subprocess.run(["cargo","test","--locked","-p","rss-mdm-app","--features","integration","--lib","inventory_runtime::tests::durable_report_recovery_and_projection","--","--ignored","--nocapture","--test-threads=1"],cwd=ROOT,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            print(collection.stdout,end='',flush=True)
            require(collection.returncode == 0 and 'test result: ok. 1 passed; 0 failed; 0 ignored;' in collection.stdout, 'collection recovery T2 did not execute successfully')
            require('"event":"mdm_inventory_failure"' in collection.stdout and '"phase":"projection_run"' in collection.stdout,
                    'worker failure lost its safe phase diagnostic')
            if not windows_only: run(["cargo","test","--locked","-p","rss-mdm-app","--features","integration","--lib","device::tests::postgres_boundary","--","--ignored","--test-threads=1"],cwd=ROOT,env=env)
        finally:
            primary = sys.exception()
            try:
                result = subprocess.run(["docker", "rm", "-f", name], capture_output=True, text=True, timeout=20)
                if result.returncode:
                    raise RuntimeError("disposable PostgreSQL container cleanup failed")
            except Exception as cleanup:
                if primary is None:
                    raise
                primary.add_note(str(cleanup))

if __name__ == "__main__": main()
