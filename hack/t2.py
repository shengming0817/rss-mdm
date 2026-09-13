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

IMAGE = "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777"
ROOT = Path(__file__).resolve().parents[1]

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
    # Install the unchanged F02/I01 schema and history before applying the new unit.
    import hashlib
    sql("SET ROLE mdm_owner; CREATE TABLE public.mdm_migrations(name text PRIMARY KEY,digest text NOT NULL,complete boolean NOT NULL DEFAULT false)")
    for unit, filename in [('access-v1','0001_access.sql'),('access-audit-request-index-v1','0002_audit_request_index.sql'),('device-identity-v1','0003_device_identity.sql')]:
        content=(ROOT/'crates/app/migrations'/filename).read_text()
        sql('SET ROLE mdm_owner; '+content)
        digest=hashlib.sha256(content.encode()).hexdigest()
        sql("INSERT INTO public.mdm_migrations VALUES('"+unit+"','"+digest+"',true)")
    legacy='eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'
    sql(f"INSERT INTO mdm_access.grants(tenant_id,id,actor,client,device,purpose,state,expires_at) VALUES('{legacy}','00000000-0000-4000-8000-000000000001','legacy','mdm','legacy-device','enrollment','available',clock_timestamp()+interval '200 seconds'),('{legacy}','00000000-0000-4000-8000-000000000002','legacy','mdm','legacy-device','enrollment','consumed',clock_timestamp()+interval '200 seconds'); INSERT INTO mdm_access.requests VALUES('{legacy}','00000000-0000-4000-8000-000000000003','00000000-0000-4000-8000-000000000002'); INSERT INTO mdm_access.devices VALUES('{legacy}','legacy-device'); INSERT INTO mdm_access.registrations VALUES('{legacy}','00000000-0000-4000-8000-000000000004','legacy-device','mdm',1,'00000000-0000-4000-8000-000000000003','active'); INSERT INTO mdm_access.credentials VALUES('{legacy}','00000000-0000-4000-8000-000000000005','00000000-0000-4000-8000-000000000004','mdm',repeat('e',64),'active'); INSERT INTO mdm_access.audit(tenant_id,id,request_id,action,result,status) VALUES('{legacy}','00000000-0000-4000-8000-000000000006','00000000-0000-4000-8000-000000000007','registration_accept','success',200); INSERT INTO mdm_access.operations VALUES('{legacy}','legacy','mdm','00000000-0000-4000-8000-000000000008',repeat('e',64),'history');")
    before=sql(f"SELECT row_to_json(a) FROM mdm_access.audit a WHERE tenant_id='{legacy}'")
    migrate(); migrate()
    require(sql(f"SELECT count(*) FROM mdm_access.grants WHERE tenant_id='{legacy}' AND state='available'")=='0','legacy grant remains usable')
    require(sql(f"SELECT state='cancelled' AND issuance_operation IS NULL AND password_digest IS NULL FROM mdm_access.requests WHERE tenant_id='{legacy}'")=='t','legacy request gained enrollment authority')
    require(sql(f"SELECT state FROM mdm_access.registrations WHERE tenant_id='{legacy}'")=='active','historical registration changed')
    require(sql(f"SELECT state FROM mdm_access.credentials WHERE tenant_id='{legacy}'")=='active','historical credential changed')
    require(before==sql(f"SELECT row_to_json(a) FROM mdm_access.audit a WHERE tenant_id='{legacy}'"),'historical audit changed')
    require(sql(f"SELECT result FROM mdm_access.operations WHERE tenant_id='{legacy}'")=='history','historical operation changed')
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
        require(sql("SELECT count(*) FROM public.mdm_migrations WHERE complete") == "14", "migration invariant rejected")
    finally:
        sql("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='mdm-t2-migration-lock'")
        holder.wait(timeout=5)
        for child in children:
            if child.poll() is None: child.terminate();child.wait(timeout=5)
    print("migration admission, immutable digest, interrupted ledger and concurrent installers passed",flush=True)

def verify_startup_deadlines(binary, root, port, env):
    import socket
    config=json.loads((ROOT/'fixtures/mdm-config.example.json').read_text())
    for name,value in [('api-password','api-fixture'),('access-password','access-fixture'),('runtime-password','runtime-fixture'),('oidc-secret','o'*40),('validation-secret','v'*40)]:
        (root/name).write_text(value);os.chmod(root/name,0o600)
    config['database']={'host':'localhost','port':int(port),'name':'mdm_test','user':'mdm_api','password_file':str(root/'api-password'),'ca_file':str(root/'ca.crt')}
    config['access_database']={**config['database'],'user':'mdm_access','password_file':str(root/'access-password')}
    config['runtime_database']={**config['database'],'user':'mdm_runtime','password_file':str(root/'runtime-password')}
    config['identity'].update(oidc_secret_file=str(root/'oidc-secret'),validation_secret_file=str(root/'validation-secret'),ca_file=str(root/'ca.crt'))
    config["windows"]=json.loads((root/"windows.json").read_text())
    runtime_password = config['runtime_database']['password_file']
    config['runtime_database']['password_file'] = str(root/'missing-runtime-password')
    invalid_runtime = root/'invalid-runtime.json'
    invalid_runtime.write_text(json.dumps(config)); invalid_runtime.chmod(0o600)
    result = subprocess.run([binary, 'serve', '--config', str(invalid_runtime)], cwd=ROOT, env=env, capture_output=True, text=True, timeout=22)
    require(result.returncode != 0 and 'startup.runtime_database_configuration' in result.stderr,
            'runtime database input lost its startup stage: ' + result.stderr)
    config['runtime_database']['password_file'] = runtime_password
    for stage in ['database','identity']:
        with socket.socket() as stalled:
            stalled.bind(('127.0.0.1',0));stalled.listen(8)
            stalled_port=stalled.getsockname()[1]
            config['database']['port']=stalled_port if stage=='database' else int(port)
            config['access_database']['port']=config['database']['port']
            config['runtime_database']['port']=config['database']['port']
            config['identity']['issuer']='https://localhost:'+str(stalled_port)+'/oidc'
            path=root/'stalled.json';path.write_text(json.dumps(config));os.chmod(path,0o600)
            start=time.monotonic()
            result=subprocess.run([binary,'serve','--config',str(path)],cwd=ROOT,env=env,capture_output=True,text=True,timeout=22)
            require(result.returncode != 0 and time.monotonic()-start < 21, 'startup dependency stall escaped total budget')
            expected='startup.reader_connection_or_admission' if stage=='database' else 'startup.identity'
            require(expected in result.stderr, 'startup failure lost safe stage classification: ' + result.stderr)
            require('api-fixture' not in result.stderr and 'o'*40 not in result.stderr, 'startup diagnostics exposed credentials')
    print('startup dependency stalls rejected within budget with safe stage diagnostics',flush=True)

def main():
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
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=MDM T2 CA", "-keyout", str(root / "ca.key"), "-out", str(root / "ca.crt")], **quiet)
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
            sql += (ROOT/'crates/app/schema/software-publication-roles.sql').read_text()
            run(["docker", "exec", "-i", name, "psql", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "mdm_test"], input=sql, stdout=subprocess.DEVNULL, timeout=15)
            env = os.environ.copy()
            env.update(MDM_FIXTURE_BIN=executables[0], PG_CA_FILE=str(root / "ca.crt"), DATABASE_URL=f"postgres://mdm_runtime:runtime-fixture@localhost:{port}/mdm_test", MDM_OWNER_URL=f"postgres://mdm_owner:owner-fixture@localhost:{port}/mdm_test", MDM_ADMIN_URL=f"postgres://postgres:local-fixture@localhost:{port}/mdm_test")
            (root / "owner-password").write_text("owner-fixture")
            os.chmod(root / "owner-password", 0o600)
            migration_config = root / "migrate.json"
            migration_config.write_text(json.dumps({"database":{"host":"localhost","port":int(port),"name":"mdm_test","user":"mdm_owner","password_file":str(root/"owner-password"),"ca_file":str(root/"ca.crt")}}))
            os.chmod(migration_config, 0o600)
            from windows_fixtures import generate
            generate(root, root/'server.crt', root/'server.key')
            env['MDM_WINDOWS_FIXTURES']=str(root)
            run(["docker", "exec", name, "createdb", "-U", "postgres", "-O", "mdm_owner", "mdm_upgrade"], stdout=subprocess.DEVNULL, timeout=10)
            upgrade = subprocess.run(["cargo", "test", "--locked", "-p", "rss-mdm-app", "--lib", "migration::tests::populated_windows_upgrade", "--", "--ignored"], cwd=ROOT, env=env, capture_output=True, text=True)
            print(upgrade.stdout, end='', flush=True)
            require(upgrade.returncode == 0 and 'test result: ok. 1 passed; 0 failed; 0 ignored;' in upgrade.stdout, 'populated Windows migration test failed: ' + upgrade.stderr)
            verify_migrations(name, migrators[0], migration_config, root, env)
            if not device_only and not windows_only:
                verify_startup_deadlines(migrators[0],root,port,env)
            print(json.dumps({"provider": IMAGE, "tls": "verify-full", "runtime": "NOSUPERUSER NOBYPASSRLS"}), flush=True)
            if not device_only and not windows_only:
                run(["cargo", "test", "--locked", "-p", "inventory-postgres-integration", "--features", "integration", "--test", "t2", *sys.argv[1:]], cwd=ROOT, env=env)
                run(["cargo","test","--locked","-p","rss-mdm-app","--test","postgres","--","--ignored"],cwd=ROOT,env=env)
            from device_t2 import identities
            with identities(root) as origin:
                windows=subprocess.run(["cargo","test","--locked","-p","rss-mdm-app","--features","integration","--lib","windows::tests","--","--ignored","--test-threads=1"],cwd=ROOT,env={**env,"MDM_TEST_IDENTITY":origin},text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                print(windows.stdout,end='',flush=True)
                require(windows.returncode == 0, 'Windows T2 failed')
                verify_windows_result(windows.stdout)
                collection=subprocess.run(["cargo","test","--locked","-p","rss-mdm-app","--features","integration","--lib","inventory_runtime::tests::durable_report_recovery_and_projection","--","--ignored","--nocapture","--test-threads=1"],cwd=ROOT,env={**env,"MDM_TEST_IDENTITY":origin},text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                print(collection.stdout,end='',flush=True)
                require(collection.returncode == 0 and 'test result: ok. 1 passed; 0 failed; 0 ignored;' in collection.stdout, 'collection recovery T2 did not execute successfully')
                require('"event":"mdm_inventory_failure"' in collection.stdout and '"phase":"projection_run"' in collection.stdout,
                        'worker failure lost its safe phase diagnostic')
                if not windows_only: run(["cargo","test","--locked","-p","rss-mdm-app","--features","integration","--lib","device::tests::postgres_boundary","--","--ignored","--test-threads=1"],cwd=ROOT,env={**env,"MDM_TEST_IDENTITY":origin})
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
