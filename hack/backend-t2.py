#!/usr/bin/env python3
"""Disposable TLS PG for N10/N11; no missing-service skips and no production setup."""
import argparse,contextlib,json,os,re,subprocess,sys,tempfile,time,uuid
from pathlib import Path
from t2 import IMAGE,run,require
ROOT=Path(__file__).resolve().parents[1]
NAMES=('policy','resource','software-release')
SCHEMAS=('mdm_policy','mdm_resource','mdm_software_release')
CONSUMERS={
 'policy':{'admission_rejects_noninherited_switchable_privileges','fact_pages_preserve_boundaries_and_reject_foreign_documents','persistence_replay_aba_and_old_facts','concurrent_cas_borrowed_rollback_and_runtime_owner','outbox_failure_and_immutable_inputs'},
 'resource':{'admission_rejects_noninherited_switchable_privileges','resource_admission_rejects_schema_and_privilege_drift','resource_immutable_versions_restart_and_reference_rollback','resource_cas_events_and_owner_admission'},
 'software-release':{'admission_rejects_noninherited_switchable_privileges','release_approval_unknown_retry_history_and_late_results','release_immutable_version_request_uniqueness_and_rollback','release_event_failure_and_runtime_admission'},
}
def verify_tests(output,expected):
    actual=set(re.findall(r'^test (\S+) \.\.\. ok$',output,re.MULTILINE))
    require(actual==expected and f'test result: ok. {len(expected)} passed; 0 failed; 0 ignored;' in output, 'backend T2 missing required behavior')
@contextlib.contextmanager
def fixture(source=ROOT,write_catalogs=False,app=False,migrations=None):
    with tempfile.TemporaryDirectory(prefix='mdm-backend-pg-') as directory:
        root=Path(directory);quiet=dict(stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
        run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=Backend T2 CA','-keyout',str(root/'ca.key'),'-out',str(root/'ca.crt')],**quiet)
        run(['openssl','req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=localhost','-keyout',str(root/'server.key'),'-out',str(root/'server.csr')],**quiet)
        (root/'ext').write_text('basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n')
        run(['openssl','x509','-req','-in',str(root/'server.csr'),'-CA',str(root/'ca.crt'),'-CAkey',str(root/'ca.key'),'-CAcreateserial','-days','1','-extfile',str(root/'ext'),'-out',str(root/'server.crt')],**quiet)
        (root/'server.key').chmod(0o644)
        name='mdm-backend-'+uuid.uuid4().hex[:12]
        def sql(statement):
            return run(['docker','exec','-i',name,'psql','-At','-v','ON_ERROR_STOP=1','-U','postgres','-d','backend'],input=statement,capture_output=True,timeout=30).stdout.strip()
        try:
            run(['docker','run','-d','--rm','--name',name,'-p','127.0.0.1::5432','-v',f'{root}:/certs:ro','-e','POSTGRES_PASSWORD=admin-fixture','-e','POSTGRES_DB=backend',IMAGE,'sh','-c','cp /certs/server.key /tmp/server.key; cp /certs/server.crt /tmp/server.crt; chown postgres:postgres /tmp/server.*; chmod 600 /tmp/server.key; exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key'],stdout=subprocess.DEVNULL,timeout=120)
            until=time.monotonic()+45
            while True:
                if subprocess.run(['docker','exec',name,'pg_isready','-h','127.0.0.1','-U','postgres','-d','backend'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5).returncode==0:break
                require(time.monotonic()<until,'backend PG startup deadline');time.sleep(.2)
            port=int(run(['docker','port',name,'5432'],capture_output=True,timeout=5).stdout.strip().rsplit(':',1)[1])
            sql("CREATE ROLE mdm_owner LOGIN PASSWORD 'owner-fixture' NOSUPERUSER NOBYPASSRLS; GRANT CREATE ON DATABASE backend TO mdm_owner; GRANT CREATE ON SCHEMA public TO mdm_owner;")
            sql(((source/'crates/app/schema/software-publication-roles.sql').read_text()+(source/'crates/app/schema/management-roles.sql').read_text()+(source/'crates/app/schema/commands-roles.sql').read_text()))
            for schema in SCHEMAS:sql(f"ALTER ROLE {schema}_runtime LOGIN PASSWORD 'backend-fixture';")
            if app:
                sql((source/'crates/app/schema/identity-roles.sql').read_text())
                sql("ALTER ROLE mdm_management_runtime LOGIN PASSWORD 'backend-fixture'; ALTER ROLE mdm_command_runtime LOGIN PASSWORD 'backend-fixture';")
                sql("ALTER ROLE mdm_software_driver LOGIN PASSWORD 'backend-fixture'; CREATE ROLE mdm_runtime LOGIN PASSWORD 'runtime-fixture' NOSUPERUSER NOBYPASSRLS; CREATE ROLE mdm_api LOGIN PASSWORD 'api-fixture' NOSUPERUSER NOBYPASSRLS; CREATE ROLE mdm_access LOGIN PASSWORD 'access-fixture' NOSUPERUSER NOBYPASSRLS;")
                password=root/'owner-password';password.write_text('owner-fixture');password.chmod(0o600)
                config=root/'migration.json';config.write_text(json.dumps({'installation':{'instance_id':'33333333-3333-4333-8333-333333333333','target':[1]*16,'lineage':[2]*16,'epoch':1,'tenants':['11111111-1111-1111-1111-111111111111','22222222-2222-2222-2222-222222222222']},'database':{'host':'localhost','port':port,'name':'backend','user':'mdm_owner','password_file':str(password),'ca_file':str(root/'ca.crt')}}));config.chmod(0o600)
                run(['cargo','run','--locked','--quiet','-p','rss-mdm-app','--bin','rss-mdm','--','migrate','--config',str(config)],cwd=source)
            else:
                if migrations is None:
                    migrations=run(['cargo','run','--locked','--quiet','-p','rss-mdm-policy-postgres','--example','policy_migrations'],cwd=source,capture_output=True).stdout
                    migrations+='\n'+'\n'.join((source/f'crates/{name}-postgres/migrations/{unit}').read_text() for name in ('resource','software-release') for unit in ('0001.sql','0002_outbox_writer.sql'))
                try:sql('BEGIN; SET ROLE mdm_owner; '+migrations+' COMMIT;')
                except subprocess.CalledProcessError as e:print(e.stderr,file=sys.stderr);raise
            if not app: sql("INSERT INTO rss_transactional_messaging.storage_lineage(target,lineage) VALUES(decode(repeat('01',16),'hex'),decode(repeat('02',16),'hex')); INSERT INTO rss_transactional_messaging.tenant_epoch VALUES('11111111-1111-1111-1111-111111111111',1),('22222222-2222-2222-2222-222222222222',1);")
            if write_catalogs:
                for n in NAMES:
                    d=source/'crates'/f'{n}-postgres/src'
                    query=(source/'crates/backend-postgres-support/src/catalog.sql').read_text()
                    schema=SCHEMAS[NAMES.index(n)]
                    v=json.loads(sql(query.replace('$1::text', "'"+schema+"'")))
                    (d/'catalog.json').write_text(json.dumps(v,indent=2)+'\n')
            if write_catalogs and app:
                d=source/'crates/app/src/software_publication';(d/'catalog.json').write_text(json.dumps(json.loads(sql((d/'catalog.sql').read_text())),indent=2)+'\n')
            config=root/'config.json';config.write_text(json.dumps({'port':port,'ca':str(root/'ca.crt'),'container':name}));config.chmod(0o600)
            yield dict(os.environ,BACKEND_PG_CONFIG=str(config)),sql
        finally:subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20)
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--write-catalogs',action='store_true');parser.add_argument('--serve',action='store_true');parser.add_argument('--app',action='store_true');args=parser.parse_args()
    with fixture(write_catalogs=args.write_catalogs,app=args.app) as(env,sql):
        if args.serve:
            out=ROOT/'artifacts/backend';out.mkdir(parents=True,exist_ok=True);(out/'environment.json').write_text(json.dumps({'BACKEND_PG_CONFIG':env['BACKEND_PG_CONFIG']}));print(env['BACKEND_PG_CONFIG'],flush=True);input('Disposable fixture ready; enter to stop. ');return
        if args.write_catalogs:return
        failed=[]
        for name in NAMES:
            for target,expected in [('consumer',CONSUMERS[name]),('recovery',{'protocol_ack_loss_and_fault_ack_recover_original_request'})]:
                result=subprocess.run(['cargo','test','--locked','-p',f'rss-mdm-{name}-postgres','--features','integration','--test',target,'--','--ignored','--test-threads=1'],cwd=ROOT,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                print(result.stdout,flush=True)
                try:
                    require(result.returncode==0,'PG suite failed');verify_tests(result.stdout,expected)
                except Exception:failed.append(name+'/'+target)
        require(not failed,'backend PG failed: '+','.join(failed))
if __name__=='__main__':main()
