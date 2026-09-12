#!/usr/bin/env python3
"""Group's independent TLS PostgreSQL fixture. Missing dependencies fail closed."""
import contextlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import uuid
from t2 import IMAGE, run, require

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    "distinct_runs_compete_on_one_revision_and_preserve_event_contract",
    "reference_target_lock_serializes_deletion",
    "lost_commit_ack_replays_durable_result_once",
    "process_death_after_admission_recovers_without_caller_snapshot",
    "concurrent_inputs_rule_changes_and_kind_boundaries",
    "atomic_event_failure_rls_and_large_member_ids",
    "admitted_input_and_command_commit_unknown_recover_by_original_identity",'durable_recalculation_no_change_fences_stale_run'}

CONSUMER_TESTS = {"static_commands_replay_and_borrowed_rollback"}

def verify_tests(output, expected=EXPECTED):
    passed = set(re.findall(r'^test (\S+) \.\.\. ok$', output, re.MULTILINE))
    require(passed == expected, f'Group T2 did not execute required cases: {passed}')
    require(f'test result: ok. {len(expected)} passed; 0 failed; 0 ignored;' in output, 'Group T2 false green')

@contextlib.contextmanager
def fixture(migrations=None):
    with tempfile.TemporaryDirectory(prefix='mdm-group-pg-') as directory:
        root = Path(directory)
        quiet = dict(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
        run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=Group T2 CA','-keyout',str(root/'ca.key'),'-out',str(root/'ca.crt')], **quiet)
        run(['openssl','req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=localhost','-keyout',str(root/'server.key'),'-out',str(root/'server.csr')], **quiet)
        (root/'extensions').write_text('basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n')
        run(['openssl','x509','-req','-in',str(root/'server.csr'),'-CA',str(root/'ca.crt'),'-CAkey',str(root/'ca.key'),'-CAcreateserial','-days','1','-extfile',str(root/'extensions'),'-out',str(root/'server.crt')], **quiet)
        os.chmod(root/'server.key',0o644)
        name='mdm-group-t2-'+uuid.uuid4().hex[:12]
        def sql(statement):
            return run(['docker','exec','-i',name,'psql','-At','-v','ON_ERROR_STOP=1','-U','postgres','-d','group_test'],input=statement,capture_output=True,timeout=30).stdout.strip()
        try:
            run(['docker','run','-d','--rm','--name',name,'-p','127.0.0.1::5432','-v',f'{root}:/certs:ro','-e','POSTGRES_PASSWORD=admin-fixture','-e','POSTGRES_DB=group_test',IMAGE,'sh','-c','cp /certs/server.key /tmp/server.key; cp /certs/server.crt /tmp/server.crt; chown postgres:postgres /tmp/server.*; chmod 600 /tmp/server.key; exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key'],stdout=subprocess.DEVNULL,timeout=120)
            until=time.monotonic()+45
            while True:
                result=subprocess.run(['docker','exec',name,'pg_isready','-h','127.0.0.1','-U','postgres','-d','group_test'],capture_output=True,timeout=5)
                if result.returncode==0: break
                if time.monotonic()>until: raise RuntimeError('Group PG startup deadline')
                time.sleep(.2)
            port=int(run(['docker','port',name,'5432'],capture_output=True,timeout=5).stdout.strip().rsplit(':',1)[1])
            sql("CREATE ROLE rss_tmsg_relay NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION; CREATE ROLE mdm_group_owner NOLOGIN NOSUPERUSER NOBYPASSRLS; CREATE ROLE mdm_group_runtime LOGIN PASSWORD 'group-fixture' NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION; GRANT CREATE ON DATABASE group_test TO mdm_group_owner; GRANT rss_tmsg_relay TO mdm_group_owner;")
            if migrations is None:
                migrations=run(['cargo','run','--locked','--quiet','-p','rss-mdm-group-postgres','--example','migrations'],cwd=ROOT,capture_output=True).stdout
            try:
                sql('BEGIN; SET ROLE mdm_group_owner; '+migrations+' COMMIT;')
            except subprocess.CalledProcessError as error:
                print(error.stderr, file=sys.stderr);raise
            sql("INSERT INTO rss_transactional_messaging.storage_lineage(target,lineage) VALUES(decode(repeat('01',16),'hex'),decode(repeat('02',16),'hex')); INSERT INTO rss_transactional_messaging.tenant_epoch VALUES('11111111-1111-1111-1111-111111111111',1),('22222222-2222-2222-2222-222222222222',1); GRANT USAGE ON SCHEMA rss_transactional_messaging TO mdm_group_runtime; GRANT SELECT ON rss_transactional_messaging.policy TO mdm_group_runtime; GRANT SELECT,INSERT ON rss_transactional_messaging.outbox TO mdm_group_runtime; GRANT USAGE ON SEQUENCE rss_transactional_messaging.outbox_seq_seq TO mdm_group_runtime; GRANT EXECUTE ON FUNCTION rss_transactional_messaging.check_execution() TO mdm_group_runtime;")
            path=root/'config.json';path.write_text(json.dumps({'port':port,'ca':str(root/'ca.crt'),'container':name}));os.chmod(path,0o600)
            env=os.environ.copy();env['GROUP_PG_CONFIG']=str(path)
            yield env,sql
        finally:
            subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20)

def main():
    with fixture() as (env,sql):
        result=subprocess.run(['cargo','test','--locked','-p','rss-mdm-group-postgres','--features','integration','--test','t2','--','--ignored','--test-threads=1','--nocapture'],cwd=ROOT,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        print(result.stdout,flush=True)
        require(result.returncode==0,'Group PG behavioral suite failed')
        verify_tests(result.stdout)
        consumer = subprocess.run(['cargo','test','--locked','-p','rss-mdm-group-postgres','--test','consumer','--','--ignored','--test-threads=1'], cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        print(consumer.stdout, flush=True)
        require(consumer.returncode == 0, 'Group public consumer failed')
        verify_tests(consumer.stdout, CONSUMER_TESTS)
        print(json.dumps({'provider':IMAGE,'tls':'verify-full','tests':sorted(EXPECTED),'T3':'not run'}))
if __name__=='__main__': main()
