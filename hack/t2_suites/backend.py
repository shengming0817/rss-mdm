#!/usr/bin/env python3
"""Disposable TLS PG for N10/N11; no missing-service skips and no production setup."""
import argparse,contextlib,json,os,re,subprocess,sys,tempfile,time,uuid
from pathlib import Path
from t2_environment import run
from verification_result import require
from build_run import lease_fds, require_lease

ROOT=Path(__file__).resolve().parents[2]
NAMES=('policy','resource','software-release')
SCHEMAS=('mdm_policy','mdm_resource','mdm_software_release')
BEHAVIORS={
 'policy':{'borrowed_reads_reject_foreign_runtime_and_tenant','configuration_cas_replay_and_runtime_isolation','scope_changes_preserve_execution_version','companion_failure_rolls_back_publication','admission_rejects_schema_and_reachable_privilege_drift','explicit_trigger_does_not_edit_configuration'},
 'resource':{'artifact_reference_index_covers_reuse_without_another_upload_and_archive_rollback','admission_rejects_noninherited_switchable_privileges','resource_admission_rejects_schema_and_privilege_drift','resource_immutable_versions_restart_and_reference_rollback','resource_cas_events_and_owner_admission'},
 'software-release':{'admission_rejects_noninherited_switchable_privileges','release_approval_unknown_retry_history_and_late_results','release_immutable_version_request_uniqueness_and_rollback','release_event_failure_and_runtime_admission'},
}
def verify_tests(output,expected):
    actual=set(re.findall(r'^test (\S+) \.\.\. ok$',output,re.MULTILINE))
    require(actual==expected and f'test result: ok. {len(expected)} passed; 0 failed; 0 ignored;' in output, 'backend T2 missing required behavior')
@contextlib.contextmanager
def fixture(context, source=ROOT,write_catalogs=False,app=False,migrations=None,case=None):
    with context.cluster(case) as owner, owner.database() as database, tempfile.TemporaryDirectory(prefix='mdm-backend-inputs-') as directory:
        root=Path(directory)
        (root/'ca.crt').write_bytes((owner.root/'ca.crt').read_bytes())
        name=owner.container();port=owner.port()
        def sql(statement): return owner.sql(statement,database)
        if app:
            password=root/'owner-password';password.write_text('owner-fixture');password.chmod(0o600)
            config=root/'migration.json';config.write_text(json.dumps({'installation':{'audit_mode':'plain','instance_id':'33333333-3333-4333-8333-333333333333','target':[1]*16,'lineage':[2]*16,'epoch':1,'tenants':['11111111-1111-1111-1111-111111111111','22222222-2222-2222-2222-222222222222']},'database':{'host':'localhost','port':port,'name':database,'user':'mdm_owner','password_file':str(password),'ca_file':str(root/'ca.crt')}}));config.chmod(0o600)
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
            d=source/'crates/software-service/src/publication';(d/'catalog.json').write_text(json.dumps(json.loads(sql((d/'catalog.sql').read_text())),indent=2)+'\n')
        config=root/'config.json';config.write_text(json.dumps({'port':port,'ca':str(root/'ca.crt'),'container':name,'database':database}));config.chmod(0o600)
        yield dict(os.environ,BACKEND_PG_CONFIG=str(config)),sql
def main(context):
    require_lease(ROOT)
    failed=[]
    for name in NAMES:
        suites=[('behavior',BEHAVIORS[name]),('recovery',{'protocol_ack_loss_and_fault_ack_recover_original_request'})]
        for target,expected in suites:
            for test in sorted(expected):
                with fixture(context,case=test) as(env,sql):
                    result=subprocess.run(['cargo','test','--locked','-p',f'rss-mdm-{name}-postgres','--features','integration','--test',target,test,'--','--ignored','--exact','--test-threads=1'],pass_fds=lease_fds(),cwd=ROOT,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                    print(result.stdout,flush=True)
                    try:
                        require(result.returncode==0,'PG suite failed');verify_tests(result.stdout,{test})
                    except Exception:failed.append(name+'/'+test)
    require(not failed,'backend PG failed: '+','.join(failed))
