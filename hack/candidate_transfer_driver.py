#!/usr/bin/env python3
"""Exact V4 artifact -> V5 migration and original backup recovery, on the owned Linux node."""
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import uuid
from driver import ROOT, BIN, Browser, check, run, write, until


def main():
    os.umask(0o077)
    current=json.loads((ROOT/'candidate.json').read_text())
    source=ROOT/'source';legacy=json.loads((source/'candidate.json').read_text())
    check(legacy['format_version']==4,'exact V4 candidate required')
    check(hashlib.sha256((source/legacy['archive']['file']).read_bytes()).hexdigest()==legacy['archive']['sha256'],'V4 archive digest')
    for name,digest in legacy['deployment'].items():
        check(hashlib.sha256((source/name).read_bytes()).hexdigest()==digest,'V4 deployment digest')
    providers=current['providers']
    for provider in ['postgres','nginx']:run('docker','pull',providers[provider],timeout=300)
    run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=Transfer TLS root',
        '-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign',
        '-keyout',str(ROOT/'ca.key'),'-out',str(ROOT/'ca.crt'))
    run('openssl','req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=localhost',
        '-keyout',str(ROOT/'server.key'),'-out',str(ROOT/'server.csr'))
    write('extensions','basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n')
    run('openssl','x509','-req','-in',str(ROOT/'server.csr'),'-CA',str(ROOT/'ca.crt'),'-CAkey',str(ROOT/'ca.key'),
        '-CAcreateserial','-days','2','-extfile',str(ROOT/'extensions'),'-out',str(ROOT/'server.crt'))
    pg=ROOT/'pg';pg.mkdir(mode=0o700)
    uid=int(run('docker','run','--rm','--entrypoint','id',providers['postgres'],'-u','postgres'))
    for name in ['server.crt','server.key']:
        (pg/name).write_bytes((ROOT/name).read_bytes());(pg/name).chmod(0o600);os.chown(pg/name,uid,uid)
    os.chown(pg,uid,uid)
    password=secrets.token_urlsafe(32);write('pg/password',password);os.chown(pg/'password',uid,uid)
    admin_password=write('database-password',password)
    run('docker','run','-d','--name','transfer-postgres','--network','host','-v',str(pg)+':/private:ro',
        '-e','POSTGRES_PASSWORD_FILE=/private/password','-e','POSTGRES_DB=mdm_test',providers['postgres'],
        'postgres','-c','ssl=on','-c','ssl_cert_file=/private/server.crt','-c','ssl_key_file=/private/server.key')
    until(lambda:subprocess.run(['docker','exec','transfer-postgres','pg_isready','-U','postgres'],capture_output=True).returncode==0)
    def sql(statement):
        result=subprocess.run(['docker','exec','-i','transfer-postgres','psql','-X','-At','-v','ON_ERROR_STOP=1','-U','postgres','-d','mdm_test'],
            input=statement,text=True,capture_output=True,timeout=30)
        check(result.returncode==0,'V4 fixture SQL');return result.stdout.strip()
    runtime=ROOT/'legacy-runtime';operator=ROOT/'legacy-operator'
    runtime.mkdir(mode=0o700);operator.mkdir(mode=0o700)
    def private(directory,name,value):
        path=directory/name;path.write_text(value if isinstance(value,str) else json.dumps(value));path.chmod(0o600)
        return '/run/mdm/'+name
    def database(directory,role):
        return dict(host='localhost',port=5432,name='mdm_test',user=role,
            password_file=private(directory,role+'.password',role+'-fixture'),ca_file='/run/mdm/ca.crt')
    for directory in [runtime,operator]:(directory/'ca.crt').write_bytes((ROOT/'ca.crt').read_bytes())
    native=os.urandom(32);ledger=os.urandom(32)
    for name,value in [('native.key',native),('ledger.key',ledger)]:
        for directory in [runtime,operator]:(directory/name).write_bytes(value);(directory/name).chmod(0o600)
    run('openssl','genpkey','-algorithm','ED25519','-outform','DER','-out',str(runtime/'task.pk8'))
    key=(runtime/'task.pk8').read_bytes()
    public=subprocess.check_output(['openssl','pkey','-inform','DER','-in',str(runtime/'task.pk8'),'-pubout','-outform','DER'])[-32:]
    (runtime/'task.pk8').write_bytes(bytes.fromhex('3051020101300506032b657004220420')+key[-32:]+bytes.fromhex('812100')+public)
    instance,tenant,admin,platform=[str(uuid.uuid4()) for _ in range(4)]
    coordinates=dict(instance_id=instance,target=[1]*16,lineage=[2]*16,audit_mode='ledger')
    config=json.loads((source/'mdm-config.example.json').read_text())
    config.update(native_protection_key_file='/run/mdm/native.key',native_protocols={},device_pki=[],
        agent_pki={'mode':'disabled'},content=None,product_origin='https://localhost:8445',listen='127.0.0.1:8081',trusted_gateway='127.0.0.1',
        audit=dict(mode='ledger',key_id='original-ledger',key_file='/run/mdm/ledger.key'),
        task_signing=dict(private_key_file='/run/mdm/task.pk8',key_id='original-task',trusted_keys={'original-task':base64.urlsafe_b64encode(public).decode().rstrip('=')}))
    config['identity'].update(instance_id=instance,tenant_id=tenant,oidc=None,database=database(runtime,'mdm_identity_runtime'),audit_worker=database(runtime,'mdm_identity_audit'))
    config['access_database']=database(runtime,'mdm_access');config['runtime_database']=database(runtime,'mdm_runtime')
    config['execution']['database']=database(runtime,'mdm_command_runtime')
    config['flow']['storage'].update(database=database(runtime,'mdm_flow_runtime'),target=[1]*16,lineage=[2]*16,epoch=1)
    config['flow']['publication'].update(database=database(runtime,'mdm_software_driver'),sources=[])
    config['webhooks']=dict(keys=[],networks=[],recovery_database=database(runtime,'mdm_webhook_operator'))
    roles=''.join("CREATE ROLE "+role+" LOGIN PASSWORD '"+role+"-fixture' NOSUPERUSER NOBYPASSRLS;" for role in ['mdm_owner','mdm_api','mdm_access','mdm_runtime'])
    roles+='GRANT CREATE ON DATABASE mdm_test TO mdm_owner; GRANT CREATE ON SCHEMA public TO mdm_owner;'
    for name in ['software-publication','flow','identity','commands','audit','webhook']:roles+=(source/f'deployment/{name}-roles.sql').read_text()
    for role in ['mdm_command_runtime','mdm_flow_runtime','mdm_software_driver','mdm_identity_runtime','mdm_identity_maintenance','mdm_identity_audit','mdm_webhook_operator','mdm_tenant_registry','mdm_identity_provisioning']:
        roles+="ALTER ROLE "+role+" LOGIN PASSWORD '"+role+"-fixture';"
    sql(roles)
    def own(directory):
        for path in [directory,*directory.iterdir()]:os.chown(path,10001,10001)
    def command(verb,value):
        private(operator,'operation.json',value);own(operator)
        return run('docker','run','--rm','--network','host','-v',str(operator)+':/run/mdm:ro',legacy['image'],verb,'--config','/run/mdm/operation.json')
    owner=database(operator,'mdm_owner')
    command('migrate',dict(database=owner,installation=coordinates))
    command('tenant-create',dict(database=owner,installation=coordinates,tenant_id=tenant,initial_epoch=1,operation_id=str(uuid.uuid4())))
    management=sql('SELECT management_tenant_id FROM public.mdm_installation')
    account_password=secrets.token_urlsafe(32);password_file=private(operator,'account-password',account_password)
    for target,principal in [(tenant,admin),(management,platform)]:
        command('initialize',dict(database=database(operator,'mdm_identity_maintenance'),installation=coordinates,tenant_id=target,expected_epoch=1,principal_id=principal,login='administrator',password_file=password_file))
        command('initialize-authorization',dict(audit=config['audit'],database=database(operator,'mdm_access'),identityDatabase=database(operator,'mdm_identity_runtime'),installation=coordinates,
            expectedEpoch=1,login='administrator',passwordFile=password_file,operationId=str(uuid.uuid4()),user=dict(instanceId=instance,tenantId=target,principalId=principal)))
    private(runtime,'config.json',config);own(runtime)
    old=run('docker','run','-d','--network','host','--name','original-v4','-v',str(runtime)+':/run/mdm:ro',legacy['image'],'serve','--config','/run/mdm/config.json')
    # Source startup must consume its original native protection identity before transfer.
    until(lambda:sql("SELECT count(*) FROM mdm_flow.native_protection WHERE tenant_id='"+tenant+"'")=='1')
    deployment=dict(server_image=current['image'],gateway_image=providers['nginx'],certificate_file=str(ROOT/'server.crt'),private_key_file=str(ROOT/'server.key'),trust_file=str(ROOT/'ca.crt'),content_volume=None)
    installation=dict(directory=str(ROOT/'installation'),deployment=deployment,additional_hosts=[],
        database=dict(administrator=dict(host='localhost',port=5432,name='mdm_test',user='postgres',password_file=admin_password,ca_file=str(ROOT/'ca.crt')),name='mdm_test'),
        audit_mode='ledger',organization_name='Transferred organization',platform_login='administrator',administrator_login='administrator',
        platform_password_file=None,administrator_password_file=None,origin='https://localhost:8445',listen='127.0.0.1:8081',trusted_gateway='127.0.0.1')
    delivery=write('account-password',account_password)
    root_owner=dict(owner,password_file=str(operator/'mdm_owner.password'),ca_file=str(ROOT/'ca.crt'))
    request=dict(operation_id=str(uuid.uuid4()),deployment=installation,owner=root_owner,source_candidate=str(source),
        source_manifest_sha256=hashlib.sha256((source/'candidate.json').read_bytes()).hexdigest(),
        platform_administrator=dict(principal_id=platform,login='administrator',password_file=delivery),
        hosts=[dict(container_id=old,administrator=dict(principal_id=admin,login='administrator',password_file=delivery),deployment=deployment,apple_material_roots=[],task_runtime_origin="https://localhost:9445",storage_profile=None,storage_expires_at=None)])
    path=write('transfer.json',request)
    migrated=json.loads(run(BIN,'transfer-v4','--config',path,timeout=300))
    check(migrated['phase']=='transferred','V4 transfer incomplete')
    check(json.loads(run(BIN,'transfer-v4','--config',path,timeout=300))==migrated,'V4 original operation replay changed identity')
    browser=Browser(8445);browser.login(tenant,'administrator',account_password)
    status,subject=browser.call('GET','/api/v1/authorization')
    check(status==200 and subject['instanceId']==instance and subject['principalId']==admin,'V4 account identity changed')
    status,trust=browser.call('GET','/api/v1/task-signing/trust')
    check(status==200 and trust['keys'][0]['id']=='original-task' and trust['keys'][0]['public_key']==base64.urlsafe_b64encode(public).decode().rstrip('='),'V4 signing identity changed')
    ledger_id=sql("SELECT DISTINCT key_id FROM rss_ledger.heads")
    check(ledger_id=='original-ledger','V4 Ledger identity changed')
    check(json.loads(run('docker','inspect',old))[0]['State']['Running'] is False,'V4 old writer restarted')
    platform_browser=Browser(8445);platform_browser.login(management,'administrator',account_password)
    status,grant=platform_browser.call('GET','/api/v1/tenant-administration/authorization')
    check(status==200 and 'tenant_administrator_create' in {g['operation'] for g in grant['grants']},'transferred platform cannot provision')
    service='rss-mdm-deployer-'+instance.replace('-','')+'.service'
    run('systemctl','disable','--now',service)
    run('systemctl','mask',service)
    for container in run('docker','ps','-aq').splitlines():
        info=json.loads(run('docker','inspect',container))[0]
        if info['Name'] not in ('/transfer-postgres','/original-v4'):run('docker','rm','-f',container)
    run('docker','exec','transfer-postgres','dropdb','-U','postgres','--force','mdm_test')
    run('docker','exec','transfer-postgres','createdb','-U','postgres','-O','mdm_owner','mdm_test')
    recover=write('restore-v4.json',dict(directory=str(ROOT/'installation'),operation_id=str(uuid.uuid4()),
        backup_manifest_sha256=migrated['backupManifestSha256'],administrator=installation['database']['administrator']))
    interrupted=subprocess.run([BIN,'restore-v4','--config',recover],capture_output=True,text=True,timeout=300)
    check(interrupted.returncode!=0,'masked supervisor incorrectly completed V4 recovery')
    check(json.loads((ROOT/'installation/recovery.json').read_text())['stage']=='contents','V4 restore did not reach original identity verification')
    run('systemctl','unmask',service)
    restored=json.loads(run(BIN,'restore-v4','--config',recover,timeout=300))
    check(restored['phase']=='transferred' and restored['hosts']==migrated['hosts'],'V4 restore replaced host identities')
    after=Browser(8445);after.login(tenant,'administrator',account_password)
    check(after.call('GET','/api/v1/authorization')[1]['principalId']==admin,'V4 recovered original account rejected')
    check(after.call('GET','/api/v1/task-signing/trust')[1]['keys'][0]['id']=='original-task','V4 recovered key identity changed')
    run('systemctl','is-active','--quiet',service)
    print(json.dumps(dict(status='passed',checks=['exact_v4_candidate','real_v4_startup','original_accounts','fixed_ledger',
        'original_task_signing_key','original_transfer_replay','old_writer_stopped','complete_platform_permissions','restore_v4_original_archive','restore_v4_interruption_replay'],
        source=legacy['archive']['manifest_digest'],limits=['management-host source; enrolled-device and provider transfer require their dedicated qualification'])))

if __name__=='__main__':
    try:main()
    except Exception as error:
        print(json.dumps(dict(status='failed',error_class=type(error).__name__)))
        raise SystemExit(1)
