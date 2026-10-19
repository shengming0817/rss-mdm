#!/usr/bin/env python3
"""Runs only inside the disposable qualification node; emits no input or credential values."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import ssl
import subprocess
import time
import uuid

ROOT=Path('/workspace')
BIN='/usr/local/bin/rss-mdm-installer'

class QualificationFailure(RuntimeError):
    pass

def check(value,message):
    if not value:raise QualificationFailure(message)

def run(*args,timeout=180):
    deadline=time.monotonic()+timeout
    while True:
        result=subprocess.run(args,text=True,capture_output=True,timeout=max(1,deadline-time.monotonic()))
        if result.returncode and args[0]==BIN and ': busy:' in result.stderr and time.monotonic()+.5<deadline:
            # A Busy rejection is safe to retry with the exact original operation input.
            time.sleep(.5)
            continue
        break
    if result.returncode:
        category=next((value for value in ('input_rejected','busy','conflict','corrupt','storage_unavailable')
                       if value+':' in result.stderr),'unclassified')
        saved=ROOT/'installation/installation.json'
        phase=json.loads(saved.read_text()).get('receipt',{}).get('stage','unreserved') if saved.exists() else 'unreserved'
        check(False,'qualification command failed: '+Path(args[0]).name+' '+str(args[1])+' category='+category+' installation='+phase)
    return result.stdout.strip()

def write(name,value):
    path=ROOT/name
    path.write_text(value if isinstance(value,str) else json.dumps(value))
    path.chmod(0o600)
    return str(path)

def until(checker,seconds=90):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        if checker():return
        time.sleep(.5)
    raise RuntimeError('qualification deadline')

class Browser:
    def __init__(self,port):
        self.port=port;self.cookie='';self.csrf=''
        self.origin='https://localhost:'+str(port)
        self.context=ssl.create_default_context(cafile=str(ROOT/'ca.crt'))
    def call(self,method,path,data=None,operation=None):
        headers={'Origin':self.origin,'X-Identity-Request':'1'}
        if self.cookie:headers['Cookie']=self.cookie
        if self.csrf:headers['X-CSRF-Token']=self.csrf
        if operation:headers['Idempotency-Key']=operation
        if data is not None:headers['Content-Type']='application/json'
        connection=http.client.HTTPSConnection('localhost',self.port,context=self.context,timeout=20)
        try:
            connection.request(method,path,json.dumps(data) if data is not None else None,headers)
            response=connection.getresponse();raw=response.read(1024*1024+1)
            check(len(raw)<=1024*1024,'response limit')
            for key,value in response.getheaders():
                if key.lower()=='set-cookie':
                    check('Secure' in value and 'HttpOnly' in value,'cookie security')
                    self.cookie=value.split(';',1)[0]
            value=json.loads(raw) if raw and 'application/json' in response.getheader('Content-Type','') else None
            if isinstance(value,dict) and 'csrfToken' in value:self.csrf=value['csrfToken']
            return response.status,value
        finally:connection.close()
    def login(self,tenant,login,password):
        check(self.call('POST','/api/v1/identity/tenants/'+tenant+'/login',
                        dict(login=login,password=password))[0]==200,'real account login')

def imported_providers(manifest):
    imported=json.loads((ROOT/'providers.json').read_text())
    providers={}
    for provider in ['postgres','nginx']:
        image=imported[provider]
        check(image['reference']==manifest['providers'][provider],'provider reference changed')
        check(run('docker','image','inspect','--format','{{.Id}}',image['image'])==image['image'],
              'imported provider identity changed')
        providers[provider]=image['image']
    return providers

def main():
    os.umask(0o077)
    manifest=json.loads((ROOT/'candidate.json').read_text())
    check(hashlib.sha256(Path(BIN).read_bytes()).hexdigest()==manifest['installer']['sha256'],
          'operator binary differs from fixed server binary')
    providers=imported_providers(manifest)
    run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=Candidate TLS CA',
        '-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign',
        '-keyout',str(ROOT/'ca.key'),'-out',str(ROOT/'ca.crt'))
    run('openssl','req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=localhost',
        '-keyout',str(ROOT/'server.key'),'-out',str(ROOT/'server.csr'))
    write('extensions','basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n')
    run('openssl','x509','-req','-in',str(ROOT/'server.csr'),'-CA',str(ROOT/'ca.crt'),'-CAkey',str(ROOT/'ca.key'),
        '-CAcreateserial','-days','2','-extfile',str(ROOT/'extensions'),'-out',str(ROOT/'server.crt'))
    pg=ROOT/'postgres';pg.mkdir(mode=0o700)
    uid=int(run('docker','run','--rm','--entrypoint','id',providers['postgres'],'-u','postgres'))
    for name in ['server.key','server.crt']:
        path=pg/name;path.write_bytes((ROOT/name).read_bytes());path.chmod(0o600);os.chown(path,uid,uid)
    os.chown(pg,uid,uid)
    password=secrets.token_urlsafe(32)
    write('postgres/password',password);os.chown(pg/'password',uid,uid)
    admin_password=write('database-password',password)
    run('docker','run','-d','--name','qualification-postgres','--network','host',
        '-v',str(pg)+':/private:ro','-e','POSTGRES_PASSWORD_FILE=/private/password',providers['postgres'],
        'postgres','-c','ssl=on','-c','ssl_cert_file=/private/server.crt','-c','ssl_key_file=/private/server.key')
    until(lambda:subprocess.run(['docker','exec','qualification-postgres','pg_isready','-U','postgres'],capture_output=True).returncode==0)
    deployment=dict(server_image=manifest['image'],gateway_image=providers['nginx'],
        certificate_file=str(ROOT/'server.crt'),private_key_file=str(ROOT/'server.key'),
        trust_file=str(ROOT/'ca.crt'),content_volume=None)
    installation=dict(directory=str(ROOT/'installation'),deployment=deployment,
        additional_hosts=[dict(origin='https://localhost:8446',listen='127.0.0.1:8082',deployment=deployment)],
        database=dict(administrator=dict(host='localhost',port=5432,name='postgres',user='postgres',
            password_file=admin_password,ca_file=str(ROOT/'ca.crt')),name='mdm'),audit_mode='ledger',
        organization_name='Candidate organization',platform_login='platform',administrator_login='administrator',
        platform_password_file=None,administrator_password_file=None,origin='https://localhost:8445',
        listen='127.0.0.1:8081',trusted_gateway='127.0.0.1')
    config=write('install.json',installation)
    first=json.loads(run(BIN,'install','--config',config,timeout=300))
    check(first['stage']=='enabled','installation did not enable')
    check(first['platformPrincipalId']!=first['administratorId'],'platform/business identities overlap')
    protected=ROOT/'installation'
    identities={name:hashlib.sha256((protected/name).read_bytes()).hexdigest()
                for name in ['platform-password','administrator-password','ledger.key','native.key','operation.key']}
    second=json.loads(run(BIN,'install','--config',config,timeout=300))
    check(second==first,'repeat installation changed receipt')
    check(all(hashlib.sha256((protected/name).read_bytes()).hexdigest()==digest for name,digest in identities.items()),
          'repeat installation replaced identity material')
    business=Browser(8445)
    business.login(first['tenantId'],'administrator',(protected/'administrator-password').read_text())
    status,subject=business.call('GET','/api/v1/authorization')
    check(status==200 and subject['principalId']==first['administratorId'],'business authorization')
    management=run('docker','exec','qualification-postgres','psql','-X','-At','-U','postgres','-d','mdm',
                   '-c','SELECT management_tenant_id FROM public.mdm_installation')
    platform=Browser(8445)
    platform.login(management,'platform',(protected/'platform-password').read_text())
    check(platform.call('GET','/api/v1/tenant-administration/authorization')[0]==200,'platform authorization')
    check(platform.call('GET','/api/v1/resources')[0] in (401,403),'platform business isolation')
    check(business.call('GET','/api/v1/tenant-administration/authorization')[0] in (401,403),'business platform isolation')
    operation=str(uuid.uuid4());account_password=secrets.token_urlsafe(32)
    request=dict(name='Second organization',administratorLogin='second',administratorPassword=account_password)
    endpoint='/api/v1/tenant-administration/provisionings'
    status,receipt=platform.call('POST',endpoint,request,operation)
    check(status in (200,202) and receipt['operationId']==operation,'complete provisioning admission')
    original=receipt['result']
    def enabled():
        status,value=platform.call('GET',endpoint+'/'+operation)
        if status!=200:return False
        progress=value['result']
        check(progress['tenantId']==original['tenantId'] and progress['hostId']==original['hostId'],'provisioning identity changed')
        return progress['phase']=='enabled'
    until(enabled,180)
    status,replayed=platform.call('POST',endpoint,request,operation)
    check(status==200 and replayed['result']['phase']=='enabled','original provisioning replay')
    other=Browser(8446);other.login(original['tenantId'],'second',account_password)
    status,subject=other.call('GET','/api/v1/authorization')
    check(status==200 and subject['tenantId']==original['tenantId'],'second host authentication')
    check(other.call('GET','/api/v1/tenant-administration/authorization')[0] in (401,403),'second tenant platform isolation')
    check(other.call('POST','/api/v1/identity/tenants/'+first['tenantId']+'/login',
                     dict(login='administrator',password=(protected/'administrator-password').read_text()))[0]!=200,
          'foreign tenant accepted on second host')
    service='rss-mdm-deployer-'+first['instanceId'].replace('-','')+'.service'
    run('systemctl','is-active','--quiet',service)
    pending_operation=str(uuid.uuid4())
    pending_request=dict(name='Capacity recovery',administratorLogin='third',administratorPassword=secrets.token_urlsafe(32))
    status,pending=platform.call('POST',endpoint,pending_request,pending_operation)
    check(status==202,'capacity operation admission')
    def capacity():
        status,value=platform.call('GET',endpoint+'/'+pending_operation)
        return status==200 and value['result']['blocked']=='capacity'
    until(capacity,90)
    # Root deployment configuration owns capacity. Add one concrete slot, then restart
    # the actual supervisor with its existing protected input and original operation.
    operator=json.loads((protected/'deployer-input.json').read_text())
    operator['additional_hosts'].append(dict(origin='https://localhost:8447',listen='127.0.0.1:8083',deployment=deployment))
    write('installation/deployer-input.json',operator)
    run('systemctl','restart',service)
    def recovered():
        status,value=platform.call('GET',endpoint+'/'+pending_operation)
        check(status==200,'capacity receipt query')
        check(value['result']['tenantId']==pending['result']['tenantId']
              and value['result']['hostId']==pending['result']['hostId'],'capacity recovery replaced identity')
        return value['result']['phase']=='enabled'
    until(recovered,180)
    third=Browser(8447)
    third.login(pending['result']['tenantId'],'third',pending_request['administratorPassword'])
    # Freeze only the daemon process: PostgreSQL and the valid old service keep running.
    # This forces the real external application boundary to fail after its checkpoint.
    run('systemctl','stop',service)
    host_directory=protected/('rss-mdm-'+first['hostId'].replace('-',''))
    revision=json.loads((host_directory/'requested-runtime.json').read_text())['runtime_binding']['revision']
    failed_operation=str(uuid.uuid4())
    failed_input=write('failed-configuration.json',dict(installation=operator,operation_id=failed_operation,
        host_id=first['hostId'],expected_revision=revision,change=dict(kind='webhook_networks',networks=[])))
    run('systemctl','kill','--kill-who=main','--signal=STOP','docker.service')
    try:
        failed=json.loads(run(BIN,'configure-host','--config',failed_input,timeout=180))
        check(failed['applied'] is None,'unavailable Docker falsely applied configuration')
    finally:run('systemctl','kill','--kill-who=main','--signal=CONT','docker.service')
    repaired_operation=str(uuid.uuid4())
    repaired_input=write('corrected-configuration.json',dict(installation=operator,operation_id=repaired_operation,
        host_id=first['hostId'],expected_revision=failed['requestedRevision'],change=dict(kind='webhook_networks',networks=[])))
    repaired=json.loads(run(BIN,'configure-host','--config',repaired_input,timeout=180))
    check(repaired['applied'] is not None,'failed configuration permanently fenced corrective input')
    check(json.loads(run(BIN,'configure-host','--config',failed_input))==failed,'old failed operation lost its receipt')
    check(json.loads((host_directory/'requested-runtime.json').read_text())['runtime_binding']['operation_id']==repaired_operation,
          'old failed operation replaced corrected runtime')
    run('systemctl','start',service)
    # Preserve external account delivery files; recovery must authenticate originals.
    accounts=[]
    for tenant,principal,login,password in [
        (management,first['platformPrincipalId'],'platform',(protected/'platform-password').read_text()),
        (first['tenantId'],first['administratorId'],'administrator',(protected/'administrator-password').read_text()),
        (original['tenantId'],replayed['result']['administratorId'],'second',account_password),
        (pending['result']['tenantId'],platform.call('GET',endpoint+'/'+pending_operation)[1]['result']['administratorId'],'third',pending_request['administratorPassword']),
    ]:
        accounts.append(dict(tenant_id=tenant,account=dict(principal_id=principal,login=login,
            password_file=write('restore-account-'+tenant,password))))
    backup_config=write('backup.json',dict(installation=operator,operation_id=str(uuid.uuid4()),
        directory=str(ROOT/'backup'),authorities=[]))
    captured=json.loads(run(BIN,'backup-installation','--config',backup_config,timeout=300))
    check(captured['stage']=='complete' and len(captured['manifestSha256'])==64,'joint backup did not seal')
    # An actual cold recovery: remove systemd links, host containers, deployment files,
    # and database while retaining only the trusted archive and original cluster roles.
    run('systemctl','disable','--now',service)
    run('systemctl','mask',service)
    containers=run('docker','ps','-aq').splitlines()
    for container in containers:
        info=json.loads(run('docker','inspect',container))[0]
        if info['Name']!='/qualification-postgres':run('docker','rm','-f',container)
    shutil.rmtree(protected)
    run('docker','exec','qualification-postgres','dropdb','-U','postgres','--force','mdm')
    run('docker','exec','qualification-postgres','createdb','-U','postgres','-O','mdm_owner','mdm')
    administrator=dict(installation['database']['administrator'],name='mdm')
    restore_config=write('restore.json',dict(directory=str(ROOT/'backup'),operation_id=str(uuid.uuid4()),
        backup_manifest_sha256=captured['manifestSha256'],administrator=administrator,accounts=accounts))
    interrupted=subprocess.run([BIN,'restore-installation','--config',restore_config],capture_output=True,text=True,timeout=300)
    check(interrupted.returncode!=0,'masked real supervisor falsely reported restored')
    check(': storage_unavailable:' in interrupted.stderr,'restore failed before the masked supervisor boundary')
    progress=json.loads((ROOT/'backup/restore-progress.json').read_text())
    check(progress['stage']=='contents','restore did not reach real supervisor failure')
    run('systemctl','unmask',service)
    restored=json.loads(run(BIN,'restore-installation','--config',restore_config,timeout=300))
    check(restored['stage']=='complete','original restore operation did not complete')
    run('systemctl','is-active','--quiet',service)
    check(all(hashlib.sha256((protected/name).read_bytes()).hexdigest()==digest for name,digest in identities.items()),
          'cold restore replaced original protection material')
    after=Browser(8445)
    after.login(first['tenantId'],'administrator',Path(accounts[1]['account']['password_file']).read_text())
    status,subject=after.call('GET','/api/v1/authorization')
    check(status==200 and subject['principalId']==first['administratorId'],'restored original authentication')
    after_platform=Browser(8445)
    after_platform.login(management,'platform',Path(accounts[0]['account']['password_file']).read_text())
    status,restored_receipt=after_platform.call('POST',endpoint,request,operation)
    check(status==200 and all(restored_receipt['result'][key]==replayed['result'][key] for key in ('tenantId','hostId','administratorId','operationId')), 'restored original provisioning identities')
    # A real pending operation proves the recovered service consumes work after its restart.
    fresh_operation=str(uuid.uuid4())
    status,_=after_platform.call('POST',endpoint,dict(name='Post recovery pending',administratorLogin='pending',
        administratorPassword=secrets.token_urlsafe(32)),fresh_operation)
    check(status==202,'post recovery admission')
    until(lambda:after_platform.call('GET',endpoint+'/'+fresh_operation)[1]['result']['blocked']=='capacity',90)
    print(json.dumps(dict(status='passed',checks=['fixed_operator_binary','single_input_install','repeat_install_identity',
        'fixed_ledger_key','independent_administrators','real_authentication','platform_business_isolation',
        'second_tenant_host','original_operation_replay','tenant_host_isolation','real_systemd_supervisor','capacity_original_operation_recovery','failed_configuration_correction','joint_cold_backup_restore','original_ledger_and_protection_material','interrupted_restore_replay','restored_supervisor_consumes_work'])))

if __name__=='__main__':
    try:main()
    except Exception as error:
        # No tracebacks, HTTP bodies, SQL or operator stderr containing private data.
        checkpoints={}
        for name in ('backup-progress.json','restore-progress.json'):
            path=ROOT/'backup'/name
            if path.exists():checkpoints[name]=json.loads(path.read_text()).get('stage')
        for name in ('ledger-checkpoints.json','database-backup.json'):
            checkpoints[name]=(ROOT/'backup'/name).exists()
        print(json.dumps(dict(status='failed',error_class=type(error).__name__,reason=str(error) if isinstance(error,QualificationFailure) else 'unexpected exception',checkpoints=checkpoints)))
        raise SystemExit(1)
