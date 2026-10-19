#!/usr/bin/env python3
"""Formal Compose acceptance: real install, accounts, provisioning and recovery; no fixture seed."""
import hashlib
import http.client
import json
from pathlib import Path
import secrets
import ssl
import subprocess
import time
import uuid
from urllib.parse import urlsplit


class Installation:
    def __init__(self, deployment):
        self.root = deployment
        self.prefix = ['docker','compose','--env-file',str(deployment/'compose.env'),'-f',str(deployment/'compose.yaml')]

    def compose(self, *args, timeout=300):
        result = subprocess.run([*self.prefix, *args], capture_output=True, text=True, timeout=timeout)
        if result.returncode:
            raise RuntimeError('formal Compose command failed: '+args[0])
        return result.stdout.strip()

    def script(self, source, *args):
        return self.compose('run','--rm','--no-deps','-T','--entrypoint','python3','operator','-c',source,*args)

    def read(self, path):
        return self.script('import pathlib,sys; print(pathlib.Path(sys.argv[1]).read_text(),end="")',path)

    def receipt(self):
        return json.loads(self.read('/var/lib/rss-mdm/installation/installation.json'))['receipt']

    def product(self, command, configuration):
        for _ in range(40):
            result = subprocess.run([*self.prefix,'run','--rm','--no-deps','-T','operator',command,'--config',configuration],
                                    capture_output=True,text=True,timeout=300)
            if result.returncode == 0:
                return json.loads(result.stdout)
            if ': busy:' not in result.stderr:
                raise RuntimeError('product maintenance failed: '+command)
            time.sleep(.5)
        raise RuntimeError('maintenance lock deadline')

    def save(self, name, value):
        path = '/var/lib/rss-mdm/'+name
        # Data goes through stdin, never through process arguments or diagnostics.
        result = subprocess.run([*self.prefix,'run','--rm','--no-deps','-T','--entrypoint','python3','operator','-c',
            'import pathlib,sys;p=pathlib.Path(sys.argv[1]);p.write_text(sys.stdin.read());p.chmod(0o600)',path],
            input=value if isinstance(value,str) else json.dumps(value),capture_output=True,text=True,timeout=30)
        check(result.returncode==0,'operator input write')
        return path

    def hosts(self):
        return json.loads(self.script('import pathlib,json; print(json.dumps([p.name.removeprefix("rss-mdm-") for p in pathlib.Path("/var/lib/rss-mdm/installation").glob("rss-mdm-*") if p.is_dir()]))'))

    def cleanup(self):
        project = json.loads((self.root/'deployment.json').read_text())['project']
        self.compose('stop','operator')
        candidates=subprocess.check_output(['docker','ps','-aq','--filter','volume='+project+'_state','--filter','label=rss.mdm.host'],text=True).split()
        if candidates:
            subprocess.run(['docker','rm','-f',*candidates],check=True,capture_output=True)
        self.compose('down','--volumes','--remove-orphans')


def check(value, reason):
    if not value:
        raise RuntimeError(reason)


def until(predicate, seconds=150):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        if predicate():return
        time.sleep(.5)
    raise RuntimeError('formal installation deadline')


class Browser:
    def __init__(self, origin, ca):
        self.origin=origin;self.url=urlsplit(origin);self.cookie='';self.csrf=''
        self.context=ssl.create_default_context(cafile=str(ca))

    def call(self, method, path, data=None, operation=None):
        headers={'Origin':self.origin,'X-Identity-Request':'1'}
        if self.cookie:headers['Cookie']=self.cookie
        if self.csrf:headers['X-CSRF-Token']=self.csrf
        if operation:headers['Idempotency-Key']=operation
        if data is not None:headers['Content-Type']='application/json'
        connection=http.client.HTTPSConnection(self.url.hostname,self.url.port or 443,context=self.context,timeout=20)
        try:
            connection.request(method,path,json.dumps(data) if data is not None else None,headers)
            response=connection.getresponse()
            cookies=response.headers.get_all('set-cookie') or []
            if cookies:self.cookie='; '.join(value.split(';',1)[0] for value in cookies)
            raw=response.read()
            value=json.loads(raw) if raw else None
            if isinstance(value,dict) and value.get('csrfToken'):self.csrf=value['csrfToken']
            return response.status,value
        finally:connection.close()

    def login(self, tenant, login, password):
        status,_=self.call('POST','/api/v1/identity/tenants/'+tenant+'/login',dict(login=login,password=password))
        check(status==200,'real account login')


def qualify(owner, origin, other_origin):
    owner.compose('up','-d',timeout=600)
    first=owner.receipt()
    check(first['stage']=='enabled','complete initialization')
    check(first['platformPrincipalId']!=first['administratorId'],'separate administrators')
    ca=owner.root/'ca.crt'
    ca.write_text(owner.read('/var/lib/rss-mdm/inputs/ca.crt'))
    administrator=owner.read('/var/lib/rss-mdm/installation/administrator-password')
    platform_password=owner.read('/var/lib/rss-mdm/installation/platform-password')
    names=['platform-password','administrator-password','ledger.key','native.key','operation.key']
    digest_code='import pathlib,hashlib,json; r=pathlib.Path("/var/lib/rss-mdm/installation"); print(json.dumps({n:hashlib.sha256((r/n).read_bytes()).hexdigest() for n in '+repr(names)+'}))'
    identities=json.loads(owner.script(digest_code))
    owner.compose('run','--rm','--no-deps','-T','install',timeout=300)
    check(owner.receipt()==first,'repeat installation changed receipt')
    check(json.loads(owner.script(digest_code))==identities,'repeat installation changed secrets')
    business=Browser(origin,ca)
    status,public=business.call('GET','/api/v1/mdm-host/config.json')
    check(status==200,'real public host configuration')
    management=public['managementTenant']
    business.login(first['tenantId'],'administrator',administrator)
    status,subject=business.call('GET','/api/v1/authorization')
    check(status==200 and subject['principalId']==first['administratorId'],'business authorization')
    platform=Browser(origin,ca);platform.login(management,'platform',platform_password)
    check(platform.call('GET','/api/v1/tenant-administration/authorization')[0]==200,'platform authorization')
    check(platform.call('GET','/api/v1/resources')[0] in (401,403),'platform business isolation')
    check(business.call('GET','/api/v1/tenant-administration/authorization')[0] in (401,403),'business platform isolation')
    operation=str(uuid.uuid4());password=secrets.token_urlsafe(32)
    request=dict(name='Second organization',administratorLogin='second',administratorPassword=password)
    endpoint='/api/v1/tenant-administration/provisionings'
    status,receipt=platform.call('POST',endpoint,request,operation)
    check(status in (200,202) and receipt['operationId']==operation,'complete provisioning admission')
    original=receipt['result']
    def enabled():
        status,value=platform.call('GET',endpoint+'/'+operation)
        if status!=200:return False
        check(value['result']['tenantId']==original['tenantId'] and value['result']['hostId']==original['hostId'],'provisioning identity changed')
        return value['result']['phase']=='enabled'
    # The Compose operator must resume the original receipt after a real restart.
    owner.compose('restart','operator')
    until(enabled)
    status,replayed=platform.call('POST',endpoint,request,operation)
    check(status==200 and replayed['result']['phase']=='enabled','original operation replay')
    other=Browser(other_origin,ca);other.login(original['tenantId'],'second',password)
    check(other.call('GET','/api/v1/authorization')[1]['tenantId']==original['tenantId'],'second host authentication')
    check(other.call('POST','/api/v1/identity/tenants/'+first['tenantId']+'/login',dict(login='administrator',password=administrator))[0]!=200,'foreign tenant login')
    # Prove private runtime/namespace isolation from Docker's actual running configuration.
    for host in owner.hosts():
        ids=subprocess.check_output(['docker','ps','-q','--filter','label=rss.mdm.host='+str(uuid.UUID(hex=host))],text=True).split()
        check(len(ids)==2,'tenant runtime services')
        for metadata in json.loads(subprocess.check_output(['docker','inspect',*ids],text=True)):
            check(metadata['Config']['User']=='10001:10001','nonroot product runtime')
            check(metadata['HostConfig']['NetworkMode']!='host','bridge runtime')
            check(not any(m['Destination']=='/run/docker.sock' for m in metadata['Mounts']),'server Docker isolation')
            check(all(m['Type']=='volume' for m in metadata['Mounts']),'no host bind inputs')
    # Complete maintenance uses the same product owner and exact operation identity.
    operator=json.loads(owner.read('/var/lib/rss-mdm/installation-input.json'))
    host='/var/lib/rss-mdm/installation/rss-mdm-'+first['hostId'].replace('-','')
    runtime=json.loads(owner.read(host+'/requested-runtime.json'))
    change=dict(installation=operator,operation_id=str(uuid.uuid4()),host_id=first['hostId'],
        expected_revision=runtime['runtime_binding']['revision'],change=dict(kind='webhook_networks',networks=[]))
    owner.compose('stop','operator')
    configured=owner.product('configure-host',owner.save('configuration.json',change))
    check(configured['applied'] is not None,'real configuration application')
    # Configuration must survive a fresh operator process and an idempotent install replay.
    owner.compose('start','operator')
    owner.compose('run','--rm','--no-deps','-T','install',timeout=300)
    check(json.loads(owner.script(digest_code))==identities,'maintenance replaced installation identity')
    check(json.loads(owner.read(host+'/requested-runtime.json'))['runtime_binding']['operation_id']==change['operation_id'],'installation replay overwrote applied configuration')
    owner.compose('stop','operator')
    # Docker failure is scoped to one maintenance container, never the shared daemon.
    runtime=json.loads(owner.read(host+'/requested-runtime.json'))
    failed_change=dict(installation=operator,operation_id=str(uuid.uuid4()),host_id=first['hostId'],
        expected_revision=runtime['runtime_binding']['revision'],change=dict(kind='webhook_networks',networks=[]))
    failed_path=owner.save('failed-configuration.json',failed_change)
    result=owner.compose('run','--rm','--no-deps','-T','-e','DOCKER_HOST=unix:///tmp/unavailable.sock','operator',
                         'configure-host','--config',failed_path,timeout=180)
    failed=json.loads(result)
    check(failed['applied'] is None,'unavailable Docker falsely applied configuration')
    corrected=dict(failed_change,operation_id=str(uuid.uuid4()),expected_revision=failed['requestedRevision'])
    repaired=owner.product('configure-host',owner.save('corrected-configuration.json',corrected))
    check(repaired['applied'] is not None,'corrective configuration blocked')
    check(owner.product('configure-host',failed_path)==failed,'failed operation lost receipt')
    # Full cold backup/restore preserves original accounts, keys, and provisioning receipts.
    backup=owner.product('backup-installation',owner.save('backup.json',dict(installation=operator,
        operation_id=str(uuid.uuid4()),directory='/var/lib/rss-mdm/backup',authorities=[])))
    check(backup['stage']=='complete','joint backup')
    accounts=[]
    for tenant,principal,login,secret in [(management,first['platformPrincipalId'],'platform',platform_password),
        (first['tenantId'],first['administratorId'],'administrator',administrator),
        (original['tenantId'],replayed['result']['administratorId'],'second',password)]:
        password_path='/var/lib/rss-mdm/restore-account-'+tenant
        # Store only in the protected operator volume; password JSON uses the same non-argv input path.
        owner.save('restore-secret-'+tenant,secret)
        accounts.append(dict(tenant_id=tenant,account=dict(principal_id=principal,login=login,
            password_file='/var/lib/rss-mdm/restore-secret-'+tenant)))
    for host_id in owner.hosts():
        ids=subprocess.check_output(['docker','ps','-aq','--filter','label=rss.mdm.host='+str(uuid.UUID(hex=host_id))],text=True).split()
        if ids:subprocess.run(['docker','rm','-f',*ids],check=True,capture_output=True)
    owner.script('import shutil;shutil.rmtree("/var/lib/rss-mdm/installation")')
    owner.compose('exec','-T','postgres','dropdb','-U','postgres','--force','mdm')
    owner.compose('exec','-T','postgres','createdb','-U','postgres','-O','mdm_owner','mdm')
    restore=dict(directory='/var/lib/rss-mdm/backup',operation_id=str(uuid.uuid4()),
        backup_manifest_sha256=backup['manifestSha256'],administrator=dict(operator['database']['administrator'],name='mdm'),accounts=accounts)
    restored=owner.product('restore-installation',owner.save('restore.json',restore))
    check(restored['stage']=='complete','cold restore')
    check(json.loads(owner.script(digest_code))==identities,'cold restore replaced identity')
    owner.compose('start','operator')
    after=Browser(origin,ca);after.login(management,'platform',platform_password)
    status,receipt=after.call('POST',endpoint,request,operation)
    check(status==200 and all(receipt['result'][key]==replayed['result'][key] for key in ('tenantId','hostId','administratorId','operationId')),'restored original provisioning')
    pending_operation=str(uuid.uuid4())
    status,_=after.call('POST',endpoint,dict(name='Capacity pending',administratorLogin='pending',administratorPassword=secrets.token_urlsafe(32)),pending_operation)
    check(status==202,'capacity admission')
    until(lambda:after.call('GET',endpoint+'/'+pending_operation)[1]['result']['blocked']=='capacity')
    return dict(status='passed',checks=['formal_install','independent_administrators','real_authentication',
        'repeat_install_identity','fixed_ledger_key','platform_business_isolation','second_tenant_host',
        'original_operation_replay','operator_restart_resume','tenant_host_isolation','nonroot_volume_runtime',
        'bridge_network','server_without_docker_authority','configuration_application','maintenance_identity_preservation','failed_configuration_correction','joint_cold_backup_restore',
        'original_ledger_and_protection_material','restored_operator_consumes_work'])
