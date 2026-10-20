#!/usr/bin/env python3
"""Small real Compose check: seeded identities, replay and a separately deployed second tenant."""
import http.client
import json
from pathlib import Path
import ssl
import subprocess
import time
import uuid
from urllib.parse import urlsplit


def check(value, reason):
    if not value: raise RuntimeError(reason)


def until(predicate, seconds=120):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        try:
            if predicate():return
        except (OSError,http.client.HTTPException):pass
        time.sleep(.5)
    raise RuntimeError('Compose readiness deadline')


class Installation:
    def __init__(self, root, compose, project, environment=None):
        self.root=root;self.compose_file=compose;self.project=project
        self.prefix=['docker','compose','--env-file',str(environment or root/'.env'),'-p',project,'-f',str(compose)]

    def compose(self,*args):
        result=subprocess.run([*self.prefix,*args],capture_output=True,text=True,timeout=600)
        if result.returncode:raise RuntimeError('Compose action failed: '+args[0])
        return result.stdout.strip()

    def script(self,source):
        return self.compose('run','--rm','--no-deps','--user','10001:10001','-T','--entrypoint','python3','init','-c',source)

    def read(self,path):
        return self.script('from pathlib import Path;print(Path('+repr(path)+').read_text(),end="")')

    def product(self,command,path='/var/lib/rss-mdm/installation-input.json'):
        return self.compose('run','--rm','--no-deps','--user','10001:10001','--entrypoint','/usr/local/bin/rss-mdm-installer','init',command,'--config',path)

    def cleanup(self):
        self.compose('down','--volumes','--remove-orphans')


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
            try:value=json.loads(raw) if raw else None
            except json.JSONDecodeError:
                if response.status in (502,503):value=None
                else:raise
            if isinstance(value,dict) and value.get('csrfToken'):self.csrf=value['csrfToken']
            return response.status,value
        finally:connection.close()

    def login(self, tenant, login, password):
        status,_=self.call('POST','/api/v1/identity/tenants/'+tenant+'/login',dict(login=login,password=password))
        check(status==200,'real account login')



def qualify(owner,origin,other_origin):
    owner.compose('up','-d')
    first=json.loads(owner.read('/var/lib/rss-mdm/installation/installation.json'))['receipt']
    check(first['stage']=='initialized','seed initialization')
    check(first['platformPrincipalId']!=first['administratorId'],'independent administrators')
    ca=owner.root/'inputs/gateway-ca.crt'
    business=Browser(origin,ca)
    until(lambda:business.call('GET','/readyz')[0]==200)
    business.login(first['tenantId'],'administrator',(owner.root/'inputs/administrator-password').read_text().strip())
    status,grants=business.call('GET','/api/v1/authorization')
    check(status==200,'real business authorization')
    owner.product('prepare-hosts')
    platform=Browser(origin,ca)
    # The public host config supplies the actual reserved management tenant.
    status,public=business.call('GET','/api/v1/mdm-host/config.json')
    check(status==200,'public management locator')
    platform.login(public['managementTenant'],'platform',(owner.root/'inputs/platform-password').read_text().strip())
    status,observed=platform.call('GET','/api/v1/tenant-administration/provisionings/'+first['operationId'])
    check(status==200 and observed['result']['phase']=='enabled','actual first host observation')
    owner.compose('run','--rm','init')
    repeated=json.loads(owner.read('/var/lib/rss-mdm/installation/installation.json'))['receipt']
    check(first==repeated,'stable seed replay')
    operation=str(uuid.uuid4())
    status,created=platform.call('POST','/api/v1/tenant-administration/provisionings',
        dict(name='Second organization',administratorLogin='second',administratorPassword='Second-compose-admin-2026!'),operation)
    check(status==202,'real second tenant and administrator')
    second=created['result']
    owner.script("import json,pathlib;p=pathlib.Path('/var/lib/rss-mdm/installation-input.json');v=json.loads(p.read_text().strip());d=dict(v['deployment'],directory='/var/lib/rss-mdm/runtime/second',probe_address='second-server:8445');v['additional_hosts']=[dict(origin=SECOND_ORIGIN,listen='127.0.0.1:8081',deployment=d)];q=p.with_name('maintenance.json');q.write_text(json.dumps(v));q.chmod(0o600)".replace('SECOND_ORIGIN',repr(other_origin)))
    owner.product('prepare-hosts','/var/lib/rss-mdm/maintenance.json')
    # Ordinary Compose override supplied by the acceptance environment, not by product code.
    second_owner=Installation(owner.root,owner.root/'tenant.compose.yaml',owner.project+'-second',owner.root/'second.env')
    try:
        second_owner.compose('up','-d')
        peer=Browser(other_origin,ca)
        until(lambda:peer.call('GET','/readyz')[0]==200)
        status,_=peer.call('POST','/api/v1/identity/tenants/'+first['tenantId']+'/login',dict(login='administrator',password=(owner.root/'inputs/administrator-password').read_text().strip()))
        check(status==401,'first tenant account rejected by second host')
        peer.login(str(second['tenantId']),'second','Second-compose-admin-2026!')
        status,_=platform.call('GET','/api/v1/resources')
        check(status in (401,403),'platform cannot access business resources')
        owner.product('prepare-hosts','/var/lib/rss-mdm/maintenance.json')
        status,observed=platform.call('GET','/api/v1/tenant-administration/provisionings/'+operation)
        check(status==200 and observed['result']['phase']=='enabled','actual second host observation')
    finally:
        second_owner.compose('down','--remove-orphans')
    # Inspect actual mounted runtime services; no init/runtime receives engine access.
    ids=owner.compose('ps','--all','--quiet').split()
    actual=json.loads(subprocess.check_output(['docker','inspect',*ids],text=True))
    check(all(not any(m['Destination'].endswith('docker.sock') for m in c['Mounts']) for c in actual),'no Docker socket')
    return dict(status='passed',checks=['seed_and_replay','first_host_observation','real_administrators_and_authorization','second_tenant_login_and_isolation','compose_owned_services'])
