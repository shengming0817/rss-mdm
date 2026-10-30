#!/usr/bin/env python3
"""Small real Compose check: seeded identities, replay and a separately deployed second tenant."""
import http.client
import json
from pathlib import Path
import ssl
import socket
import subprocess
import time
import uuid
from urllib.parse import urlsplit


def check(value, reason):
    if not value: raise RuntimeError(reason)


def until(predicate, seconds=180):
    # Product readiness includes the baseline owner's bounded retry after 60s.
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        try:
            if predicate():return
        except (OSError,http.client.HTTPException):pass
        time.sleep(.5)
    raise RuntimeError('Compose readiness deadline')


class Installation:
    def __init__(self, root, compose, project, environment=None):
        self.root=root;self.compose_file=compose;self.project=project;self.ports_file=None;self.initialization_file=None
        self.prefix=['docker','compose','--env-file',str(environment or root/'.env'),'-p',project,'-f',str(compose)]

    def compose(self,*args):
        files=[arg for path in (self.initialization_file,self.ports_file) if path for arg in ('-f',str(path))]
        result=subprocess.run([*self.prefix,*files,*args],capture_output=True,text=True,timeout=600)
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
    def __init__(self, origin, ca, port):
        self.origin=origin;self.url=urlsplit(origin);self.cookie='';self.csrf='';self.port=port
        self.context=ssl.create_default_context(cafile=str(ca))

    def call(self, method, path, data=None, operation=None):
        headers={'Origin':self.origin,'X-Identity-Request':'1'}
        if self.cookie:headers['Cookie']=self.cookie
        if self.csrf:headers['X-CSRF-Token']=self.csrf
        if operation:headers['Idempotency-Key']=operation
        if data is not None:headers['Content-Type']='application/json'
        connection=http.client.HTTPSConnection(self.url.hostname,self.url.port or 443,context=self.context,timeout=20)
        try:
            connection.sock=self.context.wrap_socket(socket.create_connection(("127.0.0.1",self.port),timeout=20),server_hostname=self.url.hostname)
            connection.request(method,path,json.dumps(data) if data is not None else None,headers)
            response=connection.getresponse()
            cookies=response.headers.get_all('set-cookie') or []
            if cookies:self.cookie='; '.join(value.split(';',1)[0] for value in cookies)
            raw=response.read()
            try:value=json.loads(raw) if raw else None
            except json.JSONDecodeError:
                if path=='/' and response.status==200:value=raw.decode('utf-8')
                elif response.status in (502,503):value=None
                else:raise
            if isinstance(value,dict) and value.get('csrfToken'):self.csrf=value['csrfToken']
            return response.status,value
        finally:connection.close()

    def login(self, tenant, login, password):
        status,_=self.call('POST','/api/v1/identity/tenants/'+tenant+'/login',dict(login=login,password=password))
        check(status==200,'real account login')



def storage_roundtrip(owner, business):
    """One stopped product database, restored by the same pinned PostgreSQL image."""
    path = '/api/v1/user-attribute-definitions/' + str(uuid.uuid4())
    definition = dict(key='restoreProof',displayName='Restore proof',source=dict(kind='identity_local'),
        pointer='/extensions/restoreProof',valueType='string',maxLength=64,maxItems=None,
        minimum=None,maximum=None,enabled=True,sensitive=False,visibility='both',
        displayUse='profile',required=False,useExistingObservation=False)
    request = dict(operationId=str(uuid.uuid4()),expectedRevision=0,value=definition)
    status, receipt = business.call('PUT', path, request)
    check(status == 200, 'candidate pre-backup write')
    configuration = json.loads(owner.read('/var/lib/rss-mdm/installation-input.json'))
    database = configuration['database']['name']
    check(database not in ('postgres','template0','template1'), 'owned product database')
    owner.compose('stop','server','maintenance')
    quoted = "'" + database.replace("'", "''") + "'"
    active = owner.compose('exec','-T','postgres','psql','-U','postgres','-d','postgres','-XAt','-v','ON_ERROR_STOP=1',
        '-c', 'SELECT count(*) FROM pg_stat_activity WHERE datname=' + quoted)
    check(active == '0', 'product writers stopped before archive')
    archive = '/tmp/candidate-product-' + uuid.uuid4().hex + '.dump'
    try:
        owner.compose('exec','-T','postgres','pg_dump','-U','postgres','--format=custom','--create','--file',archive,'--dbname',database)
        owner.compose('exec','-T','postgres','chmod','600',archive)
        owner.compose('exec','-T','postgres','dropdb','-U','postgres',database)
        owner.compose('exec','-T','postgres','pg_restore','-U','postgres','--create','--exit-on-error','--dbname','postgres',archive)
    finally:
        owner.compose('exec','-T','postgres','rm','-f',archive)
    owner.compose('up','-d','--no-deps','server','maintenance')
    until(lambda: business.call('GET','/readyz')[0] == 200)
    status, replay = business.call('PUT', path, request)
    check(status == 200 and replay == receipt, 'candidate restored original write receipt')
    status, record = business.call('GET', path)
    check(status == 200 and record is not None, 'candidate restored product read')
    request = dict(operationId=str(uuid.uuid4()),expectedRevision=1,
        value=dict(definition,displayName='After recovery'))
    status, changed = business.call('PUT', path, request)
    check(status == 200 and changed['definition']['revision'] == 2, 'candidate post-restore write')


def qualify(owner,origin,other_origin,port,second_backend):
    # Declare capacity before installation; maintenance cannot enlarge the persisted budget.
    inputs='/var/lib/rss-mdm/inputs/'
    slot=dict(origin=other_origin,listen=second_backend+':8081',deployment=dict(
        directory='/var/lib/rss-mdm/runtime/second',gateway_directory='/var/lib/rss-mdm/runtime/gateway',
        probe_address='gateway:'+str(urlsplit(other_origin).port or 443),
        certificate_file=inputs+'gateway.crt',private_key_file=inputs+'gateway.key',
        trust_file=inputs+'gateway-ca.crt',content_volume='/var/lib/rss-mdm-content'))
    initialize="import sys;sys.path.insert(0,'/usr/local/lib/rss-mdm');from initialize import run;run("+repr([slot])+")"
    owner.initialization_file=owner.root/'planned-hosts.compose.json'
    owner.initialization_file.write_text(json.dumps(dict(services=dict(init=dict(entrypoint=['python3','-c',initialize])))))
    owner.compose('up','-d','postgres')
    owner.compose('run','--rm','init')
    exported=owner.read('/var/lib/rss-mdm/runtime/gateway/gateway-ports.compose.yaml')
    owner.ports_file=owner.root/'gateway-ports.compose.yaml'
    owner.ports_file.write_text(exported)
    model=json.loads(owner.compose('config','--format','json'))
    from gateway_fixture import Gateway
    import importlib.util
    spec=importlib.util.spec_from_file_location('candidate_gateway_renderer',owner.root/'render_gateway.py')
    renderer=importlib.util.module_from_spec(spec);spec.loader.exec_module(renderer)
    Gateway('',model['services']['gateway']['ports'],renderer).publish(owner.ports_file,isolated=True,published={urlsplit(origin).port or 443:port})
    owner.compose('up','-d')
    first=json.loads(owner.read('/var/lib/rss-mdm/installation/installation.json'))['receipt']
    check(first['stage']=='initialized','seed initialization')
    check(first['platformPrincipalId']!=first['administratorId'],'independent administrators')
    ca=owner.root/'inputs/gateway-ca.crt'
    business=Browser(origin,ca,port)
    until(lambda:business.call('GET','/readyz')[0]==200)
    business.login(first['tenantId'],'administrator',(owner.root/'inputs/administrator-password').read_text().strip())
    status,grants=business.call('GET','/api/v1/authorization')
    check(status==200,'real business authorization')
    owner.product('prepare-hosts')
    platform=Browser(origin,ca,port)
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
    owner.product('prepare-hosts')
    # Ordinary Compose override supplied by the acceptance environment, not by product code.
    second_owner=Installation(owner.root,owner.root/'tenant.compose.yaml',owner.project+'-second',owner.root/'second.env')
    try:
        second_owner.compose('up','-d')
        owner.compose('run','--rm','--no-deps','--user','10001:10001','--entrypoint','python3','init','/usr/local/lib/rss-mdm/render_gateway.py','--root','/var/lib/rss-mdm/runtime/gateway')
        owner.compose('exec','-T','gateway','nginx','-t','-c','/run/gateway/nginx.conf')
        owner.compose('exec','-T','gateway','nginx','-s','reload','-c','/run/gateway/nginx.conf')
        peer=Browser(other_origin,ca,port)
        until(lambda:peer.call('GET','/readyz')[0]==200)
        status,_=peer.call('POST','/api/v1/identity/tenants/'+first['tenantId']+'/login',dict(login='administrator',password=(owner.root/'inputs/administrator-password').read_text().strip()))
        check(status==401,'first tenant account rejected by second host')
        peer.login(str(second['tenantId']),'second','Second-compose-admin-2026!')
        status,_=platform.call('GET','/api/v1/resources')
        check(status in (401,403),'platform cannot access business resources')
        owner.product('prepare-hosts')
        status,observed=platform.call('GET','/api/v1/tenant-administration/provisionings/'+operation)
        check(status==200 and observed['result']['phase']=='enabled','actual second host observation')
    finally:
        second_owner.compose('down','--remove-orphans')
    # Inspect actual mounted runtime services; no init/runtime receives engine access.
    ids=owner.compose('ps','--all','--quiet').split()
    actual=json.loads(subprocess.check_output(['docker','inspect',*ids],text=True))
    check(all(not any(m['Destination'].endswith('docker.sock') for m in c['Mounts']) for c in actual),'no Docker socket')
    published=[binding['HostPort'] for c in actual for bindings in (c.get('NetworkSettings',{}).get('Ports') or {}).values() for binding in (bindings or [])]
    check(published==[str(port)],'only gateway entry is published')
    status,static=business.call('GET','/')
    check(status==200 and isinstance(static,str) and '<html' in static.lower(),'real console static response')
    for service in ('web','server','gateway'):
        owner.compose('up','-d','--no-deps','--force-recreate',service)
        until(lambda:business.call('GET','/readyz')[0]==200)
        until(lambda:business.call('GET','/')==(200,static))
    storage_roundtrip(owner,business)
    return dict(status='passed',checks=['seed_and_replay','first_host_observation','real_administrators_and_authorization','second_tenant_login_and_isolation','compose_owned_services','same_candidate_product_restore'])
