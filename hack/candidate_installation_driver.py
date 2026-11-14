#!/usr/bin/env python3
"""Real Compose journey: add a tenant to the running shared installation."""
import http.client
import json
from pathlib import Path
import ssl
import socket
import subprocess
import time
import uuid
from urllib.parse import urlsplit, urlencode


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
        self.root=root;self.compose_file=compose;self.project=project;self.ports_file=None
        self.prefix=['docker','compose','--env-file',str(environment or root/'.env'),'-p',project,'-f',str(compose)]

    def compose(self,*args,rejected=None):
        files=['-f',str(self.ports_file)] if self.ports_file else []
        result=subprocess.run([*self.prefix,*files,*args],capture_output=True,text=True,timeout=600)
        if rejected is not None:
            check(result.returncode != 0 and rejected in result.stderr, 'expected product rejection: '+rejected)
            return ''
        if result.returncode:raise RuntimeError('Compose action failed: '+args[0])
        return result.stdout.strip()

    def script(self,source):
        return self.compose('run','--rm','--no-deps','--user','10001:10001','-T','--entrypoint','python3','init','-c',source)

    def read(self,path):
        return self.script('from pathlib import Path;print(Path('+repr(path)+').read_text(),end="")')

    def product(self,command,path='/var/lib/rss-mdm/installation-input.json',rejected=None):
        return self.compose('run','--rm','--no-deps','--user','10001:10001','--entrypoint','/usr/local/bin/rss-mdm-installer','init',command,'--config',path,rejected=rejected)

    def cleanup(self):
        self.compose('down','--volumes','--remove-orphans')


class Browser:
    def __init__(self, origin, ca, port):
        self.origin=origin;self.url=urlsplit(origin);self.cookie='';self.csrf='';self.port=port
        self.context=ssl.create_default_context(cafile=str(ca))
        self.tenant=None

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
            if raw and response.getheader('Content-Type','').startswith('application/json'):
                value=json.loads(raw)
            elif path=='/' and response.status==200:
                value=raw.decode('utf-8')
            else:
                value=None
            if isinstance(value,dict) and value.get('csrfToken'):self.csrf=value['csrfToken']
            return response.status,value
        finally:connection.close()

    def ready(self):
        status,value=self.call('GET','/readyz')
        return status==200 and isinstance(value,dict) and value.get('ready') is True

    def login(self, tenant, login, password):
        status,_=self.call('POST','/api/v1/identity/tenants/'+tenant+'/login',dict(login=login,password=password))
        check(status==200,'real account login')
        self.tenant=tenant

    def business_path(self, path):
        check(self.tenant is not None, 'authenticated tenant')
        return '/api/v1/tenants/'+self.tenant+path



def storage_roundtrip(owner, business):
    """One stopped product database, restored by the same pinned PostgreSQL image."""
    path = business.business_path('/user-attribute-definitions/' + str(uuid.uuid4()))
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
    until(business.ready)
    status, replay = business.call('PUT', path, request)
    check(status == 200 and replay == receipt, 'candidate restored original write receipt')
    status, record = business.call('GET', path)
    check(status == 200 and record is not None, 'candidate restored product read')
    request = dict(operationId=str(uuid.uuid4()),expectedRevision=1,
        value=dict(definition,displayName='After recovery'))
    status, changed = business.call('PUT', path, request)
    check(status == 200 and changed['definition']['revision'] == 2, 'candidate post-restore write')


def observe_runtime(browser,runtime):
    status,value=browser.call('GET','/readyz')
    check(status==200 and value['ready'],'host readiness')
    observed=value['observation'];binding=runtime['runtime_binding']
    for public,private in [('hostId','host_id'),('operationId','operation_id'),('revision','revision'),('materialDigest','material_digest')]:
        check(observed[public]==binding[private],'exact runtime '+public)
    check(observed['instanceId']==runtime['identity']['instance_id'],'exact installation')
    check(uuid.UUID(observed['processGeneration']).int!=0,'live process generation')
    return observed


def qualify(owner,origin,port):
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
    until(business.ready)
    password=(owner.root/'inputs/administrator-password').read_text().strip()
    business.login(first['tenantId'],'administrator',password)
    status,public=business.call('GET','/api/v1/mdm-host/config.json')
    check(status==200 and set(public)=={'serviceId','canonicalOrigin','managementTenant'}
          and public['canonicalOrigin']==origin,'current public host contract')
    platform=Browser(origin,ca,port)
    platform.login(public['managementTenant'],'platform',(owner.root/'inputs/platform-password').read_text().strip())

    def completed(operation):
        status,receipt=platform.call('GET','/api/v1/tenant-administration/provisionings/'+operation)
        check(status==200,'original provisioning receipt')
        result=receipt['result']
        check(set(result)=={'tenantId','administratorId','phase','blocked','entryPath'},'current provisioning contract')
        return result['phase']=='configured'

    until(lambda:completed(first['operationId']))
    for route in ('/authorization','/resources','/asset-fields'):
        status,value=business.call('GET',business.business_path(route))
        check(status==200,'first tenant default business: '+route)
        if route!='/authorization':check((value['asset'] if route=='/asset-fields' else value)['items'],'installed default business: '+route)

    runtime_path='/var/lib/rss-mdm/installation/runtime.json'
    original_runtime=owner.read(runtime_path)
    original_input=owner.read('/var/lib/rss-mdm/installation-input.json')
    until(business.ready)
    prior=observe_runtime(business,json.loads(original_runtime))
    def resources():
        # Snapshot actual process/deployment resources, not lazy connection occupancy.
        ids=owner.compose('ps','--status','running','--quiet').split()
        containers=json.loads(subprocess.check_output(['docker','inspect',*ids],text=True))
        check(all(not any(m['Destination'].endswith('docker.sock') for m in c['Mounts']) for c in containers),'no Docker socket')
        published=[binding['HostPort'] for c in containers for bindings in (c.get('NetworkSettings',{}).get('Ports') or {}).values() for binding in (bindings or [])]
        check(published==[str(port)],'only gateway entry is published')
        identities=owner.compose('exec','-T','postgres','psql','-U','postgres','-d','postgres','-XAt','-v','ON_ERROR_STOP=1',
            '-c',"SELECT 'database:'||datname FROM pg_database UNION ALL SELECT 'role:'||rolname FROM pg_roles ORDER BY 1")
        return sorted(ids),identities,owner.compose('config','--format','json'),owner.read('/var/lib/rss-mdm/runtime/gateway/gateway-ports.compose.yaml')
    before=resources()
    operation=str(uuid.uuid4())
    request=dict(name='Second organization',administratorLogin='administrator',administratorPassword='Second-compose-admin-2026!')
    status,created=platform.call('POST','/api/v1/tenant-administration/provisionings',request,operation)
    check(status in (200,202) or (status==503 and created=={'code':'operation_unknown'}),'shared second tenant admission: '+str(status)+' '+str(created))
    until(lambda:completed(operation))
    status,receipt=platform.call('GET','/api/v1/tenant-administration/provisionings/'+operation)
    second=receipt['result']
    check(second['tenantId']!=first['tenantId'] and second['administratorId']!=first['administratorId'],'distinct tenant and administrator')
    check(second['entryPath']=='/tenants/'+second['tenantId'] and second['blocked'] is None,'configured tenant entry')
    check(resources()==before and owner.read(runtime_path)==original_runtime,'shared containers, listeners, database roles and deployment')
    check(observe_runtime(business,json.loads(original_runtime))==prior,'same running process serves new tenant')
    peer=Browser(origin,ca,port)
    status,_=peer.call('POST','/api/v1/identity/tenants/'+second['tenantId']+'/login',dict(login='administrator',password=password))
    check(status==401,'first tenant password rejected in second tenant')
    peer.login(second['tenantId'],'administrator',request['administratorPassword'])
    for route in ('/authorization','/resources','/asset-fields'):
        status,value=peer.call('GET',peer.business_path(route))
        check(status==200,'second tenant default business: '+route)
        if route!='/authorization':check((value['asset'] if route=='/asset-fields' else value)['items'],'second tenant initialized defaults: '+route)
    for session,path in ((business,peer.business_path('/resources')),(peer,business.business_path('/resources')),(platform,peer.business_path('/resources'))):
        check(session.call('GET',path)[0] in (401,403),'session cannot cross business tenant')
    status,replayed=platform.call('POST','/api/v1/tenant-administration/provisionings',request,operation)
    check(status==200 and replayed['result']==second,'original provisioning replay')

    tenants=[];cursor=None
    while True:
        query=dict(limit=1)
        if cursor:query['cursor']=cursor
        status,page=platform.call('GET','/api/v1/tenant-administration/tenants?'+urlencode(query))
        check(status==200,'tenant directory page')
        tenants.extend(row['tenantId'] for row in page['items'])
        cursor=page['nextCursor']
        if cursor is None:break
    check(len(tenants)==len(set(tenants)) and set(tenants)=={public['managementTenant'],first['tenantId'],second['tenantId']},'complete tenant directory across pages')
    owner.compose('run','--rm','init')
    check(owner.read('/var/lib/rss-mdm/installation-input.json')==original_input,'immutable installation input')
    check(json.loads(owner.read('/var/lib/rss-mdm/installation/installation.json'))['receipt']==first,'stable installation replay')
    status,static=business.call('GET','/')
    check(status==200 and isinstance(static,str) and '<html' in static.lower(),'console static response')
    storage_roundtrip(owner,business)
    peer.login(second['tenantId'],'administrator',request['administratorPassword'])
    check(peer.call('GET',peer.business_path('/resources'))[0]==200,'second tenant survives shared database recovery')
    check(completed(operation),'original provisioning survives recovery')
    return dict(status='passed',checks=['seed_and_replay','current_host_and_provisioning_contract','same_process_second_tenant',
        'shared_deployment_and_database_resources','real_administrators_and_default_business','tenant_session_isolation',
        'tenant_directory_pagination','provisioning_replay','same_candidate_product_restore'])
