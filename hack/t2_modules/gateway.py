"""Run production browser admission and isolated Agent routing against actual nginx."""
import http.client
import socket
from pathlib import Path
from t2_processes import subprocess
import tempfile
import time
import uuid
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace
from build_run import require_lease
from gateway_fixture import render
ROOT=Path(__file__).resolve().parents[2]

def verify(context):
    verify_sni(context)
    # Only TLS/file/listener locations are adapted for this loopback protocol seam.
    # The source-key, budget, burst, error and location rules are the production file.
    config=render(ROOT/'deployment', backend='127.0.0.1:8082', public_port=8080, certificates='/run/config', web=False, plain=True)
    config=config.replace('server 127.0.0.1:8081;','server 127.0.0.1:8082;')
    locations = ''
    locations += 'location = /api/unsupported-test { default_type application/json; return 404 \'{"code":"not_found"}\'; }'
    config=config.rsplit('}',1)[0]+'server { listen 127.0.0.1:8082; client_max_body_size 128m; '+locations+' location / { return 200 "$http_x_forwarded_for"; } }}'
    with context.gateway(config) as (name,port):
        def request(path,forward='',body=None,method='POST'):
            c=http.client.HTTPConnection('127.0.0.1',port,timeout=15)
            try:
                c.request(method,path,body=body,headers={'Host':'mdm.example.test','Origin':'https://mdm.example.test','X-Identity-Request':'1','X-Forwarded-For':forward})
                r=c.getresponse();body=r.read()
                if r.status>=400 and any(r.getheader(k)!=v for k,v in [('Cache-Control','no-store'),('Referrer-Policy','no-referrer'),('X-Content-Type-Options','nosniff')]):raise RuntimeError('gateway rejection omitted security headers')
                return r.status,body
            finally:c.close()
        end=time.monotonic()+30
        while True:
            try:
                if request('/api/probe')[0]==200:break
            except OSError:pass
            if time.monotonic()>end:raise RuntimeError('gateway startup failed')
            time.sleep(.1)
        # Synthetic route payload only; registry-backed production generation is covered by management_tenant.
        public=dict(serviceId='33333333-3333-4333-8333-333333333333',canonicalOrigin='https://mdm.example.test',tenant='11111111-1111-4111-8111-111111111111',managementTenant='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')
        subprocess.run(['docker','exec','-i',name,'sh','-ec','mkdir -p /run/config; cat > /run/config/mdm.json; chmod 644 /run/config/mdm.json'],input=json.dumps(public),check=True,capture_output=True,text=True,timeout=10)
        status,body=request('/api/v1/mdm-host/config.json',method='GET')
        if status!=200 or json.loads(body)!=public:raise RuntimeError('MDM host configuration was not served by the exact static route')
        status,body=request('/api/unsupported-test',method='GET')
        if status!=404 or json.loads(body)!={'code':'not_found'}:raise RuntimeError('API error fell through to SPA')
        status,body=request('/software/native/sources/retired/test/information',method='GET')
        if status!=404 or json.loads(body)!={'code':'not_found'}:raise RuntimeError('retired native software API fell through to SPA')
        for path in ['/api/v1/agent/enroll/certificates', '/api/v1/agent/runtime/tasks/task/content', '/api/v1/agent/enroll/installations/operation/package']:
            if request(path,method='GET')[0] != 200: raise RuntimeError('shared Agent route did not reach private HTTP ingress: '+path)
        status, forwarded=request('/api/probe','203.0.113.254')
        if status!=200 or not forwarded or forwarded==b'203.0.113.254':raise RuntimeError('gateway failed to overwrite source header')
        statuses=[]
        for n in range(25):
            status,body=request('/api/v1/identity/tenants/11111111-1111-4111-8111-111111111111/login','203.0.113.'+str(n));statuses.append(status)
            if status==429 and json.loads(body)!={'code':'request_limited'}:raise RuntimeError('incorrect rate-limit response')
        if 200 not in statuses or 429 not in statuses or statuses.count(200)>14:raise RuntimeError('caller-controlled source bypassed login admission')
        time.sleep(3.2)
        if request('/api/v1/identity/tenants/11111111-1111-4111-8111-111111111111/login')[0]!=200:raise RuntimeError('login budget did not recover')
        # Each exceptional management route must reach upstream at its exact ceiling.
        # Test real chunked bodies too: a false/missing Content-Length cannot bypass nginx.
        budgets = [
            ('POST','/api/v1/devices/device/operations',16*1024*1024),
            ('POST','/api/v1/resources/resource',8*1024*1024),
            ('POST','/api/v1/policies/policy',8*1024*1024),
            ('POST','/api/v1/policies/previews',8*1024*1024),
            ('POST','/api/v1/pki/rotations',64*1024*1024),
            ('POST','/api/v1/pki/crls',64*1024*1024),
            ('POST','/api/v1/pki/signing/recover',256*1024),
            ('PUT','/api/v1/windows/entra-policy',128*1024),
            ('POST','/api/v1/certificate-archive/import',2*1024*1024),
            ('PUT','/api/v1/authorization/rules/rule',2*1024*1024),
            ('PUT','/api/v1/authorization/user-groups/group',2*1024*1024),
            ('PUT','/api/v1/tenant-administration/authorization/rules/rule',2*1024*1024),
            ('POST','/api/v1/agent-packages',1024*1024),
            ('POST','/api/v1/agent-packages/package/withdraw',1024*1024),
            ('POST','/api/v1/software/imports',1024*1024),
            ('POST','/api/v1/software/sources/source/revisions/revision',1024*1024),
            ('POST','/api/v1/software/resources/resource/versions/version',1024*1024),
        ]
        for method,path,limit in budgets:
            for length in (limit,limit+1):
                expected = 200 if length <= limit else 413
                status=request(path,method=method,body=b'x'*length)[0]
                if status!=expected:
                    raise RuntimeError('management body boundary mismatch: '+path+' '+str(length)+' status='+str(status))
                # Exercise size independently of the shared 10 requests/second admission.
                time.sleep(.12)
            chunks=(b'x'*65536 for _ in range(limit//65536+1))
            if request(path,method=method,body=chunks)[0]!=413:
                raise RuntimeError('chunked management body exceeded: '+path)
            time.sleep(.12)
        for path in ['/api/v1/devices/device/operations/id/cancel','/api/v1/resources/resource/unrelated',
                     '/api/v1/policies','/api/v1/policies/policy/rerun','/api/v1/pki/crls/unrelated',
                     '/api/v1/pki/signing/recover/unrelated','/api/v1/windows/entra-policy/unrelated',
                     '/api/v1/certificate-archive/import/unrelated','/api/v1/authorization/rules',
                     '/api/v1/authorization/user-groups/group/members',
                     '/api/v1/tenant-administration/authorization/rules/rule/unrelated',
                     '/api/v1/agent-packages/package','/api/v1/software/imports/unrelated']:
            if request(path,body=b'x'*16385)[0]!=413:raise RuntimeError('unrelated route inherited management body budget: '+path)
            time.sleep(.12)
        if request('/api/probe',body='x'*16385)[0]!=413:raise RuntimeError('oversized request was not rejected')
        if request('/api/probe?credential=synthetic-sensitive-value')[0]!=200:raise RuntimeError('gateway probe failed')
        held=[]
        try:
            deadline=time.monotonic()+3
            while len(held)<8:
                connection=socket.create_connection(('127.0.0.1',port),timeout=3)
                connection.sendall(b'POST /api/probe HTTP/1.1\r\nHost: mdm.example.test\r\nContent-Length: 1024\r\nExpect: 100-continue\r\n\r\n')
                reply=b''
                while b'\r\n\r\n' not in reply:
                    chunk=connection.recv(4096)
                    if not chunk:break
                    reply+=chunk
                if reply.startswith(b'HTTP/1.1 100 '):held.append(connection)
                else:
                    connection.close()
                    if time.monotonic()>deadline:raise RuntimeError('could not establish admitted connection set')
                    time.sleep(.05)
            deadline=time.monotonic()+3
            while request('/api/probe','198.51.100.99')[0]!=429:
                if time.monotonic()>deadline:raise RuntimeError('peer connection cap not enforced')
                time.sleep(.05)
        finally:
            for connection in held:connection.close()
        deadline=time.monotonic()+3
        while request('/api/probe')[0]!=200:
            if time.monotonic()>deadline:raise RuntimeError('connection slots did not recover')
            time.sleep(.05)
        statuses = [request('/api/protected', '203.0.113.'+str(n))[0] for n in range(40)]
        if 200 not in statuses or 429 not in statuses: raise RuntimeError('general API admission is not bounded')
        log=subprocess.run(['docker','logs',name],check=True,capture_output=True,text=True,timeout=10)
        if 'synthetic-sensitive-value' in log.stdout+log.stderr or 'mdm_gateway' not in log.stdout:raise RuntimeError('gateway logging contract failed')
        print('login gateway T2: actual peer budget, spoofed forwarding rejection, bounded recovery and shared gateway Agent routing passed')

def verify_business(context, fixture):
    from t2_hosts import Host
    from t2_modules.tenants import Browser, HostProcesses
    from verification_result import require
    builds=SimpleNamespace(processes=HostProcesses(),executables={'rss-mdm':fixture.binary})
    host=Host(builds,fixture.env['MDM_TEST_CONFIG'],fixture.root/'gateway-host')
    # The product listener stays loopback-only. This fixture relay lets the pinned
    # container gateway reach it on both Linux and Docker Desktop without changing
    # product authentication, authorization, body policy or PostgreSQL behavior.
    class Relay(BaseHTTPRequestHandler):
        def setup(self):
            super().setup();self.connection.settimeout(15)
        def do_GET(self):
            length=int(self.headers.get('Content-Length','0'))
            require(0<=length<=2*1024*1024,'gateway fixture relay body budget')
            connection=http.client.HTTPConnection(host.address,timeout=15)
            try:
                headers={k:v for k,v in self.headers.items() if k.lower() not in ('connection','transfer-encoding')}
                connection.request(self.command,self.path,body=self.rfile.read(length),headers=headers)
                response=connection.getresponse();body=response.read()
                self.send_response(response.status)
                for key,value in response.getheaders():
                    if key.lower() not in ('content-length','transfer-encoding','connection'):
                        self.send_header(key,value)
                self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            finally:connection.close()
        do_POST=do_GET
        do_PUT=do_GET
        def log_message(self,*args):pass
    try:
        with HTTPServer(('0.0.0.0',0),Relay) as relay:
            relay.timeout=15
            thread=threading.Thread(target=relay.serve_forever,daemon=True);thread.start()
            try:
                config=render(ROOT/'deployment', backend=f'host.docker.internal:{relay.server_port}', public_port=8080, certificates='/run/config', web=False, plain=True)
                with context.gateway(config) as (_,port):
                    browser=Browser(SimpleNamespace(address=f'127.0.0.1:{port}'),'https://mdm.example.test')
                    end=time.monotonic()+30
                    while True:
                        try:
                            if browser.call('GET','/readyz')[0]==200:break
                        except OSError:pass
                        require(time.monotonic()<end,'gateway business startup deadline');time.sleep(.1)
                    case=json.loads(Path(fixture.env['MDM_CASE_CONTEXT']).read_text())
                    tenant=case['tenant'];identity='/api/v1/identity/tenants/'+tenant
                    password=(fixture.root/'account-password').read_text()
                    require(browser.call('POST',identity+'/login',dict(login=next(actor['login'] for actor in case['actors'] if actor['tenant'] == case['tenant'] and actor['role'] == 'admin'),password=password))[0]==200,'gateway business login')
                    status,principal=browser.call('GET','/api/v1/authorization')
                    require(status==200,'gateway business authorization')
                    members=[dict(instanceId=principal['instanceId'],tenantId=tenant,principalId=str(uuid.uuid4())) for _ in range(256)]
                    path='/api/v1/authorization/user-groups/'+str(uuid.uuid4())
                    update=dict(operationId=str(uuid.uuid4()),expectedRevision=0,value=dict(name='gateway-large-group',enabled=True,members=members))
                    require(len(json.dumps(update).encode())>16384,'gateway business fixture not large')
                    status,receipt=browser.call('PUT',path,update)
                    require(status==200 and receipt['revision']==1,'gateway rejected legal large user group')
                    require(browser.call('PUT',path,update)==(status,receipt),'gateway business receipt replay')
                    seen=[]
                    offset=0
                    while True:
                        status,page=browser.call('GET',path+f'/members?offset={offset}&expectedRevision=1')
                        require(status==200 and page['revision']==1,'gateway member page failed')
                        seen.extend(page['items'])
                        next_offset=page['nextOffset']
                        require(len(seen)<=len(members), 'gateway member pagination exceeded expected members')
                        if next_offset is None:break
                        require(type(next_offset) is int and offset<next_offset<len(members), 'gateway member pagination did not advance within bounds')
                        offset=next_offset
                    require(len(seen)==len(members) and {m['principalId'] for m in seen}=={m['principalId'] for m in members},'gateway member pagination lost or duplicated identities')
                    query="SELECT revision::text || ':' || document::text FROM mdm_access.user_groups WHERE id='"+path.rsplit('/',1)[1]+"'"
                    before=fixture.owner.sql(query,fixture.database)
                    # Rejection must happen before another mutation reaches the business.
                    overflow=dict(update,operationId=str(uuid.uuid4()),value=dict(update['value'],name='x'*(2*1024*1024)))
                    # nginx returns HTML at this boundary, so do not decode it as JSON.
                    connection=http.client.HTTPConnection('127.0.0.1',port,timeout=15)
                    try:
                        connection.request('PUT',path,body=json.dumps(overflow),headers={'Host':'mdm.example.test','Origin':'https://mdm.example.test','Cookie':browser.cookie,'X-CSRF-Token':browser.csrf,'X-Identity-Request':'1','Content-Type':'application/json'})
                        response=connection.getresponse();response.read()
                        require(response.status==413,'gateway business overflow not rejected')
                    finally:connection.close()
                    require(fixture.owner.sql(query,fixture.database)==before,'gateway overflow changed business state')
                    require(browser.call('PUT',path,update)==(200,receipt),'gateway did not recover after overflow')
            finally:relay.shutdown();thread.join(timeout=5)
    finally:host.close()

def main(context, fixture):
    verify_network_allocation(context)
    verify(context)
    verify_business(context, fixture)


def verify_sni(context):
    """Real nginx terminates mTLS and overwrites evidence on its private HTTP hop."""
    import ssl
    from urllib.parse import unquote
    with tempfile.TemporaryDirectory(prefix='mdm-gateway-tls-') as directory:
        root=Path(directory)
        def openssl(*args):
            return subprocess.run(['openssl',*map(str,args)],cwd=root,check=True,capture_output=True,timeout=30).stdout
        openssl('req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=Gateway test CA','-keyout','ca.key','-out','ca.crt','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign','-addext','subjectKeyIdentifier=hash')
        for name,usage in [('server','serverAuth'),('client','clientAuth')]:
            openssl('req','-new','-newkey','rsa:2048','-nodes','-subj','/CN='+name,'-keyout',name+'.key','-out',name+'.csr')
            (root/'leaf.ext').write_text('subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage='+usage+'\nsubjectAltName=DNS:mdm.example.test,DNS:device.example.test,DNS:unknown.example.test\n')
            openssl('x509','-req','-in',name+'.csr','-CA','ca.crt','-CAkey','ca.key','-CAcreateserial','-days','1','-extfile','leaf.ext','-out',name+'.crt')
        expected=openssl('x509','-in','client.crt','-outform','DER')
        seen=[]
        class Backend(BaseHTTPRequestHandler):
            def do_GET(self):
                status=200;body=b'browser'
                if self.path.startswith('/api/v1/agent/'):
                    try:
                        certificate=ssl.PEM_cert_to_DER_cert(unquote(self.headers.get('X-RSS-Client-Cert','')))
                        valid=certificate==expected
                    except (ValueError,TypeError):valid=False
                    valid=valid and self.headers.get('X-RSS-Public-Origin')=='https://device.example.test'
                    valid=valid and self.headers.get('X-RSS-User-Session')=='device-user-session'
                    valid=valid and not any(self.headers.get(name) for name in ('Cookie','Authorization','X-Client-Cert','X-Device-ID','X-Tenant-ID','Forwarded'))
                    source=self.headers.get('X-Forwarded-For')
                    valid=valid and bool(source) and source!='203.0.113.9' and ',' not in source
                    status=200 if valid else 403;body=b'verified-client' if valid else b'rejected'
                    if valid:seen.append(certificate)
                self.send_response(status);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            def log_message(self,*args):pass
        backend=HTTPServer(('0.0.0.0',0),Backend)
        thread=threading.Thread(target=backend.serve_forever,daemon=True);thread.start()
        try:
            config=render(ROOT/'deployment',public_port=8080,backend=f'host.docker.internal:{backend.server_address[1]}',targets={'https://device.example.test':None},web=False,certificates='/run/probe')
            files={name:(root/name).read_text() for name in ['server.crt','server.key']}
            with context.gateway(config,files) as (name,port):
                def request(host,identity=None,authority=None,forged=True):
                    tls=ssl.create_default_context(cafile=str(root/'ca.crt'))
                    if identity:tls.load_cert_chain(root/(identity+'.crt'),root/(identity+'.key'))
                    path='/api/probe' if host=='mdm.example.test' else '/api/v1/agent/runtime/probe'
                    with socket.create_connection(('127.0.0.1',port),timeout=5) as raw:
                        with tls.wrap_socket(raw,server_hostname=host) as stream:
                            extra='X-RSS-Client-Cert: forged\r\nX-RSS-Public-Origin: https://evil.example.test\r\nX-Forwarded-For: 203.0.113.9\r\nX-Client-Cert: forged\r\nX-Device-ID: forged\r\nX-Tenant-ID: forged\r\nForwarded: for=forged\r\nCookie: session=secret\r\nAuthorization: Bearer secret\r\n' if forged else ''
                            stream.sendall(('GET '+path+' HTTP/1.1\r\nHost: '+(authority or host)+'\r\nX-RSS-User-Session: device-user-session\r\n'+extra+'Connection: close\r\n\r\n').encode())
                            chunks=[]
                            while True:
                                chunk=stream.recv(8192)
                                if not chunk:break
                                chunks.append(chunk)
                            return b''.join(chunks)
                until=time.monotonic()+30
                while True:
                    try:
                        if request('mdm.example.test').endswith(b'browser'):break
                    except OSError:pass
                    if time.monotonic()>until:raise RuntimeError('HTTPS gateway startup deadline')
                    time.sleep(.1)
                if b'421' not in request('mdm.example.test',authority='device.example.test').split(b'\r\n',1)[0]:raise RuntimeError('SNI/Host mismatch accepted')
                if not request('device.example.test','client').endswith(b'verified-client'):raise RuntimeError('gateway certificate evidence was not the actual TLS leaf')
                for host,identity in [('device.example.test',None),('device.example.test','server'),('unknown.example.test','client')]:
                    try:reply=request(host,identity)
                    except (OSError,ssl.SSLError):continue
                    if b'200 OK' in reply:raise RuntimeError('TLS identity or unknown SNI rejection bypassed')
                if seen!=[expected]:raise RuntimeError('gateway accepted forged evidence or forwarded browser credentials')
        finally:
            backend.shutdown();backend.server_close();thread.join(timeout=10)
            if thread.is_alive():raise RuntimeError('gateway HTTP participant did not stop')


def verify_network_allocation(context):
    """Two formerly colliding owners coexist; Compose adopts the reserved networks and frees their pools."""
    import hashlib
    import ipaddress
    from concurrent.futures import ThreadPoolExecutor
    from ingress_network import Ingress
    prefix='mdm-ipam-'+uuid.uuid4().hex[:12]
    buckets={}
    for index in range(257):
        project=f'{prefix}-{index}'
        bucket=hashlib.sha256(project.encode()).hexdigest()[:2]
        if bucket in buckets:
            projects=[buckets[bucket],project];break
        buckets[bucket]=project
    with tempfile.TemporaryDirectory(prefix='mdm-ingress-proof-') as temporary:
        root=Path(temporary)
        owners=[Ingress(root/str(i),project,project) for i,project in enumerate(projects)]
        recycle=Ingress(root/'recycle',prefix+'-recycle',prefix+'-recycle')
        definitions=[]
        try:
            with ThreadPoolExecutor(max_workers=2) as pool:
                values=list(pool.map(lambda owner:owner.allocate(),owners))
            a,b=[ipaddress.ip_network(value['MDM_INGRESS_SUBNET']) for value in values]
            if a.overlaps(b):raise RuntimeError('concurrent ingress allocations overlap')
            for owner,value in zip(owners,values,strict=True):
                if Ingress(owner.root,owner.project,owner.owner).allocate()!=value:raise RuntimeError('ingress resume changed addresses')
                definition=owner.root/'compose.json'
                definition.write_text(json.dumps({'services':{'probe':{'image':context.gateway_owner.providers['nginx'],'entrypoint':['/bin/sh','-c','exit 0'],'networks':{'ingress':{'ipv4_address':value['MDM_BACKEND_ADDRESS']}}}},'networks':{'ingress':{'internal':True,'ipam':{'config':[{'subnet':value['MDM_INGRESS_SUBNET']}]},'labels':{'rss.mdm.worktree':owner.owner}}}}))
                command=['docker','compose','--env-file','/dev/null','-p',owner.project,'-f',str(definition)]
                definitions.append(command)
                subprocess.run([*command,'run','--rm','--no-deps','probe'],check=True,capture_output=True,text=True,timeout=60)
                if owner.allocate()!=value:raise RuntimeError('Compose replaced the reserved network')
            subprocess.run([*definitions[0],'down','--remove-orphans'],check=True,capture_output=True,text=True,timeout=30)
            owners[0].release()
            if owners[0]._inspect() is not None:raise RuntimeError('released ingress remains allocated')
            arguments=['network','create','--driver','bridge','--internal','--subnet',str(a)]
            for key,value in recycle.labels.items():arguments+=['--label',key+'='+value]
            recycle._run(*arguments,recycle.name)
            recycle.allocate()
            if recycle.values()['MDM_INGRESS_SUBNET']!=str(a):raise RuntimeError('released pool was not reclaimed')
        finally:
            failures=[]
            for command in reversed(definitions):
                try:subprocess.run([*command,'down','--remove-orphans'],check=True,capture_output=True,text=True,timeout=30)
                except BaseException as error:failures.append(error)
            for owner in [recycle,*owners]:
                try:owner.release()
                except BaseException as error:failures.append(error)
            if failures:raise RuntimeError('owned ingress proof cleanup failed') from failures[0]
