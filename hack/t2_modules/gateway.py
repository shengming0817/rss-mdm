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
ROOT=Path(__file__).resolve().parents[2]

def verify(context):
    # Only TLS/file/listener locations are adapted for this loopback protocol seam.
    # The source-key, budget, burst, error and location rules are the production file.
    config=(ROOT/'deployment/nginx.conf').read_text()
    config=config.replace('listen 443 ssl;','listen 8080;').replace('ssl_certificate /private/mdm-tls.crt;','').replace('ssl_certificate_key /private/mdm-tls.key;','')
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
        from candidate_runtime import public_host_inputs
        public=public_host_inputs({'product_origin':'https://mdm.example.test','identity':{'tenant_id':'11111111-1111-4111-8111-111111111111','oidc':None}})['mdm.json']
        subprocess.run(['docker','exec','-i',name,'sh','-ec','mkdir -p /run/config; cat > /run/config/mdm.json; chmod 644 /run/config/mdm.json'],input=json.dumps(public),check=True,capture_output=True,text=True,timeout=10)
        status,body=request('/api/v1/mdm-host/config.json',method='GET')
        if status!=200 or json.loads(body)!=public:raise RuntimeError('MDM host configuration was not served by the exact static route')
        status,body=request('/api/unsupported-test',method='GET')
        if status!=404 or json.loads(body)!={'code':'not_found'}:raise RuntimeError('API error fell through to SPA')
        status,body=request('/software/native/sources/retired/test/information',method='GET')
        if status!=404 or json.loads(body)!={'code':'not_found'}:raise RuntimeError('retired native software API fell through to SPA')
        for path in ['/api/v1/agent/enroll/certificates', '/api/v1/agent/runtime/tasks/task/content', '/api/v1/agent/enroll/installations/operation/package']:
            if request(path,method='GET')[0] != 404: raise RuntimeError('Agent route leaked through browser gateway: '+path)
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
            for length in (limit-1,limit,limit+1):
                expected = 200 if length <= limit else 413
                if request(path,method=method,body=b'x'*length)[0]!=expected:
                    raise RuntimeError('management body boundary mismatch: '+path+' '+str(length))
            chunks=(b'x'*65536 for _ in range(limit//65536+1))
            if request(path,method=method,body=chunks)[0]!=413:
                raise RuntimeError('chunked management body exceeded: '+path)
        for path in ['/api/v1/devices/device/operations/id/cancel','/api/v1/resources/resource/unrelated',
                     '/api/v1/policies','/api/v1/policies/policy/rerun','/api/v1/pki/crls/unrelated',
                     '/api/v1/pki/signing/recover/unrelated','/api/v1/windows/entra-policy/unrelated',
                     '/api/v1/certificate-archive/import/unrelated','/api/v1/authorization/rules',
                     '/api/v1/authorization/user-groups/group/members',
                     '/api/v1/tenant-administration/authorization/rules/rule/unrelated',
                     '/api/v1/agent-packages/package','/api/v1/software/imports/unrelated']:
            if request(path,body=b'x'*16385)[0]!=413:raise RuntimeError('unrelated route inherited management body budget: '+path)
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
        print('login gateway T2: actual peer budget, spoofed forwarding rejection, bounded recovery and isolated Agent listener routing passed')

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
                config=(ROOT/'deployment/nginx.conf').read_text()
                config=config.replace('listen 443 ssl;','listen 8080;').replace('ssl_certificate /private/mdm-tls.crt;','').replace('ssl_certificate_key /private/mdm-tls.key;','')
                config=config.replace('server 127.0.0.1:8081;',f'server host.docker.internal:{relay.server_port};')
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
                    require(browser.call('POST',identity+'/login',dict(login=case['adminLogin'],password=password))[0]==200,'gateway business login')
                    status,principal=browser.call('GET','/api/v1/authorization')
                    require(status==200,'gateway business authorization')
                    members=[dict(instanceId=principal['instanceId'],tenantId=tenant,principalId=str(uuid.uuid4())) for _ in range(256)]
                    path='/api/v1/authorization/user-groups/'+str(uuid.uuid4())
                    update=dict(operationId=str(uuid.uuid4()),expectedRevision=0,value=dict(name='gateway-large-group',enabled=True,members=members))
                    require(len(json.dumps(update).encode())>16384,'gateway business fixture not large')
                    status,receipt=browser.call('PUT',path,update)
                    require(status==200 and receipt['revision']==1,'gateway rejected legal large user group')
                    require(browser.call('PUT',path,update)==(status,receipt),'gateway business receipt replay')
                    status,page=browser.call('GET',path+'/members')
                    require(status==200 and page['items'],'gateway business members not persisted')
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
                    require(browser.call('PUT',path,update)==(status,receipt),'gateway did not recover after overflow')
            finally:relay.shutdown();thread.join(timeout=5)
    finally:host.close()

def main(context, fixture):
    verify(context)
    verify_business(context, fixture)
