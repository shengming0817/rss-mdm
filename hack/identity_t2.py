#!/usr/bin/env python3
"""Real MDM Router + immutable Identity binary + PG/Hydra/TLS seams, not product T3."""
import contextlib
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import sys
import ssl
import http.client
import re
import subprocess
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
PREFIX = '/tmp/mdm-identity-input/'
SENSITIVE = set()
TENANT = '11111111-1111-4111-8111-111111111111'
ADMIN = '11111111-2222-4333-8444-555555555555'

def run(args, **kwargs):
    stage=kwargs.pop('stage',' '.join(str(v) for v in args[:3]))
    test_output=kwargs.pop('test_output',False)
    kwargs.setdefault('timeout',900 if args[0]=='cargo' else 120)
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
    if result.returncode:
        # Commands can contain disposable database configuration; never echo argv or provider output.
        text=(result.stderr + ('\n'+result.stdout if test_output else ''))[-8192:]
        for value in sorted(SENSITIVE,key=len,reverse=True):text=text.replace(value,'<redacted>')
        text=re.sub(r'(https?://)[^\s/@]+:[^\s/@]+@',r'\1<redacted>@',text)
        raise RuntimeError('fixture stage '+stage+' failed (exit '+str(result.returncode)+'): '+text)
    return result.stdout.strip()

def docker(*args, **kwargs): return run(['docker', *args], **kwargs)
def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''): h.update(chunk)
    return h.hexdigest()

def candidate():
    location = os.environ.get('MDM_IDENTITY_CANDIDATE')
    if not location: raise RuntimeError('MDM_IDENTITY_CANDIDATE must name the approved immutable candidate directory')
    root = Path(location).resolve()
    actual = json.loads((root / 'candidate.json').read_text())
    expected = json.loads((ROOT / 'fixtures/identity-candidate.json').read_text())
    if actual != expected or actual['platform'] != 'linux/amd64': raise RuntimeError('candidate identity mismatch')
    for item in actual['archives'].values():
        path = root / item['file']
        if path.parent != root or path.is_symlink() or sha(path) != item['sha256']: raise RuntimeError('candidate archive digest mismatch')
        docker('load', '--input', str(path))
    return actual

def wait(check, label, seconds=60):
    end = time.monotonic() + seconds
    last='no response'
    while True:
        try:
            if check(): return
        except (RuntimeError, OSError) as error: last=str(error)
        if time.monotonic() >= end: raise RuntimeError(label + ' readiness failed: '+last)
        time.sleep(.25)

def build_binary():
    lines = run(['cargo','build','--locked','-p','rss-mdm-app','--bin','rss-mdm','--message-format=json'],cwd=ROOT).splitlines()
    bins = [v['executable'] for line in lines if (v:=json.loads(line)).get('reason')=='compiler-artifact' and v.get('executable') and v['target']['name']=='rss-mdm']
    if len(bins)!=1: raise RuntimeError('product binary identity missing')
    return bins[0]

@contextlib.contextmanager
def fixture(c):
    name = 'mdm2343-' + uuid.uuid4().hex[:10]
    created = []
    network = name + '-net'
    architecture=docker('info','--format','{{.Architecture}}')
    native='linux/'+{'aarch64':'arm64','arm64':'arm64','x86_64':'amd64','amd64':'amd64'}[architecture]
    with tempfile.TemporaryDirectory(prefix=name+'-') as directory:
        root = Path(directory)
        def write(name, value, public=False):
            p=root/name;p.write_text(value if isinstance(value,str) else json.dumps(value));p.chmod(0o644 if public else 0o600);return p
        def secret(name): return write(name,secrets.token_urlsafe(32)).read_text()
        values={n:secret(n) for n in ['owner','runtime','maintenance','hydra-db','hydra-system','hydra-service','oidc-client','validation','upstream','mdm-owner','mdm-runtime','mdm-api','mdm-access','oidc-other','validation-other']}
        SENSITIVE.update(values.values())
        SENSITIVE.add('Fixture-only-correct-horse-battery-2026!')
        write('state-key',secrets.token_hex(32));write('new-password','Fixture-only-correct-horse-battery-2026!')
        run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=MDM T2 CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign','-keyout',str(root/'ca.key'),'-out',str(root/'ca.crt')],timeout=30)
        run(['openssl','req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=localhost','-keyout',str(root/'tls.key'),'-out',str(root/'tls.csr')],timeout=30)
        write('extensions','basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,DNS:pg,DNS:hydra-admin,IP:127.0.0.1\n',True)
        run(['openssl','x509','-req','-in',str(root/'tls.csr'),'-CA',str(root/'ca.crt'),'-CAkey',str(root/'ca.key'),'-CAcreateserial','-days','1','-extfile',str(root/'extensions'),'-out',str(root/'tls.crt')],timeout=30)
        for n in ['tls.key','ca.key']: (root/n).chmod(0o600)
        for n in ['tls.crt','ca.crt']: (root/n).chmod(0o644)
        ids=docker('network','ls','-q').split()
        used=[]
        if ids:
            for net in json.loads(docker('network','inspect',*ids)):
                used.extend(ipaddress.ip_network(v['Subnet']) for v in (net.get('IPAM',{}).get('Config') or []) if v.get('Subnet'))
        subnet=next(ipaddress.ip_network(f'10.234.{n}.0/24') for n in range(10,250) if not any(ipaddress.ip_network(f'10.234.{n}.0/24').overlaps(u) for u in used if u.version==4))
        ips={n:str(subnet.network_address+i) for n,i in [('public',2),('private',3),('identity',4),('hydra',5),('pg',6)]}
        try:
            docker('network','create','--subnet',str(subnet),network)
            # Docker owns the published ports for the entire test; no close-and-rebind window.
            def gateway_namespace(suffix):
                container=name+'-'+suffix+'-network';created.append(container)
                docker('run','-d','--name',container,'--label','rss.test=2343','--network',network,'--ip',ips[suffix],'-p','127.0.0.1::8443','--entrypoint','sleep',c['providers']['runtime'],'infinity')
                selected=int(docker('port',container,'8443/tcp').rsplit(':',1)[1])
                return container,selected
            public_network,public_port=gateway_namespace('public')
            private_network,private_port=gateway_namespace('private')
            origin=f'https://localhost:{public_port}'
            product='https://mdm.example.test'
            storage={'target':list(uuid.uuid4().bytes),'lineage':list(uuid.uuid4().bytes),'tenants':[{'tenant_id':TENANT,'epoch':1}]}
            identity_origin={'environment_id':'mdm-t2','config_version':1,'identity_public_origin':origin,'product_public_origin':product}
            database={'host':'pg','port':5432,'database':'identity','user':'identity_runtime','password_file':PREFIX+'runtime','ca_file':PREFIX+'ca.crt'}
            config={'format_version':1,'identity_origin':identity_origin,'database':database,'storage':storage,'listen':'0.0.0.0:8080','public_gateway':ips['public'],'private_gateway':ips['private'],'budgets':{'request_seconds':10,'drain_seconds':30,'resource_seconds':10},
                'oidc':{'providers':[{'tenant_id':TENANT,'issuer':origin+'/realms/unused','client_id':'identity-rp','secret_ref':'unused@1','secret_file':PREFIX+'upstream','addresses':[ips['public']+'/32']}],'ca_file':PREFIX+'ca.crt','state_key_file':PREFIX+'state-key'},
                'hydra':{'admin_url':'https://hydra-admin:8443','addresses':[ips['hydra']+'/32'],'ca_file':PREFIX+'ca.crt','service_secret_file':PREFIX+'hydra-service','request_seconds':300,'code_seconds':60,'access_token_seconds':300,'clock_skew_seconds':30,'clients':[{'tenant_id':TENANT,'client_id':'mdm','audience':'mdm-api','config_version':1,'validation_secret_file':PREFIX+'validation','oidc_secret_file':PREFIX+'oidc-client'}]}}
            config['hydra']['clients'].append({'tenant_id':TENANT,'client_id':'mdm-other','audience':'other-api','config_version':1,'validation_secret_file':PREFIX+'validation-other','oidc_secret_file':PREFIX+'oidc-other'})
            write('runtime.json',config)
            write('migration.json',{'format_version':1,'identity_origin':identity_origin,'database':{**database,'user':'postgres','password_file':PREFIX+'owner'},'storage':storage,'runtime_password_file':PREFIX+'runtime','maintenance_password_file':PREFIX+'maintenance'})
            write('maintenance.json',{'identity_origin':identity_origin,**{k:v for k,v in database.items() if k!='user'},'user':'identity_maintenance','password_file':PREFIX+'maintenance','tenant_id':TENANT,'storage_target':storage['target'],'storage_lineage':storage['lineage'],'storage_tenant_epoch':1})
            hydra={'dsn':'postgres://hydra:'+values['hydra-db']+'@pg:5432/hydra?sslmode=verify-full&sslrootcert='+PREFIX+'ca.crt','serve':{'admin':{'host':'127.0.0.1','port':4445},'public':{'host':'0.0.0.0','port':4444}},'urls':{'self':{'issuer':origin+'/oidc'},'login':origin+'/login','consent':origin+'/consent'},'secrets':{'system':[values['hydra-system']]},'oauth2':{'pkce':{'enforced':True}},'strategies':{'access_token':'opaque'},'ttl':{'login_consent_request':'300s','auth_code':'60s','access_token':'300s'},'log':{'level':'error'}}
            write('hydra.json',hydra)
            tls='ssl_certificate '+PREFIX+'tls.crt; ssl_certificate_key '+PREFIX+'tls.key;'
            def nginx(servers, extra=''):return 'pid /tmp/nginx.pid; error_log stderr crit; events {} http { access_log off; error_log stderr crit; client_body_temp_path /tmp/client; proxy_temp_path /tmp/proxy; fastcgi_temp_path /tmp/fastcgi; uwsgi_temp_path /tmp/uwsgi; scgi_temp_path /tmp/scgi; proxy_next_upstream off; '+extra+servers+'}'
            proxy='proxy_http_version 1.1; proxy_set_header X-Forwarded-For $remote_addr; proxy_set_header Forwarded "";'
            write('public.conf',nginx('server { listen 8443 ssl; '+tls+' location /oidc/ { proxy_set_header X-Forwarded-Proto https; proxy_pass http://'+ips['hydra']+':4444/; } location /api/ { '+proxy+' proxy_pass http://'+ips['identity']+':8080; } location / { return 404; } }'))
            write('private.conf',nginx('server { listen 8443 ssl; '+tls+' location = /internal/v1/identity/validate { access_log /tmp/validation.log counts; '+proxy+' proxy_pass http://'+ips['identity']+':8080; } location / { return 404; } }',"log_format counts '$uri'; "))
            write('admin.conf',nginx('server { listen 8443 ssl; '+tls+' if ($http_authorization != "Bearer '+values['hydra-service']+'") { return 403; } location / { proxy_set_header Authorization ""; proxy_pass http://127.0.0.1:4445; } }'))
            stage='cp -R /fixture /tmp/mdm-identity-input; chown -R 10001:10001 /tmp/mdm-identity-input; exec setpriv --reuid=10001 --regid=10001 --clear-groups "$@"'
            def app_run(image, command, *, suffix=None, ip=None, extra=(), shared=None):
                args=['run','--label','rss.test=2343','--user','0:0','--entrypoint','sh','-v',str(root)+':/fixture:ro']
                args+=['--platform','linux/amd64' if image in c['images'].values() else native]
                if suffix:
                    container=name+'-'+suffix;created.append(container);args+=['-d','--name',container]
                else:args+=['--rm']
                args+=['--network',('container:'+shared) if shared else network]
                if ip:args+=['--ip',ip]
                bootstrap = stage if image != c['providers']['hydra'] else 'cp -R /fixture /tmp/mdm-identity-input; exec "$@"'
                args+=list(extra)+[image,'-ec',bootstrap,'--',*command]
                docker(*args,stage='candidate '+(suffix or command[0]))
                return name+'-'+suffix if suffix else None
            pg=name+'-pg';created.append(pg)
            pg_stage='cp /fixture/tls.key /tmp/server.key; cp /fixture/tls.crt /tmp/server.crt; cp /fixture/owner /tmp/owner; chown postgres:postgres /tmp/server.key /tmp/server.crt /tmp/owner; chmod 600 /tmp/server.key /tmp/owner; export POSTGRES_PASSWORD_FILE=/tmp/owner; exec docker-entrypoint.sh postgres -c shared_preload_libraries=pg_stat_statements -c ssl=on -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key'
            docker('run','-d','--name',pg,'--label','rss.test=2343','--network',network,'--ip',ips['pg'],'--network-alias','pg','-p','127.0.0.1::5432','-v',str(root)+':/fixture:ro',c['providers']['postgres'],'sh','-ec',pg_stage)
            pg_port=int(docker('port',pg,'5432/tcp').rsplit(':',1)[1])
            wait(lambda:docker('exec',pg,'pg_isready','-h','127.0.0.1','-U','postgres',timeout=5) is not None,'PostgreSQL')
            sql="CREATE DATABASE identity; CREATE USER hydra PASSWORD '"+values['hydra-db']+"'; CREATE DATABASE hydra OWNER hydra; CREATE DATABASE mdm;"
            for role,key in [('mdm_owner','mdm-owner'),('mdm_runtime','mdm-runtime'),('mdm_api','mdm-api'),('mdm_access','mdm-access')]:sql+="CREATE ROLE "+role+" LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '"+values[key]+"';"
            sql+='GRANT CREATE ON DATABASE mdm TO mdm_owner;'
            docker('exec','-i',pg,'psql','-X','-U','postgres','-v','ON_ERROR_STOP=1',input=sql)
            docker('exec','-i',pg,'psql','-X','-U','postgres','-d','mdm','-v','ON_ERROR_STOP=1',input='GRANT CREATE ON SCHEMA public TO mdm_owner; CREATE SCHEMA test_probe; CREATE EXTENSION pg_stat_statements WITH SCHEMA test_probe; REVOKE ALL ON ALL FUNCTIONS IN SCHEMA test_probe FROM PUBLIC; REVOKE ALL ON ALL TABLES IN SCHEMA test_probe FROM PUBLIC;')
            app_run(c['images']['operator'],['identity-migrate','--config',PREFIX+'migration.json'])
            app_run(c['providers']['hydra'],['hydra','migrate','sql','-e','--yes','--config',PREFIX+'hydra.json'])
            hydra_container=app_run(c['providers']['hydra'],['hydra','serve','all','--config',PREFIX+'hydra.json'],suffix='hydra',ip=ips['hydra'],extra=['--network-alias','hydra-admin'])
            app_run(c['images']['gateway'],['nginx','-e','stderr','-c',PREFIX+'admin.conf','-g','daemon off;'],suffix='admin',shared=hydra_container)
            app_run(c['images']['operator'],['identity-clients','--config',PREFIX+'runtime.json'],shared=hydra_container)
            app_run(c['images']['operator'],['identity-admin',PREFIX+'maintenance.json','initialize',ADMIN,'admin',PREFIX+'new-password'])
            identity_container=app_run(c['images']['server'],['identity-server','--config',PREFIX+'runtime.json'],suffix='identity',ip=ips['identity'])
            wait(lambda:docker('exec',identity_container,'identity-server','--probe','127.0.0.1:8080',timeout=5) is not None,'Identity')
            app_run(c['images']['gateway'],['nginx','-e','stderr','-c',PREFIX+'public.conf','-g','daemon off;'],suffix='public',shared=public_network)
            private_container=app_run(c['images']['gateway'],['nginx','-e','stderr','-c',PREFIX+'private.conf','-g','daemon off;'],suffix='private',shared=private_network)
            context=ssl.create_default_context(cafile=str(root/'ca.crt'))
            def tls_ready(port,path,expected):
                conn=http.client.HTTPSConnection('localhost',port,context=context,timeout=3)
                try:
                    conn.request('GET',path);response=conn.getresponse();response.read()
                    if response.status!=expected:raise RuntimeError('TLS readiness HTTP status '+str(response.status))
                    return True
                finally:conn.close()
            wait(lambda:tls_ready(public_port,'/oidc/.well-known/openid-configuration',200),'public OIDC gateway')
            wait(lambda:tls_ready(private_port,'/',404),'private validation gateway')
            binary=build_binary()
            db={'host':'localhost','port':pg_port,'name':'mdm','user':'mdm_owner','password_file':str(root/'mdm-owner'),'ca_file':str(root/'ca.crt')}
            migrate=write('mdm-migration.json',{'database':db});run([binary,'migrate','--config',str(migrate)],cwd=ROOT)
            mdm={'listen':'127.0.0.1:0','product_origin':product,'identity':{'origin':f'https://localhost:{private_port}','issuer':origin+'/oidc','client_id':'mdm','tenant_id':TENANT,'audience':'mdm-api','oidc_secret_file':str(root/'oidc-client'),'validation_secret_file':str(root/'validation'),'ca_file':str(root/'ca.crt')},'database':{**db,'user':'mdm_api','password_file':str(root/'mdm-api')},'bindings':[]}
            mdm['access_database']={**db,'user':'mdm_access','password_file':str(root/'mdm-access')}
            from windows_fixtures import generate
            mdm['windows']=generate(root, root/'tls.crt', root/'tls.key')
            config_path=write('mdm.json',mdm)
            yield {**os.environ,'MDM_TEST_CONFIG':str(config_path),'MDM_TEST_PUBLIC_ORIGIN':origin,'MDM_TEST_PASSWORD_FILE':str(root/'new-password'),'MDM_TEST_PG_CONTAINER':pg,'MDM_TEST_PRIVATE_CONTAINER':private_container,'MDM_TEST_HYDRA_CONTAINER':hydra_container,'MDM_TEST_IDENTITY_CONTAINER':identity_container,'MDM_TEST_PROVIDER_PLATFORM':native}
        finally:
            primary=sys.exception()
            failures=[]
            for container in reversed(created):
                try:docker('rm','-f',container)
                except RuntimeError:failures.append(container)
            try:docker('network','rm',network)
            except RuntimeError:failures.append(network)
            if failures:
                if primary is not None:primary.add_note('owned fixture cleanup also failed')
                else:raise RuntimeError('owned fixture cleanup failed')

def main():
    c=candidate()
    from login_gateway_t2 import verify
    verify(c['providers']['nginx'])
    with fixture(c) as env:
        provider_platform=env['MDM_TEST_PROVIDER_PLATFORM']
        output=run(['cargo','test','--locked','-p','rss-mdm-app','--test','identity_t2','--','--ignored','--nocapture'],cwd=ROOT,env=env,test_output=True,stage='real Identity router matrix')
        if 'MDM_IDENTITY_MATRIX_PASSED' not in output or '1 passed; 0 failed;' not in output:raise RuntimeError('identity test proof incomplete')
    print(json.dumps({'identity_revision':c['revision'],'identity_archives':c['archives'],'provider_digests':c['providers'],'provider_platform':provider_platform,'candidate_platform':c['platform'],'result':'passed','scope':'MDM Router / SDK / immutable Identity binary / real PG and Hydra / TLS; not production T3'}))
if __name__=='__main__':main()
