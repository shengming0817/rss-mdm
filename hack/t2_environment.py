"""Worktree-owned Compose lifecycle; build target allocation remains in build_run.

ref: compose-spec/compose-spec spec.md (project isolation and service network_mode).
"""
from __future__ import annotations
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import subprocess
import time
import uuid
from build_run import lease_fds, require_lease

ROOT = Path(__file__).resolve().parents[1]
PROVIDERS = json.loads((ROOT / 'deployment/providers.lock.json').read_text())

def project_name(worktree):
    return 'mdm-' + hashlib.sha256(os.fsencode(Path(worktree).resolve())).hexdigest()[:16]

def run(args, **kwargs):
    return subprocess.run([str(arg) for arg in args], pass_fds=lease_fds(), check=True, text=True, **kwargs)

def private(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(content if isinstance(content, str) else json.dumps(content))
    path.chmod(0o600)
    return path

class Environment:
    def __init__(self, worktree=ROOT, *, group='main'):
        if not re.fullmatch(r'[a-z][a-z0-9-]*', group):
            raise ValueError('invalid environment group')
        self.worktree = Path(worktree).resolve()
        self.identity = project_name(self.worktree)
        self.project = self.identity + '-' + group
        self.root = self.worktree / 'artifacts/dev-environment' / group

    @contextlib.contextmanager
    def phase(self, name, **details):
        start = time.monotonic()
        status='passed'
        try:
            yield
        except BaseException:
            status='failed'
            raise
        finally:
            print(json.dumps(dict(phase=name, elapsed_seconds=round(time.monotonic()-start, 3), environment=self.project,status=status,**details)), flush=True)

    def variables(self):
        images=json.loads((self.root/'images.json').read_text()) if (self.root/'images.json').exists() else {}
        return {**images, **{k:v for k,v in os.environ.items() if not k.startswith('COMPOSE_')},
                'MDM_ENV_ROOT': str(self.root), 'MDM_WORKTREE_ID': self.identity,
                'MDM_POSTGRES_IMAGE': PROVIDERS['postgres'], 'MDM_RUNTIME_IMAGE': PROVIDERS['runtime'],
                'MDM_KEYCLOAK_IMAGE':PROVIDERS['keycloak'], **getattr(self,'extra',{})}

    def compose(self, *args, **kwargs):
        return run(['docker','compose','-p',self.project,'-f',ROOT/'deployment/compose.yaml',*args],
                   env=self.variables(), capture_output=True, **kwargs).stdout.strip()

    def certificate(self):
        if (self.root/'ca.crt').exists():
            run(['openssl','x509','-checkend','300','-noout','-in',self.root/'server.crt'], capture_output=True)
            return
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        quiet = dict(capture_output=True)
        run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','30','-subj','/CN=MDM local CA',
             '-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign',
             '-keyout',self.root/'ca.key','-out',self.root/'ca.crt'], **quiet)
        run(['openssl','req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=localhost',
             '-keyout',self.root/'server.key','-out',self.root/'server.csr'], **quiet)
        private(self.root/'extensions', 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,DNS:postgres,DNS:mdm.example.test,IP:127.0.0.1\n')
        run(['openssl','x509','-req','-in',self.root/'server.csr','-CA',self.root/'ca.crt','-CAkey',self.root/'ca.key',
             '-CAcreateserial','-days','30','-extfile',self.root/'extensions','-out',self.root/'server.crt'], **quiet)
        for name in ('ca.key','server.key'): (self.root/name).chmod(0o600)

    def container(self):
        ident = self.compose('ps','-q','postgres')
        if not ident or '\n' in ident: raise RuntimeError('environment PostgreSQL is not running')
        return ident

    def sql(self, statement, database='postgres'):
        return run(['docker','exec','-i',self.container(),'psql','-X','-At','-v','ON_ERROR_STOP=1',
                    '-U','postgres','-d',database], input=statement, capture_output=True, timeout=60).stdout.strip()

    def port(self):
        return int(self.compose('port','postgres','5432').rsplit(':',1)[1])

    def verify_ownership(self):
        # Query by Compose identity, then require the independent owner label on every resource.
        for kind, listing in [('container',['ps','-aq']),('volume',['volume','ls','-q']),('network',['network','ls','-q'])]:
            ids = run(['docker',*listing,'--filter',f'label=com.docker.compose.project={self.project}'],capture_output=True).stdout.split()
            if not ids: continue
            for value in json.loads(run(['docker',kind,'inspect',*ids],capture_output=True).stdout):
                labels = value.get('Config',{}).get('Labels',{}) if kind=='container' else value.get('Labels',{})
                if (labels or {}).get('rss.mdm.worktree') != self.identity:
                    raise RuntimeError('refusing foreign environment resource')

    def up(self):
        require_lease(self.worktree)
        reused=bool(self.compose('ps','-q','postgres'))
        with self.phase('prepare',reused=reused):
            self.certificate()
            private(self.root/'pg-password','local-fixture')
            self.verify_ownership()
            self.compose('up','-d','--wait','--wait-timeout','90','postgres')
            self.roles()
        return self

    def roles(self):
        sources = sorted((ROOT/'crates/app/schema').glob('*-roles.sql'))
        fingerprint = hashlib.sha256(b''.join(p.read_bytes() for p in sources)).hexdigest()
        marker = self.root/'roles.sha256'
        present = self.sql("SELECT count(*) FROM pg_roles WHERE rolname='mdm_owner'") == '1'
        if present:
            if not marker.exists() or marker.read_text()!=fingerprint:
                raise RuntimeError('role inputs changed; reset this environment')
            return
        sql = "CREATE ROLE mdm_owner LOGIN PASSWORD 'owner-fixture' NOSUPERUSER NOBYPASSRLS;"
        for role, password in [('mdm_runtime','runtime-fixture'),('mdm_api','api-fixture'),('mdm_access','access-fixture')]:
            sql += f"CREATE ROLE {role} LOGIN PASSWORD '{password}' NOSUPERUSER NOBYPASSRLS;"
        # Publication defines the borrowed relay role required by subsequent role files.
        for name in ('software-publication','flow','commands','identity','audit'):
            sql += (ROOT/f'crates/app/schema/{name}-roles.sql').read_text()
        for role in ('mdm_policy_runtime','mdm_resource_runtime','mdm_software_release_runtime','mdm_group_runtime',
                     'mdm_flow_runtime','mdm_command_runtime','mdm_software_driver'):
            sql += f"ALTER ROLE {role} LOGIN PASSWORD 'runtime-fixture';"
        for role, password in [('mdm_identity_runtime','identity-runtime-fixture'),('mdm_identity_maintenance','identity-maintenance-fixture'),('mdm_identity_audit','identity-audit-fixture')]:
            sql += f"ALTER ROLE {role} LOGIN PASSWORD '{password}';"
        sql += 'CREATE ROLE mdm_group_owner NOLOGIN NOSUPERUSER NOBYPASSRLS; GRANT rss_tmsg_relay TO mdm_group_owner;'
        self.sql('BEGIN;'+sql+' COMMIT;')
        private(marker,fingerprint)

    @contextlib.contextmanager
    def database(self, *, name=None):
        name = name or 't2_' + uuid.uuid4().hex
        if not re.fullmatch(r'[a-z][a-z0-9_]*', name): raise ValueError('invalid database name')
        self.sql(f'CREATE DATABASE "{name}" OWNER mdm_owner')
        try:
            self.sql(f'GRANT CREATE ON DATABASE "{name}" TO mdm_audit_owner,mdm_ledger_owner,mdm_group_owner; GRANT CREATE ON SCHEMA public TO mdm_owner,mdm_group_owner;', name)
            yield name
        finally:
            self.sql(f'DROP DATABASE "{name}" WITH (FORCE)')

    def stop(self):
        self.verify_ownership()
        self.compose('--profile','product','--profile','idp','stop')

    def reset(self):
        self.verify_ownership()
        self.compose('--profile','product','--profile','idp','down','--volumes','--remove-orphans')
        if self.root.exists(): shutil.rmtree(self.root)

    def status(self):
        raw=self.compose('--profile','product','--profile','idp','ps','--all','--format','json')
        services=json.loads(raw) if raw.startswith('[') else [json.loads(line) for line in raw.splitlines() if line.strip()]
        return dict(project=self.project,worktree=str(self.worktree),services=services)

    def initialize(self, mode='host', server_image=None, web_image=None):
        from candidate_fixture import installation, INSTANCE, TENANTS, ADMIN
        import secrets
        import socket
        self.up()
        if mode=='container':
            if not server_image or not web_image:raise ValueError('container mode requires --server-image and --web-image')
            images={}
            for key,value in [('MDM_SERVER_IMAGE',server_image),('MDM_WEB_IMAGE',web_image)]:
                images[key]=json.loads(run(['docker','image','inspect',value],capture_output=True).stdout)[0]['Id']
            private(self.root/'images.json',images)
            self.compose('--profile','product','up','-d','runtime-netns')
            https_port=int(self.compose('port','runtime-netns','8445').rsplit(':',1)[1])
            backend_port=8081
        else:
            def free_port():
                with socket.socket() as sock:
                    sock.bind(('127.0.0.1',0));return sock.getsockname()[1]
            saved=self.root/'host-ports.json'
            ports=json.loads(saved.read_text()) if saved.exists() else dict(https=free_port(),backend=free_port())
            private(saved,ports);https_port=ports['https'];backend_port=ports['backend']
        origin=f'https://localhost:{https_port}'
        runtime=self.root/mode/'runtime';operator=self.root/mode/'operator';gateway=self.root/mode/'gateway'
        for directory in (runtime,operator,gateway):
            directory.mkdir(parents=True,exist_ok=True,mode=0o700)
            private(directory/'ca.crt',(self.root/'ca.crt').read_text())
        passwords={'mdm_owner':'owner-fixture','mdm_access':'access-fixture','mdm_runtime':'runtime-fixture',
                   'mdm_identity_runtime':'identity-runtime-fixture','mdm_identity_maintenance':'identity-maintenance-fixture',
                   'mdm_identity_audit':'identity-audit-fixture'}
        def path(directory,name):return '/run/mdm/'+name if mode=='container' else str(directory/name)
        def database(directory,role):
            private(directory/(role+'-password'),passwords.get(role,'runtime-fixture'))
            return dict(host='postgres' if mode=='container' else 'localhost',port=5432 if mode=='container' else self.port(),
                        name='mdm_dev',user=role,password_file=path(directory,role+'-password'),ca_file=path(directory,'ca.crt'))
        config=json.loads((ROOT/'fixtures/mdm-config.example.json').read_text())
        config.update(listen=f'127.0.0.1:{backend_port}',product_origin=origin,trusted_gateway='127.0.0.1',native_protocols={})
        config['access_database']=database(runtime,'mdm_access');config['runtime_database']=database(runtime,'mdm_runtime')
        config['identity']['database']=database(runtime,'mdm_identity_runtime');config['identity']['audit_worker']=database(runtime,'mdm_identity_audit')
        config['execution']['database']=database(runtime,'mdm_command_runtime')
        config['flow']['storage']['database']=database(runtime,'mdm_flow_runtime');config['flow']['publication']['database']=database(runtime,'mdm_software_driver')
        config['identity_management']=[dict(tenant_id=TENANTS[0],instance_id=INSTANCE,principal_id=ADMIN,permissions=['accounts','providers'])]
        private(runtime/'runtime.json',config)
        password=self.root/'account-password'
        if not password.exists():private(password,secrets.token_urlsafe(32))
        private(operator/'account-password',password.read_text())
        private(operator/'migrate.json',dict(installation=installation(),database=database(operator,'mdm_owner')))
        private(operator/'initialize.json',dict(installation=installation(),database=database(operator,'mdm_identity_maintenance'),
                tenant_id=TENANTS[0],principal_id=ADMIN,login='admin',password_file=path(operator,'account-password')))
        auth=operator/'authorization.json'
        operation_file=self.root/'authorization-operation'
        if not operation_file.exists():private(operation_file,str(uuid.uuid4()))
        operation=operation_file.read_text()
        private(auth,dict(audit={'mode':'plain'},database=database(operator,'mdm_access'),identityDatabase=database(operator,'mdm_identity_runtime'),
                         installation=installation(),login='admin',passwordFile=path(operator,'account-password'),operationId=operation,
                         user=dict(instanceId=INSTANCE,tenantId=TENANTS[0],principalId=ADMIN)))
        if self.sql("SELECT count(*) FROM pg_database WHERE datname='mdm_dev'")=='0':self.sql('CREATE DATABASE mdm_dev OWNER mdm_owner')
        self.sql('GRANT CREATE ON DATABASE mdm_dev TO mdm_owner,mdm_audit_owner,mdm_ledger_owner; GRANT CREATE ON SCHEMA public TO mdm_owner','mdm_dev')
        for name in ('server.crt','server.key'):private(gateway/name,(self.root/name).read_text())
        nginx=(ROOT/'deployment/nginx.conf').read_text().replace('listen 443 ssl;',f'listen {8445 if mode=="container" else https_port} ssl;')
        nginx=nginx.replace('server 127.0.0.1:8081;',f'server 127.0.0.1:{backend_port};').replace('server_name mdm.example.test;','server_name localhost;').replace('proxy_set_header Host mdm.example.test;','proxy_set_header Host $http_host;')
        prefix='/certs' if mode=='container' else str(gateway)
        nginx=nginx.replace('/private/mdm-tls.crt',prefix+'/server.crt').replace('/private/mdm-tls.key',prefix+'/server.key').replace('/run/config/ui.json',prefix+'/ui.json')
        if mode=='host':
            nginx=nginx.replace('/tmp/mdm-',str(gateway)+'/mdm-')
            mime=os.environ.get('MDM_NGINX_MIME_TYPES','/opt/homebrew/etc/nginx/mime.types' if sys.platform=='darwin' else '/etc/nginx/mime.types')
            nginx=nginx.replace('/etc/nginx/mime.types',mime)
            nginx=nginx.replace('/usr/share/nginx/html',os.environ.get('MDM_WEB_ROOT',str(gateway/'html')))
        private(gateway/'nginx.conf',nginx)
        private(gateway/'ui.json',{'canonicalOrigin':origin,'oidcEnabled':False})
        if mode=='container':self.compose('--profile','product','run','--rm','inputs')
        else:
            result=run(['cargo','build','--locked','-p','rss-mdm-app','--bin','rss-mdm','--message-format=json'],cwd=ROOT,capture_output=True)
            binaries=[x['executable'] for line in result.stdout.splitlines() if (x:=json.loads(line)).get('reason')=='compiler-artifact' and x.get('executable') and x['target']['name']=='rss-mdm']
            if len(binaries)!=1:raise RuntimeError('product binary unavailable')
        for verb,file in [('migrate','migrate.json'),('initialize','initialize.json'),('initialize-authorization','authorization.json')]:
            if verb=='initialize' and self.sql(f"SELECT count(*) FROM identity_authority.accounts WHERE tenant_id='{TENANTS[0]}' AND principal_id='{ADMIN}'",'mdm_dev')=='1':
                continue
            with self.phase(verb):
                if mode=='container':self.compose('--profile','product','run','--rm','operator',verb,'--config','/run/mdm/'+file)
                else:run([binaries[0],verb,'--config',operator/file],capture_output=True)
        private(self.root/(mode+'-initialized.json'),dict(origin=origin,configuration=str(runtime/'runtime.json')))
        return dict(origin=origin,configuration=str(runtime/'runtime.json'),gateway=str(gateway/'nginx.conf'))

    def start_product(self):
        if not (self.root/'container-initialized.json').exists():raise RuntimeError('run init --mode container first')
        self.verify_ownership()
        # A recreated namespace gets new ports; require init to regenerate bound origins.
        actual=int(self.compose('port','runtime-netns','8445').rsplit(':',1)[1])
        expected=json.loads((self.root/'container-initialized.json').read_text())['origin']
        if expected!=f'https://localhost:{actual}':raise RuntimeError('product port changed; run init --mode container again')
        self.compose('--profile','product','up','-d','server','gateway')
        import ssl
        import urllib.request
        context=ssl.create_default_context(cafile=str(self.root/'ca.crt'))
        deadline=time.monotonic()+60
        while True:
            try:
                with urllib.request.urlopen(expected+'/readyz',context=context,timeout=3) as response:
                    if response.status==200:break
            except OSError:pass
            if time.monotonic()>deadline:raise RuntimeError('product HTTPS readiness deadline; inspect this environment logs')
            time.sleep(.2)

@contextlib.contextmanager
def cluster(*, destructive=False):
    environment = Environment(group='fault-'+uuid.uuid4().hex[:10] if destructive else 'main')
    try:
        environment.up()
        yield environment
    finally:
        if destructive: environment.reset()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['up','init','stop','reset','status'])
    parser.add_argument('--mode',choices=['host','container'],default='host')
    parser.add_argument('--group',default='development')
    parser.add_argument('--server-image')
    parser.add_argument('--web-image')
    args = parser.parse_args()
    require_lease(ROOT)
    environment = Environment(group=args.group)
    if args.action == 'init':
        print(json.dumps(environment.initialize(args.mode,args.server_image,args.web_image)))
    else:
        result = getattr(environment,args.action)()
        if args.action=='up' and args.mode=='container':environment.start_product()
        if args.action == 'status': print(json.dumps(result))
