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
        details.setdefault('reused',False)
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
        return {**{k:v for k,v in os.environ.items() if not k.startswith('COMPOSE_') and k not in ('MDM_SERVER_IMAGE','MDM_WEB_IMAGE')}, **images,
                'MDM_ENV_ROOT': str(self.root), 'MDM_WORKTREE_ID': self.identity,
                'MDM_POSTGRES_IMAGE': PROVIDERS['postgres'], 'MDM_RUNTIME_IMAGE': PROVIDERS['runtime'],
                'MDM_KEYCLOAK_IMAGE':PROVIDERS['keycloak'],'MDM_NGINX_IMAGE':PROVIDERS['nginx'], **getattr(self,'extra',{})}

    def compose(self, *args, **kwargs):
        try:
            return run(['docker','compose','-p',self.project,'-f',ROOT/'deployment/compose.yaml',*args],
                       env=self.variables(), capture_output=True, **kwargs).stdout.strip()
        except subprocess.CalledProcessError as error:
            from candidate_runtime import safe_evidence
            diagnostic=error.stderr or 'no Compose diagnostic'
            private_values=[]
            for path in self.root.rglob('*'):
                if path.is_file() and not path.is_symlink() and ('password' in path.name or 'secret' in path.name or path.suffix=='.key'):
                    private_values.append(path.read_text())
            try:diagnostic=safe_evidence(diagnostic,private_values)
            except RuntimeError:diagnostic='diagnostic-withheld'
            print(f'Compose failed ({error.returncode}): {diagnostic}',file=sys.stderr,flush=True)
            raise

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

    def issue_leaf(self, directory, names):
        directory.mkdir(parents=True,exist_ok=True,mode=0o700)
        if (directory/'server.crt').exists():
            run(['openssl','x509','-checkend','300','-noout','-in',directory/'server.crt'],capture_output=True)
            return
        quiet=dict(capture_output=True)
        run(['openssl','req','-new','-newkey','rsa:2048','-nodes','-subj','/CN='+names[0],
             '-keyout',directory/'server.key','-out',directory/'server.csr'],**quiet)
        private(directory/'extensions','basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName='+','.join('DNS:'+name for name in names)+',IP:127.0.0.1\n')
        run(['openssl','x509','-req','-in',directory/'server.csr','-CA',self.root/'ca.crt','-CAkey',self.root/'ca.key',
             '-CAcreateserial','-days','30','-extfile',directory/'extensions','-out',directory/'server.crt'],**quiet)
        (directory/'server.key').chmod(0o600)

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
        config=json.loads(self.compose('--profile','*','config','--format','json'))
        expected={
            'container':{service.get('container_name',self.project+'-'+name+'-1') for name,service in config.get('services',{}).items()},
            'volume':{value['name'] for value in config.get('volumes',{}).values()},
            'network':{value['name'] for value in config.get('networks',{}).values()},
        }
        for kind,listing,field in [('container',['ps','-a'],'Names'),('volume',['volume','ls'],'Name'),('network',['network','ls'],'Name')]:
            ids=set(run(['docker',*listing,'-q','--filter',f'label=com.docker.compose.project={self.project}'],capture_output=True).stdout.split())
            names=set(run(['docker',*listing,'--format','{{.'+field+'}}'],capture_output=True).stdout.split())
            ids.update(names & expected[kind])
            if not ids:continue
            for value in json.loads(run(['docker',kind,'inspect',*sorted(ids)],capture_output=True).stdout):
                labels=value.get('Config',{}).get('Labels',{}) if kind=='container' else value.get('Labels',{})
                if (labels or {}).get('rss.mdm.worktree')!=self.identity or (labels or {}).get('com.docker.compose.project')!=self.project:
                    raise RuntimeError('refusing foreign environment resource')

    def prepare_inputs(self, certificates=True):
        self.root.mkdir(parents=True,exist_ok=True,mode=0o700)
        marker=self.root/'owner.json'
        expected={'worktree':str(self.worktree),'project':self.project}
        if marker.exists() and json.loads(marker.read_text())!=expected:raise RuntimeError('foreign environment owner record')
        private(marker,expected)
        if certificates:self.certificate()

    def up(self):
        require_lease(self.worktree)
        reused=bool(self.compose('ps','--all','-q','postgres'))
        with self.phase('prepare',reused=reused):
            self.prepare_inputs()
            self.issue_leaf(self.root/'pg',['localhost','postgres'])
            private(self.root/'pg'/'pg-password','local-fixture')
            self.verify_ownership()
            self.compose('up','-d','--wait','--wait-timeout','90','postgres')
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
        self.compose('--profile','*','stop')

    def reset(self):
        if self.root.exists() or self.root.is_symlink():
            marker=self.root/'owner.json'
            if self.root.is_symlink() or not marker.exists() or json.loads(marker.read_text())!={'worktree':str(self.worktree),'project':self.project}:
                raise RuntimeError('refusing foreign or damaged environment owner record')
        self.verify_ownership()
        self.compose('--profile','*','down','--volumes','--remove-orphans')
        self.host_ports(release=True)
        if self.root.exists(): shutil.rmtree(self.root)

    def status(self):
        raw=self.compose('--profile','*','ps','--all','--format','json')
        services=json.loads(raw) if raw.startswith('[') else [json.loads(line) for line in raw.splitlines() if line.strip()]
        return dict(project=self.project,worktree=str(self.worktree),services=services)

    def host_ports(self, release=False):
        import fcntl
        import socket
        from build_run import owned_directory
        location=Path.home()/'.cache/rss-mdm-dev-ports'
        if release and not location.exists():return
        registry=owned_directory(location,'.mdm-dev-ports-v1')
        with (registry/'lock').open('a+') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            index=registry/'allocations.json'
            allocations=json.loads(index.read_text()) if index.exists() else {}
            if release:
                allocations.pop(self.project,None)
                private(index,allocations)
                return
            ports=allocations.get(self.project)
            def available(port):
                try:
                    with socket.socket() as sock:sock.bind(('127.0.0.1',port))
                    return True
                except OSError:return False
            if ports:
                if not all(available(port) for port in ports.values()):
                    raise RuntimeError('allocated host port is occupied; stop its process or reset and init this environment')
                return ports
            used={port for pair in allocations.values() for port in pair.values()}
            seed=int(hashlib.sha256(self.project.encode()).hexdigest()[:8],16)%20000
            for offset in range(20000):
                first=20000+2*((seed+offset)%20000)
                candidate=dict(https=first,backend=first+1)
                if not used.intersection(candidate.values()) and all(available(port) for port in candidate.values()):
                    allocations[self.project]=candidate
                    private(index,allocations)
                    return candidate
            raise RuntimeError('no host development port pair available')

    def initialize(self, mode='host', server_image=None, web_image=None):
        from candidate_fixture import installation, INSTANCE, TENANTS, ADMIN
        import secrets
        import socket
        self.up()
        with self.phase('roles',reused=self.sql("SELECT count(*) FROM pg_roles WHERE rolname='mdm_owner'")=='1'):self.roles()
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
            ports=self.host_ports()
            private(self.root/'host-ports.json',ports)
            https_port=ports['https'];backend_port=ports['backend']
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
        self.issue_leaf(self.root/'gateway-cert'/mode,['localhost','mdm.example.test'])
        for name in ('server.crt','server.key'):private(gateway/name,(self.root/'gateway-cert'/mode/name).read_text())
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
                with self.phase('initialize',reused=True):pass
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
        running=self.compose('ps','-q','server','gateway').splitlines()
        with self.phase('start-product',reused=len(running)==2):
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

class Cancelled(BaseException):
    pass

class T2Context:
    """One run owns preparation, isolation policy, cancellation and stale fault recovery."""
    def __init__(self):
        self.main=Environment()
        self.prepared=False
        self.spec=None
        self.handlers={}

    def __enter__(self):
        import signal
        require_lease(ROOT)
        def cancel(number, frame):
            # Further TERM signals must not interrupt the cleanup subprocesses.
            for sig in self.handlers:signal.signal(sig,signal.SIG_IGN)
            raise Cancelled('T2 cancelled')
        for sig in (signal.SIGTERM,signal.SIGHUP,signal.SIGQUIT):
            self.handlers[sig]=signal.signal(sig,cancel)
        try:
            for path in sorted((ROOT/'artifacts/dev-environment').glob('fault-*')):
                environment=Environment(group=path.name)
                marker=path/'owner.json'
                if path.is_symlink() or not marker.exists() or json.loads(marker.read_text())!={'worktree':str(ROOT),'project':environment.project}:
                    raise RuntimeError('unrecognized fault residue; inspect and reset explicitly')
                environment.reset()
        except BaseException:
            self.__exit__(None,None,None)
            raise
        return self

    def __exit__(self,*unused):
        import signal
        for sig,handler in self.handlers.items():signal.signal(sig,handler)

    @contextlib.contextmanager
    def cluster(self, case=None):
        destructive=self.spec.isolation=='server' or case in self.spec.destructive
        group='fault-'+self.spec.name+'-'+hashlib.sha256((case or self.spec.name).encode()).hexdigest()[:10]
        environment=Environment(group=group) if destructive else self.main
        try:
            if destructive or not self.prepared:
                environment.up()
                with environment.phase('roles',reused=environment.sql("SELECT count(*) FROM pg_roles WHERE rolname='mdm_owner'")=='1'):environment.roles()
                if not destructive:self.prepared=True
            yield environment
        finally:
            if destructive:environment.reset()

    def source_tls(self, root):
        self.main.prepare_inputs()
        directory=self.main.root/'source-cert'
        self.main.issue_leaf(directory,['source.invalid'])
        for source,target in ((self.main.root/'ca.crt','ca.pem'),(directory/'server.crt','server.pem'),(directory/'server.key','server.key')):
            private(root/target,source.read_text())

    @contextlib.contextmanager
    def gateway(self, config):
        environment=Environment(group='fault-gateway-probe')
        try:
            environment.prepare_inputs(certificates=False)
            private(environment.root/'probe/nginx.conf',config)
            environment.verify_ownership()
            environment.compose('--profile','probe','up','-d','gateway-probe')
            name=environment.compose('ps','-q','gateway-probe')
            port=int(environment.compose('port','gateway-probe','8080').rsplit(':',1)[1])
            yield name,port
        finally:
            environment.reset()

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
