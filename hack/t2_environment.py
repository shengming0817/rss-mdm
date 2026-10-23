"""Worktree-owned Compose lifecycle; build target allocation remains in build_run.

ref: compose-spec/compose-spec spec.md (project isolation and explicit networks).
"""
from __future__ import annotations
from ingress_network import Ingress
import argparse
import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
from t2_processes import private_value, subprocess
import time
import uuid
import ssl
import socket
import http.client
import ipaddress
from urllib.parse import urlsplit
from build_run import lease_fds, require_lease

ROOT = Path(__file__).resolve().parents[1]
PROVIDERS = json.loads((ROOT / 'deployment/providers.lock.json').read_text())
PKI_CA = {**json.loads((ROOT / 'fixtures/pki-tools.lock.json').read_text())['step-ca'], 'image': PROVIDERS['step-ca']}

def project_name(worktree):
    return 'mdm-' + hashlib.sha256(os.fsencode(Path(worktree).resolve())).hexdigest()[:16]

def run(args, **kwargs):
    return subprocess.run([str(arg) for arg in args], pass_fds=lease_fds(), check=True, text=True, **kwargs)

def private(path, content):
    private_value(content)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(content if isinstance(content, str) else json.dumps(content))
    path.chmod(0o600)
    return path

class Environment:
    def __init__(self, worktree=ROOT, *, group='main', compose_file=None, providers=None):
        if not re.fullmatch(r'[a-z][a-z0-9-]*', group):
            raise ValueError('invalid environment group')
        self.worktree = Path(worktree).resolve()
        self.compose_file = Path(compose_file).resolve() if compose_file else ROOT/'deployment/compose.yaml'
        self.providers = dict(providers or PROVIDERS)
        self.identity = project_name(self.worktree)
        self.project = self.identity + '-' + group
        self.root = self.worktree / 'artifacts/dev-environment' / group
        self.postgres_endpoint = None
        self.postgres_queries = dict(container=0, port=0)

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

    def variables(self, *, gateway=True):
        images=json.loads((self.root/'images.json').read_text()) if (self.root/'images.json').exists() else {}
        record=self.root/'container-gateway.json'
        tls=json.loads(record.read_text()) if record.exists() else self.local_gateway()
        settings={'MDM_PRODUCT_ORIGIN':tls['origin'] or '', 'MDM_GATEWAY_PUBLISH':tls['publish'],
                  'MDM_GATEWAY_TLS_CERT_FILE':tls['certificate_file'], 'MDM_GATEWAY_TLS_KEY_FILE':tls['key_file']} if gateway else {}
        ingress = Ingress(self.root,self.project,self.identity).values()
        return {**{k:v for k,v in os.environ.items() if not k.startswith('COMPOSE_') and k not in ('MDM_SERVER_IMAGE','MDM_WEB_IMAGE')}, **images,
                **ingress,
                'MDM_ENV_ROOT': str(self.root), 'MDM_WORKTREE_ID': self.identity,
                'MDM_POSTGRES_IMAGE': self.providers['postgres'], 'MDM_RUNTIME_IMAGE': self.providers['runtime'],
                'MDM_KEYCLOAK_IMAGE':self.providers['keycloak'],'MDM_NGINX_IMAGE':self.providers['nginx'],
                'MDM_STEP_CA_IMAGE':self.providers['step-ca'], 'MDM_STEP_CA_INTERNAL_PORT':str(PKI_CA['port']),
                'MDM_PKI_ROOT':str(self.root/'pki'), 'MDM_PKI_USER':f'{os.getuid()}:{os.getgid()}',
                'MDM_PKI_HOST_ADDRESS':'host-gateway',
                **settings, **getattr(self,'extra',{})}

    def local_gateway(self):
        directory=self.root/'container/gateway'
        return dict(origin=None,publish='127.0.0.1::8443',
                    certificate_file=str(directory/'server.crt'),key_file=str(directory/'server.key'))

    def gateway_settings(self, env_file=None):
        configured=Path(env_file).absolute() if env_file else self.worktree/'.env'
        if env_file and not configured.is_file():raise ValueError('gateway env file does not exist')
        names=('MDM_PRODUCT_ORIGIN','MDM_GATEWAY_PUBLISH','MDM_GATEWAY_TLS_CERT_FILE','MDM_GATEWAY_TLS_KEY_FILE')
        if not configured.exists() and not any(os.environ.get(name) for name in names):return self.local_gateway()
        # Compose owns dotenv parsing, interpolation, shell precedence and relative bind paths.
        model=json.loads(run(['docker','compose','--env-file',configured if configured.exists() else os.devnull,
            '--project-directory',self.worktree,'-p',self.project,'-f',self.compose_file,
            '--profile','product','config','--format','json'],env=self.variables(gateway=False),capture_output=True).stdout)
        settings=model['x-gateway']
        origin=settings['origin']
        external=(origin,settings['certificate_file'],settings['key_file'])
        if not any(external):
            tls=self.local_gateway();tls['publish']=settings['publish'];return tls
        if not all(external):raise ValueError('external gateway requires origin, certificate file and private-key file together')
        try:
            endpoint=urlsplit(origin)
            hostname=endpoint.hostname or ''
            port=443 if endpoint.port is None else endpoint.port
            canonical_host=hostname
            valid_host=bool(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?',hostname))
            try:
                address=ipaddress.ip_address(hostname);valid_host=True
                canonical_host='['+address.compressed+']' if address.version==6 else address.compressed
            except ValueError:
                # URL parsers normalize numeric hosts as IPv4; require a normal DNS name here.
                valid_host=valid_host and not re.fullmatch(r'(?:[0-9]+|0[xX][0-9a-fA-F]+)',hostname.rsplit('.',1)[-1])
            canonical='https://'+canonical_host+(':'+str(port) if port!=443 else '')
            if origin!=canonical or any(character.isspace() for character in origin) or endpoint.scheme!='https' or not valid_host or endpoint.username is not None or endpoint.password is not None or endpoint.path or endpoint.query or endpoint.fragment or not 1<=port<=65535:
                raise ValueError()
        except ValueError:raise ValueError('MDM_PRODUCT_ORIGIN must be a canonical HTTPS origin without credentials, path, query or fragment') from None
        ports=model['services']['gateway']['ports']
        if len(ports)!=1 or ports[0]['target']!=8443 or ports[0].get('protocol','tcp')!='tcp' or str(ports[0].get('published',''))!=str(port) or ports[0].get('host_ip','0.0.0.0') not in ('0.0.0.0','127.0.0.1'):
            raise ValueError('gateway publish must use TCP, bind 127.0.0.1 or 0.0.0.0 and match the origin port, targeting 8443')
        mounts={volume['target']:Path(volume['source']) for volume in model['services']['inputs']['volumes'] if volume['type']=='bind'}
        certificate=mounts['/tls-input/server.crt'];key=mounts['/tls-input/server.key']
        if any(path.is_symlink() or not path.is_file() for path in (certificate,key)):
            raise RuntimeError('external gateway requires both certificate bundle and private key as regular files')
        try:
            ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(certificate,key,password=lambda:'')
            try:ipaddress.ip_address(hostname);verify='-verify_ip'
            except ValueError:verify='-verify_hostname'
            run(['openssl','verify','-CAfile',certificate,'-partial_chain',verify,
                 hostname,'-purpose','sslserver',certificate],capture_output=True)
        except (OSError,ssl.SSLError,subprocess.CalledProcessError):
            raise RuntimeError('external gateway certificate/key is invalid, expired or does not match its domain') from None
        return dict(origin=origin,publish=settings['publish'],certificate_file=str(certificate),key_file=str(key))

    def compose(self, *args, **kwargs):
        private_values=[]
        paths=list(self.root.rglob('*'))
        tls=self.variables()
        paths.append(Path(tls['MDM_GATEWAY_TLS_KEY_FILE']))
        for path in paths:
            if path.is_file() and not path.is_symlink() and (path==Path(tls['MDM_GATEWAY_TLS_KEY_FILE']) or 'password' in path.name or 'secret' in path.name or path.suffix=='.key'):
                raw = path.read_bytes()
                values = [raw.hex(), base64.b64encode(raw).decode()]
                try:
                    values.append(raw.decode())
                except UnicodeDecodeError:
                    pass
                for value in values:
                    private_values.append(value)
                    private_value(value)
        try:
            return run(['docker','compose','--env-file',os.devnull,'--project-directory',self.worktree,'-p',self.project,'-f',self.compose_file,*args],
                       env=self.variables(), capture_output=True, **kwargs).stdout.strip()
        except subprocess.CalledProcessError as error:
            from candidate_runtime import safe_evidence
            diagnostic=error.stderr or 'no Compose diagnostic'
            try:diagnostic=safe_evidence(diagnostic,private_values)
            except RuntimeError:diagnostic='diagnostic-withheld'
            print(f'Compose failed ({error.returncode}): {diagnostic}',file=sys.stderr,flush=True)
            raise

    def certificate(self):
        if not (self.root/'ca.crt').exists():
            self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
            run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','30','-subj','/CN=MDM local CA',
                 '-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign',
                 '-addext','subjectKeyIdentifier=hash',
                 '-keyout',self.root/'ca.key','-out',self.root/'ca.crt'], capture_output=True)
            (self.root/'ca.key').chmod(0o600)
        self.issue_leaf(self.root,['localhost','postgres','mdm.example.test'])

    def issue_leaf(self, directory, names):
        directory.mkdir(parents=True,exist_ok=True,mode=0o700)
        if (directory/'server.crt').exists():
            valid = subprocess.run(
                ['openssl','verify','-x509_strict','-purpose','sslserver','-verify_hostname',names[0],
                 '-CAfile',str(self.root/'ca.crt'),str(directory/'server.crt')],
                pass_fds=lease_fds(),capture_output=True,text=True,check=False)
            fresh = subprocess.run(
                ['openssl','x509','-checkend','300','-noout','-in',str(directory/'server.crt')],
                pass_fds=lease_fds(),capture_output=True,text=True,check=False)
            if valid.returncode == 0 and fresh.returncode == 0:
                return
        quiet=dict(capture_output=True)
        run(['openssl','req','-new','-newkey','rsa:2048','-nodes','-subj','/CN='+names[0],
             '-keyout',directory/'server.key','-out',directory/'server.csr'],**quiet)
        private(directory/'extensions','basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always,issuer\nsubjectAltName='+','.join('DNS:'+name for name in names)+',IP:127.0.0.1\n')
        run(['openssl','x509','-req','-in',directory/'server.csr','-CA',self.root/'ca.crt','-CAkey',self.root/'ca.key',
             '-CAcreateserial','-days','30','-extfile',directory/'extensions','-out',directory/'server.crt'],**quiet)
        (directory/'server.key').chmod(0o600)

    def container(self):
        if self.postgres_endpoint is not None:
            return self.postgres_endpoint[0]
        self.postgres_queries['container'] += 1
        ident = self.compose('ps','-q','postgres')
        if not ident or '\n' in ident: raise RuntimeError('environment PostgreSQL is not running')
        return ident

    def sql(self, statement, database='postgres'):
        return run(['docker','exec','-i',self.container(),'psql','-X','-At','-v','ON_ERROR_STOP=1',
                    '-U','postgres','-d',database], input=statement, capture_output=True, timeout=60).stdout.strip()

    def port(self):
        if self.postgres_endpoint is not None:
            return self.postgres_endpoint[1]
        self.postgres_queries['port'] += 1
        return int(self.compose('port','postgres','5432').rsplit(':',1)[1])

    def verify_ownership(self):
        config=json.loads(self.compose('--profile','*','config','--format','json',timeout=30))
        expected={
            'container':{service.get('container_name',self.project+'-'+name+'-1') for name,service in config.get('services',{}).items()},
            'volume':{value['name'] for value in config.get('volumes',{}).values()},
            'network':{value['name'] for value in config.get('networks',{}).values()},
        }
        for kind,listing,field in [('container',['ps','-a'],'Names'),('volume',['volume','ls'],'Name'),('network',['network','ls'],'Name')]:
            ids=set(run(['docker',*listing,'-q','--filter',f'label=com.docker.compose.project={self.project}'],capture_output=True,timeout=30).stdout.split())
            names=set(run(['docker',*listing,'--format','{{.'+field+'}}'],capture_output=True,timeout=30).stdout.split())
            ids.update(names & expected[kind])
            if not ids:continue
            for value in json.loads(run(['docker',kind,'inspect',*sorted(ids)],capture_output=True,timeout=30).stdout):
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
        self.postgres_endpoint = None
        require_lease(self.worktree)
        reused=bool(self.compose('ps','--all','-q','postgres'))
        with self.phase('prepare',reused=reused):
            self.prepare_inputs()
            self.issue_leaf(self.root/'pg',['localhost','postgres'])
            private(self.root/'pg'/'pg-password','local-fixture')
            self.verify_ownership()
            self.compose('up','-d','--wait','--wait-timeout','90','postgres')
            self.verify_ownership()
            self.postgres_endpoint = (self.container(), self.port())
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
        for name in ('software-publication','flow','commands','identity','audit','webhook'):
            sql += (ROOT/f'crates/app/schema/{name}-roles.sql').read_text()
        for role in ('mdm_policy_runtime','mdm_resource_runtime','mdm_software_release_runtime','mdm_group_runtime',
                     'mdm_flow_runtime','mdm_command_runtime','mdm_software_driver','mdm_webhook_operator'):
            sql += f"ALTER ROLE {role} LOGIN PASSWORD 'runtime-fixture';"
        for role, password in [('mdm_audit_worker','audit-projection-fixture'),('mdm_identity_runtime','identity-runtime-fixture'),('mdm_identity_maintenance','identity-maintenance-fixture'),('mdm_identity_audit','identity-audit-fixture'),('mdm_tenant_registry','tenant-registry-fixture'),('mdm_identity_provisioning','identity-provisioning-fixture')]:
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
        self.postgres_endpoint = None
        self.verify_ownership()
        self.compose('--profile','*','stop')

    def reset(self):
        self.postgres_endpoint = None
        if self.root.exists() or self.root.is_symlink():
            marker=self.root/'owner.json'
            if self.root.is_symlink() or not marker.exists() or json.loads(marker.read_text())!={'worktree':str(self.worktree),'project':self.project}:
                raise RuntimeError('refusing foreign or damaged environment owner record')
        self.verify_ownership()
        self.compose('--profile','*','down','--volumes','--remove-orphans',timeout=30)
        ingress=Ingress(self.root,self.project,self.identity)
        if ingress.record.exists():ingress.release()
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

    def initialize(self, mode='host', server_image=None, web_image=None, env_file=None):
        from candidate_fixture import installation, INSTANCE, TENANTS, ADMIN
        import secrets
        if env_file and mode!='container':raise ValueError('gateway env file requires container mode')
        if mode=='container':
            if not server_image or not web_image:raise ValueError('container mode requires --server-image and --web-image')
            tls=self.gateway_settings(env_file)
            self.prepare_inputs(certificates=False)
            private(self.root/'container-gateway.json',tls)
            ingress=Ingress(self.root,self.project,self.identity).allocate()
        self.up()
        with self.phase('roles',reused=self.sql("SELECT count(*) FROM pg_roles WHERE rolname='mdm_owner'")=='1'):self.roles()
        if mode=='container':
            if not server_image or not web_image:raise ValueError('container mode requires --server-image and --web-image')
            images={}
            for key,value in [('MDM_SERVER_IMAGE',server_image),('MDM_WEB_IMAGE',web_image)]:
                images[key]=json.loads(run(['docker','image','inspect',value],capture_output=True).stdout)[0]['Id']
            private(self.root/'images.json',images)
            self.compose('--profile','product','stop','server','gateway')
            https_port=urlsplit(tls['origin']).port or 443 if tls['origin'] else self.host_ports()['https']
            if not tls['origin']:tls['publish']=f'127.0.0.1:{https_port}:8443'
            private(self.root/'container-gateway.json',tls)
            backend_port=8081
        else:
            ports=self.host_ports()
            private(self.root/'host-ports.json',ports)
            https_port=ports['https'];backend_port=ports['backend']
        origin=tls['origin'] if mode=='container' and tls['origin'] else f'https://localhost:{https_port}'
        runtime=self.root/mode/'runtime';operator=self.root/mode/'operator';gateway=self.root/mode/'gateway'
        for directory in (runtime,operator,gateway):
            directory.mkdir(parents=True,exist_ok=True,mode=0o700)
            private(directory/'ca.crt',(self.root/'ca.crt').read_text())
        passwords={'mdm_owner':'owner-fixture','mdm_access':'access-fixture','mdm_runtime':'runtime-fixture',
                   'mdm_identity_runtime':'identity-runtime-fixture','mdm_identity_maintenance':'identity-maintenance-fixture',
                   'mdm_identity_audit':'identity-audit-fixture','mdm_audit_worker':'audit-projection-fixture'}
        def path(directory,name):return '/run/mdm/'+name if mode=='container' else str(directory/name)
        def database(directory,role):
            private(directory/(role+'-password'),passwords.get(role,'runtime-fixture'))
            return dict(host='postgres' if mode=='container' else 'localhost',port=5432 if mode=='container' else self.port(),
                        name='mdm_dev',user=role,password_file=path(directory,role+'-password'),ca_file=path(directory,'ca.crt'))
        native_key=runtime/'native-data.key'
        if not native_key.exists():
            private(native_key,'').write_bytes(secrets.token_bytes(32))
        config=json.loads((ROOT/'fixtures/mdm-config.example.json').read_text())
        config['native_protection']=dict(active_file=path(runtime,'native-data.key'),historical_files=[],fingerprint_file=path(runtime,'native-data.key'))
        config.update(listen=(ingress['MDM_BACKEND_ADDRESS'] if mode=='container' else '127.0.0.1')+f':{backend_port}',product_origin=origin,trusted_gateway=ingress['MDM_GATEWAY_ADDRESS'] if mode=='container' else '127.0.0.1',native_protocols={},device_pki=[])
        config['agent_pki']={'mode':'disabled'}
        config['access_database']=database(runtime,'mdm_access');config['runtime_database']=database(runtime,'mdm_runtime')
        config['identity']['database']=database(runtime,'mdm_identity_runtime');config['identity']['audit_worker']=database(runtime,'mdm_identity_audit')
        config['audit_projection']['database']=database(runtime,'mdm_audit_worker')
        for owner, key, filename in [(config['audit_projection'], 'recovery_keys', 'audit-recovery.key'),
                                     (config['identity'], 'audit_recovery_keys', 'identity-audit-recovery.key')]:
            material = runtime / filename
            if not material.exists():
                private(material, '').write_bytes(secrets.token_bytes(32))
            owner[key] = dict(active_file=path(runtime,filename),historical_files=[])
        config['execution']['database']=database(runtime,'mdm_command_runtime')
        config['webhooks']['recovery_database']=database(runtime,'mdm_webhook_operator')
        config['flow']['storage']['database']=database(runtime,'mdm_flow_runtime');config['flow']['publication']['database']=database(runtime,'mdm_software_driver')
        private(runtime/'runtime.json',config)
        password=self.root/'account-password'
        if not password.exists():private(password,secrets.token_urlsafe(32))
        private(operator/'account-password',password.read_text())
        private(operator/'migrate.json',dict(installation=installation(),database=database(operator,'mdm_owner')))

        private(operator/'initialize.json',dict(installation=installation(),database=database(operator,'mdm_identity_maintenance'),
                tenant_id=TENANTS[0],expected_epoch=1,principal_id=ADMIN,login='admin',password_file=path(operator,'account-password')))
        auth=operator/'authorization.json'
        operation_file=self.root/'authorization-operation'
        if not operation_file.exists():private(operation_file,str(uuid.uuid4()))
        operation=operation_file.read_text()
        private(auth,dict(audit={'mode':'plain'},database=database(operator,'mdm_access'),identityDatabase=database(operator,'mdm_identity_runtime'),
                         installation=installation(),expectedEpoch=1,login='admin',passwordFile=path(operator,'account-password'),operationId=operation,
                         user=dict(instanceId=INSTANCE,tenantId=TENANTS[0],principalId=ADMIN)))
        if self.sql("SELECT count(*) FROM pg_database WHERE datname='mdm_dev'")=='0':self.sql('CREATE DATABASE mdm_dev OWNER mdm_owner')
        self.sql('GRANT CREATE ON DATABASE mdm_dev TO mdm_owner,mdm_audit_owner,mdm_ledger_owner; GRANT CREATE ON SCHEMA public TO mdm_owner','mdm_dev')
        if mode!='container' or not tls['origin']:
            self.issue_leaf(self.root/'gateway-cert'/mode,['localhost','mdm.example.test'])
            for name in ('server.crt','server.key'):private(gateway/name,(self.root/'gateway-cert'/mode/name).read_text())
        from gateway_fixture import render
        prefix='/certs' if mode=='container' else str(gateway)
        nginx=render(ROOT/'deployment', origin=origin,
                     backend=config['listen'], public_port=8443 if mode=='container' else https_port,
                     certificates=prefix, web=mode=='container')
        if mode=='host':
            nginx=nginx.replace('/tmp/mdm-',str(gateway)+'/mdm-')
            mime=os.environ.get('MDM_NGINX_MIME_TYPES','/opt/homebrew/etc/nginx/mime.types' if sys.platform=='darwin' else '/etc/nginx/mime.types')
            nginx=nginx.replace('/etc/nginx/mime.types',mime)
            web_root=Path(os.environ.get('MDM_WEB_ROOT',str(gateway/'html'))).resolve()
            nginx=nginx.replace('location / { return 404; }', 'location / { root "'+str(web_root)+'"; try_files $uri $uri/ /index.html; }')
        private(gateway/'nginx.conf',nginx)
        if mode=='container':self.compose('--profile','product','run','--rm','inputs')
        else:
            result=run(['cargo','build','--locked','-p','rss-mdm-app','--bin','rss-mdm','--message-format=json'],cwd=ROOT,capture_output=True)
            binaries=[x['executable'] for line in result.stdout.splitlines() if (x:=json.loads(line)).get('reason')=='compiler-artifact' and x.get('executable') and x['target']['name']=='rss-mdm']
            if len(binaries)!=1:raise RuntimeError('product binary unavailable')
        for verb,file in [('migrate','migrate.json'),('initialize','initialize.json'),('initialize-authorization','authorization.json')]:
            if verb=='initialize' and self.sql(f"SELECT count(*) FROM public.mdm_tenants WHERE tenant_id='{TENANTS[0]}'",'mdm_dev')=='0':
                self.sql(f"SELECT public.create_new_tenant('{TENANTS[0]}',1,NULL,NULL)",'mdm_dev')
            if verb=='initialize' and self.sql(f"SELECT count(*) FROM identity_authority.accounts WHERE tenant_id='{TENANTS[0]}' AND principal_id='{ADMIN}'",'mdm_dev')=='1':
                with self.phase('initialize',reused=True):pass
                continue
            with self.phase(verb):
                if mode=='container':self.compose('--profile','product','run','--rm','operator',verb,'--config','/run/mdm/'+file)
                else:run([binaries[0],verb,'--config',operator/file],capture_output=True)
        if mode=='container':
            public=self.compose('--profile','product','run','--rm','--no-deps','server','public-host-config','--config','/run/mdm/runtime.json')
        else:
            public=run([binaries[0],'public-host-config','--config',runtime/'runtime.json'],capture_output=True).stdout
        public=json.loads(public)
        for name in ('ui.json','mdm.json'):private(gateway/name,public[name])
        if mode=='container':self.compose('--profile','product','run','--rm','inputs')
        private(self.root/(mode+'-initialized.json'),dict(origin=origin,configuration=str(runtime/'runtime.json'),https_port=https_port))
        return dict(origin=origin,configuration=str(runtime/'runtime.json'),gateway=str(gateway/'nginx.conf'))

    def start_product(self):
        if not (self.root/'container-initialized.json').exists():raise RuntimeError('run init --mode container first')
        self.verify_ownership()
        actual=json.loads((self.root/'container-initialized.json').read_text())['https_port']
        initialized=json.loads((self.root/'container-initialized.json').read_text())
        expected=initialized['origin']
        if actual!=initialized.get('https_port',urlsplit(expected).port):raise RuntimeError('product port changed; run init --mode container again')
        Ingress(self.root,self.project,self.identity).validate()
        running=self.compose('ps','-q','server','gateway').splitlines()
        with self.phase('start-product',reused=len(running)==2):
            self.compose('--profile','product','stop','server','gateway')
            self.compose('--profile','product','run','--rm','inputs')
            self.compose('--profile','product','up','-d','--force-recreate','server','web','gateway')
            external=json.loads((self.root/'container-gateway.json').read_text())['origin'] if (self.root/'container-gateway.json').exists() else None
            context=ssl.create_default_context(cafile=None if external else str(self.root/'ca.crt'))
            deadline=time.monotonic()+60
            while True:
                try:
                    if self.probe_product(expected,actual,context):break
                    failure='http-not-ready'
                except ssl.SSLCertVerificationError as error:failure=f'tls-certificate-verification (code={error.verify_code})'
                except ssl.SSLError:failure='tls-handshake'
                except http.client.HTTPException:failure='http-response'
                except OSError:failure='transport'
                if time.monotonic()>deadline:raise RuntimeError(f'product HTTPS readiness deadline: {failure}; inspect this environment logs')
                time.sleep(.2)

    @staticmethod
    def probe_product(origin, port, context):
        # Connect locally while preserving the public SNI and HTTP Host. No DNS hairpin or proxy.
        endpoint=urlsplit(origin)
        connection=http.client.HTTPSConnection(endpoint.hostname,endpoint.port or 443,context=context,timeout=3)
        try:
            connection.sock=context.wrap_socket(socket.create_connection(('127.0.0.1',port),timeout=3),server_hostname=endpoint.hostname)
            connection.request('GET','/readyz')
            response=connection.getresponse()
            return response.status==200
        finally:connection.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['up','init','stop','reset','status'])
    parser.add_argument('--mode',choices=['host','container'],default='host')
    parser.add_argument('--group',default='development')
    parser.add_argument('--server-image')
    parser.add_argument('--web-image')
    parser.add_argument('--env-file',type=Path)
    args = parser.parse_args()
    require_lease(ROOT)
    environment = Environment(group=args.group)
    if args.action == 'init':
        print(json.dumps(environment.initialize(args.mode,args.server_image,args.web_image,args.env_file)))
    else:
        result = getattr(environment,args.action)()
        if args.action=='up' and args.mode=='container':environment.start_product()
        if args.action == 'status': print(json.dumps(result))
