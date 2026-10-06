#!/usr/bin/env python3
"""Owned product candidate deployment shared by smoke and browser acceptance."""
from enum import StrEnum
import http.client
import json
import os
import re
import base64
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import ExitStack
from release import oci_identity, platform, sha, image_metadata, immutable_image, DEPLOYMENT_FILES, ROLE_NAMES
from candidate_fixture import INSTANCE, ADMIN, TENANTS, installation

TENANT = TENANTS[0]
PASSWORD = "Candidate-only-correct-horse-battery-2026!"

def public_host_inputs(config):
    """Only public bootstrap fields derived from the product's existing runtime input."""
    return {
        "ui.json": {"canonicalOrigin": config["product_origin"], "oidcEnabled": config["identity"]["oidc"] is not None},
        "mdm.json": {"canonicalOrigin": config["product_origin"], "tenant": config["identity"]["tenant_id"]},
    }

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

class Stage(StrEnum):
    LOAD = "image-load"
    NETWORK = "network-create"
    IMAGE_INSPECT = "image-inspect"
    IDP = "idp-start"
    IDP_INSPECT = "idp-inspect"
    BROWSER = "browser-run"
    TOOLS = "tools-probe"
    TOOLS_ARCHIVE = "tools-archive"
    SECRET_VOLUME = "secret-volume"
    SECRET_INPUTS = "secret-inputs"
    POSTGRES = "postgres-start"
    SQL = "postgres-sql"
    RUNTIME_VOLUME = "runtime-volume"
    OPERATOR_VOLUME = "operator-volume"
    RUNTIME_INPUTS = "runtime-inputs"
    OPERATOR_INPUTS = "operator-inputs"
    MIGRATION = "migration"
    REPLAY = "migration-replay"
    REGISTRATION = "tenant-registration"
    INITIALIZE = "initialize"
    AUTHORIZATION_INITIALIZE = "authorization_initialize"
    AUTHORIZATION_REPLAY = "authorization_replay"
    GATEWAY = "gateway-start"
    SERVER = "server-start"
    PORT = "gateway-port"
    STOP = "server-stop"
    LOGS = "server-logs"
    EXIT = "server-exit"
    DIAGNOSTIC_STATE = "diagnostic-state"
    DIAGNOSTIC_LOGS = "diagnostic-logs"
    REMOVE_CONTAINER = "cleanup-container"
    REMOVE_VOLUME = "cleanup-volume"
    REMOVE_NETWORK = "cleanup-network"

class DockerFailure(RuntimeError):
    def __init__(self, stage, outcome, exit_code=None):
        self.stage, self.outcome, self.exit_code = stage, outcome, exit_code
        super().__init__(f"candidate Docker failure: stage={stage.value} outcome={outcome} exit_code={exit_code}")

def docker(*args, stage, timeout=120, input=None, env=None):
    if not isinstance(stage, Stage):
        raise ValueError("candidate Docker stage must be a closed value")
    try:
        result = subprocess.run(["docker", *map(str,args)], input=input, text=True, capture_output=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        raise DockerFailure(stage, "timeout") from None
    except OSError:
        raise DockerFailure(stage, "unavailable") from None
    # Do not echo command arguments, mounted configuration, HTTP credentials or provider stderr.
    if result.returncode:
        raise DockerFailure(stage, "exit", result.returncode)
    return (result.stdout + result.stderr if args[0] == "logs" else result.stdout).strip()

def wait(check, stage, seconds=45):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            if check(): return
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(.2)
    raise RuntimeError("candidate deadline: " + stage)

def inputs(root, example, gateway_file, *, database_host="postgres"):
    """Runtime and operator get separate mounts; the server never receives maintenance credentials."""
    runtime, operator = root/"container/runtime", root/"container/operator"
    runtime.mkdir(parents=True); operator.mkdir(parents=True)
    def openssl(*args):
        subprocess.run(["openssl", *map(str,args)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    openssl("req","-x509","-newkey","rsa:2048","-nodes","-days","1","-subj","/CN=MDM candidate CA",
            "-addext","basicConstraints=critical,CA:TRUE","-addext","keyUsage=critical,keyCertSign,cRLSign",
            "-addext","subjectKeyIdentifier=hash",
            "-keyout",root/"ca.key","-out",root/"ca.crt")
    openssl("req","-new","-newkey","rsa:2048","-nodes","-subj","/CN=localhost","-keyout",root/"server.key","-out",root/"server.csr")
    (root/"extensions").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\nsubjectAltName=DNS:localhost,DNS:mdm.example.test,DNS:mdm-other.example.test,DNS:idp.example.test,IP:127.0.0.1,DNS:"+database_host+"\n")
    openssl("x509","-req","-in",root/"server.csr","-CA",root/"ca.crt","-CAkey",root/"ca.key","-CAcreateserial","-days","1","-extfile",root/"extensions","-out",root/"server.crt")
    def write(directory, name, value):
        path=directory/name;path.write_text(value if isinstance(value,str) else json.dumps(value));path.chmod(0o600)
        return "/run/mdm/"+name
    def database(directory, role):
        return dict(host=database_host,port=5432,name="mdm_test",user=role,
                    password_file=write(directory,role+"-password",role+"-fixture"),ca_file="/run/mdm/ca.crt")
    for directory in [runtime,operator]: shutil.copy(root/"ca.crt",directory/"ca.crt")
    native_key=runtime/"native-data.key"
    native_key.touch(mode=0o600)
    native_key.write_bytes(os.urandom(32))
    config=json.loads(example.read_text())
    config["native_protection_key_file"]="/run/mdm/native-data.key"
    # Agent registration consumes the same explicit signing input as runtime tasks.
    key_file=runtime/'task-signing.pk8';key_file.touch(mode=0o600)
    openssl('genpkey','-algorithm','ED25519','-outform','DER','-out',key_file)
    public=subprocess.check_output(['openssl','pkey','-inform','DER','-in',str(key_file),'-pubout','-outform','DER'],timeout=30)
    private=key_file.read_bytes()
    require(private[:16]==bytes.fromhex('302e020100300506032b657004220420') and len(private)==48
            and public[:12]==bytes.fromhex('302a300506032b6570032100') and len(public)==44,
            'candidate Ed25519 key encoding')
    # ref: ring 0.17.14 ed25519/signing.rs: from_pkcs8 requires v2 with the public key.
    key_file.write_bytes(bytes.fromhex('3051020101300506032b657004220420')+private[-32:]+bytes.fromhex('812100')+public[-32:])
    config['task_signing']=dict(private_key_file='/run/mdm/task-signing.pk8',key_id='candidate',
                                trusted_keys={'candidate':base64.urlsafe_b64encode(public[-32:]).decode().rstrip('=')})
    config["native_protocols"]={}
    config["device_pki"]=[]
    for field,role in [("access_database","mdm_access"),("runtime_database","mdm_runtime")]:
        config[field]=database(runtime,role)
    config["execution"]["database"]=database(runtime,"mdm_command_runtime")
    config["identity"]["database"]=database(runtime,"mdm_identity_runtime")
    config["identity"]["audit_worker"]=database(runtime,"mdm_identity_audit")
    config["flow"]["storage"]["database"]=database(runtime,"mdm_flow_runtime")
    config["flow"]["publication"]["database"]=database(runtime,"mdm_software_driver")
    config["identity_management"]=[dict(tenant_id=TENANT,instance_id=INSTANCE,principal_id=ADMIN,permissions=["accounts"])]
    write(operator,"authorization.json",dict(audit={"mode":"plain"},database=database(operator,"mdm_access"),identityDatabase=database(operator,"mdm_identity_runtime"),installation=installation(),expectedEpoch=1,login="admin",passwordFile="/run/mdm/account-password",operationId=str(uuid.uuid4()),user=dict(instanceId=INSTANCE,tenantId=TENANT,principalId=ADMIN)))
    write(runtime,"config.json",config)
    write(operator,"migrate.json",dict(database=database(operator,"mdm_owner"),installation=installation()))
    write(operator,"tenant-create.json",dict(database=database(operator,"mdm_owner"),installation=installation(),tenant_id=TENANT,initial_epoch=1,operation_id=str(uuid.uuid4())))
    write(operator,"initialize.json",dict(database=database(operator,"mdm_identity_maintenance"),installation=installation(),tenant_id=TENANT,expected_epoch=1,principal_id=ADMIN,
                                          login="admin",password_file=write(operator,"account-password",PASSWORD)))
    gateway=gateway_file.read_text().replace("listen 443 ssl;","listen 8445 ssl;")
    gateway=gateway.replace("/run/config/ui.json","/certs/ui.json").replace("/run/config/mdm.json","/certs/mdm.json")
    gateway=gateway.replace("/private/mdm-tls.crt","/certs/server.crt").replace("/private/mdm-tls.key","/certs/server.key")
    (root/"nginx.conf").write_text(gateway)
    root.chmod(0o700)
    (root/"server.key").chmod(0o600)
    return runtime,operator

def failure_evidence(directory, created, safe_log_sources, primary, filename="smoke-failure.json", private_values=()):
    # Product and ingress logs have closed, credential-free schemas. PostgreSQL
    # statement logs can contain input values, so capture only its closed state.
    diagnostics = {"status":"failed", "error_class":type(primary).__name__, "containers":{}}
    if isinstance(primary, DockerFailure):
        diagnostics.update(stage=primary.stage.value,outcome=primary.outcome,exit_code=primary.exit_code)
    if hasattr(primary,'resource'):diagnostics['resource']=primary.resource
    if hasattr(primary,'cleanup_records'):diagnostics['cleanup']=primary.cleanup_records
    for name in created:
        value = {}
        try:
            value["state"] = docker("inspect", "--format", "{{.State.Status}}:{{.State.ExitCode}}", name, timeout=10,stage=Stage.DIAGNOSTIC_STATE)
            if name in safe_log_sources:
                log=docker("logs", "--tail", "200", name, timeout=10,stage=Stage.DIAGNOSTIC_LOGS)
                try:value['log']=safe_evidence(log,private_values)
                except RuntimeError:value['log_rejected']=True
        except Exception:
            value["diagnostic_unavailable"] = True
        diagnostics["containers"][name] = value
    try:
        with tempfile.TemporaryDirectory(prefix=".smoke-failure-", dir=directory) as temporary:
            staged = Path(temporary)/"failure.json"
            staged.write_text(json.dumps(diagnostics,indent=2)+"\n")
            os.replace(staged,directory/filename)
    except Exception:
        primary.add_note("candidate failure diagnostics could not be persisted")

class CleanupFailure(RuntimeError):
    def __init__(self, records):
        self.cleanup_records=records
        super().__init__("candidate cleanup failed")

def cleanup(created, volume, network=None):
    primary = sys.exception()
    records = []
    commands = [("container",name,Stage.REMOVE_CONTAINER,("rm","-f",name)) for name in reversed(created)]
    commands.extend(("volume",name,Stage.REMOVE_VOLUME,("volume","rm",name)) for name in ([volume] if isinstance(volume,str) else reversed(volume)))
    if network:commands.append(("network",network,Stage.REMOVE_NETWORK,("network","rm",network)))
    for kind,name,stage,command in commands:
        record=dict(kind=kind,name=name,stage=stage.value,outcome="removed",exit_code=None)
        try:docker(*command,stage=stage)
        except DockerFailure as error:record.update(outcome=error.outcome,exit_code=error.exit_code)
        except Exception:record.update(outcome="unavailable")
        records.append(record)
    failures=[record for record in records if record['outcome']!='removed']
    if failures:
        if primary is not None:
            primary.cleanup_records=getattr(primary,'cleanup_records',[])+records
            primary.add_note(f"candidate cleanup failed ({len(failures)} resources)")
        else:raise CleanupFailure(records)
    return records

def run_owned(created, owner, *args, stage, **kwargs):
    """The daemon container, not its CLI process, is the owned resource.

    ref: testcontainers-python DockerContainer.start/stop: retain identity until removal.
    """
    name=owner+'-op-'+uuid.uuid4().hex[:8]
    created.append(name)
    try:
        return docker('run','--name',name,'--label','rss.owner='+owner,*args,stage=stage,**kwargs)
    except DockerFailure as error:
        error.resource=dict(kind='container',name=name)
        raise
    finally:
        records=cleanup([name],[])
        if records[0]['outcome']=='removed':created.remove(name)

def safe_evidence(value, private_values):
    encoded=json.dumps(value)
    require(not re.search(r'[?&](?:code|state)=',encoded),'callback URL in evidence')
    require(not any(secret and (secret in encoded or json.dumps(secret)[1:-1] in encoded) for secret in private_values),'sensitive evidence rejected')
    return value

def image_identity(reference):
    value = json.loads(docker("image", "inspect", reference, stage=Stage.IMAGE_INSPECT))[0]
    return image_metadata(value)

def load_ui(directory, ui):
    archive=directory/ui['archive']['file']
    require(archive.parent==directory and not archive.is_symlink() and sha(archive)==ui['archive']['sha256'],'UI archive mismatch')
    docker('load','--input',archive,stage=Stage.LOAD)
    actual=image_identity(immutable_image(ui['id']))
    require(actual=={key:value for key,value in ui.items() if key!='archive'},'UI artifact differs from candidate')
    return actual

def verify_candidate(directory):
    manifest=json.loads((directory/"candidate.json").read_text())
    require(manifest.get("format_version")==4,"candidate V4 required; rebuild the candidate")
    archive=directory/manifest["archive"]["file"]
    require(archive.parent==directory and not archive.is_symlink() and sha(archive)==manifest["archive"]["sha256"],"candidate archive mismatch")
    digest,config=oci_identity(archive)
    require(digest==manifest["archive"]["manifest_digest"] and platform(config)==manifest["platform"],"candidate image mismatch")
    require(set(manifest["deployment"]) == set(DEPLOYMENT_FILES), "candidate deployment inputs mismatch")
    for name, digest in manifest["deployment"].items():
        path = directory / name
        require(not path.is_symlink() and path.is_file() and path.resolve().is_relative_to(directory.resolve())
                and not any(parent.is_symlink() for parent in path.parents if parent != directory and parent.is_relative_to(directory))
                and sha(path) == digest, "candidate deployment input mismatch")
    require(json.loads((directory/'deployment/providers.lock.json').read_text())==manifest['providers'],
            'candidate provider lock differs from its manifest')
    from t2_environment import ROOT
    require(sha(directory/'fixtures/pki-tools.lock.json')==sha(ROOT/'fixtures/pki-tools.lock.json'),
            'candidate PKI tools differ from the supported fixed runtime helper')
    docker("load","--input",archive,stage=Stage.LOAD)
    return manifest

class Candidate:
    """One owned PG/network namespace, product binary and canonical UI ingress."""
    def __init__(self, directory, *, prepare=None, network=None, host="mdm.example.test", instance=INSTANCE, tenant=TENANT, diagnostics=None, diagnostic_filename=None, require_ui=False):
        self.directory,self.prepare,self.host=directory,prepare,host
        self.instance,self.tenant=instance,tenant
        self.diagnostics=diagnostics or directory
        self.manifest=verify_candidate(directory)
        require(not require_ui or "ui" in self.manifest,
                "browser acceptance requires a UI image; rebuild with --web-image")
        artifact=image_identity(self.manifest["image"])
        require(self.manifest["image"].endswith("@"+self.manifest["archive"]["manifest_digest"]),"runtime image differs from candidate")
        self.image=artifact["id"]
        self.web=load_ui(directory,self.manifest["ui"]) if "ui" in self.manifest else None
        self.providers=self.manifest["providers"]
        self.name="mdm-candidate-"+uuid.uuid4().hex
        self.diagnostic_filename=diagnostic_filename or self.name+"-failure.json"
        self.pg,self.gateway,self.server=[self.name+suffix for suffix in ("-pg","-gateway","-server")]
        self.network=network or self.name+"-network"
        self.own_network=network is None
        self.pg_host=self.name+"-db"
        self.pki_stack=ExitStack()
        self.compose_environment=None
        self.compose_override=None
        self.created,self.volumes=[],[]
        self.temporary=None
        self.network_created=False
        self.private_values=[PASSWORD,"candidate-fixture"]
    def command(self,*args,stage,**kwargs):
        return docker(*args,stage=stage,**kwargs)
    def sql(self,statement):
        return self.command("exec","-i",self.pg,"psql","-X","-At","-v","ON_ERROR_STOP=1","-U","postgres","-d","mdm_test",input=statement,timeout=15,stage=Stage.SQL)
    def run_once(self,*args,stage,**kwargs):
        return run_owned(self.created,self.name,*args,stage=stage,**kwargs)
    def register_private_files(self):
        for path in self.root.rglob('*'):
            if path.is_file() and (path.suffix in {'.key','.pk8'} or 'password' in path.name or path.name in {'state','credential'}):
                raw=path.read_bytes()
                self.private_values.extend([raw.hex(),base64.b64encode(raw).decode()])
                try:self.private_values.append(raw.decode().strip())
                except UnicodeError:pass
    def copy_secret_volume(self, volume, files, uid):
        require(isinstance(uid,int) and uid>0,'invalid secret owner')
        for filename in files:
            require(filename not in {'.','..'} and re.fullmatch(r'[a-zA-Z0-9_.-]+',filename) is not None,'invalid fixture filename')
        script='mkdir -p /private; '+''.join('cp /fixture/'+name+' /private/'+name+'; ' for name in files)+f'chown -R {uid}:{uid} /private; chmod 700 /private; chmod 600 /private/*; '
        script+='; '.join(f'test "$(stat -c %a:%u /private/{name})" = "600:{uid}"' for name in files)
        self.run_once('--user','0:0','--network','none','-v',str(self.root)+':/fixture:ro','-v',volume+':/private','--entrypoint','sh',self.providers['runtime'],'-ec',script,stage=Stage.SECRET_INPUTS)
    def secret_volume(self, suffix, files, uid):
        volume=self.name+'-'+suffix
        self.volumes.append(volume);self.command('volume','create',volume,stage=Stage.SECRET_VOLUME)
        self.copy_secret_volume(volume,files,uid)
        return volume
    def compose(self,*args,stage,**kwargs):
        files=["--file",str(self.directory/"deployment/compose.yaml")]
        if self.compose_override:files += ["--file",str(self.compose_override)]
        return self.command("compose","--project-name",self.name,"--env-file",os.devnull,*files,"--profile","product",*args,
                            stage=stage,env=self.compose_environment,**kwargs)
    def container(self,service):
        ident=self.compose("ps","--all","--quiet",service,stage=Stage.IMAGE_INSPECT)
        require(bool(ident) and "\n" not in ident,"candidate Compose service missing")
        info=json.loads(self.command("inspect",ident,stage=Stage.IMAGE_INSPECT))[0]
        require(info['Config']['Labels'].get('rss.mdm.worktree')==self.worktree_identity,
                "candidate Compose resource owner mismatch")
        return info['Name'].lstrip('/')
    def operator(self,verb,config,stage):
        return self.compose("run","--rm","--no-deps","operator",verb,"--config","/run/mdm/"+config,stage=stage)
    def copy_runtime(self):
        self.compose("run","--rm","--no-deps","inputs",stage=Stage.RUNTIME_INPUTS)
    def start_server(self):
        self.compose("up","-d","--no-deps","server",stage=Stage.SERVER)
        self.server=self.container('server')
        if self.server not in self.created:self.created.append(self.server)
    def prepare_pki(self):
        from windows_fixtures import generate
        from pki_fixtures import running
        from t2_environment import private
        windows=generate(self.root,self.root/'server.crt',self.root/'server.key')
        for channel,port in [('enrollment',8443),('management',8444)]:
            windows[channel]['listen']=f'0.0.0.0:{port}'
            windows[channel]['origin']='https://localhost:'+self.compose('port','runtime-netns',str(port),stage=Stage.PORT).rsplit(':',1)[1]
        private(self.root/'windows.json',windows)
        private(self.root/'case.json',dict(tenant=self.tenant))
        env={**os.environ}
        windows_provider=self.pki_stack.enter_context(running(self.root,env,case=self.name,windows=True, windows_template=self.directory/'deployment/windows-leaf.tpl', compose_file=self.directory/'deployment/compose.yaml', providers=self.providers))
        agent_origin='https://localhost:'+self.compose('port','runtime-netns','9445',stage=Stage.PORT).rsplit(':',1)[1]
        self.agent_provider=self.pki_stack.enter_context(running(self.root,env,case=self.name,agent=True,agent_origin=agent_origin,
                                            agent_template=self.directory/'deployment/agent-leaf.tpl', compose_file=self.directory/'deployment/compose.yaml', providers=self.providers))
        def copy_file(source):
            source=Path(source)
            target=self.runtime/(sha(source)[:32]+'-'+source.name)
            if not target.exists():shutil.copyfile(source,target);target.chmod(0o600)
            return '/run/mdm/'+target.name
        def copy(value):
            if isinstance(value,dict):return {key:copy_file(item) if key.endswith('_file') else copy(item) for key,item in value.items()}
            if isinstance(value,list):return [copy(item) for item in value]
            return value
        self.config['native_protocols']['windows']=copy(json.loads((self.root/'windows.json').read_text()))
        agent=json.loads((self.root/'agent-pki.json').read_text());agent['endpoint']['listen']='0.0.0.0:9445'
        self.config['agent_pki']=copy(agent)
        providers=json.loads((self.root/'device-pki.json').read_text())
        for config, provider in zip(providers, [windows_provider, self.agent_provider], strict=True):
            docker('network','connect', provider.owner.project+'_default', self.container('runtime-netns'), stage=Stage.SERVER)
            config['origin']='https://'+provider.internal_host+':19443'
        self.config['device_pki']=copy(providers)
        self.agent_origin=agent_origin
        self.agent_port=int(agent_origin.rsplit(':',1)[1])
    def __enter__(self):
        try:
            from t2_environment import ROOT, project_name, private
            self.worktree_identity=project_name(ROOT)
            self.temporary=tempfile.TemporaryDirectory(prefix=self.name+"-")
            self.root=Path(self.temporary.name)
            self.runtime,self.operator_root=inputs(self.root,self.directory/"mdm-config.example.json",
                                                  self.directory/"deployment/nginx.conf",database_host=self.pg_host)
            self.compose_environment={**{key:value for key,value in os.environ.items() if not key.startswith('COMPOSE_')},
                'MDM_ENV_ROOT':str(self.root),'MDM_WORKTREE_ID':self.worktree_identity,
                'MDM_SERVER_IMAGE':self.image,'MDM_WEB_IMAGE':self.web['id'] if self.web else self.providers['nginx'],
                'MDM_POSTGRES_IMAGE':self.providers['postgres'],'MDM_RUNTIME_IMAGE':self.providers['runtime'],
                'MDM_NGINX_IMAGE':self.providers['nginx'],'MDM_KEYCLOAK_IMAGE':self.providers['keycloak'],
                'MDM_STEP_CA_IMAGE':self.providers['step-ca'],'MDM_STEP_CA_INTERNAL_PORT':'19443',
                'MDM_PKI_ROOT':str(self.root/'unused-pki'),'MDM_PKI_USER':f'{os.getuid()}:{os.getgid()}',
                'MDM_PKI_HOST_ADDRESS':'host-gateway','MDM_NETWORK_NAME':self.network,
                'MDM_PRODUCT_HOST':self.host,'MDM_PG_HOST':self.pg_host,'MDM_PG_DATABASE':'mdm_test',
                'MDM_SERVER_CONFIG':'config.json','MDM_PRODUCT_ORIGIN':'https://'+self.host,
                'MDM_GATEWAY_PUBLISH':'127.0.0.1::8445',
                'MDM_GATEWAY_TLS_CERT_FILE':str(self.root/'server.crt'),'MDM_GATEWAY_TLS_KEY_FILE':str(self.root/'server.key')}
            if not self.own_network:
                self.compose_override=self.root/'external-network.yaml'
                self.compose_override.write_text('networks:\n  default:\n    external: true\n    labels: !reset {}\n')
            pg=self.root/'pg';pg.mkdir()
            for name in ['server.crt','server.key']:shutil.copyfile(self.root/name,pg/name);(pg/name).chmod(0o600)
            private(pg/'pg-password','candidate-fixture')
            gateway_dir=self.root/'container/gateway';gateway_dir.mkdir()
            self.config=json.loads((self.runtime/'config.json').read_text())
            self.config['product_origin']='https://'+self.host
            self.config['identity'].update(instance_id=self.instance,tenant_id=self.tenant)
            self.config['identity_management'][0].update(instance_id=self.instance,tenant_id=self.tenant)
            self.compose('up','-d','--no-deps','postgres','runtime-netns',stage=Stage.POSTGRES)
            self.pg=self.container('postgres');self.created.append(self.pg)
            self.netns=self.container('runtime-netns');self.created.append(self.netns)
            wait(lambda:subprocess.run(['docker','exec',self.pg,'pg_isready','-h','127.0.0.1','-U','postgres'],capture_output=True,timeout=5).returncode==0,'PostgreSQL')
            self.register_private_files()
            if self.prepare:self.prepare(self)
            self.prepare_pki()
            self.register_private_files()
            private(self.runtime/'config.json',self.config)
            for file in ['migrate.json','tenant-create.json','initialize.json']:
                path=self.operator_root/file;value=json.loads(path.read_text());value['installation']['instance_id']=self.instance
                if file in ('tenant-create.json','initialize.json'):value['tenant_id']=self.tenant
                private(path,value)
            path=self.operator_root/'authorization.json';authorization=json.loads(path.read_text())
            authorization['user'].update(instanceId=self.instance,tenantId=self.tenant)
            authorization['installation']['instance_id']=self.instance
            private(path,authorization)
            gateway=(self.root/'nginx.conf').read_text().replace('mdm.example.test',self.host)
            if self.web is None:gateway=gateway.replace('location / { try_files $uri $uri/ /index.html; }','location / { return 404; }')
            private(self.root/'nginx.conf',gateway)
            for name,value in public_host_inputs(self.config).items():private(self.root/name,value)
            for name in ['nginx.conf','ui.json','mdm.json']:shutil.copyfile(self.root/name,gateway_dir/name)
            roles=''.join("CREATE ROLE "+role+" LOGIN PASSWORD '"+role+"-fixture' NOSUPERUSER NOBYPASSRLS;" for role in ['mdm_owner','mdm_api','mdm_access','mdm_runtime'])
            roles+='GRANT CREATE ON DATABASE mdm_test TO mdm_owner; GRANT CREATE ON SCHEMA public TO mdm_owner;'
            for owner in ROLE_NAMES:roles+=(self.directory/f'deployment/{owner}-roles.sql').read_text()
            for role in ['mdm_command_runtime','mdm_flow_runtime','mdm_software_driver','mdm_identity_runtime','mdm_identity_maintenance','mdm_identity_audit']:roles+="ALTER ROLE "+role+" LOGIN PASSWORD '"+role+"-fixture';"
            self.sql(roles)
            self.copy_runtime()
            self.runtime_volume=self.name+'_runtime';self.operator_volume=self.name+'_operator';self.gateway_inputs=self.name+'_gateway'
            for stage in [Stage.MIGRATION,Stage.REPLAY]:self.operator('migrate','migrate.json',stage)
            self.operator('tenant-create','tenant-create.json',Stage.REGISTRATION)
            self.operator('initialize','initialize.json',Stage.INITIALIZE)
            self.operator('initialize-authorization','authorization.json',Stage.AUTHORIZATION_INITIALIZE)
            self.operator('initialize-authorization','authorization.json',Stage.AUTHORIZATION_REPLAY)
            # Candidate fixture explicitly bootstraps the reserved tenant through existing commands.
            self.management_tenant=self.sql('SELECT management_tenant_id FROM public.mdm_installation')
            management_account=json.loads((self.operator_root/'initialize.json').read_text())
            management_account['tenant_id']=self.management_tenant
            private(self.operator_root/'management-initialize.json',management_account)
            management_auth=json.loads((self.operator_root/'authorization.json').read_text())
            management_auth['user']['tenantId']=self.management_tenant
            management_auth['operationId']=str(uuid.uuid4())
            private(self.operator_root/'management-authorization.json',management_auth)
            self.config['identity_management'].append(dict(tenant_id=self.management_tenant,instance_id=self.instance,
                principal_id=ADMIN,permissions=['accounts']))
            private(self.runtime/'config.json',self.config)
            self.copy_runtime()
            self.operator('initialize','management-initialize.json',Stage.INITIALIZE)
            self.operator('initialize-authorization','management-authorization.json',Stage.AUTHORIZATION_INITIALIZE)
            self.start_server();self.start_gateway()
            self.port=int(self.compose('port','runtime-netns','8445',stage=Stage.PORT).rsplit(':',1)[1])
            self.ready()
            return self
        except BaseException:
            self.__exit__(*sys.exc_info())
            raise
    def restore_pki_bundle(self):
        """Stopped writers: restore the original CA storage and MDM/Audit snapshot together."""
        self.compose('stop','--timeout','45','server',stage=Stage.STOP)
        original_audit=self.sql('SELECT count(*) FROM rss_audit.records')
        snapshot=self.agent_provider.backup(self.root/'agent-pki-backup')
        database=self.root/'mdm-backup.dump'
        with database.open('wb') as output:
            subprocess.run(['docker','exec',self.pg,'pg_dump','-U','postgres','-d','mdm_test','-Fc'],stdout=output,check=True,timeout=60)
        database.chmod(0o600)
        origin=self.agent_provider.restore(snapshot)
        require(origin==json.loads((self.root/'device-pki.json').read_text())[1]['origin'],'restored CA changed frozen origin')
        self.command('exec',self.pg,'dropdb','-U','postgres','--force','mdm_test',stage=Stage.SQL)
        self.command('exec',self.pg,'createdb','-U','postgres','mdm_test',stage=Stage.SQL)
        with database.open('rb') as source:
            subprocess.run(['docker','exec','-i',self.pg,'pg_restore','-U','postgres','-d','mdm_test','--exit-on-error'],stdin=source,check=True,timeout=60)
        require(self.sql('SELECT count(*) FROM rss_audit.records')==original_audit,'PKI restore changed original Audit history')
        self.compose('start','server',stage=Stage.SERVER)
        self.ready()

    def start_gateway(self):
        self.compose('up','-d','--no-deps','gateway',stage=Stage.GATEWAY)
        self.gateway=self.container('gateway')
        if self.gateway not in self.created:self.created.append(self.gateway)
    def ready(self):
        def check():
            conn=http.client.HTTPSConnection("127.0.0.1",self.port,context=ssl.create_default_context(cafile=str(self.root/"ca.crt")),timeout=3)
            try:
                conn.request("GET","/readyz",headers={"Host":self.host})
                r=conn.getresponse();r.read();return r.status==200
            finally:conn.close()
        wait(check,"product readiness",seconds=60)
    def __exit__(self,kind,error,tb):
        def record(primary):
            failure_evidence(self.diagnostics,self.created,{self.server,self.gateway},primary,self.diagnostic_filename,self.private_values)
        if error:record(error)
        failures=[]
        try:
            if self.compose_environment:
                try:self.compose('down','--volumes','--remove-orphans',stage=Stage.REMOVE_CONTAINER,timeout=120)
                except BaseException as failure:failures.append(failure)
            try:self.pki_stack.close()
            except BaseException as failure:failures.append(failure)
            try:cleanup([],self.volumes)
            except BaseException as failure:failures.append(failure)
            if failures:
                if error:error.add_note('candidate cleanup failed');record(error)
                else:record(failures[0]);raise failures[0]
        finally:
            if self.temporary and not failures:self.temporary.cleanup()
