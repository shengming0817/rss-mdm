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
from ingress_network import Ingress
from release import oci_identity, platform, sha, image_metadata, immutable_image, DEPLOYMENT_FILES, ROLE_NAMES, RUNTIME_TOOLS
from candidate_fixture import INSTANCE, ADMIN, TENANTS, installation

TENANT = TENANTS[0]
PASSWORD = "Candidate-only-correct-horse-battery-2026!"

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
    HOST_CONFIGURATION = "host-configuration"
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

def inputs(root, example, deployment_directory, *, database_host="postgres", hostname="mdm.example.test"):
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
    (root/"extensions").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\nsubjectAltName=DNS:localhost,DNS:mdm.example.test,DNS:mdm-other.example.test,DNS:idp.example.test,IP:127.0.0.1,DNS:"+hostname+",DNS:*."+hostname+",DNS:"+database_host+"\n")
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
    config["native_protection"]=dict(active_file="/run/mdm/native-data.key",historical_files=[],fingerprint_file="/run/mdm/native-data.key")
    config["task_signing"]=None
    config["content"]=dict(storage=dict(kind='volume',directory='/var/lib/mdm/content'),imports={},
        max_artifact_bytes=32*1024*1024,max_temporary_bytes=64*1024*1024,max_uploads=4,
        transfer_seconds=60,retention_seconds=3600,
        max_bundle_entries=4096,max_expansion_ratio=100)
    config["native_protocols"]={}
    config["device_pki"]=[]
    for field,role in [("access_database","mdm_access"),("runtime_database","mdm_runtime")]:
        config[field]=database(runtime,role)
    config["execution"]["database"]=database(runtime,"mdm_command_runtime")
    config["webhooks"]["recovery_database"]=database(runtime,"mdm_webhook_operator")
    config["identity"]["database"]=database(runtime,"mdm_identity_runtime")
    config["tenant_administration"]=dict(registry_database=database(runtime,"mdm_tenant_registry"),
        provisioning_database=database(runtime,"mdm_identity_provisioning"),
        fingerprint_key_file="/run/mdm/native-data.key")
    for owner in ("inventory","scope","policy","resource","software","content","telemetry","scheduler"):
        config["business_databases"][owner]=database(runtime,"mdm_"+owner+"_runtime")
    config["scope_group_database"]=database(runtime,"mdm_scope_group_consumer")
    config["publication"]["database"]=database(runtime,"mdm_software_driver")
    write(operator,"authorization.json",dict(audit={"mode":"plain"},database=database(operator,"mdm_access"),identityDatabase=database(operator,"mdm_identity_runtime"),installation=installation(),expectedEpoch=1,login="admin",passwordFile="/run/mdm/account-password",operationId=str(uuid.uuid4()),user=dict(instanceId=INSTANCE,tenantId=TENANT,principalId=ADMIN)))
    write(runtime,"config.json",config)
    write(operator,"migrate.json",dict(database=database(operator,"mdm_owner"),installation=installation()))
    write(operator,"initialize.json",dict(audit={"mode":"plain"},database=database(operator,"mdm_identity_maintenance"),installation=installation(),tenant_id=TENANT,expected_epoch=1,principal_id=ADMIN,
                                          login="admin",password_file=write(operator,"account-password",PASSWORD)))
    from gateway_fixture import render
    gateway=render(deployment_directory, origin="https://"+hostname, backend="server:8081")
    (root/"nginx.conf").write_text(gateway.configuration)
    gateway.publish(root/"gateway-ports.compose.yaml",isolated=True)
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
    return diagnostics

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
    require(manifest.get("format_version")==1,"candidate V1 required; rebuild the candidate")
    archive=directory/manifest["archive"]["file"]
    require(archive.parent==directory and not archive.is_symlink() and sha(archive)==manifest["archive"]["sha256"],"candidate archive mismatch")
    digest,config=oci_identity(archive)
    require(digest==manifest["archive"]["manifest_digest"] and platform(config)==manifest["platform"],"candidate image mismatch")
    operator=manifest["installer"]
    operator_archive=directory/operator["archive"]["file"]
    require(operator_archive.parent==directory and not operator_archive.is_symlink()
            and operator_archive.is_file() and sha(operator_archive)==operator["archive"]["sha256"],
            "candidate operator archive mismatch")
    operator_digest,operator_config=oci_identity(operator_archive,expected_user="10001:10001")
    require(operator_digest==operator["archive"]["manifest_digest"]
            and operator["image"].endswith("@"+operator_digest)
            and platform(operator_config)==manifest["platform"],"candidate operator image mismatch")
    require(set(manifest["deployment"]) == set(DEPLOYMENT_FILES), "candidate deployment inputs mismatch")
    for name, digest in manifest["deployment"].items():
        path = directory / name
        require(not path.is_symlink() and path.is_file() and path.resolve().is_relative_to(directory.resolve())
                and not any(parent.is_symlink() for parent in path.parents if parent != directory and parent.is_relative_to(directory))
                and sha(path) == digest, "candidate deployment input mismatch")
    require(json.loads((directory/'deployment/providers.lock.json').read_text())==manifest['providers'],
            'candidate provider lock differs from its manifest')
    require(set(manifest.get("tools", {})) == set(RUNTIME_TOOLS), "candidate runtime tools mismatch")
    for name, digest in manifest["tools"].items():
        path = directory / "tools" / name
        require(path.is_file() and not path.is_symlink() and sha(path) == digest, "candidate runtime tool mismatch")
    docker("load","--input",archive,stage=Stage.LOAD)
    docker("load","--input",operator_archive,stage=Stage.LOAD)
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
        self.ingress=None
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
        ports=self.root/"gateway-ports.compose.yaml"
        if not ports.is_file():raise RuntimeError("rendered gateway ports are required")
        files += ["--file",str(ports)]
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
    def prepare_telemetry(self):
        """Prepare the required baseline through the production telemetry installer."""
        from t2_environment import private
        name='telemetry_'+uuid.UUID(self.tenant).hex
        self.sql('CREATE DATABASE "'+name+'"')
        password=os.urandom(24).hex();cursor=os.urandom(32)
        self.private_values.extend([password,cursor.hex(),base64.b64encode(cursor).decode()])
        for directory in (self.runtime,self.operator_root):
            private(directory/'telemetry-password',password)
            private(directory/'telemetry-cursor','').write_bytes(cursor)
        private(self.operator_root/'telemetry-administrator','candidate-fixture')
        database=dict(host=self.pg_host,port=5432,name=name,user='postgres',
            password_file='/run/mdm/telemetry-administrator',ca_file='/run/mdm/ca.crt')
        runtime=dict(database,user='r_'+uuid.uuid4().hex,password_file='/run/mdm/telemetry-password')
        config=dict(backend=dict(kind='postgres',database=runtime),connections=2,
            cursor_key_file='/run/mdm/telemetry-cursor',ingress=dict(requestBytes=1048576,pendingBatches=64,
            batchesPerMinute=120,bytesPerMinute=8388608),limits=dict(max_points=4096,max_series=4096,
            max_bytes=1048576,replay_micros=86400000000,cursor_micros=60000000))
        day=int(time.time())//86400
        private(self.operator_root/'telemetry-prepare.json',dict(operationId=str(uuid.uuid4()),
            directory='/tmp/telemetry-installation',tenant=self.tenant,configuration=config,
            administrator=database,owner='o_'+uuid.uuid4().hex,partitions=[dict(
            startMicros=(day-1)*86400000000,endMicros=(day+2)*86400000000)],clickhouse=None))
        self.copy_runtime()
        self.operator('prepare-telemetry','telemetry-prepare.json',Stage.INITIALIZE)
        self.config['telemetry']=config

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
        for channel in ('enrollment','management'):
            windows[channel]['origin']=f'https://windows-{channel}.{self.host}'
        private(self.root/'windows.json',windows)
        private(self.root/'case.json',dict(tenant=self.tenant))
        env={**os.environ}
        windows_provider=self.pki_stack.enter_context(running(self.root,env,case=self.name,windows=True, windows_template=self.directory/'deployment/windows-leaf.tpl', compose_file=self.directory/'deployment/compose.yaml', providers=self.providers, owner_root=self.root,instance_id=self.instance))
        agent_origin=f'https://agent.{self.host}'
        self.agent_provider=self.pki_stack.enter_context(running(self.root,env,case=self.name,agent=True,agent_origin=agent_origin,
                                            agent_template=self.directory/'deployment/agent-leaf.tpl', compose_file=self.directory/'deployment/compose.yaml', providers=self.providers, owner_root=self.root,instance_id=self.instance))
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
        agent=json.loads((self.root/'agent-pki.json').read_text())
        self.config['agent_pki']=copy(agent)
        providers=json.loads((self.root/'device-pki.json').read_text())
        self.agent_external_origin=next(item['origin'] for item in providers if item['purpose']=='agent')
        self.compose('create','server',stage=Stage.SERVER)
        for config, provider in zip(providers, [windows_provider, self.agent_provider], strict=True):
            from urllib.parse import urlsplit
            from t2_environment import PKI_CA
            external=urlsplit(config['origin'])
            require(external.scheme=='https' and external.hostname=='localhost' and external.port,'invalid fixture CA origin')
            provider.owner.extra['MDM_PKI_PUBLISH']=f'127.0.0.1:{external.port}:{PKI_CA["port"]}'
            docker('network','connect', provider.owner.project+'_default', self.container('server'), stage=Stage.SERVER)
            config['origin']='https://'+provider.internal_host+':19443'
        self.config['device_pki']=copy(providers)
        self.agent_origin=agent_origin
        self.agent_port=self.port
    def __enter__(self):
        try:
            from t2_environment import ROOT, project_name, private
            self.temporary=tempfile.TemporaryDirectory(prefix=self.name+"-")
            self.root=Path(self.temporary.name)
            self.worktree_identity=project_name(self.root)
            self.runtime,self.operator_root=inputs(self.root,self.directory/"mdm-config.example.json",
                                                  self.directory/"deployment",database_host=self.pg_host,hostname=self.host)
            import socket
            with socket.socket() as reservation:
                reservation.bind(('127.0.0.1',0));self.port=reservation.getsockname()[1]
            self.ingress=Ingress(self.root,self.name,self.worktree_identity)
            ingress=self.ingress.allocate()
            self.compose_environment={**{key:value for key,value in os.environ.items() if not key.startswith('COMPOSE_')},
                **ingress,
                'MDM_ENV_ROOT':str(self.root),'MDM_WORKTREE_ID':self.worktree_identity,
                'MDM_SERVER_IMAGE':self.image,'MDM_WEB_IMAGE':self.web['id'] if self.web else self.providers['nginx'],
                'MDM_POSTGRES_IMAGE':self.providers['postgres'],'MDM_RUNTIME_IMAGE':self.providers['runtime'],
                'MDM_NGINX_IMAGE':self.providers['nginx'],'MDM_KEYCLOAK_IMAGE':self.providers['keycloak'],
                'MDM_STEP_CA_IMAGE':self.providers['step-ca'],'MDM_STEP_CA_INTERNAL_PORT':'19443',
                'MDM_PKI_ROOT':str(self.root/'unused-pki'),'MDM_PKI_USER':f'{os.getuid()}:{os.getgid()}',
                'MDM_PKI_HOST_ADDRESS':'host-gateway','MDM_NETWORK_NAME':self.network,
                'MDM_PRODUCT_HOST':self.host,'MDM_PG_HOST':self.pg_host,'MDM_PG_DATABASE':'mdm_test',
                'MDM_SERVER_CONFIG':'config.json','MDM_PRODUCT_ORIGIN':'https://'+self.host,
                'MDM_GATEWAY_BIND_IP':'127.0.0.1',
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
            self.compose('up','-d','--no-deps','postgres',stage=Stage.POSTGRES)
            self.pg=self.container('postgres');self.created.append(self.pg)
            wait(lambda:subprocess.run(['docker','exec',self.pg,'pg_isready','-h','127.0.0.1','-U','postgres'],capture_output=True,timeout=5).returncode==0,'PostgreSQL')
            self.register_private_files()
            if self.prepare:self.prepare(self)
            self.config['listen']=self.compose_environment['MDM_BACKEND_ADDRESS']+':8081'
            self.config['trusted_gateway']=self.compose_environment['MDM_GATEWAY_ADDRESS']
            self.prepare_pki()
            self.register_private_files()
            private(self.runtime/'config.json',self.config)
            for file in ['migrate.json','initialize.json']:
                path=self.operator_root/file;value=json.loads(path.read_text());value['installation']['instance_id']=self.instance
                if file == 'initialize.json':value['tenant_id']=self.tenant
                private(path,value)
            path=self.operator_root/'authorization.json';authorization=json.loads(path.read_text())
            authorization['user'].update(instanceId=self.instance,tenantId=self.tenant)
            authorization['installation']['instance_id']=self.instance
            private(path,authorization)
            from gateway_fixture import render
            endpoints=[self.config['native_protocols']['windows'][key] for key in ['enrollment','management']]+[self.config['agent_pki']['endpoint']]
            from urllib.parse import urlsplit
            gateway=render(self.directory/'deployment',origin='https://'+self.host,
                           backend=self.config['listen'],targets={e['origin']:self.config['listen'] for e in endpoints},web=self.web is not None,
                           bootstrap_origins=(self.config['native_protocols']['windows']['enrollment']['origin'],))
            private(self.root/'nginx.conf',gateway.configuration)
            gateway.publish(self.root/'gateway-ports.compose.yaml',isolated=True,published={443:self.port})
            shutil.copyfile(self.root/'nginx.conf',gateway_dir/'nginx.conf')
            roles=''.join("CREATE ROLE "+role+" LOGIN PASSWORD '"+role+"-fixture' NOSUPERUSER NOBYPASSRLS;" for role in ['mdm_owner','mdm_api','mdm_access','mdm_runtime'])
            roles+='GRANT CREATE ON DATABASE mdm_test TO mdm_owner; GRANT CREATE ON SCHEMA public TO mdm_owner;'
            for owner in ROLE_NAMES:roles+=(self.directory/f'deployment/{owner}-roles.sql').read_text()
            for role in ['mdm_command_runtime','mdm_inventory_runtime','mdm_scope_runtime','mdm_policy_runtime','mdm_resource_runtime','mdm_software_runtime','mdm_content_runtime','mdm_telemetry_runtime','mdm_scheduler_runtime','mdm_software_driver','mdm_identity_runtime','mdm_identity_maintenance','mdm_webhook_operator','mdm_scope_group_consumer','mdm_tenant_registry','mdm_identity_provisioning']:roles+="ALTER ROLE "+role+" LOGIN PASSWORD '"+role+"-fixture';"
            self.sql(roles)
            self.copy_runtime()
            self.runtime_volume=self.name+'_runtime';self.operator_volume=self.name+'_operator';self.gateway_inputs=self.name+'_gateway'
            for stage in [Stage.MIGRATION,Stage.REPLAY]:self.operator('migrate','migrate.json',stage)
            public=json.loads(self.compose('run','--rm','--no-deps','server','public-host-config','--config','/run/mdm/config.json',stage=Stage.HOST_CONFIGURATION))
            for name in ['ui.json','mdm.json']:private(gateway_dir/name,public[name])
            self.copy_runtime()
            # Configured protocol/browser fixture: registration is precondition, not install evidence.
            # Complete installation is independently exercised by candidate_installation.py.
            tenant=str(uuid.UUID(self.tenant))
            self.sql("SET ROLE mdm_owner; SELECT public.create_new_tenant('"+tenant+"'::uuid,1,'Candidate fixture',NULL)")
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
            private(self.runtime/'config.json',self.config)
            self.copy_runtime()
            self.operator('initialize','management-initialize.json',Stage.INITIALIZE)
            self.operator('initialize-authorization','management-authorization.json',Stage.AUTHORIZATION_INITIALIZE)
            self.prepare_telemetry()
            agent=self.config['agent_pki']
            self.config['agent_pki']={'mode':'disabled'}
            private(self.runtime/'config.json',self.config)
            self.copy_runtime()
            self.start_server();self.start_gateway()
            self.port=int(self.compose('port','gateway',str(urlsplit(self.config['product_origin']).port or 443),stage=Stage.PORT).rsplit(':',1)[1])
            self.ready('/livez')
            # First signing authority is generated in its final encrypted owner through real HTTP.
            from candidate_smoke import Browser
            browser=Browser(self.port,self.root/'ca.crt',host=self.host)
            require(browser.call('POST','/api/v1/identity/tenants/'+self.tenant+'/login',
                                 dict(login='admin',password=(self.operator_root/'account-password').read_text()))[0]==200,'fixture login failed')
            status,trust=browser.call('POST','/api/v1/task-signing/trust',
                dict(action='prepare',expectedRevision=0),str(uuid.uuid4()))
            require(status==200 and trust['revision']==1,'fixture signing authority failed')
            self.config['task_signing']={'revision':trust['revision']}
            self.config['agent_pki']=agent
            private(self.runtime/'config.json',self.config)
            self.compose('stop','--timeout','45','server',stage=Stage.STOP)
            self.copy_runtime()
            self.start_server()
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
        require(origin==self.agent_external_origin,'restored CA changed frozen origin')
        self.command('exec',self.pg,'dropdb','-U','postgres','--force','mdm_test',stage=Stage.SQL)
        self.command('exec',self.pg,'createdb','-U','postgres','mdm_test',stage=Stage.SQL)
        with database.open('rb') as source:
            subprocess.run(['docker','exec','-i',self.pg,'pg_restore','-U','postgres','-d','mdm_test','--exit-on-error'],stdin=source,check=True,timeout=60)
        require(self.sql('SELECT count(*) FROM rss_audit.records')==original_audit,'PKI restore changed original Audit history')
        self.compose('start','server',stage=Stage.SERVER)
        self.ready()

    def start_gateway(self):
        if self.web is not None:self.compose("up","-d","--no-deps","web",stage=Stage.GATEWAY)
        self.compose('up','-d','--no-deps','gateway',stage=Stage.GATEWAY)
        self.gateway=self.container('gateway')
        if self.gateway not in self.created:self.created.append(self.gateway)
    def ready(self, path="/readyz"):
        def check():
            conn=http.client.HTTPSConnection("127.0.0.1",self.port,context=ssl.create_default_context(cafile=str(self.root/"ca.crt")),timeout=3)
            try:
                import socket
                conn.sock=ssl.create_default_context(cafile=str(self.root/"ca.crt")).wrap_socket(socket.create_connection(("127.0.0.1",self.port),timeout=3),server_hostname=self.host)
                conn.request("GET",path,headers={"Host":self.host})
                r=conn.getresponse();r.read();return r.status==200
            finally:conn.close()
        wait(check,"product readiness",seconds=60)
    def __exit__(self,kind,error,tb):
        def record(primary):
            return failure_evidence(self.diagnostics,self.created,{self.server,self.gateway},primary,self.diagnostic_filename,self.private_values)
        original=record(error) if error else None
        failures=[]
        try:
            try:
                records=cleanup(self.created,[])
                if any(item['outcome']!='removed' for item in records):failures.append(('containers',CleanupFailure(records)))
            except BaseException as failure:failures.append(('containers',failure))
            if self.compose_environment:
                try:self.compose('down','--volumes','--remove-orphans',stage=Stage.REMOVE_CONTAINER,timeout=120)
                except BaseException as failure:failures.append(('compose',failure))
            if self.ingress is not None:
                try:self.ingress.release()
                except BaseException as failure:failures.append(('ingress',failure))
            try:self.pki_stack.close()
            except BaseException as failure:failures.append(('pki',failure))
            try:
                records=cleanup([],self.volumes)
                if any(item['outcome']!='removed' for item in records):failures.append(('volumes',CleanupFailure(records)))
            except BaseException as failure:failures.append(('volumes',failure))
            if failures:
                primary=error if error else failures[0][1]
                records=list(getattr(primary,'cleanup_records',[]))
                for stage,failure in failures:
                    for item in getattr(failure,'cleanup_records',[dict(kind='owner',name=self.name,stage=getattr(getattr(failure,'stage',None),'value',stage),outcome=getattr(failure,'outcome','unavailable'),exit_code=getattr(failure,'exit_code',None))]):
                        if item not in records:records.append(item)
                primary.cleanup_records=records
                evidence=original if original is not None else record(primary)
                evidence['cleanup']=records
                try:
                    with tempfile.TemporaryDirectory(prefix='.smoke-cleanup-',dir=self.diagnostics) as temporary:
                        staged=Path(temporary)/'failure.json'
                        staged.write_text(json.dumps(evidence,indent=2)+'\n')
                        os.replace(staged,self.diagnostics/self.diagnostic_filename)
                except Exception:primary.add_note('candidate cleanup diagnostics could not be persisted')
                if error:error.add_note('candidate cleanup failed')
                else:raise primary
        finally:
            if self.temporary and not failures:self.temporary.cleanup()
