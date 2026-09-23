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
from release import ROOT, oci_identity, platform, sha, image_metadata, immutable_image
from t2 import INSTANCE, ADMIN, TENANTS, installation

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

def docker(*args, stage, timeout=120, input=None):
    if not isinstance(stage, Stage):
        raise ValueError("candidate Docker stage must be a closed value")
    try:
        result = subprocess.run(["docker", *map(str,args)], input=input, text=True, capture_output=True, timeout=timeout)
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

def inputs(root, example):
    """Runtime and operator get separate mounts; the server never receives maintenance credentials."""
    runtime, operator = root/"runtime", root/"operator"
    runtime.mkdir(); operator.mkdir()
    def openssl(*args):
        subprocess.run(["openssl", *map(str,args)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    openssl("req","-x509","-newkey","rsa:2048","-nodes","-days","1","-subj","/CN=MDM candidate CA",
            "-addext","basicConstraints=critical,CA:TRUE","-addext","keyUsage=critical,keyCertSign,cRLSign",
            "-keyout",root/"ca.key","-out",root/"ca.crt")
    openssl("req","-new","-newkey","rsa:2048","-nodes","-subj","/CN=localhost","-keyout",root/"server.key","-out",root/"server.csr")
    (root/"extensions").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,DNS:mdm.example.test,DNS:mdm-other.example.test,DNS:idp.example.test,IP:127.0.0.1\n")
    openssl("x509","-req","-in",root/"server.csr","-CA",root/"ca.crt","-CAkey",root/"ca.key","-CAcreateserial","-days","1","-extfile",root/"extensions","-out",root/"server.crt")
    from windows_fixtures import generate
    windows = generate(root, root/"server.crt", root/"server.key")
    def write(directory, name, value):
        path=directory/name;path.write_text(value if isinstance(value,str) else json.dumps(value));path.chmod(0o600)
        return "/run/mdm/"+name
    def database(directory, role):
        return dict(host="localhost",port=5432,name="mdm_test",user=role,
                    password_file=write(directory,role+"-password",role+"-fixture"),ca_file="/run/mdm/ca.crt")
    for directory in [runtime,operator]: shutil.copy(root/"ca.crt",directory/"ca.crt")
    def copy_inputs(value):
        if isinstance(value,dict):
            return {key:copy_inputs(item) if not key.endswith("_file") else copy_file(item) for key,item in value.items()}
        return value
    def copy_file(source):
        path=runtime/Path(source).name;shutil.copy(source,path);path.chmod(0o600)
        return "/run/mdm/"+path.name
    config=json.loads(example.read_text())
    config["native_protocols"]={"windows":copy_inputs(windows)}
    for field,role in [("access_database","mdm_access"),("runtime_database","mdm_runtime"),("command_database","mdm_command_runtime")]:
        config[field]=database(runtime,role)
    config["identity"]["database"]=database(runtime,"mdm_identity_runtime")
    config["management"]["database"]=database(runtime,"mdm_management_runtime")
    config["management"]["publication_database"]=database(runtime,"mdm_software_driver")
    config["identity_management"]=[dict(tenant_id=TENANT,instance_id=INSTANCE,principal_id=ADMIN,permissions=["accounts"])]
    write(operator,"authorization.json",dict(database=database(operator,"mdm_access"),identityDatabase=database(operator,"mdm_identity_runtime"),installation=installation(),login="admin",passwordFile="/run/mdm/account-password",operationId=str(uuid.uuid4()),user=dict(instanceId=INSTANCE,tenantId=TENANT,principalId=ADMIN)))
    write(runtime,"config.json",config)
    write(operator,"migrate.json",dict(database=database(operator,"mdm_owner"),installation=installation()))
    write(operator,"initialize.json",dict(database=database(operator,"mdm_identity_maintenance"),installation=installation(),tenant_id=TENANT,principal_id=ADMIN,
                                          login="admin",password_file=write(operator,"account-password",PASSWORD)))
    gateway=(ROOT/"deployment/nginx.conf").read_text().replace("listen 443 ssl;","listen 8445 ssl;")
    gateway=gateway.replace("/run/config/ui.json","/certs/ui.json")
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

def verify_source(revision):
    current=subprocess.check_output(["/usr/bin/git","rev-parse","HEAD"],cwd=ROOT,text=True).strip()
    require(current==revision and not subprocess.check_output(["/usr/bin/git","status","--porcelain"],cwd=ROOT,text=True).strip(),"candidate requires clean matching source")

def verify_candidate(directory):
    manifest=json.loads((directory/"candidate.json").read_text())
    require(manifest.get("format_version")==2,"current product candidate format required")
    archive=directory/manifest["archive"]["file"]
    require(archive.parent==directory and not archive.is_symlink() and sha(archive)==manifest["archive"]["sha256"],"candidate archive mismatch")
    digest,config=oci_identity(archive)
    require(digest==manifest["archive"]["manifest_digest"] and config["config"]["Labels"]["org.opencontainers.image.revision"]==manifest["revision"] and platform(config)==manifest["platform"],"candidate image mismatch")
    verify_source(manifest["revision"])
    require(sha(directory/"mdm-config.example.json")==manifest["config_sha256"],"candidate configuration mismatch")
    require(sha(ROOT/"Cargo.lock")==manifest["cargo_lock_sha256"],"candidate lock mismatch")
    docker("load","--input",archive,stage=Stage.LOAD)
    return manifest

class Candidate:
    """One owned PG/network namespace, product binary and canonical UI ingress."""
    def __init__(self, directory, *, prepare=None, network=None, host="mdm.example.test", instance=INSTANCE, tenant=TENANT, diagnostics=None, diagnostic_filename=None):
        self.directory,self.prepare,self.host=directory,prepare,host
        self.instance,self.tenant=instance,tenant
        self.diagnostics=diagnostics or directory
        self.manifest=verify_candidate(directory)
        artifact=image_identity(self.manifest["image"])
        require(artifact["revision"]==self.manifest["revision"] and self.manifest["image"].endswith("@"+self.manifest["archive"]["manifest_digest"]),"runtime image differs from candidate")
        self.image=artifact["id"]
        self.web=load_ui(directory,self.manifest["ui"])
        self.providers=self.manifest["providers"]
        self.name="mdm-candidate-"+uuid.uuid4().hex
        self.diagnostic_filename=diagnostic_filename or self.name+"-failure.json"
        self.pg,self.gateway,self.server=[self.name+suffix for suffix in ("-pg","-gateway","-server")]
        self.network=network or self.name+"-network"
        self.own_network=network is None
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
    def operator(self,verb,config,stage):
        return self.run_once("--network","container:"+self.pg,"-v",self.operator_volume+":/run/mdm:ro",self.image,verb,"--config","/run/mdm/"+config,stage=stage)
    def copy_runtime(self):
        self.run_once("--user","0:0","--network","none","-v",str(self.runtime)+":/fixture:ro","-v",self.runtime_volume+":/run/mdm", "--entrypoint","sh",self.providers["runtime"],"-ec","cp -R /fixture/. /run/mdm/; chown -R 10001:10001 /run/mdm; chmod 700 /run/mdm",stage=Stage.RUNTIME_INPUTS)
    def start_server(self):
        self.created.append(self.server)
        self.command("run","-d","--name",self.server,"--network","container:"+self.pg,"-v",self.runtime_volume+":/run/mdm:ro",self.image,"serve","--config","/run/mdm/config.json",stage=Stage.SERVER)
    def __enter__(self):
        try:
            self.temporary=tempfile.TemporaryDirectory(prefix=self.name+"-")
            self.root=Path(self.temporary.name)
            self.runtime,self.operator_root=inputs(self.root,self.directory/"mdm-config.example.json")
            if self.own_network:
                self.network_created=True
                self.command("network","create",self.network,stage=Stage.NETWORK)
            self.config=json.loads((self.runtime/"config.json").read_text())
            self.config["product_origin"]="https://"+self.host
            self.config["identity"].update(instance_id=self.instance,tenant_id=self.tenant)
            self.config["identity_management"][0].update(instance_id=self.instance,tenant_id=self.tenant)
            self.register_private_files()
            if self.prepare: self.prepare(self)
            self.register_private_files()
            (self.runtime/"config.json").write_text(json.dumps(self.config))
            for file in ["migrate.json","initialize.json"]:
                path=self.operator_root/file
                value=json.loads(path.read_text());value["installation"]["instance_id"]=self.instance
                if self.tenant not in value["installation"]["tenants"]:value["installation"]["tenants"].append(self.tenant)
                if file=="initialize.json":value["tenant_id"]=self.tenant
                path.write_text(json.dumps(value))
            path=self.operator_root/'authorization.json'
            authorization=json.loads(path.read_text());authorization['user'].update(instanceId=self.instance,tenantId=self.tenant)
            authorization['installation']['instance_id']=self.instance
            if self.tenant not in authorization['installation']['tenants']:authorization['installation']['tenants'].append(self.tenant)
            path.write_text(json.dumps(authorization))
            gateway=(self.root/"nginx.conf").read_text().replace("mdm.example.test",self.host)
            (self.root/"nginx.conf").write_text(gateway)
            (self.root/"ui.json").write_text(json.dumps({"canonicalOrigin":"https://"+self.host,"oidcEnabled":self.config["identity"]["oidc"] is not None}))
            self.pg_tls=self.secret_volume("pg-tls",["server.crt","server.key"],999)
            self.created.append(self.pg)
            self.command("run","-d","--name",self.pg,"--network",self.network,"--network-alias",self.host,"-p","127.0.0.1::8445","-v",self.pg_tls+":/certs:ro","-e","POSTGRES_PASSWORD=candidate-fixture","-e","POSTGRES_DB=mdm_test",self.providers["postgres"],"sh","-ec","cp /certs/server.key /tmp/server.key; cp /certs/server.crt /tmp/server.crt; chown postgres:postgres /tmp/server.*; chmod 600 /tmp/server.key; exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key",stage=Stage.POSTGRES)
            wait(lambda:subprocess.run(["docker","exec",self.pg,"pg_isready","-h","127.0.0.1","-U","postgres"],capture_output=True,timeout=5).returncode==0,"PostgreSQL")
            roles="".join("CREATE ROLE "+r+" LOGIN PASSWORD '"+r+"-fixture' NOSUPERUSER NOBYPASSRLS;" for r in ["mdm_owner","mdm_api","mdm_access","mdm_runtime"])
            roles+="GRANT CREATE ON DATABASE mdm_test TO mdm_owner; GRANT CREATE ON SCHEMA public TO mdm_owner;"
            for owner in ["software-publication","management","identity","commands"]:roles+=(ROOT/f"crates/app/schema/{owner}-roles.sql").read_text()
            for role in ["mdm_command_runtime","mdm_management_runtime","mdm_software_driver","mdm_identity_runtime","mdm_identity_maintenance"]:roles+="ALTER ROLE "+role+" LOGIN PASSWORD '"+role+"-fixture';"
            self.sql(roles)
            self.runtime_volume,self.operator_volume=self.name+"-runtime",self.name+"-operator"
            for volume,directory,volume_stage,input_stage in [(self.runtime_volume,self.runtime,Stage.RUNTIME_VOLUME,Stage.RUNTIME_INPUTS),(self.operator_volume,self.operator_root,Stage.OPERATOR_VOLUME,Stage.OPERATOR_INPUTS)]:
                self.volumes.append(volume);self.command("volume","create",volume,stage=volume_stage)
                self.run_once("--user","0:0","--network","none","-v",str(directory)+":/fixture:ro","-v",volume+":/run/mdm","--entrypoint","sh",self.providers["runtime"],"-ec","cp -R /fixture/. /run/mdm/; chown -R 10001:10001 /run/mdm; chmod 700 /run/mdm",stage=input_stage)
            for stage in [Stage.MIGRATION,Stage.REPLAY]:self.operator("migrate","migrate.json",stage)
            self.operator("initialize","initialize.json",Stage.INITIALIZE)
            self.operator("initialize-authorization","authorization.json",Stage.AUTHORIZATION_INITIALIZE)
            self.operator("initialize-authorization","authorization.json",Stage.AUTHORIZATION_REPLAY)
            self.start_server()
            self.gateway_inputs=self.secret_volume("gateway-inputs",["server.crt","server.key","nginx.conf","ui.json"],10001)
            self.created.append(self.gateway)
            self.command("run","-d","--name",self.gateway,"--network","container:"+self.pg,"-v",self.gateway_inputs+":/certs:ro",self.web["id"],"-c","/certs/nginx.conf",stage=Stage.GATEWAY)
            self.port=int(self.command("port",self.pg,"8445/tcp",stage=Stage.PORT).rsplit(":",1)[1])
            self.ready()
            return self
        except BaseException:
            self.__exit__(*sys.exc_info())
            raise
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
        try:
            records=cleanup(self.created,self.volumes,self.network if self.network_created else None)
            if error:
                if all(r["outcome"]=="removed" for r in records):error.cleanup_records=getattr(error,"cleanup_records",[])+records
                record(error)
        except BaseException as cleanup_error:
            record(cleanup_error)
            if error:
                error.add_note("candidate cleanup failed")
            else:
                raise
        finally:
            if self.temporary:self.temporary.cleanup()
