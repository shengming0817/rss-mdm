#!/usr/bin/env python3
"""Owned product candidate deployment shared by smoke and browser acceptance."""
from enum import StrEnum
import http.client
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import uuid
from release import ROOT, oci_identity, platform, sha
from t2 import INSTANCE, ADMIN, TENANTS, installation

TENANT = TENANTS[0]
PASSWORD = "Candidate-only-correct-horse-battery-2026!"

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

class Stage(StrEnum):
    LOAD = "image-load"
    POSTGRES = "postgres-start"
    SQL = "postgres-sql"
    RUNTIME_VOLUME = "runtime-volume"
    OPERATOR_VOLUME = "operator-volume"
    RUNTIME_INPUTS = "runtime-inputs"
    OPERATOR_INPUTS = "operator-inputs"
    MIGRATION = "migration"
    REPLAY = "migration-replay"
    INITIALIZE = "initialize"
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
    config["windows"]=copy_inputs(windows)
    for field,role in [("database","mdm_api"),("access_database","mdm_access"),("runtime_database","mdm_runtime")]:
        config[field]=database(runtime,role)
    config["identity"]["database"]=database(runtime,"mdm_identity_runtime")
    config["management"]["database"]=database(runtime,"mdm_management_runtime")
    config["management"]["publication_database"]=database(runtime,"mdm_software_driver")
    config["bindings"]=[dict(tenant_id=TENANT,instance_id=INSTANCE,principal_id=ADMIN,roles=["mdm_admin"],devices=["device-1"],
                             management=[],identity_management=["accounts"],allow_wipe=False,allow_enrollment=True,allow_manage_credentials=True)]
    write(runtime,"config.json",config)
    write(operator,"migrate.json",dict(database=database(operator,"mdm_owner"),installation=installation()))
    write(operator,"initialize.json",dict(database=database(operator,"mdm_identity_maintenance"),installation=installation(),tenant_id=TENANT,principal_id=ADMIN,
                                          login="admin",password_file=write(operator,"account-password",PASSWORD)))
    gateway=(ROOT/"deployment/nginx.conf").read_text().replace("listen 443 ssl;","listen 8445 ssl;")
    gateway=gateway.replace("/run/config/ui.json","/certs/ui.json")
    gateway=gateway.replace("/private/mdm-tls.crt","/certs/server.crt").replace("/private/mdm-tls.key","/certs/server.key")
    (root/"nginx.conf").write_text(gateway)
    root.chmod(0o755)
    (root/"server.key").chmod(0o644)  # Disposable fixture key, readable by non-root TLS containers.
    return runtime,operator

def failure_evidence(directory, created, safe_log_sources, primary):
    # Product and ingress logs have closed, credential-free schemas. PostgreSQL
    # statement logs can contain input values, so capture only its closed state.
    diagnostics = {"status":"failed", "error_class":type(primary).__name__, "containers":{}}
    if isinstance(primary, DockerFailure):
        diagnostics.update(stage=primary.stage.value,outcome=primary.outcome,exit_code=primary.exit_code)
    for name in created:
        value = {}
        try:
            value["state"] = docker("inspect", "--format", "{{.State.Status}}:{{.State.ExitCode}}", name, timeout=10,stage=Stage.DIAGNOSTIC_STATE)
            if name in safe_log_sources: value["log"] = docker("logs", "--tail", "200", name, timeout=10,stage=Stage.DIAGNOSTIC_LOGS)
        except Exception:
            value["diagnostic_unavailable"] = True
        diagnostics["containers"][name] = value
    try:
        with tempfile.TemporaryDirectory(prefix=".smoke-failure-", dir=directory) as temporary:
            staged = Path(temporary)/"failure.json"
            staged.write_text(json.dumps(diagnostics,indent=2)+"\n")
            os.replace(staged,directory/"smoke-failure.json")
    except Exception:
        primary.add_note("candidate failure diagnostics could not be persisted")

def cleanup(created, volume):
    primary = sys.exception()
    failures = []
    commands = [("rm", "-f", container) for container in reversed(created)]
    commands.extend(("volume", "rm", name) for name in ([volume] if isinstance(volume,str) else reversed(volume)))
    for command in commands:
        try:
            docker(*command,stage=Stage.REMOVE_CONTAINER if command[0]=="rm" else Stage.REMOVE_VOLUME)
        except Exception as error:
            failures.append(error)
    if failures:
        message = f"candidate cleanup failed ({len(failures)} resources)"
        if primary is not None:
            primary.add_note(message)
        else:
            raise RuntimeError(message) from failures[0]


WEB_REVISION = "21dcaed4fdfb31bd4b545ca8aedabae6b53c2677"

def image_identity(reference):
    value = json.loads(docker("image", "inspect", reference, stage=Stage.LOAD))[0]
    return {"id":value["Id"], "revision":value["Config"].get("Labels",{}).get("org.opencontainers.image.revision"),
            "os":value["Os"], "architecture":value["Architecture"]}

def verify_candidate(directory):
    manifest=json.loads((directory/"candidate.json").read_text())
    archive=directory/manifest["archive"]["file"]
    require(archive.parent==directory and not archive.is_symlink() and sha(archive)==manifest["archive"]["sha256"],"candidate archive mismatch")
    digest,config=oci_identity(archive)
    require(digest==manifest["archive"]["manifest_digest"] and config["config"]["Labels"]["org.opencontainers.image.revision"]==manifest["revision"] and platform(config)==manifest["platform"],"candidate image mismatch")
    revision=subprocess.check_output(["/usr/bin/git","rev-parse","HEAD"],cwd=ROOT,text=True).strip()
    require(revision==manifest["revision"] and not subprocess.check_output(["/usr/bin/git","status","--porcelain"],cwd=ROOT,text=True).strip(),"candidate requires clean matching source")
    require(sha(directory/"mdm-config.example.json")==manifest["config_sha256"],"candidate configuration mismatch")
    require(sha(ROOT/"Cargo.lock")==manifest["cargo_lock_sha256"],"candidate lock mismatch")
    docker("load","--input",archive,stage=Stage.LOAD)
    return manifest

class Candidate:
    """One owned PG/network namespace, product binary and canonical UI ingress."""
    def __init__(self, directory, web_image, *, prepare=None, network=None, host="mdm.example.test", instance=INSTANCE, tenant=TENANT, diagnostics=None):
        self.directory,self.prepare,self.host=directory,prepare,host
        self.instance,self.tenant=instance,tenant
        self.diagnostics=diagnostics or directory
        self.manifest=verify_candidate(directory)
        self.image=image_identity(self.manifest["image"])["id"]
        self.web=image_identity(web_image)
        require(self.web["revision"]==WEB_REVISION,"UI revision mismatch")
        self.providers=self.manifest["providers"]
        self.name="mdm-candidate-"+uuid.uuid4().hex[:10]
        self.pg,self.gateway,self.server=[self.name+suffix for suffix in ("-pg","-gateway","-server")]
        self.network=network or self.name+"-network"
        self.own_network=network is None
        self.created,self.volumes=[],[]
        self.temporary=None
    def command(self,*args,stage=Stage.SERVER,**kwargs):
        return docker(*args,stage=stage,**kwargs)
    def sql(self,statement):
        return self.command("exec","-i",self.pg,"psql","-X","-At","-v","ON_ERROR_STOP=1","-U","postgres","-d","mdm_test",input=statement,timeout=15,stage=Stage.SQL)
    def operator(self,verb,config):
        return self.command("run","--rm","--network","container:"+self.pg,"-v",self.operator_volume+":/run/mdm:ro",self.image,verb,"--config","/run/mdm/"+config,stage=Stage.MIGRATION)
    def copy_runtime(self):
        self.command("run","--rm","--user","0:0","--network","none","-v",str(self.runtime)+":/fixture:ro","-v",self.runtime_volume+":/run/mdm", "--entrypoint","sh",self.providers["runtime"],"-ec","cp -R /fixture/. /run/mdm/; chown -R 10001:10001 /run/mdm; chmod 700 /run/mdm",stage=Stage.RUNTIME_INPUTS)
    def start_server(self):
        self.created.append(self.server)
        self.command("run","-d","--name",self.server,"--network","container:"+self.pg,"-v",self.runtime_volume+":/run/mdm:ro",self.image,"serve","--config","/run/mdm/config.json")
    def __enter__(self):
        try:
            self.temporary=tempfile.TemporaryDirectory(prefix=self.name+"-")
            self.root=Path(self.temporary.name)
            self.runtime,self.operator_root=inputs(self.root,self.directory/"mdm-config.example.json")
            if self.own_network: self.command("network","create",self.network,stage=Stage.POSTGRES)
            self.config=json.loads((self.runtime/"config.json").read_text())
            self.config["product_origin"]="https://"+self.host
            self.config["identity"].update(instance_id=self.instance,tenant_id=self.tenant)
            self.config["bindings"][0].update(instance_id=self.instance,tenant_id=self.tenant)
            if self.prepare: self.prepare(self)
            (self.runtime/"config.json").write_text(json.dumps(self.config))
            for file in ["migrate.json","initialize.json"]:
                path=self.operator_root/file
                value=json.loads(path.read_text());value["installation"]["instance_id"]=self.instance
                if self.tenant not in value["installation"]["tenants"]:value["installation"]["tenants"].append(self.tenant)
                if file=="initialize.json":value["tenant_id"]=self.tenant
                path.write_text(json.dumps(value))
            gateway=(self.root/"nginx.conf").read_text().replace("mdm.example.test",self.host)
            (self.root/"nginx.conf").write_text(gateway)
            (self.root/"ui.json").write_text(json.dumps({"canonicalOrigin":"https://"+self.host,"oidcEnabled":self.config["identity"]["oidc"] is not None}))
            self.created.append(self.pg)
            self.command("run","-d","--name",self.pg,"--network",self.network,"--network-alias",self.host,"-p","127.0.0.1::8445","-v",str(self.root)+":/certs:ro","-e","POSTGRES_PASSWORD=candidate-fixture","-e","POSTGRES_DB=mdm_test",self.providers["postgres"],"sh","-ec","cp /certs/server.key /tmp/server.key; cp /certs/server.crt /tmp/server.crt; chown postgres:postgres /tmp/server.*; chmod 600 /tmp/server.key; exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key",stage=Stage.POSTGRES)
            wait(lambda:subprocess.run(["docker","exec",self.pg,"pg_isready","-h","127.0.0.1","-U","postgres"],capture_output=True,timeout=5).returncode==0,"PostgreSQL")
            roles="".join("CREATE ROLE "+r+" LOGIN PASSWORD '"+r+"-fixture' NOSUPERUSER NOBYPASSRLS;" for r in ["mdm_owner","mdm_api","mdm_access","mdm_runtime"])
            roles+="GRANT CREATE ON DATABASE mdm_test TO mdm_owner; GRANT CREATE ON SCHEMA public TO mdm_owner;"
            for owner in ["software-publication","management","identity"]:roles+=(ROOT/f"crates/app/schema/{owner}-roles.sql").read_text()
            for role in ["mdm_management_runtime","mdm_software_driver","mdm_identity_runtime","mdm_identity_maintenance"]:roles+="ALTER ROLE "+role+" LOGIN PASSWORD '"+role+"-fixture';"
            self.sql(roles)
            self.runtime_volume,self.operator_volume=self.name+"-runtime",self.name+"-operator"
            for volume,directory in [(self.runtime_volume,self.runtime),(self.operator_volume,self.operator_root)]:
                self.command("volume","create",volume,stage=Stage.RUNTIME_VOLUME);self.volumes.append(volume)
                self.command("run","--rm","--user","0:0","--network","none","-v",str(directory)+":/fixture:ro","-v",volume+":/run/mdm","--entrypoint","sh",self.providers["runtime"],"-ec","cp -R /fixture/. /run/mdm/; chown -R 10001:10001 /run/mdm; chmod 700 /run/mdm",stage=Stage.RUNTIME_INPUTS)
            for _ in range(2):self.operator("migrate","migrate.json")
            self.operator("initialize","initialize.json")
            self.start_server()
            self.created.append(self.gateway)
            self.command("run","-d","--name",self.gateway,"--network","container:"+self.pg,"-v",str(self.root)+":/certs:ro",self.web["id"],"-c","/certs/nginx.conf",stage=Stage.GATEWAY)
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
        if error:failure_evidence(self.diagnostics,self.created,{self.server,self.gateway},error)
        try:
            cleanup(self.created,self.volumes)
        finally:
            try:
                if self.own_network:self.command("network","rm",self.network,stage=Stage.REMOVE_CONTAINER)
            finally:
                if self.temporary:self.temporary.cleanup()
