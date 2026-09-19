#!/usr/bin/env python3
"""Run the fixed MDM OCI with only its own PostgreSQL and HTTPS ingress."""
import argparse
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

class Browser:
    def __init__(self, port, ca):
        self.port, self.context = port, ssl.create_default_context(cafile=ca)
        self.cookie, self.csrf = "", ""
    def call(self, method, path, data=None, operation=None):
        headers = {"Host":"mdm.example.test", "Origin":"https://mdm.example.test", "X-Identity-Request":"1"}
        if self.cookie: headers["Cookie"] = self.cookie
        if self.csrf: headers["X-CSRF-Token"] = self.csrf
        if operation: headers["Idempotency-Key"] = operation
        if data is not None: headers["Content-Type"] = "application/json"
        connection = http.client.HTTPSConnection("127.0.0.1", self.port, context=self.context, timeout=15)
        try:
            connection.request(method, path, body=json.dumps(data) if data is not None else None, headers=headers)
            response = connection.getresponse()
            body = response.read()
            for key, value in response.getheaders():
                if key.lower() == "set-cookie":
                    require("Secure" in value and "HttpOnly" in value and "Path=/" in value and "Domain=" not in value,
                            "candidate cookie protections missing")
                    self.cookie = value.split(";",1)[0]
            value = json.loads(body) if body and response.getheader("Content-Type", "").startswith("application/json") else None
            if isinstance(value,dict) and "csrfToken" in value: self.csrf = value["csrfToken"]
            return response.status, value
        finally:
            connection.close()

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
    (root/"extensions").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,DNS:mdm.example.test,IP:127.0.0.1\n")
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
    gateway=gateway.replace("/private/mdm-tls.crt","/certs/server.crt").replace("/private/mdm-tls.key","/certs/server.key")
    (root/"nginx.conf").write_text(gateway)
    return runtime,operator

def run_smoke(directory):
    manifest=json.loads((directory/"candidate.json").read_text())
    archive=directory/manifest["archive"]["file"]
    require(archive.parent==directory and not archive.is_symlink() and sha(archive)==manifest["archive"]["sha256"],"candidate archive mismatch")
    digest,config=oci_identity(archive)
    require(digest==manifest["archive"]["manifest_digest"] and config["config"]["Labels"]["org.opencontainers.image.revision"]==manifest["revision"] and platform(config)==manifest["platform"],"candidate image mismatch")
    revision=subprocess.check_output(["/usr/bin/git","rev-parse","HEAD"],cwd=ROOT,text=True).strip()
    require(revision==manifest["revision"] and not subprocess.check_output(["/usr/bin/git","status","--porcelain"],cwd=ROOT,text=True).strip(),"smoke requires clean candidate source")
    example=directory/"mdm-config.example.json"
    require(sha(example)==manifest["config_sha256"],"candidate configuration mismatch")
    docker("load","--input",archive,stage=Stage.LOAD)
    image,providers=manifest["image"],manifest["providers"]
    name="mdm-candidate-"+uuid.uuid4().hex[:10]
    pg,gateway,server=name+"-pg",name+"-gateway",name+"-server"
    runtime_volume,operator_volume=name+"-runtime",name+"-operator"
    created,volumes=[],[]
    with tempfile.TemporaryDirectory(prefix=name+"-") as temporary:
        root=Path(temporary)
        runtime,operator=inputs(root,example)
        try:
            # One owned network namespace. PG and MDM both bind locally, ingress supplies the peer header.
            created.append(pg)
            docker("run","-d","--name",pg,"-p","127.0.0.1::8445","-v",str(root)+":/certs:ro",
                   "-e","POSTGRES_PASSWORD=candidate-fixture","-e","POSTGRES_DB=mdm_test",providers["postgres"],"sh","-ec",
                   "cp /certs/server.key /tmp/server.key; cp /certs/server.crt /tmp/server.crt; chown postgres:postgres /tmp/server.*; chmod 600 /tmp/server.key; exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key",stage=Stage.POSTGRES)
            wait(lambda: subprocess.run(["docker","exec",pg,"pg_isready","-h","127.0.0.1","-U","postgres"],capture_output=True,timeout=5).returncode==0,"PostgreSQL")
            def sql(statement):
                return docker("exec","-i",pg,"psql","-X","-At","-v","ON_ERROR_STOP=1","-U","postgres","-d","mdm_test",input=statement,timeout=15,stage=Stage.SQL)
            roles="".join("CREATE ROLE "+role+" LOGIN PASSWORD '"+role+"-fixture' NOSUPERUSER NOBYPASSRLS;" for role in ["mdm_owner","mdm_api","mdm_access","mdm_runtime"])
            roles+="GRANT CREATE ON DATABASE mdm_test TO mdm_owner; GRANT CREATE ON SCHEMA public TO mdm_owner;"
            for owner in ["software-publication","management","identity"]: roles+=(ROOT/f"crates/app/schema/{owner}-roles.sql").read_text()
            for role in ["mdm_management_runtime","mdm_software_driver","mdm_identity_runtime","mdm_identity_maintenance"]:
                roles+="ALTER ROLE "+role+" LOGIN PASSWORD '"+role+"-fixture';"
            sql(roles)
            for volume,directory_input,volume_stage,input_stage in [(runtime_volume,runtime,Stage.RUNTIME_VOLUME,Stage.RUNTIME_INPUTS),(operator_volume,operator,Stage.OPERATOR_VOLUME,Stage.OPERATOR_INPUTS)]:
                docker("volume","create",volume,stage=volume_stage);volumes.append(volume)
                docker("run","--rm","--user","0:0","--network","none","-v",str(directory_input)+":/fixture:ro","-v",volume+":/run/mdm",
                       "--entrypoint","sh",providers["runtime"],"-ec","cp -R /fixture/. /run/mdm/; chown -R 10001:10001 /run/mdm; chmod 700 /run/mdm",stage=input_stage)
            network=["--network","container:"+pg]
            operator_mount=["-v",operator_volume+":/run/mdm:ro"]
            for stage in [Stage.MIGRATION,Stage.REPLAY]: docker("run","--rm",*network,*operator_mount,image,"migrate","--config","/run/mdm/migrate.json",stage=stage)
            docker("run","--rm",*network,*operator_mount,image,"initialize","--config","/run/mdm/initialize.json",stage=Stage.INITIALIZE)
            created.append(gateway)
            docker("run","-d","--name",gateway,*network,"-v",str(root)+":/certs:ro",providers["nginx"],"nginx","-e","stderr","-c","/certs/nginx.conf","-g","daemon off;",stage=Stage.GATEWAY)
            created.append(server)
            docker("run","-d","--name",server,*network,"-v",runtime_volume+":/run/mdm:ro",image,"serve","--config","/run/mdm/config.json",stage=Stage.SERVER)
            port=int(docker("port",pg,"8445/tcp",stage=Stage.PORT).rsplit(":",1)[1])
            browser=Browser(port,root/"ca.crt")
            wait(lambda: browser.call("GET","/livez")== (200,{"alive":True}),"liveness")
            wait(lambda: browser.call("GET","/readyz")== (200,{"ready":True}),"readiness")
            tenant="/api/v2/tenants/"+TENANT
            require(browser.call("GET","/api/v1/authorization")[0]==401,"anonymous candidate accepted")
            require(browser.call("POST",tenant+"/login",dict(login="admin",password=PASSWORD))[0]==200,"local candidate login failed")
            status,principal=browser.call("GET","/api/v1/authorization")
            require(status==200 and (principal["instance_id"],principal["tenant_id"],principal["principal_id"])==(INSTANCE,TENANT,ADMIN),"candidate subject mismatch")
            operation=str(uuid.uuid4())
            enrollment=dict(deviceId="device-1",password="A"*43)
            status,receipt=browser.call("POST","/api/v1/enrollments",enrollment,operation)
            require(status==200 and receipt["status"]=="pending","candidate enrollment failed")
            require(browser.call("POST","/api/v1/enrollments",enrollment,operation)==(status,receipt),"candidate replay changed enrollment")
            require(browser.call("GET","/api/v1/enrollments/"+receipt["enrollmentId"])[1]["status"]=="pending","candidate enrollment query failed")
            denied=str(uuid.uuid4())
            require(browser.call("POST","/api/v1/enrollments",dict(deviceId="outside",password="A"*43),denied)[0]==403,"device scope bypass")
            require(sql("SELECT count(*) FROM mdm_access.grants WHERE device='outside'")=="0","denied enrollment wrote business state")
            require(sql("SELECT count(*) FROM mdm_access.audit WHERE operation_id='"+denied+"' AND result='denied'")=="1","candidate denial audit missing")
            require(browser.call("POST","/api/v1/devices/device-1/actions",dict(action="wipe"),str(uuid.uuid4()))[0]==403,"wipe permission bypass")
            require(browser.call("GET","/api/v1/devices/outside/inventory?source=mdm.windows")[0]==403,"inventory scope bypass")
            old_cookie=browser.cookie
            require(browser.call("POST",tenant+"/session/refresh")[0]==200 and browser.cookie!=old_cookie,"candidate refresh failed")
            stale=Browser(port,root/"ca.crt");stale.cookie=old_cookie
            require(stale.call("GET","/api/v1/authorization")[0]==401,"rotated credential accepted")
            require(browser.call("POST",tenant+"/session/logout")[0]==204,"candidate logout failed")
            require(browser.call("GET","/api/v1/authorization")[0]==401,"logged-out candidate accepted")
            started=time.monotonic();docker("stop","--time","45",server,timeout=55,stage=Stage.STOP)
            elapsed=time.monotonic()-started
            logs=docker("logs",server,stage=Stage.LOGS)
            require("mdm_request" in logs, "candidate request diagnostics missing")
            require(elapsed<45 and docker("inspect","--format","{{.State.ExitCode}}",server,stage=Stage.EXIT)=="0" and "mdm_shutdown_failure" not in logs,"candidate bounded shutdown failed")
            result=dict(revision=revision,manifest_digest=digest,archive_sha256=sha(archive),platform=manifest["platform"],dependencies=manifest["dependencies"],
                        checks=["migrate","migration_replay","initialize","livez","readyz","local_login","authoritative_subject","enrollment","idempotent_replay","device_scope_denial","denial_no_effect","denial_audit","wipe_denial","inventory_scope_denial","refresh_rotation","logout","bounded_stop"],
                        shutdown_seconds=round(elapsed,3),limits=["disposable MDM PostgreSQL and TLS namespace","no real Windows or macOS device T3"])
        except BaseException as error:
            failure_evidence(directory, created, {server,gateway}, error)
            raise
        finally:
            try:
                cleanup(created,volumes)
            except BaseException as error:
                failure_evidence(directory, created, {server,gateway}, error)
                raise
    return result,logs+"\n"

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

def smoke(directory):
    marker, log = directory / "smoke.json", directory / "smoke.log"
    for path in (marker, log, directory / "smoke-failure.json"):
        path.unlink(missing_ok=True)
    try:
        result, output = run_smoke(directory)
        # Publish only after both fixture owners have finished cleanup. The marker
        # is last and binds the log, so readers never accept a partial evidence pair.
        with tempfile.TemporaryDirectory(prefix=".smoke-", dir=directory) as temporary:
            staged_log, staged_marker = Path(temporary) / "log", Path(temporary) / "marker"
            staged_log.write_text(output)
            result["log_sha256"] = sha(staged_log)
            staged_marker.write_text(json.dumps(result, indent=2) + "\n")
            os.replace(staged_log, log)
            os.replace(staged_marker, marker)
    except BaseException:
        marker.unlink(missing_ok=True)
        log.unlink(missing_ok=True)
        raise
    print("candidate smoke: " + str(directory / "smoke.json"))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    smoke(parser.parse_args().candidate.resolve())
