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

from candidate_runtime import Candidate, Stage, docker, require, wait, verify_source

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

def run_smoke(directory):
    with Candidate(directory, diagnostic_filename="smoke-failure.json") as deployed:
        manifest=deployed.manifest
        revision=manifest["revision"];digest=manifest["archive"]["manifest_digest"];archive=directory/manifest["archive"]["file"]
        pg,gateway,server=deployed.pg,deployed.gateway,deployed.server
        sql=deployed.sql
        browser=Browser(deployed.port,deployed.root/"ca.crt")
        tenant="/api/v2/tenants/"+TENANT
        require(browser.call("GET","/api/v1/authorization")[0]==401,"anonymous candidate accepted")
        require(browser.call("POST",tenant+"/login",dict(login="admin",password=PASSWORD))[0]==200,"local candidate login failed")
        status,principal=browser.call("GET","/api/v1/authorization")
        require(status==200 and (principal["instanceId"],principal["tenantId"],principal["principalId"])==(INSTANCE,TENANT,ADMIN),"candidate subject mismatch")
        rule=dict(subject=dict(kind='user',user=dict(instanceId=INSTANCE,tenantId=TENANT,principalId=ADMIN)),grants=[dict(operation=operation,scope=dict(kind='device',id='device-1')) for operation in ['inventory_read','enrollment','credentials']])
        require(browser.call('PUT','/api/v1/authorization/rules/'+str(uuid.uuid4()),dict(operationId=str(uuid.uuid4()),expectedRevision=0,value=rule))[0]==200,'candidate explicit authorization')
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
        stale=Browser(deployed.port,deployed.root/"ca.crt");stale.cookie=old_cookie
        require(stale.call("GET","/api/v1/authorization")[0]==401,"rotated credential accepted")
        require(browser.call("POST",tenant+"/session/logout")[0]==204,"candidate logout failed")
        require(browser.call("GET","/api/v1/authorization")[0]==401,"logged-out candidate accepted")
        started=time.monotonic();docker("stop","--time","45",server,timeout=55,stage=Stage.STOP)
        elapsed=time.monotonic()-started
        logs=docker("logs",server,stage=Stage.LOGS)
        require("mdm_request" in logs, "candidate request diagnostics missing")
        require(elapsed<45 and docker("inspect","--format","{{.State.ExitCode}}",server,stage=Stage.EXIT)=="0" and "mdm_shutdown_failure" not in logs,"candidate bounded shutdown failed")
        result=dict(revision=revision,candidate_sha256=sha(directory/"candidate.json"),ui=deployed.web,manifest_digest=digest,archive_sha256=sha(archive),platform=manifest["platform"],dependencies=manifest["dependencies"],
                    checks=["migrate","migration_replay","initialize","livez","readyz","local_login","authoritative_subject","enrollment","idempotent_replay","device_scope_denial","denial_no_effect","denial_audit","wipe_denial","inventory_scope_denial","refresh_rotation","logout","bounded_stop"],
                    shutdown_seconds=round(elapsed,3),limits=["disposable MDM PostgreSQL and TLS namespace","no real Windows or macOS device T3"])
    verify_source(revision)
    return result,logs+"\n"

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
    args=parser.parse_args()
    smoke(args.candidate.resolve())
