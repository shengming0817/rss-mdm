#!/usr/bin/env python3
"""Consume the fixed MDM OCI with the approved Identity candidate and real PostgreSQL."""
import argparse
import http.client
import json
import os
from pathlib import Path
import subprocess
from urllib.parse import urlsplit
import uuid
import identity_t2 as identity
from release import ROOT, oci_identity, sha

def health(port, path):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        connection.request("GET", path, headers={"Host": "mdm.example.test"})
        response = connection.getresponse()
        body = response.read()
        if response.status != 200:
            raise RuntimeError("candidate health status " + str(response.status))
        return json.loads(body)
    finally:
        connection.close()

def smoke(directory):
    manifest = json.loads((directory / "candidate.json").read_text())
    archive = directory / manifest["archive"]["file"]
    if archive.parent != directory or archive.is_symlink() or sha(archive) != manifest["archive"]["sha256"]:
        raise ValueError("candidate archive mismatch")
    digest, config = oci_identity(archive)
    if digest != manifest["archive"]["manifest_digest"] or config["config"]["Labels"]["org.opencontainers.image.revision"] != manifest["revision"]:
        raise ValueError("candidate image mismatch")
    revision = subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if revision != manifest["revision"] or subprocess.check_output(["/usr/bin/git", "status", "--porcelain"], cwd=ROOT, text=True).strip():
        raise ValueError("smoke source must equal the clean candidate revision")
    identity.docker("load", "--input", str(archive))
    approved = identity.candidate()
    image = manifest["image"]
    with identity.fixture(approved) as environment:
        fixture = Path(environment["MDM_TEST_CONFIG"]).parent
        original = json.loads(Path(environment["MDM_TEST_CONFIG"]).read_text())
        # A test namespace forwards the fixture's localhost endpoints without terminating TLS.
        # Production keeps the configured loopback browser boundary and direct protocol TLS.
        ports = {original["database"]["port"], urlsplit(original["identity"]["origin"]).port,
                 urlsplit(original["identity"]["issuer"]).port}
        settings = json.loads(json.dumps(original).replace(str(fixture), "/run/mdm"))
        settings["listen"] = "127.0.0.1:18080"
        settings["windows"]["enrollment"].update(listen="127.0.0.1:18443", origin="https://localhost:18443")
        settings["windows"]["management"].update(listen="127.0.0.1:18444", origin="https://localhost:18444")
        settings["bindings"] = [{"tenant_id": identity.TENANT, "client_id": "mdm", "subject": identity.ADMIN,
                                 "roles": ["mdm_admin"], "devices": ["device-1"], "allow_wipe": False,
                                 "allow_enrollment": False, "allow_manage_credentials": False}]
        migration = {"database": {**settings["database"], "user": "mdm_owner", "password_file": "/run/mdm/mdm-owner"}}
        for name, value in [("candidate-config.json", settings), ("candidate-migrate.json", migration)]:
            path = fixture / name
            path.write_text(json.dumps(value))
            path.chmod(0o600)
        proxy = "pid /tmp/nginx.pid; error_log stderr crit; events {} stream { "
        proxy += " ".join("server { listen 127.0.0.1:" + str(port) + "; proxy_pass host.docker.internal:" + str(port) + "; }" for port in sorted(ports))
        proxy += " } http { access_log off; client_body_temp_path /tmp/client; proxy_temp_path /tmp/proxy; fastcgi_temp_path /tmp/fastcgi; uwsgi_temp_path /tmp/uwsgi; scgi_temp_path /tmp/scgi; server { listen 18081; location / { proxy_pass http://127.0.0.1:18080; proxy_set_header Host mdm.example.test; proxy_http_version 1.1; } } }"
        (fixture / "candidate-proxy.conf").write_text(proxy)
        (fixture / "candidate-proxy.conf").chmod(0o644)
        name = "mdm-candidate-" + uuid.uuid4().hex[:10]
        volume, proxy_name, server = name + "-inputs", name + "-proxy", name + "-server"
        created = []
        try:
            identity.docker("volume", "create", volume)
            # Operator preparation owns secret file permissions; the tested executable runs as 10001.
            identity.docker("run", "--rm", "--user", "0:0", "--network", "none", "-v", str(fixture) + ":/fixture:ro",
                            "-v", volume + ":/run/mdm", "--entrypoint", "sh", manifest["providers"]["runtime"], "-ec",
                            "cp -R /fixture/. /run/mdm/; chown -R 10001:10001 /run/mdm; chmod 700 /run/mdm")
            created.append(proxy_name)
            identity.docker("run", "-d", "--name", proxy_name, "--platform", "linux/amd64",
                            "--add-host", "host.docker.internal:host-gateway", "-p", "127.0.0.1::18081",
                            "-v", volume + ":/run/mdm:ro", "--entrypoint", "nginx", approved["images"]["gateway"],
                            "-e", "stderr", "-c", "/run/mdm/candidate-proxy.conf", "-g", "daemon off;")
            port = int(identity.docker("port", proxy_name, "18081/tcp").rsplit(":", 1)[1])
            common = ["--platform", "linux/arm64", "--network", "container:" + proxy_name, "-v", volume + ":/run/mdm:ro"]
            for _ in range(2):
                identity.docker("run", "--rm", *common, image, "migrate", "--config", "/run/mdm/candidate-migrate.json", stage="candidate migration")
            created.append(server)
            identity.docker("run", "-d", "--name", server, *common, image, "serve", "--config", "/run/mdm/candidate-config.json")
            identity.wait(lambda: health(port, "/livez") == {"alive": True}, "candidate liveness", seconds=30)
            identity.wait(lambda: health(port, "/readyz") == {"ready": True}, "candidate readiness", seconds=30)
            output = identity.run(["cargo", "test", "--locked", "-p", "rss-mdm-app", "--lib",
                                   "identity_t2::immutable_candidate_inventory_query", "--", "--ignored", "--nocapture"],
                                  cwd=ROOT, env={**environment, "MDM_CANDIDATE_HTTP_ORIGIN": "http://127.0.0.1:" + str(port)},
                                  test_output=True, stage="candidate authenticated query")
            if "test result: ok. 1 passed; 0 failed; 0 ignored;" not in output:
                raise RuntimeError("candidate query test did not execute")
            identity.docker("stop", "--time", "45", server, timeout=55)
            exit_code = identity.docker("inspect", "--format", "{{.State.ExitCode}}", server)
            logs = identity.docker("logs", server)
            if exit_code != "0" or "mdm_shutdown_failure" in logs:
                raise RuntimeError("candidate shutdown failed")
            result = {"revision": revision, "manifest_digest": digest, "archive_sha256": sha(archive),
                      "identity_revision": approved["revision"], "platform": "linux/arm64",
                      "checks": ["migrate", "migration_replay", "serve", "livez", "readyz", "online_identity",
                                 "inventory_unavailable", "inventory_last_known", "source_contract",
                                 "resource_permission", "collection_query", "graceful_stop"],
                      "limits": ["synthetic stored inventory", "test namespace TCP forwarding", "no Windows device T3"]}
            (directory / "smoke.json").write_text(json.dumps(result, indent=2) + "\n")
            (directory / "smoke.log").write_text(output + "\n" + logs + "\n")
        finally:
            for container in reversed(created):
                identity.docker("rm", "-f", container)
            identity.docker("volume", "rm", volume)
    print("candidate smoke: " + str(directory / "smoke.json"))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    smoke(parser.parse_args().candidate.resolve())
