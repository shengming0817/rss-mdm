#!/usr/bin/env python3
"""Own one disposable TLS PostgreSQL server. Missing Docker/PG is a failure."""
import sys
if sys.version_info < (3, 11):
    raise SystemExit("Python >= 3.11 is required for local CI")

import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

IMAGE = "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777"
ROOT = Path(__file__).resolve().parents[1]

def run(args, **kw):
    return subprocess.run(args, check=True, text=True, **kw)

def main():
    build = run(["cargo", "build", "--locked", "-p", "rss-mdm-examples", "--bin", "rss-mdm-fixture", "--message-format=json"], cwd=ROOT, capture_output=True)
    executables = [item["executable"] for line in build.stdout.splitlines() if (item := json.loads(line)).get("reason") == "compiler-artifact" and item.get("executable") and item["target"]["name"] == "rss-mdm-fixture"]
    if len(executables) != 1: raise RuntimeError("cannot locate the tested fixture executable")
    product = run(["cargo", "build", "--locked", "-p", "rss-mdm-app", "--bin", "rss-mdm", "--message-format=json"], cwd=ROOT, capture_output=True)
    migrators = [item["executable"] for line in product.stdout.splitlines() if (item := json.loads(line)).get("reason") == "compiler-artifact" and item.get("executable") and item["target"]["name"] == "rss-mdm"]
    if len(migrators) != 1: raise RuntimeError("cannot locate product migrator")
    name = "mdm-t2-" + uuid.uuid4().hex[:12]
    with tempfile.TemporaryDirectory(prefix="mdm-pg-") as directory:
        root = Path(directory)
        quiet = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL, "timeout": 20}
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=MDM T2 CA", "-keyout", str(root / "ca.key"), "-out", str(root / "ca.crt")], **quiet)
        run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost", "-keyout", str(root / "server.key"), "-out", str(root / "server.csr")], **quiet)
        (root / "extensions").write_text("basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n")
        run(["openssl", "x509", "-req", "-in", str(root / "server.csr"), "-CA", str(root / "ca.crt"), "-CAkey", str(root / "ca.key"), "-CAcreateserial", "-days", "1", "-extfile", str(root / "extensions"), "-out", str(root / "server.crt")], **quiet)
        os.chmod(root / "server.key", 0o644)  # disposable fixture key; copied/chmod 0600 in container
        try:
            run(["docker", "run", "-d", "--rm", "--name", name, "-p", "127.0.0.1::5432", "-v", f"{root}:/certs:ro", "-e", "POSTGRES_PASSWORD=local-fixture", "-e", "POSTGRES_DB=mdm_test", IMAGE, "sh", "-c", "cp /certs/server.key /tmp/server.key; cp /certs/server.crt /tmp/server.crt; chown postgres:postgres /tmp/server.*; chmod 600 /tmp/server.key; exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key"], stdout=subprocess.DEVNULL, timeout=120)
            end = time.monotonic() + 45
            while True:
                ready = subprocess.run(["docker", "exec", name, "pg_isready", "-U", "postgres", "-d", "mdm_test"], capture_output=True, timeout=5)
                if ready.returncode == 0:
                    # pg_isready can see initdb's temporary socket server. Require host TCP below.
                    port = run(["docker", "port", name, "5432"], capture_output=True, timeout=5).stdout.strip().rsplit(":", 1)[1]
                    probe = subprocess.run(["docker", "exec", name, "pg_isready", "-h", "127.0.0.1", "-U", "postgres", "-d", "mdm_test"], capture_output=True, timeout=5)
                    if probe.returncode == 0: break
                if time.monotonic() > end: raise RuntimeError("PostgreSQL startup deadline")
                time.sleep(0.2)
            sql = "CREATE ROLE mdm_owner LOGIN PASSWORD 'owner-fixture' NOSUPERUSER NOBYPASSRLS; CREATE ROLE mdm_runtime LOGIN PASSWORD 'runtime-fixture' NOSUPERUSER NOBYPASSRLS; CREATE ROLE mdm_api LOGIN PASSWORD 'api-fixture' NOSUPERUSER NOBYPASSRLS; GRANT CREATE ON DATABASE mdm_test TO mdm_owner; GRANT CREATE ON SCHEMA public TO mdm_owner;"
            run(["docker", "exec", "-i", name, "psql", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "mdm_test"], input=sql, stdout=subprocess.DEVNULL, timeout=15)
            env = os.environ.copy()
            env.update(MDM_FIXTURE_BIN=executables[0], PG_CA_FILE=str(root / "ca.crt"), DATABASE_URL=f"postgres://mdm_runtime:runtime-fixture@localhost:{port}/mdm_test", MDM_OWNER_URL=f"postgres://mdm_owner:owner-fixture@localhost:{port}/mdm_test", MDM_ADMIN_URL=f"postgres://postgres:local-fixture@localhost:{port}/mdm_test")
            (root / "owner-password").write_text("owner-fixture")
            os.chmod(root / "owner-password", 0o600)
            migration_config = root / "migrate.json"
            migration_config.write_text(json.dumps({"database":{"host":"localhost","port":int(port),"name":"mdm_test","user":"mdm_owner","password_file":str(root/"owner-password"),"ca_file":str(root/"ca.crt")}}))
            os.chmod(migration_config, 0o600)
            for _ in range(2): run([migrators[0],"migrate","--config",str(migration_config)],cwd=ROOT,env=env)
            print(json.dumps({"provider": IMAGE, "tls": "verify-full", "runtime": "NOSUPERUSER NOBYPASSRLS"}), flush=True)
            run(["cargo", "test", "--locked", "-p", "inventory-postgres-integration", "--features", "integration", "--test", "t2", *sys.argv[1:]], cwd=ROOT, env=env)
            run(["cargo","test","--locked","-p","rss-mdm-app","--test","postgres","--","--ignored"],cwd=ROOT,env=env)
        finally:
            primary = sys.exception()
            try:
                result = subprocess.run(["docker", "rm", "-f", name], capture_output=True, text=True, timeout=20)
                if result.returncode:
                    raise RuntimeError("disposable PostgreSQL container cleanup failed")
            except Exception as cleanup:
                if primary is None:
                    raise
                primary.add_note(str(cleanup))

if __name__ == "__main__": main()
