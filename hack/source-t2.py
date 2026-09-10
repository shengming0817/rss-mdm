#!/usr/bin/env python3
"""Real local HTTPS/Git seams; ephemeral CA and a reviewed non-loopback address."""
import os
import ipaddress
import json
import re
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

def local_address():
    if os.environ.get("SOURCE_T2_ADDRESS"):
        candidates = [os.environ["SOURCE_T2_ADDRESS"]]
    elif sys.platform == "darwin":
        interfaces = subprocess.check_output(["/sbin/ifconfig"], text=True)
        candidates = re.findall(r"\binet (\d+\.\d+\.\d+\.\d+)", interfaces)
    else:
        interfaces = json.loads(subprocess.check_output(["ip", "-j", "-4", "address", "show"], text=True))
        candidates = [entry["local"] for interface in interfaces for entry in interface["addr_info"]]
    for address in candidates:
        ip = ipaddress.ip_address(address)
        if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
            continue
        # Bind before probing so no request is sent to an unrelated remote endpoint.
        try:
            with socket.socket() as listener:
                listener.bind((address, 0))
                listener.listen(1)
                listener.settimeout(0.25)
                with socket.create_connection(listener.getsockname(), timeout=0.25):
                    with listener.accept()[0]:
                        return address
        except OSError:
            continue
    raise RuntimeError("no reachable non-loopback local IPv4 address; set SOURCE_T2_ADDRESS")

def tls_environment(root):
    address = local_address()
    (root / "ca.cnf").write_text("[req]\ndistinguished_name=dn\nx509_extensions=ca\nprompt=no\n[dn]\nCN=Source T2 CA\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n")
    (root / "server.cnf").write_text("[req]\ndistinguished_name=dn\nreq_extensions=server\nprompt=no\n[dn]\nCN=source.invalid\n[server]\nsubjectAltName=DNS:source.invalid\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
    for args in [
        ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-keyout", "ca.key", "-out", "ca.pem", "-config", "ca.cnf"],
        ["req", "-newkey", "rsa:2048", "-nodes", "-keyout", "server.key", "-out", "server.csr", "-config", "server.cnf"],
        ["x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-days", "1", "-out", "server.pem", "-extfile", "server.cnf", "-extensions", "server"],
    ]:
        subprocess.run(["openssl", *args], cwd=root, check=True, capture_output=True)
    return dict(os.environ, SOURCE_T2_TLS=str(root), SOURCE_T2_ADDRESS=address)

def main():
    failed = []
    with tempfile.TemporaryDirectory(prefix="mdm-source-tls-") as directory:
        try:
            env = tls_environment(Path(directory))
            result = subprocess.run(["cargo", "test", "--locked", "-p", "rss-mdm-winget-source", "--test", "t2_http", "--", "--ignored"], cwd=ROOT, env=env)
            if result.returncode:
                failed.append("t2_http")
        except Exception as error:
            print(f"HTTPS fixture setup failed: {error}", file=sys.stderr)
            failed.append("t2_http")
        for target in [["--test", "t2_git"], ["--lib"]]:
            result = subprocess.run(["cargo", "test", "--locked", "-p", "rss-mdm-brew-source", *target, "--", "--ignored"], cwd=ROOT)
            if result.returncode:
                failed.append("brew " + " ".join(target))
    if failed:
        print("Failed source T2 targets: " + ", ".join(failed), file=sys.stderr)
    return int(bool(failed))

if __name__ == "__main__":
    sys.exit(main())
