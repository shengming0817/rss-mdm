"""Disposable cryptographic inputs for Windows T2. No private material enters Git."""
import json
import os
from pathlib import Path
import secrets
from t2_processes import subprocess

def generate(root, tls_certificate, tls_key):
    root = Path(root)
    def openssl(*args):
        subprocess.run(["openssl", *map(str, args)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "180",
            "-subj", "/CN=RSS Windows T2 CA", "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", root/"device-ca.key", "-out", root/"device-ca.pem")
    # A short-lived issuer puts real TLS client certificates in the renewal window now.
    openssl("req", "-x509", "-key", root/"device-ca.key", "-sha256", "-days", "6",
            "-subj", "/CN=RSS Windows T2 CA", "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", root/"renewal-ca.pem")
    openssl("pkcs8", "-topk8", "-nocrypt", "-in", root/"device-ca.key", "-outform", "DER", "-out", root/"device-ca.pk8")
    openssl("pkcs8", "-topk8", "-nocrypt", "-in", tls_key, "-outform", "DER", "-out", root/"windows-tls.pk8")
    for name, bits, algorithm in [("device", "2048", "-sha256"), ("renew-device", "2048", "-sha256"), ("weak", "1024", "-sha256"), ("sha1", "2048", "-sha1")]:
        openssl("req", "-new", "-newkey", "rsa:"+bits, "-nodes", algorithm, "-subj", "/CN=untrusted-csr-subject",
                "-keyout", root/(name+".key"), "-outform", "DER", "-out", root/(name+".csr"))
    openssl("pkcs8", "-topk8", "-nocrypt", "-in", root/"device.key", "-outform", "DER", "-out", root/"device.pk8")
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "180",
            "-subj", "/CN=Untrusted T2 CA", "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", root/"rogue-ca.key", "-out", root/"rogue-ca.pem")
    (root/"rogue-leaf.ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n")
    openssl("x509", "-req", "-inform", "DER", "-in", root/"device.csr", "-CA", root/"rogue-ca.pem", "-CAkey", root/"rogue-ca.key",
            "-set_serial", "2", "-days", "90", "-sha256", "-extfile", root/"rogue-leaf.ext", "-out", root/"rogue-client.pem")
    (root/"protocol.key").write_bytes(secrets.token_bytes(32))
    for path in root.iterdir():
        if path.is_file() and (path.suffix in (".key", ".pk8") or path.name.endswith("-secret")):
            os.chmod(path, 0o600)
    endpoint = {"certificate_file":str(tls_certificate), "private_key_file":str(root/"windows-tls.pk8")}
    config = {
        "enrollment":{**endpoint, "listen":"127.0.0.1:8443", "origin":"https://localhost:8443"},
        "management":{**endpoint, "listen":"127.0.0.1:8444", "origin":"https://localhost:8444"},
        "ca_certificate_file":str(root/"device-ca.pem"), "ca_private_key_file":str(root/"device-ca.pk8"),
        "protocol_key_file":str(root/"protocol.key"), "provider_id":"RSS-MDM", "push":None, "additional_management":[], "poll":{'interval_for_first_set_of_retries': 15, 'number_of_first_retries': 10, 'interval_for_second_set_of_retries': 0, 'number_of_second_retries': 0, 'interval_for_remaining_scheduled_retries': 1440, 'number_of_remaining_scheduled_retries': 0, 'poll_on_login': False, 'all_users_poll_on_first_login': False},
    }
    (root/"windows.json").write_text(json.dumps(config))
    return config
