"""Disposable Apple credentials; public CA and APNs are never contacted by T2."""
import base64
import json
import os
from pathlib import Path
import secrets
import subprocess


def generate(root, tls_certificate, tls_key):
    root = Path(root)

    def openssl(*args):
        subprocess.run(['openssl', *map(str, args)], check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=30)

    openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '180',
            '-subj', '/CN=RSS Apple T2 Root', '-addext', 'basicConstraints=critical,CA:TRUE',
            '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
            '-keyout', root/'apple-root.key', '-out', root/'apple-root.pem')
    for name, subject, extensions in [
        ('apple-issuer', '/CN=RSS Apple Dedicated Issuer',
         'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,digitalSignature,keyCertSign,cRLSign\n'),
        ('apple-profile', '/CN=RSS Profile Signer',
         'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=emailProtection\n'),
        ('apple-apns', '/CN=RSS Test APNs/UID=com.apple.mgmt.rss-t2',
         'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n'),
    ]:
        openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-subj', subject,
                '-keyout', root/(name+'.key'), '-out', root/(name+'.csr'))
        (root/(name+'.ext')).write_text(extensions)
        openssl('x509', '-req', '-in', root/(name+'.csr'), '-CA', root/'apple-root.pem',
                '-CAkey', root/'apple-root.key', '-set_serial', str(secrets.randbits(120)),
                '-days', '90', '-sha256', '-extfile', root/(name+'.ext'), '-out', root/(name+'.pem'))
        openssl('pkcs8', '-topk8', '-nocrypt', '-in', root/(name+'.key'), '-outform', 'DER',
                '-out', root/(name+'.pk8'))
    openssl('pkcs8', '-topk8', '-nocrypt', '-in', tls_key, '-outform', 'DER', '-out', root/'apple-tls.pk8')
    for kind in ['challenge','notify']:
        (root/('apple-'+kind+'-secret')).write_text(base64.b64encode(secrets.token_bytes(32)).decode())
    for path in root.iterdir():
        if path.is_file() and (path.suffix in ('.key', '.pk8') or path.name.endswith('-secret')):
            os.chmod(path, 0o600)
    config = dict(
        management=dict(listen='127.0.0.1:8445', origin='https://localhost:8445',
                        certificate_file=str(tls_certificate), private_key_file=str(root/'apple-tls.pk8')),
        scep_url='https://localhost:9000/scep/rss', scep_provisioner='rss',
        issuer_certificate_file=str(root/'apple-issuer.pem'),
        profile_certificate_file=str(root/'apple-profile.pem'), profile_private_key_file=str(root/'apple-profile.pk8'),
        apns_certificate_file=str(root/'apple-apns.pem'), apns_private_key_file=str(root/'apple-apns.key'),
        apns_topic='com.apple.mgmt.rss-t2', challenge_webhook=dict(id='rss-challenge',secret_file=str(root/'apple-challenge-secret')), notify_webhook=dict(id='rss-notify',secret_file=str(root/'apple-notify-secret')))
    (root/'apple.json').write_text(json.dumps(config))
    return config
