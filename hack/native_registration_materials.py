"""Real Bootstrap certificate and independent runtime CSR for Registration admission."""
import json
import subprocess
import sys
import uuid
from pathlib import Path
from task_trust_materials import run


def prepare(directory, native, installation, bootstrap):
    root = directory / 'task-trust-ca'
    destination = native / 'bootstrap'
    destination.mkdir(mode=0o700)
    subject = installation.replace('-', '') + bootstrap.replace('-', '')
    extension = destination / 'leaf.conf'
    extension.write_text('basicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature\n'
                         'extendedKeyUsage=clientAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n')
    for name, dn in [('bootstrap', '/OU=rss-mdm-agent-bootstrap/CN=' + subject),
                     ('runtime', '/CN=rss-mdm-agent')]:
        run('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', dn,
            '-keyout', destination/(name+'.key'), '-out', destination/(name+'.csr'))
        (destination/(name+'.key')).chmod(0o600)
    run('x509', '-req', '-in', destination/'bootstrap.csr', '-CA', root/'ca.pem',
        '-CAkey', root/'ca.key', '-set_serial', str(uuid.uuid4().int), '-days', '1',
        '-sha256', '-extfile', extension, '-out', destination/'bootstrap.pem')
    run('pkcs8', '-topk8', '-nocrypt', '-in', root/'ca.key', '-outform', 'DER',
        '-out', destination/'provider.pk8')
    (destination/'provider.pk8').chmod(0o600)
    serial = subprocess.check_output(['openssl', 'x509', '-in', str(native/'client.pem'),
                                      '-noout', '-serial'], text=True).strip().split('=')[1]
    print(json.dumps(dict(directory=str(destination), serial=str(int(serial, 16)))))


if __name__ == '__main__':
    prepare(Path(sys.argv[1]), Path(sys.argv[2]), *sys.argv[3:])
