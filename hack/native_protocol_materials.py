"""Real native client and TLS server material; no product or business state."""
import json
import sys
import uuid
from pathlib import Path
from task_trust_materials import run


def leaf(directory, purpose, registration, request, attempt):
    root = directory / 'task-trust-ca'
    destination = directory / ('native-' + registration)
    destination.mkdir(mode=0o700)
    subject = registration if purpose == 'windows' else request.replace('-', '') + attempt.replace('-', '')
    def certificate(name, subject, usage, extra=''):
        ext = destination / (name + '.conf')
        ext.write_text('basicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=' + usage + '\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n' + extra)
        run('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', subject, '-keyout', destination/(name+'.key'), '-out', destination/(name+'.csr'))
        (destination/(name+'.key')).chmod(0o600)
        run('x509', '-req', '-in', destination/(name+'.csr'), '-CA', root/'ca.pem', '-CAkey', root/'ca.key', '-set_serial', str(uuid.uuid4().int), '-days', '1', '-sha256', '-extfile', ext, '-out', destination/(name+'.pem'))
    certificate('client', '/CN='+subject, 'clientAuth')
    certificate('server', '/CN=localhost', 'serverAuth', 'subjectAltName=DNS:localhost,IP:127.0.0.1\n')
    if purpose == 'apple':
        certificate('runtime', '/CN=Native T2/UID=com.apple.mgmt.rss-t2', 'clientAuth')
        run('pkcs8', '-topk8', '-nocrypt', '-in', destination/'runtime.key', '-outform', 'DER', '-out', destination/'runtime.pk8')
    print(json.dumps(dict(directory=str(destination), root=str(root/'ca.pem'), crl=str(root/'ca.crl'))))

if __name__ == '__main__':
    leaf(Path(sys.argv[1]), *sys.argv[2:])
