"""Minimal real Agent certificate material for Task Trust's signing admission proof."""
import base64
from datetime import datetime, timezone
import json
import subprocess
import sys
from pathlib import Path


def run(*args):
    return subprocess.run(['openssl', *map(str, args)], check=True, capture_output=True, timeout=30).stdout


def prepare(directory):
    root = directory / 'task-trust-ca'
    if root.exists():
        run('x509', '-in', root / 'ca.pem', '-checkend', '86400', '-noout')
        run('crl', '-in', root / 'ca.crl', '-noout', '-verify', '-CAfile', root / 'ca.pem')
        dates = run('crl', '-in', root / 'ca.crl', '-noout', '-lastupdate', '-nextupdate').decode().splitlines()
        validity = {key: datetime.strptime(value, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                    for key, value in (line.split('=', 1) for line in dates)}
        if not validity['lastUpdate'] <= datetime.now(timezone.utc) < validity['nextUpdate']:
            raise RuntimeError('Task Trust CA CRL is not current; reset the local T2 environment')
        return root
    root.mkdir(mode=0o700)
    (root / 'index').write_text('')
    (root / 'serial').write_text('01\n')
    (root / 'crlnumber').write_text('01\n')
    (root / 'ca.conf').write_text(f'''[req]
distinguished_name=dn
x509_extensions=ca
prompt=no
[dn]
CN=Task Trust T2 CA
[ca]
basicConstraints=critical,CA:true
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
[ca_config]
default_ca=issuer
[issuer]
database={root}/index
serial={root}/serial
crlnumber={root}/crlnumber
certificate={root}/ca.pem
private_key={root}/ca.key
default_md=sha256
default_crl_days=30
''')
    run('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '365', '-config', root/'ca.conf', '-keyout', root/'ca.key', '-out', root/'ca.pem')
    (root/'ca.key').chmod(0o600)
    run('ca', '-name', 'issuer', '-config', root/'ca.conf', '-gencrl', '-out', root/'ca.crl')
    return root


def leaf(directory, tenant, device, purpose):
    root=directory/'task-trust-ca'
    destination=directory/('task-trust-'+purpose+'-'+tenant)
    destination.mkdir(mode=0o700)
    assert purpose in ('agent', 'da_device')
    prefix = 'urn:rss-mdm:agent:v1:' if purpose == 'agent' else 'urn:rss:da:device:v1:'
    identity=prefix+tenant+':'+base64.urlsafe_b64encode(device.encode()).decode().rstrip('=')
    provisioner = b'rss-agent' if purpose == 'agent' else b'rss-da-device'
    marker=bytes.fromhex('020101')+bytes([4,len(provisioner)])+provisioner+bytes([4,10])+b'task-trust'
    marker=bytes([0x30,len(marker)])+marker
    ext=destination/'leaf.conf'
    ext.write_text('basicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\nsubjectAltName=URI:'+identity+'\n1.3.6.1.4.1.37476.9000.64.1=DER:'+marker.hex(':')+'\n')
    run('req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=rss-mdm-agent','-keyout',destination/'leaf.key','-out',destination/'leaf.csr')
    (destination/'leaf.key').chmod(0o600)
    run('x509','-req','-in',destination/'leaf.csr','-CA',root/'ca.pem','-CAkey',root/'ca.key','-set_serial',str(int(tenant.replace('-',''),16)),'-days','1','-sha256','-extfile',ext,'-out',destination/'leaf.pem')
    print(json.dumps(dict(leaf=str(destination/'leaf.pem'),root=str(root/'ca.pem'),crl=str(root/'ca.crl'),identity=identity)))

if __name__ == '__main__':
    leaf(Path(sys.argv[1]),sys.argv[2],sys.argv[3],sys.argv[4] if len(sys.argv)>4 else 'agent')
