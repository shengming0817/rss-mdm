"""Disposable Agent-only provisioner on the pinned step-ca used by native T2."""
import json
from pathlib import Path
import secrets
import shutil
from t2_processes import subprocess


def openssl(*args):
    subprocess.run(['openssl', *map(str, args)], check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, timeout=30)


def prepare(root, configuration, password):
    # Test the full development limit. The default five-year intermediate cannot
    # cover ten-year leaves; regenerate only disposable certificates, with the
    # same encrypted keys/subjects and an explicitly longer test root.
    config = json.loads(configuration.read_text())
    ca_root, intermediate, key = Path(config['root'][0]), Path(config['crt']), Path(config['key'])
    root_key = configuration.parent.parent/'secrets/root_ca_key'
    for certificate, signing_key, name in [(ca_root, root_key, 'root'), (intermediate, key, 'issuer')]:
        openssl('x509', '-x509toreq', '-in', certificate, '-signkey', signing_key,
                '-passin', 'file:'+str(password), '-out', root/(name+'.csr'))
    extensions = root/'agent-ca.ext'
    extensions.write_text('basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n')
    openssl('req', '-x509', '-in', root/'root.csr', '-key', root_key,
            '-passin', 'file:'+str(password), '-days', '7300', '-out', ca_root,
            '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
    openssl('x509', '-req', '-in', root/'issuer.csr', '-CA', ca_root, '-CAkey', root_key,
            '-passin', 'file:'+str(password), '-days', '3652', '-set_serial', str(secrets.randbits(120)),
            '-extfile', extensions, '-out', intermediate)
    provisioner = root/'agent-provisioner.pem'
    openssl('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', provisioner)
    provisioner.chmod(0o600)
    openssl('pkcs8', '-topk8', '-nocrypt', '-in', provisioner, '-outform', 'DER', '-out', root/'agent-provisioner.pk8')
    (root/'agent-provisioner.pk8').chmod(0o600)
    # Independent keys cover algorithm/strength/attribute/signature rejection.
    for name, algorithm, subject, extra in [
        ('agent', 'rsa:2048', '/CN=rss-mdm-agent', []),
        ('other', 'rsa:2048', '/CN=rss-mdm-agent', []),
        ('weak', 'rsa:1024', '/CN=rss-mdm-agent', []),
        ('sha1', 'rsa:2048', '/CN=rss-mdm-agent', ['-sha1']),
        ('ec', 'ec', '/CN=rss-mdm-agent', ['-pkeyopt', 'ec_paramgen_curve:P-256']),
        ('subject', 'rsa:2048', '/CN=claimed-device', []),
        ('san', 'rsa:2048', '/CN=rss-mdm-agent', ['-addext', 'subjectAltName=URI:urn:claimed']),
        ('ca', 'rsa:2048', '/CN=rss-mdm-agent', ['-addext', 'basicConstraints=critical,CA:TRUE']),
        ('server', 'rsa:2048', '/CN=rss-mdm-agent', ['-addext', 'extendedKeyUsage=serverAuth']),
    ]:
        openssl('req', '-new', '-newkey', algorithm, '-nodes', '-subj', subject,
                '-keyout', root/('agent-csr-'+name+'.key'), '-outform', 'DER', '-out', root/(name+'.der'), *extra)
        (root/('agent-csr-'+name+'.key')).chmod(0o600)
    openssl('pkcs8', '-topk8', '-nocrypt', '-in', root/'agent-csr-agent.key', '-outform', 'DER', '-out', root/'agent.pk8')
    (root/'agent.pk8').chmod(0o600)

    # A same-DN subordinate is a valid WebPKI path under this direct issuer,
    # but must never become another Agent signer through chain delegation.
    openssl('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', root/'agent-subordinate.key')
    (root/'agent-subordinate.key').chmod(0o600)
    openssl('x509', '-x509toreq', '-in', intermediate, '-signkey', root/'agent-subordinate.key', '-out', root/'agent-subordinate.csr')
    openssl('x509', '-req', '-in', root/'agent-subordinate.csr', '-CA', intermediate, '-CAkey', key,
            '-passin', 'file:'+str(password), '-days', '3651', '-set_serial', str(secrets.randbits(120)),
            '-extfile', extensions, '-out', root/'agent-subordinate.crt')
    openssl('pkcs8', '-topk8', '-nocrypt', '-in', root/'agent-subordinate.key', '-outform', 'DER', '-out', root/'agent-subordinate.pk8')
    (root/'agent-subordinate.pk8').chmod(0o600)


def install(root, cli, admin, origin):
    cli('crypto', 'jwk', 'create', root/'agent.pub.json', root/'agent.private.json',
        '--from-pem', root/'agent-provisioner.pem', '--alg', 'RS256', '--use', 'sig',
        '--kid', 'agent-t2-key', '--no-password', '--insecure')
    (root/'agent.private.json').unlink()
    template = Path(__file__).resolve().parents[1]/'deployment/agent-leaf.tpl'
    cli('ca', 'provisioner', 'add', 'rss-agent', '--type', 'JWK', '--public-key', root/'agent.pub.json',
        '--x509-template', template, '--disable-renewal', '--ssh=false',
        '--x509-default-dur', '8760h', '--x509-max-dur', '87600h', *admin)
    value = dict(mode='step_ca', ca_url=origin, kid='agent-t2-key',
                 tls_root_file=str(root/'step/certs/root_ca.crt'),
                 issuer_certificate_file=str(root/'step/certs/intermediate_ca.crt'),
                 provisioner_key_file=str(root/'agent-provisioner.pk8'), lifetime=dict(mode='standard'))
    (root/'agent-pki.json').write_text(json.dumps(value))


def restore(root):
    # Caller has stopped step-ca. Preserve the same path, identity, provisioner
    # database and consumed token history; never initialize a replacement CA.
    original = root/'step'
    backup = root/'step-backup'
    shutil.copytree(original, backup)
    shutil.rmtree(original)
    shutil.copytree(backup, original)
    (root/'agent-backup-restored').write_text('same CA identity, config and database restored\n')
