"""Disposable Agent-only provisioner on the pinned step-ca used by candidate verification."""
import json
from pathlib import Path
import shutil
import subprocess

def openssl(*args):
    subprocess.run(['openssl', *map(str, args)], check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, timeout=30)

def prepare(root):
    provisioner = root/'agent-provisioner.pem'
    openssl('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', provisioner)
    provisioner.chmod(0o600)
    openssl('pkcs8', '-topk8', '-nocrypt', '-in', provisioner, '-outform', 'DER', '-out', root/'agent-provisioner.pk8')
    (root/'agent-provisioner.pk8').chmod(0o600)
    openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=rss-mdm-agent',
            '-keyout', root/'agent-csr-agent.key', '-outform', 'DER', '-out', root/'agent.der')
    (root/'agent-csr-agent.key').chmod(0o600)

def install(root, cli, admin, origin, *, template_source=None):
    cli('crypto', 'jwk', 'create', root/'agent.pub.json', root/'agent.private.json',
        '--from-pem', root/'agent-provisioner.pem', '--alg', 'RS256', '--use', 'sig',
        '--kid', 'agent-candidate-key', '--no-password', '--insecure')
    (root/'agent.private.json').unlink()
    template = root/'step/templates/agent-leaf.tpl'
    template.parent.mkdir(mode=0o700,exist_ok=True)
    shutil.copyfile(template_source or Path(__file__).resolve().parents[1]/'deployment/agent-leaf.tpl', template)
    template.chmod(0o600)
    cli('ca', 'provisioner', 'add', 'rss-agent', '--type', 'JWK', '--public-key', root/'agent.pub.json',
        '--x509-template', template, '--disable-renewal', '--ssh=false',
        '--x509-default-dur', '8760h', '--x509-max-dur', '87600h', *admin)
    value = dict(mode='step_ca',
                 endpoint=dict(origin='https://mdm.example.test:9445'),
                 lifetime=dict(mode='standard'))
    (root/'agent-pki.json').write_text(json.dumps(value))
