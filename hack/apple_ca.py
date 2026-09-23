"""Fixed external SCEP provider with its own disposable CA database and admin API."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import time
import urllib.request
from apple_tools import binary


def port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


@contextmanager
def running(root, env):
    root = Path(root)
    step, ca = binary('step'), binary('step-ca')
    password = root/'step-password'
    password.write_text(secrets.token_urlsafe(32)); password.chmod(0o600)
    step_path = root/'step'
    child_env = {**env, 'STEPPATH': str(step_path)}
    ca_port, webhook_port = port(), port()
    origin = f'https://localhost:{ca_port}'

    def cli(*args):
        result = subprocess.run([str(step), *map(str, args)], env=child_env, text=True,
                                capture_output=True, timeout=30)
        if result.returncode:
            raise RuntimeError('fixed step CLI configuration failed: '+result.stderr)
        return result.stdout

    cli('ca', 'init', '--deployment-type', 'standalone', '--name', 'RSS Apple T2',
        '--dns', 'localhost', '--address', f'127.0.0.1:{ca_port}', '--provisioner', 'rss-admin',
        '--admin-subject', 'rss-admin', '--password-file', password, '--remote-management')
    configuration = step_path/'config/ca.json'
    ca_config = json.loads(configuration.read_text())
    # The webhook client trusts configured CA roots, not federatedRoots.
    ca_config['root'] = [str(step_path/'certs/root_ca.crt'), str(root/'ca.crt')]
    configuration.write_text(json.dumps(ca_config)); configuration.chmod(0o600)
    ca_root = step_path/'certs/root_ca.crt'
    admin = ['--ca-url', origin, '--root', ca_root, '--admin-subject', 'rss-admin',
             '--admin-provisioner', 'rss-admin', '--admin-password-file', password]
    template = root/'apple-leaf.tpl'
    template.write_text('{"subject":{"commonName":{{ toJson .Webhooks.rss.subject }}},"keyUsage":["digitalSignature"],"extKeyUsage":["clientAuth"],"basicConstraints":{"isCA":false}}')
    with (root/'step-ca.log').open('w') as log:
        process = subprocess.Popen([str(ca), str(configuration), '--password-file', str(password)],
                                   env=child_env, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic()+20
            while True:
                if process.poll() is not None:
                    raise RuntimeError('fixed step-ca exited during startup')
                try:
                    urllib.request.urlopen(origin+'/health', context=ssl.create_default_context(cafile=ca_root), timeout=1).close()
                    break
                except (OSError, urllib.error.URLError):
                    if time.monotonic()>deadline:
                        raise RuntimeError('fixed step-ca startup deadline')
                    time.sleep(.1)
            cli('ca', 'provisioner', 'add', 'rss', '--type', 'SCEP', '--min-public-key-length', '2048',
                '--encryption-algorithm-identifier', '2', '--scep-decrypter-certificate-file', root/'apple-issuer.pem',
                '--scep-decrypter-key-file', root/'apple-issuer.key', '--x509-template', template,
                '--disable-renewal', '--x509-max-dur', '2160h', '--x509-default-dur', '24h', *admin)
            config = json.loads((root/'apple.json').read_text())
            for kind, name, phase in [('SCEPCHALLENGE', 'rss', 'challenge'), ('NOTIFYING', 'rss_notify', 'notify')]:
                output = cli('ca', 'provisioner', 'webhook', 'add', 'rss', name, '--kind', kind,
                             '--url', f'https://localhost:{webhook_port}/native/apple/scep/{phase}', *admin)
                hook = re.search(r'Webhook ID: ([^\s]+)\s+Secret: ([^\s]+)', output)
                if not hook:
                    raise RuntimeError('fixed step CLI omitted webhook credentials')
                secret = root/('apple-'+phase+'-secret')
                secret.write_text(hook[2]); secret.chmod(0o600)
                config[phase+'_webhook'] = dict(id=hook[1], secret_file=str(secret))
            # step-ca installs its SCEP HTTP authority from the startup provisioner set.
            process.terminate(); process.wait(timeout=5)
            process = subprocess.Popen([str(ca), str(configuration), '--password-file', str(password)],
                                       env=child_env, stdout=log, stderr=subprocess.STDOUT)
            deadline = time.monotonic()+20
            while True:
                if process.poll() is not None:
                    raise RuntimeError('fixed step-ca exited while activating SCEP')
                try:
                    urllib.request.urlopen(origin+'/scep/rss?operation=GetCACaps', context=ssl.create_default_context(cafile=ca_root), timeout=1).close()
                    break
                except (OSError, urllib.error.URLError):
                    if time.monotonic()>deadline:
                        raise RuntimeError('fixed SCEP startup deadline')
                    time.sleep(.1)
            config.update(scep_url=origin+'/scep/rss', issuer_certificate_file=str(step_path/'certs/intermediate_ca.crt'))
            (root/'apple.json').write_text(json.dumps(config))
            env.update(MDM_APPLE_WEBHOOK_PORT=str(webhook_port), MDM_STEP_CA_ROOT=str(ca_root))
            print('fixed step-ca v0.30.2: isolated SCEP provisioner and authenticated webhooks ready', flush=True)
            yield
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=5)
