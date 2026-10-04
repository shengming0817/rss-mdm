"""Case-owned Compose SCEP provider; only real owners select listening addresses.

ref: smallstep/certificates v0.30.2 examples/docker/docker-compose.yml;
smallstep/cli v0.30.2 command/ca/provisioner/webhook/update.go.
"""
from contextlib import contextmanager
import ipaddress
import json
from pathlib import Path
import re
import secrets
import ssl
import time
import urllib.request
from urllib.error import URLError
from urllib.parse import urlsplit

from fixture_tools import binary
from t2_environment import PKI_CA, Environment, ROOT, private, run
from t2_processes import check_cancelled, cleanup, private_value, record_output, subprocess


class Provider:
    def __init__(self, root, case):
        if not re.fullmatch(r'[0-9a-f]{20}', case):
            raise ValueError('invalid PKI fixture case identity')
        self.root = Path(root).resolve()
        self.owner = Environment(group='t2-pki-'+case)
        self.owner.extra = {'MDM_PKI_ROOT':str(self.root)}
        self.container = None

    def compose(self, *args, **kwargs):
        return self.owner.compose('--profile', 'pki', *args, **kwargs)

    def reset(self):
        self.owner.reset()
        self.container = None

    def start(self):
        self.owner.verify_ownership()
        self.compose('up', '-d', '--no-deps', 'step-ca', timeout=120)
        self.container = self.compose('ps', '-q', 'step-ca', timeout=15)
        if not self.container or '\n' in self.container:
            raise RuntimeError('fixed step-ca container missing during startup')
        address = self.compose('port', 'step-ca', str(PKI_CA['port']), timeout=15)
        parsed = urlsplit('https://'+address)
        if parsed.hostname != '127.0.0.1' or not parsed.port or address != f'127.0.0.1:{parsed.port}':
            raise RuntimeError('fixed step-ca omitted a unique loopback mapping')
        return f'https://localhost:{parsed.port}'

    def check(self):
        check_cancelled()
        info = json.loads(run(['docker','inspect',self.container], capture_output=True, timeout=10).stdout)[0]
        if not info['State']['Running']:
            raise RuntimeError('fixed step-ca exited')

    def wait(self, origin, path, ca_root):
        context = ssl.create_default_context(cafile=ca_root)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
        deadline = time.monotonic()+30
        while True:
            self.check()
            try:
                with opener.open(origin+path, timeout=1) as response:
                    if response.status == 200:
                        return
            except ssl.SSLCertVerificationError as error:
                raise RuntimeError('fixed step-ca TLS trust verification failed') from error
            except URLError as error:
                if isinstance(error.reason, ssl.SSLCertVerificationError):
                    raise RuntimeError('fixed step-ca TLS trust verification failed') from error
            except OSError:
                pass
            if time.monotonic() >= deadline:
                raise RuntimeError('fixed step-ca TLS readiness deadline')
            time.sleep(.1)

    def webhook_listen(self):
        system = run(['docker','info','--format','{{.OperatingSystem}}'],capture_output=True,timeout=15).stdout.strip()
        if 'Docker Desktop' in system:
            return '127.0.0.1:0'
        # A native engine's private bridge gateway is a host interface, not container loopback.
        network = self.owner.project+'_default'
        info = json.loads(run(['docker','network','inspect',network],capture_output=True,timeout=15).stdout)[0]
        gateways = [entry['Gateway'] for entry in info['IPAM']['Config'] if entry.get('Gateway') and ipaddress.ip_address(entry['Gateway']).version == 4]
        if len(gateways) != 1:
            raise RuntimeError('PKI fixture requires one private IPv4 bridge gateway')
        gateway = gateways[0]
        self.owner.extra['MDM_PKI_HOST_ADDRESS'] = gateway
        return gateway+':0'

    def logs(self):
        webhook_log = self.root/'step-webhooks.log'
        if webhook_log.exists():
            record_output('step webhook CLI', webhook_log.read_text(errors='replace'))
        record_output('step-ca', self.compose('logs','--no-color','step-ca',timeout=15))


def recover():
    """Recover only this leased worktree's registered Apple projects, even without local files."""
    prefix = Environment().identity+'-t2-pki-'
    projects = set()
    for listing in (['ps','-a'], ['network','ls']):
        values = run(['docker',*listing,'--filter','label=rss.mdm.worktree='+Environment().identity,
                      '--format','{{.Label "com.docker.compose.project"}}'],capture_output=True,timeout=30).stdout.splitlines()
        projects.update(value for value in values if value.startswith(prefix))
    base = ROOT/'artifacts/dev-environment'
    if base.exists():
        projects.update(Environment(group=p.name).project for p in base.glob('t2-pki-*'))
    for project in sorted(projects):
        case = project.removeprefix(prefix)
        if not re.fullmatch(r'[0-9a-f]{20}', case):
            raise RuntimeError('invalid PKI recovery owner')
        Environment(group='t2-pki-'+case).reset()


