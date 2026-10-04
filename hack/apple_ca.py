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

from apple_tools import binary
from t2_environment import APPLE_CA, Environment, ROOT, private, run
from t2_processes import check_cancelled, cleanup, private_value, record_output, subprocess


class Provider:
    def __init__(self, root, case):
        if not re.fullmatch(r'[0-9a-f]{20}', case):
            raise ValueError('invalid Apple fixture case identity')
        self.root = Path(root).resolve()
        self.owner = Environment(group='t2-apple-'+case)
        self.owner.extra = {'MDM_APPLE_CA_ROOT':str(self.root)}
        self.container = None

    def compose(self, *args, **kwargs):
        return self.owner.compose('--profile', 'apple', *args, **kwargs)

    def reset(self):
        self.owner.reset()
        self.container = None

    def start(self):
        self.owner.verify_ownership()
        self.compose('up', '-d', '--no-deps', 'step-ca', timeout=120)
        self.container = self.compose('ps', '-q', 'step-ca', timeout=15)
        if not self.container or '\n' in self.container:
            raise RuntimeError('fixed step-ca container missing during startup')
        address = self.compose('port', 'step-ca', str(APPLE_CA['port']), timeout=15)
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
            raise RuntimeError('Apple fixture requires one private IPv4 bridge gateway')
        gateway = gateways[0]
        self.owner.extra['MDM_APPLE_HOST_ADDRESS'] = gateway
        return gateway+':0'

    def logs(self):
        webhook_log = self.root/'step-webhooks.log'
        if webhook_log.exists():
            record_output('step webhook CLI', webhook_log.read_text(errors='replace'))
        record_output('step-ca', self.compose('logs','--no-color','step-ca',timeout=15))


def recover():
    """Recover only this leased worktree's registered Apple projects, even without local files."""
    prefix = Environment().identity+'-t2-apple-'
    projects = set()
    for listing in (['ps','-a'], ['network','ls']):
        values = run(['docker',*listing,'--filter','label=rss.mdm.worktree='+Environment().identity,
                      '--format','{{.Label "com.docker.compose.project"}}'],capture_output=True,timeout=30).stdout.splitlines()
        projects.update(value for value in values if value.startswith(prefix))
    base = ROOT/'artifacts/dev-environment'
    if base.exists():
        projects.update(Environment(group=p.name).project for p in base.glob('t2-apple-*'))
    for project in sorted(projects):
        case = project.removeprefix(prefix)
        if not re.fullmatch(r'[0-9a-f]{20}', case):
            raise RuntimeError('invalid Apple recovery owner')
        Environment(group='t2-apple-'+case).reset()


@contextmanager
def running(root, env, *, case):
    root = Path(root).resolve()
    provider = Provider(root, case)
    step = binary('step')
    password = private(root/'step-password', secrets.token_urlsafe(32))
    step_path = root/'step'
    child_env = {**env, 'STEPPATH':str(step_path)}

    def cli(*args):
        result = subprocess.run([str(step), *map(str,args)],env=child_env,text=True,
                                capture_output=True,timeout=30,check=True)
        return result.stdout

    cli('ca','init','--deployment-type','standalone','--name','RSS Apple T2',
        '--dns','localhost,step-ca','--address',f"0.0.0.0:{APPLE_CA['port']}",
        '--provisioner','rss-admin','--admin-subject','rss-admin','--password-file',password,'--remote-management')
    configuration = step_path/'config/ca.json'
    ca_config = json.loads(configuration.read_text())
    ca_config['root'] = [str(step_path/'certs/root_ca.crt'), str(root/'ca.crt')]
    private(configuration, ca_config)
    ca_root = step_path/'certs/root_ca.crt'
    if env.get('MDM_AGENT_PKI_FIXTURE') == '1':
        from agent_pki_fixtures import prepare
        prepare(root, configuration, password)
    template = private(root/'apple-leaf.tpl', '{"subject":{"commonName":{{ toJson .Webhooks.rss.subject }}},"keyUsage":["digitalSignature"],"extKeyUsage":["clientAuth"],"basicConstraints":{"isCA":false}}')
    provider.owner.prepare_inputs(certificates=False)
    try:
        origin = provider.start()
        provider.wait(origin, '/health', ca_root)
        admin = ['--ca-url',origin,'--root',ca_root,'--admin-subject','rss-admin',
                 '--admin-provisioner','rss-admin','--admin-password-file',password]
        cli('ca','provisioner','add','rss','--type','SCEP','--min-public-key-length','2048',
            '--encryption-algorithm-identifier','2','--scep-decrypter-certificate-file',root/'apple-issuer.pem',
            '--scep-decrypter-key-file',root/'apple-issuer.key','--x509-template',template,
            '--disable-renewal','--x509-max-dur','2160h','--x509-default-dur','24h',*admin)
        config = json.loads((root/'apple.json').read_text())
        for kind,name,phase in [('SCEPCHALLENGE','rss','challenge'),('NOTIFYING','rss_notify','notify')]:
            output = cli('ca','provisioner','webhook','add','rss',name,'--kind',kind,
                         '--url',f'https://mdm.example.test:1/api/v1/apple/scep/{phase}',*admin)
            hook = re.search(r'Webhook ID: ([^\s]+)\s+Secret: ([^\s]+)',output)
            if not hook:
                raise RuntimeError('fixed step CLI omitted webhook credentials')
            private_value(hook[2])
            secret = private(root/('apple-'+phase+'-secret'),hook[2])
            config[phase+'_webhook'] = dict(id=hook[1],secret_file=str(secret))
        if env.get('MDM_AGENT_PKI_FIXTURE') == '1':
            from agent_pki_fixtures import install
            install(root,cli,admin,origin)
        listen = provider.webhook_listen()
        provider.logs()
        provider.owner.verify_ownership()
        provider.compose('rm','--stop','--force','--volumes','step-ca',timeout=30)
        if env.get('MDM_AGENT_PKI_FIXTURE') == '1':
            from agent_pki_fixtures import restore
            restore(root)
        origin = provider.start()
        provider.wait(origin,'/scep/rss?operation=GetCACaps',ca_root)
        config.update(scep_url=origin+'/scep/rss',issuer_certificate_file=str(step_path/'certs/intermediate_ca.crt'))
        private(root/'apple.json',config)
        if env.get('MDM_AGENT_PKI_FIXTURE') == '1':
            agent = json.loads((root/'agent-pki.json').read_text())
            agent['ca_url'] = origin
            private(root/'agent-pki.json',agent)
        env.update(MDM_STEP_CLI=str(step),MDM_STEP_CA_URL=origin,MDM_STEP_CA_ROOT=str(ca_root),
                   MDM_APPLE_WEBHOOK_LISTEN=listen)
        print('fixed step-ca v0.30.2: isolated Compose SCEP authority ready',flush=True)
        yield
        provider.check()
    finally:
        # A cancelled CLI is not proof that its daemon-owned container stopped.
        with cleanup():
            try:
                provider.logs()
            finally:
                provider.reset()
