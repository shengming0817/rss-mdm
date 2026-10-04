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


from pki_ca import Provider, recover


@contextmanager
def running(root, env, *, case):
    import shutil
    case_root=Path(root).resolve()
    root=case_root/'pki'/'apple';root.mkdir(mode=0o700,parents=True)
    for name in ('case.json','ca.crt','apple.json','apple-issuer.pem','apple-issuer.key'):
        shutil.copyfile(case_root/name,root/name);(root/name).chmod(0o600)
    import hashlib
    provider=Provider(root,hashlib.sha256((case+':apple').encode()).hexdigest()[:20])
    step = binary('step')
    password = private(root/'step-password', secrets.token_urlsafe(32))
    step_path = root/'step'
    child_env = {**env, 'STEPPATH':str(step_path)}

    def cli(*args):
        result = subprocess.run([str(step), *map(str,args)],env=child_env,text=True,
                                capture_output=True,timeout=30,check=True)
        return result.stdout

    cli('ca','init','--deployment-type','standalone','--name','RSS Apple T2',
        '--dns','localhost,step-ca','--address',f"0.0.0.0:{PKI_CA['port']}",
        '--provisioner','rss-admin','--admin-subject','rss-admin','--password-file',password,'--remote-management')
    configuration = step_path/'config/ca.json'
    ca_config = json.loads(configuration.read_text())
    ca_config['crl']=dict(enabled=True,generateOnRevoke=True,cacheDuration='10m',renewPeriod='1m')
    ca_config['authority']['backdate']='0s'
    ca_config['root'] = [str(step_path/'certs/root_ca.crt'), str(root/'ca.crt')]
    private(configuration, ca_config)
    ca_root = step_path/'certs/root_ca.crt'
    from pki_fixtures import root_crl, trust
    offline=root_crl(root,ca_root,step_path/'secrets/root_ca_key',password)
    (step_path/'secrets/root_ca_key').replace(offline/'root_ca_key')
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
        key=root/'apple-revocation.pem'
        subprocess.run(['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out',str(key)],check=True,capture_output=True,timeout=30)
        key.chmod(0o600)
        subprocess.run(['openssl','pkcs8','-topk8','-nocrypt','-in',str(key),'-outform','DER','-out',str(root/'apple-revocation.pk8')],check=True,capture_output=True,timeout=30)
        (root/'apple-revocation.pk8').chmod(0o600)
        cli('crypto','jwk','create',root/'apple-revocation.pub.json',root/'apple-revocation.private.json','--from-pem',key,
            '--alg','RS256','--use','sig','--kid','apple-revocation-key','--no-password','--insecure')
        (root/'apple-revocation.private.json').unlink()
        cli('ca','provisioner','add','rss-apple-revocation','--type','JWK','--public-key',root/'apple-revocation.pub.json',
            '--disable-renewal','--ssh=false',*admin)
        listen = provider.webhook_listen()
        provider.logs()
        provider.owner.verify_ownership()
        provider.compose('rm','--stop','--force','--volumes','step-ca',timeout=30)
        origin = provider.start()
        provider.wait(origin,'/scep/rss?operation=GetCACaps',ca_root)
        tenant=json.loads((root/'case.json').read_text())['tenant']
        config.pop('issuer_certificate_file',None)
        config.pop('scep_url',None)
        config.pop('scep_provisioner',None)
        config.update(trust_file=str(trust(root,'apple',config['management']['origin'],tenant,'rss','',origin)))
        private(case_root/'apple.json',config)
        providers_file=case_root/'device-pki.json'
        providers=json.loads(providers_file.read_text()) if providers_file.exists() else []
        trust_value=json.loads(Path(config['trust_file']).read_text())
        providers.append(dict(scep_url=origin+'/scep/rss',purpose='apple',issuer=trust_value['issuers'][0]['digest'],origin=origin,tls_root_file=str(ca_root),
            provisioner='rss-apple-revocation',kid='apple-revocation-key',provisioner_key_file=str(root/'apple-revocation.pk8')))
        private(providers_file,providers)
        env.update(MDM_STEP_CLI=str(step),MDM_STEP_CA_URL=origin,MDM_STEP_CA_ROOT=str(ca_root),
                   MDM_APPLE_WEBHOOK_LISTEN=listen,MDM_APPLE_PKI_FIXTURES=str(root))
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
        import shutil
        shutil.rmtree(offline)
