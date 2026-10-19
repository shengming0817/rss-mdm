"""Independent step-ca fixture. Windows/Agent require no SCEP, APNs or Apple enrollment.

ref: smallstep/certificates v0.30.2 authority/config/config.go; smallstep/cli command/ca/init.go.
"""
from contextlib import contextmanager
import base64
import hashlib
import json
from pathlib import Path
import secrets
import ssl
import urllib.request
from fixture_tools import binary
from pki_ca import Provider
from t2_environment import PKI_CA, private
from t2_processes import subprocess, cleanup


def root_crl(root, certificate, key, password):
    """An offline root CRL is signed outside the directory mounted into step-ca."""
    offline = root.parent / (root.name + '-offline')
    offline.mkdir(mode=0o700, exist_ok=True)
    (offline/'index').write_text('')
    (offline/'serial').write_text('01\n')
    (offline/'crlnumber').write_text('01\n')
    config = private(offline/'openssl.conf', f'[ca]\ndefault_ca=CA\n[CA]\ndatabase={offline}/index\nserial={offline}/serial\ncrlnumber={offline}/crlnumber\ncertificate={certificate}\nprivate_key={key}\ndefault_md=sha256\ndefault_crl_days=30\n')
    subprocess.run(['openssl','ca','-config',str(config),'-gencrl','-passin','file:'+str(password),
                    '-out',str(offline/'root.crl')],check=True,capture_output=True,timeout=30)
    subprocess.run(['openssl','crl','-in',str(offline/'root.crl'),'-outform','DER','-out',str(root/'root.crl.der')],check=True,capture_output=True,timeout=30)
    return offline


def isolate_root(key, password, offline):
    """Re-encrypt the offline root with a distinct secret before removing its online input."""
    root_password=private(offline/'root-password',secrets.token_urlsafe(32))
    subprocess.run(['openssl','pkey','-in',str(key),'-passin','file:'+str(password),
                    '-aes256','-passout','file:'+str(root_password),'-out',str(offline/'root_ca_key')],
                   check=True,capture_output=True,timeout=30)
    (offline/'root_ca_key').chmod(0o600)
    key.unlink()
    config=offline/'openssl.conf'
    lines=config.read_text().splitlines()
    certificate=next(Path(line.split('=',1)[1]) for line in lines if line.startswith('certificate='))
    import shutil
    shutil.copyfile(certificate,offline/'root_ca.crt')
    config.write_text('\n'.join('private_key='+str(offline/'root_ca_key') if line.startswith('private_key=')
        else 'certificate='+str(offline/'root_ca.crt') if line.startswith('certificate=') else line for line in lines)+'\n')


def certificate_der(path):
    return subprocess.run(['openssl','x509','-in',str(path),'-outform','DER'],check=True,
                          capture_output=True,timeout=30).stdout


def trust(root, purpose, origin, tenant, provisioner, kid, ca_origin):
    config=json.loads((root/'step/config/ca.json').read_text())
    root_certificate=Path(config['root'][0]); issuer=Path(config['crt'])
    context=ssl.create_default_context(cafile=str(root_certificate))
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context))
    with opener.open(ca_origin+'/crl',timeout=5) as response:
        crl=response.read(16*1024*1024+1)
    if len(crl)>16*1024*1024: raise RuntimeError('oversized fixture CRL')
    der=certificate_der(issuer)
    value=dict(version=1,origin=origin,tenant=tenant,purpose=purpose,revision=1,issuers=[dict(
        digest=hashlib.sha256(der).hexdigest(),mode='active',certificate=base64.b64encode(der).decode(),
        root=base64.b64encode(certificate_der(root_certificate)).decode(),crl=base64.b64encode(crl).decode(),
        root_crl=base64.b64encode((root/'root.crl.der').read_bytes()).decode(),provisioner=provisioner,kid=kid)])
    return private(root/(purpose+'-trust.json'),value)


def offline_materials(root, purpose):
    """Real signing material for current-state seeds; no provider process."""
    from agent_pki_fixtures import openssl
    openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '7300',
            '-subj', '/CN=RSS T2 Root', '-addext', 'basicConstraints=critical,CA:TRUE',
            '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
            '-keyout', root/'root.key', '-out', root/'root.pem')
    openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=RSS T2 Issuer',
            '-keyout', root/'issuer.key', '-out', root/'issuer.csr')
    private(root/'issuer.ext', 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n')
    openssl('x509', '-req', '-in', root/'issuer.csr', '-CA', root/'root.pem',
            '-CAkey', root/'root.key', '-set_serial', str(secrets.randbits(120)),
            '-days', '3652', '-extfile', root/'issuer.ext', '-out', root/'issuer.pem')
    for name in ('root', 'issuer'):
        private(root/(name+'.index'), '')
        private(root/(name+'.number'), '01\n')
        conf = private(root/(name+'.conf'), f'[ca]\ndefault_ca=CA\n[CA]\ndatabase={root}/{name}.index\ncrlnumber={root}/{name}.number\ncertificate={root}/{name}.pem\nprivate_key={root}/{name}.key\ndefault_md=sha256\ndefault_crl_days=30\n')
        openssl('ca', '-config', conf, '-gencrl', '-out', root/(name+'.crl'))
        openssl('crl', '-in', root/(name+'.crl'), '-outform', 'DER', '-out', root/(name+'.crl.der'))
    openssl('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', root/'provisioner.key')
    openssl('pkcs8', '-topk8', '-nocrypt', '-in', root/'provisioner.key', '-outform', 'DER', '-out', root/'provisioner.pk8')
    openssl('pkcs8', '-topk8', '-nocrypt', '-in', root/'server.key', '-outform', 'DER', '-out', root/'agent-tls.pk8')
    if purpose == 'agent':
        openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=rss-mdm-agent',
                '-keyout', root/'agent.key', '-outform', 'DER', '-out', root/'agent.der')
        openssl('pkcs8', '-topk8', '-nocrypt', '-in', root/'agent.key', '-outform', 'DER', '-out', root/'agent.pk8')
    private(root/'leaf-issuer.json', dict(certificate=str(root/'issuer.pem'), key=str(root/'issuer.key'), password=None))
    for path in root.iterdir():
        path.chmod(0o600)


def offline(root, case_root, env, purpose):
    """Bind shared immutable issuer material to the case's tenant and protocol."""
    if purpose == 'agent':
        config = dict(mode='step_ca', endpoint=dict(listen='127.0.0.1:0', origin='https://mdm.example.test:9445',
            certificate_file=str(root/'server.crt'), private_key_file=str(root/'agent-tls.pk8')), lifetime=dict(mode='standard'))
        origin = config['endpoint']['origin']
    else:
        config = json.loads((case_root/(purpose+'.json')).read_text())
        config.pop('ca_certificate_file', None)
        config.pop('ca_private_key_file', None)
        origin = config['management']['origin']
    tenant = json.loads((case_root/'case.json').read_text())['tenant']
    issuer = certificate_der(root/'issuer.pem')
    digest = hashlib.sha256(issuer).hexdigest()
    encode = lambda data: base64.b64encode(data).decode()
    provisioner = 'rss' if purpose == 'apple' else 'rss-'+purpose
    trust_value = dict(version=1, origin=origin, tenant=tenant, purpose=purpose, revision=1, issuers=[dict(
        digest=digest, mode='active', certificate=encode(issuer), root=encode(certificate_der(root/'root.pem')),
        crl=encode((root/'issuer.crl.der').read_bytes()), root_crl=encode((root/'root.crl.der').read_bytes()),
        provisioner=provisioner, kid='' if purpose == 'apple' else purpose+'-t2-key')])
    config['trust_file'] = str(private(root/(purpose+'-trust.json'), trust_value))
    if purpose == 'apple':
        config['webhooks'][0]['issuer'] = digest
    private(case_root/('agent-pki.json' if purpose == 'agent' else purpose+'.json'), config)
    # Construction metadata only: ordinary seeds never contact a signing provider.
    provider = dict(purpose=purpose, issuer=digest, origin='https://localhost:1',
        tls_root_file=str(root/'root.pem'), provisioner='rss-'+purpose, kid=purpose+'-t2-key',
        provisioner_key_file=str(root/'provisioner.pk8'))
    if purpose == 'apple':
        provider['scep_url'] = 'https://localhost:1/scep/rss'
    path = case_root/'device-pki.json'
    providers = json.loads(path.read_text()) if path.exists() else []
    private(path, [p for p in providers if p['purpose'] != purpose] + [provider])
    env['MDM_'+purpose.upper()+'_PKI_FIXTURES'] = str(root)


@contextmanager
def running(root, env, *, case, windows=False, agent=False, agent_origin=None, agent_template=None, windows_template=None, compose_file=None, providers=None, generation=None, configuration_devices=0, materials=(), owner_root=None):
    import shutil
    case_root=Path(root).resolve()
    purpose='agent' if agent else 'windows'
    if agent and windows: raise RuntimeError('one CA database per device purpose is required')
    root=case_root/'pki'/(purpose+('-'+generation if generation else ''));root.mkdir(mode=0o700,parents=True)
    for name in ('ca.crt','server.crt','case.json'):
        shutil.copyfile(case_root/name,root/name);(root/name).chmod(0o600)
    provider=Provider(root,hashlib.sha256((case+':'+purpose+(':'+generation if generation else '')).encode()).hexdigest()[:20], compose_file=compose_file, providers=providers, owner_root=owner_root);step=binary('step')
    subprocess.run(['openssl','pkcs8','-topk8','-nocrypt','-in',str(case_root/'server.key'),'-outform','DER',
                    '-out',str(root/'agent-tls.pk8')],check=True,capture_output=True,timeout=30)
    (root/'agent-tls.pk8').chmod(0o600)
    password=private(root/'step-password',secrets.token_urlsafe(32))
    child={**env,'STEPPATH':str(root/'step')}
    def cli(*args):
        return subprocess.run([str(step),*map(str,args)],env=child,text=True,capture_output=True,timeout=30,check=True).stdout
    cli('ca','init','--deployment-type','standalone','--name','RSS Device PKI T2',
        '--dns','localhost,step-ca,host.docker.internal,'+provider.internal_host,'--address',f"0.0.0.0:{PKI_CA['port']}",
        '--provisioner','rss-admin','--admin-subject','rss-admin','--password-file',password,'--remote-management')
    configuration=root/'step/config/ca.json';config=json.loads(configuration.read_text())
    config['root']=[config['root']]
    config['kms']=dict(type='softkms')
    config['crl']=dict(enabled=True,generateOnRevoke=True,cacheDuration='10m',renewPeriod='1m')
    config['authority']['backdate']='0s'
    private(configuration,config)
    if agent:
        from agent_pki_fixtures import prepare
        prepare(root,configuration,password,configuration_devices=configuration_devices, materials=materials)
    private(root/'leaf-issuer.json', dict(certificate=config['crt'], key=config['key'], password=str(password)))
    root_certificate=Path(config['root'][0]);root_key=root/'step/secrets/root_ca_key'
    offline=root_crl(root,root_certificate,root_key,password)
    isolate_root(root_key,password,offline)
    # The fixture offline key and its password are never mounted into the online CA.
    provider.owner.prepare_inputs(certificates=False)
    try:
        origin=provider.start();provider.wait(origin,'/health',root_certificate)
        admin=['--ca-url',origin,'--root',root_certificate,'--admin-subject','rss-admin',
               '--admin-provisioner','rss-admin','--admin-password-file',password]
        if agent:
            from agent_pki_fixtures import install
            install(root,cli,admin,origin,template_source=agent_template)
        if windows:
            # Disposable actual issuer key is exported only outside the CA mount for adversarial leaves.
            issuer_key=root/'windows-issuer-test.pk8'
            subprocess.run(['openssl','pkcs8','-topk8','-nocrypt','-in',str(root/'step/secrets/intermediate_ca_key'),
                '-passin','file:'+str(password),'-outform','DER','-out',str(issuer_key)],check=True,capture_output=True,timeout=30)
            issuer_key.chmod(0o600)
            key=root/'windows-provisioner.pem'
            subprocess.run(['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out',str(key)],check=True,capture_output=True,timeout=30)
            key.chmod(0o600)
            subprocess.run(['openssl','pkcs8','-topk8','-nocrypt','-in',str(key),'-outform','DER','-out',str(root/'windows-provisioner.pk8')],check=True,capture_output=True,timeout=30)
            (root/'windows-provisioner.pk8').chmod(0o600)
            cli('crypto','jwk','create',root/'windows.pub.json',root/'windows.private.json','--from-pem',key,
                '--alg','RS256','--use','sig','--kid','windows-t2-key','--no-password','--insecure')
            (root/'windows.private.json').unlink()
            (root/'step/templates').mkdir(mode=0o700,exist_ok=True)
            source=Path(windows_template) if windows_template else Path(__file__).resolve().parents[1]/'deployment/windows-leaf.tpl'
            template=private(root/'step/templates/windows-leaf.tpl',source.read_text())
            cli('ca','provisioner','add','rss-windows','--type','JWK','--public-key',root/'windows.pub.json',
                '--x509-template',template,'--disable-renewal','--ssh=false','--x509-default-dur','2160h','--x509-max-dur','2160h',*admin)
        env.update(MDM_STEP_CLI=str(step),MDM_STEP_CA_URL=origin,MDM_STEP_CA_ROOT=str(root_certificate),MDM_PKI_FIXTURES=str(root))
        tenant=json.loads((root/'case.json').read_text())['tenant']
        if agent:
            value=json.loads((root/'agent-pki.json').read_text())
            value.pop('issuer_certificate_file',None)
            value['endpoint']['certificate_file']=str(case_root/'server.crt')
            value['endpoint']['private_key_file']=str(root/'agent-tls.pk8')
            if agent_origin:value['endpoint']['origin']=agent_origin
            value['trust_file']=str(trust(root,'agent',value['endpoint']['origin'],tenant,'rss-agent','agent-t2-key',origin))
            private(case_root/('agent-pki'+('-'+generation if generation else '')+'.json'),value)
        if windows:
            value=json.loads((case_root/'windows.json').read_text())
            value.pop('ca_certificate_file',None);value.pop('ca_private_key_file',None)
            value['trust_file']=str(trust(root,'windows',value['management']['origin'],tenant,'rss-windows','windows-t2-key',origin))
            private(case_root/('windows'+('-'+generation if generation else '')+'.json'),value)
        providers_file=case_root/'device-pki.json'
        authority_entries=json.loads(providers_file.read_text()) if providers_file.exists() else []
        trust_value=json.loads(Path(value['trust_file']).read_text())
        authority_entries.append(dict(purpose=purpose,issuer=trust_value['issuers'][0]['digest'],origin=origin,
            tls_root_file=str(root_certificate),provisioner='rss-'+purpose,kid=purpose+'-t2-key',
            provisioner_key_file=str(root/(purpose+'-provisioner.pk8'))))
        private(providers_file,authority_entries)
        env['MDM_'+purpose.upper()+'_PKI'+('_CANDIDATE' if generation else '')+'_FIXTURES']=str(root)
        if agent and 'pki-recovery' in materials:
            from pki_recovery import recovering
            state = [provider]
            try:
                with recovering(root, state, case, generation, origin, compose_file, providers):
                    yield provider
            finally:
                provider = state[0]
        else:
            yield provider

        provider.check()
    finally:
        with cleanup():
            try: provider.logs()
            finally: provider.reset()
        import shutil
        shutil.rmtree(offline)
