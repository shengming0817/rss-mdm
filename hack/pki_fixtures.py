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


@contextmanager
def running(root, env, *, case, windows=False, agent=False, agent_origin=None, agent_template=None, windows_template=None, compose_file=None, providers=None, generation=None, configuration_devices=0, materials=()):
    import shutil
    case_root=Path(root).resolve()
    purpose='agent' if agent else 'windows'
    if agent and windows: raise RuntimeError('one CA database per device purpose is required')
    root=case_root/'pki'/(purpose+('-'+generation if generation else ''));root.mkdir(mode=0o700,parents=True)
    for name in ('ca.crt','server.crt','case.json'):
        shutil.copyfile(case_root/name,root/name);(root/name).chmod(0o600)
    provider=Provider(root,hashlib.sha256((case+':'+purpose+(':'+generation if generation else '')).encode()).hexdigest()[:20], compose_file=compose_file, providers=providers);step=binary('step')
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
            # The case first creates durable issuance evidence, then explicitly triggers recovery.
            import threading, contextvars
            stopped = threading.Event()
            failures = []
            def recover_after_request():
                nonlocal provider
                while not stopped.wait(.1):
                    if not (root/'agent-recovery-request').exists():
                        continue
                    try:
                        provider.fence()
                        from agent_pki_fixtures import restore
                        restore(root)
                        standby = Provider(root, hashlib.sha256((case+':agent-standby'+(':'+generation if generation else '')).encode()).hexdigest()[:20], compose_file=compose_file, providers=providers, internal_host=provider.internal_host)
                        standby.promote_from(provider, origin)
                        previous = provider
                        provider = standby
                        previous.reset()
                        (root/'agent-recovery-complete').write_text('restored and promoted after issuance\n')
                    except BaseException as error:
                        failures.append(error)
                        (root/'agent-recovery-failed').write_text(type(error).__name__)
                    return
            recovery_context = contextvars.copy_context()
            recovery = threading.Thread(target=lambda: recovery_context.run(recover_after_request), name='case-ca-recovery')
            recovery.start()
            try:
                yield provider
            finally:
                stopped.set()
                recovery.join()
            if failures:
                raise RuntimeError('case CA recovery failed') from failures[0]
            if not (root/'agent-recovery-complete').exists():
                raise RuntimeError('case did not exercise CA recovery')
        else:
            yield provider
        provider.check()
    finally:
        with cleanup():
            try: provider.logs()
            finally: provider.reset()
        import shutil
        shutil.rmtree(offline)
