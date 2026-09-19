"""Optional enterprise SSO seam. Local authentication runs before this provider starts.

ref: rss-identity b7f34c7 deployment/keycloak-totp.json; Keycloak LoA browser flow.
"""
import contextlib
import json
from pathlib import Path
import ssl
import subprocess
import sys
import time
import urllib.request
import uuid
ROOT = Path(__file__).resolve().parents[1]

def docker(*args):
    return subprocess.check_output(['docker', *args], text=True, timeout=120).strip()

@contextlib.contextmanager
def fixture(root):
    images=json.loads((ROOT/'deployment/providers.lock.json').read_text())
    name='mdm-idp-'+uuid.uuid4().hex[:12]
    containers=[]
    try:
        namespace=name+'-net';containers.append(namespace)
        docker('run','-d','--name',namespace,'-p','127.0.0.1::8443','--entrypoint','sleep',images['runtime'],'infinity')
        port=int(docker('port',namespace,'8443').rsplit(':',1)[1])
        origin=f'https://localhost:{port}'
        realm={'realm':'mdm','enabled':True,'sslRequired':'all','duplicateEmailsAllowed':True,'loginWithEmailAllowed':False,
            'clients':[{'clientId':'mdm','secret':'fixture-secret','publicClient':False,'standardFlowEnabled':True,
                'redirectUris':['https://mdm.example.test/api/v2/oidc/callback'],'attributes':{'pkce.code.challenge.method':'S256'}}],
            'users':[{'username':user,'enabled':True,'email':'same@example.test','emailVerified':True,'firstName':user,'lastName':'Fixture',
                'credentials':[{'type':'password','value':'Fixture-provider-password-2026!','temporary':False},
                    {'type':'otp','userLabel':'fixture-totp','secretData':json.dumps({'value':'fixture-totp-secret-2339'}),
                    'credentialData':json.dumps({'digits':6,'counter':0,'period':30,'algorithm':'HmacSHA1','subType':'totp'})}]} for user in ['alice','bob']]}
        realm.update(json.loads((ROOT/'fixtures/keycloak-step-up.json').read_text()))
        realm_file=root/'realm.json';realm_file.write_text(json.dumps(realm));realm_file.chmod(0o644)
        containers.append(name)
        docker('run','-d','--name',name,'--network','container:'+namespace,
            '-v',str(realm_file)+':/opt/keycloak/data/import/mdm.json:ro',
            '-v',str(root/'server.crt')+':/opt/keycloak/conf/tls.crt:ro',
            '-v',str(root/'server.key')+':/opt/keycloak/conf/tls.key:ro',images['keycloak'],
            'start-dev','--import-realm','--http-enabled=false','--hostname='+origin,
            '--https-certificate-file=/opt/keycloak/conf/tls.crt','--https-certificate-key-file=/opt/keycloak/conf/tls.key')
        context=ssl.create_default_context(cafile=str(root/'ca.crt'))
        issuer=origin+'/realms/mdm';end=time.monotonic()+120
        while True:
            try:
                with urllib.request.urlopen(issuer+'/.well-known/openid-configuration',context=context,timeout=2) as response:
                    if response.status==200:break
            except OSError:pass
            if time.monotonic()>end:raise RuntimeError('enterprise fixture readiness deadline')
            time.sleep(.25)
        yield dict(MDM_TEST_SSO_ISSUER=issuer,MDM_TEST_SSO_CA=str(root/'ca.crt'),MDM_TEST_SSO_CONTAINER=name)
    finally:
        failures=[]
        for owned in reversed(containers):
            try:docker('rm','-f',owned)
            except Exception:failures.append(owned)
        if failures:
            if sys.exception():sys.exception().add_note('enterprise fixture cleanup failed')
            else:raise RuntimeError('enterprise fixture cleanup failed')
