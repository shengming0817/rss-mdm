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
import urllib.parse
import uuid
ROOT = Path(__file__).resolve().parents[1]
SECURITY_GROUP = '7bb94be2-8f62-4bd6-93e7-7ec1f79b2363'
DEPARTMENT = {'version':1,'sourceRevision':'mdm-r1','nodes':[{'id':'root','displayName':'Company','parentId':None},{'id':'engineering','displayName':'Engineering','parentId':'root'},{'id':'team','displayName':'Team','parentId':'engineering'}],'memberships':['team']}

def configure_department(origin, context):
    credentials=urllib.parse.urlencode({'client_id':'admin-cli','grant_type':'password','username':'fixture-operator','password':'fixture-operator-password'}).encode()
    with urllib.request.urlopen(urllib.request.Request(origin+'/realms/master/protocol/openid-connect/token',data=credentials),context=context,timeout=10) as response: token=json.load(response)['access_token']
    def admin(method,path,value=None):
        request=urllib.request.Request(origin+'/admin/realms/mdm'+path,method=method,data=None if value is None else json.dumps(value).encode(),headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
        with urllib.request.urlopen(request,context=context,timeout=10) as response: return json.loads(response.read() or b'null')
    profile=admin('GET','/users/profile')
    profile['attributes']=[a for a in profile['attributes'] if a['name']!='organization_snapshot']+[{'name':'organization_snapshot','multivalued':False,'permissions':{'view':['admin'],'edit':['admin']},'validations':{'length':{'max':32768}}}]
    admin('PUT','/users/profile',profile)
    if next(a for a in admin('GET','/users/profile')['attributes'] if a['name']=='organization_snapshot')['permissions']!={'view':['admin'],'edit':['admin']}: raise RuntimeError('department attribute permissions drift')
    for user in admin('GET','/users?username=alice&exact=true'):
        user.setdefault('attributes',{})['organization_snapshot']=[json.dumps(DEPARTMENT)]
        admin('PUT','/users/'+user['id'],user)


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
        realm['groups']=[{'id':SECURITY_GROUP,'name':SECURITY_GROUP}]
        realm['users'][0]['groups']=['/'+SECURITY_GROUP]
        realm['clients'][0]['protocolMappers']=[
            {'name':'stable-security-group-codes','protocol':'openid-connect','protocolMapper':'oidc-group-membership-mapper','config':{'claim.name':'groups','full.path':'false','id.token.claim':'true','access.token.claim':'false'}},
            {'name':'department-snapshot','protocol':'openid-connect','protocolMapper':'oidc-usermodel-attribute-mapper','config':{'user.attribute':'organization_snapshot','claim.name':'organization_snapshot','jsonType.label':'JSON','multivalued':'false','aggregate.attrs':'false','id.token.claim':'true','access.token.claim':'false'}}]
        realm.update(json.loads((ROOT/'fixtures/keycloak-step-up.json').read_text()))
        realm_file=root/'realm.json';realm_file.write_text(json.dumps(realm));realm_file.chmod(0o644)
        containers.append(name)
        docker('run','-d','--name',name,'--network','container:'+namespace,
            '-e','KC_BOOTSTRAP_ADMIN_USERNAME=fixture-operator','-e','KC_BOOTSTRAP_ADMIN_PASSWORD=fixture-operator-password',
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
        configure_department(origin,context)
        yield dict(MDM_TEST_SSO_ISSUER=issuer,MDM_TEST_SSO_CA=str(root/'ca.crt'),MDM_TEST_SSO_CONTAINER=name)
    finally:
        failures=[]
        for owned in reversed(containers):
            try:docker('rm','-f',owned)
            except Exception:failures.append(owned)
        if failures:
            if sys.exception():sys.exception().add_note('enterprise fixture cleanup failed')
            else:raise RuntimeError('enterprise fixture cleanup failed')
