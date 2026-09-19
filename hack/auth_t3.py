#!/usr/bin/env python3
"""Fixed MDM binary + reused UI + real Chromium product acceptance (#2364)."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
import uuid
from candidate_runtime import Candidate, Stage, ROOT, TENANT, ADMIN, INSTANCE, docker, image_identity, require, sha, wait
from candidate_smoke import Browser

SCENARIOS = ('local_ui','account_ui','inventory','permissions','cookie_csrf','refresh','logout','logout_all',
             'account_disabled','membership_removed','restart','isolation','enterprise','unknown_subject',
             'private_binding','idp_down','pg_down','installation_mismatch','safe_logs')
PLAYWRIGHT_INTEGRITY='sha512-9bW6zvX/m0lEbgTKJ6YppOKx8H3VOPBMOCFh2irXFOT4BbHgrx5hPjwJYLT40Lu+4qtD36qKc/Hn56StUW57IA=='

def validate_checks(checks):
    require(set(checks)==set(SCENARIOS) and all(v is True for v in checks.values()),'incomplete browser acceptance')

def safe_evidence(value, private_values):
    encoded=json.dumps(value)
    require(not any(secret and secret in encoded for secret in private_values),'sensitive evidence rejected')
    return value

def enterprise(stack):
    """Production private access, not the integration-only loopback adapter."""
    stack.password=secrets.token_urlsafe(28)
    stack.client_secret=secrets.token_urlsafe(32)
    stack.idp_password=secrets.token_urlsafe(28)
    (stack.operator_root/'account-password').write_text(stack.password)
    stack.idp=stack.name+'-idp'
    issuer='https://idp.example.test:8443/realms/mdm'
    realm={'realm':'mdm','enabled':True,'sslRequired':'all','loginWithEmailAllowed':False,
           'clients':[{'clientId':'mdm','secret':stack.client_secret,'publicClient':False,'standardFlowEnabled':True,
                       'redirectUris':['https://mdm.example.test/api/v2/oidc/callback'],
                       'attributes':{'pkce.code.challenge.method':'S256'}}],
           'users':[{'id':'external-'+name,'username':name,'enabled':True,'emailVerified':True,
                     'email':name+'@example.test','firstName':name,'lastName':'Fixture',
                     'credentials':[{'type':'password','value':stack.idp_password,'temporary':False}]} for name in ['alice','unknown']]}
    (stack.root/'realm.json').write_text(json.dumps(realm));(stack.root/'realm.json').chmod(0o644)
    stack.created.append(stack.idp)
    docker('run','-d','--name',stack.idp,'--network',stack.network,'--network-alias','idp.example.test',
           '-v',str(stack.root/'realm.json')+':/opt/keycloak/data/import/mdm.json:ro',
           '-v',str(stack.root)+':/fixture:ro',stack.providers['keycloak'],'start-dev','--import-realm',
           '--http-enabled=false','--hostname=https://idp.example.test:8443',
           '--https-certificate-file=/fixture/server.crt','--https-certificate-key-file=/fixture/server.key',stage=Stage.SERVER)
    address=docker('inspect','--format','{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}',stack.idp,stage=Stage.PORT)
    ip=ipaddress.ip_address(address)
    require(any(ip in ipaddress.ip_network(n) for n in ['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16']),'fixture needs private Docker network')
    for name in ['state','credential']:
        path=stack.runtime/name;path.write_text(secrets.token_hex(32));path.chmod(0o600)
    stack.config['identity']['oidc']={
        'group_facts_max_age_seconds':300,'state_key_file':'/run/mdm/state','active_credential_key':'current',
        'credential_keys':{'current':'/run/mdm/credential'},'return_targets':{'resume':'https://mdm.example.test/auth/resume'},
        'assurance_profiles':[],
        'private_providers':[{'tenant_id':TENANT,'issuer':issuer,'client_id':'mdm','cidrs':[address+'/32']}]}
    stack.config['bindings'][0].update(identity_management=['accounts','providers'],management=['group_read','group_write','release_read'])
    stack.issuer=issuer

def seed_inventory(stack):
    registration='99999999-9999-4999-8999-999999999991';epoch='99999999-9999-4999-8999-999999999992'
    coverage=json.dumps(dict(id='device-basics',version='1',definition='model-os',format='utf8-v1'),separators=(',',':'))
    scope=json.dumps(dict(tenant=TENANT,object=registration,registration=registration,source='mdm.windows',dataset='inventory',epoch=epoch),separators=(',',':'))
    stack.sql(f"""
    INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,expires_at) VALUES('{TENANT}','99999999-9999-4999-8999-999999999993','2364-synthetic-read-fixture','{INSTANCE}','device-1','enrollment','consumed',clock_timestamp()+interval '1 hour');
    INSERT INTO mdm_access.requests(tenant_id,id,grant_id) VALUES('{TENANT}','99999999-9999-4999-8999-999999999994','99999999-9999-4999-8999-999999999993');
    INSERT INTO mdm_access.devices VALUES('{TENANT}','device-1');
    INSERT INTO mdm_access.registrations VALUES('{TENANT}','{registration}','device-1','mdm',1,'99999999-9999-4999-8999-999999999994','active');
    INSERT INTO mdm_access.credentials VALUES('{TENANT}','99999999-9999-4999-8999-999999999995','{registration}','mdm',repeat('a',64),'active');
    INSERT INTO mdm_access.report_sources VALUES('{TENANT}','{registration}','mdm.windows','{epoch}','{coverage}',true);
    INSERT INTO mdm.inventory VALUES('{TENANT}','mdm.observation.v1','inventory-v1','{scope}','{coverage}','device.model','Model-2364','synthetic-2364',1,2);
    """)

def prepare_member(stack):
    browser=Browser(stack.port,stack.root/'ca.crt')
    require(browser.call('POST',f'/api/v2/tenants/{TENANT}/login',dict(login='admin',password=stack.password))[0]==200,'bootstrap login')
    stack.member_password=secrets.token_urlsafe(28)
    status,result=browser.call('POST',f'/api/v2/tenants/{TENANT}/accounts',dict(login='member',password=stack.member_password))
    require(status==201,'bootstrap account')
    stack.member=result['principalId']
    binding=dict(stack.config['bindings'][0]);binding.update(principal_id=stack.member,identity_management=[],management=[],roles=['auditor'])
    stack.config['bindings'].append(binding)
    (stack.runtime/'config.json').write_text(json.dumps(stack.config))
    docker('stop','--time','45',stack.server,stage=Stage.STOP,timeout=55)
    stack.copy_runtime()
    docker('start',stack.server,stage=Stage.SERVER);stack.ready()
    require(browser.call('POST',f'/api/v2/tenants/{TENANT}/session/logout')[0]==204,'bootstrap logout')

def installation_mismatch(stack):
    before=stack.sql("SELECT md5(string_agg(row_to_json(a)::text,',' ORDER BY principal_id)) FROM identity_authority.accounts a")
    ledger=stack.sql("SELECT md5(string_agg(row_to_json(m)::text,',' ORDER BY name)) FROM public.mdm_migrations m")
    value=json.loads((stack.operator_root/'migrate.json').read_text())
    value['installation']['instance_id']=str(uuid.uuid4())
    docker('run','--rm','-i','--network','none','--user','0:0','-v',stack.operator_volume+':/run/mdm',
           '--entrypoint','sh',stack.providers['runtime'],'-ec',
           'cat > /run/mdm/mismatch.json; chown 10001:10001 /run/mdm/mismatch.json; chmod 600 /run/mdm/mismatch.json',
           input=json.dumps(value),stage=Stage.OPERATOR_INPUTS)
    rejected=False
    try:stack.operator('migrate','mismatch.json')
    except Exception as error:
        from candidate_runtime import DockerFailure
        if not isinstance(error,DockerFailure) or error.outcome!='exit':raise
        rejected=True
    require(rejected,'mismatched installation accepted')
    require(stack.sql("SELECT md5(string_agg(row_to_json(a)::text,',' ORDER BY principal_id)) FROM identity_authority.accounts a")==before,'mismatched installation changed accounts')
    require(stack.sql("SELECT md5(string_agg(row_to_json(m)::text,',' ORDER BY name)) FROM public.mdm_migrations m")==ledger,'mismatched installation changed ledger')
    return True

def run(candidate, web_image, tools_image, output):
    require(not output.exists(),'T3 output must be new')
    output.mkdir(parents=True)
    tool=image_identity(tools_image)
    # Use an existing fixed tools artifact; no checkout or reference application runtime needed.
    probe=docker('run','--rm','--network','none','--entrypoint','node',tool['id'],'-e',
                 "console.log(JSON.stringify({version:require('/opt/playwright-core/package.json').version,integrity:require('fs').readFileSync('/opt/playwright-integrity','utf8')}))",stage=Stage.LOAD)
    require(json.loads(probe)==dict(version='1.60.0',integrity=PLAYWRIGHT_INTEGRITY),'browser package mismatch')
    private=[]
    try:
        with Candidate(candidate,web_image,prepare=enterprise,diagnostics=output) as primary:
            prepare_member(primary);seed_inventory(primary)
            mismatch=installation_mismatch(primary)
            with Candidate(candidate,web_image,network=primary.network,host='mdm-other.example.test',
                           instance=str(uuid.uuid4()),tenant='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',diagnostics=output) as other:
                # Same port 443 on distinct private network addresses; host smoke retains 8445.
                for stack in [primary,other]:
                    conf=(stack.root/'nginx.conf').read_text().replace('listen 8445 ssl;','listen 443 ssl;\n        listen 8445 ssl;')
                    (stack.root/'nginx.conf').write_text(conf)
                    docker('exec',stack.gateway,'nginx','-c','/certs/nginx.conf','-s','reload',stage=Stage.GATEWAY)
                private=[primary.password,primary.member_password,primary.idp_password,primary.client_secret]
                params=dict(tenant=TENANT,member=primary.member,adminPassword=primary.password,memberPassword=primary.member_password,
                            idpPassword=primary.idp_password,clientSecret=primary.client_secret,issuer=primary.issuer,
                            server=primary.server,pg=primary.pg,idp=primary.idp,otherPg=other.pg,otherTenant=other.tenant,
                            runtimeVolume=primary.runtime_volume,runtimeImage=primary.providers['runtime'])
                (primary.root/'browser-input.json').write_text(json.dumps(params));(primary.root/'browser-input.json').chmod(0o600)
                (primary.root/'other-ca.crt').write_bytes((other.root/'ca.crt').read_bytes())
                browser_name=primary.name+'-browser';primary.created.append(browser_name)
                script='mkdir -p /root/.pki/nssdb; certutil -N --empty-password -d sql:/root/.pki/nssdb; certutil -A -d sql:/root/.pki/nssdb -n mdm -t "C,," -i /fixture/ca.crt; certutil -A -d sql:/root/.pki/nssdb -n other -t "C,," -i /fixture/other-ca.crt; exec node /runner/auth_t3_browser.mjs'
                raw=docker('run','--name',browser_name,'--network',primary.network,'--shm-size','1g',
                           '-v','/var/run/docker.sock:/var/run/docker.sock','-v',str(primary.root)+':/fixture:ro',
                           '-v',str(ROOT/'hack')+':/runner:ro','--entrypoint','bash',tool['id'],'-ec',script,stage=Stage.SERVER,timeout=1200)
                result=json.loads(raw);result['checks']['installation_mismatch']=mismatch;validate_checks(result['checks'])
                logs={name:docker('logs',name,stage=Stage.LOGS) for name in [primary.server,primary.gateway,other.server,other.gateway]}
                safe_evidence(logs,private+result.pop('privateValues',[]))
                result.update(mdm=primary.manifest,web=primary.web,tools=tool,
                              origins=['https://mdm.example.test','https://mdm-other.example.test'],
                              ca_sha256=[sha(primary.root/'ca.crt'),sha(other.root/'ca.crt')],
                              config_sha256=sha(primary.runtime/'config.json'),gateway_sha256=sha(primary.root/'nginx.conf'),
                              runner_sha256=sha(ROOT/'hack/auth_t3_browser.mjs'),
                              fixture='synthetic device-1 Model-2364, real product authorization and inventory query',
                              exclusions=['real device enrollment/commands/wipe','other IdP profiles','production capacity','legacy environment retirement'])
                (output/'requests.json').write_text(json.dumps(safe_evidence(result.pop('requests'),private),indent=2)+'\n')
                (output/'product.log').write_text('\n'.join(logs.values()))
                result['log_sha256']=sha(output/'product.log');result['requests_sha256']=sha(output/'requests.json')
        # Resource owners have completed cleanup before publishing success.
        result['status']='passed'
        (output/'result.json').write_text(json.dumps(safe_evidence(result,private),indent=2)+'\n')
    except BaseException as error:
        (output/'result.json').unlink(missing_ok=True)
        (output/'failure.json').write_text(json.dumps({'status':'failed','errorClass':type(error).__name__})+'\n')
        raise

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    for key in ['candidate','web-image','tools-image','output']:parser.add_argument('--'+key,required=True)
    args=parser.parse_args()
    run(Path(args.candidate).resolve(),args.web_image,args.tools_image,Path(args.output).resolve())
