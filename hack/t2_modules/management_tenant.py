"""Installation management admission through CLI bootstrap and real TCP HTTP."""
from contextlib import ExitStack, contextmanager
import json
import os
from pathlib import Path
from types import SimpleNamespace
import uuid
from candidate_fixture import ADMIN, INSTANCE, installation
from t2_database import DatabasePool
from t2_environment import private
from t2_fixtures import RunFixtures
from t2_hosts import Host
from t2_model import ROOT
from t2_processes import subprocess
from build_run import lease_fds
from verification_result import require
from t2_modules.tenants import Browser, HostProcesses

CRUD = {'tenant_create', 'tenant_read', 'tenant_update', 'tenant_delete'}
RULES = '/api/v1/tenant-administration/authorization/rules'
EFFECTIVE = '/api/v1/tenant-administration/authorization'


def bootstrap(fixture):
    root = fixture.root
    pool = SimpleNamespace(owner=fixture.owner)
    pool.database_config = lambda *args: DatabasePool.database_config(pool, *args)
    builds = SimpleNamespace(processes=HostProcesses(), executables={'rss-mdm': fixture.binary})
    password = 'Fixture-only-management-password-2026!'
    password_file = private(root / 'account-password', password)
    business = str(uuid.uuid4())
    database = pool.database_config(root, fixture.database)
    common = dict(database=database, installation=installation())

    def sql(statement):
        return fixture.owner.sql(statement, fixture.database).strip()

    def command(verb, value, accepted=True, reason=None):
        path = private(root / (verb + '.json'), value)
        result = subprocess.run([fixture.binary, verb, '--config', str(path)], cwd=ROOT,
                                pass_fds=lease_fds(), capture_output=True, text=True, timeout=75)
        require((result.returncode == 0) == accepted, 'management CLI failed: ' + verb + ': ' + result.stderr)
        if reason is not None:
            require(reason in result.stderr, 'wrong management failure stage: ' + result.stderr)
        return json.loads(result.stdout) if result.stdout.strip() else None

    command('migrate', common)
    management = sql('SELECT management_tenant_id FROM public.mdm_installation')
    require(sql('SELECT count(*) FROM identity_authority.accounts') == '0', 'installation seeded credentials')
    require(sql('SELECT count(*) FROM mdm_access.authorization_rules') == '0', 'installation seeded privileges')
    reserved = command('tenant-get', dict(**common, tenant_id=management))
    require(reserved['management'] and not reserved['deletable'] and reserved['currentEpoch'] == 1,
            'reserved tenant binding invalid')
    sql(f"SELECT public.create_new_tenant('{uuid.UUID(business)}',1,NULL,NULL)")
    seeds = {}
    initialization = {}
    for tenant in (business, management):
        account = dict(database=pool.database_config(root, fixture.database, 'mdm_identity_maintenance', 'identity-maintenance-fixture'),
                       installation=installation(), tenant_id=tenant, expected_epoch=1,
                       principal_id=ADMIN, login='admin', password_file=str(password_file))
        command('initialize', account)
        value = dict(database=pool.database_config(root, fixture.database, 'mdm_access', 'access-fixture'),
                     identityDatabase=pool.database_config(root, fixture.database, 'mdm_identity_runtime', 'identity-runtime-fixture'),
                     audit={'mode': 'plain'}, installation=installation(), expectedEpoch=1,
                     login='admin', passwordFile=str(password_file), operationId=str(uuid.uuid4()),
                     user=dict(instanceId=INSTANCE, tenantId=tenant, principalId=ADMIN))
        seeds[tenant] = command('initialize-authorization', value)
        initialization[tenant] = account

    config = RunFixtures.runtime_config(pool, root, fixture.database, business,
        native_key=os.environ['MDM_NATIVE_PROTECTION_KEY_FILE'],
        recovery_credentials=fixture.recovery_credentials)
    config['agent_pki'] = {'mode': 'disabled'}
    # Install business federation routes so management denial cannot be a missing-route 404.
    state_key = private(root / 'oidc-state-key', 'ab' * 32)
    credential_key = private(root / 'oidc-credential-key', 'cd' * 32)
    config['identity']['oidc'] = dict(group_facts_max_age_seconds=300, state_key_file=str(state_key),
        active_credential_key='current', credential_keys={'current':str(credential_key)},
        return_targets={'home':'https://mdm.example.test/done'}, private_providers=[],
        assurance_profiles=[dict(tenant_id=business,issuer='https://idp.example.invalid',client_id='mdm',keycloak_totp=False)])
    config['tenant_administration'] = dict(
        registry_database=pool.database_config(root, fixture.database, 'mdm_tenant_registry', 'tenant-registry-fixture'),
        provisioning_database=pool.database_config(root, fixture.database, 'mdm_identity_provisioning', 'identity-provisioning-fixture'),
        fingerprint_key_file=str(private(root / 'tenant-operation-key', 'x' * 32)))
    path = private(root / 'runtime.json', config)
    public = command('public-host-config', config)
    require(public == {
        'ui.json': {'canonicalOrigin': config['product_origin'], 'oidcEnabled': True},
        'mdm.json': {'serviceId': INSTANCE, 'canonicalOrigin': config['product_origin'], 'tenant': business, 'managementTenant': management},
    }, 'public host configuration did not use the installed management tenant')
    foreign = json.loads(json.dumps(config))
    foreign['identity']['tenant_id'] = management
    foreign['listen'] = '127.0.0.1:0'
    command('public-host-config', foreign, accepted=False, reason='input_rejected')
    command('serve', foreign, accepted=False, reason='startup.tenant_binding')
    with ExitStack() as stack:
        host = Host(builds, path, root / 'bootstrap-host', require_ready=False)
        stack.callback(host.close)
        admin = Browser(host, config['product_origin'])
        require(admin.call('POST', f'/api/v1/identity/tenants/{management}/login', dict(login='admin', password=password))[0] == 200, 'bootstrap login failed')
        status, value = admin.call('GET', EFFECTIVE)
        require(status == 200 and {g['operation'] for g in value['grants']} == CRUD | {'authorization_read','authorization_write','identity_accounts_manage','tenant_administrator_create'}, 'bootstrap granted unexpected powers')

@contextmanager
def management_host(fixture):
    """One host consumes the existing runner-owned management and business credentials."""
    root = fixture.root
    case = json.loads(Path(fixture.env['MDM_CASE_CONTEXT']).read_text())
    source = json.loads((root / 'management-session.json').read_text())
    management, business = source['tenant'], case['tenant']
    config = json.loads(Path(fixture.env['MDM_TEST_CONFIG']).read_text())
    pool = SimpleNamespace(owner=fixture.owner)
    pool.database_config = lambda *args: DatabasePool.database_config(pool, *args)
    database = pool.database_config(root, fixture.database)
    common = dict(database=database, installation=installation())
    config['agent_pki'] = {'mode':'disabled'}
    config['tenant_administration'] = dict(
        registry_database=pool.database_config(root, fixture.database, 'mdm_tenant_registry','tenant-registry-fixture'),
        provisioning_database=pool.database_config(root, fixture.database, 'mdm_identity_provisioning','identity-provisioning-fixture'),
        fingerprint_key_file=str(private(root / 'tenant-operation-key','x'*32)))
    password = (root / 'account-password').read_text()
    builds = SimpleNamespace(processes=HostProcesses(), executables={'rss-mdm':fixture.binary})
    def sql(statement):
        return fixture.owner.sql(statement, fixture.database).strip()
    def command(verb, value, accepted=True, reason=None):
        path = private(root / (verb + '.json'), value)
        result = subprocess.run([fixture.binary,verb,'--config',str(path)],cwd=ROOT,pass_fds=lease_fds(),capture_output=True,text=True,timeout=75)
        require((result.returncode == 0) == accepted, verb + ': ' + result.stderr)
        if reason is not None: require(reason in result.stderr, 'unexpected failure: ' + result.stderr)
        return json.loads(result.stdout) if result.stdout.strip() else None
    with ExitStack() as stack:
        path = private(root / 'management-runtime.json', config)
        host = Host(builds,path,root/'management-host',require_ready=False)
        stack.callback(host.close)
        def browser(tenant, credential):
            value=Browser(host,config['product_origin'])
            value.cookie='__Host-identity-session='+credential
            require(value.call('GET',f'/api/v1/identity/tenants/{tenant}/session')[0]==200,'prepared session rejected')
            return value
        admin=browser(management,source['credential'])
        normal=browser(business,(root/f'credential-{business}-admin').read_text())
        delegate=None; delegate_id=None; delegate_login=None
        if (root/'management-delegate.json').exists():
            prepared=json.loads((root/'management-delegate.json').read_text())
            delegate=browser(management,prepared['credential'])
            delegate_id=prepared['principal'];delegate_login=prepared['login']
        business_actor=next(a for a in case['actors'] if a['tenant']==business and a['role']=='admin')
        def login(browser,tenant,login_name=None,secret=password):
            name=login_name if login_name is not None else source['login'] if tenant==management else business_actor['login']
            require(browser.call('POST',f'/api/v1/identity/tenants/{tenant}/login',dict(login=name,password=secret))[0]==200,'local login failed')
        def operations(browser):
            status,value=browser.call('GET',EFFECTIVE)
            require(status==200 and value['tenantId']==management,'management grants unavailable')
            return {g['operation'] for g in value['grants']}
        def rule(principal,permissions):
            return dict(subject=dict(kind='user',user=dict(instanceId=INSTANCE,tenantId=management,principalId=principal)),grants=[dict(operation=operation,scope=dict(kind='tenant')) for operation in permissions])
        def write(browser,identifier,revision,value,expected=200):
            change=dict(operationId=str(uuid.uuid4()),expectedRevision=revision,value=value)
            status,receipt=browser.call('PUT',RULES+'/'+identifier,change)
            require(status==expected,'management rule response: '+str((status,receipt)))
            return change,receipt
        yield SimpleNamespace(root=root,stack=stack,host=host,path=path,pool=pool,config=config,builds=builds,
            sql=sql,command=command,common=common,password=password,management=management,business=business,
            admin=admin,normal=normal,delegate=delegate,delegate_id=delegate_id,delegate_login=delegate_login,
            login=login,operations=operations,rule=rule,write=write,business_actor=business_actor)

def http_authority(fixture):
    with management_host(fixture) as h:
        root,config,builds,sql,command,common,password = h.root,h.config,h.builds,h.sql,h.command,h.common,h.password
        management,business,admin,normal,delegate = h.management,h.business,h.admin,h.normal,h.delegate
        delegate_id,delegate_login,login,write,rule,operations = h.delegate_id,h.delegate_login,h.login,h.write,h.rule,h.operations
        api='/api/v1/identity/tenants/'+management
        business_api='/api/v1/identity/tenants/'+business
        protected=json.loads(sql(f"SELECT jsonb_build_object('id',r.id,'revision',r.revision) FROM mdm_access.authorization_initializations i JOIN mdm_access.authorization_rules r ON(r.tenant_id,r.instance)=(i.tenant_id,i.instance) AND r.document->'subject'->'user'->>'principalId'=i.principal::text WHERE i.tenant_id='{management}' AND i.instance='{INSTANCE}'"))
        status, host_context = admin.call('GET', '/api/v1/identity-host/tenants/' + management + '/context')
        require(status == 200 and host_context['tenantId'] == management and host_context['principalId'] == ADMIN
                and host_context['navigation']['manageAccounts'] and not host_context['navigation']['manageProviders'],
                'management identity host context unavailable')
        require(normal.call('GET', '/api/v1/identity-host/tenants/' + management + '/context')[0] == 401,
                'business session obtained management identity host context')
        for route in ['/api/v1/authorization', '/api/v1/authorization/user-groups', '/api/v1/resources',
                      '/api/v1/devices/device-1/inventory', '/api/v1/runtime/diagnostics', '/api/v1/settings/first-use']:
            require(admin.call('GET', route)[0] in (401, 403), 'management session entered business route: ' + route)
        require(admin.call('GET', business_api + '/accounts')[0] in (401, 403), 'management session managed business accounts')
        require(operations(delegate) == set(), 'new account automatically gained privileges')
        require(delegate.call('GET', api + '/accounts')[0] == 403, 'delegate automatically became account manager')
        identifier = str(uuid.uuid4())
        revision = 0
        for permission in sorted(CRUD):
            change, receipt = write(admin, identifier, revision, rule(delegate_id, [permission]))
            revision = receipt['revision']
            require(operations(delegate) == {permission}, 'CRUD permissions were coupled')
            require(admin.call('PUT', RULES + '/' + identifier, change) == (200, receipt), 'rule replay changed receipt')
        _, receipt = write(admin, identifier, revision, rule(delegate_id, ['tenant_read', 'authorization_read', 'authorization_write']))
        revision = receipt['revision']
        require(delegate.call('GET', RULES)[0] == 200, 'explicit authorization delegation failed')
        write(delegate, protected['id'], protected['revision'], None, 403)
        write(admin, str(uuid.uuid4()), 0, rule(delegate_id, ['resource_read']), 403)
        bad_subject = dict(subject=dict(kind='user_group', id=str(uuid.uuid4())), grants=[dict(operation='tenant_read', scope=dict(kind='tenant'))])
        write(admin, str(uuid.uuid4()), 0, bad_subject, 403)
        write(admin, identifier, revision, None)
        require(operations(delegate) == set(), 'revoked grant remained effective')

def account_lifecycle(fixture):
    with management_host(fixture) as h:
        root,config,builds,sql,command,common,password = h.root,h.config,h.builds,h.sql,h.command,h.common,h.password
        management,business,admin,normal,delegate = h.management,h.business,h.admin,h.normal,h.delegate
        delegate_id,delegate_login,login,write,rule,operations = h.delegate_id,h.delegate_login,h.login,h.write,h.rule,h.operations
        api='/api/v1/identity/tenants/'+management
        business_api='/api/v1/identity/tenants/'+business
        delegate_login='lifecycle-delegate'
        status,account=admin.call('POST',api+'/accounts',dict(login=delegate_login,password=password))
        require(status==201,'account API failed to create management subject')
        delegate_id=account['principalId'];delegate=Browser(h.host,config['product_origin'])
        login(delegate,management,delegate_login)
        require(operations(delegate)==set(),'new account gained implicit management powers')
        # Membership and account enable state are authoritative on every request.
        for state in ('membership', 'enabled'):
            require(admin.call('POST', api + '/accounts/' + delegate_id + '/' + state, dict(enabled=False))[0] == 200,
                    'account state change failed')
            require(delegate.call('GET', EFFECTIVE)[0] == 401, 'inactive account retained admission')
            require(admin.call('POST', api + '/accounts/' + delegate_id + '/' + state, dict(enabled=True))[0] == 200,
                    'account state restore failed')
            login(delegate, management, delegate_login)
        require(delegate.call('POST', api + '/session/logout')[0] == 204, 'management logout failed')
        require(delegate.call('GET', EFFECTIVE)[0] == 401, 'logged out session survived')
        # Same origin has one cookie: logging into the business tenant changes admission.
        login(admin, business)
        require(admin.call('GET', EFFECTIVE)[0] == 401, 'session switch retained management admission')
        business_rule = rule(h.business_actor['principal'], ['tenant_read'])
        business_rule['subject']['user']['tenantId'] = business
        status, _ = admin.call('PUT', '/api/v1/authorization/rules/' + str(uuid.uuid4()),
                               dict(operationId=str(uuid.uuid4()), expectedRevision=0, value=business_rule))
        require(status == 403, 'business tenant received tenant-management grant')
        login(admin, management)
        require(admin.call('POST', api + '/accounts/' + ADMIN + '/enabled', dict(enabled=False))[0] == 403,
                'initial account manager could be disabled')
        require(admin.call('POST', api + '/accounts/' + ADMIN + '/membership', dict(enabled=False))[0] == 403,
                'initial account manager membership could be removed')
        new_password = 'Fixture-only-recovered-management-2026!'
        recovery = dict(database=h.pool.database_config(root, fixture.database, 'mdm_identity_maintenance','identity-maintenance-fixture'), installation=installation(), tenant_id=management, expected_epoch=1, principal_id=ADMIN, login=None, password_file=str(private(root / 'recovered-password', new_password)))
        command('recover-password', recovery)
        require(admin.call('GET', EFFECTIVE)[0] == 401, 'recovery retained old session')
        login(admin, management, secret=new_password)
        require(operations(admin) == CRUD | {'authorization_read', 'authorization_write', 'identity_accounts_manage', 'tenant_administrator_create'}, 'password recovery changed grants')
        # Restart preserves persisted identity, grants and active management session.
        h.host.close()
        host = Host(builds, h.path, root / 'restarted',require_ready=False)
        h.stack.callback(host.close)
        admin.host = host
        require(operations(admin) == CRUD | {'authorization_read', 'authorization_write', 'identity_accounts_manage', 'tenant_administrator_create'}, 'restart lost management admission')

def assembly_admission(fixture):
    with management_host(fixture) as h:
        h.host.close()
        for table in ('mdm_audit.receipts','rss_audit.records'):
            h.sql(f'GRANT UPDATE ON {table} TO mdm_identity_provisioning')
            try: h.command('serve',h.config,accepted=False,reason='startup.identity: Audit')
            finally: h.sql(f'REVOKE UPDATE ON {table} FROM mdm_identity_provisioning')
        config=json.loads(json.dumps(h.config))
        state_key=private(h.root/'oidc-state-key','ab'*32)
        credential_key=private(h.root/'oidc-credential-key','cd'*32)
        config['identity']['oidc']=dict(group_facts_max_age_seconds=300,state_key_file=str(state_key),active_credential_key='current',credential_keys={'current':str(credential_key)},return_targets={'home':'https://mdm.example.test/done'},private_providers=[],assurance_profiles=[dict(tenant_id=h.business,issuer='https://idp.example.invalid',client_id='mdm',keycloak_totp=False)])
        host=Host(h.builds,private(h.root/'federation-runtime.json',config),h.root/'federation-host',require_ready=False)
        h.stack.callback(host.close)
        h.admin.host=host;h.normal.host=host
        require(h.normal.call('GET',f'/api/v1/identity/tenants/{h.business}/providers')[0]==200,'business provider route missing')
        require(h.admin.call('GET',f'/api/v1/identity/tenants/{h.management}/providers')[0]==403,'management entered federation')
        require(h.admin.call('POST',f'/api/v1/identity/tenants/{h.management}/oidc/{uuid.uuid4()}/login',dict(returnTarget='home'))[0]==403,'management started federation')
