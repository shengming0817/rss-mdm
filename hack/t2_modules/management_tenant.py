"""Installation management admission through CLI bootstrap and real TCP HTTP."""
from contextlib import ExitStack
import json
import os
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


def execute(fixture):
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
    # The registry Audit pool is valid; only the independently configured provisioner is unsafe.
    # Each failed serve must reject before readiness, and the normal host below proves repair.
    for table in ('mdm_audit.receipts', 'rss_audit.records'):
        sql(f'GRANT UPDATE ON {table} TO mdm_identity_provisioning')
        try:
            command('serve', config, accepted=False, reason='AuditAdmission')
        finally:
            sql(f'REVOKE UPDATE ON {table} FROM mdm_identity_provisioning')
    path = private(root / 'runtime.json', config)
    public = command('public-host-config', config)
    require(public == {
        'ui.json': {'canonicalOrigin': config['product_origin'], 'oidcEnabled': True},
        'mdm.json': {'canonicalOrigin': config['product_origin'], 'tenant': business, 'managementTenant': management},
    }, 'public host configuration did not use the installed management tenant')
    foreign = json.loads(json.dumps(config))
    foreign['identity']['tenant_id'] = management
    foreign['listen'] = '127.0.0.1:0'
    command('public-host-config', foreign, accepted=False, reason='input_rejected')
    command('serve', foreign, accepted=False, reason='startup.tenant_binding')
    api = '/api/v1/identity/tenants/' + management
    business_api = '/api/v1/identity/tenants/' + business

    def login(browser, tenant, login_name='admin', secret=password):
        status, _ = browser.call('POST', '/api/v1/identity/tenants/' + tenant + '/login',
                                 dict(login=login_name, password=secret))
        require(status == 200, 'management local login failed: ' + str(status))

    def operations(browser):
        status, value = browser.call('GET', EFFECTIVE)
        require(status == 200 and value['tenantId'] == management, 'management effective grants unavailable')
        return {grant['operation'] for grant in value['grants']}

    def rule(principal, permissions):
        return dict(subject=dict(kind='user', user=dict(instanceId=INSTANCE, tenantId=management, principalId=principal)),
                    grants=[dict(operation=operation, scope=dict(kind='tenant')) for operation in permissions])

    def write(browser, identifier, revision, value, expected=200):
        change = dict(operationId=str(uuid.uuid4()), expectedRevision=revision, value=value)
        status, receipt = browser.call('PUT', RULES + '/' + identifier, change)
        require(status == expected, 'unexpected management rule response: ' + str((status, receipt)))
        return change, receipt

    with ExitStack() as stack:
        host = Host(builds, path, root / 'host',require_ready=False)
        stack.callback(host.close)
        admin = Browser(host, config['product_origin'])
        normal = Browser(host, config['product_origin'])
        login(normal, business)
        require(normal.call('GET','/readyz')[0]==503,'missing baseline dependencies must remain unready')
        status, first_use = normal.call('GET', '/api/v1/settings/first-use')
        require(status == 200 and first_use['tenantId'] == business
                and first_use['saved']['revision'] == 0 and not first_use['complete']
                and not first_use['canComplete'], 'fresh initialized tenant has no authoritative incomplete setup')
        require(normal.call('GET', EFFECTIVE)[0] == 401, 'business session gained installation admission')
        login(admin, management)
        status, host_context = admin.call('GET', '/api/v1/identity-host/tenants/' + management + '/context')
        require(status == 200 and host_context['tenantId'] == management and host_context['principalId'] == ADMIN
                and host_context['navigation']['manageAccounts'] and not host_context['navigation']['manageProviders'],
                'management identity host context unavailable')
        require(normal.call('GET', '/api/v1/identity-host/tenants/' + management + '/context')[0] == 401,
                'business session obtained management identity host context')
        require(operations(admin) == CRUD | {'authorization_read', 'authorization_write', 'identity_accounts_manage', 'tenant_administrator_create'}, 'bootstrap granted unexpected powers')
        for route in ['/api/v1/authorization', '/api/v1/authorization/user-groups', '/api/v1/resources',
                      '/api/v1/devices/device-1/inventory', '/api/v1/runtime/diagnostics', '/api/v1/settings/first-use']:
            require(admin.call('GET', route)[0] in (401, 403), 'management session entered business route: ' + route)
        require(admin.call('GET', business_api + '/accounts')[0] in (401, 403), 'management session managed business accounts')
        require(normal.call('GET', business_api + '/providers')[0] == 200, 'business provider route is not installed')
        require(admin.call('POST', api + '/oidc/' + str(uuid.uuid4()) + '/login', dict(returnTarget='home'))[0] == 403,
                'management tenant started federation')
        require(admin.call('GET', api + '/providers')[0] == 403, 'management session managed IdPs')
        status, account = admin.call('POST', api + '/accounts', dict(login='delegate', password=password))
        require(status == 201, 'existing account API could not add a management user')
        delegate_id = account['principalId']
        delegate = Browser(host, config['product_origin'])
        login(delegate, management, 'delegate')
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
        write(delegate, seeds[management]['id'], 1, None, 403)
        write(admin, str(uuid.uuid4()), 0, rule(delegate_id, ['resource_read']), 403)
        bad_subject = dict(subject=dict(kind='user_group', id=str(uuid.uuid4())), grants=[dict(operation='tenant_read', scope=dict(kind='tenant'))])
        write(admin, str(uuid.uuid4()), 0, bad_subject, 403)
        write(admin, identifier, revision, None)
        require(operations(delegate) == set(), 'revoked grant remained effective')
        from t2_modules.tenant_http import exercise
        exercise(admin, normal, delegate, config, management, business, password, sql, command, common,
                 builds, root, stack, login, write, rule)
        # Membership and account enable state are authoritative on every request.
        for state in ('membership', 'enabled'):
            require(admin.call('POST', api + '/accounts/' + delegate_id + '/' + state, dict(enabled=False))[0] == 200,
                    'account state change failed')
            require(delegate.call('GET', EFFECTIVE)[0] == 401, 'inactive account retained admission')
            require(admin.call('POST', api + '/accounts/' + delegate_id + '/' + state, dict(enabled=True))[0] == 200,
                    'account state restore failed')
            login(delegate, management, 'delegate')
        require(delegate.call('POST', api + '/session/logout')[0] == 204, 'management logout failed')
        require(delegate.call('GET', EFFECTIVE)[0] == 401, 'logged out session survived')
        # Same origin has one cookie: logging into the business tenant changes admission.
        login(admin, business)
        require(admin.call('GET', EFFECTIVE)[0] == 401, 'session switch retained management admission')
        business_rule = rule(ADMIN, ['tenant_read'])
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
        recovery = dict(initialization[management], login=None, password_file=str(private(root / 'recovered-password', new_password)))
        command('recover-password', recovery)
        require(admin.call('GET', EFFECTIVE)[0] == 401, 'recovery retained old session')
        login(admin, management, secret=new_password)
        require(operations(admin) == CRUD | {'authorization_read', 'authorization_write', 'identity_accounts_manage', 'tenant_administrator_create'}, 'password recovery changed grants')
        # Restart preserves persisted identity, grants and active management session.
        host.close()
        host = Host(builds, path, root / 'restarted',require_ready=False)
        stack.callback(host.close)
        admin.host = host
        require(operations(admin) == CRUD | {'authorization_read', 'authorization_write', 'identity_accounts_manage', 'tenant_administrator_create'}, 'restart lost management admission')
    print('management installation/bootstrap/accounts/independent CRUD/isolation/CAS/revocation/recovery/restart passed', flush=True)
