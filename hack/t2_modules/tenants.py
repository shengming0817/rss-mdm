"""Tenant metadata CLI with explicit fixture rows and two isolated product hosts."""
from contextlib import ExitStack
import http.client
from http.cookies import SimpleCookie
import json
import os
import threading
from types import SimpleNamespace
from pathlib import Path
import uuid
from urllib.parse import urlsplit
from candidate_fixture import ADMIN, INSTANCE, installation
from t2_environment import private
from t2_processes import subprocess
from build_run import lease_fds
from t2_hosts import Host
from t2_database import DatabasePool, literal
from t2_fixtures import RunFixtures
from t2_model import ROOT
from verification_result import require


class Browser:
    def __init__(self, host, origin):
        self.host = host
        self.origin = origin
        self.cookie = ''
        self.csrf = None

    def connection(self):
        return http.client.HTTPConnection(self.host.address, timeout=10)

    def call(self, method, path, body=None, extra_headers=None):
        headers = {'Host': urlsplit(self.origin).netloc, 'Origin': self.origin,
                   'X-Identity-Request': '1', 'X-Forwarded-For': '203.0.113.7', 'X-RSS-Public-Origin': self.origin}
        if self.cookie:
            headers['Cookie'] = self.cookie
        if self.csrf:
            headers['X-CSRF-Token'] = self.csrf
        if body is not None:
            headers['Content-Type'] = 'application/json'
        headers.update(extra_headers or {})
        conn = self.connection()
        try:
            conn.request(method, path, json.dumps(body) if body is not None else None, headers)
            response = conn.getresponse()
            raw = response.read()
            value = json.loads(raw) if raw else None
            cookie = SimpleCookie()
            for name, contents in response.getheaders():
                if name.lower() == 'set-cookie':
                    cookie.load(contents)
            if '__Host-identity-session' in cookie:
                self.cookie = '__Host-identity-session=' + cookie['__Host-identity-session'].value
            if isinstance(value, dict) and 'csrfToken' in value:
                self.csrf = value['csrfToken']
            return response.status, value
        finally:
            conn.close()


# Descendants inherit the Python scenario's runner-owned process group.
class HostProcesses:
    def __init__(self):
        self.failed = threading.Event()
    def spawn(self, args, **kwargs):
        return subprocess.Popen([str(a) for a in args], pass_fds=lease_fds(), **kwargs)
    def release(self, child):
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill(); child.wait(timeout=5)
    def check(self):
        require(not self.failed.is_set(), 'tenant host exited unexpectedly')
    def cancel(self):
        self.failed.set()

def metadata_cli(fixture):
    root = fixture.root
    pool = SimpleNamespace(owner=fixture.owner)
    pool.database_config = lambda *args: DatabasePool.database_config(pool, *args)
    builds = SimpleNamespace(processes=HostProcesses(), executables={'rss-mdm':fixture.binary})
    a, b = str(uuid.uuid4()), str(uuid.uuid4())
    password = 'Fixture-only-correct-horse-battery-2026!'
    private(root / 'account-password', password)
    database = pool.database_config(root, fixture.database)
    def sql(query):
        return fixture.owner.sql(query, fixture.database).strip()
    def command(verb, value, *, accepted=True, reason=None):
        path = private(root / (verb + '.json'), value)
        result = subprocess.run([fixture.binary, verb, '--config', str(path)], cwd=ROOT,
                     pass_fds=lease_fds(), capture_output=True, text=True, timeout=75)
        require((result.returncode == 0) == accepted,
                'tenant command failed: ' + verb + ': ' + result.stderr)
        if not accepted and verb == 'serve':
            require('startup.tenant_binding' in result.stderr, 'invalid binding rejected at another stage: ' + result.stderr)
        if reason is not None:
            require(reason in result.stderr, 'unexpected tenant failure: ' + result.stderr)
        return json.loads(result.stdout) if result.stdout.strip() else None
    management = sql('SELECT management_tenant_id FROM public.mdm_installation')
    original = {t['tenantId'] for t in command('tenant-list', dict(database=database, installation=installation()))}
    def create(tenant, name=None, notes=None):
        # Fixture seeding is not a public tenant creation contract.
        sql(f"SELECT public.create_new_tenant('{uuid.UUID(tenant)}',1,{literal(name) if name is not None else 'NULL'},{literal(notes) if notes is not None else 'NULL'})")
        return command('tenant-get', dict(database=database,installation=installation(),tenant_id=tenant))
    # Exercise the public management path before any tenant use is claimed.
    common = dict(database=database, installation=installation())
    c = str(uuid.uuid4())
    created = dict(**common, tenant_id=c, initial_epoch=1, operation_id=str(uuid.uuid4()), name='测试租户', notes='说明')
    first = {'result':create(c, created['name'], created['notes'])}
    require(first['result']['revision'] == 1 and first['result']['deletable'], 'bad unused tenant fixture')
    require(command('tenant-get', dict(**common, tenant_id=c)) == first['result'], 'get differs from create')
    changed = dict(**common, tenant_id=c, expected_revision=1, operation_id=str(uuid.uuid4()), name='新名称')
    second = command('tenant-update', changed)
    require(second['result']['revision'] == 2 and second['result']['notes'] is None, 'replacement did not clear omitted notes')
    command('tenant-update', dict(changed, operation_id=str(uuid.uuid4())), accepted=False, reason='revision conflict')
    remove = dict(**common, tenant_id=c, expected_revision=2, operation_id=str(uuid.uuid4()))
    removed = command('tenant-delete', remove)
    require(removed['result']['revision'] == 3 and not removed['result']['deletable'], 'bad deletion receipt')
    require(command('tenant-delete', remove) == removed, 'deleted operation did not replay')
    command('tenant-get', dict(**common, tenant_id=c), accepted=False, reason='tenant not found')
    listed = command('tenant-list', common)
    require([t['tenantId'] for t in listed] == sorted(original), 'list leaked tombstone or changed ordering')
    reserved = command('tenant-get', dict(**common,tenant_id=management))
    require(reserved['management'] and not reserved['deletable'], 'reserved tenant is not marked')
    for verb in ('tenant-update','tenant-delete'):
        command(verb,dict(**common,tenant_id=management,expected_revision=1,operation_id=str(uuid.uuid4())),
                accepted=False,reason='reserved management tenant')
    # An authorization initialization failure still permanently claims tenant use.
    d = str(uuid.uuid4())
    create(d)
    command('initialize-authorization', dict(database=pool.database_config(root,fixture.database,'mdm_access','access-fixture'),
        identityDatabase=pool.database_config(root,fixture.database,'mdm_identity_runtime','identity-runtime-fixture'),
        audit={'mode':'plain'}, installation=installation(), expectedEpoch=1, login='admin',
        passwordFile=str(root/'account-password'), operationId=str(uuid.uuid4()),
        user=dict(instanceId=INSTANCE,tenantId=d,principalId=ADMIN)), accepted=False, reason='authorization.initialize: owner=authorization Unauthorized')
    command('tenant-delete', dict(**common, tenant_id=d, expected_revision=1, operation_id=str(uuid.uuid4())), accepted=False, reason='tenant already used')


def tenant_binding(fixture):
    root = fixture.root
    case = json.loads(Path(fixture.env['MDM_CASE_CONTEXT']).read_text())
    a, b = case['tenant'], case['peer']
    base = json.loads(Path(fixture.env['MDM_TEST_CONFIG']).read_text())
    builds = SimpleNamespace(processes=HostProcesses(), executables={'rss-mdm': fixture.binary})
    pool = SimpleNamespace(owner=fixture.owner)
    pool.database_config = lambda *args: DatabasePool.database_config(pool, *args)
    common = dict(database=pool.database_config(root, fixture.database), installation=installation())
    def sql(statement):
        return fixture.owner.sql(statement, fixture.database).strip()
    def command(verb, value, accepted=True):
        path = private(root / (verb + '.json'), value)
        result = subprocess.run([fixture.binary, verb, '--config', str(path)], cwd=ROOT,
            pass_fds=lease_fds(), capture_output=True, text=True, timeout=75)
        require((result.returncode == 0) == accepted, f'{verb}: {result.stderr}')
        if not accepted:
            require('startup.tenant_binding' in result.stderr, 'tenant binding rejected at another stage: ' + result.stderr)
    def snapshot():
        return sql(f"SELECT jsonb_build_object('epoch',(SELECT epoch FROM rss_transactional_messaging.tenant_epoch WHERE tenant_id='{a}'),'settings',(SELECT to_jsonb(s) FROM mdm_access.agent_enrollment_settings s WHERE tenant_id='{a}'))")
    before = snapshot()
    with ExitStack() as stack:
        configurations = []
        for tenant in (a, b):
            config = json.loads(json.dumps(base))
            config['identity']['tenant_id'] = tenant
            path = private(root / ('runtime-' + tenant + '.json'), config)
            host = Host(builds, path, root / ('host-' + tenant), require_ready=False)
            stack.callback(host.close)
            browser = Browser(host, config['product_origin'])
            browser.cookie = '__Host-identity-session=' + (root / f'credential-{tenant}-admin').read_text()
            actor = next(actor for actor in case['actors'] if actor['tenant'] == tenant and actor['role'] == 'admin')
            status, context = browser.call('GET', f'/api/v1/identity-host/tenants/{tenant}/context')
            require(status == 200 and context['tenantId'] == tenant and context['principalId'] == actor['principal'], 'own host lost prepared tenant identity')
            status, rules = browser.call('GET', '/api/v1/authorization/rules')
            require(status == 200 and any(rule.get('value', rule).get('subject', {}).get('user', {}).get('principalId') == actor['principal'] for rule in rules['items']), 'own host cannot read prepared grants')
            foreign = Browser(host, config['product_origin'])
            foreign.cookie = '__Host-identity-session=' + (root / f'credential-{b if tenant == a else a}-admin').read_text()
            require(foreign.call('GET', f'/api/v1/identity-host/tenants/{tenant}/context')[0] == 401, 'foreign session crossed host tenant')
            host.close()
            configurations.append(config)
        command('tenant-update', dict(**common, tenant_id=b, expected_revision=1, operation_id=str(uuid.uuid4()), name='正在使用的租户'))
        for config in configurations:
            invalid = json.loads(json.dumps(config)); invalid['listen'] = '127.0.0.1:0'
            invalid['identity']['tenant_id'] = str(uuid.uuid4())
            command('serve', invalid, False)
            invalid = json.loads(json.dumps(config)); invalid['listen'] = '127.0.0.1:0'
            invalid['flow']['storage']['epoch'] = 2
            command('serve', invalid, False)
    require(snapshot() == before, 'tenant B changed tenant A settings or epoch')
