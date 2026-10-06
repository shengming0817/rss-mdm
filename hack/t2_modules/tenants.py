"""Real CLI registration followed by two same-database, tenant-bound product hosts."""
from contextlib import ExitStack
import http.client
from http.cookies import SimpleCookie
import json
import os
import threading
from types import SimpleNamespace
import uuid
from urllib.parse import urlsplit
from candidate_fixture import ADMIN, INSTANCE, installation
from t2_environment import private
from t2_processes import subprocess
from build_run import lease_fds
from t2_hosts import Host
from t2_database import DatabasePool
from t2_fixtures import RunFixtures
from t2_model import ROOT
from verification_result import require


class Browser:
    def __init__(self, host, origin):
        self.host = host
        self.origin = origin
        self.cookie = ''
        self.csrf = None

    def call(self, method, path, body=None):
        headers = {'Host': urlsplit(self.origin).netloc, 'Origin': self.origin,
                   'X-Identity-Request': '1', 'X-Forwarded-For': '203.0.113.7'}
        if self.cookie:
            headers['Cookie'] = self.cookie
        if self.csrf:
            headers['X-CSRF-Token'] = self.csrf
        if body is not None:
            headers['Content-Type'] = 'application/json'
        conn = http.client.HTTPConnection(self.host.address, timeout=10)
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


def execute(fixture):
    root = fixture.root
    pool = SimpleNamespace(owner=fixture.owner)
    pool.database_config = lambda *args: DatabasePool.database_config(pool, *args)
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
    builds = SimpleNamespace(processes=HostProcesses(), executables={'rss-mdm':fixture.binary})
    context = SimpleNamespace(native_key=os.environ['MDM_NATIVE_PROTECTION_KEY_FILE'])
    a, b = str(uuid.uuid4()), str(uuid.uuid4())
    password = 'Fixture-only-correct-horse-battery-2026!'
    private(root / 'account-password', password)
    database = pool.database_config(root, fixture.database)
    def sql(query):
        return fixture.owner.sql(query, fixture.database).strip()
    def command(verb, value, *, accepted=True):
        path = private(root / (verb + '.json'), value)
        result = subprocess.run([fixture.binary, verb, '--config', str(path)], cwd=ROOT,
                     pass_fds=lease_fds(), capture_output=True, text=True, timeout=75)
        require((result.returncode == 0) == accepted,
                'tenant command failed: ' + verb + ': ' + result.stderr)
        if not accepted:
            require('startup.tenant_binding' in result.stderr, 'invalid binding rejected at another stage: ' + result.stderr)
        return json.loads(result.stdout) if result.stdout.strip() else None
    command('migrate', dict(database=database, installation=installation()))
    require(sql('SELECT count(*) FROM public.mdm_tenants') == '0', 'installer seeded a tenant')
    def register(tenant):
        request = dict(database=database, installation=installation(), tenant_id=tenant,
                       initial_epoch=1, operation_id=str(uuid.uuid4()))
        receipt = command('register-tenant', request)
        require(command('register-tenant', request) == receipt, 'registration replay changed receipt')
        query = dict(database=database, installation=installation(), operation_id=request['operation_id'])
        require(command('tenant-registration-status', query) == {'status':'committed','receipt':receipt},
                'registration query did not recover durable result')
        return receipt
    register(a)
    require(sql('SELECT count(*) FROM public.mdm_tenants') == '1', 'first registration changed tenant count')
    def snapshot():
        return sql(f"SELECT jsonb_build_object('epoch',(SELECT epoch FROM rss_transactional_messaging.tenant_epoch WHERE tenant_id='{a}'),'settings',(SELECT to_jsonb(s) FROM mdm_access.agent_enrollment_settings s WHERE tenant_id='{a}'))")
    before = snapshot()
    require(sql(f"SELECT count(*) FROM public.mdm_tenants WHERE tenant_id='{b}'") == '0', 'B was pre-registered')
    register(b)
    require(snapshot() == before, 'adding B changed A epoch or settings')
    command('migrate', dict(database=database, installation=installation()))
    require(sql('SELECT count(*) FROM identity_authority.accounts') == '0', 'registration seeded an account')
    configs, rules = [], []
    for tenant in (a,b):
        command('initialize', dict(database=pool.database_config(root,fixture.database,'mdm_identity_maintenance','identity-maintenance-fixture'),
                installation=installation(), tenant_id=tenant, expected_epoch=1,
                principal_id=ADMIN, login='admin', password_file=str(root/'account-password')))
        receipt = command('initialize-authorization', dict(database=pool.database_config(root,fixture.database,'mdm_access','access-fixture'),
                identityDatabase=pool.database_config(root,fixture.database,'mdm_identity_runtime','identity-runtime-fixture'),
                audit={'mode':'plain'}, installation=installation(), expectedEpoch=1,
                login='admin', passwordFile=str(root/'account-password'), operationId=str(uuid.uuid4()),
                user=dict(instanceId=INSTANCE,tenantId=tenant,principalId=ADMIN)))
        rules.append(receipt['id'])
        config = RunFixtures.runtime_config(context,pool,root,fixture.database,tenant)
        config['agent_pki'] = {'mode':'disabled'}
        configs.append(private(root/('runtime-'+tenant+'.json'),config))
    with ExitStack() as stack:
        hosts = []
        for index,path in enumerate(configs):
            host=Host(builds,path,root/('host-'+str(index)))
            stack.callback(host.close)
            hosts.append(host)
        browsers=[Browser(host,'https://mdm.example.test') for host in hosts]
        for tenant,browser,rule in zip((a,b),browsers,rules):
            require(browser.call('POST',f'/api/v1/identity/tenants/{tenant}/login',dict(login='admin',password=password))[0] == 200,
                    'registered tenant cannot log in')
            status,value=browser.call('GET',f'/api/v1/identity-host/tenants/{tenant}/context')
            require(status == 200 and value['tenantId'] == tenant and value['principalId'] == ADMIN,
                    'host context lost tenant binding')
            status,value=browser.call('GET','/api/v1/authorization/rules')
            require(status == 200 and [item['id'] for item in value['items']] == [rule],
                    'host cannot consume its own initialized authorization rule')
        for source,target,tenant in [(browsers[0],hosts[1],b),(browsers[1],hosts[0],a)]:
            foreign=Browser(target,source.origin)
            foreign.cookie,foreign.csrf=source.cookie,source.csrf
            require(foreign.call('GET',f'/api/v1/identity-host/tenants/{tenant}/context')[0] == 401,
                    'foreign tenant session crossed host binding')
        for index,path in enumerate(configs):
            config=json.loads(path.read_text())
            config['listen']='127.0.0.1:0'
            config['identity']['tenant_id']=str(uuid.uuid4())
            config['identity_management'][0]['tenant_id']=config['identity']['tenant_id']
            command('serve',config,accepted=False)
            config=json.loads(path.read_text());config['listen']='127.0.0.1:0';config['flow']['storage']['epoch']=2
            command('serve',config,accepted=False)
    require(snapshot() == before, 'initializing and consuming B changed A settings or epoch')
    print('fresh A -> register B -> account/authorization -> two real same-database hosts and tenant isolation passed',flush=True)
