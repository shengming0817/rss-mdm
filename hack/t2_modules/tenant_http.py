"""Real tenant registry protocol and repeatable administrator provisioning."""
import json
import uuid
from copy import deepcopy
from t2_modules.tenants import Browser
from t2_hosts import Host
from t2_environment import private
from verification_result import require

BASE = '/api/v1/tenant-administration'


def exercise(admin, normal, delegate, config, management, business, password, sql, command, common,
             builds, root, stack, login, write, rule):
    def call(method, path, body=None, operation=None, browser=admin):
        headers = {'Idempotency-Key': operation or str(uuid.uuid4())} if method != 'GET' else {}
        return browser.call(method, BASE + path, body, headers)

    tenant = str(uuid.uuid4())
    create = dict(tenantId=tenant, initialEpoch=1, name='HTTP tenant')
    key = str(uuid.uuid4())
    require(admin.call('POST', BASE + '/tenants', create)[0] == 400, 'missing key accepted')
    require(call('POST', '/tenants', dict(create, operationId=key))[0] == 400, 'JSON operation ID accepted')
    require(call('POST', '/tenants', create, key, normal)[0] == 401, 'business session entered registry')
    require(call('POST', '/tenants', create, key, delegate)[0] == 403, 'unprivileged manager created tenant')
    status, receipt = call('POST', '/tenants', create, key)
    require(status == 200 and receipt['operationId'] == key and receipt['result']['revision'] == 1, 'tenant HTTP create failed: ' + str((status, receipt)))
    require(call('POST', '/tenants', create, key) == (200, receipt), 'create replay changed')
    require(command('tenant-create', dict(**common,tenant_id=tenant,initial_epoch=1,name='HTTP tenant',operation_id=key)) == receipt,
            'CLI/HTTP request fingerprint diverged')
    require(call('POST', '/tenants', dict(create,name='different'), key)[0] == 409, 'key conflict accepted')
    require(call('GET', '/tenants/' + tenant) == (200,receipt['result']), 'detail differs')
    require(any(t['tenantId'] == tenant for t in call('GET','/tenants')[1]['items']), 'list omitted tenant')
    edit_key = str(uuid.uuid4())
    status, edited = call('PUT','/tenants/' + tenant,dict(expectedRevision=1,notes='updated'),edit_key)
    require(status == 200 and edited['result']['revision'] == 2 and edited['result']['name'] is None, 'replace/CAS failed')
    require(call('PUT','/tenants/' + tenant,dict(expectedRevision=1))[0] == 409, 'stale revision accepted')
    require(call('GET','/operations/' + key) == (200,receipt), 'original operation snapshot changed')
    require(call('DELETE','/tenants/' + management,dict(expectedRevision=1))[0] == 403, 'reserved tenant deleted')
    removable = str(uuid.uuid4())
    require(call('POST','/tenants',dict(tenantId=removable,initialEpoch=1))[0] == 200, 'second create failed')
    require(call('DELETE','/tenants/' + removable,dict(expectedRevision=1))[0] == 200, 'delete failed')
    require(call('GET','/tenants/' + removable)[0] == 404, 'tombstone visible')
    require(call('POST','/tenants',dict(tenantId=removable,initialEpoch=1))[0] == 409, 'tombstone reused')
    require(call('GET','/operations/not-a-uuid') == (400, {'code':'malformed_request'}), 'invalid operation did not use JSON error contract')
    request = dict(login='tenant-admin-one',password=password)
    admin_key = str(uuid.uuid4())
    path = '/tenants/' + tenant + '/administrators'
    status, first = call('POST',path,request,admin_key)
    require(status == 200 and first['result']['ruleRevision'] == 1, 'administrator provisioning failed: ' + str((status,first)))
    require(call('POST',path,request,admin_key) == (200,first), 'administrator replay changed')
    require(call('POST',path,dict(request,password=password+'changed'),admin_key)[0] == 409, 'password fingerprint conflict ignored')
    require(call('POST',path,request)[0] == 409, 'existing login was taken over')
    status, second = call('POST',path,dict(request,login='tenant-admin-two'))
    require(status == 200 and second['result']['principalId'] != first['result']['principalId'], 'subsequent administrator blocked')
    require(call('DELETE','/tenants/' + tenant,dict(expectedRevision=2))[0] == 409, 'provisioned tenant remained deletable')
    require(call('GET','/operations/' + admin_key) == (200,first), 'administrator operation lookup failed')
    administrator_rollback(call, path, tenant, password, sql)
    operator = json.loads(sql(f"SELECT operator FROM public.mdm_tenant_operations WHERE operation_id='{admin_key}'"))
    require(operator['tenantId'] == management, 'source actor lost')
    stored = sql(f"SELECT request::text FROM public.mdm_tenant_operations WHERE operation_id='{admin_key}'")
    require(password not in stored and 'fingerprint' in stored, 'password persisted in receipt request')
    target_config = deepcopy(config)
    target_config['identity']['tenant_id'] = tenant
    target_config['identity']['oidc'] = None
    target_host = Host(builds,private(root/'target-runtime.json',target_config),root/'target-host')
    stack.callback(target_host.close)
    target_admin = Browser(target_host,config['product_origin'])
    login(target_admin,tenant,'tenant-admin-one')
    status, effective = target_admin.call('GET','/api/v1/authorization')
    permissions = {g['operation'] for g in effective.get('grants',[])}
    require(status == 200 and {'identity_accounts_manage','identity_providers_manage','inventory_read','device_wipe','authorization_write'} <= permissions,
            'target administrator lacks business capabilities')
    require(not any(p.startswith('tenant_') for p in permissions), 'target administrator gained installation powers')
    require(target_admin.call('GET',BASE+'/tenants')[0] == 401, 'target administrator crossed tenant boundary')
    require(all(g['scope']['kind']=='all_devices' for g in effective['grants'] if g['operation'] in {'inventory_read','device_wipe'}), 'device scope incomplete')
    # Revoking a provisioned grant must not be undone by operation replay.
    rule_id = first['result']['ruleId']
    sql(f"UPDATE mdm_access.authorization_rules SET document=NULL,revision=revision+1 WHERE tenant_id='{tenant}' AND id='{rule_id}'")
    require(call('POST',path,request,admin_key) == (200,first), 'replay after grant revocation changed')
    require(sql(f"SELECT document IS NULL FROM mdm_access.authorization_rules WHERE tenant_id='{tenant}' AND id='{rule_id}'") == 't', 'replay regranted administrator')
    # Change target password through the independent second administrator; original fingerprint stays valid.
    other = Browser(target_host,config['product_origin'])
    login(other,tenant,'tenant-admin-two')
    require(other.call('POST',f"/api/v1/identity/tenants/{tenant}/accounts/{first['result']['principalId']}/password",dict(password=password+'rotated'))[0] == 200, 'target password reset failed')
    require(call('POST',path,request,admin_key) == (200,first), 'password change invalidated immutable replay')

    grant_id = str(uuid.uuid4())
    status, delegated_actor = delegate.call('GET','/api/v1/identity-host/tenants/' + management + '/context')
    require(status == 200, 'delegate context unavailable')
    delegated_principal = delegated_actor['principalId']
    _, delegation = write(admin,grant_id,0,rule(delegated_principal,['tenant_administrator_create']))
    delegated_key = str(uuid.uuid4())
    delegated_body = dict(request,login='delegated-admin')
    status, delegated_receipt = call('POST',path,delegated_body,delegated_key,delegate)
    require(status == 200, 'explicit administrator provisioning delegation failed')
    write(admin,grant_id,delegation['revision'],None)
    require(call('POST',path,delegated_body,delegated_key,delegate)[0] == 403, 'revoked source grant retained replay authority')
    require(call('POST',path,delegated_body,delegated_key) == (200,delegated_receipt), 'new authorized operator cannot query original replay')
    require(json.loads(sql(f"SELECT operator FROM public.mdm_tenant_operations WHERE operation_id='{delegated_key}'"))['principalId'] == delegated_principal,
            'replay rewrote original operator')
    sql(f"UPDATE identity_authority.sessions SET auth_time=auth_time-301 WHERE tenant_id='{management}' AND principal_id='{operator['principalId']}'")
    require(call('POST',path,request,admin_key)[0] == 403, 'expired recent authentication allowed replay')
    login(admin,management)
    # Optional block controls all registry routes, not a partial startup mode.
    absent = deepcopy(config)
    del absent['tenant_administration']
    absent_host = Host(builds,private(root/'without-registry.json',absent),root/'without-registry-host')
    stack.callback(absent_host.close)
    require(Browser(absent_host,config['product_origin']).call('GET',BASE+'/tenants')[0] == 404, 'disabled registry routes were mounted')
    malformed = deepcopy(config)
    malformed['tenant_administration'] = {}
    malformed['listen'] = '127.0.0.1:0'
    command('serve',malformed,accepted=False)
    lost_commit_ack(config,management,password,sql,builds,root,stack,login,tenant)


def administrator_rollback(call, path, tenant, password, sql):
    def counts():
        return sql(f"SELECT (SELECT count(*) FROM identity_authority.accounts WHERE tenant_id='{tenant}')||':'||(SELECT count(*) FROM identity_authority.local_credentials WHERE tenant_id='{tenant}')||':'||(SELECT count(*) FROM mdm_access.authorization_rules WHERE tenant_id='{tenant}')")
    operation = str(uuid.uuid4())
    request = dict(login='rollback-admin',password=password)
    before = counts()
    sql(f"CREATE FUNCTION public.reject_admin_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected receipt failure'; END $$; CREATE TRIGGER reject_admin_receipt BEFORE INSERT ON public.mdm_tenant_operations FOR EACH ROW WHEN (NEW.operation_id='{operation}'::uuid) EXECUTE FUNCTION public.reject_admin_receipt();")
    try:
        require(call('POST',path,request,operation)[0] == 503, 'receipt fault accepted')
        require(counts() == before, 'failed receipt left partial administrator')
        require(sql(f"SELECT count(*) FROM public.mdm_tenant_operations WHERE operation_id='{operation}'") == '0', 'failed operation persisted')
    finally:
        sql('DROP TRIGGER reject_admin_receipt ON public.mdm_tenant_operations; DROP FUNCTION public.reject_admin_receipt()')
    require(call('POST',path,request,operation)[0] == 200, 'rolled back request could not retry')
    # Fill remaining capacity using valid documents or tombstones, and prove account rollback.
    original = sql(f"SELECT string_agg(quote_literal(id::text),',') FROM mdm_access.authorization_rules WHERE tenant_id='{tenant}'")
    for mode in ('rows','bytes'):
        if mode == 'rows':
            fill = f"10000-(SELECT count(*) FROM mdm_access.authorization_rules WHERE tenant_id='{tenant}')"
            document = 'NULL::jsonb'
        else:
            fill = f"(8388608-(SELECT coalesce(sum(octet_length(document::text)),0) FROM mdm_access.authorization_rules WHERE tenant_id='{tenant}'))/octet_length(template.document::text)"
            document = 'template.document'
        sql(f"INSERT INTO mdm_access.authorization_rules(tenant_id,instance,id,revision,document) SELECT template.tenant_id,template.instance,gen_random_uuid(),1,{document} FROM (SELECT * FROM mdm_access.authorization_rules WHERE tenant_id='{tenant}' AND document IS NOT NULL LIMIT 1) template CROSS JOIN LATERAL generate_series(1,({fill})::int)")
        operation = str(uuid.uuid4())
        before = counts()
        try:
            require(call('POST',path,dict(request,login='capacity-'+mode),operation)[0] == 409, 'administrator exceeded authorization '+mode+' capacity')
            require(counts() == before, 'capacity rejection left partial account/rule')
            require(sql(f"SELECT count(*) FROM public.mdm_tenant_operations WHERE operation_id='{operation}'") == '0', 'capacity rejection saved receipt')
        finally:
            sql(f"DELETE FROM mdm_access.authorization_rules WHERE tenant_id='{tenant}' AND id NOT IN ({original})")


def lost_commit_ack(config,management,password,sql,builds,root,stack,login,tenant):
    """Drop actual PostgreSQL COMMIT acknowledgements without terminating TLS."""
    from concurrent.futures import ThreadPoolExecutor
    import time
    proxy = AckProxy(config['tenant_administration']['registry_database'])
    stack.callback(proxy.close)
    candidate = deepcopy(config)
    for role in ('registry_database','provisioning_database'):
        candidate['tenant_administration'][role]['port'] = proxy.port
    host = Host(builds,private(root/'ack-runtime.json',candidate),root/'ack-host')
    stack.callback(host.close)
    browser = Browser(host,config['product_origin'])
    login(browser,management)
    # Black-hole database replies after HTTP authentication; both raw reads must terminate.
    for method, route, body in (
        ('GET','/tenants',None),
        ('POST','/tenants/'+tenant+'/administrators',dict(login='blackhole-admin',password=password)),
    ):
        proxy.discard.set()
        started = time.monotonic()
        try:
            status, _ = browser.call(method,BASE+route,body,{'Idempotency-Key':str(uuid.uuid4())})
            require(status == 503 and time.monotonic()-started < 12, 'registry read deadline missing')
        finally:
            proxy.discard.clear()
        require(browser.call('GET',BASE+'/tenants')[0] == 200, 'cancelled connection poisoned registry pool')
    for kind in ('create','administrator_create'):
        operation = str(uuid.uuid4())
        if kind == 'create':
            target = str(uuid.uuid4())
            route = '/tenants'
            body = dict(tenantId=target,initialEpoch=1)
            role = 'mdm_tenant_registry'
        else:
            target = tenant
            route = '/tenants/' + tenant + '/administrators'
            body = dict(login='ack-admin',password=password)
            role = 'mdm_identity_provisioning'
        sql(f"CREATE FUNCTION public.hold_tenant_ack() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(2); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER tenant_ack AFTER INSERT ON public.mdm_tenant_operations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.operation_id='{operation}'::uuid) EXECUTE FUNCTION public.hold_tenant_ack();")
        with ThreadPoolExecutor(max_workers=1) as worker:
            response = worker.submit(browser.call,'POST',BASE+route,body,{'Idempotency-Key':operation})
            until = time.monotonic()+8
            while sql(f"SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND usename='{role}' AND query='COMMIT' AND wait_event='PgSleep'") != '1':
                require(time.monotonic()<until and not response.done(), 'COMMIT fault rendezvous not reached')
                time.sleep(0.02)
            proxy.discard.set()
            try:
                status, result = response.result(timeout=12)
                require(status == 503, 'lost COMMIT ACK falsely reported confirmed result: ' + str((status,result)))
            finally:
                proxy.discard.clear()
        sql('DROP TRIGGER tenant_ack ON public.mdm_tenant_operations; DROP FUNCTION public.hold_tenant_ack()')
        require(sql(f"SELECT count(*) FROM public.mdm_tenant_operations WHERE operation_id='{operation}'") == '1', 'COMMIT did not durably reach PostgreSQL')
        status, receipt = browser.call('GET',BASE+'/operations/'+operation)
        require(status == 200, 'durable unknown operation not queryable')
        require(browser.call('POST',BASE+route,body,{'Idempotency-Key':operation}) == (200,receipt), 'unknown operation did not replay')
        if kind == 'administrator_create':
            require(sql(f"SELECT count(*) FROM identity_authority.local_credentials WHERE tenant_id='{target}' AND login_key='ack-admin'") == '1', 'unknown commit duplicated account')
            require(sql(f"SELECT count(*) FROM mdm_access.authorization_rules WHERE tenant_id='{target}' AND id='{receipt['result']['ruleId']}'") == '1', 'unknown commit duplicated rule')


class AckProxy:
    """Same opaque TLS fault boundary as group-postgres/tests/t2.rs AckProxy."""
    def __init__(self,database):
        import socket
        import threading
        self.discard = threading.Event()
        self.stop = threading.Event()
        self.sockets = []
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1',0))
        self.listener.listen()
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        def transfer(source,target,backward):
            try:
                while not self.stop.is_set():
                    data = source.recv(16384)
                    if not data: break
                    if not backward or not self.discard.is_set(): target.sendall(data)
            except OSError:
                pass
            finally:
                source.close(); target.close()
        def accept():
            while not self.stop.is_set():
                try: client,_ = self.listener.accept()
                except socket.timeout: continue
                except OSError: break
                server = socket.create_connection((database['host'],database['port']),timeout=15)
                client.settimeout(15)
                self.sockets.extend((client,server))
                threading.Thread(target=transfer,args=(client,server,False),daemon=True).start()
                threading.Thread(target=transfer,args=(server,client,True),daemon=True).start()
        self.thread = threading.Thread(target=accept,daemon=True)
        self.thread.start()
    def close(self):
        self.stop.set()
        self.listener.close()
        for connection in self.sockets: connection.close()
        self.thread.join(timeout=2)
