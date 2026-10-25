"""Real tenant registry protocol and repeatable administrator provisioning."""
import json
import uuid
from copy import deepcopy
from t2_modules.tenants import Browser
from t2_hosts import Host
from t2_environment import private
from verification_result import require

BASE = '/api/v1/tenant-administration'


def provisioning(fixture):
    from t2_modules.management_tenant import management_host
    with management_host(fixture) as h:
        admin,normal,delegate=h.admin,h.normal,h.delegate
        config,management,business,password=h.config,h.management,h.business,h.password
        sql,command,common,builds,root,stack,login,write,rule=h.sql,h.command,h.common,h.builds,h.root,h.stack,h.login,h.write,h.rule
        def call(method,path,body=None,operation=None,browser=admin):
            headers={'Idempotency-Key':operation or str(uuid.uuid4())} if method!='GET' else {}
            return browser.call(method,BASE+path,body,headers)
        create = dict(name='HTTP tenant',administratorLogin='initial-admin',administratorPassword=password)
        key = str(uuid.uuid4())
        require(call('POST','/tenants',create)[0] == 405, 'bare creation route remains public')
        require(admin.call('POST', BASE + '/provisionings', create)[0] == 400, 'missing key accepted')
        require(call('POST', '/provisionings', dict(create, operationId=key))[0] == 400, 'JSON operation ID accepted')
        require(call('POST', '/provisionings', create, key, normal)[0] == 401, 'business session entered registry')
        require(call('POST', '/provisionings', create, key, delegate)[0] == 403, 'unprivileged manager created tenant')
        status, receipt = call('POST', '/provisionings', create, key)
        require(status == 202 and receipt['operationId'] == key and receipt['result']['phase'] == 'host_pending' and receipt['result']['administratorId'], 'complete provisioning did not reach host pending: ' + str((status,receipt)))
        tenant = receipt['result']['tenantId']
        require(call('POST','/provisionings',create,key)==(202,receipt),'provisioning replay changed identity')
        require(call('GET','/provisionings/'+key)==(200,receipt),'provisioning operation lookup failed')
        require(call('POST', '/provisionings', dict(create,name='different'), key)[0] == 409, 'key conflict accepted')
        require(call('GET', '/tenants/' + tenant)[1]['tenantId']==tenant, 'detail differs')
        require(any(t['tenantId'] == tenant for t in call('GET','/tenants')[1]['items']), 'list omitted tenant')
        edit_key = str(uuid.uuid4())
        status, edited = call('PUT','/tenants/' + tenant,dict(expectedRevision=1,notes='updated'),edit_key)
        require(status == 200 and edited['result']['revision'] == 2 and edited['result']['name'] is None, 'replace/CAS failed')
        require(call('PUT','/tenants/' + tenant,dict(expectedRevision=1))[0] == 409, 'stale revision accepted')
        require(call('GET','/operations/' + key) == (200,receipt), 'original operation snapshot changed')
        require(call('DELETE','/tenants/' + management,dict(expectedRevision=1))[0] == 403, 'reserved tenant deleted')
        require(call('DELETE','/tenants/' + tenant,dict(expectedRevision=2))[0] == 409, 'fully provisioned tenant was deletable')
        require(call('GET','/operations/not-a-uuid') == (400, {'code':'malformed_request'}), 'invalid operation did not use JSON error contract')


def administrator(fixture):
    from t2_modules.management_tenant import management_host
    with management_host(fixture) as h:
        admin,normal,delegate=h.admin,h.normal,h.delegate
        config,management,business,password=h.config,h.management,h.business,h.password
        sql,command,common,builds,root,stack,login,write,rule=h.sql,h.command,h.common,h.builds,h.root,h.stack,h.login,h.write,h.rule
        def call(method,path,body=None,operation=None,browser=admin):
            headers={'Idempotency-Key':operation or str(uuid.uuid4())} if method!='GET' else {}
            return browser.call(method,BASE+path,body,headers)
        tenant=business
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
        require(call('DELETE','/tenants/' + tenant,dict(expectedRevision=1))[0] == 409, 'provisioned tenant remained deletable')
        require(call('GET','/operations/' + admin_key) == (200,first), 'administrator operation lookup failed')
        operator = json.loads(sql(f"SELECT operator FROM public.mdm_tenant_operations WHERE operation_id='{admin_key}'"))
        require(operator['tenantId'] == management, 'source actor lost')
        stored = sql(f"SELECT request::text FROM public.mdm_tenant_operations WHERE operation_id='{admin_key}'")
        require(password not in stored and 'fingerprint' in stored, 'password persisted in receipt request')
        target_admin = Browser(h.host,config['product_origin'])
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
        sql(f"SET rss.tenant_id='{tenant}'; UPDATE mdm_access.authorization_rules SET document=NULL,revision=revision+1 WHERE tenant_id='{tenant}' AND id='{rule_id}'")
        require(call('POST',path,request,admin_key) == (200,first), 'replay after grant revocation changed')
        require(sql(f"SELECT document IS NULL FROM mdm_access.authorization_rules WHERE tenant_id='{tenant}' AND id='{rule_id}'") == 't', 'replay regranted administrator')
        # Change target password through the independent second administrator; original fingerprint stays valid.
        other = Browser(h.host,config['product_origin'])
        login(other,tenant,'tenant-admin-two')
        require(other.call('POST',f"/api/v1/identity/tenants/{tenant}/accounts/{first['result']['principalId']}/password",dict(password=password+'rotated'))[0] == 200, 'target password reset failed')
        require(call('POST',path,request,admin_key) == (200,first), 'password change invalidated immutable replay')


def recent_auth(fixture):
    from t2_modules.management_tenant import management_host
    from candidate_fixture import ADMIN
    with management_host(fixture) as h:
        admin,normal,delegate=h.admin,h.normal,h.delegate
        config,management,business,password=h.config,h.management,h.business,h.password
        sql,command,common,builds,root,stack,login,write,rule=h.sql,h.command,h.common,h.builds,h.root,h.stack,h.login,h.write,h.rule
        def call(method,path,body=None,operation=None,browser=admin):
            headers={'Idempotency-Key':operation or str(uuid.uuid4())} if method!='GET' else {}
            return browser.call(method,BASE+path,body,headers)
        tenant=business;path='/tenants/'+tenant+'/administrators';source_principal=ADMIN
        grant_id = str(uuid.uuid4())
        status, delegated_actor = delegate.call('GET','/api/v1/identity-host/tenants/' + management + '/context')
        require(status == 200, 'delegate context unavailable')
        delegated_principal = delegated_actor['principalId']
        _, delegation = write(admin,grant_id,0,rule(delegated_principal,['tenant_administrator_create']))
        delegated_key = str(uuid.uuid4())
        delegated_body = dict(login='delegated-admin',password=password)
        status, delegated_receipt = call('POST',path,delegated_body,delegated_key,delegate)
        require(status == 200, 'explicit administrator provisioning delegation failed: ' + str((status, delegated_receipt)))
        write(admin,grant_id,delegation['revision'],None)
        require(call('POST',path,delegated_body,delegated_key,delegate)[0] == 403, 'revoked source grant retained replay authority')
        require(call('POST',path,delegated_body,delegated_key) == (200,delegated_receipt), 'new authorized operator cannot query original replay')
        require(json.loads(sql(f"SELECT operator FROM public.mdm_tenant_operations WHERE operation_id='{delegated_key}'"))['principalId'] == delegated_principal,
                'replay rewrote original operator')
        sql(f"UPDATE identity_authority.sessions SET local_authenticated_at=local_authenticated_at-301 WHERE tenant_id='{management}' AND principal_id='{source_principal}'")
        require(call('POST',path,delegated_body,delegated_key)[0] == 403, 'expired recent authentication allowed replay')
        sql(f"UPDATE identity_authority.sessions SET local_authenticated_at=local_authenticated_at+301 WHERE tenant_id='{management}' AND principal_id='{source_principal}'")


def optional_routes(fixture):
    from t2_modules.tenants import HostProcesses
    from types import SimpleNamespace
    from pathlib import Path
    config=json.loads(Path(fixture.env['MDM_TEST_CONFIG']).read_text())
    config.pop('tenant_administration',None)
    builds=SimpleNamespace(processes=HostProcesses(),executables={'rss-mdm':fixture.binary})
    host=Host(builds,private(fixture.root/'without-registry.json',config),fixture.root/'without-registry-host',require_ready=False)
    try: require(Browser(host,config['product_origin']).call('GET',BASE+'/tenants')[0]==404,'disabled registry routes were mounted')
    finally: host.close()


def provisioning_pages_and_active_directory(fixture):
    from t2_modules.management_tenant import management_host
    with management_host(fixture) as h:
        _provisioning_pages_and_active_directory(h.admin,h.sql)


def administrator_rollback(fixture):
    from t2_modules.management_tenant import management_host
    with management_host(fixture) as h:
        def call(method,path,body=None,operation=None):
            return h.admin.call(method,BASE+path,body,{'Idempotency-Key':operation or str(uuid.uuid4())})
        _administrator_rollback(call,'/tenants/'+h.business+'/administrators',h.business,h.password,h.sql)


def audit_backpressure(fixture):
    from t2_modules.management_tenant import management_host
    from candidate_fixture import INSTANCE
    with management_host(fixture) as h:
        # The Webhook consumer needs only its own management permission and device scope.
        rule=dict(subject=dict(kind='user',user=dict(instanceId=INSTANCE,tenantId=h.business,principalId=h.business_actor['principal'])),grants=[dict(operation='webhook_write',scope=dict(kind='tenant')),dict(operation='inventory_read',scope=dict(kind='all_devices')),dict(operation='authorization_write',scope=dict(kind='tenant'))])
        encoded=json.dumps(rule).replace("'","''")
        h.sql(f"SET rss.tenant_id='{h.business}'; INSERT INTO mdm_access.authorization_rules VALUES('{h.business}','{INSTANCE}','{uuid.uuid4()}',1,'{encoded}'::jsonb)")
        h.host.close()
        _audit_backpressure(h.config,h.admin,h.normal,h.management,h.business,h.password,h.sql,h.builds,h.root,h.stack,fixture.owner,fixture.database)


def lost_commit_ack(fixture):
    from t2_modules.management_tenant import management_host
    with management_host(fixture) as h:
        h.host.close()
        _lost_commit_ack(h.config,h.password,h.sql,h.builds,h.root,h.stack,h.admin,h.business)


def _audit_backpressure(config, manager, target_admin, management, tenant, password, sql,
                       builds, root, stack, owner, database):
    """Real source quota refusal preserves the product reason across all App adapters."""
    import time
    from contextlib import contextmanager
    from t2_processes import subprocess
    limit = 16
    candidate = deepcopy(config)
    candidate['audit_projection']['max_events'] = limit
    candidate['audit_projection']['max_bytes'] = 10485760
    host = Host(builds, private(root/'capacity-runtime.json', candidate), root/'capacity-host', require_ready=False)
    stack.callback(host.close)
    admin, target = Browser(host, config['product_origin']), Browser(host, config['product_origin'])
    admin.cookie, admin.csrf = manager.cookie, manager.csrf
    target.cookie, target.csrf = target_admin.cookie, target_admin.csrf
    tenants = f"'{management}','{tenant}'"

    def drained():
        def pending():
            # A cancelled projection may leave a durable claim after commit-unknown.
            # Observe its actual recovery horizon; never clear or shorten that claim.
            return json.loads(sql(f"""WITH pending AS (
                SELECT r.message_id,o.status,o.lease_until,o.retry_after,
                  (SELECT max(i.lease_until) FROM rss_transactional_messaging.inbox i
                   WHERE (i.tenant_id,i.message_id)=(r.tenant_id,r.message_id)
                     AND i.disposition IS NULL) AS inbox_lease
                FROM mdm_audit.receipts r
                LEFT JOIN rss_transactional_messaging.outbox o
                  ON (o.tenant_id,o.message_id)=(r.tenant_id,r.message_id)
                WHERE r.tenant_id IN ({tenants}) AND r.projected_at IS NULL)
                SELECT jsonb_build_object('count',count(*),
                  'waitSeconds',greatest(0,coalesce(extract(epoch FROM
                    (max(greatest(lease_until,inbox_lease,retry_after))-clock_timestamp())),0)),
                  'sample',(SELECT jsonb_agg(to_jsonb(p)) FROM (SELECT * FROM pending LIMIT 8) p))
                FROM pending"""))

        state = pending()
        # Production claims last 60 s. Keep the normal 30 s processing allowance,
        # include only the observed lease horizon, and cap the entire drain at 90 s.
        until = time.monotonic() + min(90, 30 + state['waitSeconds'])
        while state['count']:
            require(time.monotonic() < until, 'audit source did not drain after quota fixture: ' + json.dumps(state))
            time.sleep(.1)
            state = pending()

    @contextmanager
    def hold_projection():
        # Source admission never writes the final Audit head. A separate bounded
        # transaction stalls only projection, without forging backlog counters.
        process = subprocess.Popen(['docker','exec','-i',owner.container(),'psql','-X','-qAt','-v','ON_ERROR_STOP=1','-U','postgres','-d',database],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            process.stdin.write("BEGIN; SET LOCAL lock_timeout='5s'; SET LOCAL idle_in_transaction_session_timeout='30s'; LOCK TABLE rss_audit.heads IN SHARE MODE; SELECT 'projection-held';\n")
            process.stdin.flush()
            require(process.stdout.readline().strip() == 'projection-held', 'audit projection lock not acquired')
            yield
        finally:
            _, errors = process.communicate('ROLLBACK;\n', timeout=10)
            require(process.returncode == 0, 'audit projection lock cleanup failed: ' + errors)

    def fill(browser, tenant_id):
        replay = None
        for source in ('mdm.business', 'mdm.request'):
            for _ in range(limit // 2 + 1):
                count = int(sql(f"SELECT coalesce((SELECT events FROM mdm_audit.backlog WHERE tenant_id='{tenant_id}' AND source_id='{source}'),0)"))
                if count == limit // 2:
                    require(sql(f"SELECT reserved_events FROM mdm_audit.backlog WHERE tenant_id='{tenant_id}' AND source_id='{source}'") == '0', 'failure reserve was already consumed')
                    break
                # Normal business and request capacity are independent. Fill each through its real owner.
                if source == 'mdm.business':
                    current = json.loads(sql(f"SELECT jsonb_build_object('id',id,'revision',revision,'value',document) FROM mdm_access.authorization_rules WHERE tenant_id='{tenant_id}' AND document IS NOT NULL ORDER BY id LIMIT 1"))
                    prefix = BASE + '/authorization/rules/' if tenant_id == management else '/api/v1/authorization/rules/'
                    change = dict(operationId=str(uuid.uuid4()), expectedRevision=current['revision'], value=current['value'])
                    replay = (prefix + current['id'], change)
                    require(browser.call('PUT', *replay)[0] == 200, source + ' fill rejected before capacity')
                else:
                    require(replay is not None, 'business replay must exist')
                    require(browser.call('PUT', *replay)[0] == 200, source + ' fill rejected before capacity')
            else:
                raise RuntimeError(source + ' did not fill its source quota')

    subscription = str(uuid.uuid4())
    settings = json.dumps(dict(presentation=dict(name='Quota rollback'), endpoint='https://receiver.invalid/', eventTypes=['device.registered'], selection=dict(kind='allDevices'), keyReference='retired-key', networkReference='retired-network'))
    # A disabled subscription with removed delivery material is legal and deletable.
    sql(f"INSERT INTO mdm_webhook.subscriptions(tenant_id,id,revision,target_version,settings) VALUES('{tenant}','{subscription}',1,1,'{settings}'::jsonb); INSERT INTO mdm_webhook.versions(tenant_id,subscription,version,settings) VALUES('{tenant}','{subscription}',1,'{settings}'::jsonb)")
    try:
        for kind in ('registry', 'provisioning', 'administrator', 'webhook'):
            drained()
            operation = str(uuid.uuid4())
            with hold_projection():
                if kind != 'webhook':
                    fill(admin, management)
                if kind in ('administrator', 'webhook'):
                    fill(target, tenant)
                before = sql(f"SELECT (SELECT count(*) FROM public.mdm_tenants)||':'||(SELECT count(*) FROM rss_transactional_messaging.tenant_epoch)||':'||(SELECT count(*) FROM identity_authority.accounts WHERE tenant_id='{tenant}')||':'||(SELECT count(*) FROM identity_authority.local_credentials WHERE tenant_id='{tenant}')||':'||(SELECT count(*) FROM mdm_access.authorization_rules WHERE tenant_id='{tenant}')")
                tenant_before = sql(f"SELECT revision||':'||coalesce(notes,'') FROM public.mdm_tenants WHERE tenant_id='{tenant}'")
                if kind == 'registry':
                    revision = int(tenant_before.split(':', 1)[0])
                    response = admin.call('PUT', BASE+'/tenants/'+tenant, dict(expectedRevision=revision,notes='must rollback'), {'Idempotency-Key':operation})
                elif kind == 'provisioning':
                    response = admin.call('POST', BASE+'/provisionings', dict(name='Quota tenant',administratorLogin='quota-admin',administratorPassword=password), {'Idempotency-Key':operation})
                elif kind == 'administrator':
                    response = admin.call('POST', BASE+'/tenants/'+tenant+'/administrators', dict(login='quota-admin',password=password), {'Idempotency-Key':operation})
                else:
                    response = target.call('PUT', '/api/v1/webhooks/subscriptions/'+subscription, dict(operationId=operation,expectedRevision=1,change=dict(kind='delete')))
                require(response == (503, {'code':'service_unavailable'}), kind+' changed safe quota response: '+str(response))
                diagnostics = [json.loads(line) for line in host.log_path.read_text().splitlines() if line.startswith('{')]
                matching = [entry for entry in diagnostics if entry.get('event') == 'mdm_request' and entry.get('operation_id') == operation]
                require(len(matching) == 1 and matching[0].get('error', {}).get('reason') == 'audit_backpressure', kind+' lost audit quota diagnostic: '+str(matching))
                after = sql(f"SELECT (SELECT count(*) FROM public.mdm_tenants)||':'||(SELECT count(*) FROM rss_transactional_messaging.tenant_epoch)||':'||(SELECT count(*) FROM identity_authority.accounts WHERE tenant_id='{tenant}')||':'||(SELECT count(*) FROM identity_authority.local_credentials WHERE tenant_id='{tenant}')||':'||(SELECT count(*) FROM mdm_access.authorization_rules WHERE tenant_id='{tenant}')")
                require(after == before, kind+' committed partial business state')
                require(sql(f"SELECT revision||':'||coalesce(notes,'') FROM public.mdm_tenants WHERE tenant_id='{tenant}'") == tenant_before, kind+' changed tenant metadata')
                require(sql(f"SELECT revision||':'||deleted FROM mdm_webhook.subscriptions WHERE tenant_id='{tenant}' AND id='{subscription}'") == '1:false', 'quota refusal deleted webhook')
                require(sql(f"SELECT count(*)||':'||min(version)||':'||bool_or(retired) FROM mdm_webhook.versions WHERE tenant_id='{tenant}' AND subscription='{subscription}'") == '1:1:false', 'quota refusal changed webhook versions')
                require(sql(f"SELECT (SELECT count(*) FROM public.mdm_tenant_operations WHERE operation_id='{operation}')+(SELECT count(*) FROM mdm_webhook.operations WHERE tenant_id='{tenant}' AND id='{operation}')") == '0', kind+' persisted business receipt')
                completion_tenant = tenant if kind == 'webhook' else management
                require(sql(f"SELECT count(*) FROM mdm_audit.receipts r JOIN rss_transactional_messaging.outbox o ON (o.tenant_id,o.message_id)=(r.tenant_id,r.message_id) WHERE r.tenant_id='{completion_tenant}' AND r.reserved AND r.projected_at IS NULL AND convert_from(r.source_bytes,'UTF8')::jsonb->>'operation'='{operation}' AND convert_from(r.source_bytes,'UTF8')::jsonb->>'outcome'='failed'") == '1', kind+' did not atomically queue failure in reserve')
            drained()
    finally:
        host.close()
        sql(f"DELETE FROM mdm_webhook.versions WHERE tenant_id='{tenant}' AND subscription='{subscription}'; DELETE FROM mdm_webhook.subscriptions WHERE tenant_id='{tenant}' AND id='{subscription}'")


def _administrator_rollback(call, path, tenant, password, sql):
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
    for mode in ('rows','bytes'):
        if mode == 'rows':
            fill = f"10000-(SELECT count(*) FROM mdm_access.authorization_rules WHERE tenant_id='{tenant}')"
            document = 'NULL::jsonb'
        else:
            fill = f"(8388608-(SELECT coalesce(sum(octet_length(document::text)),0) FROM mdm_access.authorization_rules WHERE tenant_id='{tenant}'))/octet_length(template.document::text)"
            document = 'template.document'
        seeded = json.loads(sql(f"SET rss.tenant_id='{tenant}'; WITH inserted AS (INSERT INTO mdm_access.authorization_rules(tenant_id,instance,id,revision,document) SELECT template.tenant_id,template.instance,gen_random_uuid(),1,{document} FROM (SELECT * FROM mdm_access.authorization_rules WHERE tenant_id='{tenant}' AND document IS NOT NULL LIMIT 1) template CROSS JOIN LATERAL generate_series(1,({fill})::int) RETURNING id) SELECT coalesce(json_agg(id),'[]'::json) FROM inserted"))
        operation = str(uuid.uuid4())
        before = counts()
        try:
            require(call('POST',path,dict(request,login='capacity-'+mode),operation)[0] == 409, 'administrator exceeded authorization '+mode+' capacity')
            require(counts() == before, 'capacity rejection left partial account/rule')
            require(sql(f"SELECT count(*) FROM public.mdm_tenant_operations WHERE operation_id='{operation}'") == '0', 'capacity rejection saved receipt')
        finally:
            identifiers=','.join("'"+str(uuid.UUID(value))+"'" for value in seeded)
            if identifiers: sql(f"SET rss.tenant_id='{tenant}'; DELETE FROM mdm_access.authorization_rules WHERE tenant_id='{tenant}' AND id IN ({identifiers})")


def _lost_commit_ack(config,password,sql,builds,root,stack,authenticated,tenant):
    """Drop actual PostgreSQL COMMIT acknowledgements without terminating TLS."""
    from concurrent.futures import ThreadPoolExecutor
    import time
    proxy = AckProxy(config['tenant_administration']['registry_database'])
    stack.callback(proxy.close)
    candidate = deepcopy(config)
    for role in ('registry_database','provisioning_database'):
        candidate['tenant_administration'][role]['port'] = proxy.port
    host = Host(builds,private(root/'ack-runtime.json',candidate),root/'ack-host',require_ready=False)
    stack.callback(host.close)
    browser = Browser(host,config['product_origin'])
    # The same-origin management session is valid on either product host.
    browser.cookie, browser.csrf = authenticated.cookie, authenticated.csrf
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
    for kind in ('provision','administrator_create'):
        operation = str(uuid.uuid4())
        if kind == 'provision':
            route = '/provisionings'
            body = dict(name='Lost acknowledgement',administratorLogin='ack-provision-admin',administratorPassword=password)
            role = 'mdm_tenant_registry'
        else:
            target = tenant
            route = '/tenants/' + tenant + '/administrators'
            body = dict(login='ack-admin',password=password)
            role = 'mdm_identity_provisioning'
        sql(f"CREATE FUNCTION public.hold_tenant_ack() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(2); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER tenant_ack AFTER INSERT ON public.mdm_tenant_operations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.operation_id='{operation}'::uuid) EXECUTE FUNCTION public.hold_tenant_ack();")
        stack.callback(sql, 'DROP TRIGGER IF EXISTS tenant_ack ON public.mdm_tenant_operations; DROP FUNCTION IF EXISTS public.hold_tenant_ack()')
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
        if kind == 'provision':
            original=receipt['result']
            status,resumed=browser.call('POST',BASE+route,body,{'Idempotency-Key':operation})
            require(status==202 and resumed['result']['administratorId'] is not None, 'unknown provisioning did not finish administrator phase')
            require(all(resumed['result'][key]==original[key] for key in ('tenantId','hostId','operationId')), 'unknown provisioning replaced reserved identity')
            require(browser.call('POST',BASE+route,body,{'Idempotency-Key':operation})==(202,resumed), 'provisioning replay changed completed administrator')
            target=resumed['result']['tenantId']
            require(sql(f"SELECT count(*) FROM identity_authority.local_credentials WHERE tenant_id='{target}' AND login_key='ack-provision-admin'")=='1', 'provisioning duplicated account')
        else:
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
        self.transfers = []
        self.lock = threading.Lock()
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1',0))
        self.listener.listen()
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        def transfer(source,target,backward):
            try:
                while not self.stop.is_set():
                    try: data = source.recv(16384)
                    except socket.timeout: continue
                    if not data: break
                    if not backward or not self.discard.is_set(): target.sendall(data)
            except OSError:
                pass
            finally:
                for connection in (source, target):
                    try: connection.shutdown(socket.SHUT_RDWR)
                    except OSError: pass
                    connection.close()
        def accept():
            while not self.stop.is_set():
                try: client,_ = self.listener.accept()
                except socket.timeout: continue
                except OSError: break
                try:
                    server = socket.create_connection((database['host'],database['port']),timeout=1)
                except OSError:
                    client.close()
                    continue
                client.settimeout(0.2)
                server.settimeout(0.2)
                with self.lock:
                    if self.stop.is_set():
                        client.close();server.close();break
                    self.sockets.extend((client,server))
                    for source,target,backward in ((client,server,False),(server,client,True)):
                        thread=threading.Thread(target=transfer,args=(source,target,backward),daemon=True)
                        self.transfers.append(thread);thread.start()
        self.thread = threading.Thread(target=accept,daemon=True)
        self.thread.start()
    def close(self):
        self.stop.set()
        self.listener.close()
        import socket
        import time
        with self.lock:
            for connection in self.sockets:
                try: connection.shutdown(socket.SHUT_RDWR)
                except OSError: pass
                connection.close()
        end=time.monotonic()+2
        self.thread.join(timeout=max(0,end-time.monotonic()))
        for thread in self.transfers: thread.join(timeout=max(0,end-time.monotonic()))
        require(not self.thread.is_alive() and not any(t.is_alive() for t in self.transfers),'COMMIT proxy did not release its threads')


def _provisioning_pages_and_active_directory(admin, sql):
    # Seed the minimal valid reserved receipts: listing does not require accounts or hosts to run.
    seed = uuid.uuid4().hex
    ids = f"SELECT md5('{seed}'||i::text)::uuid FROM generate_series(1,1101) i"
    before = int(sql("SELECT count(*) FROM public.mdm_tenant_operations WHERE action='provision'"))
    sql(f"INSERT INTO public.mdm_tenants(tenant_id,initial_epoch,deleted) SELECT md5('{seed}'||i::text)::uuid,1,i>1001 FROM generate_series(1,1101) i")
    try:
        sql(f"""INSERT INTO public.mdm_tenant_operations(operation_id,tenant_id,action,request,operator,receipt)
        SELECT id,id,'provision','{{}}','{{}}',jsonb_build_object('operationId',id,'action','provision','result',
        jsonb_build_object('operationId',id,'tenantId',id,'hostId',md5(id::text||'host')::uuid,
        'administratorId',NULL,'revision',1,'phase','reserved','blocked',NULL,'origin',NULL,'application',NULL))
        FROM ({ids}) q(id)""")
        seen = set()
        cursor = None
        while True:
            query = '/provisionings?limit=1000' + ('&cursor=' + cursor if cursor else '')
            status, page = admin.call('GET', BASE + query)
            require(status == 200 and 0 < len(page['items']) <= 1000, 'provisioning page failed at legal capacity')
            current = [item['operationId'] for item in page['items']]
            require(current == sorted(current) and not seen.intersection(current), 'provisioning pagination repeated or reordered rows')
            seen.update(current)
            cursor = page['nextCursor']
            if cursor is None:
                break
        require(len(seen) == before + 1101, 'provisioning history lost rows')
        status, catalog = admin.call('GET', BASE + '/settings/catalog')
        host = next(item for item in catalog['items'] if item['id'] == 'host-config')
        expected = int(sql("SELECT count(*) FROM public.mdm_tenant_operations o JOIN public.mdm_tenants t USING(tenant_id) WHERE o.action='provision' AND NOT t.deleted"))
        require(status == 200 and host['configuredCount'] == expected and expected > 1000, 'active directory omitted legal tenants or included deleted history')
        require(admin.call('GET', BASE + '/provisionings?limit=1001')[0] == 400, 'unbounded page accepted')
    finally:
        sql(f"DELETE FROM public.mdm_tenant_operations WHERE operation_id IN ({ids})")
        sql(f"DELETE FROM public.mdm_tenants WHERE tenant_id IN ({ids})")
