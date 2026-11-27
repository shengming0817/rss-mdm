#!/usr/bin/env python3
"""Run the fixed MDM OCI with only its own PostgreSQL and HTTPS ingress."""
import argparse
import base64
import secrets
from enum import StrEnum
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import socket
import time
import threading
import uuid
from release import sha
from candidate_fixture import INSTANCE, ADMIN, TENANTS, installation

TENANT = TENANTS[0]
PASSWORD = "Candidate-only-correct-horse-battery-2026!"

from candidate_runtime import Candidate, Stage, docker, failure_evidence, require, wait

class Browser:
    # Browser sessions share the loopback peer's 10 requests/second gateway quota.
    last_request = 0.0

    def __init__(self, port, ca, *, host="mdm.example.test"):
        self.host=host
        self.port, self.context = port, ssl.create_default_context(cafile=ca)
        self.cookie, self.csrf = "", ""
    def call(self, method, path, data=None, operation=None, *, chunked=False, during_upload=None):
        remaining = Browser.last_request + 0.125 - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)
        Browser.last_request = time.monotonic()
        headers = {"Host":self.host, "Origin":"https://"+self.host, "X-Identity-Request":"1"}
        if self.cookie: headers["Cookie"] = self.cookie
        if self.csrf: headers["X-CSRF-Token"] = self.csrf
        if operation: headers["Idempotency-Key"] = operation
        if data is not None: headers["Content-Type"] = "application/json"
        connection = http.client.HTTPSConnection("127.0.0.1", self.port, context=self.context, timeout=15)
        try:
            connection.sock=self.context.wrap_socket(socket.create_connection(("127.0.0.1",self.port),timeout=15),server_hostname=self.host)
            body = json.dumps(data).encode() if data is not None else None
            if chunked and body is not None:
                def chunks():
                    for offset in range(0, len(body), 65536):
                        yield body[offset:offset+65536]
                        if offset == 8*1024**2 and during_upload is not None:
                            during_upload()
                connection.request(method, path, body=chunks(), headers=headers, encode_chunked=True)
            else:
                connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            body = response.read()
            self.retry_after = response.getheader("Retry-After")
            request_id = response.getheader("x-request-id")
            self.request_id = str(uuid.UUID(request_id)) if request_id is not None else None
            for key, value in response.getheaders():
                if key.lower() == "set-cookie":
                    require("Secure" in value and "HttpOnly" in value and "Path=/" in value and "Domain=" not in value,
                            "candidate cookie protections missing")
                    self.cookie = value.split(";",1)[0]
            value = json.loads(body) if body and response.getheader("Content-Type", "").startswith("application/json") else None
            if isinstance(value,dict) and "csrfToken" in value: self.csrf = value["csrfToken"]
            return response.status, value
        finally:
            connection.close()

def verify_request_slots(browser):
    path = f'/api/v1/tenants/{TENANT}/authorization'
    held = []
    try:
        for _ in range(5):
            connection = http.client.HTTPSConnection('127.0.0.1',browser.port,context=browser.context,timeout=6)
            connection.sock = browser.context.wrap_socket(socket.create_connection(('127.0.0.1',browser.port),timeout=6),
                                                           server_hostname=browser.host)
            held.append(connection)
            connection.putrequest('GET',path,skip_host=True)
            for key, value in {'Host':browser.host,'Cookie':browser.cookie,'Origin':'https://'+browser.host,
                               'Content-Type':'application/json','Content-Length':'2'}.items():
                connection.putheader(key,value)
            connection.endheaders(b'{')
        wait(lambda: browser.call('GET', path)[0] == 429 and browser.retry_after == '1',
             'five actual requests occupy the configured host slots', seconds=3)
        # Disconnect before finishing the body; the other four requests keep their own slots.
        held.pop().close()
        wait(lambda: browser.call('GET', path)[0] == 200, 'client cancellation returned a host permit',seconds=3)
        for connection in held:
            connection.send(b'}')
            response=connection.getresponse()
            require(response.status==200, 'each retained request passed scope lookup and authorization')
            response.read()
    finally:
        for connection in held:
            connection.close()

def ingress_capacity(browser, principal, deployed, inventory_report=None):
    profile = f'/api/v1/identity/tenants/{TENANT}/accounts/{principal}/profile'
    status, original = browser.call('GET', profile)
    require(status == 200, 'local profile read')
    operation = str(uuid.uuid4())
    value = dict(displayName='Candidate', username=None, email=None, maxAgeSeconds=60,
                 extensions={f'field{n:04}': 'value' * 24 for n in range(256)})
    change = dict(operationId=operation, expectedRevision=original['revision'], value=value)
    csrf = browser.csrf
    browser.csrf = ''
    require(browser.call('PUT', profile, change)[0] == 403, 'profile CSRF')
    browser.csrf = csrf
    status, receipt = browser.call('PUT', profile, change, chunked=True)
    require(status == 200 and receipt['operationId'] == operation, 'large profile write')
    require(browser.call('GET', profile) == (200, dict(revision=receipt['revision'], value=value)), 'large profile readback')
    require(browser.call('PUT', profile, change) == (200, receipt), 'large profile replay')
    require(browser.call('GET', profile + '/operations/' + operation) == (200, receipt), 'large profile receipt')
    require(browser.call('PUT', profile, dict(change, padding='x' * 98304))[0] == 413, 'profile wire ceiling')

    for method, target in [('GET', profile), ('PUT', profile + '/adjacent')]:
        require(browser.call(method, target, change)[0] == 413, 'ordinary route budget on adjacent method/path')

    base = f'/api/v1/tenants/{TENANT}'
    source = base + '/software/source-snapshots/candidate-source'
    records = [{'name':f'item-{n}', 'version':'1'} for n in range(4096)]
    document = {'records':records, 'padding':'x'*(63*1024**2)}
    change = dict(operationId=str(uuid.uuid4()), expectedRevision=0,
                  input=dict(document=document, extraction={'records':'/records','name':'/name','version':'/version'}))
    def check_reservation():
        status, rejection = browser.call('POST', source, {})
        require(status == 429 and rejection == {'code':'request_limited'} and browser.retry_after == '1',
                'second snapshot exceeded buffered bytes')
        require(browser.call('GET', profile)[0] == 200, 'small request kept its reserved capacity')
        anonymous=Browser(browser.port,deployed.root/'ca.crt')
        require(anonymous.call('POST',source,{})[0]==401, 'anonymous snapshot rejected before reserving bytes')
    samples = []
    stopped = threading.Event()
    def sample():
        script = ('if test -r /sys/fs/cgroup/memory.current; then echo cgroup-v2 $(cat /sys/fs/cgroup/memory.current); '
                  'elif test -r /sys/fs/cgroup/memory/memory.usage_in_bytes; then echo cgroup-v1 $(cat /sys/fs/cgroup/memory/memory.usage_in_bytes); '
                  'elif test -r /proc/1/status; then awk \'/^VmRSS:/{printf "process-rss %.0f\\n",$2*1024}\' /proc/1/status; fi')
        while not stopped.is_set():
            try:
                source_name, raw=deployed.command('exec',deployed.server,'sh','-c',script,stage=Stage.SQL).split()
                samples.append((source_name,int(raw)))
            except (RuntimeError,ValueError,OSError):
                return
            stopped.wait(.08)
    sampler=threading.Thread(target=sample)
    sampler.start()
    try:
        wire_bytes=len(json.dumps(change).encode())
        status, receipt=browser.call('POST',source,change,chunked=True,during_upload=check_reservation)
        require(status==200 and receipt['entryCount']==len(records),'near-limit snapshot extract and import')
    finally:
        stopped.set()
        sampler.join()
    memory=dict(snapshotWireBytes=wire_bytes,bufferedAdmissionBytes=deployed.config['http']['buffered_body_bytes'],
                sampleCount=len(samples), source=samples[0][0] if samples else 'unavailable',
                requestStartBytes=samples[0][1] if samples else None,
                requestSampledPeakBytes=max((value for _,value in samples),default=None))
    # A declared over-limit Content-Length is enough for the official gateway to reject before upload.
    connection=http.client.HTTPSConnection('127.0.0.1',browser.port,context=browser.context,timeout=15)
    try:
        connection.sock=browser.context.wrap_socket(socket.create_connection(('127.0.0.1',browser.port),timeout=15),server_hostname=browser.host)
        connection.request('POST',source,headers={'Host':browser.host,'Content-Length':str(64*1024**2+1)})
        require(connection.getresponse().status==413, 'snapshot wire ceiling')
    finally:
        connection.close()
    for path in ('policies/missing/previews', 'policies/missing/scope/previews',
                 'policies/missing/stages/missing/scope/previews'):
        status, _ = browser.call('POST', base + '/' + path, dict(unrecognized='x'*20000))
        require(status in (400, 404, 422) and browser.request_id is not None, 'preview reached its application validator')
        require(browser.call('PUT', base + '/' + path, dict(unrecognized='x'*20000))[0] == 413,
                'preview allowance restricted to POST')

    key = 'custom.capacity_enum'
    path = f'/api/v1/tenants/{TENANT}/asset-fields/' + key
    members = [f'state{n:04}' + 's' * 128 for n in range(1024)]
    definition = dict(key=key, version=1, valueType=dict(kind='enum', values=members),
                      nullable=False, manual=False, sources={'agent.builtin': 0}, platforms=['windows'],
                      sensitivity='standard', unit=None, searchable=False, itemKey=None, timeSeries=None)
    if inventory_report is not None:
        # Publish one member of the same complete collection through the management API.
        definition = json.loads(inventory_report.read_bytes())['fields'][1]
        key = definition['key']
        path = f'/api/v1/tenants/{TENANT}/asset-fields/' + key
        members = definition['valueType']['values']
    change = dict(operationId=str(uuid.uuid4()), expectedRevision=0, input=dict(action='put', definition=definition))
    status, _ = browser.call('PUT', path, change)
    require(status in (200, 202), 'large field publication')
    def published():
        status, result = browser.call('GET', path)
        return status == 200 and result['asset']['field']['valueType']['values'] == members
    wait(published, 'complete field vocabulary readback')
    return memory

def blocked_report_diagnostic(deployed, browser, path, recorded):
    from concurrent.futures import ThreadPoolExecutor
    spare = Browser(deployed.port, deployed.root / 'ca.crt')
    identity = f'/api/v1/identity/tenants/{deployed.tenant}'
    require(spare.call('POST', identity + '/login', dict(login='admin', password=PASSWORD))[0] == 200,
            'second diagnostic session')
    holder_pids = """SELECT l.pid FROM pg_locks l JOIN pg_stat_activity a USING (pid)
        WHERE a.application_name='candidate_report_lock' AND l.relation='rss_observation.batches'::regclass
          AND l.mode='AccessExclusiveLock' AND l.granted"""
    has_lock = f"SELECT EXISTS ({holder_pids})"
    waiting = f"""SELECT EXISTS (SELECT FROM pg_stat_activity a WHERE usename='mdm_runtime'
        AND query LIKE '%AND scope=$2 AND batch_id=$3%'
        AND EXISTS (SELECT 1 FROM ({holder_pids}) h WHERE h.pid=ANY(pg_blocking_pids(a.pid))))"""
    with subprocess.Popen(["docker", *deployed.psql_args()], text=True, stdin=subprocess.PIPE,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as holder:
        try:
            holder.stdin.write("""BEGIN;
                SET LOCAL application_name='candidate_report_lock';
                SET LOCAL idle_in_transaction_session_timeout='45s';
                LOCK TABLE rss_observation.batches IN ACCESS EXCLUSIVE MODE;
                """)
            holder.stdin.flush()
            wait(lambda: deployed.sql(has_lock) == 't', 'isolated journal lock', seconds=5)
            status, degraded = browser.call('GET', path)
            require(status == 200 and degraded['originalResult'] == recorded['originalResult']
                    and degraded['executionEvidence']['availability'] == 'unavailable'
                    and deployed.sql(has_lock) == 't', 'bounded probe preserves original receipt')
            wait(lambda: deployed.sql(waiting) == 'f', 'first bounded probe released', seconds=5)
            with ThreadPoolExecutor(max_workers=1) as tasks:
                read = tasks.submit(spare.call, 'GET', path)
                wait(lambda: deployed.sql(waiting) == 't', 'live diagnostic probe waiting', seconds=5)
                require(spare.call('POST', identity + '/session/logout')[0] == 204, 'revoke diagnostic session')
                require(read.result()[0] in (401,403), 'diagnostic return uses current authority')
        finally:
            try:
                holder.communicate("ROLLBACK;\n", timeout=5)
            except subprocess.TimeoutExpired:
                holder.kill()
                holder.wait()
                raise
        require(holder.returncode == 0, 'journal lock released')


def report_history(deployed, browser, binding, call):
    report_id = str(uuid.uuid4())
    path = '/api/v1/agent/runtime/reports'
    item = path + '/' + report_id
    require(call('GET', item) == (404, {'code': 'report_not_found'}), 'unknown report identity')
    field = 'channel.mdm.enrollment'
    collection = next(c for c in binding['collections'] if any(f['key'] == field for f in c['fields']))
    request = dict(wireVersion=1, reportId=report_id, sequence=1, observedAt=int(time.time()),
                   collection=collection, body=dict(kind='snapshot', values=[
                       dict(field=field, value=dict(kind='value', value=dict(kind='string', value='unenrolled')))]))
    status, ack = call('POST', path, request)
    require(status == 202 and ack['reportId'] == report_id, 'durable report intake')
    expected = dict(ack=ack, observation='snapshot', projection='applied')
    wait(lambda: call('GET', item) == (200, expected), 'confirmed report and projection')
    run_path = f"/api/v1/tenants/{deployed.tenant}/devices/{binding['deviceId']}/collections/{report_id}"
    def run():
        status, body = browser.call('GET', run_path)
        require(status == 200, 'authorized collection run')
        return body['asset']['run']
    require(run()['delivery']['receipt']['status'] == 'found', 'management receipt')
    diagnostic_path = f"/api/v1/tenants/{deployed.tenant}/operation-diagnostics/operations/collection/{report_id}?device={binding['deviceId']}"
    def diagnostic():
        status, evidence = browser.call('GET', diagnostic_path)
        require(status == 200 and evidence['originalResult']['availability'] == 'available',
                'original collection receipt available')
        return evidence
    recorded = diagnostic()
    require(recorded['executionEvidence'] == dict(availability='available', value=dict(
        owner='inventory_report', observation='found', projection='projected')), 'live collection evidence')
    blocked_report_diagnostic(deployed, browser, diagnostic_path, recorded)
    # Simulate an unreadable Observation record in this disposable deployment.
    deployed.sql(f"UPDATE rss_observation.batches SET decision='invalid' WHERE tenant_id='{deployed.tenant}' AND batch_id='{report_id}'")
    unavailable = diagnostic()
    require(unavailable['originalResult'] == recorded['originalResult'] and
            unavailable['executionEvidence']['availability'] == 'unavailable', 'independent original receipt')
    # Seed released content and an unacknowledged product delivery in this disposable database.
    # The immutable RSS identity and independent projection receipt stay intact.
    result = deployed.sql(f"""BEGIN;
        SELECT set_config('rss.tenant_id','{deployed.tenant}',true),
               set_config('rss.execution_epoch',expected_epoch::text,true)
        FROM mdm_access.collection_runs WHERE tenant_id='{deployed.tenant}' AND id='{report_id}';
        WITH released AS (
            UPDATE rss_observation.batches SET raw=NULL,policy=NULL,decision=NULL
            WHERE tenant_id='{deployed.tenant}' AND batch_id='{report_id}' AND raw IS NOT NULL RETURNING 1
        ), pending AS (
            UPDATE mdm_access.collection_runs SET delivery_pending=true
            WHERE tenant_id='{deployed.tenant}' AND id='{report_id}' AND NOT delivery_pending RETURNING 1
        ) SELECT (SELECT count(*) FROM released),(SELECT count(*) FROM pending);
        COMMIT;""")
    require('1|1' in result.splitlines(), 'seeded exactly one released report and one pending acknowledgement')
    expected['observation'] = 'expired'
    require(call('GET', item) == (200, expected), 'expired receipt preserves intake and projection')
    def expired():
        value = run()
        pending = deployed.sql(f"SELECT delivery_pending FROM mdm_access.collection_runs WHERE tenant_id='{deployed.tenant}' AND id='{report_id}'")
        return (value['delivery'] == dict(receipt={'status':'expired'}, projection='projected')
                and pending.strip() == 'f')
    wait(expired, 'same fingerprint settles expired pending delivery')
    require(diagnostic()['executionEvidence'] == dict(availability='available', value=dict(
        owner='inventory_report', observation='expired', projection='projected')), 'expired collection evidence')
    return ['report_not_found', 'report_projection_confirmed', 'report_probe_budget', 'report_authority_rechecked', 'original_receipt_independent', 'expired_report_preserves_ack',
            'expired_report_pending_delivery_settled']

def installed_capacity_report(deployed, path, call):
    import base64
    payload = json.loads(path.read_bytes())
    def encoded(value):
        return base64.b64encode(json.dumps(value, separators=(',', ':')).encode()).decode('ascii')
    fields = encoded(payload['fields'])
    definition = encoded(payload['definition'])
    tenant = uuid.UUID(deployed.tenant)
    # Only the field catalog is a fixture; authentication, receipt and projection use the deployed service.
    deployed.sql(f"""BEGIN;
        SELECT set_config('rss.tenant_id','{tenant}',true),
               set_config('rss.storage_target',encode(s.target,'hex'),true),
               set_config('rss.storage_lineage',encode(s.lineage,'hex'),true),
               set_config('rss.execution_epoch',e.epoch::text,true)
        FROM rss_transactional_messaging.storage_lineage s JOIN rss_transactional_messaging.tenant_epoch e ON e.tenant_id='{tenant}';
        SELECT count(mdm.append_field_version('{tenant}',f->>'key',1,f))
          FROM jsonb_array_elements(convert_from(decode('{fields}','base64'),'UTF8')::jsonb) f
          WHERE NOT EXISTS (SELECT FROM mdm.field_versions v WHERE v.tenant_id='{tenant}' AND v.field=f->>'key' AND v.version=1 AND v.definition=f);
        INSERT INTO mdm.collection_definitions
          SELECT (jsonb_populate_record(NULL::mdm.collection_definitions,
             convert_from(decode('{definition}','base64'),'UTF8')::jsonb || jsonb_build_object('tenant_id','{tenant}'))).*;
        COMMIT;""")
    request=payload['report']
    request.update(reportId=str(uuid.uuid4()),observedAt=int(time.time()))
    size=len(json.dumps(request,separators=(',',':')).encode())
    require(4*1024*1024-150*1024<=size<=4*1024*1024,'candidate report fixture size')
    route='/api/v1/agent/runtime/reports'
    status,ack=call('POST',route,request)
    require(status==202 and ack['reportId']==request['reportId'],'installed large report intake')
    wait(lambda:call('GET',route+'/'+request['reportId'])==(200,dict(ack=ack,observation='snapshot',projection='applied')),
         'installed large report projection',seconds=120)
    return 'installed_near_limit_inventory_report'

def native_pki_journey(deployed,browser,inventory_report=None):
    root=deployed.root;fixture=root/'pki/agent'
    csr=base64.b64encode((fixture/'agent.der').read_bytes()).decode()
    secret=secrets.token_urlsafe(32);deployed.private_values.append(secret)
    operation=str(uuid.uuid4())
    request=dict(tenantId=deployed.tenant,wireVersion=1,operationId=operation,secret=secret,platform='macos',csr=csr)
    context=ssl.create_default_context(cafile=str(root/'ca.crt'))
    def connection():
        from urllib.parse import urlsplit
        host=urlsplit(deployed.agent_origin).hostname
        client=http.client.HTTPSConnection(host,deployed.agent_port,context=context,timeout=15)
        client.sock=context.wrap_socket(socket.create_connection(('127.0.0.1',deployed.agent_port),timeout=15),server_hostname=host)
        return client
    def call(client,method,path,body=None):
        deadline=time.monotonic()+5
        while True:
            client.request(method,path,body=json.dumps(body,separators=(',',':')) if body is not None else None,
                           headers={'Content-Type':'application/json','Host':deployed.agent_origin.removeprefix('https://')})
            response=client.getresponse();data=response.read(8*1024*1024+1)
            require(len(data)<=8*1024*1024,'candidate native response limit')
            # Functional enrollment checks share the gateway's real peer quota. Only a read
            # may retry an explicit rate denial; mutation and identity responses remain exact.
            if method=='GET' and response.status==429 and time.monotonic()<deadline:
                time.sleep(.2)
                continue
            return response.status,json.loads(data) if data else None
    client=connection()
    try:
        require(call(client,'GET','/api/v1/agent/enroll/packages?tenantId='+deployed.tenant)==(200,[]),
                'candidate native Agent package catalogue failed')
        status,pending=call(client,'POST','/api/v1/agent/enroll/requests',request)
        require(status==200 and pending['state']=='pending','candidate CSR request failed')
        status,grant=browser.call('POST',f'/api/v1/tenants/{TENANT}/agent-requests/'+pending['grantId']+'/authorize',
                                  dict(operationId=str(uuid.uuid4())))
        require(status==200 and grant['state']=='available','candidate Agent authorization failed')
        status,trust=call(client,'GET','/api/v1/agent/enroll/trust?tenantId='+deployed.tenant)
        require(status==200 and trust['origin']==deployed.agent_origin and trust['purpose']=='agent','candidate public trust authority mismatch')
        profile=dict(capabilities=['inventory.collect.v1'],platform='macos',architecture='aarch64',
                     executionContext=dict(revision=1,osVersion=[14,0,0,0],userHelper=False,systemBroker=True,interactiveUser=None,sourceCredentials=[],msixSideload=False,msixUnsigned=False))
        signing=dict(wireVersion=1,operationId=str(uuid.uuid4()),grantId=grant['grantId'],secret=secret,csr=csr,runtime=profile)
        status,candidate=call(client,'POST','/api/v1/agent/enroll/certificates',signing)
        require(status==200,f'candidate real CA signing failed: status={status}, code={candidate.get("code") if isinstance(candidate,dict) else None}')
        require(call(client,'POST','/api/v1/agent/enroll/certificates',signing)==(status,candidate),'candidate original signing replay changed result')
        path='/api/v1/agent/runtime/reports/'+str(uuid.uuid4())
        require(call(client,'GET',path)[0]==401,'candidate anonymous runtime accepted')
    finally:client.close()
    certificate=root/'candidate-agent.pem'
    certificate.write_text(''.join(ssl.DER_cert_to_PEM_cert(base64.b64decode(der)) for der in candidate['certificateChain']));certificate.chmod(0o600)
    context.load_cert_chain(certificate,fixture/'agent-csr-agent.key')
    client=connection()
    try:
        require(call(client,'GET',path)[0]==401,'unactivated candidate acquired runtime identity')
        activation=dict(wireVersion=1,operationId=str(uuid.uuid4()),issuanceId=candidate['issuanceId'])
        status,active=call(client,'POST','/api/v1/agent/enroll/activate',activation)
        require(status==200,'candidate actual mTLS activation failed')
        require(call(client,'POST','/api/v1/agent/enroll/activate',activation)==(status,active),'candidate activation replay changed registration')
        report_checks = report_history(deployed, browser, active['runtime'], lambda *args: call(client, *args))
        if inventory_report is not None:
            report_checks.append(installed_capacity_report(deployed,inventory_report,lambda *args:call(client,*args)))
    finally:client.close()
    deployed.restore_pki_bundle()
    client=connection()
    try:
        require(call(client,'GET',path)[0]==404,'restored original Agent identity rejected')
        binding=active['runtime']
        require(browser.call('POST',f'/api/v1/tenants/{TENANT}/devices/'+binding['deviceId']+'/registration/revoke',{},str(uuid.uuid4()))[0]==200,'candidate credential revoke failed')
        require(call(client,'GET',path)[0]==401,'revoked credential remained valid on retained TLS connection')
    finally:client.close()
    wait(lambda:deployed.sql("SELECT count(*) FROM mdm_pki.revocations WHERE purpose='agent' AND state='published'")=='1',
         'actual serial publication in signed CA CRL',seconds=150)
    client=connection()
    try:
        try:
            response=call(client,'GET',path)
            require(response[0]==401,'published revoked certificate acquired a new identity')
        except (ssl.SSLError,ConnectionResetError):pass
    finally:client.close()
    return report_checks + ['native_public_packages','native_public_trust','real_ca_signing','original_signing_replay','candidate_identity_denial','actual_mtls_activation',
            'activation_replay','joint_ca_mdm_audit_restore','same_registration_after_restore','retained_tls_revocation','signed_crl_serial_publication','new_tls_revocation']

def run_smoke(directory,inventory_report=None):
    def capacity_config(candidate):
        candidate.config['http']['request_slots'] = 5
    with Candidate(directory, prepare=capacity_config, diagnostic_filename="smoke-failure.json") as deployed:
        manifest=deployed.manifest
        digest=manifest["archive"]["manifest_digest"];archive=directory/manifest["archive"]["file"]
        pg,gateway,server=deployed.pg,deployed.gateway,deployed.server
        sql=deployed.sql
        browser=Browser(deployed.port,deployed.root/"ca.crt")
        require(browser.call("GET", "/livez") == (200, {"alive": True}), "candidate liveness failed")
        tenant="/api/v1/identity/tenants/"+TENANT
        require(browser.call("GET",f"/api/v1/tenants/{TENANT}/authorization")[0]==401,"anonymous candidate accepted")
        require(browser.call("POST",tenant+"/login",dict(login="admin",password=PASSWORD))[0]==200,"local candidate login failed")
        status,principal=browser.call("GET",f"/api/v1/tenants/{TENANT}/authorization")
        require(status==200 and (principal["instanceId"],principal["tenantId"],principal["principalId"])==(INSTANCE,TENANT,ADMIN),"candidate subject mismatch")
        management=Browser(deployed.port,deployed.root/"ca.crt")
        management_api="/api/v1/identity/tenants/"+deployed.management_tenant
        require(management.call("POST",management_api+"/login",dict(login="admin",password=PASSWORD))[0]==200,
                "candidate management login failed")
        status,grants=management.call("GET","/api/v1/tenant-administration/authorization")
        require(status==200 and any(grant["operation"]=="tenant_create" for grant in grants["grants"]),
                "candidate tenant creation permission missing")
        require(management.call("GET",f"/api/v1/tenants/{TENANT}/resources")[0] in (401,403),"candidate management entered business")
        require(browser.call("GET","/api/v1/tenant-administration/authorization")[0]==401,
                "candidate business entered management")
        administrator=browser
        status,account=administrator.call('POST',tenant+'/accounts',dict(login='scoped',password=PASSWORD))
        require(status==201 and isinstance(account.get('principalId'),str),'candidate scoped account creation')
        verify_request_slots(administrator)
        memory = ingress_capacity(administrator, account["principalId"], deployed,inventory_report)
        browser=Browser(deployed.port,deployed.root/'ca.crt')
        require(browser.call('POST',tenant+'/login',dict(login='scoped',password=PASSWORD))[0]==200,
                'candidate scoped account login')
        operation=str(uuid.uuid4())
        enrollment=dict(password="A"*43,source="mdm.windows",windowsProfile="Device")
        status,receipt=administrator.call("POST",f"/api/v1/tenants/{TENANT}/enrollments",enrollment,operation)
        require(status==200 and receipt["status"]=="pending","candidate enrollment failed")
        require(administrator.call("POST",f"/api/v1/tenants/{TENANT}/enrollments",enrollment,operation)==(status,receipt),"candidate replay changed enrollment")
        device=str(uuid.UUID(receipt["deviceId"]))
        rule=dict(subject=dict(kind='user',user=dict(instanceId=INSTANCE,tenantId=TENANT,principalId=account["principalId"])),grants=[dict(operation=operation,scope=dict(kind='device',id=device)) for operation in ['inventory_read','enrollment','credentials']])
        require(administrator.call('PUT',f'/api/v1/tenants/{TENANT}/authorization/rules/'+str(uuid.uuid4()),dict(operationId=str(uuid.uuid4()),expectedRevision=0,value=rule))[0]==200,'candidate explicit authorization')
        status, enrollment_status=administrator.call("GET",f"/api/v1/tenants/{TENANT}/enrollments/"+receipt["enrollmentId"])
        require(status==200 and enrollment_status.get("status")=="pending","candidate creator enrollment query failed: "+str(status))
        denied=str(uuid.uuid4())
        require(browser.call("POST",f"/api/v1/tenants/{TENANT}/enrollments",enrollment,denied)[0]==403,"device-scoped authority created a new device")
        require(browser.request_id is not None,"candidate protected response has no request identity")
        event_id = "e-" + hashlib.sha256(browser.request_id.encode()).hexdigest()
        wait(lambda: sql("SELECT count(*) FROM rss_audit.records WHERE tenant_id='"+TENANT+"' AND source_id='mdm.request' AND event_id='"+event_id+"'")=="1", "candidate denial audit projection")
        require(browser.call("POST",f"/api/v1/tenants/{TENANT}/devices/{device}/actions",dict(action="wipe"),str(uuid.uuid4()))[0]==403,"wipe permission bypass")
        require(browser.call("GET",f"/api/v1/tenants/{TENANT}/devices/88888888-8888-4888-8888-888888888882/inventory")[0]==403,"inventory scope bypass")
        # The independent native journey shares the real gateway's 10r/s, burst-20 API quota.
        # Let the browser checks' burst drain before testing mutation replay without retries.
        time.sleep(2.2)
        pki_checks=native_pki_journey(deployed,administrator,inventory_report)
        old_cookie=browser.cookie
        require(browser.call("POST",tenant+"/session/refresh")[0]==200 and browser.cookie!=old_cookie,"candidate refresh failed")
        stale=Browser(deployed.port,deployed.root/"ca.crt");stale.cookie=old_cookie
        require(stale.call("GET",f"/api/v1/tenants/{TENANT}/authorization")[0]==401,"rotated credential accepted")
        require(browser.call("POST",tenant+"/session/logout")[0]==204,"candidate logout failed")
        require(browser.call("GET",f"/api/v1/tenants/{TENANT}/authorization")[0]==401,"logged-out candidate accepted")
        started=time.monotonic();docker("stop","--time","45",server,timeout=55,stage=Stage.STOP)
        elapsed=time.monotonic()-started
        logs=docker("logs",server,stage=Stage.LOGS)
        require("mdm_request" in logs, "candidate request diagnostics missing")
        require(elapsed<45 and docker("inspect","--format","{{.State.ExitCode}}",server,stage=Stage.EXIT)=="0" and "mdm_shutdown_failure" not in logs,"candidate bounded shutdown failed")
        result=dict(ingressMemory=memory,source=manifest["source"],candidate_sha256=sha(directory/"candidate.json"),manifest_digest=digest,archive_sha256=sha(archive),platform=manifest["platform"],
                    checks=pki_checks+["concurrent_snapshot_byte_reservation","five_shared_request_slots","cancel_releases_request_slot","large_profile_write_read_replay","large_field_publication","management_bootstrap","management_login","management_grants","management_business_isolation","migrate","migration_replay","interrupted_migration_resumed","committed_migration_receipts_preserved","installed_component_revisions","initialize","authorization_initialize","authorization_replay","livez","readyz","local_login","authoritative_subject","enrollment","idempotent_replay","device_scope_denial","denial_no_effect","denial_audit","wipe_denial","inventory_scope_denial","refresh_rotation","logout","bounded_stop"],
                    shutdown_seconds=round(elapsed,3),limits=["disposable MDM PostgreSQL and TLS namespace","no real Windows or macOS device T3"])
        if deployed.web is not None:
            result["ui"] = deployed.web
    return result,logs+"\n"

def smoke(directory,inventory_report=None):
    marker, log = directory / "smoke.json", directory / "smoke.log"
    for path in (marker, log, directory / "smoke-failure.json"):
        path.unlink(missing_ok=True)
    try:
        result, output = run_smoke(directory) if inventory_report is None else run_smoke(directory,inventory_report)
        # Publish only after both fixture owners have finished cleanup. The marker
        # is last and binds the log, so readers never accept a partial evidence pair.
        with tempfile.TemporaryDirectory(prefix=".smoke-", dir=directory) as temporary:
            staged_log, staged_marker = Path(temporary) / "log", Path(temporary) / "marker"
            staged_log.write_text(output)
            result["log_sha256"] = sha(staged_log)
            staged_marker.write_text(json.dumps(result, indent=2) + "\n")
            os.replace(staged_log, log)
            os.replace(staged_marker, marker)
    except BaseException as error:
        marker.unlink(missing_ok=True)
        log.unlink(missing_ok=True)
        if not (directory / "smoke-failure.json").exists():
            failure_evidence(directory, [], set(), error)
        raise
    print("candidate smoke: " + str(directory / "smoke.json"))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument('--inventory-report',type=Path,help='Capacity fixture exported by inventory.collection')
    args=parser.parse_args()
    smoke(args.candidate.resolve(),args.inventory_report)
