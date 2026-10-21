"""Isolated real telemetry providers; production Rust owns installation and admission.

ref: docker-library/postgres docker-entrypoint.sh; timescale/timescaledb-docker Dockerfile.
"""
from __future__ import annotations
from contextlib import contextmanager, ExitStack
import json
import secrets
import uuid
import threading
from t2_environment import Environment, PROVIDERS, private


_OWNER_LOCK = threading.RLock()

@contextmanager
def telemetry_profiles(root, tenant, selected=None, primary=None):
    root = root.resolve()
    # Installation/fault cases own whole providers. Serialize reuse of these named owners.
    with _OWNER_LOCK, _profiles(root, tenant, selected, primary) as environment:
        yield environment

@contextmanager
def _profiles(root, tenant, selected, primary):
    """Separate storage databases and logins; no product schema or telemetry result seeding."""
    owners = []
    requests = []
    ch_base = None
    ch_owner = None
    try:
        for image, names in [('telemetry-postgres', ('postgres','click_house')),
                             ('telemetry-timescale', ('timescale_shared', 'timescale_dedicated'))]:
            names = tuple(kind for kind in names if selected is None or kind == selected)
            if not names:
                continue
            owner = Environment(group='t2-' + image, providers={**PROVIDERS, 'postgres': PROVIDERS[image]})
            owners.append(owner)
            owner.reset()
            owner.up()
            for kind in names:
                name = 'telemetry_' + uuid.uuid4().hex
                owner.sql(f'CREATE DATABASE "{name}"')
                if kind.startswith('timescale'):
                    owner.sql('CREATE EXTENSION IF NOT EXISTS timescaledb VERSION \'2.30.2\'', name)
                directory = root / kind
                directory.mkdir(parents=True, mode=0o700)
                password = private(directory / 'administrator-password', 'local-fixture')
                runtime_password = private(directory / 'runtime-password', secrets.token_hex(24))
                maintenance_password = private(directory / 'maintenance-password', secrets.token_hex(24))
                cursor = private(directory / 'cursor-key', '')
                cursor.write_bytes(secrets.token_bytes(32))
                database = dict(host='localhost', port=owner.port(), name=name, user='postgres',
                                password_file=str(password), ca_file=str(owner.root / 'ca.crt'))
                runtime = {**database, 'user': 'r_' + uuid.uuid4().hex,
                           'password_file': str(runtime_password)}
                role = 'o_' + uuid.uuid4().hex
                backend = dict(kind='postgres' if kind=='click_house' else kind, database=runtime)
                if kind.startswith('timescale'):
                    backend['chunk_micros'] = 86400000000
                if kind == 'timescale_dedicated':
                    backend.update(tenant=tenant, maintenance_owner=role, resolutions=[60000000],
                                   maintenance={**database, 'user': 'm_' + uuid.uuid4().hex,
                                                'password_file': str(maintenance_password)})
                configuration = dict(backend=backend, connections=2, cursor_key_file=str(cursor),
                                     ingress=dict(requestBytes=1048576, pendingBatches=64,
                                                  batchesPerMinute=120, bytesPerMinute=8388608),
                                     limits=dict(max_points=4096, max_series=4096, max_bytes=1048576,
                                                 replay_micros=86400000000, cursor_micros=60000000))
                request=dict(operationId=str(uuid.uuid4()), directory=str(directory / 'installation'),
                             tenant=tenant, configuration=configuration, administrator=database,
                             owner=role, partitions=[dict(startMicros=0, endMicros=4102444800000000)]
                             if kind == 'postgres' else [], clickhouse=None)
                if kind=='click_house':
                    ch_base,ch_owner=request,owner
                else:
                    requests.append(request)
        with ExitStack() as stack:
            if ch_base is not None:
                requests.append(stack.enter_context(clickhouse_profile(root, ch_owner, tenant, ch_base)))
            path = private(root / 'telemetry-providers.json', requests)
            environment = {'MDM_TELEMETRY_PROVIDERS': str(path)}
            if primary is not None:
                import os
                import shutil
                from pathlib import Path
                from t2_environment import run
                clients = []
                for owner, major in [(primary, 17), *((owner, 16) for owner in owners)]:
                    destination = '/tmp/telemetry-backup-ca.crt'
                    run(['docker', 'cp', str(owner.root / 'ca.crt'), owner.container() + ':' + destination], capture_output=True, timeout=30)
                    clients.append(dict(container=owner.container(), port=owner.port(), major=major, ca=destination))
                descriptor = private(root / 'telemetry-pg-clients.json', clients)
                binaries = root / 'pg-clients'
                binaries.mkdir(mode=0o700)
                for name in ('pg_dump', 'pg_restore', 'pg_dump16', 'pg_restore16'):
                    target = binaries / name
                    shutil.copyfile(Path(__file__).with_name('telemetry_pg_client.py'), target)
                    target.chmod(0o700)
                environment.update(MDM_TELEMETRY_PG_CLIENTS=str(descriptor), PATH=str(binaries) + os.pathsep + os.environ['PATH'])
            yield environment
    finally:
        failures = []
        for owner in reversed(owners):
            try:
                owner.reset()
            except Exception as error:
                failures.append(error)
        if failures:
            raise RuntimeError('telemetry provider cleanup incomplete') from failures[0]


@contextmanager
def clickhouse_profile(root, owner, tenant, base):
    import base64
    import copy
    import os
    import shutil
    import ssl
    import time
    import urllib.request
    from xml.sax.saxutils import escape
    from t2_environment import run
    name = owner.project + '-clickhouse'
    def remove():
        ids = run(['docker','ps','-aq','--filter',f'name=^/{name}$'],capture_output=True,timeout=30).stdout.split()
        for identifier in ids:
            info=json.loads(run(['docker','inspect',identifier],capture_output=True,timeout=30).stdout)[0]
            labels=info.get('Config',{}).get('Labels') or {}
            if info.get('Name')!='/'+name or labels.get('rss.mdm.worktree')!=owner.identity or labels.get('rss.mdm.fixture')!='telemetry':
                raise RuntimeError('foreign telemetry fixture')
            run(['docker','rm','-f','-v',identifier],capture_output=True,timeout=30)
    remove()
    try:
        directory=root/'clickhouse'
        directory.mkdir(mode=0o700)
        for leaf in ('data','logs','users','backups','tls'):
            (directory/leaf).mkdir(mode=0o700)
        owner.issue_leaf(directory/'tls',['localhost'])
        shutil.copyfile(owner.root/'ca.crt',directory/'tls'/'ca.crt')
        private(directory/'users'/'telemetry-installer.xml', '<clickhouse><users><mdm_test_admin><named_collection_control>1</named_collection_control></mdm_test_admin></users></clickhouse>')
        administrator=secrets.token_hex(24)
        guard=secrets.token_hex(24)
        admin_file=private(directory/'administrator-password',administrator)
        guard_file=private(directory/'guard-password',guard)
        database=base['administrator']['name']
        configuration=private(directory/'server.xml',f'''<clickhouse>
<listen_host>0.0.0.0</listen_host><https_port>8443</https_port>
<openSSL><server><certificateFile>/tls/server.crt</certificateFile><privateKeyFile>/tls/server.key</privateKeyFile><verificationMode>none</verificationMode></server></openSSL>
<named_collections><rss_ts_ch_guard><host>postgres</host><port>5432</port><database>{database}</database><user>ch_guard</user><password>{escape(guard)}</password></rss_ts_ch_guard></named_collections>
<storage_configuration><disks><mdm_backup><type>local</type><path>/backups/</path></mdm_backup></disks></storage_configuration>
<backups><allowed_disk>mdm_backup</allowed_disk></backups>
</clickhouse>''')
        args=['docker','run','-d','--name',name,'--network',owner.project+'_default',
              '--label','rss.mdm.worktree='+owner.identity,'--label','rss.mdm.fixture=telemetry',
              '--user',f'{os.getuid()}:{os.getgid()}', '-p','127.0.0.1::8443',
              '-e','CLICKHOUSE_USER=mdm_test_admin','-e','CLICKHOUSE_PASSWORD_FILE=/inputs/administrator-password',
              '-e','CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1','-e','PGSSLMODE=verify-full','-e','PGSSLROOTCERT=/tls/ca.crt']
        for source,target in [(directory/'data','/var/lib/clickhouse'),(directory/'logs','/var/log/clickhouse-server'),
                              (directory/'users','/etc/clickhouse-server/users.d'),(directory/'backups','/backups'),
                              (directory/'tls','/tls'),(configuration,'/etc/clickhouse-server/config.d/telemetry.xml'),
                              (admin_file,'/inputs/administrator-password')]:
            args+=['-v',f'{source}:{target}']
        run([*args,PROVIDERS['telemetry-clickhouse']],capture_output=True,timeout=180)
        port=int(run(['docker','port',name,'8443'],capture_output=True,timeout=30).stdout.strip().rsplit(':',1)[1])
        origin=f'https://localhost:{port}'
        context=ssl.create_default_context(cafile=str(owner.root/'ca.crt'))
        authorization='Basic '+base64.b64encode(('mdm_test_admin:'+administrator).encode()).decode()
        deadline=time.monotonic()+90
        while True:
            try:
                request=urllib.request.Request(origin+'/',data=b'SELECT version()',headers={'Authorization':authorization})
                with urllib.request.urlopen(request,context=context,timeout=3) as response:
                    if response.read().strip()!=b'25.8.12.129':raise RuntimeError('unexpected ClickHouse version')
                break
            except (OSError,TimeoutError):
                if time.monotonic()>=deadline:raise
                time.sleep(0.2)
        profile=copy.deepcopy(base)
        profile.update(operationId=str(uuid.uuid4()),directory=str(directory/'installation'),owner='o_'+uuid.uuid4().hex,partitions=[])
        profile['administrator']['name']=database
        runtime={**profile['administrator'],'user':'r_'+uuid.uuid4().hex,
                 'password_file':str(private(directory/'runtime-password',secrets.token_hex(24)))}
        credentials={role:dict(user=role+'_'+uuid.uuid4().hex,password_file=str(private(directory/(role+'-password'),secrets.token_hex(24)))) for role in ('reader','writer','maintenance')}
        profile['configuration']['backend']=dict(kind='click_house',control=runtime,endpoint=origin,ca_file=str(owner.root/'ca.crt'),
                                                 **credentials,max_scan_rows=100000,max_scan_bytes=16777216,max_memory_bytes=67108864)
        profile['clickhouse']=dict(backup_directory=str(directory/'backups'),server_configuration_files=[str(configuration),str(directory/'tls'/'ca.crt')],
                                   installer=dict(user='mdm_test_admin',password_file=str(admin_file)),guard=dict(user='ch_guard',password_file=str(guard_file)))
        yield profile
    finally:
        remove()
