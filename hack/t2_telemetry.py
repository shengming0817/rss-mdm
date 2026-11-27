"""Fixed TLS providers for the product installation's shared telemetry journey."""
from contextlib import contextmanager
import json
import os
import socket
from pathlib import Path
import time
import uuid

from dev_environment import Environment, private, run


@contextmanager
def providers(root, installation):
    # The guard connects over the installation project's private Compose network.
    timescale = Environment(root, group='telemetry-timescale-t2',
                            providers={**installation.providers,
                                       'postgres': installation.providers['telemetry-timescale']})
    if timescale.root.exists():
        timescale.reset()
    container = None
    try:
        timescale.up()
        timescale.sql('CREATE DATABASE shared_metrics TEMPLATE template0')
        timescale.sql('CREATE EXTENSION IF NOT EXISTS timescaledb', 'shared_metrics')
        timescale.sql('CREATE DATABASE dedicated_metrics TEMPLATE template0')
        timescale.sql('CREATE EXTENSION IF NOT EXISTS timescaledb', 'dedicated_metrics')
        installation.sql('CREATE DATABASE ch_control TEMPLATE template0')
        area = installation.root / 'clickhouse'
        installation.issue_leaf(area, ['localhost'])
        disk = area / 'backup'
        disk.mkdir(mode=0o700)
        password = uuid.uuid4().hex
        guard = uuid.uuid4().hex
        private(area / 'installer-password', password)
        private(area / 'guard-password', guard)
        config = private(area / 'config.d' / 'telemetry.xml', f"""<clickhouse>
<listen_host>0.0.0.0</listen_host><https_port>8443</https_port>
<openSSL><server><certificateFile>/inputs/server.crt</certificateFile><privateKeyFile>/inputs/server.key</privateKeyFile><verificationMode>none</verificationMode></server></openSSL>
<named_collections><rss_ts_ch_guard><host>postgres</host><port>5432</port><database>ch_control</database><user>ch_guard</user><password>{guard}</password></rss_ts_ch_guard></named_collections>
<storage_configuration><disks><mdm_backup><type>local</type><path>/backups/</path></mdm_backup></disks></storage_configuration>
<backups><allowed_disk>mdm_backup</allowed_disk></backups>
</clickhouse>""")
        users = private(area / 'users.xml', f"""<clickhouse><users><installer>
<password>{password}</password><networks><ip>::/0</ip></networks><profile>default</profile><quota>default</quota>
<access_management>1</access_management><named_collection_control>1</named_collection_control>
</installer></users></clickhouse>""")
        # Keep the registered HTTPS endpoint through provider restarts during policy rotation.
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        args = ['docker','run','-d','--rm','--user',f'{os.getuid()}:{os.getgid()}',
                '--network',installation.project+'_default','-p',f'127.0.0.1:{port}:8443',
                '-e','CLICKHOUSE_SKIP_USER_SETUP=1','-e','PGSSLMODE=verify-full','-e','PGSSLROOTCERT=/inputs/pg-ca.crt']
        for path,mount in [(config.parent,'/etc/clickhouse-server/config.d'),
                           (users,'/etc/clickhouse-server/users.d/installer.xml'),
                           (area/'server.crt','/inputs/server.crt'),(area/'server.key','/inputs/server.key'),
                           (installation.root/'ca.crt','/inputs/pg-ca.crt')]:
            args.extend(['-v',f'{path}:{mount}:ro'])
        container=run([*args,'-v',f'{disk}:/backups',installation.providers['telemetry-clickhouse']],capture_output=True).stdout.strip()
        endpoint=f'https://127.0.0.1:{port}'
        import ssl
        from urllib.request import build_opener, HTTPSHandler, ProxyHandler
        opener=build_opener(ProxyHandler({}), HTTPSHandler(context=ssl.create_default_context(cafile=installation.root/'ca.crt')))
        limit=time.monotonic()+60
        while True:
            try:
                with opener.open(endpoint+'/ping',timeout=2) as response:
                    if response.read(16).strip()==b'Ok.':
                        break
            except OSError:
                pass
            if time.monotonic()>=limit:
                raise RuntimeError('ClickHouse HTTPS provider did not become ready')
            time.sleep(.25)
        yield dict(container=container,endpoint=endpoint,area=str(area),ca=str(installation.root/'ca.crt'),
                   timescale=dict(host='localhost',port=timescale.port(),name='shared_metrics',user='postgres',
                                  ca_file=str(timescale.root/'ca.crt'),password_file=str(timescale.root/'pg/pg-password')))
    finally:
        try:
            if container:
                run(['docker','rm','-fv',container],capture_output=True)
        finally:
            timescale.reset()
