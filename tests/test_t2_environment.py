import tempfile
import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hack'))
from t2_environment import Environment, project_name, run as environment_run
import json
import shutil
import socket
import ssl
import threading
from types import SimpleNamespace
from unittest.mock import patch

class EnvironmentTests(unittest.TestCase):
    def test_gateway_ports_survive_new_lower_ports_hosts_and_regeneration(self):
        import importlib.util
        source = Path(__file__).resolve().parents[1] / 'deployment/render_gateway.py'
        spec = importlib.util.spec_from_file_location('gateway_renderer', source)
        renderer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(renderer)
        self.assertEqual(len({renderer.internal_port(p) for p in range(1,65536)}),65535)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            def host(identity, console, origins):
                directory=root/identity;directory.mkdir(exist_ok=True)
                (directory/'deployment.json').write_text(json.dumps(dict(hostId=identity,backend='127.0.0.1:8081',
                    consoleOrigin=console,origins=[dict(origin=value,clientCertificate=True) for value in origins],scep=[],
                    certificate=f'/run/gateway/{identity}/tls.crt',privateKey=f'/run/gateway/{identity}/tls.key')))
            def mappings():
                return {int(v.split(':')[-2]):int(v.split(':')[-1]) for v in renderer.render(root)}
            identity='33333333333343338333333333333333'
            console='https://console.example.test'
            origins=[console,'https://agent.example.test:9445']
            host(identity,console,origins)
            original=mappings()
            configuration=(root/'nginx.conf').read_text()
            association=configuration.split('location = /.well-known/apple-app-site-association {',1)[1].split('}',1)[0]
            self.assertIn('proxy_pass',association)
            self.assertNotIn('web:8080',association)
            self.assertEqual(configuration.count('location = /.well-known/apple-app-site-association {'),1)
            self.assertEqual(original[443],8443)
            host(identity,console,origins+['https://agent.example.test:9443'])
            self.assertEqual({p:mappings()[p] for p in original},original)
            # The new first host has a different console port, including a low internal listener.
            host('11111111111141118111111111111111','https://new.example.test:8443',['https://new.example.test:8443'])
            expanded=mappings()
            self.assertEqual({p:expanded[p] for p in original},original)
            self.assertEqual(expanded[8443],443)
            (root/'nginx.conf').unlink();(root/'gateway-ports.compose.yaml').unlink()
            self.assertEqual(mappings(),expanded)

    def test_gateway_requires_explicit_tls_policy(self):
        import importlib.util
        spec=importlib.util.spec_from_file_location('gateway_renderer',Path(__file__).resolve().parents[1]/'deployment/render_gateway.py')
        renderer=importlib.util.module_from_spec(spec);spec.loader.exec_module(renderer)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);identity='33333333333343338333333333333333'
            directory=root/identity;directory.mkdir()
            facts=dict(hostId=identity,backend='127.0.0.1:8081',consoleOrigin='https://mdm.example.test',
                origins=[dict(origin='https://mdm.example.test',clientCertificate=False),
                         dict(origin='https://device.example.test',clientCertificate=True)],scep=[],
                certificate=f'/run/gateway/{identity}/tls.crt',privateKey=f'/run/gateway/{identity}/tls.key')
            path=directory/'deployment.json';path.write_text(json.dumps(facts));renderer.render(root)
            for invalid in ['optional',None,1]:
                facts['origins'][0]['clientCertificate']=invalid;path.write_text(json.dumps(facts))
                with self.assertRaisesRegex(ValueError,'TLS policy'):renderer.render(root)

    def test_postgres_endpoint_belongs_to_one_successful_lifecycle(self):
        from contextlib import ExitStack
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            env = Environment(Path(tmp))
            stack.enter_context(patch('t2_environment.require_lease'))
            stack.enter_context(patch.object(env, 'prepare_inputs'))
            stack.enter_context(patch.object(env, 'issue_leaf'))
            ownership = stack.enter_context(patch.object(env, 'verify_ownership'))
            generation = [1]
            def compose(*args, **kwargs):
                if args == ('ps', '-q', 'postgres'):
                    return 'container-' + str(generation[0])
                if args == ('port', 'postgres', '5432'):
                    return '127.0.0.1:' + str(5400 + generation[0])
                return ''
            calls = stack.enter_context(patch.object(env, 'compose', side_effect=compose))
            env.up()
            for _ in range(20):
                self.assertEqual(env.container(), 'container-1')
                self.assertEqual(env.port(), 5401)
            self.assertEqual(sum(c.args == ('port', 'postgres', '5432') for c in calls.call_args_list), 1)
            self.assertEqual(sum(c.args == ('ps', '-q', 'postgres') for c in calls.call_args_list), 1)
            self.assertEqual(env.postgres_queries, dict(container=1, port=1))
            ownership.side_effect = RuntimeError('foreign')
            with self.assertRaisesRegex(RuntimeError, 'foreign'):
                env.reset()
            self.assertIsNone(env.postgres_endpoint)
            with self.assertRaisesRegex(RuntimeError, 'foreign'):
                env.up()
            self.assertIsNone(env.postgres_endpoint)
            ownership.side_effect = None
            generation[0] = 2
            env.up()
            self.assertEqual((env.container(), env.port()), ('container-2', 5402))
            self.assertEqual(env.postgres_queries, dict(container=2, port=2))

    def test_worktree_identity_is_stable_and_distinct(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = [Path(tmp) / str(i) / 'same-name' for i in range(4)]
            for path in paths: path.mkdir(parents=True)
            names = [project_name(path) for path in paths]
            self.assertEqual(len(set(names)), 4)
            self.assertEqual(project_name(paths[0] / '..' / 'same-name'), names[0])

    def test_regenerated_cached_leaf_passes_strict_python_tls(self):
        # ref: cpython Lib/ssl.py@v3.14.0 create_default_context.
        import socket
        import ssl
        from concurrent.futures import ThreadPoolExecutor
        from t2_environment import run, private
        with tempfile.TemporaryDirectory() as tmp:
            env=Environment(Path(tmp));env.certificate()
            ca=(env.root/'ca.crt').read_bytes()
            legacy=private(env.root/'legacy.extensions',
                'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n')
            run(['openssl','x509','-req','-in',env.root/'server.csr','-CA',env.root/'ca.crt',
                 '-CAkey',env.root/'ca.key','-CAcreateserial','-days','30','-extfile',legacy,
                 '-out',env.root/'server.crt'],capture_output=True)
            env.certificate()
            self.assertEqual((env.root/'ca.crt').read_bytes(),ca)
            server=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server.load_cert_chain(env.root/'server.crt',env.root/'server.key')
            client=ssl.create_default_context(cafile=str(env.root/'ca.crt'))
            client.verify_flags |= ssl.VERIFY_X509_STRICT
            with socket.socket() as listener, ThreadPoolExecutor(max_workers=1) as executor:
                listener.settimeout(5);listener.bind(('127.0.0.1',0));listener.listen(1)
                def accept():
                    raw,_=listener.accept();raw.settimeout(5)
                    with server.wrap_socket(raw,server_side=True) as peer:
                        self.assertEqual(peer.recv(4),b'ping');peer.sendall(b'pong')
                accepted=executor.submit(accept)
                with socket.create_connection(listener.getsockname(),timeout=5) as raw:
                    with client.wrap_socket(raw,server_hostname='localhost') as peer:
                        peer.sendall(b'ping');self.assertEqual(peer.recv(4),b'pong')
                accepted.result(timeout=5)

    def test_environment_does_not_follow_target_slot(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict('os.environ', {'CARGO_TARGET_DIR': '/slot-0'}):
                first = Environment(Path(tmp))
            with patch.dict('os.environ', {'CARGO_TARGET_DIR': '/slot-1'}):
                second = Environment(Path(tmp))
            self.assertEqual(first.project, second.project)
            self.assertEqual(first.root, second.root)

    def test_reset_refuses_foreign_resource_before_mutation(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            env = Environment(Path(tmp))
            with patch.object(env, 'verify_ownership', side_effect=RuntimeError('foreign')), patch.object(env, 'compose') as compose:
                with self.assertRaises(RuntimeError): env.reset()
                compose.assert_not_called()

    def test_docker_cleanup_timeout_retains_owner_for_later_recovery(self):
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            env = Environment(Path(tmp))
            env.prepare_inputs(certificates=False)
            marker = env.root/'owner.json'
            for phase in ('ownership','down'):
                def compose(*args, **kwargs):
                    self.assertEqual(kwargs['timeout'],30)
                    if phase == 'ownership' or 'down' in args:
                        raise subprocess.TimeoutExpired('docker',kwargs['timeout'])
                    return '{"services":{},"volumes":{},"networks":{}}'
                with self.subTest(phase=phase),patch.object(env,'compose',side_effect=compose),patch('t2_environment.run',return_value=SimpleNamespace(stdout='')):
                    with self.assertRaises(subprocess.TimeoutExpired):
                        env.reset()
                    self.assertTrue(marker.exists())

    def test_runtime_volume_does_not_receive_operator_secrets(self):
        source=(Path(__file__).resolve().parents[1]/'deployment/compose.yaml').read_text()
        server=source.split('  server:',1)[1].split('  gateway:',1)[0]
        self.assertIn('runtime:/run/mdm:ro',server)
        self.assertNotIn('operator:',server)
        self.assertIn('ingress: {ipv4_address:',server)
        self.assertNotIn('network_mode:',server)

    def test_role_changes_require_reset_without_running_ddl(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            env=Environment(Path(tmp));env.root.mkdir(parents=True)
            (env.root/'roles.sha256').write_text('old')
            with patch.object(env,'sql',return_value='1') as sql:
                with self.assertRaisesRegex(RuntimeError,'reset'):env.roles()
                self.assertEqual(sql.call_count,1)

    def test_status_accepts_compose_json_lines(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            env=Environment(Path(tmp))
            with patch.object(env,'compose',return_value='{"Service":"postgres"}\n{"Service":"server"}'):
                self.assertEqual(len(env.status()['services']),2)

    def test_saved_images_override_ambient_values(self):
        from unittest.mock import patch
        import json
        with tempfile.TemporaryDirectory() as tmp:
            env=Environment(Path(tmp));env.root.mkdir(parents=True)
            (env.root/'images.json').write_text(json.dumps({'MDM_SERVER_IMAGE':'sha256:reviewed','MDM_WEB_IMAGE':'sha256:web'}))
            with patch.dict('os.environ',{'MDM_SERVER_IMAGE':'unreviewed','MDM_WEB_IMAGE':'unreviewed'}):
                self.assertEqual(env.variables()['MDM_SERVER_IMAGE'],'sha256:reviewed')
                self.assertEqual(env.variables()['MDM_WEB_IMAGE'],'sha256:web')

    def test_postgres_has_no_environment_root_mount(self):
        source=(Path(__file__).resolve().parents[1]/'deployment/compose.yaml').read_text().split('  idp-netns:',1)[0]
        self.assertNotIn('${MDM_ENV_ROOT:?}:/',source)
        self.assertIn('/pg/server.key:/inputs/server.key:ro',source)

    def test_same_name_unlabelled_resource_is_rejected(self):
        import json
        from types import SimpleNamespace
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            env=Environment(Path(tmp));name=env.project+'_pg'
            config=json.dumps({'services':{},'volumes':{'pg':{'name':name}},'networks':{}})
            def run(args,**kwargs):
                output=''
                if args[:3]==['docker','volume','ls'] and '--format' in args:output=name
                if args[:3]==['docker','volume','inspect']:output=json.dumps([{'Labels':{}}])
                return SimpleNamespace(stdout=output)
            with patch.object(env,'compose',return_value=config),patch('t2_environment.run',side_effect=run):
                with self.assertRaisesRegex(RuntimeError,'foreign'):env.verify_ownership()

    def test_host_port_allocations_are_distinct_and_detect_occupation(self):
        from unittest.mock import patch
        import socket
        with tempfile.TemporaryDirectory() as tmp, patch.object(Path,'home',return_value=Path(tmp)):
            environments=[Environment(Path(tmp)/str(i)) for i in range(4)]
            pairs=[env.host_ports() for env in environments]
            self.assertEqual(len({port for pair in pairs for port in pair.values()}),8)
            self.assertEqual(environments[0].host_ports(),pairs[0])
            with socket.socket() as listener:
                listener.bind(('127.0.0.1',pairs[0]['backend']))
                with self.assertRaisesRegex(RuntimeError,'occupied'):environments[0].host_ports()
            environments[0].host_ports(release=True)

    def test_gateway_modes_have_distinct_keys_under_the_same_ca(self):
        import hashlib
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            env=Environment(Path(tmp));env.prepare_inputs()
            directories=[env.root/'gateway-cert'/mode for mode in ('host','container')]
            for directory in directories:
                env.issue_leaf(directory,['localhost','mdm.example.test'])
                subprocess.run(['openssl','verify','-x509_strict','-CAfile',str(env.root/'ca.crt'),str(directory/'server.crt')],check=True,capture_output=True)
            for name in ('server.key','server.crt'):
                self.assertNotEqual(hashlib.sha256((directories[0]/name).read_bytes()).digest(),hashlib.sha256((directories[1]/name).read_bytes()).digest())

    def test_reset_rejects_damaged_owner_record(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            env=Environment(Path(tmp));env.root.mkdir(parents=True)
            (env.root/'owner.json').write_text('{}')
            with patch.object(env,'compose') as compose:
                with self.assertRaisesRegex(RuntimeError,'owner record'):env.reset()
                compose.assert_not_called()

    def test_reset_releases_allocation_without_local_port_marker(self):
        from unittest.mock import patch
        import json
        with tempfile.TemporaryDirectory() as tmp,patch.object(Path,'home',return_value=Path(tmp)):
            env=Environment(Path(tmp)/'work');env.root.mkdir(parents=True)
            (env.root/'owner.json').write_text(json.dumps({'worktree':str(env.worktree),'project':env.project}))
            env.host_ports()
            self.assertFalse((env.root/'host-ports.json').exists())
            with patch.object(env,'verify_ownership'),patch.object(env,'compose'):env.reset()
            allocations=json.loads((Path(tmp)/'.cache/rss-mdm-dev-ports/allocations.json').read_text())
            self.assertNotIn(env.project,allocations)

class ExternalGatewayTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env=Environment(Path(self.tmp.name),group='development')
        def run(args,**kwargs):
            if args[:2]==['docker','compose'] and 'config' in args:
                self.compose_config_args=args;self.compose_config_env=kwargs['env']
                return SimpleNamespace(stdout=json.dumps(self.model))
            return environment_run(args,**kwargs)
        mock=patch('t2_environment.run',side_effect=run)
        mock.start();self.addCleanup(mock.stop)

    def certificates(self, hostname='mdm.example.test'):
        self.env.prepare_inputs()
        directory=self.env.worktree/'deployment/certs'
        self.env.issue_leaf(directory,[hostname])
        shutil.copyfile(directory/'server.crt',directory/'custom fullchain.pem')
        shutil.copyfile(directory/'server.key',directory/'custom private.pem')
        (self.env.worktree/'.env').write_text('MDM_PRODUCT_ORIGIN=https://mdm.example.test\n')
        self.model={'x-gateway':dict(origin='https://mdm.example.test',publish='0.0.0.0:443:8443',
                    certificate_file='./deployment/certs/custom fullchain.pem',key_file='./deployment/certs/custom private.pem'),
            'services':{'gateway':{'ports':[dict(target=8443,published='443',host_ip='0.0.0.0')]},
                'inputs':{'volumes':[dict(type='bind',source=str(directory/'custom fullchain.pem'),target='/tls-input/server.crt'),
                                     dict(type='bind',source=str(directory/'custom private.pem'),target='/tls-input/server.key')]}}}
        return directory

    def test_no_external_files_retains_local_mode_but_explicit_missing_directory_fails(self):
        self.assertIsNone(self.env.gateway_settings()['origin'])
        self.assertEqual(self.env.variables()['MDM_GATEWAY_PUBLISH'],'127.0.0.1::8443')
        with self.assertRaisesRegex(ValueError,'env file does not exist'):
            self.env.gateway_settings(self.env.worktree/'missing')

    def test_incomplete_mismatched_and_symlinked_inputs_do_not_fall_back(self):
        directory=self.certificates()
        key=directory/'custom private.pem'
        key.unlink()
        with self.assertRaisesRegex(RuntimeError,'requires both'):self.env.gateway_settings()
        key.symlink_to(directory/'missing.key')
        with self.assertRaisesRegex(RuntimeError,'regular files'):self.env.gateway_settings()
        key.unlink()
        key.write_text('not a private key')
        with self.assertRaisesRegex(RuntimeError,'invalid'):self.env.gateway_settings()

    def test_wrong_hostname_is_rejected(self):
        self.certificates('wrong.example.test')
        with self.assertRaisesRegex(RuntimeError,'does not match'):self.env.gateway_settings()

    def test_partial_configuration_invalid_origin_and_port_mismatch_fail(self):
        self.certificates()
        self.model['x-gateway']['key_file']=''
        with self.assertRaisesRegex(ValueError,'together'):self.env.gateway_settings()
        self.model['x-gateway']['key_file']='configured'
        for origin in ('http://mdm.example.test','https://mdm.example.test/path',
                       'https://user:password@mdm.example.test','https://mdm.example.test;bad',
                       'https://mdm.example.test:443','https://MDM.EXAMPLE.TEST',
                       'https://mdm.example.test:0','https://[broken'):
            self.model['x-gateway']['origin']=origin
            with self.assertRaisesRegex(ValueError,'HTTPS origin'):self.env.gateway_settings()
        self.model['x-gateway']['origin']='https://mdm.example.test'
        self.model['services']['gateway']['ports'][0]['protocol']='udp'
        with self.assertRaisesRegex(ValueError,'TCP'):self.env.gateway_settings()
        self.model['services']['gateway']['ports'][0]['protocol']='tcp'
        self.model['x-gateway']['origin']='https://mdm.example.test:9443'
        with self.assertRaisesRegex(ValueError,'match the origin port'):self.env.gateway_settings()
        self.model['services']['gateway']['ports'][0]['published']='9443'
        self.model['x-gateway']['publish']='127.0.0.1:9443:8443'
        self.assertEqual(self.env.gateway_settings()['origin'],'https://mdm.example.test:9443')

    def test_compose_resolves_env_again_without_using_saved_gateway_settings(self):
        self.certificates()
        self.env.root.mkdir(parents=True,exist_ok=True)
        (self.env.root/'container-gateway.json').write_text(json.dumps(self.env.local_gateway()))
        with patch.dict('os.environ',{'MDM_PRODUCT_ORIGIN':'https://shell.example.test'}):
            self.env.gateway_settings()
        self.assertEqual(self.compose_config_env['MDM_PRODUCT_ORIGIN'],'https://shell.example.test')
        self.assertEqual(self.compose_config_args[self.compose_config_args.index('--env-file')+1],self.env.worktree/'.env')
        self.assertEqual(self.compose_config_args[self.compose_config_args.index('--project-directory')+1],self.env.worktree)

    def test_external_initialize_updates_all_consumers_and_persists_source(self):
        directory=self.certificates()
        tls=self.env.gateway_settings()
        generated={'ui.json':dict(canonicalOrigin='https://mdm.example.test',oidcEnabled=False),
                   'mdm.json':dict(serviceId='33333333-3333-4333-8333-333333333333',canonicalOrigin='https://mdm.example.test',tenant='11111111-1111-4111-8111-111111111111',managementTenant='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')}
        def compose(*args):
            if 'public-host-config' in args:return json.dumps(generated)
            return '0.0.0.0:443' if args[0]=='port' else ''
        with patch('t2_environment.Ingress.allocate',return_value={'MDM_INGRESS_SUBNET':'172.29.0.0/24','MDM_GATEWAY_ADDRESS':'172.29.0.2','MDM_BACKEND_ADDRESS':'172.29.0.3'}),patch.object(self.env,'gateway_settings',return_value=tls),patch.object(self.env,'up'),patch.object(self.env,'roles'),patch.object(self.env,'sql',return_value='1'), \
             patch.object(self.env,'compose',side_effect=compose), \
             patch('t2_environment.run',return_value=SimpleNamespace(stdout='[{"Id":"sha256:reviewed"}]')):
            self.env.initialize('container','server','web')
        container=self.env.root/'container'
        origin='https://mdm.example.test'
        self.assertEqual(json.loads((container/'runtime/runtime.json').read_text())['product_origin'],origin)
        for name in ('ui.json','mdm.json'):
            self.assertEqual(json.loads((container/'gateway'/name).read_text()),generated[name])
        nginx=(container/'gateway/nginx.conf').read_text()
        self.assertIn('listen 8443 ssl;',nginx)
        self.assertIn('proxy_pass http://172.29.0.3:8081;',nginx)
        self.assertIn('proxy_set_header X-RSS-Public-Origin',nginx)
        self.assertIn('server_name mdm.example.test;',nginx)
        self.assertIn('ssl_certificate /certs/server.crt;',nginx)
        self.assertNotIn('localhost',nginx)
        variables=Environment(self.env.worktree,group='development').variables()
        self.assertEqual(variables['MDM_GATEWAY_PUBLISH'],'0.0.0.0:443:8443')
        self.assertEqual(variables['MDM_GATEWAY_TLS_CERT_FILE'],str(directory/'custom fullchain.pem'))
        self.assertEqual(variables['MDM_GATEWAY_TLS_KEY_FILE'],str(directory/'custom private.pem'))

    def test_restart_refreshes_inputs_and_uses_system_trust(self):
        self.env.root.mkdir(parents=True)
        (self.env.root/'container-initialized.json').write_text(json.dumps(dict(origin='https://mdm.example.test',https_port=443)))
        (self.env.root/'container-gateway.json').write_text(json.dumps(dict(origin='https://mdm.example.test')))
        with patch('t2_environment.Ingress.validate'),patch.object(self.env,'verify_ownership'), \
             patch.object(self.env,'compose',side_effect=lambda *args:'0.0.0.0:443' if args[0]=='port' else '') as compose, \
             patch('t2_environment.ssl.create_default_context') as context,patch.object(self.env,'probe_product') as probe:
            self.env.start_product()
        context.assert_called_once_with(cafile=None)
        commands=[call.args for call in compose.call_args_list]
        stop=commands.index(('--profile','product','stop','server','gateway'))
        copy=commands.index(('--profile','product','run','--rm','inputs'))
        start=commands.index(('--profile','product','up','-d','--force-recreate','server','web','gateway'))
        self.assertLess(stop,copy);self.assertLess(copy,start)
        self.assertEqual(probe.call_args.args[:2],('https://mdm.example.test',443))

    def test_local_probe_preserves_sni_host_and_rejects_untrusted_certificate(self):
        directory=self.certificates()
        server_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(directory/'server.crt',directory/'server.key')
        sni=[];requests=[]
        server_context.set_servername_callback(lambda sock,name,ctx:sni.append(name))
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0));listener.listen(2);listener.settimeout(5)
            port=listener.getsockname()[1]
            def serve():
                for _ in range(2):
                    raw,_=listener.accept()
                    try:
                        with server_context.wrap_socket(raw,server_side=True) as stream:
                            request=b''
                            while b'\r\n\r\n' not in request:request+=stream.recv(4096)
                            requests.append(request)
                            stream.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                    except ssl.SSLError:raw.close()
            thread=threading.Thread(target=serve,daemon=True);thread.start()
            origin='https://mdm.example.test'
            with self.assertRaises(ssl.SSLCertVerificationError):
                Environment.probe_product(origin,port,ssl.create_default_context())
            trusted=ssl.create_default_context(cafile=str(self.env.root/'ca.crt'))
            Environment.probe_product(origin,port,trusted)
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
        self.assertEqual(sni,['mdm.example.test']*2)
        self.assertIn(b'Host: mdm.example.test\r\n',requests[0])

    def test_tls_failure_reports_safe_category_and_failed_phase(self):
        import io,contextlib
        self.env.root.mkdir(parents=True)
        (self.env.root/'container-initialized.json').write_text(json.dumps(dict(origin='https://mdm.example.test',https_port=443)))
        (self.env.root/'container-gateway.json').write_text(json.dumps(dict(origin='https://mdm.example.test')))
        error=ssl.SSLCertVerificationError('untrusted private input');error.verify_code=20
        output=io.StringIO()
        with patch('t2_environment.Ingress.validate'),patch.object(self.env,'verify_ownership'), \
             patch.object(self.env,'compose',side_effect=lambda *args:'0.0.0.0:443' if args[0]=='port' else ''), \
             patch.object(self.env,'probe_product',side_effect=error), \
             patch('t2_environment.time.monotonic',side_effect=[0,0,61,62]),contextlib.redirect_stdout(output):
            with self.assertRaisesRegex(RuntimeError,'tls-certificate-verification \\(code=20\\)'):
                self.env.start_product()
        self.assertEqual(json.loads(output.getvalue())['status'],'failed')
        self.assertNotIn('untrusted private input',output.getvalue())

class ComposeDiagnostics(unittest.TestCase):
    def test_binary_native_key_does_not_block_compose_and_is_redacted(self):
        import base64, io, contextlib, subprocess
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            env=Environment(Path(tmp));env.root.mkdir(parents=True)
            raw=b"\xff"*32
            (env.root/'native-data.key').write_bytes(raw)
            with patch('t2_environment.run',return_value=type('Result',(),{'stdout':'ok'})()):
                self.assertEqual(env.compose('config'),'ok')
            for secret in [raw.hex(),base64.b64encode(raw).decode()]:
                output=io.StringIO()
                with patch('t2_environment.run',side_effect=subprocess.CalledProcessError(1,['docker'],stderr=secret)),contextlib.redirect_stderr(output):
                    with self.assertRaises(subprocess.CalledProcessError):env.compose('config')
                self.assertIn('diagnostic-withheld',output.getvalue())
                self.assertNotIn(secret,output.getvalue())

    def test_failure_keeps_safe_stderr_without_disclosing_private_input(self):
        import io,contextlib,subprocess
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            env=Environment(Path(tmp));env.root.mkdir(parents=True)
            (env.root/'account-password').write_text('private-password')
            for diagnostic,expected in [('port is already allocated','port is already allocated'),('private-password','diagnostic-withheld')]:
                output=io.StringIO()
                with patch('t2_environment.run',side_effect=subprocess.CalledProcessError(1,['docker','compose'],stderr=diagnostic)),contextlib.redirect_stderr(output):
                    with self.assertRaises(subprocess.CalledProcessError):env.compose('up','-d','postgres')
                self.assertIn(expected,output.getvalue());self.assertNotIn('private-password',output.getvalue())
