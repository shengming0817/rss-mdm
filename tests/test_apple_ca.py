"""CA mappings belong to live Compose services; callbacks keep strict HTTPS trust."""
import json
from pathlib import Path
import ssl
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'hack'))
import apple_ca
import pki_ca
from t2_environment import Environment


class ProviderTests(unittest.TestCase):
    def provider(self, root='/unused'):
        provider = pki_ca.Provider(root, 'a'*20)
        provider.owner = Mock()
        provider.owner.providers = {'step-ca': 'fixed-provider'}
        return provider

    def test_address_only_comes_from_live_service_mapping(self):
        provider = self.provider()
        provider.owner.compose.side_effect = ['', 'owned-id', '127.0.0.1:54321']
        with patch.object(pki_ca, 'run', side_effect=[SimpleNamespace(stdout='[{"Image":"fixed-image"}]'), SimpleNamespace(stdout='fixed-image')]):
            self.assertEqual(provider.start(), 'https://localhost:54321')
        provider.owner.verify_ownership.assert_called_once()
        provider.owner.compose.assert_any_call('--profile','pki','port','step-ca',str(pki_ca.PKI_CA['port']),timeout=15)

    def test_foreign_owner_and_non_loopback_or_ambiguous_mapping_fail(self):
        provider = self.provider()
        provider.owner.verify_ownership.side_effect = RuntimeError('foreign')
        with self.assertRaisesRegex(RuntimeError, 'foreign'):
            provider.start()
        provider.owner.compose.assert_not_called()
        for mapping in ('0.0.0.0:54321', '127.0.0.1:0', '127.0.0.1:54321\n127.0.0.1:54322'):
            provider = self.provider()
            provider.owner.compose.side_effect = ['', 'owned-id', mapping]
            with self.subTest(mapping=mapping), self.assertRaises((RuntimeError, ValueError)):
                with patch.object(pki_ca, 'run', side_effect=[SimpleNamespace(stdout='[{"Image":"fixed-image"}]'), SimpleNamespace(stdout='fixed-image')]):
                    provider.start()

    def test_failed_standby_logs_before_cleanup_and_preserves_primary_error(self):
        for diagnostics_fail in (False, True):
            previous, standby = self.provider(), self.provider()
            previous.owner.project, standby.owner.project = 'previous', 'standby'
            previous.owner.compose_file = standby.owner.compose_file = 'fixed-compose'
            standby.owner.extra = {}
            previous.fence = Mock()
            events = []
            primary = RuntimeError('startup failed')
            standby.start = Mock(side_effect=primary)
            def logs():
                events.append('logs')
                if diagnostics_fail:
                    raise ValueError('private diagnostic')
            def reset():
                events.append('reset')
                if diagnostics_fail:
                    raise OSError('private cleanup')
            standby.logs, standby.reset = logs, reset
            with self.subTest(diagnostics_fail=diagnostics_fail), self.assertRaises(RuntimeError) as caught:
                standby.promote_from(previous, 'https://localhost:54321')
            self.assertIs(caught.exception, primary)
            self.assertEqual(events, ['logs', 'reset'])
            self.assertNotIn('private', str(getattr(primary, '__notes__', [])))

    def test_native_linux_binds_only_its_private_network_gateway(self):
        provider = self.provider()
        provider.owner.project = 'owned-project'
        provider.owner.extra = {}
        replies = [SimpleNamespace(stdout='Debian GNU/Linux'),SimpleNamespace(stdout=json.dumps([{'IPAM':{'Config':[{'Gateway':'172.29.0.1'}]}}]))]
        with patch.object(pki_ca,'run',side_effect=replies) as run:
            self.assertEqual(provider.webhook_listen(),'172.29.0.1:0')
            run.assert_any_call(['docker','network','inspect','owned-project_default'],capture_output=True,timeout=15)
        self.assertEqual(provider.owner.extra['MDM_PKI_HOST_ADDRESS'],'172.29.0.1')

    def test_desktop_webhook_stays_on_loopback(self):
        provider = self.provider()
        with patch.object(pki_ca,'run',return_value=SimpleNamespace(stdout='Docker Desktop')) as run:
            self.assertEqual(provider.webhook_listen(),'127.0.0.1:0')
            self.assertEqual(run.call_count,1)

    def test_tls_trust_and_hostname_are_verified_against_owned_root(self):
        import http.server
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            trusted, foreign = Environment(root/'trusted'), Environment(root/'foreign')
            trusted.certificate();foreign.certificate()
            class Health(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    self.send_response(200);self.end_headers()
                def log_message(self, *_):
                    pass
            server = http.server.ThreadingHTTPServer(('127.0.0.1',0),Health)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(trusted.root/'server.crt',trusted.root/'server.key')
            server.socket = context.wrap_socket(server.socket,server_side=True)
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            provider = self.provider()
            provider.container = 'owned-id'
            live = SimpleNamespace(stdout='[{"State":{"Running":true}}]')
            origin = 'https://localhost:'+str(server.server_port)
            try:
                with patch.object(pki_ca,'run',return_value=live):
                    provider.wait(origin,'/health',trusted.root/'ca.crt')
                    with self.assertRaisesRegex(RuntimeError,'TLS trust'):
                        provider.wait(origin,'/health',foreign.root/'ca.crt')
                    with patch.object(pki_ca.ssl,'create_default_context',side_effect=lambda **_: ssl_context(trusted.root/'ca.crt')):
                        with self.assertRaisesRegex(RuntimeError,'TLS trust'):
                            provider.wait(origin,'/health',trusted.root/'ca.crt')
            finally:
                server.shutdown();thread.join(5);server.server_close()

    def test_recovery_checks_each_registered_project_before_deleting(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            owner = Environment(root)
            project = owner.identity+'-t2-pki-'+'b'*20
            replies = [SimpleNamespace(stdout=project+'\nother-project'),SimpleNamespace(stdout='')]
            with patch.object(pki_ca,'ROOT',root),patch.object(pki_ca,'Environment') as factory,patch.object(pki_ca,'run',side_effect=replies):
                factory.return_value.identity = owner.identity
                factory.return_value.project = project
                pki_ca.recover()
                factory.assert_any_call(group='t2-pki-'+'b'*20)
                factory.return_value.reset.assert_called_once()

    def test_provider_and_webhook_diagnostics_survive_private_fixture_removal(self):
        from t2_processes import diagnostics, private_value
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary)/'fixture.log'
            with tempfile.TemporaryDirectory() as case:
                provider = self.provider(case)
                (provider.root/'step-webhooks.log').write_text('TLS handshake failed; sensitive-hook-value')
                token = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmaXh0dXJlIn0.c2lnbmF0dXJl'
                provider.owner.compose.return_value = 'CA exited; sensitive-hook-value ott='+token+' jwt='+token
                with diagnostics(artifact):
                    private_value('sensitive-hook-value')
                    provider.logs()
            content = artifact.read_text()
            self.assertIn('TLS handshake failed',content)
            self.assertIn('CA exited',content)
            self.assertNotIn('sensitive-hook-value',content)
            self.assertNotIn(token,content)


def ssl_context(root):
    # Force a wrong SNI while still routing to the actual local test listener.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=root)
    original = context.wrap_socket
    context.wrap_socket = lambda sock, **kwargs: original(sock,**{**kwargs,'server_hostname':'wrong.example.test'})
    return context


class RunningTests(unittest.TestCase):
    def scenario(self, fail_at=None, agent=True):
        from contextlib import ExitStack
        stack = ExitStack();self.addCleanup(stack.close)
        temporary = stack.enter_context(tempfile.TemporaryDirectory())
        root = Path(temporary)
        (root/'apple.json').write_text(json.dumps({'management': {'origin': 'https://mdm.example.test'}}))
        (root/'case.json').write_text(json.dumps({'tenant': '00000000-0000-0000-0000-000000000001'}))
        for name in ('ca.crt', 'apple-issuer.pem', 'apple-issuer.key'):
            (root/name).write_text('fixture')
        (root/'agent-pki.json').write_text('{"kid":"unchanged"}')
        apple_root=root/'pki/apple'
        env = {'MDM_AGENT_PKI_FIXTURE':'1'} if agent else {}
        provider = Mock()
        provider.start.side_effect = ['https://localhost:50101','https://localhost:50102']
        provider.webhook_listen.return_value = '127.0.0.1:0'
        provider.owner.extra = {}
        stack.enter_context(patch.object(apple_ca,'Provider',return_value=provider))
        stack.enter_context(patch.object(apple_ca,'binary',return_value=Path('/fixed-step')))
        cli = stack.enter_context(patch.object(apple_ca.subprocess,'run'))
        def invoke(command, **kwargs):
            if command[1:3] == ['ca','init']:
                (apple_root/'step/config').mkdir(parents=True)
                (apple_root/'step/secrets').mkdir()
                (apple_root/'step/certs').mkdir()
                (apple_root/'step/config/ca.json').write_text('{"authority":{}}')
            elif fail_at == 'cli':
                raise RuntimeError('injected CLI failure')
            if '-out' in command:
                Path(command[command.index('-out')+1]).write_text('fixture')
            if command[1:4] == ['crypto','jwk','create']:
                Path(command[5]).write_text('fixture')
            return SimpleNamespace(stdout='Webhook ID: fixed-id\nSecret: c2VjcmV0\n')
        cli.side_effect = invoke
        offline=root/'pki/apple-offline';offline.mkdir(parents=True)
        stack.enter_context(patch('pki_fixtures.root_crl',return_value=offline))
        stack.enter_context(patch('pki_fixtures.isolate_root'))
        def install_trust(*args):
            path=apple_root/'trust.json';path.write_text('{"issuers":[{"digest":"fixture"}]}')
            return path
        install=stack.enter_context(patch('pki_fixtures.trust',side_effect=install_trust))
        restore=Mock()
        if fail_at == 'second-start':
            provider.start.side_effect = ['https://localhost:50101',RuntimeError('injected startup failure')]
        return root,env,provider,install,restore

    def test_recreation_publishes_final_origin_without_replacing_provisioner_identity(self):
        root,env,provider,install,restore = self.scenario()
        with apple_ca.running(root,env,case='a'*20):
            self.assertEqual(json.loads((root/'device-pki.json').read_text())[0]['scep_url'],'https://localhost:50102/scep/rss')
            self.assertEqual(json.loads((root/'agent-pki.json').read_text()),{'kid':'unchanged'})
            self.assertEqual(env['MDM_STEP_CA_URL'],'https://localhost:50102')
            self.assertEqual(env['MDM_APPLE_WEBHOOK_LISTEN'],'127.0.0.1:0')
            install.assert_called_once()
            provider.compose.assert_called_once_with('rm','--stop','--force','--volumes','step-ca',timeout=30)
        provider.reset.assert_called_once()
        provider.check.assert_called_once()

    def test_startup_cli_and_case_failures_still_remove_daemon_resources(self):
        for phase in ('second-start','cli','case'):
            root,env,provider,_,_ = self.scenario(phase)
            with self.subTest(phase=phase),self.assertRaisesRegex(RuntimeError,'injected'):
                with apple_ca.running(root,env,case='a'*20):
                    raise RuntimeError('injected case failure')
            provider.reset.assert_called_once()

    def test_log_failure_does_not_skip_resource_cleanup(self):
        root,env,provider,_,_ = self.scenario(agent=False)
        provider.logs.side_effect = RuntimeError('log unavailable')
        with self.assertRaisesRegex(RuntimeError,'log unavailable'):
            with apple_ca.running(root,env,case='a'*20):
                pass
        provider.reset.assert_called_once()

    def test_cancelled_owner_still_allows_bounded_daemon_cleanup(self):
        from t2_execution import Processes
        from t2_processes import owned_by
        root,env,provider,_,_ = self.scenario(agent=False)
        processes = Processes()
        provider.logs.side_effect = processes.check
        provider.reset.side_effect = processes.check
        with owned_by(processes):
            with self.assertRaisesRegex(RuntimeError,'T2 cancelled'):
                with apple_ca.running(root,env,case='a'*20):
                    processes.cancelled.set()
                    processes.check()
            provider.reset.assert_called_once()
            with self.assertRaisesRegex(RuntimeError,'T2 cancelled'):
                processes.check()
