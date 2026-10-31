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
import pki_ca
from dev_environment import Environment


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




def ssl_context(root):
    # Force a wrong SNI while still routing to the actual local test listener.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=root)
    original = context.wrap_socket
    context.wrap_socket = lambda sock, **kwargs: original(sock,**{**kwargs,'server_hostname':'wrong.example.test'})
    return context
