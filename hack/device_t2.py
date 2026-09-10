"""Test-only Identity response authority for the device/PG seam, not an IdP T2.

The SDK still validates tenant/client/audience/expiry over TLS. The real Identity
product remains covered by identity_t2.py. This fixture never ships in the app.
"""
from contextlib import contextmanager
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import ssl
import threading
import time

@contextmanager
def identities(root):
    tenants = ['aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb']
    credentials = {'admin-a': (tenants[0], 'administrator'), 'other-a': (tenants[0], 'other'), 'admin-b': (tenants[1], 'administrator')}
    secret = 'device-t2-validation-secret-00000000'
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_POST(self):
            value = json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))))
            expected = 'Basic '+base64.b64encode(('mdm:'+secret).encode()).decode()
            binding = credentials.get(value.get('credential'))
            allowed = self.path == '/internal/v1/identity/validate' and self.headers.get('Authorization') == expected and binding and value.get('tenant_id') == binding[0] and value.get('audience') == 'rss-mdm'
            if allowed:
                body = dict(subject=binding[1], tenant_id=binding[0], session_id='11111111-1111-4111-8111-111111111111', client_id='mdm', audience='rss-mdm', issuer=origin, auth_time=int(time.time())-10, amr=['pwd'], acr='unspecified', expires_at=int(time.time())+60)
            else:
                body = dict(code='invalid_credential', correlation_id='11111111-1111-4111-8111-111111111111')
            payload = json.dumps(body).encode()
            self.send_response(200 if allowed else 401)
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(payload)))
            self.end_headers(); self.wfile.write(payload)
    server = ThreadingHTTPServer(('127.0.0.1',0), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(root/'server.crt',root/'server.key')
    server.socket = tls.wrap_socket(server.socket,server_side=True)
    origin = 'https://localhost:'+str(server.server_port)
    thread = threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    try: yield origin
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=5)
        if thread.is_alive(): raise RuntimeError('Identity fixture did not stop')
