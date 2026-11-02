"""Local TLS issuer fixture: real JWT/CSR verification and actual X.509 signing.

This supplies an external step-ca protocol boundary; it never mutates product storage.
"""
import base64
from datetime import datetime
import hashlib
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
from pathlib import Path
import ssl
import sys
import uuid
from task_trust_materials import prepare, run


def decode(value):
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))


def main():
    directory = Path(sys.argv[1])
    directory.mkdir(mode=0o700)
    root = prepare(directory)
    (directory / 'provider.pk8').write_bytes(run('pkcs8', '-topk8', '-nocrypt', '-outform', 'DER', '-in', root / 'ca.key'))
    (directory / 'provider.pub').write_bytes(run('pkey', '-in', root / 'ca.key', '-pubout'))
    server_ext = directory / 'server.conf'
    server_ext.write_text('basicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n')
    run('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost', '-keyout', directory / 'server.key', '-out', directory / 'server.csr')
    run('x509', '-req', '-in', directory / 'server.csr', '-CA', root / 'ca.pem', '-CAkey', root / 'ca.key', '-set_serial', '99999', '-days', '2', '-extfile', server_ext, '-out', directory / 'server.pem')
    for index in (1, 2, 3):
        run('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=rss-da-device', '-keyout', directory / f'device{index}.key', '-out', directory / f'device{index}.csr')
        (directory / f'device{index}.der').write_bytes(run('req', '-in', directory / f'device{index}.csr', '-outform', 'DER'))
    (root / 'issued').mkdir(mode=0o700)
    (root / 'ca.conf').write_text((root / 'ca.conf').read_text() + f'\nnew_certs_dir={root}/issued\npolicy=policy_any\n[policy_any]\ncommonName=supplied\n')
    # The fixture intentionally allows renewing the same device subject.
    (root / 'index.attr').write_text('unique_subject = no\n')

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            try:
                assert self.path == '/sign'
                length = int(self.headers['Content-Length'])
                assert 0 < length <= 131072
                body = json.loads(self.rfile.read(length))
                header, claims, signature = body['ott'].split('.')
                payload = json.loads(decode(claims))
                assert json.loads(decode(header)) == {'alg': 'RS256', 'typ': 'JWT', 'kid': 'da-test'}
                attempt = str(uuid.UUID(payload['jti']))
                destination = directory / attempt
                destination.mkdir(mode=0o700)
                (destination / 'jwt').write_bytes((header + '.' + claims).encode())
                (destination / 'signature').write_bytes(decode(signature))
                run('dgst', '-sha256', '-verify', directory / 'provider.pub', '-signature', destination / 'signature', destination / 'jwt')
                assert payload['iss'] == 'rss-da-device' and payload['sub'] == 'rss-da-device'
                assert len(payload['sans']) == 1 and payload['sans'][0].startswith('urn:rss:da:device:v1:')
                (destination / 'csr.pem').write_text(body['csr'])
                csr = run('req', '-in', destination / 'csr.pem', '-outform', 'DER')
                run('req', '-in', destination / 'csr.pem', '-verify', '-noout')
                assert decode(payload['cnf']['x5rt#S256']) == hashlib.sha256(csr).digest()
                marker = bytes.fromhex('020101') + bytes([4, 13]) + b'rss-da-device' + bytes([4, 7]) + b'da-test'
                marker = bytes([0x30, len(marker)]) + marker
                ext = destination / 'ext.conf'
                ext.write_text('basicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\nsubjectAltName=URI:' + payload['sans'][0] + '\n1.3.6.1.4.1.37476.9000.64.1=DER:' + marker.hex(':') + '\n')
                stamp = lambda value: datetime.fromisoformat(value.replace('Z', '+00:00')).strftime('%Y%m%d%H%M%SZ')
                run('ca', '-batch', '-name', 'issuer', '-config', root / 'ca.conf', '-in', destination / 'csr.pem', '-startdate', stamp(body['notBefore']), '-enddate', stamp(body['notAfter']), '-extfile', ext, '-out', destination / 'leaf.pem', '-notext')
                leaf = (destination / 'leaf.pem').read_text()
                (directory / 'issued.jsonl').open('a').write(json.dumps({'attempt': attempt, 'identity': payload['sans'][0]}) + '\n')
                if (directory / 'drop-next').exists():
                    (directory / 'drop-next').unlink()
                    self.close_connection = True
                    return
                response = json.dumps({'crt': leaf, 'certChain': [leaf, (root / 'ca.pem').read_text()]}).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(response)))
                self.end_headers()
                self.wfile.write(response)
            except Exception as error:
                print(type(error).__name__, file=sys.stderr, flush=True)
                self.send_error(400)

    server = HTTPServer(('127.0.0.1', 0), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(directory / 'server.pem', directory / 'server.key')
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    print(json.dumps({'port': server.server_port, 'directory': str(directory)}), flush=True)
    server.serve_forever()


if __name__ == '__main__':
    main()
