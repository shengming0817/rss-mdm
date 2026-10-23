"""Adapt only transport coordinates of the production gateway renderer for isolated tests."""
import importlib.util
import json
from pathlib import Path
import re
import tempfile


def render(directory, *, origin='https://mdm.example.test', backend='127.0.0.1:8081', targets=None,
           public_port=8443, certificates='/certs', web=True, plain=False):
    source = Path(directory) / 'render_gateway.py'
    spec = importlib.util.spec_from_file_location('rss_gateway_renderer', source)
    renderer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(renderer)
    host_id = '33333333333343338333333333333333'
    origins = [origin, *(targets or {})]
    if len(origins) != len(set(origins)):
        raise ValueError('duplicate fixture origin')
    with tempfile.TemporaryDirectory(prefix='rss-gateway-') as root:
        root = Path(root)
        host = root / host_id
        host.mkdir()
        (host / 'deployment.json').write_text(json.dumps(dict(hostId=host_id,
            backend='127.0.0.1:8081', consoleOrigin=origin, origins=origins, scep=[],
            certificate=f'/run/gateway/{host_id}/tls.crt', privateKey=f'/run/gateway/{host_id}/tls.key')))
        renderer.render(root)
        config = (root / 'nginx.conf').read_text()
    config = config.replace('http://127.0.0.1:8081', 'http://' + backend)
    config = config.replace(f'/run/gateway/{host_id}/tls.crt', certificates + '/server.crt')
    config = config.replace(f'/run/gateway/{host_id}/tls.key', certificates + '/server.key')
    config = config.replace(f'/run/gateway/{host_id}/', certificates + '/')
    private_port = renderer.internal_port(renderer.origin(origin)[1])
    config = config.replace(f'listen {private_port} ssl;', f'listen {public_port} ssl;')
    config = config.replace(f'listen {private_port} ssl default_server;', f'listen {public_port} ssl default_server;')
    if not web:
        start = config.index('        location / {\n            limit_except')
        end = config.index('\n        }', start) + len('\n        }')
        config = config[:start] + '        location / { return 404; }' + config[end:]
    if plain:
        # Admission fixture has no certificates; production routing and budgets stay identical.
        config = re.sub(r'    server \{ listen [0-9]+ ssl default_server; ssl_reject_handshake on; \}\n?', '', config)
        config = re.sub(r'(?m)^\s*ssl_[^\n]+\n', '', config)
        config = config.replace(f'listen {public_port} ssl;', f'listen {public_port};')
        config = '\n'.join(line for line in config.splitlines() if 'if ($ssl_server_name' not in line)
    return config
