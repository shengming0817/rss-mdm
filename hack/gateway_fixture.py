"""Adapt only transport coordinates of the production gateway renderer for isolated tests."""
import importlib.util
import json
from pathlib import Path
import tempfile
from dataclasses import dataclass


@dataclass
class Gateway:
    configuration: str
    ports: list
    renderer: object

    def publish(self, path, *, service="gateway", isolated=False, published=None):
        ports = [dict(port) for port in self.ports]
        if isolated:
            for port in ports:
                port.update(host_ip="127.0.0.1", published=str((published or {}).get(port["target"], 0)))
        self.renderer.write(Path(path), self.renderer.ports_document(ports, service))
        return Path(path)



def render(directory, *, origin='https://mdm.example.test', backend='127.0.0.1:8081', targets=None,
           bind_ip="127.0.0.1", certificates='/certs', web=True, bootstrap_origins=()):
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
            backend='127.0.0.1:8081', consoleOrigin=origin, origins=[dict(origin=value,clientCertificate=value not in bootstrap_origins) for value in origins], scep=[],
            certificate=f'/run/gateway/{host_id}/tls.crt', privateKey=f'/run/gateway/{host_id}/tls.key')))
        ports = renderer.render(root, bind_ip)
        config = (root / 'nginx.conf').read_text()
    config = config.replace('http://127.0.0.1:8081', 'http://' + backend)
    config = config.replace(f'/run/gateway/{host_id}/tls.crt', certificates + '/server.crt')
    config = config.replace(f'/run/gateway/{host_id}/tls.key', certificates + '/server.key')
    config = config.replace(f'/run/gateway/{host_id}/', certificates + '/')
    if not web:
        start = config.index('        location / {\n            limit_except')
        end = config.index('\n        }', start) + len('\n        }')
        config = config[:start] + '        location / { return 404; }' + config[end:]
    return Gateway(config, ports, renderer)
