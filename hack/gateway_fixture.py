"""Render isolated transport participants from the shipped gateway templates.

The HTTP-only carrier proves route budgets; render() retains SNI and PROXY transport.
"""
from pathlib import Path
from urllib.parse import urlsplit


def render(directory, *, origin='https://mdm.example.test', backend='127.0.0.1:8081', targets=None,
           public_port=8443, http_port=8445, certificates='/certs', web=True, plain=False):
    directory = Path(directory)
    main = (directory / 'nginx.conf').read_text()
    http = (directory / 'http.conf').read_text()
    endpoint = urlsplit(origin)
    if endpoint.scheme != 'https' or not endpoint.hostname:
        raise ValueError('fixture canonical HTTPS origin required')
    http = http.replace('server 127.0.0.1:8081;', 'server ' + backend + ';')
    http = http.replace('server_name mdm.example.test;', 'server_name ' + endpoint.hostname + ';')
    http = http.replace('proxy_set_header Host mdm.example.test;', 'proxy_set_header Host ' + endpoint.netloc + ';')
    http = http.replace('/private/mdm-tls.crt', certificates + '/server.crt').replace('/private/mdm-tls.key', certificates + '/server.key')
    http = http.replace('/run/config/ui.json', certificates + '/ui.json').replace('/run/config/mdm.json', certificates + '/mdm.json')
    if not web:
        http = http.replace('location / { proxy_pass http://web:8080; }', 'location / { return 404; }')
    if plain:
        start = main.index('stream {')
        main = main[:start] + main[main.index('\nhttp {', start) + 1:]
        http = http.replace('listen 127.0.0.1:8445 ssl proxy_protocol;', f'listen {public_port};')
        http = '\n'.join(line for line in http.splitlines() if not any(part in line for part in (
            'ssl_certificate ', 'ssl_certificate_key ', 'set_real_ip_from ', 'real_ip_header ', 'if ($ssl_server_name')))
    else:
        routes = {endpoint.hostname: f'127.0.0.1:{http_port}', **(targets or {})}
        if len(routes) != 1 + len(targets or {}):
            raise ValueError('duplicate fixture SNI target')
        main = main.replace('include /run/gateway/routes/*.conf;', '\n'.join(f'{host} {address};' for host, address in routes.items()))
        main = main.replace('listen 8443;', f'listen {public_port};')
        http = http.replace('listen 127.0.0.1:8445 ssl proxy_protocol;', f'listen 127.0.0.1:{http_port} ssl proxy_protocol;')
    return main.replace('include /run/gateway/http/*.conf;', http)
