#!/usr/bin/env python3
"""Render Nginx from installer-exported deployment facts. No process or container control.

ref: nginx ngx_http_ssl_module ($ssl_client_escaped_cert / optional_no_ca).
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit


def origin(value):
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or parsed.username or parsed.password or parsed.path
            or parsed.query or parsed.fragment or not parsed.hostname
            or not re.fullmatch(r'[a-z0-9.-]+', parsed.hostname)
            or not 0 < (parsed.port or 443) < 65536
            or value != 'https://' + parsed.hostname + (f':{parsed.port}' if parsed.port and parsed.port != 443 else '')):
        raise ValueError('canonical HTTPS DNS origin required')
    return parsed.hostname, parsed.port or 443, parsed.netloc


def internal_port(public):
    """Stable bijection; adding or removing another host/port never moves an existing route."""
    return {443: 8443, 8443: 443}.get(public, public)


def write(path, content):
    if path.is_symlink():
        raise ValueError('gateway output must not be a symlink')
    temporary = path.with_suffix(path.suffix + '.new')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(content)
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(path)


def proxy_headers(authority, public_origin, device=False, agent=False):
    fields = {'Host': '"'+authority+'"', 'X-RSS-Public-Origin': '"'+public_origin+'"',
              'X-RSS-Client-Cert': '$ssl_client_escaped_cert', 'X-Forwarded-For': '$remote_addr'}
    for name in ('Forwarded', 'X-Real-IP', 'X-Forwarded-Host', 'X-Forwarded-Proto', 'X-Forwarded-Port',
                 'X-Client-Cert', 'X-Device-ID', 'X-Tenant-ID'):
        fields[name] = '""'
    if device:
        fields['Cookie'] = '""'
    if agent:
        fields['Authorization'] = '""'
    return ''.join(f'        proxy_set_header {name} {value};\n' for name, value in fields.items())


def location(match, backend, *, budget=None, streaming=False, headers=''):
    body = '        location ' + match + ' {\n            limit_req zone=mdm_api burst=20 nodelay;\n'
    if budget:
        body += f'            client_max_body_size {budget};\n'
    if streaming:
        body += '            proxy_request_buffering off;\n            proxy_buffering off;\n'
    return body + headers + f'            proxy_pass http://{backend};\n        }}\n'


def management(backend):
    # These exact ceilings mirror management-http/body_policy.rs; Rust checks methods too.
    routes = [
        ('~ ^/api/v1/identity/tenants/[^/]+/(login|session/reauthenticate)$', None),
        ('~ ^/api/v1/(resources/[^/]+|policies/[^/]+)$', '8m'),
        ('~ ^/api/v1/devices/[^/]+/operations$', '16m'),
        ('~ ^/api/v1/pki/(rotations|crls)$', '64m'),
        ('= /api/v1/pki/signing/recover', '256k'),
        ('~ ^/api/v1/agent-issuances/[^/]+/recover$', '256k'),
        ('~ ^/api/v1/apple/(materials/|organizations)', '256k'),
        ('= /api/v1/windows/entra-policy', '128k'),
        ('~ ^/api/v1/(certificate-archive/import|authorization/(rules|user-groups)/[^/]+|tenant-administration/authorization/rules/[^/]+)$', '2m'),
        ('~ ^/api/v1/(agent-packages(/[^/]+/withdraw)?|software/(imports|sources/[^/]+/revisions/[^/]+|resources/[^/]+/versions/[^/]+))$', '1m'),
    ]
    result = ''
    for match, budget in routes:
        entry = location(match, backend, budget=budget)
        if '/identity/tenants/' in match:
            entry = entry.replace('zone=mdm_api burst=20', 'zone=mdm_login burst=10')
        result += entry
    return result + location('/api/', backend)


def scep_locations(host):
    result = ''
    for route in host['scep']:
        if (set(route) != {'path', 'origin', 'provisioner', 'root'}
                or not re.fullmatch(r'/scep/[A-Za-z0-9_-]{1,128}', route['path'])
                or not re.fullmatch(r'scep-root-[0-9a-f]{64}\.crt', route['root'])
                or route['path'] != '/scep/' + route['provisioner']):
            raise ValueError('invalid exact SCEP route')
        ca_host, _, authority = origin(route['origin'])
        for suffix in ('', '/pkiclient.exe'):
            result += f'''        location = {route['path']}{suffix} {{
            if ($request_method !~ ^(GET|POST)$) {{ return 405; }}
            if ($arg_operation !~ ^(GetCACert|GetCACaps|PKIOperation)$) {{ return 400; }}
            client_max_body_size 2m;
            proxy_pass_request_headers off;
            proxy_set_header Host {authority};
            proxy_set_header Content-Type $content_type;
            proxy_ssl_server_name on;
            proxy_ssl_name {ca_host};
            proxy_ssl_verify on;
            proxy_ssl_verify_depth 3;
            proxy_ssl_trusted_certificate /run/gateway/{host['hostId']}/{route['root']};
            proxy_pass {route['origin']}{route['path']};
        }}
'''
    return result


def render(root, publish_address='0.0.0.0'):
    root = Path(root)
    if root.is_symlink():
        raise ValueError('gateway root must not be a symlink')
    ipaddress.ip_address(publish_address)
    hosts = []
    for path in sorted(root.glob('*/deployment.json')):
        if path.parent.is_symlink() or path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
            raise ValueError('bounded regular deployment facts required')
        host = json.loads(path.read_text())
        if set(host) != {'hostId', 'backend', 'consoleOrigin', 'origins', 'scep', 'certificate', 'privateKey'}:
            raise ValueError('unknown gateway deployment facts')
        if not re.fullmatch('[0-9a-f]{32}', host['hostId']) or path.parent.name != host['hostId']:
            raise ValueError('wrong gateway host identity')
        address, port = host['backend'].rsplit(':', 1)
        if ipaddress.ip_address(address.strip('[]')).is_unspecified or not 0 < int(port) < 65536:
            raise ValueError('literal isolated backend address required')
        if host['certificate'] != f"/run/gateway/{host['hostId']}/tls.crt" or host['privateKey'] != f"/run/gateway/{host['hostId']}/tls.key":
            raise ValueError('gateway material belongs to another host')
        if not host['origins'] or len(host['origins']) > 32:
            raise ValueError('invalid public origins')
        names = set()
        for endpoint in host['origins']:
            if (not isinstance(endpoint, dict) or set(endpoint) != {'origin', 'clientCertificate'}
                    or type(endpoint['clientCertificate']) is not bool
                    or endpoint['origin'] in names):
                raise ValueError('explicit unique origin TLS policy required')
            origin(endpoint['origin'])
            names.add(endpoint['origin'])
        if host['consoleOrigin'] not in names:
            raise ValueError('console origin missing')
        hosts.append(host)
    if not hosts or len(hosts) > 1024:
        raise ValueError('bounded exported gateway hosts required')
    ports = sorted({origin(endpoint['origin'])[1] for host in hosts for endpoint in host['origins']})
    internal = {public: internal_port(public) for public in ports}
    pairs = set()
    blocks = [f'    server {{ listen {port} ssl default_server; ssl_reject_handshake on; }}\n' for port in internal.values()]
    for host in hosts:
        for endpoint in host['origins']:
            value = endpoint['origin']
            client_auth = 'optional_no_ca' if endpoint['clientCertificate'] else 'off'
            hostname, port, authority = origin(value)
            if (hostname, port) in pairs:
                raise ValueError('public hostname/port has multiple owners')
            pairs.add((hostname, port))
            backend = host['backend']
            block = f'''    server {{
        listen {internal[port]} ssl;
        server_name {hostname};
        ssl_certificate {host['certificate']};
        ssl_certificate_key {host['privateKey']};
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_verify_client {client_auth};
        ssl_verify_depth 3;
        ssl_session_cache off;
        ssl_session_tickets off;
        ssl_early_data off;
        if ($http_host != "{authority}") {{ return 421; }}
        if ($ssl_server_name != $host) {{ return 421; }}
        client_header_timeout 10s;
        client_body_timeout 30s;
        send_timeout 30s;
        limit_conn mdm_peer_connections 8;
        limit_conn mdm_server_connections 128;
        proxy_http_version 1.1;
        proxy_next_upstream off;
        proxy_connect_timeout 5s;
        proxy_read_timeout 3600s;
        proxy_hide_header Cache-Control;
        proxy_hide_header Referrer-Policy;
        proxy_hide_header X-Content-Type-Options;
        add_header Cache-Control no-store always;
        add_header Referrer-Policy no-referrer always;
        add_header X-Content-Type-Options nosniff always;
        add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'" always;
        error_page 429 = @limited;
        location @limited {{
            default_type application/json;
            add_header Cache-Control no-store always;
            add_header Referrer-Policy no-referrer always;
            add_header X-Content-Type-Options nosniff always;
            add_header Retry-After 3 always;
            return 429 '{{"code":"request_limited"}}';
        }}
'''
            block += proxy_headers(authority, value)
            block += location('~ ^/api/v1/agent/', backend, budget='16m', streaming=True, headers=proxy_headers(authority, value, True, True))
            block += location('~ ^/(EnrollmentServer/|EnrollmentConfiguration$|ManagementServer/|checkin$|mdm$|native/apple/ddm/)', backend,
                              budget='16m', streaming=True, headers=proxy_headers(authority, value, True))
            block += location('= /livez', backend) + location('= /readyz', backend)
            if value == host['consoleOrigin']:
                block += f'''        location = /api/v1/identity-host/config.json {{ alias /run/gateway/{host['hostId']}/ui.json; }}
        location = /api/v1/mdm-host/config.json {{ alias /run/gateway/{host['hostId']}/mdm.json; }}
'''
                block += location('~ ^/api/v1/resources/[^/]+/(content|uploads/[^/]+)$', backend, budget='8g', streaming=True)
                block += management(backend) + scep_locations(host)
                block += location('= /.well-known/apple-app-site-association', backend)
                block += '''        location = /api { return 404; }
        location ^~ /api/v1/public-agent/ { return 404; }
        location ^~ /software/native/ { default_type application/json; return 404 '{"code":"not_found"}'; }
        location ~ ^/(scep|admin|sign|revoke|renew|rekey|provisioners|roots|root|crl|health|EnrollmentServer|EnrollmentConfiguration|ManagementServer|native|checkin|mdm)(/|$) { return 404; }
        location / {
            limit_except GET HEAD { deny all; }
            resolver 127.0.0.11 valid=5s ipv6=off;
            set $web_origin http://web:8080;
            proxy_pass_request_headers off;
            proxy_set_header Host web;
            proxy_pass $web_origin;
        }
'''
            else:
                block += '        location / { return 404; }\n'
            blocks.append(block + '    }\n')
    configuration = '''pid /tmp/mdm-nginx.pid;
error_log stderr crit;
events { worker_connections 1024; }
http {
    log_format mdm_safe escape=json '{"event":"mdm_gateway","status":$status,"request_id":"$request_id"}';
    access_log /dev/stdout mdm_safe;
    limit_req_zone $binary_remote_addr zone=mdm_login:10m rate=20r/m;
    limit_req_zone $binary_remote_addr zone=mdm_api:10m rate=10r/s;
    limit_conn_zone $binary_remote_addr zone=mdm_peer_connections:10m;
    limit_conn_zone $server_name zone=mdm_server_connections:1m;
    limit_req_status 429;
    limit_conn_status 429;
    include /etc/nginx/mime.types;
    default_type application/json;
    client_max_body_size 16k;
    large_client_header_buffers 4 32k;
    client_body_temp_path /tmp/mdm-body;
    proxy_temp_path /tmp/mdm-proxy;
    fastcgi_temp_path /tmp/mdm-fastcgi;
    uwsgi_temp_path /tmp/mdm-uwsgi;
    scgi_temp_path /tmp/mdm-scgi;
''' + ''.join(blocks) + '}\n'
    write(root / 'nginx.conf', configuration)
    publish_host = '[' + publish_address + ']' if ':' in publish_address else publish_address
    mappings = [f'{publish_host}:{public}:{private}' for public, private in internal.items()]
    write(root / 'gateway-ports.compose.yaml', 'services:\n  gateway:\n    ports: !override\n' + ''.join('      - ' + json.dumps(value) + '\n' for value in mappings))
    return mappings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', required=True)
    parser.add_argument('--publish-address', default='0.0.0.0')
    args = parser.parse_args()
    render(args.root, args.publish_address)


if __name__ == '__main__':
    main()
