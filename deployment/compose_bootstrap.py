#!/usr/bin/env python3
"""Prepare Docker volume inputs; product identities/accounts are created only by `install`.

Runs in a short-lived volume initializer, without a Docker socket or network.
ref: compose-spec/compose-spec 05-services.md (service_completed_successfully), 07-volumes.md.
"""
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
from urllib.parse import urlsplit

STATE = Path('/var/lib/rss-mdm')

def write(path, value, uid=10001, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError('symlink input')
    data = value if isinstance(value, bytes) else value.encode()
    if path.exists():
        if path.read_bytes() != data:
            raise ValueError('existing input differs; retain the original installation')
    else:
        with path.open('xb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    path.chmod(mode)
    os.chown(path, uid, uid)


def command(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)


def origin(value):
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.path or parsed.query or parsed.fragment
            or not re.fullmatch(r'[a-z0-9.-]+', parsed.hostname) or not parsed.port and value.endswith(':')):
        raise ValueError('canonical HTTPS origin required')
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        pass
    else:
        raise ValueError('DNS origin required; IP literals are not supported')
    return parsed


def main():
    origins = [os.environ['MDM_PRODUCT_ORIGIN']]
    origins += [v for v in os.environ.get('MDM_ADDITIONAL_ORIGINS', '').split(',') if v]
    parsed = [origin(v) for v in origins]
    ports = [v.port or 443 for v in parsed]
    if len(set(ports)) != len(ports):
        raise ValueError('each tenant slot needs a distinct published HTTPS port')
    for key in ('MDM_SERVER_IMAGE', 'MDM_WEB_IMAGE'):
        if not re.fullmatch(r'(?:[^\s]+@)?sha256:[0-9a-f]{64}', os.environ[key]):
            raise ValueError('immutable image required')
    ipaddress.ip_address(os.environ['MDM_PUBLISH_IP'])
    STATE.mkdir(exist_ok=True)
    STATE.chmod(0o700)
    os.chown(STATE, 10001, 10001)
    inputs = STATE / 'inputs'
    inputs.mkdir(mode=0o700, exist_ok=True)
    inputs.chmod(0o700)
    os.chown(inputs, 10001, 10001)
    for name in ('database-password',):
        target = inputs / name
        write(target, target.read_bytes() if target.exists() else secrets.token_urlsafe(32))
    ca = inputs / 'ca.crt'
    if not ca.exists():
        command('openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-days', '3650',
                '-subj', '/CN=RSS local installation TLS CA', '-addext', 'basicConstraints=critical,CA:TRUE',
                '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-keyout', str(inputs/'ca.key'), '-out', str(ca))
    command('openssl','x509','-in',str(ca),'-checkend','86400','-noout')
    # PostgreSQL has its own DNS identity; TLS is always verified by the product.
    def leaf(prefix, names):
        key = inputs / (prefix+'.key')
        cert = inputs / (prefix+'.crt')
        renew = prefix == 'gateway-next' or (prefix == 'postgres' and (os.environ.get('MDM_RENEW_POSTGRES_TLS') == '1'
            or (cert.exists() and subprocess.run(['openssl','x509','-in',str(cert),'-checkend','604800','-noout'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5).returncode != 0)))
        if cert.exists() and not renew:
            return
        extensions = inputs / (prefix+'.extensions')
        write(extensions, 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName='+','.join('DNS:'+n for n in names)+'\n')
        command('openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN='+names[0],
                '-keyout', str(key), '-out', str(inputs/(prefix+'.csr')))
        command('openssl', 'x509', '-req', '-in', str(inputs/(prefix+'.csr')), '-CA', str(ca),
                '-CAkey', str(inputs/'ca.key'), '-CAcreateserial', '-days', '90',
                '-extfile', str(extensions), '-out', str(cert))
    leaf('postgres', ['postgres'])
    if os.environ['MDM_TLS_MODE'] == 'local':
        leaf('gateway', sorted({p.hostname for p in parsed}))
        trust = ca
    elif os.environ['MDM_TLS_MODE'] == 'supplied':
        for name in ('gateway.crt', 'gateway.key', 'gateway-ca.crt'):
            source = Path('/inputs') / name
            if source.is_symlink() or not source.is_file():
                raise ValueError('missing regular TLS input')
            write(inputs/name, source.read_bytes())
        trust = inputs/'gateway-ca.crt'
    else:
        raise ValueError('unsupported TLS mode')
    if os.environ.get('MDM_RENEW_GATEWAY_TLS') == '1':
        if os.environ['MDM_TLS_MODE'] != 'local':
            raise ValueError('import organization gateway TLS through configure-host')
        leaf('gateway-next', sorted({p.hostname for p in parsed}))
    for name in ('platform-password', 'administrator-password'):
        source = Path('/inputs')/name
        if source.exists():
            if source.is_symlink() or not source.is_file():
                raise ValueError('regular password input required')
            write(inputs/name, source.read_bytes())
    for file in inputs.iterdir():
        if file.is_symlink() or not file.is_file():
            raise ValueError('unexpected TLS input')
        file.chmod(0o600)
        os.chown(file, 10001, 10001)
    pg = Path('/pg-input')
    pg.mkdir(exist_ok=True)
    pg.chmod(0o755)
    for source, destination in [('postgres.crt','server.crt'), ('postgres.key','server.key'), ('database-password','database-password')]:
        data=(inputs/source).read_bytes()
        if source in ('postgres.crt','postgres.key') and (pg/destination).exists() and (pg/destination).read_bytes()!=data:
            temporary=pg/(destination+'.next')
            write(temporary,data,uid=999)
            temporary.replace(pg/destination)
        else:
            write(pg/destination,data,uid=999)
    deployment = dict(server_image=os.environ['MDM_SERVER_IMAGE'], gateway_image=os.environ['MDM_WEB_IMAGE'],
        certificate_file=str(inputs/'gateway.crt'), private_key_file=str(inputs/'gateway.key'), trust_file=str(trust),
        content_volume=None, state_volume=os.environ['MDM_STATE_VOLUME'], network=os.environ['MDM_NETWORK'],
        publish_ip=os.environ['MDM_PUBLISH_IP'])
    installation = dict(directory=str(STATE/'installation'), deployment=deployment,
        additional_hosts=[dict(origin=v, listen='127.0.0.1:8081', deployment=deployment) for v in origins[1:]],
        database=dict(name='mdm', administrator=dict(host='postgres', port=5432, name='postgres', user='postgres',
            password_file=str(inputs/'database-password'), ca_file=str(ca))), audit_mode='ledger',
        organization_name=os.environ['MDM_ORGANIZATION'], platform_login=os.environ['MDM_PLATFORM_LOGIN'],
        administrator_login=os.environ['MDM_ADMINISTRATOR_LOGIN'],
        platform_password_file=str(inputs/'platform-password') if (inputs/'platform-password').exists() else None,
        administrator_password_file=str(inputs/'administrator-password') if (inputs/'administrator-password').exists() else None,
        origin=origins[0], listen='127.0.0.1:8081', trusted_gateway='127.0.0.1')
    write(STATE/'installation-input.json', json.dumps(installation, sort_keys=True))
    print(json.dumps(dict(event='installation_inputs_prepared', origins=origins)))

if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # TLS tools and input content are never included in diagnostics.
        print(json.dumps(dict(event='installation_inputs_failed', error_class=type(error).__name__)))
        raise SystemExit(1)
