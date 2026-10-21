#!/usr/bin/env python3
"""Stage supplied secrets, then run the single idempotent product initializer.

No Docker API, certificate issuance or process supervision. Compose owns infrastructure.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess

root = Path('/var/lib/rss-mdm')
inputs = root / 'inputs'
inputs.mkdir(parents=True, exist_ok=True, mode=0o700)
for name in ('database-password','platform-password','administrator-password','postgres-ca.crt','postgres.crt','postgres.key','gateway-ca.crt','gateway.crt','gateway.key'):
    source = Path('/inputs') / name
    if source.is_symlink() or not source.is_file():
        raise ValueError('regular deployment secret required')
    target = inputs / source.name
    if target.exists() and name.endswith("password") and target.read_bytes() != source.read_bytes():
        raise ValueError('retain original initialization inputs')
    if not target.exists():
        shutil.copyfile(source, target)
    target.chmod(0o600)
    os.chown(target, 10001, 10001)
content = Path('/var/lib/rss-mdm-content')
if content.is_symlink():
    raise ValueError('content volume must be a real directory')
content.mkdir(parents=True, exist_ok=True, mode=0o700)
if not content.is_dir():
    raise ValueError('content volume must be a directory')
for directory in (root, inputs, content):
    directory.chmod(0o700)
    os.chown(directory, 10001, 10001)
config = dict(directory=str(root/'installation'),
    deployment=dict(directory=str(root/'runtime/primary'), probe_address='primary-server:8445',
        certificate_file=str(inputs/'gateway.crt'), private_key_file=str(inputs/'gateway.key'),
        trust_file=str(inputs/'gateway-ca.crt'), content_volume='/var/lib/rss-mdm-content'),
    database=dict(name='mdm',administrator=dict(host='postgres',port=5432,name='postgres',user='postgres',
        password_file=str(inputs/'database-password'),ca_file=str(inputs/'postgres-ca.crt'))),
    audit_mode='ledger',organization_name=os.environ.get('MDM_ORGANIZATION','My organization'),
    platform_login='platform',administrator_login='administrator',
    platform_password_file=str(inputs/'platform-password'),administrator_password_file=str(inputs/'administrator-password'),
    origin=os.environ['MDM_PRODUCT_ORIGIN'],listen='127.0.0.1:8081',trusted_gateway='127.0.0.1')
ca_request = None
ca_source = os.environ.get('MDM_STEP_CA_CONFIG')
if ca_source:
    source = Path(ca_source)
    if source.is_symlink() or not source.is_file():
        raise ValueError('step-ca configuration file required')
    ca = json.loads(source.read_text())
    for field in ('root_certificate_file', 'root_crl_file', 'administrator_certificate_file', 'administrator_key_file'):
        source_file = Path(ca[field])
        if not source_file.is_absolute():
            source_file = source.parent / source_file
        if source_file.is_symlink() or not source_file.is_file():
            raise ValueError('regular CA material required')
        target = inputs / ('step-ca-' + field)
        if field == "root_certificate_file" and target.exists() and target.read_bytes() != source_file.read_bytes():
            raise ValueError('retain original CA inputs; use explicit CA rotation for replacement')
        staged = target.with_suffix('.new')
        shutil.copyfile(source_file, staged)
        staged.chmod(0o600)
        os.chown(staged, 10001, 10001)
        staged.replace(target)
        ca[field] = str(target)
    ca_request = root/'step-ca-input.json'
    ca_request.write_text(json.dumps(dict(installation=config, settings=ca)))
    ca_request.chmod(0o600)
    os.chown(ca_request, 10001, 10001)
path = root/'installation-input.json'
if path.exists() and json.loads(path.read_text()) != config:
    raise ValueError('initialization input changed')
path.write_text(json.dumps(config))
path.chmod(0o600)
os.chown(path,10001,10001)
os.setgroups([])
os.setgid(10001)
os.setuid(10001)
binary = '/usr/local/bin/rss-mdm-installer'
receipt = subprocess.check_output([binary, 'install', '--config', str(path)])
if ca_request:
    subprocess.run([binary, 'initialize-ca', '--config', str(ca_request)], check=True, stdout=subprocess.DEVNULL)
print(receipt.decode().strip())
