#!/usr/bin/env python3
"""Stage supplied secrets, then run the single idempotent product initializer.

No Docker API, certificate issuance or process supervision. Compose owns infrastructure.
"""
import json
import os
from pathlib import Path
import shutil

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
for directory in (root, inputs):
    directory.chmod(0o700)
    os.chown(directory, 10001, 10001)
config = dict(directory=str(root/'installation'),
    deployment=dict(directory=str(root/'runtime/primary'), probe_address='primary-server:8445',
        certificate_file=str(inputs/'gateway.crt'), private_key_file=str(inputs/'gateway.key'),
        trust_file=str(inputs/'gateway-ca.crt'), content_volume=None),
    database=dict(name='mdm',administrator=dict(host='postgres',port=5432,name='postgres',user='postgres',
        password_file=str(inputs/'database-password'),ca_file=str(inputs/'postgres-ca.crt'))),
    audit_mode='ledger',organization_name=os.environ.get('MDM_ORGANIZATION','My organization'),
    platform_login='platform',administrator_login='administrator',
    platform_password_file=str(inputs/'platform-password'),administrator_password_file=str(inputs/'administrator-password'),
    origin=os.environ['MDM_PRODUCT_ORIGIN'],listen='127.0.0.1:8081',trusted_gateway='127.0.0.1')
path = root/'installation-input.json'
if path.exists() and json.loads(path.read_text()) != config:
    raise ValueError('initialization input changed')
path.write_text(json.dumps(config))
path.chmod(0o600)
os.chown(path,10001,10001)
os.setgroups([])
os.setgid(10001)
os.setuid(10001)
os.execv('/usr/local/bin/rss-mdm-installer',['rss-mdm-installer','install','--config',str(path)])
