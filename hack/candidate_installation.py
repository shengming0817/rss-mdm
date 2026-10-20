#!/usr/bin/env python3
"""Run the ordinary Compose deployment against a real candidate; no synthetic product seed."""
import argparse
import json
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import uuid
from candidate_runtime import verify_candidate, load_ui, image_identity, sha
from candidate_installation_driver import Installation, qualify


def tls(directory):
    def openssl(*args):
        subprocess.run(['openssl',*args],cwd=directory,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    openssl('req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=Compose qualification CA',
        '-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign','-addext','subjectKeyIdentifier=hash','-keyout','ca.key','-out','ca.crt')
    for name,hostname in [('postgres','postgres'),('gateway','localhost')]:
        (directory/'leaf.ext').write_text('subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:'+hostname+'\n')
        openssl('req','-new','-newkey','rsa:2048','-nodes','-subj','/CN='+hostname,'-keyout',name+'.key','-out',name+'.csr')
        openssl('x509','-req','-in',name+'.csr','-CA','ca.crt','-CAkey','ca.key','-CAcreateserial','-days','2',
            '-extfile','leaf.ext','-out',name+'.crt')
        shutil.copy(directory/'ca.crt',directory/(name+'-ca.crt'))
    for name in ('database-password','platform-password','administrator-password'):
        (directory/name).write_text(uuid.uuid4().hex+'-Compose-2026!')
    for path in directory.iterdir():path.chmod(0o600)


def qualify_candidate(candidate):
    marker=candidate/'installation-result.json';marker.unlink(missing_ok=True)
    manifest=verify_candidate(candidate)
    ui=load_ui(candidate,manifest['ui'])
    project='mdm-seed-'+uuid.uuid4().hex[:12]
    with tempfile.TemporaryDirectory(prefix='mdm-compose-seed-') as temporary:
        root=Path(temporary);inputs=root/'inputs';inputs.mkdir(mode=0o700)
        tls(inputs)
        ports=[]
        for _ in range(2):
            with socket.socket() as listener:
                listener.bind(('127.0.0.1',0));ports.append(listener.getsockname()[1])
        origin='https://localhost:'+str(ports[0]);other='https://localhost:'+str(ports[1])
        values=dict(MDM_POSTGRES_IMAGE=manifest['providers']['postgres'],
            MDM_SERVER_IMAGE=image_identity(manifest['image'])['id'],MDM_INSTALLER_IMAGE=image_identity(manifest['installer']['image'])['id'],
            MDM_WEB_IMAGE=ui['id'],MDM_INPUT_DIRECTORY=str(inputs),MDM_PRODUCT_ORIGIN=origin,MDM_HTTPS_PORT=str(ports[0]))
        def env(path,values):path.write_text(''.join(key+'='+str(value)+'\n' for key,value in values.items()));path.chmod(0o600)
        env(root/'.env',values)
        env(root/'second.env',dict(values,MDM_PRODUCT_ORIGIN=other,MDM_HTTPS_PORT=str(ports[1]),
            MDM_RUNTIME_SUBPATH='runtime/second',MDM_STATE_VOLUME=project+'_state',MDM_NETWORK=project+'_default',MDM_SERVER_ALIAS='second-server'))
        for name in ('production.compose.yaml','tenant.compose.yaml'):shutil.copy(candidate/'deployment'/name,root/name)
        owner=Installation(root,root/'production.compose.yaml',project)
        try:
            result=qualify(owner,origin,other)
            result['candidate_sha256']=sha(candidate/'candidate.json')
        finally:owner.cleanup()
    marker.write_text(json.dumps(result,indent=2)+'\n')

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('candidate',type=Path)
    qualify_candidate(parser.parse_args().candidate.resolve())
