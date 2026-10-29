#!/usr/bin/env python3
"""Run the ordinary Compose deployment against a real candidate; no synthetic product seed."""
import argparse
import json
import platform
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import uuid
from ingress_network import Ingress
from contextlib import ExitStack
from candidate_runtime import verify_candidate, load_ui, image_identity, sha
from candidate_installation_driver import Installation, qualify


def tls(directory):
    def openssl(*args):
        subprocess.run(['openssl',*args],cwd=directory,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    openssl('req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=Compose qualification CA',
        '-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign','-addext','subjectKeyIdentifier=hash','-keyout','ca.key','-out','ca.crt')
    for name,hostname in [('postgres','postgres'),('gateway','mdm.example.test,DNS:second.example.test')]:
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
    daemon=json.loads(subprocess.check_output(['docker','info','--format','{{json .}}'],text=True,timeout=15))
    architecture={'aarch64':'arm64','x86_64':'amd64'}.get(daemon['Architecture'],daemon['Architecture'])
    environment=dict(client=dict(os=platform.system(),architecture=platform.machine()),
        docker=dict(os=daemon['OSType'],architecture=daemon['Architecture'],operating_system=daemon['OperatingSystem']),
        container_platform=manifest['platform'],
        architecture_relation='same' if manifest['platform']==daemon['OSType']+'/'+architecture else 'different')
    ui=load_ui(candidate,manifest['ui'])
    project='mdm-seed-'+uuid.uuid4().hex[:12]
    with tempfile.TemporaryDirectory(prefix='mdm-compose-seed-') as temporary, ExitStack() as cleanup:
        root=Path(temporary);inputs=root/'inputs';inputs.mkdir(mode=0o700)
        tls(inputs)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
        origin='https://mdm.example.test';other='https://second.example.test'
        network=Ingress(root,project,project)
        cleanup.callback(network.release)
        allocation=network.allocate()
        backend=allocation['MDM_BACKEND_ADDRESS'];second_backend=network.address(2)
        values=dict(MDM_POSTGRES_IMAGE=manifest['providers']['postgres'],MDM_GATEWAY_IMAGE=manifest['providers']['nginx'],
            MDM_SERVER_IMAGE=image_identity(manifest['image'])['id'],MDM_INSTALLER_IMAGE=image_identity(manifest['installer']['image'])['id'],
            MDM_WEB_IMAGE=ui['id'],MDM_INPUT_DIRECTORY=str(inputs),MDM_PRODUCT_ORIGIN=origin,
            **allocation,MDM_GATEWAY_BIND_IP='127.0.0.1')
        def env(path,values):path.write_text(''.join(key+'='+str(value)+'\n' for key,value in values.items()));path.chmod(0o600)
        env(root/'.env',values)
        env(root/'second.env',dict(values,MDM_PRODUCT_ORIGIN=other,MDM_BACKEND_ADDRESS=second_backend,MDM_INGRESS_NETWORK=project+'_ingress',
            MDM_RUNTIME_SUBPATH='runtime/second',MDM_CONTENT_VOLUME=project+'_content',MDM_STATE_VOLUME=project+'_state',MDM_NETWORK=project+'_default',MDM_SERVER_ALIAS='second-server'))
        for name in ('production.compose.yaml','tenant.compose.yaml','render_gateway.py'):shutil.copy(candidate/'deployment'/name,root/name)
        owner=Installation(root,root/'production.compose.yaml',project)
        try:
            result=qualify(owner,origin,other,port,second_backend)
            result['candidate_sha256']=sha(candidate/'candidate.json')
            result['environment']=environment
        finally:owner.cleanup()
    marker.write_text(json.dumps(result,indent=2)+'\n')

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('candidate',type=Path)
    qualify_candidate(parser.parse_args().candidate.resolve())
