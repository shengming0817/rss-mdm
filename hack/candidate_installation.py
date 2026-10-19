#!/usr/bin/env python3
"""Qualify a fixed candidate on an owned Linux systemd/Docker node, without host socket access.

The privileged outer container supplies a disposable Linux node. The real installer,
Docker daemon, systemd service, PostgreSQL, ingress and tenant containers run inside it.
No product checkout or mocked systemctl is visible to the node.
"""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import uuid
from candidate_runtime import Stage, cleanup, docker, require, verify_candidate, wait

NODE_DOCKERFILE = '''ARG OPERATOR
ARG DAEMON
FROM ${DAEMON} AS daemon
FROM ${OPERATOR}
USER 0:0
RUN apt-get update && apt-get install -y --no-install-recommends systemd dbus iptables iproute2 && rm -rf /var/lib/apt/lists/*
COPY --from=daemon /usr/local/bin/ /usr/local/bin/
COPY docker.service /etc/systemd/system/docker.service
RUN systemctl enable docker.service
ENV container=docker
STOPSIGNAL SIGRTMIN+3
ENTRYPOINT ["/sbin/init"]
'''
DOCKER_UNIT = '''[Unit]
Description=Disposable qualification Docker daemon
After=network.target
[Service]
ExecStart=/usr/local/bin/dockerd --host=unix:///var/run/docker.sock --storage-driver=vfs
Restart=on-failure
[Install]
WantedBy=multi-user.target
'''

def qualify(directory):
    manifest=verify_candidate(directory)
    name='mdm-install-'+uuid.uuid4().hex
    created=[]
    built=False
    marker=directory/'installation-result.json'
    marker.unlink(missing_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix=name) as temporary:
            context=Path(temporary)
            (context/'Dockerfile').write_text(NODE_DOCKERFILE)
            (context/'docker.service').write_text(DOCKER_UNIT)
            docker('build','--build-arg','OPERATOR='+manifest['installer']['image'],
                   '--build-arg','DAEMON='+manifest['providers']['docker-daemon'],
                   '-t',name,context,stage=Stage.TOOLS,timeout=600)
            built=True
            # No host bind mounts, host PID namespace or host Docker socket.
            created.append(name)
            docker('run','-d','--name',name,'--privileged','--cgroupns=private',
                   '--tmpfs','/run','--tmpfs','/run/lock','--tmpfs','/tmp',
                   '--tmpfs','/var/lib/postgresql/data',name,
                   stage=Stage.SERVER)
            def ready():
                return subprocess.run(['docker','exec',name,'systemctl','is-active','--quiet','docker'],
                                      capture_output=True,timeout=5).returncode==0
            wait(ready,'real systemd Docker service',seconds=90)
            docker('exec',name,'mkdir','-m','700','/workspace',stage=Stage.RUNTIME_INPUTS)
            for archive in [manifest['archive']['file']]:
                docker('cp',directory/archive,name+':/workspace/'+archive,stage=Stage.RUNTIME_INPUTS,timeout=180)
                docker('exec',name,'docker','load','--input','/workspace/'+archive,stage=Stage.LOAD,timeout=180)
            # Only the fixed test driver and candidate metadata cross this boundary.
            driver=Path(__file__).with_name('candidate_installation_driver.py')
            docker('cp',driver,name+':/workspace/driver.py',stage=Stage.RUNTIME_INPUTS)
            docker('cp',directory/'candidate.json',name+':/workspace/candidate.json',stage=Stage.RUNTIME_INPUTS)
            raw=docker('exec',name,'python3','/workspace/driver.py',stage=Stage.INITIALIZE,timeout=900)
            result=json.loads(raw)
            require(result.get('status')=='passed','installation qualification failed')
            result['candidate']=manifest['archive']['manifest_digest']
            result['platform']=manifest['platform']

    finally:
        try:
            cleanup(created,[])
        finally:
            # The node image is test-owned and contains no installation credentials.
            if built:docker('image','rm',name,stage=Stage.REMOVE_CONTAINER)
    marker.write_text(json.dumps(result,indent=2)+'\n')

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('candidate',type=Path)
    qualify(parser.parse_args().candidate.resolve())
