#!/usr/bin/env python3
"""Qualify the real Compose installation on the selected Docker context, without DinD/systemd."""
import argparse
import json
from pathlib import Path
import platform
import socket
import tempfile
from deploy import prepare
from candidate_installation_driver import Installation, qualify
from candidate_runtime import sha


def qualify_candidate(candidate):
    marker=candidate/'installation-result.json'
    marker.unlink(missing_ok=True)
    # Reserve both local ports until preparation has frozen them; never touch unrelated resources.
    sockets=[socket.socket() for _ in range(2)]
    owner=None
    try:
        for value in sockets:value.bind(('127.0.0.1',0))
        ports=[value.getsockname()[1] for value in sockets]
        origins=['https://localhost:'+str(port) for port in ports]
        with tempfile.TemporaryDirectory(prefix='mdm-compose-qualification-') as temporary:
            root=Path(temporary)/'deployment'
            prepared=prepare(candidate,root,origin=origins[0],additional_origins=origins[1])
            owner=Installation(root)
            for value in sockets:value.close()
            try:
                result=qualify(owner,*origins)
                result.update(candidate_sha256=sha(candidate/'candidate.json'),
                    compose_sha256=sha(root/'compose.yaml'),host=dict(os=platform.system(),architecture=platform.machine()),
                    container_platform=json.loads((root/'deployment.json').read_text())['platform'])
            finally:
                owner.cleanup()
                owner=None
        marker.write_text(json.dumps(result,indent=2)+'\n')
    except BaseException as error:
        (candidate/'installation-failure.json').write_text(json.dumps(dict(status='failed',error_class=type(error).__name__))+'\n')
        raise
    finally:
        for value in sockets:value.close()

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('candidate',type=Path)
    args=parser.parse_args()
    qualify_candidate(args.candidate.resolve())
