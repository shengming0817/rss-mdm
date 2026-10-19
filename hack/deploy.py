#!/usr/bin/env python3
"""Prepare a fixed candidate's formal Compose deployment; never initializes product data.

The resulting env/Compose files can be operated with ordinary `docker compose`.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import shlex
import stat
import subprocess
import uuid


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def prepare(candidate, output, *, origin='https://localhost:8445', additional_origins='https://localhost:8446',
            project=None, publish_ip='127.0.0.1', tls_mode='local', input_directory=None):
    from candidate_runtime import verify_candidate, load_ui
    manifest = verify_candidate(candidate)
    if 'ui' not in manifest:
        raise ValueError('formal console deployment requires a combined candidate with --web-image')
    ui = load_ui(candidate, manifest['ui'])
    if '/'.join((ui['os'], ui['architecture'])) != manifest['platform']:
        raise ValueError('UI platform mismatch')
    project = project or 'rss-mdm-'+uuid.uuid4().hex[:12]
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,55}', project):
        raise ValueError('invalid project name')
    endpoint = None if os.environ.get('DOCKER_CONTEXT') else os.environ.get('DOCKER_HOST')
    if not endpoint:
        context = json.loads(run('docker', 'context', 'inspect'))[0]
        endpoint = context['Endpoints']['docker']['Host']
    if not endpoint.startswith('unix://'):
        raise ValueError('select a local Unix-socket Docker context for Compose deployment')
    socket = Path(endpoint.removeprefix('unix://')).resolve(strict=True)
    metadata = socket.stat()
    if not stat.S_ISSOCK(metadata.st_mode):
        raise ValueError('Docker context endpoint is not a socket')
    output.mkdir(mode=0o700)
    inputs = input_directory.resolve(strict=True) if input_directory else output/'inputs'
    if input_directory is None:
        inputs.mkdir(mode=0o700)
    server_image=run('docker','image','inspect','--format','{{.Id}}',manifest['image'].split('@')[0])
    installer_image=run('docker','image','inspect','--format','{{.Id}}',manifest['installer']['image'].split('@')[0])
    # Docker Desktop translates socket ownership. Inspect the daemon-visible mount,
    # rather than applying the macOS filesystem's staff group inside a Linux container.
    socket_group=run('docker','run','--rm','--network','none','--user','10001:10001',
        '--mount','type=bind,source='+str(socket)+',target=/run/docker.sock',
        '--entrypoint','stat',installer_image,'-c','%g','/run/docker.sock')
    if not socket_group.isdecimal():
        raise ValueError('Docker socket group probe failed')
    values = dict(COMPOSE_PROJECT_NAME=project,
        MDM_SERVER_IMAGE=server_image, MDM_INSTALLER_IMAGE=installer_image,
        MDM_WEB_IMAGE=ui['id'], MDM_POSTGRES_IMAGE=manifest['providers']['postgres'],
        MDM_DOCKER_SOCKET=str(socket), MDM_DOCKER_GID=socket_group,
        MDM_INPUT_DIRECTORY=str(inputs), MDM_PRODUCT_ORIGIN=origin,
        MDM_ADDITIONAL_ORIGINS=additional_origins, MDM_PUBLISH_IP=publish_ip, MDM_TLS_MODE=tls_mode)
    # Single-quoted Compose env values preserve paths with spaces without interpolation.
    if any('\n' in str(v) or '\r' in str(v) or "'" in str(v) for v in values.values()):
        raise ValueError('unsupported environment value')
    env = output/'compose.env'
    env.write_text(''.join(f"{k}='{v}'\n" for k,v in values.items()))
    env.chmod(0o600)
    compose = output/'compose.yaml'
    # Freeze the actual Compose model once. Ambient MDM/COMPOSE variables cannot rebind
    # already prepared images, volumes, credentials or endpoints on later invocations.
    environment={k:v for k,v in os.environ.items() if not k.startswith(('COMPOSE_', 'MDM_'))}
    model=json.loads(subprocess.check_output(['docker','compose','--project-name',project,'--env-file',str(env),
        '-f',str(candidate/'deployment/production.compose.yaml'),'config','--format','json'],env=environment,text=True))
    compose.write_text(json.dumps(model).replace('$','$$')+'\n')
    (output/'deployment.json').write_text(json.dumps(dict(project=project, candidate=str(candidate),
        platform=manifest['platform'], host=dict(os=platform.system(), architecture=platform.machine())), indent=2)+'\n')
    return dict(project=project, environment=str(env), compose=str(compose), origin=origin)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--origin', default='https://localhost:8445')
    parser.add_argument('--additional-origins', default='https://localhost:8446')
    parser.add_argument('--project')
    parser.add_argument('--publish-ip', default='127.0.0.1')
    parser.add_argument('--tls-mode', choices=['local', 'supplied'], default='local')
    parser.add_argument('--input-directory', type=Path)
    args = parser.parse_args()
    result = prepare(args.candidate.resolve(), args.output.resolve(), origin=args.origin,
        additional_origins=args.additional_origins, project=args.project, publish_ip=args.publish_ip,
        tls_mode=args.tls_mode, input_directory=args.input_directory)
    print(json.dumps(result))
    print('docker compose --project-name '+shlex.quote(result['project'])+' -f '+shlex.quote(result['compose'])+' up -d')
