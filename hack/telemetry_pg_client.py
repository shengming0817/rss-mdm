#!/usr/bin/env python3
"""Run actual pinned provider PostgreSQL clients for native-host backup T2 cases."""
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    tool = Path(sys.argv[0]).name
    if tool not in {'pg_dump', 'pg_restore'}:
        raise ValueError('unknown archive client')
    major = 17
    executable = tool
    providers = json.loads(Path(os.environ['MDM_TELEMETRY_PG_CLIENTS']).read_text())
    args = sys.argv[1:]
    if args == ['--version']:
        provider = next(p for p in providers if p['major'] == major)
        return subprocess.run(['docker', 'exec', provider['container'], executable, '--version'], check=False).returncode
    index = args.index('--port') + 1
    provider = next(p for p in providers if p['port'] == int(args[index]) and p['major'] == major)
    args[index] = '5432'
    args[args.index('--host') + 1] = 'localhost'
    # The certificate is already mounted by the fixture owner. The binary, server and CA
    # all come from that owner; no network download or alternate PostgreSQL installation.
    command = ['docker', 'exec', '-i', '-e', 'PGPASSWORD', '-e', 'PGSSLMODE=verify-full',
               '-e', 'PGCONNECT_TIMEOUT=5', '-e', 'PGSSLROOTCERT=' + provider['ca'],
               provider['container'], executable]
    if executable == 'pg_restore':
        archive = args.pop()
        with open(archive, 'rb') as source:
            return subprocess.run([*command, *args], stdin=source, check=False).returncode
    return subprocess.run([*command, *args], check=False).returncode


if __name__ == '__main__':
    sys.exit(main())
