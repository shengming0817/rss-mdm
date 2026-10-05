#!/usr/bin/env python3
"""Materialize and verify schemas derived from the protocol's Rust declarations."""
from functools import cache
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from build_run import LEASE_ENV, lease_fds, require_lease

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / 'crates/agent-wire/schema/runtime'
MANIFEST = SCHEMAS / 'agent-v1.schema-manifest.json'
LIB = ROOT / 'crates/agent-wire/src/runtime.rs'
ENROLL = ROOT / 'crates/agent-wire/schema/enroll'
ENROLL_LIB = ROOT / 'crates/agent-wire/src/enroll.rs'


@cache
def generated():
    cargo = ['cargo', 'run', '--quiet', '--locked', '-p', 'rss-mdm-agent-wire',
             '--example', 'protocol_schema']
    if LEASE_ENV in os.environ:
        require_lease(ROOT)
        command, fds = cargo, lease_fds()
    else:
        command, fds = [sys.executable, str(ROOT / 'hack/build_run.py'), '--', *cargo], ()
    result = subprocess.run(
        command, pass_fds=fds, cwd=ROOT, check=True, stdout=subprocess.PIPE, text=True,
    )
    return json.loads(result.stdout)


def artifact(directory, manifest_path, library, area, write=False):
    manifest = json.loads(manifest_path.read_text())
    if manifest.get('apiVersion') != 1 or (area == 'runtime' and manifest.get('wireVersion') != 1):
        raise ValueError('manifest must declare Agent V1')
    entries = manifest['schemas']
    files = [entry['file'] for entry in entries]
    types = [entry['type'] for entry in entries]
    if (not files or len(files) != len(set(files)) or len(types) != len(set(types))
            or any(not name.endswith('-v1.schema.json') for name in files)):
        raise ValueError('manifest has duplicate or non-V1 schema entries')
    if set(types) != set(generated()[area]):
        raise ValueError('manifest differs from the Rust protocol declarations')
    if {path.name for path in directory.glob('*.json')} != set(files) | {manifest_path.name}:
        raise ValueError('schema directory differs from the V1 manifest')
    digest = hashlib.sha256()
    for entry in entries:
        schema = dict(generated()[area][entry['type']])
        schema['$id'] = (
            'https://rss.example/mdm/agent/runtime/v1/payload/v1/'
            + entry['file'].replace('-v1.schema.json', '.schema.json')
            if area == 'runtime' else 'https://rss.example/agent/enroll/v1/' + entry['type']
        )
        expected = (json.dumps(schema, indent=2, ensure_ascii=False) + '\n').encode()
        path = directory / entry['file']
        if write:
            path.write_bytes(expected)
        elif path.read_bytes() != expected:
            raise ValueError(f"{entry['file']}: schema differs from Rust declarations; regenerate the artifact")
        digest.update(expected)
    pattern = r'(pub const SCHEMA_FINGERPRINT:\s*&str\s*=\s*")[0-9a-f]{64}(";)'
    source = library.read_text()
    match = re.search(pattern, source)
    if match is None:
        raise ValueError('schema fingerprint declaration missing')
    if write:
        library.write_text(re.sub(pattern, lambda m: m[1] + digest.hexdigest() + m[2], source))
    elif match[0] != match[1] + digest.hexdigest() + match[2]:
        raise ValueError('schema fingerprint differs from the declared V1 artifact')


def check():
    artifact(SCHEMAS, MANIFEST, LIB, 'runtime')


def enrollment(write=False):
    artifact(ENROLL, ENROLL / 'manifest.json', ENROLL_LIB, 'enroll', write)


def main():
    try:
        if sys.argv[1:] == ['--write']:
            artifact(SCHEMAS, MANIFEST, LIB, 'runtime', True)
            enrollment(True)
        elif len(sys.argv) != 1:
            raise ValueError('usage: agent_wire_artifact.py [--write]')
        check()
        enrollment()
    except (ValueError, OSError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(f'agent-wire artifact: {error}', file=sys.stderr)
        return 1
    print('Agent enrollment V1 and runtime V1 / payload V1 schemas match Rust declarations')
    return 0


if __name__ == '__main__':
    sys.exit(main())
