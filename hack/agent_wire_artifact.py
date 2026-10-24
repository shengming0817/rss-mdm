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
FAMILIES = {
    'enterprise': ('manifest.json', 'https://rss.example/agent/enterprise/v1/', {'apiVersion': 1}),
    'platform_sso': ('manifest.json', 'https://rss.example/agent/platform-sso/v1/', {'apiVersion': 1}),
    'connections': ('manifest.json', 'https://rss.example/agent/connections/v1/', {'apiVersion': 1}),
    'runtime': ('agent-v1.schema-manifest.json',
                'https://rss.example/mdm/agent/runtime/v1/payload/v1/',
                {'apiVersion': 1, 'wireVersion': 1}),
    'enroll': ('manifest.json', 'https://rss.example/agent/enroll/v1/', {'apiVersion': 1}),
    'task_trust': ('manifest.json', 'https://rss.example/agent/task-trust/v1/', {'apiVersion': 1}),
    'pki': ('manifest.json', 'https://rss.example/agent/pki/v1/', {'apiVersion': 1}),
}


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
    if area not in FAMILIES:
        raise ValueError('unknown protocol family')
    _, identity, versions = FAMILIES[area]
    manifest = json.loads(manifest_path.read_text())
    if any(type(manifest.get(key)) is not int or manifest[key] != value
           for key, value in versions.items()):
        raise ValueError('manifest must declare Agent V1')
    entries = manifest['schemas']
    files = [entry['file'] for entry in entries]
    types = [entry['type'] for entry in entries]
    if (not files or len(files) != len(set(files)) or len(types) != len(set(types))
            or any(not re.fullmatch(r'[a-z]+(?:-[a-z]+)*-v1\.schema\.json', name) for name in files)):
        raise ValueError('manifest has duplicate or non-V1 schema entries')
    if set(types) != set(generated()[area]):
        raise ValueError('manifest differs from the Rust protocol declarations')
    expected_files = set(files) | {manifest_path.name}
    actual_files = {path.name for path in directory.glob('*.json')}
    if actual_files - expected_files or (not write and expected_files - actual_files):
        raise ValueError('schema directory differs from the V1 manifest')
    digest = hashlib.sha256()
    for entry in entries:
        schema = dict(generated()[area][entry['type']])
        schema['$id'] = (
            identity + (entry['file'].replace('-v1.schema.json', '.schema.json')
                        if area == 'runtime' else entry['type'])
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


def verify(write=False):
    if set(generated()) != set(FAMILIES):
        raise ValueError('protocol families differ from Rust declarations')
    for area, (manifest_name, _, _) in FAMILIES.items():
        directory = ROOT / 'crates/agent-wire/schema' / area
        library = ROOT / 'crates/agent-wire/src' / (area + '.rs')
        artifact(directory, directory / manifest_name, library, area, write)


def main():
    try:
        if sys.argv[1:] == ['--write']:
            verify(True)
        elif len(sys.argv) != 1:
            raise ValueError('usage: agent_wire_artifact.py [--write]')
        verify()
    except (ValueError, OSError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(f'agent-wire artifact: {error}', file=sys.stderr)
        return 1
    print('Agent enrollment V1, runtime V1 / payload V1 and PKI V1 schemas match Rust declarations')
    return 0


if __name__ == '__main__':
    sys.exit(main())
