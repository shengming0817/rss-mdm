#!/usr/bin/env python3
"""Run supplied DA initialization inputs; Rust owners perform all durable operations."""
import argparse
import json
from pathlib import Path
import subprocess


def initialize(root, binary):
    root = Path(root)
    if not root.is_absolute() or root.is_symlink() or not root.is_dir() or root.stat().st_mode & 0o077:
        raise ValueError('private absolute installation directory required')
    runtime = root / 'runtime'
    if runtime.is_symlink() or not runtime.is_dir() or runtime.stat().st_mode & 0o077:
        raise ValueError('private runtime directory required')
    entries = [('prepare-database', 'database.json'), ('install', 'install.json')]
    accounts = json.loads((root / 'accounts.json').read_text())
    if not isinstance(accounts, list) or not accounts:
        raise ValueError('explicit original account input paths required')
    entries += [('initialize-account', name) for name in accounts]
    entries.append(('diagnose', 'runtime/runtime.json'))
    for command, name in entries:
        path = root / name
        if Path(name).is_absolute() or '..' in Path(name).parts or not path.is_file() or path.is_symlink() or path.stat().st_mode & 0o077:
            raise ValueError('protected input file required')
        subprocess.run([binary, command, '--config', str(path)], check=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--binary', default='/usr/local/bin/rss-da-installer')
    args = parser.parse_args()
    initialize(args.directory, args.binary)
