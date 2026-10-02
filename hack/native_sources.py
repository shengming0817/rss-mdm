#!/usr/bin/env python3
"""Pack fixed machine schemas and restore their ignored offline working copies.

ref: CPython Lib/zipfile/__init__.py (ZipInfo and ZipFile).
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import stat
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SOURCES = Path('crates/native-schema/sources')
GROUPS = {
    'windows-ddf': Path('crates/windows-mdm/ddf/upstream'),
    'windows-admx': Path('crates/windows-mdm/schema/upstream/admx'),
    'apple-schema': Path('crates/apple-mdm/schema/upstream'),
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def pack(root=ROOT):
    destination = root / SOURCES
    destination.mkdir(parents=True, exist_ok=True)
    archives = {}
    for name, relative in GROUPS.items():
        source = root / relative
        files = sorted(p for p in source.rglob('*') if p.is_file())
        if not files or any(p.is_symlink() for p in files):
            raise ValueError(f'missing or invalid schema source: {name}')
        archive = destination / f'{name}.zip'
        with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as output:
            for path in files:
                info = zipfile.ZipInfo(path.relative_to(source).as_posix(), (1980, 1, 1, 0, 0, 0))
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                output.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        archives[name] = {'sha256': digest(archive.read_bytes()), 'files': len(files)}
    (destination / 'lock.json').write_text(json.dumps(archives, indent=2) + '\n')


def prepare(root=ROOT):
    archives = json.loads((root / SOURCES / 'lock.json').read_text())
    if set(archives) != set(GROUPS):
        raise ValueError('native schema archive set does not match its owners')
    for name, relative in GROUPS.items():
        archive = root / SOURCES / f'{name}.zip'
        expected = archives[name]
        if digest(archive.read_bytes()) != expected['sha256']:
            raise ValueError(f'native schema ZIP digest mismatch: {name}')
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.is_symlink():
            raise ValueError('schema cache must not be a symlink')
        with tempfile.TemporaryDirectory(prefix='.native-schema-', dir=destination.parent) as directory:
            staged = Path(directory) / 'source'
            staged.mkdir()
            with zipfile.ZipFile(archive) as source:
                entries = source.infolist()
                if len(entries) != expected['files'] or len({entry.filename for entry in entries}) != len(entries):
                    raise ValueError('invalid native schema ZIP inventory')
                for entry in entries:
                    path = PurePosixPath(entry.filename)
                    if path.is_absolute() or '..' in path.parts or '\\' in entry.filename or not stat.S_ISREG(entry.external_attr >> 16):
                        raise ValueError('invalid native schema ZIP member')
                    target = staged.joinpath(*path.parts)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(source.read(entry))
            if destination.exists():
                destination.rename(Path(directory) / 'previous')
            staged.rename(destination)
            # TemporaryDirectory releases only the replaced, reproducible cache.


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['pack', 'prepare'])
    args = parser.parse_args()
    (pack if args.action == 'pack' else prepare)()


if __name__ == '__main__':
    main()
