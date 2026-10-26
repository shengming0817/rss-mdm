"""Expose the owned PostgreSQL image's archive clients to native Rust T2 tests."""
import os
import shutil
from pathlib import Path
from t2_environment import private, run


def clients(root, owners):
    descriptors = []
    for owner in owners:
        destination = '/tmp/archive-client-ca.crt'
        run(['docker', 'cp', str(owner.root / 'ca.crt'), owner.container() + ':' + destination], capture_output=True, timeout=30)
        descriptors.append(dict(container=owner.container(), port=owner.port(), major=17, ca=destination))
    descriptor = private(root / 'pg-archive-clients.json', descriptors)
    binaries = root / 'pg-clients'
    binaries.mkdir(mode=0o700)
    for name in ('pg_dump', 'pg_restore'):
        target = binaries / name
        shutil.copyfile(Path(__file__).with_name('postgres_archive_client.py'), target)
        target.chmod(0o700)
    return dict(MDM_PG_ARCHIVE_CLIENTS=str(descriptor), PATH=str(binaries) + os.pathsep + os.environ['PATH'])
