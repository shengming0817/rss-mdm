"""Explicit CA recovery proof; ordinary trust fixtures never call this lifecycle."""
from contextlib import contextmanager
import contextvars
import hashlib
import shutil
import threading
from pki_ca import Provider

def restore(root):
    # Caller has stopped step-ca. Preserve the same path, identity, provisioner
    # database and consumed token history; never initialize a replacement CA.
    original = root/'step'
    backup = root/'step-backup'
    shutil.copytree(original, backup)
    # Keep shared filesystem inodes stable while discarding every original byte.
    # Docker Desktop can retain a stale view after removing/recreating this tree.
    for path in original.rglob('*'):
        if path.is_file():
            path.write_bytes(b'')
    shutil.copytree(backup, original, dirs_exist_ok=True)
    (root/'agent-backup-restored').write_text('same CA identity, config and database restored\n')


@contextmanager
def recovering(root, state, case, generation, origin, compose_file, providers):
    stopped = threading.Event()
    failures = []
    def recover_after_request():
        while not stopped.wait(.1):
            if not (root/'agent-recovery-request').exists():
                continue
            try:
                provider = state[0]
                provider.fence()
                restore(root)
                standby = Provider(root, hashlib.sha256((case+':agent-standby'+(':'+generation if generation else '')).encode()).hexdigest()[:20], compose_file=compose_file, providers=providers, internal_host=provider.internal_host)
                try:
                    standby.promote_from(provider, origin)
                except BaseException:
                    standby.reset()
                    raise
                state[0] = standby
                provider.reset()
                (root/'agent-recovery-complete').write_text('restored and promoted after issuance\n')
            except BaseException as error:
                failures.append(error)
                (root/'agent-recovery-failed').write_text(type(error).__name__)
            return
    context = contextvars.copy_context()
    worker = threading.Thread(target=lambda: context.run(recover_after_request), name='case-ca-recovery')
    worker.start()
    try:
        yield
    finally:
        stopped.set()
        worker.join()
    if failures:
        raise RuntimeError('case CA recovery failed') from failures[0]
    if not (root/'agent-recovery-complete').exists():
        raise RuntimeError('case did not exercise CA recovery')
