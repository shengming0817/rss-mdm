#!/usr/bin/env python3
"""One whole-command lease for a worktree and its Cargo target.

Adapted from RSS hack/ci-run.py at e901f5a1cd023e28d3a190e36ed8508f2afc467e.
ref: CPython v3.11.13 Lib/subprocess.py (explicit pass_fds across Python children).
ref: mozilla/sccache v0.15.0 src/commands.rs (start server before taking leases).
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time

SCCACHE_VERSION = '0.15.0'
LEASE_ENV = '_MDM_BUILD_LEASE'
LOCK_ROOT = Path.home() / '.cache/rss-mdm-build-locks'
POOL_MARKER = '.mdm-target-pool-v1'


def log(message):
    print(f'mdm-build: {message}', file=sys.stderr, flush=True)


def directory(path):
    if path.is_symlink():
        raise ValueError(f'refusing symlink directory: {path}')
    path.mkdir(parents=True, exist_ok=True)
    return canonical_directory(path)


def canonical_directory(path):
    """Ask the filesystem for its spelling, including case/Unicode aliases on macOS."""
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        if sys.platform == 'darwin':
            return Path(os.fsdecode(fcntl.fcntl(fd, fcntl.F_GETPATH, bytes(1024)).split(b'\0', 1)[0]))
        return Path(os.readlink(f'/proc/self/fd/{fd}'))
    finally:
        os.close(fd)


def lock_file(path, blocking=False):
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError(f'not a regular lock file: {path}')
        fcntl.flock(fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        return fd
    except BlockingIOError:
        os.close(fd)
        return None
    except BaseException:
        os.close(fd)
        raise


def owned_directory(path, marker):
    root = directory(path)
    fd = lock_file(root / '.init.lock', blocking=True)
    try:
        identity = root / marker
        if not identity.exists() and not identity.is_symlink():
            if any(p.name != '.init.lock' for p in root.iterdir()):
                raise ValueError(f'refusing unmarked nonempty directory: {root}')
            out = os.open(identity, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(out, 'w') as stream:
                stream.write(marker + '\n')
        source = os.open(identity, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(source) as stream:
            if stream.read() != marker + '\n':
                raise ValueError(f'invalid directory identity: {root}')
        return root
    finally:
        os.close(fd)


def lock_path(kind, path):
    # Resources are canonicalized before allocation. Keep the key stable across cargo clean.
    digest = hashlib.sha256(os.fsencode(path)).hexdigest()
    return LOCK_ROOT / f'{kind}-{digest}.lock'


def take_lock(kind, path):
    fd = lock_file(lock_path(kind, path))
    if fd is None:
        raise ValueError(f'{kind} busy: {path}')
    return fd


def lease_fds():
    """Borrow inherited locks; never reopen, unlock, or silently discard a bad lease."""
    raw = os.environ.get(LEASE_ENV)
    if raw is None:
        return ()
    try:
        lease = json.loads(raw)
        fds = tuple(lease['fds'])
        if len(fds) != 2 or any(type(fd) is not int or fd < 3 for fd in fds) or len(set(fds)) != 2:
            raise ValueError('invalid descriptor list')
        for kind, fd in zip(('worktree', 'target'), fds):
            expected = Path(lease[kind])
            if not expected.is_absolute() or expected.resolve() != expected:
                raise ValueError('noncanonical resource')
            held = os.fstat(fd)
            locked = lock_path(kind, expected).stat(follow_symlinks=False)
            if not stat.S_ISREG(held.st_mode) or (held.st_dev, held.st_ino) != (locked.st_dev, locked.st_ino):
                raise ValueError('descriptor does not identify the resource lock')
        if Path(os.environ['CARGO_TARGET_DIR']).resolve() != Path(lease['target']):
            raise ValueError('target changed within a run')
        return fds
    except (ValueError, TypeError, KeyError, OSError) as error:
        raise ValueError('invalid build lease; use make or hack/build_run.py') from error


def require_lease(worktree):
    if not lease_fds():
        raise ValueError('build lease required; use make or python3 hack/build_run.py -- COMMAND')
    if Path(json.loads(os.environ[LEASE_ENV])['worktree']) != canonical_directory(worktree):
        raise ValueError('build lease belongs to a different worktree')


def target_config(env, worktree):
    raw = env.get('MDM_TARGET_POOL_N', '4')
    if raw not in ('0', 'off') and not re.fullmatch(r'[1-9][0-9]*', raw):
        raise ValueError('MDM_TARGET_POOL_N must be positive, 0 or off')
    explicit = env.get('CARGO_TARGET_DIR')
    if explicit is not None:
        if not explicit.strip():
            raise ValueError('CARGO_TARGET_DIR must not be empty')
        if raw not in ('0', 'off') and 'MDM_TARGET_POOL_N' in env:
            raise ValueError('explicit pool size and CARGO_TARGET_DIR conflict')
        target = Path(explicit).resolve()
        # A pool directory is managed only by its allocator, even when currently idle.
        if any((parent / POOL_MARKER).exists() for parent in (target, *target.parents)):
            raise ValueError('explicit target must not point inside a managed pool')
        return None, target
    if raw in ('0', 'off'):
        return None, worktree / 'target'
    root = Path(env.get('MDM_TARGET_POOL_ROOT', str(Path.home() / '.cache/rss-mdm-cargo-target-pool')))
    return (root.absolute(), int(raw)), None


def metadata(root, index):
    path = root / f'slot-{index}.json'
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd) as stream:
            value = json.load(stream)
        if (not isinstance(value, dict) or not isinstance(value.get('worktree'), str)
                or type(value.get('last_used')) not in (float, int)):
            raise ValueError(f'invalid slot metadata: {path}')
        return value
    except FileNotFoundError:
        return None


def write_metadata(root, index, worktree):
    path = root / f'.lease-{os.getpid()}.tmp'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump({'worktree': str(worktree), 'last_used': time.time()}, stream)
        os.replace(path, root / f'slot-{index}.json')
    finally:
        path.unlink(missing_ok=True)


def acquire_slot(root, slots, worktree):
    root = owned_directory(root, POOL_MARKER)
    global_fd = lock_file(root / '.pool.lock', blocking=True)
    held = {}
    try:
        indices = set(range(slots))
        indices.update(int(p.name[5:]) for p in root.glob('slot-*') if re.fullmatch(r'slot-[0-9]+', p.name))
        candidates = []
        for index in sorted(indices):
            target = root / f'slot-{index}'
            if target.is_symlink():
                raise ValueError(f'refusing symlink slot: {target}')
            # Establish the actual filesystem spelling before choosing its one lock identity.
            target = directory(target)
            value = metadata(root, index)
            fd = lock_file(lock_path('target', target))
            if fd is None:
                continue
            held[index] = fd
            if index >= slots:
                if target.exists():
                    shutil.rmtree(target)
                (root / f'slot-{index}.json').unlink(missing_ok=True)
                continue
            rank = (0 if value and value['worktree'] == str(worktree) else
                    1 if value is None else 2 if not Path(value['worktree']).exists() else 3)
            candidates.append((rank, value['last_used'] if value else 0, index))
        if not candidates:
            raise ValueError(f'pool full ({slots} slots): {root}')
        rank, _, index = min(candidates)
        target = canonical_directory(root / f'slot-{index}')
        if rank != 0 and target.exists():
            shutil.rmtree(target)
        directory(target)
        write_metadata(root, index, worktree)
        return target, held.pop(index)
    finally:
        for fd in held.values():
            os.close(fd)
        os.close(global_fd)


def compiler_cache(env, worktree):
    mode = env.get('MDM_COMPILER_CACHE', 'auto')
    if mode not in ('auto', 'on', 'off'):
        raise ValueError('MDM_COMPILER_CACHE must be auto, on or off')
    wrappers = ('RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CARGO_BUILD_RUSTC_WRAPPER',
                'CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER')
    if any(env.get(key) for key in wrappers):
        raise ValueError('custom rustc wrapper conflicts with managed compiler cache')
    # Override ancestor Cargo configuration too: this runner owns compiler caching.
    env.update(RUSTC_WRAPPER='', RUSTC_WORKSPACE_WRAPPER='')
    if mode == 'off':
        return
    binary = shutil.which('sccache', path=env.get('PATH'))
    try:
        version = subprocess.run([binary, '--version'], env=env, capture_output=True, text=True, timeout=10) if binary else None
        if version is None or version.returncode or version.stdout.strip() != f'sccache {SCCACHE_VERSION}':
            raise ValueError(f'sccache {SCCACHE_VERSION} unavailable')
        git = subprocess.run(['/usr/bin/git', '-C', str(worktree), 'rev-parse', '--path-format=absolute', '--git-common-dir'],
                             capture_output=True, text=True, timeout=10)
        root = (Path(git.stdout.strip()).parent / '.cache/sccache/objects' if git.returncode == 0
                else Path.home() / '.cache/rss-mdm-sccache/objects')
        env.setdefault('SCCACHE_DIR', str(root))
        env.setdefault('SCCACHE_SERVER_UDS', str(Path(env['SCCACHE_DIR']) / 'server.sock'))
        env.setdefault('SCCACHE_CACHE_SIZE', '10G')
        env['SCCACHE_DIR'] = str(directory(Path(env['SCCACHE_DIR'])))
        uds = Path(env['SCCACHE_SERVER_UDS'])
        env['SCCACHE_SERVER_UDS'] = str(directory(uds.parent) / uds.name)
        if len(os.fsencode(env['SCCACHE_SERVER_UDS'])) >= 100:
            raise ValueError('sccache socket path is too long')
        startup_fd = lock_file(Path(env['SCCACHE_SERVER_UDS'] + '.lock'), blocking=True)
        try:
            def connect():
                with socket.socket(socket.AF_UNIX) as connection:
                    connection.settimeout(5)
                    connection.connect(env['SCCACHE_SERVER_UDS'])
            try:
                connect()
            except (FileNotFoundError, ConnectionRefusedError):
                subprocess.run([binary, '--start-server'], env=env, capture_output=True, timeout=15)
                connect()
        finally:
            os.close(startup_fd)
        probe = subprocess.run([binary, '--show-stats', '--stats-format', 'json'], env=env,
                               capture_output=True, text=True, timeout=15)
        stats = json.loads(probe.stdout)
        if (probe.returncode or stats.get('version') != SCCACHE_VERSION
                or stats.get('cache_location') != f'Local disk: "{Path(env["SCCACHE_DIR"]).resolve()}"'):
            raise ValueError('sccache server version/cache directory differs; restart it after active builds exit')
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        if mode == 'on':
            raise ValueError(f'compiler cache unavailable: {error}') from error
        log(f'compiler cache disabled: {error}')
        return
    env.update(RUSTC_WRAPPER=binary, CARGO_INCREMENTAL='0', SCCACHE_IGNORE_SERVER_IO_ERROR='1')
    log(f'compiler cache enabled: sccache {SCCACHE_VERSION}')


def run_child(argv, env, fds):
    process = None
    cancelled = []
    previous = {}
    def forward(sig, _frame):
        if not cancelled:
            cancelled.append((sig, time.monotonic()))
        if process is not None:
            try:
                os.killpg(process.pid, sig)
            except ProcessLookupError:
                pass
    try:
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            previous[sig] = signal.signal(sig, forward)
        process = subprocess.Popen(argv, env=env, start_new_session=True, pass_fds=fds)
        if cancelled:
            forward(cancelled[0][0], None)
        while True:
            try:
                result = process.wait(timeout=.1)
                break
            except subprocess.TimeoutExpired:
                if cancelled and time.monotonic() - cancelled[0][1] >= 5:
                    forward(signal.SIGKILL, None)
        # A shell can exit on TERM while a grandchild ignores it. Reap that group too.
        if cancelled:
            end = cancelled[0][1] + 5
            while True:
                try:
                    os.killpg(process.pid, 0)
                except ProcessLookupError:
                    break
                if time.monotonic() >= end:
                    forward(signal.SIGKILL, None)
                    break
                time.sleep(.02)
            return 128 + cancelled[0][0]
        return result if result >= 0 else 128 - result
    finally:
        if process is not None and process.poll() is None:
            forward(signal.SIGKILL, None)
            process.wait()
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def main(argv):
    if len(argv) < 2 or argv[0] != '--':
        raise ValueError('usage: build_run.py -- COMMAND [ARG...]')
    if LEASE_ENV in os.environ:
        raise ValueError('nested build runner is not allowed; inherit the existing lease')
    env = os.environ.copy()
    worktree = canonical_directory(Path.cwd())
    pool, target = target_config(env, worktree)
    # A persistent cache daemon must never inherit a build lease.
    compiler_cache(env, worktree)
    owned_directory(LOCK_ROOT, '.mdm-build-locks-v1')
    work_fd = take_lock('worktree', worktree)
    target_fd = None
    try:
        if pool:
            target, target_fd = acquire_slot(*pool, worktree)
        else:
            target = directory(target.resolve())
            target_fd = take_lock('target', target)
        env['CARGO_TARGET_DIR'] = str(target)
        fds = (work_fd, target_fd)
        env[LEASE_ENV] = json.dumps({'worktree': str(worktree), 'target': str(target), 'fds': fds})
        log(f'target={target} pool={"on" if pool else "off"}')
        return run_child(argv[1:], env, fds)
    finally:
        # No LOCK_UN: surviving children can still own the same open file descriptions.
        if target_fd is not None:
            os.close(target_fd)
        os.close(work_fd)


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except (ValueError, OSError) as error:
        log(str(error))
        sys.exit(2)
