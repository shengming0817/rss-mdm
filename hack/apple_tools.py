"""Verify fixed fixture tools and serialize complete cache publication.

ref: CPython Lib/tempfile.py; build_run.lock_file (separate open-file lock owners).
"""
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import tarfile
import tempfile
import time
import urllib.request

from build_run import lease_fds, lock_file, require_lease
from t2_processes import check_cancelled

ROOT = Path(__file__).resolve().parents[1]
LOCK = json.loads((ROOT/'fixtures/apple-tools.lock.json').read_text())


@contextmanager
def publication(directory):
    directory.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + 300
    held = None
    try:
        while held is None:
            check_cancelled()
            held = lock_file(directory/'.publish.lock')
            if held is None:
                if time.monotonic() >= deadline:
                    raise RuntimeError('fixture tool publication lock deadline')
                time.sleep(.05)
        check_cancelled()
        yield
    finally:
        if held is not None:
            os.close(held)


def publish(path, content, mode=0o600):
    """Replace only verified bytes; cleanup never touches another caller's stage."""
    fd, temporary = tempfile.mkstemp(prefix='.'+path.name+'-', dir=path.parent)
    staged = Path(temporary)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            os.fchmod(stream.fileno(), mode)
        staged.replace(path)
    finally:
        staged.unlink(missing_ok=True)


def verified_archive(path, url, expected, *, timeout, limit):
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        data = b''
    if hashlib.sha256(data).hexdigest() == expected:
        return data
    with urllib.request.urlopen(url, timeout=timeout) as response:
        data = response.read(limit)
    if hashlib.sha256(data).hexdigest() != expected:
        raise RuntimeError('fixed fixture source/artifact checksum mismatch')
    check_cancelled()
    publish(path, data)
    return data


def binary(name):
    item = LOCK[name]
    system = platform.system().lower()
    machine = {'aarch64': 'arm64', 'arm64': 'arm64', 'x86_64': 'amd64'}[platform.machine()]
    expected = item['artifacts'][system+'-'+machine]
    cache = Path(os.environ.get('CARGO_TARGET_DIR', ROOT/'target'))/'apple-tools'/expected
    with publication(cache):
        filename = f"{name}_{system}_{item['version']}_{machine}.tar.gz"
        url = f"https://github.com/{item['repository']}/releases/download/v{item['version']}/{filename}"
        data = verified_archive(cache/'archive.tar.gz', url, expected, timeout=120, limit=160*1024*1024)
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as tar:
            candidates = [member for member in tar.getmembers() if member.isfile() and (member.name == name or member.name.endswith('/bin/'+name))]
            if len(candidates) != 1:
                raise RuntimeError(f'{name}: fixed archive has an unexpected shape')
            content = tar.extractfile(candidates[0]).read()
        destination = cache/name
        if not destination.exists() or destination.read_bytes() != content or not os.access(destination, os.X_OK):
            publish(destination, content, 0o700)
        return destination


if __name__ == '__main__':
    require_lease(ROOT)
    print('step', binary('step'), flush=True)


def nano_identity():
    from t2_processes import subprocess
    effective = json.loads(subprocess.check_output(
        ['go','env','-json','GOOS','GOARCH','GOAMD64','GOARM','GOARM64','GOVERSION','GOROOT','GOTOOLCHAIN','CGO_ENABLED','CC','CXX','CGO_CFLAGS','CGO_CPPFLAGS','CGO_CXXFLAGS','CGO_LDFLAGS','GOFLAGS','GOEXPERIMENT'],text=True,env={**os.environ,'GOWORK':'off'}))
    return dict(source=LOCK['nanomdm']['sourceArchiveSha256'], toolchain=effective,
                flags=['-mod=readonly','-trimpath','./cmd/nanomdm'])


def nano_binary():
    """Verify source and built artifact; reuse only the exact effective build identity."""
    from t2_processes import subprocess
    item = LOCK['nanomdm']
    cache = Path(os.environ.get('CARGO_TARGET_DIR', ROOT/'target'))/'apple-tools'/item['sourceArchiveSha256']
    identity = nano_identity()
    key = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    output = cache/key
    with publication(output):
        # Different effective builds share only an atomically published, verified archive.
        data = verified_archive(cache/'archive.tar.gz',
            'https://codeload.github.com/micromdm/nanomdm/tar.gz/'+item['revision'],
            item['sourceArchiveSha256'], timeout=60, limit=16*1024*1024)
        destination, manifest = output/'nanomdm', output/'manifest.json'
        try:
            proof = json.loads(manifest.read_text())
            if proof['identity'] == identity and proof['sha256'] == hashlib.sha256(destination.read_bytes()).hexdigest() and os.access(destination, os.X_OK):
                return destination
        except (OSError, ValueError, KeyError, TypeError):
            pass
        with tempfile.TemporaryDirectory(prefix='build-', dir=cache) as temporary:
            with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as tar:
                tar.extractall(temporary, filter='data')
            source, built = Path(temporary)/('nanomdm-'+item['revision']), Path(temporary)/'nanomdm'
            env = {**os.environ, 'GOWORK':'off', 'GOCACHE':str(cache/'go-build'), 'GOMODCACHE':str(cache/'go-mod')}
            subprocess.run(['go','build','-mod=readonly','-trimpath','-o',str(built),'./cmd/nanomdm'],
                           pass_fds=lease_fds(), cwd=source, env=env, check=True, timeout=180)
            check_cancelled()
            content = built.read_bytes()
            proof = dict(identity=identity, sha256=hashlib.sha256(content).hexdigest())
            publish(destination, content, 0o700)
            publish(manifest, json.dumps(proof).encode())
        return destination
