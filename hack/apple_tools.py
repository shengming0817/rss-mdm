"""Fetch fixed upstream test/operator binaries; verify archive bytes before extracting."""
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
LOCK = json.loads((ROOT/'fixtures/apple-tools.lock.json').read_text())


def binary(name):
    item = LOCK[name]
    system = platform.system().lower()
    machine = {'aarch64': 'arm64', 'arm64': 'arm64', 'x86_64': 'amd64'}[platform.machine()]
    expected = item['artifacts'][system+'-'+machine]
    cache = Path(os.environ.get('CARGO_TARGET_DIR', ROOT/'target'))/'apple-tools'/expected
    archive = cache/'archive.tar.gz'
    cache.mkdir(parents=True, exist_ok=True)
    if not archive.exists():
        filename = f"{name}_{system}_{item['version']}_{machine}.tar.gz"
        url = f"https://github.com/{item['repository']}/releases/download/v{item['version']}/{filename}"
        data = urllib.request.urlopen(url, timeout=120).read(160*1024*1024)
    else:
        data = archive.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise RuntimeError(f'{name}: fixed artifact checksum mismatch')
    archive.write_bytes(data)
    destination = cache/name
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as tar:
        candidates = [member for member in tar.getmembers() if member.isfile() and (member.name == name or member.name.endswith('/bin/'+name))]
        if len(candidates) != 1:
            raise RuntimeError(f'{name}: fixed archive has an unexpected shape')
        content = tar.extractfile(candidates[0]).read()
    if not destination.exists() or destination.read_bytes() != content:
        destination.write_bytes(content)
        destination.chmod(0o700)
    return destination


if __name__ == '__main__':
    for name in ['step', 'step-ca']:
        print(name, binary(name), flush=True)


def nano_binary():
    """Build only the checksum-verified, unmodified upstream oracle with its go.sum."""
    import subprocess
    item = LOCK['nanomdm']
    cache = Path(os.environ.get('CARGO_TARGET_DIR', ROOT/'target'))/'apple-tools'/item['sourceArchiveSha256']
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache/'archive.tar.gz'
    data = archive.read_bytes() if archive.exists() else urllib.request.urlopen(
        'https://codeload.github.com/micromdm/nanomdm/tar.gz/'+item['revision'],timeout=60).read(16*1024*1024)
    if hashlib.sha256(data).hexdigest() != item['sourceArchiveSha256']:
        raise RuntimeError('NanoMDM oracle source checksum mismatch')
    archive.write_bytes(data)
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as tar:
        tar.extractall(cache,filter='data')
    source = cache/('nanomdm-'+item['revision'])
    destination = cache/'nanomdm'
    subprocess.run(['go','build','-mod=readonly','-trimpath','-o',str(destination),'./cmd/nanomdm'],
                   cwd=source,env={**os.environ,'GOWORK':'off'},check=True,timeout=180)
    return destination
