"""Fetch fixed upstream test/operator binaries; verify archive bytes before extracting."""
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import tarfile
import tempfile
import urllib.request

from build_run import lease_fds, require_lease

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
    require_lease(ROOT)
    for name in ['step', 'step-ca']:
        print(name, binary(name), flush=True)


def nano_identity():
    import subprocess
    effective = json.loads(subprocess.check_output(
        ['go','env','-json','GOOS','GOARCH','GOAMD64','GOARM','GOARM64','GOVERSION','GOROOT','GOTOOLCHAIN','CGO_ENABLED','CC','CXX','GOFLAGS','GOEXPERIMENT'],text=True))
    return dict(source=LOCK['nanomdm']['sourceArchiveSha256'], toolchain=effective,
                flags=['-mod=readonly','-trimpath','./cmd/nanomdm'])


def nano_binary():
    """Verify source and built artifact; reuse only the exact effective build identity."""
    import subprocess
    item = LOCK['nanomdm']
    cache = Path(os.environ.get('CARGO_TARGET_DIR', ROOT/'target'))/'apple-tools'/item['sourceArchiveSha256']
    cache.mkdir(parents=True, exist_ok=True)
    identity=nano_identity()
    key=hashlib.sha256(json.dumps(identity,sort_keys=True).encode()).hexdigest()
    output=cache/key
    output.mkdir(exist_ok=True)
    archive=cache/'archive.tar.gz'
    for attempt in range(2):
        data=archive.read_bytes() if archive.exists() else urllib.request.urlopen(
            'https://codeload.github.com/micromdm/nanomdm/tar.gz/'+item['revision'],timeout=60).read(16*1024*1024)
        if hashlib.sha256(data).hexdigest()==item['sourceArchiveSha256']:break
        archive.unlink(missing_ok=True)
    else:raise RuntimeError('NanoMDM oracle source checksum mismatch')
    archive.write_bytes(data)
    destination=output/'nanomdm';manifest=output/'manifest.json'
    try:
        proof=json.loads(manifest.read_text())
        if proof['identity']==identity and proof['sha256']==hashlib.sha256(destination.read_bytes()).hexdigest() and os.access(destination,os.X_OK):
            return destination
    except (OSError,ValueError,KeyError):pass
    with tempfile.TemporaryDirectory(prefix='build-',dir=cache) as temporary:
        with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as tar:tar.extractall(temporary,filter='data')
        source=Path(temporary)/('nanomdm-'+item['revision']);built=Path(temporary)/'nanomdm'
        env={**os.environ,'GOWORK':'off','GOCACHE':str(cache/'go-build'),'GOMODCACHE':str(cache/'go-mod')}
        subprocess.run(['go','build','-mod=readonly','-trimpath','-o',str(built),'./cmd/nanomdm'],
                       pass_fds=lease_fds(),cwd=source,env=env,check=True,timeout=180)
        built.chmod(0o700);built.replace(destination)
        proof=dict(identity=identity,sha256=hashlib.sha256(destination.read_bytes()).hexdigest())
        staged=output/'manifest.tmp';staged.write_text(json.dumps(proof));staged.replace(manifest)
    return destination
