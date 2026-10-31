"""Case-owned Compose device CA provider; only real owners select listening addresses.

ref: smallstep/certificates v0.30.2 examples/docker/docker-compose.yml;
smallstep/certificates v0.30.2 authority/config/config.go.
"""
import json
from pathlib import Path
import re
import ssl
import time
import urllib.request
from urllib.error import URLError
from urllib.parse import urlsplit

from dev_environment import PKI_CA, Environment, ROOT, private, run
import subprocess

class Provider:
    def __init__(self, root, case, *, compose_file=None, providers=None, internal_host=None, owner_root=None):
        if not re.fullmatch(r'[0-9a-f]{20}', case):
            raise ValueError('invalid PKI fixture case identity')
        self.root = Path(root).resolve()
        self.owner = Environment(owner_root or ROOT, group='candidate-pki-'+case, compose_file=compose_file, providers=providers)
        self.internal_host = internal_host or 'ca-'+case
        self.owner.extra = {'MDM_PKI_ROOT':str(self.root), 'MDM_PKI_INTERNAL_HOST':self.internal_host, 'MDM_NETWORK_NAME':self.owner.project+'_default'}
        self.container = None

    def compose(self, *args, **kwargs):
        return self.owner.compose('--profile', 'pki', *args, **kwargs)

    def reset(self):
        self.owner.reset()
        self.container = None

    def start(self):
        self.owner.verify_ownership()
        self.compose('up', '-d', '--no-deps', 'step-ca', timeout=120)
        self.container = self.compose('ps', '-q', 'step-ca', timeout=15)
        if not self.container or '\n' in self.container:
            raise RuntimeError('fixed step-ca container missing during startup')
        actual = json.loads(run(['docker','inspect',self.container],capture_output=True,timeout=10).stdout)[0]
        expected = run(['docker','image','inspect',self.owner.providers['step-ca'],'--format','{{.Id}}'],capture_output=True,timeout=10).stdout.strip()
        if actual['Image'] != expected:
            raise RuntimeError('CA container image differs from fixed provider')
        address = self.compose('port', 'step-ca', str(PKI_CA['port']), timeout=15)
        parsed = urlsplit('https://'+address)
        if parsed.hostname != '127.0.0.1' or not parsed.port or address != f'127.0.0.1:{parsed.port}':
            raise RuntimeError('fixed step-ca omitted a unique loopback mapping')
        return f'https://localhost:{parsed.port}'

    def fence(self):
        """Remove the old writer before any replacement can open the same CA database."""
        self.owner.verify_ownership()
        self.compose('rm','--stop','--force','--volumes','step-ca',timeout=30)
        if self.compose('ps','--all','--quiet','step-ca',timeout=10):
            raise RuntimeError('CA writer isolation was not confirmed')
        self.container=None

    def backup(self, destination):
        """A stopped, isolated CA snapshot; MDM/Audit backup coordination stays with deployment."""
        import hashlib, shutil, tempfile
        destination=Path(destination).absolute()
        if destination.exists() or destination.is_relative_to(self.root):
            raise RuntimeError('CA backup must use a new independent directory')
        self.fence()
        destination.parent.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='.ca-backup-',dir=destination.parent) as temporary:
            staged=Path(temporary)/'snapshot';staged.mkdir(mode=0o700)
            if any(path.is_symlink() for path in self.root.rglob('*')):
                raise RuntimeError('CA backup source cannot contain symbolic links')
            shutil.copytree(self.root,staged/'online')
            offline=self.root.parent/(self.root.name+'-offline')
            if not offline.is_dir():raise RuntimeError('offline root backup inputs are missing')
            if any(path.is_symlink() for path in offline.rglob('*')):
                raise RuntimeError('offline root backup cannot contain symbolic links')
            shutil.copytree(offline,staged/'offline')
            files={str(path.relative_to(staged)):hashlib.sha256(path.read_bytes()).hexdigest()
                   for path in staged.rglob('*') if path.is_file()}
            if any(path.is_symlink() for path in staged.rglob('*')):
                raise RuntimeError('CA snapshot cannot contain symbolic links')
            private(staged/'manifest.json',dict(version=1,root=str(self.root),files=files))
            staged.rename(destination)
        return destination

    def restore(self, snapshot):
        """Restore original bytes under the same identity; never initialize replacement keys/CA."""
        import hashlib, shutil
        snapshot=Path(snapshot).resolve()
        manifest=json.loads((snapshot/'manifest.json').read_text())
        if manifest.get('version')!=1 or manifest.get('root')!=str(self.root):
            raise RuntimeError('CA restore storage identity mismatch')
        if any(path.is_symlink() for path in snapshot.rglob('*')):
            raise RuntimeError('CA restore snapshot cannot contain symbolic links')
        actual={str(path.relative_to(snapshot)):hashlib.sha256(path.read_bytes()).hexdigest()
                for directory in ('online','offline') for path in (snapshot/directory).rglob('*') if path.is_file()}
        if actual!=manifest['files'] or any(path.is_symlink() for path in snapshot.rglob('*')):
            raise RuntimeError('CA restore snapshot integrity rejected')
        self.fence()
        for name,target in [('online',self.root),('offline',self.root.parent/(self.root.name+'-offline'))]:
            source=snapshot/name
            if target.exists():
                for path in sorted(target.rglob('*'),reverse=True):
                    if path.is_symlink():raise RuntimeError('CA restore target cannot contain symbolic links')
                    if path.is_file() and not (source/path.relative_to(target)).exists():path.unlink()
            shutil.copytree(source,target,dirs_exist_ok=True)
        config=json.loads((self.root/'step/config/ca.json').read_text())
        if (self.root/'step/secrets/root_ca_key').exists():
            raise RuntimeError('offline root key entered online CA storage')
        origin=self.start();self.wait(origin,'/health',Path(config['root'][0]))
        return origin

    def check(self):

        info = json.loads(run(['docker','inspect',self.container], capture_output=True, timeout=10).stdout)[0]
        if not info['State']['Running']:
            raise RuntimeError('fixed step-ca exited')

    def wait(self, origin, path, ca_root):
        context = ssl.create_default_context(cafile=ca_root)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
        deadline = time.monotonic()+30
        while True:
            self.check()
            try:
                with opener.open(origin+path, timeout=1) as response:
                    if response.status == 200:
                        return
            except ssl.SSLCertVerificationError as error:
                raise RuntimeError('fixed step-ca TLS trust verification failed') from error
            except URLError as error:
                if isinstance(error.reason, ssl.SSLCertVerificationError):
                    raise RuntimeError('fixed step-ca TLS trust verification failed') from error
            except OSError:
                pass
            if time.monotonic() >= deadline:
                raise RuntimeError('fixed step-ca TLS readiness deadline')
            time.sleep(.1)

    def logs(self):
        return self.compose('logs', '--no-color', 'step-ca', timeout=15)
