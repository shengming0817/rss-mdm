"""Disposable fixed NanoMDM oracle: private loopback/file storage, no product database or hooks."""
from contextlib import contextmanager
import os
import base64
import ssl
import json
from pathlib import Path
import secrets
from t2_processes import subprocess
import time
import urllib.request
import urllib.error
import socket
from fixture_tools import nano_binary


def port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


@contextmanager
def running(root, env):
    root = Path(root)
    binary = nano_binary()
    address = '127.0.0.1:'+str(port())
    api_key = secrets.token_urlsafe(32)
    config=json.loads((root/'apple.json').read_text())
    trust=json.loads(Path(config['trust_file']).read_text())
    active=[issuer for issuer in trust['issuers'] if issuer['mode']=='active']
    if trust['purpose']!='apple' or len(active)!=1:
        raise RuntimeError('NanoMDM oracle requires the active Apple issuer')
    issuer_file=root/'nano-issuer.pem'
    issuer_file.write_text(ssl.DER_cert_to_PEM_cert(base64.b64decode(active[0]['certificate'],validate=True)))
    with (root/'nano.log').open('w') as log:
        process = subprocess.Popen([str(binary),'-listen',address,'-ca',str(issuer_file),
                                    '-storage','filekv','-storage-dsn',str(root/'nano-data'),
                                    '-cert-header','X-Fixture-Certificate','-checkin','-ua-zl-dc',
                                    '-push-url','http://127.0.0.1:1'],
                                   env={'PATH':os.environ['PATH'],'NANOMDM_API':api_key},stdout=log,stderr=subprocess.STDOUT)
        try:
            deadline=time.monotonic()+15
            while True:
                if process.poll() is not None:
                    raise RuntimeError('fixed NanoMDM oracle exited')
                try:
                    urllib.request.urlopen('http://'+address+'/version',timeout=1).close()
                    break
                except urllib.error.HTTPError:
                    break
                except OSError:
                    if time.monotonic()>deadline:
                        raise RuntimeError('fixed NanoMDM oracle startup deadline')
                    time.sleep(.1)
            env.update(MDM_NANO_URL='http://'+address,MDM_NANO_API_KEY=api_key)
            print('fixed NanoMDM: isolated protocol oracle ready; no product database or hooks',flush=True)
            yield
        finally:
            process.terminate()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill();process.wait(timeout=5)
