"""Disposable fixed NanoMDM oracle: private loopback/file storage, no product database or hooks."""
from contextlib import contextmanager
import os
from pathlib import Path
import secrets
import subprocess
import time
import urllib.request
import urllib.error
from apple_ca import port
from apple_tools import nano_binary


@contextmanager
def running(root, env):
    root = Path(root)
    binary = nano_binary()
    address = '127.0.0.1:'+str(port())
    api_key = secrets.token_urlsafe(32)
    with (root/'nano.log').open('w') as log:
        process = subprocess.Popen([str(binary),'-listen',address,'-ca',str(root/'step/certs/intermediate_ca.crt'),
                                    '-storage','filekv','-storage-dsn',str(root/'nano-data'),
                                    '-cert-header','X-Fixture-Certificate','-checkin',
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
