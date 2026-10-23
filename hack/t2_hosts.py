"""The run owns ordinary workers through the existing product serve entry point."""
import json
import hashlib
from pathlib import Path
import threading
import time
import urllib.request
from urllib.parse import urlsplit
from t2_environment import private
from t2_model import ROOT
from verification_result import require


def worker_config(path):
    config = json.loads(Path(path).read_text())
    config.update(listen='127.0.0.1:0', native_protocols={}, agent_pki={'mode': 'disabled'}, device_pki=[])
    return config


def compatibility(path):
    def material(value, key=''):
        if isinstance(value, dict):
            return {k: material(v, k) for k, v in value.items()}
        if isinstance(value, list):
            return [material(v) for v in value]
        if key.endswith('_file') and isinstance(value, str):
            return hashlib.sha256(Path(value).read_bytes()).hexdigest()
        return value
    return hashlib.sha256(json.dumps(material(worker_config(path)), sort_keys=True).encode()).hexdigest()


class Host:
    def __init__(self, builds, config_path, output, *, require_ready=True):
        self.processes = builds.processes
        self.stopping = threading.Event()
        self.failed = threading.Event()
        self.state_lock = threading.Lock()
        self.closed = False
        self.thread = None
        self.child = None
        output.mkdir(parents=True, exist_ok=True)
        self.log_path = output / 'host.log'
        self.log = self.log_path.open('w')
        config = worker_config(config_path)
        self.address = None
        path = private(Path(config_path).with_name('host.json'), config)
        try:
            receipt_path = output / 'listener.jsonl'
            with receipt_path.open('w') as receipt:
                self.child = self.processes.spawn([builds.executables['rss-mdm'], 'serve', '--config', path],
                                                   cwd=ROOT, stdout=receipt, stderr=self.log)
            end = time.monotonic() + 30
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            while True:
                self.processes.check()
                require(self.child.poll() is None, f'public T2 host exited during startup; see {self.log_path}')
                if self.address is None:
                    value = receipt_path.read_text()
                    if value.endswith('\n'):
                        receipt = json.loads(value)
                        address = urlsplit('http://' + receipt['address'])
                        require(receipt['event'] == 'listener-bound' and address.hostname == '127.0.0.1'
                                and address.port and address.netloc == receipt['address'], 'invalid T2 listener receipt')
                        self.address = receipt['address']
                try:
                    if self.address is None:
                        raise OSError('listener receipt pending')
                    request = urllib.request.Request('http://' + self.address + ('/readyz' if require_ready else '/livez'),
                                                     headers={'Host': urlsplit(config['product_origin']).netloc, 'X-RSS-Public-Origin': config['product_origin'], 'X-Forwarded-For':'127.0.0.1'})
                    with opener.open(request, timeout=1) as response:
                        if response.status == 200:
                            break
                except OSError:
                    pass
                require(time.monotonic() < end, f'public T2 host readiness deadline; see {self.log_path}')
                self.stopping.wait(.1)
            self.thread = threading.Thread(target=self.monitor, name='t2-host', daemon=True)
            self.thread.start()
        except BaseException:
            self.close()
            # Python scenarios use temporary roots; retain startup diagnostics in test.log.
            self.diagnostics()
            raise

    def diagnostics(self):
        try:
            print(self.log_path.read_text()[-16384:], flush=True)
        except OSError:
            print('T2 host diagnostics unavailable: ' + str(self.log_path), flush=True)

    def monitor(self):
        while not self.stopping.wait(.2):
            with self.state_lock:
                if self.stopping.is_set():
                    return
                code = self.child.poll()
                if code is None:
                    continue
                self.failed.set()
                try:
                    private(self.log_path.with_name('failure.json'),
                            dict(event='unexpected-host-exit', exitCode=code, log='host.log'))
                except OSError:
                    print('T2 host failure record unavailable: ' + str(self.log_path), flush=True)
            self.processes.cancel()
            return

    def check(self):
        require(not self.failed.is_set() and self.child.poll() is None,
                f'public T2 host died; this run cannot reuse its environment; see {self.log_path}')

    def close(self):
        with self.state_lock:
            if self.closed:
                return
            self.closed = True
            self.stopping.set()
        if self.thread is not None:
            self.thread.join()
        try:
            if self.failed.is_set():
                print('Unexpected T2 host exit: ' + str(self.log_path), flush=True)
                self.diagnostics()
        finally:
            try:
                if self.child is not None:
                    self.processes.release(self.child)
            finally:
                self.log.close()
