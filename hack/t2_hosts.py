"""Explicit product HTTP scenarios own their real serve process."""
import json
from pathlib import Path
import threading
import time
import urllib.request
import urllib.error
from urllib.parse import urlsplit
from t2_environment import private
from t2_model import ROOT
from verification_result import require


def management_config(path):
    config = json.loads(Path(path).read_text())
    config.update(listen='127.0.0.1:0', native_protocols={}, agent_pki={'mode': 'disabled'}, device_pki=[])
    return config



class Host:
    def __init__(self, builds, config_path, output, *, require_ready=True, ready_timeout=30):
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
        config = management_config(config_path)
        self.address = None
        path = private(Path(config_path).with_name('host.json'), config)
        try:
            receipt_path = output / 'listener.jsonl'
            with receipt_path.open('w') as receipt:
                self.child = self.processes.spawn([builds.executables['rss-mdm'], 'serve', '--config', path],
                                                   cwd=ROOT, stdout=receipt, stderr=self.log)
            end = time.monotonic() + ready_timeout
            health = 'no health response'
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
                except urllib.error.HTTPError as error:
                    health = error.read(4096).decode('utf-8', errors='replace')
                    error.close()
                except OSError:
                    pass
                require(time.monotonic() < end, f'public T2 host readiness deadline: {health}; see {self.log_path}')
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
                self.record_failure(code)
            return

    def record_failure(self, code):
        if self.failed.is_set():
            return
        self.failed.set()
        try:
            private(self.log_path.with_name('failure.json'),
                    dict(event='unexpected-host-exit', exitCode=code, log='host.log'))
        except OSError:
            print('T2 host failure record unavailable: ' + str(self.log_path), flush=True)

    def check(self):
        with self.state_lock:
            code = self.child.poll()
            if code is not None and not self.stopping.is_set():
                self.record_failure(code)
            if self.failed.is_set() or code is not None:
                error = RuntimeError(f'public T2 host died; this environment cannot be reused; see {self.log_path}')
                error.root_cause = str(self.log_path.with_name('failure.json'))
                raise error

    def close(self):
        with self.state_lock:
            if self.closed:
                return
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
                self.closed = True
            finally:
                self.log.close()
