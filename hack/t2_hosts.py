"""The run owns ordinary workers through the existing product serve entry point."""
import json
from pathlib import Path
import threading
import time
import urllib.request
from urllib.parse import urlsplit
from t2_environment import private
from t2_registry import ROOT
from verification_result import require


class Host:
    def __init__(self, builds, config_path, output):
        self.processes = builds.processes
        self.stopping = threading.Event()
        self.failed = threading.Event()
        self.thread = None
        self.child = None
        output.mkdir(parents=True, exist_ok=True)
        self.log_path = output / 'host.log'
        self.log = self.log_path.open('w')
        config = json.loads(Path(config_path).read_text())
        self.address = None
        config.update(listen='127.0.0.1:0', native_protocols={})
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
                    request = urllib.request.Request('http://' + self.address + '/readyz',
                                                     headers={'Host': urlsplit(config['product_origin']).netloc})
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
            raise

    def monitor(self):
        while not self.stopping.wait(.2):
            if self.child.poll() is not None:
                self.failed.set()
                self.processes.cancel()
                return

    def check(self):
        require(not self.failed.is_set() and self.child.poll() is None,
                f'public T2 host died; this run cannot reuse its environment; see {self.log_path}')

    def close(self):
        self.stopping.set()
        if self.thread is not None:
            self.thread.join()
        if self.child is not None:
            self.processes.release(self.child)
        self.log.close()
