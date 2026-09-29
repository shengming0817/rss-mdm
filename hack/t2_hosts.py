"""The run owns ordinary workers through the existing product serve entry point."""
import json
from pathlib import Path
import socket
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
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            self.address = f'127.0.0.1:{listener.getsockname()[1]}'
        config.update(listen=self.address, native_protocols={})
        path = private(Path(config_path).with_name('host.json'), config)
        try:
            self.child = self.processes.spawn([builds.executables['rss-mdm'], 'serve', '--config', path],
                                               cwd=ROOT, stdout=self.log, stderr=self.log)
            end = time.monotonic() + 30
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            while True:
                self.processes.check()
                require(self.child.poll() is None, 'public T2 host exited during startup; see host.log')
                try:
                    request = urllib.request.Request('http://' + self.address + '/readyz',
                                                     headers={'Host': urlsplit(config['product_origin']).netloc})
                    with opener.open(request, timeout=1) as response:
                        if response.status == 200:
                            break
                except OSError:
                    pass
                require(time.monotonic() < end, 'public T2 host readiness deadline; see host.log')
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
                'public T2 host died; this run cannot reuse its environment')

    def close(self):
        self.stopping.set()
        if self.thread is not None:
            self.thread.join()
        if self.child is not None:
            self.processes.release(self.child)
        self.log.close()
