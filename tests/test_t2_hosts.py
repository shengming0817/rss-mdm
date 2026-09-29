"""Public worker failure invalidates its environment and releases its owned process."""
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import Mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hack'))
from t2_hosts import Host


class HostTests(unittest.TestCase):
    def test_child_owns_ephemeral_port_even_when_competitor_takes_probed_port(self):
        import json
        import socket
        import tempfile
        from types import SimpleNamespace
        from unittest.mock import patch
        from t2_execution import Processes
        with tempfile.TemporaryDirectory() as tmp, socket.socket() as competitor, \
             patch('t2_execution.lease_fds', return_value=()):
            root = Path(tmp)
            script = root / 'serve.py'
            script.write_text('''import http.server, json, sys
config = json.load(open(sys.argv[-1]))
host, port = config['listen'].split(':')
class Ready(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers()
server = http.server.HTTPServer((host, int(port)), Ready)
print(json.dumps({'event':'listener-bound','address': '%s:%s' % server.server_address}), flush=True)
server.serve_forever()
''')
            config = root / 'config.json'
            config.write_text(json.dumps({'product_origin': 'https://mdm.example.test'}))
            processes = Processes()
            spawn = processes.spawn
            def start(args, **kwargs):
                chosen = json.loads(Path(args[-1]).read_text())['listen']
                competitor.bind(('127.0.0.1', int(chosen.rsplit(':', 1)[1])))
                competitor.listen()
                return spawn([sys.executable, script, args[-1]], **kwargs)
            try:
                with patch.object(processes, 'spawn', side_effect=start):
                    host = Host(SimpleNamespace(processes=processes, executables={'rss-mdm':'unused'}), config, root/'output')
                try:
                    self.assertNotEqual(int(host.address.rsplit(':', 1)[1]), competitor.getsockname()[1])
                    with socket.socket() as thief, self.assertRaises(OSError):
                        thief.bind(('127.0.0.1', int(host.address.rsplit(':', 1)[1])))
                finally:
                    host.close()
            finally:
                processes.close()

    def host(self):
        host = Host.__new__(Host)
        host.processes = Mock()
        host.child = Mock()
        host.log = Mock()
        host.log_path = Path('/owned/host.log')
        host.stopping = threading.Event()
        host.failed = threading.Event()
        host.thread = None
        return host

    def test_unexpected_exit_cancels_run(self):
        host = self.host()
        host.child.poll.return_value = 1
        host.monitor()
        self.assertTrue(host.failed.is_set())
        host.processes.cancel.assert_called_once()
        with self.assertRaisesRegex(RuntimeError, 'host died'):
            host.check()

    def test_intentional_close_releases_only_owned_process(self):
        host = self.host()
        host.close()
        host.monitor()
        host.processes.release.assert_called_once_with(host.child)
        host.processes.cancel.assert_not_called()
        host.log.close.assert_called_once()

    def test_readiness_failure_releases_child_and_log(self):
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / 'config.json'
            config.write_text(json.dumps({'native_protocols': {}}))
            builds = Mock()
            builds.executables = {'rss-mdm': '/rss-mdm'}
            builds.processes.spawn.return_value.poll.return_value = 1
            with self.assertRaisesRegex(RuntimeError, 'startup'):
                Host(builds, config, root / 'output')
            builds.processes.release.assert_called_once_with(builds.processes.spawn.return_value)
