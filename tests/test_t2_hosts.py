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
        host.state_lock = threading.Lock()
        host.closed = False
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

    def test_diagnostic_failure_preserves_cleanup_and_close_is_idempotent(self):
        from unittest.mock import patch
        host = self.host()
        host.failed.set()
        with patch.object(Path, 'read_text', side_effect=OSError('unreadable')):
            host.close()
            host.close()
        host.processes.release.assert_called_once_with(host.child)
        host.log.close.assert_called_once()

    def test_unexpected_exit_retains_first_failure_record(self):
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            host = self.host()
            host.log_path = Path(tmp) / 'host.log'
            host.child.poll.return_value = 7
            host.monitor()
            record = json.loads(host.log_path.with_name('failure.json').read_text())
            self.assertEqual(record, dict(event='unexpected-host-exit', exitCode=7, log='host.log'))
            host.processes.cancel.assert_called_once()

    def test_close_wins_monitor_race_without_reporting_failure(self):
        from unittest.mock import patch
        host = self.host()
        passed_wait = threading.Event()
        def wait(_):
            passed_wait.set()
            return False
        host.state_lock.acquire()
        monitor = threading.Thread(target=host.monitor)
        try:
            with patch.object(host.stopping, 'wait', side_effect=wait):
                monitor.start()
                self.assertTrue(passed_wait.wait(2))
                host.stopping.set()
                host.state_lock.release()
                monitor.join(2)
        finally:
            if host.state_lock.locked():
                host.state_lock.release()
            monitor.join(2)
        self.assertFalse(monitor.is_alive())
        host.child.poll.assert_not_called()
        host.processes.cancel.assert_not_called()

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
