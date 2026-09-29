"""Public worker failure invalidates its environment and releases its owned process."""
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import Mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hack'))
from t2_hosts import Host


class HostTests(unittest.TestCase):
    def host(self):
        host = Host.__new__(Host)
        host.processes = Mock()
        host.child = Mock()
        host.log = Mock()
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
