"""Shared fixture tool publication preserves files and honors cancellation."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hack'))
import fixture_tools as tools


class FixtureToolPublication(unittest.TestCase):
    def test_atomic_replace_failure_only_removes_own_stage(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            final, foreign = root/'manifest.json', root/'.other-stage'
            final.write_bytes(b'previous')
            foreign.write_bytes(b'another caller')
            with patch.object(Path, 'replace', side_effect=OSError('publication failed')):
                with self.assertRaisesRegex(OSError, 'publication failed'):
                    tools.publish(final, b'new')
            self.assertEqual(final.read_bytes(), b'previous')
            self.assertEqual(foreign.read_bytes(), b'another caller')
            self.assertEqual(set(root.iterdir()), {final, foreign})

    def test_waiting_publisher_honors_run_cancellation(self):
        import concurrent.futures
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with tools.publication(root):
                with patch.object(tools, 'check_cancelled', side_effect=RuntimeError('T2 cancelled')):
                    with concurrent.futures.ThreadPoolExecutor(1) as pool:
                        with self.assertRaisesRegex(RuntimeError, 'T2 cancelled'):
                            pool.submit(self.take, root).result(5)
            with tools.publication(root):
                pass

    @staticmethod
    def take(root):
        with tools.publication(root):
            pass
