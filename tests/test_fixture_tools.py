"""Shared fixture tool publication preserves files."""
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

    @staticmethod
    def take(root):
        with tools.publication(root):
            pass
