"""Check the manual gate without running any capacity workload."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'hack' / f'{name}.py')
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class ManualCapacity(unittest.TestCase):
    def test_missing_authorization_rejects_before_side_effects(self):
        capacity = module('capacity')
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary) / 'must-not-exist'
            with patch.object(capacity, 'OUT', out), patch.object(capacity, 'hardware') as hardware, patch.object(capacity, 'measure') as measure, patch('sys.argv', ['capacity.py', '--case', 'static']), contextlib.redirect_stderr(io.StringIO()) as error:
                with self.assertRaises(SystemExit) as result:
                    capacity.main()
            self.assertEqual(result.exception.code, 2)
            self.assertIn('explicit human authorization', error.getvalue())
            self.assertFalse(out.exists())
            hardware.assert_not_called()
            measure.assert_not_called()

    def test_full_ci_plan_excludes_capacity_and_preserves_manual_evidence(self):
        ci = module('ci')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            out = root / 'local-ci'
            evidence = root / 'capacity' / 'result.json'
            evidence.parent.mkdir()
            evidence.write_text('manual evidence')
            with patch.object(ci, 'OUT', out), patch.object(ci, 'select_impact', return_value={'full': True, 'packages': []}), patch.dict('os.environ', {'CI_PLAN': '1'}), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(ci.main(), 0)
                plan = json.loads((out / 'plan.json').read_text())
                self.assertNotIn('capacity', plan['gates'])
                self.assertNotIn('hack/capacity.py', json.dumps(plan))
                ci.clear_execution_evidence(plan['gates'])
            self.assertEqual(evidence.read_text(), 'manual evidence')
