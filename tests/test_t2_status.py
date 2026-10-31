"""Discovery, selection and execution receipts must not turn absent proofs green."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hack'))
import ci_impact
import t2
from t2_environment import profiles
from t2_registry import MODULES, PACKAGE, affected, discover


def listing(cases):
    return {'rust-suites': {'app': dict(**{'package-name': PACKAGE, 'binary-name': 'rss_mdm_app'},
                                      status='listed', testcases=cases)}}


class T2Status(unittest.TestCase):
    def test_discovery_owns_names_and_rejects_missing_unowned_and_nonignored(self):
        module = 'foundation.tenants'
        name = MODULES[module]['prefix'] + 'current_behavior'
        self.assertEqual(discover(listing({name: {'ignored': True}}), [module]), {module: [name]})
        for cases in ({}, {'unowned': {'ignored': True}}, {name: {'ignored': False}}):
            with self.assertRaises(RuntimeError):
                discover(listing(cases), [module])
        # Ordinary T1 may coexist, and unrelated active T2 is not executed.
        self.assertEqual(discover(listing({'unit': {'ignored': False}, name: {'ignored': True}}), []), {})

    def test_input_selection_is_direct_and_t1_does_not_expand(self):
        self.assertEqual(affected(['apps/server/tests/foundation/tenants.rs']), ['foundation.tenants'])
        self.assertEqual(affected(['apps/server/tests/identity/unit.rs']), [])
        self.assertEqual(affected(['Cargo.toml']), [])
        self.assertEqual(affected(['apps/server/tests/foundation/support.rs']), sorted(MODULES))
        self.assertEqual(profiles(['foundation.tenants', 'foundation.authorization']), ['shared', 'transaction'])
        decision = ci_impact.selected([], t2=['foundation.tenants'])
        self.assertEqual(decision['t2']['modules'], ['foundation.tenants'])
        decision['t2']['modules'] = ['unknown']
        with self.assertRaises(ci_impact.SelectionError):
            ci_impact.validate_selection(decision, [], [])

    def test_report_rejects_zero_missing_duplicate_failed_and_skipped(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / 'junit.xml'
            for body in ('', '<testcase name="other"/>',
                         '<testcase name="case"/><testcase name="case"/>',
                         '<testcase name="case"><failure/></testcase>',
                         '<testcase name="case"><skipped/></testcase>'):
                report.write_text('<testsuites><testsuite>' + body + '</testsuite></testsuites>')
                with self.assertRaises(RuntimeError):
                    t2.verify_report(report, ['case'])
            report.write_text('<testsuites><testsuite><testcase name="case"/></testsuite></testsuites>')
            self.assertEqual(t2.verify_report(report, ['case']), 1)

    def test_invalid_arguments_remove_old_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / 'artifacts/local-t2'
            output.mkdir(parents=True)
            receipt = output / 'result.json'
            receipt.write_text('{"status":"passed"}')
            with (patch.object(t2, 'ROOT', root), patch.object(t2, 'require_lease'),
                  contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit)):
                t2.main(['--module', 'unknown'])
            self.assertFalse(receipt.exists())

    def test_legal_empty_selection_is_skipped_and_failed_discovery_revokes_success(self):
        import ci
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            (output / 'result.json').write_text('{"status":"passed"}')
            with (patch.object(t2, 'require_lease'), patch.object(ci, 'working_source_state', return_value='state'),
                  patch.object(t2.subprocess, 'check_output', return_value='head'),
                  patch.object(t2.subprocess, 'run', side_effect=RuntimeError('build unavailable'))):
                result = t2.run_modules([], output)
                self.assertEqual((result['status'], result['reason']), ('skipped', 'no-modules-selected'))
                with self.assertRaisesRegex(RuntimeError, 'build unavailable'):
                    t2.run_modules(['foundation.tenants'], output)
            receipt = json.loads((output / 'result.json').read_text())
            self.assertEqual(receipt['status'], 'failed')
            self.assertEqual(receipt['executedCases'], 0)
