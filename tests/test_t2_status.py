"""Discovery, selection and execution receipts must not turn absent proofs green."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import subprocess
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
        self.assertEqual(affected(['hack/task_trust_materials.py']), ['agent.delivery', 'apple.protocol', 'task_trust', 'windows.protocol'])
        self.assertEqual(affected(['apps/server/tests/support/authority.rs']), sorted(MODULES))
        self.assertEqual(profiles(['foundation.tenants', 'foundation.authorization']), ['shared', 'transaction'])
        decision = ci_impact.selected([], t2=['foundation.tenants'])
        self.assertEqual(decision['t2']['modules'], ['foundation.tenants'])
        decision['t2']['modules'] = ['unknown']
        with self.assertRaises(ci_impact.SelectionError):
            ci_impact.validate_selection(decision, [], [])

    def test_channel_sql_and_signature_retirement_select_real_consumers(self):
        for schema in ('install.sql', 'relations.sql'):
            with self.subTest(schema=schema):
                self.assertEqual(affected(['crates/execution-service/schema/' + schema]),
                                 ['agent.delivery', 'apple.protocol', 'policy.configuration', 'windows.protocol'])
                self.assertEqual(affected(['crates/agent-channel/schema/' + schema]),
                                 ['agent.delivery', 'task_trust'])
        self.assertEqual(affected(['crates/execution-service/README.md']), [])
        for path in ('apps/server/src/runtime_diagnostics.rs',
                     'crates/policy-service/src/worker/health.rs',
                     'crates/policy-service/src/worker/completion.rs',
                     'crates/policy-service/src/configuration/source_changes.rs',
                     'crates/policy-service/schema/configuration-source-changes.sql'):
            with self.subTest(path=path):
                self.assertIn('foundation.lifecycle', affected([path]))

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

    def test_old_junit_cannot_substitute_for_missing_current_report(self):
        import ci
        import t2_environment
        module = 'foundation.tenants'
        name = MODULES[module]['prefix'] + 'proof'
        @contextlib.contextmanager
        def prepared(*args):
            yield {}
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            (output / '.config').mkdir()
            (output / '.config/nextest.toml').write_text('[profile.t2.junit]\npath="foundation.xml"\n')
            (output / 'junit.xml').write_text('<testsuites><testsuite><testcase name="' + name + '"/></testsuite></testsuites>')
            def run(args, **kwargs):
                if args[1:3] == ['nextest', 'list']:
                    body = json.dumps(listing({name: {'ignored': True}}))
                elif args[1] == 'metadata':
                    body = json.dumps({'target_directory': temporary})
                elif args[1] == 'build':
                    body = json.dumps({'reason': 'compiler-artifact', 'executable': '/unused',
                                       'target': {'name': 'rss-mdm'}})
                else:
                    body = ''  # Successful exit, but no fresh JUnit from nextest.
                return subprocess.CompletedProcess(args, 0, body, '')
            with (patch.object(t2, 'ROOT', output), patch.object(t2, 'require_lease'), patch.object(ci, 'working_source_state', return_value='new-source'),
                  patch.object(t2_environment, 'prepared', prepared),
                  patch.object(t2.subprocess, 'check_output', return_value='head'),
                  patch.object(t2.subprocess, 'run', side_effect=run)):
                with self.assertRaisesRegex(RuntimeError, 'did not publish'):
                    t2.run_modules([module], output)
            evidence = json.loads((output / 'result.json').read_text())
            self.assertEqual(evidence['status'], 'failed')
            self.assertFalse((output / 'junit.xml').exists())

    def test_real_shutdown_inputs_select_the_existing_lifecycle_proof(self):
        from ci_registry import ROOT
        for path, expected in (
            ('apps/server/src/owner_storage.rs', ['foundation.lifecycle']),
            ('apps/server/src/worker_wake.rs', ['foundation.lifecycle']),
            ('apps/server/src/scheduler.rs', ['foundation.lifecycle']),
            ('apps/server/src/scope_group_changes.rs', ['foundation.lifecycle']),
            ('apps/server/src/clock.rs', []),
        ):
            with self.subTest(path=path), \
                 patch.object(ci_impact, 'changed_paths', return_value=[ci_impact.Change('M', path, path)]), \
                 patch.object(ci_impact, 'baseline_tree', return_value=contextlib.nullcontext(ROOT)):
                # Keep real registry, Cargo ownership and public selection. Only the
                # Git input list is supplied, so missing input mappings fail this test.
                decision = ci_impact.select(ROOT, 'current-working-input')
                self.assertEqual(decision['t2']['modules'], expected)
