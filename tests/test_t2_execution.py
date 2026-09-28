"""The same discovered binary and exact identity must produce the result."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hack'))
from t2_execution import Builds, Case, Processes, file_stamp, parse_listing, validate_ownership, verify_case, strict_json
from t2_registry import MODULES, Module


class ExecutionProof(unittest.TestCase):
    def listing(self):
        return {'rust-suites': {'resource::behavior': {
            'package-name': 'rss-mdm-resource-postgres', 'kind': 'test',
            'binary-id': 'resource::behavior', 'binary-name': 'behavior',
            'binary-path': '/target/behavior', 'status': 'listed',
            'testcases': {'new_name': {'ignored': True, 'filter-match': {'status': 'matches'}}},
        }}}

    def test_discovery_uses_current_names_and_exact_target(self):
        module = MODULES['resource.persistence']
        cases = parse_listing(self.listing(), module)
        self.assertEqual([case.name for case in cases], ['new_name'])
        self.assertIn('rss-mdm-resource-postgres', cases[0].id)
        self.assertIn('integration', cases[0].id)
        bad = self.listing()
        bad['rust-suites']['resource::behavior']['package-name'] = 'other'
        with self.assertRaises(RuntimeError):
            parse_listing(bad, module)

    def test_empty_discovery_and_duplicate_json_are_rejected(self):
        with self.assertRaises(RuntimeError):
            parse_listing({'rust-suites': {}}, MODULES['resource.persistence'])
        with self.assertRaises(ValueError):
            strict_json('{"testcases":{"x":{},"x":{}}}')

    def test_unowned_and_multiply_owned_tests_fail_discovery(self):
        module = MODULES['resource.persistence']
        validate_ownership(self.listing(), module.build, [module])
        for owners in ([], [module, Module('duplicate', module.build, ('',))]):
            with self.subTest(owners=owners), self.assertRaisesRegex(RuntimeError, 'exactly one'):
                validate_ownership(self.listing(), module.build, owners)

    def test_support_children_are_discovered_only_by_their_fixture(self):
        module = MODULES['resource.persistence']
        document = self.listing()
        document['rust-suites']['resource::behavior']['testcases'] = {
            'test_support::child': {'ignored': True, 'filter-match': {'status': 'matches'}}}
        validate_ownership(document, module.build, [])
        with self.assertRaisesRegex(RuntimeError, 'empty'):
            parse_listing(document, module)
        self.assertEqual(parse_listing(document, module, include_support=True)[0].name,
                         'test_support::child')

    def test_replaced_binary_cannot_run_against_old_discovery(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / 'test'
            executable.write_text('first')
            builds = Builds.__new__(Builds)
            build = MODULES['resource.persistence'].build
            builds.stamps = {build: (executable, file_stamp(executable))}
            builds.verify_binary(build)
            executable.write_text('second')
            with self.assertRaisesRegex(RuntimeError, 'changed'):
                builds.verify_binary(build)

    def test_exit_code_identity_count_and_terminal_status_are_all_required(self):
        case = parse_listing(self.listing(), MODULES['resource.persistence'])[0]
        good = '<testsuites tests="1"><testsuite tests="1" failures="0" errors="0"><testcase classname="resource::behavior" name="new_name"/></testsuite></testsuites>'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'result.xml'
            path.write_text(good)
            verify_case(path, case, 0)
            with self.assertRaises(RuntimeError):
                verify_case(path, case, 1)
            bad = [good.replace('new_name', 'unrelated'),
                   good.replace('tests="1"', 'tests="0"'),
                   good.replace('name="new_name"/>', 'name="new_name"><skipped/></testcase>'),
                   good.replace('name="new_name"/>', 'name="new_name"><failure/></testcase>'),
                   good.replace('</testsuite>', '<testcase classname="resource::behavior" name="new_name"/></testsuite>')]
            for report in bad:
                with self.subTest(report=report):
                    path.write_text(report)
                    with self.assertRaises(RuntimeError):
                        verify_case(path, case, 0)

    def test_rust_executor_enforces_and_records_a_bounded_case(self):
        from unittest.mock import Mock, patch
        import tomllib
        import t2_execution
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            builds = Builds.__new__(Builds)
            builds.verify_binary = Mock()
            builds.reuse = Mock(return_value=[])
            builds.processes = Mock()
            builds.processes.run.return_value.returncode = 0
            case = parse_listing(self.listing(), MODULES['resource.persistence'])[0]
            with patch.object(t2_execution, 'verify_case'):
                builds.execute(case, {}, output)
            config = tomllib.loads((output/'nextest.toml').read_text())
            self.assertEqual(config['profile']['default']['slow-timeout'],
                             {'period':'600s','terminate-after':1})
            self.assertEqual(builds.processes.run.call_args.kwargs['timeout'], 615)

    def test_python_executor_logs_success_and_kills_hung_scenarios(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        import os
        import t2_execution
        with tempfile.TemporaryDirectory() as directory, patch('t2_execution.lease_fds', return_value=()):
            root = Path(directory)
            (root/'hack').mkdir()
            script = root/'hack/t2_python.py'
            builds = Builds.__new__(Builds)
            builds.processes = Processes()
            fixture = SimpleNamespace(root=root, database=None, migration_config=None,
                                      binary=None, env=dict(os.environ))
            script.write_text('print("PASS python/gateway.admission", flush=True)')
            with patch.object(t2_execution, 'ROOT', root):
                builds.execute_python(MODULES['gateway.admission'], fixture, root)
            self.assertIn('PASS python/gateway.admission',(root/'test.log').read_text())
            marker = root/'pid'
            script.write_text('import os,time; from pathlib import Path; Path(' + repr(str(marker)) + ').write_text(str(os.getpid())); time.sleep(30)')
            with patch.object(t2_execution, 'ROOT', root), patch.object(t2_execution, 'CASE_TIMEOUT', .3):
                with self.assertRaisesRegex(RuntimeError,'deadline'):
                    builds.execute_python(MODULES['gateway.admission'], fixture, root)
            self.assertFalse(builds.processes.children)
            with self.assertRaises(ProcessLookupError):
                os.kill(int(marker.read_text()), 0)


class ProcessOwnership(unittest.TestCase):
    def test_fixture_stdin_protocol_and_persistent_children_share_cancellation(self):
        from unittest.mock import patch
        from t2_processes import owned_by, subprocess as fixture_process
        with patch('t2_execution.lease_fds', return_value=()):
            processes = Processes()
            with owned_by(processes):
                result = fixture_process.run([sys.executable, '-c',
                    'import sys; print(sys.stdin.read().upper())'],
                    input='fixture', capture_output=True, text=True, check=True, timeout=3)
                self.assertEqual(result.stdout.strip(), 'FIXTURE')
                with fixture_process.Popen([sys.executable, '-c',
                        'import time; print("ready", flush=True); time.sleep(30)'],
                        stdout=fixture_process.PIPE, text=True) as child:
                    self.assertEqual(child.stdout.readline().strip(), 'ready')
                    self.assertEqual(len(processes.children), 1)
                    processes.cancel()
                    self.assertNotEqual(child.wait(timeout=3), 0)
                self.assertFalse(processes.children)
                with self.assertRaisesRegex(RuntimeError, 'cancelled'):
                    fixture_process.run([sys.executable, '-c', 'pass'])
                with processes.cleanup():
                    fixture_process.run([sys.executable, '-c', 'pass'], check=True)
                self.assertFalse(processes.children)

    def test_build_protocol_stdout_is_separate_from_diagnostics(self):
        from unittest.mock import patch
        with patch('t2_execution.lease_fds', return_value=()):
            processes = Processes()
            result = processes.run([sys.executable, '-c',
                'import sys; print("{}", flush=True); print("diagnostic", file=sys.stderr)'],
                capture=True, separate_stderr=True)
            self.assertEqual(strict_json(result.stdout), {})
            self.assertEqual(result.stderr.strip(), 'diagnostic')
            self.assertFalse(processes.children)

    def test_deadline_terminates_and_reaps_the_owned_process(self):
        import os
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory, patch('t2_execution.lease_fds', return_value=()):
            marker = Path(directory) / 'pid'
            code = 'import os,time; from pathlib import Path; Path(' + repr(str(marker)) + ').write_text(str(os.getpid())); time.sleep(30)'
            processes = Processes()
            with self.assertRaisesRegex(RuntimeError, 'deadline'):
                processes.run([sys.executable, '-c', code], capture=True, timeout=.3)
            self.assertFalse(processes.children)
            with self.assertRaises(ProcessLookupError):
                os.kill(int(marker.read_text()), 0)
            processes.cancel()
            with self.assertRaisesRegex(RuntimeError, 'cancelled'):
                processes.run([sys.executable, '-c', 'raise SystemExit(0)'])


if __name__ == '__main__':
    unittest.main()
