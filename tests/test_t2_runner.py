"""Selection, preparation, concurrency and evidence contracts of the public MODULE runner."""
from contextlib import contextmanager, ExitStack, redirect_stdout, redirect_stderr
from io import StringIO
from pathlib import Path
import sys
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch, Mock
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hack'))
import t2
import t2_fixtures
from t2_registry import MODULES
from t2_execution import Case


class Selection(unittest.TestCase):
    def test_named_all_and_empty_are_distinct(self):
        self.assertEqual(t2.select_modules('content.http', {}), ['content.http'])
        self.assertEqual(t2.select_modules('all', {}), sorted(MODULES))
        self.assertEqual(t2.select_modules('affected', {'t2Full': False, 'modules': []}), [])
        self.assertEqual(t2.select_modules('affected', {'t2Full': True, 'modules': []}), sorted(MODULES))

    def test_unknown_and_removed_selectors_never_fall_back(self):
        with self.assertRaisesRegex(ValueError, 'available'):
            t2.select_modules('management', {})
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit):
            t2.main(['--suite', 'all'])
        with patch.dict('os.environ', {'SUITE': 'all'}), redirect_stderr(StringIO()), self.assertRaises(SystemExit):
            t2.main(['--module', 'all'])

    def test_unknown_module_lists_both_public_selection_modes(self):
        message = StringIO()
        with redirect_stderr(message), self.assertRaises(SystemExit):
            t2.main(['--module', 'unknown'])
        self.assertIn('available: affected, all, ', message.getvalue())


class Execution(unittest.TestCase):
    @contextmanager
    def harness(self, *, execute=None, discover=None):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            stack.enter_context(patch.object(t2, 'require_lease'))
            stack.enter_context(patch.object(t2.shutil, 'which', return_value='/tool'))
            stack.enter_context(redirect_stdout(StringIO()))
            builds = stack.enter_context(patch.object(t2, 'Builds')).return_value
            builds.elapsed = 0
            builds.discover.side_effect = discover or (lambda module: [
                Case(module.build, module.id, Path('/leased/binary'), module.id + '::case')])
            builds.execute.side_effect = execute
            fixtures_type = stack.enter_context(patch.object(t2_fixtures, 'RunFixtures'))
            fixtures = fixtures_type.return_value.__enter__.return_value
            fixtures.counts = {}
            @contextmanager
            def scenario(module, output):
                yield SimpleNamespace(env={'MODULE_ID': module.id})
            fixtures.scenario.side_effect = scenario
            yield Path(directory), builds, fixtures_type, fixtures

    def test_missing_dependencies_fail_before_build_and_service_start(self):
        with self.harness() as (root, builds, fixture_type, _), patch.object(t2.shutil, 'which', return_value=None):
            with self.assertRaisesRegex(RuntimeError, 'missing dependencies'):
                t2.run_modules(['sources.winget'], root)
            builds.prepare.assert_not_called()
            fixture_type.assert_not_called()

    def test_execution_failure_keeps_callsite_and_cleans_up(self):
        def fail(*unused):
            raise ValueError('fixture rejected')
        with self.harness(execute=fail) as (root, _, fixture_type, _):
            result = t2.run_modules(['sources.winget'], root)['sources.winget']
            self.assertEqual(result['status'], 'failed')
            case = next(iter(result['cases'].values()))
            self.assertEqual(case['reason'], 'ValueError')
            log = (root / case['failureLog']).read_text()
            self.assertIn('Traceback', log)
            self.assertIn('fixture rejected', log)
            fixture_type.return_value.__exit__.assert_called_once()

    def test_rust_and_python_failures_link_output_and_traceback(self):
        def fail(*args):
            (args[-1]/'test.log').write_text('actual failing process output')
            raise RuntimeError('process exited nonzero')
        for module in ('agent.registration','gateway.admission'):
            with self.harness(execute=fail) as (root, builds, _, _):
                builds.execute_python.side_effect=fail
                value=t2.run_modules([module],root)[module]
                case=next(iter(value['cases'].values()))
                self.assertIn('actual failing process output',(root/case['log']).read_text())
                self.assertIn('process exited nonzero',(root/case['failureLog']).read_text())

    def test_empty_selection_creates_no_run_directory(self):
        with self.harness() as (root, *_):
            t2.run_modules([],root)
            self.assertEqual(list(root.iterdir()),[])

    def test_real_fixture_failure_keeps_safe_output_for_setup_and_cleanup(self):
        from t2_environment import private, run
        from t2_processes import diagnostic_phase
        for phase in ('setup', 'cleanup'):
            with self.subTest(phase=phase), self.harness() as (root, _, _, fixtures):
                secret = 'fixture-credential-value'
                @contextmanager
                def scenario(module, output):
                    private(output / 'account-password', secret)
                    if phase == 'cleanup':
                        yield SimpleNamespace(env={})
                    with diagnostic_phase(phase):
                        run([sys.executable, '-c',
                             'import sys; print("fixture stdout"); '
                             'print("fixture stderr", file=sys.stderr); raise SystemExit(2)'],
                            capture_output=True, timeout=3)
                    yield SimpleNamespace(env={})
                fixtures.scenario.side_effect = scenario
                value = t2.run_modules(['sources.winget'], root)['sources.winget']
                self.assertEqual(value['status'], 'failed')
                case = next(iter(value['cases'].values()))
                diagnostic = (root / case['fixtureLog']).read_text()
                self.assertIn('fixture stdout', diagnostic)
                self.assertIn('fixture stderr', diagnostic)
                self.assertIn('[' + phase + ']', diagnostic)
                self.assertIn('fixture.log', (root / case['failureLog']).read_text())

    def test_shared_preparation_failure_links_run_diagnostics(self):
        from t2_environment import run
        def prepare(modules):
            run([sys.executable, '-c', 'import sys; print("shared preparation rejected", file=sys.stderr); raise SystemExit(2)'],
                capture_output=True, timeout=3)
        with self.harness() as (root, _, _, fixtures):
            fixtures.prepare.side_effect = prepare
            with self.assertRaises(t2.RunFailure) as caught:
                t2.run_modules(['sources.winget'], root)
            self.assertIn('shared preparation rejected', (root / caught.exception.evidence['fixtureLog']).read_text())

    def test_parallel_fixture_diagnostics_do_not_mix_cases(self):
        from t2_environment import run
        barrier = threading.Barrier(2)
        @contextmanager
        def scenario(module, output):
            barrier.wait(timeout=3)
            run([sys.executable, '-c', 'import sys; print(sys.argv[1]); raise SystemExit(2)', module.id],
                capture_output=True, timeout=3)
            yield SimpleNamespace(env={})
        with self.harness() as (root, _, _, fixtures):
            fixtures.scenario.side_effect = scenario
            names = ['agent.registration', 'agent.reports']
            results = t2.run_modules(names, root, jobs=2)
            for name in names:
                case = next(iter(results[name]['cases'].values()))
                diagnostic = (root / case['fixtureLog']).read_text()
                self.assertIn(name, diagnostic)
                self.assertNotIn(next(other for other in names if other != name), diagnostic)

    def test_fixture_secrets_never_enter_diagnostic_or_traceback(self):
        from t2_environment import private, run
        with self.harness() as (root, _, _, fixtures):
            secret = 'fixture-credential-value'
            @contextmanager
            def scenario(module, output):
                private(output / 'account-password', secret)
                run([sys.executable, '-c',
                     'import sys; print(' + repr(secret) + ', file=sys.stderr); raise SystemExit(2)'],
                    capture_output=True, timeout=3)
                yield SimpleNamespace(env={})
            fixtures.scenario.side_effect = scenario
            value = t2.run_modules(['sources.winget'], root)['sources.winget']
            case = next(iter(value['cases'].values()))
            for key in ('log', 'fixtureLog', 'failureLog'):
                self.assertNotIn(secret, (root / case[key]).read_text())
            self.assertIn('diagnostic-withheld', (root / case['fixtureLog']).read_text())

    def test_owned_fixture_process_preserves_diagnostics_and_reaps_child(self):
        from t2_processes import diagnostics, owned_by, subprocess as fixture_process
        from t2_execution import Processes
        with tempfile.TemporaryDirectory() as directory, patch('t2_execution.lease_fds', return_value=()):
            log = Path(directory) / 'fixture.log'
            processes = Processes()
            try:
                with owned_by(processes), diagnostics(log), self.assertRaises(subprocess.CalledProcessError):
                    fixture_process.run([sys.executable, '-c',
                        'import sys; print("owned setup failure", file=sys.stderr); raise SystemExit(2)'],
                        capture_output=True, text=True, check=True, timeout=3)
                self.assertIn('owned setup failure', log.read_text())
                self.assertFalse(processes.children)
            finally:
                processes.close()

    def test_reused_compose_secrets_are_protected_before_command_logging(self):
        from t2_environment import Environment
        from t2_processes import diagnostics, subprocess as fixture_process
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = Environment(root)
            environment.root.mkdir(parents=True)
            secret = 'previous-run-password'
            (environment.root / 'database-password').write_text(secret)
            log = root / 'fixture.log'
            def fail(*args, **kwargs):
                return fixture_process.run([sys.executable, '-c',
                    'import sys; print(' + repr(secret) + ', file=sys.stderr); raise SystemExit(2)'],
                    capture_output=True, text=True, check=True, timeout=3)
            with diagnostics(log), patch('t2_environment.run', side_effect=fail), \
                 redirect_stderr(StringIO()), self.assertRaises(subprocess.CalledProcessError):
                environment.compose('ps')
            self.assertNotIn(secret, log.read_text())
            self.assertIn('diagnostic-withheld', log.read_text())

    def test_retention_bounds_owned_runs_and_preserves_current_formal_evidence(self):
        import json
        with self.harness() as (root, *_):
            ids=[f'20260928T0100{n:02d}Z-12345678' for n in range(9)]
            for run_id in ids:
                directory=root/run_id;directory.mkdir()
                (directory/'result.json').write_text(json.dumps({'runId':run_id}))
            (root/'result.json').write_text(json.dumps({'modules':{'owner':{'runId':ids[0]}}}))
            unknown=root/'20260928T010059Z-12345678';unknown.mkdir()
            foreign=root/'foreign';foreign.mkdir();(foreign/'proof').write_text('untouched')
            link=root/'20260928T010058Z-12345678';link.symlink_to(foreign,target_is_directory=True)
            result=t2.run_modules(['gateway.admission'],root,listing=True)
            known=[p for p in root.iterdir() if p.is_dir() and not p.is_symlink() and
                   ((p/'run.json').exists() or (p/'result.json').exists())]
            self.assertLessEqual(len(known),5)
            self.assertTrue((root/ids[0]).is_dir())
            self.assertFalse((root/ids[1]).exists())
            self.assertTrue(unknown.is_dir())
            self.assertTrue(link.is_symlink())
            self.assertEqual((foreign/'proof').read_text(),'untouched')

    def test_empty_selection_keeps_old_evidence_and_starts_nothing(self):
        with self.harness() as (root, builds, fixture_type, _):
            old = root / 'previous.log'; old.write_text('old evidence')
            link = root / 'linked.log'; link.symlink_to(old)
            result = t2.run_modules([], root)
            builds.prepare.assert_not_called()
            fixture_type.assert_not_called()
            self.assertEqual(old.read_text(), 'old evidence')
            self.assertTrue(link.is_symlink())
            self.assertTrue(all(value['status'] == 'skipped' for value in result.values()))

    def test_list_and_unknown_case_do_not_prepare_services(self):
        with self.harness() as (root, _, fixture_type, _):
            t2.run_modules(['sources.winget'], root, listing=True)
            fixture_type.assert_not_called()
            with self.assertRaisesRegex(RuntimeError, 'unknown CASE'):
                t2.run_modules(['sources.winget'], root, selected_case='invented')
            fixture_type.assert_not_called()

    def test_discovery_failure_and_duplicate_ownership_stop_before_services(self):
        with self.harness(discover=Mock(side_effect=RuntimeError('empty discovery'))) as (root, _, fixture_type, _):
            with self.assertRaisesRegex(RuntimeError, 'empty discovery'):
                t2.run_modules(['agent.registration'], root)
            fixture_type.assert_not_called()
        case = Case(MODULES['agent.registration'].build, 'app', Path('/leased/app'), 'same')
        with self.harness(discover=lambda _: [case]) as (root, _, fixture_type, _):
            with self.assertRaisesRegex(RuntimeError, 'multiple modules'):
                t2.run_modules(['agent.registration', 'agent.reports'], root)
            fixture_type.assert_not_called()

    def test_jobs_bound_module_concurrency_and_exclusive_phase_waits(self):
        ordinary = ['agent.registration', 'agent.reports']
        for jobs in (1, 2):
            with self.subTest(jobs=jobs):
                lock = threading.Lock()
                barrier = threading.Barrier(2) if jobs == 2 else None
                active, peak, completed = 0, 0, set()
                def execute(case, env, output):
                    nonlocal active, peak
                    module = env['MODULE_ID']
                    with lock:
                        if module == 'identity.local':
                            self.assertEqual(completed, set(ordinary))
                            self.assertEqual(active, 0)
                        active += 1
                        peak = max(peak, active)
                    if module in ordinary and barrier:
                        barrier.wait(timeout=3)
                    time.sleep(.01)
                    with lock:
                        active -= 1
                        completed.add(module)
                with self.harness(execute=execute) as (root, _, _, fixtures):
                    results = t2.run_modules([*ordinary, 'identity.local'], root, jobs=jobs)
                    self.assertTrue(all(results[name]['status'] == 'passed' for name in [*ordinary, 'identity.local']))
                    self.assertEqual(peak, jobs)
                    fixtures.reset.assert_called_once()

    def test_python_scenarios_use_the_owned_logged_executor(self):
        with self.harness() as (root, builds, _, _):
            result = t2.run_modules(['gateway.admission'], root)
            builds.execute_python.assert_called_once()
            case = result['gateway.admission']['cases']['python/gateway.admission']
            self.assertTrue(case['log'].endswith('/test.log'))
            self.assertEqual(case['timeoutSeconds'], 600)

    def test_list_requires_discovery_tools_only_and_preserves_nonselection(self):
        with self.harness() as (root, _, fixture_type, _), patch.object(t2.shutil, 'which',
                side_effect=lambda tool: None if tool in {'docker', 'openssl', 'go'} else '/tool'):
            result = t2.run_modules(['gateway.admission', 'agent.registration'], root, listing=True)
            self.assertEqual(result['gateway.admission']['reason'], 'list-only')
            self.assertEqual(result['content.http']['reason'], 'not-selected')
            fixture_type.assert_not_called()

    def test_preparation_failure_has_direct_run_evidence(self):
        with self.harness(discover=Mock(side_effect=RuntimeError('bad discovery'))) as (root, *_):
            with self.assertRaises(t2.RunFailure) as caught:
                t2.run_modules(['agent.registration'], root)
            evidence = caught.exception.evidence
            self.assertTrue(evidence['runId'])
            self.assertIn('bad discovery', (root / evidence['log']).read_text())


class StableInput(unittest.TestCase):
    def test_hard_interruption_invalidates_only_current_mode_evidence(self):
        import json
        for listing in (False, True):
            with self.subTest(listing=listing), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                output = root / 'artifacts/local-t2'
                output.mkdir(parents=True)
                for name in ('result.json', 'list.json'):
                    (output / name).write_text(json.dumps({'status': 'passed', 'old': True}))
                code = '''
import os, sys
from pathlib import Path
from unittest.mock import patch
import ci, t2
with patch.object(t2, 'ROOT', Path(sys.argv[1])), patch.object(t2, 'require_lease'), patch.object(ci, 'working_source_state', side_effect=lambda: os._exit(73)):
    t2.main(['--module', 'agent.registration', '--list', sys.argv[2]])
'''
                result = subprocess.run([sys.executable, '-c', code, str(root), str(int(listing))],
                                        cwd=Path(t2.__file__).parent, capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 73, result.stderr)
                current, other = ('list.json', 'result.json') if listing else ('result.json', 'list.json')
                self.assertFalse((output / current).exists())
                self.assertTrue(json.loads((output / other).read_text())['old'])

    def test_top_level_failure_preserves_run_id_and_log(self):
        import ci
        import json
        failure = {'runId': 'unique-run', 'status':'failed', 'reason':'RuntimeError', 'log':'unique-run/failure.log'}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(t2, 'ROOT', root), patch.object(t2, 'require_lease'), \
                 patch.object(ci, 'working_source_state', return_value='stable'), \
                 patch.object(t2, 'run_modules', side_effect=t2.RunFailure('discovery', failure)):
                with self.assertRaises(t2.RunFailure):
                    t2.main(['--module', 'agent.registration'])
            result = json.loads((root / 'artifacts/local-t2/result.json').read_text())
            self.assertEqual(result['execution'], failure)

    def test_changed_source_cannot_publish_success(self):
        import ci
        import json
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(t2, 'ROOT', root), patch.object(t2, 'require_lease'), \
                 patch.object(ci, 'working_source_state', side_effect=['before', 'after']), \
                 patch.object(t2, 'run_modules', return_value={'sources.winget': {'status':'passed'}}):
                with self.assertRaisesRegex(RuntimeError, 'source changed'):
                    t2.main(['--module', 'sources.winget'])
            self.assertEqual(json.loads((root / 'artifacts/local-t2/result.json').read_text())['status'], 'failed')


if __name__ == '__main__':
    unittest.main()
