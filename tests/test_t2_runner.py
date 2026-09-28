"""Selection, preparation, concurrency and evidence contracts of the public MODULE runner."""
from contextlib import contextmanager, ExitStack, redirect_stdout, redirect_stderr
from io import StringIO
from pathlib import Path
import sys
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
            log = (root / case['log']).read_text()
            self.assertIn('Traceback', log)
            self.assertIn('fixture rejected', log)
            fixture_type.return_value.__exit__.assert_called_once()

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
