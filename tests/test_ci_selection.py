"""Runner selection, external fixture inputs and failure collection."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('selection_ci', Path(__file__).resolve().parents[1] / 'hack/ci.py')
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)


def result(stdout='', returncode=0):
    return SimpleNamespace(stdout=stdout, returncode=returncode)


class Selection(unittest.TestCase):
    def test_merge_base_and_fallbacks(self):
        cases = [
            ('0', [result('develop'), result()], True, 'develop'),
            ('1', [result('topic'), result()], True, 'explicit-full'),
            ('0', [result('topic'), result(returncode=1)], True, 'selection-unavailable'),
            ('0', [result('topic'), result('base'), result('{"full":false,"packages":[],"reasons":[]}'), result(' M file')], True, 'dirty-input'),
            ('0', [result('topic'), result('base'), result('{"full":false,"packages":["unknown"],"reasons":[]}')], True, 'selection-unavailable'),
            ('0', [result('topic'), result('base'), result('{"full":false,"packages":["rss-mdm-group"],"reasons":["package-change"]}'), result()], False, 'package-change'),
        ]
        for full, outputs, expected, reason in cases:
            with self.subTest(reason=reason), patch.dict(ci.os.environ, {'CI_FULL': full, 'CI_BASE': 'origin/develop'}), patch.object(ci, 'command', side_effect=outputs) as command:
                selected = ci.select_impact('head')
                self.assertEqual(selected['full'], expected)
                self.assertTrue(selected['reasons'][0].startswith(reason))
                if not expected:
                    self.assertEqual(command.call_args_list[1].args[0], ['/usr/bin/git', 'merge-base', 'origin/develop', 'head'])
                    self.assertEqual(command.call_args_list[2].args[0][-4:], ['--base', 'base', '--head', 'head'])

    def test_package_commands_and_external_fixture_inputs(self):
        selection = {'full': False, 'packages': ['rss-mdm-winget-source']}
        args = ['cargo', 'test', '--locked', '--workspace', '--lib']
        self.assertEqual(ci.gate_command('t1', args, selection), ['cargo', 'test', '--locked', '-p', 'rss-mdm-winget-source', '--lib'])
        for name in ['source-t2', 'source-consumers', 'isolation', 'new-gate']:
            self.assertTrue(ci.selected_gate(name, selection), name)
        for name in ['group-t2', 'core-consumers', 'advisories']:
            self.assertFalse(ci.selected_gate(name, selection), name)
        for package in ci.APP_INPUTS:
            for name in ['inventory-consumers', 'backend-consumers', 'backend-t2', 'asset-t2', 'command-t2']:
                self.assertTrue(ci.selected_gate(name, {'full': False, 'packages': [package]}), (package, name))

    def test_docs_skip_rust_and_failure_collection_keeps_running(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            (out / 't1.log').write_text('stale passed')
            stale_paths = [out / name for name in (
                'isolated-build.log', 'metadata-normal.json', 'metadata-integration.json',
                'metadata-normal.stderr.log', 'metadata-integration.stderr.log',
                'tree-normal.txt', 'tree-integration.txt', 'pin.log',
                'core-consumers/result.json', 'inventory-consumers/result.json',
                'backend-consumers/policy/result.json', 'group-postgres-consumers/result.json')]
            source_out = out / 'separate-source-consumers'
            stale_paths.append(source_out / 'result.json')
            for path in stale_paths:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('old-head passed')
            output = io.StringIO()
            calls = []
            def command(args, **kwargs):
                calls.append(args)
                if 'rev-parse' in args: return result('head\n')
                if 'status' in args: return result()
                if '-m' in args: return result('failure', 1)
                return result()
            selection = {'full': False, 'packages': [], 'reasons': ['docs-only']}
            with patch.object(ci, 'OUT', out), patch.object(ci, 'SOURCE_CONSUMER_OUT', source_out, create=True), patch.object(ci, 'select_impact', return_value=selection), patch.object(ci, 'command', side_effect=command), patch.object(ci, 'isolate') as isolation, patch.object(ci, 'group_consumer') as consumer, patch.dict(ci.os.environ, {'CI_PLAN': '0'}), contextlib.redirect_stdout(output):
                self.assertEqual(ci.main(), 1)
            evidence = json.loads((out / 'result.json').read_text())
            self.assertEqual(evidence['gates']['script-tests'], 'failed')
            self.assertEqual(evidence['gates']['fmt'], 'passed')
            self.assertEqual(evidence['gates']['t1'], 'skipped')
            self.assertEqual(evidence['gates']['identity'], 'passed')
            self.assertFalse((out / 't1.log').exists())
            for path in stale_paths:
                self.assertFalse(path.exists(), str(path))
            plan = json.loads((out / 'selection.json').read_text())
            self.assertEqual(set(plan['gates']), set(evidence['gates']))
            self.assertNotIn('local CI: isolated Git consumer', output.getvalue())
            self.assertIn('isolation: skipped', output.getvalue())
            self.assertIn('group-consumer: skipped', output.getvalue())
            isolation.assert_not_called()
            consumer.assert_not_called()
            self.assertFalse(any('test' in args for args in calls))

    def test_cleanup_preserves_unowned_evidence_and_does_not_follow_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / 'local-ci'
            out.mkdir()
            retained = out / 'identity-recheck' / 'result.json'
            retained.parent.mkdir()
            retained.write_text('retained proof')
            external = Path(directory) / 'external'
            external.mkdir()
            (external / 'result.json').write_text('external proof')
            (out / 'core-consumers').symlink_to(external, target_is_directory=True)
            source = Path(directory) / 'source-consumers'
            source.mkdir()
            (source / 'result.json').write_text('stale proof')
            with patch.object(ci, 'OUT', out), patch.object(ci, 'SOURCE_CONSUMER_OUT', source):
                ci.clear_execution_evidence(['core-consumers', 't1'])
                ci.clear_execution_evidence(['core-consumers', 't1'])
            self.assertTrue(retained.exists())
            self.assertEqual((external / 'result.json').read_text(), 'external proof')
            self.assertFalse((out / 'core-consumers').is_symlink())
            self.assertFalse(source.exists())

    def test_plan_does_not_execute_or_erase_previous_result(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            (out / 'result.json').write_text('previous execution')
            (out / 'selection.json').write_text('previous selection')
            with patch.object(ci, 'OUT', out), patch.object(ci, 'select_impact', return_value={'full': True, 'packages': [], 'reasons': ['explicit-full']}), patch.object(ci, 'command', return_value=result('head')) as command, patch.dict(ci.os.environ, {'CI_PLAN': '1'}), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(ci.main(), 0)
            self.assertEqual(command.call_count, 1)
            self.assertEqual((out / 'result.json').read_text(), 'previous execution')
            self.assertEqual((out / 'selection.json').read_text(), 'previous selection')
            plan = json.loads((out / 'plan.json').read_text())
            self.assertTrue(all(gate['selected'] for gate in plan['gates'].values()))
            for name in ('pin', 'identity', 'isolation', 'group-consumer'):
                self.assertTrue(plan['gates'][name]['check'])
