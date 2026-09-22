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
    def test_ci_plan_never_registers_manual_consumers(self):
        manual = {
            'core-consumers', 'inventory-consumers', 'backend-consumers',
            'group-postgres-consumers', 'source-consumers', 'agent-wire-consumer',
            'group-consumer',
        }
        for selection in (
            {'full': True, 'packages': [], 'reasons': ['global-input']},
            {'full': False, 'packages': ['rss-mdm-app'], 'reasons': ['package-change']},
            {'full': False, 'packages': [], 'reasons': ['docs-only']},
        ):
            with self.subTest(selection=selection), tempfile.TemporaryDirectory() as directory:
                out = Path(directory)
                with patch.object(ci, 'OUT', out), patch.object(ci, 'select_impact', return_value=selection), patch.object(ci, 'command', return_value=result('head')), patch.dict(ci.os.environ, {'CI_PLAN': '1'}), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(ci.main(), 0)
                gates = json.loads((out / 'plan.json').read_text())['gates']
                self.assertFalse(manual & gates.keys())
                self.assertEqual(gates['t2']['selected'], selection['full'] or 'rss-mdm-app' in selection['packages'])

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
        for name in ['source-t2', 'isolation', 'new-gate']:
            self.assertTrue(ci.selected_gate(name, selection), name)
        for name in ['group-t2', 'advisories']:
            self.assertFalse(ci.selected_gate(name, selection), name)
        for package in ci.APP_INPUTS:
            for name in ['backend-t2', 'asset-t2', 'command-t2']:
                self.assertTrue(ci.selected_gate(name, {'full': False, 'packages': [package]}), (package, name))

    def test_docs_skip_rust_and_failure_collection_keeps_running(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            (out / 't1.log').write_text('stale passed')
            stale_paths = [out / name for name in (
                'isolated-build.log', 'metadata-normal.json', 'metadata-integration.json',
                'metadata-normal.stderr.log', 'metadata-integration.stderr.log',
                'tree-normal.txt', 'tree-integration.txt', 'pin.log')]
            source_out = out / 'separate-source-consumers'
            legacy_paths = [out / 'core-consumers/result.json', out / 'group-consumer.log']
            manual_paths = [source_out / 'result.json']
            for path in stale_paths + legacy_paths + manual_paths:
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
            with patch.object(ci, 'OUT', out), patch.object(ci, 'select_impact', return_value=selection), patch.object(ci, 'command', side_effect=command), patch.object(ci, 'isolate') as isolation, patch.dict(ci.os.environ, {'CI_PLAN': '0'}), contextlib.redirect_stdout(output):
                self.assertEqual(ci.main(), 1)
            evidence = json.loads((out / 'result.json').read_text())
            self.assertEqual(evidence['gates']['script-tests'], 'failed')
            self.assertEqual(evidence['gates']['fmt'], 'passed')
            self.assertEqual(evidence['gates']['t1'], 'skipped')
            self.assertEqual(evidence['gates']['identity'], 'passed')
            self.assertFalse((out / 't1.log').exists())
            for path in stale_paths + legacy_paths:
                self.assertFalse(path.exists(), str(path))
            for path in manual_paths:
                self.assertEqual(path.read_text(), 'old-head passed')
            plan = json.loads((out / 'selection.json').read_text())
            self.assertEqual(set(plan['gates']), set(evidence['gates']))
            self.assertNotIn('local CI: isolated Git consumer', output.getvalue())
            self.assertIn('isolation: skipped', output.getvalue())
            isolation.assert_not_called()
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
            (out / 'isolated-build.log').symlink_to(external / 'result.json')
            manual = out / 'core-consumers'
            manual.mkdir()
            (manual / 'result.json').write_text('manual proof')
            source = Path(directory) / 'source-consumers'
            source.mkdir()
            (source / 'result.json').write_text('stale proof')
            with patch.object(ci, 'OUT', out):
                ci.clear_execution_evidence(['t1'])
                ci.clear_execution_evidence(['t1'])
            self.assertTrue(retained.exists())
            self.assertEqual((external / 'result.json').read_text(), 'external proof')
            self.assertFalse((out / 'isolated-build.log').is_symlink())
            self.assertFalse(manual.exists())
            self.assertTrue((source / 'result.json').exists())

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
            for name in ('pin', 'identity', 'isolation'):
                self.assertTrue(plan['gates'][name]['check'])


class EntryModes(unittest.TestCase):
    def test_named_targets_override_inherited_or_command_line_preview(self):
        import os
        import shutil
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copyfile(ci.ROOT / 'Makefile', root / 'Makefile')
            subprocess.run(['/usr/bin/git', 'init', '-q', str(root)], check=True)
            python = root / 'python3'
            python.write_text('#!/bin/sh\nprintf "%s:%s" "$CI_PLAN" "$CI_FULL"\n')
            python.chmod(0o755)
            env = {**os.environ, 'PATH': str(root) + os.pathsep + os.environ['PATH'], 'CI_PLAN': '1', 'CI_FULL': '0'}
            for target, expected in [('ci','0:0'), ('ci-full','0:1'), ('ci-plan','1:0')]:
                for override in ([], ['CI_PLAN=1']):
                    with self.subTest(target=target, override=override):
                        result = subprocess.run(['make','-s',target,*override], cwd=root, env=env, text=True, capture_output=True)
                        self.assertEqual(result.returncode,0,result.stderr)
                        self.assertEqual(result.stdout,expected)

    def test_unexpected_selector_error_has_safe_internal_diagnostic(self):
        spec = importlib.util.spec_from_file_location('impact_failure', ci.ROOT / 'hack/ci-impact.py')
        impact = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(impact)
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(impact.sys,'argv',['ci-impact.py','--base','base','--head','HEAD']), patch.object(impact,'run',return_value=SimpleNamespace(returncode=0,stdout=str(ci.ROOT).encode())), patch.object(impact,'select',side_effect=RuntimeError('private-error-text')), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            impact.main()
        self.assertEqual(json.loads(stdout.getvalue()),{'full':True,'packages':[],'reasons':['selector-internal']})
        self.assertIn('phase=selection',stderr.getvalue())
        self.assertIn('RuntimeError',stderr.getvalue())
        self.assertNotIn('private-error-text',stderr.getvalue())


    def test_runner_keeps_stderr_diagnostic_out_of_json(self):
        import sys
        original = ci.command
        def command(args, **kwargs):
            if 'branch' in args: return result('topic')
            if 'merge-base' in args: return result('base')
            if 'status' in args: return result()
            self.assertTrue(kwargs.get('separate_stderr'))
            payload = json.dumps({'full':True, 'packages':[], 'reasons':['selector-internal']})
            script = f"import sys; print({payload!r}); print('selector-internal phase=selection exception=RuntimeError', file=sys.stderr)"
            return original([sys.executable, '-c', script], **kwargs)
        with patch.dict(ci.os.environ, {'CI_FULL':'0'}), patch.object(ci,'command',side_effect=command):
            selection = ci.select_impact('head')
        self.assertEqual(selection['reasons'],['selector-internal'])
        self.assertIn('phase=selection',selection['diagnostic'])
