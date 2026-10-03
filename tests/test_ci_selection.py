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

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hack'))

from ci_impact import selected as make_selection, explicit_selection, SelectionError

spec = importlib.util.spec_from_file_location(
    'selection_ci', Path(__file__).resolve().parents[1] / 'hack/ci.py'
)
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)


def result(stdout='', returncode=0):
    return SimpleNamespace(stdout=stdout, stderr='', returncode=returncode)


class Selection(unittest.TestCase):
    def test_failed_selector_diagnostic_reaches_formal_entry(self):
        failure = SimpleNamespace(
            stdout=json.dumps(
                {
                    'status': 'failed',
                    'error': {
                        'code': 'selector-internal',
                        'phase': 'selection',
                        'inputs': [],
                    },
                }
            ),
            stderr='selector-internal phase=selection exception=RuntimeError\n',
            returncode=1,
        )
        diagnostic = io.StringIO()
        with (
            patch.dict(ci.os.environ, {'CI_FULL': '0', 'CI_T2': 'none'}),
            patch.object(ci, 'command', side_effect=[result('base'), failure]),
            contextlib.redirect_stderr(diagnostic),
            self.assertRaises(SelectionError),
        ):
            ci.select_impact('head')
        self.assertEqual(diagnostic.getvalue(), failure.stderr)

    def test_native_source_checks_follow_their_actual_owners(self):
        selection = make_selection(['rss-mdm-winget-source'], [], [], [])
        self.assertFalse(ci.selected_gate('native-schema', selection))
        for owner in [
            'rss-mdm-apple-mdm',
            'rss-mdm-windows-mdm',
            'rss-mdm-native-schema',
        ]:
            selection['cargo']['packages'] = [owner]
            self.assertTrue(ci.selected_gate('native-schema', selection))

    def test_explicit_cargo_full_does_not_expand_integration(self):
        decision = make_selection(
            ['rss-mdm-resource-postgres'],
            ['resource.persistence'],
            [],
            [{'kind': 'business', 'input': 'test-input', 'modules': []}],
        )
        with (
            patch.dict(ci.os.environ, {'CI_FULL': '1'}),
            patch.object(
                ci,
                'command',
                side_effect=[result('base'), result(json.dumps(decision))],
            ),
        ):
            selected = ci.select_impact('head')
        self.assertTrue((selected['cargo']['mode'] == 'all'))
        self.assertFalse((selected['t2']['mode'] == 'all'))
        self.assertEqual(selected['t2']['modules'], ['resource.persistence'])

    def test_merge_base_and_fallbacks(self):
        decision = make_selection(
            ['rss-mdm-group'],
            ['group.persistence'],
            [],
            [{'kind': 'business', 'input': 'package-change', 'modules': []}],
        )
        with (
            patch.dict(ci.os.environ, {'CI_FULL': '0'}),
            patch.object(
                ci,
                'command',
                side_effect=[result('base'), result(json.dumps(decision))],
            ) as command,
        ):
            selected = ci.select_impact('head')
            self.assertFalse((selected['cargo']['mode'] == 'all'))
            self.assertEqual(selected['t2']['modules'], ['group.persistence'])
            self.assertFalse(
                any('branch' in call.args[0] for call in command.call_args_list)
            )
        for outputs in ([result(returncode=1)], [result('base'), result('{}')]):
            with (
                patch.dict(ci.os.environ, {'CI_FULL': '0'}),
                patch.object(ci, 'command', side_effect=outputs),
            ):
                with self.assertRaises(SelectionError):
                    ci.select_impact('head')

    def test_package_commands_and_external_fixture_inputs(self):
        selection = make_selection(
            ['rss-mdm-winget-source'], ['sources.winget'], [], []
        )
        self.assertEqual(
            ci.gate_command('t1', ['cargo', 'test', '--workspace', '--lib'], selection),
            ['cargo', 'test', '-p', 'rss-mdm-winget-source', '--lib'],
        )
        self.assertFalse(ci.selected_gate('script-tests', selection))

    def test_compliance_owner_selects_real_router_module(self):
        from ci_impact import select_inputs, SelectionError

        for owner in ['compliance', 'compliance-postgres', 'group-postgres']:
            self.assertTrue(
                any(
                    name.startswith('compliance.')
                    for name in select_inputs(
                        ['crates/' + owner + '/src/lib.rs']
                    ).modules
                )
            )
        self.assertFalse(
            any(
                name.startswith('compliance.')
                for name in select_inputs(['crates/winget-source/src/lib.rs']).modules
            )
        )

    def test_docs_skip_rust_and_failure_collection_keeps_running(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            (out / 't1.log').write_text('stale passed')
            stale_paths = [out / 'pin.log']
            for path in stale_paths:
                path.write_text('previous run')
            output = io.StringIO()
            calls = []

            def command(args, **kwargs):
                calls.append(args)
                if 'rev-parse' in args:
                    return result('head\n')
                if 'status' in args:
                    return result()
                if 'fmt' in args:
                    return result('failure', 1)
                return result()

            selection = make_selection(
                [],
                [],
                [],
                [{'kind': 'documentation', 'input': 'docs-only', 'modules': []}],
            )
            with (
                patch.object(ci, 'require_lease'),
                patch.object(ci, 'OUT', out),
                patch.object(ci, 'select_impact', return_value=selection),
                patch.object(ci, 'command', side_effect=command),
                patch.object(ci, 'dependency_graphs') as graphs,
                patch.dict(ci.os.environ, {'CI_PLAN': '0', 'CI_T2': 'none'}),
                contextlib.redirect_stdout(output),
            ):
                self.assertEqual(ci.main(), 1)
            evidence = json.loads((out / 'result.json').read_text())
            self.assertEqual(evidence['gates']['script-tests']['status'], 'skipped')
            self.assertEqual(evidence['gates']['fmt']['status'], 'failed')
            self.assertEqual(evidence['gates']['t1']['status'], 'skipped')
            self.assertFalse((out / 't1.log').exists())
            for path in stale_paths:
                self.assertFalse(path.exists(), str(path))
            plan = json.loads((out / 'selection.json').read_text())
            self.assertEqual(set(plan['gates']), set(evidence['gates']))
            graphs.assert_not_called()
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
            (out / 'pin.log').symlink_to(external / 'result.json')
            with patch.object(ci, 'OUT', out):
                ci.clear_execution_evidence(['t1'])
                ci.clear_execution_evidence(['t1'])
            self.assertTrue(retained.exists())
            self.assertEqual((external / 'result.json').read_text(), 'external proof')
            self.assertFalse((out / 'pin.log').is_symlink())

    def test_plan_does_not_execute_or_erase_previous_result(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            (out / 'result.json').write_text('previous execution')
            (out / 'selection.json').write_text('previous selection')
            with (
                patch.object(ci, 'require_lease'),
                patch.object(ci, 'OUT', out),
                patch.object(
                    ci,
                    'select_impact',
                    return_value=explicit_selection(
                        ci.LOCAL_PACKAGES, ci.MODULES, ci.all_tools()
                    ),
                ),
                patch.object(ci, 'command', return_value=result('head')) as command,
                patch.dict(ci.os.environ, {'CI_PLAN': '1'}),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(ci.main(), 0)
            self.assertEqual(command.call_count, 1)
            self.assertEqual((out / 'result.json').read_text(), 'previous execution')
            self.assertEqual((out / 'selection.json').read_text(), 'previous selection')
            plan = json.loads((out / 'plan.json').read_text())
            self.assertTrue(all(gate['selected'] for gate in plan['gates'].values()))
            for name in ('pin',):
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
            env = {
                **os.environ,
                'PATH': str(root) + os.pathsep + os.environ['PATH'],
                'CI_PLAN': '1',
                'CI_FULL': '0',
            }
            for target, expected in [
                ('ci', '0:0'),
                ('ci-full', '0:1'),
                ('ci-plan', '1:0'),
            ]:
                for override in ([], ['CI_PLAN=1']):
                    with self.subTest(target=target, override=override):
                        result = subprocess.run(
                            ['make', '-s', target, *override],
                            cwd=root,
                            env=env,
                            text=True,
                            capture_output=True,
                        )
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(result.stdout, expected)

    def test_unexpected_selector_error_has_safe_internal_diagnostic(self):
        import ci_impact as impact

        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            patch.object(impact.sys, 'argv', ['ci-impact.py', '--base', 'base']),
            patch.object(
                impact,
                'run',
                return_value=SimpleNamespace(
                    returncode=0, stdout=str(ci.ROOT).encode()
                ),
            ),
            patch.object(
                impact, 'select', side_effect=RuntimeError('private-error-text')
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(impact.main(), 1)
        self.assertEqual(
            json.loads(stdout.getvalue())['error']['code'], 'selector-internal'
        )
        self.assertIn('phase=selection', stderr.getvalue())
        self.assertIn('RuntimeError', stderr.getvalue())
        self.assertNotIn('private-error-text', stderr.getvalue())

    def test_invalid_or_duplicate_results_fail(self):
        decisions = [
            {},
            make_selection([], ['missing-module']),
            make_selection(['rss-mdm-resource'], []),
        ]
        decisions[-1]['cargo']['packages'] *= 2
        for decision in decisions:
            with patch.object(
                ci,
                'command',
                side_effect=[result('base'), result(json.dumps(decision))],
            ):
                with self.assertRaises(SelectionError):
                    ci.select_impact('head')
        with patch.object(
            ci,
            'command',
            side_effect=[
                result('base'),
                result('{"status":"selected","status":"failed"}'),
            ],
        ):
            with self.assertRaises(SelectionError):
                ci.select_impact('head')

    def test_failed_selection_does_not_run_gates_or_publish_passed(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            (out / 'result.json').write_text('{"status":"passed"}')
            with (
                patch.object(ci, 'require_lease'),
                patch.object(ci, 'OUT', out),
                patch.object(
                    ci, 'select_impact', side_effect=SelectionError('base-unavailable')
                ),
                patch.object(ci, 'command', return_value=result('head')),
                patch.object(ci, 'working_source_state', return_value='stable'),
                patch.object(ci, 'gate_command') as gate,
                patch.dict(ci.os.environ, {'CI_PLAN': '0', 'CI_T2': 'none'}),
            ):
                with self.assertRaises(SelectionError):
                    ci.main()
            gate.assert_not_called()
            evidence = json.loads((out / 'result.json').read_text())
            self.assertEqual(evidence['status'], 'failed')
            self.assertEqual(evidence['selection']['error']['code'], 'base-unavailable')

    def test_explicit_full_bypasses_unavailable_baseline(self):
        with (
            patch.dict(ci.os.environ, {'CI_FULL': '1', 'CI_T2': 'all'}),
            patch.object(ci, 'command') as command,
        ):
            decision = ci.select_impact('head', 'missing-base')
        command.assert_not_called()
        self.assertEqual(decision['t2']['mode'], 'all')
        self.assertEqual(set(decision['t2']['modules']), set(ci.MODULES))
