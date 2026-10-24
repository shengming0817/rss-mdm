#!/usr/bin/env python3
"""Black-box contract for consumer-based CI and T2 selection."""

from __future__ import annotations

import importlib.util
import json
import re
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch


RSS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RSS_ROOT / 'hack'))
DEFAULT_SELECTOR = [sys.executable, str(RSS_ROOT / 'hack' / 'ci_impact.py')]


def selector_command() -> list[str]:
    override = os.environ.get('CI_IMPACT_COMMAND')
    return shlex.split(override) if override else DEFAULT_SELECTOR


class FixtureRepo:
    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix='rss-ci-impact-')
        self.root = Path(self._tmp.name)
        self._write(
            'Cargo.toml',
            """[workspace]
resolver = "2"
members = [
  "crates/core",
  "crates/leaf",
  "crates/other",
  "crates/dev-consumer",
  "crates/build-consumer",
  "crates/optional-consumer",
  "tests/leaf-integration",
  "tests/other-integration",
]
""",
        )
        self._package('crates/core', 'core')
        self._package('crates/leaf', 'leaf', dependencies={'core': '../core'})
        self._package('crates/other', 'other')
        self._package(
            'crates/dev-consumer',
            'dev-consumer',
            dev_dependencies={'core': '../core'},
        )
        self._package(
            'crates/build-consumer',
            'build-consumer',
            build_dependencies={'core': '../core'},
        )
        self._package(
            'crates/optional-consumer',
            'optional-consumer',
            optional_dependencies={'core': '../core'},
        )
        self._package(
            'tests/leaf-integration',
            'leaf-integration',
            dependencies={'leaf': '../../crates/leaf'},
            publish=False,
        )
        self._package(
            'tests/other-integration',
            'other-integration',
            dependencies={'other': '../../crates/other'},
            publish=False,
        )
        self._write('crates/leaf/src/obsolete.rs', 'pub const OBSOLETE: bool = true;\n')
        self._write('README.md', 'fixture\n')
        self._write('docs/guide.md', 'guide\n')
        self.git('init', '-q')
        self.git('config', 'user.email', 'ci-impact@example.invalid')
        self.git('config', 'user.name', 'CI Impact Test')
        subprocess.run(
            ['cargo', 'metadata', '--format-version', '1'],
            cwd=self.root,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        self._write('hack/t2_model.py', (RSS_ROOT / 'hack/t2_model.py').read_text())
        self._write(
            'hack/t2_registry.py',
            """from t2_model import Build, Module
MODULES = {n:Module(n, Build(n), ('',), production_inputs=(p+'/src/*',), test_inputs=(p+'/tests/*',))
           for n,p in [('core','crates/core'),('leaf','crates/leaf'),('other','crates/other'),
           ('dev-consumer','crates/dev-consumer'),('build-consumer','crates/build-consumer'),
           ('optional-consumer','crates/optional-consumer'),('leaf-integration','tests/leaf-integration'),
           ('other-integration','tests/other-integration')]}
T1_INPUTS = ()
TOOL_INPUTS = {'hack/t2_registry.py': ('test_registry',)}
CONTROL_INPUTS = {'Makefile': {'format':'make', 'tools':['test_registry']},
                  'deny.toml': {'format':'tools', 'tools':['test_registry']},
                  '.cargo/config.toml': {'format':'toml', 'tools':['test_registry'],
                                         'fields': {'build.jobs':'tools', 'build.rustflags':'runtime'}},
                  'rust-toolchain.toml': {'format':'toml', 'tools':['test_registry'],
                                          'fields': {'toolchain.channel':'runtime', 'toolchain.components':'tools'}}}
""",
        )
        self._write('tests/test_registry.py', '')
        self.commit('base')
        self.base = self.git('rev-parse', 'HEAD').stdout.strip()

    def close(self) -> None:
        self._tmp.cleanup()

    def _write(self, relative: str, content: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding='utf-8')

    def _package(
        self,
        relative: str,
        name: str,
        *,
        dependencies: dict[str, str] | None = None,
        dev_dependencies: dict[str, str] | None = None,
        build_dependencies: dict[str, str] | None = None,
        optional_dependencies: dict[str, str] | None = None,
        publish: bool = True,
    ) -> None:
        manifest = [
            '[package]',
            f'name = "{name}"',
            'version = "0.1.0"',
            'edition = "2024"',
        ]
        if not publish:
            manifest.append('publish = false')
        for heading, values in (
            ('dependencies', dependencies),
            ('dev-dependencies', dev_dependencies),
            ('build-dependencies', build_dependencies),
        ):
            if values:
                manifest.extend(['', f'[{heading}]'])
                manifest.extend(
                    f'{dependency} = {{ path = "{path}" }}'
                    for dependency, path in values.items()
                )
        if optional_dependencies:
            manifest.extend(
                ['', '[features]', 'default = []', 'integration = ["dep:core"]']
            )
            manifest.extend(['', '[dependencies]'])
            manifest.extend(
                f'{dependency} = {{ path = "{path}", optional = true }}'
                for dependency, path in optional_dependencies.items()
            )
        self._write(f'{relative}/Cargo.toml', '\n'.join(manifest) + '\n')
        self._write(f'{relative}/src/lib.rs', f'pub const NAME: &str = "{name}";\n')

    def git(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ['/usr/bin/git', *args],
            cwd=self.root,
            check=check,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def commit(self, message: str) -> str:
        self.git('add', '-A')
        self.git('commit', '-qm', message)
        return self.git('rev-parse', 'HEAD').stdout.strip()

    def change(self, relative: str, content: str = 'changed\n') -> str:
        self._write(relative, content)
        return self.commit(f'change {relative}')

    def delete(self, relative: str) -> str:
        (self.root / relative).unlink()
        return self.commit(f'delete {relative}')

    def rename(self, source: str, destination: str) -> str:
        destination_path = self.root / destination
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(self.root / source, destination_path)
        return self.commit(f'rename {source}')

    def copy(self, source: str, destination: str) -> str:
        destination_path = self.root / destination
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.root / source, destination_path)
        return self.commit(f'copy {source}')

    def select(
        self,
        *,
        base: str | None = None,
        head: str = 'HEAD',
        environment: dict[str, str] | None = None,
    ) -> tuple[bytes, dict]:
        if head != 'HEAD':
            self.git('checkout', '--detach', head)
        process_environment = os.environ.copy()
        process_environment.update(environment or {})
        result = subprocess.run(
            [
                *selector_command(),
                '--base',
                base or self.base,
            ],
            cwd=self.root,
            check=False,
            env=process_environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._last_result = result
        raw = result.stdout
        decision = json.loads(raw)
        if decision['status'] == 'selected':
            from ci_impact import validate_selection

            validate_selection(
                decision,
                [tomllib.loads(path.read_text())['package']['name']
                 for path in self.root.glob('*/**/Cargo.toml')],
                decision['t2']['modules'],
                [path.stem for path in (self.root / 'tests').glob('test_*.py')],
            )
        if result.returncode != int(decision['status'] == 'failed'):
            raise AssertionError(
                f'inconsistent selector exit: {result.stderr!r} {decision!r}'
            )
        return raw, decision


class CiImpactContract(unittest.TestCase):
    def setUp(self):
        self.repo = FixtureRepo()

    def tearDown(self):
        self.repo.close()

    def assert_selected(self, decision, packages, modules):
        self.assertEqual(decision['status'], 'selected', decision)
        self.assertEqual(
            decision['cargo'], {'mode': 'affected', 'packages': sorted(packages)}
        )
        self.assertEqual(
            decision['t2'], {'mode': 'affected', 'modules': sorted(modules)}
        )

    def test_docs_and_no_changes_do_not_select_packages(self):
        first, decision = self.repo.select()
        self.assert_selected(decision, [], [])
        self.assertEqual(first, self.repo.select()[0])
        self.repo.change('docs/guide.md')
        self.assert_selected(self.repo.select()[1], [], [])

    def test_working_sources_staged_unstaged_untracked_deleted(self):
        for mode in ('staged', 'unstaged', 'new', 'deleted'):
            with self.subTest(mode=mode):
                self.repo.git('reset', '--hard', self.repo.base)
                self.repo.git('clean', '-fd')
                path = self.repo.root / 'crates/leaf/src/obsolete.rs'
                if mode == 'deleted':
                    path.unlink()
                elif mode == 'new':
                    path.with_name('new.rs').write_text('pub const NEW: bool = true;')
                else:
                    path.write_text('changed')
                    if mode == 'staged':
                        self.repo.git('add', str(path))
                self.assert_selected(
                    self.repo.select()[1], ['leaf', 'leaf-integration'], ['leaf']
                )

    def test_reverse_cargo_closure_does_not_expand_t2(self):
        self.repo.change('crates/core/src/lib.rs')
        self.assert_selected(
            self.repo.select()[1],
            [
                'core',
                'leaf',
                'dev-consumer',
                'build-consumer',
                'optional-consumer',
                'leaf-integration',
            ],
            ['core'],
        )

    def test_rename_and_copy_union_both_owners(self):
        for mode in ('rename', 'copy'):
            with self.subTest(mode=mode):
                self.repo.git('reset', '--hard', self.repo.base)
                getattr(self.repo, mode)(
                    'crates/leaf/src/obsolete.rs', 'crates/other/src/copied.rs'
                )
                self.assert_selected(
                    self.repo.select()[1],
                    ['leaf', 'leaf-integration', 'other', 'other-integration'],
                    ['leaf', 'other'],
                )

    def test_edited_rename_accepts_git_padded_similarity(self):
        old = 'crates/leaf/src/obsolete.rs'
        original = ''.join(f'pub const ITEM_{i}: usize = {i};\n' for i in range(20))
        self.repo.change(old, original)
        self.repo.base = self.repo.git('rev-parse', 'HEAD').stdout.strip()
        self.repo.rename(old, 'crates/other/src/copied.rs')
        self.repo.change('crates/other/src/copied.rs', original.replace('ITEM_0', 'RENAMED_0'))
        status = self.repo.git('diff', '--name-status', '--find-renames', self.repo.base).stdout
        self.assertRegex(status, r'R0[0-9]{2}')
        self.assert_selected(self.repo.select()[1], ['leaf', 'leaf-integration', 'other', 'other-integration'], ['leaf', 'other'])

    def test_unknown_input_and_bad_baseline_fail(self):
        self.repo.change('unknown.file')
        decision = self.repo.select()[1]
        self.assertEqual(decision['status'], 'failed')
        self.assertEqual(decision['error']['code'], 'unmapped-input')
        decision = self.repo.select(base='missing')[1]
        self.assertEqual(decision['status'], 'failed')
        self.assertEqual(decision['error']['code'], 'diff-unavailable')

    def test_rename_and_copy_require_each_endpoint_owner(self):
        for mode in ('rename', 'copy'):
            with self.subTest(mode=mode):
                self.repo.git('reset', '--hard', self.repo.base)
                self.repo.git('clean', '-fd')
                getattr(self.repo, mode)(
                    'crates/leaf/src/obsolete.rs', 'unknown/input.rs'
                )
                decision = self.repo.select()[1]
                self.assertEqual(decision['status'], 'failed')
                self.assertEqual(decision['error']['code'], 'unmapped-input')
                self.assertIn('unknown/input.rs', decision['error']['inputs'])

    def test_copy_to_tool_does_not_erase_business_source_owner(self):
        registry = self.repo.root / 'hack/t2_registry.py'
        registry.write_text(
            registry.read_text()
            + "\nTOOL_INPUTS['hack/tool.py'] = ('test_registry',)\nTOOL_ONLY_INPUTS = ('hack/tool.py',)\n"
        )
        self.repo.commit('declare tool owner')
        self.repo.base = self.repo.git('rev-parse', 'HEAD').stdout.strip()
        self.repo.copy('crates/leaf/src/obsolete.rs', 'hack/tool.py')
        decision = self.repo.select()[1]
        self.assert_selected(decision, ['leaf', 'leaf-integration'], ['leaf'])
        self.assertEqual(decision['toolTests'], ['test_registry'])

    def test_type_change_is_a_diff_failure(self):
        path = self.repo.root / 'crates/leaf/src/obsolete.rs'
        path.unlink()
        path.symlink_to('lib.rs')
        self.assertEqual(self.repo.select()[1]['error']['code'], 'diff-invalid')

    def test_registry_mapping_change_is_local(self):
        p = self.repo.root / 'hack/t2_registry.py'
        p.write_text(
            p.read_text()
            + "\nfrom dataclasses import replace\nMODULES['leaf'] = replace(MODULES['leaf'], production_inputs=('crates/leaf/src/*','shared/input.rs'))\n"
        )
        decision = self.repo.select()[1]
        self.assert_selected(decision, [], [])
        self.assertEqual(decision['toolTests'], ['test_registry'])

    def test_removed_mapping_keeps_cargo_without_old_t2_consumers(self):
        p = self.repo.root / 'hack/t2_registry.py'
        p.write_text(
            p.read_text()
            + "\nfrom dataclasses import replace\nMODULES['leaf'] = replace(MODULES['leaf'], production_inputs=('new/input.rs',))\n"
        )
        self.repo.change('crates/leaf/src/obsolete.rs')
        self.assert_selected(
            self.repo.select()[1], ['leaf', 'leaf-integration'], []
        )

    def test_deleted_module_requires_current_carrier_owner(self):
        self.repo._write('crates/leaf/tests/behavior.rs', '')
        self.repo.commit('test carrier')
        self.repo.base = self.repo.git('rev-parse', 'HEAD').stdout.strip()
        p = self.repo.root / 'hack/t2_registry.py'
        p.write_text(p.read_text() + "\ndel MODULES['leaf']\n")
        self.assertEqual(self.repo.select()[1]['error']['code'], 'test-carrier-without-owner')
        p.write_text(p.read_text() + "from dataclasses import replace\nMODULES['other'] = replace(MODULES['other'], test_inputs=('crates/leaf/tests/*',))\n")
        decision = self.repo.select()[1]
        self.assert_selected(decision, [], ['other'])
        self.assertEqual(decision['removedModules'][0]['owners'], ['other'])
        self.assertEqual(decision['ownershipChecks'], [dict(package='leaf', kind='lib', target='', features=[])])

    def test_removed_last_module_still_requests_discovery(self):
        p = self.repo.root / 'hack/t2_registry.py'
        p.write_text(p.read_text() + "\ndel MODULES['leaf']\n")
        decision = self.repo.select()[1]
        self.assert_selected(decision, [], [])
        self.assertEqual(decision['removedModules'], [dict(module='leaf', carriers=[], owners=[])])
        self.assertEqual(decision['ownershipChecks'], [dict(package='leaf', kind='lib', target='', features=[])])

    def test_deleted_test_can_exit_without_old_name_registration(self):
        self.repo._write('crates/leaf/tests/behavior.rs', '')
        self.repo.commit('test carrier')
        self.repo.base = self.repo.git('rev-parse', 'HEAD').stdout.strip()
        self.repo.delete('crates/leaf/tests/behavior.rs')
        p = self.repo.root / 'hack/t2_registry.py'
        p.write_text(p.read_text() + "\ndel MODULES['leaf']\n")
        decision = self.repo.select()[1]
        self.assertEqual(decision['status'], 'selected')
        self.assertEqual(decision['t2']['modules'], [])
        self.assertEqual(decision['removedModules'][0]['carriers'],
                         [dict(path='crates/leaf/tests/behavior.rs', kind='deleted', modules=[])])

    def test_selector_change_requests_ownership_check_not_other_modules(self):
        p = self.repo.root / 'hack/t2_registry.py'
        p.write_text(p.read_text() + "\nfrom dataclasses import replace\nMODULES['leaf'] = replace(MODULES['leaf'], selectors=('current::',))\n")
        decision = self.repo.select()[1]
        self.assert_selected(decision, [], ['leaf'])
        self.assertEqual([b['package'] for b in decision['ownershipChecks']], ['leaf'])


    def test_test_input_selects_owner_and_assertion_changes(self):
        self.repo.change('crates/leaf/tests/behavior.rs', 'assert!(false);')
        self.assert_selected(
            self.repo.select()[1], ['leaf'], ['leaf']
        )

    def test_member_manifest_nonsemantic_and_dependency_changes(self):
        p = self.repo.root / 'crates/leaf/Cargo.toml'
        p.write_text(
            p.read_text().replace(
                'version = "0.1.0"', 'version = "0.1.0"\ndescription = "changed"'
            )
        )
        self.assert_selected(self.repo.select()[1], [], [])
        p.write_text(
            p.read_text().replace(
                'path = "../core"', 'package = "other", path = "../other"'
            )
        )
        subprocess.run(
            ['cargo', 'metadata', '--format-version', '1'],
            cwd=self.repo.root,
            check=True,
            capture_output=True,
        )
        decision = self.repo.select()[1]
        self.assertEqual(decision['status'], 'selected', decision)
        self.assertEqual(decision['t2']['modules'], [])
        self.assertEqual(set(decision['cargo']['packages']), {'leaf', 'leaf-integration'})
        self.assertNotIn('other-integration', decision['t2']['modules'])

    def test_lock_comment_does_not_select_business(self):
        p = self.repo.root / 'Cargo.lock'
        p.write_text(p.read_text() + '\n# comment\n')
        decision = self.repo.select()[1]
        self.assert_selected(decision, [], [])
        self.assertIn(dict(kind='tool', input='Cargo.lock', modules=[], detail='dependency'),
                      decision['reasons'])

    def test_makefile_and_policy_select_tools_only(self):
        for path in ('Makefile', 'deny.toml'):
            self.repo.change(path, '# tool input\n')
            decision = self.repo.select()[1]
            self.assert_selected(decision, [], [])
            self.assertEqual(decision['toolTests'], ['test_registry'])

    def test_shared_controls_only_expand_cargo(self):
        registry = self.repo.root / 'hack/t2_registry.py'
        registry.write_text(
            registry.read_text()
            + "\nMODULES['host'] = Module('host', None, (), profile='none', fixtures=('identity',), python='test_registry', db_mode=None, scope=None)\n"
            + "MODULES['python-only'] = Module('python-only', None, (), profile='none', python='test_registry', db_mode=None, scope=None)\n"
        )
        self.repo.commit('declare Rust fixture and Python consumers')
        self.repo.base = self.repo.git('rev-parse', 'HEAD').stdout.strip()
        for path, content, detail in (
            ('Cargo.toml', (self.repo.root / 'Cargo.toml').read_text() + '\n[profile.dev]\nopt-level=1\n',
             'cargo-only'),
            (
                'Makefile',
                'export RUSTFLAGS := -C debuginfo=1\n',
                'shared-compiler-environment',
            ),
            (
                'rust-toolchain.toml',
                '[toolchain]\nchannel = "stable"\n',
                'shared-runtime',
            ),
            (
                '.cargo/config.toml',
                '[build]\nrustflags = ["-C", "debuginfo=1"]\n',
                'shared-runtime',
            ),
        ):
            with self.subTest(path=path):
                self.repo.git('reset', '--hard', self.repo.base)
                self.repo.git('clean', '-fd')
                self.repo._write(path, content)
                decision = self.repo.select()[1]
                self.assertEqual(decision['status'], 'selected', decision)
                self.assertEqual(
                    decision['t2'], {'mode': 'affected', 'modules': []}
                )
                self.assertEqual(len(decision['cargo']['packages']), 8)
                self.assertEqual(decision['toolTests'], [] if path == 'Cargo.toml' else ['test_registry'])
                if path != 'Cargo.toml':
                    self.assertTrue(any(r.get('detail') == detail for r in decision['reasons']))

    def test_control_tool_fields_and_unknown_fields(self):
        for path, content in (
            ('.cargo/config.toml', '[build]\njobs = 2\n'),
            ('rust-toolchain.toml', '[toolchain]\ncomponents = ["clippy"]\n'),
        ):
            with self.subTest(path=path):
                self.repo.git('reset', '--hard', self.repo.base)
                self.repo.git('clean', '-fd')
                self.repo._write(path, content)
                decision = self.repo.select()[1]
                self.assert_selected(decision, [], [])
                self.assertEqual(decision['toolTests'], ['test_registry'])
        self.repo._write('.cargo/config.toml', '[unclassified]\nsetting = true\n')
        decision = self.repo.select()[1]
        self.assertEqual(decision['status'], 'failed')
        self.assertEqual(decision['error']['code'], 'unclassified-config')

    def test_metadata_failure_is_not_full(self):
        self.repo.change('crates/leaf/src/lib.rs')
        with tempfile.TemporaryDirectory() as directory:
            cargo = Path(directory) / 'cargo'
            cargo.write_text('#!/bin/sh\nexit 1\n')
            cargo.chmod(0o755)
            decision = self.repo.select(
                environment={'PATH': directory + os.pathsep + os.environ['PATH']}
            )[1]
        self.assertEqual(decision['status'], 'failed')
        self.assertEqual(decision['error']['code'], 'metadata-unavailable')
        self.assertIn('version=baseline:' + self.repo.base, decision['error']['inputs'])
        self.assertIn('stage=metadata', decision['error']['inputs'])
        self.assertIn('exit=1', decision['error']['inputs'])

    def test_current_metadata_failure_has_safe_location(self):
        self.repo.change('crates/leaf/src/lib.rs')
        with tempfile.TemporaryDirectory() as directory:
            cargo = Path(directory) / 'cargo'
            actual = shutil.which('cargo')
            cargo.write_text('#!/bin/sh\nif [ "$PWD" = ' + shlex.quote(str(self.repo.root.resolve()))
                             + ' ]; then echo "failed to fetch credential-secret" >&2; exit 7; fi\nexec '
                             + shlex.quote(actual) + ' "$@"\n')
            cargo.chmod(0o755)
            raw, decision = self.repo.select(environment={'PATH': directory + os.pathsep + os.environ['PATH']})
        self.assertEqual(decision['status'], 'failed')
        self.assertIn('version=current', decision['error']['inputs'])
        self.assertIn('stage=metadata', decision['error']['inputs'])
        self.assertIn('exit=7', decision['error']['inputs'])
        self.assertIn('diagnostic=dependency-fetch', decision['error']['inputs'])
        self.assertNotIn(b'credential-secret', raw + self.repo._last_result.stderr)

    def test_new_module_and_changed_fixture_selector_are_local(self):
        p = self.repo.root / 'hack/t2_registry.py'
        p.write_text(
            p.read_text()
            + "\nMODULES['new.owner'] = Module('new.owner', Build('leaf'), ('new::',), production_inputs=('crates/leaf/src/new.rs',))\n"
        )
        self.assert_selected(self.repo.select()[1], [], ['new.owner'])
        p.write_text(
            p.read_text()
            + "from dataclasses import replace\nMODULES['leaf'] = replace(MODULES['leaf'], profile='backend', fixtures=('tls',), selectors=('new::',))\n"
        )
        self.assert_selected(self.repo.select()[1], [], ['leaf', 'new.owner'])

    def test_helper_direct_consumers_and_unit_carriers(self):
        p = self.repo.root / 'hack/t2_registry.py'
        p.write_text(
            p.read_text()
            + "\nfrom dataclasses import replace\nMODULES['leaf'] = replace(MODULES['leaf'], support_inputs=('tests/support/helper.rs',))\nT1_INPUTS = ('crates/core/tests/unit.rs',)\n"
        )
        self.repo.commit('declare helper and T1')
        self.repo.base = self.repo.git('rev-parse', 'HEAD').stdout.strip()
        self.repo.change('tests/support/helper.rs')
        self.assert_selected(self.repo.select()[1], ['leaf'], ['leaf'])
        self.repo.git('reset', '--hard', self.repo.base)
        # A declaration-only entry compiles/discovers its target, including when
        # the baseline used to map that entry to all of its business tests.
        registry = self.repo.root / 'hack/t2_registry.py'
        registry.write_text(registry.read_text() + "\nTOOL_INPUTS['crates/leaf/tests/mod.rs'] = ('test_registry',)\nTOOL_ONLY_INPUTS = ('crates/leaf/tests/mod.rs',)\n")
        self.repo.change('crates/leaf/tests/mod.rs', 'mod helper;\n')
        decision = self.repo.select()[1]
        self.assert_selected(decision, ['leaf'], [])
        self.assertEqual([b['package'] for b in decision['ownershipChecks']], ['leaf'])
        self.repo.git('reset', '--hard', self.repo.base)
        # Remove T2 ownership for the T1 file, as declared by the real source owner.
        p = self.repo.root / 'hack/t2_registry.py'
        p.write_text(
            p.read_text()
            + "\nMODULES['core'] = replace(MODULES['core'], test_inputs=())\n"
        )
        self.repo.commit('separate unit carrier')
        self.repo.base = self.repo.git('rev-parse', 'HEAD').stdout.strip()
        self.repo.change('crates/core/tests/unit.rs')
        self.assert_selected(self.repo.select()[1], ['core'], [])

    def test_dev_consumption_is_terminal_for_sources_and_manifest_changes(self):
        manifest = self.repo.root / 'crates/other/Cargo.toml'
        manifest.write_text(manifest.read_text() + '\n[dependencies]\ndev-consumer={path="../dev-consumer"}\n')
        subprocess.run(['cargo', 'metadata', '--format-version', '1'], cwd=self.repo.root,
                       check=True, capture_output=True)
        self.repo.commit('production consumer of a test consumer')
        self.repo.base = self.repo.git('rev-parse', 'HEAD').stdout.strip()
        self.repo.change('crates/core/src/lib.rs')
        decision = self.repo.select()[1]
        self.assertIn('dev-consumer', decision['cargo']['packages'])
        self.assertNotIn('other', decision['cargo']['packages'])
        self.assertNotIn('other-integration', decision['cargo']['packages'])
        self.repo.git('reset', '--hard', self.repo.base)
        manifest = self.repo.root / 'crates/dev-consumer/Cargo.toml'
        manifest.write_text(manifest.read_text().replace('path = "../core"', 'path = "../leaf", package="leaf"'))
        subprocess.run(['cargo', 'metadata', '--format-version', '1'], cwd=self.repo.root,
                       check=True, capture_output=True)
        self.assert_selected(self.repo.select()[1], ['dev-consumer'], [])

    def test_crate_readme_contributes_cargo_but_no_t2(self):
        self.repo.change('crates/leaf/README.md', 'docs')
        self.assert_selected(self.repo.select()[1], ['leaf', 'leaf-integration'], [])

    def test_representative_proof_uses_current_carrier_without_business_matrix(self):
        p = self.repo.root / 'hack/t2_registry.py'
        p.write_text(
            p.read_text()
            + "\nTOOL_INPUTS['hack/runtime.py'] = ('test_registry',)\nTOOL_ONLY_INPUTS = ('hack/runtime.py',)\nREPRESENTATIVE_INPUTS = {'hack/runtime.py': ('leaf',)}\n"
        )
        self.repo.change('hack/runtime.py', '# changed execution seam')
        decision = self.repo.select()[1]
        self.assert_selected(decision, [], ['leaf'])
        self.assertTrue(
            any(
                r['kind'] == 'representative' and r['modules'] == ['leaf']
                for r in decision['reasons']
            )
        )

    def test_retired_representative_does_not_run_from_baseline(self):
        registry = self.repo.root / 'hack/t2_registry.py'
        registry.write_text(registry.read_text() + "\nTOOL_INPUTS['hack/runtime.py'] = ('test_registry',)\nTOOL_ONLY_INPUTS = ('hack/runtime.py',)\nREPRESENTATIVE_INPUTS = {'hack/runtime.py': ('leaf',)}\n")
        self.repo._write('hack/runtime.py', '# execution')
        self.repo.commit('representative owner')
        self.repo.base = self.repo.git('rev-parse', 'HEAD').stdout.strip()
        registry.write_text(registry.read_text() + "\nREPRESENTATIVE_INPUTS = {}\n")
        self.repo.change('hack/runtime.py', '# changed execution')
        self.assert_selected(self.repo.select()[1], [], [])

    def test_damaged_registry_fails_before_metadata(self):
        p = self.repo.root / 'hack/t2_registry.py'
        p.write_text(p.read_text() + "\nMODULES = {'broken': None}\n")
        decision = self.repo.select()[1]
        self.assertEqual(decision['status'], 'failed')
        self.assertEqual(decision['error']['code'], 'registry-unavailable')
        self.assertIn('version=current', decision['error']['inputs'])
        self.assertIn('stage=registry', decision['error']['inputs'])
        self.assertIn('exit=1', decision['error']['inputs'])
        self.assertIn('diagnostic=TypeError', decision['error']['inputs'])

    def test_optional_dependency_change_selects_only_cargo(self):
        p = self.repo.root / 'crates/optional-consumer/Cargo.toml'
        p.write_text(
            p.read_text().replace(
                'path = "../core"', 'package = "other", path = "../other"'
            )
        )
        subprocess.run(
            ['cargo', 'metadata', '--all-features', '--format-version', '1'],
            cwd=self.repo.root,
            check=True,
            capture_output=True,
        )
        decision = self.repo.select()[1]
        self.assert_selected(decision, ['optional-consumer'], [])


class CargoDependencies(unittest.TestCase):

    def test_lock_qualification_preserves_identity_and_rejects_ambiguity(self):
        from ci_impact import lock_entries, SelectionError
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / 'Cargo.lock'
            base = 'version=4\n[[package]]\nname="consumer"\nversion="1.0.0"\ndependencies=["driver"]\n[[package]]\nname="driver"\nversion="1.0.0"\nsource="registry+test"\nchecksum="a"\n'
            lock.write_text(base)
            original = lock_entries(root)[('consumer', '1.0.0', None)]
            duplicate = '\n[[package]]\nname="driver"\nversion="2.0.0"\nsource="registry+test"\nchecksum="b"\n'
            lock.write_text(base.replace('["driver"]', '["driver 1.0.0 (registry+test)"]') + duplicate)
            self.assertEqual(lock_entries(root)[('consumer', '1.0.0', None)], original)
            lock.write_text(base + duplicate)
            with self.assertRaisesRegex(SelectionError, 'lock-invalid'):
                lock_entries(root)

    def test_git_lock_qualification_matches_the_exact_revision(self):
        from ci_impact import lock_dependency, SelectionError
        a = 'git+https://example.test/rss?rev=aaaa'
        b = 'git+https://example.test/rss?rev=bbbb'
        packages = [dict(name='driver', version='1.0.0', source=a+'#aaaa'),
                    dict(name='driver', version='1.0.0', source=b+'#bbbb')]
        self.assertEqual(lock_dependency('driver 1.0.0 ('+a+')', packages),
                         ('driver', '1.0.0', a+'#aaaa'))
        for reference in ('driver 1.0.0', 'driver 1.0.0 (git+https://example.test/rss?rev=cccc)',
                          'driver 1.0.0 ('+a+'#wrong)'):
            with self.assertRaisesRegex(SelectionError, 'lock-invalid'):
                lock_dependency(reference, packages)

    def test_lock_identity_and_checksum_changes_select_only_cargo(self):
        from ci_impact import Graph, Change, analyze_dependencies

        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            graphs = []
            for label, version, checksum in [
                ('old', '1.0.0', 'a'),
                ('new', '1.1.0', 'b'),
            ]:
                root = parent / label
                (root / 'crates/service').mkdir(parents=True)
                (root / 'Cargo.toml').write_text(
                    '[workspace]\nmembers=["crates/service"]\n'
                )
                (root / 'crates/service/Cargo.toml').write_text(
                    '[package]\nname="service"\nversion="1.0.0"\n[dependencies]\ndriver={package="database",version="1"}\n'
                )
                (root / 'Cargo.lock').write_text(
                    'version=4\n[[package]]\nname="database"\nversion="'
                    + version
                    + '"\nsource="registry+test"\nchecksum="'
                    + checksum
                    + '"\n'
                )
                dep = {
                    'name': 'driver',
                    'pkg': 'db',
                    'dep_kinds': [{'kind': None, 'target': None}],
                }
                graphs.append(
                    Graph(
                        root,
                        dict(
                            workspace_root=str(root),
                            workspace_members=['service'],
                            packages=[
                                dict(
                                    id='service',
                                    name='service',
                                    dependencies=[dict(name='database', rename='driver', kind=None)],
                                    version='1.0.0',
                                    source=None,
                                    manifest_path=str(
                                        root / 'crates/service/Cargo.toml'
                                    ),
                                ),
                                dict(
                                    id='db',
                                    name='database',
                                    version=version,
                                    source='registry+test',
                                ),
                            ],
                            resolve=dict(
                                nodes=[
                                    dict(id='service', deps=[dep], features=[]),
                                    dict(id='db', deps=[], features=[]),
                                ]
                            ),
                        ),
                    )
                )
            packages, reasons = analyze_dependencies(
                parent / 'old',
                parent / 'new',
                [Change('M', 'Cargo.lock', 'Cargo.lock')],
                graphs,
            )
            self.assertEqual(packages, {'service'})
            self.assertTrue(all(not reason['modules'] for reason in reasons))
            # Same version/source but changed checksum is still an input change.
            (parent / 'new/Cargo.lock').write_text(
                (parent / 'old/Cargo.lock')
                .read_text()
                .replace('checksum="a"', 'checksum="b"')
            )
            graphs[1].packages['db']['version'] = '1.0.0'
            graphs[1].identity['db'] = graphs[0].identity['db']
            self.assertEqual(
                analyze_dependencies(
                    parent / 'old',
                    parent / 'new',
                    [Change('M', 'Cargo.lock', 'Cargo.lock')],
                    graphs,
                    )[0],
                {'service'},
            )


if __name__ == '__main__':
    unittest.main()
