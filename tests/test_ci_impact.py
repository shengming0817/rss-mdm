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
DEPENDENCY_POLICIES = {}
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
                decision['cargo']['packages'],
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
        self.assert_selected(decision, [], ['leaf'])
        self.assertEqual(decision['toolTests'], ['test_registry'])

    def test_removed_mapping_preserves_old_consumer(self):
        p = self.repo.root / 'hack/t2_registry.py'
        p.write_text(
            p.read_text()
            + "\nfrom dataclasses import replace\nMODULES['leaf'] = replace(MODULES['leaf'], production_inputs=('new/input.rs',))\n"
        )
        self.repo.change('crates/leaf/src/obsolete.rs')
        self.assert_selected(
            self.repo.select()[1], ['leaf', 'leaf-integration'], ['leaf']
        )

    def test_deleted_module_needs_current_proof_owner(self):
        p = self.repo.root / 'hack/t2_registry.py'
        p.write_text(p.read_text() + "\ndel MODULES['leaf']\n")
        self.assertEqual(
            self.repo.select()[1]['error']['code'], 'deleted-module-without-proof'
        )
        p.write_text(
            p.read_text()
            + "from dataclasses import replace\nMODULES['other'] = replace(MODULES['other'], replaces=('leaf',))\n"
        )
        decision = self.repo.select()[1]
        self.assert_selected(decision, [], ['other'])
        self.assertEqual(
            decision['removedModules'], [{'module': 'leaf', 'successors': ['other']}]
        )

    def test_test_input_selects_owner_and_assertion_changes(self):
        self.repo.change('crates/leaf/tests/behavior.rs', 'assert!(false);')
        self.assert_selected(
            self.repo.select()[1], ['leaf', 'leaf-integration'], ['leaf']
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
        self.assertIn('leaf', decision['t2']['modules'])
        self.assertNotIn('other-integration', decision['t2']['modules'])

    def test_lock_comment_does_not_select_business(self):
        p = self.repo.root / 'Cargo.lock'
        p.write_text(p.read_text() + '\n# comment\n')
        self.assert_selected(self.repo.select()[1], [], [])

    def test_makefile_and_policy_select_tools_only(self):
        for path in ('Makefile', 'deny.toml'):
            self.repo.change(path, '# tool input\n')
            decision = self.repo.select()[1]
            self.assert_selected(decision, [], [])
            self.assertEqual(decision['toolTests'], ['test_registry'])

    def test_shared_controls_select_actual_runtime_consumers(self):
        registry = self.repo.root / 'hack/t2_registry.py'
        registry.write_text(
            registry.read_text()
            + "\nMODULES['host'] = Module('host', None, (), profile='none', fixtures=('identity',), python='test_registry', db_mode=None, scope=None)\n"
            + "MODULES['python-only'] = Module('python-only', None, (), profile='none', python='test_registry', db_mode=None, scope=None)\n"
        )
        self.repo.commit('declare Rust fixture and Python consumers')
        self.repo.base = self.repo.git('rev-parse', 'HEAD').stdout.strip()
        expected = sorted(
            [
                'core',
                'leaf',
                'other',
                'dev-consumer',
                'build-consumer',
                'optional-consumer',
                'leaf-integration',
                'other-integration',
                'host',
            ]
        )
        for path, content, detail in (
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
                    decision['t2'], {'mode': 'affected', 'modules': expected}
                )
                self.assertEqual(len(decision['cargo']['packages']), 8)
                self.assertEqual(decision['toolTests'], ['test_registry'])
                self.assertTrue(
                    any(r.get('detail') == detail for r in decision['reasons'])
                )

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
        self.assert_selected(self.repo.select()[1], [], ['leaf'])
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
            [],
        )

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

    def test_damaged_registry_fails_before_metadata(self):
        p = self.repo.root / 'hack/t2_registry.py'
        p.write_text(p.read_text() + "\nMODULES = {'broken': None}\n")
        decision = self.repo.select()[1]
        self.assertEqual(decision['status'], 'failed')
        self.assertEqual(decision['error']['code'], 'registry-unavailable')

    def test_optional_dependency_not_enabled_by_build_selects_no_t2(self):
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


class DependencyOwnership(unittest.TestCase):
    def test_app_external_and_dev_edges_use_explicit_seams(self):
        from dataclasses import asdict
        from ci_impact import Graph, Registry, dependency_consumers, SelectionError
        from t2_registry import APP
        from t2_model import Module, DependencyInput

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'crates/app').mkdir(parents=True)
            (root / 'Cargo.toml').write_text('[workspace]\nmembers=["crates/app"]\n')
            (root / 'crates/app/Cargo.toml').write_text(
                '[package]\nname="rss-mdm-app"\nversion="1.0.0"\n[dependencies]\ndb_driver={package="db-package",version="1"}\n[dev-dependencies]\ndb_driver={package="db-package",version="1"}\n'
            )
            dependency = {
                'name': 'db_driver',
                'pkg': 'db',
                'dep_kinds': [{'kind': None, 'target': None}],
            }
            graph = Graph(
                root,
                dict(
                    workspace_root=str(root),
                    workspace_members=['app'],
                    packages=[
                        dict(
                            id='app',
                            name='rss-mdm-app',
                            version='1.0.0',
                            source=None,
                            manifest_path=str(root / 'crates/app/Cargo.toml'),
                            dependencies=[dict(name='db-package', rename='db_driver', kind=kind) for kind in (None, 'dev')],
                        ),
                        dict(
                            id='db',
                            name='db-package',
                            version='1.2.0',
                            source='registry+test',
                        ),
                    ],
                    resolve=dict(
                        nodes=[
                            dict(id='app', deps=[dependency], features=[]),
                            dict(id='db', deps=[], features=[]),
                        ]
                    ),
                ),
            )

            def module(name, kind):
                return json.loads(
                    json.dumps(
                        asdict(
                            Module(
                                name,
                                APP,
                                ('test::',),
                                dependency_inputs=(
                                    DependencyInput(
                                        'crates/app/Cargo.toml', 'db_driver', kind
                                    ),
                                ),
                            )
                        )
                    )
                )

            registry = Registry(
                {'normal': module('normal', 'normal'), 'dev': module('dev', 'dev')},
                (),
                {},
                {},
                {},
                (),
                {},
            )
            self.assertEqual(
                dependency_consumers(graph, registry, 'app', dependency, 'normal'),
                ({'normal'}, set()),
            )
            self.assertEqual(
                dependency_consumers(graph, registry, 'app', dependency, 'dev'),
                ({'dev'}, set()),
            )
            registry = Registry({}, (), {}, {}, {}, (), {})
            with self.assertRaisesRegex(SelectionError, 'unowned-dependency'):
                dependency_consumers(graph, registry, 'app', dependency, 'normal')
            for invalid in ({}, False, {'cargoOnly': False}, {'tools': []}):
                with self.subTest(policy=invalid):
                    registry = Registry({}, (), {},
                                        {'crates/app/Cargo.toml': {'normal:db_driver': invalid}},
                                        {}, (), {})
                    with self.assertRaisesRegex(SelectionError, 'unowned-dependency'):
                        dependency_consumers(graph, registry, 'app', dependency, 'normal')
            registry = Registry(
                {},
                (),
                {},
                {
                    'crates/app/Cargo.toml': {
                        'normal:db_driver': {'tools': ['test_registry']}
                    }
                },
                {},
                (),
                {},
            )
            self.assertEqual(
                dependency_consumers(graph, registry, 'app', dependency, 'normal'),
                (set(), {'test_registry'}),
            )

    def test_lock_identity_and_checksum_changes_use_old_and_new_consumers(self):
        from ci_impact import Graph, Registry, Change, analyze_dependencies
        from t2_model import Module, Build
        from dataclasses import asdict

        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            graphs = []
            registries = []
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
                module = Module(
                    label,
                    Build('service'),
                    ('test::',),
                    production_inputs=('crates/service/src/*',),
                )
                registries.append(
                    Registry(
                        {label: json.loads(json.dumps(asdict(module)))},
                        (),
                        {},
                        {},
                        {},
                        (),
                        {},
                    )
                )
            packages, modules, tools, reasons = analyze_dependencies(
                parent / 'old',
                parent / 'new',
                [Change('M', 'Cargo.lock', 'Cargo.lock')],
                graphs,
                registries,
            )
            self.assertEqual(packages, {'service'})
            self.assertEqual(modules, {'old', 'new'})
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
                    registries,
                )[1],
                {'old', 'new'},
            )


if __name__ == '__main__':
    unittest.main()
