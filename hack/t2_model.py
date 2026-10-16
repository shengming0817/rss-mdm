"""T2 execution descriptions and policy validation; no selection or registration."""

from __future__ import annotations
from dataclasses import dataclass, replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class DependencyInput:
    owner_manifest: str
    dependency: str
    kind: str = 'normal'


@dataclass(frozen=True, order=True)
class Build:
    package: str
    kind: str = 'lib'
    target: str = ''
    features: tuple[str, ...] = ()

    def cargo_args(self):
        args = ['--locked', '-p', self.package]
        args += ['--lib'] if self.kind == 'lib' else ['--' + self.kind, self.target]
        if self.features:
            args += ['--features', ','.join(self.features)]
        return args


@dataclass(frozen=True)
class CasePolicy:
    selector: str
    db_mode: str | None
    scope: str | None
    fixtures: tuple[str, ...] | None = None

    actors: tuple[tuple[str, str], ...] | None = None
    configuration_devices: int | None = None
    materials: tuple[str, ...] | None = None

    def matches(self, name):
        return (
            name.startswith(self.selector)
            if self.selector.endswith('::')
            else name == self.selector
        )


@dataclass(frozen=True)
class Module:
    id: str
    build: Build | None
    selectors: tuple[str, ...]
    profile: str = 'product'
    fixtures: tuple[str, ...] = ()
    production_inputs: tuple[str, ...] = ()
    test_inputs: tuple[str, ...] = ()
    support_inputs: tuple[str, ...] = ()
    db_mode: str | None = 'reuse'
    scope: str | None = 'objects'
    policies: tuple[CasePolicy, ...] = ()
    python: str | None = None
    children: tuple[str, ...] = ()
    expected_cases: int | None = None
    dependency_inputs: tuple[DependencyInput, ...] = ()

    actors: tuple[tuple[str, str], ...] = ()
    configuration_devices: int = 0
    materials: tuple[str, ...] = ()

    @property
    def postgres(self):
        return self.profile != 'none'

    @property
    def tools(self):
        result = {'python3'}
        if self.build:
            result.update(('cargo', 'cargo-nextest'))
        if self.postgres or 'gateway' in self.fixtures or 'idp' in self.fixtures or 's3' in self.fixtures or 'scep' in self.fixtures:
            result.add('docker')
        if self.postgres or set(self.fixtures) & {
            's3',
            'tls',
            'windows',
            'apple',
            'scep',
            'apns',
        }:
            result.add('openssl')
        if self.id == 'windows.declared':
            result.add('xmlsec1')
        if 'homebrew' in self.fixtures:
            result.add('brew')
        if 'git' in self.fixtures:
            result.add('/usr/bin/git')
        if set(self.fixtures) & {'scep', 'oracle'}:
            result.add('go')
        return tuple(sorted(result))

    def includes(self, test):
        return any(
            not item or (test.startswith(item) if item.endswith('::') else test == item)
            for item in self.selectors
        )


def resolve_cases(module, names):
    """Resolve the discovered set before selection, so stale exceptions never disappear."""
    for policy in module.policies:
        if not any(policy.matches(name) for name in names):
            raise ValueError('stale case policy: ' + module.id + ': ' + policy.selector)
    resolved = []
    for name in names:
        matches = [policy for policy in module.policies if policy.matches(name)]
        if len(matches) > 1:
            raise ValueError('overlapping case policies: ' + module.id + ': ' + name)
        value = module
        if matches:
            policy = matches[0]
            value = replace(
                module,
                db_mode=policy.db_mode,
                scope=policy.scope,
                fixtures=module.fixtures
                if policy.fixtures is None
                else policy.fixtures,
                actors=module.actors if policy.actors is None else policy.actors,
                configuration_devices=module.configuration_devices if policy.configuration_devices is None else policy.configuration_devices,
                materials=module.materials if policy.materials is None else policy.materials,
            )
        if 'identity' not in value.fixtures:
            value = replace(value, actors=())
        if (len(set(value.actors)) != len(value.actors)
                or any(side not in {'tenant', 'peer'} or role not in {'admin', 'other'}
                       or side == 'peer' and value.scope != 'pair' for side, role in value.actors)
                or type(value.configuration_devices) is not int or value.configuration_devices < 0):
            raise ValueError('invalid preparation needs: ' + module.id + ': ' + name)
        allowed_materials = {'windows-weak-csr', 'windows-rogue-client', 'windows-renewal', 'pki-recovery',
                             'agent-long-lived', 'other'}
        if len(set(value.materials)) != len(value.materials) or set(value.materials) - allowed_materials:
            raise ValueError('invalid cryptographic materials: ' + module.id + ': ' + name)
        if 'agent_pki' in value.fixtures and value.db_mode == 'reuse' and value.scope == 'objects' and (value.materials or value.configuration_devices):
            raise ValueError('mutable CA material requires private tenant: ' + module.id + ': ' + name)
        if value.profile == 'none':
            valid = value.db_mode is None and value.scope is None
        else:
            valid = (
                value.db_mode in {'reuse', 'fresh', 'instance'}
                and value.scope in {'objects', 'tenant', 'pair'}
                and (value.profile != 'empty' or value.db_mode == 'fresh')
            )
        if not valid:
            raise ValueError('invalid database policy: ' + module.id + ': ' + name)
        if (
            'local_worker' in value.fixtures
            and value.db_mode == 'reuse'
            and value.scope == 'objects'
            or {'local_worker', 'shared_worker'} <= set(value.fixtures)
        ):
            raise ValueError(
                'conflicting consumer ownership: ' + module.id + ': ' + name
            )
        resolved.append(replace(value, policies=()))
    return resolved


def all_tools(root=ROOT):
    return sorted(path.stem for path in (root / 'tests').glob('test_*.py'))
