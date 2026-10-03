"""One affected selector: versioned descriptions, Cargo facts, explicit ownership.

ref: cargo src/cargo/ops/cargo_output_metadata.rs@8a925ac84ebfd768f4bae0825b0badb9f7a75a54
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
from fnmatch import fnmatchcase
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import tempfile
import tomllib

from t2_model import ROOT, all_tools


class SelectionError(RuntimeError):
    def __init__(self, code, *inputs):
        self.code = code
        self.inputs = list(inputs)
        super().__init__(code + (': ' + ', '.join(inputs) if inputs else ''))


def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=unique)


def run(args, root):
    try:
        return subprocess.run(
            args,
            cwd=root,
            capture_output=True,
            env={**os.environ, 'GIT_TERMINAL_PROMPT': '0'},
        )
    except OSError as error:
        raise SelectionError('command-unavailable', args[0]) from error


def valid_path(path):
    return (
        isinstance(path, str)
        and bool(path)
        and '\x00' not in path
        and not PurePosixPath(path).is_absolute()
        and '..' not in PurePosixPath(path).parts
    )


@dataclass(frozen=True, order=True)
class Change:
    status: str
    old: str = ''
    new: str = ''


def changed_paths(root, base):
    result = run(
        [
            '/usr/bin/git',
            'diff',
            '--name-status',
            '-z',
            '--find-renames',
            '--find-copies',
            '--find-copies-harder',
            base,
            '--',
        ],
        root,
    )
    if result.returncode:
        raise SelectionError('diff-unavailable', base)
    try:
        fields = result.stdout.decode().split('\0')
        if fields[-1] != '':
            raise ValueError('unterminated diff')
        fields.pop()
        changes, cursor = set(), 0
        while cursor < len(fields):
            status = fields[cursor]
            cursor += 1
            if not re.fullmatch(r'[ADM]|[RC](100|[0-9]{1,2})', status):
                raise ValueError('invalid status')
            count = 2 if status[0] in 'RC' else 1
            paths = fields[cursor : cursor + count]
            cursor += count
            if len(paths) != count or not all(valid_path(p) for p in paths):
                raise ValueError('invalid path')
            changes.add(
                Change(
                    status[0],
                    paths[0] if status[0] != 'A' else '',
                    paths[-1] if status[0] != 'D' else '',
                )
            )
        untracked = run(
            ['/usr/bin/git', 'ls-files', '-z', '--others', '--exclude-standard'], root
        )
        if untracked.returncode:
            raise SelectionError('diff-unavailable', base)
        for path in filter(None, untracked.stdout.decode().split('\0')):
            if not valid_path(path):
                raise ValueError('invalid untracked path')
            changes.add(Change('A', new=path))
        return sorted(changes)
    except (ValueError, UnicodeDecodeError) as error:
        raise SelectionError('diff-invalid') from error


@contextmanager
def baseline_tree(root, base):
    result = run(['/usr/bin/git', 'archive', '--format=tar', base], root)
    if result.returncode:
        raise SelectionError('base-unavailable', base)
    with tempfile.TemporaryDirectory(prefix='rss-mdm-impact-') as directory:
        with tarfile.open(fileobj=io.BytesIO(result.stdout)) as archive:
            archive.extractall(directory, filter='data')
        yield Path(directory).resolve()


EXPORT = """
import dataclasses, json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(sys.argv[1]) / 'hack'))
import t2_registry as r
print(json.dumps(dict(modules={k:dataclasses.asdict(v) for k,v in r.MODULES.items()},
                     t1=list(r.T1_INPUTS), tools=r.TOOL_INPUTS,
                     dependencies=getattr(r, 'DEPENDENCY_POLICIES', {}),
                     controls=getattr(r, 'CONTROL_INPUTS', {}), toolOnly=list(getattr(r, 'TOOL_ONLY_INPUTS', ())), representatives=getattr(r, 'REPRESENTATIVE_INPUTS', {}))))
"""


@dataclass(frozen=True)
class Registry:
    modules: dict
    t1: tuple
    tools: dict
    dependencies: dict
    controls: dict
    tool_only: tuple
    representatives: dict


def validate_registry(data):
    try:
        modules = data['modules']
        if not isinstance(modules, dict) or not isinstance(data['tools'], dict):
            raise ValueError('invalid descriptions')
        for name, module in modules.items():
            if not isinstance(name, str) or module['id'] != name:
                raise ValueError('invalid module id')
            # Optional ownership annotations did not exist on historic descriptions.
            # This projection reads facts, never runs a historic selection algorithm.
            module.setdefault('dependency_inputs', [])
            module.setdefault('replaces', [])
            for field in ('production_inputs', 'test_inputs', 'support_inputs'):
                if not isinstance(module[field], list) or not all(
                    valid_path(p) for p in module[field]
                ):
                    raise ValueError('invalid input patterns')
            for field in ('selectors', 'fixtures', 'children', 'replaces'):
                if not isinstance(module[field], list) or not all(
                    isinstance(v, str) and (v or field == 'selectors')
                    for v in module[field]
                ):
                    raise ValueError('invalid module list')
            if (
                not isinstance(module['profile'], str)
                or not module['profile']
                or module['db_mode'] not in {None, 'reuse', 'fresh', 'instance'}
                or module['scope'] not in {None, 'objects', 'tenant', 'pair'}
            ):
                raise ValueError('invalid environment policy')
            if (module['profile'] == 'none') != (
                module['db_mode'] is None and module['scope'] is None
            ):
                raise ValueError('inconsistent environment policy')
            if module['profile'] == 'empty' and module['db_mode'] != 'fresh':
                raise ValueError('empty profile must be fresh')
            if module['build'] is not None:
                build = module['build']
                if (
                    not isinstance(build['package'], str)
                    or not build['package']
                    or build['kind'] not in {'lib', 'bin', 'test', 'example', 'bench'}
                    or not isinstance(build['target'], str)
                    or not isinstance(build['features'], list)
                    or not all(isinstance(f, str) and f for f in build['features'])
                ):
                    raise ValueError('invalid build')
            if not isinstance(module['dependency_inputs'], list):
                raise ValueError('invalid dependency inputs')
            for dep in module['dependency_inputs']:
                if (
                    not valid_path(dep['owner_manifest'])
                    or not dep['owner_manifest'].endswith('Cargo.toml')
                    or not isinstance(dep['dependency'], str)
                    or not dep['dependency']
                    or dep['kind'] not in {'normal', 'dev', 'build'}
                ):
                    raise ValueError('invalid dependency input')
            if not isinstance(module['policies'], list):
                raise ValueError('invalid policies')
            for policy in module['policies']:
                if (
                    not isinstance(policy['selector'], str)
                    or not policy['selector']
                    or policy['db_mode'] not in {None, 'reuse', 'fresh', 'instance'}
                    or policy['scope'] not in {None, 'objects', 'tenant', 'pair'}
                    or policy['fixtures'] is not None
                    and (
                        not isinstance(policy['fixtures'], list)
                        or not all(isinstance(f, str) for f in policy['fixtures'])
                    )
                ):
                    raise ValueError('invalid case policy')
            if module['build'] is not None and not module['selectors']:
                raise ValueError('missing executable selector')
            if module['build'] is None and not module['python']:
                raise ValueError('missing executable carrier')
        if not isinstance(data['t1'], list) or not all(
            valid_path(p) for p in data['t1']
        ):
            raise ValueError('invalid T1 inputs')
        for path, tests in data['tools'].items():
            if (
                not valid_path(path)
                or not isinstance(tests, list)
                or not all(isinstance(t, str) and t.startswith('test_') for t in tests)
            ):
                raise ValueError('invalid tool inputs')
        for path, names in data['representatives'].items():
            if path not in data['toolOnly'] or not set(names) <= modules.keys():
                raise ValueError('invalid representative proof')
        if (
            not isinstance(data['toolOnly'], list)
            or not set(data['toolOnly']) <= data['tools'].keys()
        ):
            raise ValueError('invalid tool-only ownership')
        if not isinstance(data['dependencies'], dict) or not isinstance(
            data['controls'], dict
        ):
            raise ValueError('invalid input policy')
        for manifest, entries in data['dependencies'].items():
            if not valid_path(manifest) or not isinstance(entries, dict):
                raise ValueError('invalid dependency policy')
            for edge, policy in entries.items():
                if (
                    not isinstance(edge, str)
                    or edge.split(':')[0] not in {'normal', 'build', 'dev'}
                    or not isinstance(policy, dict)
                    or not (policy.get('cargoOnly') is True or policy.get('tools'))
                ):
                    raise ValueError('unowned dependency policy')
        return Registry(
            modules,
            tuple(data['t1']),
            data['tools'],
            data['dependencies'],
            data['controls'],
            tuple(data['toolOnly']),
            data['representatives'],
        )
    except (KeyError, TypeError, ValueError) as error:
        raise SelectionError('registry-invalid') from error


def snapshot(root):
    result = run([sys.executable, '-I', '-B', '-c', EXPORT, str(root)], root)
    if result.returncode:
        raise SelectionError('registry-unavailable')
    try:
        return validate_registry(strict_json(result.stdout))
    except (ValueError, UnicodeDecodeError) as error:
        raise SelectionError('registry-invalid') from error


def current_registry():
    import t2_registry as r

    return validate_registry(
        dict(
            modules={
                k: json.loads(json.dumps(asdict(v))) for k, v in r.MODULES.items()
            },
            t1=list(r.T1_INPUTS),
            tools={k: list(v) for k, v in r.TOOL_INPUTS.items()},
            dependencies=r.DEPENDENCY_POLICIES,
            controls=r.CONTROL_INPUTS,
            toolOnly=list(r.TOOL_ONLY_INPUTS),
            representatives=r.REPRESENTATIVE_INPUTS,
        )
    )


def matches(path, patterns):
    return any(fnmatchcase(path, pattern) for pattern in patterns)


def is_docs(path):
    return (
        path.startswith(('docs/', '.github/project-template/'))
        or path.endswith('.md')
        or path in {'LICENSE', 'LICENSE.md', '.gitignore'}
    )


@dataclass(frozen=True)
class Inputs:
    modules: tuple
    tools: tuple
    reasons: tuple


def path_inputs(path, registry):
    if is_docs(path):
        return Inputs((), (), ('documentation:' + path,))
    tools = set(registry.tools.get(path, ()))
    if path.startswith('tests/test_') and path.endswith('.py'):
        tools.add(Path(path).stem)
    if path in registry.tool_only:
        return Inputs(
            tuple(sorted(registry.representatives.get(path, ()))),
            tuple(sorted(tools)),
            ('tool-input:' + path,),
        )
    found = {
        name
        for name, m in registry.modules.items()
        if matches(path, m['test_inputs'] + m['support_inputs'])
    }
    if found:
        return Inputs(
            tuple(sorted(found)), tuple(sorted(tools)), ('test-input:' + path,)
        )
    if matches(path, registry.t1):
        return Inputs((), tuple(sorted(tools)), ('unit-test:' + path,))
    found = {
        name
        for name, m in registry.modules.items()
        if matches(path, m['production_inputs'])
    }
    if found:
        return Inputs(
            tuple(sorted(found)), tuple(sorted(tools)), ('production:' + path,)
        )
    if tools or path in registry.controls:
        return Inputs((), tuple(sorted(tools)), ('tool-input:' + path,))
    raise SelectionError('unmapped-input', path)


def select_inputs(paths, registry=None):
    """Pure path matching used by the one selector and ownership behavior tests."""
    registry = registry or current_registry()
    modules, tools, reasons = set(), set(), set()
    for path in sorted(set(paths)):
        inputs = path_inputs(path, registry)
        modules.update(inputs.modules)
        tools.update(inputs.tools)
        reasons.update(inputs.reasons)
    return Inputs(tuple(sorted(modules)), tuple(sorted(tools)), tuple(sorted(reasons)))


def selected(
    cargo,
    modules,
    tools=(),
    reasons=(),
    *,
    cargo_mode='affected',
    t2_mode='affected',
    removed=(),
):
    reasons = [
        {
            key: sorted(set(value))
            if key in {'modules', 'packages', 'tools'}
            else value
            for key, value in reason.items()
        }
        for reason in reasons
    ]
    return dict(
        status='selected',
        cargo=dict(mode=cargo_mode, packages=sorted(set(cargo))),
        t2=dict(mode=t2_mode, modules=sorted(set(modules))),
        toolTests=sorted(set(tools)),
        reasons=[
            value
            for _, value in sorted(
                {json.dumps(r, sort_keys=True): r for r in reasons}.items()
            )
        ],
        removedModules=list(removed),
    )


def explicit_selection(packages, modules, tools=(), *, cargo_mode='all', t2_mode='all'):
    return selected(
        packages,
        modules,
        tools,
        [
            dict(
                kind='explicit-full',
                input='requested-mode',
                packages=sorted(packages) if cargo_mode == 'all' else [],
                modules=sorted(modules) if t2_mode == 'all' else [],
            )
        ],
        cargo_mode=cargo_mode,
        t2_mode=t2_mode,
    )


def failure(error, phase):
    return dict(
        status='failed', error=dict(code=error.code, phase=phase, inputs=error.inputs)
    )


class Graph:
    def __init__(self, root, data):
        root = Path(root).resolve()
        try:
            if Path(data['workspace_root']).resolve() != root:
                raise ValueError('workspace root mismatch')
            self.packages = {p['id']: p for p in data['packages']}
            self.nodes = {n['id']: n for n in data['resolve']['nodes']}
            self.members = set(data['workspace_members'])
            if (
                len(self.packages) != len(data['packages'])
                or len(self.nodes) != len(data['resolve']['nodes'])
                or not self.members <= self.packages.keys()
                or not self.members <= self.nodes.keys()
            ):
                raise ValueError('incomplete metadata')
            self.root = root
            self.manifests = {
                k: Path(self.packages[k]['manifest_path'])
                .resolve()
                .relative_to(root)
                .as_posix()
                for k in self.members
            }
            self.by_manifest = {v: k for k, v in self.manifests.items()}
            self.roots = sorted(
                ((PurePosixPath(v).parent, k) for k, v in self.manifests.items()),
                key=lambda x: -len(x[0].parts),
            )
            self.identity = {
                k: ('workspace', self.manifests[k])
                if k in self.members
                else (p['name'], p['version'], p['source'])
                for k, p in self.packages.items()
            }
            self.reverse = {k: set() for k in self.members}
            for key, node in self.nodes.items():
                for dep in node['deps']:
                    if (
                        dep['pkg'] not in self.packages
                        or dep['pkg'] not in self.nodes
                        or not isinstance(dep['dep_kinds'], list)
                    ):
                        raise ValueError('invalid dependency edge')
                    if key in self.members and dep['pkg'] in self.members:
                        self.reverse[dep['pkg']].add(key)
        except (KeyError, TypeError, ValueError) as error:
            raise SelectionError('metadata-invalid') from error

    def owner(self, path):
        candidate = PurePosixPath(path)
        return next(
            (k for p, k in self.roots if candidate == p or p in candidate.parents), None
        )

    def closure(self, keys, *, reverse=False):
        selected, pending = set(keys), list(keys)
        while pending:
            key = pending.pop()
            deps = (
                self.reverse.get(key, ())
                if reverse
                else (
                    d['pkg']
                    for d in self.nodes[key]['deps']
                    if any(k['kind'] != 'dev' for k in d['dep_kinds'])
                )
            )
            for dep in deps:
                if dep not in selected:
                    selected.add(dep)
                    pending.append(dep)
        return selected

    def names(self, keys):
        return {self.packages[k]['name'] for k in keys if k in self.members}


def metadata(root):
    result = run(
        ['cargo', 'metadata', '--locked', '--all-features', '--format-version', '1'],
        root,
    )
    if result.returncode:
        raise SelectionError('metadata-unavailable')
    try:
        return Graph(root, strict_json(result.stdout))
    except (ValueError, UnicodeDecodeError) as error:
        raise SelectionError('metadata-invalid') from error


def package_consumers(graph, registry, key, kind='normal'):
    if graph.packages[key]['name'] == 'rss-mdm-app':
        return set()  # App is an assembly package, not a semantic dependency seed.
    prefix = str(PurePosixPath(graph.manifests[key]).parent) + '/'
    fields = (
        ('test_inputs', 'support_inputs') if kind == 'dev' else ('production_inputs',)
    )
    return {
        name
        for name, m in registry.modules.items()
        if any(p.startswith(prefix) for field in fields for p in m[field])
    }


def dependency_alias(graph, key, dep, kind):
    manifest = tomllib.loads((graph.root / graph.manifests[key]).read_text())
    workspace = (
        tomllib.loads((graph.root / 'Cargo.toml').read_text())
        .get('workspace', {})
        .get('dependencies', {})
    )
    section = {
        'normal': 'dependencies',
        'build': 'build-dependencies',
        'dev': 'dev-dependencies',
    }[kind]
    declarations = dict(manifest.get(section, {}))
    for values in manifest.get('target', {}).values():
        declarations.update(values.get(section, {}))
    direct = [alias for alias in declarations if alias.replace('-', '_') == dep['name']]
    if len(direct) == 1:
        return direct[0]
    names = []
    for alias, value in declarations.items():
        if isinstance(value, dict) and value.get('workspace'):
            value = (
                {**workspace.get(alias, {}), **value}
                if isinstance(workspace.get(alias), dict)
                else value
            )
        package = value.get('package', alias) if isinstance(value, dict) else alias
        if package == graph.packages[dep['pkg']]['name']:
            names.append(alias)
    if len(names) != 1:
        raise SelectionError(
            'dependency-alias-unavailable', graph.manifests[key], dep['name']
        )
    return names[0]


def optional_active(graph, key, dep, alias, kind, module, explicit):
    declarations = graph.packages[key].get('dependencies', ())
    optional = any(
        (d.get('rename') or d['name']) == alias
        and (d['kind'] or 'normal') == kind
        and d.get('optional')
        for d in declarations
    )
    if not optional:
        return True
    build = module['build']
    if not build or build['package'] != graph.packages[key]['name']:
        if explicit:
            return True  # An explicit seam includes forwarded/fixture features.
        raise SelectionError(
            'optional-dependency-ownership', graph.manifests[key], alias
        )
    features = graph.packages[key]['features']
    pending = [*build['features'], *(['default'] if 'default' in features else [])]
    seen = set()
    while pending:
        feature = pending.pop()
        if feature in seen:
            continue
        seen.add(feature)
        if (
            feature == 'dep:' + alias
            or feature.startswith(alias + '/')
            or feature == alias
            and feature not in features
        ):
            return True
        pending.extend(features.get(feature, ()))
    return False


def dependency_consumers(graph, registry, key, dep, kind):
    manifest = graph.manifests[key]
    alias = dependency_alias(graph, key, dep, kind)
    explicit = {
        name
        for name, m in registry.modules.items()
        if any(
            d['owner_manifest'] == manifest
            and d['dependency'] == alias
            and d['kind'] == kind
            for d in m['dependency_inputs']
        )
    }
    policy = registry.dependencies.get(manifest, {}).get(kind + ':' + alias)
    if graph.packages[key]['name'] == 'rss-mdm-app':
        implicit = (
            package_consumers(graph, registry, dep['pkg'], kind)
            if dep['pkg'] in graph.members
            else set()
        )
    else:
        implicit = package_consumers(graph, registry, key, kind)
    claimed = explicit | implicit
    consumers = {
        name
        for name in claimed
        if optional_active(
            graph, key, dep, alias, kind, registry.modules[name], name in explicit
        )
    }
    if not claimed and policy is None:
        raise SelectionError('unowned-dependency', manifest, kind + ':' + alias)
    return consumers, set(policy.get('tools', ())) if policy else set()


def lock_entries(root):
    try:
        doc = tomllib.loads((root / 'Cargo.lock').read_text())
        return {
            (p['name'], p['version'], p.get('source')): p
            for p in doc.get('package', ())
        }
    except (OSError, ValueError, KeyError) as error:
        raise SelectionError('lock-invalid') from error


def flatten(value, prefix=()):
    if isinstance(value, dict):
        return {
            key: item
            for k, v in value.items()
            for key, item in flatten(v, prefix + (k,)).items()
        }
    return {prefix: value}


def manifest_diff(oldroot, root, path):
    def read(tree):
        p = tree / path
        try:
            return tomllib.loads(p.read_text()) if p.exists() else {}
        except (OSError, ValueError) as error:
            raise SelectionError('manifest-invalid', path) from error

    a, b = flatten(read(oldroot)), flatten(read(root))
    return {k for k in a.keys() | b.keys() if a.get(k) != b.get(k)}


def analyze_dependencies(oldroot, root, changes, graphs, registries):
    """Changed resolved nodes and declaration edges, with both consumer owners."""
    packages, modules, tools, reasons = set(), set(), set(), []
    oldgraph, graph = graphs
    oldreg, registry = registries
    lock_changed = any(c.old == 'Cargo.lock' or c.new == 'Cargo.lock' for c in changes)
    entries = (lock_entries(oldroot), lock_entries(root)) if lock_changed else ({}, {})
    changed_lock = {
        k
        for k in entries[0].keys() | entries[1].keys()
        if entries[0].get(k) != entries[1].get(k)
    }
    manifest_paths = {
        p
        for c in changes
        for p in (c.old, c.new)
        if p and (p == 'Cargo.toml' or p.endswith('/Cargo.toml'))
    }
    manifest_fields = {p: manifest_diff(oldroot, root, p) for p in manifest_paths}
    # Root inheritance changes propagate to member entries using that alias.
    inherited = {
        field[2]
        for field in manifest_fields.get('Cargo.toml', ())
        if len(field) > 2 and field[:2] == ('workspace', 'dependencies')
    }
    features = [
        {g.identity[k]: set(node['features']) for k, node in g.nodes.items()}
        for g in graphs
    ]
    changed_features = {
        k
        for k in features[0].keys() | features[1].keys()
        if features[0].get(k) != features[1].get(k)
    }
    common = {
        field
        for field in manifest_fields.get('Cargo.toml', ())
        if not (len(field) > 1 and field[:2] == ('workspace', 'dependencies'))
    }
    runtime_common = set()
    cargo_common = set()
    for field in common:
        if (
            field[0] == 'profile'
            or field[:2] == ('workspace', 'package')
            and len(field) > 2
            and field[2] in {'version', 'edition', 'rust-version'}
        ):
            runtime_common.add(field)
        elif (
            field[0] in {'lints', 'patch', 'replace'}
            or field[:2]
            in {
                ('workspace', 'members'),
                ('workspace', 'default-members'),
                ('workspace', 'exclude'),
                ('workspace', 'resolver'),
                ('workspace', 'lints'),
                ('workspace', 'metadata'),
            }
            or field[:2] == ('workspace', 'package')
            and len(field) > 2
            and field[2]
            in {
                'description',
                'homepage',
                'repository',
                'license',
                'license-file',
                'publish',
                'readme',
                'authors',
            }
        ):
            cargo_common.add(field)
        else:
            raise SelectionError('unclassified-manifest', 'Cargo.toml', '.'.join(field))
    for g, reg in zip(graphs, registries):
        seeds = set()
        for key, manifest in g.manifests.items():
            fields = manifest_fields.get(manifest, set())
            dependency_fields = {
                'dependencies',
                'dev-dependencies',
                'build-dependencies',
                'target',
            }
            behavioral = {
                f
                for f in fields
                if f[0] not in dependency_fields | {'lints'}
                and not (
                    f[:2]
                    in {
                        ('package', 'description'),
                        ('package', 'homepage'),
                        ('package', 'repository'),
                        ('package', 'license'),
                        ('package', 'publish'),
                        ('package', 'readme'),
                    }
                )
            }
            if behavioral or runtime_common:
                seeds.add(key)
                consumers = package_consumers(g, reg, key)
                if g.packages[key]['name'] == 'rss-mdm-app':
                    consumers = {
                        n
                        for n, m in reg.modules.items()
                        if m['build'] and m['build']['package'] == 'rss-mdm-app'
                    }
                modules.update(consumers)
                reasons.append(
                    dict(
                        kind='business',
                        input=manifest if behavioral else 'Cargo.toml',
                        modules=sorted(consumers),
                        detail='build-description',
                    )
                )
            if cargo_common:
                seeds.add(key)
            for dep in g.nodes[key]['deps']:
                for dk in dep['dep_kinds']:
                    kind = dk['kind'] or 'normal'
                    alias = dependency_alias(g, key, dep, kind)
                    sections = {
                        'normal': 'dependencies',
                        'dev': 'dev-dependencies',
                        'build': 'build-dependencies',
                    }
                    changed_declaration = alias in {
                        f[1] for f in fields if len(f) > 1 and f[0] == sections[kind]
                    }
                    changed_declaration |= any(
                        len(f) > 3
                        and f[0] == 'target'
                        and f[2] == sections[kind]
                        and f[3] == alias
                        for f in fields
                    )
                    # Resolve workspace aliases from the actual manifest, not package names.
                    manifest_doc = tomllib.loads(
                        (oldroot if g is oldgraph else root)
                        .joinpath(manifest)
                        .read_text()
                    )
                    declaration = manifest_doc.get(sections[kind], {}).get(alias, {})
                    changed_declaration |= (
                        alias in inherited
                        and isinstance(declaration, dict)
                        and declaration.get('workspace') is True
                    )
                    reachable = g.closure({dep['pkg']})
                    hit = (
                        changed_declaration
                        or bool({g.identity[k] for k in reachable} & changed_features)
                        or bool(
                            {
                                (
                                    g.packages[k]['name'],
                                    g.packages[k]['version'],
                                    g.packages[k]['source'],
                                )
                                for k in reachable
                            }
                            & changed_lock
                        )
                    )
                    if not hit:
                        continue
                    consumers, owned_tools = dependency_consumers(
                        g, reg, key, dep, kind
                    )
                    seeds.add(key)
                    modules.update(consumers)
                    tools.update(owned_tools)
                    reasons.append(
                        dict(
                            kind='tool'
                            if owned_tools and not consumers
                            else 'business',
                            input=manifest + ':' + kind + ':' + alias,
                            modules=sorted(consumers),
                            tools=sorted(owned_tools),
                            detail='dependency',
                        )
                    )
        packages.update(g.names(g.closure(seeds, reverse=True)))
    packages &= graph.names(graph.members)
    return packages, modules, tools, reasons


def analyze_controls(oldroot, root, changes, registries):
    packages_all = False
    modules = set()
    tools = set()
    reasons = []
    for c in changes:
        for path, tree, registry in (
            (c.old, oldroot, registries[0]),
            (c.new, root, registries[1]),
        ):
            if not path or path not in registry.controls:
                continue
            policy = registry.controls[path]
            tools.update(policy.get('tools', ()))
            if policy['format'] == 'tools':
                continue
            if policy['format'] == 'make':

                def compiler_environment(tree):
                    text = (tree / path).read_text() if (tree / path).exists() else ''
                    return sorted(
                        line.strip()
                        for line in text.splitlines()
                        if re.search(
                            r'\b(?:RUSTFLAGS|CARGO_ENCODED_RUSTFLAGS|RUSTC|RUSTC_WRAPPER|CARGO_BUILD_TARGET|CARGO_BUILD_RUSTFLAGS)\b',
                            line,
                        )
                        and not line.lstrip().startswith('#')
                    )

                if compiler_environment(oldroot) != compiler_environment(root):
                    packages_all = True
                    consumed = {
                        name
                        for name, m in registry.modules.items()
                        if m['build'] or 'identity' in m['fixtures']
                    }
                    modules.update(consumed)
                    reasons.append(
                        dict(
                            kind='business',
                            input=path,
                            modules=sorted(consumed),
                            detail='shared-compiler-environment',
                        )
                    )
                continue
            try:
                left = (
                    tomllib.loads((oldroot / path).read_text())
                    if (oldroot / path).exists()
                    else {}
                )
                right = (
                    tomllib.loads((root / path).read_text())
                    if (root / path).exists()
                    else {}
                )
            except (OSError, ValueError) as error:
                raise SelectionError('config-invalid', path) from error
            changed = {
                k
                for k in flatten(left).keys() | flatten(right).keys()
                if flatten(left).get(k) != flatten(right).get(k)
            }
            for field in changed:
                category = next(
                    (
                        v
                        for prefix, v in policy['fields'].items()
                        if '.'.join(field) == prefix
                        or '.'.join(field).startswith(prefix + '.')
                    ),
                    None,
                )
                if category is None:
                    raise SelectionError('unclassified-config', path, '.'.join(field))
                if category == 'runtime':
                    packages_all = True
                    consumed = {
                        name
                        for name, m in registry.modules.items()
                        if m['build'] or 'identity' in m['fixtures']
                    }
                    modules.update(consumed)
                    reasons.append(
                        dict(
                            kind='business',
                            input=path + ':' + '.'.join(field),
                            modules=sorted(consumed),
                            detail='shared-runtime',
                        )
                    )
    return packages_all, modules, tools, reasons


def select(root, base):
    changes = changed_paths(root, base)
    if not changes:
        return selected([], [])
    if all(is_docs(p) for c in changes for p in (c.old, c.new) if p) and not any(
        p.startswith('crates/') for c in changes for p in (c.old, c.new)
    ):
        return selected(
            [], [], reasons=[dict(kind='documentation', input='docs-only', modules=[])]
        )
    with baseline_tree(root, base) as oldroot:
        before, after = snapshot(oldroot), snapshot(root)
        modules, tools, reasons = set(), set(), []
        removed = []
        for name in before.modules.keys() | after.modules.keys():
            old, new = before.modules.get(name), after.modules.get(name)
            # Dependency annotations describe the selector, not executable module
            # behavior. They are verified by tool tests; changed Cargo inputs are
            # resolved through both annotations below.
            executable_old = (
                {
                    k: (
                        sorted(p for p in v if p not in after.tool_only)
                        if k == 'support_inputs'
                        else v
                    )
                    for k, v in old.items()
                    if k != 'dependency_inputs'
                }
                if old
                else None
            )
            executable_new = (
                {
                    k: (
                        sorted(p for p in v if p not in after.tool_only)
                        if k == 'support_inputs'
                        else v
                    )
                    for k, v in new.items()
                    if k != 'dependency_inputs'
                }
                if new
                else None
            )
            if executable_old != executable_new:
                modules.add(name)
                reasons.append(
                    dict(
                        kind='business',
                        input='module-description:' + name,
                        modules=[name],
                    )
                )
            if new is None:
                successors = {
                    n for n, m in after.modules.items() if name in m['replaces']
                }
                if not successors:
                    raise SelectionError('deleted-module-without-proof', name)
                modules.update(successors)
                removed.append(dict(module=name, successors=sorted(successors)))
        for path in before.representatives.keys() | after.representatives.keys():
            old_proof, new_proof = (
                set(before.representatives.get(path, ())),
                set(after.representatives.get(path, ())),
            )
            if old_proof != new_proof:
                modules.update(old_proof | new_proof)
                reasons.append(
                    dict(
                        kind='representative',
                        input=path,
                        modules=sorted(old_proof | new_proof),
                        tools=[],
                    )
                )
        need_graph = any(
            p and (p.startswith('crates/') or p == 'Cargo.toml' or p == 'Cargo.lock')
            for c in changes
            for p in (c.old, c.new)
        )
        graphs = (metadata(oldroot), metadata(root)) if need_graph else None
        packages = set()
        for c in changes:
            for path in sorted({p for p in (c.old, c.new) if p}):
                # Ownership is required per rename/copy endpoint. For a stable
                # path either revision may carry a mapping that was removed.
                if (
                    path == 'Cargo.lock'
                    or path == 'Cargo.toml'
                    or path.endswith('/Cargo.toml')
                ):
                    continue
                if path in after.tool_only:
                    tools.update(after.tools.get(path, ()))
                    representatives = set(before.representatives.get(path, ())) | set(
                        after.representatives.get(path, ())
                    )
                    modules.update(representatives)
                    reasons.append(
                        dict(
                            kind='representative' if representatives else 'tool',
                            input=path,
                            modules=sorted(representatives),
                            tools=list(after.tools.get(path, ())),
                        )
                    )
                    continue
                claimed = False
                for registry, g in (
                    (before, graphs[0] if graphs else None),
                    (after, graphs[1] if graphs else None),
                ):
                    try:
                        impact = path_inputs(path, registry)
                    except SelectionError:
                        continue
                    claimed = True
                    modules.update(impact.modules)
                    tools.update(impact.tools)
                    reasons.append(
                        dict(
                            kind='tool'
                            if impact.tools and not impact.modules
                            else 'business'
                            if impact.modules
                            else 'documentation'
                            if is_docs(path)
                            else 'unit-test',
                            input=path,
                            modules=list(impact.modules),
                            tools=list(impact.tools),
                        )
                    )
                    if g:
                        key = g.owner(path)
                        if key:
                            packages.update(g.names(g.closure({key}, reverse=True)))
                if not claimed:
                    raise SelectionError('unmapped-input', path)
        if graphs:
            p, m, t, r = analyze_dependencies(
                oldroot, root, changes, graphs, (before, after)
            )
            packages.update(p)
            modules.update(m)
            tools.update(t)
            reasons.extend(r)
            packages &= graphs[1].names(graphs[1].members)
        full, m, t, r = analyze_controls(oldroot, root, changes, (before, after))
        modules.update(m)
        tools.update(t)
        reasons.extend(r)
        unknown = modules - after.modules.keys() - {m['module'] for m in removed}
        if unknown:
            raise SelectionError('proof-module-unavailable', *sorted(unknown))
        modules &= after.modules.keys()
        if full:
            if graphs is None:
                graphs = (metadata(oldroot), metadata(root))
            packages = graphs[1].names(graphs[1].members)
        if not tools <= set(all_tools(root)):
            raise SelectionError(
                'tool-test-unavailable', *sorted(tools - set(all_tools(root)))
            )
        return selected(
            packages,
            modules,
            tools,
            reasons,
            removed=sorted(removed, key=lambda x: x['module']),
        )


def validate_selection(decision, packages, modules, tools):
    try:
        if decision['status'] != 'selected':
            e = decision['error']
            raise SelectionError(e['code'], *e['inputs'])
        for key, field, allowed, modes in (
            ('cargo', 'packages', packages, {'affected', 'all'}),
            ('t2', 'modules', modules, {'affected', 'all', 'module'}),
        ):
            item = decision[key]
            values = item[field]
            if (
                item['mode'] not in modes
                or not isinstance(values, list)
                or not all(isinstance(v, str) for v in values)
                or values != sorted(set(values))
                or not set(values) <= set(allowed)
            ):
                raise ValueError('invalid selection')
            if item['mode'] == 'all' and set(values) != set(allowed):
                raise ValueError('incomplete full selection')
        if (
            not isinstance(decision['toolTests'], list)
            or decision['toolTests'] != sorted(set(decision['toolTests']))
            or not set(decision['toolTests']) <= set(tools)
        ):
            raise ValueError('invalid tool selection')
        if not isinstance(decision['reasons'], list) or not isinstance(
            decision['removedModules'], list
        ):
            raise ValueError('invalid selection evidence')
        removed_ids = set()
        for record in decision['removedModules']:
            if (
                not isinstance(record['module'], str)
                or not record['module']
                or record['module'] in modules
                or record['module'] in removed_ids
            ):
                raise ValueError('invalid removed module')
            removed_ids.add(record['module'])
            if (
                not isinstance(record['successors'], list)
                or not record['successors']
                or record['successors'] != sorted(set(record['successors']))
                or not set(record['successors']) <= set(decision['t2']['modules'])
            ):
                raise ValueError('invalid successor proof')
        for record in decision['reasons']:
            if (
                record['kind']
                not in {
                    'business',
                    'tool',
                    'representative',
                    'explicit-full',
                    'unit-test',
                    'documentation',
                }
                or not isinstance(record['input'], str)
                or not record['input']
            ):
                raise ValueError('invalid selection reason')
            for field, allowed in (
                ('modules', set(modules) | removed_ids),
                ('packages', set(packages)),
                ('tools', set(tools)),
            ):
                values = record.get(field, [])
                if (
                    not isinstance(values, list)
                    or not all(isinstance(v, str) for v in values)
                    or values != sorted(set(values))
                    or not set(values) <= allowed
                ):
                    raise ValueError('invalid reason target')
        return decision
    except SelectionError:
        raise
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        raise SelectionError('selection-invalid') from error


def main():
    phase = 'arguments'
    try:
        if len(sys.argv) != 3 or sys.argv[1] != '--base' or not sys.argv[2]:
            raise SelectionError('invalid-arguments')
        phase = 'repository'
        result = run(['/usr/bin/git', 'rev-parse', '--show-toplevel'], Path.cwd())
        if result.returncode:
            raise SelectionError('repository-unavailable')
        root = Path(os.fsdecode(result.stdout.rstrip(b'\n'))).resolve()
        phase = 'selection'
        decision = select(root, sys.argv[2])
        print(json.dumps(decision, separators=(',', ':')))
        return 0
    except SelectionError as error:
        print(json.dumps(failure(error, phase), separators=(',', ':')))
        return 1
    except Exception as error:
        print(
            f'selector-internal phase={phase} exception={type(error).__name__}',
            file=sys.stderr,
        )
        print(
            json.dumps(
                failure(SelectionError('selector-internal'), phase),
                separators=(',', ':'),
            )
        )
        return 1


if __name__ == '__main__':
    sys.exit(main())
