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
        untracked = run(['/usr/bin/git', 'ls-files', '-z', '--others', '--exclude-standard'], root)
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


REGISTRY_ATTRIBUTES = {
    't1': 'T1_INPUTS',
    'tools': 'TOOL_INPUTS',
    'dependencies': 'DEPENDENCY_POLICIES',
    'controls': 'CONTROL_INPUTS',
    'toolOnly': 'TOOL_ONLY_INPUTS',
    'representatives': 'REPRESENTATIVE_INPUTS',
}


def registry_data(registry):
    data = {'modules': {name: asdict(module) for name, module in registry.MODULES.items()}}
    data.update(
        {
            name: getattr(registry, attr) if name in {'t1', 'tools'} else getattr(registry, attr, {})
            for name, attr in REGISTRY_ATTRIBUTES.items()
        }
    )
    return json.loads(json.dumps(data))


EXPORT = """
from dataclasses import asdict
import json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(sys.argv[1]) / 'hack'))
import t2_registry as registry
attributes = json.loads(sys.argv[2])
data = {'modules': {name: asdict(module) for name, module in registry.MODULES.items()}}
data.update({name: getattr(registry, attr) if name in {'t1', 'tools'} else getattr(registry, attr, {})
             for name, attr in attributes.items()})
print(json.dumps(data))
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
    """Check selection ownership; execution policy belongs to the runner."""
    try:
        modules = data['modules']
        for name, module in modules.items():
            if module['id'] != name:
                raise ValueError('module id mismatch')
            module.setdefault('dependency_inputs', [])
            module.setdefault('replaces', [])
            for field in ('production_inputs', 'test_inputs', 'support_inputs'):
                if not all(valid_path(path) for path in module[field]):
                    raise ValueError('invalid input path')
            for dep in module['dependency_inputs']:
                if (
                    not valid_path(dep['owner_manifest'])
                    or not dep['dependency']
                    or dep['kind'] not in {'normal', 'dev', 'build'}
                ):
                    raise ValueError('invalid dependency ownership')
        if not all(valid_path(path) for path in data['t1']):
            raise ValueError('invalid T1 input')
        for path, tests in data['tools'].items():
            if not valid_path(path) or not all(test.startswith('test_') for test in tests):
                raise ValueError('invalid tool ownership')
        if not set(data['toolOnly']) <= data['tools'].keys():
            raise ValueError('missing tool owner')
        for path, names in data['representatives'].items():
            if path not in data['toolOnly'] or not set(names) <= modules.keys():
                raise ValueError('invalid representative proof')
        return Registry(
            modules,
            tuple(data['t1']),
            data['tools'],
            data['dependencies'],
            data['controls'],
            tuple(data['toolOnly']),
            data['representatives'],
        )
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        raise SelectionError('registry-invalid') from error


def snapshot(root):
    result = run([sys.executable, '-I', '-B', '-c', EXPORT, str(root), json.dumps(REGISTRY_ATTRIBUTES)], root)
    if result.returncode:
        raise SelectionError('registry-unavailable')
    try:
        return validate_registry(strict_json(result.stdout))
    except (ValueError, UnicodeDecodeError) as error:
        raise SelectionError('registry-invalid') from error


def current_registry():
    import t2_registry as r

    return validate_registry(registry_data(r))


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
    kind: str = ''


def path_inputs(path, registry):
    if is_docs(path):
        return Inputs((), (), 'documentation')
    tools = set(registry.tools.get(path, ()))
    if path.startswith('tests/test_') and path.endswith('.py'):
        tools.add(Path(path).stem)
    tools = tuple(sorted(tools))
    if path in registry.tool_only:
        proof = tuple(sorted(registry.representatives.get(path, ())))
        return Inputs(proof, tools, 'representative' if proof else 'tool')
    for fields in (('test_inputs', 'support_inputs'), ('production_inputs',)):
        owners = tuple(
            sorted(
                name
                for name, module in registry.modules.items()
                if any(matches(path, module[field]) for field in fields)
            )
        )
        if owners:
            return Inputs(owners, tools, 'business')
        if fields[0] == 'test_inputs' and matches(path, registry.t1):
            return Inputs((), tools, 'unit-test')
    if tools or path in registry.controls:
        return Inputs((), tools, 'tool')
    raise SelectionError('unmapped-input', path)


def select_inputs(paths, registry=None):
    """Use the formal selector's matcher for direct ownership behavior tests."""
    registry = registry or current_registry()
    modules, tools = set(), set()
    for path in sorted(set(paths)):
        impact = path_inputs(path, registry)
        modules.update(impact.modules)
        tools.update(impact.tools)
    return Inputs(tuple(sorted(modules)), tuple(sorted(tools)))


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
        {key: sorted(set(value)) if key in {'modules', 'packages', 'tools'} else value for key, value in reason.items()}
        for reason in reasons
    ]
    return dict(
        status='selected',
        cargo=dict(mode=cargo_mode, packages=sorted(set(cargo))),
        t2=dict(mode=t2_mode, modules=sorted(set(modules))),
        toolTests=sorted(set(tools)),
        reasons=[value for _, value in sorted({json.dumps(r, sort_keys=True): r for r in reasons}.items())],
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
    return dict(status='failed', error=dict(code=error.code, phase=phase, inputs=error.inputs))


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
                k: Path(self.packages[k]['manifest_path']).resolve().relative_to(root).as_posix() for k in self.members
            }
            self.roots = sorted(
                ((PurePosixPath(v).parent, k) for k, v in self.manifests.items()),
                key=lambda x: -len(x[0].parts),
            )
            self.identity = {
                k: ('workspace', self.manifests[k]) if k in self.members else (p['name'], p['version'], p['source'])
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
        return next((k for p, k in self.roots if candidate == p or p in candidate.parents), None)

    def closure(self, keys, *, reverse=False):
        selected, pending = set(keys), list(keys)
        while pending:
            key = pending.pop()
            deps = (
                self.reverse.get(key, ())
                if reverse
                else (d['pkg'] for d in self.nodes[key]['deps'] if any(k['kind'] != 'dev' for k in d['dep_kinds']))
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
    fields = ('test_inputs', 'support_inputs') if kind == 'dev' else ('production_inputs',)
    return {
        name for name, m in registry.modules.items() if any(p.startswith(prefix) for field in fields for p in m[field])
    }


def dependency_alias(graph, key, dep, kind):
    # Cargo has already resolved workspace inheritance and package renames.
    declarations = [d for d in graph.packages[key]['dependencies'] if (d['kind'] or 'normal') == kind]
    aliases = {
        (d.get('rename') or d['name'])
        for d in declarations
        if (d.get('rename') or d['name']).replace('-', '_') == dep['name']
    }
    if not aliases:
        aliases = {
            (d.get('rename') or d['name']) for d in declarations if d['name'] == graph.packages[dep['pkg']]['name']
        }
    if len(aliases) != 1:
        raise SelectionError('dependency-alias-unavailable', graph.manifests[key], dep['name'])
    return aliases.pop()


def optional_active(graph, key, dep, alias, kind, module, explicit):
    declarations = graph.packages[key].get('dependencies', ())
    optional = any(
        (d.get('rename') or d['name']) == alias and (d['kind'] or 'normal') == kind and d.get('optional')
        for d in declarations
    )
    if not optional:
        return True
    build = module['build']
    if not build or build['package'] != graph.packages[key]['name']:
        if explicit:
            return True  # An explicit seam includes forwarded/fixture features.
        raise SelectionError('optional-dependency-ownership', graph.manifests[key], alias)
    features = graph.packages[key]['features']
    pending = [*build['features'], *(['default'] if 'default' in features else [])]
    seen = set()
    while pending:
        feature = pending.pop()
        if feature in seen:
            continue
        seen.add(feature)
        if feature == 'dep:' + alias or feature.startswith(alias + '/') or feature == alias and feature not in features:
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
            d['owner_manifest'] == manifest and d['dependency'] == alias and d['kind'] == kind
            for d in m['dependency_inputs']
        )
    }
    policy = registry.dependencies.get(manifest, {}).get(kind + ':' + alias)
    if graph.packages[key]['name'] == 'rss-mdm-app':
        implicit = package_consumers(graph, registry, dep['pkg'], kind) if dep['pkg'] in graph.members else set()
    else:
        implicit = package_consumers(graph, registry, key, kind)
    claimed = explicit | implicit
    consumers = {
        name
        for name in claimed
        if optional_active(graph, key, dep, alias, kind, registry.modules[name], name in explicit)
    }
    if not claimed and policy is None:
        raise SelectionError('unowned-dependency', manifest, kind + ':' + alias)
    return consumers, set(policy.get('tools', ())) if policy else set()


def lock_entries(root):
    try:
        doc = tomllib.loads((root / 'Cargo.lock').read_text())
        return {(p['name'], p['version'], p.get('source')): p for p in doc.get('package', ())}
    except (OSError, ValueError, KeyError) as error:
        raise SelectionError('lock-invalid') from error


def flatten(value, prefix=()):
    if isinstance(value, dict):
        return {key: item for k, v in value.items() for key, item in flatten(v, prefix + (k,)).items()}
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


DEPENDENCY_SECTIONS = {'normal': 'dependencies', 'dev': 'dev-dependencies', 'build': 'build-dependencies'}
PACKAGE_DOC_FIELDS = {
    'description',
    'homepage',
    'repository',
    'license',
    'license-file',
    'publish',
    'readme',
    'authors',
}
WORKSPACE_CARGO_FIELDS = {'members', 'default-members', 'exclude', 'resolver', 'lints', 'metadata'}


def analyze_dependencies(oldroot, root, changes, graphs, registries):
    """Compare declarations and resolved dependencies, retaining both owners."""
    packages, modules, tools, reasons = set(), set(), set(), []
    paths = {p for c in changes for p in (c.old, c.new) if p}
    entries = [lock_entries(tree) for tree in (oldroot, root)] if 'Cargo.lock' in paths else [{}, {}]
    changed_lock = {key for key in entries[0].keys() | entries[1].keys() if entries[0].get(key) != entries[1].get(key)}
    manifest_fields = {
        p: manifest_diff(oldroot, root, p) for p in paths if p == 'Cargo.toml' or p.endswith('/Cargo.toml')
    }
    root_fields = manifest_fields.get('Cargo.toml', ())
    inherited = {f[2] for f in root_fields if len(f) > 2 and f[:2] == ('workspace', 'dependencies')}
    runtime_common, cargo_common = False, False
    for field in root_fields:
        if field[:2] == ('workspace', 'dependencies'):
            continue
        if (
            field[0] == 'profile'
            or field[:2] == ('workspace', 'package')
            and field[2] in {'version', 'edition', 'rust-version'}
        ):
            runtime_common = True
        elif (
            field[0] in {'lints', 'patch', 'replace'}
            or field[0] == 'workspace'
            and field[1] in WORKSPACE_CARGO_FIELDS
            or field[:2] == ('workspace', 'package')
            and field[2] in PACKAGE_DOC_FIELDS
        ):
            cargo_common = True
        else:
            raise SelectionError('unclassified-manifest', 'Cargo.toml', '.'.join(field))
    features = [{g.identity[key]: set(node['features']) for key, node in g.nodes.items()} for g in graphs]
    changed_nodes = {
        key for key in features[0].keys() | features[1].keys() if features[0].get(key) != features[1].get(key)
    }
    for g, reg in zip(graphs, registries):
        seeds = set()
        for key, manifest in g.manifests.items():
            fields = manifest_fields.get(manifest, ())
            behavioral = any(
                f[0] not in set(DEPENDENCY_SECTIONS.values()) | {'target', 'lints'}
                and not (f[0] == 'package' and f[1] in PACKAGE_DOC_FIELDS)
                for f in fields
            )
            if behavioral or runtime_common:
                consumers = package_consumers(g, reg, key)
                if g.packages[key]['name'] == 'rss-mdm-app':
                    consumers = {
                        n for n, m in reg.modules.items() if m['build'] and m['build']['package'] == 'rss-mdm-app'
                    }
                seeds.add(key)
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
            # Parse only changed/inheriting manifests, once per revision and owner.
            document = tomllib.loads((g.root / manifest).read_text()) if inherited else {}
            for dep in g.nodes[key]['deps']:
                reachable = g.closure({dep['pkg']})
                resolved_change = bool({g.identity[node] for node in reachable} & changed_nodes)
                resolved_change |= bool(
                    {
                        (g.packages[node]['name'], g.packages[node]['version'], g.packages[node]['source'])
                        for node in reachable
                    }
                    & changed_lock
                )
                if not fields and not inherited and not resolved_change:
                    continue
                for dk in dep['dep_kinds']:
                    kind = dk['kind'] or 'normal'
                    alias = dependency_alias(g, key, dep, kind)
                    section = DEPENDENCY_SECTIONS[kind]
                    changed_declaration = any(
                        len(f) > 1
                        and f[:2] == (section, alias)
                        or len(f) > 3
                        and f[0] == 'target'
                        and f[2:4] == (section, alias)
                        for f in fields
                    )
                    declarations = [document, *document.get('target', {}).values()]
                    changed_declaration |= alias in inherited and any(
                        isinstance(owner.get(section, {}).get(alias), dict)
                        and owner[section][alias].get('workspace') is True
                        for owner in declarations
                    )
                    if not changed_declaration and not resolved_change:
                        continue
                    consumers, owned_tools = dependency_consumers(g, reg, key, dep, kind)
                    seeds.add(key)
                    modules.update(consumers)
                    tools.update(owned_tools)
                    reasons.append(
                        dict(
                            kind='tool' if owned_tools and not consumers else 'business',
                            input=manifest + ':' + kind + ':' + alias,
                            modules=sorted(consumers),
                            tools=sorted(owned_tools),
                            detail='dependency',
                        )
                    )
        packages.update(g.names(g.closure(seeds, reverse=True)))
    return packages & graphs[1].names(graphs[1].members), modules, tools, reasons


def runtime_consumers(registry):
    return {name for name, module in registry.modules.items() if module['build'] or 'identity' in module['fixtures']}


def analyze_controls(oldroot, root, changes, registries):
    packages_all, modules, tools, reasons = False, set(), set(), []
    paths = {p for change in changes for p in (change.old, change.new) if p}
    for path in sorted(paths & (registries[0].controls.keys() | registries[1].controls.keys())):
        policies = [reg.controls[path] for reg in registries if path in reg.controls]
        for policy in policies:
            tools.update(policy.get('tools', ()))
        formats = {policy['format'] for policy in policies}
        if formats == {'tools'}:
            continue
        try:
            texts = [(tree / path).read_text() if (tree / path).exists() else '' for tree in (oldroot, root)]
            if 'make' in formats:
                compiler = [
                    sorted(
                        line.strip()
                        for line in text.splitlines()
                        if not line.lstrip().startswith('#')
                        and re.search(
                            r'\b(?:RUSTFLAGS|CARGO_ENCODED_RUSTFLAGS|RUSTC|RUSTC_WRAPPER|CARGO_BUILD_TARGET|CARGO_BUILD_RUSTFLAGS)\b',
                            line,
                        )
                    )
                    for text in texts
                ]
                runtime = ['shared-compiler-environment'] if compiler[0] != compiler[1] else []
            else:
                fields = [flatten(tomllib.loads(text)) for text in texts]
                changed = {
                    '.'.join(key)
                    for key in fields[0].keys() | fields[1].keys()
                    if fields[0].get(key) != fields[1].get(key)
                }
                runtime = []
                for field in sorted(changed):
                    categories = {
                        category
                        for policy in policies
                        for prefix, category in policy.get('fields', {}).items()
                        if field == prefix or field.startswith(prefix + '.')
                    }
                    if not categories:
                        raise SelectionError('unclassified-config', path, field)
                    if 'runtime' in categories:
                        runtime.append(field)
        except (OSError, ValueError) as error:
            raise SelectionError('config-invalid', path) from error
        if runtime:
            packages_all = True
            consumers = set().union(*(runtime_consumers(reg) for reg in registries))
            modules.update(consumers)
            for field in runtime:
                reasons.append(
                    dict(
                        kind='business',
                        input=path if 'make' in formats else path + ':' + field,
                        modules=sorted(consumers),
                        detail=field if 'make' in formats else 'shared-runtime',
                    )
                )
    return packages_all, modules, tools, reasons


def module_behavior(module, tool_only):
    if module is None:
        return None
    return {
        key: [path for path in value if path not in tool_only] if key == 'support_inputs' else value
        for key, value in module.items()
        if key != 'dependency_inputs'
    }


def select(root, base):
    changes = changed_paths(root, base)
    paths = {path for change in changes for path in (change.old, change.new) if path}
    if not paths:
        return selected([], [])
    if all(is_docs(path) and not path.startswith('crates/') for path in paths):
        return selected([], [], reasons=[dict(kind='documentation', input='docs-only', modules=[])])
    with baseline_tree(root, base) as oldroot:
        before, after = snapshot(oldroot), snapshot(root)
        modules, tools, packages, reasons, removed = set(), set(), set(), [], []
        for name in before.modules.keys() | after.modules.keys():
            old, new = before.modules.get(name), after.modules.get(name)
            if module_behavior(old, after.tool_only) != module_behavior(new, after.tool_only):
                modules.add(name)
                reasons.append(dict(kind='business', input='module-description:' + name, modules=[name]))
            if new is None:
                successors = {n for n, module in after.modules.items() if name in module['replaces']}
                if not successors:
                    raise SelectionError('deleted-module-without-proof', name)
                modules.update(successors)
                removed.append(dict(module=name, successors=sorted(successors)))
        for path in before.representatives.keys() | after.representatives.keys():
            old, new = set(before.representatives.get(path, ())), set(after.representatives.get(path, ()))
            if old != new:
                modules.update(old | new)
                reasons.append(dict(kind='representative', input=path, modules=sorted(old | new)))
        cargo_inputs = any(p.startswith('crates/') or p in {'Cargo.toml', 'Cargo.lock'} for p in paths)
        graphs = (metadata(oldroot), metadata(root)) if cargo_inputs else (None, None)
        for path in sorted(paths):
            if path in {'Cargo.toml', 'Cargo.lock'} or path.endswith('/Cargo.toml'):
                continue
            # Treat each rename/copy endpoint independently. A stable path may
            # retain its old owner after a mapping is removed or migrated.
            owners = [(after, None)] if path in after.tool_only else zip((before, after), graphs)
            claimed = False
            for registry, graph in owners:
                try:
                    impact = path_inputs(path, registry)
                except SelectionError:
                    continue
                claimed = True
                consumers = set(impact.modules)
                if path in after.tool_only:
                    consumers.update(before.representatives.get(path, ()))
                modules.update(consumers)
                tools.update(impact.tools)
                reasons.append(
                    dict(
                        kind='representative' if path in after.tool_only and consumers else impact.kind,
                        input=path,
                        modules=sorted(consumers),
                        tools=list(impact.tools),
                    )
                )
                if graph:
                    owner = graph.owner(path)
                    if owner:
                        packages.update(graph.names(graph.closure({owner}, reverse=True)))
            if not claimed:
                raise SelectionError('unmapped-input', path)
        if cargo_inputs:
            p, m, t, r = analyze_dependencies(oldroot, root, changes, graphs, (before, after))
            packages.update(p)
            modules.update(m)
            tools.update(t)
            reasons.extend(r)
            packages &= graphs[1].names(graphs[1].members)
        all_cargo, m, t, r = analyze_controls(oldroot, root, changes, (before, after))
        modules.update(m)
        tools.update(t)
        reasons.extend(r)
        missing = modules - after.modules.keys() - {item['module'] for item in removed}
        if missing:
            raise SelectionError('proof-module-unavailable', *sorted(missing))
        if all_cargo:
            current_graph = graphs[1] or metadata(root)
            packages = current_graph.names(current_graph.members)
        if not tools <= set(all_tools(root)):
            raise SelectionError('tool-test-unavailable', *sorted(tools - set(all_tools(root))))
        return selected(
            packages,
            modules & after.modules.keys(),
            tools,
            reasons,
            removed=sorted(removed, key=lambda item: item['module']),
        )


def selection_targets(values, allowed):
    if not isinstance(values, list) or values != sorted(set(values)) or not set(values) <= set(allowed):
        raise ValueError('invalid selection targets')
    return set(values)


def validate_selection(decision, packages, modules, tools):
    try:
        if decision['status'] != 'selected':
            error = decision['error']
            raise SelectionError(error['code'], *error['inputs'])
        for key, field, allowed, modes in (
            ('cargo', 'packages', packages, {'affected', 'all'}),
            ('t2', 'modules', modules, {'affected', 'all', 'module'}),
        ):
            item = decision[key]
            values = selection_targets(item[field], allowed)
            if item['mode'] not in modes or item['mode'] == 'all' and values != set(allowed):
                raise ValueError('invalid selection mode')
        selection_targets(decision['toolTests'], tools)
        if not isinstance(decision['reasons'], list) or not isinstance(decision['removedModules'], list):
            raise ValueError('invalid selection evidence')
        removed = set()
        for record in decision['removedModules']:
            name = record['module']
            if not isinstance(name, str) or not name or name in modules or name in removed:
                raise ValueError('invalid removed module')
            removed.add(name)
            if not selection_targets(record['successors'], decision['t2']['modules']):
                raise ValueError('missing successor proof')
        for reason in decision['reasons']:
            if (
                reason['kind']
                not in {'business', 'tool', 'representative', 'explicit-full', 'unit-test', 'documentation'}
                or not isinstance(reason['input'], str)
                or not reason['input']
            ):
                raise ValueError('invalid selection reason')
            for field, allowed in (('modules', set(modules) | removed), ('packages', packages), ('tools', tools)):
                selection_targets(reason.get(field, []), allowed)
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
