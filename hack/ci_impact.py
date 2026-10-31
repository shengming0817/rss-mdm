"""One affected selector: current input owners and baseline/current Cargo facts.

ref: cargo src/cargo/ops/cargo_output_metadata.rs@8a925ac84ebfd768f4bae0825b0badb9f7a75a54
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
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

from ci_registry import ROOT, all_tools

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
            if not re.fullmatch(r'[ADM]|[RC](100|0[0-9]{2}|[0-9]{1,2})', status):
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

@dataclass(frozen=True)
class Registry:
    t1: tuple
    tools: dict
    controls: dict
    consumers: dict
    t2: dict

def current_registry(root=ROOT):
    # Only current ownership is executable. Baseline metadata describes Cargo, not old tests.
    result = run([sys.executable, '-I', '-B', '-c',
        "import sys,json;sys.path.insert(0,sys.argv[1]);import ci_registry as r;"
        "print(json.dumps([r.T1_INPUTS,r.TOOL_INPUTS,r.CONTROL_INPUTS,r.T1_CONSUMERS,r.T2_INPUTS]))",
        str(root / 'hack')], root)
    if result.returncode:
        raise analysis_failure('registry-unavailable', 'current', 'registry', result)
    try:
        t1, tools, controls, consumers, t2 = strict_json(result.stdout)
        if not all(valid_path(p) for p in (*t1, *tools, *controls, *consumers)):
            raise ValueError('invalid registry input')
        if any(not isinstance(t, str) or not t.startswith('test_') for tests in tools.values() for t in tests):
            raise ValueError('invalid tool owner')
        if not all(isinstance(name, str) and patterns and all(valid_path(p) for p in patterns)
                   for name, patterns in t2.items()):
            raise ValueError("invalid T2 input")
        return Registry(tuple(t1), tools, controls, consumers, t2)
    except (ValueError, TypeError, AttributeError) as error:
        raise SelectionError('registry-invalid') from error

def analysis_failure(code, version, stage, result=None):
    diagnostic = 'invalid-analysis-result'
    if result is not None and result.returncode:
        text = result.stderr.decode(errors='replace')
        diagnostic = next(
            (
                label
                for token, label in (
                    ('lock file', 'lock-resolution'),
                    ('failed to parse manifest', 'manifest-parse'),
                    ('failed to fetch', 'dependency-fetch'),
                    ('failed to download', 'dependency-fetch'),
                    ('failed to select', 'dependency-resolution'),
                )
                if token in text
            ),
            'process-failed',
        )
        exception = re.search(
            r'(?m)^(TypeError|ValueError|NameError|ImportError|ModuleNotFoundError|SyntaxError|AttributeError|RuntimeError|OSError|KeyError):',
            text,
        )
        if stage == 'registry' and exception:
            diagnostic = exception.group(1)
    inputs = [f'version={version}', f'stage={stage}', f'diagnostic={diagnostic}']
    if result is not None:
        inputs.append(f'exit={result.returncode}')
    return SelectionError(code, *inputs)

def matches(path, patterns):
    return any(fnmatchcase(path, pattern) for pattern in patterns)

def is_package_path(path):
    return path.startswith(('crates/', 'apps/'))

def is_docs(path):
    return (
        path.startswith(('docs/', '.github/project-template/'))
        or path.endswith('.md')
        or path in {'LICENSE', 'LICENSE.md', '.gitignore'}
    )

@dataclass(frozen=True)
class Inputs:
    tools: tuple
    kind: str = ''

def path_inputs(path, registry, *, production=False):
    if is_docs(path):
        return Inputs((), 'documentation')
    tools = set(registry.tools.get(path, ()))
    if path.startswith('tests/test_') and path.endswith('.py'):
        tools.add(Path(path).stem)
    if tools or path in registry.controls:
        return Inputs(tuple(sorted(tools)), 'tool')
    if matches(path, registry.t1) or any(matches(path, (p,)) for p in registry.consumers):
        return Inputs((), 'unit-test')
    if any(matches(path, patterns) for patterns in registry.t2.values()):
        return Inputs((), 'business' if production else 'integration-test')
    if production:
        return Inputs((), 'business')
    raise SelectionError('unmapped-input', path)

def select_inputs(paths, registry=None):
    registry = registry or current_registry()
    tools, graph = set(), None
    for path in sorted(set(paths)):
        try:
            impact = path_inputs(path, registry)
        except SelectionError:
            graph = graph or metadata(ROOT)
            impact = path_inputs(path, registry, production=graph.production(path))
        tools.update(impact.tools)
    return Inputs(tuple(sorted(tools)))

def selected(cargo, tools=(), reasons=(), *, cargo_mode='affected', ownership_packages=(), t2=(), t2_mode='affected'):
    return dict(status='selected', cargo=dict(mode=cargo_mode, packages=sorted(set(cargo))),
                toolTests=sorted(set(tools)), reasons=list(reasons),
                ownershipPackages=sorted(set(ownership_packages)),
                t2=dict(mode=t2_mode, modules=sorted(set(t2))))

def explicit_selection(packages, tools=()):
    return selected(packages, tools, [dict(kind='explicit-full', input='requested-mode')],
                    cargo_mode='all', ownership_packages=packages,
                    t2=current_registry().t2, t2_mode='all')

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
                        self.reverse[dep['pkg']].add((key, any(k['kind'] != 'dev' for k in dep['dep_kinds'])))
        except (KeyError, TypeError, ValueError) as error:
            raise SelectionError('metadata-invalid') from error

    def owner(self, path):
        candidate = PurePosixPath(path)
        return next((k for p, k in self.roots if candidate == p or p in candidate.parents), None)

    def production(self, path):
        owner = self.owner(path)
        if owner is None:
            return False
        relative = PurePosixPath(path).relative_to(PurePosixPath(self.manifests[owner]).parent)
        return relative.parts[0] in {'src', 'schema', 'migrations'} or str(relative) == 'build.rs'

    def closure(self, keys, *, reverse=False):
        selected, pending, tests = set(keys), list(keys), set()
        while pending:
            key = pending.pop()
            edges = (self.reverse.get(key, ()) if reverse else
                     ((d['pkg'], True) for d in self.nodes[key]['deps']
                      if any(k['kind'] != 'dev' for k in d['dep_kinds'])))
            for dep, production in edges:
                if not production:
                    tests.add(dep)
                elif dep not in selected:
                    selected.add(dep)
                    pending.append(dep)
        return selected | tests

    def names(self, keys):
        return {self.packages[k]['name'] for k in keys if k in self.members}

def metadata(root, version='current'):
    result = run(
        ['cargo', 'metadata', '--locked', '--all-features', '--format-version', '1'],
        root,
    )
    if result.returncode:
        raise analysis_failure('metadata-unavailable', version, 'metadata', result)
    try:
        return Graph(root, strict_json(result.stdout))
    except (ValueError, UnicodeDecodeError, SelectionError) as error:
        raise analysis_failure('metadata-invalid', version, 'metadata', result) from error

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

def lock_entries(root):
    try:
        doc = tomllib.loads((root / 'Cargo.lock').read_text())
        packages = doc.get('package', ())
        entries = {}
        for package in packages:
            normalized = dict(package)
            normalized['dependencies'] = sorted(lock_dependency(dep, packages) for dep in package.get('dependencies', ()))
            entries[(package['name'], package['version'], package.get('source'))] = normalized
        return entries
    except (OSError, ValueError, KeyError) as error:
        raise SelectionError('lock-invalid') from error

def lock_dependency(reference, packages):
    # Cargo adds version/source qualifiers when a new duplicate name is introduced.
    # Compare resolved identities, so serialization-only changes do not affect consumers.
    fields = reference.split(' ', 2)
    matches = [p for p in packages if p['name'] == fields[0]
               and (len(fields) < 2 or p['version'] == fields[1])
               and (len(fields) < 3 or lock_source_matches(p.get('source'), fields[2].removeprefix('(').removesuffix(')')))]
    if len(matches) != 1:
        raise SelectionError('lock-invalid')
    package = matches[0]
    return package['name'], package['version'], package.get('source') or ''

def lock_source_matches(source, reference):
    # Cargo's Git dependency qualifier omits the resolved commit fragment.
    # Keep URL/revision exact, and require the fragment when one was supplied.
    if source == reference:
        return True
    return (isinstance(source, str) and source.startswith('git+')
            and '#' not in reference and source.rsplit('#', 1)[0] == reference)

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

def analyze_dependencies(oldroot, root, changes, graphs):
    """Select Cargo checks only; dependencies do not imply business T2."""
    packages, reasons = set(), []
    paths = {p for c in changes for p in (c.old, c.new) if p}
    # Security scans own the complete dependency inputs, even when a changed
    # lock entry has no current workspace consumer and selects no Cargo package.
    reasons.extend(dict(kind='tool', input=path, detail='dependency')
                   for path in sorted(paths)
                   if path in {'Cargo.toml', 'Cargo.lock'} or path.endswith('/Cargo.toml'))
    entries = [lock_entries(tree) for tree in (oldroot, root)] if 'Cargo.lock' in paths else [{}, {}]
    changed_lock = {key for key in entries[0].keys() | entries[1].keys() if entries[0].get(key) != entries[1].get(key)}
    manifest_fields = {
        p: manifest_diff(oldroot, root, p) for p in paths if p == 'Cargo.toml' or p.endswith('/Cargo.toml')
    }
    root_fields = manifest_fields.get('Cargo.toml', ())
    inherited = {f[2] for f in root_fields if len(f) > 2 and f[:2] == ('workspace', 'dependencies')}
    cargo_common = False
    for field in root_fields:
        if field[:2] == ('workspace', 'dependencies'):
            continue
        if (
            field[0] == 'profile'
            or field[:2] == ('workspace', 'package')
            and field[2] in {'version', 'edition', 'rust-version'}
        ):
            cargo_common = True
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
    for g in graphs:
        seeds = set(g.members) if cargo_common else set()
        test_seeds = set()
        for key, manifest in g.manifests.items():
            fields = manifest_fields.get(manifest, ())
            behavioral = any(
                f[0] not in set(DEPENDENCY_SECTIONS.values()) | {'target', 'lints'}
                and not (f[0] == 'package' and f[1] in PACKAGE_DOC_FIELDS)
                for f in fields
            )
            if behavioral:
                seeds.add(key)
                reasons.append(dict(kind='tool', input=manifest, detail='build-description'))
            # Parse only changed/inheriting manifests, once per revision and owner.
            document = tomllib.loads((g.root / manifest).read_text()) if inherited else {}
            for dep in g.nodes[key]['deps']:
                reachable = g.closure({dep['pkg']})
                resolved_change = bool({g.identity[node] for node in reachable} & changed_nodes)
                resolved_change |= bool(
                    {
                        (g.packages[node]['name'], g.packages[node]['version'], g.packages[node]['source'])
                        for node in reachable if node not in g.members
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
                    (test_seeds if kind == 'dev' else seeds).add(key)
                    reasons.append(dict(kind='tool', input=manifest + ':' + kind + ':' + alias,
                                        detail='dependency'))
        packages.update(g.names(g.closure(seeds, reverse=True) | test_seeds))
    return packages & graphs[1].names(graphs[1].members), reasons

def analyze_controls(oldroot, root, changes, registry):
    packages_all, tools, reasons = False, set(), []
    paths = {p for change in changes for p in (change.old, change.new) if p}
    for path in sorted(paths & registry.controls.keys()):
        policies = [registry.controls[path]]
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
            for field in runtime:
                reasons.append(
                    dict(
                        kind='tool',
                        input=path if 'make' in formats else path + ':' + field,
                        detail=field if 'make' in formats else 'shared-runtime',
                    )
                )
    return packages_all, tools, reasons

def select(root, base):
    changes = changed_paths(root, base)
    paths = {p for c in changes for p in (c.old, c.new) if p}
    if not paths:
        return selected([])
    if all(is_docs(p) and not is_package_path(p) for p in paths):
        return selected([], reasons=[dict(kind='documentation', input='docs-only')])
    current = current_registry(root)
    if any(t not in all_tools(root) for tests in current.tools.values() for t in tests):
        raise SelectionError('tool-test-unavailable')
    with baseline_tree(root, base) as oldroot:
        cargo_inputs = any(is_package_path(p) or p.endswith('.rs') or p in {'Cargo.toml','Cargo.lock'} for p in paths)
        graphs = (metadata(oldroot, 'baseline:' + base), metadata(root)) if cargo_inputs else (None, None)
        packages, tools, reasons = set(), set(), []
        for path in sorted(paths):
            if path in {'Cargo.toml','Cargo.lock'} or path.endswith('/Cargo.toml'):
                continue
            present = (root / path).is_file()
            production = any(g and g.production(path) for g in graphs)
            if not present:
                # A Git-proven removed carrier has no current execution owner.
                # Current paths (including rename destinations) still require explicit ownership.
                if not (oldroot / path).is_file():
                    raise SelectionError('unmapped-input', path)
                reasons.append(dict(kind='removed-input', input=path))
            else:
                impact = path_inputs(path, current, production=production)
                tools.update(impact.tools)
                reasons.append(dict(kind=impact.kind, input=path))
            for g in graphs:
                if g:
                    owner = g.owner(path)
                    if owner:
                        relative = PurePosixPath(path).relative_to(PurePosixPath(g.manifests[owner]).parent)
                        packages.update(g.names({owner} if relative.parts[0] == 'tests' else g.closure({owner}, reverse=True)))
            for pattern, consumers in current.consumers.items():
                if matches(path, (pattern,)):
                    packages.update(consumers)
        if cargo_inputs:
            p, r = analyze_dependencies(oldroot, root, changes, graphs)
            packages.update(p); reasons.extend(r)
            packages &= graphs[1].names(graphs[1].members)
        all_cargo, t, r = analyze_controls(oldroot, root, changes, current)
        tools.update(t); reasons.extend(r)
        if all_cargo:
            graph = graphs[1] or metadata(root)
            packages = graph.names(graph.members)
        if not tools <= set(all_tools(root)):
            raise SelectionError('tool-test-unavailable', *sorted(tools - set(all_tools(root))))
        return selected(packages, tools, reasons, ownership_packages=packages,
                        t2=[name for name, patterns in current.t2.items()
                            if any(matches(path, patterns) for path in paths)])

def selection_targets(values, allowed):
    if not isinstance(values, list) or values != sorted(set(values)) or not set(values) <= set(allowed):
        raise ValueError('invalid selection targets')
    return set(values)

def validate_selection(decision, packages, tools):
    try:
        if decision['status'] != 'selected':
            error = decision['error']
            raise SelectionError(error['code'], *error['inputs'])
        cargo = decision['cargo']
        chosen = selection_targets(cargo['packages'], packages)
        if cargo['mode'] not in {'affected','all'} or cargo['mode'] == 'all' and chosen != set(packages):
            raise ValueError('invalid Cargo mode')
        integration = decision['t2']
        modules = selection_targets(integration['modules'], current_registry().t2)
        if integration['mode'] not in {'affected', 'all'} or integration['mode'] == 'all' and modules != set(current_registry().t2):
            raise ValueError('invalid T2 selection')
        selection_targets(decision['toolTests'], tools)
        selection_targets(decision['ownershipPackages'], chosen)
        for reason in decision['reasons']:
            if reason['kind'] not in {'business','tool','unit-test','integration-test','documentation','explicit-full','removed-input'} or not isinstance(reason['input'],str) or not reason['input']:
                raise ValueError('invalid reason')
        return decision
    except SelectionError:
        raise
    except (KeyError,TypeError,ValueError,AttributeError) as error:
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
