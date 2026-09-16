#!/usr/bin/env python3
"""One committed Group adapter, production features and real PG, outside both workspaces."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import ci
from core_consumer import isolated_env, check_ancestors, prepare_output

spec = importlib.util.spec_from_file_location('group_t2', Path(__file__).with_name('group-t2.py'))
pg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pg)
PRODUCTS = {'rss-mdm-group-postgres', 'rss-mdm-group'}
RSS = {'rss-contract', 'rss-request-context', 'rss-diag-context', 'rss-redact',
       'rss-transactional-messaging', 'rss-transactional-messaging-postgres'}
DIRECT = {'rss-mdm-group-postgres', 'rss-contract', 'rss-request-context',
          'rss-transactional-messaging', 'rss-transactional-messaging-postgres',
          'tokio', 'sqlx', 'serde_json', 'uuid'}
FORBIDDEN = {'rss-mdm-app', 'axum', 'reqwest', 'hyper'}
def direct_dependencies(capability):
    direct = (DIRECT - {'rss-mdm-group-postgres'}) | {f'rss-mdm-{capability}-postgres'}
    # Backend contract assertions hash schema bytes; this dependency is already in each adapter closure.
    return direct if capability == 'group' else (direct - {'uuid'}) | {'sha2'}


INACTIVE_DRIVERS = {'sqlx-mysql', 'sqlx-sqlite'}


def verify_closure(data, product_source, pin, locked, capability="group"):
    ci.require(capability in {"group", "policy", "resource", "software-release"}, "unknown PG capability")
    product = f"rss-mdm-{capability}-postgres"
    products = {product, f"rss-mdm-{capability}"}
    if capability != "group": products.add("rss-mdm-backend-postgres-support")
    direct_expected = direct_dependencies(capability)
    packages = {p['id']: p for p in data['packages']}
    nodes = {n['id']: n for n in data['resolve']['nodes']}
    root = data['resolve']['root']
    ci.require(data['workspace_members'] == [root] and packages[root]['source'] is None,
               'consumer must be the sole local member')
    ci.require(set(packages) == set(nodes), 'incomplete resolved graph')
    direct = nodes[root]['deps']
    ci.require({packages[d['pkg']]['name'] for d in direct} == direct_expected, 'unexpected consumer direct dependency')
    ci.require(all(d['dep_kinds'] == [{'kind': None, 'target': None}] for d in direct), 'consumer requires normal edges')
    adapter = [p['id'] for p in packages.values() if p['name'] == product]
    ci.require(len(adapter) == 1, 'exactly one adapter required')
    reached, pending = set(), adapter[:]
    while pending:
        key = pending.pop()
        if key in reached:
            continue
        reached.add(key)
        for d in nodes[key]['deps']:
            if any(k['kind'] != 'dev' for k in d['dep_kinds']):
                pending.append(d['pkg'])
    ci.require(reached == set(packages) - {root}, 'consumer dependencies must belong to adapter closure')
    upstream = f'git+{pin[0]}?rev={pin[1]}#{pin[1]}'
    found = set()
    for key in reached:
        p = packages[key]
        name, source = p['name'], p['source']
        ci.require(not any(name == n or name.startswith(n + '-') for n in FORBIDDEN), f'forbidden adapter dependency: {name}')
        if name in products:
            ci.require(source == product_source, 'product source must equal tested Git SHA')
            found.add(name)
        elif name in RSS:
            ci.require(source == upstream, 'RSS source must equal product pin')
            found.add(name)
        else:
            ci.require(not name.startswith('rss-'), f'unrelated product/RSS dependency: {name}')
            ci.require((name, p['version'], source) in locked and source == 'registry+https://github.com/rust-lang/crates.io-index', f'dependency differs from product lock: {name}')
        ci.require('integration' not in nodes[key]['features'], 'test feature leaked into production consumer')
        if name in {product, "rss-mdm-backend-postgres-support"}:
            ci.require(nodes[key]['features'] == [], 'extend matrix when adapter production features change')
        if name == 'rss-transactional-messaging':
            ci.require(nodes[key]['features'] == ['consumer', 'default', 'producer'], 'fixed RSS PG adapter core features differ')
        if name in {'sqlx', 'sqlx-macros', 'sqlx-macros-core'}:
            ci.require(not any(f.startswith(('mysql', 'sqlite', '_sqlite', 'sqlx-mysql', 'sqlx-sqlite')) for f in nodes[key]['features']), 'non-PG driver feature enabled')
        if name in INACTIVE_DRIVERS:
            # Cargo metadata 1.96 retains SQLx's weak optional edges (e.g.
            # sqlx-sqlite?/json) even without its enabling feature. Check the
            # source of those edges and independently inspect the active tree.
            parents = {packages[n['id']]['name'] for n in nodes.values() if any(d['pkg'] == key for d in n['deps'])}
            ci.require(parents <= {'sqlx', 'sqlx-macros-core'}, 'non-PG driver has a real consumer')
    ci.require(found == products | RSS, 'missing required product/RSS closure')


def verify_active_tree(tree, capability="group"):
    ci.require(capability in {"group", "policy", "resource", "software-release"}, "unknown PG capability")
    products = {f"rss-mdm-{capability}-postgres", f"rss-mdm-{capability}"}
    if capability != "group": products.add("rss-mdm-backend-postgres-support")
    names = {line.split()[0] for line in tree.splitlines() if line.strip()}
    ci.require(products | RSS <= names and 'sqlx-postgres' in names, 'active tree is incomplete')
    ci.require(not any(name == banned or name.startswith(banned + '-') for name in names for banned in FORBIDDEN | INACTIVE_DRIVERS), 'forbidden active dependency')


def verify_no_feature_supplement(consumer, baseline):
    def features(data):
        root = data['resolve']['root']
        return {n['id']: set(n['features']) for n in data['resolve']['nodes'] if n['id'] != root}
    used, provided = features(consumer), features(baseline)
    ci.require(set(used) == set(provided), 'public consumer supplements adapter dependency closure')
    ci.require(all(used[key] <= provided[key] for key in used), 'public consumer supplements adapter features')


def run_consumer(source, base, defaults, head, pin, out, capability="group", fixture=None, config_key="GROUP_PG_CONFIG", expected_tests=None):
    ci.require(capability in {"group", "policy", "resource", "software-release"}, "unknown PG capability")
    product = f"rss-mdm-{capability}-postgres"
    direct = direct_dependencies(capability)
    store = {"group":"GroupStore", "policy":"PolicyStore", "resource":"ResourceStore", "software-release":"ReleaseStore"}[capability]
    fixture = fixture or pg.fixture
    expected_tests = pg.CONSUMER_TESTS if expected_tests is None else expected_tests
    name = 'default' if defaults else 'no-default'
    root = base / name
    (root / 'tests').mkdir(parents=True)
    check_ancestors(root)
    shutil.copytree(source / f'crates/{capability}-postgres/tests/support', root / 'tests/support')
    shutil.copyfile(source / f'crates/{capability}-postgres/tests/consumer.rs', root / 'tests/consumer.rs')
    shutil.copyfile(source / 'rust-toolchain.toml', root / 'rust-toolchain.toml')
    shutil.copyfile(source / 'Cargo.lock', root / 'Cargo.lock')
    deps = ci.tomllib.loads((source / 'Cargo.toml').read_text())['workspace']['dependencies']
    manifest = '[workspace]\n[package]\nname="group-pg-consumer"\nversion="0.0.0"\nedition="2024"\n[dependencies]\n'
    manifest += f'{product}={{git={json.dumps(source.as_uri())},rev="{head}",default-features={str(defaults).lower()}}}\n'
    for dep in sorted(direct - {product}):
        value = deps[dep]
        if dep == 'tokio':
            value = {**value, 'features': ['macros', 'rt-multi-thread', 'time']}
        if isinstance(value, str):
            manifest += f'{dep}={json.dumps(value)}\n'
        else:
            manifest += dep + '={' + ','.join(f'{k}={json.dumps(v)}' for k, v in value.items()) + '}\n'
    (root / 'Cargo.toml').write_text(manifest)
    env = isolated_env(root)
    env['CARGO_NET_GIT_FETCH_WITH_CLI'] = 'true'
    env['RUSTUP_TOOLCHAIN'] = ci.tomllib.loads((root / 'rust-toolchain.toml').read_text())['toolchain']['channel']
    # Keep Python current while forcing Cargo's Git transport to the system binary.
    (root / 'tools').mkdir()
    (root / 'tools/git').symlink_to('/usr/bin/git')
    env['PATH'] = str(root / 'tools') + os.pathsep + env.get('PATH', '')
    log = out / f'{name}.log'
    log.write_text('')
    commands = []

    def run(args, extra=None, cwd=None):
        result = subprocess.run(args, cwd=cwd or root, env={**env, **(extra or {})}, stdin=subprocess.DEVNULL, capture_output=True, text=True)
        with log.open('a') as stream:
            stream.write(json.dumps(args) + '\n' + result.stderr)
            if args[:2] != ['cargo', 'metadata']:
                stream.write(result.stdout)
        commands.append({'argv': args, 'workspace': 'adapter-only' if cwd else 'public-consumer', 'exitCode': result.returncode})
        ci.require(result.returncode == 0, f'{name} failed; see {log}')
        return result.stdout

    toolchain = {'rustc': run(['rustc', '-Vv']), 'cargo': run(['cargo', '-V'])}
    run(['cargo', 'metadata', '--format-version', '1'])
    lock_hash = hashlib.sha256((root / 'Cargo.lock').read_bytes()).hexdigest()
    data = json.loads(run(['cargo', 'metadata', '--locked', '--format-version', '1']))
    locked = {(p['name'], p['version'], p.get('source')) for p in ci.tomllib.loads((source / 'Cargo.lock').read_text())['package'] if p.get('source', '').startswith('registry+')}
    (out / f'{name}-metadata.json').write_text(json.dumps(data))
    verify_closure(data, f'git+{source.as_uri()}?rev={head}#{head}', pin, locked, capability)
    # Resolve a second workspace with literally one dependency to prove the
    # fixture's public RSS/SQLx/Tokio edges cannot supply missing features.
    baseline = root / 'adapter-only'
    (baseline / 'src').mkdir(parents=True)
    (baseline / 'src/lib.rs').write_text(f"pub use rss_mdm_{capability.replace('-', '_')}_postgres::{store};\n")
    (baseline / 'Cargo.toml').write_text('[workspace]\n[package]\nname="group-adapter-only"\nversion="0.0.0"\nedition="2024"\n[dependencies]\n' +
        f'{product}={{git={json.dumps(source.as_uri())},rev="{head}",default-features={str(defaults).lower()}}}\n')
    shutil.copyfile(root / 'Cargo.lock', baseline / 'Cargo.lock')
    baseline_env = {'CARGO_TARGET_DIR': str(baseline / 'target')}
    run(['cargo', 'metadata', '--format-version', '1'], baseline_env, baseline)
    baseline_data = json.loads(run(['cargo', 'metadata', '--locked', '--format-version', '1'], baseline_env, baseline))
    (out / f'{name}-adapter-only-metadata.json').write_text(json.dumps(baseline_data))
    verify_no_feature_supplement(data, baseline_data)
    run(['cargo', 'check', '--locked'], baseline_env, baseline)
    shutil.copyfile(baseline / 'Cargo.lock', out / f'{name}-adapter-only-Cargo.lock')
    (out / f'{name}-metadata.json').write_text(json.dumps(data))
    (out / f'{name}-tree.txt').write_text(run(['cargo', 'tree', '--locked', '-e', 'features']))
    active = run(['cargo', 'tree', '--locked', '--target', 'all', '-e', 'normal,build', '--prefix', 'none'])
    (out / f'{name}-active-tree.txt').write_text(active)
    verify_active_tree(active, capability)
    run(['cargo', 'check', '--locked', '--all-targets'])
    run(['cargo', 'test', '--locked', '--no-run'])
    # Schema is installed from this consumer's exact public dependencies as well.
    (root / 'examples').mkdir()
    example = 'migrations' if capability == 'group' else capability.replace('-', '_') + '_migrations'
    shutil.copyfile(source / f'crates/{capability}-postgres/examples/{example}.rs', root / 'examples/migrations.rs')
    migration = run(['cargo', 'run', '--locked', '--quiet', '--example', 'migrations'])
    with fixture(migrations=migration) as (fixture_env, _):
        result = run(['cargo', 'test', '--locked', '--test', 'consumer', '--', '--ignored', '--test-threads=1'],
                     {config_key: fixture_env[config_key]})
        pg.verify_tests(result, expected_tests)
    ci.require(hashlib.sha256((root / 'Cargo.lock').read_bytes()).hexdigest() == lock_hash, 'locked consumer changed its lock')
    shutil.copyfile(root / 'Cargo.lock', out / f'{name}-Cargo.lock')
    return {'head': head, 'rssRevision': pin[1], 'defaultFeatures': defaults, 'lockSha256': lock_hash,
            'features': {n['id']: n['features'] for n in data['resolve']['nodes']}, 'commands': commands,
            'status': 'passed', 'toolchain': toolchain, 'provider': pg.IMAGE, 'T3': 'not run'}


def main():
    out = ci.OUT / 'group-postgres-consumers'
    prepare_output(out)
    head = ci.command(['/usr/bin/git', 'rev-parse', 'HEAD']).stdout.strip()
    ci.require(not ci.command(['/usr/bin/git', 'status', '--porcelain']).stdout.strip(), 'commit tested source before consumer verification')
    results = []
    with tempfile.TemporaryDirectory(prefix='mdm-group-pg-consumer-', dir='/tmp') as directory:
        base = Path(directory).resolve()
        source = base / 'source'
        subprocess.run(['/usr/bin/git', 'clone', '--quiet', '--no-hardlinks', str(ci.ROOT), str(source)], check=True, env=ci.noninteractive())
        subprocess.run(['/usr/bin/git', '-C', str(source), 'checkout', '--quiet', '--detach', head], check=True, env=ci.noninteractive())
        pin = ci.workspace_pin(source)
        for defaults in (True, False):
            try:
                result = run_consumer(source, base, defaults, head, pin, out)
            except Exception as error:
                result = {'head': head, 'defaultFeatures': defaults, 'status': 'failed', 'error': str(error)}
            results.append(result)
            print(json.dumps({k: v for k, v in result.items() if k != 'features'}), flush=True)
    (out / 'result.json').write_text(json.dumps(results, indent=2) + '\n')
    return int(any(r['status'] != 'passed' for r in results))


if __name__ == '__main__':
    raise SystemExit(main())
