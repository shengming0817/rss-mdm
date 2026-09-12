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
FORBIDDEN = {'rss-mdm-app', 'axum', 'reqwest', 'hyper', 'sqlx-mysql', 'sqlx-sqlite'}


def verify_closure(data, product_source, pin, locked):
    packages = {p['id']: p for p in data['packages']}
    nodes = {n['id']: n for n in data['resolve']['nodes']}
    root = data['resolve']['root']
    ci.require(data['workspace_members'] == [root] and packages[root]['source'] is None,
               'consumer must be the sole local member')
    ci.require(set(packages) == set(nodes), 'incomplete resolved graph')
    direct = nodes[root]['deps']
    ci.require({packages[d['pkg']]['name'] for d in direct} == DIRECT, 'unexpected consumer direct dependency')
    ci.require(all(d['dep_kinds'] == [{'kind': None, 'target': None}] for d in direct), 'consumer requires normal edges')
    adapter = [p['id'] for p in packages.values() if p['name'] == 'rss-mdm-group-postgres']
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
        if name in PRODUCTS:
            ci.require(source == product_source, 'product source must equal tested Git SHA')
            found.add(name)
        elif name in RSS:
            ci.require(source == upstream, 'RSS source must equal product pin')
            found.add(name)
        else:
            ci.require(not name.startswith('rss-'), f'unrelated product/RSS dependency: {name}')
            ci.require((name, p['version'], source) in locked and source == 'registry+https://github.com/rust-lang/crates.io-index', f'dependency differs from product lock: {name}')
        ci.require('integration' not in nodes[key]['features'], 'test feature leaked into production consumer')
        if name == 'rss-mdm-group-postgres':
            ci.require(nodes[key]['features'] == [], 'extend matrix when adapter production features change')
        if name == 'rss-transactional-messaging':
            ci.require(nodes[key]['features'] == ['producer'], 'consumer must select only producer')
    ci.require(found == PRODUCTS | RSS, 'missing required product/RSS closure')


def run_consumer(source, base, defaults, head, pin, out):
    name = 'default' if defaults else 'no-default'
    root = base / name
    (root / 'tests').mkdir(parents=True)
    check_ancestors(root)
    shutil.copytree(source / 'crates/group-postgres/tests/support', root / 'tests/support')
    shutil.copyfile(source / 'crates/group-postgres/tests/consumer.rs', root / 'tests/consumer.rs')
    shutil.copyfile(source / 'rust-toolchain.toml', root / 'rust-toolchain.toml')
    shutil.copyfile(source / 'Cargo.lock', root / 'Cargo.lock')
    deps = ci.tomllib.loads((source / 'Cargo.toml').read_text())['workspace']['dependencies']
    manifest = '[workspace]\n[package]\nname="group-pg-consumer"\nversion="0.0.0"\nedition="2024"\n[dependencies]\n'
    manifest += f'rss-mdm-group-postgres={{git={json.dumps(source.as_uri())},rev="{head}",default-features={str(defaults).lower()}}}\n'
    for dep in sorted(DIRECT - {'rss-mdm-group-postgres'}):
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

    def run(args, extra=None):
        result = subprocess.run(args, cwd=root, env={**env, **(extra or {})}, stdin=subprocess.DEVNULL, capture_output=True, text=True)
        with log.open('a') as stream:
            stream.write(json.dumps(args) + '\n' + result.stderr)
            if args[:2] != ['cargo', 'metadata']:
                stream.write(result.stdout)
        commands.append({'argv': args, 'exitCode': result.returncode})
        ci.require(result.returncode == 0, f'{name} failed; see {log}')
        return result.stdout

    toolchain = {'rustc': run(['rustc', '-Vv']), 'cargo': run(['cargo', '-V'])}
    run(['cargo', 'metadata', '--format-version', '1'])
    lock_hash = hashlib.sha256((root / 'Cargo.lock').read_bytes()).hexdigest()
    data = json.loads(run(['cargo', 'metadata', '--locked', '--format-version', '1']))
    locked = {(p['name'], p['version'], p.get('source')) for p in ci.tomllib.loads((source / 'Cargo.lock').read_text())['package'] if p.get('source', '').startswith('registry+')}
    verify_closure(data, f'git+{source.as_uri()}?rev={head}#{head}', pin, locked)
    (out / f'{name}-metadata.json').write_text(json.dumps(data))
    (out / f'{name}-tree.txt').write_text(run(['cargo', 'tree', '--locked', '-e', 'features']))
    run(['cargo', 'check', '--locked', '--all-targets'])
    run(['cargo', 'test', '--locked', '--no-run'])
    # Schema is installed from this consumer's exact public dependencies as well.
    (root / 'examples').mkdir()
    shutil.copyfile(source / 'crates/group-postgres/examples/migrations.rs', root / 'examples/migrations.rs')
    migration = run(['cargo', 'run', '--locked', '--quiet', '--example', 'migrations'])
    with pg.fixture(migrations=migration) as (fixture_env, _):
        result = run(['cargo', 'test', '--locked', '--test', 'consumer', '--', '--ignored', '--test-threads=1'],
                     {'GROUP_PG_CONFIG': fixture_env['GROUP_PG_CONFIG']})
        pg.verify_tests(result, pg.CONSUMER_TESTS)
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
