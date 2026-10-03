"""Prebuild once; nextest owns Rust discovery and Cargo execution environments.

ref: nextest nextest-runner/src/test_command.rs@75ddba7e911b44c5c0700dac0415d824403de9bd
"""
from __future__ import annotations

from dataclasses import dataclass
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import subprocess
import threading
import time
import xml.etree.ElementTree as ET

from build_run import lease_fds, require_lease
from t2_registry import APP, MODULES, IDENTITY_SETUP
from t2_model import ROOT, Build, Module
from verification_result import require


CASE_TIMEOUT = 600


def strict_json(value):
    def unique(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise ValueError('duplicate JSON key: ' + key)
            result[key] = item
        return result
    return json.loads(value, object_pairs_hook=unique)


@dataclass(frozen=True)
class Case:
    build: Build
    binary: str
    executable: str
    name: str

    @property
    def id(self):
        target = self.build.kind + (':' + self.build.target if self.build.target else '')
        return f'{self.build.package}/{target}[{",".join(self.build.features)}]/{self.name}'

    @property
    def key(self):
        return hashlib.sha256(self.id.encode()).hexdigest()[:20]


@dataclass(frozen=True)
class Invocation:
    module: Module
    case: Case | None
    invocation: int = 0

    @property
    def id(self):
        return self.case.id if self.case else 'python/' + self.module.id

    @property
    def key(self):
        return hashlib.sha256(f'{self.id}:{self.invocation}'.encode()).hexdigest()[:20]

    @property
    def policy(self):
        return dict(profile=self.module.profile, dbMode=self.module.db_mode,
                    scope=self.module.scope, fixtures=list(self.module.fixtures))


def validate_ownership(document, build, modules):
    """Every ignored test is executed by exactly one public owner or declared caller."""
    modules = [module for module in modules if module.build == build]
    names = []
    for binary in document['rust-suites'].values():
        if binary['package-name'] != build.package or binary['kind'] != build.kind:
            continue
        if build.target and binary['binary-name'] != build.target:
            continue
        require(binary['status'] == 'listed', 'incomplete target discovery')
        names.extend(name for name, test in binary['testcases'].items() if test['ignored'])
    for name in names:
        owners = [module.id for module in modules if module.includes(name)]
        owners += [module.id + ':child' for module in modules for prefix in module.children
                   if name.startswith(prefix)]
        require(len(owners) == 1, f'ignored test needs exactly one module owner: {name}: {owners}')
    for module in modules:
        for prefix in module.children:
            require(sum(name.startswith(prefix) for name in names) == 1,
                    'declared caller must discover exactly one child: ' + module.id + ': ' + prefix)
        if module.expected_cases is not None:
            require(sum(module.includes(name) for name in names) == module.expected_cases,
                    'fixture target has missing or additional entries: ' + module.id)


def file_stamp(path):
    status = Path(path).stat()
    return (status.st_dev, status.st_ino, status.st_size, status.st_mtime_ns, status.st_ctime_ns)


def parse_listing(document, module):
    require(isinstance(document, dict) and isinstance(document.get('rust-suites'), dict),
            'invalid nextest discovery document')
    cases = []
    for binary_id, binary in document['rust-suites'].items():
        if binary['package-name'] != module.build.package:
            continue
        if binary['kind'] != module.build.kind:
            continue
        if module.build.target and binary['binary-name'] != module.build.target:
            continue
        require(binary_id == binary['binary-id'] and binary['status'] == 'listed',
                'target discovery did not complete')
        for name, test in binary['testcases'].items():
            if test['filter-match']['status'] != 'matches' or not test['ignored']:
                continue
            if module.includes(name):
                cases.append(Case(module.build, binary_id, binary['binary-path'], name))
    require(bool(cases), 'empty test discovery: ' + module.id)
    if module.expected_cases is not None:
        require(len(cases) == module.expected_cases, 'unexpected fixture entry count: ' + module.id)
    require(len({case.id for case in cases}) == len(cases), 'duplicate discovered test identity')
    return sorted(cases, key=lambda case: case.id)


def verify_case(path, case, exit_code):
    require(exit_code == 0, f'Rust test process failed: {case.id} ({exit_code})')
    try:
        root = ET.parse(path).getroot()
        tests = root.findall('.//testcase')
        require(len(tests) == 1, 'missing or duplicate executed test')
        require(tests[0].get('name') == case.name and tests[0].get('classname') == case.binary,
                'execution identity differs from discovery')
        require(not any(root.findall('.//' + tag) for tag in ('failure', 'error', 'skipped', 'rerunFailure', 'flakyFailure')),
                'failed, ignored or retried test cannot pass')
        for suite in [root, *root.findall('.//testsuite')]:
            require(int(suite.get('tests', '-1')) == 1 and
                    int(suite.get('failures', '0')) == 0 and int(suite.get('errors', '0')) == 0 and
                    int(suite.get('skipped', '0')) == 0, 'execution counts differ from discovery')
    except (OSError, ET.ParseError, ValueError) as error:
        raise RuntimeError('missing or invalid test result') from error


class Processes:
    """One run owns every process group, including discovery and fixture commands."""
    def __init__(self):
        self.cancelled = threading.Event()
        self.lock = threading.RLock()
        self.children = set()
        self.local = threading.local()

    def check(self):
        require(not self.cancelled.is_set() or getattr(self.local, 'cleanup', False), 'T2 cancelled')

    @contextmanager
    def cleanup(self):
        previous = getattr(self.local, 'cleanup', False)
        self.local.cleanup = True
        try:
            yield
        finally:
            self.local.cleanup = previous

    def spawn(self, args, **kwargs):
        with self.lock:
            self.check()
            kwargs.setdefault('pass_fds', lease_fds())
            kwargs['start_new_session'] = True
            child = subprocess.Popen([str(arg) for arg in args], **kwargs)
            self.children.add(child)
            return child

    def release(self, child):
        with self.lock:
            if child not in self.children:
                return
            self.children.remove(child)
        self.stop(child)

    def run_fixture(self, args, *, input=None, capture_output=False, timeout=None, check=False, **kwargs):
        if input is not None:
            require('stdin' not in kwargs, 'input and stdin cannot both be provided')
            kwargs['stdin'] = subprocess.PIPE
        if capture_output:
            require('stdout' not in kwargs and 'stderr' not in kwargs, 'conflicting capture streams')
            kwargs.update(stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        child = self.spawn(args, **kwargs)
        started = time.monotonic()
        sent = False
        try:
            while True:
                self.check()
                if timeout is not None and time.monotonic() - started > timeout:
                    raise subprocess.TimeoutExpired(args, timeout)
                try:
                    stdout, stderr = child.communicate(input=None if sent else input, timeout=.2)
                    self.check()
                    result = subprocess.CompletedProcess(args, child.returncode, stdout, stderr)
                    if check:
                        result.check_returncode()
                    return result
                except subprocess.TimeoutExpired:
                    sent = True
        finally:
            self.release(child)
            for stream in (child.stdin, child.stdout, child.stderr):
                if stream is not None:
                    stream.close()

    def run(self, args, *, env=None, log=None, capture=False, separate_stderr=False, timeout=None, cwd=ROOT):
        require(not self.cancelled.is_set(), 'T2 cancelled')
        start = time.monotonic()
        output = subprocess.PIPE if capture else log
        with self.lock:
            require(not self.cancelled.is_set(), 'T2 cancelled')
            child = subprocess.Popen([str(arg) for arg in args], cwd=cwd, env=env,
                                     text=True, stdout=output, stderr=subprocess.PIPE if separate_stderr else subprocess.STDOUT,
                                     pass_fds=lease_fds(), start_new_session=True)
            self.children.add(child)
        try:
            while True:
                try:
                    stdout, stderr = child.communicate(timeout=.2)
                    return subprocess.CompletedProcess(args, child.returncode, stdout or '', stderr or '')
                except subprocess.TimeoutExpired:
                    if self.cancelled.is_set() or (timeout and time.monotonic() - start > timeout):
                        self.stop(child)
                        raise RuntimeError('T2 cancelled' if self.cancelled.is_set() else 'case execution deadline exceeded')
        finally:
            # A successful parent must not leave owned descendants running.
            self.stop(child)
            for stream in (child.stdin, child.stdout, child.stderr):
                if stream is not None:
                    stream.close()
            with self.lock:
                self.children.discard(child)

    @staticmethod
    def stop(child):
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        # The parent may have exited while a descendant ignored TERM.
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()

    def cancel(self):
        if self.cancelled.is_set():
            return
        self.cancelled.set()
        with self.lock:
            children = list(self.children)
        for child in children:
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

    def close(self):
        self.cancel()
        with self.lock:
            children = list(self.children)
        for child in children:
            self.release(child)
            for stream in (child.stdin, child.stdout, child.stderr):
                if stream is not None:
                    stream.close()


class Builds:
    def __init__(self, output, processes):
        self.output = output.resolve() / 'build'
        self.output.mkdir(parents=True)
        self.processes = processes
        self.metadata = self.output / 'cargo.json'
        self.targets = {}
        self.listings = {}
        self.executables = {}
        self.stamps = {}
        self.elapsed = 0

    def command(self, args, log):
        result = self.processes.run(args, capture=True)
        log.write_text(result.stdout)
        require(result.returncode == 0, 'build or discovery failed; see ' + str(log))
        return result.stdout

    def prepare(self, modules):
        require_lease(ROOT)
        start = time.monotonic()
        # stderr must not contaminate the JSON metadata protocol.
        metadata = self.processes.run(['cargo', 'metadata', '--locked', '--all-features', '--format-version', '1'],
                                  cwd=ROOT, capture=True, separate_stderr=True)
        (self.output / 'metadata.stderr.log').write_text(metadata.stderr)
        require(metadata.returncode == 0, 'Cargo metadata failed')
        package_names = {item['id']: item['name'] for item in strict_json(metadata.stdout)['packages']}
        self.metadata.write_text(metadata.stdout)
        builds = {module.build for module in modules if module.build}
        if any('identity' in module.fixtures for module in modules):
            builds.add(APP)
        for index, build in enumerate(sorted(builds)):
            directory = self.output / str(index)
            directory.mkdir()
            result = self.processes.run(['cargo', 'nextest', 'list', *build.cargo_args(),
                                     '--list-type', 'binaries-only', '--message-format', 'json'],
                                    cwd=ROOT, capture=True, separate_stderr=True)
            (directory / 'compile.log').write_text(result.stderr)
            require(result.returncode == 0, 'prebuild failed; see ' + str(directory / 'compile.log'))
            document = strict_json(result.stdout)
            expected = [item for item in document['rust-binaries'].values()
                        if package_names.get(item['package-id']) == build.package and item['kind'] == build.kind
                        and (not build.target or item['binary-name'] == build.target)]
            require(len(expected) == 1, 'ambiguous or missing prebuilt target')
            target_dir = Path(document['rust-build-meta']['target-directory']).resolve()
            executable = Path(expected[0]['binary-path']).resolve()
            require(executable.is_file() and executable.is_relative_to(target_dir),
                    'test executable is outside the leased target')
            path = directory / 'binaries.json'
            path.write_text(result.stdout)
            self.targets[build] = path
            self.stamps[build] = (executable, file_stamp(executable))
            listing = self.processes.run(['cargo', 'nextest', 'list', *self.reuse(build),
                                      '--run-ignored', 'only', '--message-format', 'json'],
                                     cwd=ROOT, capture=True, separate_stderr=True)
            (directory / 'discovery.log').write_text(listing.stderr)
            require(listing.returncode == 0, 'Rust discovery failed')
            self.listings[build] = strict_json(listing.stdout)
            validate_ownership(self.listings[build], build, [*MODULES.values(), IDENTITY_SETUP])
            self.verify_binary(build)
            (directory / 'tests.json').write_text(listing.stdout)
        binaries = set()
        if any(module.postgres for module in modules):
            binaries.add(Build('rss-mdm-app', 'bin', 'rss-mdm'))
        if any('examples' in module.fixtures for module in modules):
            binaries.add(Build('rss-mdm-examples', 'bin', 'rss-mdm-fixture'))
        if any(module.profile == 'backend' for module in modules):
            binaries.add(Build('rss-mdm-policy-postgres', 'example', 'policy_migrations'))
        if any(module.profile == 'group' for module in modules):
            binaries.add(Build('rss-mdm-group-postgres', 'example', 'migrations'))
        for build in sorted(binaries):
            result = self.processes.run(['cargo', 'build', *build.cargo_args(), '--message-format=json'],
                                    cwd=ROOT, capture=True, separate_stderr=True)
            (self.output / (build.target + '.log')).write_text(result.stderr)
            require(result.returncode == 0, 'fixture binary build failed: ' + build.target)
            outputs = [item['executable'] for line in result.stdout.splitlines()
                       if (item := strict_json(line)).get('reason') == 'compiler-artifact'
                       and item.get('executable') and item['target']['name'] == build.target
                       and build.kind in item['target']['kind']]
            require(len(outputs) == 1, 'ambiguous fixture executable: ' + build.target)
            self.executables[build.target] = outputs[0]
        self.elapsed = time.monotonic() - start

    def reuse(self, build):
        return ['--cargo-metadata', str(self.metadata), '--binaries-metadata', str(self.targets[build])]

    def verify_binary(self, build):
        executable, stamp = self.stamps[build]
        require(file_stamp(executable) == stamp, 'test executable changed after build/discovery')

    def discover(self, module):
        self.verify_binary(module.build)
        return parse_listing(self.listings[module.build], module)

    def execute(self, case, env, output):
        self.verify_binary(case.build)
        output = output.resolve()
        output.mkdir(parents=True, exist_ok=True)
        report = output / 'junit.xml'
        # Separate stores prevent concurrent nextest invocations overwriting evidence.
        config = output / 'nextest.toml'
        config.write_text('[store]\ndir = ' + json.dumps(str(output / 'nextest')) +
                          '\n[profile.default]\nretries = 0\ntest-threads = 1\n' +
                          f'slow-timeout = {{ period = "{CASE_TIMEOUT}s", terminate-after = 1 }}\n' +
                          '[profile.default.junit]\npath = ' + json.dumps(str(report)) + '\n')
        args = ['cargo', 'nextest', 'run', *self.reuse(case.build),
                '--config-file', str(config), '--user-config-file', 'none',
                '--no-capture', '--retries', '0', '--no-tests', 'fail', '--run-ignored', 'only',
                '-E', f'binary_id(={case.binary})', '--', '--exact', case.name]
        with (output / 'test.log').open('w') as log:
            result = self.processes.run(args, env=env, log=log, timeout=CASE_TIMEOUT + 15)
        verify_case(report, case, result.returncode)

    def execute_python(self, module, fixture, output):
        payload = output / 'fixture.json'
        payload.write_text(json.dumps({
            'root': str(fixture.root), 'database': fixture.database,
            'migration_config': str(fixture.migration_config) if fixture.migration_config else None,
            'binary': fixture.binary,
        }))
        payload.chmod(0o600)
        with (output / 'test.log').open('w') as log:
            result = self.processes.run(
                [sys.executable, '-u', ROOT / 'hack/t2_python.py', module.id, payload],
                env=fixture.env, log=log, timeout=CASE_TIMEOUT)
        require(result.returncode == 0, 'Python scenario failed: ' + module.id)
