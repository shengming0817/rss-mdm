"""Fixture subprocesses share the current T2 run's process-group ownership."""
from contextlib import contextmanager
from contextvars import ContextVar
import json
import os
import re
import subprocess as standard

_owner = None
_diagnostic = ContextVar('t2_fixture_diagnostic', default=None)


@contextmanager
def diagnostics(path):
    """Keep each concurrent scenario's preparation/cleanup evidence separate.

    ref: pytest-dev/pytest src/_pytest/capture.py (per-test phase capture).
    """
    parent = _diagnostic.get()
    state = {'path': path, 'phase': 'setup', 'secrets': set(parent['secrets']) if parent else set()}
    path.write_text('Fixture preparation and cleanup diagnostics.\n')
    token = _diagnostic.set(state)
    try:
        yield
    finally:
        _diagnostic.reset(token)


@contextmanager
def diagnostic_phase(phase):
    state = _diagnostic.get()
    previous = state['phase'] if state else None
    if state:
        state['phase'] = phase
    try:
        yield
    finally:
        if state:
            state['phase'] = previous


def private_value(value):
    """Register generated private inputs before cleanup can remove their files."""
    state = _diagnostic.get()
    if state is None:
        return
    if isinstance(value, str):
        if value:
            state['secrets'].add(value)
        try:
            parsed = json.loads(value)
        except ValueError:
            return
        if isinstance(parsed, (dict, list)):
            private_value(parsed)
    elif isinstance(value, dict):
        for item in value.values():
            private_value(item)
    elif isinstance(value, list):
        for item in value:
            private_value(item)


def command_failure(error, kwargs):
    state = _diagnostic.get()
    if state is None:
        return
    from candidate_runtime import safe_evidence
    for key, value in (kwargs.get('env') or os.environ).items():
        if re.search(r'password|secret|token|credential|private.?key', key, re.I):
            private_value(value)
    private_value(kwargs.get('input'))
    streams = {}
    for name in ('stdout', 'stderr'):
        value = getattr(error, name, None) or ''
        if isinstance(value, bytes):
            value = value.decode('utf-8', errors='replace')
        try:
            streams[name] = safe_evidence(value, state['secrets'])
        except RuntimeError:
            streams[name] = 'diagnostic-withheld'
    # CalledProcessError/TimeoutExpired.__str__ echo argv, which may contain
    # credentials or inline configuration. Keep status and stack, never argv.
    executable = os.path.basename(str(error.cmd[0])) if isinstance(error.cmd, (list, tuple)) else 'command'
    error.cmd = '[fixture command arguments withheld]'
    error.stdout, error.stderr = streams['stdout'], streams['stderr']
    with state['path'].open('a') as log:
        log.write(f'[{state["phase"]}] {executable}: {type(error).__name__}: {error}\n')
        for name, value in streams.items():
            log.write(f'{name}:\n{value or "(no captured output)"}\n')


@contextmanager
def owned_by(owner):
    global _owner
    if _owner is not None:
        raise RuntimeError('nested T2 process ownership')
    _owner = owner
    try:
        yield
    finally:
        _owner = None


class Child:
    def __init__(self, owner, child):
        self.owner, self.child = owner, child

    def __getattr__(self, name):
        return getattr(self.child, name)

    def poll(self):
        result = self.child.poll()
        if result is not None:
            self.owner.release(self.child)
        return result

    def wait(self, *args, **kwargs):
        result = self.child.wait(*args, **kwargs)
        self.owner.release(self.child)
        return result

    def communicate(self, *args, **kwargs):
        result = self.child.communicate(*args, **kwargs)
        self.owner.release(self.child)
        return result

    def __enter__(self):
        self.child.__enter__()
        return self

    def __exit__(self, *args):
        try:
            return self.child.__exit__(*args)
        finally:
            self.owner.release(self.child)


class Subprocess:
    def __getattr__(self, name):
        return getattr(standard, name)

    def run(self, args, **kwargs):
        try:
            return (_owner.run_fixture(args, **kwargs) if _owner is not None
                    else standard.run(args, **kwargs))
        except (standard.CalledProcessError, standard.TimeoutExpired) as error:
            command_failure(error, kwargs)
            raise

    def Popen(self, args, **kwargs):
        return (Child(_owner, _owner.spawn(args, **kwargs)) if _owner is not None
                else standard.Popen(args, **kwargs))

    def check_output(self, args, **kwargs):
        return self.run(args, check=True, stdout=standard.PIPE, **kwargs).stdout


subprocess = Subprocess()
