"""Fixture subprocesses share the current T2 run's process-group ownership."""
from contextlib import contextmanager
import subprocess as standard

_owner = None


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
        return (_owner.run_fixture(args, **kwargs) if _owner is not None
                else standard.run(args, **kwargs))

    def Popen(self, args, **kwargs):
        return (Child(_owner, _owner.spawn(args, **kwargs)) if _owner is not None
                else standard.Popen(args, **kwargs))

    def check_output(self, args, **kwargs):
        return self.run(args, check=True, stdout=standard.PIPE, **kwargs).stdout


subprocess = Subprocess()
