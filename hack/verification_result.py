"""Shared result shape for executed and skipped local verification stages."""
import time

def result(status, started=None, **details):
    return dict(status=status, elapsedSeconds=round(time.monotonic()-started,3) if started is not None else 0, **details)

def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def publish(path, payload):
    import json
    import os
    import tempfile
    path.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.NamedTemporaryFile(mode='w',dir=path.parent,prefix='.result-',delete=False) as stream:
        temporary=stream.name
        try:
            json.dump(payload,stream,indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        except BaseException:
            os.unlink(temporary)
            raise
    try:os.replace(temporary,path)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)
