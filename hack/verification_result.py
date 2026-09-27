"""Shared result shape for executed and skipped local verification stages."""
import time

def result(status, started=None, **details):
    return dict(status=status, elapsedSeconds=round(time.monotonic()-started,3) if started is not None else 0, **details)

def require(condition, message):
    if not condition:
        raise RuntimeError(message)
