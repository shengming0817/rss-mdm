"""Classify explicit Rust test/support carriers for production boundary guards."""
from pathlib import Path

def is_test_path(path):
    parts=[Path(part).stem for part in Path(path).parts]
    return any(part in {'tests','t2','test_support','fixtures'} or
               part.endswith(('_tests','_test_support','_fixture')) for part in parts)
