#!/usr/bin/env python3
"""Enterprise software through real TCP, TLS origins, PostgreSQL and the content filesystem."""
import importlib.util
import os
from pathlib import Path
import tempfile
from t2 import main
from build_run import require_lease
if __name__ == '__main__':
    require_lease(Path(__file__).resolve().parents[1])
    spec = importlib.util.spec_from_file_location('software_source_tls', Path(__file__).with_name('source-t2.py'))
    source = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(source)
    with tempfile.TemporaryDirectory(prefix='mdm-software-origin-') as directory:
        os.environ.update(source.tls_environment(Path(directory)))
        main(software_only=True)
