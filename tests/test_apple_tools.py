import hashlib
import importlib.util
import io
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "hack"))

spec = importlib.util.spec_from_file_location('apple_tools', ROOT / 'hack/apple_tools.py')
tools = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tools)


class OracleSource(unittest.TestCase):
    def test_archive_not_cached_tree_is_the_only_build_input(self):
        content = io.BytesIO()
        with tarfile.open(fileobj=content, mode='w:gz') as archive:
            member = tarfile.TarInfo('nanomdm-fixed/go.mod')
            body = b'module test\n'
            member.size = len(body)
            archive.addfile(member, io.BytesIO(body))
        data = content.getvalue()
        digest = hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary) / 'apple-tools' / digest
            source = cache / 'nanomdm-fixed'
            source.mkdir(parents=True)
            (cache / 'archive.tar.gz').write_bytes(data)
            (source / 'injected.go').write_text('package main')
            seen = []

            def build(args, *, cwd, **kwargs):
                self.assertFalse((cwd / 'injected.go').exists())
                self.assertEqual((cwd / 'go.mod').read_bytes(), body)
                (cwd / 'injected.go').write_text('package main')
                seen.append(cwd)
                Path(args[args.index('-o') + 1]).write_bytes(b'binary')

            # This isolated, mocked build owns a temporary target, not the enclosing CI lease.
            env = {key: value for key, value in os.environ.items() if not key.startswith('_MDM_')}
            env['CARGO_TARGET_DIR'] = temporary
            with patch.dict(os.environ, env, clear=True), patch.object(tools, 'LOCK', {'nanomdm': {'revision': 'fixed', 'sourceArchiveSha256': digest}}), patch('subprocess.run', side_effect=build):
                tools.nano_binary()
                tools.nano_binary()
            self.assertEqual(len(seen), 2)
            self.assertNotEqual(seen[0], seen[1])
            self.assertTrue(all(not path.exists() for path in seen))
