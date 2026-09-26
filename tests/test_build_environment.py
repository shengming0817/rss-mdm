"""A managed compiler must not delegate target writes to a detached cache server."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_build_run import SCRIPT, clean_env


class BuildEnvironmentTests(unittest.TestCase):
    def test_managed_run_never_starts_sccache_and_clears_ancestor_wrappers(self):
        with tempfile.TemporaryDirectory(prefix='mdm-direct-') as temporary:
            root = Path(temporary).resolve()
            subprocess.run(['/usr/bin/git', 'init', '-q', str(root)], check=True, env=clean_env())
            binary = root / 'bin'; binary.mkdir()
            probe = root / 'cache-started'
            cache = binary / 'sccache'
            cache.write_text('#!' + sys.executable + '\nfrom pathlib import Path\n'
                             f'Path({str(probe)!r}).touch()\nraise SystemExit(99)\n')
            cache.chmod(0o755)
            config = root / '.cargo'; config.mkdir()
            (config / 'config.toml').write_text(f'[build]\nrustc-wrapper="{cache}"\n')
            (root / 'src').mkdir()
            (root / 'src/lib.rs').write_text('pub fn value() -> u8 { 42 }')
            (root / 'Cargo.toml').write_text('[package]\nname="direct-proof"\nversion="0.0.0"\nedition="2021"\n')
            env = clean_env() | {'PATH': str(binary) + os.pathsep + os.environ['PATH'],
                                 'MDM_TARGET_POOL_ROOT': str(root / 'pool')}
            result = subprocess.run([sys.executable, str(SCRIPT), '--', 'cargo', 'check', '--offline'],
                                    cwd=root, env=env, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(probe.exists())
            for name in ('RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CARGO_BUILD_RUSTC_WRAPPER',
                         'CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER'):
                result = subprocess.run([sys.executable, str(SCRIPT), '--', sys.executable, '-c', 'pass'],
                                        cwd=root, env=env | {name: str(cache)},
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 2)
                self.assertIn('custom rustc wrapper', result.stderr)
            self.assertFalse(probe.exists())


if __name__ == '__main__':
    unittest.main()
