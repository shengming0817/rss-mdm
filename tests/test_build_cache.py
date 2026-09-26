"""Compiler caching cannot acquire or extend the lifetime of a build lease."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest

from test_build_run import SCRIPT, clean_env

FAKE_CACHE = '''import json,os,socket,sys,time
from pathlib import Path
if sys.argv[1] == '--version':
 print('sccache 0.15.0'); raise SystemExit(0)
if sys.argv[1] == '--show-stats':
 print(json.dumps({'version':'0.15.0','cache_location':f'Local disk: "{Path(os.environ["SCCACHE_DIR"]).resolve()}"'})); raise SystemExit(0)
if sys.argv[1] == '--start-server':
 inherited=[]
 for fd in range(3,128):
  try: os.fstat(fd); inherited.append(fd)
  except OSError: pass
 Path(os.environ['CACHE_PROBE']).write_text(json.dumps({'fds':inherited,'lease':os.environ.get('_MDM_BUILD_LEASE')}))
 listener=socket.socket(socket.AF_UNIX); listener.bind(os.environ['SCCACHE_SERVER_UDS']); listener.listen(8)
 pid=os.fork()
 if pid: Path(os.environ['CACHE_PID']).write_text(str(pid)); raise SystemExit(0)
 os.setsid()
 for fd in (0,1,2):
  sink=os.open(os.devnull,os.O_RDWR); os.dup2(sink,fd); os.close(sink)
 while True:
  connection,_=listener.accept(); connection.close()
os.execvp(sys.argv[1],sys.argv[1:])
'''


class BuildCacheTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='mdmc-', dir='/tmp')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.bin = self.root / 'bin'; self.bin.mkdir()
        self.cache = self.bin / 'sccache'
        self.cache.write_text('#!' + sys.executable + '\n' + FAKE_CACHE)
        self.cache.chmod(0o755)
        self.env = clean_env() | {'PATH': str(self.bin) + ':/usr/bin:/bin',
                                 'MDM_TARGET_POOL_ROOT': str(self.root / 'pool'),
                                 'MDM_COMPILER_CACHE': 'on',
                                 'SCCACHE_DIR': str(self.root / 'objects'),
                                 'SCCACHE_SERVER_UDS': str(self.root / 'server.sock'),
                                 'CACHE_PROBE': str(self.root / 'probe'),
                                 'CACHE_PID': str(self.root / 'pid')}
        self.addCleanup(self.stop_server)

    def stop_server(self):
        path = self.root / 'pid'
        if path.exists():
            try:
                os.kill(int(path.read_text()), signal.SIGTERM)
            except ProcessLookupError:
                pass

    def invoke(self, code='pass', **env):
        return subprocess.run([sys.executable, str(SCRIPT), '--', sys.executable, '-c', code],
                              cwd=self.root, env=self.env | env, capture_output=True, text=True, timeout=20)

    def test_daemon_has_no_lease_and_does_not_block_reuse(self):
        for _ in range(2):
            result = self.invoke('import os; print(os.environ["RUSTC_WRAPPER"])')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), str(self.cache))
        self.assertEqual(json.loads((self.root / 'probe').read_text()), {'fds': [], 'lease': None})
        os.kill(int((self.root / 'pid').read_text()), 0)
        failure = self.invoke('raise SystemExit(7)')
        self.assertEqual(failure.returncode, 7, failure.stderr)

    def test_missing_cache_auto_degrades_on_fails_off_never_starts(self):
        self.cache.unlink()
        for mode, status in [('auto', 0), ('on', 2), ('off', 0)]:
            with self.subTest(mode=mode):
                result = self.invoke('import os; print(repr(os.environ["RUSTC_WRAPPER"]))', MDM_COMPILER_CACHE=mode)
                self.assertEqual(result.returncode, status, result.stderr)
                if not status:
                    self.assertEqual(result.stdout.strip(), "''")
        self.assertFalse((self.root / 'probe').exists())

    def test_custom_wrapper_is_rejected_in_every_mode(self):
        for mode in ('auto', 'on', 'off'):
            result = self.invoke(MDM_COMPILER_CACHE=mode, RUSTC_WRAPPER='/custom/wrapper')
            self.assertEqual(result.returncode, 2)
            self.assertIn('custom rustc wrapper', result.stderr)
        self.assertFalse((self.root / 'pool').exists())

    def test_failed_startup_does_not_mask_compiler_failure(self):
        self.cache.write_text('#!' + sys.executable + '\nimport sys\n'
                              'if sys.argv[1]=="--version": print("sccache 0.15.0")\n'
                              'else: raise SystemExit(1)\n')
        result = self.invoke('raise SystemExit(7)', MDM_COMPILER_CACHE='auto')
        self.assertEqual(result.returncode, 7)
        self.assertIn('compiler cache disabled', result.stderr)


if __name__ == '__main__':
    unittest.main()
