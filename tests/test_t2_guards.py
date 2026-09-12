"""Optimized Python must still reject an installer that wrote before admission."""
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
class T2Guards(unittest.TestCase):
    def test_windows_runner_rejects_empty_or_partial_success(self):
        sys.path.insert(0,str(ROOT/'hack'))
        import t2
        cases=[
            'running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored;',
            'test windows::tests::issuance_recovery_and_enrollment_boundaries ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;',
            'test unrelated::one ... ok\ntest unrelated::two ... ok\ntest result: ok. 2 passed; 0 failed; 0 ignored;',
        ]
        for output in cases:
            with self.subTest(output=output),self.assertRaises(RuntimeError):
                t2.verify_windows_result(output)
        t2.verify_windows_result('test windows::tests::issuance_recovery_and_enrollment_boundaries ... ok\ntest windows::tests::native_tls_enrollment_management_replay_and_revoke ... ok\ntest result: ok. 2 passed; 0 failed; 0 ignored;')
    def test_optimized_rejected_installer_cannot_write_ddl(self):
        code='''
import sys,tempfile,json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,'hack')
import t2
with tempfile.TemporaryDirectory() as directory:
 root=Path(directory);config=root/'config.json';config.write_text(json.dumps({'database':{}}))
 with patch.object(t2,'run',return_value=SimpleNamespace(stdout='f')),patch.object(t2.subprocess,'run',return_value=SimpleNamespace(returncode=1,stderr='')):
  try:t2.verify_migrations('fixture','binary',config,root,{})
  except RuntimeError as e:
   if str(e)!='rejected migrator performed DDL':raise SystemExit('wrong failure classification')
  else:raise SystemExit('unsafe installation passed')
'''
        result=subprocess.run([sys.executable,'-O','-c',code],cwd=ROOT,env={**os.environ,'PYTHONOPTIMIZE':'1'},capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
