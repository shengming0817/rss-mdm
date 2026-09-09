"""Optimized Python must still reject an installer that wrote before admission."""
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
class T2Guards(unittest.TestCase):
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
