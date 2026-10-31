"""Every surviving App T1 carrier has a current CI input owner."""
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'hack'))
from ci_impact import select_inputs

class AppTestLayout(unittest.TestCase):
    def test_current_app_test_inputs_have_owners(self):
        for path in (ROOT/'apps/server/tests').rglob('*.rs'):
            select_inputs([path.relative_to(ROOT).as_posix()])
