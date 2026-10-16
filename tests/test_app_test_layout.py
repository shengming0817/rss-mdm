"""App test implementations live outside the production source tree."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'hack'))
from ci_impact import select_inputs, SelectionError


class AppTestLayout(unittest.TestCase):
    def test_every_current_test_file_has_explicit_selection_ownership(self):
        for path in (ROOT/'crates/app/tests').rglob('*.rs'):
            relative=str(path.relative_to(ROOT))
            select_inputs([relative])
        self.assertEqual(select_inputs(['crates/app/tests/assets/group_support.rs']).modules,
                         ('assets.group_input',))
        self.assertNotIn('apple.cms',select_inputs(['crates/app/tests/support/mod.rs']).modules)
        self.assertNotIn('audit.receipts',select_inputs(['crates/app/tests/support/mod.rs']).modules)

    def test_moved_t1_remains_t1_and_new_owners_select_exactly(self):
        self.assertEqual(select_inputs(['crates/content-service/tests/unit.rs']).modules,())
        self.assertEqual(select_inputs(['crates/app/tests/apple/apns.rs']).modules,('apple.apns',))
        self.assertEqual(select_inputs(['crates/app/tests/agent/registration.rs']).modules,('agent.registration',))

if __name__=='__main__':unittest.main()
