"""App test implementations live outside the production source tree."""
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'hack'))
from rust_test_layout import is_test_path
from t2_registry import select_paths


class AppTestLayout(unittest.TestCase):
    def test_src_contains_neither_test_carriers_nor_test_functions(self):
        source = ROOT/'crates/app/src'
        bad = []
        for path in source.rglob('*.rs'):
            text = path.read_text()
            if is_test_path(path.relative_to(source)) or re.search(r'#\[(?:tokio::)?test(?:\([^\]]*\))?\]', text):
                bad.append(str(path.relative_to(ROOT)))
        self.assertEqual(bad, [])

    def test_test_only_modules_are_loaded_from_tests(self):
        for path in (ROOT/'crates/app/src').rglob('*.rs'):
            text = path.read_text()
            for match in re.finditer(r'#\[cfg\([^\n]*\btest\b[^\n]*\)\]\s*((?:#\[[^\n]*\]\s*)*)(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*([;{])',text):
                self.assertEqual(match[2], ';', str(path))
                attribute = re.search(r'#\[path\s*=\s*"([^"]+)"\]', match[1])
                self.assertIsNotNone(attribute,str(path))
                target = (path.parent/attribute[1]).resolve()
                self.assertTrue(target.is_file(),str(target))
                self.assertTrue(target.is_relative_to(ROOT/'crates/app/tests') or
                                target.is_relative_to(ROOT/'tests/support'),str(target))

    def test_test_directory_does_not_create_accidental_cargo_targets(self):
        root=ROOT/'crates/app/tests'
        self.assertTrue(root.is_dir())
        self.assertEqual({path.name for path in root.glob('*.rs')},{'publication.rs'})
        self.assertEqual(list(root.glob('*/main.rs')),[])

    def test_every_current_test_file_has_explicit_selection_ownership(self):
        for path in (ROOT/'crates/app/tests').rglob('*.rs'):
            relative=str(path.relative_to(ROOT))
            self.assertFalse(select_paths([relative]).full,relative)
        self.assertEqual(select_paths(['crates/app/tests/assets/group_support.rs']).modules,
                         ('assets.group_input',))
        self.assertNotIn('apple.cms',select_paths(['crates/app/tests/support/mod.rs']).modules)
        self.assertNotIn('audit.receipts',select_paths(['crates/app/tests/support/mod.rs']).modules)

    def test_moved_t1_remains_t1_and_new_owners_select_exactly(self):
        self.assertEqual(select_paths(['crates/app/tests/content/unit.rs']).modules,())
        self.assertEqual(select_paths(['crates/app/tests/apple/apns.rs']).modules,('apple.apns',))
        self.assertEqual(select_paths(['crates/app/tests/agent/registration.rs']).modules,('agent.registration',))

if __name__=='__main__':unittest.main()
