"""Guard the product's capability boundaries, not its file layout."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'crates/app/src'


class FoundationBoundaries(unittest.TestCase):
    def test_business_code_has_no_aggregate_state_or_store(self):
        violations = []
        for path in SOURCE.rglob('*.rs'):
            source = path.read_text()
            if re.search(r'\bAccessStore\b|\bstruct\s+App\b|State\s*<\s*Arc\s*<\s*App\b', source):
                violations.append(str(path.relative_to(ROOT)))
        self.assertEqual(violations, [])

    def test_assets_execute_through_their_own_capability(self):
        violations = []
        for path in (SOURCE / 'management').rglob('*.rs'):
            if re.search(r'Command::Asset\b', path.read_text()):
                violations.append(str(path.relative_to(ROOT)))
        self.assertEqual(violations, [])

    def test_authentication_does_not_own_product_authorization(self):
        identity = SOURCE / 'identity.rs'
        self.assertNotIn('authorization: Option<', identity.read_text())


if __name__ == '__main__':
    unittest.main()
