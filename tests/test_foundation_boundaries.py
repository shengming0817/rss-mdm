"""Guard the product's capability boundaries, not its file layout."""
from pathlib import Path
import re
import unittest
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"hack"))
from rust_test_layout import is_test_path

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
        for path in (SOURCE / 'planning').rglob('*.rs'):
            if re.search(r'Command::Asset\b', path.read_text()):
                violations.append(str(path.relative_to(ROOT)))
        self.assertEqual(violations, [])

    def test_authentication_does_not_own_product_authorization(self):
        identity = SOURCE / 'identity.rs'
        self.assertFalse('authorization: Option<' in identity.read_text())

    def test_business_writes_have_one_capability_owner(self):
        owners = {
            'grants': 'enrollment', 'requests': 'enrollment',
            'enrollment_intents': 'enrollment', 'enrollment_certificates': 'enrollment',
            'devices': 'device', 'registrations': 'device', 'credentials': 'device',
            'agent_bindings': 'device', 'collection_runs': 'collection',
        }
        violations = []
        for path in SOURCE.rglob('*.rs'):
            relative = path.relative_to(SOURCE)
            if is_test_path(relative):
                continue
            source = path.read_text()
            for table in re.findall(r'(?:INSERT INTO|UPDATE|DELETE FROM)\s+mdm_access\.(\w+)', source):
                owner = owners.get(table)
                if owner and relative.parts[0] not in (owner, owner + '.rs'):
                    violations.append(f'{relative}: {table} belongs to {owner}')
        self.assertEqual(violations, [])

    def test_asset_queries_use_owner_read_interfaces(self):
        for path in (SOURCE / 'assets').glob('*.rs'):
            self.assertNotIn('mdm_access.', path.read_text(), str(path))

    def test_only_composition_and_fixtures_can_use_assembly(self):
        for path in SOURCE.rglob('*.rs'):
            relative = path.relative_to(SOURCE)
            if str(relative) == 'api.rs' or is_test_path(relative):
                continue
            self.assertFalse(re.search(r'\bAssembly\b', path.read_text()), str(relative))


if __name__ == '__main__':
    unittest.main()
