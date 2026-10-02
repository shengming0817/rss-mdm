"""#2529 must replace old ownership, not wrap it in a compatibility facade."""
from pathlib import Path
import unittest
import tomllib
ROOT = Path(__file__).resolve().parents[1]
class SoftwareOwnership(unittest.TestCase):
    def test_content_has_no_signing_or_whole_body_path(self):
        content = ROOT / 'crates/content-service/src'
        self.assertTrue(content.is_dir())
        for path in content.rglob('*.rs'):
            if path.name == 'tests.rs':
                continue
            text = path.read_text()
            self.assertNotIn('Ed25519KeyPair', text)
            self.assertNotIn('Result<Vec<u8>', text)
        self.assertFalse((ROOT / 'crates/app/src/task_content.rs').exists())
    def test_publication_service_cannot_depend_on_app(self):
        service = ROOT / 'crates/software-service'
        self.assertTrue(service.is_dir())
        dependencies = tomllib.loads((service / 'Cargo.toml').read_text())['dependencies']
        for consumer in ('rss-mdm-app', 'rss-mdm-flow-service',
                         'rss-mdm-content-service', 'rss-mdm-management-http'):
            self.assertNotIn(consumer, dependencies)
        for path in service.rglob('*.rs'):
            self.assertNotIn('crate::config::secret', path.read_text())
if __name__ == '__main__':
    unittest.main()
