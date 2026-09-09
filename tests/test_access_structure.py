"""Production graph and executable ownership; not authentication proof."""
import pathlib
import tomllib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

class AccessOwnership(unittest.TestCase):
    def test_product_owns_binary_and_migrations(self):
        manifest = tomllib.loads((ROOT / 'crates/app/Cargo.toml').read_text())
        self.assertEqual([b['name'] for b in manifest['bin']], ['rss-mdm'])
        self.assertNotIn('rss-mdm-examples', manifest.get('dependencies', {}))
        example = tomllib.loads((ROOT / 'crates/examples/Cargo.toml').read_text())
        self.assertEqual([b['name'] for b in example['bin']], ['rss-mdm-fixture'])

    def test_identity_has_one_fixed_public_source(self):
        shared = tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']['dependencies']
        client = shared['rss-identity-client']
        self.assertRegex(client['rev'], r'^[0-9a-f]{40}$')
        self.assertEqual(client, shared['rss-identity-contracts'])
        self.assertNotEqual(client['git'], shared['rss-runtime']['git'])
        self.assertNotIn('path', client)
