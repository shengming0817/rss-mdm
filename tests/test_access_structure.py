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
        self.assertEqual(client['git'], 'https://dev.azure.com/shengming0923/rss/_git/rss-identity')
        self.assertEqual(client['rev'], '2e66cac2bb8064701c5e99c992858b178f875656')
        self.assertNotIn('path', client)
