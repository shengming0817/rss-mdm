"""The modular host must not regain business, protocol, or signing authority."""
from pathlib import Path
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]
SERVICES = {'authorization-service', 'registration-service', 'inventory-service',
            'flow-service', 'content-service'}
INGRESS = {'management-http', 'agent-channel', 'windows-channel', 'apple-channel'}


def dependencies(package):
    manifest = ROOT / 'crates' / package / 'Cargo.toml'
    if not manifest.is_file():
        raise AssertionError(f'missing capability owner: {package}')
    data = tomllib.loads(manifest.read_text())
    return set(data.get('dependencies', {}))


class CapabilityBoundaries(unittest.TestCase):
    def test_certificate_has_no_transport_storage_or_business_dependencies(self):
        deps = dependencies('certificate')
        self.assertFalse(deps & {'sqlx', 'axum', 'reqwest', 'rss-runtime'})
        self.assertFalse({name for name in deps if name.startswith('rss-mdm-')})

    def test_apple_codec_has_no_runtime_or_product_dependencies(self):
        deps = dependencies('apple-mdm')
        self.assertFalse(deps & {'sqlx', 'axum', 'reqwest', 'tokio', 'tokio-rustls'})
        self.assertFalse({name for name in deps if name.startswith('rss-mdm-')})

    def test_services_cannot_import_host_or_ingress(self):
        forbidden = {'rss-mdm-app', 'axum'} | {f'rss-mdm-{p}' for p in INGRESS}
        for package in SERVICES:
            with self.subTest(package=package):
                self.assertFalse(dependencies(package) & forbidden)

    def test_inventory_has_no_channel_protocol_dependencies(self):
        self.assertFalse(dependencies("inventory-service") & {
            "rss-mdm-agent-wire", "rss-mdm-windows-mdm", "rss-mdm-apple-mdm", "plist"})

    def test_channels_do_not_depend_on_each_other(self):
        forbidden = {'rss-mdm-app'} | {f'rss-mdm-{p}' for p in INGRESS}
        for package in INGRESS:
            with self.subTest(package=package):
                self.assertFalse(dependencies(package) & forbidden)

    def test_host_has_no_business_module_owners(self):
        forbidden = {'authorization', 'device', 'enrollment', 'assets', 'collection',
                     'execution', 'planning', 'resource_catalog', 'content',
                     'agent', 'apple', 'windows', 'operations', 'transaction'}
        actual = {p.stem for p in (ROOT / 'crates/app/src').iterdir()}
        self.assertFalse(actual & forbidden, sorted(actual & forbidden))


if __name__ == '__main__':
    unittest.main()
