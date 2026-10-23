"""The modular host must not regain business, protocol, or signing authority."""
from pathlib import Path
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]
SERVICES = {'authorization-service', 'registration-service', 'inventory-service',
            'flow-service', 'execution-service', 'content-service'}
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

    def test_query_and_route_contract_keep_their_owners(self):
        query = dependencies('query')
        self.assertFalse(query & {'axum', 'sqlx', 'tokio'})
        self.assertFalse({name for name in query if name.startswith(('rss-mdm-', 'rss-identity-'))})
        route = dependencies('http-contract')
        self.assertFalse(route & {'sqlx', 'rss-runtime'})
        self.assertFalse({name for name in route if name.startswith(('rss-mdm-', 'rss-identity-'))})
        for package in SERVICES | {'resource', 'resource-postgres'}:
            self.assertNotIn('rss-mdm-http-contract', dependencies(package), package)

    def test_services_cannot_import_host_or_ingress(self):
        forbidden = {'rss-mdm-app', 'axum'} | {f'rss-mdm-{p}' for p in INGRESS}
        for package in SERVICES:
            with self.subTest(package=package):
                self.assertFalse(dependencies(package) & forbidden)

    def test_inventory_has_no_channel_protocol_dependencies(self):
        self.assertFalse(dependencies("inventory-service") & {
            "rss-mdm-windows-mdm", "rss-mdm-apple-mdm", "plist"})

    def test_channels_do_not_depend_on_each_other(self):
        forbidden = {'rss-mdm-app'} | {f'rss-mdm-{p}' for p in INGRESS}
        for package in INGRESS:
            with self.subTest(package=package):
                self.assertFalse(dependencies(package) & forbidden)

    def test_native_protocols_have_no_flow_error_bus_dependency(self):
        for package in ('agent-channel', 'windows-channel', 'apple-channel'):
            self.assertNotIn('rss-mdm-flow-service', dependencies(package), package)

    def test_execution_and_content_do_not_depend_on_flow(self):
        for owner in ('execution-service', 'content-service'):
            self.assertNotIn('rss-mdm-flow-service', dependencies(owner))

    def test_publication_has_no_consumer_dependencies(self):
        self.assertFalse(dependencies('software-service') & {
            'rss-mdm-app', 'rss-mdm-flow-service', 'rss-mdm-content-service',
            'rss-mdm-management-http'})


if __name__ == '__main__':
    unittest.main()
