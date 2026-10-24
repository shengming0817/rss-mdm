"""Forbidden edges use Cargo's package identity, not the dependency alias."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hack'))
from ci import verify_capability_boundaries


class CapabilityBoundaries(unittest.TestCase):
    def test_target_optional_renamed_and_build_edges_cannot_hide_forbidden_packages(self):
        names = ('certificate apple-mdm inventory-service software-service authorization-service '
                 'registration-service flow-service execution-service content-service management-http '
                 'agent-channel windows-channel apple-channel query http-contract resource resource-postgres').split()
        packages = [dict(id=n, name='rss-mdm-' + n, dependencies=[]) for n in names]
        data = dict(packages=packages, workspace_members=names)
        verify_capability_boundaries(data)
        for owner, name in (('inventory-service', 'axum'), ('query', 'rss-identity-core'),
                            ('http-contract', 'rss-mdm-resource'), ('resource', 'rss-mdm-http-contract')):
            package = next(p for p in packages if p['id'] == owner)
            for kind, target, rename, optional in ((None, None, None, False),
                    (None, 'cfg(unix)', 'alias', False), ('build', 'cfg(windows)', None, True)):
                with self.subTest(owner=owner, kind=kind, target=target, rename=rename):
                    package['dependencies'] = [dict(name=name, kind=kind, target=target, rename=rename, optional=optional)]
                    with self.assertRaisesRegex(RuntimeError, owner):
                        verify_capability_boundaries(data)
            package['dependencies'] = [dict(name=name, kind='dev')]
            verify_capability_boundaries(data)
            package['dependencies'] = []


if __name__ == '__main__':
    unittest.main()
