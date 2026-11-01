"""Forbidden edges use Cargo's package identity, not the dependency alias."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hack'))
from ci import verify_capability_boundaries


class CapabilityBoundaries(unittest.TestCase):
    def test_target_optional_renamed_and_build_edges_cannot_hide_forbidden_packages(self):
        names = ('group-service compliance-service recovery-observation certificate apple-mdm inventory-service software-service authorization-service '
                 'registration-service script-service device-service content-service webhook-service management-http device-access-http '
                 'task-state task-trust agent-channel windows-channel apple-channel query http-contract resource resource-postgres group group-postgres scope policy scope-postgres scope-service policy-service resource-service').split()
        packages = [dict(id=n, name='rss-mdm-' + n, dependencies=[]) for n in names]
        data = dict(packages=packages, workspace_members=names)
        verify_capability_boundaries(data)
        trust = next(p for p in packages if p['id'] == 'task-trust')
        trust['dependencies'] = [dict(name=name, kind=None) for name in
                                 ('rss-mdm-registration-service', 'rss-mdm-authorization-service')]
        verify_capability_boundaries(data)
        # Platform SSO consumes canonical wire DTOs, whose pure production closure is separately checked.
        apple = next(p for p in packages if p['id'] == 'apple-mdm')
        apple['dependencies'] = [dict(name='rss-mdm-agent-wire', kind=None)]
        verify_capability_boundaries(data)
        apple['dependencies'] = [dict(name='rss-mdm-registration-service', kind=None)]
        with self.assertRaisesRegex(RuntimeError, 'apple-mdm'):
            verify_capability_boundaries(data)
        apple['dependencies'] = []
        for owner, name in (('task-state', 'rss-mdm-script-service'),
                            ('task-state', 'rss-reconcile'), ('task-state', 'sqlx'),
                            ('task-trust', 'rss-mdm-device-service'),
                            ('task-trust', 'rss-mdm-script-service'),
                            ('task-trust', 'rss-mdm-inventory-service'),
                            ('software-service', 'rss-mdm-agent-channel'),
                            ('software-service', 'rss-mdm-windows-channel'),
                            ('software-service', 'rss-mdm-apple-channel'),
                            ('device-access-http','rss-mdm-agent-channel'), ('agent-channel','rss-mdm-device-access-http'), ('task-trust','rss-mdm-device-access-http'), ('agent-channel','rss-mdm-device-service'), ('windows-channel','rss-mdm-device-service'), ('webhook-service','rss-mdm-management-http'), ('webhook-service','rss-mdm-inventory-service'), ('inventory-service', 'axum'), ('query', 'rss-identity-core'),
                            ('http-contract', 'rss-mdm-resource'), ('resource', 'rss-mdm-http-contract'),
                            ('scope', 'rss-mdm-policy-service'),
                            ('scope', 'rss-transactional-messaging-postgres'),
                            ('group', 'reqwest'),
                            ('scope-postgres', 'rss-mdm-resource-service'),
                            ('inventory-service', 'rss-mdm-policy-service'),
                            ('inventory-service','rss-mdm-group-service'),
                            ('group-service','rss-mdm-compliance-service'),
                            ('compliance-service','rss-mdm-group-service'),
                            ('recovery-observation','rss-mdm-group-service'),
                            ('recovery-observation','sqlx'),
                            ('resource-service', 'rss-mdm-policy-service')):
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
