"""Fixture preparation follows the selected modules and service phase."""
from pathlib import Path
import sys
import unittest
import threading
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hack'))
from t2_fixtures import RunFixtures
from t2_registry import MODULES


class PreparationTests(unittest.TestCase):
    def fixture(self):
        # No service is started by these preparation contract tests.
        fixture = RunFixtures.__new__(RunFixtures)
        fixture.postgres = Mock()
        fixture.template = Mock()
        fixture.lock = threading.RLock()
        fixture.certificates = Mock()
        return fixture

    def test_stale_gateway_is_recovered_even_without_postgres(self):
        fixture = self.fixture()
        fixture.owner, fixture.gateway_owner = Mock(), Mock()
        fixture.owner.root.exists.return_value = False
        fixture.gateway_owner.root.exists.return_value = True
        fixture.cleanup_environments()
        fixture.owner.reset.assert_not_called()
        fixture.gateway_owner.reset.assert_called_once()

    def test_cleanup_attempts_all_owners_if_one_fails(self):
        fixture = self.fixture()
        fixture.owner, fixture.gateway_owner = Mock(), Mock()
        fixture.owner.reset.side_effect = RuntimeError('broken postgres cleanup')
        with self.assertRaisesRegex(RuntimeError, 'clean owned'):
            fixture.cleanup_environments()
        fixture.gateway_owner.reset.assert_called_once()

    def test_exclusive_only_does_not_start_an_unused_normal_service(self):
        fixture = self.fixture()
        fixture.prepare([MODULES['identity.local']])
        fixture.postgres.assert_not_called()
        fixture.template.assert_not_called()

    def test_normal_modules_share_one_service_and_profile_baseline(self):
        fixture = self.fixture()
        fixture.prepare([MODULES['agent.registration'], MODULES['agent.reports']])
        fixture.postgres.assert_called_once_with()
        fixture.template.assert_called_once_with('product')

    def test_artifact_only_starts_no_database(self):
        fixture = self.fixture()
        fixture.prepare([MODULES['publication.artifact']])
        fixture.postgres.assert_not_called()
        fixture.template.assert_not_called()


if __name__ == '__main__':
    unittest.main()
