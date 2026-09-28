"""Module ownership is both the execution and integration-impact boundary."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hack'))
from t2_registry import MODULES, select_paths


class ModuleImpactTests(unittest.TestCase):
    def selected(self, path):
        return set(select_paths([path]).modules)

    def test_installation_python_selects_only_its_module_and_guards(self):
        selection = select_paths(['hack/t2_modules/installation.py'])
        self.assertFalse(selection.full)
        self.assertEqual(selection.modules, ('installation.migration',))
        self.assertIn('test_t2_guards', selection.tools)

    def test_cluster_role_admission_test_is_exclusive(self):
        self.assertTrue(MODULES['inventory.reader'].exclusive)
        self.assertFalse(MODULES['inventory.manual'].exclusive)

    def test_unknown_ci_or_nextest_inputs_cannot_silently_skip_integration(self):
        for path in ('.github/workflows/new.yml', '.github/actions/new/action.yml', '.config/nextest.toml'):
            self.assertTrue(select_paths([path]).full)

    def test_test_module_carriers_select_exact_children(self):
        expected = {
            'crates/app/src/agent/t2/mod.rs': {'agent.registration','agent.reports'},
            'crates/app/src/api/t2/mod.rs': {'api.identity_context'},
            'crates/app/src/execution/t2/mod.rs': {name for name in MODULES if name.startswith('execution.')},
        }
        for path, modules in expected.items():
            selection=select_paths([path])
            self.assertFalse(selection.full,path)
            self.assertEqual(set(selection.modules),modules,path)

    def test_test_changes_do_not_select_production_consumers(self):
        self.assertEqual(self.selected('crates/resource-postgres/tests/behavior.rs'),
                         {'resource.persistence'})
        self.assertEqual(self.selected('crates/app/src/content/tests.rs'), set())
        self.assertEqual(self.selected('crates/scope/tests/model.rs'), set())
        self.assertEqual(self.selected('crates/app/src/apple/push_tests.rs'), {'apple.apns'})

    def test_moved_tests_are_owned_without_business_propagation(self):
        for path, owner in (
            ('crates/app/src/identity/t2/local/mod.rs', 'identity.local'),
            ('crates/app/src/enrollment/t2/http/mod.rs', 'enrollment.http'),
            ('crates/app/src/api/t2/identity_context/mod.rs', 'api.identity_context'),
            ('crates/app/src/agent/t2/reports.rs', 'agent.reports'),
            ('crates/app/src/execution/t2/agent/history.rs', 'execution.agent.history'),
            ('crates/examples/src/app/t2/projection.rs', 'inventory.projection'),
            ('crates/app/src/assets/t2/http/identity_read.rs', 'assets.http'),
        ):
            with self.subTest(path=path):
                self.assertEqual(self.selected(path), {owner})

    def test_shared_registration_fixture_selects_only_direct_consumers(self):
        self.assertEqual(self.selected('crates/app/src/test_support/agent.rs'),
                         {'agent.registration', 'agent.reports', 'planning.remote'})

    def test_content_range_selects_real_download_consumers(self):
        self.assertEqual(self.selected('crates/app/src/content/range.rs'),
                         {'content.http', 'execution.agent.content', 'execution.software.content'})

    def test_git_change_selects_only_git_seams(self):
        self.assertEqual(self.selected('crates/brew-source/src/git.rs'),
                         {'sources.brew_git', 'sources.brew_recovery', 'publication.brew'})

    def test_product_migrations_do_not_start_unrelated_protocol_fixtures(self):
        selected = self.selected('crates/app/src/migration.rs')
        self.assertIn('installation.migration', selected)
        self.assertIn('catalog.contract', selected)
        self.assertNotIn('apple.cms', selected)
        self.assertNotIn('apple.apns', selected)
        self.assertNotIn('sources.winget', selected)
        self.assertNotIn('publication.artifact', selected)
        self.assertNotIn('gateway.admission', selected)

    def test_python_tests_and_docs_do_not_select_integration(self):
        self.assertEqual(self.selected('tests/test_source_t2.py'), set())
        self.assertEqual(self.selected('docs/guides/local-development.md'), set())
        self.assertEqual(self.selected('deny.toml'), set())
        self.assertEqual(self.selected('clippy.toml'), set())

    def test_unknown_and_execution_infrastructure_are_fail_closed(self):
        for path in ('unknown.file', 'hack/t2.py', 'hack/t2_environment.py',
                     'crates/app/src/new_owner/tests.rs'):
            with self.subTest(path=path):
                selection = select_paths([path])
                self.assertTrue(selection.full)
                self.assertEqual(set(selection.modules), set(MODULES))

    def test_multiple_inputs_union_without_broadening(self):
        selection = select_paths(['crates/resource-postgres/tests/behavior.rs',
                                  'crates/app/src/apple/push_tests.rs',
                                  'crates/resource-postgres/tests/behavior.rs'])
        self.assertEqual(selection.modules, ('apple.apns', 'resource.persistence'))

    def test_authorization_and_audit_module_inputs_stay_local(self):
        self.assertEqual(self.selected('crates/app/src/authorization/t2/capacity.rs'),
                         {'authorization.capacity'})
        self.assertEqual(self.selected('crates/app/src/authorization/t2/mod.rs'),
                         {'authorization.' + part for part in
                          ('rules', 'membership', 'capacity', 'initialization', 'admission')})
        self.assertEqual(self.selected('crates/app/src/audit_integration_tests/recovery.rs'),
                         {'audit.recovery'})
        self.assertEqual(self.selected('crates/compliance-postgres/tests/t2.rs'),
                         {'compliance.storage'})

    def test_target_selection_accepts_discovered_test_renames(self):
        module = MODULES['resource.persistence']
        self.assertTrue(module.includes('a_new_behavior'))
        self.assertTrue(module.includes('admission::renamed_behavior'))

    def test_every_production_pattern_matches_a_real_owner_input(self):
        root = Path(__file__).resolve().parents[1]
        for module in MODULES.values():
            for pattern in module.production_inputs:
                with self.subTest(module=module.id, pattern=pattern):
                    self.assertTrue(list(root.glob(pattern)), 'invented production path')

    def test_resource_storage_reaches_real_consumers_without_artifact_only(self):
        selected = self.selected('crates/resource-postgres/src/lib.rs')
        expected = {'resource.persistence','resource.recovery','software.catalog','software.http',
                    'content.http','content.mirror','content.gc','planning.software',
                    'planning.resource_archive','publication.winget','publication.brew',
                    'publication.mapping','publication.withdrawal','publication.recovery'}
        self.assertTrue(expected <= selected, expected - selected)
        self.assertTrue(selected.isdisjoint({'publication.artifact','sources.winget',
                                            'apple.apns','apple.cms','gateway.admission'}))

    def test_task_wire_and_signing_select_task_consumers_not_native_protocols(self):
        expected = {'planning.agent_policy','planning.frequency','planning.remote','planning.software',
                    'execution.agent.delivery','execution.agent.poll','execution.agent.content',
                    'execution.agent.recovery','execution.software.offer','execution.software.content',
                    'execution.software.recovery'}
        for path in ('crates/agent-wire/src/tasks.rs',
                     'crates/agent-wire/schema/signed-task-v3.schema.json',
                     'crates/app/src/task_signing.rs'):
            selected = self.selected(path)
            self.assertTrue(expected <= selected, expected - selected)
            self.assertTrue(selected.isdisjoint({'agent.registration','agent.reports','windows.management',
                                                'apple.policy','identity.sso','gateway.admission'}))
        self.assertEqual(self.selected('crates/agent-wire/schema/registration-request-v3.schema.json'),
                         {'agent.registration'})
        self.assertEqual(self.selected('crates/agent-wire/schema/report-request-v3.schema.json'),
                         {'agent.reports'})

    def test_group_inputs_reach_published_scope_consumers_only(self):
        selected = self.selected('crates/group-postgres/src/lib.rs')
        self.assertTrue({'group.persistence','group.generations','planning.group_scope','planning.scope',
                         'planning.http','planning.policy','compliance.group_input','planning.frequency'} <= selected)
        self.assertTrue(selected.isdisjoint({'authorization.membership','content.http','identity.sso',
                                            'planning.agent_policy','publication.winget','windows.management'}))
        self.assertEqual(self.selected('crates/group-postgres/tests/t2.rs'), {'group.persistence'})

    def test_apple_push_includes_transport_durable_push_and_health_only(self):
        self.assertEqual(self.selected('crates/app/src/apple/push.rs'),
                         {'apple.apns','apple.push','apple.host'})

    def test_formal_migration_excludes_every_no_pg_module(self):
        selected = self.selected('crates/app/migrations/0021_software_deployment.sql')
        self.assertEqual(selected, {name for name, module in MODULES.items() if module.postgres})

    def test_authority_and_audit_select_distinct_mutation_seams(self):
        selected = self.selected('crates/app/src/authorization/context.rs')
        self.assertTrue({'authorization.rules','enrollment.http','content.http','content.mirror',
                         'planning.agent_policy','planning.software','software.http','windows.issuance',
                         'apple.scep','apple.renewal','compliance.http','execution.commands.admission'} <= selected)
        self.assertTrue(selected.isdisjoint({'assets.queries','execution.agent.history','windows.limits',
                                            'publication.artifact','sources.brew_git','apple.apns'}))
        selected = self.selected('crates/audit-integration/src/lib.rs')
        self.assertTrue({'audit.receipts','audit.integrity','audit.recovery','audit.budget',
                         'authorization.rules','enrollment.recovery','device.binding','content.http',
                         'software.catalog','execution.commands.dispatch','publication.recovery'} <= selected)
        self.assertTrue(selected.isdisjoint({'publication.artifact','sources.brew_git','apple.apns','apple.cms'}))

    def test_publication_files_select_their_real_semantic_modules(self):
        self.assertEqual(self.selected('crates/software-service/src/publication/driver.rs'),
                         {'publication.winget','publication.brew','publication.withdrawal','publication.recovery'})
        self.assertEqual(self.selected('crates/software-service/src/publication/references.rs'),
                         {'publication.mapping','planning.resource_archive'})
        self.assertEqual(self.selected('crates/app/src/software_catalog.rs'), {'software.http'})

    def test_shared_software_helpers_follow_behavioral_consumption(self):
        self.assertEqual(self.selected('tests/support/software/ack.rs'), {'publication.recovery'})
        self.assertEqual(self.selected('tests/support/software/pg.rs'),
                         {'software.catalog','publication.winget','publication.brew','publication.mapping',
                          'publication.withdrawal','publication.recovery'})
        selected = self.selected('tests/support/software/mod.rs')
        self.assertTrue({'software.catalog','software.http','planning.resource_archive','authorization.rules',
                         'content.http','content.mirror','content.gc','publication.artifact'} <= selected)
        self.assertNotIn('identity.sso', selected)

    def test_new_deleted_and_mixed_test_paths_remain_owned(self):
        from unittest.mock import patch
        from t2_registry import APP, Module
        # Selection does not depend on whether a test file still exists on disk.
        self.assertEqual(self.selected('crates/app/src/execution/t2/agent/history/deleted.rs'),
                         {'execution.agent.history'})
        module = Module('new.owner', APP, ('new::',),
                        test_inputs=('crates/app/src/new/t2.rs',))
        with patch.dict(MODULES, {'new.owner': module}):
            self.assertEqual(self.selected('crates/app/src/new/t2.rs'), {'new.owner'})
        selected = set(select_paths(['crates/app/src/content/tests.rs',
                                    'crates/app/src/content/range.rs',
                                    'crates/resource-postgres/tests/behavior.rs']).modules)
        self.assertEqual(selected, {'content.http','execution.agent.content',
                                    'execution.software.content','resource.persistence'})
        self.assertEqual(select_paths([]).modules, ())


if __name__ == '__main__':
    unittest.main()
