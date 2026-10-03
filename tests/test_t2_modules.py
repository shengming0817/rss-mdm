"""Module ownership is both the execution and integration-impact boundary."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hack'))
from t2_registry import MODULES, select_paths


class ModuleImpactTests(unittest.TestCase):
    def test_collection_inputs_select_their_actual_protocol_consumers(self):
        cases={
            'crates/execution-service/src/actions/output.rs': {'execution.agent.delivery'},
            'crates/execution-service/src/actions/native_collection.rs': {'windows.management','apple.collection'},
            'crates/execution-service/src/actions/recovery.rs': {'windows.management','apple.collection','execution.agent.recovery','execution.software.recovery'},
        }
        for path,expected in cases.items():
            selected=select_paths([path])
            self.assertFalse(selected.full)
            self.assertEqual(expected, set(selected.modules),(path,selected.modules))

    def test_flow_settlement_selects_its_actual_owners(self):
        selected = select_paths(['crates/flow-service/src/transaction.rs'])
        self.assertFalse(selected.full)
        self.assertTrue({'planning.http', 'planning.recovery', 'planning.resource_archive', 'planning.software', 'planning.onboarding'} <= set(selected.modules))
        self.assertFalse({'enrollment.http', 'agent.registration', 'audit.recovery'} & set(selected.modules))

    def test_export_reader_selects_publication_read_and_withdrawal_consumers(self):
        selected = select_paths(['crates/software-service/src/publication/execution.rs'])
        self.assertFalse(selected.full)
        self.assertTrue({'publication.winget', 'publication.brew', 'publication.withdrawal', 'execution.software.offer'} <= set(selected.modules))

    def test_http_projection_selects_diagnostic_and_management_consumers(self):
        for path in ('crates/management-http/src/response.rs', 'crates/management-http/src/diagnostic.rs'):
            selected = select_paths([path])
            self.assertFalse(selected.full, path)
            self.assertTrue({'api.diagnostics', 'planning.http', 'software.http', 'content.http'} <= set(selected.modules), path)

    def test_execution_queries_select_read_consumers_without_unrelated_protocols(self):
        for path in ('crates/execution-service/src/queries/records.rs',
                     'crates/execution-service/src/queries/error.rs'):
            selected = select_paths([path])
            self.assertFalse(selected.full)
            self.assertEqual(set(selected.modules), {
                'execution.agent.history', 'execution.commands.windows', 'planning.http',
                'planning.agent_policy', 'planning.remote', 'planning.software'}
                | ({'apple.commands','apple.users'} if path.endswith('/records.rs') else {'windows.declared'}))

    def test_native_modules_select_actual_write_read_permission_and_helper_inputs(self):
        for path in ('crates/execution-service/src/service.rs',
                     'crates/execution-service/src/queries/records.rs',
                     'crates/execution-service/src/permissions.rs',
                     'crates/app/tests/device/support.rs'):
            selected = select_paths([path])
            self.assertFalse(selected.full, path)
            self.assertTrue({'apple.commands', 'apple.users'} <= set(selected.modules), path)

    def test_script_preparation_selects_all_script_entrances(self):
        for path in ('crates/resource/src/script.rs',
                     'crates/execution-service/src/input_preparation.rs',
                     'crates/execution-service/src/freeze_inputs.rs',
                     'crates/flow-service/src/resource_catalog/mod.rs'):
            selected = select_paths([path])
            self.assertFalse(selected.full, path)
            self.assertTrue({'planning.agent_policy', 'planning.remote'} <= set(selected.modules), path)
        self.assertIn('execution.agent.recovery', self.selected('crates/resource/src/script.rs'))

    def test_native_rules_select_configuration_consumer(self):
        for path in ('crates/windows-mdm/src/native/request.rs', 'crates/windows-mdm/src/native/verification.rs'):
            self.assertIn('execution.commands.configuration', self.selected(path), path)

    def test_declared_protocol_consumers_select_linked_end_to_end_proof(self):
        for path in (
            'crates/execution-service/src/protocol.rs',
            'crates/execution-service/src/native_configuration.rs',
            'crates/registration-service/src/enrollment/store.rs',
            'crates/registration-service/src/device/read.rs',
            'crates/registration-service/src/device/store.rs',
            'crates/windows-channel/src/management/session.rs',
            'crates/windows-channel/src/renewal.rs',
            'crates/windows-mdm/src/native/request.rs',
            'crates/windows-mdm/src/native/declared.rs',
            'crates/windows-mdm/src/native/verification.rs',
            'crates/certificate/src/windows/linked.rs',
            'crates/management-http/src/error_projection.rs',
        ):
            self.assertIn('windows.declared', self.selected(path), path)

    def test_console_projection_inputs_select_their_http_consumers(self):
        for path in ('crates/resource-postgres/src/codec.rs',
                     'crates/inventory-postgres/src/lib.rs',
                     'crates/execution-service/src/directory.rs'):
            self.assertIn('planning.http', self.selected(path), path)
        self.assertIn('execution.agent.history', self.selected('crates/execution-service/src/directory.rs'))
        self.assertIn('planning.http', self.selected('crates/app/tests/support/agent_execution.rs'))
    def selected(self, path):
        return set(select_paths([path]).modules)

    def test_channel_registrars_select_their_live_consumers(self):
        app = self.selected('crates/app/src/api.rs')
        self.assertTrue({'agent.registration', 'agent.reports', 'windows.management',
                         'apple.identity', 'content.http', 'authorization.rules',
                         'host.lifecycle', 'api.identity_context'} <= app)
        self.assertTrue(app.isdisjoint({'apple.cms', 'apple.apns', 'sources.winget'}))
        self.assertEqual(self.selected('crates/agent-channel/src/tasks.rs'), {
            'execution.agent.delivery', 'execution.agent.poll', 'execution.agent.content',
            'execution.agent.recovery', 'execution.software.offer',
            'execution.software.content', 'execution.software.recovery'})
        self.assertEqual(self.selected('crates/windows-channel/src/lib.rs'), {
            'windows.enrollment', 'windows.issuance', 'windows.management',
            'windows.commands', 'windows.retention', 'windows.limits', 'windows.declared'})

    def test_runtime_diagnostics_has_exact_tests_and_live_owner_inputs(self):
        self.assertEqual(self.selected('crates/app/tests/api/runtime_diagnostics.rs'), {'diagnostics.http'})
        for path in ('crates/app/src/runtime_diagnostics.rs', 'crates/management-http/src/runtime_diagnostics.rs',
                     'crates/inventory-service/src/inventory_runtime.rs', 'crates/inventory-service/src/inventory_runtime/diagnostics.rs',
                     'crates/flow-service/src/automation/runtime.rs', 'crates/app/src/identity_audit.rs'):
            self.assertIn('diagnostics.http', self.selected(path), path)
        self.assertTrue(self.selected('crates/app/tests/api/runtime_diagnostics.rs').isdisjoint({'installation.migration','apple.apns'}))

    def test_device_audit_boundaries_select_fault_projection_tests(self):
        for path in ('crates/audit-integration/src/completion.rs',
                     'crates/agent-channel/src/boundary.rs',
                     'crates/windows-channel/src/boundary.rs',
                     'crates/apple-channel/src/boundary.rs'):
            self.assertIn('api.diagnostics', self.selected(path), path)

    def test_installation_python_selects_only_its_module_and_guards(self):
        selection = select_paths(['hack/t2_modules/installation.py'])
        self.assertFalse(selection.full)
        self.assertEqual(selection.modules, ('installation.migration',))
        self.assertIn('test_t2_guards', selection.tools)

    def test_cluster_role_admission_owns_an_instance(self):
        self.assertEqual(MODULES['inventory.reader'].db_mode, 'instance')
        self.assertEqual(MODULES['inventory.manual'].db_mode, 'reuse')

    def test_unknown_ci_or_nextest_inputs_cannot_silently_skip_integration(self):
        for path in ('.github/workflows/new.yml', '.github/actions/new/action.yml', '.config/nextest.toml'):
            self.assertTrue(select_paths([path]).full)

    def test_test_module_carriers_select_exact_children(self):
        expected = {
            'crates/app/tests/agent/mod.rs': {'agent.registration','agent.reports'},
            'crates/app/tests/api/mod.rs': {'api.identity_context','diagnostics.http'},
            'crates/app/tests/execution/mod.rs': {name for name in MODULES if name.startswith('execution.')},
        }
        for path, modules in expected.items():
            selection=select_paths([path])
            self.assertFalse(selection.full,path)
            self.assertEqual(set(selection.modules),modules,path)

    def test_app_helpers_select_all_actual_consumers(self):
        self.assertEqual(self.selected('crates/app/tests/support/software.rs'), {
            'software.http','content.http','content.mirror','content.gc',
            'planning.software','planning.policy','planning.http','apple.policy','execution.software.offer','execution.software.content','execution.software.recovery'})
        self.assertEqual(self.selected('crates/app/tests/support/process.rs'),
                         {'inventory.runtime','execution.commands.recovery'})
        self.assertEqual(self.selected('crates/app/tests/execution/support.rs'),
                         {'execution.commands.'+part for part in ('admission','dispatch','recovery','windows','configuration','onboarding')} | {'windows.commands','windows.declared'})
        self.assertEqual(self.selected('crates/app/tests/execution/support/configuration.rs'), {'execution.commands.configuration','windows.declared'})
        self.assertEqual(self.selected('crates/app/tests/execution/support/native.rs'),
                         self.selected('crates/app/tests/execution/support.rs'))
        device = self.selected('crates/app/tests/device/support.rs')
        required = {'authorization.admission','enrollment.recovery','native.tls','software.http',
                    'planning.http','execution.software.offer','execution.software.content','execution.software.recovery'}
        required |= {name for name in MODULES if name.startswith(('device.','windows.','execution.commands.'))}
        required |= {'apple.'+part for part in ('collection','profile','policy','renewal','identity','push','fairness','host','scep')}
        self.assertTrue(required <= device,required-device)
        self.assertTrue(device.isdisjoint({'identity.sso','content.http','apple.cms','apple.apns','publication.artifact'}))
        audit = self.selected('crates/app/tests/support/audit.rs')
        required = {'diagnostics.http','api.diagnostics','device.recovery','device.revocation','execution.commands.admission','execution.commands.onboarding',
                    'execution.commands.dispatch','windows.enrollment','windows.issuance','windows.limits',
                    'apple.policy','apple.identity','planning.scope','planning.group_scope','planning.assets',
                    'planning.recovery','planning.resource_archive','planning.agent_policy','assets.http',
                    'enrollment.http','content.http','compliance.http','compliance.recovery','compliance.group_input',
                    'authorization.capacity','authorization.rules','execution.agent.history','execution.agent.content','software.http'}
        required |= {'audit.'+part for part in ('receipts','integrity','recovery','budget')}
        self.assertEqual(audit,required)

    def test_test_changes_do_not_select_production_consumers(self):
        self.assertEqual(self.selected('crates/resource-postgres/tests/behavior.rs'),
                         {'resource.persistence'})
        self.assertEqual(self.selected('crates/content-service/tests/unit.rs'), set())
        self.assertEqual(self.selected('crates/scope/tests/model.rs'), set())
        self.assertEqual(self.selected('crates/app/tests/apple/apns.rs'), {'apple.apns'})

    def test_moved_tests_are_owned_without_business_propagation(self):
        for path, owner in (
            ('crates/app/tests/identity/local.rs', 'identity.local'),
            ('crates/app/tests/enrollment/http.rs', 'enrollment.http'),
            ('crates/app/tests/api/identity_context.rs', 'api.identity_context'),
            ('crates/app/tests/agent/reports.rs', 'agent.reports'),
            ('crates/app/tests/execution/agent/history.rs', 'execution.agent.history'),
            ('crates/examples/src/app/t2/projection.rs', 'inventory.projection'),
            ('crates/app/tests/assets/http.rs', 'assets.http'),
        ):
            with self.subTest(path=path):
                self.assertEqual(self.selected(path), {owner})

    def test_shared_registration_fixture_selects_only_direct_consumers(self):
        self.assertEqual(self.selected('crates/app/tests/support/agent.rs'),
                         {'agent.registration', 'agent.reports', 'planning.remote'})

    def test_content_range_selects_real_download_consumers(self):
        self.assertEqual(self.selected('crates/content-service/src/range.rs'),
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
                                  'crates/app/tests/apple/apns.rs',
                                  'crates/resource-postgres/tests/behavior.rs'])
        self.assertEqual(selection.modules, ('apple.apns', 'resource.persistence'))

    def test_authorization_and_audit_module_inputs_stay_local(self):
        self.assertEqual(self.selected('crates/app/tests/authorization/capacity.rs'),
                         {'authorization.capacity'})
        self.assertEqual(self.selected('crates/app/tests/authorization/mod.rs'),
                         {'authorization.' + part for part in
                          ('rules', 'membership', 'capacity', 'initialization', 'admission')})
        self.assertEqual(self.selected('crates/app/tests/audit/recovery.rs'),
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
                     'crates/agent-wire/schema/signed-task-v6.schema.json',
                     'crates/execution-service/src/task_signing.rs'):
            selected = self.selected(path)
            self.assertTrue(expected <= selected, expected - selected)
            self.assertTrue(selected.isdisjoint({'agent.registration','agent.reports','windows.management',
                                                'apple.policy','identity.sso','gateway.admission'}))
        self.assertEqual(self.selected('crates/agent-wire/schema/registration-request-v6.schema.json'),
                         {'agent.registration'})
        self.assertEqual(self.selected('crates/agent-wire/schema/report-request-v6.schema.json'),
                         {'agent.reports','planning.onboarding'})

    def test_onboarding_wire_selects_its_actual_consumers(self):
        inputs = {
            'crates/agent-wire/src/onboarding.rs': {
                'agent.reports','planning.onboarding','execution.commands.onboarding',
                'apple.onboarding','execution.agent.delivery','execution.agent.poll','execution.agent.recovery'},
            'crates/agent-wire/schema/managed-registration-request-v6.schema.json': {
                'execution.commands.onboarding','apple.onboarding'},
        }
        for path, expected in inputs.items():
            selected = select_paths([path])
            self.assertFalse(selected.full, path)
            self.assertEqual(set(selected.modules), expected, path)

    def test_shared_onboarding_paths_reach_both_native_protocols(self):
        for path in ('crates/agent-wire/src/lib.rs',
                     'crates/execution-service/src/managed_registration.rs',
                     'crates/execution-service/src/native_installation.rs',
                     'crates/inventory-service/src/collection/channel.rs'):
            selection = select_paths([path])
            self.assertFalse(selection.full, path)
            self.assertTrue({'execution.commands.onboarding','apple.onboarding'} <= set(selection.modules), path)

    def test_group_inputs_reach_published_scope_consumers_only(self):
        selected = self.selected('crates/group-postgres/src/lib.rs')
        self.assertTrue({'group.persistence','group.generations','planning.group_scope','planning.scope',
                         'planning.http','planning.policy','compliance.group_input','planning.frequency'} <= selected)
        self.assertTrue(selected.isdisjoint({'authorization.membership','content.http','identity.sso',
                                            'planning.agent_policy','publication.winget','windows.management'}))
        self.assertEqual(self.selected('crates/group-postgres/tests/t2.rs'), {'group.persistence'})

    def test_apple_push_includes_transport_durable_push_and_health_only(self):
        self.assertEqual(self.selected('crates/apple-channel/src/push.rs'),
                         {'apple.apns','apple.push','apple.host'})

    def test_formal_migration_excludes_every_no_pg_module(self):
        selected = self.selected('crates/flow-service/schema/install.sql')
        self.assertEqual(selected, {name for name, module in MODULES.items() if module.postgres})

    def test_authority_and_audit_select_distinct_mutation_seams(self):
        selected = self.selected('crates/authorization-service/src/context.rs')
        self.assertTrue({'authorization.rules','enrollment.http','content.http','content.mirror',
                         'planning.agent_policy','planning.software','software.http','windows.issuance',
                         'apple.scep','apple.renewal','compliance.http','execution.commands.admission'} <= selected)
        self.assertTrue(selected.isdisjoint({'assets.queries','execution.agent.history','windows.limits',
                                            'publication.artifact','sources.brew_git','apple.apns'}))
        selected = self.selected('crates/audit-integration/src/lib.rs')
        self.assertTrue({'audit.receipts','audit.integrity','audit.recovery','audit.budget','execution.commands.onboarding',
                         'authorization.rules','enrollment.recovery','device.binding','content.http',
                         'software.catalog','execution.commands.dispatch','publication.recovery'} <= selected)
        self.assertTrue(selected.isdisjoint({'publication.artifact','sources.brew_git','apple.apns','apple.cms'}))

    def test_publication_files_select_their_real_semantic_modules(self):
        self.assertEqual(self.selected('crates/software-service/src/publication/driver.rs'),
                         {'publication.winget','publication.brew','publication.withdrawal','publication.recovery'})
        self.assertEqual(self.selected('crates/software-service/src/publication/references.rs'),
                         {'publication.mapping','planning.resource_archive'})
        self.assertEqual(self.selected('crates/management-http/src/software_catalog.rs'), {'software.http'})
        self.assertEqual(self.selected('crates/software-service/src/management/catalog.rs'), {'software.http'})
        self.assertEqual(self.selected('crates/content-service/src/software.rs'), {'software.http'})
        self.assertEqual(self.selected('crates/software-service/src/preparation/mod.rs'),
                         {'software.catalog','planning.software','planning.onboarding','execution.commands.onboarding',
                          'execution.software.offer','execution.software.content','execution.software.recovery'})


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
        self.assertEqual(self.selected('crates/app/tests/execution/agent/history/deleted.rs'),
                         {'execution.agent.history'})
        module = Module('new.owner', APP, ('new::',),
                        test_inputs=('crates/app/tests/new/mod.rs',))
        with patch.dict(MODULES, {'new.owner': module}):
            self.assertEqual(self.selected('crates/app/tests/new/mod.rs'), {'new.owner'})
        selected = set(select_paths(['crates/content-service/tests/unit.rs',
                                    'crates/content-service/src/range.rs',
                                    'crates/resource-postgres/tests/behavior.rs']).modules)
        self.assertEqual(selected, {'content.http','execution.agent.content',
                                    'execution.software.content','resource.persistence'})
        self.assertEqual(select_paths([]).modules, ())


if __name__ == '__main__':
    unittest.main()
