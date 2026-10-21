"""Module ownership is both the execution and integration-impact boundary."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hack'))
from t2_registry import MODULES
from ci_impact import select_inputs, SelectionError


class ModuleImpactTests(unittest.TestCase):
    def test_descriptive_objects_select_their_storage_and_http_consumers(self):
        cases = {
            'crates/policy/src/presentation.rs': {'policy.persistence', 'planning.self_service'},
            'crates/group-postgres/src/presentation.rs': {'group.persistence'},
            'crates/resource/src/presentation.rs': {'resource.persistence', 'software.http'},
            'crates/compliance/src/presentation.rs': {'compliance.storage', 'compliance.http'},
            'crates/certificate-archive-service/src/presentation.rs': {'certificate-archive.http'},
            'crates/webhook-service/src/presentation.rs': {'webhooks.product'},
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                self.assertTrue(expected <= set(select_inputs([path]).modules))

    def test_recovery_schema_selects_installation_catalog_and_business_consumers(self):
        selected=set(select_inputs(['crates/recovery-credentials/schema/install.sql']).modules)
        self.assertTrue({'installation.migration','catalog.contract','recovery-credentials.http','apple.commands','execution.agent.delivery'} <= selected,selected)

    def test_upload_budget_selects_its_content_and_execution_consumers(self):
        self.assertEqual(self.selected('crates/content-service/src/budget.rs'),
                         self.selected('crates/content-service/src/transaction.rs'))
        for module in ('content.http', 'content.storage', 'content.mirror'):
            self.assertIn(module, self.selected('crates/content-service/src/budget.rs'))

    def test_macos_native_definitions_select_the_shared_collection_consumers(self):
        shared = select_inputs(['crates/agent-wire/src/native_collection.rs']).modules
        selected = select_inputs(['crates/agent-wire/src/native_collection/macos.rs']).modules
        self.assertEqual(selected, shared)
        self.assertIn('execution.agent.delivery', selected)
        self.assertIn('planning.agent_policy', selected)
        self.assertEqual(select_inputs(['crates/agent-wire/tests/macos_collection.rs']).modules, ())

    def test_management_limits_and_moved_entra_owners_select_real_consumers(self):
        for path, expected in {
            'crates/management-http/src/body_policy.rs': {'windows.entra', 'agent.pki', 'planning.agent_policy', 'content.http'},
            'crates/registration-service/src/windows_entra.rs': {'windows.entra'},
            'crates/inventory-service/src/apple_collection_receipts.rs': {'apple.collection'},
            'crates/registration-service/src/windows_receipts.rs': {'windows.entra', 'windows.issuance', 'windows.declared'},
            'crates/registration-service/schema/windows-receipts.sql': {'windows.entra', 'windows.issuance', 'windows.declared'},
        }.items():
            with self.subTest(path=path):
                self.assertTrue(expected <= set(select_inputs([path]).modules))

    def test_selected_channel_inputs_reach_native_and_self_service_consumers(self):
        for path in ('crates/inventory-service/src/objects.rs','crates/device-service/src/planning.rs','crates/device-service/src/planning/snapshots.rs','crates/flow-service/src/planning/targets.rs','crates/flow-service/src/planning/automation/relations.rs'):
            with self.subTest(path=path):
                selected=set(select_inputs([path]).modules)
                self.assertTrue({'apple.policy','apple.collection','apple.account_enrollment','apple.onboarding','planning.self_service','planning.onboarding','execution.commands.onboarding'} <= selected, selected)
                self.assertTrue(selected.isdisjoint({'apple.apns','sources.brew_git','identity.oidc'}),selected)

    def test_shared_apple_organization_schema_selects_both_enrollment_consumers(self):
        selected=select_inputs(['crates/apple-channel/schema/organizations.sql'])
        self.assertTrue({'apple.ade','apple.account_enrollment'} <= set(selected.modules))

    def test_configuration_inputs_select_their_real_consumers(self):
        for path, expected in {
            'crates/content-service/src/reader.rs': {'agent.configurations', 'content.http', 'content.storage'},
            'crates/agent-channel/src/enroll.rs': {'agent.configurations', 'agent.pki', 'agent.registration'},
            'crates/agent-wire/src/enroll.rs': {'agent.configurations', 'agent.pki', 'agent.registration'},
        }.items():
            with self.subTest(path=path):
                selected = set(select_inputs([path]).modules)
                self.assertTrue(expected <= selected, selected)
                self.assertTrue(selected.isdisjoint({'sources.brew_git', 'apple.apns'}), selected)

    def test_pki_artifacts_select_the_shared_protocol_consumers(self):
        expected = select_inputs(['crates/agent-wire/src/pki.rs']).modules
        for file in ('manifest.json', 'trust-v1.schema.json', 'acknowledgement-v1.schema.json'):
            selected = select_inputs(['crates/agent-wire/schema/pki/' + file])
            self.assertEqual(selected.modules, expected)
            self.assertIn('agent.pki', selected.modules)
        self.assertEqual(select_inputs(['crates/agent-wire/tests/pki.rs']).modules, ())

    def test_self_service_consumes_trusted_subject_and_session_authority(self):
        for path in ('crates/authorization-service/src/evaluate.rs',
                     'crates/authorization-service/src/session.rs'):
            self.assertIn('planning.self_service', select_inputs([path]).modules, path)

    def test_agent_pki_consumes_authorization_registration_audit_and_tls_inputs(self):
        for path in ('crates/authorization-service/src/context.rs',
                     'crates/registration-service/src/enrollment/store.rs',
                     'crates/registration-service/src/operations.rs',
                     'crates/audit-integration/src/store.rs',
                     'crates/certificate/src/peer.rs'):
            selected = select_inputs([path])
            self.assertIn('agent.pki', selected.modules, path)
        selected = select_inputs(['crates/certificate/tests/agent.rs'])
        self.assertEqual(selected.modules, ())

    def test_archive_selects_real_consumers_and_keeps_t1_independent(self):
        for path in ('crates/native-protection/src/lib.rs',
                     'crates/authorization-service/src/model.rs',
                     'crates/audit-integration/src/lib.rs',
                     'crates/management-http/src/boundary.rs',
                     'crates/app/tests/support/planning_http.rs'):
            selected = select_inputs([path])
            self.assertIn('certificate-archive.http', selected.modules, path)
        selected = select_inputs(['crates/certificate-archive-service/tests/behavior.rs'])
        self.assertEqual(selected.modules, ())

    def test_collection_inputs_select_their_actual_protocol_consumers(self):
        cases={
            'crates/execution-service/src/actions/output.rs': {'execution.agent.delivery'},
            'crates/execution-service/src/actions/native_collection.rs': {'windows.management','apple.collection','apple.fairness','apple.identity','apple.policy'},
            'crates/execution-service/src/actions/native_recovery.rs': {'windows.management','apple.collection','apple.fairness','apple.identity','apple.policy'},
            'crates/execution-service/src/actions/recovery.rs': {'windows.management','apple.collection','apple.fairness','apple.identity','apple.policy','execution.agent.recovery','execution.software.recovery'},
        }
        for path,expected in cases.items():
            selected=select_inputs([path])
            self.assertEqual(expected, set(selected.modules),(path,selected.modules))

    def test_flow_settlement_selects_its_actual_owners(self):
        selected = select_inputs(['crates/flow-service/src/transaction.rs'])
        self.assertTrue({'planning.http', 'planning.recovery', 'planning.resource_archive', 'planning.software', 'planning.onboarding'} <= set(selected.modules))
        self.assertFalse({'enrollment.http', 'agent.registration', 'audit.recovery'} & set(selected.modules))

    def test_shared_job_and_route_owners_are_selected(self):
        expected = {
            'crates/flow-service/src/automation/jobs.rs': {
                'assets.queries', 'assets.group_input', 'compliance.http', 'compliance.group_input',
                'planning.group_scope', 'planning.scope', 'planning.policy', 'planning.agent_policy',
                'planning.frequency', 'planning.recovery', 'diagnostics.http'},
            'crates/management-http/src/planning/mod.rs': {
                'planning.self_service', 'planning.http', 'planning.policy', 'planning.agent_policy', 'planning.frequency',
                'planning.software'},
            'crates/management-http/src/software_native.rs': {
                'publication.winget', 'publication.brew', 'publication.withdrawal'},
            'hack/enrollment-password.py': {'enrollment.http', 'enrollment.recovery'},
        }
        for path, modules in expected.items():
            with self.subTest(path=path):
                self.assertEqual(set(select_inputs([path]).modules), modules)

    def test_export_reader_selects_publication_read_and_withdrawal_consumers(self):
        selected = select_inputs(['crates/software-service/src/publication/execution.rs'])
        self.assertTrue({'publication.winget', 'publication.brew', 'publication.withdrawal', 'execution.software.offer'} <= set(selected.modules))

    def test_http_projection_selects_diagnostic_and_management_consumers(self):
        for path in ('crates/management-http/src/response.rs', 'crates/management-http/src/diagnostic.rs'):
            selected = select_inputs([path])
            self.assertTrue({'api.diagnostics', 'planning.http', 'software.http', 'content.http'} <= set(selected.modules), path)

    def test_execution_queries_select_read_consumers_without_unrelated_protocols(self):
        for path in ('crates/execution-service/src/queries/records.rs',
                     'crates/execution-service/src/queries/error.rs'):
            selected = select_inputs([path])
            self.assertEqual(set(selected.modules), {
                'execution.agent.history', 'execution.commands.windows', 'planning.http',
                'planning.agent_policy', 'planning.software'}
                | ({'apple.commands','apple.users','apple.ddm'} if path.endswith('/records.rs') else {'windows.declared'}))

    def test_native_modules_select_actual_write_read_permission_and_helper_inputs(self):
        for path in ('crates/execution-service/src/service.rs',
                     'crates/execution-service/src/queries/records.rs',
                     'crates/execution-service/src/permissions.rs',
                     'crates/app/tests/device/support.rs'):
            selected = select_inputs([path])
            self.assertTrue({'apple.commands', 'apple.users'} <= set(selected.modules), path)

    def test_ddm_authority_and_reads_select_native_consumers(self):
        for path in ('crates/authorization-service/src/authority.rs',
                     'crates/authorization-service/src/model.rs',
                     'crates/execution-service/src/frozen.rs',
                     'crates/execution-service/src/storage.rs',
                     'crates/execution-service/src/apple.rs',
                     'crates/execution-service/src/authority.rs',
                     'crates/execution-service/src/permissions.rs',
                     'crates/execution-service/src/queries.rs',
                     'crates/execution-service/src/transaction.rs',
                     'crates/apple-mdm/src/native/request.rs'):
            selected = select_inputs([path])
            self.assertTrue({'apple.ddm'} <= set(selected.modules), path)

    def test_script_preparation_selects_all_script_entrances(self):
        for path in ('crates/resource/src/script.rs',
                     'crates/execution-service/src/input_preparation.rs',
                     'crates/execution-service/src/freeze_inputs.rs',
                     'crates/flow-service/src/resource_catalog/mod.rs'):
            selected = select_inputs([path])
            self.assertTrue({'planning.agent_policy'} <= set(selected.modules), path)
        self.assertIn('execution.agent.recovery', self.selected('crates/resource/src/script.rs'))
        for path in ('crates/execution-service/src/input_preparation.rs',
                     'crates/execution-service/src/input_preparation/publication.rs'):
            self.assertTrue({'planning.frequency', 'execution.agent.delivery',
                             'execution.agent.content', 'execution.agent.recovery'}
                            <= set(self.selected(path)), path)


    def test_configuration_preparation_selects_lifecycle_consumer(self):
        for path in ('crates/execution-service/src/input_preparation.rs',
                     'crates/execution-service/src/input_preparation/request.rs',
                     'crates/execution-service/src/input_preparation/native.rs',
                     'crates/execution-service/src/input_preparation/publication.rs'):
            with self.subTest(path=path):
                self.assertIn('execution.commands.configuration', self.selected(path))
        for path in ('crates/execution-service/src/input_preparation/preview.rs',
                     'crates/execution-service/src/input_preparation/software.rs'):
            with self.subTest(path=path):
                self.assertNotIn('execution.commands.configuration', self.selected(path))

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
            'crates/device-trust/src/windows/linked.rs',
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
        return set(select_inputs([path]).modules)

    def test_channel_registrars_select_their_live_consumers(self):
        app = self.selected('crates/app/src/api.rs')
        self.assertTrue({'agent.registration', 'agent.reports', 'windows.management',
                         'apple.identity', 'content.http', 'authorization.rules',
                         'host.lifecycle', 'api.identity_context'} <= app)
        self.assertTrue(app.isdisjoint({'apple.cms', 'apple.apns', 'sources.winget'}))
        self.assertEqual(self.selected('crates/agent-channel/src/tasks.rs'), {
            'execution.agent.task_trust','planning.self_service', 'execution.agent.delivery', 'execution.agent.poll', 'execution.agent.content',
            'execution.agent.recovery', 'execution.software.offer',
            'execution.software.content', 'execution.software.recovery'})
        self.assertEqual(self.selected('crates/windows-channel/src/lib.rs'), {
            'windows.enrollment', 'windows.issuance', 'windows.management',
            'windows.commands', 'windows.retention', 'windows.limits', 'windows.declared', 'windows.entra'})

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
        selection = select_inputs(['hack/t2_modules/installation.py'])
        self.assertEqual(selection.modules, ('installation.migration',))
        self.assertIn('test_t2_guards', selection.tools)
        self.assertEqual(select_inputs(['crates/app/tests/tenant_registry/business.rs']).modules, ('installation.registry',))

    def test_cluster_role_admission_owns_an_instance(self):
        self.assertEqual(MODULES['inventory.reader'].db_mode, 'instance')
        self.assertEqual(MODULES['inventory.manual'].db_mode, 'reuse')

    def test_unknown_ci_or_nextest_inputs_are_rejected(self):
        for path in ('.github/workflows/new.yml', '.github/actions/new/action.yml', '.config/nextest.toml'):
            with self.assertRaises(SelectionError):
                select_inputs([path])

    def test_test_module_carriers_select_exact_children(self):
        expected = {
            'crates/app/tests/agent/mod.rs': {'agent.registration','agent.reports','agent.configurations'},
            'crates/app/tests/api/mod.rs': {'api.identity_context','diagnostics.http'},
            'crates/app/tests/execution/mod.rs': {name for name in MODULES if name.startswith('execution.')},
        }
        for path, modules in expected.items():
            selection=select_inputs([path])
            self.assertEqual(set(selection.modules),modules,path)

    def test_storage_selects_its_frontier_encryption_provider_and_fixture_inputs(self):
        for path in ('crates/content-service/src/upload.rs',
                     'crates/content-service/src/protected.rs',
                     'crates/content-s3/src/lib.rs',
                     'crates/app/tests/support/software.rs'):
            self.assertIn('content.storage', self.selected(path), path)
        self.assertTrue(MODULES['content.storage'].dependency_inputs)

    def test_app_helpers_select_all_actual_consumers(self):
        self.assertEqual(self.selected('crates/app/tests/support/software.rs'), {
            'agent.configurations','planning.self_service','software.http','content.http','content.mirror','content.gc','content.storage',
            'planning.software','planning.policy','planning.http','planning.group_scope','apple.policy','execution.software.offer','execution.software.content','execution.software.recovery'})
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
        required |= {name for name in MODULES if name != 'windows.push_transport' and name.startswith(('device.','windows.','execution.commands.'))}
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
        required |= {'telemetry.ingress.'+kind for kind in ('postgres','timescale_shared','timescale_dedicated','click_house')}
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
                         {'execution.agent.task_trust','agent.configurations','planning.self_service','agent.registration','agent.reports','execution.agent.poll','execution.agent.recovery','planning.onboarding','execution.commands.onboarding','execution.agent.delivery','execution.software.recovery','planning.agent_policy','execution.software.offer','execution.agent.history','assets.http','execution.agent.content','apple.onboarding','planning.software','planning.http','execution.software.content','planning.frequency','execution.commands.windows','software.http'} | {'telemetry.ingress.'+kind for kind in ('postgres','timescale_shared','timescale_dedicated','click_house')})

    def test_case_only_windows_inputs_select_directory_consumers(self):
        for path in ('hack/windows_fixtures.py', 'deployment/windows-leaf.tpl'):
            with self.subTest(path=path):
                selected = self.selected(path)
                self.assertIn('planning.http', selected)
                self.assertNotIn('planning.self_service', selected)

    def test_windows_csr_unit_input_does_not_select_t2(self):
        selected = select_inputs(['crates/certificate/tests/windows.rs'])
        self.assertEqual(selected.modules, ())

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
        # Shared migration setup is proven by installation/catalog.
        self.assertNotIn('gateway.admission', selected)

    def test_python_tests_and_docs_do_not_select_integration(self):
        self.assertEqual(self.selected('tests/test_source_t2.py'), set())
        self.assertEqual(self.selected('docs/guides/local-development.md'), set())
        self.assertEqual(self.selected('deny.toml'), set())
        self.assertEqual(self.selected('clippy.toml'), set())

    def test_unknown_inputs_fail_and_runner_changes_select_tools(self):
        for path in ('unknown.file', 'crates/app/src/new_owner/tests.rs'):
            with self.assertRaises(SelectionError):
                select_inputs([path])
        for path in ('hack/t2.py', 'hack/t2_environment.py'):
            self.assertTrue(select_inputs([path]).tools)

    def test_multiple_inputs_union_without_broadening(self):
        selection = select_inputs(['crates/resource-postgres/tests/behavior.rs',
                                  'crates/app/tests/apple/apns.rs',
                                  'crates/resource-postgres/tests/behavior.rs'])
        self.assertEqual(selection.modules, ('apple.apns', 'resource.persistence'))

    def test_real_execution_tools_select_existing_representatives(self):
        pg = {'api.identity_context', 'group.persistence', 'policy.persistence'}
        for path in ('hack/t2_database.py', 'hack/t2_context.py'):
            selection = select_inputs([path])
            self.assertEqual(set(selection.modules), pg)
            self.assertTrue(selection.tools)
        for path in ('hack/t2_environment.py', 'hack/t2_fixtures.py'):
            self.assertEqual(self.selected(path), pg | {'host.lifecycle', 'gateway.admission'})
        self.assertEqual(self.selected('hack/t2_hosts.py'), {'host.lifecycle'})
        self.assertEqual(self.selected('hack/t2_execution.py'), {'policy.persistence'})
        for path in ('hack/ci_impact.py', 'hack/t2.py', 'hack/verification_result.py'):
            self.assertEqual(self.selected(path), set())

    def test_authorization_and_audit_module_inputs_stay_local(self):
        self.assertEqual(self.selected('crates/app/tests/authorization/capacity.rs'),
                         {'authorization.capacity'})
        self.assertEqual(self.selected('crates/app/tests/authorization/mod.rs'),
                         {'authorization.' + part for part in
                          ('rules', 'membership', 'capacity', 'initialization', 'admission', 'programmatic')})
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
        expected = {'planning.agent_policy','planning.frequency','planning.software',
                    'execution.agent.delivery','execution.agent.poll','execution.agent.content',
                    'execution.agent.recovery','execution.software.offer','execution.software.content',
                    'execution.software.recovery'}
        for path in ('crates/agent-wire/src/tasks.rs',
                     'crates/agent-wire/schema/runtime/signed-task-v1.schema.json',
                     'crates/execution-service/src/task_signing.rs'):
            selected = self.selected(path)
            self.assertTrue(expected <= selected, expected - selected)
            self.assertTrue(selected.isdisjoint({'agent.registration','agent.reports','windows.management',
                                                'apple.policy','identity.sso','gateway.admission'}))
        self.assertEqual(self.selected('crates/agent-wire/schema/runtime/binding-profile-v1.schema.json'),
                         {'agent.registration'})
        self.assertEqual(self.selected('crates/agent-wire/schema/runtime/report-request-v1.schema.json'),
                         {'agent.reports','planning.onboarding'})

    def test_wire_schema_renames_keep_baseline_and_current_consumers(self):
        from dataclasses import replace
        from ci_impact import current_registry
        current = current_registry()
        baseline = replace(current, modules={
            name: {**module, 'production_inputs': tuple(
                path.replace('-v1.schema', '-v6.schema') for path in module['production_inputs'])}
            for name, module in current.modules.items()
        })
        for shape in ['signed-task', 'binding-profile', 'report-request', 'error-body', 'agent']:
            suffix = '.schema-manifest.json' if shape == 'agent' else '.schema.json'
            old = f'crates/agent-wire/schema/runtime/{shape}-v6{suffix}'
            new = f'crates/agent-wire/schema/runtime/{shape}-v1{suffix}'
            with self.subTest(shape=shape):
                self.assertEqual(select_inputs([old], baseline).modules,
                                 select_inputs([new], current).modules)
                self.assertTrue(select_inputs([new], current).modules)

    def test_onboarding_wire_selects_its_actual_consumers(self):
        inputs = {
            'crates/agent-wire/src/onboarding.rs': {
                'agent.reports','planning.onboarding','execution.commands.onboarding',
                'apple.onboarding','execution.agent.delivery','execution.agent.poll','execution.agent.recovery'},
            'crates/agent-wire/schema/enroll/native-grant-request-v1.schema.json': {
                'execution.commands.onboarding','apple.onboarding','agent.pki','agent.pki-recovery','agent.registration','agent.reports','execution.agent.delivery'},
        }
        for path, expected in inputs.items():
            selected = select_inputs([path])
            self.assertEqual(set(selected.modules), expected, path)

    def test_shared_onboarding_paths_reach_both_native_protocols(self):
        for path in ('crates/agent-wire/src/lib.rs',
                     'crates/execution-service/src/managed_registration.rs',
                     'crates/execution-service/src/native_installation.rs',
                     'crates/inventory-service/src/collection/channel.rs'):
            selection = select_inputs([path])
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

    def test_local_schema_selects_installation_and_real_consumers(self):
        self.assertEqual(self.selected('crates/app/schema/self-service-access.sql'),
                         {'installation.migration', 'catalog.contract', 'planning.self_service', 'execution.software.offer', 'execution.software.content', 'execution.software.recovery'})
        self.assertEqual(self.selected('crates/windows-channel/schema/entra.sql'),
                         {'installation.migration', 'catalog.contract', 'windows.entra'})
        selected = self.selected('crates/flow-service/schema/install.sql')
        self.assertTrue({'installation.migration', 'catalog.contract', 'planning.policy', 'planning.recovery'} <= selected)
        self.assertTrue(selected.isdisjoint({'identity.sso', 'apple.cms', 'agent.pki', 'resource.persistence'}))

    def test_audit_permissions_cover_self_service_reads(self):
        for path in ('crates/app/schema/audit-runtime.sql', 'crates/app/schema/audit-roles.sql'):
            selected = self.selected(path)
            self.assertIn('planning.self_service', selected)
            self.assertNotIn('resource.persistence', selected)

    def test_migration_registration_is_not_execution_or_all_pg(self):
        self.assertEqual(self.selected('crates/app/src/migration/units.rs'),
                         {'installation.migration', 'installation.tenants', 'deployment.management-tenant', 'catalog.contract'})
        self.assertIn('api.identity_context', self.selected('crates/app/src/migration.rs'))

    def test_recovery_helper_and_normal_transport_have_distinct_consumers(self):
        self.assertEqual(self.selected('hack/pki_recovery.py'), {'agent.pki-recovery'})
        self.assertEqual(self.selected('crates/app/tests/agent_pki/recovery.rs'), {'agent.pki-recovery'})
        self.assertEqual(self.selected('crates/app/tests/support/agent_http.rs'), {'agent.pki', 'agent.configurations'})
        self.assertNotIn('agent.configurations', self.selected('crates/app/tests/agent_pki/mod.rs'))


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
        self.assertEqual(self.selected('crates/app/src/publication_config.rs'),
                         {'publication.winget','publication.brew','publication.mapping','publication.withdrawal','publication.recovery'})
        self.assertEqual(self.selected('crates/software-service/src/publication/driver.rs'),
                         {'publication.winget','publication.brew','publication.withdrawal','publication.recovery'})
        self.assertEqual(self.selected('crates/software-service/src/publication/references.rs'),
                         {'publication.mapping','planning.resource_archive'})
        self.assertEqual(self.selected('crates/management-http/src/software_catalog.rs'), {'software.http','agent.configurations'})
        self.assertEqual(self.selected('crates/software-service/src/management/catalog.rs'), {'software.http'})
        self.assertEqual(self.selected('crates/content-service/src/software.rs'), {'software.http','agent.configurations'})
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
        from t2_registry import APP
        from t2_model import Module
        # Selection does not depend on whether a test file still exists on disk.
        self.assertEqual(self.selected('crates/app/tests/execution/agent/history/deleted.rs'),
                         {'execution.agent.history'})
        module = Module('new.owner', APP, ('new::',),
                        test_inputs=('crates/app/tests/new/mod.rs',))
        with patch.dict(MODULES, {'new.owner': module}):
            self.assertEqual(self.selected('crates/app/tests/new/mod.rs'), {'new.owner'})
        selected = set(select_inputs(['crates/content-service/tests/unit.rs',
                                    'crates/content-service/src/range.rs',
                                    'crates/resource-postgres/tests/behavior.rs']).modules)
        self.assertEqual(selected, {'content.http','execution.agent.content',
                                    'execution.software.content','resource.persistence'})
        self.assertEqual(select_inputs([]).modules, ())


if __name__ == '__main__':
    unittest.main()
