"""Module ownership is both the execution and integration-impact boundary."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hack'))
from t2_registry import MODULES
from ci_impact import select_inputs, SelectionError


class ModuleImpactTests(unittest.TestCase):
    def test_native_windows_record_fields_select_their_query_consumer(self):
        self.assertEqual(set(select_inputs(['crates/inventory/src/builtin/windows.rs']).modules),
                         {'windows.management', 'inventory.runtime', 'assets.http', 'assets.queries'})

    def test_action_dispatch_schema_selects_its_actual_consumers(self):
        selected = set(select_inputs(['crates/execution-service/src/actions/dispatch-v1.json']).modules)
        self.assertEqual(selected, {'planning.onboarding', 'execution.agent.delivery', 'device-access.http'})
        self.assertEqual(selected | {'execution.agent.history'}, set(select_inputs(['crates/execution-service/src/actions/production.rs']).modules))
        self.assertIn('execution.commands.dispatch', select_inputs(['crates/execution-service/src/dispatch-v1.json']).modules)
        for name in ('begin', 'challenge', 'confirm', 'recovery-use'):
            self.assertEqual(select_inputs([f'crates/agent-wire/schema/runtime/access-{name}-v1.schema.json']).modules, ('device-access.http',))


    def test_recovery_schema_selects_installation_and_business_consumers(self):
        selected=set(select_inputs(['crates/recovery-credentials/schema/install.sql']).modules)
        self.assertTrue({'installation.migration','recovery-credentials.http','apple.commands','execution.agent.delivery'} <= selected,selected)


    def test_management_limits_and_moved_entra_owners_select_real_consumers(self):
        for path, expected in {
            'crates/management-http/src/body_policy.rs': {'api.identity_context', 'api.diagnostics'},
            'crates/registration-service/src/windows_entra.rs': {'windows.entra'},
            'crates/inventory-service/src/apple_collection_receipts.rs': {'apple.collection'},
            'crates/registration-service/src/windows_receipts.rs': {'windows.entra', 'windows.issuance', 'windows.declared'},
            'crates/registration-service/schema/windows-receipts.sql': {'windows.entra', 'windows.issuance', 'windows.declared'},
        }.items():
            with self.subTest(path=path):
                self.assertTrue(expected <= set(select_inputs([path]).modules))


    def test_shared_apple_organization_schema_selects_both_enrollment_consumers(self):
        selected=select_inputs(['crates/apple-channel/schema/account-enrollment.sql'])
        self.assertTrue({'apple.ade','apple.account_enrollment'} <= set(selected.modules))


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


    def test_export_reader_selects_publication_read_and_withdrawal_consumers(self):
        selected = select_inputs(['crates/software-service/src/publication/execution.rs'])
        self.assertTrue({'publication.winget', 'publication.brew', 'publication.withdrawal', 'execution.software.offer'} <= set(selected.modules))


    def test_native_channel_storage_selects_its_direct_protocol_proofs(self):
        self.assertTrue({'apple.commands', 'apple.users'} <=
                        self.selected('crates/apple-channel/src/flow_store.rs'))

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
        for path in ('crates/execution-service/src/native_configuration.rs',):
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
        self.assertEqual(self.selected('apps/server/tests/support/agent_execution.rs'), {'execution.agent.delivery'})
    def selected(self, path):
        return set(select_inputs([path]).modules)

    def test_current_user_owns_projection_session_and_device_authority_inputs(self):
        for path in (
            'crates/device-service/src/presentation.rs',
            'crates/device-service/src/views.rs',
            'crates/management-http/src/device_views.rs',
            'crates/registration-service/src/device/directory.rs',
            'crates/authorization-service/src/session.rs',
            'crates/registration-service/src/device/management.rs',
            'crates/registration-service/src/device/store.rs',
        ):
            self.assertIn('agent.current_user', self.selected(path), path)
        self.assertEqual(self.selected('apps/server/tests/device/views.rs'), {'device.views'})
        self.assertNotIn('agent.current_user', self.selected('crates/brew-source/src/lib.rs'))


    def test_device_access_direct_execution_consumers_select_http_evidence(self):
        for path in ('crates/execution-service/src/actions/agent.rs',
                     'crates/execution-service/src/actions/storage.rs',
                     'crates/registration-service/src/lifecycle.rs',
                     'apps/server/tests/support/task_signature.rs',
                     'crates/execution-service/src/input_preparation.rs'):
            self.assertIn('device-access.http', self.selected(path), path)

    def test_runtime_diagnostics_has_exact_tests_and_live_owner_inputs(self):
        self.assertEqual(self.selected('apps/server/tests/api/runtime_diagnostics.rs'), {'diagnostics.http'})
        for path in ('apps/server/src/runtime_diagnostics.rs', 'crates/management-http/src/runtime_diagnostics.rs',
                     'crates/inventory-service/src/inventory_runtime.rs', 'crates/inventory-service/src/inventory_runtime/diagnostics.rs',
                     'crates/execution-service/src/source_changes.rs'):
            self.assertIn('diagnostics.http', self.selected(path), path)
        self.assertTrue(self.selected('apps/server/tests/api/runtime_diagnostics.rs').isdisjoint({'installation.migration','apple.apns'}))

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
        self.assertEqual(select_inputs(['apps/server/tests/tenant_registry/business.rs']).modules, ('installation.registry',))

    def test_cluster_role_admission_owns_an_instance(self):
        self.assertEqual(MODULES['inventory.reader'].db_mode, 'instance')
        self.assertEqual(MODULES['inventory.manual'].db_mode, 'reuse')

    def test_unknown_ci_or_nextest_inputs_are_rejected(self):
        for path in ('.github/workflows/new.yml', '.github/actions/new/action.yml', '.config/nextest.toml'):
            with self.assertRaises(SelectionError):
                select_inputs([path])

    def test_pure_test_carriers_only_compile_and_discover(self):
        for path in ('apps/server/tests/agent/mod.rs', 'apps/server/tests/api/mod.rs',
                     'apps/server/tests/execution/mod.rs', 'apps/server/tests/fixtures/execution.rs'):
            selection = select_inputs([path])
            self.assertEqual(selection.modules, (), path)
            self.assertIn('test_app_test_layout', selection.tools)

    def test_storage_selects_its_frontier_encryption_provider_and_fixture_inputs(self):
        for path in ('crates/content-service/src/upload.rs',
                     'crates/content-service/src/protected.rs',
                     'crates/content-s3/src/lib.rs'):
            self.assertIn('content.storage', self.selected(path), path)


    def test_test_changes_do_not_select_production_consumers(self):
        self.assertEqual(self.selected('crates/resource-postgres/tests/behavior.rs'),
                         {'resource.persistence'})
        self.assertEqual(self.selected('crates/content-service/tests/unit.rs'), set())
        self.assertEqual(self.selected('crates/scope/tests/model.rs'), set())
        self.assertEqual(self.selected('apps/server/tests/apple/apns.rs'), {'apple.apns'})

    def test_moved_tests_are_owned_without_business_propagation(self):
        for path, owner in (
            ('apps/server/tests/identity/local.rs', 'identity.local'),
            ('apps/server/tests/enrollment/http.rs', 'enrollment.http'),
            ('apps/server/tests/api/identity_context.rs', 'api.identity_context'),
            ('apps/server/tests/agent/reports.rs', 'agent.reports'),
            ('apps/server/tests/execution/agent/history.rs', 'execution.agent.history'),
            ('crates/examples/src/app/t2/projection.rs', 'inventory.projection'),
            ('apps/server/tests/assets/http.rs', 'assets.http'),
        ):
            with self.subTest(path=path):
                self.assertEqual(self.selected(path), {owner})


    def test_case_only_windows_inputs_select_directory_consumers(self):
        for path in ('hack/windows_fixtures.py', 'deployment/windows-leaf.tpl'):
            with self.subTest(path=path):
                selected = self.selected(path)
                self.assertIn('windows.issuance', selected)
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
        selected = self.selected('apps/server/src/migration.rs')
        self.assertIn('installation.migration', selected)
        self.assertIn('installation.storage', selected)
        self.assertNotIn('apple.cms', selected)
        self.assertNotIn('apple.apns', selected)
        self.assertNotIn('sources.winget', selected)
        self.assertNotIn('publication.artifact', selected)
        # Shared migration setup is proven by its installation owners.
        self.assertNotIn('gateway.admission', selected)

    def test_python_tests_and_docs_do_not_select_integration(self):
        self.assertEqual(self.selected('tests/test_source_t2.py'), set())
        self.assertEqual(self.selected('docs/guides/local-development.md'), set())
        self.assertEqual(self.selected('deny.toml'), set())
        self.assertEqual(self.selected('clippy.toml'), set())

    def test_unknown_inputs_fail_and_runner_changes_select_tools(self):
        for path in ('unknown.file', 'apps/server/src/new_owner/tests.rs'):
            with self.assertRaises(SelectionError):
                select_inputs([path])
        for path in ('hack/t2.py', 'hack/t2_environment.py'):
            self.assertTrue(select_inputs([path]).tools)

    def test_multiple_inputs_union_without_broadening(self):
        selection = select_inputs(['crates/resource-postgres/tests/behavior.rs',
                                  'apps/server/tests/apple/apns.rs',
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
        self.assertEqual(self.selected('apps/server/tests/authorization/capacity.rs'),
                         {'authorization.capacity'})
        self.assertEqual(self.selected('apps/server/tests/authorization/mod.rs'),
                         {'authorization.' + part for part in
                          ('rules', 'membership', 'capacity', 'initialization', 'admission', 'programmatic')})
        self.assertEqual(self.selected('apps/server/tests/audit/recovery.rs'),
                         {'audit.recovery'})
        self.assertEqual(self.selected('crates/compliance-postgres/tests/t2.rs'),
                         {'compliance.storage'})

    def test_target_selection_accepts_discovered_test_renames(self):
        module = MODULES['resource.persistence']
        self.assertTrue(module.includes('a_new_behavior'))
        self.assertTrue(module.includes('admission::renamed_behavior'))

    def test_http_contract_proofs_name_existing_modules(self):
        import re
        root = Path(__file__).resolve().parents[1]
        source = (root / 'crates/http-contract/src/catalog.rs').read_text()
        proofs = re.findall(r'\bproof:\s*"([^"]+)"', source)
        self.assertTrue(proofs)
        self.assertEqual(set(proofs) - MODULES.keys(), set())

    def test_every_production_pattern_matches_a_real_owner_input(self):
        root = Path(__file__).resolve().parents[1]
        for module in MODULES.values():
            for pattern in module.production_inputs:
                with self.subTest(module=module.id, pattern=pattern):
                    self.assertTrue(list(root.glob(pattern)), 'invented production path')


    def test_apple_push_includes_transport_durable_push_and_health_only(self):
        self.assertEqual(self.selected('crates/apple-channel/src/push.rs'),
                         {'apple.apns','apple.push','apple.host'})

    def test_local_schema_selects_installation_and_real_consumers(self):
        self.assertTrue({'installation.migration'} <= self.selected('crates/execution-service/schema/install.sql'))
        self.assertEqual(self.selected('crates/windows-channel/schema/entra.sql'),
                         {'installation.migration', 'windows.entra'})
        selected = self.selected('crates/software-service/src/management/publication/install.sql')
        self.assertTrue({'installation.migration'} <= selected)
        self.assertTrue(selected.isdisjoint({'identity.sso', 'apple.cms', 'agent.pki', 'resource.persistence'}))


    def test_storage_admission_inputs_select_the_runtime_owner(self):
        for path in (
            'apps/server/schema/business-roles.sql',
            'crates/execution-service/src/policy-participant-admission.sql',
            'apps/server/schema/installation.sql',
            'apps/server/schema/platform-sso-identity.sql',
            'apps/server/schema/commands-roles.sql',
            'crates/inventory-service/schema/relations.sql',
             'apps/server/schema/messaging-runtime.sql',
            'crates/apple-channel/schema/account-enrollment.sql',
            'crates/apple-channel/schema/platform-qualifications.sql',
            'crates/apple-channel/schema/profile-qualifications.sql',
            'crates/authorization-service/schema/authority.sql',
            'crates/device-service/schema/install.sql',
            'crates/device-service/schema/object-qualification.sql',
            'crates/execution-service/schema/device-access-qualification.sql',
            'crates/software-service/src/management/publication/install.sql',
            'crates/execution-service/schema/scope-projections.sql',
            'crates/scope-postgres/schema/install.sql',
            'crates/inventory-service/schema/collection-metadata.sql',
            'crates/inventory-service/schema/install.sql',
            'crates/registration-service/schema/device-access.sql',
        ):
            with self.subTest(path=path):
                self.assertIn('installation.storage', self.selected(path))

    def test_migration_registration_is_not_execution_or_all_pg(self):
        self.assertEqual(self.selected('apps/server/src/migration/units.rs'),
                         {'installation.migration', 'installation.tenants', 'deployment.management-tenant', 'installation.storage'})
        self.assertIn('api.identity_context', self.selected('apps/server/src/migration.rs'))

    def test_recovery_helper_and_normal_transport_have_distinct_consumers(self):
        self.assertEqual(self.selected('hack/pki_recovery.py'), {'agent.pki-recovery'})
        self.assertEqual(self.selected('apps/server/tests/agent_pki/recovery.rs'), {'agent.pki-recovery'})
        self.assertEqual(self.selected('apps/server/tests/support/agent_http.rs'),
                         {'agent.pki', 'agent.configurations', 'agent.listener'})
        self.assertNotIn('agent.configurations', self.selected('apps/server/tests/agent_pki/mod.rs'))


    def test_publication_files_select_their_real_semantic_modules(self):
        self.assertEqual(self.selected('crates/software-service/src/publication/driver.rs'),
                         {'publication.winget','publication.brew','publication.withdrawal','publication.recovery'})
        self.assertEqual(self.selected('crates/software-service/src/publication/references.rs'),
                         {'publication.mapping','planning.resource_archive'})
        self.assertEqual(self.selected('crates/management-http/src/software_catalog.rs'), {'software.http','agent.configurations','authorization.programmatic'})
        self.assertEqual(self.selected('crates/software-service/src/management/catalog.rs'), {'software.http'})
        self.assertEqual(self.selected('crates/content-service/src/software.rs'), {'software.http','agent.configurations'})


    def test_new_deleted_and_mixed_test_paths_remain_owned(self):
        from unittest.mock import patch
        from t2_registry import APP
        from t2_model import Module
        # Selection does not depend on whether a test file still exists on disk.
        self.assertEqual(self.selected('apps/server/tests/execution/agent/history/deleted.rs'),
                         {'execution.agent.history'})
        module = Module('new.owner', APP, ('new::',),
                        test_inputs=('apps/server/tests/new/mod.rs',))
        with patch.dict(MODULES, {'new.owner': module}):
            self.assertEqual(self.selected('apps/server/tests/new/mod.rs'), {'new.owner'})
        selected = set(select_inputs(['crates/content-service/tests/unit.rs',
                                    'crates/content-service/src/range.rs',
                                    'crates/resource-postgres/tests/behavior.rs']).modules)
        self.assertEqual(selected, {'content.http','execution.agent.content',
                                    'execution.software.content','resource.persistence'})
        self.assertEqual(select_inputs([]).modules, ())


class DirectProofs(unittest.TestCase):
    def test_production_windows_context_receives_registered_identity_actors(self):
        from types import SimpleNamespace
        from t2_context import contexts
        module=MODULES['windows.production']
        job=SimpleNamespace(module=module,id='windows::t2::production::origins',invocation=0,key='windows-production/0')
        context=contexts('production-binding-proof',[job])[job.key]
        self.assertEqual([(actor['tenant'],actor['role']) for actor in context['actors']],[(context['tenant'],'admin')])

    def test_shared_contracts_keep_fast_checks_without_business_t2(self):
        for path in ('crates/management-http/examples/resource_query.rs',
                     'crates/management-http/examples/management_capabilities.rs',
                     'apps/server/examples/http_contract.rs',
                     'crates/management-http/tests/http_contract.rs',
                     'crates/http-contract/src/collections.rs',
                     'apps/server/src/lib.rs', 'crates/agent-wire/src/runtime.rs',
                     'crates/agent-wire/src/mapping.rs', 'crates/agent-wire/src/native_collection.rs',
                     'crates/query/src/lib.rs', 'crates/compliance/src/lib.rs'):
            with self.subTest(path=path):
                self.assertEqual(select_inputs([path]).modules, ())

    def test_preparation_and_composition_select_owner_proofs(self):
        for path, expected in {
            'crates/http-contract/src/catalog.rs': {'agent.listener'},
            'apps/server/src/assembly/mod.rs','apps/server/src/assembly/http.rs': {'agent.listener', 'api.identity_context', 'api.diagnostics','windows.production','apple.host'},
            'crates/http-contract/src/module.rs': {'agent.listener','windows.production','apple.host','api.identity_context'},
            'crates/http-contract/src/router.rs': {'agent.listener','windows.production','apple.host','api.identity_context'},
            'crates/http-contract/src/routing.rs': {'agent.listener','windows.production','apple.host','api.identity_context'},
            'crates/agent-channel/src/policy_events.rs': {'agent.listener', 'policy.events'},
            'crates/agent-channel/src/tasks.rs': set('agent.listener execution.agent.content execution.software.content execution.software.offer device-access.http execution.agent.task_trust execution.agent.poll execution.agent.recovery planning.self_service execution.agent.delivery agent.current_user execution.software.recovery'.split()),
            'apps/server/src/native/gateway.rs': set('apple.host agent.listener gateway.business gateway.admission gateway.network windows.production gateway.tls'.split()),
            'crates/management-http/src/router.rs': {'api.identity_context', 'api.diagnostics'},
            'apps/server/src/config.rs': {'host.lifecycle'},
            'apps/server/tests/support/authority.rs': {'authorization.rules'},
            'apps/server/tests/support/http.rs': {'api.identity_context', 'identity.local', 'identity.sso',
                                                 'apple.collection', 'windows.management', 'assets.queries'},
            'apps/server/tests/support/runtime.rs': {'api.identity_context'},
            'apps/server/tests/support/tls.rs': {'windows.management', 'apple.identity', 'agent.registration'},
            'tests/support/context.rs': {'group.persistence'},
            'apps/server/schema/business-roles.sql': {'installation.migration', 'installation.storage'},
        }.items():
            with self.subTest(path=path):
                self.assertEqual(set(select_inputs([path]).modules), expected)

    def test_business_audit_assertions_keep_direct_callers(self):
        selected = set(select_inputs(['apps/server/tests/support/audit.rs']).modules)
        self.assertTrue({'content.http', 'authorization.rules', 'audit.integrity'} <= selected)
        self.assertNotIn('sources.winget', selected)

    def test_business_changes_still_select_direct_http_and_storage_proofs(self):
        for path, expected in {
            'crates/management-http/src/device_access.rs': {'device-access.http','authorization.programmatic'},
            'crates/management-http/src/recovery_credentials.rs': {'recovery-credentials.http'},
            'crates/authorization-service/src/api_key.rs': {'authorization.programmatic'},
            'crates/resource-postgres/src/lib.rs': {'resource.persistence', 'resource.recovery'},
            'crates/compliance-postgres/src/lib.rs': {'compliance.storage'},
            'crates/group-postgres/src/lib.rs': {'group.persistence', 'group.generations', 'groups.service'},
            'crates/query-postgres/src/lib.rs': {'planning.http'},
            'crates/software-service/src/preparation/mod.rs': {'software.catalog'},
            'crates/software-service/src/preparation/execution.rs': {'software.catalog'},
        }.items():
            with self.subTest(path=path):
                self.assertEqual(set(select_inputs([path]).modules), expected)


if __name__ == '__main__':
    unittest.main()
