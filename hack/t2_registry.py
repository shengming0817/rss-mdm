"""Test modules own execution, integration inputs and fixture requirements.

Rust test names come from the built target, never from a second test roster.
ref: meilisearch tests/integration.rs@909ef7fef5ba264dc914c4778d6328c5edca5ca7
"""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from t2_model import Build, Module, CasePolicy

ROOT = Path(__file__).resolve().parents[1]
APP = Build('rss-mdm-app', features=('integration',))


# One fixture-owned preparation target. Names are discovered, not copied here.
PREPARATION = Module('preparation', APP, ('test_support::preparation::prepare',), expected_cases=1)

MODULES: dict[str, Module] = {}


def add(name, *, build=APP, selectors=(), profile='product', fixtures=(),
        sources=(), tests=(), support=(), python=None, children=(), actors=()):
    if name in MODULES:
        raise ValueError('duplicate module: ' + name)
    if build is not None and not selectors:
        raise ValueError('module must select a target or Rust namespace: ' + name)
    MODULES[name] = Module(name, build, tuple(selectors), profile, tuple(fixtures),
                          tuple(sources), tuple(tests), tuple(support),
                          db_mode=None if profile == 'none' else 'reuse',
                          scope=None if profile == 'none' else 'objects', python=python, children=tuple(children), actors=tuple(actors))


CAPABILITY_INPUTS = {'identity.local': ('crates/app/src/identity.rs',),
 'authorization.programmatic': ('crates/authorization-service/src/api_key.rs','crates/authorization-service/src/api_key_store.rs','crates/authorization-service/src/credential.rs','crates/authorization-service/src/network_policy.rs','crates/management-http/src/api_access.rs','crates/management-http/src/identity.rs'),
 'identity.sso': ('crates/app/src/identity.rs',),
 'authorization.rules': ('crates/authorization-service/src/store.rs',
                         'crates/authorization-service/src/evaluate.rs',
                         'crates/authorization-service/src/model.rs'),
 'authorization.membership': ('crates/authorization-service/src/store.rs',
                              'crates/authorization-service/src/authority.rs'),
 'authorization.capacity': ('crates/authorization-service/src/store.rs',
                            'crates/authorization-service/src/authority.rs'),
 'authorization.initialization': ('crates/authorization-service/src/initialization.rs',),
 'authorization.admission': ('crates/authorization-service/src/access-contract.json',),
 'enrollment.http': ('crates/management-http/src/enrollment/http.rs',
                     'crates/registration-service/src/enrollment/read.rs'),
 'enrollment.quotas': ('crates/registration-service/src/quotas.rs', 'crates/registration-service/src/quotas/*', 'crates/registration-service/schema/quotas.sql', 'crates/registration-service/schema/quota-usage.sql', 'crates/management-http/src/enrollment/quotas.rs'),
 'enrollment.recovery': ('crates/registration-service/src/enrollment/store.rs',),
 'device.associations': ('crates/device-service/src/*','crates/device-service/schema/*','crates/registration-service/src/device/endpoints.rs'),
 'device.views': ('crates/device-service/src/*','crates/management-http/src/device_views.rs','crates/inventory-service/src/assets/planning.rs'),
 'device.binding': ('crates/registration-service/src/device.rs',
                    'crates/registration-service/src/device/store.rs'),
 'device.revocation': ('crates/registration-service/src/device.rs',
                       'crates/app/src/registration_lifecycle.rs'),
 'device.recovery': ('crates/registration-service/src/device/store.rs',),
 'device.admission': ('crates/registration-service/src/access-contract.json',),
 'agent.configurations': ('crates/registration-service/src/agent/configurations.rs','crates/registration-service/src/agent/settings.rs','crates/registration-service/schema/agent-configurations.sql','crates/software-service/src/agent_packages*','crates/management-http/src/agent_enrollment.rs','crates/management-http/src/software_catalog.rs','crates/app/src/agent_configurations.rs','crates/agent-wire/src/enroll/configuration.rs'),
 'agent.registration': ('crates/agent-channel/src/lib.rs',),
 'agent.reports': ('crates/agent-channel/src/lib.rs',),
 'assets.http': ('crates/inventory-service/src/assets/scopes.rs', 'crates/inventory-service/src/assets/field_layout.rs', 'crates/management-http/src/assets/http.rs', 'crates/inventory-service/src/assets/store.rs', 'crates/inventory-service/src/assets/fields.rs', 'crates/inventory-service/src/assets/lists.rs'),
 'assets.queries': ('crates/inventory-service/src/assets/query*.rs',
                    'crates/inventory-service/src/assets/filter.rs'),
 'assets.sources': ('crates/inventory-service/src/assets/store.rs',
                    'crates/inventory-service/src/assets/quality.rs',
                    'crates/inventory-service/src/collection/read.rs'),
 'assets.group_input': ('crates/inventory-service/src/assets/planning.rs',
                        'crates/inventory-service/src/assets/quality.rs'),
 'planning.onboarding': ('crates/execution-service/src/enrollment_preparation.rs', 'crates/execution-service/src/sources/onboarding.rs', 'crates/inventory-service/src/collection/channel.rs', 'crates/execution-service/src/actions/production.rs', 'crates/execution-service/src/actions/poll.rs', 'crates/execution-service/src/actions/storage.rs', 'crates/inventory-service/src/assets/channel.rs', 'crates/agent-channel/src/lib.rs'),
 'planning.assets': ('crates/flow-service/src/planning/sources.rs',
                     'crates/flow-service/src/planning/automation/dispatch.rs',
                     'crates/inventory-service/src/assets/planning.rs'),
 'planning.scope': ('crates/flow-service/src/planning/scopes.rs',
                    'crates/flow-service/src/planning/pages/scope.rs',
                    'crates/flow-service/src/planning/automation/scopes.rs'),
 'planning.group_scope': ('crates/inventory-service/src/groups/mod.rs',
                          'crates/flow-service/src/planning/group_definition.rs',
                          'crates/flow-service/src/planning/scopes.rs',
                          'crates/flow-service/src/planning/automation/groups.rs',
                          'crates/flow-service/src/planning/automation/scopes.rs'),
 'planning.policy': ('crates/flow-service/src/planning/policies/*.rs',),
 'planning.recovery': ('crates/app/src/flow/admission.sql',
                       'crates/flow-service/src/planning/storage.rs',
                       'crates/flow-service/src/planning/admission.sql',
                       'crates/flow-service/src/planning/automation/health.rs'),
 'planning.http': ('crates/management-http/src/planning/http.rs',
                   'crates/flow-service/src/planning/pages.rs',
                   'crates/management-http/src/planning/policies/http.rs'),
 'planning.agent_policy': ('crates/execution-service/src/freeze_inputs.rs',
                           'crates/flow-service/src/planning/policies/mod.rs',
                           'crates/management-http/src/planning/policies/http.rs',
                           'crates/management-http/src/planning/policies/preview.rs',
                           'crates/flow-service/src/planning/policies/rerun.rs',
                           'crates/execution-service/src/sources/admission.rs',
                           'crates/flow-service/src/planning/policies/storage.rs'),
 'planning.frequency': ('crates/execution-service/src/sources/admission.rs',
                        'crates/flow-service/src/planning/policies/reconcile.rs'),
 'planning.software': ('crates/execution-service/src/sources/software.rs',
                       'crates/flow-service/src/planning/policies/mod.rs'),
 'planning.resource_archive': ('crates/flow-service/src/resource_catalog/mod.rs',
                               'crates/flow-service/src/planning/references.rs'),
 'compliance.http': ('crates/management-http/src/compliance/http.rs',
                     'crates/inventory-service/src/compliance/read.rs'),
 'compliance.evaluation': ('crates/inventory-service/src/compliance/evaluation.rs',),
 'compliance.recovery': ('crates/inventory-service/src/compliance/dispatch.rs',
                         'crates/inventory-service/src/compliance/freshness.rs'),
 'compliance.group_input': ('crates/inventory-service/src/compliance/evaluation.rs',
                            'crates/inventory-service/src/compliance/freshness.rs'),
 'execution.agent.task_trust': ('crates/execution-service/src/task_signing/*','crates/agent-channel/src/tasks.rs','crates/management-http/src/execution/http.rs','crates/agent-wire/src/task_trust.rs'),
 'execution.agent.delivery': ('crates/execution-service/src/actions/agent.rs',
                              'crates/execution-service/src/actions/production.rs',
                              'crates/execution-service/src/actions/collection.rs'),
 'execution.agent.content': ('crates/agent-channel/src/tasks.rs',
                             'crates/management-http/src/content/http.rs'),
 'execution.agent.history': ('crates/execution-service/src/actions/history.rs',),
 'execution.agent.poll': ('crates/execution-service/src/actions/poll.rs',),
 'execution.agent.recovery': ('crates/execution-service/src/actions/recovery.rs',),
 'execution.commands.admission': ('crates/management-http/src/execution/http.rs',
                                  'crates/execution-service/src/storage.rs',
                                  'crates/execution-service/src/admission.sql',
                                  'crates/timeline-service/src/*',
                                  'crates/management-http/src/timeline.rs'),
 'execution.commands.dispatch': ('crates/execution-service/src/recovery.rs',),
 'execution.commands.recovery': ('crates/execution-service/src/recovery.rs',
                                 'crates/execution-service/src/lifecycle.rs'),
 'execution.commands.windows': ('crates/execution-service/src/native.rs',),
 'execution.commands.onboarding': ('crates/execution-service/src/agent_preparation.rs','crates/windows-mdm/src/software.rs','crates/execution-service/src/native_installation.rs','crates/execution-service/src/managed_registration.rs','crates/windows-channel/src/agent_collection.rs','crates/registration-service/src/enrollment/managed.rs'),
 'execution.commands.configuration': ('crates/execution-service/src/native_configuration.rs',
                                 'crates/execution-service/src/native.rs'),
 'execution.software.offer': ('crates/execution-service/src/actions/software.rs',
                              'crates/execution-service/src/payload.rs'),
 'execution.software.content': ('crates/agent-channel/src/tasks.rs',
                                'crates/management-http/src/content/http.rs'),
 'execution.software.recovery': ('crates/execution-service/src/actions/software.rs',
                                 'crates/execution-service/src/actions/recovery.rs'),
 'software.http': ('crates/management-http/src/software_catalog.rs',),
 'content.http': ('crates/management-http/src/content/http.rs', 'crates/content-service/src/upload.rs'),
 'content.mirror': ('crates/management-http/src/content/http.rs', 'crates/content-service/src/upload.rs'),
 'content.gc': ('crates/content-service/src/cleanup.rs', 'crates/content-service/src/event.rs'),
 'windows.declared': (
     'crates/windows-channel/src/lib.rs', 'crates/windows-channel/src/linked.rs',
     'crates/windows-channel/src/boundary.rs', 'crates/windows-channel/src/management.rs',
     'crates/windows-channel/src/management/session.rs', 'crates/windows-channel/src/renewal.rs',
     'crates/device-trust/src/windows/linked.rs',
     'crates/registration-service/src/device/linked.rs',
     'crates/registration-service/src/device/management.rs',
     'crates/registration-service/src/device/store.rs',
     'crates/registration-service/src/device/read.rs',
     'crates/registration-service/src/enrollment/store.rs',
     'crates/registration-service/src/device.rs',
     'crates/execution-service/src/native.rs',
     'crates/execution-service/src/protocol.rs',
     'crates/execution-service/src/storage.rs',
     'crates/execution-service/src/error.rs',
     'crates/execution-service/src/queries/error.rs',
     'crates/management-http/src/error.rs',
     'crates/management-http/src/error_projection.rs',
     'crates/management-http/src/response.rs',
     'crates/execution-service/src/native_configuration.rs',
     'crates/windows-mdm/src/native/resolved.rs',
     'crates/windows-mdm/src/native/request.rs',
     'crates/windows-mdm/src/native/declared.rs',
     'crates/windows-mdm/src/native/verification.rs',
     'crates/windows-mdm/src/syncml.rs'),
 'windows.issuance': ('crates/windows-channel/src/issuance.rs', 'crates/certificate/src/windows.rs', 'crates/device-trust/src/windows.rs'),
 'windows.enrollment': ('crates/windows-channel/src/lib.rs',
                        'crates/timeline-service/src/*',
                        'crates/management-http/src/timeline.rs'),
 'windows.management': ('crates/windows-channel/src/management.rs',
                        'crates/windows-channel/src/protection.rs'),
 'windows.commands': ('crates/windows-channel/src/management.rs',
                      'crates/execution-service/src/native.rs'),
 'windows.retention': ('crates/windows-channel/src/retention.rs',),
 'windows.limits': ('crates/app/src/native/admission.rs',)}


CAPABILITY_INPUTS['planning.custom_events'] = ('crates/flow-service/src/planning/events.rs','crates/flow-service/src/planning/events/*','crates/execution-service/src/policy_events.rs','crates/agent-channel/src/policy_events.rs','crates/management-http/src/policy_events.rs','crates/agent-wire/src/policy_events.rs')
CAPABILITY_INPUTS['planning.self_service'] = ('crates/execution-service/src/self_service.rs', 'crates/execution-service/src/self_service/*', 'crates/execution-service/src/script_eligibility.rs', 'crates/agent-channel/src/tasks.rs')

def app_family(owner, *, namespace=None, identity=True,
               fixtures=(), profile='product'):
    namespace = namespace or owner.replace('.', '::') + '::t2'
    test_root = namespace.replace('::t2', '').replace('::', '/')
    children = [name.rsplit('.', 1)[1] for name in CAPABILITY_INPUTS if name.rsplit('.', 1)[0] == owner]
    if not children:
        raise ValueError('missing App production inputs: ' + owner)
    for child in children:
        add(owner + '.' + child,
            selectors=(namespace + '::' + child + '::',), profile=profile,
            fixtures=(('identity',) if identity else ()) + tuple(fixtures),
            sources=CAPABILITY_INPUTS[owner + '.' + child],
            tests=(f'crates/app/tests/{test_root}/{child}.rs',
                   f'crates/app/tests/{test_root}/{child}/*'),
            support=(f'crates/app/tests/{test_root}/mod.rs',))


add('agent.pki', selectors=('agent_pki_tests::',), fixtures=('identity','agent_pki','task_signing'),
    sources=('crates/certificate/src/agent.rs','crates/registration-service/src/agent_pki.rs',
             'crates/app/src/agent_pki.rs','deployment/agent-leaf.tpl',
             'crates/registration-service/src/operations.rs','crates/pki-service/src/*','crates/pki-service/schema/*',
             'crates/device-trust/src/*','crates/app/src/device_pki.rs','crates/management-http/src/pki.rs'),
    tests=('crates/app/tests/agent_pki/mod.rs','crates/app/tests/agent_pki/maintenance.rs'),
    support=('hack/agent_pki_fixtures.py','crates/app/tests/enrollment/support.rs','crates/app/tests/windows/support.rs'))
MODULES['agent.pki'] = replace(MODULES['agent.pki'], scope='tenant', policies=(
    CasePolicy('agent_pki_tests::restored_ca_preserves_authorized_agent_issuance_and_activation',
               'reuse', 'pair'),
    CasePolicy('agent_pki_tests::agent_ingress_holds_one_global_permit_per_request', 'reuse', 'tenant'),
    CasePolicy('agent_pki_tests::production_agent_listener_bootstraps_activates_and_rechecks_revocation', 'reuse', 'tenant',('identity','windows','agent_pki','task_signing')),
    CasePolicy('agent_pki_tests::rotation_requires_installed_trust_and_published_revocation_before_retirement', 'reuse', 'pair',('identity','agent_pki','task_signing','pki_rotation')),
    CasePolicy('agent_pki_tests::multiple_expired_publications_require_one_atomic_set_and_replay_exactly', 'reuse', 'tenant',('identity','agent_pki','task_signing','pki_rotation')),
    CasePolicy('agent_pki_tests::unknown_original_ca_result_blocks_retirement_after_rotation', 'reuse', 'tenant',('identity','agent_pki','task_signing','pki_rotation')),
    CasePolicy('agent_pki_tests::frozen_signing_uses_original_issuer_after_direct_activation', 'reuse', 'tenant', ('identity','agent_pki','task_signing','pki_rotation')),
    CasePolicy('agent_pki_tests::management_rotation_accepts_direct_activation_and_rejects_retired_action', 'reuse', 'tenant', ('identity','windows','agent_pki','task_signing','pki_rotation')),
))

add('installation.migration', selectors=('migration::tests::failed_unit_rolls_back_schema_and_can_resume_original_name','migration::tests::ledger_installation_grants_actual_business_writers','migration::tests::fresh_installation_replay_and_mismatch_rejection','tenant_registry::tests::rollback_failure_preserves_primary_reason_and_cleanup_evidence'), profile='empty',
    sources=('crates/app/src/migration.rs','crates/app/src/tenant_registry.rs','crates/app/src/tenant_use.rs','crates/app/schema/installation.sql'), tests=('crates/app/tests/migration/mod.rs','crates/app/tests/tenant_registry/mod.rs',),
    python=('installation', 'execute'), support=('hack/t2_modules/installation.py',))
add('installation.registry', selectors=('tenant_registry::tests::business::',), profile='product',
    sources=('crates/app/src/migration.rs','crates/app/src/tenant_registry.rs','crates/app/src/tenant_use.rs','crates/app/schema/installation.sql'),
    tests=('crates/app/tests/tenant_registry/business.rs',), support=('crates/app/tests/tenant_registry/mod.rs',))
MODULES['installation.registry'] = replace(MODULES['installation.registry'], db_mode='fresh', scope='objects')
add('installation.tenants', build=None, profile='product', python=('tenants', 'metadata_cli'),
    sources=('crates/app/src/tenant_registry.rs','crates/app/src/tenant_use.rs','crates/app/schema/installation.sql','crates/app/src/main.rs','crates/app/src/migration.rs','crates/app/src/maintenance.rs','crates/app/src/authorization_bootstrap.rs','crates/app/src/lifecycle.rs'),
    support=('hack/t2_modules/tenants.py',))
MODULES['installation.tenants'] = replace(MODULES['installation.tenants'], db_mode='fresh', scope='objects')
MODULES['installation.tenant_binding'] = replace(MODULES['installation.tenants'], id='installation.tenant_binding', python=('tenants', 'tenant_binding'), fixtures=('identity',), scope='pair', actors=(('tenant','admin'),('peer','admin')))

add('deployment.management-tenant', build=None, profile='product', python=('management_tenant', 'http_authority'), fixtures=('identity','management_delegate'),
    sources=('crates/app/src/identity.rs','crates/app/src/migration.rs','crates/app/schema/installation.sql','crates/authorization-service/src/tenancy.rs','crates/authorization-service/src/database.rs','crates/authorization-service/src/store.rs','crates/authorization-service/src/model.rs','crates/authorization-service/src/evaluate.rs','crates/authorization-service/src/identity_management.rs','crates/management-http/src/tenant_administration.rs','crates/management-http/src/authorization/http.rs','crates/app/src/tenant_http.rs','crates/app/src/tenant_administrator.rs','crates/app/src/tenant_registry.rs','crates/app/schema/tenant-administration.sql'),
    support=('hack/t2_modules/management_tenant.py','hack/t2_modules/tenants.py','hack/t2_modules/tenant_http.py',))
MODULES['deployment.management-tenant'] = replace(MODULES['deployment.management-tenant'], db_mode='fresh', scope='objects')
for name, entry, fixtures, profile in (
    ('deployment.management-bootstrap', 'bootstrap', (), 'empty'),
    ('deployment.management-assembly', 'assembly_admission', ('identity','management'), 'product'),
    ('deployment.management-accounts', 'account_lifecycle', ('identity','management'), 'product'),
):
    MODULES[name] = replace(MODULES['deployment.management-tenant'], id=name, python=('management_tenant', entry), fixtures=fixtures, profile=profile)
for name, entry, fixtures in (
    ('installation.provisioning_http', 'provisioning', ('identity','management_delegate')),
    ('installation.administrator_http', 'administrator', ('identity','management')),
    ('installation.registry_recent_auth', 'recent_auth', ('identity','management_delegate')),
    ('installation.registry_assembly', 'optional_routes', ('runtime_config',)),
    ('installation.registry_pages', 'provisioning_pages_and_active_directory', ('identity','management')),
    ('installation.administrator_rollback', 'administrator_rollback', ('identity','management')),
    ('installation.registry_commit_unknown', 'lost_commit_ack', ('identity','management')),
):
    MODULES[name] = replace(MODULES['deployment.management-tenant'], id=name, python=('tenant_http', entry), fixtures=fixtures)

add('recovery-credentials.http',fixtures=('identity',),selectors=('recovery_credentials_tests::',),
    sources=('crates/recovery-credentials/src/*','crates/recovery-credentials/schema/*','crates/management-http/src/recovery_credentials.rs','crates/app/src/recovery_credentials.rs','crates/agent-channel/src/filevault.rs','crates/agent-wire/src/filevault.rs'),
    tests=('crates/app/tests/recovery_credentials/mod.rs','crates/app/tests/recovery_credentials/filevault.rs'),support=())
MODULES['recovery-credentials.http']=replace(MODULES['recovery-credentials.http'],scope='tenant',db_mode='fresh')
add('certificate-archive.http',fixtures=('identity',),selectors=('certificate_archive_tests::',),
    sources=('crates/certificate-archive-service/src/*','crates/certificate-archive-service/schema/*','crates/management-http/src/certificate_archive/*','crates/app/src/certificate_archive.rs'),
    tests=('crates/app/tests/certificate_archive/mod.rs',),support=())
MODULES['certificate-archive.http']=replace(MODULES['certificate-archive.http'],scope='tenant',policies=(CasePolicy('certificate_archive_tests::permissions_rls_immutable_versions_and_tampering_are_enforced','fresh','pair',('identity',)),))
add('timeline.http',fixtures=('identity',),selectors=('timeline_tests::',),sources=('crates/timeline-service/src/*','crates/timeline-service/schema/*','crates/management-http/src/timeline.rs','crates/registration-service/src/device/read.rs','crates/inventory-service/src/assets/mod.rs','crates/execution-service/src/timeline.rs'),tests=('crates/app/tests/timeline/mod.rs',),support=())
MODULES['timeline.http']=replace(MODULES['timeline.http'],db_mode='fresh',policies=(
    CasePolicy('timeline_tests::existing_business_facts_are_queryable_over_real_http','fresh','objects',('identity','windows')),
    CasePolicy('timeline_tests::administrators_use_existing_access_and_tenant_isolation_is_preserved','fresh','pair',('identity',)),
))
for part in ('receipts', 'integrity', 'recovery', 'budget'):
    add('audit.' + part, selectors=(f'audit_integration_tests::{part}::',),
        sources=('crates/audit-integration/src/*', 'crates/audit-integration/src/budget.rs'),
        tests=(f'crates/app/tests/audit/{part}.rs',),
        support=('crates/app/tests/audit/mod.rs',))
MODULES['audit.recovery'] = replace(MODULES['audit.recovery'], children=('audit_integration_tests::test_support::',))
app_family('identity', fixtures=())
MODULES['identity.sso'] = replace(MODULES['identity.sso'], fixtures=('identity', 'idp'))
app_family('authorization')
MODULES['authorization.programmatic'] = replace(MODULES['authorization.programmatic'], db_mode='instance', scope='objects', policies=(
    CasePolicy('authorization::t2::programmatic::business_writes_bind_key_actor_and_managed_enrollment',
               'instance', 'objects', ('identity', 'windows')),
))
for name in ('rules', 'membership', 'capacity', 'initialization', 'admission'):
    key = 'authorization.' + name
    MODULES[key] = replace(MODULES[key], support_inputs=('crates/app/tests/authorization/mod.rs',))
app_family('enrollment')
MODULES['enrollment.quotas'] = replace(MODULES['enrollment.quotas'], scope='tenant', support_inputs=(*MODULES['enrollment.quotas'].support_inputs, ), fixtures=(*MODULES['enrollment.quotas'].fixtures, 'content'))
app_family('device')
for part in ('binding', 'revocation', 'recovery', 'admission', 'associations', 'views'):
    key = 'device.' + part
    MODULES[key] = replace(MODULES[key], support_inputs=('crates/app/tests/device/mod.rs',))
MODULES['device.views'] = replace(MODULES['device.views'], support_inputs=(*MODULES['device.views'].support_inputs, 'crates/app/tests/device/associations.rs'))
for name in ('device.associations','device.views'):
    MODULES[name]=replace(MODULES[name],scope='tenant',
        production_inputs=(*MODULES[name].production_inputs,
            'crates/inventory/src/assets.rs','crates/inventory/src/builtin.rs',
            'crates/inventory-postgres/src/history.rs','crates/inventory-postgres/src/catalog.rs',
            'crates/inventory-service/src/assets/planning.rs',
            'crates/registration-service/src/device/endpoints.rs',
            'crates/registration-service/src/device/directory.rs'),
        support_inputs=(*MODULES[name].support_inputs,))
app_family('agent')
for name, target in (('manual', 'manual'), ('reader', 'reader')):
    add('inventory.' + name,
        build=Build('rss-mdm-inventory-postgres', 'test', target), selectors=('',),
        sources=('crates/inventory-postgres/src/*', 'crates/inventory-postgres/migrations/*'),
        tests=(f'crates/inventory-postgres/tests/{target}.rs',),
        support=('crates/inventory-postgres/tests/support/*',))
MODULES['inventory.manual'] = replace(MODULES['inventory.manual'], policies=(CasePolicy('field_catalog_cas_history_and_rollback_are_atomic','reuse','tenant'), CasePolicy('seed_retirement_and_reinitialization_preserve_tenant_catalog','reuse','tenant')))
for name in ('projection', 'recovery', 'process'):
    add('inventory.' + name,
        build=Build('rss-mdm-examples', features=('integration',)),
        selectors=('app::t2::' + name + '::',), fixtures=('examples',) if name == 'process' else (),
        sources=('crates/examples/src/app.rs', 'crates/inventory-postgres/src/*'),
        tests=(f'crates/examples/src/app/t2/{name}.rs',),
        support=('crates/examples/src/app/t2/mod.rs',))
add('worker.wake', selectors=('worker_wake::tests::',), fixtures=('identity',),
    sources=('crates/app/src/worker_wake.rs',),
    tests=('crates/app/tests/worker_wake/mod.rs',), support=())
MODULES['worker.wake'] = replace(MODULES['worker.wake'], policies=(CasePolicy('worker_wake::tests::committed_hints_reconnect_and_restart_preserve_durable_markers', 'reuse', 'pair'),))
add('inventory.runtime', selectors=('inventory_runtime::tests::',), fixtures=('identity',),
    sources=('crates/inventory-service/src/inventory_runtime.rs',),
    tests=('crates/app/tests/inventory_runtime/mod.rs',), support=())
add('examples.cli', build=Build('rss-mdm-examples', features=('integration',)),
    selectors=('app::t2::cli::',), fixtures=('examples',),
    sources=('crates/examples/src/*',),
    tests=('crates/examples/src/app/t2/cli.rs',), support=('crates/examples/src/app/t2/mod.rs',))
add('api.diagnostics', selectors=('api::tests::',),
    sources=('crates/app/src/diagnostic.rs',
             'crates/app/src/error_projection.rs'))
add('api.identity_context', selectors=('api::t2::identity_context::',), fixtures=('identity',),
    sources=(),
    tests=('crates/app/tests/api/identity_context.rs',))
add('diagnostics.http', selectors=('api::t2::runtime_diagnostics::',), fixtures=('identity','local_worker'),
    sources=('crates/app/src/runtime_diagnostics.rs', 'crates/management-http/src/runtime_diagnostics.rs',
             'crates/execution-service/src/health.rs', 'crates/execution-service/src/recovery.rs',
             'crates/inventory-service/src/inventory_runtime/diagnostics.rs',
             'crates/flow-service/src/planning/automation/health.rs'),
    tests=('crates/app/tests/api/runtime_diagnostics.rs','crates/app/tests/api/execution_health.rs',))
MODULES['diagnostics.http'] = replace(MODULES['diagnostics.http'], scope='tenant', support_inputs=('crates/app/tests/inventory_runtime/support.rs','crates/app/tests/planning/support.rs'), policies=(
    CasePolicy('api::t2::runtime_diagnostics::execution_first_scan_failure_recovers_only_after_real_success', 'instance', 'tenant'),
    CasePolicy('api::t2::runtime_diagnostics::runner_failure_is_visible_while_bridge_and_queries_succeed', 'instance', 'tenant'),
))
add('host.lifecycle', build=None, python=('host', 'verify_startup_deadlines'), fixtures=('runtime_config',),
    sources=('crates/app/src/lifecycle.rs', 'crates/app/src/main.rs', ),
    support=('hack/t2_modules/host.py',))
app_family('assets')
for name, target in (('persistence', 't2'), ('generations', 'generations')):
    add('group.' + name, build=Build('rss-mdm-group-postgres', 'test', target, ('integration',)),
        selectors=('',), profile='group',
        sources=('crates/group-postgres/src/*', 'crates/group-postgres/migrations/*'),
        tests=(f'crates/group-postgres/tests/{target}.rs',),
        support=('crates/group-postgres/tests/support/*',))
app_family('planning',
           namespace='planning::t2')
for name in ('planning.assets', 'planning.scope', 'planning.group_scope', 'planning.recovery',
             'planning.resource_archive', 'assets.http', 'audit.integrity'):
    MODULES[name] = replace(MODULES[name], support_inputs=MODULES[name].support_inputs +
                            ('crates/app/tests/planning/support.rs',))
MODULES['planning.resource_archive'] = replace(MODULES['planning.resource_archive'], fixtures=('identity', 'tls'))
MODULES['audit.integrity'] = replace(MODULES['audit.integrity'],
    test_inputs=MODULES['audit.integrity'].test_inputs + ('crates/app/tests/audit/owner_admission.rs', 'crates/app/tests/audit/query_cost.rs'))
for name in ('policy', 'resource', 'software_release'):
    package = name.replace('_', '-')
    for suffix, target in (('persistence', 'behavior'), ('recovery', 'recovery')):
        add(name + '.' + suffix,
            build=Build('rss-mdm-' + package + '-postgres', 'test', target, ('integration',)),
            selectors=('',), profile='backend',
            sources=(f'crates/{package}-postgres/src/*', f'crates/{package}-postgres/migrations/*',
                     'crates/backend-postgres-support/src/*'),
            tests=(f'crates/{package}-postgres/tests/{target}.rs',),
            support=(f'crates/{package}-postgres/tests/support/*',))
add('compliance.storage', build=Build('rss-mdm-compliance-postgres', 'test', 't2'),
    selectors=('',), sources=('crates/compliance-postgres/src/*', 'crates/compliance-postgres/migrations/*'),
    tests=('crates/compliance-postgres/tests/t2.rs',),
    support=())
app_family('compliance')
app_family('execution.agent',
           namespace='execution::t2::agent', fixtures=('content',))
app_family('execution.commands',
           namespace='execution::t2::commands')
for name in ('execution.commands.windows','execution.commands.configuration','execution.commands.onboarding'):
    MODULES[name] = replace(MODULES[name], fixtures=MODULES[name].fixtures+('windows',),
        support_inputs=MODULES[name].support_inputs+('crates/app/tests/windows/support.rs',))
app_family('execution.software',
           namespace='execution::t2::software', fixtures=('content',))
add('software.catalog', build=Build('rss-mdm-software-service', 'test', 'catalog_t2'), selectors=('',),
    sources=('crates/software-service/src/catalog/*', 'crates/software-service/src/preparation/*'),
    tests=('crates/software-service/tests/catalog_t2.rs', 'crates/software-service/tests/catalog/*'),
    support=())
app_family('software', namespace='software_catalog::t2', fixtures=('content',))
app_family('content', fixtures=('content',))
add('content.storage', selectors=('content::t2::storage::',), fixtures=('identity','s3','content'),
    sources=('crates/content-service/src/backend.rs','crates/content-service/src/journal.rs','crates/content-service/src/reader.rs','crates/content-service/src/upload.rs','crates/content-service/src/protected.rs','crates/content-service/src/cleanup.rs','crates/content-s3/src/*'),
    tests=('crates/app/tests/content/storage.rs',), support=('hack/s3_fixtures.py','fixtures/s3-provider.lock.json','crates/app/tests/content/http.rs','fixtures/mdm-content-s3.example.json'))
MODULES['content.storage']=replace(MODULES['content.storage'],db_mode='fresh')

for name in ('content.http', 'content.mirror', 'content.gc', 'software.http'):
    MODULES[name] = replace(MODULES[name], support_inputs=MODULES[name].support_inputs +
        ('tests/support/software/*',))
MODULES['content.mirror'] = replace(MODULES['content.mirror'], fixtures=('identity', 'tls','content'))
for part in ('winget', 'brew', 'mapping', 'withdrawal', 'recovery', 'artifact'):
    add('publication.' + part,
        build=Build('rss-mdm-software-service', 'test', 'publication_t2'),
        selectors=(part + '::',), profile='none' if part == 'artifact' else 'product',
        fixtures=('tls', 'git') if part == 'brew' else ('tls',),
        sources=tuple('crates/software-service/src/publication/' + path for path in {
            'winget': ('artifact.rs','config.rs','driver.rs','service.rs','spec.rs','storage.rs','service.rs'),
            'brew': ('artifact.rs','config.rs','driver.rs','service.rs','spec.rs','storage.rs','service.rs'),
            'mapping': ('artifact.rs','config.rs','service.rs','spec.rs','storage.rs','service.rs','references.rs'),
            'withdrawal': ('config.rs','driver.rs','service.rs','storage.rs','service.rs'),
            'recovery': ('config.rs','driver.rs','service.rs','storage.rs','service.rs'),
            'artifact': ('artifact.rs',),
        }[part]),
        tests=(f'crates/software-service/tests/publication/{part}.rs',),
        support=('tests/support/software/*', 'crates/software-service/tests/publication_t2.rs'))
add('sources.winget', build=Build('rss-mdm-winget-source', 'test', 't2_http'), selectors=('',),
    profile='none', fixtures=('tls',), sources=('crates/winget-source/src/*',),
    tests=('crates/winget-source/tests/t2_http.rs',), support=())
add('sources.brew_git', build=Build('rss-mdm-brew-source', 'test', 't2_git'), selectors=('',),
    profile='none', fixtures=('git',), sources=('crates/brew-source/src/git.rs',),
    tests=('crates/brew-source/tests/t2_git.rs',))
add('sources.brew_recovery', build=Build('rss-mdm-brew-source'),
    selectors=('git::recovery_tests::',), profile='none', fixtures=('git',),
    sources=('crates/brew-source/src/git.rs',))
app_family('windows',
           fixtures=('windows',), namespace='windows::t2')
MODULES['windows.enrollment'] = replace(MODULES['windows.enrollment'], fixtures=('identity','windows','content'))
add('windows.push_transport', selectors=('windows::t2::push_transport::',), profile='none', fixtures=('windows',),
    sources=('crates/windows-channel/src/push.rs',),
    tests=('crates/app/tests/windows/push_transport.rs',))
MODULES['windows.declared'] = replace(MODULES['windows.declared'], support_inputs=(*MODULES['windows.declared'].support_inputs, 'crates/app/tests/windows/support.rs', 'crates/app/tests/enrollment/support.rs', ), db_mode='fresh', scope='objects')
add('windows.entra', selectors=('windows::t2::entra::',), profile='product',fixtures=('windows','identity','local_worker'),
    sources=('crates/windows-channel/src/entra/*','crates/windows-channel/schema/entra.sql','crates/windows-channel/schema/entra-web.sql','crates/authorization-service/src/entra.rs','crates/management-http/src/windows_entra.rs'),
    support=('crates/app/tests/windows/support.rs','crates/app/tests/windows/mod.rs'),tests=('crates/app/tests/windows/entra.rs',))
MODULES['windows.entra']=replace(MODULES['windows.entra'],scope='tenant',policies=(CasePolicy('windows::t2::entra::consent_native_issuance_replay_scope_and_revocation','fresh','objects'),))
for name in ('windows.issuance','windows.enrollment','windows.management','windows.commands','windows.retention','windows.limits','execution.commands.windows','execution.commands.configuration','execution.commands.onboarding'):
    MODULES[name] = replace(MODULES[name], support_inputs=MODULES[name].support_inputs + ('crates/app/tests/windows/support.rs',))
for name in ('enrollment.recovery','windows.issuance','windows.enrollment','windows.management','windows.commands','windows.retention','windows.limits','execution.commands.windows','execution.commands.configuration','execution.commands.onboarding'):
    MODULES[name] = replace(MODULES[name], support_inputs=MODULES[name].support_inputs + ('crates/app/tests/enrollment/support.rs',))
for part in ('cms', 'apns', 'scep', 'collection', 'profile', 'policy', 'onboarding', 'renewal', 'identity', 'push', 'fairness', 'host', 'commands', 'users', 'ddm'):
    no_pg = part in ('cms', 'apns')
    fixtures = ('apple',) + (() if no_pg else ('identity',))
    if part in ('profile', 'policy', 'ddm', 'onboarding', 'collection', 'identity'):
        fixtures += ('content',)
    if part in ('scep', 'renewal', 'identity', 'host'):
        fixtures += ('scep',)
    if part in ('apns', 'push', 'host'):
        fixtures += ('apns',)
    selectors = {'cms': ('apple::certificate::tests::',), 'apns': ('apple::push::tests::',)}.get(part, (f'apple::tests::{part}::',))
    source = {
        'cms': ('certificate.rs',), 'apns': ('push.rs',),
        'scep': ('enrollment.rs',), 'collection': ('checkin.rs','protocol.rs'),
        'profile': ('profile.rs',), 'policy': ('profile.rs','attempt.rs'),
        'onboarding': ('agent_collection.rs','flow_store.rs','checkin.rs'),
        'renewal': ('renewal.rs',), 'identity': ('checkin.rs','enrollment.rs'),
        'push': ('push.rs',), 'fairness': ('attempt.rs','protocol.rs'),
        'host': ('mod.rs','config.rs'),
        'ddm': ('ddm.rs','profiles.rs','exchange.rs'),
        'commands': ('native.rs','flow_store.rs','attempt.rs'), 'users': ('checkin.rs','flow_store.rs','material.rs'),
    }[part]
    add('apple.' + part, selectors=selectors, profile='none' if no_pg else 'product',
        fixtures=fixtures, sources=tuple(('crates/app/src/assembly/apple/' if path in ('mod.rs','config.rs') else 'crates/certificate/src/' if path=='certificate.rs' else 'crates/apple-mdm/src/' if path in ('protocol.rs','profile.rs') else 'crates/apple-channel/src/') + ('apple.rs' if path=='certificate.rs' else path) for path in source),
        tests=(('crates/app/tests/apple/apns.rs',) if part == 'apns' else
               ('crates/app/tests/apple/cms.rs',) if part == 'cms' else (f'crates/app/tests/apple/{part}.rs',)))
MODULES['apple.cms'] = replace(MODULES['apple.cms'], production_inputs=(*MODULES['apple.cms'].production_inputs, 'crates/certificate/src/apple/account.rs'))
add('apple.ade', selectors=('apple::tests::ade::',), profile='product',
    fixtures=('apple','identity','scep'),
    sources=('crates/apple-channel/src/ade/*','crates/apple-channel/schema/ade.sql','crates/apple-channel/schema/account-enrollment.sql','crates/apple-channel/src/organizations.rs',
             'crates/certificate/src/apple/ade.rs','crates/certificate/fixtures/*',
             'crates/registration-service/src/enrollment/native.rs','crates/registration-service/src/enrollment/read.rs',
             'crates/apple-channel/src/enrollment.rs','crates/apple-channel/src/renewal.rs','crates/apple-channel/src/lib.rs',
             'crates/apple-channel/src/access-admission.sql','crates/app/src/lifecycle.rs','crates/app/src/enrollment_progress.rs',
             'crates/apple-mdm/src/profile.rs'),
    support=('crates/app/tests/apple/mod.rs','crates/app/tests/apple/account_enrollment.rs','crates/app/tests/apple/support/scep.rs','crates/app/tests/apple/lifecycle.rs'),
    tests=('crates/app/tests/apple/ade.rs',))
MODULES['apple.ade'] = replace(MODULES['apple.ade'], scope='tenant')
add('apple.platform_sso', selectors=('apple::tests::platform_sso::',), profile='product',
    fixtures=('apple','identity','scep','agent_pki','task_signing'),
    sources=('crates/agent-wire/src/platform_sso.rs','crates/agent-wire/schema/platform_sso/*','crates/apple-channel/src/platform_sso/*','crates/apple-channel/schema/platform-sso.sql','crates/apple-mdm/src/platform_sso.rs',
             'crates/apple-channel/src/flow_store.rs','crates/apple-channel/src/lib.rs','crates/apple-channel/src/access-admission.sql',
             'crates/app/src/assembly/apple/*','crates/app/src/identity.rs','crates/app/schema/platform-sso-identity.sql',
             'crates/device-service/src/planning.rs','crates/device-service/src/planning/*','crates/inventory-postgres/src/reader.rs',
             'crates/execution-service/src/device_access.rs','crates/registration-service/src/device/store.rs'),
    support=('crates/app/tests/apple/mod.rs','crates/app/tests/apple/lifecycle.rs','crates/app/tests/apple/policy.rs','crates/app/tests/apple/support/scep.rs'),
    tests=('crates/app/tests/apple/platform_sso.rs','crates/app/tests/apple/platform_sso/*.rs'),)
MODULES['apple.platform_sso']=replace(MODULES['apple.platform_sso'],scope='tenant',policies=(
    CasePolicy('apple::tests::platform_sso::password::native_password_registration_exchange_and_recovery','reuse','tenant',(*MODULES['apple.platform_sso'].fixtures,'content','idp')),
    CasePolicy('apple::tests::platform_sso::native_registration_login_browser_bridge_and_revocation', 'reuse', 'tenant', (*MODULES['apple.platform_sso'].fixtures, 'content')),
    CasePolicy('apple::tests::platform_sso::third_party_profile_dispatch_with_rss_runtime', 'reuse', 'tenant', (*MODULES['apple.platform_sso'].fixtures, 'content')),
    CasePolicy('apple::tests::platform_sso::third_party_profile_dispatch_without_rss_runtime', 'reuse', 'tenant', (*MODULES['apple.platform_sso'].fixtures, 'content')),
))
add('apple.account_enrollment', selectors=('apple::tests::account_enrollment::',), profile='product',
    fixtures=('apple','identity','scep'),
    sources=('crates/apple-channel/src/account_enrollment/*', 'crates/apple-channel/schema/account-enrollment.sql',
             'crates/registration-service/src/enrollment/native.rs',
             'crates/certificate/src/apple/account.rs', 'crates/app/src/enrollment_progress.rs',
             'crates/apple-channel/src/lib.rs','crates/apple-channel/src/checkin.rs','crates/apple-channel/src/enrollment.rs',
             'crates/apple-channel/src/renewal.rs','crates/registration-service/src/device.rs','crates/registration-service/src/device/store.rs',
             'crates/apple-channel/src/exchange.rs','crates/apple-channel/src/ddm.rs','crates/apple-channel/src/ddm/assets.rs',
             'crates/apple-mdm/src/profile.rs','crates/apple-mdm/src/protocol.rs',
             'crates/authorization-service/src/session.rs','crates/app/src/assembly/apple/*',
             'crates/app/src/identity.rs','crates/execution-service/src/admission.sql'),
    support=('crates/app/tests/apple/mod.rs','crates/app/tests/apple/support/scep.rs', 'crates/app/tests/apple/lifecycle.rs', 'crates/app/tests/apple/renewal.rs'),
    tests=('crates/app/tests/apple/account_enrollment.rs',))
# Gateway protocol proofs have no product storage or Identity prerequisite.
for name in ('network', 'tls', 'admission'):
    add('gateway.' + name, build=None, profile='none', python=('gateway', name), fixtures=('gateway',),
        sources=('deployment/render_gateway.py','crates/app/src/native/gateway.rs','crates/certificate/src/peer.rs'),
        support=('hack/t2_modules/gateway.py','hack/gateway_fixture.py'))
add('gateway.business', build=None, python=('gateway', 'business'), fixtures=('gateway','identity'),
    sources=('deployment/render_gateway.py','crates/app/src/native/gateway.rs'),
    support=('hack/t2_modules/gateway.py','hack/gateway_fixture.py'))
MODULES['gateway.business'] = replace(MODULES['gateway.business'], scope='tenant')


# Isolation follows state and observation ownership. Only exceptions name a case.
MODULES['installation.migration'] = replace(MODULES['installation.migration'], db_mode='fresh', scope='objects')
MODULES['audit.receipts'] = replace(MODULES['audit.receipts'], db_mode='reuse', scope='tenant')
MODULES['audit.integrity'] = replace(MODULES['audit.integrity'], db_mode='instance', scope='objects', policies=(
    CasePolicy('audit_integration_tests::integrity::storage_integrity_is_enforced', 'fresh', 'objects'),
    CasePolicy('audit_integration_tests::integrity::query_cost::startup_probes_leave_both_transaction_hot_paths', 'fresh', 'objects'),
))
MODULES['audit.recovery'] = replace(MODULES['audit.recovery'], db_mode='reuse', scope='pair')
MODULES['audit.budget'] = replace(MODULES['audit.budget'], db_mode='reuse', scope='tenant')
MODULES['identity.local'] = replace(MODULES['identity.local'], db_mode='instance', scope='objects', policies=(
    CasePolicy('identity::t2::local::correct_passwords_keep_sessions_usable_and_expose_retry_after', 'reuse', 'tenant'),
))
MODULES['identity.sso'] = replace(MODULES['identity.sso'], db_mode='reuse', scope='tenant')
MODULES['authorization.rules'] = replace(MODULES['authorization.rules'], db_mode='reuse', scope='tenant', policies=(
    CasePolicy('authorization::t2::rules::capability_routes_without_application_preserve_revocation_and_atomicity', 'fresh', 'objects'),
))
MODULES['authorization.membership'] = replace(MODULES['authorization.membership'], db_mode='reuse', scope='tenant')
MODULES['authorization.capacity'] = replace(MODULES['authorization.capacity'], db_mode='reuse', scope='tenant')
MODULES['authorization.initialization'] = replace(MODULES['authorization.initialization'], db_mode='reuse', scope='tenant', policies=(
    CasePolicy('authorization::t2::initialization::initialization_receipt_atomicity_and_recovery', 'fresh', 'objects'),
))
MODULES['authorization.admission'] = replace(MODULES['authorization.admission'], db_mode='instance', scope='objects')
MODULES['device.binding'] = replace(MODULES['device.binding'], db_mode='reuse', scope='pair')
MODULES['device.recovery'] = replace(MODULES['device.recovery'], db_mode='reuse', scope='objects', policies=(
    CasePolicy('device::t2::recovery::revocation_and_replacement_unknown_commit', 'fresh', 'objects'),
    CasePolicy('device::t2::recovery::bind_and_revoke_settlement_classification', 'reuse', 'tenant'),
))
MODULES['agent.registration'] = replace(MODULES['agent.registration'], policies=(
    CasePolicy('agent::t2::registration::registration_recovery_preserves_credential_rotation', 'reuse', 'tenant'),
))
MODULES['agent.reports'] = replace(MODULES['agent.reports'], db_mode='reuse', scope='tenant')
MODULES['inventory.reader'] = replace(MODULES['inventory.reader'], db_mode='instance', scope='pair', policies=(
    CasePolicy('watermark_fence_rejects_unrelated_grantee', 'fresh', 'objects'),
))
MODULES['inventory.projection'] = replace(MODULES['inventory.projection'], db_mode='reuse', scope='pair', policies=(
    CasePolicy('app::t2::projection::missing_collection_and_corrupt_result_preserve_projection', 'fresh', 'objects'),
    CasePolicy('app::t2::projection::invocation_horizon', 'fresh', 'objects'),
))
MODULES['inventory.recovery'] = replace(MODULES['inventory.recovery'], db_mode='reuse', scope='tenant', policies=(
    CasePolicy('app::t2::recovery::admission_drift', 'instance', 'objects'),
))
MODULES['inventory.process'] = replace(MODULES['inventory.process'], db_mode='fresh', scope='objects')
MODULES['inventory.runtime'] = replace(MODULES['inventory.runtime'], db_mode='fresh', scope='objects')
MODULES['examples.cli'] = replace(MODULES['examples.cli'], db_mode='fresh', scope='tenant')
MODULES['api.identity_context'] = replace(MODULES['api.identity_context'], db_mode='reuse', scope='tenant')
MODULES['host.lifecycle'] = replace(MODULES['host.lifecycle'], db_mode='fresh', scope='objects')
MODULES['assets.http'] = replace(MODULES['assets.http'], db_mode='fresh', scope='objects', policies=(
    CasePolicy('assets::t2::http::field_layout::shared_layout_round_trip_permissions_and_retired_fields', 'fresh', 'pair'),
    CasePolicy('assets::t2::http::storage::asset_capability_owns_execution_and_receipt_recovery', 'reuse', 'tenant', fixtures=('runtime_config',), actors=()),
    CasePolicy('assets::t2::http::storage::asset_commit_unknown_recovers_original_receipts', 'reuse', 'objects', fixtures=('runtime_config',), actors=()),
    CasePolicy('assets::t2::http::storage::asset_storage_failures_are_not_malformed', 'fresh', 'objects', fixtures=('runtime_config',), actors=()),
))
MODULES['assets.queries'] = replace(MODULES['assets.queries'], db_mode='reuse', scope='tenant')
MODULES['assets.sources'] = replace(MODULES['assets.sources'], db_mode='reuse', scope='tenant')
MODULES['assets.group_input'] = replace(MODULES['assets.group_input'], db_mode='reuse', scope='tenant', policies=(
    CasePolicy('assets::t2::group_input::typed_and_collected_facts_become_group_input', 'reuse', 'tenant', ('identity','local_worker')),
))
MODULES['group.persistence'] = replace(MODULES['group.persistence'], db_mode='reuse', scope='objects', policies=(
    CasePolicy('admission_rejects_missing_keys_and_unsafe_authority', 'instance', 'objects'),
    CasePolicy('atomic_event_failure_rls_and_large_member_ids', 'fresh', 'objects'),
    CasePolicy('lost_commit_ack_replays_durable_result_once', 'fresh', 'objects'),
))
MODULES['planning.assets'] = replace(MODULES['planning.assets'], db_mode='reuse', scope='tenant')
MODULES['planning.scope'] = replace(MODULES['planning.scope'], db_mode='reuse', scope='tenant', policies=(
    CasePolicy('planning::t2::scope::corrupt_scope_is_a_storage_failure_not_a_client_error', 'fresh', 'objects'),
))
MODULES['planning.group_scope'] = replace(MODULES['planning.group_scope'], db_mode='reuse', scope='tenant', policies=(
    CasePolicy('planning::t2::group_scope::group_delete_scope_reference_compete_without_dangling_references', 'reuse', 'tenant'),
    CasePolicy('planning::t2::group_scope::group_scope_replay_and_audit_atomicity', 'fresh', 'pair'),
), fixtures=(*MODULES['planning.group_scope'].fixtures, 'content'))
MODULES['planning.onboarding'] = replace(MODULES['planning.onboarding'], db_mode='reuse', scope='tenant', fixtures=(*MODULES['planning.onboarding'].fixtures, 'content'))
MODULES['planning.policy'] = replace(MODULES['planning.policy'], db_mode='reuse', scope='tenant', fixtures=(*MODULES['planning.policy'].fixtures, 'content'))
MODULES['planning.recovery'] = replace(MODULES['planning.recovery'], db_mode='reuse', scope='tenant', policies=(
    CasePolicy('planning::t2::recovery::ingress::device_pages_commit_unknown_restart_and_later_window', 'reuse', 'pair'),
    CasePolicy('planning::t2::recovery::corrupt_background_query_is_not_client_input', 'fresh', 'objects'),
    CasePolicy('planning::t2::recovery::management_admission_rejects_schema_and_privilege_drift', 'instance', 'objects'),
    CasePolicy('planning::t2::recovery::rss_exhaustion_records_failed_task_and_atomic_audit', 'fresh', 'objects'),
))
MODULES['planning.http'] = replace(MODULES['planning.http'], db_mode='fresh', scope='objects', policies=(
    CasePolicy('planning::t2::http::collection_blueprints_instantiate_replay_and_keep_tenant_versions', 'fresh', 'objects', ('identity','content','task_signing')),
    CasePolicy('planning::t2::http::nested_groups_sources_references_and_authorized_pages', 'fresh', 'objects', ('identity','content','task_signing','local_worker')),
    CasePolicy('planning::t2::http::planning_routes_and_derived_result_authorization', 'fresh', 'objects', ('identity','content','task_signing','local_worker')),
))
MODULES['planning.agent_policy'] = replace(MODULES['planning.agent_policy'], db_mode='reuse', scope='objects', policies=(
    CasePolicy('planning::t2::agent_policy::policy_scan_reaches_late_match', 'reuse', 'tenant'),
    CasePolicy('planning::t2::agent_policy::preview_publish_authorization_and_commit_replay', 'reuse', 'tenant'),
    CasePolicy('planning::t2::agent_policy::script_preparation_is_shared_without_preview_effects', 'reuse', 'tenant'),
), fixtures=(*MODULES['planning.agent_policy'].fixtures, 'content'))
MODULES['planning.frequency'] = replace(MODULES['planning.frequency'], db_mode='reuse', scope='objects', policies=(
    CasePolicy('planning::t2::frequency::once_per_entry_tracks_membership_epochs', 'reuse', 'tenant'),
), fixtures=(*MODULES['planning.frequency'].fixtures, 'content'))
MODULES['planning.software'] = replace(MODULES['planning.software'], db_mode='reuse', scope='objects', policies=(
    CasePolicy('planning::t2::software::rollout_time_success_gates_and_stage_evidence', 'reuse', 'tenant'),
    CasePolicy('planning::t2::software::rollout_statistics_checkpoint_excluded_pages_and_reject_stale_inputs', 'fresh', 'tenant'),
), fixtures=(*MODULES['planning.software'].fixtures, 'content'))
MODULES['policy.persistence'] = replace(MODULES['policy.persistence'], db_mode='reuse', scope='objects', policies=(
    CasePolicy('admission_rejects_schema_and_reachable_privilege_drift', 'instance', 'objects'),
))
MODULES['policy.recovery'] = replace(MODULES['policy.recovery'], db_mode='fresh', scope='objects')
MODULES['resource.persistence'] = replace(MODULES['resource.persistence'], db_mode='instance', scope='objects', policies=(
    CasePolicy('artifact_reference_index_covers_reuse_without_another_upload_and_archive_rollback', 'reuse', 'objects'),
    CasePolicy('resource_cas_events_and_owner_admission', 'fresh', 'objects'),
    CasePolicy('resource_immutable_versions_reopen_and_reference_rollback', 'reuse', 'objects'),
    CasePolicy('storage_rejects_invalid_format_without_rewriting_immutable_bytes', 'fresh', 'objects'),
))
MODULES['resource.recovery'] = replace(MODULES['resource.recovery'], db_mode='fresh', scope='objects')
MODULES['software_release.persistence'] = replace(MODULES['software_release.persistence'], db_mode='reuse', scope='objects', policies=(
    CasePolicy('admission_rejects_noninherited_switchable_privileges', 'instance', 'objects'),
    CasePolicy('release_events_and_runtime_binding', 'reuse', 'objects'),
))
MODULES['software_release.recovery'] = replace(MODULES['software_release.recovery'], db_mode='fresh', scope='objects')
MODULES['compliance.storage'] = replace(MODULES['compliance.storage'], db_mode='fresh', scope='objects', policies=(
    CasePolicy('immutable_versions_results_and_tenant_transactions', 'reuse', 'pair'),
))
MODULES['compliance.http'] = replace(MODULES['compliance.http'], db_mode='reuse', scope='pair')
MODULES['compliance.evaluation'] = replace(MODULES['compliance.evaluation'], db_mode='reuse', scope='tenant')
MODULES['compliance.recovery'] = replace(MODULES['compliance.recovery'], db_mode='fresh', scope='objects', policies=(
    CasePolicy('compliance::t2::recovery::mutation_unknown_commit_recovers_original_response', 'reuse', 'tenant'),
))
MODULES['compliance.group_input'] = replace(MODULES['compliance.group_input'], db_mode='reuse', scope='tenant')
MODULES['execution.agent.delivery'] = replace(MODULES['execution.agent.delivery'], db_mode='reuse', scope='tenant', policies=(
    CasePolicy('execution::t2::agent::delivery::registration_capability_and_wire_gate', 'reuse', 'objects'),
))
MODULES['execution.agent.history'] = replace(MODULES['execution.agent.history'], db_mode='reuse', scope='tenant')
MODULES['execution.agent.poll'] = replace(MODULES['execution.agent.poll'], db_mode='reuse', scope='tenant')
MODULES['execution.commands.admission'] = replace(MODULES['execution.commands.admission'], db_mode='reuse', scope='tenant', policies=(
    CasePolicy('execution::t2::commands::admission::minimum_role_scope_and_storage_admission', 'instance', 'objects'),
))
MODULES['execution.commands.dispatch'] = replace(MODULES['execution.commands.dispatch'], db_mode='reuse', scope='tenant')
MODULES['execution.commands.recovery'] = replace(MODULES['execution.commands.recovery'], db_mode='fresh', scope='objects')
MODULES['execution.commands.windows'] = replace(MODULES['execution.commands.windows'], scope='tenant', fixtures=(*MODULES['execution.commands.windows'].fixtures, 'content'))
MODULES['windows.management'] = replace(MODULES['windows.management'], scope='tenant', policies=(CasePolicy('windows::t2::management::damaged_committed_transcript_fails_closed_without_rewriting_evidence','fresh','tenant'),))
MODULES['execution.commands.configuration'] = replace(MODULES['execution.commands.configuration'], db_mode='reuse', scope='tenant')
MODULES['execution.commands.onboarding'] = replace(MODULES['execution.commands.onboarding'], db_mode='reuse', scope='tenant',support_inputs=(*MODULES['execution.commands.onboarding'].support_inputs,'crates/app/tests/support/channel_onboarding.rs',), fixtures=(*MODULES['execution.commands.onboarding'].fixtures, 'content'))
MODULES['software.catalog'] = replace(MODULES['software.catalog'], db_mode='instance', scope='objects', policies=(
    CasePolicy('transactions::dependency_admission_uses_exact_current_enablement', 'reuse', 'objects'),
    CasePolicy('transactions::source_receipts_follow_the_borrowed_transaction', 'reuse', 'tenant'),
))
MODULES['software.http'] = replace(MODULES['software.http'], db_mode='reuse', scope='objects', policies=(
    CasePolicy('software_catalog::t2::http::imports::rest_import_binds_original_material_and_replays_without_source', 'reuse', 'objects', ('identity','tls','content')),
    CasePolicy('software_catalog::t2::http::publication::brew::immutable_native_tap_is_consumed_by_git_and_homebrew_and_withdrawn', 'fresh', 'objects', ('identity','tls','git','homebrew','content')),
    CasePolicy('software_catalog::t2::http::publication::publication_http_authority_receipts_and_public_native_binding', 'reuse', 'tenant', ('identity','tls','local_worker','content')),
))
MODULES['content.http'] = replace(MODULES['content.http'], db_mode='fresh', scope='objects')
MODULES['content.mirror'] = replace(MODULES['content.mirror'], db_mode='fresh', scope='objects')
MODULES['content.gc'] = replace(MODULES['content.gc'], db_mode='instance', scope='objects', policies=(
    CasePolicy('content::t2::gc::reference_and_gc_are_serialized', 'reuse', 'objects'),
))
MODULES['publication.winget'] = replace(MODULES['publication.winget'], db_mode='fresh', scope='objects')
MODULES['publication.brew'] = replace(MODULES['publication.brew'], db_mode='fresh', scope='objects')
MODULES['publication.mapping'] = replace(MODULES['publication.mapping'], db_mode='fresh', scope='objects')
MODULES['publication.recovery'] = replace(MODULES['publication.recovery'], db_mode='fresh', scope='objects')
MODULES['windows.issuance'] = replace(MODULES['windows.issuance'], db_mode='fresh', scope='objects')
MODULES['windows.retention'] = replace(MODULES['windows.retention'], db_mode='fresh', scope='objects')
MODULES['windows.limits'] = replace(MODULES['windows.limits'], db_mode='reuse', scope='tenant')
for name in ('apple.collection','apple.scep','apple.commands','apple.users','apple.ddm'):
    MODULES[name] = replace(MODULES[name],scope='tenant',fixtures=(*MODULES[name].fixtures,'local_worker'))
MODULES['apple.profile'] = replace(MODULES['apple.profile'], scope='tenant', fixtures=(*MODULES['apple.profile'].fixtures,'local_worker'))
MODULES['apple.policy'] = replace(MODULES['apple.policy'], db_mode='reuse', scope='tenant', fixtures=(*MODULES['apple.policy'].fixtures,'local_worker'), policies=(
    CasePolicy('apple::tests::policy::current_authorization_and_deadlines', 'reuse', 'tenant'),
))
MODULES['apple.onboarding'] = replace(MODULES['apple.onboarding'], db_mode='reuse', scope='tenant', fixtures=(*MODULES['apple.onboarding'].fixtures,'local_worker'), support_inputs=(*MODULES['apple.onboarding'].support_inputs,'crates/app/tests/support/channel_onboarding.rs',))
MODULES['apple.renewal'] = replace(MODULES['apple.renewal'], db_mode='reuse', scope='tenant')
MODULES['apple.identity'] = replace(MODULES['apple.identity'], db_mode='reuse', scope='tenant', fixtures=(*MODULES['apple.identity'].fixtures,'local_worker'), policies=(
    CasePolicy('apple::tests::identity::token_is_required_before_management', 'reuse', 'tenant'),
))
MODULES['apple.push'] = replace(MODULES['apple.push'], db_mode='reuse', scope='tenant', policies=(
    CasePolicy('apple::tests::push::deadline_query_failure_is_not_healthy_idle', 'fresh', 'objects'),
))
MODULES['apple.fairness'] = replace(MODULES['apple.fairness'], db_mode='reuse', scope='tenant')
MODULES['apple.host'] = replace(MODULES['apple.host'], db_mode='fresh', scope='objects')

# These cases start their actual domain consumers in the case tenant.
for name in ('planning.http',
             'planning.policy', 'planning.agent_policy', 'planning.frequency', 'planning.software', 'planning.onboarding', 'compliance.evaluation', 'compliance.recovery',
             'execution.agent.delivery', 'execution.agent.content', 'execution.agent.history',
             'execution.agent.poll', 'execution.agent.recovery', 'execution.software.offer',
             'execution.software.content', 'execution.software.recovery',
             'windows.enrollment', 'windows.management',
             'windows.commands', 'windows.limits'):
    value = MODULES[name]
    MODULES[name] = replace(value, fixtures=(*value.fixtures, 'local_worker'),
                            scope='tenant' if value.db_mode == 'reuse' else value.scope)
for name in ('compliance.http', 'compliance.group_input'):
    MODULES[name] = replace(MODULES[name], fixtures=(*MODULES[name].fixtures, 'local_worker'))


def case_fixtures(module, selector, marker):
    value = MODULES[module]
    fixtures = tuple(f for f in value.fixtures if f not in {'local_worker'})
    fixtures += (marker,) if marker else ()
    previous = next((p for p in value.policies if p.selector == selector),
                    CasePolicy(selector, value.db_mode, value.scope))
    MODULES[module] = replace(value, policies=(*[p for p in value.policies if p.selector != selector],
                                               replace(previous, fixtures=fixtures)))


case_fixtures('windows.issuance', 'windows::t2::issuance::native_renewal_preserves_registration_and_activates_only_after_new_tls_proof', 'local_worker')
# Template flows own Automation/Execution shutdown before durable recovery and retirement.
MODULES['windows.management'] = replace(MODULES['windows.management'], policies=(*MODULES['windows.management'].policies,
    CasePolicy('windows::t2::management::collection::', 'reuse', 'tenant', ('identity','windows','content','local_worker')),
))
case_fixtures('diagnostics.http', 'api::t2::runtime_diagnostics::execution_first_scan_failure_recovers_only_after_real_success', None)
case_fixtures('execution.agent.poll', 'execution::t2::agent::poll::cancellation_backlog_does_not_starve_live_offer', 'local_worker')
case_fixtures('planning.http', 'planning::t2::http::console_scope_ready_tracks_current_admission', 'local_worker')
case_fixtures('planning.frequency', 'planning::t2::frequency::once_per_entry_tracks_membership_epochs', 'local_worker')
case_fixtures('planning.software', 'planning::t2::software::rollout_time_success_gates_and_stage_evidence', 'local_worker')
case_fixtures('planning.software', 'planning::t2::software::rollout_statistics_checkpoint_excluded_pages_and_reject_stale_inputs', 'local_worker')
case_fixtures('compliance.recovery', 'compliance::t2::recovery::mutation_unknown_commit_recovers_original_response', None)
case_fixtures('compliance.recovery', 'compliance::t2::recovery::rule_and_fact_revisions_fence_stale_publication', 'local_worker')
case_fixtures('execution.agent.delivery', 'execution::t2::agent::delivery::registration_capability_and_wire_gate', None)
MODULES['content.http'] = replace(MODULES['content.http'], policies=(
    CasePolicy('content::t2::http::corrupt_uploads_have_no_binding_and_distinct_operations_bind_verified_content', 'reuse', 'objects'),
))

case_fixtures('execution.agent.delivery', 'execution::t2::agent::delivery::offer_start_result_replay_and_inventory_projection', 'local_worker')
case_fixtures('execution.agent.delivery', 'execution::t2::agent::delivery::native_inventory_only_partial_empty_chunked_and_revoked', 'local_worker')
case_fixtures('execution.agent.delivery', 'execution::t2::agent::delivery::native_unmapped_evidence_requires_sensitive_permission', 'local_worker')
case_fixtures('execution.agent.delivery', 'execution::t2::agent::delivery::native_all_query_failures_preserve_execution_completion', 'local_worker')
case_fixtures('execution.agent.delivery', 'execution::t2::agent::delivery::signing::collection_claim_requires_signer_and_recovers_without_republication', 'local_worker')
for name in ('agent.reports', 'inventory.runtime', 'planning.assets', 'planning.scope',
             'planning.group_scope', 'planning.recovery', 'execution.commands.dispatch',
             'execution.commands.recovery', 'execution.commands.configuration', 'execution.commands.windows', 'execution.commands.onboarding', 'windows.retention',
             'windows.declared', 'apple.push', 'apple.fairness', 'apple.renewal', 'apple.host'):
    value = MODULES[name]
    # Local consumer controls are meaningful only in their own observation tenant.
    if value.scope == 'tenant' or value.db_mode in {'fresh', 'instance'}:
        MODULES[name] = replace(value, fixtures=(*value.fixtures, 'local_worker'))


case_fixtures('planning.group_scope', 'planning::t2::group_scope::group_delete_scope_reference_compete_without_dangling_references', None)

def consume(inputs, names):
    """The named modules test a real production path through these inputs."""
    for name in names.split() if isinstance(names, str) else names:
        MODULES[name] = replace(MODULES[name], production_inputs=MODULES[name].production_inputs + tuple(inputs))


consume(('crates/execution-service/src/collection_eligibility.rs',), 'windows.management apple.collection planning.agent_policy planning.http')
consume(('crates/inventory/src/builtin/standard.rs', 'crates/inventory/src/builtin/standard/*.rs'), 'inventory.manual inventory.runtime assets.http')
consume(('crates/resource/src/blueprints.rs',), 'planning.http')

consume(('crates/content-service/src/range.rs',),
        'content.http execution.agent.content execution.software.content')
consume(('crates/content-service/src/upload.rs', 'crates/content-service/src/bundle.rs'),
        'content.http software.http')
consume(('crates/content-service/src/cleanup.rs', 'crates/content-service/src/event.rs'),
        'content.gc planning.resource_archive')
consume(('crates/brew-source/src/*',), 'publication.brew')
consume(('crates/winget-source/src/*',), 'publication.winget publication.recovery content.mirror')
consume(('crates/resource/src/script.rs',),
        'planning.agent_policy planning.frequency execution.agent.delivery execution.agent.content execution.agent.recovery')
consume(('crates/execution-service/src/input_preparation.rs', 'crates/execution-service/src/input_preparation/*'), 'planning.agent_policy execution.agent.delivery')
consume(('crates/execution-service/src/input_preparation.rs',
         'crates/execution-service/src/input_preparation/request.rs',
         'crates/execution-service/src/input_preparation/native.rs',
         'crates/execution-service/src/input_preparation/publication.rs'),
        'execution.commands.configuration')
consume(('crates/execution-service/src/freeze_inputs.rs', 'crates/flow-service/src/resource_catalog/mod.rs'),
        'planning.agent_policy planning.onboarding')
consume(('crates/policy/src/presentation.rs',), 'planning.self_service')
for name in ('execution.agent.delivery', 'execution.software.offer'):
    MODULES[name] = replace(MODULES[name], support_inputs=(*MODULES[name].support_inputs,
                           'crates/app/tests/support/task_signature.rs'))
consume(('crates/agent-wire/schema/runtime/binding-profile-*.json',), 'agent.registration')
consume(('crates/agent-wire/schema/runtime/report-*.json',), 'agent.reports planning.onboarding')
consume(('crates/agent-wire/src/onboarding.rs',),
        'agent.reports planning.onboarding execution.commands.onboarding apple.onboarding execution.agent.delivery execution.agent.poll execution.agent.recovery')
consume(('crates/agent-wire/schema/enroll/native-grant-request-v1.schema.json',),
        'execution.commands.onboarding apple.onboarding')
# Native onboarding shares one durable installation and managed-registration owner.
consume(('crates/execution-service/src/native_installation.rs',
         'crates/execution-service/src/managed_registration.rs',
         'crates/execution-service/src/agent_preparation.rs',

         'crates/registration-service/src/enrollment/managed.rs'),
        'execution.commands.onboarding apple.onboarding')
consume(('crates/execution-service/src/sources/onboarding.rs',
         'crates/inventory-service/src/collection/channel.rs',
         'crates/inventory-service/src/assets/channel.rs',
         'crates/flow-service/src/planning/automation/scopes.rs'),
        'planning.onboarding execution.commands.onboarding apple.onboarding')
consume(('crates/windows-channel/src/management.rs','crates/windows-channel/src/boundary.rs'),
        'execution.commands.onboarding')
consume(('crates/apple-channel/src/checkin.rs','crates/apple-channel/src/boundary.rs'),
        'apple.onboarding')
consume(('crates/apple-channel/src/push.rs',), 'apple.push apple.host')
consume(('crates/certificate/src/apple.rs',), 'apple.scep apple.renewal apple.identity')
consume(('crates/flow-service/src/planning/automation.rs','crates/inventory-service/src/inventory_runtime.rs','crates/inventory-service/src/inventory_runtime/*','crates/flow-service/src/automation/runtime.rs','crates/flow-service/src/automation/completion.rs','crates/flow-service/src/planning/mod.rs','crates/app/src/identity.rs','crates/apple-channel/src/lib.rs','crates/inventory-service/src/collection/*'), 'diagnostics.http')
consume(('crates/app/src/identity.rs',), 'identity.local identity.sso api.identity_context')
consume(('crates/execution-service/src/sources/software.rs',),
        'planning.software execution.software.offer execution.software.recovery')
consume(('hack/enrollment-password.py',), 'enrollment.http enrollment.recovery')
consume(('crates/management-http/src/software_native.rs',),
        'publication.winget publication.brew publication.withdrawal')
consume(('crates/flow-service/src/planning/automation/dispatch.rs',),
        'planning.assets planning.policy planning.scope planning.group_scope planning.recovery compliance.group_input')
consume(('crates/flow-service/src/planning/automation/groups.rs',), 'planning.group_scope assets.group_input compliance.group_input')
consume(('crates/flow-service/src/planning/automation/scopes.rs',), 'planning.scope planning.group_scope planning.frequency planning.software')
consume(('crates/execution-service/src/actions/poll.rs',), 'execution.agent.poll execution.agent.delivery')
consume(('crates/execution-service/src/actions/history.rs',), 'execution.agent.history')
consume(('crates/execution-service/src/actions/software.rs',), 'execution.software.offer execution.software.content execution.software.recovery')
consume(('crates/execution-service/src/actions/agent.rs',), 'execution.agent.delivery execution.agent.content execution.agent.recovery')
consume(('crates/execution-service/src/actions/recovery.rs',), 'execution.agent.recovery execution.software.recovery')
consume(('crates/software-service/src/publication/references.rs',), 'planning.resource_archive')
consume(('crates/software-service/src/publication/*.sql',),
        'publication.winget publication.brew publication.mapping publication.withdrawal publication.recovery')


consume(('crates/management-http/src/http_operation.rs',), 'authorization.programmatic content.http content.mirror enrollment.http planning.http software.http')
consume(('crates/authorization-service/src/initialization.rs', 'crates/app/src/authorization_bootstrap.rs'), 'authorization.initialization')
consume(('crates/audit-integration/src/completion.rs',
         'crates/agent-channel/src/boundary.rs', 'crates/windows-channel/src/boundary.rs',
         'crates/apple-channel/src/boundary.rs'), 'api.diagnostics')
consume(('crates/agent-channel/src/boundary.rs', 'crates/agent-channel/src/bindings.rs', 'crates/agent-channel/src/operations.rs'), 'agent.registration agent.reports execution.agent.delivery execution.agent.poll')
consume(('crates/agent-channel/src/content.rs',), 'execution.agent.content execution.software.content')
consume(('crates/windows-channel/src/collection.rs', 'crates/windows-channel/src/boundary.rs'), 'windows.management windows.retention windows.limits inventory.runtime')
consume(('crates/inventory-service/src/collection*', 'crates/inventory-service/src/apple_collection.rs', 'crates/inventory-service/src/collection/*'), 'agent.reports windows.management windows.retention apple.collection apple.renewal inventory.runtime')
consume(('crates/inventory-service/src/groups/*',), 'planning.http planning.group_scope assets.group_input compliance.group_input')
consume(('crates/apple-channel/src/boundary.rs',), 'apple.scep apple.collection apple.profile apple.renewal apple.identity apple.host')

# Software resource decisions and file staging have explicit behavioral consumers.
consume(('crates/software-service/src/management/catalog.rs', 'crates/software-service/src/management/content.rs',
         'crates/software-service/src/management/error.rs', 'crates/software-service/src/management/transaction.rs',
         'crates/software-service/src/management/mod.rs'), 'software.http')
consume(('crates/software-service/src/management/publication/*',), 'software.http')
consume(('crates/software-service/src/publication/access.rs', 'crates/software-service/src/publication/read.rs', 'crates/software-service/src/publication/worker.rs', 'crates/software-service/src/publication/derive.rs'), 'software.http publication.winget publication.brew publication.mapping publication.withdrawal publication.recovery')
consume(('crates/content-service/src/software.rs',), 'software.http')

consume(('crates/agent-channel/src/tasks.rs',),
        'execution.agent.delivery execution.agent.poll execution.agent.content execution.agent.recovery execution.software.offer execution.software.content execution.software.recovery')
consume(('crates/windows-channel/src/lib.rs',),
        'windows.enrollment windows.issuance windows.management windows.commands windows.retention windows.limits')


# Webhook-specific product risks; RSS owns transport/signature and retry conformance.
add('webhooks.product', selectors=('webhook_tests::',), fixtures=('identity','tls'),
    sources=('crates/webhook-service/src/*','crates/webhook-service/schema/*','crates/app/src/webhooks/*','crates/management-http/src/webhooks.rs','crates/registration-service/src/webhook.rs'),
    tests=('crates/app/tests/webhooks/mod.rs',), support=('hack/source_fixtures.py',))
# This case owns its relay and material configuration; retained ordinary hosts must not claim its deliveries.
MODULES['webhooks.product'] = replace(MODULES['webhooks.product'], scope='tenant')


MODULES['api.diagnostics'] = replace(MODULES['api.diagnostics'], test_inputs=('crates/app/tests/api/diagnostics.rs',))
for name in ('software.http','authorization.rules'):
    MODULES[name] = replace(MODULES[name], fixtures=MODULES[name].fixtures+('tls',))
for name in ('software.http','authorization.rules'):
    MODULES[name] = replace(MODULES[name], support_inputs=MODULES[name].support_inputs + ('crates/app/tests/support/publication_http.rs','tests/support/software/*'))
for name in ('inventory.runtime', 'agent.reports', 'assets.group_input', 'assets.sources',
             'compliance.evaluation', 'execution.agent.delivery'):
    MODULES[name] = replace(MODULES[name], support_inputs=MODULES[name].support_inputs +
        ('crates/app/tests/inventory_runtime/support.rs',))


for name in ('apple.apns', 'apple.push', 'apple.host'):
    MODULES[name] = replace(MODULES[name], support_inputs=MODULES[name].support_inputs +
        ('crates/app/tests/apple/support/apns.rs',))
for name, path in (('apple.push','push_cycle'), ('apple.host','production')):
    MODULES[name] = replace(MODULES[name], test_inputs=(f'crates/app/tests/apple/{path}.rs',))

add('settings.recent_auth', selectors=('user_profiles::recent_tests::',), fixtures=('identity','windows'),
    sources=('crates/authorization-service/src/context.rs','crates/apple-channel/src/runtime_materials/mod.rs','crates/windows-channel/src/wns_materials.rs','crates/content-service/src/connections/authority.rs','crates/mail-service/src/authority.rs','crates/execution-service/src/task_signing/service.rs','crates/app/src/webhooks/mod.rs','crates/app/src/settings.rs'),
    tests=('crates/app/tests/settings/recent_auth.rs',),
    support=())

add('settings.user_profiles', selectors=('user_profiles::tests::',), fixtures=('identity',),
    sources=('crates/app/src/user_profiles.rs','crates/app/src/user_profiles/*','crates/management-http/src/user_profiles.rs','crates/authorization-service/src/identity_management.rs'),
    tests=('crates/app/tests/settings/user_profiles.rs',),
    support=())
MODULES['settings.user_profiles'] = replace(MODULES['settings.user_profiles'], scope='pair')

add('settings.first_use', selectors=('first_use::tests::',), fixtures=('identity','windows'),
    sources=('crates/app/src/first_use.rs','crates/app/src/first_use/*',
             'crates/app/src/settings.rs','crates/management-http/src/first_use.rs',
             'crates/app/src/registration_channels.rs'),
    tests=('crates/app/tests/settings/first_use.rs',),
    support=())
MODULES['settings.first_use'] = replace(MODULES['settings.first_use'], scope='pair')

# Runtime fixture consumers sign durable candidates and use completed TLS peers.
AGENT_FIXTURE_CONSUMERS = tuple(('planning.custom_events execution.agent.task_trust planning.self_service agent.registration agent.reports execution.agent.delivery execution.agent.poll execution.agent.content execution.agent.recovery execution.agent.history execution.software.offer execution.software.content execution.software.recovery planning.onboarding execution.commands.onboarding apple.onboarding planning.agent_policy planning.frequency planning.software').split())
AGENT_FIXTURES = ('identity','agent_pki','task_signing')
for name in AGENT_FIXTURE_CONSUMERS:
    module=MODULES[name]
    policies=tuple(replace(policy, fixtures=tuple(dict.fromkeys((*policy.fixtures,*AGENT_FIXTURES)))) if policy.fixtures is not None else policy for policy in module.policies)
    MODULES[name]=replace(module,fixtures=tuple(dict.fromkeys((*module.fixtures,*AGENT_FIXTURES))),policies=policies)

# Only these mixed cases consume Agent enrollment; other native cases keep their fixtures.
AGENT_FIXTURE_CASES = {
    'planning.http': 'planning::t2::http::console_script_support_requires_signer_and_content',
    'execution.commands.windows': 'execution::t2::commands::windows::console_mixed_kind_cursor_and_device_visibility',
    'software.http': 'software_catalog::t2::http::publication::publication_http_authority_receipts_and_public_native_binding',
}
for name, selector in AGENT_FIXTURE_CASES.items():
    module = MODULES[name]
    policies = list(module.policies)
    existing = next((i for i, policy in enumerate(policies) if policy.selector == selector), None)
    policy = policies[existing] if existing is not None else CasePolicy(selector, module.db_mode, module.scope)
    policy = replace(policy, fixtures=tuple(dict.fromkeys((*(policy.fixtures or module.fixtures), *AGENT_FIXTURES, 'content'))))
    if existing is None:
        policies.append(policy)
    else:
        policies[existing] = policy
    MODULES[name] = replace(module, policies=tuple(policies))

for name, module in tuple(MODULES.items()):
    support = tuple(path for path in module.support_inputs if path != 'tests/support/software/*')
    if name in ('software.catalog','software.http','authorization.rules','content.http','content.mirror','content.gc','planning.resource_archive') or name.startswith('publication.'):
        support += ('tests/support/software/mod.rs',)
    if name == 'software.catalog' or name.startswith('publication.') and name != 'publication.artifact':
        support += ('tests/support/software/pg.rs',)
    if name == 'publication.recovery':
        support += ('tests/support/software/ack.rs',)
    if name in ('apple.cms','apple.apns'):
        support = tuple(path for path in support if not path.startswith('crates/app/tests/support/'))
    MODULES[name] = replace(module, support_inputs=support)
for owner in ('policy','resource','software_release'):
    for part in ('persistence','recovery'):
        name=owner+'.'+part
        package=owner.replace('_','-')
        support=tuple(path for path in MODULES[name].support_inputs if path != f'crates/{package}-postgres/tests/support/*')
        support += (f'crates/{package}-postgres/tests/support/mod.rs',)
        if owner == 'policy':
            support += (f'crates/{package}-postgres/tests/support/operations.rs',)
        if part == 'recovery':
            support += (f'crates/{package}-postgres/tests/support/ack.rs',)
        MODULES[name] = replace(MODULES[name],support_inputs=support)
MODULES['audit.recovery'] = replace(MODULES['audit.recovery'], support_inputs=MODULES['audit.recovery'].support_inputs+('crates/app/tests/audit/test_support.rs',))

# App test-only namespace carriers preserve the existing Rust case identities.
MODULES['apple.cms']=replace(MODULES['apple.cms'],support_inputs=(*MODULES['apple.cms'].support_inputs,'crates/app/tests/apple/certificate_support.rs'))
MODULES['apple.apns']=replace(MODULES['apple.apns'],support_inputs=(*MODULES['apple.apns'].support_inputs,'crates/app/tests/apple/push_support.rs'))

# These carrier files compose exactly these test children, not production consumers.
MODULES['execution.commands.dispatch'] = replace(
    MODULES['execution.commands.dispatch'], children=('execution::test_support::',))

MODULES['assets.group_input'] = replace(MODULES['assets.group_input'], support_inputs=MODULES['assets.group_input'].support_inputs+('crates/app/tests/assets/group_support.rs',))

# Shared preparation is proven by existing owner scenarios. Business assertion helpers
# remain with their direct tests; preparing a fixture does not select every user.
APP_HELPER_CONSUMERS = {
    'support/process.rs': ('api.identity_context',),
    'support/runtime.rs': ('api.identity_context',),
    # Cookie, collection GET and asynchronous-query assertions are exercised here.
    'support/http.rs': ('api.identity_context', 'identity.local', 'identity.sso',
                        'apple.collection', 'windows.management', 'assets.queries'),
    'support/identity.rs': ('identity.local', 'identity.sso'),
    'support/authority.rs': ('authorization.rules',),
    'support/settings.rs': ('settings.recent_auth', 'settings.first_use', 'execution.agent.task_trust'),
    'device/support.rs': ('device.binding',),
    'support/agent.rs': ('agent.registration',),
    'support/agent_tls.rs': ('agent.registration',),
    'support/command.rs': ('execution.commands.admission',),
    'support/agent_execution.rs': ('execution.agent.delivery',),
    'support/software_execution.rs': ('execution.software.offer',),
    'support/software.rs': ('software.http',),
    'support/planning_http.rs': ('planning.http',),
    'support/inventory.rs': ('inventory.runtime',),
    'support/audit.rs': ('agent.pki', 'api.diagnostics', 'apple.collection', 'apple.identity', 'apple.policy', 'apple.profile', 'assets.http', 'audit.budget', 'audit.integrity', 'audit.receipts', 'audit.recovery', 'authorization.capacity', 'authorization.initialization', 'authorization.programmatic', 'authorization.rules', 'compliance.group_input', 'compliance.http', 'compliance.recovery', 'content.http', 'device.recovery', 'device.revocation', 'diagnostics.http', 'enrollment.http', 'enrollment.quotas', 'execution.agent.content', 'execution.agent.history', 'execution.commands.admission', 'execution.commands.dispatch', 'execution.commands.onboarding', 'execution.commands.windows', 'planning.agent_policy', 'planning.assets', 'planning.group_scope', 'planning.recovery', 'planning.resource_archive', 'planning.scope', 'planning.self_service', 'settings.first_use', 'software.http', 'timeline.http', 'windows.enrollment', 'windows.issuance', 'windows.limits', 'windows.retention'),
    'support/gateway.rs': ('windows.management', 'apple.identity', 'agent.registration'),
    'support/tls.rs': ('windows.management', 'apple.identity', 'agent.registration'),
    'execution/support.rs': ('execution.commands.admission', 'execution.commands.configuration'),
    'execution/support/configuration.rs': ('execution.commands.configuration', 'windows.declared'),
    'execution/support/native.rs': ('execution.commands.configuration',),
}

# Console reads use the existing real HTTP integration owners.
MODULES['planning.http'] = replace(MODULES['planning.http'], production_inputs=(*MODULES['planning.http'].production_inputs,
    'crates/resource-postgres/src/codec.rs',
    'crates/inventory-postgres/src/lib.rs',
    'crates/execution-service/src/directory.rs',
    'crates/registration-service/src/device/directory.rs',
    'crates/inventory-service/src/assets/directory.rs',
    'crates/inventory-service/src/groups/directory.rs',
    'crates/group-postgres/src/directory.rs',
    'crates/resource-postgres/src/directory.rs',
    'crates/flow-service/src/resource_catalog/directory.rs',
    'crates/flow-service/src/resource_catalog/wire.rs',
    'crates/flow-service/src/planning/directory.rs',
    'crates/management-http/src/enrollment/directory.rs',
    'crates/management-http/src/resource_catalog/http.rs'), support_inputs=(*MODULES['planning.http'].support_inputs, ))
MODULES['execution.agent.history'] = replace(MODULES['execution.agent.history'], production_inputs=(*MODULES['execution.agent.history'].production_inputs,
    'crates/execution-service/src/directory.rs', 'crates/management-http/src/execution/http.rs'))

TOOL_INPUTS = {
    'hack/gateway_fixture.py': ('test_t2_environment',),
    'deployment/render_gateway.py': ('test_t2_environment',),
    'hack/ingress_network.py': ('test_ingress_network','test_t2_environment','test_candidate_smoke','test_release'),
    'hack/t2_context.py': ('test_t2_context', 'test_t2_fixtures'),
    'hack/t2_database.py': ('test_t2_fixtures',),
    'hack/t2_hosts.py': ('test_t2_hosts',),
    'hack/t2_modules/installation.py': ('test_t2_guards',),
    'hack/t2_python.py': ('test_t2_execution', 'test_t2_runner'),
    'hack/t2_model.py': ('test_t2_policy', 'test_t2_modules', 'test_t2_execution', 'test_t2_runner'),
    'hack/ci_impact.py': ('test_ci_impact', 'test_ci_selection', 'test_t2_modules'),
    'hack/t2_registry.py': ('test_app_test_layout', 'test_t2_policy', 'test_t2_modules', 'test_t2_runner', 'test_ci_selection', 'test_ci_impact'),
    'hack/t2.py': ('test_t2_modules', 'test_t2_runner', 'test_t2_guards'),
    'hack/t2_execution.py': ('test_t2_execution', 'test_t2_runner'),
    'hack/t2_processes.py': ('test_t2_execution', 'test_t2_fixtures', 'test_t2_runner', 'test_fixture_tools', 'test_apple_ca'),
    'hack/source_fixtures.py': ('test_source_t2',),
    'hack/s3_fixtures.py': ('test_s3_fixtures',),
    'fixtures/s3-provider.lock.json': ('test_s3_fixtures',),
    'hack/t2_environment.py': ('test_t2_environment', 'test_t2_runner', 'test_apple_ca'),
    '.env.example': ('test_t2_environment', 'test_t2_runner'),
    'deployment/compose.yaml': ('test_t2_environment', 'test_t2_runner', 'test_apple_ca'),
    'hack/t2_fixtures.py': ('test_t2_fixtures', 'test_t2_environment', 'test_t2_runner'),
    'hack/verification_result.py': ('test_t2_runner', 'test_t2_modules', 'test_ci_selection', 'test_ci'),
    'hack/build_run.py': ('test_build_run', 'test_build_environment'),
    'hack/ci.py': ('test_ci', 'test_ci_selection'),
    'hack/agent_wire_artifact.py': ('test_agent_wire_artifact',),
    'hack/fixture_tools.py': ('test_fixture_tools',),
    'hack/apple_ca.py': ('test_apple_ca',),
    'hack/pki_ca.py': ('test_apple_ca',),
    'hack/agent_pki_fixtures.py': ('test_t2_fixtures',),
    'hack/pki_recovery.py': ('test_pki_recovery',),
    'hack/auth_t3.py': ('test_auth_t3',),
    'hack/auth_t3_browser.mjs': ('test_auth_t3',),
    'hack/release.py': ('test_release',),
    'hack/candidate_runtime.py': ('test_candidate_smoke',),
    'hack/candidate_installation.py': ('test_candidate_smoke',),
    'hack/candidate_installation_driver.py': ('test_candidate_smoke',),
    'hack/candidate_fixture.py': ('test_candidate_smoke', 'test_t2_context'),
    'hack/candidate_smoke.py': ('test_candidate_smoke',),
}
T1_INPUTS = (
    'crates/app/tests/support/context_validation.rs',
    'crates/software-service/tests/imports.rs',
    "crates/examples/tests/model.rs",
    'crates/windows-channel/tests/unit.rs',
    'crates/apple-channel/tests/apns.rs', 'crates/winget-source/tests/community.rs',
    'crates/app/tests/windows/unit.rs','fixtures/snapshot.json', 'crates/content-s3/tests/unit.rs', 'crates/inventory-service/tests/assets/unit.rs') + ('crates/app/tests/agent_pki/health.rs','crates/certificate/tests/agent.rs','crates/certificate/tests/apple.rs','crates/certificate/tests/windows.rs','crates/recovery-credentials/tests/*','crates/certificate-archive-service/tests/behavior.rs','crates/authorization-service/tests/unit.rs','crates/inventory-service/tests/runtime.rs','crates/software-service/tests/management/*') + tuple(f'crates/{name}/tests/*' for name in (
    'inventory', 'group', 'scope', 'policy', 'resource', 'software-release',
    'compliance', 'agent-wire', 'windows-mdm', 'apple-mdm', 'content-service', 'device-trust')) + (
    'crates/app/tests/agent/unit.rs',
    'crates/app/tests/apple/webhook_unit.rs',
    'crates/inventory-service/tests/assets/query_sort_unit.rs',
    'crates/inventory-service/tests/assets/query_read_unit.rs',
    'crates/inventory-service/tests/assets/rsql_unit.rs',
    'crates/app/tests/assets/unit.rs',
    'crates/app/tests/audit_budget/unit.rs',
    'crates/audit-integration/tests/budget/unit.rs',
    'crates/audit-integration/tests/facts.rs',
    'crates/app/tests/authorization/unit.rs',
    'crates/app/tests/collection/unit.rs',
    'crates/inventory-service/tests/collection.rs',
    'crates/inventory-service/tests/compliance/evaluation_unit.rs',
    'crates/app/tests/compliance/evaluation_unit.rs',
    'crates/app/tests/config/unit.rs',
    'crates/app/tests/device/coordinates_unit.rs',
    'crates/app/tests/diagnostic/unit.rs',
    'crates/app/tests/enrollment/credentials_unit.rs',
    'crates/app/tests/enrollment/unit.rs',
    'crates/app/tests/error_projection/unit.rs',
    'crates/execution-service/tests/actions/state_unit.rs',
    'crates/execution-service/tests/model_unit.rs',
    'crates/execution-service/tests/model_phase_unit.rs',
    'crates/execution-service/tests/agent_install_unit.rs',
    'crates/execution-service/tests/recovery_unit.rs',
    'crates/execution-service/tests/query_records.rs',
    'crates/execution-service/tests/device_control_unit.rs',
    'crates/execution-service/tests/actions/state_schedule_unit.rs',
    'crates/app/tests/config/publication_unit.rs',
    'crates/app/tests/identity/unit.rs',
    'crates/app/tests/lifecycle/unit.rs',
    'crates/app/tests/native/admission_unit.rs',
    'crates/app/tests/planning/pages_unit.rs',
    'crates/app/tests/planning/wire_unit.rs',
    'crates/app/tests/windows/unit.rs',
    'crates/brew-source/tests/templates.rs', 'crates/winget-source/tests/protocol.rs',
    'crates/winget-source/tests/publication_schema.rs', 'crates/winget-source/tests/version.rs',
    'crates/app/tests/apple/health_unit.rs',
    'crates/flow-service/tests/planning/automation/scopes_unit.rs',
    'crates/app/tests/publication.rs',
)


MODULES['execution.commands.windows'] = replace(MODULES['execution.commands.windows'], production_inputs=(*MODULES['execution.commands.windows'].production_inputs, 'crates/execution-service/src/directory.rs', 'crates/management-http/src/execution/http.rs'), support_inputs=(*MODULES['execution.commands.windows'].support_inputs, ))

MODULES['windows.management'] = replace(MODULES['windows.management'], test_inputs=(*MODULES['windows.management'].test_inputs, 'crates/app/tests/windows/collection.rs'), production_inputs=(*MODULES['windows.management'].production_inputs, 'crates/windows-channel/src/template_collection.rs'))
consume(("crates/software-service/tests/support/imports.rs",), "software.catalog")

consume(('crates/execution-service/src/actions/output.rs',), 'execution.agent.delivery')
consume(('crates/execution-service/src/actions/native_collection.rs',
         'crates/execution-service/src/actions/recovery.rs',
         'crates/execution-service/src/actions/native_recovery.rs'), 'windows.management apple.collection apple.fairness apple.identity apple.policy')

consume(('crates/native-protection/*', 'crates/execution-service/src/input_storage.rs', 'crates/execution-service/src/protection.rs'), 'certificate-archive.http')

consume(('crates/content-service/src/protected.rs',), 'content.http content.gc execution.commands.configuration ')


consume(('crates/execution-service/src/agent_install.rs',), 'execution.commands.onboarding apple.onboarding planning.policy planning.agent_policy')
consume(('crates/execution-service/src/enrollment.rs',), 'planning.onboarding planning.policy execution.agent.delivery execution.agent.poll execution.agent.recovery')
consume(('crates/execution-service/src/configuration.rs', 'crates/execution-service/src/model.rs', 'crates/execution-service/src/permissions.rs'), 'execution.commands.admission execution.commands.windows execution.commands.configuration execution.commands.onboarding windows.management apple.profile planning.policy ')

consume(('crates/execution-service/src/queries/assignments.rs',), 'planning.http planning.agent_policy')
consume(('crates/execution-service/src/queries/preview.rs',), 'planning.agent_policy planning.software planning.policy')
consume(('crates/execution-service/src/apple.rs',), 'apple.profile apple.onboarding execution.commands.admission')
consume(('crates/execution-service/src/apple_push.rs',), 'apple.push apple.fairness apple.host')
consume(('crates/execution-service/src/protocol.rs',), 'windows.management windows.commands execution.commands.windows execution.commands.configuration execution.commands.onboarding')
consume(('crates/execution-service/src/sources/enrollment.rs',), 'planning.onboarding execution.agent.delivery execution.agent.poll execution.agent.recovery')
consume(('crates/execution-service/src/wake.rs',), 'planning.policy planning.agent_policy planning.frequency planning.scope planning.group_scope execution.commands.configuration execution.commands.onboarding')
consume(('crates/execution-service/src/worker_wake.rs',), 'execution.commands.dispatch execution.commands.recovery apple.push apple.fairness')

consume(('crates/software-service/src/publication/execution.rs',), 'planning.software execution.software.offer execution.software.content execution.software.recovery publication.mapping publication.winget publication.brew publication.withdrawal')

consume(('crates/windows-channel/src/transcript.rs', 'crates/windows-channel/src/large_object.rs',
         'crates/windows-channel/src/notifications.rs', 'crates/windows-channel/src/management/*'),
        'windows.management windows.commands windows.retention execution.commands.windows execution.commands.configuration execution.commands.onboarding inventory.runtime')
consume(('crates/execution-service/src/native/*', 'crates/execution-service/src/native_rules.rs'),
        'execution.commands.windows execution.commands.configuration execution.commands.onboarding windows.management windows.commands')

# Native Windows channel maintenance and retirement consumers.
MODULES['windows.management'] = replace(MODULES['windows.management'], test_inputs=(*MODULES['windows.management'].test_inputs, 'crates/app/tests/windows/wns.rs'))
consume(('crates/windows-channel/src/push*', 'crates/windows-channel/src/unenrollment.rs', 'crates/execution-service/src/windows_wake.rs'), 'windows.management device.revocation')
consume(('crates/windows-channel/src/renewal.rs', 'crates/device-trust/src/windows/*'), 'windows.issuance windows.management')
consume(('crates/execution-service/src/retirement*',), 'device.revocation windows.management apple.identity')
consume(('crates/windows-mdm/src/provisioning/*',), 'windows.issuance windows.enrollment execution.commands.windows')


# Native DDM responsibilities and Resource delivery use real product HTTP consumers.
consume(('crates/apple-channel/src/ddm*', 'crates/apple-channel/src/ddm/*',
         'crates/apple-mdm/src/native/ddm*', 'crates/apple-mdm/src/native/ddm/*',
         'crates/execution-service/src/apple_assets.rs'), 'apple.ddm ')
consume(('crates/apple-channel/src/profiles.rs', 'crates/apple-channel/src/exchange.rs',
         'crates/apple-channel/src/evidence.rs', 'crates/apple-mdm/src/native/profiles.rs',
         'crates/apple-mdm/src/native/evidence.rs'), 'apple.profile apple.policy apple.ddm ')
for name in ('apple.profile', 'apple.ddm'):
    MODULES[name] = replace(MODULES[name], support_inputs=(*MODULES[name].support_inputs,
        'crates/app/tests/apple/ddm.rs','crates/app/tests/apple/users.rs','crates/app/tests/apple/policy.rs',
        ))

consume(('crates/execution-service/src/service.rs', 'crates/execution-service/src/apple.rs', 'crates/execution-service/src/authority.rs',
         'crates/execution-service/src/source_authority.rs', 'crates/execution-service/src/permissions.rs',
         'crates/execution-service/src/queries.rs', 'crates/execution-service/src/queries/records.rs',
         'crates/execution-service/src/transaction.rs', 'crates/execution-service/src/channels.rs',
         'crates/execution-service/src/configuration.rs', 'crates/execution-service/src/native_configuration.rs',
         'crates/execution-service/src/model.rs', 'crates/apple-mdm/src/native/request.rs'), 'apple.ddm ')
consume(('crates/execution-service/src/native_configuration.rs',), 'apple.profile apple.policy')

consume(('crates/authorization-service/src/authority.rs', 'crates/authorization-service/src/model.rs', 'crates/execution-service/src/frozen.rs',
         'crates/execution-service/src/storage.rs'), 'apple.ddm ')

# Native evidence and HTTP projection inputs follow their actual production consumers (#2642).
consume(('crates/agent-wire/src/tasks/results.rs',),
        'planning.software execution.software.offer execution.software.content execution.software.recovery')
consume(('crates/windows-mdm/src/native/receipt.rs',),
        'windows.declared execution.commands.onboarding')

# Non-business inputs have explicit verification owners, never a full fallback.
CONTROL_INPUTS = {
    'Makefile': {
        'format': 'make',
        'tools': ['test_ci_selection', 'test_build_run', 'test_t2_runner'],
    },
    'deny.toml': {'format': 'tools', 'tools': ['test_ci']},
    'clippy.toml': {'format': 'tools', 'tools': ['test_ci']},
    '.cargo/config.toml': {
        'format': 'toml',
        'tools': ['test_build_environment'],
        'fields': {
            'net': 'tools',
            'build.target-dir': 'tools',
            'build.jobs': 'tools',
            'build.rustflags': 'runtime',
            'build.rustc': 'runtime',
            'build.target': 'runtime',
            'target': 'runtime',
            'source': 'runtime',
            'patch': 'runtime',
            'env': 'runtime',
        },
    },
    'rust-toolchain.toml': {
        'format': 'toml',
        'tools': ['test_build_environment'],
        'fields': {
            'toolchain.channel': 'runtime',
            'toolchain.targets': 'runtime',
            'toolchain.profile': 'tools',
            'toolchain.components': 'tools',
        },
    },
}
# Execution mechanism owns its behavior proof. These paths are not business
# helper inputs even when historical descriptions listed them as shared support.
TOOL_ONLY_INPUTS = (
    'crates/app/tests/support/mod.rs',
    'crates/app/tests/support/preparation.rs',
    'crates/app/tests/support/pki.rs',
    'hack/t2_model.py',
    'hack/t2_registry.py',
    'hack/ci_impact.py',
    'hack/t2.py',
    'hack/t2_execution.py',
    'hack/t2_python.py',
    'hack/t2_processes.py',
    'hack/t2_environment.py',
    'hack/t2_fixtures.py',
    'hack/t2_database.py',
    'hack/t2_context.py',
    'hack/candidate_fixture.py',
    'hack/t2_hosts.py',
    'hack/verification_result.py',
)

# Pure test assembly changes require compilation/discovery, not business execution.
TOOL_ONLY_INPUTS += tuple(
    f'crates/app/tests/{path}' for path in (
        'fixtures/agent.rs', 'fixtures/assets.rs', 'fixtures/authorization.rs',
        'fixtures/collection.rs', 'fixtures/compliance.rs', 'fixtures/content.rs',
        'fixtures/device.rs', 'fixtures/enrollment.rs', 'fixtures/execution.rs',
        'fixtures/inventory_runtime.rs', 'fixtures/planning.rs',
        'fixtures/resource_catalog.rs', 'fixtures/software_catalog.rs',
        'agent/mod.rs', 'api/mod.rs', 'enrollment/mod.rs',
        'execution/agent/mod.rs', 'execution/commands/mod.rs', 'execution/mod.rs',
        'execution/software/mod.rs', 'identity/mod.rs', 'planning/mod.rs',
        'software_catalog/mod.rs', 'windows/mod.rs',
    )
)
for path in TOOL_ONLY_INPUTS:
    if path.startswith('crates/app/tests/') and path != 'crates/app/tests/support/preparation.rs':
        TOOL_INPUTS[path] = ('test_app_test_layout',)

# Real execution uses existing carriers: product/Identity, group, backend with
# fault isolation, and the Python host/gateway. Scheduling and reporting remain
# covered by tool tests; none of these declarations adds a business matrix.
PG_REPRESENTATIVES = ('api.identity_context', 'group.persistence', 'policy.persistence')
REPRESENTATIVE_INPUTS = {
    'crates/app/tests/support/preparation.rs': ('api.identity_context', 'agent.registration'),
    'crates/app/tests/support/pki.rs': ('agent.registration',),
    'hack/t2_execution.py': ('policy.persistence',),
    'hack/t2_python.py': ('host.lifecycle', 'gateway.admission'),
    'hack/t2_processes.py': ('host.lifecycle',),
    'hack/t2_environment.py': (*PG_REPRESENTATIVES, 'host.lifecycle', 'gateway.admission'),
    'hack/t2_fixtures.py': (*PG_REPRESENTATIVES, 'host.lifecycle', 'gateway.admission'),
    'hack/t2_database.py': PG_REPRESENTATIVES,
    'hack/t2_context.py': PG_REPRESENTATIVES,
    'hack/candidate_fixture.py': (*PG_REPRESENTATIVES, 'installation.tenants'),
    'hack/t2_hosts.py': ('host.lifecycle',),
}


consume(('crates/agent-channel/src/database.rs',), 'agent.registration agent.reports execution.agent.delivery execution.agent.poll execution.agent.content')
consume(('crates/agent-wire/src/enroll.rs','crates/management-http/src/agent_enrollment.rs'), 'agent.registration agent.pki execution.commands.onboarding apple.onboarding')
consume(('crates/registration-service/src/lib.rs','crates/registration-service/src/error.rs'), 'agent.registration agent.pki device.binding device.revocation enrollment.http')
consume(('crates/windows-channel/src/error.rs',), 'windows.enrollment windows.management execution.commands.onboarding api.diagnostics')
consume(('crates/apple-channel/src/error.rs', 'crates/apple-channel/src/diagnostic.rs'), 'apple.ade apple.account_enrollment apple.profile apple.onboarding apple.collection api.diagnostics')
consume(('crates/inventory-service/src/error.rs',), 'agent.reports planning.onboarding assets.http api.diagnostics')


MODULES['execution.commands.windows'] = replace(MODULES['execution.commands.windows'],
    selectors=(*MODULES['execution.commands.windows'].selectors, 'execution::t2::commands::control::'),
    test_inputs=(*MODULES['execution.commands.windows'].test_inputs, 'crates/app/tests/execution/commands/control.rs'))

add('content.s3', build=Build('rss-mdm-content-s3'), selectors=('s3_tests::',), profile='none', fixtures=('s3',),
    sources=('crates/content-s3/src/*',), tests=('crates/content-s3/tests/s3.rs',),
    support=('hack/s3_fixtures.py','fixtures/s3-provider.lock.json'))

consume(('crates/content-service/src/backend.rs', 'crates/content-service/src/journal.rs', 'crates/content-service/src/reader.rs', 'crates/content-service/schema/*.sql'), 'content.storage')


MODULES['planning.self_service'] = replace(MODULES['planning.self_service'], fixtures=('identity','local_worker','agent_pki','task_signing','content'), scope='tenant', support_inputs=())


consume(('crates/windows-channel/src/protocol_device.rs',), 'windows.issuance windows.enrollment windows.management windows.declared')

consume(('crates/registration-service/src/quotas.rs', 'crates/registration-service/schema/quota-usage.sql'), 'agent.registration')

consume(('crates/management-http/src/enrollment/mod.rs',), 'enrollment.http enrollment.quotas')

T1_INPUTS += ('crates/registration-service/tests/credentials.rs',)
T1_INPUTS += ('crates/software-service/tests/execution_context.rs',
              'crates/software-service/tests/execution_evidence.rs')
consume(('crates/windows-channel/src/enrollment_store.rs',), 'windows.issuance windows.enrollment windows.declared')


consume(('crates/app/src/enrollment_progress.rs',), 'enrollment.http windows.enrollment windows.management apple.scep apple.identity')
consume(('crates/registration-service/src/database.rs',), 'enrollment.http enrollment.recovery enrollment.quotas device.binding device.revocation device.recovery agent.registration agent.pki')

MODULES['agent.configurations'] = replace(MODULES['agent.configurations'], fixtures=('identity','agent_pki','task_signing','content'), scope='tenant', support_inputs=(*MODULES['agent.configurations'].support_inputs,'crates/app/tests/support/agent_http.rs','tests/support/software/mod.rs'))
consume(('crates/registration-service/src/agent/*','crates/registration-service/schema/agent-configurations.sql','crates/software-service/src/agent_packages*','crates/content-service/src/software.rs','crates/content-service/src/reader.rs','crates/app/src/agent_configurations.rs','crates/agent-channel/src/enroll.rs','crates/agent-wire/src/enroll.rs','crates/agent-wire/src/enroll/configuration.rs','crates/management-http/src/agent_enrollment.rs','crates/management-http/src/software_catalog.rs'), 'agent.configurations')


consume(('crates/windows-channel/src/operations.rs','crates/registration-service/src/windows_receipts.rs','crates/registration-service/schema/windows-receipts.sql'), 'windows.entra windows.issuance windows.declared')

consume(('crates/execution-service/src/device_control.rs',), 'execution.commands.admission execution.commands.dispatch execution.commands.recovery execution.commands.windows apple.commands apple.policy')


consume(('crates/execution-service/src/native/outbound.rs',), 'execution.commands.windows')

consume((), 'windows.management apple.collection')

consume(('crates/apple-channel/src/collection.rs',), 'apple.collection')

consume(('crates/execution-service/src/queries.rs',), 'apple.commands apple.policy')

consume(('crates/execution-service/src/wake.rs', 'crates/execution-service/src/recovery.rs'), 'apple.commands apple.policy apple.account_enrollment')

consume(('crates/inventory-service/src/objects.rs', 'crates/device-service/src/planning.rs', 'crates/device-service/src/planning/snapshots.rs'), 'planning.group_scope device.views')
consume(('crates/flow-service/src/planning/targets.rs', 'crates/flow-service/src/planning/automation/relations.rs'), 'planning.group_scope planning.scope')
MODULES['planning.group_scope'] = replace(MODULES['planning.group_scope'],
    test_inputs=(*MODULES['planning.group_scope'].test_inputs,'crates/app/tests/planning/associated.rs'),
    selectors=(*MODULES['planning.group_scope'].selectors,'planning::t2::associated::'),
    support_inputs=(*MODULES['planning.group_scope'].support_inputs,'crates/app/tests/device/associations.rs','crates/app/tests/device/mod.rs',))
consume(('crates/app/src/flow.rs',), 'planning.group_scope planning.scope planning.policy planning.frequency planning.agent_policy planning.software planning.onboarding')

consume(('crates/flow-service/src/planning/automation/model.rs',), 'planning.group_scope planning.scope planning.policy planning.frequency planning.agent_policy planning.software planning.onboarding')
T1_INPUTS += ('crates/flow-service/tests/planning/pages_unit.rs',)
consume(('crates/inventory-service/src/compliance/mod.rs','crates/inventory-service/src/compliance/evaluation.rs'), 'compliance.group_input')
consume(('crates/inventory-service/src/lib.rs',), 'planning.group_scope planning.scope assets.group_input compliance.group_input')

MODULES['planning.group_scope']=replace(MODULES['planning.group_scope'],support_inputs=tuple(dict.fromkeys((*MODULES['planning.group_scope'].support_inputs,))))

MODULES['execution.commands.configuration'] = replace(MODULES['execution.commands.configuration'], support_inputs=(*MODULES['execution.commands.configuration'].support_inputs, 'crates/app/tests/device/associations.rs', ))

consume(('crates/execution-service/src/sources/software/stats.rs',), 'planning.software execution.software.offer execution.software.recovery execution.software.content planning.self_service')

# Entra's application owner and HTTP completion are shared with the native ingress.
consume(('crates/registration-service/src/windows_entra.rs',
         'crates/registration-service/schema/windows-entra-policy.sql'), 'windows.entra')
consume(('crates/management-http/src/body_policy.rs',
         'crates/management-http/src/boundary.rs',
         'crates/management-http/src/error.rs',
         'crates/management-http/src/error_projection.rs'), 'windows.entra')

MODULES['windows.entra'] = replace(MODULES['windows.entra'], policies=(*MODULES['windows.entra'].policies, CasePolicy('windows::t2::entra::management_policy_body_replay_and_audit_faults', 'fresh', 'objects')))

MODULES['agent.pki'] = replace(MODULES['agent.pki'], policies=(*MODULES['agent.pki'].policies, CasePolicy('agent_pki_tests::management_crl_publication_accepts_large_signed_material_and_rejects_overflow', 'reuse', 'tenant', ('identity','windows','agent_pki','task_signing'))))

# Git may select this unchanged receipt owner as a copy source; both endpoints need consumers.
consume(('crates/inventory-service/src/apple_collection*.rs',), 'apple.collection')

consume(('crates/management-http/src/software_publication/http.rs',),
        'publication.winget publication.brew publication.mapping publication.withdrawal publication.recovery')

consume(('crates/windows-mdm/src/native/collection.rs', 'crates/windows-mdm/schema/collection/*', 'crates/native-schema/src/windows/collection.rs'), 'windows.management')
consume(('crates/resource/src/blueprints/windows.rs',), 'planning.http windows.management')
consume(('crates/inventory/src/builtin/windows.rs',), 'windows.management inventory.runtime assets.http assets.queries')
T1_INPUTS += ('crates/execution-service/tests/native_collection_unit.rs', 'fixtures/windows-collection/*')
consume(('crates/native-schema/src/windows.rs', 'crates/native-schema/src/windows/generate.rs'), 'windows.management')

consume(('crates/apple-channel/src/collection_context.rs', 'crates/apple-channel/src/collection_values.rs', 'fixtures/apple-collection/*'), 'apple.collection')
consume(('crates/inventory/src/builtin/apple*.rs', 'crates/resource/src/blueprints/apple.rs', 'crates/inventory-service/src/collection/declarative.rs'), 'apple.collection apple.ddm planning.http')
consume(('crates/inventory-service/src/assets/model.rs',), 'assets.http assets.queries assets.sources assets.group_input planning.assets apple.collection')
consume(('crates/inventory-service/src/assets/runs.rs',), 'assets.http assets.sources apple.collection')

consume(("crates/execution-service/src/agent_collection_eligibility.rs", "crates/execution-service/src/actions/agent_collection.rs"), "planning.agent_policy execution.agent.delivery execution.agent.history execution.agent.recovery assets.sources assets.queries planning.group_scope compliance.evaluation")


consume(("crates/examples/examples/fixture_snapshot.rs",), "examples.cli")

MODULES['execution.agent.delivery'] = replace(MODULES['execution.agent.delivery'], support_inputs=(*MODULES['execution.agent.delivery'].support_inputs, 'crates/app/tests/execution/agent/windows_assets.rs'))

# Shared condition DTO and HTTP asset command dispatch are consumed by these seams.
consume(("crates/inventory-service/src/compliance/model.rs",), "compliance.http compliance.evaluation compliance.recovery compliance.group_input")
consume(("crates/management-http/src/assets/mod.rs",), "assets.http assets.queries assets.sources assets.group_input apple.collection")
consume(('crates/registration-service/src/admission.rs', 'crates/registration-service/schema/admission.sql', 'crates/management-http/src/enrollment/channels.rs', 'crates/app/src/registration_channels.rs'), 'enrollment.quotas installation.migration')

# Account requirements belong to the existing module description. Cases with no
# identity dependency resolve to no actors, even when overriding module fixtures.
_OTHER_ACTORS = frozenset('planning.custom_events settings.user_profiles settings.first_use execution.agent.task_trust authorization.programmatic recovery-credentials.http certificate-archive.http timeline.http identity.local authorization.rules authorization.membership authorization.capacity authorization.initialization authorization.admission enrollment.http enrollment.quotas enrollment.recovery device.binding device.revocation device.recovery agent.configurations agent.registration agent.reports api.identity_context diagnostics.http assets.http assets.queries planning.onboarding planning.group_scope planning.policy planning.http planning.agent_policy planning.frequency planning.software planning.self_service compliance.http execution.agent.delivery execution.agent.content execution.agent.history execution.agent.poll execution.agent.recovery execution.software.offer execution.software.content execution.software.recovery software.http execution.commands.admission execution.commands.windows'.split())
for name, module in tuple(MODULES.items()):
    if 'identity' not in module.fixtures:
        continue
    roles = ('admin', 'other') if name in _OTHER_ACTORS else ('admin',)
    actors = tuple(('tenant', role) for role in roles)
    if module.scope == 'pair':
        actors += (('peer', 'admin'),)
    policies = tuple(replace(policy, actors=tuple((side, role) for side, role in actors
        if side != 'peer' or policy.scope == 'pair') + ((('peer', 'admin'),)
        if policy.scope == 'pair' and module.scope != 'pair' else ())) for policy in module.policies)
    MODULES[name] = replace(module, actors=actors, policies=policies)

# Exceptional cryptographic material has an actual consuming case.
MODULES['windows.declared'] = replace(MODULES['windows.declared'], materials=('windows-renewal',))
_pki_materials = {
    'administrator_recovery_receipt_is_independent_of_issued_certificate': ('agent-large-csr',),
    'restored_ca_preserves_authorized_agent_issuance_and_activation': ('pki-recovery',),
    'explicit_development_limit_and_unknown_result_remain_auditable': ('agent-long-lived',),
    'provisioner_rejects_substituted_csr_and_consumed_token': ('other',),
}
module = MODULES['agent.pki']
policies = list(module.policies)
for suffix, materials in _pki_materials.items():
    selector = 'agent_pki_tests::' + suffix
    matching = next((i for i, p in enumerate(policies) if p.selector == selector), None)
    if matching is None:
        policies.append(CasePolicy(selector, module.db_mode, module.scope, actors=module.actors, materials=materials))
    else:
        policies[matching] = replace(policies[matching], materials=materials)
MODULES['agent.pki'] = replace(module, policies=tuple(policies))
module = MODULES['agent.configurations']
_counts = {
    'connection_publication_requires_deployment_and_preserves_operations': (1, ()),
    'fixed_packages_and_configurations_activate_beyond_self_quota': (4, ()),
    'finite_reservations_and_frozen_authority_survive_revoke': (6, ('other',)),
    'unknown_exchange_and_issuance_do_not_reset_quantity': (2, ()),
    'expired_reservation_cannot_be_consumed_after_configuration_lock_wait': (2, ()),
    'backend_settings_are_the_only_grant_lifetime_authority': (2, ('other',)),
    'configuration_scope_follows_current_candidate_admission': (2, ()),
}
MODULES[module.id] = replace(module, policies=tuple(
    CasePolicy('agent::t2::configurations::' + name, module.db_mode, module.scope,
               actors=module.actors, configuration_devices=count, materials=materials)
    for name, (count, materials) in _counts.items()))

# These native protocol and account-directory cases consume a second member actor.
for name, suffix in (
    ('apple.account_enrollment', 'apple::tests::account_enrollment::account_enrollment_and_reauthentication_keep_one_registration'),
    ('windows.enrollment', 'windows::t2::enrollment::self_enrollment_preserves_server_identity_and_terminal_protocol_id'),
    ('windows.entra', 'windows::t2::entra::management_policy_body_replay_and_audit_faults'),
    ('apple.scep', 'apple::tests::scep::self_enrollment_uses_current_user_and_one_macos_allocation'),
):
    module = MODULES[name]
    policies = list(module.policies)
    actors = (('tenant', 'admin'), ('tenant', 'other'))
    index = next((i for i, policy in enumerate(policies) if policy.selector == suffix), None)
    if index is None:
        policies.append(CasePolicy(suffix, module.db_mode, module.scope, actors=actors))
    else:
        policies[index] = replace(policies[index], actors=actors)
    MODULES[name] = replace(module, policies=tuple(policies))

# Current Windows credential seeds are prerequisites only for these downstream consumers.
for name in ("windows.management", "windows.retention", "windows.commands"):
    MODULES[name] = replace(MODULES[name], support_inputs=(*MODULES[name].support_inputs,
        "crates/windows-channel/src/issuance/fixture.rs"))

# Material and actor exceptions follow the actual case, not the whole namespace.
for module_id, selector, materials, actors in (
    ('windows.issuance', 'windows::t2::issuance::native_renewal_preserves_registration_and_activates_only_after_new_tls_proof', ('windows-renewal',), None),
    ('windows.enrollment', 'windows::t2::enrollment::discovery_wstep_replay_and_tls_identity', ('windows-rogue-client',), None),
    ('windows.entra', 'windows::t2::entra::consent_native_issuance_replay_scope_and_revocation', ('windows-weak-csr', 'windows-renewal'), None),
):
    module = MODULES[module_id]
    policies = list(module.policies)
    index = next((i for i, p in enumerate(policies) if p.selector == selector), None)
    policy = policies[index] if index is not None else CasePolicy(selector, module.db_mode, module.scope)
    policy = replace(policy, materials=materials, actors=actors if actors is not None else module.actors if policy.actors is None else policy.actors)
    if index is None:
        policies.append(policy)
    else:
        policies[index] = policy
    MODULES[module_id] = replace(module, policies=tuple(policies))

# Recovery is a distinct proof. Its policy and production seams come from the
# final PKI description; it does not duplicate the ordinary PKI test namespace.
module = MODULES['agent.pki']
recovery_selector = 'agent_pki_tests::restored_ca_preserves_authorized_agent_issuance_and_activation'
recovery_policy, = (p for p in module.policies if p.selector == recovery_selector)
MODULES['agent.pki-recovery'] = replace(module, id='agent.pki-recovery',
    selectors=('agent_pki_recovery_tests::',),
    test_inputs=('crates/app/tests/agent_pki/recovery.rs',),
    support_inputs=(*module.support_inputs, 'crates/app/tests/agent_pki/mod.rs', 'hack/pki_recovery.py'),
    scope=recovery_policy.scope, actors=recovery_policy.actors,
    materials=recovery_policy.materials, policies=())
MODULES['agent.pki'] = replace(module,
    policies=tuple(p for p in module.policies if p.selector != recovery_selector),
    support_inputs=(*module.support_inputs, 'crates/app/tests/support/agent_http.rs'))

# These consumers mutate their business actor (other), not their provisioning admin.
for name in ('execution.agent.delivery', 'execution.agent.poll', 'execution.agent.content',
             'execution.agent.history', 'execution.agent.recovery', 'execution.software.offer',
             'execution.software.content', 'execution.software.recovery', 'planning.agent_policy',
             'planning.frequency', 'planning.software'):
    module = MODULES[name]
    MODULES[name] = replace(module, fixtures=(*module.fixtures, 'stable_admin'),
        policies=tuple(replace(p, fixtures=(*p.fixtures, 'stable_admin')) if p.fixtures is not None else p for p in module.policies))

# Only issuance/lifecycle consumers require a live signing authority.
for name, additions in {
    'agent.pki': ('ca_agent',), 'agent.pki-recovery': ('ca_agent',),
    'agent.registration': ('ca_agent',), 'agent.configurations': ('ca_agent',),
    'windows.issuance': ('ca_windows',), 'windows.enrollment': ('ca_windows',),
    'windows.entra': ('ca_windows',), 'windows.declared': ('ca_windows',),
}.items():
    module = MODULES[name]
    MODULES[name] = replace(module, fixtures=(*module.fixtures, *additions),
        policies=tuple(replace(p, fixtures=(*p.fixtures, *additions)) if p.fixtures is not None else p for p in module.policies))
# These hosts own tenant-wide trust/origins or mutate issuer lifecycle state.
# Scope follows that state, not the presence of Windows/Apple fixture material.
for name in ('agent.registration', 'windows.declared', 'windows.issuance', 'windows.enrollment',
             'windows.entra', 'windows.commands', 'windows.retention', 'execution.commands.recovery',
             'apple.host', 'apple.account_enrollment'):
    module = MODULES[name]
    MODULES[name] = replace(module, scope='tenant',
        policies=tuple(replace(p, scope='tenant') if p.scope == 'objects' else p for p in module.policies))

# Actual credential lifecycle actions, not their downstream prerequisite peers.
for module_id, selector, fixture in (
    ('apple.onboarding', 'apple::tests::onboarding::absent_agent_group_installs_fixed_package_and_registers_independently', 'ca_agent'),
    ('execution.commands.onboarding', 'execution::t2::commands::onboarding::windows_policy_install_register_and_replay_use_independent_identity', 'ca_agent'),
    ('execution.commands.onboarding', 'execution::t2::commands::onboarding::historical_bootstrap_cleanup_survives_current_identity_completion', 'ca_agent'),
    ('execution.commands.onboarding', 'execution::t2::commands::onboarding::windows_policy_install_register_and_replay_use_independent_identity', 'ca_windows'),
    ('execution.commands.onboarding', 'execution::t2::commands::onboarding::replacement_rejects_old_installation_and_requires_current_epoch_absence', 'ca_windows'),
    ('execution.commands.configuration', 'execution::t2::commands::configuration::native_object_sets_share_a_device_and_withdraw_only_their_own_objects', 'ca_windows'),
    ('execution.software.recovery', 'execution::t2::software::recovery::unknown_effect_survives_credential_recovery', 'ca_agent'),
    ('windows.management', 'windows::t2::management::session_replay_nonce_collection_and_revoke', 'ca_windows'),
):
    module = MODULES[module_id]
    previous = next((p for p in module.policies if p.selector == selector),
                    CasePolicy(selector, module.db_mode, module.scope))
    fixtures = previous.fixtures if previous.fixtures is not None else module.fixtures
    policy = replace(previous, fixtures=(*fixtures, fixture))
    if module_id == 'execution.software.recovery':
        policy = replace(policy, scope='tenant')
    MODULES[module_id] = replace(module, policies=(*[p for p in module.policies if p.selector != selector], policy))
module = MODULES['apple.identity']
MODULES[module.id] = replace(module, policies=tuple(replace(p, fixtures=tuple(f for f in module.fixtures if f != 'scep'))
    if p.selector.endswith('token_is_required_before_management') else p for p in module.policies))


# Installation/catalog prove the shared setup once. Runtime consumers come from
# the owning capability, never from sharing a PostgreSQL fixture.
consume(('crates/app/src/migration/units.rs',),
        'installation.migration installation.tenants deployment.management-tenant')
consume(('crates/app/schema/*.sql', 'crates/*-service/schema/*.sql',
         'crates/*-channel/schema/*.sql', 'crates/*-postgres/migrations/*.sql'),
        'installation.migration')

# install/relations contain the owner's complete storage contract. Reuse the
# existing production consumption declarations rather than a second owner list.

consume(('crates/inventory-service/schema/source-facts.sql',), 'device.associations')


consume(('crates/app/src/migration.rs',),
        'installation.migration installation.tenants deployment.management-tenant api.identity_context')


# Context preparation is consumed directly by these six protocol modules.
consume(('crates/apple-channel/src/native.rs',),
        'apple.commands apple.users apple.policy apple.identity apple.push apple.host')
for name in ('apple.commands', 'apple.users', 'apple.identity', 'apple.push', 'apple.host'):
    MODULES[name] = replace(MODULES[name], support_inputs=(*MODULES[name].support_inputs,
        'crates/app/tests/apple/policy.rs'))

# ExecutionSource candidate pagination moved from the protocol host to its PG consumer.
MODULES['planning.policy'] = replace(MODULES['planning.policy'], selectors=(*MODULES['planning.policy'].selectors, 'planning::t2::execution_source::'), test_inputs=(*MODULES['planning.policy'].test_inputs, 'crates/app/tests/planning/execution_source.rs'), support_inputs=(*MODULES['planning.policy'].support_inputs,'crates/app/tests/planning/support.rs',), production_inputs=(*MODULES['planning.policy'].production_inputs, 'crates/flow-service/src/planning/execution_source.rs'))

# Role membership faults require a disposable PG instance, not only a fresh database.
MODULES['installation.migration'] = replace(MODULES['installation.migration'], policies=(*MODULES['installation.migration'].policies,
    CasePolicy('migration::tests::fresh_installation_replay_and_mismatch_rejection', 'instance', 'objects'),
    CasePolicy('migration::tests::ledger_installation_grants_actual_business_writers', 'instance', 'objects'),
))

# Management query seams: reuse the owning behavioral carriers.
consume(('crates/content-service/src/service/script.rs',), 'planning.agent_policy content.http')
consume(('crates/group-postgres/src/memberships.rs','crates/inventory-service/src/groups/memberships.rs'), 'planning.policy planning.http group.generations')
consume(('crates/execution-service/src/queries/ddm.rs',), 'apple.ddm')

T1_INPUTS += ('crates/timeline-service/tests/model.rs',)
consume(('crates/device-trust/src/windows/*', 'crates/device-trust/fixtures/*'), 'windows.issuance windows.management')

consume(('crates/recovery-credentials/src/*','crates/recovery-credentials/schema/*','crates/execution-service/src/recovery_credentials.rs','crates/execution-service/src/credential_tasks.rs','crates/execution-service/src/credential_maintenance.rs'), 'recovery-credentials.http apple.commands execution.agent.delivery')

consume(('crates/recovery-credentials/schema/*.sql',), 'installation.migration')

# Dedicated bootstrap protocol scenarios consume real CA material and isolated lifecycle state.
for name in ('execution.commands.onboarding', 'apple.onboarding', 'planning.onboarding'):
    module = MODULES[name]
    MODULES[name] = replace(module, materials=(*module.materials, 'agent-bootstrap'),
        production_inputs=(*module.production_inputs, 'crates/registration-service/src/agent/bootstrap.rs',
            'crates/registration-service/src/enrollment/agent_policy.rs', 'crates/execution-service/src/bootstrap_delivery.rs',
            'crates/execution-service/src/actions/native_enrollment.rs', 'crates/windows-channel/src/agent_enrollment.rs',
            'crates/windows-mdm/src/software/*', 'crates/certificate/src/bootstrap.rs'),
        support_inputs=(*module.support_inputs, 'hack/bootstrap_fixtures.py', 'crates/app/tests/support/bootstrap.rs', 'crates/app/tests/support/native_handoff.rs'))

module = MODULES['apple.onboarding']
MODULES['apple.onboarding'] = replace(module, policies=(*module.policies, CasePolicy(
    'apple::tests::onboarding::agent_handoff_completes_native_registration_and_token_update',
    db_mode='reuse', scope='tenant', fixtures=tuple(dict.fromkeys((*module.fixtures, 'scep'))))))

# The webhook unit carrier moved from the Apple channel to its shared PKI owner.
T1_INPUTS += ('crates/apple-channel/tests/webhook.rs', 'crates/pki-service/tests/scep.rs')
consume(('crates/agent-wire/schema/enroll/native-enrollment-request-v1.schema.json',
         'crates/agent-wire/schema/enroll/native-enrollment-receipt-v1.schema.json'),
        'execution.commands.onboarding apple.onboarding planning.onboarding')

for name, selector in (
    ('execution.commands.onboarding', 'execution::t2::commands::onboarding::agent_handoff_completes_windows_issuance_and_authenticated_signin'),
    ('apple.onboarding', 'apple::tests::onboarding::agent_handoff_completes_native_registration_and_token_update')):
    module = MODULES[name]
    policies = tuple(p for p in module.policies if p.selector != selector)
    MODULES[name] = replace(module, policies=(*policies, CasePolicy(selector,
        db_mode='reuse', scope='tenant',
        actors=tuple(dict.fromkeys((*module.actors, ('tenant', 'other')))),
        fixtures=tuple(dict.fromkeys((*module.fixtures, 'scep' if name == 'apple.onboarding' else 'ca_windows'))))))

consume(('crates/apple-channel/src/recovery_credentials.rs',), 'apple.commands')

# Explicit software channel uses the existing Policy, shared Run and protocol owners.
consume(('crates/execution-service/src/native_software.rs',
         'crates/execution-service/src/actions/native_software.rs',
         'crates/management-http/src/software_content.rs'),
        'execution.software.offer execution.software.recovery execution.commands.onboarding apple.onboarding planning.software')
T1_INPUTS += ('crates/execution-service/tests/native_software_unit.rs',)
consume(('crates/app/tests/execution/commands/onboarding/native_software.rs',), 'execution.commands.onboarding')

consume(('crates/app/tests/apple/onboarding/native_software.rs',), 'apple.onboarding')
consume(('crates/execution-service/src/unmanage.rs', 'crates/execution-service/src/queries/lifecycle.rs', 'crates/device-service/src/lifecycle*',
         'crates/flow-service/src/planning/policies/lifecycle.rs', 'crates/agent-wire/src/unmanage.rs'),
        'planning.onboarding device.associations device.views execution.agent.delivery windows.management apple.identity')

consume(('crates/registration-service/src/lifecycle.rs',),
        'planning.onboarding device.associations device.binding device.revocation agent.registration windows.management apple.identity')

consume(('crates/app/schema/webhook-roles.sql',), 'webhooks.product installation.migration')
consume(('crates/registration-service/src/agent/activation.rs','crates/registration-service/src/device/store.rs','crates/registration-service/src/device/linked.rs','crates/execution-service/src/actions/storage.rs','crates/inventory-service/src/compliance/evaluation.rs','crates/authorization-service/src/model.rs'), 'webhooks.product')


consume(('crates/apple-channel/src/runtime_materials/*','crates/apple-channel/schema/runtime-materials.sql'), 'apple.host')
consume(('crates/app/src/setup/host.rs',), 'api.diagnostics apple.host')
consume(('crates/app/src/tenant_provisioning.rs','crates/app/schema/provisioning.sql'), 'deployment.management-tenant')
consume(('crates/app/src/webhooks/mod.rs',), 'deployment.management-tenant')

consume(('crates/app/tests/support/task_signing.rs',), 'execution.agent.task_trust execution.agent.delivery')

add('installation.providers', selectors=('setup::providers::storage::tests::real_storage_creation_replay_and_broad_import_rejection',), profile='none', fixtures=('s3',),
    sources=('crates/app/src/setup/providers/*',), tests=('crates/app/tests/setup/providers.rs',), support=('hack/s3_fixtures.py','fixtures/s3-provider.lock.json'))
consume(('crates/content-service/src/connections*','crates/content-service/schema/connections.sql','crates/management-http/src/content/connections.rs','crates/app/tests/support/storage.rs'), 'content.storage')
consume(('crates/app/src/setup/application.rs',), 'deployment.management-tenant content.storage execution.agent.task_trust apple.host')

consume(('crates/app/src/setup/protection.rs',), 'content.storage execution.agent.task_trust apple.host')

consume(('crates/content-service/src/backup.rs','crates/app/src/setup/backup/storage.rs'), 'content.storage installation.migration audit.integrity apple.host')

consume(('crates/app/src/settings.rs','crates/management-http/src/settings.rs','crates/management-http/schema/SettingsCatalog.json'), 'execution.agent.task_trust')
consume(('crates/windows-channel/src/wns_materials.rs','crates/windows-channel/schema/wns-materials.sql'), 'windows.management')
add('installation.smtp_transport', selectors=('setup::providers::mail::tests::real_tls_authentication_and_unknown_submission_are_distinct',), profile='none', fixtures=('windows',), sources=('crates/mail-service/src/transport.rs',), tests=('crates/app/tests/setup/mail.rs',))
add('installation.smtp', selectors=('setup::providers::mail::tests::unknown_submission_is_not_requeued_and_materials_rewrap','setup::providers::mail::tests::runtime_role_cannot_insert_provider_success'), fixtures=('windows','runtime_config'), sources=('crates/mail-service/src/*','crates/mail-service/schema/*','crates/app/src/setup/providers/mail.rs','crates/management-http/src/mail.rs'), tests=('crates/app/tests/setup/mail.rs',))
add('installation.ca_admin', selectors=('setup::providers::step_ca::tests::authenticated_readback_recovers_original_provider',), profile='none', fixtures=('windows',), sources=('crates/app/src/setup/providers/step_ca/*',), tests=('crates/app/tests/setup/ca_admin.rs',))
MODULES['agent.pki'] = replace(MODULES['agent.pki'], policies=(*MODULES['agent.pki'].policies, CasePolicy('agent_pki_tests::bootstrap_sources_select_current_issuer_and_reject_missing_application', 'reuse', 'tenant', ('identity','agent_pki','task_signing','pki_rotation'))))
add('installation.backup', selectors=('setup::backup::tests::database_connection_fence_replays_and_restores_original_grants','setup::backup::tests::plain_backup_verification_has_no_ledger_dependency'), profile='empty', sources=('crates/app/src/setup/backup.rs','crates/app/src/setup/snapshot_tree.rs','crates/app/src/setup/backup/archive.rs','crates/app/src/setup/backup/ledger.rs','crates/app/src/setup/backup/accounts.rs'), tests=('crates/app/tests/setup/backup.rs',))
MODULES['installation.backup'] = replace(MODULES['installation.backup'], db_mode='instance', scope='objects')
add('installation.ca', selectors=('setup::providers::step_ca::tests::actual_ca_creates_and_imports_exact_purpose_resources','setup::providers::step_ca::tests::unified_ca_initialization_replays_and_isolates_tenants'), profile='product', fixtures=('agent_pki','ca_agent'), sources=('crates/app/src/setup/providers/step_ca/*',), tests=('crates/app/tests/setup/ca_admin.rs',))
MODULES['installation.ca'] = replace(MODULES['installation.ca'], policies=(CasePolicy('setup::providers::step_ca::tests::unified_ca_initialization_replays_and_isolates_tenants','reuse','tenant',('windows','ca_windows')),))
add('installation.webhook', selectors=('setup::providers::webhook::tests::receiver_possession_gates_activation_and_old_ciphertexts_remain_readable',), fixtures=('windows','runtime_config'), sources=('crates/app/src/setup/providers/webhook.rs','crates/app/src/webhooks/*','crates/webhook-service/src/materials.rs','crates/webhook-service/schema/materials.sql'), tests=('crates/app/tests/setup/webhook.rs',))
add('installation.native_rewrap', selectors=('setup::protection::tests::ade_original_material_survives_rotation_and_corrupt_rows_roll_back',), sources=('crates/apple-channel/src/rewrap.rs','crates/app/src/setup/protection.rs'), tests=('crates/app/tests/setup/native_rewrap.rs',))

# These cases mutate singleton material heads or observe all records in a tenant.
for name in ('execution.agent.task_trust', 'installation.smtp', 'installation.webhook', 'installation.native_rewrap'):
    MODULES[name] = replace(MODULES[name], scope='tenant')
module = MODULES['content.storage']
MODULES['content.storage'] = replace(module, policies=(*module.policies, CasePolicy(
    'content::t2::storage::restored_provider_version_rebinds_atomically_without_reissuing_content',
    'reuse', 'tenant', actors=module.actors)))

consume(('crates/agent-wire/schema/task_trust/*',), 'execution.agent.task_trust')

# Installation orchestration is additionally qualified against fixed Compose candidates.
# Its shared SQL/authentication and restore seams retain their existing T2 owners.
consume(('crates/app/src/setup/configure.rs','crates/app/src/setup/runtime_files.rs','crates/app/src/setup/installation.rs',
         'crates/app/src/setup/postgres.rs','crates/app/src/setup/tenant_hosts.rs'),
        'deployment.management-tenant installation.backup')
consume(('crates/app/src/setup/public_configuration.rs',), 'deployment.management-tenant')
consume(('crates/app/src/ca_webhooks.rs',), 'apple.scep agent.pki')
consume(('crates/app/src/task_signing.rs',), 'execution.agent.task_trust')
consume(('crates/apple-channel/src/database.rs',), 'apple.host')
consume(('crates/management-http/src/content/mod.rs',), 'content.storage')
consume(('crates/windows-channel/schema/Wns.json',), 'windows.management')
T1_INPUTS += ('crates/app/src/setup/local.rs','crates/app/src/setup/mod.rs','crates/app/src/setup/model.rs',
              'crates/app/tests/setup/runtime_files.rs','crates/app/tests/setup/installation.rs',
              'crates/app/tests/setup/postgres.rs','crates/app/tests/setup/public_configuration.rs',
              'crates/mail-service/examples/mail_schema.rs','crates/webhook-service/examples/materials_schema.rs','crates/windows-channel/examples/wns_schema.rs')
TOOL_INPUTS['deployment/Dockerfile'] = ('test_release',)


# This no-write assertion observes all tenant facts, not just one operation.
module = MODULES['planning.agent_policy']
MODULES['planning.agent_policy'] = replace(module, policies=(*module.policies, CasePolicy(
    'planning::t2::agent_policy::registered_script_eligibility_gates_preview_and_automatic',
    'reuse', 'tenant', actors=module.actors)))


add('installation.storage_reconcile', selectors=('setup::providers::reconcile::tests::failed_candidates_and_expired_evidence_do_not_block_later_work',), fixtures=('runtime_config','s3'), sources=('crates/app/src/setup/providers/reconcile.rs','crates/content-service/src/connections.rs','crates/content-service/schema/connections.sql'), tests=('crates/app/tests/setup/reconcile.rs',))
MODULES['installation.storage_reconcile'] = replace(MODULES['installation.storage_reconcile'], db_mode='fresh', scope='pair')

consume(('crates/execution-service/src/task_signing/observations.sql',), 'execution.agent.task_trust installation.migration')
consume(('crates/pki-service/src/observations.rs','crates/pki-service/schema/observations.sql'), 'agent.pki installation.migration')

module = MODULES['agent.pki']
MODULES['agent.pki'] = replace(module, policies=tuple(
    replace(policy, actors=(*module.actors, ('tenant', 'other')))
    if policy.selector in ('agent_pki_tests::production_agent_listener_bootstraps_activates_and_rechecks_revocation',
                           'agent_pki_tests::management_rotation_accepts_direct_activation_and_rejects_retired_action')
    else policy for policy in module.policies))

TOOL_INPUTS['deployment/production.compose.yaml'] = ('test_release',)
TOOL_INPUTS['deployment/sit.compose.yaml'] = ('test_release',)
TOOL_INPUTS['deployment/initialize.py'] = ('test_release',)
TOOL_INPUTS['deployment/tenant.compose.yaml'] = ('test_release',)

consume(('crates/app/schema/first-use.sql',), 'settings.first_use installation.migration')
consume(('crates/management-http/schema/FirstUse.json','crates/management-http/examples/first_use_schema.rs'), 'settings.first_use')

add('telemetry.storage', selectors=('telemetry::tests::explicit_installations_replay_and_reopen_without_runtime_ddl',), profile='none', fixtures=('telemetry',),
    sources=('crates/app/src/telemetry.rs','crates/app/src/setup/providers/telemetry.rs','crates/app/src/setup/providers/telemetry/*'),
    tests=('crates/app/tests/telemetry/storage.rs',), support=('hack/telemetry_fixtures.py','deployment/providers.lock.json'))


for backend in ('postgres','timescale_shared','timescale_dedicated','click_house'):
    name='telemetry.ingress.'+backend
    base=MODULES['planning.agent_policy']
    add(name,selectors=(('telemetry::ingress::postgres','telemetry::ingress::postgres_current','telemetry::ingress::postgres_history','telemetry::ingress::postgres_baseline_recovers_original_receipts_without_overwriting_edits') if backend=='postgres' else ('telemetry::ingress::'+backend,)),fixtures=tuple(dict.fromkeys((*(f for f in base.fixtures if f!='local_worker'),'telemetry'))),actors=base.actors,
        sources=('crates/app/src/telemetry.rs','crates/app/src/setup/providers/telemetry.rs','crates/app/src/setup/providers/telemetry/*','crates/app/src/setup/backup.rs','crates/app/src/setup/backup/archive.rs','crates/app/src/setup/backup/telemetry.rs','crates/telemetry-service/src/*','crates/agent-channel/src/telemetry.rs','crates/management-http/src/telemetry.rs','crates/flow-service/src/planning/policies/telemetry.rs','crates/flow-service/src/resource_catalog/telemetry.rs'),
        tests=('crates/app/tests/telemetry/ingress.rs','crates/app/tests/telemetry/counter.rs','crates/app/tests/telemetry/recovery.rs',*(('crates/app/tests/telemetry/gaps.rs','crates/app/tests/telemetry/performance.rs') if backend=='postgres' else ())),support=('hack/telemetry_fixtures.py','hack/postgres_archive.py','hack/postgres_archive_client.py','crates/app/tests/setup/telemetry_backup.rs',))
    MODULES[name]=replace(MODULES[name],scope='pair' if backend=='postgres' else 'tenant',db_mode='fresh',materials=base.materials,actors=tuple(dict.fromkeys((*base.actors,*( (('peer','admin'),) if backend=='postgres' else () )))))

consume(('crates/agent-wire/src/telemetry.rs','crates/agent-wire/src/telemetry_gap.rs','crates/agent-wire/schema/runtime/telemetry-*.schema.json','crates/agent-wire/schema/runtime/signed-telemetry-configuration-v1.schema.json'),
        'telemetry.ingress.postgres telemetry.ingress.timescale_shared telemetry.ingress.timescale_dedicated telemetry.ingress.click_house')

# The shared entry point contains declarations only; Rust checks its composition.
TOOL_INPUTS['crates/app/tests/support/mod.rs'] = ('test_t2_modules',)
TOOL_INPUTS['crates/app/tests/support/preparation.rs'] = ('test_t2_fixtures',)
TOOL_INPUTS['crates/app/tests/support/pki.rs'] = ('test_t2_modules',)

consume(('crates/telemetry-service/src/schema.sql',), 'installation.migration')
consume(('crates/telemetry-service/src/admission.sql',), 'telemetry.ingress.postgres')

# Nested group inputs and dependency reads reuse the existing product owners.

case_fixtures('planning.group_scope', 'planning::t2::group_scope::definition_validation_resumes_without_partial_publication', None)
case_fixtures('planning.group_scope', 'planning::t2::group_scope::nested_large_source_evidence_retries_with_smaller_pages', None)
case_fixtures('planning.scope', 'planning::t2::scope::pending_group_source_keeps_scope_identity_and_recovers_after_restart', None)

# Installer preparation consumes the same content journal and catalog transaction.
consume(('crates/software-service/src/management/installers.rs', 'crates/software-service/src/catalog/installers.rs',
         'crates/content-service/src/installer.rs','crates/content-service/src/installer/cfb_budget.rs', 'crates/content-service/src/native.rs'), 'agent.configurations')
for name in ('agent.configurations', 'execution.commands.onboarding', 'apple.onboarding'):
    module = MODULES[name]
    MODULES[name] = replace(module, support_inputs=tuple(dict.fromkeys((*module.support_inputs,
        'crates/content-service/tests/fixtures/installers.rs'))))

consume(('crates/software-service/src/imports.rs',), 'software.catalog software.http')
T1_INPUTS += ('crates/software-service/tests/export.rs',)

# Install the shared preparation proof owners after module registration.
for relative, consumers in APP_HELPER_CONSUMERS.items():
    path = 'crates/app/tests/' + relative
    for name, module in list(MODULES.items()):
        inputs = tuple(value for value in module.support_inputs if value != path)
        if name in consumers:
            inputs += (path,)
        MODULES[name] = replace(module, support_inputs=inputs)

# Enterprise current-user binding has its own HTTP/Identity/PG seam; OS collection is unrelated.
add('agent.current_user', selectors=('agent::t2::current_user::',), fixtures=('identity','agent_pki'),
    sources=('crates/registration-service/src/agent/current_user.rs','crates/registration-service/src/device/registration_user.rs','crates/agent-channel/src/tasks.rs','crates/agent-wire/src/current_user.rs','crates/agent-wire/schema/runtime/current-user-v1.schema.json','crates/agent-wire/schema/runtime/current-user-change-v1.schema.json','crates/registration-service/schema/install.sql','crates/device-service/src/presentation.rs','crates/device-service/src/views.rs','crates/management-http/src/device_views.rs','crates/registration-service/src/device/directory.rs','crates/authorization-service/src/session.rs','crates/registration-service/src/device/management.rs','crates/registration-service/src/device/store.rs'),
    tests=('crates/app/tests/agent/current_user.rs',),
    support=('crates/app/tests/agent/mod.rs',), actors=(('tenant','admin'),('tenant','other')))
MODULES['agent.current_user'] = replace(MODULES['agent.current_user'], scope='tenant')
consume(('crates/registration-service/src/device/registration_user.rs','crates/management-http/src/enrollment/registration_user.rs'), 'enrollment.quotas device.views')
consume(('crates/registration-service/src/agent/current_user.rs',), 'device.views')

consume(('crates/agent-channel/src/boundary.rs',), 'agent.pki agent.current_user')

# Tenant defaults remain App orchestration over the existing owners.
consume(('crates/app/src/baseline/*.rs','crates/app/schema/baseline.sql','crates/authorization-service/src/baseline.rs'), 'telemetry.ingress.postgres authorization.initialization')
consume(('crates/app/src/setup/default_telemetry.rs',), 'telemetry.storage deployment.management-tenant')

MODULES['planning.group_scope']=replace(MODULES['planning.group_scope'],policies=(*MODULES['planning.group_scope'].policies,CasePolicy('planning::t2::group_scope::system_lifecycle_snapshot_pages_before_collection_and_preserves_old_authority','fresh','tenant')))

consume(('crates/app/schema/user-profiles.sql',), 'settings.user_profiles installation.migration')

# Personnel is consumed only by the authorized device directory/detail and its session seam.
consume(('crates/device-service/src/personnel.rs',), 'device.views agent.current_user')

MODULES['device.views'] = replace(MODULES['device.views'], test_inputs=(*MODULES['device.views'].test_inputs, 'crates/app/tests/device/personnel.rs'))

consume(('crates/device-service/src/personnel.rs',), 'identity.sso')

# Final-history assertions drive the same installed projector as the product worker.

consume(('crates/apple-channel/src/operations.rs',), 'apple.scep apple.identity apple.collection apple.renewal apple.ade apple.account_enrollment apple.host')

consume(('crates/flow-service/src/automation/inventory_tasks.rs', 'crates/flow-service/src/automation/model.rs'), 'planning.assets planning.onboarding assets.queries')
consume(('crates/flow-service/src/planning/receipts.rs',), 'planning.http planning.scope planning.policy planning.software planning.recovery')
consume(('crates/flow-service/src/resource_catalog/receipts.rs',), 'planning.http planning.resource_archive')
consume(('crates/inventory-service/src/assets/receipts.rs', 'crates/inventory-service/src/transaction.rs'), 'assets.http assets.queries planning.assets')
consume(('crates/inventory-service/src/operations.rs',), 'agent.reports windows.management apple.collection inventory.runtime')
consume(('crates/windows-channel/src/diagnostic.rs',), 'api.diagnostics windows.management')


consume(('crates/app/src/native/gateway.rs',), 'gateway.admission apple.host')
consume(('crates/app/src/channel_status.rs',), 'diagnostics.http apple.host')

# Transport and complete-host dispatch fixtures are consumed by these test/helper owners.

MODULES['agent.pki'] = replace(MODULES['agent.pki'], policies=(*MODULES['agent.pki'].policies,
    CasePolicy('agent_pki_tests::corrupt_persisted_root_crl_is_fatal_to_admission', 'fresh', 'tenant')))

MODULES['execution.agent.task_trust'] = replace(MODULES['execution.agent.task_trust'], policies=(*MODULES['execution.agent.task_trust'].policies,
    CasePolicy('execution::t2::agent::task_trust::selected_material_corruption_is_fatal_even_with_a_matching_active_key', 'fresh', 'tenant')))

consume(('hack/ingress_network.py',), 'gateway.network')
# Device Access owns the joint human/device ceremony and exact application receipts.
add('device-access.http',selectors=('agent::t2::device_access::',),fixtures=('identity','agent_pki','task_signing','local_worker'),
    sources=('crates/agent-wire/schema/runtime/access-*.schema.json','crates/registration-service/src/device_access.rs','crates/registration-service/src/device_access/*','crates/registration-service/schema/device-access.sql','crates/execution-service/src/device_access.rs','crates/execution-service/src/device_access/*','crates/agent-wire/src/device_access.rs','crates/management-http/src/device_access.rs','crates/agent-channel/src/tasks.rs','crates/agent-channel/src/filevault.rs','crates/app/src/registration_lifecycle.rs'),
    tests=('crates/app/tests/agent/device_access.rs','crates/app/tests/agent/device_access/*.rs'),support=(),actors=(('tenant','admin'),('tenant','other')))
MODULES['device-access.http']=replace(MODULES['device-access.http'],scope='tenant')
for selector in (
    'agent::t2::device_access::first_binding_requires_current_device_and_human_then_stays_admin_only',
    'agent::t2::device_access::step_up_is_atomic_with_receipts_and_concurrent_duplicates',
    'agent::t2::device_access::binding_commit_serializes_session_revocation',
    'agent::t2::device_access::binding_rollback_releases_session_guard',
    'agent::t2::device_access::queries::native_discovery_uses_signed_window_continuation',
):
    case_fixtures('device-access.http', selector, None)
module=MODULES['device-access.http']
MODULES['device-access.http']=replace(module, policies=(*module.policies,CasePolicy('agent::t2::device_access::enterprise::two_rps_exchange_cancel_and_revoke','reuse','tenant',fixtures=(*module.fixtures,'idp'))),support_inputs=(*module.support_inputs,'hack/enterprise_idp.py'))
consume(('crates/registration-service/src/enterprise.rs','crates/registration-service/src/enterprise/*','crates/registration-service/schema/enterprise.sql','crates/management-http/src/enterprise_broker.rs','crates/app/src/identity/enterprise.rs','crates/agent-wire/src/enterprise.rs','crates/agent-wire/schema/enterprise/*'),'device-access.http')
consume(('crates/registration-service/schema/enterprise.sql',),'installation.migration')
consume(('crates/registration-service/schema/device-access.sql',),'installation.migration device.admission')
consume(('crates/agent-wire/src/device_access.rs','crates/execution-service/src/device_access.rs','crates/execution-service/src/device_access/*','crates/registration-service/src/device_access*','crates/registration-service/src/device_access/*'),'recovery-credentials.http execution.agent.delivery')
T1_INPUTS += ('crates/agent-wire/tests/device_access.rs',)

consume(('crates/execution-service/src/actions/agent.rs','crates/execution-service/src/actions/storage.rs','crates/execution-service/src/input_preparation.rs','crates/execution-service/src/input_preparation/*'), 'device-access.http')


consume(('crates/agent-channel/schema/install.sql',), 'device-access.http')

consume(('crates/registration-service/src/lifecycle.rs',), 'device-access.http')
MODULES['device-access.http']=replace(MODULES['device-access.http'],support_inputs=tuple(dict.fromkeys((*MODULES['device-access.http'].support_inputs,'crates/app/tests/support/task_signature.rs'))))

consume(('crates/execution-service/src/actions/production.rs','crates/execution-service/src/actions/dispatch-v1.json'), 'planning.onboarding execution.agent.delivery device-access.http')

# Full Scope/sequence is shared by enterprise collection and periodic telemetry intake.
consume(('crates/inventory-service/src/collection/telemetry.rs',), 'telemetry.ingress.postgres')

consume(('crates/registration-service/src/agent/connections.rs','crates/agent-wire/src/connections.rs','crates/agent-wire/schema/connections/*'), 'agent.configurations agent.pki')


T1_INPUTS += ('crates/certificate/tests/peer.rs', 'crates/agent-wire/tests/fixtures/pki-v1-vectors.json')
consume(('crates/content-service/src/installer/xar_metadata.rs',), 'agent.configurations')

consume(('crates/inventory-service/src/database.rs',), 'inventory.runtime')

consume(('crates/recovery-credentials/src/storage.rs',), 'device-access.http')

consume(('crates/flow-service/src/planning/group_references.sql',), 'planning.http planning.group_scope')
consume(('crates/inventory-service/src/assets/summaries.rs',), 'device.views assets.http assets.sources apple.collection')
consume(('crates/inventory-service/schema/directory.sql','crates/registration-service/schema/directory.sql','crates/device-service/schema/directory.sql'), 'device.views agent.current_user')
consume(('crates/inventory-service/schema/collection-metadata.sql',), 'assets.queries assets.sources inventory.runtime')

# Read-only qualifications share their owners with locked authentication consumers.
consume(('crates/apple-channel/schema/platform-qualifications.sql','crates/apple-channel/schema/profile-qualifications.sql','crates/apple-channel/src/profiles.rs','crates/apple-channel/src/rewrap.rs'), 'apple.platform_sso apple.profile')
consume(('crates/authorization-service/schema/authority.sql','crates/device-service/schema/object-qualification.sql','crates/flow-service/schema/qualification.sql','crates/execution-service/schema/device-access-qualification.sql'), 'apple.platform_sso device.views planning.group_scope planning.policy device-access.http authorization.programmatic')


# Generated SQL needs an existing real PostgreSQL query proof; pure parsing stays in T1.
consume(('crates/query-postgres/src/lib.rs',), 'planning.http')

# Resource query execution and common ingress composition have distinct proof owners.
consume(('crates/resource/src/directory.rs',), 'planning.http software.http')
consume(('crates/flow-service/src/action_admission.rs',), 'planning.http planning.policy')
T1_INPUTS += ('crates/query/tests/*', 'crates/query-postgres/tests/*', 'crates/http-contract/tests/*',
              'crates/resource/tests/directory.rs', 'crates/management-http/examples/resource_query.rs', 'crates/management-http/examples/management_capabilities.rs')
consume(('crates/management-http/src/execution/actions/http.rs',), 'execution.agent.history')


consume(('crates/registration-service/src/agent/configurations/*.rs',), 'agent.configurations')
consume(('crates/inventory-service/src/assets/saved_directory.rs',), 'assets.queries')
consume(('crates/inventory-service/src/compliance/directory.rs',), 'compliance.http')
consume(('crates/software-service/src/management/directory.rs', 'crates/software-service/src/management/publication/directory.rs'), 'software.http')
consume(('crates/software-service/src/agent_packages/*.rs',), 'agent.configurations')

# These cases upload artifacts or assemble publication; declare their real storage dependency.
for name, selector in (
    ('authorization.programmatic', 'authorization::t2::programmatic::streamed_content_rejects_rotated_key_before_binding'),
    ('authorization.rules', 'authorization::t2::rules::route_permissions::each_route_requires_its_exact_capability'),
    ('execution.commands.configuration', 'execution::t2::commands::configuration::associated_agent_health_executes_only_original_mdm_and_missing_channel_has_no_effects'),
    ('execution.commands.configuration', 'execution::t2::commands::configuration::native_object_sets_share_a_device_and_withdraw_only_their_own_objects'),
    ('windows.declared', 'windows::t2::declared::declared_policy_delete_claims_recover_from_unknown_commit'),
    ('windows.declared', 'windows::t2::declared::signed_parent_enrollment_independent_tls_and_retirement'),
    ('apple.collection', 'apple::tests::collection::disabled_template_policy_rejects_first_report'),
    ('apple.collection', 'apple::tests::collection::published_native_template_uses_policy_and_direct_collection_progress'),
    ('apple.collection', 'apple::tests::collection::builtin_applications_preserve_optional_identifiers_and_last_trusted_snapshot'),
    ('apple.collection', 'apple::tests::collection::template_access_rights_change_rejects_first_report'),
    ('apple.collection', 'apple::tests::collection::template_revocation_rejects_first_report'),
    ('apple.collection', 'apple::tests::collection::user_collection_cannot_cross_device_or_other_user_namespace'),
    ('apple.identity', 'apple::tests::identity::token_is_required_before_management'),
    ('apple.identity', 'apple::tests::identity::replacement_token_fencing_and_retirement'),
    ('apple.fairness', 'apple::tests::fairness::expired_queue_does_not_starve_current_collection'),
    ('apple.account_enrollment', 'apple::tests::account_enrollment::account_enrollment_and_reauthentication_keep_one_registration'),
):
    module = MODULES[name]
    previous = next((p for p in module.policies if p.selector == selector),
                    CasePolicy(selector, module.db_mode, module.scope))
    fixtures = previous.fixtures if previous.fixtures is not None else module.fixtures
    policy = replace(previous, fixtures=tuple(dict.fromkeys((*fixtures, 'content'))))
    MODULES[name] = replace(module, policies=(*[p for p in module.policies if p.selector != selector], policy))


T1_INPUTS += ('crates/inventory-service/src/operation.rs',
              'crates/inventory-service/examples/packaged_collections.rs',
              'crates/management-http/src/resource_catalog/mod.rs',
              'crates/management-http/examples/collection_schema.rs',
              'crates/management-http/schema/Collection.json')

# Policy locking is shared by policy writes and native configuration execution.

# Product-wide startup/restore has one owner; provider recovery stays with telemetry.
add('installation.storage', selectors=('setup::backup::storage_tests::',),
    fixtures=('identity','pg_archive'),
    sources=('crates/app/src/database.rs','crates/app/src/migration.rs','crates/app/src/migration/*',
             'crates/app/src/flow.rs','crates/app/src/flow/admission.sql','crates/app/src/execution_assembly.rs',
             'crates/*/src/storage_authority.rs','crates/*/src/authority-admission.sql',
             'crates/inventory-service/src/collection-trigger-admission.sql',
             'crates/app/schema/flow-roles.sql',
             'crates/app/schema/installation.sql',
             'crates/app/schema/platform-sso-identity.sql',
             'crates/app/schema/commands-roles.sql',
             'crates/inventory-service/schema/relations.sql',
             'crates/flow-service/schema/relations.sql',
             'crates/apple-channel/schema/account-enrollment.sql',
             'crates/apple-channel/schema/platform-qualifications.sql',
             'crates/apple-channel/schema/profile-qualifications.sql',
             'crates/authorization-service/schema/authority.sql',
             'crates/device-service/schema/install.sql',
             'crates/device-service/schema/object-qualification.sql',
             'crates/execution-service/schema/device-access-qualification.sql',
             'crates/flow-service/schema/install.sql',
             'crates/flow-service/schema/qualification.sql',
             'crates/inventory-service/schema/collection-metadata.sql',
             'crates/inventory-service/schema/install.sql',
             'crates/registration-service/schema/device-access.sql'),
    tests=('crates/app/tests/setup/storage.rs',),
    support=('hack/postgres_archive.py','hack/postgres_archive_client.py'))
MODULES['installation.storage'] = replace(MODULES['installation.storage'], db_mode='fresh',
    actors=(('tenant','admin'),), scope='objects')

if __name__ == '__main__':
    import argparse
    import json
    parser = argparse.ArgumentParser(description='Read canonical T2 registration identities')
    parser.add_argument('--module-ids', action='store_true', required=True)
    parser.parse_args()
    print(json.dumps(sorted(MODULES)))

# Certificate-based enrollment is carried by management TLS, separately from bootstrap.
consume(('crates/windows-channel/src/certificate_enrollment.rs',), 'windows.enrollment windows.issuance windows.declared')
consume(('crates/registration-service/src/enterprise.rs','crates/registration-service/schema/enterprise.sql','crates/registration-service/src/enterprise/platform.rs'),'apple.platform_sso')
# QUERY-05: page bounds, source evidence batching and continuation owners.
consume(('crates/device-service/src/directory*', 'crates/device-service/src/association_directory.rs'), 'device.views device.associations agent.current_user')
consume(('crates/execution-service/src/query_generation.rs',), 'execution.commands.windows execution.commands.recovery device.revocation apple.ddm')
consume(('crates/inventory-service/src/assets/rsql.rs','crates/inventory-service/src/assets/field_directory.rs','crates/inventory-service/src/assets/windows.rs'), 'assets.http assets.queries assets.sources')

for name in ('device.views', 'execution.commands.windows'):
    MODULES[name] = replace(MODULES[name], support_inputs=MODULES[name].support_inputs + ('crates/app/tests/support/query_reads.rs',))

# Shared composition is exercised by its own HTTP/host proof, not every fixture user.
consume(('crates/app/src/api.rs', 'crates/management-http/src/router.rs',
         'crates/management-http/src/body_policy.rs', 'crates/management-http/src/boundary.rs',
         'crates/management-http/src/response.rs', 'crates/management-http/src/error*.rs'),
        'api.identity_context api.diagnostics')
consume(('crates/app/src/config.rs',), 'host.lifecycle')
consume(('crates/backend-postgres-support/src/access*', 'crates/*/src/access-contract.json',
         'crates/app/src/database.rs'), 'authorization.admission device.admission')
consume(('crates/audit-integration/src/budget.rs',), 'audit.budget')
consume(('crates/app/schema/audit-runtime.sql', 'crates/app/schema/audit-roles.sql'),
        'audit.integrity installation.migration')
consume(('crates/app/schema/identity-roles.sql',), 'authorization.admission installation.migration')
consume(('crates/windows-channel/src/trust_installation.rs',), 'windows.issuance')
consume(('crates/apple-channel/src/trust_installation.rs', 'crates/apple-channel/src/access-admission.sql'), 'apple.scep')
consume(('fixtures/mdm-config.example.json',), 'host.lifecycle installation.migration')
consume(('deployment/providers.lock.json', 'fixtures/pki-tools.lock.json'), 'installation.ca')

consume(('tests/support/context.rs',), 'group.persistence')
consume(('hack/windows_fixtures.py', 'deployment/windows-leaf.tpl'), 'windows.issuance')
consume(('hack/apple_fixtures.py',), 'apple.scep')
consume(('hack/pki_fixtures.py',), 'agent.pki')
consume(('hack/enterprise_idp.py',), 'identity.sso')
consume(('crates/app/schema/flow-roles.sql', 'crates/app/schema/software-publication-roles.sql'),
        'installation.migration')
consume(('crates/inventory-service/schema/group-selections.sql',), 'planning.group_scope')

consume(('crates/execution-service/src/dispatch-v1.json',), 'execution.commands.dispatch')
consume(('crates/execution-service/src/queries/records.rs',), 'execution.agent.history execution.commands.windows')
consume(('crates/flow-service/src/automation/jobs.rs',), 'planning.recovery')

consume(('crates/app/tests/fixtures/error.rs',), 'api.diagnostics')

MODULES['certificate-archive.http'] = replace(MODULES['certificate-archive.http'], policies=(*MODULES['certificate-archive.http'].policies,
    CasePolicy('certificate_archive_tests::issued_results_keep_exact_request_versions_across_clean_shutdown', 'reuse', 'tenant', ('identity',), materials=('archive-issued',))))
for name in ('encrypted_versions_replay_rewrap_and_registration_retirement', 'postgres_backup_restores_material_only_with_the_correct_key',
             'unknown_candidates_block_rotation_and_retention_preserves_unresolved_material',
             'retention_sweep_skips_protected_registrations_and_advances_past_blocked_copies',
             'unescrowed_agent_mutation_protects_retired_material_from_expiry'):
    module = MODULES['recovery-credentials.http']
    MODULES[module.id] = replace(module, policies=(*module.policies, CasePolicy('recovery_credentials_tests::' + name,
        'fresh' if name == 'postgres_backup_restores_material_only_with_the_correct_key' else 'reuse', 'tenant', (), actors=())))

# Final concrete preparation needs after shared module defaults are applied.
for module_id, selector, fixtures, db_mode, scope, actors in (
    ('installation.ca', 'setup::providers::step_ca::tests::unified_ca_initialization_replays_and_isolates_tenants', ('windows', 'ca_windows'), None, 'pair', ()),
    ('assets.sources', 'assets::t2::sources::sources_resolution_and_retained_quality', MODULES['assets.sources'].fixtures, None, None, (('tenant', 'admin'), ('tenant', 'other'))),
    ('planning.http', 'planning::t2::http::console_pending_directory_and_permission_changes', ('identity',), None, None, None),
    ('planning.http', 'planning::t2::http::console_directory_pages_registered_revoked_and_pending', ('identity',), None, None, None),
    ('planning.http', 'planning::t2::http::console_collection_routes_reuse_current_policy', ('identity',), None, None, None),
    ('planning.http', 'planning::t2::http::console_metadata_filters_and_selectors', ('identity',), None, None, None),
    ('planning.http', 'planning::t2::http::resource_query_executes_filter_sort_projection_and_bound_continuations', ('identity',), None, None, None),
    ('planning.http', 'planning::t2::http::reverse_memberships_revalidate_authority_after_request_snapshot', ('identity',), None, None, None),
    ('planning.http', 'planning::t2::http::console_inventory_presence_uses_current_dataset_authority', ('identity',), None, None, None),
    ('planning.http', 'planning::t2::http::collection_blueprints_instantiate_replay_and_keep_tenant_versions', ('identity', 'content'), None, None, None),
    ('planning.http', 'planning::t2::http::planning_routes_and_derived_result_authorization', ('identity', 'content', 'local_worker'), None, None, None),
    ('planning.http', 'planning::t2::http::nested_groups_sources_references_and_authorized_pages', ('identity', 'content', 'local_worker'), None, None, None),
    ('authorization.programmatic', 'authorization::t2::programmatic::business_writes_bind_key_actor_and_managed_enrollment', ('identity',), 'instance', 'objects', (('tenant', 'admin'),)),
    ('authorization.programmatic', 'authorization::t2::programmatic::streamed_content_rejects_rotated_key_before_binding', ('identity', 'content'), 'instance', 'objects', (('tenant', 'admin'),)),
    ('installation.smtp', 'setup::providers::mail::tests::runtime_role_cannot_insert_provider_success', ('runtime_config',), 'reuse', 'objects', ()),
    ('windows.management', 'windows::t2::management::wns::runtime_role_cannot_insert_provider_success', ('runtime_config',), 'reuse', 'objects', ()),
    ('authorization.rules', 'authorization::t2::rules::route_permissions::each_route_requires_its_exact_capability', ('identity',), 'reuse', 'tenant', (('tenant', 'admin'), ('tenant', 'other'))),
    ('windows.limits', 'windows::t2::limits::accepted_peer_rate_limit_and_refill', ('windows', 'runtime_config'), 'reuse', 'tenant', ()),
    ('windows.entra', 'windows::t2::entra::management_policy_body_replay_and_audit_faults', ('identity',), 'fresh', 'objects', (('tenant', 'admin'), ('tenant', 'other'))),
    ('planning.http', 'planning::t2::http::console_script_support_requires_signer_and_content', ('identity', 'agent_pki', 'task_signing', 'content'), None, None, None),
    ('planning.software', 'planning::t2::software::reenabling_same_material_preserves_execution_version', ('identity', 'content'), None, None, (('tenant', 'admin'),)),
    ('execution.commands.windows', 'execution::t2::commands::windows::console_mixed_kind_cursor_and_device_visibility', ('identity', 'content', 'agent_pki', 'task_signing'), None, None, None),
    ('apple.platform_sso', 'apple::tests::platform_sso::nonce_is_bounded_and_never_stored_in_plaintext', ('identity',), None, None, None),
    ('apple.push', 'apple::tests::push::deadline_query_failure_is_not_healthy_idle', ('apple', 'identity'), None, None, None),
    ('content.gc', 'content::t2::gc::catalog_evidence_retains_pin_without_reserving_transfer', ('runtime_config', 'content'), 'reuse', 'objects', ()),
    ('planning.policy', 'planning::t2::policy::assignment_pagination_uses_published_scope_without_eager_execution', ('identity', 'content', 'local_worker'), None, None, None),
    ('planning.policy', 'planning::t2::execution_source::empty_candidate_page_preserves_progress_to_the_next_matching_policy', ('identity',), None, None, None),
    ('apple.host', 'apple::tests::host::missing_apple_materials_keep_management_ready_and_listener_closed', ('apple', 'identity'), None, None, None),
    ('apple.host', 'apple::tests::host::unavailable_apple_provider_keeps_management_ready_and_listener_closed', ('apple', 'identity'), None, None, None),
    ('apple.host', 'apple::tests::host::conflicting_apple_trust_preserves_history_and_keeps_management_ready', ('apple', 'identity', 'scep'), None, None, None),
 ):
    module = MODULES[module_id]
    existing = next((p for p in module.policies if p.selector == selector),
                    CasePolicy(selector, module.db_mode, module.scope))
    policy = replace(existing, fixtures=fixtures,
        db_mode=db_mode or existing.db_mode, scope=scope or existing.scope,
        actors=actors if actors is not None else existing.actors)
    MODULES[module_id] = replace(module, policies=tuple(p for p in module.policies if p.selector != selector) + (policy,))

# Owner seed codecs are preparation inputs, not new product behavior selectors.
for path, owner in (
    ('crates/content-service/src/fixture.rs', 'content.http'),
    ('crates/policy-postgres/src/fixture.rs', 'policy.persistence'),
    ('crates/group-postgres/src/fixture.rs', 'group.generations'),
    ('crates/resource-postgres/src/fixture.rs', 'resource.persistence'),
    ('crates/execution-service/src/service/fixture.rs', 'execution.commands.windows'),
):
    module = MODULES[owner]
    MODULES[owner] = replace(module, support_inputs=tuple(dict.fromkeys((*module.support_inputs, path))))
consume(('crates/app/tests/settings/first_use.rs',), 'agent.configurations')

for selector in (
    'planning::t2::self_service::sensitive_status_rechecks_read_permissions_without_leaking_diagnostics',
    'planning::t2::self_service::employee_request_ids_are_independent_and_unknown_is_hidden',
):
    case_fixtures('planning.self_service', selector, None)

consume(('crates/agent-wire/src/addressing.rs',), 'planning.http planning.self_service policy.persistence')

T1_INPUTS += ('crates/agent-wire/examples/protocol_schema.rs',)

# Remaining management query owners; route declarations alone do not imply business coverage.
consume(('crates/authorization-service/src/directory.rs',), 'authorization.rules authorization.membership authorization.capacity authorization.programmatic')
consume(('crates/webhook-service/src/directory.rs',), 'webhooks.product')
consume(('crates/certificate-archive-service/src/directory.rs',), 'certificate-archive.http')
consume(('crates/apple-channel/src/management_query.rs',), 'apple.account_enrollment apple.ade settings.recent_auth')
consume(('crates/app/src/tenant_directory.rs',), 'installation.tenants deployment.management-tenant settings.recent_auth')
consume(('crates/content-service/src/connections/authority.rs',), 'content.storage settings.recent_auth')

# #3005: exact capability preparation and table-wide fault observation domains.
for module_id, selector, fixtures, db_mode in (
    ('agent.current_user', 'agent::t2::current_user::current_user_read_skips_audit_even_with_business_contention', ('identity','agent_pki'), 'fresh'),
    ('agent.current_user', 'agent::t2::current_user::slow_login_preflight_preserves_source_settlement', ('identity','agent_pki'), 'fresh'),
    ('device-access.http', 'agent::t2::device_access::queries::binding_directory_uses_checked_queries_and_signed_continuations', ('identity','agent_pki'), 'reuse'),
    ('device-access.http', 'agent::t2::device_access::filevault::cms_upload_has_independent_authorization_and_exact_audit_replay', ('identity','agent_pki'), 'reuse'),
    ('authorization.programmatic', 'authorization::t2::programmatic::all_critical_action_denials_keep_actor_target_and_request_identity', ('identity','agent_pki'), 'reuse'),
):
    module=MODULES[module_id]
    MODULES[module_id]=replace(module, policies=(*[p for p in module.policies if p.selector!=selector],
        CasePolicy(selector, db_mode, 'tenant', fixtures=fixtures)))
for path, owner in (
    ('crates/app/tests/support/agent_runtime.rs', 'execution.agent.delivery'),
    ('crates/app/tests/support/current_user.rs', 'agent.current_user'),
):
    module=MODULES[owner]
    MODULES[owner]=replace(module,support_inputs=(*module.support_inputs,path))
consume(('crates/management-http/src/boundary.rs','crates/management-http/src/webhooks.rs',
         'crates/management-http/src/device_access.rs','crates/management-http/src/software_catalog.rs',
         'crates/management-http/src/execution/http.rs'), 'authorization.programmatic')

# Unified management subcollection query owners (#3010).
consume(('crates/execution-service/src/queries/window.rs',), 'planning.policy planning.agent_policy telemetry.ingress.postgres')
consume(('crates/registration-service/src/enrollment/registrations.rs',), 'device.revocation')
consume(('crates/flow-service/src/automation/inventory_tasks.rs',), 'compliance.http')

T1_INPUTS += ('crates/inventory-service/tests/groups_pages.rs',)


# Tests alter actor grants and claim the tenant-wide event queue.
MODULES['planning.custom_events'] = replace(MODULES['planning.custom_events'], scope='tenant', fixtures=tuple(dict.fromkeys((*MODULES['planning.custom_events'].fixtures, 'content', 'task_signing', 'local_worker'))), support_inputs=MODULES['planning.custom_events'].support_inputs + ('crates/app/tests/planning/support.rs',))
# This event authorization regression performs real credential issuance/activation.
case_fixtures('planning.custom_events', 'planning::t2::custom_events::rotated_credential_cannot_accept_replay_or_read_but_accepted_work_survives', 'ca_agent')
consume(('crates/registration-service/src/device/store.rs',), 'planning.custom_events')
MODULES['planning.custom_events'] = replace(MODULES['planning.custom_events'], support_inputs=(*MODULES['planning.custom_events'].support_inputs, 'crates/app/tests/support/agent.rs'))

# Execution authorization projection shares the real command/source owner contracts (#2883).
consume(('crates/execution-service/src/authorization_decision.rs', 'crates/execution-service/src/authority/*.rs'),
        'execution.commands.admission execution.commands.windows execution.commands.recovery execution.commands.configuration execution.commands.onboarding apple.commands apple.policy apple.ddm planning.policy planning.software')
consume(('crates/execution-service/src/directory/*.rs',), 'execution.commands.windows')

T1_INPUTS += ('crates/execution-service/tests/authorization_decision.rs',)
# Inventory streaming owns PG integrity/recovery and all three task consumers.
consume(('crates/inventory-postgres/src/arrays/scan.rs',), 'inventory.manual compliance.evaluation')
consume(('crates/inventory-service/src/assets/evaluation.rs',), 'assets.group_input assets.queries compliance.evaluation')
MODULES['inventory.manual'] = replace(MODULES['inventory.manual'], policies=(*MODULES['inventory.manual'].policies, CasePolicy('array_scan_recovers_across_transactions_and_rejects_incomplete_payloads','reuse','tenant')))
# Endpoint fencing is shared by native registration, execution and renewal.
consume(('crates/execution-service/src/action_admission.rs',
         'crates/registration-service/src/lifecycle.rs'),
        'execution.commands.onboarding execution.commands.recovery execution.commands.configuration planning.self_service windows.declared device.associations device.revocation')
consume(('crates/app/tests/execution/commands/onboarding/endpoint_lock.rs',),
        'execution.commands.onboarding')

consume(('crates/execution-service/src/service/fixture.rs',), 'apple.policy')
