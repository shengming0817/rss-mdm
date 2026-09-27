"""One static registry for T2 execution and non-Cargo input selection."""
from collections import Counter
from dataclasses import dataclass
from functools import partial
from pathlib import Path
import re
from typing import Callable
from verification_result import verify_tests
from t2_suites import product, backend, group, management, publication, sources, gateway

ROOT=Path(__file__).resolve().parents[1]
@dataclass(frozen=True)
class Suite:
    name: str
    module: str
    executor: Callable
    expected: tuple[str,...]
    tools: tuple[str,...] = ('cargo','docker','openssl')
    fixtures: tuple[str,...] = ()
    isolation: str = 'database'
    destructive: frozenset[str] = frozenset()
    success_marker: str | None = None
    input_modules: tuple[str,...] = ()

    def verify(self, output):
        if self.expected:verify_tests(output,self.expected)
        if self.success_marker and self.success_marker not in output:raise RuntimeError('missing suite completion: '+self.name)

def product_suite(name,scenario,expected,*,fixtures=('identity',),isolation='database',tools=('cargo','docker','openssl'),success_marker=None):
    tests=tuple(expected)+(('identity_fixture::seed_accounts',) if 'identity' in fixtures else ())
    return Suite(name,'product',partial(product.run_scenario,scenario=scenario),tests,tools,fixtures,isolation,success_marker=success_marker)

SUITES={
 'installation':product_suite('installation',product.installation_tests,('migration::tests::fresh_installation_replay_and_mismatch_rejection','audit_integration_tests::installed_audit_receipts_replay_and_atomicity','audit_integration_tests::operation_cutoff_leaves_owner_time_to_rollback'),fixtures=('unmigrated',),isolation='server'),
 'foundation':product_suite('foundation',product.foundation,('identity_t2::authorization::capability_routes_without_application_preserve_revocation_and_atomicity','device::tests::postgres_boundary','inventory_runtime::tests::durable_report_recovery_and_projection','api::tests::audit_failure_logs_preserve_action_and_origin','api::tests::request_diagnostics_keep_causes_internal_and_issue_request_ids','real_pg_inventory_and_recovery','reader_is_exact_tenant_scoped_and_read_only'),fixtures=('identity','examples'),isolation='server'),
 'windows':product_suite('windows',product.windows,('windows::tests::issuance_recovery_and_enrollment_boundaries','windows::tests::native_tls_enrollment_management_replay_and_revoke'),fixtures=('identity','windows'),isolation='server'),
 'assets':product_suite('assets',product.assets,('identity_t2::assets::asset_write_query_group_and_isolation',)),
 'compliance':product_suite('compliance',product.compliance,('identity_t2::compliance::rules_facts_groups_history_and_authorization',)),
 'commands':product_suite('commands',product.commands,('windows::tests::native_command_operations_and_observation',),fixtures=('identity','windows'),isolation='server'),
 'tasks':product_suite('tasks',product.tasks,('identity_t2::tasks::enterprise_task_delivery_and_inventory',)),
 'software':product_suite('software',product.software,('identity_t2::software::enterprise_catalog_content_and_atomic_admission',),fixtures=('identity','sources'),isolation='server'),
 'apple':product_suite('apple',product.apple,('apple::certificate::tests::cms_is_attached_and_independently_verified','apple::push::tests::production_transport_receipts_are_not_command_evidence','apple::tests::native_enrollment_collection_and_profile_lifecycle'),fixtures=('identity','apple'),tools=('cargo','docker','openssl','go')),
 'identity':product_suite('identity',product.identity,('identity_audit::tests::http_events_deliver_replay_and_fail_closed','identity_t2::authorization::capability_routes_without_application_preserve_revocation_and_atomicity','identity_t2::authorization::persistent_rules_membership_cas_replay_and_restart','identity_t2::local_identity_mdm_authorization_and_revocation','identity_t2::sso::product_callback_link_step_up_and_provider_isolation'),fixtures=('identity','sources','windows'),isolation='server'),
 'catalog':product_suite('catalog',product.catalog,(),fixtures=(),success_marker='command catalog check: all contracts match isolated migrations'),
 'management':Suite('management','management',management.main,tuple(sorted(management.EXPECTED))+('public_manual_cas_rollback_and_tenant_isolation',),destructive=frozenset({'planning::tests::management_admission_rejects_schema_and_privilege_drift','planning::tests::audit_startup_rejects_each_borrowed_owner_snapshot_isolation'}),input_modules=('backend',)),
 'backend':Suite('backend','backend',backend.main,tuple(test for name in backend.NAMES for test in sorted(backend.BEHAVIORS[name]))+('protocol_ack_loss_and_fault_ack_recover_original_request',)*3,destructive=frozenset({'admission_rejects_schema_and_reachable_privilege_drift','admission_rejects_noninherited_switchable_privileges','resource_admission_rejects_schema_and_privilege_drift','release_event_failure_and_runtime_admission'})),
 'group':Suite('group','group',group.main,tuple(sorted(group.EXPECTED|group.GENERATIONS)),destructive=frozenset({'admission_rejects_catalog_and_security_drift'})),
 'publication':Suite('publication','publication',publication.main,('publication_result_commit_unknown_recovers_one_external_call_and_audit','public_artifact_digest_length_tls_redirect_and_timeout_fail_closed','preflight_failure_allows_explicit_retry_without_resubmitting_unknown','full_version_publication_recovery_and_public_artifact_boundary','unknown_publication_blocks_withdrawal_and_audit_failure_rolls_back','brew_full_version_recovery_shared_tap_and_old_version_withdrawal','ring_isolation_unstarted_withdrawal_and_lost_delete_ack','complete_variant_mapping_and_resource_reference_protection','planning::tests::resource_archive::candidate_reference_blocks_archive_and_race_is_atomic'),fixtures=('sources',),input_modules=('backend','sources')),
 'sources':Suite('sources','sources',sources.main,tuple(test for names in sources.EXPECTED.values() for test in sorted(names)),tools=('cargo','openssl','/usr/bin/git'),isolation='none'),
 'gateway':Suite('gateway','gateway',gateway.main,(),tools=('docker',),isolation='none',success_marker='login gateway T2: actual peer budget'),
}
for name,suite in SUITES.items():
    if name!=suite.name or not callable(suite.executor) or suite.isolation not in {'none','database','server'} or not set(suite.fixtures)<={'identity','unmigrated','examples','windows','apple','sources'} or (not suite.expected and not suite.success_marker):
        raise RuntimeError('incomplete T2 registration: '+name)
# Direct source ownership, independent of the larger Cargo reverse dependency closure.
OWNERS={
 'group':('group','management','compliance','tasks'), 'group-postgres':('group','management','compliance','tasks'),
 'policy':('backend','management','tasks'), 'policy-postgres':('backend','management','tasks'),
 'resource':('backend','management','publication','software','tasks'), 'resource-postgres':('backend','management','publication','software','tasks'),
 'software-release':('backend','publication','software'), 'software-release-postgres':('backend','publication','software'),
 'backend-postgres-support':('backend','management','publication','software','tasks'),
 'software-service':('publication','software','catalog'), 'winget-source':('sources','publication'), 'brew-source':('sources','publication'),
 'compliance':('compliance',), 'compliance-postgres':('compliance',),
 'inventory':('foundation','assets','management','compliance'), 'inventory-postgres':('foundation','assets','management','compliance'),
 'windows-mdm':('windows','commands','identity'), 'agent-wire':('commands','tasks'), 'scope':tuple(SUITES),
 'audit-integration':tuple(SUITES), 'examples':tuple(SUITES),
}
APP={
 'apple':('apple',),'windows':('windows','commands','identity'),'planning':('management','publication','compliance'),
 'execution':('commands','tasks','catalog'),'task_signing':('tasks',),'inventory_runtime':('foundation','assets','management','compliance'),
 'device':('foundation','windows','apple'),'flow':('management','publication','software','catalog'),
 'content':('software','publication','catalog'),'compliance':('compliance',),'assets':('assets','management'),
}
TOOL_INPUTS={
 'hack/verification_result.py':('test_t2_runner','test_ci_selection','test_ci','test_t2_guards','test_foundation_t2','test_source_t2'),
 'hack/apple_tools.py':('test_apple_tools',), 'fixtures/apple-tools.lock.json':('test_apple_tools',),
 'hack/build_run.py':('test_build_run','test_build_environment'),
 'hack/ci.py':('test_ci','test_ci_selection'), 'hack/ci-impact.py':('test_ci_impact','test_ci_selection'),
 'hack/ci_registry.py':('test_t2_runner','test_ci_selection','test_ci_impact'),
 'hack/t2.py':('test_t2_runner','test_t2_guards'),
 'hack/t2_environment.py':('test_t2_environment','test_t2_runner'),
 'hack/auth_t3.py':('test_auth_t3',),'hack/auth_t3_browser.mjs':('test_auth_t3',),
 'hack/release.py':('test_release',),'hack/candidate_runtime.py':('test_candidate_smoke',),
 'hack/candidate_smoke.py':('test_candidate_smoke',),
 'hack/agent_wire_compat.py':('test_agent_wire_compat',),
}

def all_tools(): return sorted(p.stem for p in (ROOT/'tests').glob('test_*.py'))

def select_paths(paths):
    suites=set(); tests=set(); reasons=set()
    for path in paths:
        bits=path.split('/')
        if path.startswith('docs/') or path.endswith('.md') or path in ('LICENSE','.gitignore'):continue
        if path.startswith('tests/test_') and path.endswith('.py'):
            tests.add(Path(path).stem);continue
        if path in TOOL_INPUTS:
            tests.update(TOOL_INPUTS[path])
            if path in ('hack/build_run.py','hack/ci.py','hack/ci-impact.py','hack/ci_registry.py','hack/t2.py','hack/t2_environment.py','hack/verification_result.py'):
                suites.update(SUITES)
            elif 'apple' in path:suites.add('apple')
            continue
        if path.startswith('hack/t2_suites/'):
            module=Path(path).stem
            consumers={name for name,suite in SUITES.items() if module==suite.module or module in suite.input_modules or (module=='sources' and 'sources' in suite.fixtures)}
            suites.update(consumers or SUITES)
            if not consumers:reasons.add('unmapped-suite-input:'+path)
            tests.update(('test_t2_guards','test_t2_runner','test_t2_environment'))
            if module=='__init__':suites.update(SUITES)
            continue
        if path.startswith('crates/') and len(bits)>2:
            crate=bits[1]
            if crate=='app':
                module=Path(bits[3]).stem if len(bits)>3 and bits[2]=='src' else ''
                suites.update(APP.get(module,tuple(SUITES)))
            else:suites.update(OWNERS.get(crate,tuple(SUITES)))
            # Structural tests inspect Rust/SQL inputs outside Python import edges.
            if crate=='app':tests.update(('test_access_structure','test_foundation_boundaries','test_flow_boundaries','test_audit_surface','test_software_ownership','test_auth_t3'))
            if crate in ('policy-postgres','resource-postgres','software-release-postgres','backend-postgres-support'):tests.add('test_backend_support')
            if crate=='software-service':tests.update(('test_software_ownership','test_flow_boundaries','test_audit_surface'))
            if crate=='windows-mdm':tests.add('test_ddf')
            if crate=='agent-wire':tests.add('test_agent_wire_compat')
            continue
        if path.startswith('tests/inventory-postgres-integration/'):
            suites.add('foundation');continue
        if path.startswith('fixtures/') or path.startswith('deployment/'):
            suites.update(SUITES);tests.update(all_tools());reasons.add('shared-fixture');continue
        suites.update(SUITES);tests.update(all_tools());reasons.add('unknown-or-global-input:'+path)
    return sorted(suites),sorted(tests),sorted(reasons)

def execute(name, context):
    context.spec=SUITES[name]
    return context.spec.executor(context)
