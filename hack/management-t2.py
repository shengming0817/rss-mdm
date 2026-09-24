#!/usr/bin/env python3
"""Product composition transactions against the formal migrated TLS PostgreSQL fixture."""
import importlib.util,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('backend_t2',ROOT/'hack/backend-t2.py')
pg=importlib.util.module_from_spec(spec);spec.loader.exec_module(pg)
EXPECTED={"management::tests::recovery::ingress_batches_reuse_published_group_coverage","management::tests::recovery::frozen_fields_manual_and_quality_survive_updates_deletes_and_rollback","management::tests::recovery::corrupt_background_query_is_not_client_input","management::tests::recovery::scope_history_survives_deletion","management::tests::recovery::policy_waits_for_scope_and_inherits_failure","management::tests::recovery::suspended_ingress_fails_readiness_and_restart_recovers_forwarded_input","management::tests::recovery::live_checkpoint_restart_fences_old_worker","management::tests::recovery::rss_exhaustion_records_failed_task_and_atomic_audit","management::tests::recovery::result_cursors_survive_instances_restart_and_group_deletion","management::tests::recovery::unknown_policy_result_is_not_found","management::tests::saving_new_scope_replaces_automatic_candidate_binding","management::tests::durable_asset_group_scope_candidate_pipeline",'management::tests::asset_history_rollback_replay_and_frozen_watermark','management::tests::asset_storage_failures_are_not_malformed','management::tests::asset_commit_unknown_recovers_original_receipts','management::tests::expired_guard_after_lock_rejects_mutation_and_replay','management::tests::corrupt_scope_is_a_storage_failure_not_a_client_error','management::tests::registration_replacement_invalidates_direct_and_group_previews','management::tests::group_delete_scope_reference_compete_without_dangling_references','management::tests::management_admission_rejects_schema_and_privilege_drift','management::tests::group_scope_plan_replay_stale_and_audit_atomicity','management::tests::initial_empty_group_scope_and_revision_competition'}
failures=[]
for test in sorted(EXPECTED):
    with pg.fixture(app=True) as(env,sql):
        result=subprocess.run(['cargo','test','--locked','-p','rss-mdm-app','--features','integration','--lib',test,'--','--ignored','--exact'],cwd=ROOT,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        print(result.stdout,flush=True)
        try:
            pg.require(result.returncode==0,'management T2 failed')
            pg.verify_tests(result.stdout,{test})
        except Exception:
            failures.append(test)
with pg.fixture(app=True) as (env, sql):
    result = subprocess.run(['cargo', 'test', '--locked', '-p', 'rss-mdm-inventory-postgres', '--test', 'manual', '--', '--ignored'], cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(result.stdout, flush=True)
    try:
        pg.require(result.returncode == 0, 'manual inventory T2 failed')
        pg.verify_tests(result.stdout, {'public_manual_cas_rollback_and_tenant_isolation'})
    except Exception:
        failures.append('inventory/manual')
pg.require(not failures,'management T2 failed: '+','.join(failures))
