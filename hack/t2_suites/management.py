#!/usr/bin/env python3
"""Product composition transactions against the formal migrated TLS PostgreSQL fixture."""
import importlib.util,subprocess
from pathlib import Path
from build_run import lease_fds, require_lease

ROOT=Path(__file__).resolve().parents[2]
from t2_suites import backend as pg
EXPECTED={"planning::tests::recovery::ingress_batches_reuse_published_group_coverage","planning::tests::recovery::frozen_fields_manual_and_quality_survive_updates_deletes_and_rollback","planning::tests::recovery::corrupt_background_query_is_not_client_input","planning::tests::recovery::scope_history_survives_deletion","planning::tests::recovery::suspended_ingress_fails_readiness_and_restart_recovers_forwarded_input","planning::tests::recovery::live_checkpoint_restart_fences_old_worker","planning::tests::recovery::rss_exhaustion_records_failed_task_and_atomic_audit","planning::tests::recovery::result_cursors_survive_instances_restart_and_group_deletion","planning::tests::durable_asset_group_scope_pipeline",'planning::tests::asset_history_rollback_replay_and_frozen_watermark','planning::tests::asset_storage_failures_are_not_malformed','planning::tests::asset_commit_unknown_recovers_original_receipts','planning::tests::expired_guard_after_lock_rejects_mutation_and_replay','planning::tests::corrupt_scope_is_a_storage_failure_not_a_client_error','planning::tests::registration_replacement_invalidates_direct_and_group_admission','planning::tests::group_delete_scope_reference_compete_without_dangling_references','planning::tests::management_admission_rejects_schema_and_privilege_drift','planning::tests::group_scope_replay_and_audit_atomicity','planning::tests::initial_empty_group_scope_and_revision_competition'}
EXPECTED.add("planning::tests::recovery::superseded_group_links_reused_successor")
EXPECTED.add("planning::tests::recovery::published_scope_job_does_not_swallow_new_definition")
EXPECTED.add("planning::tests::asset_capability_owns_execution_and_receipt_recovery")
EXPECTED.add("planning::tests::audit_startup_rejects_each_borrowed_owner_snapshot_isolation")

def main(context):
    require_lease(ROOT)
    failures=[]
    for test in sorted(EXPECTED):
        with pg.fixture(context,app=True,case=test) as(env,sql):
            result=subprocess.run(['cargo','test','--locked','-p','rss-mdm-app','--features','integration','--lib',test,'--','--ignored','--exact'],pass_fds=lease_fds(), cwd=ROOT,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            print(result.stdout,flush=True)
            try:
                pg.require(result.returncode==0,'planning T2 failed')
                pg.verify_tests(result.stdout,{test})
            except Exception:
                failures.append(test)
    with pg.fixture(context,app=True) as (env, sql):
        result = subprocess.run(['cargo', 'test', '--locked', '-p', 'rss-mdm-inventory-postgres', '--test', 'manual', '--', '--ignored'], pass_fds=lease_fds(), cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        print(result.stdout, flush=True)
        try:
            pg.require(result.returncode == 0, 'manual inventory T2 failed')
            pg.verify_tests(result.stdout, {'public_manual_cas_rollback_and_tenant_isolation'})
        except Exception:
            failures.append('inventory/manual')
    pg.require(not failures,'planning T2 failed: '+','.join(failures))
