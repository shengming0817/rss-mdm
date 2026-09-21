#!/usr/bin/env python3
"""Product composition transactions against the formal migrated TLS PostgreSQL fixture."""
import importlib.util,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('backend_t2',ROOT/'hack/backend-t2.py')
pg=importlib.util.module_from_spec(spec);spec.loader.exec_module(pg)
EXPECTED={'management::tests::asset_commit_unknown_recovers_original_receipts','management::tests::expired_guard_after_lock_rejects_mutation_and_replay','management::tests::corrupt_scope_is_a_storage_failure_not_a_client_error','management::tests::registration_replacement_invalidates_direct_and_group_previews','management::tests::group_delete_scope_reference_compete_without_dangling_references','management::tests::management_admission_rejects_schema_and_privilege_drift','management::tests::group_scope_plan_replay_stale_and_audit_atomicity','management::tests::initial_empty_group_scope_and_revision_competition'}
with pg.fixture(app=True) as(env,sql):
    result=subprocess.run(['cargo','test','--locked','-p','rss-mdm-app','--features','integration','--lib','management::tests::','--','--ignored','--test-threads=1'],cwd=ROOT,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    print(result.stdout,flush=True)
    pg.require(result.returncode==0,'management T2 failed')
    pg.verify_tests(result.stdout,EXPECTED)
