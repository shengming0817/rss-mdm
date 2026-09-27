#!/usr/bin/env python3
"""Group's independent TLS PostgreSQL fixture. Missing dependencies fail closed."""
import contextlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import uuid
from t2_environment import run
from verification_result import require

from build_run import lease_fds, require_lease

ROOT = Path(__file__).resolve().parents[2]
EXPECTED = {
    "standalone_delete_requires_companion_transaction",
    "borrowed_entries_reject_same_tenant_foreign_runtime_without_events",
    "admission_rejects_catalog_and_security_drift",
    "distinct_runs_compete_on_one_revision_and_preserve_event_contract",
    "reference_target_lock_serializes_deletion",
    "lost_commit_ack_replays_durable_result_once",
    "process_death_after_admission_recovers_without_caller_snapshot",
    "concurrent_inputs_rule_changes_and_kind_boundaries",
    "atomic_event_failure_rls_and_large_member_ids",
    "admitted_input_and_command_commit_unknown_recover_by_original_identity"}


def verify_tests(output, expected=EXPECTED):
    passed = set(re.findall(r'^test (\S+) \.\.\. ok$', output, re.MULTILINE))
    require(passed == expected, f'Group T2 did not execute required cases: {passed}')
    require(f'test result: ok. {len(expected)} passed; 0 failed; 0 ignored;' in output, 'Group T2 false green')

@contextlib.contextmanager
def fixture(context, migrations=None, case=None):
    with context.cluster(case) as owner, owner.database() as database, tempfile.TemporaryDirectory(prefix='mdm-group-inputs-') as directory:
        root=Path(directory)
        (root/'ca.crt').write_bytes((owner.root/'ca.crt').read_bytes())
        name=owner.container();port=owner.port()
        def sql(statement): return owner.sql(statement,database)
        if migrations is None:
            migrations=run(['cargo','run','--locked','--quiet','-p','rss-mdm-group-postgres','--example','migrations'],cwd=ROOT,capture_output=True).stdout
        try:
            sql('BEGIN; SET ROLE mdm_group_owner; '+migrations+' COMMIT;')
        except subprocess.CalledProcessError as error:
            print(error.stderr, file=sys.stderr);raise
        sql("INSERT INTO rss_transactional_messaging.storage_lineage(target,lineage) VALUES(decode(repeat('01',16),'hex'),decode(repeat('02',16),'hex')); INSERT INTO rss_transactional_messaging.tenant_epoch VALUES('11111111-1111-1111-1111-111111111111',1),('22222222-2222-2222-2222-222222222222',1);")
        path=root/'config.json';path.write_text(json.dumps({'port':port,'ca':str(root/'ca.crt'),'container':name,'database':database}));path.chmod(0o600)
        yield dict(os.environ,GROUP_PG_CONFIG=str(path)),sql

GENERATIONS={'staged_pages_publish_atomically_and_replay_without_duplicate_members','static_patches_use_the_same_sealed_publication_and_preserve_old_sets','static_commands_replay_and_borrowed_rollback','durable_recalculation_no_change_fences_stale_run','delta_evaluates_only_changed_devices_and_preserves_old_results'}

def main(context):
    require_lease(ROOT)
    failures=[]
    for target,expected in [('t2',EXPECTED),('generations',GENERATIONS)]:
        for test in sorted(expected):
            with fixture(context,case=test) as(env,sql):
                result=subprocess.run(['cargo','test','--locked','-p','rss-mdm-group-postgres','--features','integration','--test',target,test,'--','--ignored','--exact','--test-threads=1','--show-output'],pass_fds=lease_fds(),cwd=ROOT,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                print(result.stdout,flush=True)
                try:
                    require(result.returncode==0,'Group T2 failed');verify_tests(result.stdout,{test})
                except Exception:failures.append(test)
    require(not failures,'Group T2 failed: '+','.join(failures))
