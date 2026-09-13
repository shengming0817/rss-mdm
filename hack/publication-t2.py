#!/usr/bin/env python3
"""Actual app use cases against disposable PG, HTTPS and bare Git; no client installation."""
import importlib.util,os,subprocess,tempfile,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def module(name,file):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file));value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
pg=module('backend_t2','backend-t2.py');source=module('source_t2','source-t2.py')
def run(env):
    with tempfile.TemporaryDirectory(prefix='mdm-publication-https-') as directory:
        tls=source.tls_environment(Path(directory));tls.update(env)
        result=subprocess.run(['cargo','test','--locked','-p','rss-mdm-app','--test','publication_t2','--','--ignored','--test-threads=1'],cwd=ROOT,env=tls,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        print(result.stdout,flush=True)
        if result.returncode:raise RuntimeError('publication T2 failed')
        pg.verify_tests(result.stdout, {'archive_and_candidate_reference_race_is_atomic','publication_result_commit_unknown_recovers_one_external_call_and_audit','public_artifact_digest_length_tls_redirect_and_timeout_fail_closed','preflight_failure_allows_explicit_retry_without_resubmitting_unknown','full_version_publication_recovery_and_public_artifact_boundary','unknown_publication_blocks_withdrawal_and_audit_failure_rolls_back','brew_full_version_recovery_shared_tap_and_old_version_withdrawal','ring_isolation_unstarted_withdrawal_and_lost_delete_ack','complete_variant_mapping_and_resource_reference_protection'})
def main():
    if '--existing' in sys.argv:
        import json
        config=json.loads((ROOT/'artifacts/backend/environment.json').read_text());run({**os.environ,**config})
    else:
        with pg.fixture(app=True) as(env,sql):run(env)
if __name__=='__main__':main()
