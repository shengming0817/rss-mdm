#!/usr/bin/env python3
"""Actual app use cases against disposable PG, HTTPS and bare Git; no client installation."""
import importlib.util,os,subprocess,tempfile,sys
from pathlib import Path
from build_run import lease_fds, require_lease

ROOT=Path(__file__).resolve().parents[2]
from t2_suites import backend as pg, sources as source
def run(env,context):
    with tempfile.TemporaryDirectory(prefix='mdm-publication-https-') as directory:
        tls=source.tls_environment(Path(directory),context);tls.update(env)
        result=subprocess.run(['cargo','test','--locked','-p','rss-mdm-app','--test','publication_t2','--','--ignored','--test-threads=1'],pass_fds=lease_fds(), cwd=ROOT,env=tls,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        print(result.stdout,flush=True)
        if result.returncode:raise RuntimeError('publication T2 failed')
        result=subprocess.run(['cargo','test','--locked','-p','rss-mdm-app','--lib','planning::tests::resource_archive::candidate_reference_blocks_archive_and_race_is_atomic','--','--ignored','--exact'],pass_fds=lease_fds(), cwd=ROOT,env=tls,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        print(result.stdout,flush=True)
        if result.returncode:raise RuntimeError('planning resource archive T2 failed')
def main(context):
    require_lease(ROOT)
    with pg.fixture(context,app=True) as(env,sql):run(env,context)
