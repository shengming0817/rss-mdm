#!/usr/bin/env python3
"""The sole public T2 dispatcher. Suite implementations have no CLI."""
import argparse
import contextlib
import json
import os
from pathlib import Path
import shutil
import sys
import time
from build_run import require_lease
from ci_registry import ROOT, SUITES, execute

def select_suites(suite,selection):
    if suite=='all':return sorted(SUITES)
    if suite=='affected':return sorted(SUITES) if selection.get('full') else sorted(selection['t2Suites'])
    if suite not in SUITES:raise ValueError('unknown SUITE; available: '+', '.join(['affected','all',*sorted(SUITES)]))
    return [suite]

def run_suites(names, output):
    require_lease(ROOT)
    output.mkdir(parents=True,exist_ok=True)
    results={}
    for name in names:
        (output/(name+'.log')).write_text('')
        started=time.monotonic()
        try:
            missing=[tool for tool in SUITES[name].tools if not shutil.which(tool)]
            if missing:raise RuntimeError('missing dependencies: '+', '.join(missing))
            print('T2: '+name,flush=True)
            # FD redirection also captures inherited child output while preserving the build lease.
            with (output/(name+'.log')).open('w') as log:
                sys.stdout.flush();sys.stderr.flush()
                saved=[os.dup(1),os.dup(2)]
                try:
                    os.dup2(log.fileno(),1);os.dup2(log.fileno(),2)
                    outcome=execute(name)
                    if outcome not in (None,0):raise RuntimeError('suite returned failure')
                finally:
                    sys.stdout.flush();sys.stderr.flush()
                    os.dup2(saved[0],1);os.dup2(saved[1],2)
                    for fd in saved:os.close(fd)
            status='passed'
        except Exception as error:
            status='failed'
            with (output/(name+'.log')).open('a') as log:log.write('\n'+str(error)+'\n')
        results[name]={'status':status,'elapsedSeconds':round(time.monotonic()-started,3)}
        print(f'T2 {name}: {status} ({results[name]["elapsedSeconds"]}s)',flush=True)
    return results

def main(argv=None):
    parser=argparse.ArgumentParser()
    parser.add_argument('--suite',default='affected')
    parser.add_argument('--base',default=os.environ.get('CI_BASE','origin/develop'))
    args=parser.parse_args(argv)
    # Validate spelling before selection or starting any services.
    if args.suite not in ('all','affected',*SUITES):parser.error('unknown SUITE; available: '+', '.join(['affected','all',*sorted(SUITES)]))
    require_lease(ROOT)
    import ci
    source_state=ci.working_source_state()
    selection=ci.select_impact(ci.command(['/usr/bin/git','rev-parse','HEAD']).stdout.strip(),base=args.base)
    names=select_suites(args.suite,selection)
    if not names:print('T2: no-t2-selected (integration verification not performed)',flush=True)
    output=ROOT/'artifacts/local-t2'
    output.mkdir(parents=True,exist_ok=True)
    (output/'result.json').unlink(missing_ok=True)
    results=run_suites(names,output)
    if ci.working_source_state()!=source_state:
        results['source-stability']={'status':'failed','reason':'source changed during T2'}
    evidence={'selection':selection,'suite':args.suite,'status':'failed' if any(x['status']=='failed' for x in results.values()) else 'passed' if names else 'skipped','suites':results}
    (output/'result.json').write_text(json.dumps(evidence,indent=2)+'\n')
    return int(evidence['status']=='failed')

if __name__=='__main__':sys.exit(main())
