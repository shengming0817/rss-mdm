#!/usr/bin/env python3
"""Report the product T2 coverage gap until new owner proofs are implemented."""
import argparse
import json
from pathlib import Path
import sys

from build_run import require_lease
from verification_result import publish, require

ROOT = Path(__file__).resolve().parents[1]

def coverage():
    return dict(status='skipped', reason='not-built', modules=[], executedCases=0)

def main(argv=None):
    output = ROOT / 'artifacts/local-t2'
    require_lease(ROOT)
    require(not output.is_symlink(), 'T2 output directory cannot be a symlink')
    output.mkdir(parents=True, exist_ok=True)
    receipt = output / 'result.json'
    # Invalid invocations must not leave a previous success visible either.
    receipt.unlink(missing_ok=True)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--module', choices=('affected', 'all'), default='affected')
    args = parser.parse_args(argv)
    from ci import command, working_source_state
    head = command(['/usr/bin/git', 'rev-parse', 'HEAD'])
    require(head.returncode == 0, 'cannot resolve source revision')
    evidence = dict(coverage(), requestedMode=args.module, sourceRevision=head.stdout.strip(),
                    sourceState=working_source_state())
    publish(receipt, evidence)
    print(json.dumps(evidence, indent=2))
    print('T2 尚未重建；零用例不代表验证通过。', file=sys.stderr)
    return 1

if __name__ == '__main__':
    sys.exit(main())
