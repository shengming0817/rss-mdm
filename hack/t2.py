#!/usr/bin/env python3
"""Run discovered owner proofs through nextest and existing resource/build owners."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

from build_run import lease_fds, require_lease
from t2_registry import MODULES, PACKAGE, discover
from verification_result import publish, require

ROOT = Path(__file__).resolve().parents[1]


def selection_status(modules, reason='not-requested'):
    return dict(status='skipped', reason=reason, modules=list(modules), executedCases=0,
                coverage='registered-foundation-proofs-only; other owners not rebuilt')


def verify_report(path, expected):
    cases = ET.parse(path).getroot().findall('.//testcase')
    names = [case.attrib['name'] for case in cases]
    require(len(names) == len(set(names)) and set(names) == set(expected),
            'T2 executed set differs from discovery')
    require(not any(case.find(tag) is not None for case in cases
                    for tag in ('failure', 'error', 'skipped')), 'T2 failed or skipped')
    return len(names)


def run_modules(modules, output=None):
    from ci import working_source_state
    from t2_environment import prepared
    require_lease(ROOT)
    output = Path(output or ROOT / 'artifacts/local-t2')
    require(not output.is_symlink(), 'T2 output directory cannot be a symlink')
    output.mkdir(parents=True, exist_ok=True)
    receipt = output / 'result.json'
    receipt.unlink(missing_ok=True)
    (output / 'junit.xml').unlink(missing_ok=True)
    state = working_source_state()
    evidence = selection_status(modules)
    evidence.update(sourceState=state, resources=[])
    evidence['sourceRevision'] = subprocess.check_output(['/usr/bin/git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    started = time.monotonic()

    def command(args, name, *, env=None, check=True):
        result = subprocess.run(args, cwd=ROOT, env=env, pass_fds=lease_fds(),
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (output / name).write_text(result.stdout)
        (output / (name + '.stderr')).write_text(result.stderr)
        if check:
            require(result.returncode == 0, 'T2 command failed; see ' + str(output / name))
        return result

    try:
        if not modules:
            evidence.update(reason='no-modules-selected')
            return evidence
        require(len(modules) == len(set(modules)) and set(modules) <= MODULES.keys(), 'invalid T2 selection')
        evidence.update(status='failed', reason='discovery')
        listing = command(['cargo', 'nextest', 'list', '--locked', '-p', PACKAGE, '--lib',
                           '--message-format', 'json'], 'discovery.json')
        found = discover(json.loads(listing.stdout), modules)
        expected = [case for cases in found.values() for case in cases]
        evidence['discovered'] = found
        build = command(['cargo', 'build', '--locked', '-p', PACKAGE, '--bin', 'rss-mdm',
                         '--message-format=json'], 'build.json')
        artifacts = [json.loads(line) for line in build.stdout.splitlines() if line.startswith('{')]
        binary = next(value['executable'] for value in artifacts
                      if value.get('reason') == 'compiler-artifact' and value.get('executable')
                      and value['target']['name'] == 'rss-mdm')
        evidence['reason'] = 'preparation'
        with prepared(ROOT, modules, binary, command, evidence['resources']) as inputs:
            expression = ' | '.join('test(=' + name + ')' for name in expected)
            metadata = command(['cargo', 'metadata', '--locked', '--format-version', '1', '--no-deps'], 'metadata.json')
            report = Path(json.loads(metadata.stdout)['target_directory']) / 'nextest/t2/foundation.xml'
            report.unlink(missing_ok=True)
            evidence['reason'] = 'business'
            execution = command(['cargo', 'nextest', 'run', '--locked', '-p', PACKAGE, '--lib',
                                 '--run-ignored', 'only', '--profile', 't2', '-E', expression],
                                'execution.log', env={**os.environ, **inputs}, check=False)
            require(report.is_file(), 'this T2 execution did not publish its JUnit report')
            if report.is_file():
                (output / 'junit.xml').write_bytes(report.read_bytes())
                cases = ET.parse(output / 'junit.xml').getroot().findall('.//testcase')
                evidence['executedCases'] = sum(case.find('skipped') is None for case in cases)
                evidence['cases'] = [dict(name=case.attrib['name'],
                    status='skipped' if case.find('skipped') is not None else
                           'failed' if any(case.find(tag) is not None for tag in ('failure', 'error')) else 'passed')
                    for case in cases]
            require(execution.returncode == 0, 'T2 execution failed; see execution.log')
            evidence['executedCases'] = verify_report(output / 'junit.xml', expected)
            evidence['reason'] = 'cleanup'
        require(working_source_state() == state, 'source changed during T2')
        evidence.update(status='passed', reason='executed')
        return evidence
    except BaseException as error:
        evidence.update(status='failed', error=str(error))
        raise
    finally:
        evidence['elapsedSeconds'] = round(time.monotonic() - started, 3)
        publish(receipt, evidence)


def main(argv=None):
    require_lease(ROOT)
    output = ROOT / 'artifacts/local-t2'
    require(not output.is_symlink(), 'T2 output directory cannot be a symlink')
    (output / 'result.json').unlink(missing_ok=True)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--module', choices=('affected', 'all', *MODULES), default='affected')
    args = parser.parse_args(argv)
    try:
        if args.module == 'affected':
            from ci import select_impact
            head = subprocess.check_output(['/usr/bin/git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
            modules = select_impact(head)['t2']['modules']
        else:
            modules = sorted(MODULES) if args.module == 'all' else [args.module]
        result = run_modules(modules, output)
        print(json.dumps(result, indent=2))
        return 0
    except Exception as error:
        if not (output / 'result.json').exists():
            publish(output / 'result.json', dict(status='failed', reason='selection', error=str(error)))
        print(str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
