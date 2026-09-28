#!/usr/bin/env python3
"""One public module executor. Discovery, selection and evidence share one owner."""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import importlib
import json
import os
from pathlib import Path
import shutil
import signal
import sys
import time
import traceback
import uuid

from build_run import require_lease
from t2_registry import ROOT, MODULES
from t2_execution import Builds, Processes
from verification_result import result as stage_result, publish, require


def select_modules(module, selection):
    if module == 'all':
        return sorted(MODULES)
    if module == 'affected':
        return sorted(MODULES) if selection['t2Full'] else sorted(selection['modules'])
    if module not in MODULES:
        raise ValueError('unknown MODULE; available: ' + ', '.join(['affected', 'all', *sorted(MODULES)]))
    return [module]


def run_modules(names, output, *, jobs=2, selected_case='', listing=False):
    require_lease(ROOT)
    require(type(jobs) is int and jobs > 0, 'JOBS must be a positive integer')
    require(not output.is_symlink(), 'T2 output directory cannot be a symlink')
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    run_id = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + uuid.uuid4().hex[:8]
    directory = output / run_id
    directory.mkdir()
    results = {name: stage_result('skipped', reason='not-selected') for name in MODULES}
    if not names:
        require(not selected_case, 'CASE does not belong to any selected module')
        return results
    modules = [MODULES[name] for name in names]
    processes = Processes()
    previous = {}
    def cancel(number, frame):
        processes.cancel()
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
        previous[sig] = signal.signal(sig, cancel)
    try:
        for module in modules:
            missing = [tool for tool in module.tools if not shutil.which(tool)]
            require(not missing, 'missing dependencies for ' + module.id + ': ' + ', '.join(missing))
        builds = Builds(directory, processes)
        builds.prepare(modules)
        discovered = {module.id: builds.discover(module) if module.build else [] for module in modules}
        owners = {}
        for module in modules:
            for case in discovered[module.id]:
                require(case.id not in owners, 'test belongs to multiple modules: ' + case.id)
                owners[case.id] = module.id
        python_cases = {f'python/{module.id}': module.id for module in modules if module.python}
        inventory = {'runId': run_id, 'buildSeconds': round(builds.elapsed, 3),
                     'dependencies': {module.id: {'postgres': module.postgres, 'fixtures': list(module.fixtures), 'exclusive': module.exclusive} for module in modules},
                     'modules': {name: [case.id for case in cases] +
                                 ([f'python/{name}'] if MODULES[name].python else [])
                                 for name, cases in discovered.items()}}
        publish(directory / 'discovery.json', inventory)
        if selected_case:
            require(selected_case in owners or selected_case in python_cases,
                    'unknown CASE in selected modules: ' + selected_case)
            owner = owners.get(selected_case, python_cases.get(selected_case))
            modules = [MODULES[owner]]
            discovered = {owner: [case for case in discovered[owner] if case.id == selected_case]}
        if listing:
            print(json.dumps(inventory, indent=2), flush=True)
            return {name: stage_result('skipped', reason='list-only') for name in MODULES}
        from t2_fixtures import RunFixtures
        with RunFixtures(builds, directory) as fixtures:
            fixtures.prepare(modules)
            def execute(module):
                started = time.monotonic()
                module_dir = directory / module.id
                module_dir.mkdir()
                cases = {}
                def scenario(case):
                    key = case.key if case else 'python'
                    case_id = case.id if case else 'python/' + module.id
                    case_dir = module_dir / key
                    case_dir.mkdir()
                    begin = time.monotonic()
                    try:
                        require(not processes.cancelled.is_set(), 'T2 cancelled')
                        if module.exclusive:
                            fixtures.reset()
                        with fixtures.scenario(module, case_dir) as fixture:
                            prepared = time.monotonic()
                            if case:
                                builds.execute(case, fixture.env, case_dir)
                            elif module.python == 'gateway':
                                importlib.import_module('t2_modules.gateway').main(fixtures)
                            else:
                                importlib.import_module('t2_modules.' + module.python).execute(fixture)
                            executed = time.monotonic()
                        end = time.monotonic()
                        cases[case_id] = stage_result('passed', begin,
                            setupSeconds=round(prepared-begin, 3), testSeconds=round(executed-prepared, 3),
                            cleanupSeconds=round(end-executed, 3), startedMonotonic=begin, endedMonotonic=end,
                            log=str(case_dir.relative_to(output)))
                    except BaseException as error:
                        (case_dir / 'failure.log').write_text(traceback.format_exc())
                        cases[case_id] = stage_result('failed', begin, reason=type(error).__name__,
                            startedMonotonic=begin, endedMonotonic=time.monotonic(), log=str(case_dir.relative_to(output)))
                    print(f'T2 {module.id}: {cases[case_id]["status"]} {case_id}', flush=True)
                for case in discovered[module.id]:
                    scenario(case)
                if module.python and (not selected_case or selected_case == 'python/' + module.id):
                    scenario(None)
                require(bool(cases), 'module executed no cases: ' + module.id)
                outcome = stage_result('failed' if any(r['status'] == 'failed' for r in cases.values()) else 'passed',
                                       started, cases=cases, runId=run_id)
                publish(module_dir / 'result.json', outcome)
                return outcome
            normal = [module for module in modules if not module.exclusive]
            with ThreadPoolExecutor(max_workers=jobs) as executor:
                futures = {executor.submit(execute, module): module.id for module in normal}
                for future in as_completed(futures):
                    results[futures[future]] = future.result()
            # The normal phase is fully drained before a global PG fault can run.
            for module in modules:
                if module.exclusive:
                    results[module.id] = execute(module)
            publish(directory / 'resources.json', dict(fixtures.counts))
        require(not processes.cancelled.is_set(), 'T2 cancelled')
        publish(directory / 'result.json', {'runId': run_id, 'modules': results})
        return results
    except BaseException as error:
        (directory / 'failure.log').write_text(traceback.format_exc())
        publish(directory / 'result.json', {'runId': run_id, 'status': 'failed',
                'reason': type(error).__name__, 'log': str((directory / 'failure.log').relative_to(output))})
        raise
    finally:
        processes.close()
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--module', default='affected')
    parser.add_argument('--base', default=os.environ.get('CI_BASE', 'origin/develop'))
    parser.add_argument('--jobs', type=int, default=2)
    parser.add_argument('--case', default='')
    parser.add_argument('--list', nargs='?', const='1', choices=('0', '1'), default='0')
    arguments = sys.argv[1:] if argv is None else argv
    if any(arg == '--suite' or arg.startswith('--suite=') for arg in arguments):
        parser.error('--suite was removed; use --module')
    args = parser.parse_args(arguments)
    if 'SUITE' in os.environ:
        parser.error('SUITE was removed; use MODULE')
    if args.module not in ('affected', 'all', *MODULES):
        parser.error('unknown MODULE; available: ' + ', '.join(sorted(MODULES)))
    if args.jobs < 1:
        parser.error('JOBS must be positive')
    require_lease(ROOT)
    import ci
    output = ROOT / 'artifacts/local-t2'
    require(not output.is_symlink(), 'T2 output directory cannot be a symlink')
    output.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    try:
        source = ci.working_source_state()
        if args.module == 'affected':
            head = ci.command(['/usr/bin/git', 'rev-parse', 'HEAD']).stdout.strip()
            selection = ci.select_impact(head, base=args.base)
        else:
            selection = {'t2Full': args.module == 'all', 'modules': select_modules(args.module, {})}
        names = select_modules(args.module, selection)
        results = run_modules(names, output, jobs=args.jobs, selected_case=args.case, listing=args.list == '1')
        require(ci.working_source_state() == source, 'source changed during T2')
        status = ('failed' if any(item['status'] == 'failed' for item in results.values()) else
                  'skipped' if not names or args.list == '1' else 'passed')
        evidence = {'module': args.module, 'selection': selection, 'status': status, 'modules': results}
        if not names:
            evidence['reason'] = 'no-modules-selected'
        publish(output / ('list.json' if args.list == '1' else 'result.json'), evidence)
        return int(status == 'failed')
    except BaseException as error:
        publish(output / ('list.json' if args.list == '1' else 'result.json'),
                {'status': 'failed', 'module': args.module, 'execution': stage_result('failed', started, reason=type(error).__name__)})
        raise


if __name__ == '__main__':
    sys.exit(main())
