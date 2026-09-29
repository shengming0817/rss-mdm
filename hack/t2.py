#!/usr/bin/env python3
"""One public module executor. Discovery, selection and evidence share one owner."""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from contextvars import copy_context
from dataclasses import replace
import json
import os
import re
from pathlib import Path
import shutil
import signal
import sys
import time
import traceback
import uuid

from build_run import require_lease
from t2_registry import ROOT, MODULES, resolve_cases
from t2_execution import Builds, Processes, Invocation, CASE_TIMEOUT
from t2_processes import diagnostic_phase, diagnostics
from verification_result import result as stage_result, publish, require


MAX_RETAINED_RUNS = 5
RUN_ID = re.compile(r'[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}')


def prune_runs(output, current=None):
    """Bound only this entry point's proven records; never follow directory symlinks.

    ref: https://nexte.st/docs/features/record-replay-rerun/managing-runs/
    """
    def read(path):
        if path.is_symlink():
            return {}
        try:
            return json.loads(path.read_text())
        except (OSError, ValueError):
            return {}
    def references(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key == 'runId' and isinstance(item, str):
                    yield item
                else:
                    yield from references(item)
        elif isinstance(value, list):
            for item in value:
                yield from references(item)
    owned = []
    for directory in output.iterdir():
        if directory.is_symlink() or not directory.is_dir() or not RUN_ID.fullmatch(directory.name):
            continue
        for record in ('run.json', 'result.json', 'discovery.json'):
            value = read(directory / record)
            if isinstance(value, dict) and value.get('runId') == directory.name:
                owned.append(directory)
                break
    protected = {current} | set(references(read(output/'result.json'))) | set(references(read(output/'list.json')))
    protected &= {directory.name for directory in owned}
    require(len(protected) <= MAX_RETAINED_RUNS, 'result references exceed T2 retention limit')
    recent = sorted((directory for directory in owned if directory.name not in protected),
                    key=lambda directory: (directory.stat().st_mtime_ns, directory.name), reverse=True)
    for directory in recent[MAX_RETAINED_RUNS-len(protected):]:
        shutil.rmtree(directory)


class RunFailure(RuntimeError):
    def __init__(self, message, evidence):
        super().__init__(message)
        self.evidence = evidence


def module_choices():
    return ('affected', 'all', *sorted(MODULES))


def select_modules(module, selection):
    if module == 'all':
        return sorted(MODULES)
    if module == 'affected':
        return sorted(MODULES) if selection['t2Full'] else sorted(selection['modules'])
    if module not in MODULES:
        raise ValueError('unknown MODULE; available: ' + ', '.join(module_choices()))
    return [module]


def dispatch(invocations, execute, processes, jobs):
    """Submit only runnable cases: a waiting fault never occupies a worker slot."""
    pending = list(invocations)
    running = {}
    with ThreadPoolExecutor(max_workers=jobs) as executor:
        while pending or running:
            fault_active = any(job.module.db_mode == 'instance' for job in running.values())
            while pending and len(running) < jobs and not processes.cancelled.is_set():
                index = next((i for i, job in enumerate(pending)
                              if job.module.db_mode != 'instance' or not fault_active), None)
                if index is None:
                    break
                job = pending.pop(index)
                fault_active |= job.module.db_mode == 'instance'
                running[executor.submit(copy_context().run, execute, job)] = job
            if not running:
                for job in pending:
                    yield job, stage_result('failed', reason='cancelled-before-start', policy=job.policy,
                                            caseId=job.id, invocationId=job.key, startedMonotonic=None,
                                            endedMonotonic=time.monotonic())
                break
            done, _ = wait(running, return_when=FIRST_COMPLETED)
            for future in done:
                job = running.pop(future)
                yield job, future.result()


def reuse_phases(invocations, plan):
    """Fixed qualification, using actual discovered cases rather than a second roster."""
    require(isinstance(plan, dict) and set(plan) == {'objects', 'tenants'}, 'reuse plan requires objects and tenants')
    require(all(isinstance(v, list) and len(v) == 2 and all(isinstance(x, str) for x in v)
                for v in plan.values()), 'reuse plan needs two case IDs per observation scope')
    ids = plan['objects'] + plan['tenants']
    available = {job.id: job for job in invocations}
    require(len(set(ids)) == 4 and all(name in available for name in ids), 'reuse plan includes duplicate or undiscovered cases')
    selected = [available[name] for name in ids]
    require(all(job.case and job.module.db_mode == 'reuse' for job in selected)
            and len({job.module.profile for job in selected}) == 1, 'reuse qualification requires one compatible profile')
    require(all(job.module.scope == 'objects' for job in selected[:2])
            and all(job.module.scope in ('tenant', 'pair') for job in selected[2:]), 'reuse observation scopes differ from plan')
    a, b, c, d = selected
    phases, occurrences = [], {}
    for group in ([a], [b], [a], [b], [a], [b], [a, b], [c, d]):
        phase = []
        for job in group:
            invocation = occurrences.get(job.id, 0)
            phase.append(replace(job, invocation=invocation))
            occurrences[job.id] = invocation + 1
        phases.append(phase)
    return phases


def verify_reuse_phase(outcomes, anchor, scope=None):
    for value in outcomes:
        environment = value['environment']
        require(value['status'] == 'passed', 'reuse qualification case failed')
        require(anchor[2] is not None and tuple(environment[k] for k in ('pg', 'pgGeneration', 'database')) == anchor,
                'reuse qualification changed its physical database')
    if scope:
        require(max(x['executionStartedMonotonic'] for x in outcomes) < min(x['executionEndedMonotonic'] for x in outcomes),
                'reuse qualification executions did not overlap')
        tenants = {x['environment']['tenant'] for x in outcomes}
        require(len(tenants) == (1 if scope == 'objects' else 2), 'reuse qualification tenant scope mismatch')


def execute_case(job, builds, fixtures, case_dir, output, rendezvous=None):
    (case_dir / 'test.log').write_text('Case preparation started; execution output follows when ready.\n')
    begin = time.monotonic()
    receipt = dict(environment=fixtures.evidence(job))
    common = dict(caseId=job.id, invocationId=job.key, policy=job.policy,
                  startedMonotonic=begin, timeoutSeconds=CASE_TIMEOUT,
                  log=str((case_dir / 'test.log').relative_to(output)),
                  fixtureLog=str((case_dir / 'fixture.log').relative_to(output)))
    try:
        require(not builds.processes.cancelled.is_set(), 'T2 cancelled')
        with fixtures.scenario(job, case_dir, receipt) as fixture:
            if rendezvous is not None:
                fixture.env['MDM_CASE_RENDEZVOUS'] = str(rendezvous)
            with diagnostic_phase('execution'):
                common['executionStartedMonotonic'] = time.monotonic()
                if job.case:
                    builds.execute(job.case, fixture.env, case_dir)
                else:
                    builds.execute_python(job.module, fixture, case_dir)
                common['executionEndedMonotonic'] = time.monotonic()
        result = stage_result('passed', begin, **common)
    except BaseException as error:
        (case_dir / 'failure.log').write_text('Fixture diagnostics: fixture.log\n' + traceback.format_exc())
        result = stage_result('failed', begin, **common,
                              reason=type(error).__name__,
                              failureLog=str((case_dir / 'failure.log').relative_to(output)))
        print(f'T2 failure output: {case_dir / "test.log"}; traceback: {case_dir / "failure.log"}', flush=True)
    end = time.monotonic()
    cleaned = receipt.get('cleaned', end)
    cleanup = receipt.get('cleanupStarted', cleaned)
    prepared = receipt.get('prepared', cleanup)
    result.update(environment=receipt['environment'], endedMonotonic=end,
                  setupSeconds=round(prepared-begin, 3), testSeconds=round(cleanup-prepared, 3),
                  cleanupSeconds=round(cleaned-cleanup, 3))
    print(f'T2 {job.module.id}: {result["status"]} {job.id}', flush=True)
    return result


def run_modules(names, output, *, jobs=2, selected_case='', listing=False, reuse_plan=None):
    require_lease(ROOT)
    require(type(jobs) is int and jobs > 0, 'JOBS must be a positive integer')
    require(not output.is_symlink(), 'T2 output directory cannot be a symlink')
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    results = {name: stage_result('skipped', reason='not-selected') for name in MODULES}
    if not names:
        require(not selected_case and reuse_plan is None, 'CASE or reuse plan does not belong to any selected module')
        prune_runs(output)
        return results
    run_id = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + uuid.uuid4().hex[:8]
    directory = output / run_id
    directory.mkdir()
    publish(directory / 'run.json', {'runId': run_id})
    prune_runs(output, run_id)
    modules = [MODULES[name] for name in names]
    processes = Processes()
    previous = {}
    qualification = []
    def cancel(number, frame):
        processes.cancel()
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
        previous[sig] = signal.signal(sig, cancel)
    try:
        for module in modules:
            tools = (('python3', 'cargo', 'cargo-nextest') if module.build else ('python3',)) if listing else module.tools
            missing = [tool for tool in tools if not shutil.which(tool)]
            require(not missing, 'missing dependencies for ' + module.id + ': ' + ', '.join(missing))
        builds = Builds(directory, processes)
        builds.prepare(modules)
        discovered = {module.id: builds.discover(module) if module.build else [] for module in modules}
        owners = {}
        for module in modules:
            for case in discovered[module.id]:
                require(case.id not in owners, 'test belongs to multiple modules: ' + case.id)
                owners[case.id] = module.id
        invocations = []
        for module in modules:
            cases = [*discovered[module.id], *([None] if module.python else [])]
            case_names = [case.name if case else 'python/' + module.id for case in cases]
            policies = resolve_cases(module, case_names)
            invocations.extend(Invocation(policy, case) for policy, case in zip(policies, cases))
        phases = [invocations]
        if reuse_plan is not None:
            require(not selected_case and not listing, 'reuse plan cannot be combined with CASE or LIST')
            require(jobs >= 2, 'reuse qualification needs JOBS >= 2')
            phases = reuse_phases(invocations, reuse_plan)
            invocations = [job for phase in phases for job in phase]
        inventory = {'runId': run_id, 'buildSeconds': round(builds.elapsed, 3),
                     'modules': {module.id: [job.id for job in invocations if job.module.id == module.id]
                                 for module in modules},
                     'policies': {job.id: job.policy for job in invocations}}
        publish(directory / 'discovery.json', inventory)
        if selected_case:
            require(selected_case in inventory['policies'], 'unknown CASE in selected modules: ' + selected_case)
            invocations = [job for job in invocations if job.id == selected_case]
            phases = [invocations]
        if listing:
            print(json.dumps(inventory, indent=2), flush=True)
            results.update({job.module.id: stage_result('skipped', reason='list-only') for job in invocations})
            return results
        from t2_fixtures import RunFixtures
        from t2_database import measure
        fixtures = RunFixtures(builds, directory, jobs)
        try:
            with diagnostics(directory / 'fixture.log'), fixtures:
                with measure(fixtures.costs, 'run-prepare'):
                    fixtures.prepare(invocations)
                completed = {}
                started = time.monotonic()
                anchor = None
                for index, phase in enumerate(phases):
                    rendezvous = None
                    if reuse_plan is not None and len(phase) == 2:
                        rendezvous = directory / ('rendezvous-' + str(index))
                        rendezvous.mkdir()
                        publish(rendezvous / 'participants.json', [job.key for job in phase])
                    def execute(job):
                        case_dir = directory / job.module.id / job.key
                        case_dir.mkdir(parents=True)
                        with diagnostics(case_dir / 'fixture.log'):
                            return execute_case(job, builds, fixtures, case_dir, output, rendezvous)
                    outcomes = []
                    for job, outcome in dispatch(phase, execute, processes, jobs):
                        outcome.setdefault('environment', fixtures.evidence(job))
                        completed.setdefault(job.module.id, {})[job.key] = outcome
                        publish(directory / job.module.id / job.key / 'result.json', outcome)
                        outcomes.append(outcome)
                    if reuse_plan is not None:
                        if anchor is None:
                            anchor = tuple(outcomes[0]['environment'][k] for k in ('pg', 'pgGeneration', 'database'))
                        scope = ('objects' if index == 6 else 'tenants') if rendezvous else None
                        verify_reuse_phase(outcomes, anchor, scope)
                        if rendezvous:
                            require(all((rendezvous / job.key).is_file() for job in phase),
                                    'Rust cases did not reach the qualification rendezvous')
                        qualification.append(dict(phase=index, scope=scope, invocations=[job.key for job in phase],
                                                  database=anchor[2], pg=anchor[0], pgGeneration=anchor[1], status='passed'))
                        publish(directory / 'reuse.json', dict(status='running', plan=reuse_plan, phases=qualification))
                for name, cases in completed.items():
                    outcome = stage_result('failed' if any(r['status'] == 'failed' for r in cases.values()) else 'passed',
                                           started, cases=cases, runId=run_id)
                    publish(directory / name / 'result.json', outcome)
                    results[name] = outcome
        finally:
            publish(directory / 'resources.json', fixtures.costs.snapshot())
        require(not processes.cancelled.is_set(), 'T2 cancelled')
        if reuse_plan is not None:
            publish(directory / 'reuse.json', dict(status='passed', plan=reuse_plan, phases=qualification))
        publish(directory / 'result.json', {'runId': run_id, 'modules': results})
        return results
    except BaseException as error:
        if reuse_plan is not None:
            publish(directory / 'reuse.json', dict(status='failed', plan=reuse_plan, phases=qualification))
        (directory / 'failure.log').write_text(traceback.format_exc())
        failure = {'runId': run_id, 'status': 'failed', 'reason': type(error).__name__,
                   'log': str((directory / 'failure.log').relative_to(output))}
        if (directory / 'fixture.log').exists():
            failure['fixtureLog'] = str((directory / 'fixture.log').relative_to(output))
        publish(directory / 'result.json', failure)
        raise RunFailure(str(error), failure) from error
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
    parser.add_argument('--reuse-plan', type=Path)
    parser.add_argument('--list', nargs='?', const='1', choices=('0', '1'), default='0')
    arguments = sys.argv[1:] if argv is None else argv
    if any(arg == '--suite' or arg.startswith('--suite=') for arg in arguments):
        parser.error('--suite was removed; use --module')
    args = parser.parse_args(arguments)
    if 'SUITE' in os.environ:
        parser.error('SUITE was removed; use MODULE')
    if args.module not in module_choices():
        parser.error('unknown MODULE; available: ' + ', '.join(module_choices()))
    if args.jobs < 1:
        parser.error('JOBS must be positive')
    require_lease(ROOT)
    import ci
    output = ROOT / 'artifacts/local-t2'
    require(not output.is_symlink(), 'T2 output directory cannot be a symlink')
    output.mkdir(parents=True, exist_ok=True)
    result_path = output / ('list.json' if args.list == '1' else 'result.json')
    result_path.unlink(missing_ok=True)
    started = time.monotonic()
    try:
        source = ci.working_source_state()
        if args.module == 'affected':
            head = ci.command(['/usr/bin/git', 'rev-parse', 'HEAD']).stdout.strip()
            selection = ci.select_impact(head, base=args.base)
        else:
            selection = {'t2Full': args.module == 'all', 'modules': select_modules(args.module, {})}
        names = select_modules(args.module, selection)
        results = run_modules(names, output, jobs=args.jobs, selected_case=args.case, listing=args.list == '1',
                              reuse_plan=json.loads(args.reuse_plan.read_text()) if args.reuse_plan else None)
        require(ci.working_source_state() == source, 'source changed during T2')
        status = ('failed' if any(item['status'] == 'failed' for item in results.values()) else
                  'skipped' if not names or args.list == '1' else 'passed')
        evidence = {'module': args.module, 'selection': selection, 'status': status, 'modules': results}
        if not names:
            evidence['reason'] = 'no-modules-selected'
        publish(result_path, evidence)
        return int(status == 'failed')
    except BaseException as error:
        publish(result_path,
                {'status': 'failed', 'module': args.module, 'execution': error.evidence if isinstance(error, RunFailure) else stage_result('failed', started, reason=type(error).__name__)})
        raise


if __name__ == '__main__':
    sys.exit(main())
