"""One static registry for T2 execution and non-Cargo input selection."""
from dataclasses import dataclass
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
@dataclass(frozen=True)
class Suite:
    module: str
    tools: tuple[str,...] = ('cargo','docker','openssl')

SUITES={name:Suite('product') for name in ('installation','foundation','windows','assets','compliance','commands','tasks','software','apple','identity','catalog')}
SUITES.update({name:Suite(name) for name in ('management','group','backend','publication','sources','gateway')})
SUITES['sources']=Suite('sources',('cargo','openssl','/usr/bin/git'))
SUITES['apple']=Suite('product',('cargo','docker','openssl','go'))
SUITES['gateway']=Suite('gateway',('docker',))
# Direct source ownership, independent of the larger Cargo reverse dependency closure.
OWNERS={
 'group':('group','management','compliance'), 'group-postgres':('group','management','compliance'),
 'policy':('backend','management'), 'policy-postgres':('backend','management'),
 'resource':('backend','management','publication'), 'resource-postgres':('backend','management','publication'),
 'software-release':('backend','publication','software'), 'software-release-postgres':('backend','publication','software'),
 'backend-postgres-support':('backend','management','publication'),
 'software-service':('publication','software','catalog'), 'winget-source':('sources','publication'), 'brew-source':('sources','publication'),
 'compliance':('compliance',), 'compliance-postgres':('compliance',),
 'inventory':('foundation','assets','management'), 'inventory-postgres':('foundation','assets','management'),
 'windows-mdm':('windows','commands'), 'agent-wire':('commands','tasks'), 'scope':tuple(SUITES),
 'audit-integration':tuple(SUITES), 'examples':tuple(SUITES),
}
APP={
 'apple':('apple',),'windows':('windows','commands'),'planning':('management','publication','compliance'),
 'execution':('commands','tasks','catalog'),'task_signing':('tasks',),'inventory_runtime':('foundation','assets','management'),
 'device':('foundation','windows','apple'),'flow':('management','publication','software','catalog'),
 'content':('software','publication','catalog'),'compliance':('compliance',),'assets':('assets','management'),
}
TOOL_INPUTS={
 'hack/apple_tools.py':('test_apple_tools',), 'fixtures/apple-tools.lock.json':('test_apple_tools',),
 'hack/build_run.py':('test_build_run','test_build_environment'),
 'hack/ci.py':('test_ci','test_ci_selection'), 'hack/ci-impact.py':('test_ci_impact','test_ci_selection'),
 'hack/ci_registry.py':('test_t2_runner','test_ci_selection','test_ci_impact'),
 'hack/t2.py':('test_t2_runner','test_t2_guards'),
 'hack/t2_environment.py':('test_t2_environment','test_t2_runner'),
 'hack/auth_t3.py':('test_auth_t3',),'hack/auth_t3_browser.mjs':('test_auth_t3',),
 'hack/release.py':('test_release',),'hack/candidate_runtime.py':('test_candidate_smoke',),
 'hack/candidate_smoke.py':('test_candidate_smoke',),
 'hack/agent_wire_compat.py':('test_agent_wire_compat',),
}

def all_tools(): return sorted(p.stem for p in (ROOT/'tests').glob('test_*.py'))

def select_paths(paths):
    suites=set(); tests=set(); reasons=set()
    for path in paths:
        bits=path.split('/')
        if path.startswith('docs/') or path.endswith('.md') or path in ('LICENSE','.gitignore'):continue
        if path.startswith('tests/test_') and path.endswith('.py'):
            tests.add(Path(path).stem);continue
        if path in TOOL_INPUTS:
            tests.update(TOOL_INPUTS[path])
            if path in ('hack/build_run.py','hack/ci.py','hack/ci-impact.py','hack/ci_registry.py','hack/t2.py','hack/t2_environment.py'):
                suites.update(SUITES)
            elif 'apple' in path:suites.add('apple')
            continue
        if path.startswith('hack/t2_suites/'):
            module=Path(path).stem
            suites.update(name for name,suite in SUITES.items() if suite.module==module)
            tests.update(('test_t2_guards','test_t2_runner','test_t2_environment'))
            if module=='__init__':suites.update(SUITES)
            continue
        if path.startswith('crates/') and len(bits)>2:
            crate=bits[1]
            if crate=='app':
                module=Path(bits[3]).stem if len(bits)>3 and bits[2]=='src' else ''
                suites.update(APP.get(module,tuple(SUITES)))
            else:suites.update(OWNERS.get(crate,tuple(SUITES)))
            # Structural tests inspect Rust/SQL inputs outside Python import edges.
            if crate=='app':tests.update(('test_access_structure','test_foundation_boundaries','test_flow_boundaries','test_audit_surface','test_software_ownership','test_auth_t3'))
            if crate in ('policy-postgres','resource-postgres','software-release-postgres','backend-postgres-support'):tests.add('test_backend_support')
            if crate=='software-service':tests.update(('test_software_ownership','test_flow_boundaries','test_audit_surface'))
            if crate=='windows-mdm':tests.add('test_ddf')
            if crate=='agent-wire':tests.add('test_agent_wire_compat')
            continue
        if path.startswith('tests/inventory-postgres-integration/'):
            suites.add('foundation');continue
        if path.startswith('fixtures/') or path.startswith('deployment/'):
            suites.update(SUITES);tests.update(all_tools());reasons.add('shared-fixture');continue
        suites.update(SUITES);tests.update(all_tools());reasons.add('unknown-or-global-input:'+path)
    return sorted(suites),sorted(tests),sorted(reasons)

def execute(name):
    import importlib
    suite=SUITES[name]
    module=importlib.import_module('t2_suites.'+suite.module)
    if suite.module=='product':return module.execute(name)
    if name=='gateway':
        import json
        return module.verify(json.loads((ROOT/'deployment/providers.lock.json').read_text())['nginx'])
    return module.main()
