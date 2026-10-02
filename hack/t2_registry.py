"""Test modules own execution, integration inputs and fixture requirements.

Rust test names come from the built target, never from a second test roster.
ref: meilisearch tests/integration.rs@909ef7fef5ba264dc914c4778d6328c5edca5ca7
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from fnmatch import fnmatchcase
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True, order=True)
class Build:
    package: str
    kind: str = 'lib'
    target: str = ''
    features: tuple[str, ...] = ()

    def cargo_args(self):
        args = ['--locked', '-p', self.package]
        args += ['--lib'] if self.kind == 'lib' else ['--' + self.kind, self.target]
        if self.features:
            args += ['--features', ','.join(self.features)]
        return args


APP = Build('rss-mdm-app', features=('integration',))


@dataclass(frozen=True)
class CasePolicy:
    selector: str
    db_mode: str | None
    scope: str | None
    fixtures: tuple[str, ...] | None = None

    def matches(self, name):
        return name.startswith(self.selector) if self.selector.endswith('::') else name == self.selector


@dataclass(frozen=True)
class Module:
    id: str
    build: Build | None
    selectors: tuple[str, ...]
    profile: str = 'product'
    fixtures: tuple[str, ...] = ()
    production_inputs: tuple[str, ...] = ()
    test_inputs: tuple[str, ...] = ()
    support_inputs: tuple[str, ...] = ()
    db_mode: str | None = 'reuse'
    scope: str | None = 'objects'
    policies: tuple[CasePolicy, ...] = ()
    python: str | None = None
    children: tuple[str, ...] = ()
    expected_cases: int | None = None

    @property
    def postgres(self):
        return self.profile != 'none'

    @property
    def tools(self):
        result = {'python3'}
        if self.build:
            result.update(('cargo', 'cargo-nextest'))
        if self.postgres or 'gateway' in self.fixtures or 'idp' in self.fixtures:
            result.add('docker')
        if self.postgres or set(self.fixtures) & {'tls', 'windows', 'apple', 'scep', 'apns'}:
            result.add('openssl')
        if 'homebrew' in self.fixtures:
            result.add('brew')
        if 'git' in self.fixtures:
            result.add('/usr/bin/git')
        if set(self.fixtures) & {'scep', 'oracle'}:
            result.add('go')
        return tuple(sorted(result))

    def includes(self, test):
        return any(not item or (test.startswith(item) if item.endswith('::') else test == item)
                   for item in self.selectors)



def resolve_cases(module, names):
    """Resolve the discovered set before selection, so stale exceptions never disappear."""
    for policy in module.policies:
        if not any(policy.matches(name) for name in names):
            raise ValueError('stale case policy: ' + module.id + ': ' + policy.selector)
    resolved = []
    for name in names:
        matches = [policy for policy in module.policies if policy.matches(name)]
        if len(matches) > 1:
            raise ValueError('overlapping case policies: ' + module.id + ': ' + name)
        value = module
        if matches:
            policy = matches[0]
            value = replace(module, db_mode=policy.db_mode, scope=policy.scope,
                            fixtures=module.fixtures if policy.fixtures is None else policy.fixtures)
        if value.profile == 'none':
            valid = value.db_mode is None and value.scope is None
        else:
            valid = (value.db_mode in {'reuse', 'fresh', 'instance'} and
                     value.scope in {'objects', 'tenant', 'pair'} and
                     (value.profile != 'empty' or value.db_mode == 'fresh'))
        if not valid:
            raise ValueError('invalid database policy: ' + module.id + ': ' + name)
        if ('local_worker' in value.fixtures and value.db_mode == 'reuse' and value.scope == 'objects'
                or {'local_worker', 'shared_worker'} <= set(value.fixtures)):
            raise ValueError('conflicting consumer ownership: ' + module.id + ': ' + name)
        resolved.append(replace(value, policies=()))
    return resolved

# One fixture-owned preparation target. Names are discovered, not copied here.
IDENTITY_SETUP = Module('identity-setup', APP, ('test_support::identity::',), expected_cases=1)

MODULES: dict[str, Module] = {}


def add(name, *, build=APP, selectors=(), profile='product', fixtures=(),
        sources=(), tests=(), support=(), python=None, children=()):
    if name in MODULES:
        raise ValueError('duplicate module: ' + name)
    if build is not None and not selectors:
        raise ValueError('module must select a target or Rust namespace: ' + name)
    MODULES[name] = Module(name, build, tuple(selectors), profile, tuple(fixtures),
                          tuple(sources), tuple(tests), tuple(support),
                          db_mode=None if profile == 'none' else 'reuse',
                          scope=None if profile == 'none' else 'objects', python=python, children=tuple(children))


CAPABILITY_INPUTS = {'identity.local': ('crates/app/src/identity.rs',),
 'identity.sso': ('crates/app/src/identity.rs',),
 'authorization.rules': ('crates/authorization-service/src/store.rs',
                         'crates/authorization-service/src/evaluate.rs',
                         'crates/authorization-service/src/model.rs'),
 'authorization.membership': ('crates/authorization-service/src/store.rs',
                              'crates/authorization-service/src/authority.rs'),
 'authorization.capacity': ('crates/authorization-service/src/store.rs',
                            'crates/authorization-service/src/authority.rs'),
 'authorization.initialization': ('crates/authorization-service/src/initialization.rs',),
 'authorization.admission': ('crates/authorization-service/src/access-contract.json',),
 'enrollment.http': ('crates/management-http/src/enrollment/http.rs',
                     'crates/registration-service/src/enrollment/read.rs'),
 'enrollment.recovery': ('crates/registration-service/src/enrollment/store.rs',),
 'device.binding': ('crates/registration-service/src/device.rs',
                    'crates/registration-service/src/device/store.rs'),
 'device.revocation': ('crates/registration-service/src/device.rs',
                       'crates/app/src/registration_lifecycle.rs'),
 'device.recovery': ('crates/registration-service/src/device/store.rs',),
 'device.admission': ('crates/registration-service/src/access-contract.json',),
 'agent.registration': ('crates/agent-channel/src/lib.rs',),
 'agent.reports': ('crates/agent-channel/src/lib.rs',),
 'assets.http': ('crates/management-http/src/assets/http.rs', 'crates/inventory-service/src/assets/store.rs'),
 'assets.queries': ('crates/inventory-service/src/assets/query*.rs',
                    'crates/inventory-service/src/assets/filter.rs'),
 'assets.sources': ('crates/inventory-service/src/assets/store.rs',
                    'crates/inventory-service/src/assets/quality.rs',
                    'crates/inventory-service/src/collection/read.rs'),
 'assets.group_input': ('crates/inventory-service/src/assets/planning.rs',
                        'crates/inventory-service/src/assets/quality.rs'),
 'planning.onboarding': ('crates/flow-service/src/planning/policies/enrollment.rs', 'crates/flow-service/src/planning/policies/onboarding.rs', 'crates/inventory-service/src/collection/channel.rs', 'crates/flow-service/src/execution/actions/*', 'crates/inventory-service/src/assets/channel.rs', 'crates/agent-channel/src/lib.rs'),
 'planning.assets': ('crates/flow-service/src/planning/sources.rs',
                     'crates/flow-service/src/planning/automation/dispatch.rs',
                     'crates/inventory-service/src/assets/planning.rs'),
 'planning.scope': ('crates/flow-service/src/planning/scopes.rs',
                    'crates/flow-service/src/planning/pages/scope.rs',
                    'crates/flow-service/src/planning/automation/scopes.rs'),
 'planning.group_scope': ('crates/inventory-service/src/groups/mod.rs',
                          'crates/flow-service/src/planning/scopes.rs',
                          'crates/flow-service/src/planning/automation/groups.rs',
                          'crates/flow-service/src/planning/automation/scopes.rs'),
 'planning.policy': ('crates/flow-service/src/planning/policies/*.rs',),
 'planning.recovery': ('crates/flow-service/src/planning/storage.rs',
                       'crates/flow-service/src/planning/admission.sql',
                       'crates/flow-service/src/planning/automation/health.rs'),
 'planning.http': ('crates/management-http/src/planning/http.rs',
                   'crates/flow-service/src/planning/pages.rs',
                   'crates/management-http/src/planning/policies/http.rs'),
 'planning.agent_policy': ('crates/flow-service/src/planning/freeze_inputs.rs',
                           'crates/flow-service/src/planning/policies/mod.rs',
                           'crates/management-http/src/planning/policies/http.rs',
                           'crates/management-http/src/planning/policies/preview.rs',
                           'crates/flow-service/src/planning/policies/rerun.rs',
                           'crates/flow-service/src/planning/policies/admission.rs',
                           'crates/flow-service/src/planning/policies/storage.rs'),
 'planning.frequency': ('crates/flow-service/src/planning/policies/admission.rs',
                        'crates/flow-service/src/planning/policies/reconcile.rs'),
 'planning.remote': ('crates/flow-service/src/planning/remote_operations/*.rs',
                     'crates/flow-service/src/execution/remote.rs'),
 'planning.software': ('crates/flow-service/src/planning/policies/software.rs',
                       'crates/flow-service/src/planning/policies/mod.rs'),
 'planning.resource_archive': ('crates/flow-service/src/resource_catalog/mod.rs',
                               'crates/flow-service/src/planning/references.rs'),
 'compliance.http': ('crates/management-http/src/compliance/http.rs',
                     'crates/inventory-service/src/compliance/read.rs'),
 'compliance.evaluation': ('crates/inventory-service/src/compliance/evaluation.rs',),
 'compliance.recovery': ('crates/inventory-service/src/compliance/dispatch.rs',
                         'crates/inventory-service/src/compliance/freshness.rs'),
 'compliance.group_input': ('crates/inventory-service/src/compliance/evaluation.rs',
                            'crates/inventory-service/src/compliance/freshness.rs'),
 'execution.agent.delivery': ('crates/flow-service/src/execution/actions/agent.rs',
                              'crates/flow-service/src/execution/actions/production.rs',
                              'crates/flow-service/src/execution/actions/collection.rs'),
 'execution.agent.content': ('crates/agent-channel/src/tasks.rs',
                             'crates/management-http/src/content/http.rs'),
 'execution.agent.history': ('crates/flow-service/src/execution/actions/history.rs',),
 'execution.agent.poll': ('crates/flow-service/src/execution/actions/poll.rs',),
 'execution.agent.recovery': ('crates/flow-service/src/execution/actions/recovery.rs',),
 'execution.commands.admission': ('crates/management-http/src/execution/http.rs',
                                  'crates/flow-service/src/execution/storage.rs',
                                  'crates/flow-service/src/execution/admission.sql'),
 'execution.commands.dispatch': ('crates/flow-service/src/execution/recovery.rs',),
 'execution.commands.recovery': ('crates/flow-service/src/execution/recovery.rs',
                                 'crates/flow-service/src/execution/lifecycle.rs'),
 'execution.commands.windows': ('crates/flow-service/src/execution/native.rs',),
 'execution.commands.onboarding': ('crates/flow-service/src/planning/policies/agent_install.rs','crates/windows-mdm/src/software.rs','crates/flow-service/src/execution/agent_install.rs','crates/flow-service/src/execution/managed_registration.rs','crates/windows-channel/src/agent_collection.rs','crates/agent-channel/src/managed.rs','crates/registration-service/src/enrollment/managed.rs'),
 'execution.commands.configuration': ('crates/flow-service/src/execution/configuration.rs',
                                 'crates/flow-service/src/execution/native.rs'),
 'execution.software.offer': ('crates/flow-service/src/execution/actions/software.rs',
                              'crates/flow-service/src/execution/actions/payload.rs'),
 'execution.software.content': ('crates/agent-channel/src/tasks.rs',
                                'crates/management-http/src/content/http.rs'),
 'execution.software.recovery': ('crates/flow-service/src/execution/actions/software.rs',
                                 'crates/flow-service/src/execution/actions/recovery.rs'),
 'software.http': ('crates/management-http/src/software_catalog.rs',),
 'content.http': ('crates/management-http/src/content/http.rs', 'crates/content-service/src/upload.rs'),
 'content.mirror': ('crates/management-http/src/content/http.rs', 'crates/content-service/src/upload.rs'),
 'content.gc': ('crates/content-service/src/cleanup.rs', 'crates/content-service/src/event.rs'),
 'windows.issuance': ('crates/windows-channel/src/issuance.rs', 'crates/certificate/src/windows.rs'),
 'windows.enrollment': ('crates/windows-channel/src/lib.rs',),
 'windows.management': ('crates/windows-channel/src/management.rs',
                        'crates/windows-channel/src/protection.rs'),
 'windows.commands': ('crates/windows-channel/src/management.rs',
                      'crates/flow-service/src/execution/native.rs'),
 'windows.retention': ('crates/windows-channel/src/retention.rs',),
 'windows.limits': ('crates/app/src/native/admission.rs',)}


def app_family(owner, *, namespace=None, identity=True,
               fixtures=(), profile='product'):
    namespace = namespace or owner.replace('.', '::') + '::t2'
    test_root = namespace.replace('::t2', '').replace('::', '/')
    children = [name.rsplit('.', 1)[1] for name in CAPABILITY_INPUTS if name.rsplit('.', 1)[0] == owner]
    if not children:
        raise ValueError('missing App production inputs: ' + owner)
    for child in children:
        add(owner + '.' + child,
            selectors=(namespace + '::' + child + '::',), profile=profile,
            fixtures=(('identity',) if identity else ()) + tuple(fixtures),
            sources=CAPABILITY_INPUTS[owner + '.' + child],
            tests=(f'crates/app/tests/{test_root}/{child}.rs',
                   f'crates/app/tests/{test_root}/{child}/*'),
            support=(f'crates/app/tests/{test_root}/mod.rs',))


add('installation.migration', selectors=('migration::tests::',), profile='empty',
    sources=('crates/app/src/migration.rs',),
    tests=('crates/app/tests/migration/mod.rs',),
    python='installation', support=('hack/t2_modules/installation.py',))
add('timeline.http',fixtures=('identity',),selectors=('timeline_tests::',),sources=('crates/timeline-service/src/*','crates/timeline-service/schema/*','crates/management-http/src/timeline.rs','crates/registration-service/src/device/read.rs','crates/inventory-service/src/assets/mod.rs','crates/flow-service/src/execution/timeline.rs'),tests=('crates/app/tests/timeline/mod.rs',),support=('crates/app/tests/support/authority.rs','crates/app/tests/support/planning_http.rs','crates/app/tests/device/support.rs'))
MODULES['timeline.http']=replace(MODULES['timeline.http'],db_mode='fresh',policies=(
    CasePolicy('timeline_tests::existing_business_facts_are_queryable_over_real_http','fresh','objects',('identity','windows')),
    CasePolicy('timeline_tests::administrators_use_existing_access_and_tenant_isolation_is_preserved','fresh','pair',('identity',)),
))
for part in ('receipts', 'integrity', 'recovery', 'budget'):
    add('audit.' + part, selectors=(f'audit_integration_tests::{part}::',),
        sources=('crates/audit-integration/src/*', 'crates/audit-integration/src/budget.rs',
                 'crates/flow-service/src/transaction.rs'),
        tests=(f'crates/app/tests/audit/{part}.rs',),
        support=('crates/app/tests/audit/mod.rs',))
MODULES['audit.recovery'] = replace(MODULES['audit.recovery'], children=('audit_integration_tests::test_support::',))
app_family('identity', fixtures=())
MODULES['identity.sso'] = replace(MODULES['identity.sso'], fixtures=('identity', 'idp'))
add('identity.audit', selectors=('identity_audit::tests::',), fixtures=('identity',),
    sources=('crates/app/src/identity_audit.rs',),
    tests=('crates/app/tests/identity_audit/mod.rs',))
app_family('authorization')
for name in ('rules', 'membership', 'capacity', 'initialization', 'admission'):
    key = 'authorization.' + name
    MODULES[key] = replace(MODULES[key], support_inputs=('crates/app/tests/authorization/mod.rs',))
app_family('enrollment')
app_family('device')
for part in ('binding', 'revocation', 'recovery', 'admission'):
    key = 'device.' + part
    MODULES[key] = replace(MODULES[key], support_inputs=('crates/app/tests/device/mod.rs',))
app_family('agent')
for name in ('agent.registration', 'agent.reports'):
    MODULES[name] = replace(MODULES[name], support_inputs=(*MODULES[name].support_inputs, 'crates/app/tests/support/agent.rs'))
for name, target in (('manual', 'manual'), ('reader', 'reader')):
    add('inventory.' + name,
        build=Build('rss-mdm-inventory-postgres', 'test', target), selectors=('',),
        sources=('crates/inventory-postgres/src/*', 'crates/inventory-postgres/migrations/*'),
        tests=(f'crates/inventory-postgres/tests/{target}.rs',),
        support=('crates/inventory-postgres/tests/support/*',))
MODULES['inventory.manual'] = replace(MODULES['inventory.manual'], policies=(CasePolicy('field_catalog_cas_history_and_rollback_are_atomic','reuse','tenant'),))
for name in ('projection', 'recovery', 'process'):
    add('inventory.' + name,
        build=Build('rss-mdm-examples', features=('integration',)),
        selectors=('app::t2::' + name + '::',), fixtures=('examples',) if name == 'process' else (),
        sources=('crates/examples/src/app.rs', 'crates/inventory-postgres/src/*'),
        tests=(f'crates/examples/src/app/t2/{name}.rs',),
        support=('crates/examples/src/app/t2/mod.rs',))
add('worker.wake', selectors=('worker_wake::tests::',),
    sources=('crates/app/src/worker_wake.rs',),
    tests=('crates/app/tests/worker_wake/mod.rs',), support=())
add('inventory.runtime', selectors=('inventory_runtime::tests::',), fixtures=('identity',),
    sources=('crates/inventory-service/src/inventory_runtime.rs',),
    tests=('crates/app/tests/inventory_runtime/mod.rs',), support=())
add('examples.cli', build=Build('rss-mdm-examples', features=('integration',)),
    selectors=('app::t2::cli::',), fixtures=('examples',),
    sources=('crates/examples/src/*',),
    tests=('crates/examples/src/app/t2/cli.rs',), support=('crates/examples/src/app/t2/mod.rs',))
add('api.diagnostics', selectors=('api::tests::',),
    sources=('crates/app/src/api.rs', 'crates/app/src/diagnostic.rs',
             'crates/app/src/error_projection.rs'))
add('api.identity_context', selectors=('api::t2::identity_context::',), fixtures=('identity',),
    sources=('crates/app/src/api.rs',),
    tests=('crates/app/tests/api/identity_context.rs',))
add('diagnostics.http', selectors=('api::t2::runtime_diagnostics::',), fixtures=('identity','local_worker'),
    sources=('crates/app/src/runtime_diagnostics.rs', 'crates/management-http/src/runtime_diagnostics.rs',
             'crates/flow-service/src/execution/health.rs', 'crates/flow-service/src/execution/recovery.rs',
             'crates/inventory-service/src/inventory_runtime/diagnostics.rs',
             'crates/flow-service/src/planning/automation/health.rs'),
    tests=('crates/app/tests/api/runtime_diagnostics.rs','crates/app/tests/api/execution_health.rs',))
MODULES['diagnostics.http'] = replace(MODULES['diagnostics.http'], scope='tenant', support_inputs=('crates/app/tests/support/audit.rs','crates/app/tests/device/support.rs','crates/app/tests/inventory_runtime/support.rs','crates/app/tests/planning/support.rs'), policies=(
    CasePolicy('api::t2::runtime_diagnostics::execution_first_scan_failure_recovers_only_after_real_success', 'instance', 'tenant'),
    CasePolicy('api::t2::runtime_diagnostics::runner_failure_is_visible_while_bridge_and_queries_succeed', 'instance', 'tenant'),
))
add('host.lifecycle', build=None, python='host', fixtures=('identity',),
    sources=('crates/app/src/lifecycle.rs', 'crates/app/src/main.rs'),
    support=('hack/t2_modules/host.py',))
app_family('assets')
for name, target in (('persistence', 't2'), ('generations', 'generations')):
    add('group.' + name, build=Build('rss-mdm-group-postgres', 'test', target, ('integration',)),
        selectors=('',), profile='group',
        sources=('crates/group-postgres/src/*', 'crates/group-postgres/migrations/*'),
        tests=(f'crates/group-postgres/tests/{target}.rs',),
        support=('crates/group-postgres/tests/support/*',))
app_family('planning',
           namespace='planning::t2')
for name in ('planning.assets', 'planning.scope', 'planning.group_scope', 'planning.recovery',
             'planning.resource_archive', 'assets.http', 'audit.integrity'):
    MODULES[name] = replace(MODULES[name], support_inputs=MODULES[name].support_inputs +
                            ('crates/app/tests/planning/support.rs',))
MODULES['planning.resource_archive'] = replace(MODULES['planning.resource_archive'], fixtures=('identity', 'tls'))
MODULES['audit.integrity'] = replace(MODULES['audit.integrity'],
    test_inputs=MODULES['audit.integrity'].test_inputs + ('crates/app/tests/audit/owner_admission.rs',))
for name in ('policy', 'resource', 'software_release'):
    package = name.replace('_', '-')
    for suffix, target in (('persistence', 'behavior'), ('recovery', 'recovery')):
        add(name + '.' + suffix,
            build=Build('rss-mdm-' + package + '-postgres', 'test', target, ('integration',)),
            selectors=('',), profile='backend',
            sources=(f'crates/{package}-postgres/src/*', f'crates/{package}-postgres/migrations/*',
                     'crates/backend-postgres-support/src/*'),
            tests=(f'crates/{package}-postgres/tests/{target}.rs',),
            support=(f'crates/{package}-postgres/tests/support/*',))
add('compliance.storage', build=Build('rss-mdm-compliance-postgres', 'test', 't2'),
    selectors=('',), sources=('crates/compliance-postgres/src/*', 'crates/compliance-postgres/migrations/*'),
    tests=('crates/compliance-postgres/tests/t2.rs',),
    support=())
app_family('compliance')
app_family('execution.agent',
           namespace='execution::t2::agent')
app_family('execution.commands',
           namespace='execution::t2::commands')
for name in ('execution.commands.admission','execution.commands.dispatch','execution.commands.recovery','execution.commands.windows','execution.commands.configuration','execution.commands.onboarding'):
    MODULES[name] = replace(MODULES[name], fixtures=MODULES[name].fixtures+('windows',),
        support_inputs=MODULES[name].support_inputs+('crates/app/tests/execution/support/*', 'crates/app/tests/windows/support.rs',))
app_family('execution.software',
           namespace='execution::t2::software')
for name in ('execution.software.offer', 'execution.software.content', 'execution.software.recovery', 'planning.software'):
    MODULES[name] = replace(MODULES[name], support_inputs=MODULES[name].support_inputs +
        ('crates/app/tests/support/software_execution.rs',))
for name in ('execution.agent.delivery', 'execution.agent.content', 'execution.agent.history', 'execution.agent.poll', 'execution.agent.recovery', 'planning.agent_policy', 'planning.frequency', 'planning.remote', 'planning.onboarding'):
    MODULES[name] = replace(MODULES[name], support_inputs=MODULES[name].support_inputs +
        ('crates/app/tests/support/agent_execution.rs',))
add('software.catalog', build=Build('rss-mdm-software-service', 'test', 'catalog_t2'), selectors=('',),
    sources=('crates/software-service/src/catalog/*',),
    tests=('crates/software-service/tests/catalog_t2.rs', 'crates/software-service/tests/catalog/*'),
    support=())
app_family('software', namespace='software_catalog::t2')
app_family('content')
for name in ('content.http', 'content.mirror', 'content.gc', 'software.http'):
    MODULES[name] = replace(MODULES[name], support_inputs=MODULES[name].support_inputs +
        ('tests/support/software/*',))
MODULES['content.mirror'] = replace(MODULES['content.mirror'], fixtures=('identity', 'tls'))
for part in ('winget', 'brew', 'mapping', 'withdrawal', 'recovery', 'artifact'):
    add('publication.' + part,
        build=Build('rss-mdm-software-service', 'test', 'publication_t2'),
        selectors=(part + '::',), profile='none' if part == 'artifact' else 'product',
        fixtures=('tls', 'git') if part == 'brew' else ('tls',),
        sources=tuple('crates/software-service/src/publication/' + path for path in {
            'winget': ('artifact.rs','config.rs','driver.rs','service.rs','spec.rs','storage.rs','service.rs'),
            'brew': ('artifact.rs','config.rs','driver.rs','service.rs','spec.rs','storage.rs','service.rs'),
            'mapping': ('artifact.rs','config.rs','service.rs','spec.rs','storage.rs','service.rs','references.rs'),
            'withdrawal': ('config.rs','driver.rs','service.rs','storage.rs','service.rs'),
            'recovery': ('config.rs','driver.rs','service.rs','storage.rs','service.rs'),
            'artifact': ('artifact.rs',),
        }[part]),
        tests=(f'crates/software-service/tests/publication/{part}.rs',),
        support=('tests/support/software/*',))
add('sources.winget', build=Build('rss-mdm-winget-source', 'test', 't2_http'), selectors=('',),
    profile='none', fixtures=('tls',), sources=('crates/winget-source/src/*',),
    tests=('crates/winget-source/tests/t2_http.rs',), support=())
add('sources.brew_git', build=Build('rss-mdm-brew-source', 'test', 't2_git'), selectors=('',),
    profile='none', fixtures=('git',), sources=('crates/brew-source/src/git.rs',),
    tests=('crates/brew-source/tests/t2_git.rs',))
add('sources.brew_recovery', build=Build('rss-mdm-brew-source'),
    selectors=('git::recovery_tests::',), profile='none', fixtures=('git',),
    sources=('crates/brew-source/src/git.rs',))
add('native.tls', selectors=('native::tls::tests::',), profile='product', fixtures=('windows',),
    sources=('crates/app/src/native/*',),
    tests=('crates/app/tests/native/tls.rs',))
app_family('windows',
           fixtures=('windows',), namespace='windows::t2')
for name in ('windows.issuance','windows.enrollment','windows.management','windows.commands','windows.retention','windows.limits','execution.commands.windows','execution.commands.configuration','execution.commands.onboarding'):
    MODULES[name] = replace(MODULES[name], support_inputs=MODULES[name].support_inputs + ('crates/app/tests/windows/support.rs',))
for name in ('enrollment.recovery','windows.issuance','windows.enrollment','windows.management','windows.commands','windows.retention','windows.limits','execution.commands.admission','execution.commands.dispatch','execution.commands.recovery','execution.commands.windows','execution.commands.configuration','execution.commands.onboarding'):
    MODULES[name] = replace(MODULES[name], support_inputs=MODULES[name].support_inputs + ('crates/app/tests/enrollment/support.rs',))
for part in ('cms', 'apns', 'scep', 'collection', 'profile', 'policy', 'onboarding', 'renewal', 'identity', 'push', 'fairness', 'host'):
    no_pg = part in ('cms', 'apns')
    fixtures = ('apple',) + (() if no_pg else ('identity', 'oracle'))
    if part in ('scep', 'renewal', 'identity'):
        fixtures += ('scep',)
    if part in ('apns', 'push', 'host'):
        fixtures += ('apns',)
    selectors = {'cms': ('apple::certificate::tests::',), 'apns': ('apple::push::tests::',)}.get(part, (f'apple::tests::{part}::',))
    source = {
        'cms': ('certificate.rs',), 'apns': ('push.rs',),
        'scep': ('enrollment.rs','webhook.rs'), 'collection': ('checkin.rs','protocol.rs'),
        'profile': ('profile.rs',), 'policy': ('profile.rs','attempt.rs'),
        'onboarding': ('agent_collection.rs','flow_store.rs','checkin.rs'),
        'renewal': ('renewal.rs',), 'identity': ('checkin.rs','enrollment.rs'),
        'push': ('push.rs',), 'fairness': ('attempt.rs','protocol.rs'),
        'host': ('mod.rs','config.rs'),
    }[part]
    add('apple.' + part, selectors=selectors, profile='none' if no_pg else 'product',
        fixtures=fixtures, sources=tuple(('crates/app/src/assembly/apple/' if path in ('mod.rs','config.rs') else 'crates/certificate/src/' if path=='certificate.rs' else 'crates/apple-mdm/src/' if path in ('protocol.rs','profile.rs') else 'crates/apple-channel/src/') + ('apple.rs' if path=='certificate.rs' else path) for path in source),
        tests=(('crates/app/tests/apple/apns.rs',) if part == 'apns' else
               ('crates/app/tests/apple/cms.rs',) if part == 'cms' else (f'crates/app/tests/apple/{part}.rs',)))
add('catalog.contract', build=None, python='catalog',
    sources=('crates/*-service/src/*/catalog.sql', 'crates/*-service/src/*/catalog.json',
             'crates/software-service/src/*/catalog.sql', 'crates/software-service/src/*/catalog.json'),
    support=('hack/command_catalog.py', 'hack/t2_modules/catalog.py'))
add('gateway.admission', build=None, python='gateway', profile='none', fixtures=('gateway',),
    sources=('deployment/nginx.conf',), support=('hack/t2_modules/gateway.py',))


# Isolation follows state and observation ownership. Only exceptions name a case.
MODULES['installation.migration'] = replace(MODULES['installation.migration'], db_mode='fresh', scope='objects')
MODULES['audit.receipts'] = replace(MODULES['audit.receipts'], db_mode='reuse', scope='tenant')
MODULES['audit.integrity'] = replace(MODULES['audit.integrity'], db_mode='instance', scope='objects', policies=(
    CasePolicy('audit_integration_tests::integrity::storage_integrity_is_enforced', 'fresh', 'objects'),
))
MODULES['audit.recovery'] = replace(MODULES['audit.recovery'], db_mode='reuse', scope='tenant')
MODULES['audit.budget'] = replace(MODULES['audit.budget'], db_mode='reuse', scope='tenant')
MODULES['identity.local'] = replace(MODULES['identity.local'], db_mode='instance', scope='objects')
MODULES['identity.sso'] = replace(MODULES['identity.sso'], db_mode='reuse', scope='tenant')
MODULES['identity.audit'] = replace(MODULES['identity.audit'], db_mode='instance', scope='objects')
MODULES['authorization.rules'] = replace(MODULES['authorization.rules'], db_mode='reuse', scope='tenant', policies=(
    CasePolicy('authorization::t2::rules::capability_routes_without_application_preserve_revocation_and_atomicity', 'fresh', 'objects'),
    CasePolicy('authorization::t2::rules::enrollment_grant_does_not_authorize_wipe', 'reuse', 'objects'),
))
MODULES['authorization.membership'] = replace(MODULES['authorization.membership'], db_mode='reuse', scope='tenant')
MODULES['authorization.capacity'] = replace(MODULES['authorization.capacity'], db_mode='reuse', scope='tenant')
MODULES['authorization.initialization'] = replace(MODULES['authorization.initialization'], db_mode='reuse', scope='tenant', policies=(
    CasePolicy('authorization::t2::initialization::initialization_receipt_atomicity_and_recovery', 'fresh', 'objects'),
))
MODULES['authorization.admission'] = replace(MODULES['authorization.admission'], db_mode='instance', scope='objects')
MODULES['device.binding'] = replace(MODULES['device.binding'], db_mode='reuse', scope='pair')
MODULES['device.recovery'] = replace(MODULES['device.recovery'], db_mode='reuse', scope='objects', policies=(
    CasePolicy('device::t2::recovery::revocation_and_replacement_unknown_commit', 'fresh', 'objects'),
    CasePolicy('device::t2::recovery::bounded_bind_and_revoke_settlement', 'reuse', 'tenant'),
))
MODULES['agent.registration'] = replace(MODULES['agent.registration'], policies=(
    CasePolicy('agent::t2::registration::registration_recovery_preserves_credential_rotation', 'reuse', 'tenant'),
))
MODULES['agent.reports'] = replace(MODULES['agent.reports'], db_mode='reuse', scope='tenant')
MODULES['inventory.reader'] = replace(MODULES['inventory.reader'], db_mode='instance', scope='objects', policies=(
    CasePolicy('watermark_fence_rejects_unrelated_grantee', 'fresh', 'objects'),
))
MODULES['inventory.projection'] = replace(MODULES['inventory.projection'], db_mode='reuse', scope='pair', policies=(
    CasePolicy('app::t2::projection::unregistered_dataset_and_poison_are_rejected', 'fresh', 'objects'),
    CasePolicy('app::t2::projection::invocation_horizon', 'fresh', 'objects'),
))
MODULES['inventory.recovery'] = replace(MODULES['inventory.recovery'], db_mode='reuse', scope='tenant', policies=(
    CasePolicy('app::t2::recovery::admission_drift', 'instance', 'objects'),
))
MODULES['inventory.process'] = replace(MODULES['inventory.process'], db_mode='fresh', scope='objects')
MODULES['inventory.runtime'] = replace(MODULES['inventory.runtime'], db_mode='fresh', scope='objects')
MODULES['examples.cli'] = replace(MODULES['examples.cli'], db_mode='reuse', scope='tenant')
MODULES['api.identity_context'] = replace(MODULES['api.identity_context'], db_mode='reuse', scope='tenant')
MODULES['host.lifecycle'] = replace(MODULES['host.lifecycle'], db_mode='fresh', scope='objects')
MODULES['assets.http'] = replace(MODULES['assets.http'], db_mode='fresh', scope='objects', policies=(
    CasePolicy('assets::t2::http::storage::asset_capability_owns_execution_and_receipt_recovery', 'reuse', 'pair'),
    CasePolicy('assets::t2::http::storage::asset_commit_unknown_recovers_original_receipts', 'reuse', 'objects'),
))
MODULES['assets.queries'] = replace(MODULES['assets.queries'], db_mode='reuse', scope='tenant')
MODULES['assets.sources'] = replace(MODULES['assets.sources'], db_mode='reuse', scope='tenant')
MODULES['assets.group_input'] = replace(MODULES['assets.group_input'], db_mode='reuse', scope='tenant')
MODULES['group.persistence'] = replace(MODULES['group.persistence'], db_mode='reuse', scope='objects', policies=(
    CasePolicy('admission_rejects_catalog_and_security_drift', 'instance', 'objects'),
    CasePolicy('atomic_event_failure_rls_and_large_member_ids', 'fresh', 'objects'),
    CasePolicy('lost_commit_ack_replays_durable_result_once', 'fresh', 'objects'),
))
MODULES['planning.assets'] = replace(MODULES['planning.assets'], db_mode='reuse', scope='tenant')
MODULES['planning.scope'] = replace(MODULES['planning.scope'], db_mode='reuse', scope='tenant', policies=(
    CasePolicy('planning::t2::scope::corrupt_scope_is_a_storage_failure_not_a_client_error', 'fresh', 'objects'),
))
MODULES['planning.group_scope'] = replace(MODULES['planning.group_scope'], db_mode='reuse', scope='tenant', policies=(
    CasePolicy('planning::t2::group_scope::group_delete_scope_reference_compete_without_dangling_references', 'reuse', 'objects'),
    CasePolicy('planning::t2::group_scope::group_scope_replay_and_audit_atomicity', 'fresh', 'pair'),
))
MODULES['planning.onboarding'] = replace(MODULES['planning.onboarding'], db_mode='reuse', scope='tenant')
MODULES['planning.policy'] = replace(MODULES['planning.policy'], db_mode='reuse', scope='tenant')
MODULES['planning.recovery'] = replace(MODULES['planning.recovery'], db_mode='reuse', scope='tenant', policies=(
    CasePolicy('planning::t2::recovery::corrupt_background_query_is_not_client_input', 'fresh', 'objects'),
    CasePolicy('planning::t2::recovery::management_admission_rejects_schema_and_privilege_drift', 'instance', 'objects'),
    CasePolicy('planning::t2::recovery::rss_exhaustion_records_failed_task_and_atomic_audit', 'fresh', 'objects'),
))
MODULES['planning.http'] = replace(MODULES['planning.http'], db_mode='fresh', scope='objects')
MODULES['planning.agent_policy'] = replace(MODULES['planning.agent_policy'], db_mode='reuse', scope='objects', policies=(
    CasePolicy('planning::t2::agent_policy::policy_scan_reaches_late_match', 'reuse', 'tenant'),
    CasePolicy('planning::t2::agent_policy::preview_publish_authorization_and_commit_replay', 'reuse', 'tenant'),
    CasePolicy('planning::t2::agent_policy::script_preparation_is_shared_without_preview_effects', 'reuse', 'tenant'),
))
MODULES['planning.frequency'] = replace(MODULES['planning.frequency'], db_mode='reuse', scope='objects', policies=(
    CasePolicy('planning::t2::frequency::once_per_entry_tracks_membership_epochs', 'reuse', 'tenant'),
))
MODULES['planning.remote'] = replace(MODULES['planning.remote'], db_mode='reuse', scope='tenant')
MODULES['planning.software'] = replace(MODULES['planning.software'], db_mode='reuse', scope='objects', policies=(
    CasePolicy('planning::t2::software::rollout_time_success_gates_and_stage_evidence', 'reuse', 'tenant'),
))
MODULES['policy.persistence'] = replace(MODULES['policy.persistence'], db_mode='reuse', scope='objects', policies=(
    CasePolicy('admission_rejects_schema_and_reachable_privilege_drift', 'instance', 'objects'),
))
MODULES['policy.recovery'] = replace(MODULES['policy.recovery'], db_mode='fresh', scope='objects')
MODULES['resource.persistence'] = replace(MODULES['resource.persistence'], db_mode='instance', scope='objects', policies=(
    CasePolicy('artifact_reference_index_covers_reuse_without_another_upload_and_archive_rollback', 'reuse', 'objects'),
    CasePolicy('resource_cas_events_and_owner_admission', 'fresh', 'objects'),
    CasePolicy('resource_immutable_versions_restart_and_reference_rollback', 'reuse', 'objects'),
))
MODULES['resource.recovery'] = replace(MODULES['resource.recovery'], db_mode='fresh', scope='objects')
MODULES['software_release.persistence'] = replace(MODULES['software_release.persistence'], db_mode='reuse', scope='objects', policies=(
    CasePolicy('admission_rejects_noninherited_switchable_privileges', 'instance', 'objects'),
    CasePolicy('release_event_failure_and_runtime_admission', 'fresh', 'objects'),
))
MODULES['software_release.recovery'] = replace(MODULES['software_release.recovery'], db_mode='fresh', scope='objects')
MODULES['compliance.storage'] = replace(MODULES['compliance.storage'], db_mode='fresh', scope='objects', policies=(
    CasePolicy('immutable_versions_results_and_tenant_transactions', 'reuse', 'pair'),
))
MODULES['compliance.http'] = replace(MODULES['compliance.http'], db_mode='reuse', scope='pair')
MODULES['compliance.evaluation'] = replace(MODULES['compliance.evaluation'], db_mode='reuse', scope='tenant')
MODULES['compliance.recovery'] = replace(MODULES['compliance.recovery'], db_mode='fresh', scope='objects', policies=(
    CasePolicy('compliance::t2::recovery::mutation_unknown_commit_recovers_original_response', 'reuse', 'tenant'),
))
MODULES['compliance.group_input'] = replace(MODULES['compliance.group_input'], db_mode='reuse', scope='tenant')
MODULES['execution.agent.delivery'] = replace(MODULES['execution.agent.delivery'], db_mode='reuse', scope='tenant', policies=(
    CasePolicy('execution::t2::agent::delivery::registration_capability_and_wire_gate', 'reuse', 'objects'),
))
MODULES['execution.agent.history'] = replace(MODULES['execution.agent.history'], db_mode='reuse', scope='tenant')
MODULES['execution.agent.poll'] = replace(MODULES['execution.agent.poll'], db_mode='reuse', scope='tenant')
MODULES['execution.commands.admission'] = replace(MODULES['execution.commands.admission'], db_mode='reuse', scope='tenant', policies=(
    CasePolicy('execution::t2::commands::admission::minimum_role_scope_and_storage_admission', 'instance', 'objects'),
))
MODULES['execution.commands.dispatch'] = replace(MODULES['execution.commands.dispatch'], db_mode='reuse', scope='tenant')
MODULES['execution.commands.recovery'] = replace(MODULES['execution.commands.recovery'], db_mode='fresh', scope='objects')
MODULES['execution.commands.windows'] = replace(MODULES['execution.commands.windows'], scope='tenant')
MODULES['windows.management'] = replace(MODULES['windows.management'], scope='tenant')
MODULES['execution.commands.configuration'] = replace(MODULES['execution.commands.configuration'], db_mode='reuse', scope='tenant')
MODULES['execution.commands.onboarding'] = replace(MODULES['execution.commands.onboarding'], db_mode='reuse', scope='tenant',support_inputs=(*MODULES['execution.commands.onboarding'].support_inputs,'crates/app/tests/support/channel_onboarding.rs','crates/app/tests/support/software.rs','crates/app/tests/execution/support.rs'))
MODULES['software.catalog'] = replace(MODULES['software.catalog'], db_mode='instance', scope='objects', policies=(
    CasePolicy('transactions::dependency_admission_uses_exact_current_approval', 'reuse', 'objects'),
    CasePolicy('transactions::source_receipts_follow_the_borrowed_transaction', 'reuse', 'tenant'),
))
MODULES['software.http'] = replace(MODULES['software.http'], db_mode='reuse', scope='objects', policies=(
    CasePolicy('software_catalog::t2::http::imports::exact_rest_community_and_brew_imports_preserve_evidence_and_replay', 'fresh', 'objects', ('identity','tls')),
    CasePolicy('software_catalog::t2::http::publication::brew::immutable_native_tap_is_consumed_by_git_and_homebrew_and_withdrawn', 'fresh', 'objects', ('identity','tls','git','homebrew')),
    CasePolicy('software_catalog::t2::http::publication::publication_http_authority_receipts_and_public_native_binding', 'reuse', 'tenant', ('identity','tls','local_worker')),
))
MODULES['content.http'] = replace(MODULES['content.http'], db_mode='fresh', scope='objects')
MODULES['content.mirror'] = replace(MODULES['content.mirror'], db_mode='fresh', scope='objects')
MODULES['content.gc'] = replace(MODULES['content.gc'], db_mode='instance', scope='objects', policies=(
    CasePolicy('content::t2::gc::reference_and_gc_are_serialized', 'reuse', 'objects'),
))
MODULES['publication.winget'] = replace(MODULES['publication.winget'], db_mode='fresh', scope='objects')
MODULES['publication.brew'] = replace(MODULES['publication.brew'], db_mode='fresh', scope='objects')
MODULES['publication.mapping'] = replace(MODULES['publication.mapping'], db_mode='fresh', scope='objects')
MODULES['publication.recovery'] = replace(MODULES['publication.recovery'], db_mode='fresh', scope='objects')
MODULES['windows.issuance'] = replace(MODULES['windows.issuance'], db_mode='fresh', scope='objects')
MODULES['windows.retention'] = replace(MODULES['windows.retention'], db_mode='fresh', scope='objects')
MODULES['windows.limits'] = replace(MODULES['windows.limits'], db_mode='reuse', scope='tenant')
MODULES['apple.policy'] = replace(MODULES['apple.policy'], db_mode='reuse', scope='tenant', policies=(
    CasePolicy('apple::tests::policy::current_approval_and_deadlines', 'reuse', 'objects'),
))
MODULES['apple.onboarding'] = replace(MODULES['apple.onboarding'], db_mode='reuse', scope='tenant', fixtures=(*MODULES['apple.onboarding'].fixtures,'local_worker'), support_inputs=(*MODULES['apple.onboarding'].support_inputs,'crates/app/tests/support/channel_onboarding.rs','crates/app/tests/support/software.rs'))
MODULES['apple.renewal'] = replace(MODULES['apple.renewal'], db_mode='reuse', scope='tenant')
MODULES['apple.identity'] = replace(MODULES['apple.identity'], db_mode='reuse', scope='tenant', policies=(
    CasePolicy('apple::tests::identity::token_is_required_before_management', 'reuse', 'objects'),
))
MODULES['apple.push'] = replace(MODULES['apple.push'], db_mode='reuse', scope='tenant', policies=(
    CasePolicy('apple::tests::push::deadline_query_failure_is_not_healthy_idle', 'fresh', 'objects'),
))
MODULES['apple.fairness'] = replace(MODULES['apple.fairness'], db_mode='reuse', scope='tenant')
MODULES['apple.host'] = replace(MODULES['apple.host'], db_mode='fresh', scope='objects')

# These cases need the production consumers; precise stop/restart tests own theirs.
for name in ('assets.queries', 'assets.sources', 'assets.group_input', 'planning.http',
             'planning.policy', 'planning.agent_policy', 'planning.frequency', 'planning.remote',
             'planning.software', 'planning.onboarding', 'compliance.evaluation', 'compliance.recovery',
             'execution.agent.delivery', 'execution.agent.content', 'execution.agent.history',
             'execution.agent.poll', 'execution.agent.recovery', 'execution.software.offer',
             'execution.software.content', 'execution.software.recovery',
             'windows.enrollment', 'windows.management',
             'windows.commands', 'windows.limits'):
    MODULES[name] = replace(MODULES[name], fixtures=(*MODULES[name].fixtures, 'shared_worker'))
for name in ('compliance.http', 'compliance.group_input'):
    MODULES[name] = replace(MODULES[name], fixtures=(*MODULES[name].fixtures, 'local_worker'))


def case_fixtures(module, selector, marker):
    value = MODULES[module]
    fixtures = tuple(f for f in value.fixtures if f not in {'shared_worker', 'local_worker'})
    fixtures += (marker,) if marker else ()
    previous = next((p for p in value.policies if p.selector == selector),
                    CasePolicy(selector, value.db_mode, value.scope))
    MODULES[module] = replace(value, policies=(*[p for p in value.policies if p.selector != selector],
                                               replace(previous, fixtures=fixtures)))


case_fixtures('diagnostics.http', 'api::t2::runtime_diagnostics::execution_first_scan_failure_recovers_only_after_real_success', None)
case_fixtures('assets.http', 'assets::t2::http::manual::manual_types_replay_cas_and_rollback', 'shared_worker')
case_fixtures('planning.http', 'planning::t2::http::console_scope_ready_tracks_current_admission', 'local_worker')
case_fixtures('planning.remote', 'planning::t2::remote::bulk_pages_restart_and_cancellation_are_durable', 'local_worker')
case_fixtures('compliance.recovery', 'compliance::t2::recovery::mutation_unknown_commit_recovers_original_response', None)
case_fixtures('compliance.recovery', 'compliance::t2::recovery::rule_and_fact_revisions_fence_stale_publication', 'local_worker')
case_fixtures('execution.agent.delivery', 'execution::t2::agent::delivery::registration_capability_and_wire_gate', None)
MODULES['content.http'] = replace(MODULES['content.http'], policies=(
    CasePolicy('content::t2::http::corrupt_uploads_have_no_binding_and_new_operations_reuse_verified_content', 'reuse', 'objects'),
))

case_fixtures('execution.agent.delivery', 'execution::t2::agent::delivery::offer_start_result_replay_and_inventory_projection', 'local_worker')
for name in ('agent.reports', 'inventory.runtime', 'planning.assets', 'planning.scope',
             'planning.group_scope', 'planning.recovery', 'execution.commands.dispatch',
             'execution.commands.recovery', 'execution.commands.configuration', 'execution.commands.windows', 'execution.commands.onboarding', 'windows.retention',
             'apple.push', 'apple.fairness', 'apple.renewal', 'apple.host'):
    value = MODULES[name]
    # Local consumer controls are meaningful only in their own observation tenant.
    if value.scope == 'tenant' or value.db_mode in {'fresh', 'instance'}:
        MODULES[name] = replace(value, fixtures=(*value.fixtures, 'local_worker'))


case_fixtures('planning.group_scope', 'planning::t2::group_scope::group_delete_scope_reference_compete_without_dangling_references', None)

def consume(inputs, names):
    """The named modules test a real production path through these inputs."""
    for name in names.split():
        MODULES[name] = replace(MODULES[name], production_inputs=MODULES[name].production_inputs + tuple(inputs))


consume(('crates/content-service/src/range.rs',),
        'content.http execution.agent.content execution.software.content')
consume(('crates/content-service/src/upload.rs', 'crates/content-service/src/bundle.rs'),
        'content.http software.http')
consume(('crates/content-service/src/cleanup.rs', 'crates/content-service/src/event.rs'),
        'content.gc planning.resource_archive')
consume(('crates/brew-source/src/*',), 'publication.brew')
consume(('crates/winget-source/src/*',), 'publication.winget publication.recovery content.mirror')
consume(('crates/group/src/*', 'crates/group-postgres/src/*', 'crates/group-postgres/migrations/*'),
        'group.persistence group.generations planning.group_scope planning.scope compliance.group_input planning.frequency assets.group_input planning.http planning.policy')
consume(('crates/scope/src/*',),
        'planning.scope planning.group_scope planning.policy planning.frequency planning.remote planning.software')
consume(('crates/policy/src/*', 'crates/policy-postgres/src/*', 'crates/policy-postgres/migrations/*'),
        'policy.persistence policy.recovery planning.policy planning.agent_policy planning.frequency planning.software execution.agent.delivery execution.software.offer')
consume(('crates/resource/src/*', 'crates/resource-postgres/src/*', 'crates/resource-postgres/migrations/*'),
        'resource.persistence resource.recovery software.catalog software.http content.http content.mirror content.gc planning.policy planning.resource_archive planning.software publication.winget publication.brew publication.mapping publication.withdrawal publication.recovery')
consume(('crates/software-release/src/*', 'crates/software-release-postgres/src/*', 'crates/software-release-postgres/migrations/*'),
        'software_release.persistence software_release.recovery publication.winget publication.brew publication.mapping publication.withdrawal publication.recovery')
consume(('crates/inventory/src/*', 'crates/inventory-postgres/src/*', 'crates/inventory-postgres/migrations/*'),
        'inventory.manual inventory.reader inventory.projection inventory.recovery inventory.runtime assets.http assets.queries assets.sources assets.group_input planning.assets planning.group_scope compliance.evaluation')
consume(('crates/compliance/src/*', 'crates/compliance-postgres/src/*', 'crates/compliance-postgres/migrations/*'),
        'compliance.storage compliance.http compliance.evaluation compliance.recovery compliance.group_input')
consume(('crates/resource/src/script.rs', 'crates/flow-service/src/resource_catalog/scripts.rs'),
        'planning.agent_policy planning.remote planning.frequency execution.agent.delivery execution.agent.content execution.agent.recovery')
consume(('crates/flow-service/src/planning/freeze_inputs.rs', 'crates/flow-service/src/resource_catalog/mod.rs'),
        'planning.agent_policy planning.remote planning.onboarding')
TASK_CONSUMERS = 'planning.onboarding planning.policy planning.agent_policy planning.frequency planning.remote planning.software execution.agent.delivery execution.agent.poll execution.agent.content execution.agent.history execution.agent.recovery execution.software.offer execution.software.content execution.software.recovery'
consume(('crates/agent-wire/src/tasks.rs', 'crates/agent-wire/schema/task-*.json',
         'crates/agent-wire/schema/signed-task-v5.schema.json', 'crates/execution-service/src/task_signing.rs'), TASK_CONSUMERS)
# lib.rs owns shared identities, capability, errors, registration and report shapes.
consume(('crates/agent-wire/src/lib.rs','crates/agent-wire/schema/error-body-v5.schema.json',
         'crates/agent-wire/schema/agent-v5.schema-manifest.json'), TASK_CONSUMERS + ' agent.registration agent.reports execution.commands.onboarding apple.onboarding')
consume(('crates/agent-wire/schema/registration-*.json',), 'agent.registration')
consume(('crates/agent-wire/schema/report-*.json',), 'agent.reports planning.onboarding')
consume(('crates/agent-wire/src/onboarding.rs',),
        'agent.reports planning.onboarding execution.commands.onboarding apple.onboarding execution.agent.delivery execution.agent.poll execution.agent.recovery')
consume(('crates/agent-wire/schema/managed-registration-request-v5.schema.json',),
        'execution.commands.onboarding apple.onboarding')
# Native onboarding shares one durable installation and managed-registration owner.
consume(('crates/flow-service/src/execution/agent_install.rs',
         'crates/flow-service/src/execution/managed_registration.rs',
         'crates/flow-service/src/planning/policies/agent_install.rs',
         'crates/agent-channel/src/managed.rs',
         'crates/registration-service/src/enrollment/managed.rs'),
        'execution.commands.onboarding apple.onboarding')
consume(('crates/flow-service/src/planning/policies/onboarding.rs',
         'crates/inventory-service/src/collection/channel.rs',
         'crates/inventory-service/src/assets/channel.rs',
         'crates/flow-service/src/planning/automation/scopes.rs'),
        'planning.onboarding execution.commands.onboarding apple.onboarding')
consume(('crates/windows-channel/src/management.rs','crates/windows-channel/src/boundary.rs'),
        'execution.commands.onboarding')
consume(('crates/apple-channel/src/checkin.rs','crates/apple-channel/src/boundary.rs'),
        'apple.onboarding')
consume(('crates/windows-mdm/src/*',),
        'windows.enrollment windows.management windows.commands execution.commands.windows execution.commands.configuration')
consume(('crates/apple-channel/src/push.rs',), 'apple.push apple.host')
consume(('crates/certificate/src/apple.rs',), 'apple.scep apple.renewal apple.identity')
consume(('crates/software-service/src/lib.rs', 'crates/software-service/src/publication/mod.rs'),
        'software.catalog software.http publication.winget publication.brew publication.mapping publication.withdrawal publication.recovery publication.artifact')
consume(('crates/software-service/src/catalog/*',),
        'software.http planning.software execution.software.offer execution.software.content execution.software.recovery')
AUTH_CONSUMERS = 'diagnostics.http authorization.rules authorization.membership authorization.capacity authorization.initialization authorization.admission api.identity_context enrollment.http enrollment.recovery assets.http planning.http planning.policy planning.agent_policy planning.frequency planning.remote planning.software compliance.http software.http content.http content.mirror content.gc execution.commands.admission windows.issuance windows.management apple.scep apple.profile apple.policy apple.onboarding apple.renewal'
consume(('crates/authorization-service/src/*.rs','crates/management-http/src/authorization/http.rs','crates/management-http/src/lib.rs'), AUTH_CONSUMERS)
consume(('crates/flow-service/src/planning/automation.rs','crates/inventory-service/src/inventory_runtime.rs','crates/inventory-service/src/inventory_runtime/*','crates/flow-service/src/automation/runtime.rs','crates/flow-service/src/automation/completion.rs','crates/flow-service/src/planning/mod.rs','crates/app/src/identity_audit.rs','crates/app/src/identity.rs','crates/apple-channel/src/lib.rs','crates/inventory-service/src/collection/*'), 'diagnostics.http')
consume(('crates/app/src/identity.rs',), 'identity.local identity.sso identity.audit api.identity_context')
consume(('crates/registration-service/src/device/*', 'crates/registration-service/src/device.rs', 'crates/app/src/registration_lifecycle.rs'),
        'device.binding device.revocation device.recovery device.admission agent.registration agent.reports windows.issuance windows.management apple.identity inventory.runtime execution.agent.delivery')
consume(('crates/registration-service/src/enrollment.rs', 'crates/registration-service/src/enrollment/*'),
        'enrollment.http enrollment.recovery agent.registration windows.enrollment apple.scep')
consume(('crates/flow-service/src/planning/remote_operations/*',), 'planning.remote')
consume(('crates/flow-service/src/planning/policies/software.rs',),
        'planning.software execution.software.offer execution.software.recovery')
consume(('crates/flow-service/src/planning/policies/*',), 'planning.policy planning.agent_policy planning.frequency')
consume(('crates/flow-service/src/planning/automation/groups.rs',), 'planning.group_scope assets.group_input compliance.group_input')
consume(('crates/flow-service/src/planning/automation/scopes.rs',), 'planning.scope planning.group_scope planning.frequency planning.remote planning.software')
consume(('crates/flow-service/src/execution/actions/poll.rs',), 'execution.agent.poll execution.agent.delivery')
consume(('crates/flow-service/src/execution/actions/history.rs',), 'execution.agent.history')
consume(('crates/flow-service/src/execution/actions/software.rs',), 'execution.software.offer execution.software.content execution.software.recovery')
consume(('crates/flow-service/src/execution/actions/agent.rs',), 'execution.agent.delivery execution.agent.content execution.agent.recovery')
consume(('crates/flow-service/src/execution/actions/recovery.rs',), 'execution.agent.recovery execution.software.recovery')
AUDITED_MODULES = 'diagnostics.http audit.receipts audit.integrity audit.recovery audit.budget authorization.rules authorization.membership authorization.capacity authorization.initialization authorization.admission identity.audit enrollment.http enrollment.recovery device.binding device.revocation device.recovery device.admission agent.registration agent.reports assets.http planning.http planning.policy planning.agent_policy planning.frequency planning.remote planning.software planning.onboarding planning.group_scope planning.recovery planning.resource_archive compliance.http compliance.recovery software.catalog software.http content.http content.mirror content.gc execution.agent.delivery execution.agent.content execution.agent.recovery execution.software.offer execution.software.content execution.software.recovery execution.commands.admission execution.commands.dispatch execution.commands.recovery execution.commands.windows execution.commands.configuration execution.commands.onboarding windows.issuance windows.management windows.commands apple.scep apple.collection apple.profile apple.policy apple.onboarding apple.renewal apple.identity apple.push publication.winget publication.brew publication.mapping publication.withdrawal publication.recovery'
consume(('crates/audit-integration/src/*',), AUDITED_MODULES)
consume(('crates/flow-service/src/transaction.rs',), ' '.join(name for name in AUDITED_MODULES.split() if MODULES[name].build == APP))
consume(('crates/audit-integration/src/budget.rs',), 'audit.budget enrollment.http enrollment.recovery device.binding device.revocation device.recovery agent.registration windows.issuance windows.management apple.scep apple.profile apple.renewal content.http content.mirror content.gc')
consume(('crates/software-service/src/publication/references.rs',), 'planning.resource_archive')
consume(('crates/software-service/src/publication/*.sql', 'crates/software-service/src/publication/*catalog.json'),
        'publication.winget publication.brew publication.mapping publication.withdrawal publication.recovery catalog.contract')

consume(('crates/certificate/src/*',), 'windows.issuance windows.management apple.scep apple.identity apple.renewal apple.cms native.tls')
consume(('crates/apple-mdm/src/*',), 'apple.scep apple.collection apple.profile apple.policy apple.onboarding apple.renewal apple.identity')


consume(('crates/management-http/src/boundary.rs', 'crates/management-http/src/api.rs', 'crates/management-http/src/router.rs', 'crates/management-http/src/identity.rs', 'crates/management-http/src/error*.rs'), AUTH_CONSUMERS + ' api.diagnostics')
consume(('crates/authorization-service/src/initialization.rs', 'crates/app/src/authorization_bootstrap.rs'), 'authorization.initialization')
consume(('crates/audit-integration/src/completion.rs',
         'crates/agent-channel/src/boundary.rs', 'crates/windows-channel/src/boundary.rs',
         'crates/apple-channel/src/boundary.rs'), 'api.diagnostics')
consume(('crates/agent-channel/src/boundary.rs', 'crates/agent-channel/src/bindings.rs', 'crates/agent-channel/src/operations.rs'), 'agent.registration agent.reports execution.agent.delivery execution.agent.poll')
consume(('crates/agent-channel/src/content.rs',), 'execution.agent.content execution.software.content')
consume(('crates/windows-channel/src/collection.rs', 'crates/windows-channel/src/boundary.rs'), 'windows.management windows.retention windows.limits inventory.runtime')
consume(('crates/app/src/assembly/windows/*',), 'windows.enrollment windows.issuance windows.management windows.retention windows.limits native.tls')
consume(('crates/inventory-service/src/collection*',), 'agent.reports windows.management windows.retention apple.collection apple.renewal inventory.runtime')
consume(('crates/inventory-service/src/groups/*',), 'planning.http planning.group_scope assets.group_input compliance.group_input')
consume(('crates/content-service/src/lib.rs', 'crates/content-service/src/bindings.rs', 'crates/content-service/src/service*', 'crates/content-service/src/transaction.rs'), 'content.http content.mirror content.gc execution.agent.content execution.software.content software.http')
consume(('crates/flow-service/src/storage*',), 'planning.recovery assets.http compliance.http planning.http software.http content.http')
consume(('crates/apple-channel/src/boundary.rs',), 'apple.scep apple.collection apple.profile apple.renewal apple.identity apple.host')

# Software resource decisions and file staging have explicit behavioral consumers.
consume(('crates/software-service/src/preparation/*',),
        'software.catalog planning.software planning.onboarding execution.commands.onboarding execution.software.offer execution.software.content execution.software.recovery')
consume(('crates/software-service/src/management/catalog.rs', 'crates/software-service/src/management/content.rs',
         'crates/software-service/src/management/error.rs', 'crates/software-service/src/management/transaction.rs',
         'crates/software-service/src/management/mod.rs'), 'software.http')
consume(('crates/software-service/src/management/publication/*',), 'software.http catalog.contract')
consume(('crates/content-service/src/software.rs',), 'software.http')

# App router assembly and channel registrars select every actual ingress consumer.
consume(('crates/app/src/api.rs',), ' '.join(name for name, module in MODULES.items()
        if module.build == APP and 'identity' in module.fixtures) + ' api.diagnostics host.lifecycle')
consume(('crates/agent-channel/src/tasks.rs',),
        'execution.agent.delivery execution.agent.poll execution.agent.content execution.agent.recovery execution.software.offer execution.software.content execution.software.recovery')
consume(('crates/windows-channel/src/lib.rs',),
        'windows.enrollment windows.issuance windows.management windows.commands windows.retention windows.limits')

consume(('crates/backend-postgres-support/src/access*', 'crates/*/src/access-contract.json', 'crates/app/src/database.rs'),
        ' '.join(name for name, module in MODULES.items() if module.build == APP and module.postgres))

# Shared production configuration has a broad, but real, consumer set. No-PG
# protocol modules do not become consumers merely because they live in App.
PRODUCT_INPUTS = ('crates/app/src/migration.rs',
                  'crates/app/schema/*', 'crates/*-service/schema/*', 'crates/*-channel/schema/*')
for name, module in tuple(MODULES.items()):
    if module.postgres:
        MODULES[name] = replace(module, production_inputs=module.production_inputs + PRODUCT_INPUTS)
    if module.build == APP:
        MODULES[name] = replace(MODULES[name], support_inputs=(*MODULES[name].support_inputs,'crates/app/tests/fixtures/error.rs'))
        MODULES[name] = replace(MODULES[name], production_inputs=MODULES[name].production_inputs +
                                ('crates/app/src/lib.rs', 'crates/app/src/config.rs'))
    support = ('hack/t2_environment.py', 'hack/t2_fixtures.py')
    if 'tls' in module.fixtures:
        support += ('hack/source_fixtures.py',)
    if 'identity' in module.fixtures or name == 'installation.migration':
        support += ('crates/app/tests/support/identity.rs',)
    if 'identity' in module.fixtures or name == 'installation.migration':
        support += ('crates/app/tests/support/mod.rs', 'crates/app/tests/support/authority.rs', 'crates/app/tests/support/http.rs')
    MODULES[name] = replace(MODULES[name], support_inputs=MODULES[name].support_inputs + support)


MODULES['api.diagnostics'] = replace(MODULES['api.diagnostics'], test_inputs=('crates/app/tests/api/diagnostics.rs',))
for name in ('software.http','authorization.rules'):
    MODULES[name] = replace(MODULES[name], fixtures=MODULES[name].fixtures+('tls',))
MODULES['planning.remote'] = replace(MODULES['planning.remote'], support_inputs=MODULES['planning.remote'].support_inputs+('crates/app/tests/support/agent.rs',))
for name in ('planning.http','planning.policy','software.http','authorization.rules'):
    MODULES[name] = replace(MODULES[name], support_inputs=MODULES[name].support_inputs + ('crates/app/tests/support/planning_http.rs',))
for name in ('software.http','authorization.rules'):
    MODULES[name] = replace(MODULES[name], support_inputs=MODULES[name].support_inputs + ('crates/app/tests/support/publication_http.rs','tests/support/software/*'))
for name in ('inventory.runtime', 'agent.reports', 'assets.group_input', 'assets.sources',
             'compliance.evaluation', 'execution.agent.delivery'):
    MODULES[name] = replace(MODULES[name], support_inputs=MODULES[name].support_inputs +
        ('crates/app/tests/inventory_runtime/support.rs',))
for name in ('assets.sources', 'assets.group_input', 'compliance.evaluation', 'planning.http'):
    MODULES[name] = replace(MODULES[name], support_inputs=MODULES[name].support_inputs +
        ('crates/app/tests/support/inventory.rs',))


for name in [name for name in MODULES if name.startswith('apple.') and name not in ('apple.cms', 'apple.apns')]:
    MODULES[name] = replace(MODULES[name], support_inputs=MODULES[name].support_inputs +
        ('crates/app/tests/apple/mod.rs', 'crates/app/tests/apple/support/scep.rs',
         'crates/app/tests/apple/lifecycle.rs', 'crates/app/tests/apple/oracle.rs', 'hack/apple_oracle.py'))
for name in ('apple.apns', 'apple.push', 'apple.host'):
    MODULES[name] = replace(MODULES[name], support_inputs=MODULES[name].support_inputs +
        ('crates/app/tests/apple/support/apns.rs',))
for name, path in (('apple.push','push_cycle'), ('apple.host','production')):
    MODULES[name] = replace(MODULES[name], test_inputs=(f'crates/app/tests/apple/{path}.rs',))

for name, module in tuple(MODULES.items()):
    support = tuple(path for path in module.support_inputs if path != 'tests/support/software/*')
    if name in ('software.catalog','software.http','authorization.rules','content.http','content.mirror','content.gc','planning.resource_archive') or name.startswith('publication.'):
        support += ('tests/support/software/mod.rs',)
    if name == 'software.catalog' or name.startswith('publication.') and name != 'publication.artifact':
        support += ('tests/support/software/pg.rs',)
    if name == 'publication.recovery':
        support += ('tests/support/software/ack.rs',)
    if 'windows' in module.fixtures:
        support += ('hack/windows_fixtures.py',)
    if 'apple' in module.fixtures:
        support += ('hack/apple_fixtures.py',)
    if set(module.fixtures) & {'scep','oracle'}:
        support += ('hack/apple_tools.py','fixtures/apple-tools.lock.json')
    if 'scep' in module.fixtures:
        support += ('hack/apple_ca.py',)
    if 'idp' in module.fixtures:
        support += ('hack/enterprise_idp.py',)
    if name in ('apple.cms','apple.apns','native.tls'):
        support = tuple(path for path in support if not path.startswith('crates/app/tests/support/'))
    MODULES[name] = replace(module, support_inputs=support)
for owner in ('policy','resource','software_release'):
    for part in ('persistence','recovery'):
        name=owner+'.'+part
        package=owner.replace('_','-')
        support=tuple(path for path in MODULES[name].support_inputs if path != f'crates/{package}-postgres/tests/support/*')
        support += (f'crates/{package}-postgres/tests/support/mod.rs',)
        if owner == 'policy':
            support += (f'crates/{package}-postgres/tests/support/operations.rs',)
        if part == 'recovery':
            support += (f'crates/{package}-postgres/tests/support/ack.rs',)
        MODULES[name] = replace(MODULES[name],support_inputs=support)
MODULES['audit.recovery'] = replace(MODULES['audit.recovery'], support_inputs=MODULES['audit.recovery'].support_inputs+('crates/app/tests/audit/test_support.rs',))

# App test-only namespace carriers preserve the existing Rust case identities.
for family in ('agent','assets','authorization','collection','compliance','content','device','enrollment','execution','inventory_runtime','planning','resource_catalog','software_catalog'):
    prefix={'inventory_runtime':'inventory.','software_catalog':'software.','resource_catalog':'planning.resource_archive','collection':'apple.collection'}.get(family,family+'.')
    carrier=f'crates/app/tests/fixtures/{family}.rs'
    if (ROOT/carrier).is_file():
        for name, module in list(MODULES.items()):
            if name.startswith(prefix):
                MODULES[name]=replace(module,support_inputs=(*module.support_inputs,carrier))
MODULES['apple.cms']=replace(MODULES['apple.cms'],support_inputs=(*MODULES['apple.cms'].support_inputs,'crates/app/tests/apple/certificate_support.rs'))
MODULES['apple.apns']=replace(MODULES['apple.apns'],support_inputs=(*MODULES['apple.apns'].support_inputs,'crates/app/tests/apple/push_support.rs'))

def all_tools():
    return sorted(path.stem for path in (ROOT / 'tests').glob('test_*.py'))


# These carrier files compose exactly these test children, not production consumers.
for name, module in list(MODULES.items()):
    carrier = ('crates/app/tests/api/mod.rs' if name in ('api.identity_context','diagnostics.http') else
               'crates/app/tests/execution/mod.rs' if name.startswith('execution.') else None)
    if carrier:
        MODULES[name] = replace(module, support_inputs=(*module.support_inputs, carrier))
MODULES['execution.commands.dispatch'] = replace(
    MODULES['execution.commands.dispatch'], children=('execution::test_support::',))

MODULES['assets.group_input'] = replace(MODULES['assets.group_input'], support_inputs=MODULES['assets.group_input'].support_inputs+('crates/app/tests/assets/group_support.rs',))

# Verified helper call sites. These edges select tests, never production consumers.
APP_HELPER_CONSUMERS = {
    'support/software_execution.rs': ('software.http','planning.software','execution.software.offer','execution.software.content','execution.software.recovery'),
    'support/software.rs': (
        'software.http','content.http','content.mirror','content.gc','planning.software',
        'execution.software.offer','execution.software.content','execution.software.recovery'),
    'support/process.rs': ('inventory.runtime','execution.commands.recovery'),
    'execution/support.rs': (
        'execution.commands.admission','execution.commands.dispatch','execution.commands.recovery',
        'execution.commands.windows','execution.commands.configuration','execution.commands.onboarding','windows.commands'),
    'device/support.rs': (
        'diagnostics.http',
        'device.binding','device.revocation','device.recovery','device.admission',
        'agent.reports','inventory.runtime','assets.group_input','assets.sources','compliance.evaluation',
        'execution.agent.delivery','authorization.admission','enrollment.recovery','native.tls',
        'planning.http','software.http','execution.software.offer','execution.software.content',
        'execution.software.recovery','execution.commands.admission','execution.commands.dispatch',
        'execution.commands.recovery','execution.commands.windows','execution.commands.configuration','execution.commands.onboarding',
        'windows.commands','windows.enrollment','windows.issuance','windows.limits','windows.management','windows.retention',
        'apple.collection','apple.profile','apple.policy','apple.onboarding','apple.renewal','apple.identity','apple.push',
        'apple.fairness','apple.host','apple.scep'),
    'support/audit.rs': (
        'diagnostics.http',
        'audit.receipts','audit.integrity','audit.recovery','audit.budget',
        'api.diagnostics','device.recovery','device.revocation','execution.commands.admission','execution.commands.onboarding',
        'execution.commands.dispatch','windows.enrollment','windows.issuance','windows.limits',
        'apple.policy','apple.identity','planning.scope','planning.group_scope','planning.assets',
        'planning.recovery','planning.resource_archive','planning.agent_policy','assets.http',
        'enrollment.http','content.http','compliance.http','compliance.recovery','compliance.group_input',
        'authorization.capacity','authorization.rules','execution.agent.history','execution.agent.content','software.http'),
}
APP_HELPER_CONSUMERS['execution/support/native.rs'] = APP_HELPER_CONSUMERS['execution/support.rs']
for relative, consumers in APP_HELPER_CONSUMERS.items():
    path = 'crates/app/tests/' + relative
    for name, module in list(MODULES.items()):
        inputs = tuple(value for value in module.support_inputs if value != path)
        if name in consumers:
            inputs += (path,)
        MODULES[name] = replace(module, support_inputs=inputs)

for name, module in list(MODULES.items()):
    if module.build and module.postgres:
        MODULES[name] = replace(module, support_inputs=(*module.support_inputs, 'tests/support/context.rs'))

# Console reads use the existing real HTTP integration owners.
MODULES['planning.http'] = replace(MODULES['planning.http'], production_inputs=(*MODULES['planning.http'].production_inputs,
    'crates/resource-postgres/src/codec.rs',
    'crates/inventory-postgres/src/lib.rs',
    'crates/flow-service/src/execution/directory.rs',
    'crates/registration-service/src/device/directory.rs',
    'crates/inventory-service/src/assets/directory.rs',
    'crates/inventory-service/src/groups/directory.rs',
    'crates/group-postgres/src/directory.rs',
    'crates/resource-postgres/src/directory.rs',
    'crates/flow-service/src/resource_catalog/directory.rs',
    'crates/flow-service/src/planning/directory.rs',
    'crates/management-http/src/enrollment/directory.rs',
    'crates/management-http/src/resource_catalog/http.rs'), support_inputs=(*MODULES['planning.http'].support_inputs, 'crates/app/tests/support/agent_execution.rs'))
MODULES['execution.agent.history'] = replace(MODULES['execution.agent.history'], production_inputs=(*MODULES['execution.agent.history'].production_inputs,
    'crates/flow-service/src/execution/directory.rs', 'crates/management-http/src/execution/http.rs'))

TOOL_INPUTS = {
    'hack/t2_context.py': ('test_t2_context', 'test_t2_fixtures'),
    'hack/t2_database.py': ('test_t2_fixtures',),
    'hack/t2_hosts.py': ('test_t2_hosts',),
    'hack/t2_modules/installation.py': ('test_t2_guards',),
    'hack/t2_python.py': ('test_t2_execution', 'test_t2_runner'),
    'hack/rust_test_layout.py': ('test_audit_surface','test_foundation_boundaries','test_flow_boundaries'),
    'hack/t2_registry.py': ('test_app_test_layout', 'test_t2_policy', 'test_t2_modules', 'test_t2_runner', 'test_ci_selection', 'test_ci_impact'),
    'hack/t2.py': ('test_t2_modules', 'test_t2_runner', 'test_t2_guards'),
    'hack/t2_execution.py': ('test_t2_execution', 'test_t2_runner'),
    'hack/t2_processes.py': ('test_t2_execution', 'test_t2_fixtures', 'test_t2_runner'),
    'hack/source_fixtures.py': ('test_source_t2',),
    'hack/t2_environment.py': ('test_t2_environment', 'test_t2_runner'),
    'hack/t2_fixtures.py': ('test_t2_fixtures', 'test_t2_environment', 'test_t2_runner'),
    'hack/verification_result.py': ('test_t2_runner', 'test_t2_modules', 'test_ci_selection', 'test_ci'),
    'hack/build_run.py': ('test_build_run', 'test_build_environment'),
    'hack/ci.py': ('test_ci', 'test_ci_selection'),
    'hack/ci-impact.py': ('test_ci_impact', 'test_ci_selection', 'test_t2_modules'),
    'hack/agent_wire_artifact.py': ('test_agent_wire_artifact',),
    'hack/apple_tools.py': ('test_apple_tools',),
    'fixtures/apple-tools.lock.json': ('test_apple_tools',),
    'hack/auth_t3.py': ('test_auth_t3',),
    'hack/auth_t3_browser.mjs': ('test_auth_t3',),
    'hack/release.py': ('test_release',),
    'hack/candidate_runtime.py': ('test_candidate_smoke',),
    'hack/candidate_smoke.py': ('test_candidate_smoke',),
}
EXECUTION_INPUTS = {'hack/t2_python.py', 'hack/t2.py', 'hack/t2_registry.py', 'hack/t2_environment.py',
                    'hack/t2_fixtures.py', 'hack/t2_context.py', 'hack/t2_database.py', 'hack/t2_hosts.py', 'hack/t2_execution.py', 'hack/t2_processes.py', 'hack/verification_result.py'}
GLOBAL_INPUTS = {'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'Makefile', 'hack/build_run.py'}
POLICY_INPUTS = {'deny.toml', 'clippy.toml'}


def matches(path, patterns):
    return any(fnmatchcase(path, pattern) for pattern in patterns)


T1_INPUTS = ('crates/authorization-service/tests/unit.rs','crates/inventory-service/tests/runtime.rs','crates/software-service/tests/management/*') + tuple(f'crates/{name}/tests/*' for name in (
    'inventory', 'group', 'scope', 'policy', 'resource', 'software-release',
    'compliance', 'agent-wire', 'windows-mdm', 'apple-mdm', 'content-service')) + (
    'crates/app/tests/agent/unit.rs',
    'crates/app/tests/apple/webhook_unit.rs',
    'crates/app/tests/assets/query_sort_unit.rs',
    'crates/app/tests/assets/unit.rs',
    'crates/app/tests/audit_budget/unit.rs',
    'crates/app/tests/authorization/unit.rs',
    'crates/app/tests/collection/unit.rs',
    'crates/app/tests/compliance/evaluation_unit.rs',
    'crates/app/tests/config/unit.rs',
    'crates/app/tests/device/coordinates_unit.rs',
    'crates/app/tests/diagnostic/unit.rs',
    'crates/app/tests/enrollment/credentials_unit.rs',
    'crates/app/tests/enrollment/unit.rs',
    'crates/app/tests/error_projection/unit.rs',
    'crates/app/tests/execution/actions/state_unit.rs',
    'crates/execution-service/tests/model_unit.rs',
    'crates/execution-service/tests/model_phase_unit.rs',
    'crates/execution-service/tests/agent_install_unit.rs',
    'crates/app/tests/execution/recovery_unit.rs',
    'crates/app/tests/flow/unit.rs',
    'crates/app/tests/config/publication_unit.rs',
    'crates/app/tests/identity/unit.rs',
    'crates/app/tests/lifecycle/unit.rs',
    'crates/app/tests/native/admission_unit.rs',
    'crates/app/tests/planning/pages_unit.rs',
    'crates/app/tests/planning/wire_unit.rs',
    'crates/app/tests/windows/unit.rs',
    'crates/brew-source/tests/templates.rs', 'crates/winget-source/tests/protocol.rs',
    'crates/winget-source/tests/publication_schema.rs', 'crates/winget-source/tests/version.rs',
    'crates/app/tests/apple/health_unit.rs',
    'crates/app/tests/execution/model_phase_unit.rs',
    'crates/app/tests/execution/remote_phase_unit.rs',
    'crates/app/tests/execution/actions/state_schedule_unit.rs',
    'crates/app/tests/planning/automation/scopes_unit.rs',
    'crates/app/tests/publication.rs',
)


@dataclass(frozen=True)
class Impact:
    full: bool
    modules: tuple[str, ...]
    tools: tuple[str, ...]
    reasons: tuple[str, ...]


def select_paths(paths):
    modules, tools, reasons = set(), set(), set()
    full = False
    for path in sorted(set(paths)):
        if path.startswith('docs/') or path.endswith('.md') or path in {'LICENSE', '.gitignore'}:
            continue
        if path.startswith('tests/test_') and path.endswith('.py'):
            tools.add(Path(path).stem)
            continue
        tools.update(TOOL_INPUTS.get(path, ()))
        if path in GLOBAL_INPUTS or path in EXECUTION_INPUTS or path.startswith('.cargo/'):
            full = True
            reasons.add('integration-global:' + path)
            continue
        if path in POLICY_INPUTS:
            tools.add('test_ci')
            continue
        support = {name for name, module in MODULES.items() if matches(path, module.support_inputs)}
        tests = {name for name, module in MODULES.items() if matches(path, module.test_inputs)}
        if support or tests:
            modules.update(support | tests)
            reasons.add('test-input:' + path)
            continue
        if matches(path, T1_INPUTS):
            # Only known T1 carriers are exempt. Unknown tests/helpers fail full.
            reasons.add('unit-test:' + path)
            continue
        found = {name for name, module in MODULES.items() if matches(path, module.production_inputs)}
        if path.endswith('/Cargo.toml'):
            package_root = path.removesuffix('Cargo.toml')
            found |= {name for name, module in MODULES.items()
                      if any(pattern.startswith(package_root) for pattern in module.production_inputs)}
        if found:
            modules.update(found)
            reasons.add('production:' + path)
            continue
        if path in TOOL_INPUTS:
            continue
        full = True
        reasons.add('integration-unmapped:' + path)
    if full:
        modules.update(MODULES)
        tools.update(all_tools())
    return Impact(full, tuple(sorted(modules)), tuple(sorted(tools)), tuple(sorted(reasons)))

MODULES['execution.commands.windows'] = replace(MODULES['execution.commands.windows'], production_inputs=(*MODULES['execution.commands.windows'].production_inputs, 'crates/flow-service/src/execution/directory.rs', 'crates/management-http/src/execution/http.rs'), support_inputs=(*MODULES['execution.commands.windows'].support_inputs, 'crates/app/tests/support/agent_execution.rs'))

MODULES['windows.management'] = replace(MODULES['windows.management'], test_inputs=(*MODULES['windows.management'].test_inputs, 'crates/app/tests/windows/collection.rs'), production_inputs=(*MODULES['windows.management'].production_inputs, 'crates/windows-channel/src/template_collection.rs'))
consume(("crates/software-service/tests/support/imports.rs",), "software.catalog")

consume(('crates/flow-service/src/execution/actions/output.rs',), 'execution.agent.delivery')
consume(('crates/flow-service/src/execution/actions/native_collection.rs',
         'crates/flow-service/src/execution/actions/recovery.rs'), 'windows.management apple.collection')

consume(('crates/native-protection/*', 'crates/flow-service/src/execution/input_storage.rs', 'crates/execution-service/src/protection.rs'), 'windows.enrollment windows.management execution.commands.admission execution.commands.windows execution.commands.configuration execution.commands.onboarding apple.profile')

consume(('crates/content-service/src/protected.rs',), 'content.http content.gc execution.commands.configuration planning.remote')

# Native Configuration consumers upload immutable content through the same HTTP fixture.
for name in ('apple.policy', 'planning.policy', 'planning.http'):
    MODULES[name] = replace(MODULES[name], support_inputs=tuple(dict.fromkeys((*MODULES[name].support_inputs, 'crates/app/tests/support/planning_http.rs', 'crates/app/tests/support/agent_execution.rs', 'crates/app/tests/support/software.rs'))))

consume(('crates/execution-service/src/action_contract.rs', 'crates/execution-service/src/frozen.rs'), TASK_CONSUMERS + ' windows.management apple.collection execution.commands.configuration execution.commands.onboarding')
consume(('crates/execution-service/src/agent_install.rs',), 'execution.commands.onboarding apple.onboarding planning.policy planning.agent_policy')
consume(('crates/execution-service/src/enrollment.rs',), 'planning.onboarding planning.policy execution.agent.delivery execution.agent.poll execution.agent.recovery')
consume(('crates/execution-service/src/configuration.rs', 'crates/execution-service/src/model.rs', 'crates/execution-service/src/permissions.rs'), 'execution.commands.admission execution.commands.windows execution.commands.configuration execution.commands.onboarding windows.management apple.profile planning.policy planning.remote')
consume(('crates/execution-service/src/target.rs','crates/execution-service/src/payload.rs'), TASK_CONSUMERS)
consume(('crates/execution-service/src/lib.rs','crates/execution-service/src/error.rs'), TASK_CONSUMERS + ' execution.commands.admission execution.commands.windows execution.commands.configuration execution.commands.onboarding windows.management apple.profile')
