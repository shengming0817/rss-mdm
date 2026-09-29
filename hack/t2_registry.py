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


APP_INPUTS = {
    'identity.local': ('identity.rs',),
    'identity.sso': ('identity.rs',),
    'authorization.rules': ('authorization/store.rs', 'authorization/evaluate.rs', 'authorization/model.rs'),
    'authorization.membership': ('authorization/store.rs', 'authorization/authority.rs'),
    'authorization.capacity': ('authorization/store.rs', 'authorization/authority.rs'),
    'authorization.initialization': ('authorization/initialize.rs',),
    'authorization.admission': ('authorization/admission.rs',),
    'enrollment.http': ('enrollment/http.rs', 'enrollment/read.rs'),
    'enrollment.recovery': ('enrollment/store.rs',),
    'device.binding': ('device.rs', 'device/store.rs'),
    'device.revocation': ('device.rs', 'registration_lifecycle.rs'),
    'device.recovery': ('device/store.rs',),
    'device.admission': ('device/admission.rs',),
    'agent.registration': ('agent.rs',),
    'agent.reports': ('agent.rs',),
    'assets.http': ('assets/http.rs', 'assets/store.rs'),
    'assets.queries': ('assets/query*.rs', 'assets/filter.rs'),
    'assets.sources': ('assets/store.rs', 'assets/quality.rs', 'assets/collection.rs'),
    'assets.group_input': ('assets/planning.rs', 'assets/quality.rs'),
    'planning.assets': ('planning/sources.rs', 'planning/automation/dispatch.rs', 'assets/planning.rs'),
    'planning.scope': ('planning/scopes.rs', 'planning/pages/scope.rs', 'planning/automation/scopes.rs'),
    'planning.group_scope': ('planning/groups.rs', 'planning/scopes.rs', 'planning/automation/groups.rs', 'planning/automation/scopes.rs'),
    'planning.policy': ('planning/policies/*.rs',),
    'planning.recovery': ('planning/storage.rs', 'planning/admission.sql', 'planning/automation/health.rs'),
    'planning.http': ('planning/http.rs', 'planning/pages.rs', 'planning/policies/http.rs'),
    'planning.agent_policy': ('planning/action_contract.rs', 'planning/policies/mod.rs', 'planning/policies/http.rs', 'planning/policies/preview.rs', 'planning/policies/rerun.rs', 'planning/policies/admission.rs', 'planning/policies/storage.rs'),
    'planning.frequency': ('planning/policies/admission.rs', 'planning/policies/reconcile.rs'),
    'planning.remote': ('planning/remote_operations/*.rs', 'execution/remote.rs'),
    'planning.software': ('planning/policies/software.rs', 'planning/policies/mod.rs'),
    'planning.resource_archive': ('resource_catalog/mod.rs', 'planning/references.rs'),
    'compliance.http': ('compliance/http.rs', 'compliance/read.rs'),
    'compliance.evaluation': ('compliance/evaluation.rs',),
    'compliance.recovery': ('compliance/dispatch.rs', 'compliance/freshness.rs'),
    'compliance.group_input': ('compliance/evaluation.rs', 'compliance/freshness.rs'),
    'execution.agent.delivery': ('execution/actions/agent.rs', 'execution/actions/production.rs', 'execution/actions/collection.rs'),
    'execution.agent.content': ('execution/actions/http.rs', 'content/http.rs'),
    'execution.agent.history': ('execution/actions/history.rs',),
    'execution.agent.poll': ('execution/actions/poll.rs',),
    'execution.agent.recovery': ('execution/actions/recovery.rs',),
    'execution.commands.admission': ('execution/http.rs', 'execution/storage.rs', 'execution/admission.sql'),
    'execution.commands.dispatch': ('execution/recovery.rs',),
    'execution.commands.recovery': ('execution/recovery.rs', 'execution/lifecycle.rs'),
    'execution.commands.windows': ('execution/native.rs',),
    'execution.commands.firewall': ('execution/configuration.rs', 'execution/native.rs'),
    'execution.software.offer': ('execution/actions/software.rs', 'execution/actions/payload.rs'),
    'execution.software.content': ('execution/actions/http.rs', 'content/http.rs'),
    'execution.software.recovery': ('execution/actions/software.rs', 'execution/actions/recovery.rs'),
    'software.http': ('software_catalog.rs',),
    'content.http': ('content/http.rs', 'content/upload.rs'),
    'content.mirror': ('content/http.rs', 'content/upload.rs'),
    'content.gc': ('content/cleanup.rs', 'content/event.rs'),
    'windows.issuance': ('windows/issuance.rs', 'windows/certificate.rs'),
    'windows.enrollment': ('windows/mod.rs',),
    'windows.management': ('windows/management.rs', 'windows/protection.rs'),
    'windows.commands': ('windows/management.rs', 'execution/native.rs'),
    'windows.retention': ('windows/retention.rs',),
    'windows.limits': ('native/admission.rs',),
}


def app_family(owner, *, namespace=None, identity=True,
               fixtures=(), profile='product'):
    namespace = namespace or owner.replace('.', '::') + '::t2'
    test_root = namespace.replace('::t2', '').replace('::', '/')
    children = [name.rsplit('.', 1)[1] for name in APP_INPUTS if name.rsplit('.', 1)[0] == owner]
    if not children:
        raise ValueError('missing App production inputs: ' + owner)
    for child in children:
        add(owner + '.' + child,
            selectors=(namespace + '::' + child + '::',), profile=profile,
            fixtures=(('identity',) if identity else ()) + tuple(fixtures),
            sources=tuple('crates/app/src/' + path for path in APP_INPUTS[owner + '.' + child]),
            tests=(f'crates/app/tests/{test_root}/{child}.rs',
                   f'crates/app/tests/{test_root}/{child}/*'),
            support=(f'crates/app/tests/{test_root}/mod.rs',))


add('installation.migration', selectors=('migration::tests::',), profile='empty',
    sources=('crates/app/src/migration.rs',),
    tests=('crates/app/tests/migration/mod.rs',),
    python='installation', support=('hack/t2_modules/installation.py',))
for part in ('receipts', 'integrity', 'recovery', 'budget'):
    add('audit.' + part, selectors=(f'audit_integration_tests::{part}::',),
        sources=('crates/audit-integration/src/*', 'crates/app/src/audit_budget.rs',
                 'crates/app/src/transaction.rs'),
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
    sources=('crates/app/src/inventory_runtime.rs',),
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
for name in ('planning.assets', 'planning.scope', 'planning.group_scope', 'planning.recovery', 'planning.resource_archive'):
    MODULES[name] = replace(MODULES[name], fixtures=())
MODULES['planning.resource_archive'] = replace(MODULES['planning.resource_archive'], fixtures=('tls',))
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
for name in ('execution.commands.admission','execution.commands.dispatch','execution.commands.recovery','execution.commands.windows','execution.commands.firewall'):
    MODULES[name] = replace(MODULES[name], fixtures=MODULES[name].fixtures+('windows',),
        support_inputs=MODULES[name].support_inputs+('crates/app/tests/execution/support/*', 'crates/app/tests/windows/support.rs',))
app_family('execution.software',
           namespace='execution::t2::software')
for name in ('execution.software.offer', 'execution.software.content', 'execution.software.recovery', 'planning.software'):
    MODULES[name] = replace(MODULES[name], support_inputs=MODULES[name].support_inputs +
        ('crates/app/tests/support/software_execution.rs',))
for name in ('execution.agent.delivery', 'execution.agent.content', 'execution.agent.history', 'execution.agent.poll', 'execution.agent.recovery', 'planning.agent_policy', 'planning.frequency', 'planning.remote'):
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
            'winget': ('artifact.rs','config.rs','driver.rs','service.rs','spec.rs','storage.rs','receipts.rs'),
            'brew': ('artifact.rs','config.rs','driver.rs','service.rs','spec.rs','storage.rs','receipts.rs'),
            'mapping': ('artifact.rs','config.rs','service.rs','spec.rs','storage.rs','receipts.rs','references.rs'),
            'withdrawal': ('config.rs','driver.rs','service.rs','storage.rs','receipts.rs'),
            'recovery': ('config.rs','driver.rs','service.rs','storage.rs','receipts.rs'),
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
for name in ('windows.issuance','windows.enrollment','windows.management','windows.commands','windows.retention','windows.limits','execution.commands.windows','execution.commands.firewall'):
    MODULES[name] = replace(MODULES[name], support_inputs=MODULES[name].support_inputs + ('crates/app/tests/windows/support.rs',))
for name in ('enrollment.recovery','windows.issuance','windows.enrollment','windows.management','windows.commands','windows.retention','windows.limits','execution.commands.admission','execution.commands.dispatch','execution.commands.recovery','execution.commands.windows','execution.commands.firewall'):
    MODULES[name] = replace(MODULES[name], support_inputs=MODULES[name].support_inputs + ('crates/app/tests/enrollment/support.rs',))
for part in ('cms', 'apns', 'scep', 'collection', 'profile', 'policy', 'renewal', 'identity', 'push', 'fairness', 'host'):
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
        'renewal': ('renewal.rs',), 'identity': ('checkin.rs','enrollment.rs'),
        'push': ('push.rs',), 'fairness': ('attempt.rs','protocol.rs'),
        'host': ('mod.rs','config.rs'),
    }[part]
    add('apple.' + part, selectors=selectors, profile='none' if no_pg else 'product',
        fixtures=fixtures, sources=tuple('crates/app/src/apple/' + path for path in source),
        tests=(('crates/app/tests/apple/apns.rs',) if part == 'apns' else
               () if part == 'cms' else (f'crates/app/tests/apple/{part}.rs',)))
add('catalog.contract', build=None, python='catalog',
    sources=('crates/app/src/*/catalog.sql', 'crates/app/src/*/catalog.json',
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
    CasePolicy('app::t2::projection::filter_and_poison', 'fresh', 'objects'),
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
    CasePolicy('planning::t2::group_scope::group_scope_replay_and_audit_atomicity', 'fresh', 'objects'),
))
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
MODULES['execution.commands.firewall'] = replace(MODULES['execution.commands.firewall'], db_mode='reuse', scope='tenant')
MODULES['software.catalog'] = replace(MODULES['software.catalog'], db_mode='instance', scope='objects', policies=(
    CasePolicy('transactions::dependency_admission_uses_exact_current_approval', 'reuse', 'objects'),
    CasePolicy('transactions::source_receipts_follow_the_borrowed_transaction', 'reuse', 'tenant'),
))
MODULES['software.http'] = replace(MODULES['software.http'], db_mode='reuse', scope='objects', policies=(
    CasePolicy('software_catalog::t2::http::publication::publication_http_authority_receipts_and_unknown_outcome', 'reuse', 'tenant'),
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
MODULES['apple.renewal'] = replace(MODULES['apple.renewal'], db_mode='reuse', scope='tenant')
MODULES['apple.identity'] = replace(MODULES['apple.identity'], db_mode='reuse', scope='tenant', policies=(
    CasePolicy('apple::tests::identity::token_is_required_before_management', 'reuse', 'objects'),
))
MODULES['apple.push'] = replace(MODULES['apple.push'], db_mode='reuse', scope='tenant')
MODULES['apple.fairness'] = replace(MODULES['apple.fairness'], db_mode='reuse', scope='tenant')
MODULES['apple.host'] = replace(MODULES['apple.host'], db_mode='fresh', scope='objects')

# These cases need the production consumers; precise stop/restart tests own theirs.
for name in ('assets.queries', 'assets.sources', 'assets.group_input', 'planning.http',
             'planning.policy', 'planning.agent_policy', 'planning.frequency', 'planning.remote',
             'planning.software', 'compliance.evaluation', 'compliance.recovery',
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


case_fixtures('assets.http', 'assets::t2::http::manual::manual_types_replay_cas_and_rollback', 'shared_worker')
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
             'execution.commands.recovery', 'execution.commands.firewall', 'execution.commands.windows', 'windows.retention',
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


consume(('crates/app/src/content/range.rs',),
        'content.http execution.agent.content execution.software.content')
consume(('crates/app/src/content/upload.rs', 'crates/app/src/content/bundle.rs'),
        'content.http software.http')
consume(('crates/app/src/content/cleanup.rs', 'crates/app/src/content/event.rs'),
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
TASK_CONSUMERS = 'planning.policy planning.agent_policy planning.frequency planning.remote planning.software execution.agent.delivery execution.agent.poll execution.agent.content execution.agent.history execution.agent.recovery execution.software.offer execution.software.content execution.software.recovery'
consume(('crates/agent-wire/src/tasks.rs', 'crates/agent-wire/schema/task-*.json',
         'crates/agent-wire/schema/signed-task-v3.schema.json', 'crates/app/src/task_signing.rs'), TASK_CONSUMERS)
# lib.rs owns shared identities, capability, errors, registration and report shapes.
consume(('crates/agent-wire/src/lib.rs','crates/agent-wire/schema/error-body-v3.schema.json',
         'crates/agent-wire/schema/agent-v3.schema-manifest.json'), TASK_CONSUMERS + ' agent.registration agent.reports')
consume(('crates/agent-wire/schema/registration-*.json',), 'agent.registration')
consume(('crates/agent-wire/schema/report-*.json',), 'agent.reports')
consume(('crates/windows-mdm/src/*',),
        'windows.enrollment windows.management windows.commands execution.commands.windows')
consume(('crates/app/src/apple/push.rs',), 'apple.push apple.host')
consume(('crates/app/src/apple/certificate.rs',), 'apple.scep apple.renewal apple.identity')
consume(('crates/software-service/src/lib.rs', 'crates/software-service/src/publication/mod.rs'),
        'software.catalog software.http publication.winget publication.brew publication.mapping publication.withdrawal publication.recovery publication.artifact')
consume(('crates/software-service/src/catalog/*',),
        'software.http planning.software execution.software.offer execution.software.content execution.software.recovery')
AUTH_CONSUMERS = 'authorization.rules authorization.membership authorization.capacity authorization.initialization authorization.admission api.identity_context enrollment.http enrollment.recovery assets.http planning.http planning.policy planning.agent_policy planning.frequency planning.remote planning.software compliance.http software.http content.http content.mirror content.gc execution.commands.admission windows.issuance windows.management apple.scep apple.profile apple.policy apple.renewal'
consume(('crates/app/src/authorization/*.rs',), AUTH_CONSUMERS)
consume(('crates/app/src/identity.rs',), 'identity.local identity.sso identity.audit api.identity_context')
consume(('crates/app/src/device/*', 'crates/app/src/device.rs', 'crates/app/src/registration_lifecycle.rs'),
        'device.binding device.revocation device.recovery device.admission agent.registration agent.reports windows.issuance windows.management apple.identity inventory.runtime execution.agent.delivery')
consume(('crates/app/src/enrollment.rs', 'crates/app/src/enrollment/*'),
        'enrollment.http enrollment.recovery agent.registration windows.enrollment apple.scep')
consume(('crates/app/src/planning/remote_operations/*',), 'planning.remote')
consume(('crates/app/src/planning/policies/software.rs',),
        'planning.software execution.software.offer execution.software.recovery')
consume(('crates/app/src/planning/policies/*',), 'planning.policy planning.agent_policy planning.frequency')
consume(('crates/app/src/planning/automation/groups.rs',), 'planning.group_scope assets.group_input compliance.group_input')
consume(('crates/app/src/planning/automation/scopes.rs',), 'planning.scope planning.group_scope planning.frequency planning.remote planning.software')
consume(('crates/app/src/execution/actions/poll.rs',), 'execution.agent.poll execution.agent.delivery')
consume(('crates/app/src/execution/actions/history.rs',), 'execution.agent.history')
consume(('crates/app/src/execution/actions/software.rs',), 'execution.software.offer execution.software.content execution.software.recovery')
consume(('crates/app/src/execution/actions/agent.rs',), 'execution.agent.delivery execution.agent.content execution.agent.recovery')
consume(('crates/app/src/execution/actions/recovery.rs',), 'execution.agent.recovery execution.software.recovery')
AUDITED_MODULES = 'audit.receipts audit.integrity audit.recovery audit.budget authorization.rules authorization.membership authorization.capacity authorization.initialization authorization.admission identity.audit enrollment.http enrollment.recovery device.binding device.revocation device.recovery device.admission agent.registration agent.reports assets.http planning.http planning.policy planning.agent_policy planning.frequency planning.remote planning.software planning.group_scope planning.recovery planning.resource_archive compliance.http compliance.recovery software.catalog software.http content.http content.mirror content.gc execution.agent.delivery execution.agent.content execution.agent.recovery execution.software.offer execution.software.content execution.software.recovery execution.commands.admission execution.commands.dispatch execution.commands.recovery execution.commands.windows execution.commands.firewall windows.issuance windows.management windows.commands apple.scep apple.collection apple.profile apple.policy apple.renewal apple.identity apple.push publication.winget publication.brew publication.mapping publication.withdrawal publication.recovery'
consume(('crates/audit-integration/src/*',), AUDITED_MODULES)
consume(('crates/app/src/transaction.rs',), ' '.join(name for name in AUDITED_MODULES.split() if MODULES[name].build == APP))
consume(('crates/app/src/audit_budget.rs',), 'audit.budget enrollment.http enrollment.recovery device.binding device.revocation device.recovery agent.registration windows.issuance windows.management apple.scep apple.profile apple.renewal content.http content.mirror content.gc')
consume(('crates/software-service/src/publication/references.rs',), 'planning.resource_archive')
consume(('crates/software-service/src/publication/*.sql', 'crates/software-service/src/publication/*catalog.json'),
        'publication.winget publication.brew publication.mapping publication.withdrawal publication.recovery catalog.contract')

# Shared production configuration has a broad, but real, consumer set. No-PG
# protocol modules do not become consumers merely because they live in App.
PRODUCT_INPUTS = ('crates/app/src/migration.rs',
                  'crates/app/schema/*', 'crates/app/migrations/*',
                  'crates/app/src/*/install.sql',
                  'crates/app/src/*/*/schema.sql')
for name, module in tuple(MODULES.items()):
    if module.postgres:
        MODULES[name] = replace(module, production_inputs=module.production_inputs + PRODUCT_INPUTS)
    if module.build == APP:
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


MODULES['apple.cms'] = replace(MODULES['apple.cms'], test_inputs=('crates/app/tests/apple/cms.rs',))
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

def all_tools():
    return sorted(path.stem for path in (ROOT / 'tests').glob('test_*.py'))


# These carrier files compose exactly these test children, not production consumers.
for name, module in list(MODULES.items()):
    carrier = ('crates/app/tests/api/mod.rs' if name == 'api.identity_context' else
               'crates/app/tests/execution/mod.rs' if name.startswith('execution.') else None)
    if carrier:
        MODULES[name] = replace(module, support_inputs=(*module.support_inputs, carrier))
MODULES['execution.commands.dispatch'] = replace(
    MODULES['execution.commands.dispatch'], children=('execution::test_support::',))

MODULES['assets.group_input'] = replace(MODULES['assets.group_input'], support_inputs=MODULES['assets.group_input'].support_inputs+('crates/app/tests/assets/group_support.rs',))

# Verified helper call sites. These edges select tests, never production consumers.
APP_HELPER_CONSUMERS = {
    'support/software.rs': (
        'software.http','content.http','content.mirror','content.gc','planning.software',
        'execution.software.offer','execution.software.content','execution.software.recovery'),
    'support/process.rs': ('inventory.runtime','execution.commands.recovery'),
    'execution/support.rs': (
        'execution.commands.admission','execution.commands.dispatch','execution.commands.recovery',
        'execution.commands.windows','execution.commands.firewall','windows.commands'),
    'device/support.rs': (
        'device.binding','device.revocation','device.recovery','device.admission',
        'agent.reports','inventory.runtime','assets.group_input','assets.sources','compliance.evaluation',
        'execution.agent.delivery','authorization.admission','enrollment.recovery','native.tls',
        'planning.http','software.http','execution.software.offer','execution.software.content',
        'execution.software.recovery','execution.commands.admission','execution.commands.dispatch',
        'execution.commands.recovery','execution.commands.windows','execution.commands.firewall',
        'windows.commands','windows.enrollment','windows.issuance','windows.limits','windows.management','windows.retention',
        'apple.collection','apple.profile','apple.policy','apple.renewal','apple.identity','apple.push',
        'apple.fairness','apple.host','apple.scep'),
    'support/audit.rs': (
        'audit.receipts','audit.integrity','audit.recovery','audit.budget',
        'api.diagnostics','device.recovery','device.revocation','execution.commands.admission',
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


T1_INPUTS = tuple(f'crates/{name}/tests/*' for name in (
    'inventory', 'group', 'scope', 'policy', 'resource', 'software-release',
    'compliance', 'agent-wire', 'windows-mdm')) + (
    'crates/app/tests/agent/unit.rs',
    'crates/app/tests/apple/profile_unit.rs',
    'crates/app/tests/apple/protocol_unit.rs',
    'crates/app/tests/apple/webhook_unit.rs',
    'crates/app/tests/assets/query_sort_unit.rs',
    'crates/app/tests/assets/unit.rs',
    'crates/app/tests/audit_budget/unit.rs',
    'crates/app/tests/authorization/unit.rs',
    'crates/app/tests/collection/unit.rs',
    'crates/app/tests/compliance/evaluation_unit.rs',
    'crates/app/tests/config/unit.rs',
    'crates/app/tests/content/unit.rs',
    'crates/app/tests/device/coordinates_unit.rs',
    'crates/app/tests/diagnostic/unit.rs',
    'crates/app/tests/enrollment/credentials_unit.rs',
    'crates/app/tests/enrollment/unit.rs',
    'crates/app/tests/error_projection/unit.rs',
    'crates/app/tests/execution/actions/state_unit.rs',
    'crates/app/tests/execution/model_unit.rs',
    'crates/app/tests/execution/recovery_unit.rs',
    'crates/app/tests/flow/unit.rs',
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
