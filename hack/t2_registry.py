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
class Module:
    id: str
    build: Build | None
    selectors: tuple[str, ...]
    profile: str = 'product'
    fixtures: tuple[str, ...] = ()
    production_inputs: tuple[str, ...] = ()
    test_inputs: tuple[str, ...] = ()
    support_inputs: tuple[str, ...] = ()
    exclusive: bool = False
    python: str | None = None

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


MODULES: dict[str, Module] = {}


def add(name, *, build=APP, selectors=(), profile='product', fixtures=(),
        sources=(), tests=(), support=(), exclusive=False, python=None):
    if name in MODULES:
        raise ValueError('duplicate module: ' + name)
    if build is not None and not selectors:
        raise ValueError('module must select a target or Rust namespace: ' + name)
    MODULES[name] = Module(name, build, tuple(selectors), profile, tuple(fixtures),
                          tuple(sources), tuple(tests), tuple(support), exclusive, python)


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
               fixtures=(), exclusive=(), profile='product'):
    namespace = namespace or owner.replace('.', '::') + '::t2'
    test_root = namespace.replace('::', '/')
    children = [name.rsplit('.', 1)[1] for name in APP_INPUTS if name.rsplit('.', 1)[0] == owner]
    if not children:
        raise ValueError('missing App production inputs: ' + owner)
    for child in children:
        add(owner + '.' + child,
            selectors=(namespace + '::' + child + '::',), profile=profile,
            fixtures=(('identity',) if identity else ()) + tuple(fixtures),
            sources=tuple('crates/app/src/' + path for path in APP_INPUTS[owner + '.' + child]),
            tests=(f'crates/app/src/{test_root}/{child}.rs',
                   f'crates/app/src/{test_root}/{child}/*'),
            support=(f'crates/app/src/{test_root}/mod.rs', f'crates/app/src/{test_root}.rs'),
            exclusive=child in exclusive)


add('installation.migration', selectors=('migration::tests::',), profile='empty',
    sources=('crates/app/src/migration.rs', 'crates/app/src/migration/*'),
    tests=('crates/app/src/migration/tests.rs',), exclusive=True,
    python='installation')
for part in ('receipts', 'integrity', 'recovery', 'budget'):
    add('audit.' + part, selectors=(f'audit_integration_tests::{part}::',),
        sources=('crates/audit-integration/src/*', 'crates/app/src/audit_budget.rs',
                 'crates/app/src/transaction.rs'),
        tests=(f'crates/app/src/audit_integration_tests/{part}.rs',),
        support=('crates/app/src/audit_test_support.rs', 'crates/app/src/audit_integration_tests.rs'))
app_family('identity', fixtures=(), exclusive=('local',))
MODULES['identity.sso'] = replace(MODULES['identity.sso'], fixtures=('identity', 'idp'))
add('identity.audit', selectors=('identity_audit::tests::',), fixtures=('identity',),
    sources=('crates/app/src/identity_audit.rs', 'crates/app/src/identity_audit/*'),
    tests=('crates/app/src/identity_audit/tests.rs',), exclusive=True)
app_family('authorization',
           exclusive=('admission',))
for name in ('rules', 'membership', 'capacity', 'initialization', 'admission'):
    key = 'authorization.' + name
    MODULES[key] = replace(MODULES[key], support_inputs=('crates/app/src/authorization/t2/mod.rs',))
app_family('enrollment')
app_family('device')
for part in ('binding', 'revocation', 'recovery', 'admission'):
    key = 'device.' + part
    MODULES[key] = replace(MODULES[key], support_inputs=('crates/app/src/device/t2/mod.rs', 'crates/app/src/device/test_support.rs'))
app_family('agent')
for name in ('agent.registration', 'agent.reports'):
    MODULES[name] = replace(MODULES[name], support_inputs=('crates/app/src/test_support/agent.rs',))
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
        support=('crates/examples/src/app/t2/mod.rs',), exclusive=name == 'recovery')
add('inventory.runtime', selectors=('inventory_runtime::tests::',), fixtures=('identity',),
    sources=('crates/app/src/inventory_runtime.rs', 'crates/app/src/inventory_runtime/*'),
    tests=('crates/app/src/inventory_runtime/tests.rs',), support=('crates/app/src/device/test_support.rs',))
add('examples.cli', build=Build('rss-mdm-examples', features=('integration',)),
    selectors=('app::t2::cli::',), fixtures=('examples',),
    sources=('crates/examples/src/*',),
    tests=('crates/examples/src/app/t2/cli.rs',), support=('crates/examples/src/app/t2/mod.rs',))
add('api.diagnostics', selectors=('api::tests::',),
    sources=('crates/app/src/api.rs', 'crates/app/src/diagnostic.rs',
             'crates/app/src/error_projection.rs'))
add('api.identity_context', selectors=('api::t2::identity_context::',), fixtures=('identity',),
    sources=('crates/app/src/api.rs',),
    tests=('crates/app/src/api/t2/identity_context/*',))
add('host.lifecycle', build=None, python='host', fixtures=('identity',),
    sources=('crates/app/src/lifecycle.rs', 'crates/app/src/main.rs'),
    support=('hack/t2_modules/host.py',))
app_family('assets')
for name, target in (('persistence', 't2'), ('generations', 'generations')):
    add('group.' + name, build=Build('rss-mdm-group-postgres', 'test', target, ('integration',)),
        selectors=('',), profile='group',
        sources=('crates/group-postgres/src/*', 'crates/group-postgres/migrations/*'),
        tests=(f'crates/group-postgres/tests/{target}.rs',),
        support=('crates/group-postgres/tests/support/*',), exclusive=name == 'persistence')
app_family('planning',
           namespace='planning::t2')
for name in ('planning.assets', 'planning.scope', 'planning.group_scope', 'planning.recovery',
             'planning.resource_archive', 'assets.http', 'audit.integrity'):
    MODULES[name] = replace(MODULES[name], support_inputs=MODULES[name].support_inputs +
                            ('crates/app/src/test_support/planning.rs',))
for name in ('planning.assets', 'planning.scope', 'planning.group_scope', 'planning.recovery', 'planning.resource_archive'):
    MODULES[name] = replace(MODULES[name], fixtures=())
MODULES['planning.resource_archive'] = replace(MODULES['planning.resource_archive'], fixtures=('tls',))
for name in ('planning.recovery', 'audit.integrity'):
    MODULES[name] = replace(MODULES[name], exclusive=True)
MODULES['audit.integrity'] = replace(MODULES['audit.integrity'],
    test_inputs=MODULES['audit.integrity'].test_inputs + ('crates/app/src/audit_integration_tests/owner_admission.rs',))
for name in ('policy', 'resource', 'software_release'):
    package = name.replace('_', '-')
    for suffix, target in (('persistence', 'behavior'), ('recovery', 'recovery')):
        add(name + '.' + suffix,
            build=Build('rss-mdm-' + package + '-postgres', 'test', target, ('integration',)),
            selectors=('',), profile='backend',
            sources=(f'crates/{package}-postgres/src/*', f'crates/{package}-postgres/migrations/*',
                     'crates/backend-postgres-support/src/*'),
            tests=(f'crates/{package}-postgres/tests/{target}.rs',),
            support=(f'crates/{package}-postgres/tests/support/*',),
            exclusive=suffix == 'persistence')
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
        support_inputs=MODULES[name].support_inputs+('crates/app/src/execution/test_support.rs','crates/app/src/execution/test_support/*','crates/app/src/windows/test_support.rs'))
MODULES['execution.commands.admission'] = replace(MODULES['execution.commands.admission'], exclusive=True)
app_family('execution.software',
           namespace='execution::t2::software')
for name in ('execution.software.offer', 'execution.software.content', 'execution.software.recovery', 'planning.software'):
    MODULES[name] = replace(MODULES[name], support_inputs=MODULES[name].support_inputs +
        ('crates/app/src/test_support/software_execution.rs',))
for name in ('execution.agent.delivery', 'execution.agent.content', 'execution.agent.history', 'execution.agent.poll', 'execution.agent.recovery', 'planning.agent_policy', 'planning.frequency', 'planning.remote'):
    MODULES[name] = replace(MODULES[name], support_inputs=MODULES[name].support_inputs +
        ('crates/app/src/test_support/agent_execution.rs',))
add('software.catalog', build=Build('rss-mdm-software-service', 'test', 'catalog_t2'), selectors=('',),
    sources=('crates/software-service/src/catalog/*',),
    tests=('crates/software-service/tests/catalog_t2.rs', 'crates/software-service/tests/catalog/*'),
    support=(), exclusive=True)
app_family('software', namespace='software_catalog::t2')
app_family('content')
for name in ('content.http', 'content.mirror', 'content.gc', 'software.http'):
    MODULES[name] = replace(MODULES[name], support_inputs=MODULES[name].support_inputs +
        ('crates/app/src/test_support/software.rs', 'tests/support/software/*'))
MODULES['content.mirror'] = replace(MODULES['content.mirror'], fixtures=('identity', 'tls'))
MODULES['content.gc'] = replace(MODULES['content.gc'], exclusive=True)
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
    tests=('crates/app/src/native/tls_tests.rs',))
app_family('windows',
           fixtures=('windows',), namespace='windows::t2')
for name in ('windows.issuance','windows.enrollment','windows.management','windows.commands','windows.retention','windows.limits','execution.commands.windows','execution.commands.firewall'):
    MODULES[name] = replace(MODULES[name], support_inputs=MODULES[name].support_inputs + ('crates/app/src/windows/test_support.rs',))
for name in ('enrollment.recovery','windows.issuance','windows.enrollment','windows.management','windows.commands','windows.retention','windows.limits','execution.commands.admission','execution.commands.dispatch','execution.commands.recovery','execution.commands.windows','execution.commands.firewall'):
    MODULES[name] = replace(MODULES[name], support_inputs=MODULES[name].support_inputs + ('crates/app/src/enrollment/test_support.rs',))
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
        tests=(('crates/app/src/apple/push_tests.rs',) if part == 'apns' else
               () if part == 'cms' else (f'crates/app/src/apple/tests/{part}.rs',)))
add('catalog.contract', build=None, python='catalog',
    sources=('crates/app/src/*/catalog.sql', 'crates/app/src/*/catalog.json',
             'crates/software-service/src/*/catalog.sql', 'crates/software-service/src/*/catalog.json'),
    support=('hack/command_catalog.py', 'hack/t2_modules/catalog.py'))
add('gateway.admission', build=None, python='gateway', profile='none', fixtures=('gateway',),
    sources=('deployment/nginx.conf',), support=('hack/t2_modules/gateway.py',))


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
PRODUCT_INPUTS = ('crates/app/src/migration.rs', 'crates/app/src/migration/*',
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
    if 'identity' in module.fixtures:
        support += ('crates/app/src/test_support/identity.rs',)
    if module.build == APP:
        support += ('crates/app/src/test_support/mod.rs', 'crates/app/src/test_support/authority.rs', 'crates/app/src/test_support/http.rs')
    MODULES[name] = replace(MODULES[name], support_inputs=MODULES[name].support_inputs + support)


MODULES['apple.cms'] = replace(MODULES['apple.cms'], test_inputs=())
for name in ('software.http','authorization.rules'):
    MODULES[name] = replace(MODULES[name], fixtures=MODULES[name].fixtures+('tls',))
MODULES['planning.remote'] = replace(MODULES['planning.remote'], support_inputs=MODULES['planning.remote'].support_inputs+('crates/app/src/test_support/agent.rs',))
for name in ('planning.http','planning.policy','software.http','authorization.rules'):
    MODULES[name] = replace(MODULES[name], support_inputs=MODULES[name].support_inputs + ('crates/app/src/test_support/planning_http.rs',))
for name in ('software.http','authorization.rules'):
    MODULES[name] = replace(MODULES[name], support_inputs=MODULES[name].support_inputs + ('crates/app/src/test_support/publication_http.rs','tests/support/software/*'))
for name in ('inventory.runtime', 'agent.reports', 'assets.group_input', 'assets.sources',
             'compliance.evaluation', 'execution.agent.delivery'):
    MODULES[name] = replace(MODULES[name], support_inputs=MODULES[name].support_inputs +
        ('crates/app/src/test_support/inventory_runtime.rs', 'crates/app/src/device/test_support.rs'))
for name in ('assets.sources', 'assets.group_input', 'compliance.evaluation', 'planning.http'):
    MODULES[name] = replace(MODULES[name], support_inputs=MODULES[name].support_inputs +
        ('crates/app/src/test_support/inventory.rs',))

MODULES['inventory.runtime'] = replace(MODULES['inventory.runtime'],
    support_inputs=MODULES['inventory.runtime'].support_inputs + ('crates/app/src/test_support/process.rs',))

for name in [name for name in MODULES if name.startswith('apple.') and name not in ('apple.cms', 'apple.apns')]:
    MODULES[name] = replace(MODULES[name], support_inputs=MODULES[name].support_inputs +
        ('crates/app/src/apple/tests.rs', 'crates/app/src/apple/test_support/scep.rs',
         'crates/app/src/apple/tests/lifecycle.rs', 'crates/app/src/apple/tests/oracle.rs', 'hack/apple_oracle.py'))
for name in ('apple.apns', 'apple.push', 'apple.host'):
    MODULES[name] = replace(MODULES[name], support_inputs=MODULES[name].support_inputs +
        ('crates/app/src/apple/test_support/apns.rs',))
for name, path in (('apple.push','push_cycle'), ('apple.host','production')):
    MODULES[name] = replace(MODULES[name], test_inputs=(f'crates/app/src/apple/tests/{path}.rs',))

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
        support = tuple(path for path in support if not path.startswith('crates/app/src/test_support/'))
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
MODULES['audit.recovery'] = replace(MODULES['audit.recovery'], support_inputs=MODULES['audit.recovery'].support_inputs+('crates/app/src/audit_integration_tests/test_support.rs',))

def all_tools():
    return sorted(path.stem for path in (ROOT / 'tests').glob('test_*.py'))


TOOL_INPUTS = {
    'hack/rust_test_layout.py': ('test_audit_surface','test_foundation_boundaries','test_flow_boundaries'),
    'hack/t2_registry.py': ('test_t2_modules', 'test_t2_runner', 'test_ci_selection', 'test_ci_impact'),
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
EXECUTION_INPUTS = {'hack/t2.py', 'hack/t2_registry.py', 'hack/t2_environment.py',
                    'hack/t2_fixtures.py', 'hack/t2_execution.py', 'hack/t2_processes.py', 'hack/verification_result.py'}
GLOBAL_INPUTS = {'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'Makefile', 'hack/build_run.py'}
POLICY_INPUTS = {'deny.toml', 'clippy.toml'}


def matches(path, patterns):
    return any(fnmatchcase(path, pattern) for pattern in patterns)


T1_INPUTS = tuple(f'crates/{name}/tests/*' for name in (
    'inventory', 'group', 'scope', 'policy', 'resource', 'software-release',
    'compliance', 'agent-wire', 'windows-mdm')) + (
    'crates/app/src/content/tests.rs', 'crates/app/src/authorization/tests.rs',
    'crates/brew-source/tests/templates.rs', 'crates/winget-source/tests/protocol.rs',
    'crates/winget-source/tests/publication_schema.rs', 'crates/winget-source/tests/version.rs',
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
