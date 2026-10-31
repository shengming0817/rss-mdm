"""Active product consumer proofs; discovery owns the Rust function names.

Only direct behavior inputs select T2. Preparation is not a business dependency graph.
"""
from fnmatch import fnmatchcase

PACKAGE = 'rss-mdm-app'
MODULES = {
    'foundation.authorization': dict(
        prefix='foundation_t2::authorization::', profiles=('shared', 'transaction'),
        inputs=('crates/audit-integration/src/*', 'crates/authorization-service/src/*', 'crates/authorization-service/schema/*',
                'apps/server/tests/foundation/authorization.rs')),
    'foundation.audit': dict(
        prefix='foundation_t2::audit::', profiles=('audit',),
        inputs=('crates/management-http/src/boundary.rs', 'crates/audit-integration/src/*',
                'apps/server/schema/audit-*.sql', 'apps/server/tests/foundation/audit.rs')),
    'foundation.tenants': dict(
        prefix='foundation_t2::tenants::', profiles=('shared',),
        inputs=('apps/server/src/administration/tenants/*', 'apps/server/schema/installation.sql',
                'apps/server/tests/foundation/tenants.rs')),
    'foundation.recovery': dict(
        prefix='installation::backup::t2::', profiles=('recovery',),
        inputs=('apps/server/src/installation/backup.rs',
                'crates/inventory-postgres/migrations/asset-cuts.sql',
                'crates/inventory-postgres/migrations/install.sql',
                'apps/server/tests/foundation/recovery.rs')),
    'foundation.lifecycle': dict(
        prefix='foundation_t2::lifecycle::', profiles=('lifecycle',),
        inputs=('apps/server/src/lifecycle.rs', 'apps/server/src/identity.rs',
                'apps/server/src/database.rs', 'apps/server/src/owner_storage.rs',
                'apps/server/src/worker_wake.rs', 'apps/server/src/assembly/*',
                'apps/server/tests/foundation/lifecycle.rs')),
}
SUPPORT = ('apps/server/tests/foundation/support.rs',)


def affected(paths):
    return sorted(name for name, module in MODULES.items()
                  if any(any(fnmatchcase(path, pattern) for pattern in module['inputs'] + SUPPORT)
                         for path in paths))


def owners(package, target, name):
    return [module for module, value in MODULES.items()
            if package == PACKAGE and target == PACKAGE.replace('-', '_')
            and name.startswith(value['prefix'])]


def discover(document, modules, *, package=None):
    """Validate ignored ownership, then derive the requested nonempty execution set."""
    from verification_result import require
    require(isinstance(document.get('rust-suites'), dict), 'invalid nextest discovery')
    found = {module: [] for module in modules}
    seen = set()
    for suite in document['rust-suites'].values():
        if package is not None and suite['package-name'] != package:
            continue
        require(suite['status'] == 'listed', 'incomplete target discovery')
        target = suite['binary-name']
        for name, case in suite['testcases'].items():
            assigned = owners(suite['package-name'], target, name)
            require(len(assigned) <= 1, 'ambiguous T2 execution owner')
            require(not case['ignored'] or assigned, 'ignored test has no execution owner: ' + name)
            require(not assigned or case['ignored'], 'T2 must be ignored by ordinary T1: ' + name)
            if assigned and assigned[0] in found:
                key = (suite['package-name'], target, name)
                require(key not in seen, 'duplicate T2 discovery')
                seen.add(key)
                found[assigned[0]].append(name)
    for module, cases in found.items():
        require(cases, 'zero T2 discovery: ' + module)
    return {module: sorted(cases) for module, cases in found.items()}
