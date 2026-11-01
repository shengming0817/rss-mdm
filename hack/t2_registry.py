"""Active product consumer proofs; discovery owns the Rust function names.

Only direct behavior inputs select T2. Preparation is not a business dependency graph.
"""
from fnmatch import fnmatchcase

PACKAGE = 'rss-mdm-app'
MODULES = {
    "registration.device_access": dict(prefix="assembly::credential_owners_t2::registration::", profiles=("shared",), inputs=("crates/registration-service/src/device_access*", "crates/registration-service/schema/device-access*", "apps/server/tests/credential_owners/*", "apps/server/src/assembly/access_execution.rs", "apps/server/src/assembly/registration_agent_facts.rs", "apps/server/src/assembly/registration_sources.rs", "crates/agent-channel/src/bindings.rs", "apps/server/tests/support/planning.rs", "apps/server/tests/task_trust/support.rs", "hack/task_trust_materials.py")),
    "recovery.credentials": dict(prefix="assembly::credential_owners_t2::credentials::", profiles=("shared", "recovery_maintenance", "recovery_audit"), inputs=("crates/recovery-credentials/*", "apps/server/tests/credential_owners/*", "apps/server/src/assembly/credential*", "crates/device-service/src/control/credential_inputs.rs", "crates/apple-channel/src/recovery_credentials.rs", "crates/apple-channel/src/flow_store.rs", "crates/apple-channel/src/protection.rs", "apps/server/tests/support/native_identity.rs", "apps/server/tests/task_trust/support.rs", "hack/native_protocol_materials.py", "hack/task_trust_materials.py")),
    'software.deployment': dict(prefix='assembly::software_t2::', profiles=('shared',),
        inputs=('crates/software-service/*', 'crates/device-service/src/control/source_changes.rs',
                'apps/server/src/assembly/software*',
                'apps/server/tests/software/*', 'apps/server/tests/support/command_runtime.rs',
                'apps/server/tests/support/planning.rs', 'hack/task_trust_materials.py')),
    'registration.installation': dict(prefix='assembly::registration_installation_t2::', profiles=('shared',),
        inputs=('crates/registration-service/src/installation/*', 'crates/registration-service/src/agent*',
                'crates/registration-service/src/agent/*', 'crates/registration-service/schema/*',
                'crates/software-service/src/installation/*', 'crates/software-service/src/deployment/managed_registration.rs',
                'crates/software-service/src/deployment/native_installation.rs',
                'apps/server/src/assembly/registration*', 'apps/server/tests/registration/*',
                'apps/server/tests/software/support.rs', 'apps/server/tests/support/native_identity.rs',
                'hack/native_registration_materials.py', 'hack/native_protocol_materials.py', 'hack/task_trust_materials.py')),
    'script.delivery': dict(prefix='assembly::execution_owners_t2::script_cases::', profiles=('shared',),
        inputs=('crates/script-service/*', 'crates/inventory-service/src/collection/*',
                'crates/inventory-service/schema/*', 'crates/agent-channel/*',
                'crates/device-service/src/control/capacity.rs', 'crates/task-state/*',
                'crates/device-service/src/control/actions/history.rs', 'crates/device-service/src/control/unmanage.rs',
                'crates/device-service/src/control/task_cleanup.rs', 'crates/device-service/src/control/actions/poll.rs',
                'crates/device-service/src/control/actions/agent.rs', 'crates/management-http/src/execution/task_reads.rs',
                'apps/server/src/assembly/*', 'apps/server/src/registration_lifecycle.rs',
                'apps/server/tests/execution_owners/*', 'apps/server/tests/support/planning.rs',
                'apps/server/tests/support/command_runtime.rs', 'apps/server/tests/task_trust/support.rs',
                'hack/task_trust_materials.py')),
    'inventory.preview': dict(prefix='assembly::execution_owners_t2::mixed::', profiles=('shared',), inputs=('crates/inventory-service/*','apps/server/tests/execution_owners/*','apps/server/src/assembly/*')),
    'inventory.collection': dict(prefix='assembly::execution_owners_t2::inventory::', profiles=('shared',),
        inputs=('crates/script-service/*', 'crates/inventory-service/src/collection/*',
                'crates/inventory-service/schema/*', 'crates/agent-channel/*',
                'crates/device-service/src/control/capacity.rs', 'crates/task-state/*',
                'crates/device-service/src/control/actions/history.rs', 'crates/device-service/src/control/unmanage.rs',
                'crates/device-service/src/control/task_cleanup.rs', 'crates/device-service/src/control/actions/poll.rs',
                'crates/device-service/src/control/actions/agent.rs', 'crates/management-http/src/execution/task_reads.rs',
                'apps/server/src/assembly/*', 'apps/server/src/registration_lifecycle.rs',
                'apps/server/tests/execution_owners/*', 'apps/server/tests/support/planning.rs',
                'apps/server/tests/support/command_runtime.rs', 'apps/server/tests/task_trust/support.rs',
                'hack/task_trust_materials.py')),
    'device.retirement': dict(prefix='assembly::execution_owners_t2::retirement::', profiles=('shared',),
        inputs=('crates/script-service/*', 'crates/inventory-service/src/collection/*',
                'crates/inventory-service/schema/*', 'crates/agent-channel/*',
                'crates/device-service/src/control/*', 'crates/device-service/src/lifecycle.rs',
                'crates/device-service/src/planning*', 'crates/device-service/schema/*',
                'crates/registration-service/src/lifecycle.rs', 'crates/registration-service/schema/*',
                'crates/pki-service/src/certificates.rs', 'crates/pki-service/schema/install.sql',
                'crates/task-state/*', 'crates/management-http/src/execution/task_reads.rs',
                'apps/server/src/assembly/*', 'apps/server/src/registration_lifecycle.rs',
                'apps/server/tests/execution_owners/*', 'apps/server/tests/support/planning.rs',
                'apps/server/tests/support/command_runtime.rs', 'apps/server/tests/task_trust/support.rs',
                'hack/task_trust_materials.py')),
    'task.composition': dict(prefix='assembly::execution_owners_t2::composition::', profiles=('shared',),
        inputs=('crates/script-service/*', 'crates/inventory-service/src/collection/*',
                'crates/inventory-service/schema/*', 'crates/agent-channel/*',
                'crates/device-service/src/control/capacity.rs', 'crates/task-state/*',
                'crates/device-service/src/control/actions/history.rs', 'crates/device-service/src/control/unmanage.rs',
                'crates/device-service/src/control/task_cleanup.rs', 'crates/device-service/src/control/actions/poll.rs',
                'crates/device-service/src/control/actions/agent.rs', 'crates/management-http/src/execution/task_reads.rs',
                'apps/server/src/assembly/*', 'apps/server/src/registration_lifecycle.rs',
                'apps/server/tests/execution_owners/*', 'apps/server/tests/support/planning.rs',
                'apps/server/tests/support/command_runtime.rs', 'apps/server/tests/task_trust/support.rs',
                'hack/task_trust_materials.py')),
    'task.locking': dict(prefix='assembly::execution_owners_t2::locking::', profiles=('shared',),
        inputs=('crates/script-service/*', 'crates/inventory-service/src/collection/*',
                'crates/inventory-service/schema/*', 'crates/agent-channel/*',
                'crates/device-service/src/control/capacity.rs', 'crates/task-state/*',
                'crates/device-service/src/control/actions/history.rs', 'crates/device-service/src/control/unmanage.rs',
                'crates/device-service/src/control/task_cleanup.rs', 'crates/device-service/src/control/actions/poll.rs',
                'crates/device-service/src/control/actions/agent.rs', 'crates/management-http/src/execution/task_reads.rs',
                'apps/server/src/assembly/*', 'apps/server/src/registration_lifecycle.rs',
                'apps/server/tests/execution_owners/*', 'apps/server/tests/support/planning.rs',
                'apps/server/tests/support/command_runtime.rs', 'apps/server/tests/task_trust/support.rs',
                'hack/task_trust_materials.py')),
    'task.recovery': dict(prefix='assembly::execution_owners_t2::workers::', profiles=('shared',),
        inputs=('crates/script-service/*', 'crates/inventory-service/src/collection/*',
                'crates/inventory-service/schema/*', 'crates/agent-channel/*',
                'crates/device-service/src/control/capacity.rs', 'crates/task-state/*',
                'crates/device-service/src/control/actions/history.rs', 'crates/device-service/src/control/unmanage.rs',
                'crates/device-service/src/control/task_cleanup.rs', 'crates/device-service/src/control/actions/poll.rs',
                'crates/device-service/src/control/actions/agent.rs', 'crates/management-http/src/execution/task_reads.rs',
                'apps/server/src/assembly/*', 'apps/server/src/registration_lifecycle.rs',
                'apps/server/tests/execution_owners/*', 'apps/server/tests/support/planning.rs',
                'apps/server/tests/support/command_runtime.rs', 'apps/server/tests/task_trust/support.rs',
                'hack/task_trust_materials.py')),
    'device.control': dict(prefix='assembly::device_t2::', profiles=('shared',), inputs=('crates/device-service/*','apps/server/tests/device/*','apps/server/src/assembly/*','apps/server/tests/support/command_runtime.rs','apps/server/tests/support/native_identity.rs','hack/native_protocol_materials.py')),
    'scope.publication': dict(prefix='scope_t2::', profiles=('shared',),
        inputs=('crates/scope-service/*', 'crates/scope-postgres/*', 'crates/device-service/src/planning*',
                'apps/server/src/scopes.rs', 'apps/server/tests/scope/*', 'apps/server/tests/support/planning.rs')),
    'policy.configuration': dict(prefix='policy_configuration_t2::', profiles=('shared',),
        inputs=('crates/policy-service/*', 'crates/policy-postgres/*', 'crates/native-protection/*',
                'crates/registration-service/src/command_authority.rs', 'crates/registration-service/schema/command-authorities.sql',
                'apps/server/src/assembly/configuration_*', 'apps/server/src/assembly/native_ownership.rs',
                'apps/server/src/assembly/policy*', 'crates/device-service/src/control/recovery.rs',
                'crates/device-service/schema/control-*', 'apps/server/src/assembly/command-admission.sql',
                'apps/server/tests/policy/*', 'apps/server/tests/support/planning.rs')),
    'agent.delivery': dict(prefix='agent_t2::', profiles=('shared',),
        inputs=('crates/agent-channel/*', 'crates/device-service/schema/control-*', 'crates/device-service/src/control/actions/agent.rs',
                'crates/device-service/src/control/actions/poll.rs', 'crates/device-service/src/control/agent_facts.rs',
                'apps/server/src/assembly/agent_*', 'apps/server/tests/agent/*',
                'apps/server/src/assembly/command*', 'apps/server/src/assembly/execution.rs',
                'apps/server/tests/support/command_runtime.rs', 'apps/server/tests/task_trust/support.rs',
                'hack/task_trust_materials.py')),
    'windows.protocol': dict(prefix='windows_t2::', profiles=('shared',),
        inputs=('crates/windows-channel/*',
                'crates/policy-service/src/configuration/windows*', 'crates/policy-service/src/configuration/protocol.rs', 'crates/policy-service/src/configuration/storage.rs', 'crates/policy-service/src/configuration/authority.rs', 'crates/policy-service/schema/*', 'crates/registration-service/src/command_authority.rs', 'crates/registration-service/schema/command-authorities.sql', 'apps/server/src/assembly/native_ownership.rs', 'apps/server/src/assembly/configuration_channels.rs', 'crates/device-service/schema/control-*', 'crates/device-service/src/control/protocol.rs',
                'crates/device-service/src/control/windows_*',
                'crates/windows-mdm/src/native/*', 'apps/server/src/assembly/windows_*',
                'apps/server/tests/windows/protocol.rs', 'apps/server/tests/support/native_identity.rs',
                'apps/server/src/assembly/command*', 'apps/server/src/assembly/execution.rs',
                'apps/server/tests/support/command_runtime.rs', 'hack/native_protocol_materials.py',
                'hack/task_trust_materials.py')),
    'apple.protocol': dict(prefix='apple_t2::', profiles=('shared',),
        inputs=('crates/apple-channel/*',
                'crates/policy-service/src/configuration/apple.rs', 'crates/policy-service/src/configuration/assets.rs', 'crates/policy-service/src/configuration/protocol.rs', 'crates/policy-service/src/configuration/storage.rs', 'crates/policy-service/src/configuration/authority.rs', 'crates/policy-service/schema/*', 'crates/registration-service/src/command_authority.rs', 'crates/registration-service/schema/command-authorities.sql', 'apps/server/src/assembly/native_ownership.rs', 'apps/server/src/assembly/configuration_channels.rs', 'crates/device-service/schema/control-*', 'crates/device-service/src/control/apple*',
                'apps/server/src/assembly/apple_*', 'apps/server/tests/apple/*',
                'apps/server/tests/support/native_identity.rs', 'apps/server/src/assembly/command*', 'apps/server/src/assembly/execution.rs',
                'apps/server/tests/support/command_runtime.rs',
                'hack/native_protocol_materials.py', 'hack/task_trust_materials.py')),

    'task_trust': dict(prefix='task_trust_t2::', profiles=('shared',),
        inputs=('crates/task-trust/*', 'apps/server/tests/task_trust/*',
                'hack/task_trust_materials.py',
                'crates/agent-channel/src/signature_retirement.rs',
                'crates/agent-channel/schema/*',
                'crates/device-service/src/control/actions/agent.rs',
                'crates/registration-service/src/device.rs',
                'crates/registration-service/src/device/*',
                'crates/agent-channel/src/tasks.rs', 'apps/server/src/task_signing.rs')),

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
                'apps/server/src/worker_wake.rs', 'apps/server/src/scheduler.rs',
                'apps/server/src/runtime_diagnostics.rs', 'crates/policy-service/src/worker/health.rs',
                'crates/policy-service/src/worker/completion.rs', 'crates/policy-service/src/configuration/source_changes.rs',
                'crates/policy-service/schema/configuration-source-changes.sql',
                'apps/server/src/scope_group_changes.rs', 'apps/server/src/assembly/*',
                'apps/server/tests/foundation/lifecycle.rs')),
}
SUPPORT = ('apps/server/tests/support/authority.rs',)


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
