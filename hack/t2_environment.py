"""Resources used by the foundation proofs, borrowing the existing Compose owner.

No business seed, test invocation or cross-domain preparation belongs here.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import uuid

from build_run import lock_file
from dev_environment import Environment, private
from verification_result import require


def profiles(modules):
    from t2_registry import MODULES
    return sorted({profile for module in modules for profile in MODULES[module]['profiles']})


@contextmanager
def prepared(root, modules, binary, command, resources):
    environment = Environment(root, group='foundation-t2')
    environment.root.mkdir(parents=True, exist_ok=True, mode=0o700)
    held = lock_file(environment.root / '.prepare.lock')
    require(held is not None, 'foundation environment is already in use')
    with os.fdopen(held, 'r'):
        with environment.phase('foundation-pg'):
            before = environment.compose('ps', '--all', '-q', 'postgres')
            environment.up()
            resources.append(dict(kind='postgres', identity=environment.container(),
                                  action='reused' if before == environment.container() else 'created'))
            had_roles = environment.sql("SELECT count(*) FROM pg_roles WHERE rolname='mdm_owner'") == '1'
            environment.roles()
            resources.append(dict(kind='roles', identity=environment.project,
                                  action='reused' if had_roles else 'created'))
        system = environment.sql('SELECT system_identifier FROM pg_control_system()')
        installation = dict(audit_mode='plain', instance_id='33333333-3333-4333-8333-333333333333',
                            target=[1] * 16, lineage=[2] * 16)
        description = command([str(binary), '--describe'], 'migration-manifest.log').stdout
        schema = hashlib.sha256(description.encode()).hexdigest()
        role_passwords = {
            'postgres': 'local-fixture', 'mdm_owner': 'owner-fixture',
            'mdm_identity_runtime': 'identity-runtime-fixture',
            'mdm_identity_maintenance': 'identity-maintenance-fixture',
            'mdm_tenant_registry': 'tenant-registry-fixture',
            'mdm_identity_provisioning': 'identity-provisioning-fixture',
        }
        directory = environment.root / 'foundation'
        directory.mkdir(exist_ok=True, mode=0o700)
        for role, password in role_passwords.items():
            private(directory / (role + '-password'), password)
        private(directory / 'runtime-password', 'runtime-fixture')
        for name, value in [('native.key', 17), ('fingerprint.key', 19)]:
            path = directory / name
            if not path.exists():
                path.write_bytes(bytes([value]) * 32)
                path.chmod(0o600)

        def database(name, role):
            return dict(host='localhost', port=environment.port(), name=name, user=role,
                        ca_file=str(environment.root / 'ca.crt'),
                        password_file=str(directory / (role + '-password')
                                          if role in role_passwords else directory / 'runtime-password'))

        created = []
        values = {}
        try:
            for profile in profiles(modules):
                shared = profile == 'shared'
                name = 't2_foundation' if shared else 't2_' + uuid.uuid4().hex
                present = environment.sql("SELECT oid FROM pg_database WHERE datname='" + name + "'")
                marker = directory / (name + '.json')
                if present:
                    expected = dict(system=system, oid=present, schema=schema, installation=installation)
                    require(marker.is_file() and json.loads(marker.read_text()) == expected,
                            'incompatible foundation database; explicitly reset the environment')
                else:
                    environment.sql('CREATE DATABASE ' + name + ' OWNER mdm_owner TEMPLATE template0;')
                    created.append(name)
                    environment.sql('GRANT CREATE ON SCHEMA public TO mdm_owner,mdm_group_owner; '
                                    'GRANT CREATE ON DATABASE ' + name + ' TO mdm_audit_owner,mdm_ledger_owner,mdm_group_owner;', name)
                resources.append(dict(kind='database', identity=name, profile=profile,
                                      action='reused' if present else 'created'))
                values[profile] = {role: database(name, role) for role in (
                    'postgres', 'mdm_owner', 'mdm_access', 'mdm_runtime', 'mdm_command_runtime',
                    'mdm_identity_runtime', 'mdm_identity_maintenance', 'mdm_tenant_registry',
                    'mdm_identity_provisioning', 'mdm_inventory_runtime', 'mdm_scope_runtime',
                    'mdm_policy_runtime', 'mdm_resource_runtime', 'mdm_software_runtime',
                    'mdm_content_runtime', 'mdm_telemetry_runtime', 'mdm_scheduler_runtime',
                    'mdm_scope_group_consumer', 'mdm_webhook_operator', 'mdm_software_driver')}
                if profile != 'recovery':
                    config = directory / (name + '-migrate.json')
                    private(config, dict(database=database(name, 'mdm_owner'), installation=installation))
                    command([str(binary), 'migrate', '--config', str(config)], name + '-migrate.log')
                    resources.append(dict(kind='schema', identity=name, action='validated' if present else 'installed'))
                    if shared:
                        private(marker, dict(system=system,
                            oid=environment.sql("SELECT oid FROM pg_database WHERE datname='" + name + "'"),
                            schema=schema, installation=installation))
            manifest = directory / 'inputs.json'
            private(manifest, dict(installation=installation, databases=values, directory=str(directory)))
            yield {'RSS_MDM_T2_ENV': str(manifest)}
        finally:
            cleanup_errors = []
            for name in created:
                # A successfully published shared environment remains reusable; private/fault
                # observations are disposable. Failed preparation is never silently retried.
                if name == 't2_foundation' and (directory / (name + '.json')).is_file():
                    continue
                try:
                    environment.sql('DROP DATABASE ' + name + ' WITH (FORCE);')
                    resources.append(dict(kind='database', identity=name, action='dropped'))
                except Exception as error:
                    resources.append(dict(kind='database', identity=name, action='cleanup-failed'))
                    cleanup_errors.append(str(error))
            require(not cleanup_errors, 'foundation database cleanup failed: ' + '; '.join(cleanup_errors))
