"""Exact production action declarations and their source ownership."""
from pathlib import Path
import re
import os
import unittest
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"hack"))
from rust_test_layout import is_test_path

ROOT = Path(__file__).resolve().parents[1]
PRODUCERS = ('app','software-service','authorization-service','registration-service','inventory-service','flow-service','execution-service','content-service','management-http','agent-channel','windows-channel','apple-channel')
def production_paths():
    return [path for owner in PRODUCERS for path in (ROOT/'crates'/owner/'src').rglob('*.rs')]

# Each entry binds an action to its declaration or dispatch entry in the production call path.
OWNERS = {
 'windows_renewal':'crates/windows-channel/src/renewal.rs',
 'windows_push':'crates/windows-channel/src/push_worker.rs',
 'timeline_read': 'crates/management-http/src/boundary.rs',
 'audit_search': 'crates/management-http/src/boundary.rs','agent_content':'crates/execution-service/src/native_installation.rs','authentication':'crates/management-http/src/boundary.rs','agent_registration': 'crates/agent-channel/src/lib.rs',
 'agent_report': 'crates/agent-channel/src/lib.rs',
 'agent_report_read': 'crates/agent-channel/src/lib.rs',
 'apple_asset': 'crates/apple-channel/src/boundary.rs',
 'apple_checkin': 'crates/apple-channel/src/boundary.rs',
 'apple_management': 'crates/app/src/native/mod.rs',
 'apple_profile': 'crates/apple-channel/src/boundary.rs',
 'apple_push': 'crates/execution-service/src/apple_push.rs',
 'apple_renewal': 'crates/apple-channel/src/renewal.rs',
 'apple_scep': 'crates/app/src/native/mod.rs',
 'authorization_departments_read': 'crates/management-http/src/boundary.rs',
 'authorization_effective_read': 'crates/management-http/src/boundary.rs',
 'authorization_groups_read': 'crates/management-http/src/boundary.rs',
 'authorization_initialize': 'crates/authorization-service/src/store.rs',
 'authorization_members_read': 'crates/management-http/src/boundary.rs',
 'authorization_rules_read': 'crates/management-http/src/boundary.rs',
 'authorization_write': 'crates/authorization-service/src/store.rs',
 'automation_completed': 'crates/flow-service/src/automation/jobs.rs',
 'automation_failed': 'crates/flow-service/src/planning/automation/health.rs',
 'collection_finish': 'crates/inventory-service/src/collection/store.rs',
 'collection_read': 'crates/management-http/src/router.rs',
 'collection_start': 'crates/inventory-service/src/apple_collection.rs',
 'command_accept': 'crates/agent-channel/src/tasks.rs',
 'command_approve': 'crates/management-http/src/execution/http.rs',
 'command_cancel': 'crates/management-http/src/execution/http.rs',
 'command_dispatch': 'crates/execution-service/src/actions/recovery.rs',
 'command_read': 'crates/agent-channel/src/tasks.rs',
 'command_reconcile': 'crates/execution-service/src/actions/recovery.rs',
 'compliance_read': 'crates/management-http/src/compliance/http.rs',
 'compliance_write': 'crates/management-http/src/compliance/http.rs',
 'credential_revoke': 'crates/registration-service/src/device.rs',
 'device_action': 'crates/management-http/src/router.rs',
 'enrollment_cancel': 'crates/management-http/src/boundary.rs',
 'enrollment_create': 'crates/registration-service/src/device.rs',
 'enrollment_issue': 'crates/windows-channel/src/lib.rs',
 'enrollment_read': 'crates/management-http/src/boundary.rs',
 'enrollment_resume': 'crates/management-http/src/boundary.rs',
 'inventory_read': 'crates/management-http/src/assets/http.rs',
 'management_read': 'crates/content-service/src/service.rs',
 'management_write': 'crates/content-service/src/service.rs',
 'protected_request': 'crates/app/src/native/mod.rs',
 'runtime_diagnostics_read': 'crates/management-http/src/runtime_diagnostics.rs',
 'registration_bind': 'crates/registration-service/src/device.rs',
 'registration_read': 'crates/management-http/src/boundary.rs',
 'software_approve': 'crates/software-service/src/publication/service.rs',
 'software_authorize': 'crates/software-service/src/publication/service.rs',
 'software_binding': 'crates/software-service/src/publication/storage.rs',
 'software_call': 'crates/software-service/src/publication/driver.rs',
 'software_candidate': 'crates/software-service/src/publication/service.rs',
 'software_preflight': 'crates/software-service/src/management/publication/service.rs',
 'software_result': 'crates/software-service/src/publication/driver.rs',
 'software_validate': 'crates/software-service/src/publication/service.rs',
 'software_withdraw': 'crates/software-service/src/publication/driver.rs',
 'windows_discovery': 'crates/windows-channel/src/boundary.rs',
 'windows_management': 'crates/windows-channel/src/management.rs',
 'windows_policy': 'crates/windows-channel/src/boundary.rs'}

DECLARATIONS = {
    ('windows_renewal', 'crates/windows-channel/src/renewal.rs'),
    ('windows_push', 'crates/windows-channel/src/push_worker.rs'),
    ('credential_revoke', 'crates/execution-service/src/retirement.rs'),
 ('management_read','crates/management-http/src/enrollment/directory.rs'),
 ('management_read','crates/management-http/src/remote_operations/http.rs'),
 ('timeline_read','crates/management-http/src/boundary.rs'),
 ('audit_search','crates/management-http/src/boundary.rs'),
 ('runtime_diagnostics_read','crates/management-http/src/runtime_diagnostics.rs'),
 ('runtime_diagnostics_read','crates/management-http/src/boundary.rs'),
 ('agent_registration','crates/windows-channel/src/boundary.rs'),
 ('agent_registration','crates/apple-channel/src/boundary.rs'),
 ('agent_registration','crates/execution-service/src/managed_registration.rs'),
 ('collection_finish','crates/inventory-service/src/collection/channel.rs'),
 ('command_accept','crates/execution-service/src/native_installation.rs'),
 ('agent_content','crates/execution-service/src/native_installation.rs'),
 ('authentication','crates/management-http/src/boundary.rs'),('agent_registration', 'crates/agent-channel/src/boundary.rs'),
 ('agent_registration', 'crates/agent-channel/src/lib.rs'),
 ('agent_report', 'crates/agent-channel/src/boundary.rs'),
 ('agent_report', 'crates/agent-channel/src/lib.rs'),
 ('agent_report_read', 'crates/agent-channel/src/boundary.rs'),
 ('agent_report_read', 'crates/agent-channel/src/lib.rs'),
 ('apple_asset', 'crates/apple-channel/src/boundary.rs'),
 ('apple_checkin', 'crates/apple-channel/src/boundary.rs'),
 ('apple_management', 'crates/app/src/native/mod.rs'),
 ('apple_management', 'crates/apple-channel/src/boundary.rs'),
 ('apple_profile', 'crates/apple-channel/src/boundary.rs'),
 ('apple_push', 'crates/execution-service/src/apple_push.rs'),
 ('apple_renewal', 'crates/apple-channel/src/renewal.rs'),
 ('apple_scep', 'crates/app/src/native/mod.rs'),
 ('apple_scep', 'crates/apple-channel/src/boundary.rs'),
 ('authorization_departments_read', 'crates/management-http/src/boundary.rs'),
 ('authorization_effective_read', 'crates/management-http/src/boundary.rs'),
 ('authorization_groups_read', 'crates/management-http/src/boundary.rs'),
 ('authorization_initialize', 'crates/app/src/authorization_bootstrap.rs'),
 ('authorization_initialize', 'crates/authorization-service/src/store.rs'),
 ('authorization_members_read', 'crates/management-http/src/boundary.rs'),
 ('authorization_rules_read', 'crates/management-http/src/boundary.rs'),
 ('authorization_write', 'crates/authorization-service/src/store.rs'),
 ('authorization_write', 'crates/management-http/src/authorization/http.rs'),
 ('authorization_write', 'crates/management-http/src/boundary.rs'),
 ('automation_completed', 'crates/flow-service/src/automation/jobs.rs'),
 ('automation_failed', 'crates/flow-service/src/planning/automation/health.rs'),
 ('collection_finish', 'crates/inventory-service/src/collection/store.rs'),
 ('collection_finish', 'crates/windows-channel/src/retention.rs'),
 ('collection_read', 'crates/management-http/src/boundary.rs'),
 ('collection_read', 'crates/management-http/src/router.rs'),
 ('collection_start', 'crates/inventory-service/src/apple_collection.rs'),
 ('collection_start', 'crates/management-http/src/boundary.rs'),
 ('command_accept', 'crates/agent-channel/src/tasks.rs'),
 ('command_accept', 'crates/execution-service/src/actions/production.rs'),
 ('command_accept', 'crates/execution-service/src/native_configuration.rs'),
 ('command_accept', 'crates/execution-service/src/remote_execution.rs'),
 ('command_accept', 'crates/management-http/src/execution/http.rs'),
 ('command_approve', 'crates/management-http/src/execution/http.rs'),
 ('command_cancel', 'crates/management-http/src/execution/http.rs'),
 ('command_dispatch', 'crates/execution-service/src/actions/recovery.rs'),
 ('command_dispatch', 'crates/execution-service/src/recovery.rs'),
 ('command_read', 'crates/agent-channel/src/tasks.rs'),
 ('command_read', 'crates/management-http/src/execution/actions/http.rs'),
 ('command_read', 'crates/management-http/src/execution/http.rs'),
 ('command_read', 'crates/management-http/src/remote_operations/http.rs'),
 ('command_reconcile', 'crates/execution-service/src/actions/recovery.rs'),
 ('command_reconcile', 'crates/execution-service/src/recovery.rs'),
 ('compliance_read', 'crates/management-http/src/compliance/http.rs'),
 ('compliance_write', 'crates/management-http/src/compliance/http.rs'),
 ('credential_revoke', 'crates/management-http/src/boundary.rs'),
 ('credential_revoke', 'crates/registration-service/src/device.rs'),
 ('device_action', 'crates/management-http/src/boundary.rs'),
 ('device_action', 'crates/management-http/src/router.rs'),
 ('enrollment_cancel', 'crates/management-http/src/boundary.rs'),
 ('enrollment_create', 'crates/management-http/src/boundary.rs'),
 ('enrollment_create', 'crates/registration-service/src/device.rs'),
 ('enrollment_issue', 'crates/windows-channel/src/boundary.rs'),
 ('enrollment_issue', 'crates/windows-channel/src/lib.rs'),
 ('enrollment_issue', 'crates/windows-channel/src/linked.rs'),
 ('enrollment_read', 'crates/management-http/src/boundary.rs'),
 ('enrollment_resume', 'crates/management-http/src/boundary.rs'),
 ('inventory_read', 'crates/management-http/src/assets/http.rs'),
 ('inventory_read', 'crates/management-http/src/boundary.rs'),
 ('management_read', 'crates/content-service/src/service.rs'),
 ('management_read', 'crates/execution-service/src/recovery.rs'),
 ('management_read', 'crates/execution-service/src/queries/preview.rs'),
 ('management_read', 'crates/execution-service/src/queries/assignments.rs'),
 ('management_read', 'crates/flow-service/src/planning/policies/read.rs'),
 ('management_read', 'crates/execution-service/src/remote_operations/read.rs'),
 ('management_read', 'crates/software-service/src/management/catalog.rs'),
 ('management_read', 'crates/software-service/src/management/publication/service.rs'),
 ('management_read', 'crates/management-http/src/planning/http.rs'),
 ('management_read', 'crates/management-http/src/resource_catalog/http.rs'),
 ('management_write', 'crates/content-service/src/service.rs'),
 ('management_write', 'crates/execution-service/src/actions/recovery.rs'),
 ('management_write', 'crates/execution-service/src/recovery.rs'),
 ('management_write', 'crates/execution-service/src/remote_operations/read.rs'),
 ('management_write', 'crates/software-service/src/management/catalog.rs'),
 ('management_write', 'crates/software-service/src/management/publication/service.rs'),
 ('management_write', 'crates/management-http/src/assets/http.rs'),
 ('management_write', 'crates/management-http/src/planning/http.rs'),
 ('management_write', 'crates/management-http/src/planning/policies/http.rs'),
 ('management_write', 'crates/management-http/src/remote_operations/http.rs'),
 ('management_write', 'crates/management-http/src/resource_catalog/http.rs'),
 ('protected_request', 'crates/agent-channel/src/boundary.rs'),
 ('protected_request', 'crates/app/src/native/mod.rs'),
 ('protected_request', 'crates/apple-channel/src/boundary.rs'),
 ('protected_request', 'crates/management-http/src/boundary.rs'),
 ('protected_request', 'crates/windows-channel/src/boundary.rs'),
 ('registration_bind', 'crates/registration-service/src/device.rs'),
 ('registration_read', 'crates/management-http/src/boundary.rs'),
 ('software_approve', 'crates/software-service/src/publication/service.rs'),
 ('software_authorize', 'crates/software-service/src/publication/service.rs'),
 ('software_binding', 'crates/software-service/src/publication/storage.rs'),
 ('software_call', 'crates/software-service/src/publication/driver.rs'),
 ('software_candidate', 'crates/software-service/src/publication/service.rs'),
 ('software_preflight', 'crates/software-service/src/management/publication/service.rs'),
 ('software_result', 'crates/software-service/src/publication/driver.rs'),
 ('software_validate', 'crates/software-service/src/publication/service.rs'),
 ('software_withdraw', 'crates/software-service/src/publication/driver.rs'),
 ('windows_discovery', 'crates/windows-channel/src/boundary.rs'),
 ('windows_management', 'crates/app/src/native/mod.rs'),
 ('windows_management', 'crates/windows-channel/src/boundary.rs'),
 ('windows_management', 'crates/windows-channel/src/management.rs'),
 ('windows_policy', 'crates/windows-channel/src/boundary.rs')}


def arguments(source, start):
    """Read one Rust call's arguments, respecting nested delimiters and quoted strings."""
    depth, argument, result = 0, start, []
    quoted = escaped = False
    for i in range(start, len(source)):
        char = source[i]
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0:
                result.append(source[argument:i])
                return result
            depth -= 1
        elif char == "," and depth == 0:
            result.append(source[argument:i])
            argument = i + 1
    raise AssertionError("unterminated producer call")


def declared_actions():
    calls = {"RequestAudit::new": 1, ".operation": 1, ".set_action": 0,
             "db::fact": 3, ".transition_audited": 3}
    result = set()
    for path in production_paths():
        if is_test_path(path):
            continue
        source = path.read_text()
        for call, index in calls.items():
            for match in re.finditer(re.escape(call) + r"\s*\(", source):
                args = arguments(source, match.end())
                if len(args) > index:
                    result.update((action, os.path.relpath(path, ROOT)) for action in re.findall(r'"([a-z_]+)"', args[index]))
    for owner in ('management-http','agent-channel','windows-channel','apple-channel'):
        name=f'crates/{owner}/src/boundary.rs'
        source=(ROOT/name).read_text().split('fn route_action',1)[1].split('#[cfg(test)]',1)[0]
        result.update((action,name) for action in re.findall(r'"([a-z_]+)"',source))
    name='crates/app/src/native/mod.rs'
    source=(ROOT/name).read_text().split('const fn audit_action',1)[1].split('pub(crate) fn',1)[0]
    result.update((action,name) for action in re.findall(r'"([a-z_]+)"',source))
    for action,name in [('software_binding','crates/software-service/src/publication/storage.rs'),('automation_completed','crates/flow-service/src/automation/jobs.rs')]:
        if '"'+action+'"' in (ROOT/name).read_text():result.add((action,name))
    return result


class AuditSurface(unittest.TestCase):
    def test_every_declared_action_has_an_explicit_production_owner(self):
        self.assertEqual(declared_actions(), DECLARATIONS)
        self.assertEqual({action for action, _ in DECLARATIONS}, OWNERS.keys())
        for action, owner in OWNERS.items():
            with self.subTest(action=action):
                self.assertIn((action, owner), DECLARATIONS)

    def test_retired_audit_writes_and_transaction_forwarders_do_not_exist(self):
        self.assertFalse((ROOT / "crates/app/src/audit.rs").exists())
        self.assertNotIn("'audit'", (ROOT / "crates/execution-service/src/dependencies.sql").read_text())
        for path in production_paths():
            source = path.read_text()
            self.assertNotIn("mdm_access.audit", source, str(path))
            self.assertNotIn("append_on_connection", source, str(path))

class PrincipalBindingBoundary(unittest.TestCase):
    def test_browser_and_native_producers_use_authorization_owner(self):
        owners = {'crates/authorization-service/src/context.rs', 'crates/authorization-service/src/store.rs', 'crates/software-service/src/publication/storage.rs'}
        actual = set()
        for path in production_paths():
            relative = os.path.relpath(path, ROOT)
            if is_test_path(path):
                continue
            source = path.read_text()
            self.assertNotRegex(source, r'\.identify(?:_operator)?\(')
            if '.set_principal(' in source:
                actual.add(relative)
        self.assertEqual(actual, owners)
