"""Exact production action declarations and their source ownership."""
from pathlib import Path
import re
import os
import unittest

ROOT = Path(__file__).resolve().parents[1] / "crates/app/src"
SERVICE = ROOT.parents[1] / "software-service/src"
def production_paths():
    return [*ROOT.rglob("*.rs"), *SERVICE.rglob("*.rs")]

# Each entry binds an action to its declaration or dispatch entry in the production call path.
OWNERS = {
    "compliance_write": "compliance/http.rs",
    "compliance_read": "compliance/http.rs",
    "agent_registration": "agent.rs",
    "agent_report": "agent.rs",
    "agent_report_read": "api.rs",
    "apple_checkin": "api.rs",
    "apple_management": "api.rs",
    "apple_profile": "api.rs",
    "apple_push": "execution/apple_push.rs",
    "apple_renewal": "apple/renewal.rs",
    "apple_scep": "api.rs",
    "authentication": "api.rs",
    "authorization_departments_read": "api.rs",
    "authorization_effective_read": "api.rs",
    "authorization_groups_read": "api.rs",
    "authorization_initialize": "authorization/store.rs",
    "authorization_members_read": "api.rs",
    "authorization_rules_read": "api.rs",
    "authorization_write": "authorization/store.rs",
    "automation_failed": "planning/automation/health.rs",
    "automation_completed": "automation/jobs.rs",
    "collection_finish": "collection/store.rs",
    "collection_read": "api.rs",
    "collection_start": "collection/apple.rs",
    "command_accept": "execution/actions/http.rs",
    "command_approve": "execution/http.rs",
    "command_cancel": "execution/http.rs",
    "command_dispatch": "execution/recovery.rs",
    "command_read": "execution/actions/http.rs",
    "command_reconcile": "execution/actions/recovery.rs",
    "credential_revoke": "device.rs",
    "device_action": "api.rs",
    "enrollment_cancel": "api.rs",
    "enrollment_create": "api.rs",
    "enrollment_issue": "api.rs",
    "enrollment_read": "api.rs",
    "enrollment_resume": "api.rs",
    "inventory_read": "api.rs",
    "management_read": "execution/recovery.rs",
    "management_write": "resource_catalog/http.rs",
    "protected_request": "api.rs",
    "registration_bind": "device.rs",
    "registration_read": "api.rs",
    "software_binding": "../../software-service/src/publication/storage.rs",
    "software_candidate": "../../software-service/src/publication/service.rs",
    "software_validate": "../../software-service/src/publication/service.rs",
    "software_approve": "../../software-service/src/publication/service.rs",
    "software_authorize": "../../software-service/src/publication/service.rs",
    "software_call": "../../software-service/src/publication/driver.rs",
    "software_preflight": "../../software-service/src/publication/driver.rs",
    "software_result": "../../software-service/src/publication/driver.rs",
    "software_withdraw": "../../software-service/src/publication/driver.rs",
    "windows_discovery": "api.rs",
    "windows_management": "api.rs",
    "windows_policy": "api.rs",
}


DECLARATIONS = {
    ('compliance_write', 'compliance/http.rs'),
    ('compliance_read', 'compliance/http.rs'),
    ('agent_registration', 'agent.rs'),
    ('agent_registration', 'api.rs'),
    ('agent_report', 'agent.rs'),
    ('agent_report', 'api.rs'),
    ('agent_report_read', 'agent.rs'),
    ('agent_report_read', 'api.rs'),
    ('apple_checkin', 'api.rs'),
    ('apple_management', 'api.rs'),
    ('apple_management', 'native/mod.rs'),
    ('apple_profile', 'api.rs'),
    ('apple_push', 'execution/apple_push.rs'),
    ('apple_renewal', 'apple/renewal.rs'),
    ('apple_scep', 'api.rs'),
    ('apple_scep', 'native/mod.rs'),
    ('authentication', 'api.rs'),
    ('authorization_departments_read', 'api.rs'),
    ('authorization_effective_read', 'api.rs'),
    ('authorization_groups_read', 'api.rs'),
    ('authorization_initialize', 'authorization/initialize.rs'),
    ('authorization_initialize', 'authorization/store.rs'),
    ('authorization_members_read', 'api.rs'),
    ('authorization_rules_read', 'api.rs'),
    ('authorization_write', 'api.rs'),
    ('authorization_write', 'authorization/http.rs'),
    ('authorization_write', 'authorization/store.rs'),
    ('automation_completed', 'automation/jobs.rs'),
    ('automation_failed', 'planning/automation/health.rs'),
    ('collection_finish', 'collection/store.rs'),
    ('collection_finish', 'windows/retention.rs'),
    ('collection_read', 'api.rs'),
    ('collection_start', 'api.rs'),
    ('collection_start', 'collection/apple.rs'),
    ('command_accept', 'execution/actions/http.rs'),
    ('command_accept', 'execution/actions/production.rs'),
    ('command_accept', 'execution/http.rs'),
    ('command_approve', 'execution/http.rs'),
    ('command_cancel', 'execution/http.rs'),
    ('command_dispatch', 'execution/actions/recovery.rs'),
    ('command_dispatch', 'execution/recovery.rs'),
    ('command_read', 'execution/actions/http.rs'),
    ('command_read', 'execution/http.rs'),
    ('command_reconcile', 'execution/actions/recovery.rs'),
    ('command_reconcile', 'execution/recovery.rs'),
    ('credential_revoke', 'api.rs'),
    ('credential_revoke', 'device.rs'),
    ('device_action', 'api.rs'),
    ('enrollment_cancel', 'api.rs'),
    ('enrollment_create', 'api.rs'),
    ('enrollment_issue', 'api.rs'),
    ('enrollment_read', 'api.rs'),
    ('enrollment_resume', 'api.rs'),
    ('inventory_read', 'api.rs'),
    ('inventory_read', 'assets/http.rs'),
    ('management_read', 'execution/recovery.rs'),
    ('management_read', 'planning/http.rs'),
    ('management_read', 'software_publication/http.rs'),
    ('management_write', 'content/http.rs'),
    ('management_write', 'execution/actions/recovery.rs'),
    ('management_write', 'execution/recovery.rs'),
    ('management_write', 'assets/http.rs'),
    ('management_write', 'planning/http.rs'),
    ('management_write', 'software_publication/http.rs'),
    ('protected_request', 'api.rs'),
    ('protected_request', 'native/mod.rs'),
    ('registration_bind', 'device.rs'),
    ('registration_read', 'api.rs'),
    ('software_approve', '../../software-service/src/publication/service.rs'),
    ('software_authorize', '../../software-service/src/publication/service.rs'),
    ('software_binding', '../../software-service/src/publication/storage.rs'),
    ('software_call', '../../software-service/src/publication/driver.rs'),
    ('software_candidate', '../../software-service/src/publication/service.rs'),
    ('software_preflight', 'software_publication/http.rs'),
    ('software_preflight', '../../software-service/src/publication/driver.rs'),
    ('software_result', '../../software-service/src/publication/driver.rs'),
    ('software_validate', '../../software-service/src/publication/service.rs'),
    ('software_withdraw', '../../software-service/src/publication/driver.rs'),
    ('windows_discovery', 'api.rs'),
    ('windows_management', 'api.rs'),
    ('windows_management', 'native/mod.rs'),
    ('windows_management', 'windows/management.rs'),
    ('windows_policy', 'api.rs'),
    ('management_read', 'resource_catalog/http.rs'),
    ('management_write', 'resource_catalog/http.rs'),
}


DECLARATIONS.update({("command_read","planning/remote_operations/http.rs")})
DECLARATIONS.update({("management_read","planning/policies/http.rs"),("management_read","planning/policies/preview.rs"),("management_read","planning/remote_operations/http.rs")})
DECLARATIONS.update({('command_accept', 'execution/configuration.rs'), ('command_accept', 'execution/remote.rs'), ('management_write', 'planning/policies/http.rs'), ('management_write', 'planning/remote_operations/http.rs')})
DECLARATIONS.update({('management_read','software_catalog.rs'),('management_read','content/http.rs'),('management_write','software_catalog.rs')})

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
        if "test" in path.stem or "fixture" in path.stem or any(
                part in ("tests", "identity_t2") for part in path.parts):
            continue
        source = path.read_text().split("#[cfg(test)]\nmod tests")[0]
        for call, index in calls.items():
            for match in re.finditer(re.escape(call) + r"\s*\(", source):
                args = arguments(source, match.end())
                if len(args) > index:
                    result.update((action, os.path.relpath(path, ROOT)) for action in re.findall(r'"([a-z_]+)"', args[index]))
    for name, start, end in [("api.rs", "fn route_action", "pub(crate) async fn envelope"),
                              ("native/mod.rs", "const fn audit_action", "pub(crate) fn")]:
        source = (ROOT / name).read_text().split(start, 1)[1].split(end, 1)[0]
        result.update((action, name) for action in re.findall(r'"([a-z_]+)"', source))
    # These two labels are selected inside product dispatch, not passed literally to a call.
    for action, name in [("software_binding", "../../software-service/src/publication/storage.rs"),
                         ("automation_completed", "automation/jobs.rs")]:
        if '"' + action + '"' in (ROOT / name).read_text():
            result.add((action, name))
    return result


class AuditSurface(unittest.TestCase):
    def test_every_declared_action_has_an_explicit_production_owner(self):
        self.assertEqual(declared_actions(), DECLARATIONS)
        self.assertEqual({action for action, _ in DECLARATIONS}, OWNERS.keys())
        for action, owner in OWNERS.items():
            with self.subTest(action=action):
                self.assertIn((action, owner), DECLARATIONS)

    def test_retired_audit_writes_and_transaction_forwarders_do_not_exist(self):
        self.assertFalse((ROOT / "audit.rs").exists())
        self.assertNotIn("'audit'", (ROOT / "execution/dependencies.sql").read_text())
        for path in [*ROOT.rglob("*.rs"), *ROOT.rglob("*.sql")]:
            source = path.read_text()
            self.assertNotIn("mdm_access.audit", source, str(path))
            self.assertNotIn("append_on_connection", source, str(path))

class PrincipalBindingBoundary(unittest.TestCase):
    def test_browser_and_native_producers_use_authorization_owner(self):
        owners = {'authorization/context.rs', 'authorization/store.rs', '../../software-service/src/publication/storage.rs'}
        actual = set()
        for path in production_paths():
            relative = os.path.relpath(path, ROOT)
            if 'tests' in relative or 'identity_fixture' in relative or 'identity_t2' in relative:
                continue
            source = path.read_text().split('#[cfg(test)]\nmod tests')[0]
            self.assertNotRegex(source, r'\.identify(?:_operator)?\(')
            if '.set_principal(' in source:
                actual.add(relative)
        self.assertEqual(actual, owners)
