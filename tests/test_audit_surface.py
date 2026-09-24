"""Production action inventory: source ownership and request/business event boundaries."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1] / "crates/app/src"
# Each entry binds an action to its declaration or dispatch entry in the production call path.
# "both" means the owner produces business facts and the envelope independently settles
# rejection, reads, replay or unknown requests. Internal scheduling cursors are not facts.
OWNERS = {
    "agent_registration": ("agent.rs", "both"),
    "agent_report": ("agent.rs", "both"),
    "agent_report_read": ("api.rs", "request"),
    "apple_checkin": ("api.rs", "both"),
    "apple_management": ("api.rs", "request"),
    "apple_profile": ("api.rs", "both"),
    "apple_push": ("commands/apple_push.rs", "business"),
    "apple_renewal": ("apple/renewal.rs", "business"),
    "apple_scep": ("api.rs", "both"),
    "authentication": ("api.rs", "identity"),
    "authorization_departments_read": ("api.rs", "request"),
    "authorization_effective_read": ("api.rs", "request"),
    "authorization_groups_read": ("api.rs", "request"),
    "authorization_initialize": ("authorization/store.rs", "business"),
    "authorization_members_read": ("api.rs", "request"),
    "authorization_rules_read": ("api.rs", "request"),
    "authorization_write": ("authorization/store.rs", "both"),
    "automation_failed": ("management/automation/completion.rs", "business"),
    "automation_completed": ("management/automation/jobs.rs", "business"),
    "collection_finish": ("collection/store.rs", "business"),
    "collection_read": ("api.rs", "request"),
    "collection_start": ("collection/apple.rs", "both"),
    "command_accept": ("commands/actions/http.rs", "both"),
    "command_approve": ("commands/actions/http.rs", "both"),
    "command_cancel": ("commands/actions/http.rs", "both"),
    "command_dispatch": ("commands/recovery.rs", "business"),
    "command_read": ("commands/actions/http.rs", "both"),
    "command_reconcile": ("commands/actions/recovery.rs", "business"),
    "credential_revoke": ("device.rs", "both"),
    "device_action": ("api.rs", "request"),
    "enrollment_cancel": ("api.rs", "both"),
    "enrollment_create": ("api.rs", "both"),
    "enrollment_issue": ("api.rs", "both"),
    "enrollment_read": ("api.rs", "request"),
    "enrollment_resume": ("api.rs", "both"),
    "inventory_read": ("api.rs", "request"),
    "management_read": ("commands/recovery.rs", "request"),
    "management_write": ("commands/actions/http.rs", "both"),
    "plan_execute": ("commands/http.rs", "both"),
    "plan_preview": ("management/http.rs", "both"),
    "plan_save": ("management/http.rs", "both"),
    "protected_request": ("api.rs", "request"),
    "registration_bind": ("device.rs", "business"),
    "registration_read": ("api.rs", "request"),
    "software_binding": ("software_publication/storage.rs", "business"),
    "software_candidate": ("software_publication/service.rs", "business"),
    "software_validate": ("software_publication/service.rs", "business"),
    "software_approve": ("software_publication/service.rs", "business"),
    "software_authorize": ("software_publication/service.rs", "business"),
    "software_call": ("software_publication/driver.rs", "business"),
    "software_preflight": ("software_publication/driver.rs", "both"),
    "software_result": ("software_publication/driver.rs", "business"),
    "software_withdraw": ("software_publication/driver.rs", "business"),
    "windows_discovery": ("api.rs", "request"),
    "windows_management": ("api.rs", "request"),
    "windows_policy": ("api.rs", "request"),
}


DECLARATIONS = {
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
    ('apple_push', 'commands/apple_push.rs'),
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
    ('automation_completed', 'management/automation/jobs.rs'),
    ('automation_failed', 'management/automation/completion.rs'),
    ('collection_finish', 'collection/store.rs'),
    ('collection_finish', 'windows/retention.rs'),
    ('collection_read', 'api.rs'),
    ('collection_start', 'api.rs'),
    ('collection_start', 'collection/apple.rs'),
    ('command_accept', 'commands/actions/http.rs'),
    ('command_accept', 'commands/actions/production.rs'),
    ('command_accept', 'commands/http.rs'),
    ('command_accept', 'commands/plans.rs'),
    ('command_approve', 'commands/actions/http.rs'),
    ('command_approve', 'commands/http.rs'),
    ('command_cancel', 'commands/actions/http.rs'),
    ('command_cancel', 'commands/http.rs'),
    ('command_dispatch', 'commands/actions/recovery.rs'),
    ('command_dispatch', 'commands/recovery.rs'),
    ('command_read', 'commands/actions/http.rs'),
    ('command_read', 'commands/http.rs'),
    ('command_reconcile', 'commands/actions/recovery.rs'),
    ('command_reconcile', 'commands/recovery.rs'),
    ('credential_revoke', 'api.rs'),
    ('credential_revoke', 'device.rs'),
    ('device_action', 'api.rs'),
    ('enrollment_cancel', 'api.rs'),
    ('enrollment_create', 'api.rs'),
    ('enrollment_issue', 'api.rs'),
    ('enrollment_read', 'api.rs'),
    ('enrollment_resume', 'api.rs'),
    ('inventory_read', 'api.rs'),
    ('inventory_read', 'management/assets/http.rs'),
    ('management_read', 'commands/recovery.rs'),
    ('management_read', 'management/http.rs'),
    ('management_read', 'management/publications.rs'),
    ('management_write', 'commands/actions/http.rs'),
    ('management_write', 'commands/actions/recovery.rs'),
    ('management_write', 'commands/recovery.rs'),
    ('management_write', 'management/assets/http.rs'),
    ('management_write', 'management/http.rs'),
    ('management_write', 'management/publications.rs'),
    ('plan_execute', 'commands/http.rs'),
    ('plan_preview', 'management/http.rs'),
    ('plan_save', 'management/http.rs'),
    ('protected_request', 'api.rs'),
    ('protected_request', 'native/mod.rs'),
    ('registration_bind', 'device.rs'),
    ('registration_read', 'api.rs'),
    ('software_approve', 'software_publication/service.rs'),
    ('software_authorize', 'software_publication/service.rs'),
    ('software_binding', 'software_publication/storage.rs'),
    ('software_call', 'software_publication/driver.rs'),
    ('software_candidate', 'software_publication/service.rs'),
    ('software_preflight', 'management/publications.rs'),
    ('software_preflight', 'software_publication/driver.rs'),
    ('software_result', 'software_publication/driver.rs'),
    ('software_validate', 'software_publication/service.rs'),
    ('software_withdraw', 'software_publication/driver.rs'),
    ('windows_discovery', 'api.rs'),
    ('windows_management', 'api.rs'),
    ('windows_management', 'native/mod.rs'),
    ('windows_management', 'windows/management.rs'),
    ('windows_policy', 'api.rs'),
}


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
    for path in ROOT.rglob("*.rs"):
        if "test" in path.stem or "fixture" in path.stem or any(
                part in ("tests", "identity_t2") for part in path.parts):
            continue
        source = path.read_text().split("#[cfg(test)]\nmod tests")[0]
        for call, index in calls.items():
            for match in re.finditer(re.escape(call) + r"\s*\(", source):
                args = arguments(source, match.end())
                if len(args) > index:
                    result.update((action, str(path.relative_to(ROOT))) for action in re.findall(r'"([a-z_]+)"', args[index]))
    for name, start, end in [("api.rs", "fn route_action", "pub(crate) async fn envelope"),
                              ("native/mod.rs", "const fn audit_action", "pub(crate) fn")]:
        source = (ROOT / name).read_text().split(start, 1)[1].split(end, 1)[0]
        result.update((action, name) for action in re.findall(r'"([a-z_]+)"', source))
    # These two labels are selected inside product dispatch, not passed literally to a call.
    for action, name in [("software_binding", "software_publication/storage.rs"),
                         ("automation_completed", "management/automation/jobs.rs")]:
        if '"' + action + '"' in (ROOT / name).read_text():
            result.add((action, name))
    return result


class AuditSurface(unittest.TestCase):
    def test_every_declared_action_has_an_explicit_production_owner(self):
        self.assertEqual(declared_actions(), DECLARATIONS)
        self.assertEqual({action for action, _ in DECLARATIONS}, OWNERS.keys())
        for action, (owner, kind) in OWNERS.items():
            with self.subTest(action=action):
                self.assertIn((action, owner), DECLARATIONS)
                self.assertIn(kind, {"request", "business", "both", "identity"})

    def test_retired_audit_writes_and_transaction_forwarders_do_not_exist(self):
        self.assertFalse((ROOT / "audit.rs").exists())
        for path in ROOT.rglob("*.rs"):
            source = path.read_text()
            self.assertNotIn("mdm_access.audit", source, str(path))
            self.assertNotIn("append_on_connection", source, str(path))
