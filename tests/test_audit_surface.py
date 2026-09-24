"""Production action inventory: source ownership and request/business event boundaries."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1] / "crates/app/src"
# Each entry names the actual producing call path, not a legacy table or forwarding facade.
# "both" means the owner produces business facts and the envelope independently settles
# rejection, reads, replay or unknown requests. Internal scheduling cursors are not facts.
OWNERS = {
    "agent_registration": ("agent.rs", "both"),
    "agent_report": ("agent.rs", "both"),
    "agent_report_read": ("api.rs", "request"),
    "apple_checkin": ("apple/checkin.rs", "both"),
    "apple_management": ("commands/apple.rs", "request"),
    "apple_profile": ("apple/enrollment.rs", "both"),
    "apple_push": ("commands/apple_push.rs", "business"),
    "apple_renewal": ("apple/renewal.rs", "business"),
    "apple_scep": ("apple/enrollment.rs", "both"),
    "authentication": ("identity.rs", "identity"),
    "authorization_departments_read": ("api.rs", "request"),
    "authorization_effective_read": ("api.rs", "request"),
    "authorization_groups_read": ("api.rs", "request"),
    "authorization_initialize": ("authorization/store.rs", "business"),
    "authorization_members_read": ("api.rs", "request"),
    "authorization_rules_read": ("api.rs", "request"),
    "authorization_write": ("authorization/store.rs", "both"),
    "automation_failed": ("management/automation/jobs.rs", "business"),
    "automation_completed": ("management/automation/jobs.rs", "business"),
    "collection_finish": ("collection/store.rs", "business"),
    "collection_read": ("api.rs", "request"),
    "collection_start": ("collection/apple.rs", "both"),
    "command_accept": ("commands/service.rs", "both"),
    "command_approve": ("commands/actions/service.rs", "both"),
    "command_cancel": ("commands/service.rs", "both"),
    "command_dispatch": ("commands/recovery.rs", "business"),
    "command_read": ("commands/actions/agent.rs", "both"),
    "command_reconcile": ("commands/actions/recovery.rs", "business"),
    "credential_revoke": ("device.rs", "both"),
    "device_action": ("api.rs", "request"),
    "enrollment_cancel": ("enrollment/store.rs", "both"),
    "enrollment_create": ("enrollment/store.rs", "both"),
    "enrollment_issue": ("windows/issuance.rs", "both"),
    "enrollment_read": ("api.rs", "request"),
    "enrollment_resume": ("enrollment/store.rs", "both"),
    "inventory_read": ("api.rs", "request"),
    "management_read": ("management/transaction.rs", "request"),
    "management_write": ("management/transaction.rs", "both"),
    "plan_execute": ("commands/plans.rs", "both"),
    "plan_preview": ("management/transaction.rs", "both"),
    "plan_save": ("management/transaction.rs", "both"),
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
    "windows_management": ("commands/protocol.rs", "request"),
    "windows_policy": ("api.rs", "request"),
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
                    result.update(re.findall(r'"([a-z_]+)"', args[index]))
    for name, start, end in [("api.rs", "fn route_action", "pub(crate) async fn envelope"),
                              ("native/mod.rs", "const fn audit_action", "pub(crate) fn")]:
        source = (ROOT / name).read_text().split(start, 1)[1].split(end, 1)[0]
        result.update(re.findall(r'"([a-z_]+)"', source))
    return result


class AuditSurface(unittest.TestCase):
    def test_every_declared_action_has_an_explicit_production_owner(self):
        self.assertFalse(declared_actions() - OWNERS.keys())
        for action, (owner, kind) in OWNERS.items():
            with self.subTest(action=action):
                self.assertTrue((ROOT / owner).is_file())
                self.assertIn(kind, {"request", "business", "both", "identity"})

    def test_retired_audit_writes_and_transaction_forwarders_do_not_exist(self):
        self.assertFalse((ROOT / "audit.rs").exists())
        for path in ROOT.rglob("*.rs"):
            source = path.read_text()
            self.assertNotIn("mdm_access.audit", source, str(path))
            self.assertNotIn("append_on_connection", source, str(path))
