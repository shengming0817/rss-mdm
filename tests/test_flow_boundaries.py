"""Product flow ownership: prevent reintroducing the pre-2521 service graph."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "crates/app/src"


class FlowOwnership(unittest.TestCase):
    def test_capability_owners_replace_composite_services(self):
        for owner in ("resource_catalog", "planning", "execution", "assets"):
            self.assertTrue((APP / owner / "mod.rs").is_file(), owner)
        self.assertFalse((APP / "management").exists())
        self.assertFalse((APP / "commands").exists())

    def test_execution_cannot_write_authored_policies(self):
        files = list((APP / "execution").rglob("*.rs"))
        self.assertTrue(files)
        for path in files:
            text = path.read_text()
            for forbidden in ("INSERT INTO mdm_policy.policies",
                              "UPDATE mdm_policy.policies",
                              "crate::management::", "crate::planning::configuration"):
                self.assertNotIn(forbidden, text, str(path))

    def test_retired_plan_model_and_authority_do_not_escape_to_execution(self):
        for path in (APP / "execution").rglob("*.rs"):
            text = path.read_text()
            for forbidden in ("planning::actions::storage", "planning::actions::model", "ActionDispatch"):
                self.assertNotIn(forbidden, text, str(path))

    def test_content_capabilities_and_settlement_have_one_owner(self):
        content = (APP / "content/mod.rs").read_text()
        self.assertNotIn("Ed25519KeyPair", content)
        self.assertFalse((APP / "task_content.rs").exists())
        self.assertTrue((APP / "task_signing.rs").is_file())
        self.assertFalse((APP / "mutation.rs").exists())
        self.assertFalse((APP / "execution_transaction.rs").exists())
        for path in (APP / "planning").rglob("*.rs"):
            if path.name.endswith("tests.rs"):
                continue
            self.assertNotIn("crate::flow::", path.read_text(), str(path))

    def test_each_receipt_owner_has_a_distinct_audit_identity(self):
        for owner in ("planning", "assets", "resource_catalog"):
            self.assertIn('format!("' + owner + ':{id}")', (APP / owner / "receipts.rs").read_text())

        self.assertIn('format!("software_publication:{id}")', (ROOT / "crates/software-service/src/publication/receipts.rs").read_text())

    def test_task_and_planning_pages_cannot_project_inventory_errors(self):
        for name in ("execution/actions/storage.rs", "execution/actions/history.rs", "planning/pages.rs", "planning/pages/scope.rs"):
            self.assertNotIn("Error::NotFound", (APP / name).read_text(), name)

    def test_policy_and_execution_progress_have_distinct_storage(self):
        schema = (ROOT / "crates/policy-postgres/migrations/0001.sql").read_text()
        self.assertIn("CREATE TABLE mdm_policy.policies", schema)
        app_sql = "\n".join(p.read_text() for p in (ROOT / "crates/app/migrations").glob("*.sql"))
        self.assertIn("CREATE TABLE mdm_commands.action_runs", app_sql)
        self.assertNotIn("CREATE TABLE mdm_policy.policies", app_sql)
        self.assertNotIn("CREATE TABLE mdm_planning.action_plans", app_sql)
        self.assertNotIn("policy_target_work", app_sql)


if __name__ == "__main__":
    unittest.main()
