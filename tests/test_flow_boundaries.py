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

    def test_execution_cannot_write_authored_plans(self):
        files = list((APP / "execution").rglob("*.rs"))
        self.assertTrue(files)
        for path in files:
            text = path.read_text()
            for forbidden in ("INSERT INTO mdm_planning.action_plans",
                              "UPDATE mdm_planning.action_plans",
                              "crate::management::", "crate::planning::configuration"):
                self.assertNotIn(forbidden, text, str(path))

    def test_private_plan_model_and_authority_do_not_escape_to_execution(self):
        for path in (APP / "execution").rglob("*.rs"):
            text = path.read_text()
            for forbidden in ("planning::actions::storage", "planning::actions::model", "ActionDispatch"):
                self.assertNotIn(forbidden, text, str(path))
        role_sql = (ROOT / "crates/app/migrations/0016_enterprise_tasks.sql").read_text()
        for statement in role_sql.split(";"):
            if "GRANT" in statement and "mdm_planning.action_plans" in statement and "TO mdm_command_runtime" in statement:
                self.assertNotIn("INSERT", statement)
                self.assertNotIn("UPDATE", statement)

    def test_content_capabilities_and_settlement_have_one_owner(self):
        content = (APP / "task_content.rs").read_text()
        for capability in ("ArtifactReader", "ArtifactWriter", "TaskSigner"):
            self.assertIn("trait " + capability, content)
        self.assertNotIn("ContentPort", content)
        self.assertFalse((APP / "mutation.rs").exists())
        self.assertFalse((APP / "execution_transaction.rs").exists())
        for path in (APP / "planning").rglob("*.rs"):
            if path.name.endswith("tests.rs"):
                continue
            self.assertNotIn("crate::flow::", path.read_text(), str(path))

    def test_each_receipt_owner_has_a_distinct_audit_identity(self):
        for owner in ("planning", "assets", "resource_catalog", "software_publication"):
            self.assertIn('format!("' + owner + ':{id}")', (APP / owner / "receipts.rs").read_text())

    def test_task_and_planning_pages_cannot_project_inventory_errors(self):
        for name in ("execution/actions/storage.rs", "execution/actions/history.rs", "planning/pages.rs", "planning/pages/scope.rs", "planning/pages/policy.rs"):
            self.assertNotIn("Error::NotFound", (APP / name).read_text(), name)

    def test_plan_and_execution_progress_have_distinct_storage(self):
        sql = "\n".join(p.read_text() for p in (ROOT / "crates/app/migrations").glob("*.sql"))
        self.assertIn("CREATE TABLE mdm_planning.action_plans", sql)
        self.assertIn("CREATE TABLE mdm_commands.action_progress", sql)
        self.assertFalse("CREATE TABLE mdm_commands.action_plans" in sql)


if __name__ == "__main__":
    unittest.main()
