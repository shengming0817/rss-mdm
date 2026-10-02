"""Product flow ownership: prevent reintroducing the composite service graph."""
from pathlib import Path
import unittest
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"hack"))
from rust_test_layout import is_test_path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "crates/app/src"
FLOW = ROOT / "crates/flow-service/src"
INVENTORY = ROOT / "crates/inventory-service/src"
EXECUTION = ROOT / "crates/execution-service/src"


class FlowOwnership(unittest.TestCase):
    def test_capability_owners_replace_composite_services(self):
        for owner in ("resource_catalog", "planning", "assets"):
            self.assertTrue(((INVENTORY if owner == "assets" else FLOW) / owner / "mod.rs").is_file(), owner)
        self.assertTrue((EXECUTION / "lib.rs").is_file())
        self.assertFalse((FLOW / "execution").exists())
        self.assertFalse((APP / "management").exists())
        self.assertFalse((APP / "commands").exists())

    def test_flow_policy_only_retains_input_preparation(self):
        policy = (FLOW / "planning/policies/mod.rs").read_text()
        for forbidden in ("ExecutionRead", "Arc<ExecutionService>", "Arc<Queries>"):
            self.assertNotIn(forbidden, policy)
        manifest = (ROOT / "crates/execution-service/Cargo.toml").read_text()
        self.assertNotIn("rss-mdm-flow-service", manifest)

    def test_execution_cannot_write_authored_policies(self):
        files = list(EXECUTION.rglob("*.rs"))
        self.assertTrue(files)
        for path in files:
            text = path.read_text()
            for forbidden in ("INSERT INTO mdm_policy.policies",
                              "UPDATE mdm_policy.policies",
                              "INSERT INTO mdm_policy.versions",
                              "UPDATE mdm_policy.versions", "crate::management::"):
                self.assertNotIn(forbidden, text, str(path))

    def test_retired_plan_model_and_authority_do_not_escape_to_execution(self):
        for path in EXECUTION.rglob("*.rs"):
            text = path.read_text()
            for forbidden in ("planning::actions::storage", "planning::actions::model", "ActionDispatch"):
                self.assertNotIn(forbidden, text, str(path))

    def test_content_capabilities_and_settlement_have_one_owner(self):
        content = (ROOT / "crates/content-service/src/lib.rs").read_text()
        self.assertNotIn("Ed25519KeyPair", content)
        self.assertFalse((APP / "task_content.rs").exists())
        self.assertTrue((EXECUTION / "task_signing.rs").is_file())
        self.assertFalse((APP / "mutation.rs").exists())
        self.assertFalse((APP / "execution_transaction.rs").exists())
        for path in (FLOW / "planning").rglob("*.rs"):
            if is_test_path(path):
                continue
            self.assertNotIn("crate::flow::", path.read_text(), str(path))

    def test_each_receipt_owner_has_a_distinct_audit_identity(self):
        for owner in ("planning", "assets", "resource_catalog"):
            self.assertRegex( ((INVENTORY if owner == "assets" else FLOW) / owner / "receipts.rs").read_text(), r'format!\(\s*"' + owner + r':\{\}:\{id\}"')

        self.assertRegex((ROOT / "crates/software-service/src/management/publication/receipts.rs").read_text(), r'format!\(\s*"software_publication:\{\}:\{id\}"')

    def test_task_and_planning_pages_cannot_project_inventory_errors(self):
        for path in (EXECUTION / "actions/storage.rs", EXECUTION / "actions/history.rs",
                     FLOW / "planning/pages.rs", FLOW / "planning/pages/scope.rs"):
            self.assertNotIn("Error::NotFound", path.read_text(), str(path))

    def test_policy_and_execution_progress_have_distinct_storage(self):
        schema = (ROOT / "crates/policy-postgres/migrations/0001.sql").read_text()
        self.assertIn("CREATE TABLE mdm_policy.policies", schema)
        app_sql = (ROOT / "crates/execution-service/schema/install.sql").read_text()
        self.assertIn("CREATE TABLE mdm_commands.action_runs", app_sql)
        self.assertNotIn("CREATE TABLE mdm_policy.policies", app_sql)
        self.assertNotIn("CREATE TABLE mdm_planning.action_plans", app_sql)
        self.assertNotIn("policy_target_work", app_sql)


if __name__ == "__main__":
    unittest.main()
