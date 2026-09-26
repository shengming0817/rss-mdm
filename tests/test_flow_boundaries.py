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

    def test_plan_and_execution_progress_have_distinct_storage(self):
        sql = "\n".join(p.read_text() for p in (ROOT / "crates/app/migrations").glob("*.sql"))
        self.assertIn("CREATE TABLE mdm_planning.action_plans", sql)
        self.assertIn("CREATE TABLE mdm_commands.action_progress", sql)
        self.assertFalse("CREATE TABLE mdm_commands.action_plans" in sql)


if __name__ == "__main__":
    unittest.main()
