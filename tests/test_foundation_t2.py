import importlib.util
from pathlib import Path
import subprocess
import unittest
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "hack"))
spec = importlib.util.spec_from_file_location("foundation_t2", Path(__file__).resolve().parents[1] / "hack/t2_suites/product.py")
t2 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t2)


class FoundationSelection(unittest.TestCase):
    def test_all_three_exact_tests_must_execute(self):
        def run(args, **kwargs):
            self.assertIn("--exact", args)
            self.assertIn("--nocapture", args)
            selected = args[args.index("--lib") + 1]
            return subprocess.CompletedProcess(args, 0, stdout=f'test {selected} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n'+'{"event":"mdm_inventory_failure","phase":"projection_run"}\n')
        with patch.object(t2.subprocess, "run", side_effect=run) as runner, patch("builtins.print"):
            t2.run_foundation_tests({})
        self.assertEqual(runner.call_count, 3)


if __name__ == "__main__":
    unittest.main()
