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
    def test_zero_tests_is_not_a_success(self):
        result = subprocess.CompletedProcess([], 0, stdout="test result: ok. 0 passed; 0 failed; 0 ignored; 100 filtered out;\n")
        with patch.object(t2.subprocess, "run", return_value=result):
            with self.assertRaises(RuntimeError):
                t2.run_foundation_tests({})

    def test_wrong_extra_ignored_or_failed_results_are_rejected(self):
        def fake(kind):
            def run(args, **kwargs):
                selected = args[args.index("--lib") + 1]
                name = "wrong::test" if kind == "wrong" else selected
                output = f"test {name} ... ok\n"
                if kind == "extra":
                    output += "test extra::test ... ok\n"
                output += ("test result: ok. 0 passed; 0 failed; 1 ignored;\n" if kind == "ignored"
                           else "test result: ok. 1 passed; 0 failed; 0 ignored;\n")
                return subprocess.CompletedProcess(args, 1 if kind == "failed" else 0, stdout=output)
            return run
        for kind in ["wrong", "extra", "ignored", "failed"]:
            with self.subTest(kind=kind), patch.object(t2.subprocess, "run", side_effect=fake(kind)), patch("builtins.print"):
                with self.assertRaises(RuntimeError):
                    t2.run_foundation_tests({})

    def test_all_three_exact_tests_must_execute(self):
        def run(args, **kwargs):
            self.assertIn("--exact", args)
            self.assertIn("--show-output", args)
            selected = args[args.index("--lib") + 1]
            return subprocess.CompletedProcess(args, 0, stdout=f'test {selected} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n'+'{"event":"mdm_inventory_failure","phase":"projection_run"}\n')
        with patch.object(t2.subprocess, "run", side_effect=run) as runner, patch("builtins.print"):
            t2.run_foundation_tests({})
        self.assertEqual(runner.call_count, 3)


if __name__ == "__main__":
    unittest.main()
