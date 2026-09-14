"""The source runner must reject Cargo success without the promised behavior."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("source_t2", Path(__file__).with_name("source-t2.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

class ExecutionOracle(unittest.TestCase):
    def test_requires_exact_successful_execution(self):
        good = "test required ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"
        runner.verify_tests(good, {"required"})
        for output in [
            "test result: ok. 0 passed; 0 failed; 0 ignored;",
            good.replace("required", "other"),
            good.replace("0 ignored", "1 ignored"),
            good + "test extra ... ok\n",
            good.replace("... ok", "... ignored"),
            good.replace("1 passed", "2 passed"),
        ]:
            with self.subTest(output=output), self.assertRaises(RuntimeError):
                runner.verify_tests(output, {"required"})

if __name__ == "__main__":
    unittest.main()
