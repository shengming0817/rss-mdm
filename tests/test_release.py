import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("release", Path(__file__).resolve().parents[1] / "hack/release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class CandidatePublication(unittest.TestCase):
    def test_failed_acquisition_leaves_output_available_for_retry(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            header = root / "header"
            header.write_text("disposable-test-header")
            header.chmod(0o600)
            output = root / "candidate"
            for _ in range(2):
                with mock.patch.object(release, "run", side_effect=["", "a" * 40]), mock.patch.object(
                    release.subprocess, "run", side_effect=RuntimeError("source archive unavailable")
                ):
                    with self.assertRaisesRegex(RuntimeError, "source archive unavailable"):
                        release.build(output, header)
                self.assertFalse(output.exists())
                self.assertEqual(sorted(p.name for p in root.iterdir()), ["header"])


if __name__ == "__main__":
    unittest.main()
