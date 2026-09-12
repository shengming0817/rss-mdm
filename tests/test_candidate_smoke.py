import sys
from pathlib import Path
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "hack"))
import candidate_smoke as candidate


class SmokeCompletion(unittest.TestCase):
    def test_cleanup_attempts_every_owned_resource(self):
        with mock.patch.object(candidate.identity, "docker", side_effect=[RuntimeError("first"), "", ""]) as docker:
            with self.assertRaisesRegex(RuntimeError, "candidate cleanup failed"):
                candidate.cleanup(["proxy", "server"], "inputs")
            self.assertEqual(docker.call_args_list, [mock.call("rm", "-f", "server"), mock.call("rm", "-f", "proxy"), mock.call("volume", "rm", "inputs")])

    def test_failed_verification_cannot_leave_success_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name in ["smoke.json", "smoke.log"]:
                (directory / name).write_text("stale success")
            with mock.patch.object(candidate, "run_smoke", side_effect=RuntimeError("cleanup rejected")):
                with self.assertRaisesRegex(RuntimeError, "cleanup rejected"):
                    candidate.smoke(directory)
            self.assertFalse((directory / "smoke.json").exists())
            self.assertFalse((directory / "smoke.log").exists())

    def test_publication_failure_leaves_no_success_marker(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with mock.patch.object(candidate, "run_smoke", return_value=({"revision": "fixture"}, "logs")), mock.patch.object(candidate.os, "replace", side_effect=OSError("disk failure")):
                with self.assertRaisesRegex(OSError, "disk failure"):
                    candidate.smoke(directory)
            self.assertEqual(list(directory.iterdir()), [])

    def test_cleanup_preserves_primary_and_records_cleanup_failure(self):
        primary = RuntimeError("verification failed")
        with mock.patch.object(candidate.identity, "docker", side_effect=RuntimeError("cleanup failed")):
            with self.assertRaisesRegex(RuntimeError, "verification failed"):
                try:
                    raise primary
                finally:
                    candidate.cleanup(["server"], "inputs")
        self.assertEqual(primary.__notes__, ["candidate cleanup failed (2 resources)"])
