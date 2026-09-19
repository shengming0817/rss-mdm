import sys
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "hack"))
import candidate_smoke as smoke
import candidate_runtime as candidate


class SmokeCompletion(unittest.TestCase):
    def test_readiness_retries_temporary_html_gateway_error(self):
        browser = smoke.Browser.__new__(smoke.Browser)
        browser.port, browser.context, browser.cookie, browser.csrf = 443, None, "", ""
        unavailable = mock.Mock(status=502)
        unavailable.getheaders.return_value = []
        unavailable.getheader.return_value = "text/html"
        unavailable.read.return_value = b"<html>Bad Gateway</html>"
        ready = mock.Mock(status=200)
        ready.getheaders.return_value = []
        ready.getheader.return_value = "application/json"
        ready.read.return_value = b'{"ready":true}'
        with mock.patch.object(candidate.http.client, "HTTPSConnection") as connect:
            connect.return_value.getresponse.side_effect = [unavailable, ready]
            candidate.wait(lambda: browser.call("GET", "/readyz") == (200, {"ready":True}), "readiness", seconds=1)
            self.assertEqual(connect.call_count, 2)
            self.assertEqual(connect.return_value.close.call_count, 2)

    def test_candidate_diagnostics_include_stderr_without_exposing_command_errors(self):
        result = mock.Mock(returncode=0, stdout="", stderr='{"event":"mdm_shutdown_failure"}\n')
        with mock.patch.object(candidate.subprocess, "run", return_value=result):
            self.assertIn("mdm_shutdown_failure", candidate.docker("logs", "server",stage=candidate.Stage.LOGS))
            result.returncode = 1
            result.stderr = "synthetic-private-input"
            failures = []
            for stage in [candidate.Stage.POSTGRES,candidate.Stage.MIGRATION,candidate.Stage.INITIALIZE,candidate.Stage.SERVER]:
                with self.assertRaises(candidate.DockerFailure) as failure:
                    candidate.docker("run", "synthetic-private-input",stage=stage)
                failures.append(str(failure.exception))
                self.assertIn("stage="+stage.value, failures[-1])
                self.assertIn("exit_code=1", failures[-1])
                self.assertNotIn("synthetic-private-input", failures[-1])
            self.assertEqual(len(set(failures)),4)

    def test_docker_timeout_and_persisted_failure_retain_only_closed_fields(self):
        private="synthetic-private-input"
        timeout=candidate.subprocess.TimeoutExpired(["docker","run",private],1,output=private,stderr=private)
        with mock.patch.object(candidate.subprocess,"run",side_effect=timeout):
            with self.assertRaises(candidate.DockerFailure) as failure:
                candidate.docker("run",private,stage=candidate.Stage.MIGRATION)
        self.assertNotIn(private,str(failure.exception))
        with tempfile.TemporaryDirectory() as temporary:
            candidate.failure_evidence(Path(temporary),[],set(),failure.exception)
            evidence=(Path(temporary)/"smoke-failure.json").read_text()
            self.assertNotIn(private,evidence)
            self.assertEqual(json.loads(evidence),{"status":"failed","error_class":"DockerFailure","containers":{},"stage":"migration","outcome":"timeout","exit_code":None})

    def test_cleanup_attempts_every_owned_resource(self):
        with mock.patch.object(candidate, "docker", side_effect=[RuntimeError("first"), "", ""]) as docker:
            with self.assertRaisesRegex(RuntimeError, "candidate cleanup failed"):
                candidate.cleanup(["proxy", "server"], "inputs")
            self.assertEqual(docker.call_args_list, [mock.call("rm", "-f", "server",stage=candidate.Stage.REMOVE_CONTAINER), mock.call("rm", "-f", "proxy",stage=candidate.Stage.REMOVE_CONTAINER), mock.call("volume", "rm", "inputs",stage=candidate.Stage.REMOVE_VOLUME)])

    def test_failed_verification_cannot_leave_success_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name in ["smoke.json", "smoke.log"]:
                (directory / name).write_text("stale success")
            with mock.patch.object(smoke, "run_smoke", side_effect=RuntimeError("cleanup rejected")):
                with self.assertRaisesRegex(RuntimeError, "cleanup rejected"):
                    smoke.smoke(directory, "fixture-ui")
            self.assertFalse((directory / "smoke.json").exists())
            self.assertFalse((directory / "smoke.log").exists())

    def test_publication_failure_leaves_no_success_marker(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with mock.patch.object(smoke, "run_smoke", return_value=({"revision": "fixture"}, "logs")), mock.patch.object(candidate.os, "replace", side_effect=OSError("disk failure")):
                with self.assertRaisesRegex(OSError, "disk failure"):
                    smoke.smoke(directory, "fixture-ui")
            self.assertEqual(list(directory.iterdir()), [])

    def test_cleanup_preserves_primary_and_records_cleanup_failure(self):
        primary = RuntimeError("verification failed")
        with mock.patch.object(candidate, "docker", side_effect=RuntimeError("cleanup failed")):
            with self.assertRaisesRegex(RuntimeError, "verification failed"):
                try:
                    raise primary
                finally:
                    candidate.cleanup(["server"], "inputs")
        self.assertEqual(primary.__notes__, ["candidate cleanup failed (2 resources)"])


class RuntimeOwnership(unittest.TestCase):
    def test_operator_preserves_exact_stage(self):
        owner=candidate.Candidate.__new__(candidate.Candidate)
        owner.pg,owner.operator_volume,owner.image='pg','operator','image'
        owner.command=mock.Mock(return_value='')
        for stage in [candidate.Stage.MIGRATION,candidate.Stage.REPLAY,candidate.Stage.INITIALIZE]:
            owner.operator('migrate','input.json',stage)
            self.assertEqual(owner.command.call_args.kwargs['stage'],stage)

    def test_network_cleanup_does_not_replace_primary(self):
        primary=RuntimeError('browser rejected')
        with mock.patch.object(candidate,'docker',side_effect=RuntimeError('cleanup')) as command:
            with self.assertRaisesRegex(RuntimeError,'browser rejected'):
                try:raise primary
                finally:candidate.cleanup(['server'],['volume'],'network')
            self.assertEqual(command.call_count,3)
        self.assertIn('3 resources',primary.__notes__[0])

    def test_two_owners_keep_both_failure_records(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            for owner in ['first','second']:
                candidate.failure_evidence(root,[],set(),RuntimeError('failed'),owner+'-failure.json')
            self.assertEqual(len(list(root.glob('*-failure.json'))),2)
