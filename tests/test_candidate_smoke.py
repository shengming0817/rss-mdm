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
        browser.port, browser.context, browser.cookie, browser.csrf = 443, mock.Mock(), "", ""
        browser.host="mdm.example.test"
        unavailable = mock.Mock(status=502)
        unavailable.getheaders.return_value = []
        unavailable.getheader.side_effect = lambda name, default=None: {"Content-Type":"text/html"}.get(name, default)
        unavailable.read.return_value = b"<html>Bad Gateway</html>"
        ready = mock.Mock(status=200)
        ready.getheaders.return_value = []
        ready.getheader.side_effect = lambda name, default=None: {"Content-Type":"application/json"}.get(name, default)
        ready.read.return_value = b'{"ready":true}'
        with mock.patch.object(candidate.http.client, "HTTPSConnection") as connect, mock.patch.object(smoke.socket, "create_connection"):
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
                owner=candidate.Candidate.__new__(candidate.Candidate)
                owner.name="owned";owner.created=["proxy","server"];owner.volumes=["inputs"]
                owner.server="server";owner.gateway="gateway";owner.private_values=[]
                owner.diagnostics=Path("unused");owner.diagnostic_filename="failure.json"
                owner.compose_environment={"owned":"compose"};owner.compose=mock.Mock()
                owner.ingress=None;owner.pki_stack=mock.Mock();owner.temporary=mock.Mock()
                with mock.patch.object(candidate,"failure_evidence"):
                    owner.__exit__(None,None,None)
            self.assertEqual(docker.call_args_list, [mock.call("rm", "-f", "server",stage=candidate.Stage.REMOVE_CONTAINER), mock.call("rm", "-f", "proxy",stage=candidate.Stage.REMOVE_CONTAINER), mock.call("volume", "rm", "inputs",stage=candidate.Stage.REMOVE_VOLUME)])

    def test_failed_verification_cannot_leave_success_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name in ["smoke.json", "smoke.log"]:
                (directory / name).write_text("stale success")
            with mock.patch.object(smoke, "run_smoke", side_effect=RuntimeError("cleanup rejected")):
                with self.assertRaisesRegex(RuntimeError, "cleanup rejected"):
                    smoke.smoke(directory)
            self.assertFalse((directory / "smoke.json").exists())
            self.assertFalse((directory / "smoke.log").exists())

    def test_publication_failure_leaves_no_success_marker(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with mock.patch.object(smoke, "run_smoke", return_value=({"revision": "fixture"}, "logs")), mock.patch.object(candidate.os, "replace", side_effect=OSError("disk failure")):
                with self.assertRaisesRegex(OSError, "disk failure"):
                    smoke.smoke(directory)
            # The mocked os.replace also rejects failure evidence publication.
            self.assertEqual(list(directory.iterdir()), [])

    def test_cleanup_preserves_primary_and_records_cleanup_failure(self):
        for primary in [RuntimeError("verification failed"),None]:
            with self.subTest(primary=primary),tempfile.TemporaryDirectory() as temporary:
                owner=candidate.Candidate.__new__(candidate.Candidate)
                owner.name="owned";owner.created=["server","idp"];owner.volumes=["inputs"]
                owner.server="server";owner.gateway="gateway";owner.private_values=[]
                owner.diagnostics=Path(temporary);owner.diagnostic_filename="failure.json"
                owner.compose_environment={"owned":"compose"}
                owner.compose=mock.Mock(side_effect=candidate.DockerFailure(candidate.Stage.REMOVE_CONTAINER,"exit",9))
                owner.ingress=None;owner.pki_stack=mock.Mock();owner.temporary=mock.Mock()
                owner.pki_stack.close.side_effect=RuntimeError("PKI cleanup")
                def docker(*args,**kwargs):
                    if args[0]=='inspect':return 'running:0'
                    if args[0]=='logs':return 'safe product log'
                    raise candidate.DockerFailure(kwargs['stage'],'exit',7)
                with mock.patch.object(candidate,'docker',side_effect=docker):
                    with self.assertRaises(RuntimeError) as caught:
                        if primary:
                            try:raise primary
                            finally:owner.__exit__(type(primary),primary,None)
                        else:owner.__exit__(None,None,None)
                if primary:self.assertIs(caught.exception,primary)
                evidence=json.loads((Path(temporary)/'failure.json').read_text())
                self.assertEqual(evidence['error_class'],'RuntimeError' if primary else 'CleanupFailure')
                self.assertEqual({r['name'] for r in evidence['cleanup']},{'server','idp','inputs','owned'})
                self.assertTrue(any(r['stage']=='pki' for r in evidence['cleanup']))
                self.assertTrue(any(r['exit_code']==9 for r in evidence['cleanup']))
                if primary:self.assertEqual(evidence['containers']['server']['log'],'safe product log')
                owner.temporary.cleanup.assert_not_called()


class RuntimeOwnership(unittest.TestCase):
    def test_constructor_failure_has_closed_diagnostics_and_no_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'candidate.json').write_text('{"format_version":2}')
            with self.assertRaisesRegex(RuntimeError, 'V1 required'):
                smoke.smoke(root)
            record = json.loads((root / 'smoke-failure.json').read_text())
            self.assertEqual(record, {'status':'failed', 'error_class':'RuntimeError', 'containers':{}})
            self.assertFalse((root / 'smoke.json').exists())

    def test_backend_constructor_skips_ui_but_browser_requires_it(self):
        manifest = {"image":"server@sha256:fixture", "archive":{"manifest_digest":"sha256:fixture"}, "providers":{"nginx":"nginx@sha256:fixture"}}
        with mock.patch.object(candidate, "verify_candidate", return_value=manifest), \
             mock.patch.object(candidate, "image_identity", return_value={"id":"server-id"}) as inspect, \
             mock.patch.object(candidate, "load_ui") as load:
            owner = candidate.Candidate(Path("candidate"))
            self.assertIsNone(owner.web)
            load.assert_not_called()
            inspect.reset_mock()
            with self.assertRaisesRegex(RuntimeError, "requires a UI image.*--web-image"):
                candidate.Candidate(Path("candidate"), require_ui=True)
            inspect.assert_not_called()
            manifest["ui"] = {"archive": "invalid"}
            load.side_effect = RuntimeError("UI archive mismatch")
            with self.assertRaisesRegex(RuntimeError, "UI archive mismatch"):
                candidate.Candidate(Path("candidate"))

    def test_gateway_and_operator_use_canonical_compose_services(self):
        owner=candidate.Candidate.__new__(candidate.Candidate)
        owner.gateway='gateway';owner.created=[];owner.web=None
        owner.compose=mock.Mock(return_value='');owner.container=mock.Mock(return_value='owned-gateway')
        owner.start_gateway()
        owner.compose.assert_called_once_with('up','-d','--no-deps','gateway',stage=candidate.Stage.GATEWAY)
        self.assertEqual(owner.created,['owned-gateway'])
        owner.compose.reset_mock()
        owner.operator('migrate','migrate.json',candidate.Stage.MIGRATION)
        owner.compose.assert_called_once_with('run','--rm','--no-deps','operator','migrate','--config','/run/mdm/migrate.json',stage=candidate.Stage.MIGRATION)

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

    def test_smoke_explicitly_selects_fixed_diagnostic_filename(self):
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(smoke,'Candidate') as factory:
            factory.return_value.__enter__.side_effect=RuntimeError('fixture failure')
            with self.assertRaisesRegex(RuntimeError,'fixture failure'):
                smoke.smoke(Path(temp))
            factory.assert_called_once_with(Path(temp),diagnostic_filename='smoke-failure.json')


class ExternalReviewRegressions(unittest.TestCase):
    def test_owned_timeout_reclaims_daemon_container(self):
        created=[]
        with mock.patch.object(candidate,'docker',side_effect=[candidate.DockerFailure(candidate.Stage.MIGRATION,'timeout'), '']) as command:
            with self.assertRaises(candidate.DockerFailure):
                candidate.run_owned(created,'test-owner','image','sleep','60',stage=candidate.Stage.MIGRATION)
        self.assertEqual(created,[])
        first=command.call_args_list[0].args
        self.assertEqual(first[:2],('run','--name'))
        self.assertEqual(command.call_args_list[1].args,('rm','-f',first[2]))

    def test_cleanup_failure_preserves_resource_and_closed_outcome(self):
        with mock.patch.object(candidate,'docker',side_effect=candidate.DockerFailure(candidate.Stage.REMOVE_VOLUME,'exit',7)):
            with self.assertRaises(candidate.CleanupFailure) as failure:
                candidate.cleanup([],['owned-volume'])
        self.assertEqual(failure.exception.cleanup_records,[{'kind':'volume','name':'owned-volume','stage':'cleanup-volume','outcome':'exit','exit_code':7}])

    def test_host_fixture_keeps_private_directory_and_tls_key(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            candidate.inputs(root,Path(__file__).resolve().parents[1]/'fixtures/mdm-config.example.json',Path(__file__).resolve().parents[1]/'deployment')
            self.assertEqual(root.stat().st_mode & 0o077,0)
            self.assertEqual((root/'server.key').stat().st_mode & 0o077,0)
            verified=candidate.subprocess.run([
                'openssl','verify','-x509_strict','-purpose','sslserver',
                '-verify_hostname','localhost','-CAfile',str(root/'ca.crt'),str(root/'server.crt')
            ],capture_output=True,text=True,timeout=10)
            self.assertEqual(verified.returncode,0,verified.stderr)


    def test_ui_archive_mismatch_fails_before_image_load(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/'ui.tar').write_bytes(b'changed')
            with mock.patch.object(candidate,'docker') as command:
                with self.assertRaisesRegex(RuntimeError,'UI archive mismatch'):
                    candidate.load_ui(root,{'archive':{'file':'ui.tar','sha256':'0'*64}})
                command.assert_not_called()

class CandidateInputs(unittest.TestCase):
    def test_delivered_inputs_reject_missing_or_changed_material(self):
        import release
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / 'server.oci.tar'; archive.write_bytes(b'oci')
            deployment = {}
            for name in release.DEPLOYMENT_FILES:
                path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes((release.ROOT/('fixtures/'+name if name == 'mdm-config.example.json' else 'apps/server/schema/'+Path(name).name if name.endswith('-roles.sql') else name)).read_bytes())
                deployment[name] = release.sha(path)
            installer=root/'rss-mdm-installer';installer.write_bytes(b'fixed-binary')
            operator=root/'installer.oci.tar';operator.write_bytes(b'operator-oci')
            tools={}
            for name in release.RUNTIME_TOOLS:
                path=root/'tools'/name;path.parent.mkdir(exist_ok=True);path.write_bytes((release.ROOT/'hack'/name).read_bytes());tools[name]=release.sha(path)
            manifest = {'format_version':1, 'tools':tools, 'installer':{'file':installer.name,'sha256':release.sha(installer),'image':'operator@sha256:fixture','archive':{'file':operator.name,'sha256':release.sha(operator),'manifest_digest':'sha256:fixture'}}, 'archive':{'file':archive.name,'sha256':release.sha(archive),'manifest_digest':'sha256:fixture'}, 'platform':'linux/arm64', 'deployment':deployment,'providers':json.loads((root/'deployment/providers.lock.json').read_text())}
            (root / 'candidate.json').write_text(json.dumps(manifest))
            with mock.patch.object(candidate, 'oci_identity', return_value=('sha256:fixture', {'os':'linux','architecture':'arm64'})), mock.patch.object(candidate, 'docker') as docker:
                candidate.verify_candidate(root)
                self.assertEqual(docker.call_count,2)
                docker.reset_mock()
                path = root / 'deployment/business-roles.sql'; path.write_text('changed')
                with self.assertRaisesRegex(RuntimeError, 'deployment input'): candidate.verify_candidate(root)
                docker.assert_not_called()
                path.unlink()
                with self.assertRaisesRegex(RuntimeError, 'deployment input'): candidate.verify_candidate(root)
                path.symlink_to(root / 'deployment/identity-roles.sql')
                with self.assertRaisesRegex(RuntimeError, 'deployment input'): candidate.verify_candidate(root)
                docker.assert_not_called()
                path.unlink()
                path.write_text('fixture')
                manifest['deployment']['../outside.sql'] = 'not-allowed'
                (root / 'candidate.json').write_text(json.dumps(manifest))
                with self.assertRaisesRegex(RuntimeError, 'deployment inputs'): candidate.verify_candidate(root)
                manifest['format_version'] = 2
                (root / 'candidate.json').write_text(json.dumps(manifest))
                with self.assertRaisesRegex(RuntimeError, 'V1 required'): candidate.verify_candidate(root)
                docker.assert_not_called()

if __name__ == "__main__":
    unittest.main()

class BaselinePrivacy(unittest.TestCase):
    def test_telemetry_preparation_registers_new_secrets_before_external_commands(self):
        import base64
        with tempfile.TemporaryDirectory() as temporary:
            owner=candidate.Candidate.__new__(candidate.Candidate)
            owner.tenant=candidate.TENANT;owner.pg_host='postgres';owner.config={};owner.private_values=[]
            owner.runtime=Path(temporary)/'runtime';owner.runtime.mkdir()
            owner.operator_root=Path(temporary)/'operator';owner.operator_root.mkdir()
            owner.sql=mock.Mock();owner.copy_runtime=mock.Mock()
            def prepare(*args):
                password=(owner.runtime/'telemetry-password').read_text()
                cursor=(owner.runtime/'telemetry-cursor').read_bytes()
                for secret in [password,cursor.hex(),base64.b64encode(cursor).decode()]:
                    with self.assertRaises(RuntimeError):candidate.safe_evidence(secret,owner.private_values)
            owner.operator=mock.Mock(side_effect=prepare)
            owner.prepare_telemetry()
            owner.operator.assert_called_once()
