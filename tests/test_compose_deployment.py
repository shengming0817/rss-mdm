"""Cross-platform deployment contracts; full installation behavior is qualified on real Docker."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'hack'))
import candidate_installation as acceptance
import deploy


class FormalInstallation(unittest.TestCase):
    def test_failure_or_cleanup_failure_never_publishes_success(self):
        for failure in ('install', 'cleanup'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary)
                def prepare(candidate, output, **kwargs):
                    output.mkdir()
                    (output/'compose.yaml').write_text('services: {}')
                    (output/'deployment.json').write_text('{"platform":"linux/arm64"}')
                with mock.patch.object(acceptance,'prepare',side_effect=prepare),mock.patch.object(acceptance,'Installation') as owner,\
                     mock.patch.object(acceptance,'qualify',side_effect=RuntimeError('private') if failure=='install' else None,return_value={'status':'passed'}):
                    if failure=='cleanup':owner.return_value.cleanup.side_effect=RuntimeError('private')
                    (root/'candidate.json').write_text('{}')
                    with self.assertRaises(RuntimeError):acceptance.qualify_candidate(root)
                    self.assertFalse((root/'installation-result.json').exists())
                    self.assertNotIn('private',(root/'installation-failure.json').read_text())
                    owner.return_value.cleanup.assert_called_once()

    def test_formal_compose_does_not_publish_operator_or_database(self):
        # Parse the actual interpolated Compose model, rather than mirroring its YAML.
        import os
        import subprocess
        values=dict(os.environ,MDM_INSTALLER_IMAGE='installer',MDM_SERVER_IMAGE='server',MDM_WEB_IMAGE='web',
                    MDM_POSTGRES_IMAGE='postgres',MDM_INPUT_DIRECTORY='/tmp',MDM_DOCKER_SOCKET='/tmp/docker.sock',COMPOSE_PROJECT_NAME='formal-contract')
        result=subprocess.run(['docker','compose','-f',str(ROOT/'deployment/production.compose.yaml'),'config','--format','json'],
                              env=values,capture_output=True,text=True,timeout=20,check=True)
        model=json.loads(result.stdout)
        self.assertEqual(model['services']['operator']['user'],'10001:10001')
        self.assertEqual(model['services']['install']['user'],'10001:10001')
        self.assertEqual(model['services']['operator']['depends_on']['install']['condition'],'service_completed_successfully')
        for name,service in model['services'].items():
            self.assertFalse(service.get('ports'))
            self.assertNotEqual(service.get('network_mode'),'host')
            self.assertFalse(service.get('privileged',False))
        self.assertFalse(any(m['target']=='/run/docker.sock' for m in model['services']['bootstrap']['volumes']))

    def test_bootstrap_never_calls_database_or_product_seed(self):
        spec=importlib.util.spec_from_file_location('compose_bootstrap',ROOT/'deployment/compose_bootstrap.py')
        bootstrap=importlib.util.module_from_spec(spec);spec.loader.exec_module(bootstrap)
        for invalid in ('http://localhost:8445','https://user:pass@example.test','https://example.test/path'):
            with self.assertRaises(ValueError):bootstrap.origin(invalid)
        self.assertEqual(bootstrap.origin('https://localhost:8445').port,8445)

if __name__=='__main__':unittest.main()
