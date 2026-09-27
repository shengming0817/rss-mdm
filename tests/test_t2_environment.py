import tempfile
import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hack'))
from t2_environment import Environment, project_name

class EnvironmentTests(unittest.TestCase):
    def test_worktree_identity_is_stable_and_distinct(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = [Path(tmp) / str(i) / 'same-name' for i in range(4)]
            for path in paths: path.mkdir(parents=True)
            names = [project_name(path) for path in paths]
            self.assertEqual(len(set(names)), 4)
            self.assertEqual(project_name(paths[0] / '..' / 'same-name'), names[0])

    def test_environment_does_not_follow_target_slot(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict('os.environ', {'CARGO_TARGET_DIR': '/slot-0'}):
                first = Environment(Path(tmp))
            with patch.dict('os.environ', {'CARGO_TARGET_DIR': '/slot-1'}):
                second = Environment(Path(tmp))
            self.assertEqual(first.project, second.project)
            self.assertEqual(first.root, second.root)

    def test_reset_refuses_foreign_resource_before_mutation(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            env = Environment(Path(tmp))
            with patch.object(env, 'verify_ownership', side_effect=RuntimeError('foreign')), patch.object(env, 'compose') as compose:
                with self.assertRaises(RuntimeError): env.reset()
                compose.assert_not_called()

    def test_runtime_volume_does_not_receive_operator_secrets(self):
        source=(Path(__file__).resolve().parents[1]/'deployment/compose.yaml').read_text()
        server=source.split('  server:',1)[1].split('  gateway:',1)[0]
        self.assertIn('runtime:/run/mdm:ro',server)
        self.assertNotIn('operator:',server)
        self.assertIn('network_mode: service:runtime-netns',server)

    def test_role_changes_require_reset_without_running_ddl(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            env=Environment(Path(tmp));env.root.mkdir(parents=True)
            (env.root/'roles.sha256').write_text('old')
            with patch.object(env,'sql',return_value='1') as sql:
                with self.assertRaisesRegex(RuntimeError,'reset'):env.roles()
                self.assertEqual(sql.call_count,1)

    def test_status_accepts_compose_json_lines(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            env=Environment(Path(tmp))
            with patch.object(env,'compose',return_value='{"Service":"postgres"}\n{"Service":"server"}'):
                self.assertEqual(len(env.status()['services']),2)

    def test_saved_images_override_ambient_values(self):
        from unittest.mock import patch
        import json
        with tempfile.TemporaryDirectory() as tmp:
            env=Environment(Path(tmp));env.root.mkdir(parents=True)
            (env.root/'images.json').write_text(json.dumps({'MDM_SERVER_IMAGE':'sha256:reviewed','MDM_WEB_IMAGE':'sha256:web'}))
            with patch.dict('os.environ',{'MDM_SERVER_IMAGE':'unreviewed','MDM_WEB_IMAGE':'unreviewed'}):
                self.assertEqual(env.variables()['MDM_SERVER_IMAGE'],'sha256:reviewed')
                self.assertEqual(env.variables()['MDM_WEB_IMAGE'],'sha256:web')

    def test_postgres_has_no_environment_root_mount(self):
        source=(Path(__file__).resolve().parents[1]/'deployment/compose.yaml').read_text().split('  idp-netns:',1)[0]
        self.assertNotIn('${MDM_ENV_ROOT:?}:/',source)
        self.assertIn('/pg/server.key:/inputs/server.key:ro',source)

    def test_same_name_unlabelled_resource_is_rejected(self):
        import json
        from types import SimpleNamespace
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            env=Environment(Path(tmp));name=env.project+'_pg'
            config=json.dumps({'services':{},'volumes':{'pg':{'name':name}},'networks':{}})
            def run(args,**kwargs):
                output=''
                if args[:3]==['docker','volume','ls'] and '--format' in args:output=name
                if args[:3]==['docker','volume','inspect']:output=json.dumps([{'Labels':{}}])
                return SimpleNamespace(stdout=output)
            with patch.object(env,'compose',return_value=config),patch('t2_environment.run',side_effect=run):
                with self.assertRaisesRegex(RuntimeError,'foreign'):env.verify_ownership()

    def test_host_port_allocations_are_distinct_and_detect_occupation(self):
        from unittest.mock import patch
        import socket
        with tempfile.TemporaryDirectory() as tmp, patch.object(Path,'home',return_value=Path(tmp)):
            environments=[Environment(Path(tmp)/str(i)) for i in range(4)]
            pairs=[env.host_ports() for env in environments]
            self.assertEqual(len({port for pair in pairs for port in pair.values()}),8)
            self.assertEqual(environments[0].host_ports(),pairs[0])
            with socket.socket() as listener:
                listener.bind(('127.0.0.1',pairs[0]['backend']))
                with self.assertRaisesRegex(RuntimeError,'occupied'):environments[0].host_ports()
            environments[0].host_ports(release=True)

    def test_fault_environment_is_reset_after_controlled_cancellation(self):
        from t2_environment import T2Context, Cancelled
        from types import SimpleNamespace
        from unittest.mock import patch,MagicMock
        context=T2Context();context.spec=SimpleNamespace(name='software',isolation='server',destructive=frozenset())
        owned=MagicMock()
        with patch('t2_environment.Environment',return_value=owned):
            with self.assertRaises(Cancelled),context.cluster():raise Cancelled()
        owned.reset.assert_called_once()

    def test_gateway_modes_have_distinct_keys_under_the_same_ca(self):
        import hashlib
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            env=Environment(Path(tmp));env.prepare_inputs()
            directories=[env.root/'gateway-cert'/mode for mode in ('host','container')]
            for directory in directories:
                env.issue_leaf(directory,['localhost','mdm.example.test'])
                subprocess.run(['openssl','verify','-CAfile',str(env.root/'ca.crt'),str(directory/'server.crt')],check=True,capture_output=True)
            for name in ('server.key','server.crt'):
                self.assertNotEqual(hashlib.sha256((directories[0]/name).read_bytes()).digest(),hashlib.sha256((directories[1]/name).read_bytes()).digest())

    def test_reset_rejects_damaged_owner_record(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            env=Environment(Path(tmp));env.root.mkdir(parents=True)
            (env.root/'owner.json').write_text('{}')
            with patch.object(env,'compose') as compose:
                with self.assertRaisesRegex(RuntimeError,'owner record'):env.reset()
                compose.assert_not_called()

    def test_reset_releases_allocation_without_local_port_marker(self):
        from unittest.mock import patch
        import json
        with tempfile.TemporaryDirectory() as tmp,patch.object(Path,'home',return_value=Path(tmp)):
            env=Environment(Path(tmp)/'work');env.root.mkdir(parents=True)
            (env.root/'owner.json').write_text(json.dumps({'worktree':str(env.worktree),'project':env.project}))
            env.host_ports()
            self.assertFalse((env.root/'host-ports.json').exists())
            with patch.object(env,'verify_ownership'),patch.object(env,'compose'):env.reset()
            allocations=json.loads((Path(tmp)/'.cache/rss-mdm-dev-ports/allocations.json').read_text())
            self.assertNotIn(env.project,allocations)
