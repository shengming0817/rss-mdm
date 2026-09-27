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
