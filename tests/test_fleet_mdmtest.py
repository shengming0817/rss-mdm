"""Supply-chain and credential cleanup checks; protocol proof comes from the live deployment."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('fleet_prepare', ROOT/'hack/fleet_mdmtest/prepare.py')
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)

class FleetSourceGuard(unittest.TestCase):
    def test_foreign_checkout_is_rejected_before_any_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in prepare.UPSTREAM:
                path = root/relative
                path.parent.mkdir(parents=True,exist_ok=True)
                path.write_text('untrusted upstream bytes')
            before = {str(p.relative_to(root)):p.read_bytes() for p in root.rglob('*') if p.is_file()}
            with mock.patch.object(prepare.subprocess,'run') as run:
                with self.assertRaisesRegex(RuntimeError,'unsupported Fleet source'):
                    prepare.prepare(root)
                run.assert_not_called()
            after = {str(p.relative_to(root)):p.read_bytes() for p in root.rglob('*') if p.is_file()}
            self.assertEqual(before,after)

    def test_saved_original_is_also_verified_before_reapplying(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            relative=next(iter(prepare.UPSTREAM))
            path=root/relative;path.parent.mkdir(parents=True);path.write_text('modified working copy')
            original=path.with_suffix('.go.upstream');original.write_text('tampered backup')
            with self.assertRaisesRegex(RuntimeError,'unsupported Fleet source'):
                prepare.prepare(root)
            self.assertEqual(path.read_text(),'modified working copy')


class FleetEvidenceSafety(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec=importlib.util.spec_from_file_location('fleet_live',ROOT/'hack/fleet_mdmtest/run.py')
        cls.live=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.live)

    def test_existing_evidence_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);marker=root/'result.json';marker.write_text('prior evidence')
            args=mock.Mock(output=root)
            with mock.patch.object(self.live,'API') as api:
                with self.assertRaisesRegex(RuntimeError,'output directory must be empty'):
                    self.live.main(args)
                api.assert_not_called()
            self.assertEqual(marker.read_text(),'prior evidence')

    def test_stuck_client_is_killed_and_private_configuration_removed(self):
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            peer=self.live.Device.__new__(self.live.Device)
            peer.config=Path(directory)/'private-config.json';peer.config.write_text('sensitive registration input')
            peer.p=mock.Mock();peer.p.wait.side_effect=[subprocess.TimeoutExpired('client',10),0]
            peer.error=mock.Mock()
            peer.close()
            peer.p.kill.assert_called_once()
            self.assertFalse(peer.config.exists())
