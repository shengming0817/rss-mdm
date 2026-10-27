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

    def test_fresh_operation_snapshot_conflict_is_recorded_and_bounded(self):
        api=self.live.API.__new__(self.live.API);api.snapshot_conflicts=[]
        api.call=mock.Mock(side_effect=[self.live.HTTPFailure('GET','/api/v1/operations',409,'request-1'),{'items':[]}])
        with mock.patch.object(self.live.time,'sleep'):
            self.assertEqual(api.operations('simulated-device'),{'items':[]})
        self.assertEqual(api.snapshot_conflicts[0]['requestId'],'request-1')
        self.assertTrue(all(c.args[0]=='GET' and 'cursor' not in c.args[1] for c in api.call.call_args_list))
        api.call=mock.Mock(side_effect=self.live.HTTPFailure('GET','/api/v1/operations',409))
        with mock.patch.object(self.live.time,'sleep'),self.assertRaises(self.live.HTTPFailure):
            api.operations('simulated-device')
        self.assertEqual(api.call.call_count,8)
        policy='20c4145d-c78d-46bd-9c05-e753f4945280'
        path='/api/v1/policies/'+policy+'/assignments'
        api.call=mock.Mock(side_effect=[self.live.HTTPFailure('GET',path,409,'request-2'),{'items':[]}])
        with mock.patch.object(self.live.time,'sleep'):
            self.assertEqual(api.assignments(policy),{'items':[]})
        self.assertEqual(api.snapshot_conflicts[-1]['path'],path)
        api.call.assert_called_with('GET',path)

    def test_http_writes_and_unavailable_reads_are_not_retried(self):
        import urllib.error
        api=self.live.API.__new__(self.live.API);api.origin='https://test.invalid';api.csrf=None
        api.http=mock.Mock();api.http.open.side_effect=urllib.error.HTTPError('https://test.invalid/write',503,'unavailable',{},None)
        with mock.patch.object(self.live.time,'sleep'),self.assertRaises(self.live.HTTPFailure):
            api.call('POST','/write',{})
        api.http.open.assert_called_once()
        api.snapshot_conflicts=[];api.call=mock.Mock(side_effect=self.live.HTTPFailure('GET','/api/v1/operations',503))
        with self.assertRaises(self.live.HTTPFailure):api.operations('simulated-device')
        api.call.assert_called_once()
        self.assertEqual(api.snapshot_conflicts,[])

    def test_rate_limited_reads_wait_but_writes_and_excessive_delays_fail(self):
        import urllib.error
        from email.message import Message
        headers=Message();headers['Retry-After']='2'
        api=self.live.API.__new__(self.live.API);api.origin='https://test.invalid';api.csrf=None;api.rate_limits=[]
        api.http=mock.Mock()
        def denied():return urllib.error.HTTPError(api.origin+'/read',429,'rate limited',headers,None)
        response=mock.MagicMock();response.__enter__.return_value=response
        response.read.return_value=b'{"items":[]}'
        response.headers.get_content_type.return_value='application/json'
        api.http.open.side_effect=[denied(),response]
        with mock.patch.object(self.live.time,'sleep') as sleep:
            self.assertEqual(api.call('GET','/read'),{'items':[]})
        self.assertIn(mock.call(2),sleep.call_args_list)
        self.assertEqual(api.rate_limits[0]['status'],429)
        api.http.open.reset_mock();api.http.open.side_effect=denied()
        with mock.patch.object(self.live.time,'sleep'),self.assertRaises(self.live.HTTPFailure):
            api.call('POST','/write',{})
        api.http.open.assert_called_once()
        headers.replace_header('Retry-After','3600')
        api.http.open.reset_mock();api.http.open.side_effect=denied()
        with mock.patch.object(self.live.time,'sleep'),self.assertRaises(self.live.HTTPFailure):
            api.call('GET','/read')
        api.http.open.assert_called_once()
