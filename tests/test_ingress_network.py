import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'hack'))
from ingress_network import Ingress


class NetworkTests(unittest.TestCase):
    def test_allocation_persists_daemon_addresses_and_compose_ownership(self):
        with tempfile.TemporaryDirectory() as directory:
            owner=Ingress(Path(directory),'mdm-test','worktree')
            networks={}
            def engine(*args):
                if args[:2]==('network','ls'):
                    return '\n'.join(json.dumps(dict(Name=v['Name'],ID=k)) for k,v in networks.items())
                if args[:2]==('network','inspect'):return json.dumps([networks[args[2]]])
                if args[:2]==('network','create'):
                    self.assertNotIn('--subnet',args)
                    labels=dict(args[i+1].split('=',1) for i,a in enumerate(args) if a=='--label')
                    networks['id']=dict(Id='id',Name=args[-1],Driver='bridge',Internal=True,Labels=labels,IPAM={'Config':[{'Subnet':'10.42.0.0/24','Gateway':'10.42.0.1'}]})
                    return 'id'
                if args[:2]==('network','rm'):del networks[args[2]];return args[2]
                raise AssertionError(args)
            with patch.object(Ingress,'_run',side_effect=engine) as run:
                self.assertEqual(owner.values(),{})
                run.assert_not_called()
                expected=dict(MDM_INGRESS_SUBNET='10.42.0.0/24',MDM_GATEWAY_ADDRESS='10.42.0.2',MDM_BACKEND_ADDRESS='10.42.0.3')
                self.assertEqual(owner.allocate(),expected)
                self.assertEqual(Ingress(owner.root,owner.project,owner.owner).allocate(),expected)
                self.assertEqual(owner.address(2),'10.42.0.4')
                self.assertEqual(owner.record.stat().st_mode & 0o777,0o600)
                self.assertEqual(sum(c.args[:2]==('network','create') for c in run.call_args_list),1)
                networks['id']['Labels']['rss.mdm.worktree']='foreign'
                with self.assertRaisesRegex(RuntimeError,'foreign'):owner.release()
                self.assertTrue(networks)
                networks['id']['Labels']['rss.mdm.worktree']='worktree'
                owner.release();self.assertFalse(networks);self.assertFalse(owner.record.exists())
                owner.release()

    def test_missing_record_has_no_address_fallback_and_changed_allocation_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            owner=Ingress(Path(directory),'mdm-test','worktree')
            with self.assertRaisesRegex(RuntimeError,'not allocated'):owner.address(0)
            record=dict(id='original',name=owner.name,owner=owner.owner,subnet='10.42.0.0/24',bridge_gateway='10.42.0.1')
            owner.record.write_text(json.dumps(record))
            with patch.object(owner,'_inspect',return_value=dict(record,id='replacement')):
                with self.assertRaisesRegex(RuntimeError,'changed'):owner.allocate()
                with self.assertRaisesRegex(RuntimeError,'changed'):owner.release()
