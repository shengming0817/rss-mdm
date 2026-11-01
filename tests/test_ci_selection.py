"""Current CI selection, evidence lifecycle and ignored-test admission."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hack'))
import ci
import ci_impact as impact
from ci_impact import selected, explicit_selection, SelectionError
from test_ownership import validate_listing

def result(stdout='', returncode=0):
    return subprocess.CompletedProcess([], returncode, stdout, '')

class Selection(unittest.TestCase):
    def test_merge_base_failure_and_invalid_selector_fail_closed(self):
        for outputs in ([result(returncode=1)], [result('base'), result('{}')],
                        [result('base'), result('{"status":"selected","status":"failed"}')]):
            with patch.object(ci, 'command', side_effect=outputs), self.assertRaises(SelectionError):
                ci.select_impact('head')

    def test_package_and_tool_gates_follow_current_consumers(self):
        selection = selected(['rss-mdm-winget-source'])
        self.assertEqual(ci.gate_command('t1', ['cargo','test','--workspace','--lib'], selection),
                         ['cargo','test','-p','rss-mdm-winget-source','--lib'])
        self.assertFalse(ci.selected_gate('native-schema', selection))
        self.assertFalse(ci.selected_gate('collection-schema', selection))
        self.assertFalse(ci.selected_gate('script-tests', selection))
        selection['toolTests'] = ['test_http_contract_artifact']
        self.assertTrue(ci.selected_gate('collection-schema', selection))
        for package in ('rss-mdm-native-schema','rss-mdm-apple-mdm','rss-mdm-windows-mdm'):
            self.assertTrue(ci.selected_gate('native-schema', selected([package])))

    def test_selection_rejects_unknown_duplicate_and_unselected_ownership(self):
        for value in (selected(['missing']), selected(['rss-mdm-app'], ownership_packages=['rss-mdm-resource']),
                      selected([], tools=['missing'])):
            with self.assertRaises(SelectionError):
                impact.validate_selection(value, ci.LOCAL_PACKAGES, ci.all_tools())
        value=selected(['rss-mdm-app']);value['cargo']['packages'] *= 2
        with self.assertRaises(SelectionError):
            impact.validate_selection(value, ci.LOCAL_PACKAGES, ci.all_tools())

    def test_listing_requires_complete_target_and_rejects_ignored(self):
        suite={'package-name':'owner','status':'listed','testcases':{'case':{'ignored':False}}}
        document={'rust-suites':{'owner':suite}}
        validate_listing(document,'owner')
        suite['testcases']['case']['ignored']=True
        with self.assertRaisesRegex(RuntimeError,'no execution owner'):validate_listing(document,'owner')
        suite['testcases']={};suite['status']='skipped'
        with self.assertRaisesRegex(RuntimeError,'incomplete'):validate_listing(document,'owner')
        with self.assertRaisesRegex(RuntimeError,'missing'):validate_listing({'rust-suites':{}},'owner')

    def test_listing_requires_only_modules_owned_by_each_package(self):
        modules = {
            'app.proof': dict(prefix='app::', profiles=('shared',), inputs=()),
            'agent.proof': dict(package='agent', target='foundation', prefix='agent::', profiles=('agent',), inputs=()),
        }
        document = {'rust-suites': {
            'app': {'package-name': 'rss-mdm-app', 'binary-name': 'rss_mdm_app', 'status': 'listed',
                    'testcases': {'app::case': {'ignored': True}}},
            'agent': {'package-name': 'agent', 'binary-name': 'foundation', 'status': 'listed',
                      'testcases': {'agent::case': {'ignored': True}}},
        }}
        with patch('t2_registry.MODULES', modules):
            for package in ('rss-mdm-app', 'agent'):
                validate_listing(document, package)
            document['rust-suites']['agent']['testcases'] = {}
            with self.assertRaisesRegex(RuntimeError, 'zero T2 discovery: agent.proof'):
                validate_listing(document, 'agent')

    def run_ci(self, out, *, full=False, failed_gate=False, failed_owner=False, plan=False, failed_t2=False):
        selection=selected(['rss-mdm-app'], ownership_packages=['rss-mdm-app'])
        with (patch.object(ci,'require_lease'),patch.object(ci,'OUT',out),
              patch.object(ci,'command',return_value=result('head')),
              patch.object(ci,'fast_gates',return_value=[('fmt',['cargo','fmt']),('check',['cargo','check'])]),
              patch.object(ci,'selected_gate',return_value=True),patch.object(ci,'gate_command',side_effect=lambda n,a,s:a),
              patch.object(ci,'select_impact',return_value=selection),patch.object(ci,'working_source_state',return_value='stable'),
              patch.object(ci,'workspace_pin',side_effect=RuntimeError('pin failure') if failed_gate else None,return_value=('url','rev')),
              patch.object(ci,'dependency_graphs'),
              patch.object(ci,'run_modules',return_value={'status':'failed' if failed_t2 else 'passed','executedCases':1}),
              patch('test_ownership.check_ownership',side_effect=RuntimeError('unowned ignored') if failed_owner else None) as owner,
              patch.dict(ci.os.environ,{'CI_T2':'all' if full else 'none','CI_FULL':'0','CI_PLAN':'1' if plan else '0'}),
              contextlib.redirect_stdout(io.StringIO())):
            code=ci.main()
        return code,owner

    def test_ci_collects_failures_and_keeps_ownership_gate(self):
        for pin,ownership in ((False,False),(True,False),(False,True)):
            with self.subTest(pin=pin,ownership=ownership),tempfile.TemporaryDirectory() as temporary:
                out=Path(temporary);code,owner=self.run_ci(out,failed_gate=pin,failed_owner=ownership)
                self.assertEqual(code,int(pin or ownership));owner.assert_called_once()
                evidence=json.loads((out/'result.json').read_text())
                self.assertEqual(evidence['gates']['check']['status'],'passed')
                self.assertEqual(evidence['t2']['reason'],'not-requested')

    def test_full_ci_uses_actual_t2_verdict(self):
        for failed in (False, True):
            with self.subTest(failed=failed),tempfile.TemporaryDirectory() as temporary:
                out=Path(temporary);code,_=self.run_ci(out,full=True,failed_t2=failed)
                self.assertEqual(code,int(failed))
                evidence=json.loads((out/'result.json').read_text())
                self.assertEqual(evidence['verificationComplete'],not failed)
                self.assertEqual(evidence['t2']['status'],'failed' if failed else 'passed')

    def test_plan_preserves_execution_and_does_not_discover(self):
        with tempfile.TemporaryDirectory() as temporary:
            out=Path(temporary);(out/'result.json').write_text('previous execution')
            code,owner=self.run_ci(out,plan=True)
            self.assertEqual(code,0);owner.assert_not_called()
            self.assertEqual((out/'result.json').read_text(),'previous execution')
            self.assertEqual(json.loads((out/'plan.json').read_text())['t2']['reason'],'not-requested')

    def test_cleanup_keeps_other_evidence_and_does_not_follow_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);out=root/'ci';out.mkdir();external=root/'other';external.mkdir()
            (external/'result.json').write_text('retained')
            (out/'t2').symlink_to(external,target_is_directory=True)
            (out/'unowned.log').write_text('retain')
            with patch.object(ci,'OUT',out):ci.clear_execution_evidence(['fmt'])
            self.assertFalse((out/'t2').exists());self.assertTrue((out/'unowned.log').exists())
            self.assertEqual((external/'result.json').read_text(),'retained')

    def test_invalid_mode_fails_before_gates(self):
        with patch.dict(ci.os.environ,{'CI_T2':'typo'}),patch.object(ci,'fast_gates') as gates:
            with self.assertRaisesRegex(RuntimeError,'CI_T2'):ci.execute_ci()
            gates.assert_not_called()
