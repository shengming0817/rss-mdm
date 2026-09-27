import importlib.util
import unittest
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'hack'))
import ci_registry as registry
import t2
class RegistryTests(unittest.TestCase):
    def test_named_all_and_empty(self):
        self.assertEqual(t2.select_suites('management',{}),['management'])
        self.assertEqual(set(t2.select_suites('all',{})),set(registry.SUITES))
        self.assertEqual(t2.select_suites('affected',{'full':False,'t2Suites':[]}),[])
    def test_unknown_never_falls_back(self):
        with self.assertRaisesRegex(ValueError,'available'): t2.select_suites('typo',{})
    def test_unknown_input_is_conservative(self):
        self.assertEqual(set(registry.select_paths(['unknown.file'])[0]),set(registry.SUITES))
    def test_docs_do_not_select_services_or_tools(self):
        self.assertEqual(registry.select_paths(['docs/guides/local-development.md'])[:2], ([],[]))
    def test_migration_selects_all_and_sql_selects_owner(self):
        self.assertEqual(set(registry.select_paths(['crates/app/src/migration.rs'])[0]),set(registry.SUITES))
        self.assertIn('group',registry.select_paths(['crates/group-postgres/migrations/0001.sql'])[0])
    def test_app_local_path_does_not_force_all(self):
        suites,_,_=registry.select_paths(['crates/app/src/apple/certificate.rs'])
        self.assertIn('apple',suites)
        self.assertNotIn('software',suites)

class ExecutionTests(unittest.TestCase):
    def test_nonzero_suite_result_cannot_pass(self):
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp, patch.object(t2,'require_lease'), patch.object(t2,'T2Context'), patch.object(t2.shutil,'which',return_value='/tool'), patch.object(t2,'execute',return_value=1):
            result=t2.run_suites(['sources'],Path(tmp))
            self.assertEqual(result['sources']['status'],'failed')

    def test_missing_dependency_fails_before_execution(self):
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp, patch.object(t2,'require_lease'), patch.object(t2,'T2Context'), patch.object(t2.shutil,'which',return_value=None), patch.object(t2,'execute') as execute:
            result=t2.run_suites(['apple'],Path(tmp))
            self.assertEqual(result['apple']['status'],'failed')
            execute.assert_not_called()

class ConsumerSelectionTests(unittest.TestCase):
    def test_cross_crate_consumers_are_selected(self):
        cases={'resource':{'software','tasks'},'resource-postgres':{'software','tasks'},'inventory':{'compliance'},
               'inventory-postgres':{'compliance'},'group-postgres':{'tasks'},'policy':{'tasks'}}
        for owner,required in cases.items():
            with self.subTest(owner=owner):self.assertLessEqual(required,set(registry.select_paths(['crates/'+owner+'/src/lib.rs'])[0]))

class Oracles(unittest.TestCase):
    def test_every_registration_has_executor_and_completion_oracle(self):
        for suite in registry.SUITES.values():
            self.assertTrue(callable(suite.executor))
            self.assertTrue(suite.expected or suite.success_marker)

    def test_every_cargo_suite_rejects_wrong_names_zero_and_ignored(self):
        for suite in registry.SUITES.values():
            if not suite.expected:continue
            output=''.join('test '+name+' ... ok\n' for name in suite.expected)
            output+=f'test result: ok. {len(suite.expected)} passed; 0 failed; 0 ignored;\n'
            suite.verify(output)
            for bad in (output.replace(suite.expected[0],'unrelated'), output.replace('0 ignored','1 ignored'),'test result: ok. 0 passed; 0 failed; 0 ignored;\n'):
                with self.subTest(suite=suite.name),self.assertRaises(RuntimeError):suite.verify(bad)


class EvidenceTests(unittest.TestCase):
    def test_empty_selection_removes_owned_old_logs_without_following_links(self):
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp, patch.object(t2,'require_lease'):
            root=Path(tmp);outside=root/'retained';outside.write_text('retained')
            out=root/'t2';out.mkdir();(out/'management.log').symlink_to(outside)
            (out/'apple.log').write_text('old pass')
            with patch.object(t2,'T2Context') as context:
                result=t2.run_suites([],out)
                context.assert_not_called()
            self.assertEqual(outside.read_text(),'retained')
            self.assertFalse((out/'management.log').exists())
            self.assertFalse((out/'apple.log').exists())
            self.assertTrue(all(item['status']=='skipped' and item['elapsedSeconds']==0 for item in result.values()))

class InterleavedCargoOutput(unittest.TestCase):
    def test_diagnostics_between_test_prefix_and_status_keep_exact_identity(self):
        from verification_result import verify_tests
        output='test expected ... {"event":"diagnostic"}\nok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n'
        verify_tests(output,['expected'])
        for bad in (output.replace('expected','unrelated'),output.replace('1 passed','0 passed'),output.replace('0 ignored','1 ignored')):
            with self.assertRaises(RuntimeError):verify_tests(bad,['expected'])

class EarlyFailureEvidence(unittest.TestCase):
    def test_preflight_error_replaces_old_success(self):
        import json,tempfile
        from unittest.mock import patch
        import ci
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'artifacts/local-t2';out.mkdir(parents=True)
            (out/'result.json').write_text('{"status":"passed"}')
            with patch.object(t2,'ROOT',Path(tmp)),patch.object(t2,'require_lease'),patch.object(ci,'working_source_state',side_effect=RuntimeError('source changed')):
                with self.assertRaises(RuntimeError):t2.main(['--suite','all'])
            self.assertEqual(json.loads((out/'result.json').read_text())['status'],'failed')


class SharedFixtureSelection(unittest.TestCase):
    def test_backend_helper_selects_its_composed_consumers(self):
        self.assertLessEqual({'backend','management','publication'},set(registry.select_paths(['hack/t2_suites/backend.py'])[0]))

    def test_source_tls_helper_selects_all_actual_consumers(self):
        self.assertLessEqual({'sources','publication','software','identity'},set(registry.select_paths(['hack/t2_suites/sources.py'])[0]))

    def test_unknown_suite_helper_is_conservative(self):
        self.assertEqual(set(registry.SUITES),set(registry.select_paths(['hack/t2_suites/new_shared_helper.py'])[0]))

    def test_windows_changes_select_identity_enrollment(self):
        self.assertIn('identity',registry.select_paths(['crates/windows-mdm/src/lib.rs'])[0])


class ToolGateSelection(unittest.TestCase):
    def test_wire_checker_change_runs_the_actual_compatibility_check(self):
        import ci
        _,tests,_=registry.select_paths(['hack/agent_wire_artifact.py'])
        self.assertTrue(ci.selected_gate('agent-wire-artifact',{'full':False,'packages':[],'toolTests':tests,'t2Suites':[]}))

class ReviewRegressions(unittest.TestCase):
    def test_app_shared_consumers(self):
        cases={'flow':{'tasks','windows','apple','commands','identity'},'execution':{'windows','apple','management','identity'},'inventory_runtime':{'tasks','windows','apple','identity'},'device':{'assets','compliance','tasks','management','identity'}}
        for module,expected in cases.items():
            with self.subTest(module=module):self.assertLessEqual(expected,set(registry.select_paths(['crates/app/src/'+module+'.rs'])[0]))

    def test_failed_suite_keeps_callsite_and_log_pointer(self):
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp,patch.object(t2,'require_lease'),patch.object(t2,'T2Context'),patch.object(t2.shutil,'which',return_value='/tool'),patch.object(t2,'execute',side_effect=ValueError('fixture rejected')):
            result=t2.run_suites(['catalog'],Path(tmp))['catalog']
            self.assertEqual(result['reason'],'ValueError');self.assertEqual(result['log'],'catalog.log')
            self.assertIn('Traceback',(Path(tmp)/'catalog.log').read_text())


class CentralOracleTests(unittest.TestCase):
    def test_executor_success_cannot_bypass_registry(self):
        import tempfile
        from unittest.mock import patch
        for output in ('', 'test unrelated ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;'):
            with self.subTest(output=output),tempfile.TemporaryDirectory() as tmp,patch.object(t2,'require_lease'),patch.object(t2,'T2Context'),patch.object(t2.shutil,'which',return_value='/tool'),patch.object(t2,'execute',side_effect=lambda *args:print(output)):
                result=t2.run_suites(['windows'],Path(tmp))
                self.assertEqual(result['windows']['status'],'failed')
