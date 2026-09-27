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
