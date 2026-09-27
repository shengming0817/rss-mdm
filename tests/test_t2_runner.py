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
        with tempfile.TemporaryDirectory() as tmp, patch.object(t2,'require_lease'), patch.object(t2.shutil,'which',return_value='/tool'), patch.object(t2,'execute',return_value=1):
            result=t2.run_suites(['sources'],Path(tmp))
            self.assertEqual(result['sources']['status'],'failed')

    def test_missing_dependency_fails_before_execution(self):
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp, patch.object(t2,'require_lease'), patch.object(t2.shutil,'which',return_value=None), patch.object(t2,'execute') as execute:
            result=t2.run_suites(['apple'],Path(tmp))
            self.assertEqual(result['apple']['status'],'failed')
            execute.assert_not_called()
