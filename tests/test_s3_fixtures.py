"""S3 fixture ownership and actual affected/T2 resource boundary."""
from pathlib import Path
import json
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'hack'))
import s3_fixtures
from t2_registry import MODULES

class S3Fixtures(unittest.TestCase):
    def test_foreign_container_is_never_removed(self):
        fixture=s3_fixtures.S3Environment()
        info={'Name':'/'+fixture.name,'Config':{'Labels':{'rss.mdm.worktree':'foreign','rss.mdm.fixture':'content-s3'}}}
        with patch.object(s3_fixtures,'run') as run:
            run.side_effect=[type('Output',(),{'stdout':'id'})(),type('Output',(),{'stdout':json.dumps([info])})()]
            with self.assertRaisesRegex(RuntimeError,'ownership mismatch'):
                fixture.reset()
            self.assertEqual(run.call_count,2)
            self.assertTrue(all(call.kwargs["timeout"] == 30 for call in run.call_args_list))

    def test_exact_owned_container_is_cleaned(self):
        fixture=s3_fixtures.S3Environment()
        info={'Name':'/'+fixture.name,'Config':{'Labels':{'rss.mdm.worktree':fixture.owner.identity,'rss.mdm.fixture':'content-s3'}}}
        with patch.object(s3_fixtures,'run') as run:
            run.side_effect=[type('Output',(),{'stdout':'selected'})(),type('Output',(),{'stdout':json.dumps([info])})(),None]
            fixture.reset()
            run.assert_called_with(['docker','rm','-f','-v','selected'],capture_output=True,timeout=30)

    def test_s3_target_requires_real_provider_tools_without_database(self):
        module=MODULES['content.s3']
        self.assertFalse(module.postgres)
        self.assertIn('docker',module.tools)
        self.assertIn('openssl',module.tools)
        self.assertEqual(module.build.package,'rss-mdm-content-s3')
        self.assertEqual(module.fixtures,('s3',))

if __name__=='__main__':unittest.main()
