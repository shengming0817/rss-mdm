import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'hack'))
import auth_t3

class ProofTests(unittest.TestCase):
    def test_missing_or_failed_scenario_cannot_pass(self):
        complete={name:True for name in auth_t3.SCENARIOS}
        auth_t3.validate_checks(complete)
        for name in complete:
            missing=dict(complete);del missing[name]
            with self.assertRaises(RuntimeError):auth_t3.validate_checks(missing)
            failed=dict(complete);failed[name]=False
            with self.assertRaises(RuntimeError):auth_t3.validate_checks(failed)
    def test_sensitive_values_never_enter_evidence(self):
        with self.assertRaises(RuntimeError):auth_t3.safe_evidence({'log':'secret-credential'},['secret-credential'])
        self.assertEqual(auth_t3.safe_evidence({'status':401},['secret-credential']),{'status':401})
    def test_different_candidate_must_not_be_accepted(self):
        with self.assertRaises(RuntimeError):auth_t3.validate_checks({})
