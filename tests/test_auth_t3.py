import sys
import tempfile
import unittest
import re
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'hack'))
import auth_t3

class ProofTests(unittest.TestCase):
    def test_inventory_seed_tracks_the_canonical_projection_generation(self):
        source=(Path(__file__).resolve().parents[1]/'crates/inventory-postgres/src/inventory.rs').read_text()
        generation=re.search(r'const GENERATION: &str = "([^"]+)";',source)
        self.assertIsNotNone(generation)
        self.assertEqual(auth_t3.INVENTORY_GENERATION,generation.group(1))

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
    def test_dynamic_callback_code_cannot_enter_evidence(self):
        with self.assertRaises(RuntimeError):auth_t3.safe_evidence({'log':'/api/v2/oidc/callback?code=unanticipated-value'},[])

    def test_generated_runtime_keys_and_multiline_secret_are_rejected(self):
        for secret in ['a'*64, '-----BEGIN PRIVATE KEY-----\nprivate-key-body\n-----END PRIVATE KEY-----']:
            with self.assertRaises(RuntimeError):auth_t3.safe_evidence({'log':secret},[secret])

class NormalModeTests(unittest.TestCase):
    def test_normal_checks_exclude_only_explicit_faults(self):
        expected=set(auth_t3.SCENARIOS)-auth_t3.FAULT_SCENARIOS
        auth_t3.validate_checks(dict.fromkeys(expected,True),'normal')
        with self.assertRaises(RuntimeError):auth_t3.validate_checks(dict.fromkeys(expected-{'permissions'},True),'normal')

    def test_normal_input_cannot_supply_service_controls(self):
        import json
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'input.json';path.write_text(json.dumps({'mode':'normal','pg':'someone-elses-pg'}));path.chmod(0o600)
            with patch.object(auth_t3.subprocess,'run') as run:
                with self.assertRaisesRegex(RuntimeError,'service control'):auth_t3.run_normal(path,Path(tmp)/'output')
                run.assert_not_called()
