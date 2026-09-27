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

class NormalSafetyTests(unittest.TestCase):
    def params(self):
        return dict(mode='normal',origin='https://mdm.example.test',otherOrigin='https://other.example.test',issuer='https://idp.example.test/realms/mdm',adminPassword='admin-secret',memberPassword='member-secret',idpPassword='idp-secret',clientSecret='client-secret')

    def test_issuer_rejects_insecure_or_ambiguous_urls_before_browser(self):
        import json
        from unittest.mock import patch
        for url in ('http://idp.test','https:///realms/a','https://user@idp.test','https://idp.test?token=x','https://idp.test#fragment','https://idp.test:bad/a','https://idp.test/\\evil'):
            with self.subTest(url=url),tempfile.TemporaryDirectory() as tmp:
                path=Path(tmp)/'input.json';params=self.params();params['issuer']=url
                path.write_text(json.dumps(params));path.chmod(0o600)
                with patch.object(auth_t3.subprocess,'run') as run:
                    with self.assertRaises((RuntimeError,ValueError)):auth_t3.run_normal(path,Path(tmp)/'out')
                    run.assert_not_called()

    def test_browser_failure_preserves_safe_stage_and_withholds_secrets(self):
        import json,subprocess
        from unittest.mock import patch
        for reason,expected in [('login selector unavailable','login selector unavailable'),('idp-secret','diagnostic-withheld')]:
            with self.subTest(reason=reason),tempfile.TemporaryDirectory() as tmp:
                path=Path(tmp)/'input.json';path.write_text(json.dumps(self.params()));path.chmod(0o600)
                error=subprocess.CalledProcessError(1,['node'],stderr=json.dumps(dict(stage='enterprise',errorClass='TimeoutError',reason=reason)))
                with patch.object(auth_t3.subprocess,'run',side_effect=error):
                    with self.assertRaises(subprocess.CalledProcessError):auth_t3.run_normal(path,Path(tmp)/'out')
                value=json.loads((Path(tmp)/'out/failure.json').read_text())
                self.assertEqual(value['stage'],'enterprise');self.assertEqual(value['reason'],expected)
                self.assertNotIn('idp-secret',json.dumps(value))

class BrowserBoundaryTests(unittest.TestCase):
    def test_launch_modes_and_launch_failure_evidence(self):
        import json,os,subprocess
        source=Path(auth_t3.__file__).with_name('auth_t3_browser.mjs')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);module=root/'playwright.cjs';options=root/'launch.json';params=root/'input.json'
            module.write_text("exports.chromium={launch:async options=>{require('fs').writeFileSync(process.env.PROBE_OUTPUT,JSON.stringify(options));throw new Error('launch-probe')}};")
            for mode in ('normal','faults'):
                params.write_text(json.dumps(dict(mode=mode,origin='https://mdm.test',otherOrigin='https://other.test')))
                result=subprocess.run(['node',str(source),str(params)],capture_output=True,text=True,env={**os.environ,'MDM_PLAYWRIGHT_MODULE':str(module),'PROBE_OUTPUT':str(options)})
                self.assertEqual(result.returncode,1)
                self.assertEqual(json.loads(options.read_text())['chromiumSandbox'],mode=='normal')
                self.assertEqual(json.loads(result.stderr)['stage'],'launch')

    def test_cross_origin_redirect_cannot_receive_idp_password(self):
        import subprocess
        source=Path(auth_t3.__file__).with_name('auth_t3_browser.mjs').read_text()
        function=source[source.index('async function keycloak('):source.index('let admin,member;')]
        probe="""
const input={issuer:'https://idp.test/realms/mdm',idpPassword:'private'};
const assert=(ok,message)=>{if(!ok)throw new Error(message)};
let filled=0;
const page={waitForURL:async()=>{},url:()=> 'https://attacker.test/login',locator:()=>({waitFor:async()=>{},fill:async()=>{filled++},click:async()=>{}})};
try{await keycloak(page,'alice');throw new Error('accepted redirect')}catch(e){if(e.message!=='untrusted IdP navigation'||filled!==0)throw e}
"""
        result=subprocess.run(['node','--input-type=module','-e',function+probe],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
