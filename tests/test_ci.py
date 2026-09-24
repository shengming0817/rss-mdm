import importlib.util
from pathlib import Path
import unittest
import copy
import tempfile
import sys

spec = importlib.util.spec_from_file_location("local_ci", Path(__file__).resolve().parents[1] / "hack/ci.py")
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)
sys.path.insert(0, str(ci.ROOT / "hack"))

class DependencyPolicy(unittest.TestCase):
    def test_t2_umbrella_runs_enterprise_tasks(self):
        lines=(ci.ROOT/'Makefile').read_text().splitlines()
        start=lines.index('t2:')+1
        recipe=[]
        for line in lines[start:]:
            if not line.startswith('\t'):
                break
            recipe.append(line)
        self.assertIn('\tpython3 hack/task-t2.py',recipe)

    def test_require_survives_optimized_python(self):
        with self.assertRaises(RuntimeError):
            ci.require(False, "reject")

    def test_source_and_feature_mismatch_are_rejected(self):
        root = ci.ROOT
        pin = ci.rss_pin(ci.tomllib.loads((ci.ROOT / "Cargo.toml").read_text()))
        url, rev = pin
        source = f"git+{url}?rev={rev}#{rev}"
        data = {"packages": [
            *[{"id":name,"name":name,"manifest_path":str(root/path/"Cargo.toml"),"source":None} for name,path in ci.LOCAL_PACKAGES.items()],
            {"id":"obs","name":"rss-observation-postgres","source":source},
            {"id":"proj","name":"rss-projection-postgres","source":source}],
            "workspace_members":list(ci.LOCAL_PACKAGES), "resolve":{"nodes":[
                *[{"id":name,"features":[]} for name in ci.LOCAL_PACKAGES],{"id":"obs","features":[]},{"id":"proj","features":[]}]}}
        registry = 'registry+https://github.com/rust-lang/crates.io-index'
        identity_url,revision = ci.identity_pin(ci.tomllib.loads((root / 'Cargo.toml').read_text()))
        identity_source = f'git+{identity_url}?rev={revision}#{revision}'
        extra = [{'id':name,'name':name,'version':version,'source':registry} for name,version in [('openidconnect','4.0.1'),('rsa','0.9.10')]]
        extra += [{'id':name,'name':name,'source':identity_source} for name in ci.IDENTITY_PACKAGES]
        data['packages'][-2:-2] = extra
        for node in data['resolve']['nodes']: node['deps'] = []
        next(n for n in data['resolve']['nodes'] if n['id']=='rss-mdm-app')['deps'] = [{'pkg':name} for name in ci.IDENTITY_PACKAGES]
        data['resolve']['nodes'][-2:-2] = [{'id':p['id'],'features':[],'deps':([{'pkg':'rsa'}] if p['id']=='openidconnect' else [{'pkg':'openidconnect'}] if p['id']=='rss-identity-oidc' else [])} for p in extra]
        for kind in ('policy', 'resource', 'software-release'):
            next(n for n in data['resolve']['nodes'] if n['id'] == f'rss-mdm-{kind}-postgres')['deps'].append({'pkg':'rss-mdm-backend-postgres-support'})
        ci.verify_metadata(data,root,"normal",pin)
        for name in ci.IDENTITY_PACKAGES:
            target = next(p for p in data['packages'] if p['name']==name)
            previous=target['source'];target['source']='path+file:///untrusted'
            with self.assertRaises(RuntimeError): ci.verify_metadata(data,root,'normal',pin)
            target['source']=previous
        rsa=next(p for p in data['packages'] if p['name']=='rsa');rsa['version']='0.9.11'
        with self.assertRaises(RuntimeError): ci.verify_metadata(data,root,'normal',pin)
        rsa['version']='0.9.10'
        app=next(n for n in data['resolve']['nodes'] if n['id']=='rss-mdm-app')
        for injected in ['rsa','rss-mdm-examples']:
            app['deps'].append({'pkg':injected})
            with self.assertRaises(RuntimeError): ci.verify_metadata(data,root,'normal',pin)
            app['deps'].pop()
        with self.assertRaises(RuntimeError): ci.verify_metadata(data,root,"integration",pin)
        data["resolve"]["nodes"][-2]["features"] = ["integration"]
        with self.assertRaises(RuntimeError): ci.verify_metadata(data,root,"normal",pin)
        data["resolve"]["nodes"][-2]["features"] = []
        data["packages"][-2]["source"] = "path+file:///parent/rss"
        with self.assertRaises(RuntimeError): ci.verify_metadata(data,root,"normal",pin)

    def test_auth_is_noninteractive(self):
        self.assertEqual(ci.noninteractive({})["GIT_TERMINAL_PROMPT"], "0")

    def test_manifest_is_only_pin_authority(self):
        manifest = ci.tomllib.loads((ci.ROOT / "Cargo.toml").read_text())
        url, rev = ci.rss_pin(manifest)
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            bad = copy.deepcopy(manifest)
            bad.setdefault(section, {})["alias"] = {"package":"rss-contract", "git":url, "rev":"0" * 40}
            with self.assertRaises(RuntimeError): ci.rss_pin(bad)
        for source in ({"path":"../rss"}, {"git":url,"rev":rev,"branch":"develop"}, {"git":url,"rev":"short"}):
            bad = copy.deepcopy(manifest)
            bad.setdefault("target", {})["cfg(unix)"] = {"dependencies":{"rss-hidden":source}}
            with self.assertRaises(RuntimeError): ci.rss_pin(bad)
        updated = copy.deepcopy(manifest)
        for section in ("dependencies",):
            for name, dep in updated["workspace"][section].items():
                if name.startswith("rss-") and name not in ci.LOCAL_PACKAGES: dep["rev"] = "1" * 40
        self.assertEqual(ci.rss_pin(updated), (url, "1" * 40))

    def test_workspace_inheritance_and_member_source_are_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for path in ci.LOCAL_PACKAGES.values():
                (root / path).mkdir(parents=True)
                (root / path / "Cargo.toml").write_text((ci.ROOT / path / "Cargo.toml").read_text())
            (root / "Cargo.toml").write_text((ci.ROOT / "Cargo.toml").read_text())
            (root / "deny.toml").write_text((ci.ROOT / "deny.toml").read_text())
            member = root / "crates/inventory/Cargo.toml"
            original = (ci.ROOT / "crates/inventory/Cargo.toml").read_text()
            member.write_text(original)
            self.assertEqual(ci.workspace_pin(root), ci.rss_pin(ci.tomllib.loads((root / "Cargo.toml").read_text())))
            for bad in [
                'rss-observation = { path = "../../../rss/crates/observation" }',
                'rss-observation = { workspace = true, git = "https://example.com/rss" }',
                'rss-observation = { git = "https://example.com/rss", rev = "' + '0' * 40 + '" }',
            ]:
                with self.subTest(dependency=bad):
                    member.write_text(original.replace('rss-observation.workspace = true', bad))
                    with self.assertRaises(RuntimeError): ci.workspace_pin(root)

    def test_old_root_package_location_is_rejected(self):
        root = ci.ROOT
        data = {"packages": [{"id": "app", "name": "rss-mdm-inventory", "manifest_path": str(root / "Cargo.toml"), "source": None}]}
        with self.assertRaises(RuntimeError):
            ci.verify_metadata(data, root, "normal", ci.workspace_pin(ci.ROOT))

    def test_local_members_do_not_exempt_external_paths(self):
        manifest = ci.tomllib.loads((ci.ROOT / "Cargo.toml").read_text())
        for source in ({"path": "../rss/crates/inventory"}, {"git": "https://example.com/fork", "rev": "0" * 40}):
            with self.subTest(source=source):
                bad = copy.deepcopy(manifest)
                bad["workspace"]["dependencies"]["rss-mdm-inventory"] = source
                with self.assertRaises(RuntimeError): ci.rss_pin(bad)

class CodecFixtures(unittest.TestCase):
    def test_protocol_member_and_fixture_provenance_are_exact(self):
        import hashlib
        import json
        self.assertEqual(ci.LOCAL_PACKAGES["rss-mdm-windows-mdm"], "crates/windows-mdm")
        for directory, extension in [("windows-mdm", "xml"), ("winget-source", "json")]:
            root = ci.ROOT / f"crates/{directory}/tests/fixtures"
            manifest = json.loads((root / "provenance.json").read_text())
            if isinstance(manifest, list):
                fixtures = {entry["file"]: entry["sha256"] for entry in manifest}
                self.assertEqual(len(fixtures), len(manifest), "duplicate provenance entry")
                self.assertTrue(all(entry["origin"].strip() for entry in manifest))
            else:
                fixtures = manifest["fixtures"]
            self.assertEqual(set(fixtures), {p.name for p in root.glob(f"*.{extension}") if p.name != "provenance.json"})
            for name, digest in fixtures.items():
                self.assertEqual(hashlib.sha256((root / name).read_bytes()).hexdigest(), digest, name)

class AdvisoryPolicy(unittest.TestCase):
    def test_advisory_acceptance_is_exact(self):
        manifest=ci.tomllib.loads((ci.ROOT/'Cargo.toml').read_text())
        policy=ci.tomllib.loads((ci.ROOT/'deny.toml').read_text())
        ci.verify_policy(policy,manifest)
        for ignores in [[],['RUSTSEC-2023-0071','RUSTSEC-9999-0001'],['RUSTSEC-9999-0001']]:
            changed=copy.deepcopy(policy);changed['advisories']['ignore']=ignores
            with self.assertRaises(RuntimeError):ci.verify_policy(changed,manifest)
        changed=copy.deepcopy(policy);changed['sources']['allow-git'].append('https://example.com/unapproved')
        with self.assertRaises(RuntimeError):ci.verify_policy(changed,manifest)


class WorkingTreeStability(unittest.TestCase):
    def test_ci_accepts_stable_dirty_inputs(self):
        self.run_ci_with_edit(False)

    def test_ci_fails_if_source_changes_during_a_gate(self):
        self.run_ci_with_edit(True)

    def run_ci_with_edit(self, edit):
        from unittest import mock
        import subprocess
        import json
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(['/usr/bin/git', 'init', '-q', str(root)], check=True)
            (root / 'Cargo.toml').write_text('[workspace]\nmembers=[]\n')
            (root / 'Cargo.lock').write_text('version = 4\n')
            (root / '.gitignore').write_text('/artifacts/\n')
            source = root / 'source.rs'; source.write_text('before')
            def command(args):
                if edit and args[0] != '/usr/bin/git':
                    source.write_text('after')
                return subprocess.CompletedProcess(args, 0, 'revision')
            selection = {'full': False, 'packages': []}
            with mock.patch.object(ci, 'ROOT', root), mock.patch.object(ci, 'OUT', root / 'artifacts'), mock.patch.object(ci, 'command', side_effect=command), mock.patch.object(ci, 'select_impact', return_value=selection), mock.patch.object(ci, 'selected_gate', side_effect=lambda name, _: name == 'fmt'), mock.patch.object(ci, 'gate_command', side_effect=lambda name, args, selection: args), mock.patch.object(ci, 'workspace_pin', return_value=('url', 'rev')), mock.patch.object(ci, 'identity_pin', return_value=('url', 'rev')), mock.patch.object(ci, 'clear_execution_evidence'), mock.patch.dict(ci.os.environ, {'CI_PLAN':'0'}):
                self.assertEqual(ci.main(), int(edit))
            result = json.loads((root / 'artifacts/result.json').read_text())
            self.assertEqual(result['gates']['source-stability'], 'failed' if edit else 'passed')

    def test_state_covers_working_file_lifecycle(self):
        from unittest import mock
        import subprocess
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(['/usr/bin/git', 'init', '-q', str(root)], check=True)
            source = root / 'source.rs'; source.write_text('initial')
            subprocess.run(['/usr/bin/git', '-C', str(root), 'add', '.'], check=True)
            with mock.patch.object(ci, 'ROOT', root):
                state = ci.working_source_state()
                for action in (lambda: source.write_text('unstaged'),
                               lambda: (root / 'new.rs').write_text('untracked'),
                               lambda: source.unlink()):
                    action()
                    updated = ci.working_source_state()
                    self.assertNotEqual(state, updated)
                    state = updated
                self.assertEqual(state, ci.working_source_state())
