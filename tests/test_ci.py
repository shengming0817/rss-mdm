import importlib.util
from pathlib import Path
import unittest
import copy
import tempfile

spec = importlib.util.spec_from_file_location("local_ci", Path(__file__).resolve().parents[1] / "hack/ci.py")
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)

class IsolationGates(unittest.TestCase):
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
        revision = ci.identity_pin(ci.tomllib.loads((root / 'Cargo.toml').read_text()))
        identity_source = f'git+{ci.IDENTITY_URL}?rev={revision}#{revision}'
        extra = [{'id':name,'name':name,'version':version,'source':registry} for name,version in [('openidconnect','4.0.1'),('rsa','0.9.10')]]
        extra += [{'id':name,'name':name,'source':identity_source} for name in ci.IDENTITY_PACKAGES]
        data['packages'][-2:-2] = extra
        for node in data['resolve']['nodes']: node['deps'] = []
        next(n for n in data['resolve']['nodes'] if n['id']=='rss-mdm-app')['deps'] = [{'pkg':'openidconnect'},{'pkg':'rss-identity-client'}]
        data['resolve']['nodes'][-2:-2] = [{'id':p['id'],'features':[],'deps':([{'pkg':'rsa'}] if p['id']=='openidconnect' else [])} for p in extra]
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
        root = ci.ROOT / "crates/windows-mdm/tests/fixtures"
        manifest = json.loads((root / "provenance.json").read_text())
        self.assertEqual(set(manifest["fixtures"]), {p.name for p in root.glob("*.xml")})
        for name, digest in manifest["fixtures"].items():
            self.assertEqual(hashlib.sha256((root / name).read_bytes()).hexdigest(), digest, name)
