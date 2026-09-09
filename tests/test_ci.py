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
        root = Path("/tmp/consumer").resolve()
        pin = ci.rss_pin(ci.tomllib.loads((ci.ROOT / "Cargo.toml").read_text()))
        url, rev = pin
        source = f"git+{url}?rev={rev}#{rev}"
        data = {"packages": [
            *[{"id":name,"name":name,"manifest_path":str(root/path/"Cargo.toml"),"source":None} for name,path in ci.LOCAL_PACKAGES.items()],
            {"id":"obs","name":"rss-observation-postgres","source":source},
            {"id":"proj","name":"rss-projection-postgres","source":source}],
            "workspace_members":list(ci.LOCAL_PACKAGES), "resolve":{"nodes":[
                *[{"id":name,"features":[]} for name in ci.LOCAL_PACKAGES],{"id":"obs","features":[]},{"id":"proj","features":[]}]}}
        ci.verify_metadata(data,root,"normal",pin)
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
        root = Path("/tmp/consumer").resolve()
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

class SourceConsumerBoundary(unittest.TestCase):
    def test_source_identity_and_transitive_forbidden_dependencies(self):
        spec = importlib.util.spec_from_file_location("source_consumers", ci.ROOT / "hack/source-consumers.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        product = "rss-mdm-resource"
        data = {"packages": [{"id": "p", "name": product, "source": "product-sha"}], "resolve": {"nodes": [{"id": "p", "deps": []}]}}
        self.assertEqual(module.verify_graph(data, product, "product-sha", "rss-sha"), [product])
        with self.assertRaises(RuntimeError):
            module.verify_graph(data, product, "other-sha", "rss-sha")
        data["packages"].append({"id": "http", "name": "reqwest", "source": "registry"})
        data["resolve"]["nodes"].extend([{"id": "http", "deps": []}])
        data["resolve"]["nodes"][0]["deps"].append({"pkg": "http", "dep_kinds": [{"kind": None}]})
        with self.assertRaises(RuntimeError):
            module.verify_graph(data, product, "product-sha", "rss-sha")
        data["packages"][1]["name"] = "rss-mdm-brew-source"
        with self.assertRaises(RuntimeError):
            module.verify_graph(data, product, "product-sha", "rss-sha")

class SourceConsumerFailureCollection(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("source_consumers", ci.ROOT / "hack/source-consumers.py")
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def test_setup_failure_does_not_skip_later_packages(self):
        visited = []
        def run_one(name, test):
            visited.append(name)
            if name == "resource":
                raise OSError("injected fixture-copy failure")
            return {"status": "passed"}
        result = self.module.collect_consumers(run_one)
        self.assertEqual(visited, list(self.module.PACKAGES))
        self.assertEqual(result["resource"]["status"], "failed")
        self.assertEqual(result["brew-source"]["status"], "passed")

    def test_new_features_and_tokio_expansion_are_rejected(self):
        product = "rss-mdm-brew-source"
        data = {"packages": [{"id": "p", "name": product, "source": "product-sha", "features": {}}], "resolve": {"nodes": [{"id": "p", "deps": [], "features": []}]}}
        self.module.verify_graph(data, product, "product-sha", "rss-sha")
        data["packages"][0]["features"] = {"default": ["new-capability"]}
        with self.assertRaises(RuntimeError):
            self.module.verify_graph(data, product, "product-sha", "rss-sha")
        data["packages"][0]["features"] = {}
        data["packages"].append({"id": "tokio", "name": "tokio", "source": "registry"})
        data["resolve"]["nodes"].append({"id": "tokio", "deps": [], "features": ["process", "time", "net"]})
        data["resolve"]["nodes"][0]["deps"] = [{"pkg": "tokio", "dep_kinds": [{"kind": None}]}]
        with self.assertRaises(RuntimeError):
            self.module.verify_graph(data, product, "product-sha", "rss-sha")
        data["resolve"]["nodes"][1]["features"] = ["process", "time"]
        self.module.verify_graph(data, product, "product-sha", "rss-sha")

    def test_dirty_input_cannot_leave_previous_success_receipt(self):
        from unittest.mock import patch
        import json
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            (out / "result.json").write_text('{"status":"passed","head":"old"}')
            (out / "resource-metadata.json").write_text('{"old":true}')
            with patch.object(self.module, "OUT", out), patch.object(self.module.subprocess, "check_output", return_value=" M changed"):
                self.assertEqual(self.module.main(), 1)
            self.assertFalse((out / "resource-metadata.json").exists())
            self.assertEqual(json.loads((out / "result.json").read_text())["status"], "failed")
