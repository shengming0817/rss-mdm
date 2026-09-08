import importlib.util
from pathlib import Path
import unittest
import copy

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
            {"id":"app","name":"rss-mdm","manifest_path":str(root/"Cargo.toml"),"source":None},
            {"id":"obs","name":"rss-observation-postgres","source":source},
            {"id":"proj","name":"rss-projection-postgres","source":source}],
            "workspace_members":["app"], "resolve":{"nodes":[
                {"id":"app","features":[]},{"id":"obs","features":[]},{"id":"proj","features":[]}]}}
        ci.verify_metadata(data,root,"normal",pin)
        with self.assertRaises(RuntimeError): ci.verify_metadata(data,root,"integration",pin)
        data["resolve"]["nodes"][1]["features"] = ["integration"]
        with self.assertRaises(RuntimeError): ci.verify_metadata(data,root,"normal",pin)
        data["resolve"]["nodes"][1]["features"] = []
        data["packages"][1]["source"] = "path+file:///parent/rss"
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
        for section in ("dependencies", "dev-dependencies"):
            for name, dep in updated[section].items():
                if name.startswith("rss-"): dep["rev"] = "1" * 40
        self.assertEqual(ci.rss_pin(updated), (url, "1" * 40))
