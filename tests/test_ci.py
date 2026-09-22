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
import group_consumer as group

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

class GroupConsumer(unittest.TestCase):
    def test_only_pinned_group_and_value_types_are_consumed(self):
        pin = ci.workspace_pin(ci.ROOT)
        source = 'git+file:///tmp/source?rev=' + 'a' * 40 + '#' + 'a' * 40
        rss_source = f'git+{pin[0]}?rev={pin[1]}#{pin[1]}'
        names = ['group-consumer', 'rss-mdm-group', 'rss-contract', 'rss-request-context']
        data = {'workspace_members': ['group-consumer'], 'packages': [
            {'id': n, 'name': n, 'features': {}, 'source': None if i == 0 else source if i == 1 else rss_source}
            for i, n in enumerate(names)], 'resolve': {'root': 'group-consumer', 'nodes': [
                {'id': n, 'features': [], 'deps': [{'pkg': p} for p in (names[1:] if i == 0 else names[2:] if i == 1 else [])]}
                for i, n in enumerate(names)]}}
        group.verify_group_consumer(data, source, pin)
        for bad_source in [None, 'path+file:///parent/rss', rss_source.replace(pin[1], '0' * 40)]:
            bad = copy.deepcopy(data); bad['packages'][2]['source'] = bad_source
            with self.assertRaises(RuntimeError): group.verify_group_consumer(bad, source, pin)
        for dependency in ['rss-mdm-inventory', 'rss-mdm-group-postgres', 'reqwest', 'sqlx', 'rss-mdm-windows-mdm']:
            bad = copy.deepcopy(data)
            bad['packages'].append({'id': dependency, 'name': dependency, 'source': 'registry+https://github.com/rust-lang/crates.io-index'})
            bad['resolve']['nodes'][1]['deps'].append({'pkg': dependency})
            with self.assertRaises(RuntimeError): group.verify_group_consumer(bad, source, pin)
        for parent, dependency in [('rss-contract', 'sqlx'), ('rss-request-context', 'reqwest')]:
            with self.subTest(parent=parent, dependency=dependency):
                bad = copy.deepcopy(data)
                bad['packages'].append({'id': dependency, 'name': dependency, 'source': 'registry+https://github.com/rust-lang/crates.io-index'})
                bad['resolve']['nodes'].append({'id': dependency, 'features': [], 'deps': []})
                next(n for n in bad['resolve']['nodes'] if n['id'] == parent)['deps'].append({'pkg': dependency, 'dep_kinds': [{'kind': None, 'target': None}]})
                with self.assertRaisesRegex(RuntimeError, 'forbidden Group production dependency'):
                    group.verify_group_consumer(bad, source, pin)
        for dependency in ['sqlx-postgres', 'hyper-util', 'postgres-types', 'axum-core']:
            for kind, rejected in [(None, True), ('build', True), ('dev', False)]:
                with self.subTest(dependency=dependency, kind=kind):
                    bad = copy.deepcopy(data)
                    # Distinct IDs/names model Cargo package identity and dependency renaming.
                    bad['packages'].extend([
                        {'id': 'bridge-id', 'name': 'benign-bridge', 'source': 'registry+https://github.com/rust-lang/crates.io-index'},
                        {'id': 'forbidden-id', 'name': dependency, 'source': 'registry+https://github.com/rust-lang/crates.io-index'},
                    ])
                    bad['resolve']['nodes'][2]['deps'].append({'pkg': 'bridge-id', 'dep_kinds': [{'kind': None}]})
                    bad['resolve']['nodes'].extend([
                        {'id': 'bridge-id', 'deps': [{'name': 'alias', 'pkg': 'forbidden-id', 'dep_kinds': [{'kind': kind, 'target': 'cfg(windows)'}]}]},
                        {'id': 'forbidden-id', 'deps': []},
                    ])
                    if rejected:
                        with self.assertRaisesRegex(RuntimeError, 'forbidden Group production dependency'):
                            group.verify_group_consumer(bad, source, pin)
                    else:
                        group.verify_group_consumer(bad, source, pin)
        bad = copy.deepcopy(data); bad['packages'][1]['source'] = 'path+file:///tmp/group'
        with self.assertRaises(RuntimeError): group.verify_group_consumer(bad, source, pin)
        for declared, resolved in [({'default': ['new']}, []), ({}, ['new'])]:
            bad = copy.deepcopy(data); bad['packages'][1]['features'] = declared; bad['resolve']['nodes'][1]['features'] = resolved
            with self.assertRaises(RuntimeError): group.verify_group_consumer(bad, source, pin)
        bad = copy.deepcopy(data); bad['resolve']['nodes'][0]['deps'].pop()
        with self.assertRaises(RuntimeError): group.verify_group_consumer(bad, source, pin)

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

class CoreConsumerGate(unittest.TestCase):
    def test_core_closure_rejects_foreign_core_provider_and_wrong_sources(self):
        import sys
        sys.path.insert(0,str(ci.ROOT/'hack'))
        import core_consumer as core
        pin=('https://example.com/rss','1'*40)
        product='git+file:///isolated/source?rev='+'2'*40+'#'+'2'*40
        upstream='git+'+pin[0]+'?rev='+pin[1]+'#'+pin[1]
        registry='registry+https://github.com/rust-lang/crates.io-index'
        data={'workspace_members':['consumer'],'packages':[
            {'id':'consumer','name':'consumer','source':None},
            {'id':'scope','name':'rss-mdm-scope','source':product},
            {'id':'contract','name':'rss-contract','source':upstream},
            {'id':'context','name':'rss-request-context','source':upstream},
            {'id':'error','name':'thiserror','version':'2.0.20','source':registry}], 'resolve': {'root':'consumer', 'nodes': [
                {'id':node, 'deps':[{'pkg':dep, 'dep_kinds':[{'kind':None,'target':None}]} for dep in deps]}
                for node,deps in [('consumer',['scope','contract','context']),('scope',['contract','context','error']),('contract',[]),('context',[]),('error',[])]]}}
        locked={('thiserror','2.0.20',registry)}
        core.verify_closure(data,'rss-mdm-scope',product,pin,locked)
        for kind in ['dev', 'build']:
            bad=copy.deepcopy(data)
            bad['resolve']['nodes'][0]['deps'][1]['dep_kinds']=[{'kind':kind,'target':None}]
            with self.subTest(direct_kind=kind), self.assertRaises(RuntimeError):
                core.verify_closure(bad,'rss-mdm-scope',product,pin,locked)
        for core_name in ['rss-mdm-scope', 'rss-mdm-policy', 'rss-mdm-software-release']:
            selected=copy.deepcopy(data)
            selected['packages'][1]['name']=core_name
            core.verify_closure(selected,core_name,product,pin,locked)
            for target in ['scope', 'contract', 'context']:
                bad=copy.deepcopy(selected)
                bad['resolve']['nodes'][0]['deps']=[d for d in bad['resolve']['nodes'][0]['deps'] if d['pkg']!=target]
                with self.subTest(core=core_name,missing=target),self.assertRaises(RuntimeError):
                    core.verify_closure(bad,core_name,product,pin,locked)
        for declared,selected in [({'default':['new']},[]),({},['new'])]:
            bad=copy.deepcopy(data)
            bad['packages'][1]['features']=declared
            bad['resolve']['nodes'][1]['features']=selected
            with self.assertRaises(RuntimeError):
                core.verify_closure(bad,'rss-mdm-scope',product,pin,locked)
        for owner in ['contract', 'context']:
            bad=copy.deepcopy(data)
            next(n for n in bad['resolve']['nodes'] if n['id']==owner)['features']=['default']
            with self.subTest(canonical_feature_owner=owner),self.assertRaises(RuntimeError):
                core.verify_closure(bad,'rss-mdm-scope',product,pin,locked)
        for kinds in [[{'kind':'dev','target':None}], [{'kind':'build','target':None}], [{'kind':None,'target':'cfg(windows)'}], []]:
            bad=copy.deepcopy(data)
            bad['resolve']['nodes'][0]['deps'][0]['dep_kinds']=kinds
            with self.subTest(root_kinds=kinds), self.assertRaises(RuntimeError):
                core.verify_closure(bad,'rss-mdm-scope',product,pin,locked)
        for node_id in ['contract','context','error']:
            bad=copy.deepcopy(data)
            bad['resolve']['nodes'][1]['deps']=[d for d in bad['resolve']['nodes'][1]['deps'] if d['pkg']!=node_id]
            with self.subTest(disconnected=node_id), self.assertRaises(RuntimeError):
                core.verify_closure(bad,'rss-mdm-scope',product,pin,locked)
        bad=copy.deepcopy(data);bad['resolve']=None
        with self.assertRaises(RuntimeError):core.verify_closure(bad,'rss-mdm-scope',product,pin,locked)
        # Renaming changes the library name, never the package identity of an edge.
        renamed=copy.deepcopy(data);renamed['resolve']['nodes'][0]['deps'][0]['name']='renamed_core'
        renamed['resolve']['nodes'][1]['deps'][-1]['dep_kinds']=[{'kind':'build','target':None}]
        core.verify_closure(renamed,'rss-mdm-scope',product,pin,locked)
        for name,source in [('rss-mdm-policy',product),('sqlx-core',registry),('hyper',registry),('mongodb',registry),('rss-observation',upstream),('helper','path+file:///parent')]:
            bad=copy.deepcopy(data);bad['packages'].append({'id':'bad','name':name,'source':source})
            bad['resolve']['nodes'].append({'id':'bad','deps':[]})
            bad['resolve']['nodes'][1]['deps'].append({'pkg':'bad','dep_kinds':[{'kind':None,'target':None}]})
            with self.subTest(name=name),self.assertRaises(RuntimeError):core.verify_closure(bad,'rss-mdm-scope',product,pin,locked)
        bad=copy.deepcopy(data);bad['packages'][1]['source']='path+file:///parent'
        with self.assertRaises(RuntimeError):core.verify_closure(bad,'rss-mdm-scope',product,pin,locked)
        bad=copy.deepcopy(data);bad['packages'].pop(1)
        with self.assertRaises(RuntimeError):core.verify_closure(bad,'rss-mdm-scope',product,pin,locked)

        bad=copy.deepcopy(data);bad['packages'][-1]['version']='999.0.0'
        with self.assertRaises(RuntimeError):core.verify_closure(bad,'rss-mdm-scope',product,pin,locked)

    def test_consumer_drops_ambient_toolchain_and_stale_evidence(self):
        import sys
        from unittest.mock import patch
        sys.path.insert(0,str(ci.ROOT/'hack'))
        import core_consumer as core
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            with patch.dict(core.os.environ,{'RUSTUP_TOOLCHAIN':'nightly'}):
                self.assertFalse('RUSTUP_TOOLCHAIN' in core.isolated_env(root))
            out=root/'evidence';out.mkdir();(out/'result.json').write_text('old success')
            (out/'old-metadata.json').write_text('{}')
            core.prepare_output(out)
            self.assertEqual(list(out.iterdir()),[])
class GroupEvidence(unittest.TestCase):
    def test_manual_entry_prepares_workspace_before_cargo_failure(self):
        from unittest import mock
        from types import SimpleNamespace
        def command(args, **kwargs):
            if 'rust-toolchain.toml' in args[-1]:
                return SimpleNamespace(returncode=0, stdout='[toolchain]\nchannel="1.96.0"\n')
            return SimpleNamespace(returncode=0, stdout='')
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            failed_cargo = SimpleNamespace(returncode=1, stdout='', stderr='fixture failure')
            with mock.patch.object(group, 'OUT', out), mock.patch.object(group, 'command', side_effect=command), mock.patch.object(group, 'workspace_pin', return_value=('https://example.invalid/rss', 'a' * 40)), mock.patch.object(group.subprocess, 'run', return_value=failed_cargo):
                with self.assertRaisesRegex(RuntimeError, 'Group consumer command failed'):
                    group.group_consumer('b' * 40)
            self.assertIn('fixture failure', (out / 'group-consumer.log').read_text())

    def test_early_failure_cannot_leave_an_old_success_log(self):
        from unittest import mock
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            (out / 'group-consumer.log').write_text('old success')
            with mock.patch.object(group, 'OUT', out), mock.patch.object(group, 'command', return_value=SimpleNamespace(returncode=0, stdout=' M tracked')):
                with self.assertRaises(RuntimeError): group.group_consumer('b' * 40)
            log = (out / 'group-consumer.log').read_text()
            self.assertNotIn('old success', log)
            self.assertIn('b' * 40, log)
