import importlib.util
import hashlib
import io
import json
import tarfile
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("release", Path(__file__).resolve().parents[1] / "hack/release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class CandidatePublication(unittest.TestCase):
    def test_candidate_inputs_reject_mutable_image_tags(self):
        for value in ['rss-identity-web:latest','rss-tools:test','sha256:short']:
            with self.assertRaises(ValueError):release.immutable_image(value)
        expected='sha256:'+'a'*64
        self.assertEqual(release.immutable_image(expected),expected)

    def test_platform_comes_from_verified_oci_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            for architecture in ["amd64", "arm64"]:
                path = Path(temporary) / "candidate.tar"
                config = {"os":"linux", "architecture":architecture, "config":{"User":"10001:10001"}}
                blobs = {}
                def blob(value):
                    data = json.dumps(value).encode()
                    digest = "sha256:" + hashlib.sha256(data).hexdigest()
                    blobs["blobs/sha256/" + digest[7:]] = data
                    return {"digest":digest}
                descriptor = blob({"config":blob(config)})
                blobs["index.json"] = json.dumps({"manifests":[descriptor]}).encode()
                with tarfile.open(path, "w") as archive:
                    for name, data in blobs.items():
                        entry = tarfile.TarInfo(name); entry.size = len(data)
                        archive.addfile(entry, io.BytesIO(data))
                digest, actual = release.oci_identity(path)
                self.assertEqual(digest, descriptor["digest"])
                self.assertEqual(release.platform(actual), "linux/" + architecture)

    def test_failed_acquisition_leaves_output_available_for_retry(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            header = root / "header"
            header.write_text("disposable-test-header")
            header.chmod(0o600)
            output = root / "candidate"
            for _ in range(2):
                with mock.patch.object(release, "build_staged", side_effect=RuntimeError("build failed")):
                    with self.assertRaisesRegex(RuntimeError, "build failed"):
                        release.build(output, header, "sha256:"+"a"*64)
                self.assertFalse(output.exists())
                self.assertEqual(sorted(p.name for p in root.iterdir()), ["header"])



class WorkingSource(unittest.TestCase):
    def test_private_header_in_source_is_rejected_before_docker(self):
        import subprocess
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'repo'; root.mkdir()
            subprocess.run(['/usr/bin/git', 'init', '-q', str(root)], check=True)
            (root / 'Cargo.toml').write_text('[workspace]\nmembers=[]\n')
            subprocess.run(['/usr/bin/git', '-C', str(root), 'add', 'Cargo.toml'], check=True)
            (root / 'deployment').mkdir()
            header = root / 'deployment/azure-header'
            header.write_text('synthetic authorization'); header.chmod(0o600)
            with mock.patch.object(release, 'ROOT', root), mock.patch.object(release, 'run', return_value='revision'), mock.patch.object(release, 'snapshot_ui') as ui:
                with self.assertRaisesRegex(ValueError, 'credential file'):
                    release.build(Path(temporary) / 'candidate', header, 'sha256:'+'a'*64)
                ui.assert_not_called()
            self.assertFalse((Path(temporary) / 'candidate').exists())

    def test_copy_uses_working_bytes_and_ignores_unrelated_files(self):
        import subprocess
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'repo'; root.mkdir()
            subprocess.run(['/usr/bin/git', 'init', '-q', str(root)], check=True)
            (root / 'Cargo.toml').write_text('[workspace]\nmembers=["crates/app"]\n')
            (root / 'Cargo.lock').write_text('version = 4\n')
            (root / 'rust-toolchain.toml').write_text('[toolchain]\nchannel="1.96.0"\n')
            (root / 'crates/app').mkdir(parents=True)
            (root / 'crates/app/old.rs').write_text('old')
            subprocess.run(['/usr/bin/git', '-C', str(root), 'add', '.'], check=True)
            (root / 'Cargo.lock').write_text('version = 4\n# current working bytes\n')
            (root / 'crates/app/old.rs').unlink()
            (root / 'crates/app/new.rs').write_text('unsubmitted')
            subprocess.run(['/usr/bin/git', '-C', str(root), 'add', 'crates/app/new.rs'], check=True)
            (root / 'private-secret').write_text('must not enter context')
            destination = Path(temporary) / 'source'
            release.copy_source(root, destination)
            self.assertEqual((destination / 'Cargo.lock').read_text(), 'version = 4\n# current working bytes\n')
            self.assertEqual((destination / 'crates/app/new.rs').read_text(), 'unsubmitted')
            self.assertFalse((destination / 'crates/app/old.rs').exists())
            self.assertFalse((destination / 'private-secret').exists())
            (root / 'crates/app/escape').symlink_to(root / 'private-secret')
            with self.assertRaises(ValueError):
                release.copy_source(root, Path(temporary) / 'bad-source')

    def test_unknown_input_is_rejected(self):
        import subprocess
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'repo'; root.mkdir()
            subprocess.run(['/usr/bin/git', 'init', '-q', str(root)], check=True)
            (root / 'Cargo.toml').write_text('[workspace]\nmembers=["crates/app"]\n')
            (root / 'crates/app').mkdir(parents=True)
            subprocess.run(['/usr/bin/git', '-C', str(root), 'add', '.'], check=True)
            (root / 'crates/app/operator-token.pem').write_text('synthetic private token')
            with self.assertRaisesRegex(ValueError, 'untracked build input'):
                release.copy_source(root, Path(temporary) / 'source')

    def test_change_during_copy_is_rejected(self):
        import subprocess
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'repo'; root.mkdir()
            subprocess.run(['/usr/bin/git', 'init', '-q', str(root)], check=True)
            (root / 'Cargo.toml').write_text('[workspace]\nmembers=[]\n')
            subprocess.run(['/usr/bin/git', '-C', str(root), 'add', '.'], check=True)
            original = release.shutil.copy2
            def changing_copy(source, target):
                original(source, target)
                source.write_text(source.read_text() + '# changed\n')
            with mock.patch.object(release.shutil, 'copy2', side_effect=changing_copy):
                with self.assertRaisesRegex(ValueError, 'changed during'):
                    release.copy_source(root, Path(temporary) / 'source')

    def test_ui_revision_is_information_not_admission(self):
        value = {'Id':'sha256:'+'a'*64,'Os':'linux','Architecture':'arm64','Config':{'User':'10001:10001','Labels':None}}
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'ui.tar'; output.write_bytes(b'image')
            with mock.patch.object(release, 'run', return_value=json.dumps([value])), mock.patch.object(release.subprocess, 'run'):
                result = release.snapshot_ui(value['Id'], output)
            self.assertIsNone(result['revision'])

if __name__ == "__main__":
    unittest.main()
