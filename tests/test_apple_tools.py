import hashlib
import importlib.util
import io
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "hack"))

spec = importlib.util.spec_from_file_location('apple_tools', ROOT / 'hack/apple_tools.py')
tools = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tools)


class OracleSource(unittest.TestCase):
    def test_archive_not_cached_tree_is_the_only_build_input(self):
        content = io.BytesIO()
        with tarfile.open(fileobj=content, mode='w:gz') as archive:
            member = tarfile.TarInfo('nanomdm-fixed/go.mod')
            body = b'module test\n'
            member.size = len(body)
            archive.addfile(member, io.BytesIO(body))
        data = content.getvalue()
        digest = hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary) / 'apple-tools' / digest
            source = cache / 'nanomdm-fixed'
            source.mkdir(parents=True)
            (cache / 'archive.tar.gz').write_bytes(data)
            (source / 'injected.go').write_text('package main')
            seen = []

            def build(args, *, cwd, **kwargs):
                self.assertFalse((cwd / 'injected.go').exists())
                self.assertEqual((cwd / 'go.mod').read_bytes(), body)
                (cwd / 'injected.go').write_text('package main')
                seen.append(cwd)
                Path(args[args.index('-o') + 1]).write_bytes(b'binary')

            # This isolated, mocked build owns a temporary target, not the enclosing CI lease.
            env = {key: value for key, value in os.environ.items() if not key.startswith('_MDM_')}
            env['CARGO_TARGET_DIR'] = temporary
            with patch.dict(os.environ, env, clear=True), patch.object(tools, 'LOCK', {'nanomdm': {'revision': 'fixed', 'sourceArchiveSha256': digest}}), patch('subprocess.run', side_effect=build), patch.object(tools,'nano_identity',return_value={'source':digest,'toolchain':'fixed','flags':[]}):
                tools.nano_binary()
                tools.nano_binary()
            self.assertEqual(len(seen), 1)
            self.assertTrue(all(not path.exists() for path in seen))

class NanoCache(unittest.TestCase):
    def test_cache_identity_includes_effective_toolchain_and_flags(self):
        with patch('t2_processes.subprocess.check_output',return_value='{"GOOS":"darwin","GOARCH":"arm64","GOVERSION":"go1.25.1","CGO_ENABLED":"1","GOFLAGS":"","GOROOT":"/go"}'):
            first=tools.nano_identity()
        with patch('t2_processes.subprocess.check_output',return_value='{"GOOS":"darwin","GOARCH":"arm64","GOVERSION":"go1.25.2","CGO_ENABLED":"1","GOFLAGS":"","GOROOT":"/go"}'):
            self.assertNotEqual(first,tools.nano_identity())


class ConcurrentPublication(unittest.TestCase):
    def fixture(self):
        from contextlib import ExitStack
        stack = ExitStack()
        self.addCleanup(stack.close)
        temporary = stack.enter_context(tempfile.TemporaryDirectory())
        content = io.BytesIO()
        with tarfile.open(fileobj=content, mode='w:gz') as archive:
            member = tarfile.TarInfo('nanomdm-fixed/go.mod')
            member.size = len(b'module test\n')
            archive.addfile(member, io.BytesIO(b'module test\n'))
        data = content.getvalue()
        digest = hashlib.sha256(data).hexdigest()
        env = {key: value for key, value in os.environ.items() if not key.startswith('_MDM_')}
        env['CARGO_TARGET_DIR'] = temporary
        stack.enter_context(patch.dict(os.environ, env, clear=True))
        stack.enter_context(patch.object(tools, 'LOCK', {'nanomdm': {'revision':'fixed', 'sourceArchiveSha256':digest}}))
        identity = {'source':digest, 'toolchain':'fixed', 'flags':[]}
        stack.enter_context(patch.object(tools, 'nano_identity', return_value=identity))
        response = stack.enter_context(patch.object(tools.urllib.request, 'urlopen'))
        response.return_value.__enter__.return_value.read.return_value = data
        self.builds = 0
        def build(args, **kwargs):
            self.builds += 1
            Path(args[args.index('-o')+1]).write_bytes(b'verified-binary')
        return stack, Path(temporary), build, identity

    def test_cold_concurrent_callers_build_once_and_reverify_published_artifact(self):
        import concurrent.futures
        import threading
        stack, root, build, identity = self.fixture()
        entered, release, contended = threading.Event(), threading.Event(), threading.Event()
        original_lock = tools.lock_file
        def locked(*args, **kwargs):
            held = original_lock(*args, **kwargs)
            if held is None:
                contended.set()
            return held
        def slow_build(*args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise RuntimeError('missing build release')
            build(*args, **kwargs)
        stack.enter_context(patch.object(tools, 'lock_file', side_effect=locked))
        stack.enter_context(patch('t2_processes.subprocess.run', side_effect=slow_build))
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            first = pool.submit(tools.nano_binary)
            self.assertTrue(entered.wait(5))
            second = pool.submit(tools.nano_binary)
            try:
                self.assertTrue(contended.wait(5))
            finally:
                release.set()
            paths = [first.result(5), second.result(5)]
        self.assertEqual(paths[0], paths[1])
        self.assertEqual(self.builds, 1)
        proof = __import__('json').loads(paths[0].with_name('manifest.json').read_text())
        self.assertEqual(proof, dict(identity=identity, sha256=hashlib.sha256(paths[0].read_bytes()).hexdigest()))
        self.assertFalse(list(root.rglob('build-*')))
        self.assertFalse(list(root.rglob('.manifest.json-*')))

    def test_failed_manifest_publish_releases_lock_and_next_caller_recovers(self):
        import concurrent.futures
        import threading
        stack, root, build, _ = self.fixture()
        entered, release, contended = threading.Event(), threading.Event(), threading.Event()
        original_publish, original_lock = tools.publish, tools.lock_file
        failed = False
        def publish(path, *args):
            nonlocal failed
            if path.name == 'manifest.json' and not failed:
                failed = True
                entered.set()
                if not release.wait(5):
                    raise RuntimeError('missing publication release')
                raise OSError('injected manifest publication failure')
            return original_publish(path, *args)
        def locked(*args, **kwargs):
            held = original_lock(*args, **kwargs)
            if held is None:
                contended.set()
            return held
        stack.enter_context(patch('t2_processes.subprocess.run', side_effect=build))
        stack.enter_context(patch.object(tools, 'publish', side_effect=publish))
        stack.enter_context(patch.object(tools, 'lock_file', side_effect=locked))
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            first = pool.submit(tools.nano_binary)
            self.assertTrue(entered.wait(5))
            second = pool.submit(tools.nano_binary)
            try:
                self.assertTrue(contended.wait(5))
            finally:
                release.set()
            with self.assertRaisesRegex(OSError, 'injected'):
                first.result(5)
            path = second.result(5)
        self.assertEqual(path.read_bytes(), b'verified-binary')
        self.assertEqual(self.builds, 2)
        self.assertTrue(path.with_name('manifest.json').exists())
        self.assertFalse(list(root.rglob('build-*')))

    def test_corrupt_proof_binary_permissions_and_changed_identity_require_build(self):
        stack, _, build, identity = self.fixture()
        stack.enter_context(patch('t2_processes.subprocess.run', side_effect=build))
        path = tools.nano_binary()
        for damaged in ('proof', 'binary', 'permissions'):
            if damaged == 'proof':
                path.with_name('manifest.json').write_text('null')
            elif damaged == 'binary':
                path.write_bytes(b'corrupt')
            else:
                path.chmod(0o600)
            self.assertEqual(tools.nano_binary().read_bytes(), b'verified-binary')
        identity['toolchain'] = 'different'
        self.assertNotEqual(tools.nano_binary(), path)
        self.assertEqual(self.builds, 5)

    def test_corrupt_archive_is_never_used_for_build_or_published_on_download_failure(self):
        stack, root, build, identity = self.fixture()
        cache = root/'apple-tools'/identity['source']
        cache.mkdir(parents=True)
        (cache/'archive.tar.gz').write_bytes(b'corrupt')
        stack.enter_context(patch('t2_processes.subprocess.run', side_effect=build))
        with patch.object(tools.urllib.request, 'urlopen') as response:
            response.return_value.__enter__.return_value.read.return_value = b'also-corrupt'
            with self.assertRaisesRegex(RuntimeError, 'checksum mismatch'):
                tools.nano_binary()
        self.assertEqual(self.builds, 0)
        self.assertEqual((cache/'archive.tar.gz').read_bytes(), b'corrupt')
        self.assertEqual(tools.nano_binary().read_bytes(), b'verified-binary')

    def test_atomic_replace_failure_only_removes_own_stage(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            final, foreign = root/'manifest.json', root/'.other-stage'
            final.write_bytes(b'previous')
            foreign.write_bytes(b'another caller')
            with patch.object(Path, 'replace', side_effect=OSError('publication failed')):
                with self.assertRaisesRegex(OSError, 'publication failed'):
                    tools.publish(final, b'new')
            self.assertEqual(final.read_bytes(), b'previous')
            self.assertEqual(foreign.read_bytes(), b'another caller')
            self.assertEqual(set(root.iterdir()), {final, foreign})

    def test_waiting_publisher_honors_run_cancellation(self):
        import concurrent.futures
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with tools.publication(root):
                with patch.object(tools, 'check_cancelled', side_effect=RuntimeError('T2 cancelled')):
                    with concurrent.futures.ThreadPoolExecutor(1) as pool:
                        with self.assertRaisesRegex(RuntimeError, 'T2 cancelled'):
                            pool.submit(self.take, root).result(5)
            with tools.publication(root):
                pass

    @staticmethod
    def take(root):
        with tools.publication(root):
            pass
