import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('native_sources', Path(__file__).parents[1] / 'hack/native_sources.py')
sources = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sources)


class NativeSourcesTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        for name, relative in sources.GROUPS.items():
            path = self.root / relative
            path.mkdir(parents=True)
            (path / 'source.json').write_text(json.dumps({'source': name}))
        sources.pack(self.root)

    def test_pack_is_stable_and_prepare_replaces_stale_cache(self):
        first = (self.root / sources.SOURCES / 'lock.json').read_bytes()
        sources.pack(self.root)
        self.assertEqual(first, (self.root / sources.SOURCES / 'lock.json').read_bytes())
        for relative in sources.GROUPS.values():
            (self.root / relative / 'stale').write_text('not in the archive')
            (self.root / relative / 'source.json').write_text('corrupt cache')
        sources.prepare(self.root)
        for name, relative in sources.GROUPS.items():
            self.assertEqual(json.loads((self.root / relative / 'source.json').read_text()), {'source': name})
            self.assertFalse((self.root / relative / 'stale').exists())

    def test_changed_archive_is_rejected_before_replacing_cache(self):
        archive = self.root / sources.SOURCES / 'windows-ddf.zip'
        archive.write_bytes(archive.read_bytes() + b'changed')
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            sources.prepare(self.root)
        self.assertTrue((self.root / sources.GROUPS['windows-ddf'] / 'source.json').exists())

    def test_archive_cannot_write_outside_source_cache(self):
        import stat
        import zipfile
        archive = self.root / sources.SOURCES / 'windows-ddf.zip'
        with zipfile.ZipFile(archive, 'w') as output:
            info = zipfile.ZipInfo('../outside')
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            output.writestr(info, b'escape')
        lock_path = self.root / sources.SOURCES / 'lock.json'
        lock = json.loads(lock_path.read_text())
        lock['windows-ddf']['sha256'] = sources.digest(archive.read_bytes())
        lock_path.write_text(json.dumps(lock))
        with self.assertRaisesRegex(ValueError, 'invalid native schema ZIP member'):
            sources.prepare(self.root)
        self.assertFalse((self.root / sources.GROUPS['windows-ddf'].parent / 'outside').exists())
