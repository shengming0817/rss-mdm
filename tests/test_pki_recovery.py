"""CA backup restoration preserves shared filesystem handles, never old bytes."""
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'hack'))
from pki_recovery import restore


class BackupRestore(unittest.TestCase):
    def test_backup_restores_keys_config_and_token_history_without_replacing_inodes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root/'step'
            contents = {'secrets/root_ca_key':b'encrypted-key',
                        'config/ca.json':b'{"same":"authority"}',
                        'db/000001.vlog':b'consumed-token-history'}
            for name, content in contents.items():
                path = original/name
                path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes(content)
                path.chmod(0o600)
            inodes = {path.relative_to(original):path.stat().st_ino for path in (original,*original.rglob('*'))}
            copytree = shutil.copytree
            def copying(source, target, *args, **kwargs):
                if Path(source) == root/'step-backup':
                    self.assertTrue(all((original/name).read_bytes() == b'' for name in contents))
                return copytree(source,target,*args,**kwargs)
            with patch('pki_recovery.shutil.copytree',side_effect=copying):
                restore(root)
            for name, content in contents.items():
                self.assertEqual((original/name).read_bytes(),content)
                self.assertEqual((root/'step-backup'/name).read_bytes(),content)
                self.assertEqual(os.stat(original/name).st_mode & 0o777,0o600)
            for name, inode in inodes.items():
                self.assertEqual((original/name).stat().st_ino,inode)
            self.assertTrue((root/'agent-backup-restored').is_file())
