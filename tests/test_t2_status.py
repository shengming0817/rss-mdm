"""An unavailable T2 surface cannot produce successful verification evidence."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'hack'))
import ci
import t2


class T2Status(unittest.TestCase):
    def test_all_public_modes_record_not_built_and_revoke_old_success(self):
        for mode in ('affected','all'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);output=root/'artifacts/local-t2';output.mkdir(parents=True)
                (output/'result.json').write_text('{"status":"passed"}')
                with (patch.object(t2,'ROOT',root),patch.object(t2,'require_lease'),
                      patch.object(ci,'command',return_value=subprocess.CompletedProcess([],0,'revision')),
                      patch.object(ci,'working_source_state',return_value='state'),
                      contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO())):
                    self.assertEqual(t2.main(['--module',mode]),1)
                evidence=json.loads((output/'result.json').read_text())
                self.assertEqual(evidence['status'],'skipped');self.assertEqual(evidence['reason'],'not-built')
                self.assertEqual(evidence['executedCases'],0);self.assertEqual(evidence['sourceRevision'],'revision')

    def test_invalid_arguments_do_not_preserve_old_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);output=root/'artifacts/local-t2';output.mkdir(parents=True)
            receipt=output/'result.json';receipt.write_text('{"status":"passed"}')
            with (patch.object(t2,'ROOT',root),patch.object(t2,'require_lease'),
                  contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit) as caught):
                t2.main(['--module','unknown'])
            self.assertEqual(caught.exception.code,2);self.assertFalse(receipt.exists())
