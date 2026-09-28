"""Source fixtures probe only addresses owned by the test host."""
from pathlib import Path
import os
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'hack'))
import source_fixtures

class SourceFixtureBoundary(unittest.TestCase):
    def test_loopback_override_never_becomes_a_source_endpoint(self):
        with patch.dict(os.environ,{'SOURCE_T2_ADDRESS':'127.0.0.1'}), patch.object(source_fixtures.socket,'socket') as socket:
            with self.assertRaisesRegex(RuntimeError,'non-loopback'):
                source_fixtures.local_address()
            socket.assert_not_called()

    def test_unowned_address_is_not_contacted(self):
        with patch.dict(os.environ,{'SOURCE_T2_ADDRESS':'192.0.2.8'}), patch.object(source_fixtures.socket,'socket') as socket, patch.object(source_fixtures.socket,'create_connection') as connect:
            socket.return_value.__enter__.return_value.bind.side_effect=OSError('not assigned')
            with self.assertRaisesRegex(RuntimeError,'non-loopback'):
                source_fixtures.local_address()
            connect.assert_not_called()

if __name__=='__main__':unittest.main()
