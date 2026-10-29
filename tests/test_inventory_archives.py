import contextlib
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import inventory
import verify_backup
import verify_roots


class InventoryArchiveTests(unittest.TestCase):
    def test_metadata_count_does_not_follow_symlinks(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t).resolve(); (root/'one.L0CK3D').write_bytes(b'cipher')
            (root/'two').write_bytes(b'other'); (root/'link').symlink_to('/unrelated')
            out=io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(inventory.scan_root(str(root),set()),0)
            groups=[json.loads(l) for l in out.getvalue().splitlines() if json.loads(l)['event']=='group']
            self.assertEqual(sum(x['locked_files'] for x in groups),1)
            self.assertEqual(sum(x['other_files'] for x in groups),1)
            self.assertEqual(sum(x['symlinks'] for x in groups),1)

    def test_root_list_count_is_explicit_not_fixed_to_one_incident(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t).resolve(); volume=root/'volume';volume.mkdir();child=volume/'share';child.mkdir()
            listing=root/'roots';listing.write_bytes(str(child).encode()+b'\0')
            mounts={str(volume):[('1:1','/','btrfs','/dev/test')]}
            args=['verify_roots.py',str(listing),'--volume',str(volume),'--expected-count','1']
            with patch('sys.argv',args),patch('verify_roots.mount_table',return_value=mounts),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(verify_roots.main(),0)
            args[-1]='2'
            with patch('sys.argv',args),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(verify_roots.main(),2)

    def test_original_hash_checked_even_without_metadata_change(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'file.txt';p.write_bytes(b'known original')
            expected=hashlib.sha256(p.read_bytes()).hexdigest()
            self.assertTrue(verify_backup.validate(p,expected)['matches_expected_sha256'])
            with self.assertRaises(ValueError):verify_backup.validate(p,'0'*64)
            with self.assertRaises(ValueError):verify_backup.validate(p,'not a digest')

    def test_archive_cli_returns_failure_for_trailing_nonzero_data(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'backup.tar'
            with tarfile.open(p,'w') as tar:
                entry=tarfile.TarInfo('data');entry.size=1;tar.addfile(entry,io.BytesIO(b'x'))
            with p.open('ab') as f:f.write(b'wrong footer')
            result=subprocess.run([sys.executable,verify_backup.__file__,str(p)],capture_output=True)
            self.assertEqual(result.returncode,1)


if __name__ == '__main__':
    unittest.main()
