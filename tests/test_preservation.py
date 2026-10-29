import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from capture_qemu_ram import copy_range
from carve_memory import carve
from check_publish import inspect_blob
from recover_ram_keys import Ram, recover
from scan_indicators import scan
from seal_evidence import seal, verify
from unpack_upx import unpack


class PreservationTests(unittest.TestCase):
    def test_carve_bounded_offsets_and_source_hash(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);src=root/'ram';src.write_bytes(bytes(range(64)))
            result=carve(src,[0,32],16,root/'regions')
            self.assertEqual(result['source_sha256'],hashlib.sha256(src.read_bytes()).hexdigest())
            self.assertEqual((root/'regions/offset-20.bin').read_bytes(),bytes(range(32,48)))
            with self.assertRaises(ValueError):carve(src,[60],16,root/'bad')
            self.assertFalse((root/'bad').exists())

    def test_seal_preserves_source_and_refuses_reuse_and_tampering(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); source = root/'source'; source.mkdir()
            (source/'one').write_bytes(b'evidence')
            (source/'link').symlink_to('/does/not/exist')
            destination = root/'sealed'
            result = seal(source, destination)
            self.assertEqual(result['files'], 1)
            self.assertEqual(verify(destination)['verified_files'], 1)
            self.assertEqual((source/'one').read_bytes(), b'evidence')
            self.assertFalse((destination/'link').exists())
            self.assertEqual((destination/'one').stat().st_mode & 0o777, 0o400)
            with self.assertRaises(FileExistsError): seal(source, destination)
            (destination/'one').chmod(0o600); (destination/'one').write_bytes(b'changed!')
            with self.assertRaises(ValueError): verify(destination)
            destination.chmod(0o700)

    def test_capture_exact_range_short_reads_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); src = root/'memory'; src.write_bytes(bytes(range(64)))
            fd = os.open(src, os.O_RDONLY)
            try:
                out = root/'copy'
                self.assertEqual(copy_range(fd,out,8,32),hashlib.sha256(bytes(range(8,40))).hexdigest())
                with self.assertRaises(FileExistsError): copy_range(fd,out,0,1)
                with self.assertRaises(OSError): copy_range(fd,root/'short',32,64)
            finally: os.close(fd)

    def test_synthetic_page_tables_and_private_key_candidate(self):
        data = bytearray(65536)
        va = 0x401f90; signature = bytes(range(64))
        data[0x3f90:0x3fd0] = signature
        def word(at, value): struct.pack_into('<Q',data,at,value)
        word(0x1000+2*8,0x2005); word(0x2000+1*8,0x3005)
        word(0x2000+((0x542000>>12)&511)*8,0x4005)
        word(0x2000+((0x53f000>>12)&511)*8,0x5005)
        word(0x1000+9*8,0x6005)
        word(0x6000+((0x130f000>>12)&511)*8,0x7005)
        word(0x47f8,0x130fa00); data[0x5c8c]=0x20
        master=bytes(range(48)); data[0x7a00:0x7a30]=master
        profile={'ram_bytes':len(data),'low_ram_end':0xc0000000,'high_ram_start':0x100000000,
                 'entry':{'va':va,'hex':signature.hex()},'mode_va':0x53fc8c,'master_pointer_va':0x5427f8}
        with tempfile.TemporaryDirectory() as t:
            out=Path(t)/'keys'; result=recover(data,profile,out)
            found=[x for x in result['master_candidates'] if 'master_file' in x]
            self.assertEqual(len(found),1)
            self.assertEqual((out/found[0]['master_file']).read_bytes(),master)
            self.assertEqual((out/found[0]['master_file']).stat().st_mode & 0o777,0o400)
            with self.assertRaises(FileExistsError): recover(data,profile,out)
        ram=Ram(data,0x8000,0x10000)
        self.assertEqual(ram.offset(ram.physical(0x9000)),0x9000)
        with self.assertRaises(ValueError): ram.offset(0x9000)
        with self.assertRaises(ValueError): ram.readv(0x1000,0x80000000,1)

    def test_indicator_context_is_data_and_limits_are_reported(self):
        with tempfile.TemporaryDirectory() as t:
            path=Path(t)/'log';path.write_bytes(b'PLUGIN_VALUE_END\nLD_PRELOAD\x1b\x00LD_PRELOAD')
            result=scan(path,1)
            self.assertTrue(any(x.get('truncated') for x in result['hits']))
            self.assertIn('\\u001b',json.dumps(result))

    def test_publication_blocks_private_and_actual_key_encodings(self):
        secret=bytes(range(48))
        self.assertTrue(inspect_blob('private/secret.bin',secret,'100644',(secret,)))
        self.assertTrue(inspect_blob('docs/key.md',secret.hex().encode(),'100644',(secret.hex().encode(),)))
        self.assertTrue(inspect_blob('docs/link.md',b'safe','120000'))
        user_path=b'/' + b'Users' + b'/fixture/file'
        self.assertIn('personal absolute path',inspect_blob('docs/path.md',user_path,'100644'))
        scanner=Path(__file__).parents[1]/'scripts/check_publish.py'
        self.assertFalse(inspect_blob('scripts/check_publish.py',scanner.read_bytes(),'100644'))
        self.assertFalse(inspect_blob('docs/note.md',b'Use private storage.','100644'))
        self.assertFalse(inspect_blob('README_CN.md',b'Safe documentation.','100644'))

    def test_unpack_never_executes_unreviewed_input(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t); src=root/'sample'; src.write_bytes(b'not ELF')
            with patch('unpack_upx.subprocess.run') as run:
                with self.assertRaises(ValueError): unpack(src,root/'out',Path('/trusted/upx'),'0'*64)
                run.assert_not_called()
            self.assertFalse((root/'out').exists())

    def test_unpack_derivative_and_cleanup_are_scoped(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);src=root/'sample';raw=b'\x7fELF synthetic UPX! fixture';src.write_bytes(raw)
            upx=root/'trusted-upx';upx.write_text('synthetic placeholder; never run')
            expected=hashlib.sha256(raw).hexdigest();out=root/'out'
            def fake_unpack(args, **kwargs):
                self.assertEqual(Path(args[-1]).read_bytes(),raw)
                Path(args[3]).write_bytes(b'\x7fELF derivative')
            with patch('unpack_upx.subprocess.run',side_effect=fake_unpack):
                result=unpack(src,out,upx,expected)
            self.assertEqual(result['output_sha256'],hashlib.sha256(out.read_bytes()).hexdigest())
            self.assertEqual(src.read_bytes(),raw)
            self.assertEqual(out.stat().st_mode & 0o777,0o600)
            with patch('unpack_upx.subprocess.run') as run:
                with self.assertRaises(FileExistsError):unpack(src,out,upx,expected)
                run.assert_not_called()
            other=root/'raced-output'
            def fail_after_replacement(*args, **kwargs):
                other.unlink();other.write_bytes(b'belongs to another writer')
                raise RuntimeError('synthetic failure')
            with patch('unpack_upx.subprocess.run',side_effect=fail_after_replacement):
                with self.assertRaises(RuntimeError):unpack(src,other,upx,expected)
            self.assertEqual(other.read_bytes(),b'belongs to another writer')


if __name__ == '__main__':
    unittest.main()
