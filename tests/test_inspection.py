"""Only synthetic footer, LiME and iomem data; no victim material."""
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from file_layout import FOOTER_SIZE, RecoveryError, parse_marker
from inspect_footer import inspect_copy
from inspect_lime import (MAGIC, inspect_lime, read_segments, system_ram_ranges,
                          uncovered)

SCRIPTS = Path(__file__).resolve().parents[1]/'skills/dsm-ransomware-rescue/scripts'


def lime_segment(start, payload, endian='<'):
    return struct.pack(endian+'IIQQ8s', MAGIC, 1, start, start+len(payload)-1, bytes(8))+payload


class FooterInspectionTests(unittest.TestCase):
    def test_layout_inspection_accepts_other_marker_without_claiming_key_match(self):
        with tempfile.TemporaryDirectory() as t:
            path = Path(t)/'private-name.L0CK3D'
            data = bytearray(1003+FOOTER_SIZE)
            data[-20:-16] = bytes.fromhex('883c0309')
            data[-16:-12] = bytes((0x25, 20, 0x20, 0))
            struct.pack_into('<Q', data, len(data)-8, 1003)
            path.write_bytes(data)
            result = inspect_copy(path)
            self.assertEqual(result['marker'], '883c0309')
            self.assertEqual(result['expected_encrypted_bytes'], 210)
            self.assertEqual(result['encrypted_ranges'], [
                {'offset': 0, 'length': 70}, {'offset': 466, 'length': 70},
                {'offset': 932, 'length': 70}])
            self.assertNotIn('private-name', json.dumps(result))
            self.assertIn('layout only', result['validation'])
            self.assertEqual(path.read_bytes(), data)

    def test_footer_inspection_refuses_unsupported_and_incomplete_copies(self):
        with tempfile.TemporaryDirectory() as t:
            path = Path(t)/'copy'; base = bytearray(1003+FOOTER_SIZE)
            base[-16:-12] = bytes((0x25, 10, 0x20, 0))
            struct.pack_into('<Q', base, len(base)-8, 1003)
            for offset, value in ((-14, 0x21), (-13, 1), (-16, 0x22), (-15, 11), (-8, 0)):
                data = base.copy(); data[offset] = value; path.write_bytes(data)
                with self.assertRaises(RecoveryError): inspect_copy(path)
            for data in (b'few', base[:-1], base+b'appended log'):
                path.write_bytes(data)
                with self.assertRaises(RecoveryError): inspect_copy(path)
            path.write_bytes(base)
            link = Path(t)/'link'; link.symlink_to(path)
            with self.assertRaises(RecoveryError): inspect_copy(link)
            fifo = Path(t)/'pipe'; os.mkfifo(fifo)
            with self.assertRaises(RecoveryError): inspect_copy(fifo)

    def test_marker_parser_is_strict(self):
        self.assertEqual(parse_marker('CE35A593'), bytes.fromhex('ce35a593'))
        for value in ('', 'ce 35 a5 93', '0xce35a593', 'ce35a59', 'ce35a59300', 'zz35a593', None):
            with self.assertRaises(RecoveryError): parse_marker(value)


class LimeInspectionTests(unittest.TestCase):
    def test_cli_distinguishes_valid_structure_missing_ram_and_bad_dump(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); path = root/'ram'; iomem = root/'iomem'
            path.write_bytes(lime_segment(0x1000, b'A'*16))
            args = [sys.executable, str(SCRIPTS/'inspect_lime.py'), '--input-copy', str(path)]
            result = subprocess.run(args, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIsNone(json.loads(result.stdout)['coverage_matches_iomem'])
            iomem.write_text('1000-101f : System RAM\n')
            result = subprocess.run(args+['--iomem-copy', str(iomem)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertFalse(json.loads(result.stdout)['coverage_matches_iomem'])
            path.write_bytes(b'broken')
            result = subprocess.run(args, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertNotIn(str(path), result.stderr)

    def test_headers_include_padding_and_inclusive_end_with_physical_gap(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); path = root/'ram'; iomem = root/'iomem'
            data = lime_segment(0x1000, b'A'*16)+lime_segment(0x2000, b'B'*32)
            path.write_bytes(data)
            iomem.write_text('00001000-0000100f : System RAM\n00002000-0000201f : System RAM\n')
            result = inspect_lime(path, iomem, True)
            self.assertTrue(result['coverage_matches_iomem'])
            self.assertEqual(result['payload_bytes'], 48)
            self.assertEqual([s['file_offset'] for s in result['segments']], [32, 80])
            self.assertEqual(result['address_gaps'], [{'start': 0x1010, 'end_inclusive': 0x1fff}])
            self.assertEqual(result['sha256'], hashlib.sha256(data).hexdigest())
            self.assertEqual(path.read_bytes(), data)
            self.assertIsNone(inspect_lime(path)['coverage_matches_iomem'])
            iomem.write_text('00001000-0000101f : System RAM\n')
            result = inspect_lime(path, iomem)
            self.assertFalse(result['coverage_matches_iomem'])
            self.assertEqual(result['missing_system_ram'], [{'start': 0x1010, 'end_inclusive': 0x101f}])
            self.assertEqual(result['outside_system_ram'], [{'start': 0x2000, 'end_inclusive': 0x201f}])

    def test_reject_truncation_bad_headers_overlap_and_mixed_endianness(self):
        good = lime_segment(0x1000, b'A'*16)
        bad_version = bytearray(good); bad_version[4] = 2
        bad_reserved = bytearray(good); bad_reserved[24] = 1
        reversed_range = struct.pack('<IIQQ8s', MAGIC, 1, 9, 1, bytes(8))
        for data in (b'', good[:24], good[:-1], good+b'x', bytes(bad_version),
                     bytes(bad_reserved), reversed_range, good+good,
                     good+lime_segment(0x1008, b'X'*16),
                     good+lime_segment(0x2000, b'X'*16, '>'), b'not lime'*4):
            with self.subTest(size=len(data)):
                with self.assertRaises(ValueError): read_segments(io.BytesIO(data), len(data))
        data = lime_segment(0x4000, b'A', '>')
        segments, endian = read_segments(io.BytesIO(data), len(data))
        self.assertEqual(endian, 'big'); self.assertEqual(segments[0]['bytes'], 1)

    def test_iomem_comparison_handles_splits_and_rejects_redaction(self):
        self.assertEqual(uncovered([(0, 10)], [(0, 3), (3, 10)]), [])
        self.assertEqual(uncovered([(0, 10)], [(2, 4), (7, 8)]), [
            {'start': 0, 'end_inclusive': 1}, {'start': 4, 'end_inclusive': 6},
            {'start': 8, 'end_inclusive': 9}])
        for text in ('', '00000000-00000000 : System RAM\n',
                     '1000-2000 : System RAM\n1500-2500 : System RAM\n',
                     '2000-1000 : System RAM\n'):
            with self.assertRaises(ValueError): system_ram_ranges(text)

    def test_lime_refuses_symlink_and_special_input(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); path = root/'ram'; path.write_bytes(lime_segment(1, b'A'))
            link = root/'link'; link.symlink_to(path)
            with self.assertRaises(OSError): inspect_lime(link)
            fifo = root/'pipe'; os.mkfifo(fifo)
            with self.assertRaises(ValueError): inspect_lime(fifo)


if __name__ == '__main__':
    unittest.main()
