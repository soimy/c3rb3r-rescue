"""Synthetic records only; never read the published incident material."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from check_publish import inspect_blob
from export_public_key import export_key


class PublicKeyTests(unittest.TestCase):
    def test_export_exact_private_mode_and_no_overwrite(self):
        raw = bytes(range(48))
        data = {'schema_version': 1, 'format': 'iv16-aes-key32',
                'material_hex': raw.hex(), 'material_sha256': hashlib.sha256(raw).hexdigest()}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record, output = root/'candidate.json', root/'candidate.bin'
            record.write_text(json.dumps(data))
            result = export_key(record, output)
            self.assertEqual(output.read_bytes(), raw)
            self.assertEqual(result['bytes'], 48)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                export_key(record, output)
            link = root/'link'
            link.symlink_to(output)
            with self.assertRaises(OSError):
                export_key(record, link)
            self.assertEqual(output.read_bytes(), raw)

    def test_invalid_candidate_is_rejected_before_output(self):
        good = {'schema_version': 1, 'format': 'iv16-aes-key32',
                'material_hex': bytes(range(48)).hex(),
                'material_sha256': hashlib.sha256(bytes(range(48))).hexdigest()}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record, output = root/'candidate.json', root/'must-not-exist'
            for changed in [{'material_sha256': '0'*64}, {'material_hex': 'bad hex'},
                            {'material_hex': '00', 'material_sha256': hashlib.sha256(b'\0').hexdigest()},
                            {'format': 'unknown'}, {'schema_version': 2}]:
                record.write_text(json.dumps(dict(good, **changed)))
                with self.assertRaises(ValueError):
                    export_key(record, output)
                self.assertFalse(output.exists())

    def test_publication_exception_requires_exact_path_and_blob(self):
        path = 'profiles/synthetic-public-key.json'
        secret = bytes(range(48)).hex().encode()
        blob = b'{"synthetic": "'+secret+b'"}\n'
        allowed = {path: hashlib.sha256(blob).hexdigest()}
        with patch('check_publish.PUBLIC_KEY_RECORDS', allowed):
            self.assertFalse(inspect_blob(path, blob, '100644', (secret,)))
            self.assertTrue(inspect_blob('docs/accidental-key.md', blob, '100644', (secret,)))
            self.assertTrue(inspect_blob(path, blob+b' ', '100644', (secret,)))
            self.assertTrue(inspect_blob(path, b'{}', '100644'))
            self.assertTrue(inspect_blob(path, blob, '120000', (secret,)))


if __name__ == '__main__':
    unittest.main()
