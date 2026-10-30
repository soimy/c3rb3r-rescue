"""Synthetic local self-checks. This file never reads actual secret material."""

import hashlib
import os
from pathlib import Path
import struct
import tempfile
import unittest

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from decrypt_copy import (CALL_LIMIT, FOOTER_SIZE, MARKER, RecoveryError,
                          chacha8_call, decrypt_copy, encrypted_segments)


class RecoveryTests(unittest.TestCase):
    def test_explicit_other_session_marker_preserves_crypto_checks(self):
        marker = bytes.fromhex('492cb42b')  # Public metadata, synthetic keys/content only.
        master, file_key, nonce = bytes(range(48)), bytes(range(32)), bytes(range(8))
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); copies = root/'copies'; copies.mkdir()
            secret = root/'master'; secret.write_bytes(master)
            for mode, percent in ((0x26, 0), (0x25, 10)):
                plain = bytes(range(251))*100; body = bytearray(plain); counter = 0
                for offset, length in encrypted_segments(len(plain), mode, percent):
                    body[offset:offset+length], counter = chacha8_call(
                        bytes(body[offset:offset+length]), file_key, nonce, counter)
                footer = bytearray(FOOTER_SIZE)
                encryptor = Cipher(algorithms.AES(master[16:]), modes.CBC(master[:16])).encryptor()
                footer[:48] = encryptor.update(file_key+nonce+nonce)+encryptor.finalize()
                footer[568:572] = marker
                footer[572:576] = bytes((mode, percent, 0x20, 0))
                struct.pack_into('<Q', footer, 580, len(plain))
                source = copies/str(mode); source.write_bytes(body+footer)
                output = root/('recovered-%d' % mode)
                expected = hashlib.sha256(plain).hexdigest()
                with self.assertRaisesRegex(RecoveryError, 'marker differs'):
                    decrypt_copy(source, output, secret, copies, expected)
                self.assertFalse(output.exists())
                for invalid in (None, b'', b'long-marker', '492cb42b'):
                    with self.assertRaises(RecoveryError):
                        decrypt_copy(source, output, secret, copies, expected, invalid)
                bad = root/'bad-master'; bad.write_bytes(master[:16]+bytes(32))
                with self.assertRaisesRegex(RecoveryError, 'nonce check failed'):
                    decrypt_copy(source, output, bad, copies, expected, marker)
                self.assertFalse(output.exists())
                result = decrypt_copy(source, output, secret, copies, expected, marker)
                self.assertEqual(output.read_bytes(), plain)
                self.assertEqual(result['observed_marker'], marker.hex())
                self.assertEqual(result['expected_marker'], marker.hex())
                self.assertEqual(source.read_bytes(), body+footer)

    def test_published_chacha8_vectors(self):
        # Primary implementation project's vectors, attributed there to Bernstein.
        # https://github.com/randombit/botan/blob/master/src/tests/data/stream/chacha.vec
        vectors = [
            (bytes(32), bytes(8),
             "3E00EF2F895F40D67F5BB8E81F09A5A12C840EC3CE9A7F3B181BE188EF711A1E"
             "984CE172B9216F419F445367456D5619314A42A3DA86B001387BFDB80E0CFE42"
             "D2AEFA0DEAA5C151BF0ADB6C01F2A5ADC0FD581259F9A2AADCF20F8FD566A26B"
             "5032EC38BBC5DA98EE0C6F568B872A65A08ABF251DEB21BB4B56E5D8821E68AA"),
            (bytes.fromhex("00112233445566778899AABBCCDDEEFFFFEEDDCCBBAA99887766554433221100"),
             bytes.fromhex("0F1E2D3C4B5A6978"),
             "DB43AD9D1E842D1272E4530E276B3F568F8859B3F7CF6D9D2C74FA53808CB515"
             "7A8EBF46AD3DCC4B6C7DADDE131784B0120E0E22F6D5F9FFA7407D4A21B695D9"
             "C5DD30BF55612FAB9BDD118920C19816470C7F5DCD42325DBBED8C57A56281C144"
             "CB0F03E81B3004624E0650A1CE5AFAF9A7CD8163F6DBD72602257DD96E471E"),
        ]
        for key, nonce, expected in vectors:
            expected = bytes.fromhex(expected)
            actual, counter = chacha8_call(bytes(len(expected)), key, nonce)
            self.assertEqual(actual, expected)
            self.assertEqual(counter, 2)
            short, next_counter = chacha8_call(bytes(7), key, nonce)
            following, final_counter = chacha8_call(bytes(64), key, nonce, next_counter)
            self.assertEqual(short, expected[:7])
            self.assertEqual(following, expected[64:128])
            self.assertEqual(final_counter, 2)

    def test_counter_high_word_and_call_limit(self):
        key, nonce = bytes(range(32)), bytes(range(8))
        actual, counter = chacha8_call(bytes(128), key, nonce, (1 << 32) - 1)
        left, _ = chacha8_call(bytes(64), key, nonce, (1 << 32) - 1)
        right, _ = chacha8_call(bytes(64), key, nonce, 1 << 32)
        self.assertEqual(actual, left + right)
        self.assertEqual(counter, (1 << 32) + 1)
        with self.assertRaises(RecoveryError):
            chacha8_call(bytes(CALL_LIMIT + 1), key, nonce)
        with self.assertRaises(RecoveryError):
            chacha8_call(bytes(128), key, nonce, (1 << 64) - 1)

    def test_partial_ranges(self):
        # Literal expectations from the decompiled integer arithmetic and seeks.
        self.assertEqual(encrypted_segments(1003, 0x25, 20),
                         [(0, 70), (466, 70), (932, 70)])
        self.assertEqual(encrypted_segments(1003, 0x25, 50),
                         [(0, 100), (200, 100), (400, 100), (600, 100), (800, 100)])
        for percent, factor in ((10, 4), (15, 5), (20, 7), (25, 9), (30, 10),
                                (35, 12), (40, 14), (60, 20), (70, 23), (80, 27)):
            segments = encrypted_segments(10000, 0x25, percent)
            self.assertEqual([length for _, length in segments], [factor * 100] * 3)
            self.assertLessEqual(segments[-1][0] + segments[-1][1], 10000)

    def test_copy_recovery_and_rejections(self):
        master = bytes(range(48))  # Public synthetic fixture, never an incident key.
        file_key, nonce = bytes(reversed(range(32))), bytes.fromhex("01030507090b0d0f")
        with tempfile.TemporaryDirectory(prefix="decrypt-selfcheck-") as temporary:
            root = Path(temporary)
            copies = root / "copies"
            copies.mkdir()
            secret = root / "synthetic-master"
            secret.write_bytes(master)
            cases = [(0x24, 0, CALL_LIMIT + 77),
                     (0x26, 0, 2 * 1024 * 1024 + 51),
                     (0x25, 80, 20_000_123),
                     (0x25, 50, 6_000_123)]
            for index, (mode, percent, size) in enumerate(cases):
                with self.subTest(mode=hex(mode), percent=percent):
                    plain = (bytes(range(251)) * (size // 251 + 1))[:size]
                    body = bytearray(plain)
                    counter = 0
                    for offset, length in encrypted_segments(size, mode, percent):
                        cursor = offset
                        while length:
                            amount = min(length, CALL_LIMIT)
                            block, counter = chacha8_call(bytes(body[cursor:cursor + amount]),
                                                          file_key, nonce, counter)
                            body[cursor:cursor + amount] = block
                            cursor += amount
                            length -= amount
                    footer = bytearray(FOOTER_SIZE)
                    encryptor = Cipher(algorithms.AES(master[16:]), modes.CBC(master[:16])).encryptor()
                    footer[:48] = encryptor.update(file_key + nonce + nonce) + encryptor.finalize()
                    footer[568:572] = MARKER
                    footer[572:576] = bytes((mode, percent, 0x20, 0))
                    struct.pack_into("<I", footer, 576, 240002)
                    struct.pack_into("<Q", footer, 580, size)
                    source = copies / f"fixture-{index}.L0CK3D"
                    source.write_bytes(body + footer)
                    source_hash = hashlib.sha256(source.read_bytes()).digest()
                    expected = hashlib.sha256(plain).hexdigest()
                    output = root / f"recovered-{index}"
                    result = decrypt_copy(source, output, secret, copies, expected)
                    self.assertEqual(output.read_bytes(), plain)
                    self.assertEqual(result["sha256"], expected)
                    self.assertEqual(result["cipher_blocks_consumed"], counter)
                    self.assertEqual(output.stat().st_mode & 0o777, 0o600)
                    with self.assertRaises(FileExistsError):
                        decrypt_copy(source, output, secret, copies)
                    with self.assertRaises(FileExistsError):
                        decrypt_copy(source, source, secret, copies)
                    self.assertEqual(hashlib.sha256(source.read_bytes()).digest(), source_hash)

            source = copies / "fixture-0.L0CK3D"
            failed_output = root / "must-not-exist"
            secret.write_bytes(master[:16] + bytes(32))
            with self.assertRaisesRegex(RecoveryError, "nonce check failed"):
                decrypt_copy(source, failed_output, secret, copies)
            self.assertFalse(failed_output.exists())
            secret.write_bytes(master)
            with self.assertRaisesRegex(RecoveryError, "expected SHA-256"):
                decrypt_copy(source, failed_output, secret, copies, "00" * 32)
            self.assertFalse(failed_output.exists())
            wrong_iv = bytes((master[0] ^ 1,)) + master[1:]
            secret.write_bytes(wrong_iv)
            expected = hashlib.sha256((root / "recovered-0").read_bytes()).hexdigest()
            with self.assertRaisesRegex(RecoveryError, "expected SHA-256"):
                decrypt_copy(source, failed_output, secret, copies, expected)
            self.assertFalse(failed_output.exists())
            secret.write_bytes(master)

            failed_output.symlink_to(root / "recovered-0")
            with self.assertRaises(FileExistsError):
                decrypt_copy(source, failed_output, secret, copies)
            self.assertEqual(hashlib.sha256((root / "recovered-0").read_bytes()).hexdigest(), expected)
            failed_output.unlink()

            appended = copies / "appended.L0CK3D"
            appended.write_bytes(source.read_bytes() + b"new log record\n")
            with self.assertRaisesRegex(RecoveryError, "appended"):
                decrypt_copy(appended, failed_output, secret, copies)
            self.assertFalse(failed_output.exists())
            decoy = copies / "decoy.L0CK3D"
            content = bytearray(source.read_bytes())
            content[-14] = 0x21
            decoy.write_bytes(content)
            with self.assertRaisesRegex(RecoveryError, "mode 0x20"):
                decrypt_copy(decoy, failed_output, secret, copies)
            (root / "unrelated").mkdir()
            with self.assertRaises(RecoveryError):
                decrypt_copy(source, failed_output, secret, root / "unrelated")
            link = copies / "linked.L0CK3D"
            os.link(source, link)
            with self.assertRaisesRegex(RecoveryError, "hard links"):
                decrypt_copy(link, failed_output, secret, copies)
            link.unlink()
            link.symlink_to(source)
            with self.assertRaisesRegex(RecoveryError, "symbolic link"):
                decrypt_copy(link, failed_output, secret, copies)


if __name__ == "__main__":
    unittest.main(verbosity=2)
