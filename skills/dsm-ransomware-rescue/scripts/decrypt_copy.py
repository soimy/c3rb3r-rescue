#!/usr/bin/env python3
"""Offline, copy-only recovery prototype for this incident; never runs the sample.

Requires numpy and cryptography. Input must be an independent regular file inside
an explicitly designated copy directory. Output is exclusively created mode 0600.
Only complete EOF footers are supported; appended logs and interrupted encryption
need separate analysis. A valid key record does not authenticate file contents.
"""

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
import struct
import sys

import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

FOOTER_SIZE = 588
CALL_LIMIT = 5 * 1024 * 1024
FIRST_LIMIT = 1024 * 1024
# The four-byte identifier observed in this incident, not a universal signature.
MARKER = bytes.fromhex("ce35a593")
PARTIAL_FACTORS = {10: 4, 15: 5, 20: 7, 25: 9, 30: 10, 35: 12,
                   40: 14, 50: 10, 60: 20, 70: 23, 80: 27}


class RecoveryError(ValueError):
    pass


def chacha8_call(data, key, nonce, counter=0):
    """One observed process_bytes call, including discarded short-block tail."""
    if len(key) != 32 or len(nonce) != 8:
        raise RecoveryError("ChaCha8 requires a 32-byte key and 8-byte nonce")
    if len(data) > CALL_LIMIT:
        raise RecoveryError("One cipher call must not exceed 5 MiB")
    count = (len(data) + 63) // 64
    if counter < 0 or counter + count > (1 << 64):
        raise RecoveryError("ChaCha counter is outside the supported range")
    if not count:
        return b"", counter
    initial = np.empty((16, count), dtype=np.uint32)
    fixed = struct.unpack("<12I", b"expand 32-byte k" + key)
    initial[:12] = np.array(fixed, dtype=np.uint32)[:, None]
    counters = np.arange(count, dtype=np.uint64) + np.uint64(counter)
    initial[12] = counters.astype(np.uint32)
    initial[13] = (counters >> np.uint64(32)).astype(np.uint32)
    initial[14:] = np.array(struct.unpack("<2I", nonce), dtype=np.uint32)[:, None]
    x = initial.copy()

    def quarter(a, b, c, d):
        x[a] += x[b]
        x[d] ^= x[a]
        x[d] = (x[d] << np.uint32(16)) | (x[d] >> np.uint32(16))
        x[c] += x[d]
        x[b] ^= x[c]
        x[b] = (x[b] << np.uint32(12)) | (x[b] >> np.uint32(20))
        x[a] += x[b]
        x[d] ^= x[a]
        x[d] = (x[d] << np.uint32(8)) | (x[d] >> np.uint32(24))
        x[c] += x[d]
        x[b] ^= x[c]
        x[b] = (x[b] << np.uint32(7)) | (x[b] >> np.uint32(25))

    for _ in range(4):
        quarter(0, 4, 8, 12)
        quarter(1, 5, 9, 13)
        quarter(2, 6, 10, 14)
        quarter(3, 7, 11, 15)
        quarter(0, 5, 10, 15)
        quarter(1, 6, 11, 12)
        quarter(2, 7, 8, 13)
        quarter(3, 4, 9, 14)
    x += initial
    stream = x.T.astype("<u4", copy=False).tobytes()
    plain = np.bitwise_xor(np.frombuffer(data, dtype=np.uint8),
                           np.frombuffer(stream, dtype=np.uint8, count=len(data)))
    return plain.tobytes(), counter + count


def encrypted_segments(size, mode, percent):
    if mode == 0x24:
        if percent:
            raise RecoveryError("Unexpected parameter for full mode")
        return [(0, size)]
    if mode == 0x26:
        if percent:
            raise RecoveryError("Unexpected parameter for first-1-MiB mode")
        return [(0, min(size, FIRST_LIMIT))]
    if mode != 0x25 or percent not in PARTIAL_FACTORS:
        raise RecoveryError("Unsupported encryption mode or partial parameter")
    length = (size // 100) * PARTIAL_FACTORS[percent]
    count = 5 if percent == 50 else 3
    gap = length if percent == 50 else (size - 3 * length) // 2
    return [(index * (length + gap), length) for index in range(count)]


def read_footer(source, size):
    if size < FOOTER_SIZE:
        raise RecoveryError("Input is too short for a complete footer")
    source.seek(-FOOTER_SIZE, os.SEEK_END)
    footer = source.read(FOOTER_SIZE)
    if footer[568:572] != MARKER:
        raise RecoveryError("Expected incident footer is not at EOF; appended data is unsupported")
    mode, percent, crypto_mode, reserved = footer[572:576]
    original_size = struct.unpack_from("<Q", footer, 580)[0]
    if original_size != size - FOOTER_SIZE:
        raise RecoveryError("Stored size does not match EOF footer; appended/truncated data is unsupported")
    if crypto_mode != 0x20 or reserved != 0:
        raise RecoveryError("Only crypto mode 0x20 is supported; refuse decoy/unknown records")
    segments = encrypted_segments(original_size, mode, percent)
    if any(offset < 0 or length < 0 or offset + length > original_size
           for offset, length in segments):
        raise RecoveryError("Invalid encrypted byte ranges")
    return footer, original_size, mode, percent, segments


def unwrap_record(footer, master):
    if len(master) != 48:
        raise RecoveryError("Master material must be exactly 48 bytes (IV16 + key32)")
    decryptor = Cipher(algorithms.AES(master[16:]), modes.CBC(master[:16])).decryptor()
    record = decryptor.update(footer[:48]) + decryptor.finalize()
    if not hmac.compare_digest(record[32:40], record[40:48]):
        raise RecoveryError("Key-record nonce check failed; no output was created")
    return record[:32], record[32:40]


def readonly_regular(path, *, independent=False):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or (independent and info.st_nlink != 1):
        os.close(fd)
        raise RecoveryError("Input must be a regular file; recovery copies cannot be hard links")
    return os.fdopen(fd, "rb"), info


def decrypt_copy(input_copy, output, master_file, copy_root, expected_sha256=None):
    root = Path(copy_root).resolve(strict=True)
    if not root.is_dir():
        raise RecoveryError("Copy root must be a directory")
    candidate = Path(input_copy)
    if candidate.is_symlink():
        raise RecoveryError("Input copy cannot be a symbolic link")
    candidate = candidate.resolve(strict=True)
    if not candidate.is_relative_to(root):
        raise RecoveryError("Input must be inside the explicitly designated copy root")
    if expected_sha256 is not None:
        if len(expected_sha256) != 64:
            raise RecoveryError("Expected SHA-256 must contain 64 hexadecimal characters")
        try:
            if len(bytes.fromhex(expected_sha256)) != 32:
                raise ValueError("Not a complete digest")
        except ValueError as error:
            raise RecoveryError("Invalid expected SHA-256") from error
        expected_sha256 = expected_sha256.lower()
    with readonly_regular(master_file)[0] as secret:
        master = secret.read(49)
    source, before = readonly_regular(candidate, independent=True)
    output = Path(output)
    created = None
    try:
        with source:
            footer, original_size, mode, percent, segments = read_footer(source, before.st_size)
            key, nonce = unwrap_record(footer, master)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(output, flags, 0o600)
            created = os.fstat(fd)
            digest = hashlib.sha256()
            counter = 0
            position = 0
            source.seek(0)
            with os.fdopen(fd, "wb") as destination:
                def transfer(length, encrypted):
                    nonlocal counter, position
                    while length:
                        amount = min(length, CALL_LIMIT)
                        block = source.read(amount)
                        if len(block) != amount:
                            raise RecoveryError("Input changed or became truncated during recovery")
                        if encrypted:
                            block, counter = chacha8_call(block, key, nonce, counter)
                        destination.write(block)
                        digest.update(block)
                        length -= amount
                        position += amount

                for offset, length in segments:
                    transfer(offset - position, False)
                    transfer(length, True)
                transfer(original_size - position, False)
                after = os.fstat(source.fileno())
                if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                        after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                    raise RecoveryError("Input metadata changed during recovery")
                recovered_hash = digest.hexdigest()
                if expected_sha256 and not hmac.compare_digest(recovered_hash, expected_sha256):
                    raise RecoveryError("Recovered file does not match the expected SHA-256")
                destination.flush()
                os.fsync(destination.fileno())
        return {"output": str(output.resolve()), "bytes": original_size,
                "sha256": recovered_hash, "mode": hex(mode), "percent_parameter": percent,
                "cipher_blocks_consumed": counter,
                "verification": "known-original-sha256" if expected_sha256 else
                "key-record-only; independently validate full file contents"}
    except BaseException:
        if created is not None:
            try:
                current = output.lstat()
                if (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino):
                    output.unlink()
            except FileNotFoundError:
                pass
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--copy-root", required=True, help="Directory containing rescue copies only")
    parser.add_argument("--input-copy", required=True)
    parser.add_argument("--master-file", required=True, help="Private 48-byte IV16 + AES-key32 file")
    parser.add_argument("--output", required=True, help="New output path; must not already exist")
    parser.add_argument("--expected-sha256", help="Optional known-original hash; mismatch removes new output")
    args = parser.parse_args()
    try:
        result = decrypt_copy(args.input_copy, args.output, args.master_file,
                              args.copy_root, args.expected_sha256)
    except (OSError, RecoveryError) as error:
        print(f"Recovery refused/failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
