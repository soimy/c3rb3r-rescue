"""Shared, standard-library-only parser for the reviewed 588-byte EOF layout.

A marker is a session hint, not a signature or proof of a usable key.
Only the inspector may omit expected_marker; decryption must bind it explicitly.
"""
import os
import re
import struct

FOOTER_SIZE = 588
FIRST_LIMIT = 1024 * 1024
# The four-byte identifier observed in this incident, not a universal signature.
MARKER = bytes.fromhex("ce35a593")
PARTIAL_FACTORS = {10: 4, 15: 5, 20: 7, 25: 9, 30: 10, 35: 12,
                   40: 14, 50: 10, 60: 20, 70: 23, 80: 27}


class RecoveryError(ValueError):
    pass


def parse_marker(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-fA-F]{8}', value):
        raise RecoveryError('Expected marker must be exactly eight hexadecimal characters')
    return bytes.fromhex(value)


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


def read_footer(source, size, expected_marker=MARKER):
    if expected_marker is not None and (not isinstance(expected_marker, bytes) or len(expected_marker) != 4):
        raise RecoveryError("Expected marker must be exactly four bytes")
    if size < FOOTER_SIZE:
        raise RecoveryError("Input is too short for a complete footer")
    source.seek(-FOOTER_SIZE, os.SEEK_END)
    footer = source.read(FOOTER_SIZE)
    if len(footer) != FOOTER_SIZE:
        raise RecoveryError("Incomplete EOF footer")
    if expected_marker is not None and footer[568:572] != expected_marker:
        raise RecoveryError("EOF marker differs from expected session; wrong session or appended data")
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
