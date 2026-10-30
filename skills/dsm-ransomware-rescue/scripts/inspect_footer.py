#!/usr/bin/env python3
"""Inspect one saved ciphertext copy without keys or decryption (Python 3.8+).

Print only layout metadata, never wrapped key records, content or file paths.
No filesystem traversal, block-device access, output files or network requests.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

from file_layout import RecoveryError, read_footer


def inspect_copy(path):
    path = Path(path)
    if path.is_symlink():
        raise RecoveryError('Input cannot be a symbolic link')
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(fd, 'rb') as source:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise RecoveryError('Input must be a regular saved ciphertext copy')
        footer, size, mode, percent, segments = read_footer(source, before.st_size, None)
        after = os.fstat(fd)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise RecoveryError('Input changed during inspection')
    return {'schema': 1, 'layout': 'reviewed-588-byte-EOF', 'marker': footer[568:572].hex(),
            'footer_sha256': hashlib.sha256(footer).hexdigest(),
            'original_size': size, 'mode': hex(mode), 'percent_parameter': percent,
            'crypto_mode': '0x20',
            'encrypted_ranges': [{'offset': offset, 'length': length} for offset, length in segments],
            'expected_encrypted_bytes': sum(length for _, length in segments),
            'validation': 'layout only; not key applicability, encryption completion or recoverability'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-copy', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = inspect_copy(args.input_copy)
    except OSError as exc:
        print('Inspection failed: %s (errno %s)' % (type(exc).__name__, exc.errno), file=sys.stderr)
        return 1
    except RecoveryError as exc:
        print('Inspection refused: %s' % exc, file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
