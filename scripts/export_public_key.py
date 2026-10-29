#!/usr/bin/env python3
"""Export a published JSON recovery candidate as a new 48-byte master file.

The record hash detects corruption, not applicability to another victim.
No decryption is attempted, and no key bytes are printed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat


def export_key(record, output):
    fd = os.open(record, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 65536:
            raise ValueError('Expected a small regular JSON record')
        data = json.loads(source.read(65537))
    if data.get('schema_version') != 1 or data.get('format') != 'iv16-aes-key32':
        raise ValueError('Unsupported recovery key record')
    raw = bytes.fromhex(data['material_hex'])
    digest = hashlib.sha256(raw).hexdigest()
    if len(raw) != 48 or digest != data['material_sha256']:
        raise ValueError('Recovery material length/hash mismatch')
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as destination:
        destination.write(raw)
        destination.flush()
        os.fsync(destination.fileno())
    return {'bytes': len(raw), 'sha256': digest, 'output': str(output),
            'applicability': 'unverified for your files; require full-content validation'}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--record', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(export_key(args.record, args.output)))


if __name__ == '__main__':
    main()
