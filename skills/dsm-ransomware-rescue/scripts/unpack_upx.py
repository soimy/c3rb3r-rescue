#!/usr/bin/env python3
"""Unpack a COPY with a caller-supplied trusted UPX binary; never execute payloads."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def unpack(source, output, upx, expected_sha256):
    source, output, upx = Path(source), Path(output), Path(upx)
    if source.is_symlink() or not source.is_file():
        raise ValueError('Input must be an independent regular sample copy')
    if source.stat().st_nlink != 1 or source.stat().st_size > 32 * 1024**2:
        raise ValueError('Refuse hard links or unexpected sample size')
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError('Input hash differs from reviewed sample')
    if not raw.startswith(b'\x7fELF') or b'UPX!' not in raw:
        raise ValueError('Expected an ELF UPX sample')
    if not upx.is_absolute() or not upx.is_file():
        raise ValueError('Supply an absolute path to a trusted UPX installation')
    # Exclusive reservation prevents clobbering a symlink or earlier derivative.
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    created = os.fstat(fd)
    try:
        with tempfile.TemporaryDirectory(prefix='upx-static-') as tmp:
            copied = Path(tmp) / 'input.sample'
            copied.write_bytes(raw)
            copied.chmod(0o600)
            derivative = Path(tmp) / 'output.sample'
            result = subprocess.run([str(upx), '-d', '-o', str(derivative), str(copied)],
                                    capture_output=True, timeout=120, check=True)
            data = derivative.read_bytes()
            if not data.startswith(b'\x7fELF') or len(data) > 64 * 1024**2:
                raise ValueError('Unexpected unpacked output')
            with os.fdopen(fd, 'wb') as out:
                fd = None
                out.write(data)
                out.flush()
                os.fsync(out.fileno())
        return {'source_sha256': expected_sha256, 'output_sha256': hashlib.sha256(data).hexdigest(),
                'output_bytes': len(data), 'execution': 'trusted unpacker only; payload never executed'}
    except BaseException:
        if fd is not None:
            os.close(fd)
        try:
            current = output.lstat()
            if (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino):
                output.unlink()
        except FileNotFoundError:
            pass
        raise


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input-copy', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--upx', type=Path, required=True)
    p.add_argument('--expected-sha256', required=True)
    a = p.parse_args()
    print(json.dumps(unpack(a.input_copy, a.output, a.upx, a.expected_sha256)))


if __name__ == '__main__':
    main()
