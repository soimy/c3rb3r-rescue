#!/usr/bin/env python3
"""Save bounded raw RAM regions with source hash and exact file offsets.

Offsets are file offsets, not guest physical or virtual addresses. No decoding,
target execution, or network access. Output is sensitive and must stay private.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat


def carve(source, offsets, length, destination):
    if not offsets or not 0 < length <= 1024**2:
        raise ValueError('Select offsets and a length between 1 byte and 1 MiB')
    if len(set(offsets)) != len(offsets):
        raise ValueError('Duplicate offsets')
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as f:
        before = os.fstat(f.fileno())
        if not stat.S_ISREG(before.st_mode) or any(o < 0 or o + length > before.st_size for o in offsets):
            raise ValueError('Not a saved file or region outside its bounds')
        h = hashlib.sha256()
        for block in iter(lambda: f.read(8 * 1024**2), b''):
            h.update(block)
        destination = Path(destination)
        destination.mkdir(mode=0o700)
        regions = []
        for offset in offsets:
            f.seek(offset); data = f.read(length)
            if len(data) != length:
                raise OSError('Short read; no completed manifest')
            path = destination / ('offset-%x.bin' % offset)
            with path.open('xb') as out:
                out.write(data)
                out.flush(); os.fsync(out.fileno())
            path.chmod(0o400)
            regions.append({'file': path.name, 'file_offset': offset, 'bytes': length,
                            'sha256': hashlib.sha256(data).hexdigest()})
        after = os.fstat(f.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('Source changed; fragments retained without completion manifest')
    result = {'source_bytes': before.st_size, 'source_sha256': h.hexdigest(), 'regions': regions}
    with (destination/'carve.json').open('x') as out:
        json.dump(result, out, indent=2)
    return result


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input', type=Path, required=True)
    p.add_argument('--offset', action='append', type=lambda x:int(x,0), required=True)
    p.add_argument('--length', type=lambda x:int(x,0), default=16384)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    print(json.dumps(carve(a.input,a.offset,a.length,a.output)))


if __name__ == '__main__':
    main()
