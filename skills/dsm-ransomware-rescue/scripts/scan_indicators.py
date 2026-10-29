#!/usr/bin/env python3
"""Find fixed incident indicators in saved files. Never decode/execute commands.

Context may contain credentials: write the JSON report into private storage.
Matches in RAM can be constants or stale data; they do not prove exploitation.
"""
import argparse
import hashlib
import json
import mmap
import os
from pathlib import Path
import stat

MARKERS = (b'PLUGIN_VALUE_END', b'PLUGIN_VALUE_START', b'LD_PRELOAD',
           b'LD_DEBUG_OUTPUT', b'synotgkk', b'synotade', b'l0ck.enc',
           b'libgld', b'qnetd', b'xdy5')


def scan(path, limit=200):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as f:
        before = os.fstat(f.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('Only saved regular files are accepted')
        hits = []
        if before.st_size:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
                for marker in MARKERS:
                    offset = 0
                    count = 0
                    while count < limit:
                        at = data.find(marker, offset)
                        if at < 0:
                            break
                        hits.append({'marker': marker.decode(), 'offset': at,
                                     'context': data[max(0, at-128):at+len(marker)+256].decode('utf-8', 'backslashreplace')})
                        count += 1
                        offset = at + 1
                    if count == limit and data.find(marker, offset) >= 0:
                        hits.append({'marker': marker.decode(), 'truncated': True})
        after = os.fstat(f.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('Input changed during scan')
    return {'file': str(path), 'bytes': before.st_size, 'hits': hits}


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input', type=Path, action='append', required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--max-per-marker', type=int, default=200)
    a = p.parse_args()
    if a.max_per_marker < 1:
        raise ValueError('Positive limit required')
    # Reserve the destination before scanning; never overwrite earlier evidence.
    with a.output.open('x') as out:
        result = [scan(p, a.max_per_marker) for p in a.input]
        json.dump(result, out, ensure_ascii=True, indent=2)
    print(json.dumps({'files': len(result), 'report': str(a.output),
                      'hit_records': sum(len(x['hits']) for x in result)}))


if __name__ == '__main__':
    main()
