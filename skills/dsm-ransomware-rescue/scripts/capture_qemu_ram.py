#!/usr/bin/env python3
"""Read one explicitly selected QEMU host RAM mapping into a NEW private file.

Linux root required. Inspect /proc/PID/maps and QEMU memory layout first. This
does not stop a VM; live reads are temporally inconsistent, not an atomic dump.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import time


def copy_range(source_fd, destination, start, length):
    if start < 0 or length <= 0:
        raise ValueError('Invalid capture range')
    h = hashlib.sha256()
    copied = 0
    with Path(destination).open('xb') as out:
        while copied < length:
            data = os.pread(source_fd, min(8 * 1024**2, length - copied), start + copied)
            if not data:
                raise OSError('Short read; incomplete copy retained, no completion receipt')
            out.write(data)
            h.update(data)
            copied += len(data)
        out.flush()
        os.fsync(out.fileno())
    return h.hexdigest()


def process_identity(proc):
    stat = (proc / 'stat').read_text()
    start_ticks = int(stat.rsplit(')', 1)[1].split()[19])
    return start_ticks, (proc / 'cmdline').read_bytes()


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--pid', type=int, required=True)
    p.add_argument('--start', type=lambda x: int(x, 0), required=True)
    p.add_argument('--length', type=lambda x: int(x, 0), required=True)
    p.add_argument('--expected-start-ticks', type=int, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    proc = Path('/proc') / str(a.pid)
    before = process_identity(proc)
    exe = Path(os.readlink(proc / 'exe')).name
    if before[0] != a.expected_start_ticks or exe not in ('kvm', 'qemu-system-x86_64'):
        raise ValueError('QEMU identity mismatch')
    maps = (proc / 'maps').read_text()
    selected = [line for line in maps.splitlines()
                if line.split()[0] == '%x-%x' % (a.start, a.start + a.length)]
    if len(selected) != 1 or not selected[0].split()[1].startswith('rw'):
        raise ValueError('Exact readable/writable mapping not found; do not guess pc.ram')
    if a.length <= 0 or shutil.disk_usage(a.output.parent).free < a.length + 1024**3:
        raise ValueError('Invalid size or insufficient destination space')
    if a.output.exists() or a.output.with_suffix(a.output.suffix + '.json').exists():
        raise FileExistsError('Output or receipt exists')
    started = time.time()
    fd = os.open(proc / 'mem', os.O_RDONLY)
    try:
        sha = copy_range(fd, a.output, a.start, a.length)
    finally:
        os.close(fd)
    if process_identity(proc) != before or selected[0] not in (proc / 'maps').read_text().splitlines():
        raise ValueError('QEMU identity/mapping changed; capture retained but not certified')
    check = hashlib.sha256()
    with a.output.open('rb') as inp:
        for block in iter(lambda: inp.read(8 * 1024**2), b''):
            check.update(block)
    if check.hexdigest() != sha:
        raise ValueError('Destination readback failed')
    result = {'pid': a.pid, 'start_ticks': before[0], 'host_mapping': selected[0],
              'bytes': a.length, 'sha256': sha, 'started_unix': started,
              'ended_unix': time.time(), 'readback_verified': True,
              'consistency': 'live, non-atomic; VM was not paused by this tool'}
    with a.output.with_suffix(a.output.suffix + '.json').open('x') as out:
        json.dump(result, out, indent=2)
    a.output.chmod(0o400)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
