#!/usr/bin/env python3
"""Preserve an explicitly identified, already stopped Linux process (Python 3.8+).

Reads /proc/PID/mem without ptrace attach, signals, sysctl changes or modules.
This is a virtual-address mapping collection, NOT a core file or physical dump.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import time

# Compatibility report: https://github.com/soimy/c3rb3r-rescue/issues/14
# Linux pread uses signed 64-bit off_t. x86 [vsyscall] can lie above it.
PREAD_OFFSET_LIMIT = 1 << 63


def parse_stat(text):
    fields = text.rsplit(')', 1)[1].split()
    return {'state': fields[0], 'start_ticks': int(fields[19])}


def identity(proc):
    result = parse_stat((proc/'stat').read_text())
    threads = {}
    for task in sorted((proc/'task').iterdir()):
        if not task.name.isdigit():
            continue
        item = parse_stat((task/'stat').read_text())
        status = (task/'status').read_text()
        tracer = re.search(r'^TracerPid:\s*(\d+)\s*$', status, re.M)
        if tracer is None:
            raise ValueError('Missing thread tracer identity')
        item['tracer_pid'] = int(tracer.group(1))
        threads[task.name] = item
    if not threads:
        raise ValueError('No threads found')
    result['threads'] = threads
    return result


def require_stopped(state, expected_ticks):
    if state['start_ticks'] != expected_ticks:
        raise ValueError('Process start time differs; possible PID reuse')
    if state['state'] != 'T' or any(t['state'] != 'T' or t['tracer_pid'] for t in state['threads'].values()):
        raise ValueError('Every thread must already be T with no attached tracer; no signals sent')


def parse_maps(text):
    regions, previous_end = [], 0
    for line in text.splitlines():
        fields = line.split(None, 5)
        start, end = (int(x, 16) for x in fields[0].split('-'))
        if len(fields) < 5 or start < previous_end or end <= start:
            raise ValueError('Invalid or overlapping process maps')
        previous_end = end
        regions.append({'start': start, 'end': end, 'permissions': fields[1],
                        'path': fields[5] if len(fields) == 6 else ''})
    return regions


def select_mappings(regions):
    readable = [r for r in regions if r['permissions'].startswith('r')]
    selected = [r for r in readable if r['end'] <= PREAD_OFFSET_LIMIT]
    excluded = [dict(r, reason='offset_exceeds_signed_off_t') for r in readable
                if r['end'] > PREAD_OFFSET_LIMIT]
    return sorted(selected, key=priority), excluded


def hash_file(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1024**2), b''):
            h.update(block)
    return h.hexdigest()


def private_file(path):
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb')


def save(path, data):
    with private_file(path) as f:
        f.write(data); f.flush(); os.fsync(f.fileno())
    path.chmod(0o400)


def capture_region(fd, region, output, page_size):
    """Keep unreadable pages as explicit holes; never certify zero fill as data."""
    start, end = region['start'], region['end']
    h, holes = hashlib.sha256(), []
    with private_file(output) as out:
        for va in range(start, end, page_size):
            length = min(page_size, end - va)
            error = None
            try:
                data = os.pread(fd, length, va)
                if len(data) != length:
                    error = 'short_read'
            except OSError as exc:
                data, error = b'', 'errno_%s' % exc.errno
            # Retain a short prefix; mark only the missing part as unavailable.
            out.write(data); h.update(data)
            if error:
                missing = length - len(data)
                hole_start = va + len(data)
                if holes and holes[-1]['end'] == hole_start and holes[-1]['reason'] == error:
                    holes[-1]['end'] = va + length
                else:
                    holes.append({'start': hole_start, 'end': va + length, 'reason': error})
                out.seek(missing, os.SEEK_CUR)
                h.update(bytes(missing))
        out.truncate(end-start); out.flush(); os.fsync(out.fileno())
    if hash_file(output) != h.hexdigest():
        raise ValueError('Destination readback mismatch')
    output.chmod(0o400)
    return dict(region, file=output.name, bytes=end-start, sha256=h.hexdigest(),
                holes=holes, complete=not holes)


def priority(region):
    p = region['permissions']
    anonymous = not region['path'] or region['path'].startswith(('[heap]', '[stack', '[anon:'))
    return (0 if 'w' in p and p.endswith('p') and anonymous else 1 if 'w' in p else 2,
            region['start'])


def capture(proc, output, expected_ticks, expected_exe_sha256, expected_output_device):
    proc, output = Path(proc), Path(output)
    if not re.fullmatch('[0-9a-fA-F]{64}', expected_exe_sha256):
        raise ValueError('Expected executable SHA-256 is required')
    before = identity(proc); require_stopped(before, expected_ticks)
    maps = (proc/'maps').read_bytes()
    regions = parse_maps(maps.decode())
    selected, excluded = select_mappings(regions)
    if not selected:
        raise ValueError('No readable mappings addressable by pread')
    exe_sha = hash_file(proc/'exe')
    if exe_sha != expected_exe_sha256.lower():
        raise ValueError('Executable hash differs from reviewed process')
    parent = output.parent.resolve(strict=True)
    if parent.stat().st_dev != expected_output_device:
        raise ValueError('Destination device changed; check the evidence mount')
    required = sum(r['end']-r['start'] for r in selected) + (proc/'exe').stat().st_size + 64*1024**2
    if shutil.disk_usage(parent).free < required:
        raise ValueError('Insufficient destination space for selected virtual mappings')
    # Open the proc handle before creating outputs; denied access changes nothing.
    fd = os.open(proc/'mem', os.O_RDONLY)
    try:
        output.mkdir(mode=0o700)
    except BaseException:
        os.close(fd)
        raise
    started, captured = time.time(), []
    try:
        for name in ('stat', 'status', 'maps', 'cmdline', 'limits', 'coredump_filter'):
            try:
                data = (proc/name).read_bytes()
            except FileNotFoundError:
                continue
            save(output/(name + '.snapshot'), data)
        with (proc/'exe').open('rb') as source, private_file(output/'executable.bin') as dest:
            shutil.copyfileobj(source, dest, 1024**2)
            dest.flush(); os.fsync(dest.fileno())
        if hash_file(output/'executable.bin') != exe_sha:
            raise ValueError('Executable changed while copying')
        (output/'executable.bin').chmod(0o400)
        save(output/'identity.json', json.dumps(before, indent=2).encode())
        with private_file(output/'regions.jsonl') as journal:
            for region in selected:
                now = identity(proc); require_stopped(now, expected_ticks)
                if now != before or (proc/'maps').read_bytes() != maps:
                    raise ValueError('Process threads or maps changed; keep partial evidence')
                if output.stat().st_dev != expected_output_device:
                    raise ValueError('Destination device changed during collection')
                name = 'map-%x-%x.bin' % (region['start'], region['end'])
                item = capture_region(fd, region, output/name, os.sysconf('SC_PAGE_SIZE'))
                captured.append(item)
                journal.write((json.dumps(item) + '\n').encode())
                journal.flush(); os.fsync(journal.fileno())
        after = identity(proc); require_stopped(after, expected_ticks)
        if after != before or (proc/'maps').read_bytes() != maps or hash_file(proc/'exe') != exe_sha:
            raise ValueError('Process identity, mappings or executable changed')
        result = {'schema': 1, 'format': 'linux-process-mappings', 'pid': int(proc.name),
                  'start_ticks': expected_ticks, 'exe_sha256': exe_sha,
                  'started_unix': started, 'ended_unix': time.time(),
                  'complete': not excluded and all(r['complete'] for r in captured),
                  'selected_mappings_complete': all(r['complete'] for r in captured),
                  'regions': captured, 'excluded_unaddressable': excluded,
                  'pread_offset_limit_exclusive': PREAD_OFFSET_LIMIT,
                  'excluded_nonreadable': [r for r in regions if not r['permissions'].startswith('r')],
                  'scope': 'Readable user mappings below signed off_t limit; no registers, kernel RAM or unmapped pages',
                  'consistency': 'Stopped threads checked at boundaries; shared pages can change; reads may fault in swapped pages'}
        save(output/'capture.json', json.dumps(result, indent=2).encode())
        (output/'regions.jsonl').chmod(0o400)
        return result
    except BaseException as exc:
        # Preserve completed maps and progress on interruption; never fake success.
        save(output/'failure.json', json.dumps({'complete': False, 'error_type': type(exc).__name__,
             'message': str(exc), 'finished_regions': len(captured)}, indent=2).encode())
        raise
    finally:
        os.close(fd)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    inspect = sub.add_parser('inspect'); inspect.add_argument('--pid', type=int, required=True)
    collect = sub.add_parser('capture'); collect.add_argument('--pid', type=int, required=True)
    collect.add_argument('--expected-start-ticks', type=int, required=True)
    collect.add_argument('--expected-exe-sha256', required=True)
    collect.add_argument('--expected-output-device', type=int, required=True)
    collect.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.pid <= 0:
        parser.error('PID must be positive')
    proc = Path('/proc')/str(args.pid)
    if args.action == 'inspect':
        info = identity(proc)
        selected, excluded = select_mappings(parse_maps((proc/'maps').read_text()))
        info.update(pid=args.pid, exe_sha256=hash_file(proc/'exe'),
                    readable_bytes=sum(r['end']-r['start'] for r in selected),
                    readable_bytes_scope='Selected pread-addressable mappings',
                    excluded_unaddressable=excluded)
        print(json.dumps(info, indent=2)); return 0
    result = capture(proc, args.output, args.expected_start_ticks, args.expected_exe_sha256,
                     args.expected_output_device)
    print(json.dumps({'complete': result['complete'], 'regions': len(result['regions']),
                      'selected_mappings_complete': result['selected_mappings_complete'],
                      'excluded_unaddressable': len(result['excluded_unaddressable']),
                      'receipt': str(args.output/'capture.json')}))
    return 0 if result['complete'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
