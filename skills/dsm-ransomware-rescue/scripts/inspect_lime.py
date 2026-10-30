#!/usr/bin/env python3
"""Offline LiME v1 structure/range inspection, Python 3.8+ standard library.

Reads saved regular files only; never acquires RAM or converts address layouts.
An accepted structure/coverage map cannot prove captured bytes or keys are valid.
"""
import argparse
import hashlib
import json
import os
import re
import stat
import struct
import sys

# Format: https://github.com/504ensicsLabs/LiME/blob/master/src/lime.h
# Acquisition/report context: https://github.com/soimy/c3rb3r-rescue/issues/9
MAGIC = 0x4C694D45
HEADER_SIZE = 32


def read_segments(source, size):
    offset, previous_end, endian = 0, -1, None
    segments = []
    while offset < size:
        source.seek(offset)
        header = source.read(HEADER_SIZE)
        if len(header) != HEADER_SIZE:
            raise ValueError('Truncated LiME header at offset %d' % offset)
        if endian is None:
            if struct.unpack_from('<I', header)[0] == MAGIC:
                endian = '<'
            elif struct.unpack_from('>I', header)[0] == MAGIC:
                endian = '>'
            else:
                raise ValueError('Not uncompressed LiME; raw/ELF/compressed inputs need separate handling')
        magic, version, start, end, reserved = struct.unpack(endian + 'IIQQ8s', header)
        if magic != MAGIC or version != 1 or reserved != bytes(8):
            raise ValueError('Unsupported LiME header at offset %d' % offset)
        if end < start or start <= previous_end:
            raise ValueError('Reversed, overlapping or unordered physical ranges')
        length = end - start + 1  # LiME end addresses are inclusive.
        if length > size - offset - HEADER_SIZE:
            raise ValueError('Truncated LiME payload at offset %d' % offset)
        segments.append({'start': start, 'end_inclusive': end, 'bytes': length,
                         'file_offset': offset + HEADER_SIZE})
        previous_end, offset = end, offset + HEADER_SIZE + length
    if not segments:
        raise ValueError('Empty LiME input')
    return segments, 'little' if endian == '<' else 'big'


def system_ram_ranges(text):
    ranges = sorted((int(a, 16), int(b, 16) + 1) for a, b in re.findall(
        r'^\s*([0-9a-fA-F]+)-([0-9a-fA-F]+)\s*:\s*System RAM\s*$', text, re.M))
    if not ranges or all(a == 0 and b == 1 for a, b in ranges):
        raise ValueError('No usable System RAM ranges; iomem may be redacted')
    previous_end = -1
    for start, end in ranges:
        if end <= start or start < previous_end:
            raise ValueError('Invalid or overlapping System RAM ranges')
        previous_end = end
    return ranges


def uncovered(wanted, available):
    result = []
    for start, end in wanted:
        cursor = start
        for left, right in available:
            if right <= cursor:
                continue
            if left >= end:
                break
            if left > cursor:
                result.append({'start': cursor, 'end_inclusive': left - 1})
            cursor = min(end, max(cursor, right))
        if cursor < end:
            result.append({'start': cursor, 'end_inclusive': end - 1})
    return result


def regular_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, 'O_NOFOLLOW', 0))
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise ValueError('Only saved regular files are accepted')
    return os.fdopen(fd, 'rb')


def inspect_lime(path, iomem=None, full_hash=False):
    with regular_file(path) as source:
        before = os.fstat(source.fileno())
        segments, endian = read_segments(source, before.st_size)
        digest = None
        if full_hash:
            source.seek(0)
            h = hashlib.sha256()
            for block in iter(lambda: source.read(1024**2), b''):
                h.update(block)
            digest = h.hexdigest()
        after = os.fstat(source.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('LiME file changed during inspection')
    captured = [(s['start'], s['end_inclusive'] + 1) for s in segments]
    result = {'schema': 1, 'format': 'LiME-v1', 'byte_order': endian,
              'structurally_valid': True, 'file_bytes': before.st_size,
              'payload_bytes': sum(s['bytes'] for s in segments), 'sha256': digest,
              'segments': segments, 'coverage_matches_iomem': None,
              'address_gaps': [{'start': a[1], 'end_inclusive': b[0] - 1}
                               for a, b in zip(captured, captured[1:]) if a[1] < b[0]],
              'validation': 'Structure/ranges only; not atomicity, actual page readability or key presence'}
    if iomem is not None:
        with regular_file(iomem) as saved:
            text = saved.read(1024**2 + 1)
        if len(text) > 1024**2:
            raise ValueError('Saved iomem exceeds 1 MiB')
        expected = system_ram_ranges(text.decode('ascii'))
        missing, unexpected = uncovered(expected, captured), uncovered(captured, expected)
        result.update(missing_system_ram=missing, outside_system_ram=unexpected,
                      coverage_matches_iomem=not missing and not unexpected)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-copy', required=True)
    parser.add_argument('--iomem-copy', help='Same-machine /proc/iomem saved around capture, with usable addresses')
    parser.add_argument('--sha256', action='store_true', help='Read the entire saved file to compute its digest')
    args = parser.parse_args()
    try:
        result = inspect_lime(args.input_copy, args.iomem_copy, args.sha256)
    except OSError as exc:
        print('Inspection failed: %s (errno %s)' % (type(exc).__name__, exc.errno), file=sys.stderr)
        return 1
    except ValueError as exc:
        print('Inspection refused: %s' % exc, file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 2 if result['coverage_matches_iomem'] is False else 0


if __name__ == '__main__':
    raise SystemExit(main())
