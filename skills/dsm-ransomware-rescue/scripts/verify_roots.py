#!/usr/bin/env python3
"""Preflight a reviewed NUL-delimited DSM root list before a read-only scan."""

import argparse
import json
import os
import re
import stat
import sys


VOLUMES = ('/volume1', '/volume2')
SPECIAL = ('/root', '/opt')
DOCKER_ANCESTORS = {'/volume1/@docker', '/volume1/@docker/btrfs'}


def unescape(value):
    return re.sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1), 8)), value)


def mount_table():
    mounts = {}
    with open('/proc/self/mountinfo', encoding='utf-8', errors='surrogateescape') as src:
        for line in src:
            fields = line.split()
            separator = fields.index('-')
            path = unescape(fields[4])
            mounts.setdefault(path, []).append((fields[2], unescape(fields[3]),
                                                  fields[separator + 1], unescape(fields[separator + 2])))
    return mounts


def below(path, parent):
    return path.startswith(parent.rstrip('/') + '/')


def verify(path, mounts, volumes=VOLUMES, special=SPECIAL, allowed=DOCKER_ANCESTORS):
    if not os.path.isabs(path) or os.path.normpath(path) != path:
        return 'invalid_or_unnormalized_path'
    base = next((v for v in volumes if below(path, v)), None)
    if base is None and path not in special:
        return 'outside_allowed_roots'
    if base is not None and (base not in mounts or len(mounts[base]) != 1):
        return 'volume_mount_missing_or_stacked'
    for mount, entries in mounts.items():
        if mount == path or below(mount, path):
            return 'candidate_contains_explicit_mount'
        if base and below(path, mount) and below(mount, base):
            if mount not in allowed or len(entries) != 1:
                return 'unapproved_mount_ancestor'
            vol_dev, vol_root, vol_type, vol_source = mounts[base][0]
            dev, mount_root, fs_type, source = entries[0]
            expected_root = os.path.normpath(os.path.join(vol_root, mount[len(base):].lstrip('/')))
            if (dev, fs_type, source, mount_root) != (vol_dev, vol_type, vol_source, expected_root):
                return 'docker_ancestor_not_same_source'
    current = '/'
    try:
        for part in path.split('/')[1:]:
            current = os.path.join(current, part)
            if not stat.S_ISDIR(os.lstat(current).st_mode):
                return 'symlink_or_not_directory'
    except OSError as exc:
        return 'lstat_error_' + str(exc.errno)
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root_list')
    parser.add_argument('--expected-count', type=int)
    parser.add_argument('--volume', action='append', default=None)
    parser.add_argument('--special-root', action='append', default=[])
    parser.add_argument('--allow-mount-ancestor', action='append', default=[])
    args = parser.parse_args()
    try:
        fd = os.open(args.root_list, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(fd, 'rb') as src:
            if not stat.S_ISREG(os.fstat(src.fileno()).st_mode):
                raise ValueError('list is not a regular file')
            raw = src.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024 or not raw.endswith(b'\0'):
            raise ValueError('list too large or missing final NUL')
        paths = [os.fsdecode(value) for value in raw[:-1].split(b'\0')]
        if not paths or len(set(paths)) != len(paths) or not all(paths):
            raise ValueError('expected unique nonempty paths')
        if args.expected_count is not None and len(paths) != args.expected_count:
            raise ValueError('path count differs from reviewed list')
        mounts = mount_table()
        errors = []
        valid_paths = []
        for path in paths:
            reason = verify(path, mounts, tuple(args.volume or VOLUMES),
                            tuple(args.special_root), set(args.allow_mount_ancestor))
            if reason:
                errors.append({'path': path, 'reason': reason})
            else:
                valid_paths.append(path)
        for index, first in enumerate(valid_paths):
            for second in valid_paths[index + 1:]:
                if (below(first, second) or below(second, first)) and os.lstat(first).st_dev == os.lstat(second).st_dev:
                    errors.append({'path': first, 'other_path': second,
                                   'reason': 'overlap_same_device'})
        print(json.dumps({'valid': not errors, 'paths': len(paths), 'errors': errors},
                         ensure_ascii=True), flush=True)
        return 1 if errors else 0
    except (OSError, ValueError, IndexError) as exc:
        print(json.dumps({'valid': False, 'error': str(exc)}, ensure_ascii=True), flush=True)
        return 2


if __name__ == '__main__':
    sys.exit(main())
