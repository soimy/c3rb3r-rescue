#!/usr/bin/env python3
"""Count filesystem metadata; never follow symlinks or read file contents."""

import json
import os
import re
import signal
import stat
import sys
import time


def emit(record):
    print(json.dumps(record, ensure_ascii=True, sort_keys=True), flush=True)


def mount_points():
    try:
        with open('/proc/self/mountinfo', encoding='utf-8', errors='surrogateescape') as source:
            paths = [line.split()[4] for line in source]
    except OSError:
        return None
    return {re.sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1), 8)), path)
            for path in paths}


def counts():
    return {'directories': 0, 'files': 0, 'locked_files': 0, 'locked_bytes': 0,
            'other_files': 0, 'other_bytes': 0, 'ransom_notes': 0,
            'hardlinked_file_entries': 0, 'symlinks': 0, 'special': 0,
            'different_device_skipped': 0, 'same_device_mounts': 0,
            'skipped_device_examples': [], 'skipped_device_examples_omitted': 0,
            'errors': 0, 'errors_by_errno': {}, 'error_examples': [],
            'error_examples_omitted': 0}


def sample(stats, field, value):
    if len(stats[field]) < 20:
        stats[field].append(value)
    else:
        stats[field + '_omitted'] += 1


def error(stats, exc, path):
    stats['errors'] += 1
    code = str(exc.errno) if exc.errno is not None else 'unknown'
    stats['errors_by_errno'][code] = stats['errors_by_errno'].get(code, 0) + 1
    sample(stats, 'error_examples', {'path': path, 'errno': code})


def skip_device(stats, path):
    stats['different_device_skipped'] += 1
    sample(stats, 'skipped_device_examples', path)


def count_entry(stats, name, info):
    if stat.S_ISLNK(info.st_mode):
        stats['symlinks'] += 1
    elif stat.S_ISREG(info.st_mode):
        stats['files'] += 1
        if info.st_nlink > 1:
            stats['hardlinked_file_entries'] += 1
        if name.lower().endswith('.l0ck3d'):
            stats['locked_files'] += 1
            stats['locked_bytes'] += info.st_size
        else:
            stats['other_files'] += 1
            stats['other_bytes'] += info.st_size
        if name.lower() == 'read-me3.txt':
            stats['ransom_notes'] += 1
    else:
        stats['special'] += 1


def scan_group(path, root_device, mounts):
    stats = counts()
    pending = [path]
    active_directory = None
    last_report = time.monotonic()
    try:
        while pending:
            directory = pending.pop()
            active_directory = directory
            stats['directories'] += 1
            try:
                with os.scandir(directory) as entries:
                    for entry in entries:
                        try:
                            info = entry.stat(follow_symlinks=False)
                        except OSError as exc:
                            error(stats, exc, entry.path)
                            continue
                        if info.st_dev != root_device:
                            skip_device(stats, entry.path)
                        elif stat.S_ISDIR(info.st_mode):
                            if mounts is not None and entry.path in mounts:
                                stats['same_device_mounts'] += 1
                            pending.append(entry.path)
                        else:
                            count_entry(stats, entry.name, info)
                        if time.monotonic() - last_report >= 30:
                            emit({'event': 'progress', 'group': path,
                                  'pending_directories': len(pending), **stats})
                            last_report = time.monotonic()
            except OSError as exc:
                error(stats, exc, directory)
            active_directory = None
    except KeyboardInterrupt:
        emit({'event': 'group', 'group': path, 'complete_in_scope': False,
              'active_directory': active_directory,
              'pending_directories': len(pending) + int(active_directory is not None), **stats})
        raise
    emit({'event': 'group', 'group': path,
          'complete_in_scope': stats['errors'] == 0, **stats})
    return stats['errors']


def scan_root(root, mounts):
    root_stats = counts()
    groups = []
    try:
        info = os.lstat(root)
        if not stat.S_ISDIR(info.st_mode):
            raise OSError(20, 'root is not a directory')
        with os.scandir(root) as entries:
            for entry in entries:
                try:
                    item = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    error(root_stats, exc, entry.path)
                    continue
                if item.st_dev != info.st_dev:
                    skip_device(root_stats, entry.path)
                elif stat.S_ISDIR(item.st_mode):
                    if mounts is not None and entry.path in mounts:
                        root_stats['same_device_mounts'] += 1
                    groups.append(entry.path)
                else:
                    count_entry(root_stats, entry.name, item)
    except KeyboardInterrupt:
        emit({'event': 'group', 'group': root + '/(root entries)',
              'complete_in_scope': False, **root_stats})
        raise
    except OSError as exc:
        error(root_stats, exc, root)
        emit({'event': 'root', 'root': root, 'complete_in_scope': False, **root_stats})
        return root_stats['errors']
    emit({'event': 'group', 'group': root + '/(root entries)',
          'complete_in_scope': root_stats['errors'] == 0, **root_stats})
    errors = root_stats['errors']
    for group in sorted(groups):
        errors += scan_group(group, info.st_dev, mounts)
    emit({'event': 'root', 'root': root, 'complete_in_scope': errors == 0,
          'groups': len(groups) + 1, 'errors': errors})
    return errors


def stop(_signum, _frame):
    raise KeyboardInterrupt


def main():
    if len(sys.argv) < 2:
        print('usage: inventory.py ROOT [ROOT ...]', file=sys.stderr)
        return 2
    signal.signal(signal.SIGTERM, stop)
    roots = [os.path.abspath(path) for path in sys.argv[1:]]
    overlaps = [[a, b] for index, a in enumerate(roots) for b in roots[index + 1:]
                if os.path.commonpath([a, b]) in (a, b)]
    mounts = mount_points()
    emit({'event': 'start', 'roots': roots, 'overlapping_roots': overlaps,
          'mountinfo_available': mounts is not None,
          'note': 'other_files are not proven healthy; hardlinks and CoW affect totals'})
    errors = 0
    try:
        for root in roots:
            errors += scan_root(root, mounts)
    except KeyboardInterrupt:
        emit({'event': 'interrupted', 'completed_errors': errors})
        return 130
    emit({'event': 'done', 'errors': errors})
    return 2 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
