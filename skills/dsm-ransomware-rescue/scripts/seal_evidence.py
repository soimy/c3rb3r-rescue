#!/usr/bin/env python3
"""Copy a quiescent evidence tree, hash/read back every file, and seal the copy.

This is an integrity baseline, not a disk image, timestamp authority, or WORM.
Symlinks and special files are recorded as metadata and never followed/copied.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import time


def digest(path):
    h = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError('Not a regular file')
        for data in iter(lambda: stream.read(8 * 1024**2), b''):
            h.update(data)
    return h.hexdigest()


def identity(s):
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def seal(source, destination):
    source, destination = Path(source), Path(destination)
    if source.is_symlink() or not source.is_dir():
        raise ValueError('Source must be a real directory')
    source = source.resolve()
    destination = destination.absolute()
    if destination.resolve().is_relative_to(source):
        raise ValueError('Destination must be outside source')
    destination.mkdir(mode=0o700)  # Never reuse an existing collection.
    records = []
    dirs = [destination]
    for root, dirnames, names in os.walk(source, followlinks=False):
        root = Path(root)
        # Refuse concurrent directory swaps; this collector is for quiescent trees.
        if root.is_symlink():
            raise ValueError('Source directory changed to a symlink')
        for name in sorted(dirnames + names):
            src = root / name
            rel = src.relative_to(source)
            dst = destination / rel
            before = src.lstat()
            item = {'path': str(rel), 'mode': stat.S_IMODE(before.st_mode),
                    'device': before.st_dev, 'inode': before.st_ino,
                    'nlink': before.st_nlink, 'bytes': before.st_size,
                    'mtime_ns': before.st_mtime_ns, 'ctime_ns': before.st_ctime_ns}
            if stat.S_ISLNK(before.st_mode):
                item.update(kind='symlink_metadata_only', target=os.readlink(src))
                if name in dirnames:
                    dirnames.remove(name)
            elif stat.S_ISDIR(before.st_mode):
                dst.mkdir(mode=0o700)
                dirs.append(dst)
                continue
            elif stat.S_ISREG(before.st_mode):
                fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW)
                h = hashlib.sha256()
                with os.fdopen(fd, 'rb') as inp, dst.open('xb') as out:
                    if identity(os.fstat(inp.fileno())) != identity(before):
                        raise ValueError('Source changed before copy: ' + str(rel))
                    for data in iter(lambda: inp.read(8 * 1024**2), b''):
                        out.write(data)
                        h.update(data)
                    out.flush()
                    os.fsync(out.fileno())
                    if identity(os.fstat(inp.fileno())) != identity(before):
                        raise ValueError('Source changed while copying: ' + str(rel))
                if digest(dst) != h.hexdigest():
                    raise ValueError('Readback mismatch: ' + str(rel))
                dst.chmod(0o400)
                item.update(kind='file', sha256=h.hexdigest())
            else:
                item['kind'] = 'special_metadata_only'
            records.append(item)
    result = {'schema': 1, 'source': str(source), 'completed_unix': time.time(),
              'files': records, 'copy_readback_verified': True,
              'limitations': 'Not an atomic snapshot; source must be quiescent. No filesystem repair or execution.'}
    manifest = destination / 'SEAL.json'
    with manifest.open('x') as out:
        json.dump(result, out, ensure_ascii=True, indent=2)
        out.write('\n')
        out.flush()
        os.fsync(out.fileno())
    witness = digest(manifest)
    with (destination / 'SEAL.sha256').open('x') as out:
        out.write(witness + '  SEAL.json\n')
    manifest.chmod(0o400)
    (destination / 'SEAL.sha256').chmod(0o400)
    for directory in reversed(dirs):
        directory.chmod(0o500)
    return {'files': sum(x['kind'] == 'file' for x in records),
            'bytes': sum(x['bytes'] for x in records if x['kind'] == 'file'),
            'manifest_sha256': witness}


def verify(root):
    root = Path(root).resolve(strict=True)
    expected = (root / 'SEAL.sha256').read_text().split()[0]
    if digest(root / 'SEAL.json') != expected:
        raise ValueError('Seal manifest changed')
    manifest = json.loads((root / 'SEAL.json').read_text())
    count = 0
    for item in manifest['files']:
        if item['kind'] != 'file':
            continue
        rel = Path(item['path'])
        path = root / rel
        if rel.is_absolute() or '..' in rel.parts or not path.resolve().is_relative_to(root):
            raise ValueError('Unsafe manifest path')
        if path.is_symlink() or path.stat().st_size != item['bytes'] or digest(path) != item['sha256']:
            raise ValueError('Evidence mismatch: ' + str(rel))
        count += 1
    return {'verified_files': count, 'manifest_sha256': expected}


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='action', required=True)
    s = sub.add_parser('copy'); s.add_argument('source'); s.add_argument('destination')
    v = sub.add_parser('verify'); v.add_argument('directory')
    a = p.parse_args()
    print(json.dumps(seal(a.source, a.destination) if a.action == 'copy' else verify(a.directory)))


if __name__ == '__main__':
    main()
