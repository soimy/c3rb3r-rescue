#!/usr/bin/env python3
"""Extract a sample-specific candidate from SAVED process maps, never a live PID.

Supports the reviewed non-PIE x86-64 layout only. A candidate is not authenticated:
validate it against independent originals with decrypt_copy.py on copies.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import struct


def read_va(root, regions, address, size):
    if address < 0 or size <= 0 or size > 4096:
        raise ValueError('Invalid bounded virtual read')
    output = bytearray()
    while len(output) < size:
        va = address + len(output)
        matches = [r for r in regions if r['start'] <= va < r['end']]
        if len(matches) != 1:
            raise ValueError('Missing or overlapping virtual mapping')
        region = matches[0]; length = min(size-len(output), region['end']-va)
        if any(h['start'] < va+length and h['end'] > va for h in region['holes']):
            raise ValueError('Required key/code bytes overlap an unreadable page')
        filename = 'map-%x-%x.bin' % (region['start'], region['end'])
        if region['file'] != filename:
            raise ValueError('Unexpected map filename')
        fd = os.open(root/filename, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as f:
            before = os.fstat(f.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size != region['end']-region['start']:
                raise ValueError('Map size or type differs')
            digest = hashlib.sha256()
            for block in iter(lambda: f.read(1024**2), b''):
                digest.update(block)
            if digest.hexdigest() != region['sha256']:
                raise ValueError('Map checksum differs')
            f.seek(va-region['start']); data = f.read(length)
            after = os.fstat(f.fileno())
            if len(data) != length or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError('Map changed during validation')
            output.extend(data)
    return bytes(output)


def recover(directory, profile, destination):
    root = Path(directory).resolve(strict=True)
    manifest_path = root/'capture.json'
    if manifest_path.is_symlink() or manifest_path.stat().st_size > 8*1024**2:
        raise ValueError('Invalid capture manifest')
    raw = manifest_path.read_bytes(); manifest = json.loads(raw)
    if manifest.get('schema') != 1 or manifest.get('format') != 'linux-process-mappings':
        raise ValueError('Expected a saved process mapping collection')
    if manifest['exe_sha256'] not in (profile['packed_sha256'], profile['unpacked_sha256']):
        raise ValueError('Executable does not match the reviewed sample profile')
    regions = manifest['regions']
    reader = lambda address, size: read_va(root, regions, address, size)
    signature = bytes.fromhex(profile['entry']['hex'])
    if reader(profile['entry']['va'], len(signature)) != signature:
        raise ValueError('Code signature differs; no ASLR/layout guessing')
    if reader(profile['mode_va'], 1) != b'\x20':
        raise ValueError('Unsupported runtime crypto mode')
    pointer = struct.unpack('<Q', reader(profile['master_pointer_va'], 8))[0]
    if not pointer:
        raise ValueError('Master pointer is empty')
    material = reader(pointer, 48)
    if not any(material[:16]) or not any(material[16:]):
        raise ValueError('Empty IV or AES material')
    destination = Path(destination); destination.mkdir(mode=0o700)
    path = destination/'master-candidate.bin'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(material); f.flush(); os.fsync(f.fileno())
    path.chmod(0o400)
    result = {'candidate_file': path.name, 'bytes': 48, 'master_pointer_va': hex(pointer),
              'capture_manifest_sha256': hashlib.sha256(raw).hexdigest(),
              'capture_complete': manifest['complete'],
              'validation': 'structural candidate only; full-file cryptographic comparison required'}
    fd = os.open(destination/'candidate.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(result, f, indent=2)
    return result


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--profile', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(recover(args.capture, json.loads(args.profile.read_text()), args.output)))


if __name__ == '__main__':
    main()
