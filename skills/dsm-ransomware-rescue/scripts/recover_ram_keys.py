#!/usr/bin/env python3
"""Recover sample-specific key candidates from an offline pc.ram copy.

Supports the documented low-1-GiB process VA, user 4-KiB page-table layout only.
No process is attached, no sample is executed, and no key bytes are printed.
"""
import argparse
import hashlib
import json
import mmap
import os
from pathlib import Path
import stat
import struct

MASK = 0x000FFFFFFFFFF000


class Ram:
    def __init__(self, data, low_end, high_start):
        if low_end <= 0 or high_start < low_end:
            raise ValueError('Invalid RAM map')
        self.data, self.low, self.high = data, low_end, high_start

    def physical(self, offset):
        return offset if offset < self.low else offset + self.high - self.low

    def offset(self, physical):
        if 0 <= physical < self.low:
            offset = physical
        elif self.high <= physical:
            offset = physical - self.high + self.low
        else:
            raise ValueError('Address lies in the uncaptured PCI hole')
        if not 0 <= offset < len(self.data):
            raise ValueError('Address lies outside the RAM copy')
        return offset

    def readp(self, physical, size):
        offset = self.offset(physical)
        if size < 0 or offset + size > len(self.data):
            raise ValueError('Truncated physical read')
        if size and self.offset(physical + size - 1) != offset + size - 1:
            raise ValueError('Physical read crosses an address gap')
        return self.data[offset:offset + size]

    def u64(self, physical):
        return struct.unpack('<Q', self.readp(physical, 8))[0]

    def readv(self, pd, va, length):
        if length < 0 or not 0 <= va < 0x40000000 or va + length > 0x40000000:
            raise ValueError('Only low-1-GiB process VA is supported')
        output = bytearray()
        while length:
            pde = self.u64(pd + ((va >> 21) & 511) * 8)
            if pde & 5 != 5 or pde & 128:
                raise ValueError('Missing user PDE or unsupported huge page')
            pte = self.u64((pde & MASK) + ((va >> 12) & 511) * 8)
            if pte & 5 != 5:
                raise ValueError('Missing user PTE')
            count = min(length, 4096 - (va & 4095))
            output.extend(self.readp((pte & MASK) + (va & 4095), count))
            va += count
            length -= count
        return bytes(output)


def save_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(data)
    Path(path).chmod(0o400)


def recover(data, profile, destination):
    destination = Path(destination)
    if len(data) != profile['ram_bytes'] or len(data) % 4096:
        raise ValueError('RAM size does not match the reviewed profile')
    destination.mkdir(mode=0o700)
    ram = Ram(data, profile['low_ram_end'], profile['high_ram_start'])
    va = profile['entry']['va']
    needle = bytes.fromhex(profile['entry']['hex'])
    if not 16 <= len(needle) <= 512 or (va & 4095) + len(needle) > 4096:
        raise ValueError('Invalid page signature')
    entries = set()
    at = 0
    while True:
        at = data.find(needle, at)
        if at < 0:
            break
        if at % 4096 == va % 4096:
            entries.add(ram.physical(at & ~4095))
        at += 1
    pt_index, pd_index = (va >> 12) & 511, (va >> 21) & 511
    pts = set()
    for offset in range(0, len(data), 4096):
        value = struct.unpack_from('<Q', data, offset + pt_index * 8)[0]
        if value & 5 == 5 and not value >> 63 and value & MASK in entries:
            pts.add(ram.physical(offset))
    pds = set()
    for offset in range(0, len(data), 4096):
        value = struct.unpack_from('<Q', data, offset + pd_index * 8)[0]
        if value & 5 == 5 and not value & 128 and value & MASK in pts:
            pds.add(ram.physical(offset))
    candidates = []
    for pd in sorted(pds):
        item = {'pd_physical': hex(pd)}
        try:
            if ram.readv(pd, va, len(needle)) != needle:
                raise ValueError('Code page mismatch')
            mode = ram.readv(pd, profile['mode_va'], 1)[0]
            if mode != 0x20:
                raise ValueError('Mode is not 0x20; decoy/unknown records refused')
            ptr = struct.unpack('<Q', ram.readv(pd, profile['master_pointer_va'], 8))[0]
            material = ram.readv(pd, ptr, 48)
            if not any(material):
                raise ValueError('Empty master candidate')
            name = 'master-pd-%x.bin' % pd
            save_private(destination / name, material)
            item.update(mode=mode, master_pointer=hex(ptr), master_file=name,
                        master_sha256=hashlib.sha256(material).hexdigest())
        except (ValueError, struct.error) as exc:
            item['error'] = str(exc)
        candidates.append(item)
    objects = []
    at = 0
    while True:
        at = data.find(b'expand 32-byte k', at)
        if at < 0:
            break
        if at >= 24 and at - 24 + 768 <= len(data):
            state = data[at:at + 104]
            if state[16:48] == state[72:104] and state[56:64] == state[64:72] and any(state[16:48]):
                name = 'file-object-%x.bin' % ram.physical(at - 24)
                save_private(destination / name, data[at - 24:at - 24 + 768])
                objects.append({'physical': hex(ram.physical(at - 24)), 'file': name})
        at += 1
    result = {'entry_pages': sorted(entries), 'pt_pages': sorted(pts), 'pd_pages': sorted(pds),
              'master_candidates': candidates, 'file_objects': objects,
              'limits': 'Live RAM acquisition may contain stale mappings. Candidates require footer and independent full-content validation.'}
    save_private(destination / 'scan-report.json', (json.dumps(result, indent=2)+'\n').encode())
    return result


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--ram', type=Path, required=True)
    p.add_argument('--profile', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    fd = os.open(a.ram, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise ValueError('RAM must be a saved regular file')
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
            result = recover(data, json.loads(a.profile.read_text()), a.output)
    print(json.dumps({'master_candidates': sum('master_file' in x for x in result['master_candidates']),
                      'file_objects': len(result['file_objects']), 'private_output': str(a.output)}))


if __name__ == '__main__':
    main()
