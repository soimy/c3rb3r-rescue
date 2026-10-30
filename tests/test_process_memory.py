import hashlib
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from capture_process_memory import (PREAD_OFFSET_LIMIT, capture, capture_region,
                                    identity, parse_maps, parse_stat, require_stopped,
                                    select_mappings)
from recover_process_key import read_va, recover


def fake_stat(pid=123, state='T', ticks=900):
    return '%s (process with ) spaces) %s %s %s 0\n' % (pid, state, ' '.join(['0']*18), ticks)


class ProcessMemoryTests(unittest.TestCase):
    def test_vsyscall_is_excluded_with_receipt_not_overflow(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t).resolve(); proc = root/'123'; task = proc/'task/123'
            task.mkdir(parents=True)
            for path in (proc, task):
                (path/'stat').write_text(fake_stat())
                (path/'status').write_text('TracerPid:\t0\n')
            (proc/'maps').write_text('0000-1000 rw-p 0 00:00 0 [heap]\n'
                                    'ffffffffff600000-ffffffffff601000 r-xp 0 00:00 0 [vsyscall]\n')
            (proc/'exe').write_bytes(b'synthetic executable')
            (proc/'mem').write_bytes(b'K'*4096)
            selected, excluded = select_mappings(parse_maps((proc/'maps').read_text()))
            self.assertEqual(sum(r['end']-r['start'] for r in selected), 4096)
            self.assertEqual(excluded[0]['path'], '[vsyscall]')
            result = capture(proc, root/'capture', 900,
                             hashlib.sha256((proc/'exe').read_bytes()).hexdigest(), root.stat().st_dev)
            self.assertFalse(result['complete'])
            self.assertTrue(result['selected_mappings_complete'])
            self.assertEqual(result['excluded_unaddressable'], excluded)
            self.assertEqual(len(result['regions']), 1)
            self.assertEqual(read_va(root/'capture', result['regions'], 0, 16), b'K'*16)
            self.assertEqual(json.loads((root/'capture/capture.json').read_text())['excluded_unaddressable'], excluded)

    def test_off_t_limit_boundary_and_nonreadable_maps(self):
        limit = PREAD_OFFSET_LIMIT
        regions = [{'start': limit-4096, 'end': limit, 'permissions': 'r--p', 'path': ''},
                   {'start': limit-1, 'end': limit+1, 'permissions': 'r--p', 'path': ''},
                   {'start': limit, 'end': limit+4096, 'permissions': '--xp', 'path': ''}]
        selected, excluded = select_mappings(regions)
        self.assertEqual(selected, regions[:1])
        self.assertEqual(len(excluded), 1)
        self.assertEqual(excluded[0]['reason'], 'offset_exceeds_signed_off_t')

    def test_pid_thread_and_map_guards(self):
        self.assertEqual(parse_stat(fake_stat())['start_ticks'], 900)
        stopped={'state':'T','start_ticks':900,'threads':{'123':{'state':'T','tracer_pid':0}}}
        require_stopped(stopped,900)
        with self.assertRaises(ValueError): require_stopped(stopped,901)
        for state,tracer in [('D',0),('S',0),('t',1),('T',1)]:
            changed=dict(stopped,threads={'123':{'state':state,'tracer_pid':tracer}})
            with self.assertRaises(ValueError): require_stopped(changed,900)
        maps=parse_maps('1000-2000 rw-p 0 00:00 0 [heap]\n2000-3000 r-xp 0 00:00 0 /sample file\n')
        self.assertEqual(maps[1]['path'],'/sample file')
        with self.assertRaises(ValueError): parse_maps('1000-3000 rw-p 0 00:00 0\n2000-4000 r--p 0 00:00 0')

    def test_page_holes_preserve_remaining_memory_and_are_not_keys(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t); out=root/'map-0-3000.bin'; content=b'A'*4096+b'B'*4096+b'C'*4096
            def read(fd,length,offset):
                if offset==4096: raise OSError(5,'synthetic unreadable page')
                return content[offset:offset+length]
            with patch('capture_process_memory.os.pread',side_effect=read):
                result=capture_region(9,{'start':0,'end':12288,'permissions':'rw-p'},out,4096)
            self.assertFalse(result['complete']); self.assertEqual(len(result['holes']),1)
            self.assertEqual(read_va(root,[result],8192,16),b'C'*16)
            with self.assertRaises(ValueError): read_va(root,[result],4096,16)
            with self.assertRaises(FileExistsError): capture_region(9,result,out,4096)

    def test_capture_validates_identity_mount_and_keeps_partial_errors(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t).resolve(); proc=root/'123'; proc.mkdir(); task=proc/'task/123';task.mkdir(parents=True)
            for path in (proc,task):
                (path/'stat').write_text(fake_stat());(path/'status').write_text('TracerPid:\t0\n')
            (proc/'maps').write_text('0000-1000 rw-p 0 00:00 0 [heap]\n1000-2000 r-xp 0 00:00 0\n')
            (proc/'exe').write_bytes(b'synthetic executable'); (proc/'mem').write_bytes(b'K'*4096+b'C'*4096)
            digest=hashlib.sha256((proc/'exe').read_bytes()).hexdigest(); dev=root.stat().st_dev
            with self.assertRaises(ValueError): capture(proc,root/'wrong-pid',901,digest,dev)
            with self.assertRaises(ValueError): capture(proc,root/'wrong-sha',900,'0'*64,dev)
            with self.assertRaises(ValueError): capture(proc,root/'wrong-device',900,digest,dev+1)
            self.assertEqual(sorted(p.name for p in root.iterdir()),['123'])
            result=capture(proc,root/'good',900,digest,dev)
            self.assertTrue(result['complete']);self.assertEqual(len(result['regions']),2)
            with self.assertRaises(FileExistsError): capture(proc,root/'good',900,digest,dev)
            with patch('capture_process_memory.capture_region',side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt): capture(proc,root/'partial',900,digest,dev)
            self.assertTrue((root/'partial/failure.json').exists())
            self.assertFalse((root/'partial/capture.json').exists())
            self.assertEqual(parse_stat((proc/'stat').read_text())['state'],'T')

    def test_saved_process_candidate_checks_signature_hash_mode_and_holes(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);data=bytearray(4096);data[16:24]=b'CODETEST';data[32]=0x20
            struct.pack_into('<Q',data,40,128);master=bytes(range(48));data[128:176]=master
            sample='a'*64;path=root/'map-0-1000.bin';path.write_bytes(data)
            region={'start':0,'end':4096,'file':path.name,'sha256':hashlib.sha256(data).hexdigest(),'holes':[]}
            manifest={'schema':1,'format':'linux-process-mappings','exe_sha256':sample,'complete':True,'regions':[region]}
            profile={'packed_sha256':sample,'unpacked_sha256':'b'*64,'entry':{'va':16,'hex':b'CODETEST'.hex()},
                     'mode_va':32,'master_pointer_va':40}
            (root/'capture.json').write_text(json.dumps(manifest))
            recover(root,profile,root/'candidate')
            self.assertEqual((root/'candidate/master-candidate.bin').read_bytes(),master)
            self.assertEqual((root/'candidate/master-candidate.bin').stat().st_mode&0o777,0o400)
            with self.assertRaises(FileExistsError):recover(root,profile,root/'candidate')
            data[32]=0x21;path.write_bytes(data);region['sha256']=hashlib.sha256(data).hexdigest()
            (root/'capture.json').write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):recover(root,profile,root/'decoy')
            data[32]=0x20;path.write_bytes(data)
            with self.assertRaises(ValueError):recover(root,profile,root/'tampered')
            region['sha256']=hashlib.sha256(data).hexdigest();region['holes']=[{'start':128,'end':176}]
            (root/'capture.json').write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):recover(root,profile,root/'hole')

    @unittest.skipUnless(sys.platform=='linux','Requires Linux /proc; fixture tests run on other hosts')
    def test_linux_stopped_child_round_trip_without_resuming(self):
        # Only this harmless child is signalled; never inspect an ambient process.
        child=subprocess.Popen([sys.executable,'-c',
            'import ctypes,time; b=ctypes.create_string_buffer(b"synthetic-volatile-marker"); '
            'print(ctypes.addressof(b),flush=True); time.sleep(60)'],stdout=subprocess.PIPE,text=True)
        try:
            address=int(child.stdout.readline().strip());os.kill(child.pid,signal.SIGSTOP)
            proc=Path('/proc')/str(child.pid)
            for _ in range(100):
                if identity(proc)['state']=='T':break
                time.sleep(0.01)
            with tempfile.TemporaryDirectory() as t:
                root=Path(t);ticks=identity(proc)['start_ticks']
                digest=hashlib.sha256((proc/'exe').read_bytes()).hexdigest()
                result=capture(proc,root/'capture',ticks,digest,root.stat().st_dev)
                self.assertEqual(read_va(root/'capture',result['regions'],address,25),b'synthetic-volatile-marker')
                self.assertEqual(identity(proc)['state'],'T')
        finally:
            child.kill();child.wait();child.stdout.close()


if __name__=='__main__':unittest.main()
