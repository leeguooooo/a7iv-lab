"""Offline, source-bound KikiLog framing; never contacts a camera.

Frames are confirmed against the original module's record_userlog_tim code.
Event names and payload meanings remain unknown. Timestamps use the firmware's
1970-01-01 base and represent the camera clock, whose correctness is unverified.
"""
import argparse
import collections
import datetime
import hashlib
import json
import struct
from pathlib import Path

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_LR, UC_ARM64_REG_PC, UC_ARM64_REG_SP

ROOT = Path(__file__).resolve().parent
ELF = ROOT / 'local/analysis/kikilog-linked/kikilog.analysis.elf'
EXPECTED = '62f6b479eb2829c69172bfc98f9291c95646ee4545132586654261267c56edcc'


def validate_framing():
    assert hashlib.sha256(ELF.read_bytes()).hexdigest() == EXPECTED
    results = []
    for flags in (0, 0x80000000, 0x20000, 0x80020000):
        u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        u.mem_map(0x100000, 0x500000)
        with ELF.open('rb') as f:
            e = ELFFile(f)
            sy = {s.name: s['st_value'] for s in e.get_section_by_name('.symtab').iter_symbols() if s.name}
            for seg in e.iter_segments():
                if seg['p_type'] == 'PT_LOAD' and seg['p_filesz']:
                    u.mem_write(seg['p_vaddr'], seg.data())
        base = 0x10000000
        u.mem_map(base, 0x20000)
        dest, src, stop = base, base+0x3000, base+0x1f000
        u.mem_write(sy['p_ulogtim_buf'], struct.pack('<Q', dest))
        u.mem_write(sy['wp_ulogtim_buf'], struct.pack('<I', 0))
        # Keep the normal timestamp branch; substitute only its clock provider.
        u.mem_write(0x10b918, struct.pack('<I', 0))
        payload = bytes.fromhex('1020304050607080')
        u.mem_write(src, struct.pack('<HII', 0x92, 0x301, flags)+payload)
        state = {'returned': False}
        def hook(_u, addr, size, context):
            if addr == 0x1013e0:
                u.reg_write(UC_ARM64_REG_X0, 0x12345678)
                u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_LR))
            elif addr == sy['kikilog_update']:
                raise RuntimeError('Unexpected storage flush')
            elif addr == stop:
                state['returned'] = True
                u.emu_stop()
        u.hook_add(UC_HOOK_CODE, hook)
        u.reg_write(UC_ARM64_REG_X0, src)
        u.reg_write(UC_ARM64_REG_X1, 0x55667788)
        u.reg_write(UC_ARM64_REG_SP, base+0x18000)
        u.reg_write(UC_ARM64_REG_LR, stop)
        u.emu_start(sy['record_userlog_tim'], 0, count=10000)
        assert state['returned']
        n = struct.unpack('<I', bytes(u.mem_read(sy['wp_ulogtim_buf'], 4)))[0]
        extra = bool(flags & 0x80020000)
        expected = struct.pack('<II', 0x09200301 | (0x80000000 if extra else 0), 0x12345678)
        if flags & 0x20000:
            expected += struct.pack('<Q', 0x55667788)
        elif flags & 0x80000000:
            expected += payload
        assert bytes(u.mem_read(dest, n)) == expected
        results.append({'flags': hex(flags), 'bytes': n, 'passed': True})
    return results


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    assert not a.output.exists(), 'Use a new report path'
    tests = validate_framing()
    b = a.input.read_bytes()
    assert len(b) == 0x408000
    assert b[:0x204000] == b[0x204000:], 'Mirrored banks differ; selection not implemented'
    footer = struct.unpack_from('<16I', b, 0x203fc0)
    cursor, phase = footer[0], footer[3]
    assert footer[-1] == 0xaaaaaaaa and 0 <= cursor <= 0x200000 and cursor % 8 == 0
    assert phase == 0, 'Wrapped/in-progress ring ordering not implemented'
    pos = 0
    tail = collections.deque(maxlen=256)
    ids = collections.Counter()
    nonzero = []
    while pos < cursor:
        tag, stamp = struct.unpack_from('<II', b, pos)
        assert tag != 0xffffffff, f'Unexpected erased frame at {pos:x}'
        size = 16 if tag & 0x80000000 else 8
        assert pos+size <= cursor, 'Truncated final frame'
        event_id = tag & 0x7fffffff
        row = {'offset': hex(pos), 'event_id': f'{event_id:08x}', 'camera_seconds_since_1970': stamp}
        if stamp:
            nonzero.append(stamp)
            row['camera_clock_utc_basis'] = datetime.datetime.fromtimestamp(stamp, datetime.timezone.utc).isoformat()
        if size == 16:
            row['payload_hex'] = b[pos+8:pos+16].hex()
        tail.append(row)
        ids[f'{event_id:08x}'] += 1
        pos += size
    report = {'input_sha256': hashlib.sha256(b).hexdigest(), 'hardware_access': False,
              'framing_tests': tests, 'mirror_equal': True, 'cursor': cursor, 'phase': phase,
              'frames': sum(ids.values()), 'distinct_event_ids': len(ids),
              'event_names_known': False, 'payload_semantics_known': False,
              'camera_clock_verified': False, 'nonzero_timestamp_minmax': [min(nonzero), max(nonzero)],
              'last_256_frames': list(tail)}
    a.output.write_text(json.dumps(report, indent=2)+'\n')
    a.output.chmod(0o600)
    print(json.dumps({k: report[k] for k in ['framing_tests','mirror_equal','cursor','frames','distinct_event_ids','nonzero_timestamp_minmax']}, indent=2))


if __name__ == '__main__':
    main()
