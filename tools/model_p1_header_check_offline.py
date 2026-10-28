"""Run exact P1 Header::Check A64 code in a synthetic CPU, with no OS/syscalls."""
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import zlib

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_INTR
from unicorn.arm64_const import UC_ARM64_REG_SP, UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_LR, UC_ARM64_REG_PC

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'output/rea-study/p1-stock-key-after-gates-01'
LIB = OUT / 'libupdatercorecommon.so'
SHA = 'cfe23b709f1a4feba16642729f39c9bb5f4516caa188fa67a6d31d3c1d833425'


def run(raw, header):
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    elf = ELFFile(io.BytesIO(raw));pages = set()
    for s in elf.iter_segments():
        if s['p_type'] == 'PT_LOAD':
            pages.update(range(s['p_vaddr'] & ~4095, (s['p_vaddr'] + s['p_memsz'] + 4095) & ~4095, 4096))
    for page in sorted(pages):u.mem_map(page, 4096)
    for s in elf.iter_segments():
        if s['p_type'] == 'PT_LOAD':u.mem_write(s['p_vaddr'], s.data())
    obj, data, stack, stop = 0x81000000, 0x81001000, 0x82000000, 0x90000000
    u.mem_map(obj, 8192);u.mem_map(stack, 65536);u.mem_map(stop, 4096)
    u.mem_write(obj + 8, struct.pack('<Q', data));u.mem_write(data, header)
    u.reg_write(UC_ARM64_REG_X0, obj);u.reg_write(UC_ARM64_REG_SP, stack + 32768)
    u.reg_write(UC_ARM64_REG_LR, stop)
    result = {'memcmp_calls': 0}
    def code(machine, address, size, ignored):
        if address == stop:
            result['return'] = machine.reg_read(UC_ARM64_REG_X0);machine.emu_stop()
        elif address == 0x85a0:  # Sole modeled external operation: exact byte comparison.
            a, b, n = [machine.reg_read(r) for r in (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2)]
            if n not in (4, 8):raise ValueError('Unexpected memcmp length')
            machine.reg_write(UC_ARM64_REG_X0, int(bytes(machine.mem_read(a, n)) != bytes(machine.mem_read(b, n))))
            machine.reg_write(UC_ARM64_REG_PC, machine.reg_read(UC_ARM64_REG_LR));result['memcmp_calls'] += 1
    def syscall(*args):raise ValueError('No syscalls admitted')
    u.hook_add(UC_HOOK_CODE, code);u.hook_add(UC_HOOK_INTR, syscall)
    u.emu_start(0x96fc, 0, count=200000)
    if 'return' not in result:raise ValueError('CPU model did not return')
    return result


def main():
    raw = LIB.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SHA:raise ValueError('Actual patched core changed')
    with (ROOT / 'output/fl23-stock-receiver-plain-01/plain.DO_NOT_INSTALL.bin').open('rb') as f:
        header = f.read(512)
    cases = [('candidate', header, 1)]
    for name, offset in [('wrong_magic', 0), ('wrong_format', 12), ('wrong_crc', 8), ('corrupt_payload', 48)]:
        value = bytearray(header);value[offset] ^= 1;cases.append((name, bytes(value), 0))
    value = bytearray(header);value[0x10] = ord('?')
    struct.pack_into('<I', value, 8, zlib.crc32(value[12:]))
    cases.append(('unknown_mode_with_valid_header_crc', bytes(value), 1))
    tests = []
    for name, value, expected in cases:
        result = run(raw, value)
        if result['return'] != expected:raise ValueError('Unexpected Header::Check result')
        tests.append(dict(case=name, expected=expected, **result))
    result = dict(all_passed=True, original_A64_function_executed_in_CPU_model=True,
        library_sha256=SHA, function='0x96fc', header_mode=chr(header[0x10]), tests=tests,
        external_operation_modeled='memcmp only', OS_calls=0, camera_operations=0,
        normal_AP_to_updater_handoff_proven=False, whole_update_acceptance_proven=False,
        conclusion='This function checks UDTRFIRM, format0100 and CRC; mode checks must be sought elsewhere',
        script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    with (OUT / 'header-check-cpu-model.json').open('x') as f:
        os.fchmod(f.fileno(),0o600);json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps(result))


if __name__ == '__main__':main()
