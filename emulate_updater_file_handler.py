"""Execute original updater FileHandler instructions with mocked libc only."""
from pathlib import Path
import hashlib
import json
import struct
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X30, UC_ARM64_REG_SP, UC_ARM64_REG_PC

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / 'output/claude-updater-chain-01/extract/updater-initrd/usr/lib/libupdatercommon.so'
RAW = SOURCE.read_bytes()
assert hashlib.sha256(RAW).hexdigest() == '537d4dc66029fed9bc413e8adc6ade638f1068716cf801536fd5476108a3b797'


def run(entry, results):
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    u.mem_map(0, 0x30000)
    u.mem_write(0, RAW)
    u.mem_map(0x100000, 0x10000)
    obj, buf, count, stop = 0x100000, 0x100100, 0x100200, 0x10f000
    u.mem_write(obj, bytes(8) + struct.pack('<i', 12))
    u.mem_write(buf, b'abcd')
    u.reg_write(UC_ARM64_REG_X0, obj)
    u.reg_write(UC_ARM64_REG_X1, buf)
    u.reg_write(UC_ARM64_REG_X2, 4)
    u.reg_write(UC_ARM64_REG_X3, count)
    u.reg_write(UC_ARM64_REG_X30, stop)
    u.reg_write(UC_ARM64_REG_SP, 0x10e000)
    pending, calls, reached = list(results), [], []
    def hook(uc, pc, size, ctx):
        if pc == stop:
            reached.append(True)
            uc.emu_stop()
        elif pc in (0x6e90, 0x6e40):
            assert pending, 'unexpected extra libc call'
            n = pending.pop(0)
            row = dict(api='write' if pc == 0x6e90 else 'close', fd=uc.reg_read(UC_ARM64_REG_X0), result=n)
            if pc == 0x6e90:
                row.update(pointer=uc.reg_read(UC_ARM64_REG_X1), requested=uc.reg_read(UC_ARM64_REG_X2))
            calls.append(row)
            uc.reg_write(UC_ARM64_REG_X0, n & 0xffffffffffffffff)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_X30))
        elif pc == 0x6de0:
            uc.mem_write(0x100300, struct.pack('<i', 5))
            uc.reg_write(UC_ARM64_REG_X0, 0x100300)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_X30))
        elif pc == 0x6fd0:
            uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_X30))
    u.hook_add(UC_HOOK_CODE, hook)
    u.emu_start(entry, 0, count=1000)
    assert reached and not pending
    return dict(return_value=u.reg_read(UC_ARM64_REG_X0),
                reported_bytes=struct.unpack('<Q', u.mem_read(count, 8))[0],
                final_fd=struct.unpack('<i', u.mem_read(obj+8, 4))[0], calls=calls)


def main():
    cases = []
    for name, responses, ok, count in [
        ('complete', [4], 1, 4), ('short_then_complete', [2, 2], 1, 4),
        ('three_short', [1, 1, 2], 1, 4), ('initial_error', [-1], 0, 0),
        ('initial_zero', [0], 0, 0), ('short_then_error', [2, -1], 0, 2),
        ('short_then_zero', [2, 0], 0, 2)]:
        r = run(0x8824, responses)
        assert r['return_value'] == ok and r['reported_bytes'] == count
        assert r['final_fd'] == 12
        if len(responses) > 1:
            assert r['calls'][1]['pointer'] == 0x100100 + responses[0]
            assert r['calls'][1]['requested'] == 4 - responses[0]
        cases.append(dict(case=name, **r))
    for n, expected in [(0,1), (-1,0)]:
        r = run(0x8670, [n])
        assert r['return_value'] == expected and r['final_fd'] == -1
        cases.append(dict(case='close_success' if n == 0 else 'close_failure', **r))
    out = ROOT / 'output/rea-study/updater-file-handler-offline'
    out.mkdir(exist_ok=True)
    report = dict(cases=cases, assertions_passed=True, camera_io=False,
        libc_write_close_errno_and_log_mocked=True,
        source_sha256=hashlib.sha256(RAW).hexdigest(),
        limitations=['No real filesystem, block driver, kernel flush or durability observed',
                     'Valid fd and buffer only; invalid-object exception paths not covered'])
    (out/'tests.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(dict(cases=len(cases), assertions_passed=True, camera_io=False)))


if __name__ == '__main__':
    main()
