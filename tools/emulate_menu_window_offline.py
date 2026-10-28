"""Run the actual saved AArch64 menu worker in Unicorn over synthetic syscalls.

No SDK, USB, real /proc, process-memory, block, card, or device access. The only
host inputs are reviewed workspace artifacts. Every pwrite targets sparse
Python bytearrays; the model never executes bootstrap or real ARM processes.
"""
import argparse
from collections import Counter
import hashlib
import io
import json
from pathlib import Path
import struct

import unicorn
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_INTR, UC_HOOK_BLOCK
from unicorn.arm64_const import UC_ARM64_REG_SP, UC_ARM64_REG_X0, UC_ARM64_REG_X8
from elftools.elf.elffile import ELFFile

from menu_window_profile import ROOT, MODULES, OBSERVATION_OFFSETS, OBSERVATION_SIZES, require, sha
from verify_menu_window_offline import verify

CASES = (
    'success', 'not_root', 'low_tmpfs', 'wrong_tmpfs', 'bad_start_nonce', 'half_start',
    'start_short_reads', 'missing_app', 'missing_lib', 'inconsistent_versions',
    'wrong_app_anchor', 'duplicate_app', 'app_maps_change_before_patch',
    'app_pid_reused_after_patch', 'lib_maps_change_after_patch',
    'first_patch_error', 'first_patch_short', 'second_patch_error', 'second_patch_short',
    'lib_restore_error', 'lib_restore_short', 'app_restore_error', 'clock_backward',
    'terminate_after_first_patch', 'terminate_after_both_patches',
    'ready_half_write_error', 'patched_half_write_error', 'result_half_write_error',
    'record_short_writes_completed',
)
EARLY = {'not_root', 'low_tmpfs', 'wrong_tmpfs', 'bad_start_nonce', 'half_start',
         'missing_app', 'missing_lib', 'inconsistent_versions', 'wrong_app_anchor',
         'duplicate_app', 'app_maps_change_before_patch', 'ready_half_write_error'}
SUCCESS = {'success', 'start_short_reads', 'record_short_writes_completed'}
TERMINATED = {'terminate_after_first_patch', 'terminate_after_both_patches'}
UNKNOWN_MEMORY = {'app_pid_reused_after_patch', 'lib_maps_change_after_patch',
                  'lib_restore_error', 'lib_restore_short', 'app_restore_error'} | TERMINATED
RESULT = struct.Struct('<8s16s51q')


def dirent(name, kind=4):
    value = name.encode() + b'\0'
    length = (19 + len(value) + 7) & ~7
    row = bytearray(length)
    struct.pack_into('<QQHB', row, 0, 1, 0, length, kind)
    row[19:19 + len(value)] = value
    return bytes(row)


def emulate(directory, scenario, manifest):
    require(scenario in CASES, 'Unknown model case')
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    debug = (directory / 'worker.debug.elf').read_bytes()
    elf = ELFFile(io.BytesIO(debug))
    pages = set()
    for segment in elf.iter_segments():
        if segment['p_type'] == 'PT_LOAD':
            pages.update(range(segment['p_vaddr'] & ~4095,
                               (segment['p_vaddr'] + segment['p_memsz'] + 4095) & ~4095, 4096))
    ranges = []
    for page in sorted(pages):
        if ranges and ranges[-1][1] == page:
            ranges[-1][1] += 4096
        else:
            ranges.append([page, page + 4096])
    for first, last in ranges:
        u.mem_map(first, last - first)
    for segment in elf.iter_segments():
        if segment['p_type'] == 'PT_LOAD':
            u.mem_write(segment['p_vaddr'], segment.data())
    stack = 0x90000000
    u.mem_map(stack, 0x100000)
    sp = stack + 0x80000
    u.reg_write(UC_ARM64_REG_SP, sp)
    u.mem_write(sp, struct.pack('<4Q', 2, sp + 256, sp + 300, 0))
    u.mem_write(sp + 256, b'worker\0')
    u.mem_write(sp + 300, b'123\0')
    nonce = bytes.fromhex(manifest['nonce'])
    job = manifest['job_dir']
    start_token = b'M4DSTART' + nonce + struct.pack('<Q', 1)
    if scenario == 'bad_start_nonce':
        start_token = start_token[:8] + bytes([start_token[8] ^ 1]) + start_token[9:]
    if scenario == 'half_start':
        start_token = start_token[:16]
    files = {job + '/worker': b'SYNTHETIC_EXECUTABLE_ALREADY_LOADED', job + '/start': start_token}
    bases = {'lib': 0x40000000, 'app': 0x50000000}
    profiles = {'lib': MODULES['libupdaterufp.so'], 'app': MODULES['appFw.so']}
    # Sparse synthetic mm regions only; anchors include the target instructions.
    memory = {}
    for name, profile in profiles.items():
        memory[name] = {
            bases[name] + profile['anchor_offset']: bytearray.fromhex(profile['anchor_hex']),
            bases[name] + profile['global_version_offset']: bytearray(
                (0x0602 if name == 'lib' else (6 << 16) | 2).to_bytes(profile['version_bytes'], 'little')),
        }
    if scenario == 'inconsistent_versions':
        memory['app'][bases['app'] + profiles['app']['global_version_offset']] = bytearray(struct.pack('<I', (6 << 16) | 1))
    if scenario == 'wrong_app_anchor':
        memory['app'][bases['app'] + profiles['app']['anchor_offset']][0] ^= 1
    for offset, size in zip(OBSERVATION_OFFSETS, OBSERVATION_SIZES):
        memory['app'][bases['app'] + offset] = bytearray(size)
    state = {'next_fd': 3, 'clock_ns': 1000000000, 'clock_rollback_injected': False,
             'exit': None, 'stopped_by_model': False, 'blocks': 0, 'maps_changed_app': False,
             'maps_changed_lib': False, 'app_mem_opened': False, 'patched_record_closed': False,
             'half_file_fault_injected': False, 'reads_split': 0, 'record_short_writes': 0}
    fds, writes, file_writes, calls, completed = {}, [], [], Counter(), {}

    def read_memory(name, address, count):
        require(0 < count <= 64, 'Unexpected synthetic memory read length')
        hits = [(base, raw) for base, raw in memory[name].items()
                if base <= address and address + count <= base + len(raw)]
        require(len(hits) == 1, 'Native read outside synthetic mm fixture')
        base, raw = hits[0]
        return bytes(raw[address - base:address - base + count])

    def write_memory(name, address, raw):
        require(address == bases[name] + profiles[name]['patch_offset'] and 0 < len(raw) <= 4,
                'Native pwrite outside reviewed four-byte synthetic target')
        base = bases[name] + profiles[name]['anchor_offset']
        offset = address - base
        memory[name][base][offset:offset + len(raw)] = raw

    def map_data(pid):
        if pid == 123:
            if scenario == 'missing_lib':
                return b''
            inode = 113 if state['maps_changed_lib'] else 112
            return (f'40000000-40008000 r-xp 00000000 00:01 {inode} /usr/lib/libupdaterufp.so\n'
                    '40025000-40026000 rw-p 00025000 00:01 112 /usr/lib/libupdaterufp.so\n').encode()
        if pid in (456, 457):
            if scenario == 'missing_app' or (pid == 457 and scenario != 'duplicate_app'):
                return b''
            inode = 115 if state['maps_changed_app'] else 114
            return (f'50000000-53000000 r-xp 00000000 00:01 {inode} /usr/lib/appFw.so\n'
                    '57f00000-59000000 rw-p 07f00000 00:01 114 /usr/lib/appFw.so\n').encode()
        require(pid in (1, 234), 'Unexpected synthetic PID')
        return b''

    def text(address):
        raw = bytes(u.mem_read(address, 512))
        require(b'\0' in raw, 'Unbounded syscall pathname')
        return raw.split(b'\0', 1)[0].decode('ascii')

    def ret(value):
        u.reg_write(UC_ARM64_REG_X0, value & ((1 << 64) - 1))

    def record(raw):
        require(len(raw) == RESULT.size, 'Partial native record rejected')
        magic, observed_nonce, *values = RESULT.unpack(raw)
        require(magic == b'M4DWL002' and observed_nonce == nonce, 'Native record identity mismatch')
        return dict(zip(manifest['result']['fields'], values))

    def syscall(_u, number, _data):
        require(number == 2, 'Unexpected Unicorn interrupt (only AArch64 SVC accepted)')
        no = u.reg_read(UC_ARM64_REG_X8)
        a, b, c, d, e, f = [u.reg_read(UC_ARM64_REG_X0 + i) for i in range(6)]
        calls[no] += 1
        if no == 56:  # openat; strictly synthetic path table
            path = text(b)
            if c == 0x880c1:
                require(path in {job + '/' + n for n in ('ready', 'patched', 'result')} and d == 0o600,
                        'Unexpected synthetic publication create')
                if path in files:
                    ret(-17)
                    return
                files[path] = b''
                row = {'kind': 'file', 'path': path, 'position': 0, 'write': True}
            elif path in ('/proc', '/proc/self/fd'):
                require(c == 0x8c000, 'Unexpected directory flags')
                names = ['.', '1', '123', '234', '456']
                if scenario == 'duplicate_app':
                    names.append('457')
                if path == '/proc/self/fd':
                    names = ['.', str(state['next_fd'])]
                row = {'kind': 'directory', 'path': path, 'position': 0,
                       'data': b''.join(dirent(name) for name in names)}
            elif path.startswith('/proc/') and path.endswith('/maps'):
                require(c == 0x88000, 'Unexpected maps flags')
                pid = int(path.split('/')[2])
                if scenario == 'app_maps_change_before_patch' and pid == 456 and state['app_mem_opened']:
                    state['maps_changed_app'] = True
                row = {'kind': 'maps', 'path': path, 'position': 0, 'data': map_data(pid)}
            elif path in ('/proc/123/mem', '/proc/456/mem'):
                require(c == 0x88002, 'Unexpected proc mem flags')
                target = 'lib' if path == '/proc/123/mem' else 'app'
                if target == 'app':
                    state['app_mem_opened'] = True
                # A retained fd refers to this original synthetic mm even if PID maps change.
                row = {'kind': 'memory', 'path': path, 'target': target, 'mm_identity': target + '_original'}
            else:
                require(path in (job + '/start',), 'Unexpected synthetic read path: ' + path)
                require(c == 0x88000, 'Unexpected file flags')
                if path not in files:
                    ret(-2)
                    return
                row = {'kind': 'file', 'path': path, 'position': 0, 'write': False}
            fd = state['next_fd']
            state['next_fd'] += 1
            fds[fd] = row
            ret(fd)
        elif no == 57:  # close
            row = fds.pop(a, None)
            if row and row['kind'] == 'file' and row.get('write'):
                path = row['path']
                completed[path.rsplit('/', 1)[1]] = files[path]
                if path == job + '/patched':
                    state['patched_record_closed'] = True
            ret(0 if row else -9)
        elif no in (61, 63):  # getdents64 / read
            require(a in fds, 'Read from unknown synthetic fd')
            row = fds[a]
            require(row['kind'] == 'directory' if no == 61 else row['kind'] in ('file', 'maps'),
                    'Unexpected synthetic read syscall/fd kind')
            raw = row['data'] if row['kind'] in ('directory', 'maps') else files[row['path']]
            pos = row['position']
            count = min(c, len(raw) - pos)
            if scenario == 'start_short_reads' and row['path'] == job + '/start' and count > 3:
                count = 3
                state['reads_split'] += 1
            if count:
                u.mem_write(b, raw[pos:pos + count])
            row['position'] += count
            ret(count)
        elif no == 64:  # write; only native publications in synthetic byte strings
            row = fds[a]
            require(row['kind'] == 'file' and row.get('write') and c <= 432, 'Unexpected native publication write')
            path = row['path']
            raw = bytes(u.mem_read(b, c))
            target_name = path.rsplit('/', 1)[1]
            fault = scenario == target_name + '_half_write_error'
            if fault and len(files[path]) > 0:
                count = -5
            elif fault:
                count = c // 2
                state['half_file_fault_injected'] = True
            elif scenario == 'record_short_writes_completed' and c > 31:
                count = 31
                state['record_short_writes'] += 1
            else:
                count = c
            if count > 0:
                files[path] += raw[:count]
            file_writes.append({'record': target_name, 'requested': c, 'returned': count,
                                'cumulative_bytes': len(files[path])})
            ret(count)
        elif no == 35:  # unlinkat, only the volatile worker/start names
            path = text(b)
            require(path in (job + '/worker', job + '/start'), 'Unexpected unlink')
            if path in files:
                del files[path]
                ret(0)
            else:
                ret(-2)
        elif no == 43:  # statfs
            require(text(a) == '/tmp_wbshd', 'Unexpected statfs')
            free = 1 if scenario == 'low_tmpfs' else 100000
            u.mem_write(b, struct.pack('<15q', 0 if scenario == 'wrong_tmpfs' else 0x1021994,
                                      4096, 100000, free, free, 0, 0, 0, 255, 4096, 0, 0, 0, 0, 0))
            ret(0)
        elif no == 67:  # pread64, exclusively synthetic /proc/PID/mem
            row = fds[a]
            require(row['kind'] == 'memory', 'pread to nonmemory synthetic fd')
            u.mem_write(b, read_memory(row['target'], d, c))
            ret(c)
        elif no == 68:  # pwrite64, exclusively reviewed targets in Python bytearrays
            row = fds[a]
            require(row['kind'] == 'memory' and c == 4, 'Unexpected pwrite fd/count')
            target = row['target']
            raw = bytes(u.mem_read(b, c))
            profile = profiles[target]
            require(d == bases[target] + profile['patch_offset'], 'pwrite address outside fixed target')
            if raw.hex() == profile['patch_hex']:
                phase = 'patch'
            else:
                require(raw.hex() == profile['original_hex'], 'pwrite bytes outside original/patch pair')
                phase = 'restore'
            count = 4
            order = 'first' if target == 'app' else 'second'
            if phase == 'patch' and scenario == order + '_patch_error':
                count = -5
            if phase == 'patch' and scenario == order + '_patch_short':
                count = 2
            if phase == 'restore' and scenario == target + '_restore_error':
                count = -5
            if phase == 'restore' and scenario == target + '_restore_short':
                count = 2
            before = read_memory(target, d, 4)
            if count > 0:
                write_memory(target, d, raw[:count])
            writes.append({'target': target, 'phase': phase, 'address': hex(d), 'requested': 4,
                           'returned': count, 'before_hex': before.hex(), 'requested_hex': raw.hex(),
                           'after_hex': read_memory(target, d, 4).hex(), 'fd_mm_identity': row['mm_identity']})
            if phase == 'patch' and count == 4:
                if target == 'app' and scenario == 'app_pid_reused_after_patch':
                    state['maps_changed_app'] = True
                if target == 'lib' and scenario == 'lib_maps_change_after_patch':
                    state['maps_changed_lib'] = True
                terminate = scenario == 'terminate_after_first_patch' and target == 'app'
                terminate |= scenario == 'terminate_after_both_patches' and target == 'lib'
                if terminate:
                    ret(count)
                    state['stopped_by_model'] = True
                    u.emu_stop()
                    return
            ret(count)
        elif no == 175:
            ret(1000 if scenario == 'not_root' else 0)
        elif no == 172:
            ret(234)
        elif no == 173:
            ret(1)
        elif no == 113:  # clock_gettime(CLOCK_MONOTONIC)
            require(a == 1, 'Unexpected clock id')
            if scenario == 'clock_backward' and state['patched_record_closed']:
                if not state['clock_rollback_injected']:
                    now = state['clock_ns']
                    state['clock_rollback_injected'] = True
                else:
                    now = state['clock_ns'] - 1000000000
            else:
                now = state['clock_ns']
                state['clock_ns'] += 100000000000
            u.mem_write(b, struct.pack('<2q', now // 1000000000, now % 1000000000))
            ret(0)
        elif no == 101:  # nanosleep, synthetic time only
            requested = struct.unpack('<2q', bytes(u.mem_read(a, 16)))
            require(requested[0] >= 0 and 0 <= requested[1] < 1000000000, 'Bad synthetic sleep')
            ret(0)
        elif no == 94:
            state['exit'] = a
            u.emu_stop()
        else:
            raise RuntimeError('Unexpected menu worker syscall ' + str(no))

    def block(_u, _address, _size, _data):
        state['blocks'] += 1

    u.hook_add(UC_HOOK_INTR, syscall)
    u.hook_add(UC_HOOK_BLOCK, block)
    u.emu_start(elf['e_entry'], 0, count=6000000)
    require(state['exit'] is not None or state['stopped_by_model'], 'Native instruction budget exhausted unexpectedly')
    terminal_raw = files.get(job + '/result')
    terminal = record(terminal_raw) if terminal_raw is not None and len(terminal_raw) == 432 else None
    raw_result_bytes = len(terminal_raw) if terminal_raw is not None else 0
    final = {}
    for target, profile in profiles.items():
        raw = read_memory(target, bases[target] + profile['patch_offset'], 4).hex()
        final[target] = {'hex': raw, 'state': 'original' if raw == profile['original_hex'] else
                         'patched' if raw == profile['patch_hex'] else 'mixed_or_other'}
    if scenario in SUCCESS:
        require(state['exit'] == 0 and terminal and terminal['phase'] == 6 and terminal['error'] == 0,
                'Success case did not publish native success')
        require([(w['target'], w['phase']) for w in writes] ==
                [('app', 'patch'), ('lib', 'patch'), ('lib', 'restore'), ('app', 'restore')],
                'Native patch/restore order differs')
        require(terminal['patched'] == terminal['app_patched'] == terminal['restored'] ==
                terminal['app_restored'] == 1 and terminal['hold_seconds'] >= 600 and
                terminal['restore_status'] == terminal['app_restore_status'] == 0, 'Native success flags differ')
    elif scenario in TERMINATED:
        require(state['exit'] is None and state['stopped_by_model'] and terminal_raw is None,
                'Model interruption falsely produced a terminal result')
        require(not any(w['phase'] == 'restore' for w in writes), 'Model added automatic restoration')
    elif scenario == 'result_half_write_error':
        require(state['exit'] == 0 and terminal is None and raw_result_bytes == 216,
                'Partial terminal record accepted or missing-publication scenario not reached')
    else:
        require(state['exit'] == 1 and terminal and terminal['phase'] == 90 and terminal['error'] < 0,
                'Failure case falsely reported success')
    if scenario in EARLY:
        require(not writes, 'Admission failure performed synthetic pwrite')
    if scenario not in UNKNOWN_MEMORY:
        require(all(item['state'] == 'original' for item in final.values()), 'Expected native restoration did not occur')
    else:
        require(any(item['state'] != 'original' for item in final.values()), 'Expected unresolved memory state not reached')
    if scenario.endswith('_patch_short'):
        target = 'app' if scenario.startswith('first') else 'lib'
        selected = [w for w in writes if w['target'] == target]
        require([(w['phase'], w['returned']) for w in selected] == [('patch', 2), ('restore', 4)],
                'Short instruction write was completed with subword replay instead of restoration')
    if scenario in ('first_patch_error', 'second_patch_error'):
        require(any(w['phase'] == 'patch' and w['returned'] == -5 for w in writes), 'Patch error injection missed')
    if scenario in ('lib_restore_error', 'app_restore_error', 'lib_restore_short'):
        target = 'app' if scenario == 'app_restore_error' else 'lib'
        prefix = 'app_' if target == 'app' else ''
        require(terminal[prefix + 'restored'] == 0 and terminal[prefix + 'restore_status'] < 0,
                'Failed restoration falsely reported restored')
    if scenario == 'app_pid_reused_after_patch':
        require(terminal['app_restore_status'] == -116 and final['app']['state'] == 'patched',
                'Changed PID/maps identity was overwritten')
    if scenario == 'lib_maps_change_after_patch':
        require(terminal['restore_status'] == -116 and terminal['app_restored'] == 1,
                'Changed lib mapping handling differs')
    if scenario == 'clock_backward':
        require(state['clock_rollback_injected'] and terminal['error'] == -5,
                'Backward clock case not reached')
    if scenario == 'start_short_reads':
        require(state['reads_split'] > 0, 'START read splitting missed')
    if scenario == 'record_short_writes_completed':
        require(state['record_short_writes'] > 0 and all(len(completed[n]) == 432 for n in ('ready', 'patched', 'result')),
                'Native publication short-write retry was not exercised')
    if scenario.endswith('_half_write_error'):
        target_name = scenario.removesuffix('_half_write_error')
        require(state['half_file_fault_injected'] and len(files[job + '/' + target_name]) == 216,
                'Half native publication injection missed')
    classification = 'RESTORED_NATIVE_FAILURE' if terminal and terminal['error'] else 'RESTORED_NATIVE_SUCCESS'
    if scenario in EARLY:
        classification = 'REFUSED_ZERO_MEMORY_WRITES'
    if scenario in UNKNOWN_MEMORY or scenario == 'result_half_write_error':
        classification = 'UNKNOWN_NO_AUTOMATIC_RECOVERY_CLAIM'
    return {'case': scenario, 'passed': True, 'actual_native_instruction_execution': True,
            'native_basic_blocks_executed': state['blocks'], 'instruction_budget': 6000000,
            'native_exit': state['exit'], 'model_interrupted': state['stopped_by_model'],
            'classification': classification, 'pwrite_calls': len(writes),
            'memory_writes': writes, 'final_synthetic_mm_bytes': final,
            'terminal_record_bytes': raw_result_bytes, 'terminal_record_complete': terminal is not None,
            'native_terminal': terminal, 'publication_write_events': file_writes,
            'syscall_counts': dict(sorted(calls.items())),
            'retained_fd_targets': 'Synthetic original mm; /proc/PID/maps identity can change independently',
            'host_or_physical_restoration_proven': False, 'hardware_operations': 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--job', type=Path, default=ROOT / 'output/menu-stock-window-offline-01')
    parser.add_argument('--case', choices=CASES, action='append')
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    job = args.job.absolute()
    verify(job)  # Read-only independent source/ELF/artifact/ABI validation first.
    original_hashes = {name: sha(job / name) for name in ('manifest.json', 'verification.json')}
    manifest = json.loads((job / 'manifest.json').read_text())
    cases = tuple(args.case) if args.case else CASES
    require(len(set(cases)) == len(cases), 'Duplicate model cases')
    results = []
    for scenario in cases:
        results.append(emulate(job, scenario, manifest))
        print(scenario + ' PASS', flush=True)
    verify(job)
    require(original_hashes == {name: sha(job / name) for name in original_hashes}, 'Original manifest/verification changed')
    report = {'schema': 'camera-menu-stock-real-worker-synthetic-syscalls/1', 'all_passed': True,
        'coverage_complete_for_declared_matrix': len(results) == len(CASES) and set(cases) == set(CASES),
        'scope': 'Actual debug worker AArch64 instructions in Unicorn; synthetic syscall/proc/sparse-mm model only',
        'engine': {'name': 'Unicorn', 'version': unicorn.__version__, 'target': 'AArch64'},
        'manifest_sha256': original_hashes['manifest.json'], 'verification_sha256': original_hashes['verification.json'],
        'debug_worker_sha256': sha(job / 'worker.debug.elf'), 'emulator_sha256': sha(Path(__file__)),
        'profile_sha256': sha(ROOT / 'tools/menu_window_profile.py'),
        'native_fault_model_executed': True, 'native_execution_kind': 'EMULATED_INSTRUCTIONS_ONLY',
        'real_ARM_process_executed': False, 'bootstrap_executed': False, 'hardware_operations': 0,
        'admission': 'OFFLINE_NOT_BODY_BOUND', 'host_executor_created': False,
        'original_manifest_updated': False, 'case_count': len(results), 'cases': results,
        'model_assumptions': ['Only fixed /proc synthetic PIDs and exact fixture maps are modeled',
            'Finite synchronous pread/pwrite operate only on Python bytearrays; no Linux kernel is emulated',
            'Synthetic monotonic time advances by 100 seconds per clock call; nanosleep consumes no wall time',
            'Retained synthetic mem fd refers to the original mm when a PID/maps fixture changes',
            'Model interruption stops Unicorn immediately after selected patch pwrite; it is not a signal-handler or crash simulation'],
        'limitations': ['No real process scheduling, concurrent target instruction execution, or cross-core four-byte atomicity evidence',
            'No real Linux /proc mem permission/COW behavior, D-cache/I-cache coherence or cache-maintenance validation',
            'No independent watchdog; model interruption demonstrates an unresolved patch without automatic restoration',
            'No bootstrap constructor/loading, service protocol, live maps, current versions, card package or SD/updater handoff validation',
            'No real suspend/resume, unbounded blocking syscall, SIGKILL, power-loss or physical installation acceptance',
            'Partial records are exposed by the syscall fixture; this is not a test of a new Mac host record collector',
            'Manifest/verification historical native_fault_model_executed=false remains unchanged; this separate report adds later evidence']}
    destination = args.report or job / 'native-model-report.json'
    destination = destination.absolute()
    require(destination.is_relative_to(ROOT / 'output') and
            not any(p.is_symlink() for p in (destination, *destination.parents)), 'Workspace non-symlink report path required')
    with destination.open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'case_count': len(results), 'all_passed': True, 'report': str(destination),
                      'hardware_operations': 0, 'real_ARM_process_executed': False}))


if __name__ == '__main__':
    main()
